//! Read-your-writes staging, bounded shared caches, and reversible checkpoints.
use crate::batch_data::{checkpoint_entry_charge, BatchOperation, CompactKey};
use crate::{
    push_bounded_scan_entry, validate_prefix_scan_request, AccountedWriteBatch,
    CheckpointWriteBatch, ColumnFamily, NameTreePathRecord, PrefixScanBudget, PrefixScanPage,
    ReadSnapshot, ScanEntry, SharedBytes, StoreError, WriteBatch, PREFIX_SCAN_MAX_BYTES,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, VecDeque},
    rc::Rc,
};

type StagedChanges = HashMap<ColumnFamily, HashMap<CompactKey, BatchOperation>>;
type SharedStagedChanges = Rc<RefCell<StagedChanges>>;
type StagedCheckpointEntry = (ColumnFamily, CompactKey, Option<BatchOperation>);
#[derive(Default)]
struct StagedCheckpoint {
    journal: Vec<StagedCheckpointEntry>,
    retained_charge: u64,
}

/// Snapshot caches stop admitting entries when either limit is reached. Byte
/// admission includes values, keys, and conservative allocation/table framing.
pub const STAGED_NAME_NODE_READ_CACHE_LIMIT: usize = 131_072;
pub const STAGED_NAME_NODE_READ_CACHE_BYTES: usize = 32 * 1024 * 1024;
pub const STAGED_STATE_POINT_READ_CACHE_LIMIT: usize = 65_536;
pub const STAGED_STATE_POINT_READ_CACHE_BYTES: usize = 16 * 1024 * 1024;
const CACHE_ENTRY_FRAMING_BYTES: usize = 256;
// Reserve the first inner table and the outer family-table slots before
// admitting a family's first value, including a single near-limit value.
const CACHE_FAMILY_FRAMING_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheUsage {
    pub entries: usize,
    pub retained_bytes: usize,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnapshotCacheUsage {
    pub name_nodes: CacheUsage,
    pub state_points: CacheUsage,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StagingMemoryUsage {
    pub operations: usize,
    pub key_heap_bytes: usize,
    pub value_capacity_bytes: usize,
    pub operation_capacity_bytes: usize,
    pub charged_effect_bytes: u64,
}

#[derive(Default)]
struct PointReadCache {
    values: HashMap<ColumnFamily, HashMap<CompactKey, Option<SharedBytes>>>,
    usage: CacheUsage,
}
impl PointReadCache {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Option<&Option<SharedBytes>> {
        self.values.get(&family).and_then(|values| values.get(key))
    }
    fn insert(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        value: Option<SharedBytes>,
        max_entries: usize,
        max_bytes: usize,
    ) {
        if self.get(family, key).is_some() || self.usage.entries >= max_entries {
            return;
        }
        let family_bytes = if self.values.contains_key(&family) {
            0
        } else {
            CACHE_FAMILY_FRAMING_BYTES
        };
        let Some(bytes) = key
            .len()
            .checked_add(value.as_ref().map_or(0, SharedBytes::retained_capacity))
            .and_then(|bytes| bytes.checked_add(CACHE_ENTRY_FRAMING_BYTES))
            .and_then(|bytes| bytes.checked_add(family_bytes))
        else {
            return;
        };
        let Some(next_bytes) = self.usage.retained_bytes.checked_add(bytes) else {
            return;
        };
        if next_bytes > max_bytes {
            return;
        }
        self.values
            .entry(family)
            .or_default()
            .insert(CompactKey::new(key), value);
        self.usage.entries += 1;
        self.usage.retained_bytes = next_bytes;
    }
}

const fn caches_staged_state_point_read(family: ColumnFamily) -> bool {
    matches!(
        family,
        ColumnFamily::Meta
            | ColumnFamily::Headers
            | ColumnFamily::HeightIndex
            | ColumnFamily::BlockIndex
            | ColumnFamily::TxIndex
            | ColumnFamily::Utxo
            | ColumnFamily::NameState
            | ColumnFamily::Snapshots
    )
}

/// Read-your-writes overlay sharing immutable values with snapshots, journals
/// and backend batches. Each final key owns both its value and admission charge.
#[derive(Clone, Debug, Default)]
pub struct StagingOverlay {
    changes: SharedStagedChanges,
}
impl StagingOverlay {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn snapshot<'a, S: ReadSnapshot>(&self, base: &'a S) -> StagedSnapshot<'a, S> {
        StagedSnapshot {
            base,
            changes: Rc::clone(&self.changes),
            name_node_reads: RefCell::default(),
            state_point_reads: RefCell::default(),
        }
    }
    fn make_batch<B: WriteBatch>(
        &self,
        inner: B,
        defer_all_writes: bool,
        defer_name_tree_nodes: bool,
    ) -> StagedBatch<B> {
        StagedBatch {
            inner,
            changes: Rc::clone(&self.changes),
            defer_all_writes,
            defer_name_tree_nodes,
            checkpoint: None,
        }
    }
    pub fn batch<B: WriteBatch>(&self, inner: B) -> StagedBatch<B> {
        self.make_batch(inner, false, false)
    }
    /// Defer immutable name nodes for publication into append-only pages.
    pub fn batch_with_deferred_name_tree_nodes<B: WriteBatch>(&self, inner: B) -> StagedBatch<B> {
        self.make_batch(inner, false, true)
    }
    /// Retain final values only in the overlay until all staged reads finish.
    pub fn batch_with_deferred_writes<B: WriteBatch>(&self, inner: B) -> StagedBatch<B> {
        self.make_batch(inner, true, false)
    }
    pub fn batch_with_deferred_writes_and_name_tree_nodes<B: WriteBatch>(
        &self,
        inner: B,
    ) -> StagedBatch<B> {
        self.make_batch(inner, true, true)
    }
    pub fn staged_family(&self, family: ColumnFamily) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        self.changes
            .borrow()
            .get(&family)
            .map(|changes| {
                changes
                    .iter()
                    .map(|(key, operation)| {
                        (
                            key.to_vec(),
                            operation.value.as_ref().map(|value| value.to_vec()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Consume one family after staged reads finish. A uniquely owned shared
    /// buffer returns its original allocation rather than cloning its bytes.
    pub fn take_staged_family(&self, family: ColumnFamily) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        self.changes
            .borrow_mut()
            .remove(&family)
            .map(|changes| {
                changes
                    .into_iter()
                    .map(|(key, operation)| {
                        (key.to_vec(), operation.value.map(SharedBytes::into_vec))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Deterministic retained ownership counters for profiling. Hash-table
    /// capacity is an estimate from allocated bucket slots, excluding allocator
    /// bookkeeping; `charged_effect_bytes` is the caller's admission sum.
    pub fn memory_usage(&self) -> StagingMemoryUsage {
        let mut usage = StagingMemoryUsage::default();
        for changes in self.changes.borrow().values() {
            usage.operations = usage.operations.saturating_add(changes.len());
            let buckets = if changes.capacity() == 0 {
                0
            } else {
                changes.capacity().next_power_of_two()
            };
            usage.operation_capacity_bytes = usage.operation_capacity_bytes.saturating_add(
                buckets.saturating_mul(size_of::<(CompactKey, BatchOperation)>() + 1),
            );
            for (key, operation) in changes {
                usage.key_heap_bytes = usage.key_heap_bytes.saturating_add(key.heap_bytes());
                usage.value_capacity_bytes = usage.value_capacity_bytes.saturating_add(
                    operation
                        .value
                        .as_ref()
                        .map_or(0, SharedBytes::retained_capacity),
                );
                usage.charged_effect_bytes =
                    usage.charged_effect_bytes.saturating_add(operation.charge);
            }
        }
        usage
    }
}

pub struct StagedSnapshot<'a, S: ReadSnapshot> {
    base: &'a S,
    changes: SharedStagedChanges,
    name_node_reads: RefCell<PointReadCache>,
    state_point_reads: RefCell<PointReadCache>,
}
impl<S: ReadSnapshot> StagedSnapshot<'_, S> {
    pub fn cache_usage(&self) -> SnapshotCacheUsage {
        SnapshotCacheUsage {
            name_nodes: self.name_node_reads.borrow().usage,
            state_points: self.state_point_reads.borrow().usage,
        }
    }
    fn cache_value(&self, family: ColumnFamily, key: &[u8], value: Option<SharedBytes>) {
        if family == ColumnFamily::NameTreeNodes {
            if value.is_some() {
                self.name_node_reads.borrow_mut().insert(
                    family,
                    key,
                    value,
                    STAGED_NAME_NODE_READ_CACHE_LIMIT,
                    STAGED_NAME_NODE_READ_CACHE_BYTES,
                );
            }
        } else if caches_staged_state_point_read(family) {
            self.state_point_reads.borrow_mut().insert(
                family,
                key,
                value,
                STAGED_STATE_POINT_READ_CACHE_LIMIT,
                STAGED_STATE_POINT_READ_CACHE_BYTES,
            );
        }
    }
    fn resolved(&self, family: ColumnFamily, key: &[u8]) -> Option<Option<SharedBytes>> {
        if let Some(operation) = self
            .changes
            .borrow()
            .get(&family)
            .and_then(|changes| changes.get(key))
        {
            return Some(operation.value.clone());
        }
        if family == ColumnFamily::NameTreeNodes {
            return self.name_node_reads.borrow().get(family, key).cloned();
        }
        if caches_staged_state_point_read(family) {
            return self.state_point_reads.borrow().get(family, key).cloned();
        }
        None
    }
}
impl<S: ReadSnapshot> ReadSnapshot for StagedSnapshot<'_, S> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.get_shared(family, key)
            .map(|value| value.map(SharedBytes::into_vec))
    }
    fn get_shared(
        &self,
        family: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<SharedBytes>, StoreError> {
        if let Some(value) = self.resolved(family, key) {
            return Ok(value);
        }
        let value = self.base.get_shared(family, key)?;
        self.cache_value(family, key, value.clone());
        Ok(value)
    }
    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        self.get_many_shared(family, keys).map(|values| {
            values
                .into_iter()
                .map(|value| value.map(SharedBytes::into_vec))
                .collect()
        })
    }
    fn get_many_shared(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<SharedBytes>>, StoreError> {
        let resolved = keys
            .iter()
            .map(|key| self.resolved(family, key))
            .collect::<Vec<_>>();
        let missing_keys = keys
            .iter()
            .zip(&resolved)
            .filter_map(|(key, value)| value.is_none().then_some(*key))
            .collect::<Vec<_>>();
        let missing_values = if missing_keys.is_empty() {
            Vec::new()
        } else {
            self.base.get_many_shared(family, &missing_keys)?
        };
        if missing_values.len() != missing_keys.len() {
            return Err(StoreError::Backend(format!(
                "snapshot multi-get returned {} values for {} requested keys",
                missing_values.len(),
                missing_keys.len()
            )));
        }
        let mut missing_values = missing_keys.into_iter().zip(missing_values);
        let mut values = Vec::with_capacity(keys.len());
        for value in resolved {
            match value {
                Some(value) => values.push(value),
                None => {
                    let (key, value) = missing_values.next().ok_or_else(|| {
                        StoreError::Backend(
                            "snapshot multi-get returned fewer values than requested".to_owned(),
                        )
                    })?;
                    self.cache_value(family, key, value.clone());
                    values.push(value);
                }
            }
        }
        Ok(values)
    }
    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        let mut entries = self
            .base
            .scan_prefix(family, prefix)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        let changes = self.changes.borrow();
        if let Some(changes) = changes.get(&family) {
            for (key, operation) in changes {
                if !key.starts_with(prefix) {
                    continue;
                }
                match &operation.value {
                    Some(value) => {
                        entries.insert(key.to_vec(), value.to_vec());
                    }
                    None => {
                        entries.remove(key.as_slice());
                    }
                }
            }
        }

        Ok(entries.into_iter().collect())
    }

    fn scan_prefix_page(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        budget: PrefixScanBudget,
    ) -> Result<PrefixScanPage, StoreError> {
        let budget = validate_prefix_scan_request(prefix, start_after, budget)?;
        let changes = self.changes.borrow();
        let Some(changes) = changes.get(&family) else {
            return self
                .base
                .scan_prefix_page(family, prefix, start_after, budget);
        };

        // The overlay's point-write table is deliberately unordered. Prefix
        // scans are uncommon control-plane operations, so materialize only
        // matching references and sort those once for the ordered merge.
        let mut staged = changes
            .iter()
            .filter(|(key, _)| {
                key.starts_with(prefix) && start_after.is_none_or(|cursor| key.as_slice() > cursor)
            })
            .collect::<Vec<_>>();
        staged.sort_unstable_by_key(|(key, _)| *key);
        let mut staged = staged.into_iter().peekable();
        let mut base_entries = VecDeque::<ScanEntry>::new();
        let mut base_cursor = start_after.map(<[u8]>::to_vec);
        let mut base_complete = false;
        let base_budget = PrefixScanBudget {
            // One merge lookahead never needs to materialize more base keys
            // than the caller could return in this page. Keep the maximum byte
            // allowance so a staged delete can suppress an oversized base
            // value without producing a false page-budget rejection.
            max_entries: budget.max_entries,
            max_bytes: PREFIX_SCAN_MAX_BYTES,
        };
        let mut page = PrefixScanPage::default();

        loop {
            if base_entries.is_empty() && !base_complete {
                let raw = self.base.scan_prefix_page(
                    family,
                    prefix,
                    base_cursor.as_deref(),
                    base_budget,
                )?;
                if raw.entries.is_empty() && raw.continuation.is_some() {
                    return Err(StoreError::Backend(
                        "prefix page continuation did not advance".to_owned(),
                    ));
                }
                base_cursor = raw.continuation.clone();
                base_complete = raw.continuation.is_none();
                base_entries = raw.entries.into();
                if base_entries.is_empty() && !base_complete {
                    continue;
                }
            }

            let ordering = match (base_entries.front(), staged.peek()) {
                (Some((base_key, _)), Some((staged_key, _))) => {
                    Some(base_key.as_slice().cmp(staged_key.as_slice()))
                }
                (Some(_), None) => Some(std::cmp::Ordering::Less),
                (None, Some(_)) => Some(std::cmp::Ordering::Greater),
                (None, None) if base_complete => None,
                (None, None) => continue,
            };
            let Some(ordering) = ordering else {
                return Ok(page);
            };

            let candidate = match ordering {
                std::cmp::Ordering::Less => base_entries.pop_front(),
                std::cmp::Ordering::Equal => {
                    base_entries.pop_front();
                    staged.next().and_then(|(key, value)| {
                        value
                            .value
                            .as_ref()
                            .map(|value| (key.to_vec(), value.to_vec()))
                    })
                }
                std::cmp::Ordering::Greater => staged.next().and_then(|(key, value)| {
                    value
                        .value
                        .as_ref()
                        .map(|value| (key.to_vec(), value.to_vec()))
                }),
            };
            let Some((key, value)) = candidate else {
                continue;
            };
            if !push_bounded_scan_entry(&mut page, &key, &value, budget)? {
                return Ok(page);
            }
        }
    }

    fn prefetch_name_tree_paths(
        &self,
        root: [u8; 32],
        keys: &[[u8; 32]],
    ) -> Result<Option<Vec<NameTreePathRecord>>, StoreError> {
        if self
            .changes
            .borrow()
            .get(&ColumnFamily::NameTreeNodes)
            .is_some_and(|changes| !changes.is_empty())
        {
            return Ok(None);
        }
        self.base.prefetch_name_tree_paths(root, keys)
    }
}
pub struct StagedBatch<B: WriteBatch> {
    pub(crate) inner: B,
    changes: SharedStagedChanges,
    defer_name_tree_nodes: bool,
    defer_all_writes: bool,
    checkpoint: Option<StagedCheckpoint>,
}
impl<B: WriteBatch> StagedBatch<B> {
    fn forwards(&self, family: ColumnFamily) -> bool {
        !self.defer_all_writes
            && !(self.defer_name_tree_nodes && family == ColumnFamily::NameTreeNodes)
    }
    pub fn into_inner(self) -> B {
        assert!(
            !self.defer_all_writes,
            "fully deferred staged writes must be materialized before commit"
        );
        self.inner
    }
    /// Move each final immutable value and its charge into the backend, keeping
    /// at most one ownership allocation throughout deferred materialization.
    pub fn into_materialized_inner(mut self) -> Result<B, StoreError> {
        if !self.defer_all_writes {
            return Err(StoreError::Backend(
                "staged batch does not contain fully deferred writes".to_owned(),
            ));
        }
        if self.checkpoint.is_some() {
            return Err(StoreError::Backend(
                "cannot materialize a staged batch with an active checkpoint".to_owned(),
            ));
        }
        if Rc::strong_count(&self.changes) > 2 {
            return Err(StoreError::Backend(
                "cannot materialize deferred writes while staged readers or cloned overlays remain"
                    .to_owned(),
            ));
        }
        let changes = {
            let mut changes = self.changes.borrow_mut();
            if self.defer_name_tree_nodes
                && changes
                    .get(&ColumnFamily::NameTreeNodes)
                    .is_some_and(|nodes| !nodes.is_empty())
            {
                return Err(StoreError::Backend(
                    "cannot materialize deferred immutable name nodes into the backend batch"
                        .to_owned(),
                ));
            }
            std::mem::take(&mut *changes)
        };
        let operation_count = changes.values().map(HashMap::len).sum();
        self.inner.reserve_operations(operation_count);
        for (family, operations) in changes {
            for (key, operation) in operations {
                match operation.value {
                    Some(value) => {
                        self.inner
                            .put_shared_accounted(family, &key, value, operation.charge)?
                    }
                    None => self
                        .inner
                        .delete_with_charge(family, &key, operation.charge)?,
                }
            }
        }
        Ok(self.inner)
    }
    fn replace(&mut self, family: ColumnFamily, key: &[u8], mut operation: BatchOperation) {
        let mut changes = self.changes.borrow_mut();
        let changes = changes.entry(family).or_default();
        let Some(checkpoint) = &mut self.checkpoint else {
            changes.insert(CompactKey::new(key), operation);
            return;
        };
        let previous = changes.get(key);
        let recorded = previous.is_some_and(|previous| previous.checkpointed);
        let additional = checkpoint_entry_charge(key, previous);
        operation.checkpointed = true;
        let key = CompactKey::new(key);
        let previous = changes.insert(key.clone(), operation);
        if !recorded {
            checkpoint.journal.push((family, key, previous));
            checkpoint.retained_charge = checkpoint.retained_charge.saturating_add(additional);
        }
    }
}
impl<B: WriteBatch> WriteBatch for StagedBatch<B> {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.put_shared_accounted(family, key, SharedBytes::from(value), 0)
    }
    fn put_shared(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        value: SharedBytes,
    ) -> Result<(), StoreError> {
        self.put_shared_accounted(family, key, value, 0)
    }
    fn put_shared_accounted(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        value: SharedBytes,
        charge: u64,
    ) -> Result<(), StoreError> {
        if self.forwards(family) {
            self.inner
                .put_shared_accounted(family, key, value.clone(), charge)?;
        }
        self.replace(family, key, BatchOperation::new(Some(value), charge));
        Ok(())
    }
    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        self.delete_with_charge(family, key, 0)
    }
    fn delete_with_charge(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        charge: u64,
    ) -> Result<(), StoreError> {
        if self.forwards(family) {
            self.inner.delete_with_charge(family, key, charge)?;
        }
        self.replace(family, key, BatchOperation::new(None, charge));
        Ok(())
    }
}
impl<B: AccountedWriteBatch> AccountedWriteBatch for StagedBatch<B> {
    fn operation_charge(&self, family: ColumnFamily, key: &[u8]) -> u64 {
        self.changes
            .borrow()
            .get(&family)
            .and_then(|changes| changes.get(key))
            .map_or_else(
                || self.inner.operation_charge(family, key),
                |operation| operation.charge,
            )
    }
    fn checkpoint_retained_charge(&self) -> u64 {
        self.checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.retained_charge)
            .saturating_add(self.inner.checkpoint_retained_charge())
    }
    fn checkpoint_replacement_charge(&self, family: ColumnFamily, key: &[u8]) -> u64 {
        let own = if self.checkpoint.is_some() {
            checkpoint_entry_charge(
                key,
                self.changes
                    .borrow()
                    .get(&family)
                    .and_then(|changes| changes.get(key)),
            )
        } else {
            0
        };
        own.saturating_add(if self.forwards(family) {
            self.inner.checkpoint_replacement_charge(family, key)
        } else {
            0
        })
    }
}
impl<B: CheckpointWriteBatch> CheckpointWriteBatch for StagedBatch<B> {
    fn begin_checkpoint(&mut self) -> Result<(), StoreError> {
        if self.checkpoint.is_some() {
            return Err(StoreError::Backend(
                "staged batch checkpoint is already active".to_owned(),
            ));
        }
        self.inner.begin_checkpoint()?;
        self.checkpoint = Some(StagedCheckpoint::default());
        Ok(())
    }
    fn commit_checkpoint(&mut self) -> Result<(), StoreError> {
        if self.checkpoint.is_none() {
            return Err(StoreError::Backend(
                "staged batch checkpoint is not active".to_owned(),
            ));
        }
        self.inner.commit_checkpoint()?;
        let checkpoint = self
            .checkpoint
            .take()
            .expect("staged checkpoint presence checked above");
        let mut changes = self.changes.borrow_mut();
        for (family, key, _) in checkpoint.journal {
            if let Some(operation) = changes
                .get_mut(&family)
                .and_then(|changes| changes.get_mut(key.as_slice()))
            {
                operation.checkpointed = false;
            }
        }
        Ok(())
    }
    fn rollback_checkpoint(&mut self) -> Result<(), StoreError> {
        if self.checkpoint.is_none() {
            return Err(StoreError::Backend(
                "staged batch checkpoint is not active".to_owned(),
            ));
        }
        self.inner.rollback_checkpoint()?;
        let checkpoint = self
            .checkpoint
            .take()
            .expect("staged checkpoint presence checked above");
        let mut changes = self.changes.borrow_mut();
        for (family, key, previous) in checkpoint.journal.into_iter().rev() {
            let family_empty = {
                let family_changes = changes.entry(family).or_default();
                match previous {
                    Some(previous) => {
                        family_changes.insert(key, previous);
                    }
                    None => {
                        family_changes.remove(key.as_slice());
                    }
                }
                family_changes.is_empty()
            };
            if family_empty {
                changes.remove(&family);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryBatch, MemoryStore, RocksBatch, Store};

    fn exercise_backend_checkpoint_accounting<
        B: AccountedWriteBatch + CheckpointWriteBatch + Default,
    >() {
        let mut batch = B::default();
        batch
            .put_accounted(ColumnFamily::Utxo, b"key", b"original", 400)
            .unwrap();
        batch.begin_checkpoint().unwrap();
        let retained = batch.checkpoint_replacement_charge(ColumnFamily::Utxo, b"key");
        assert!(retained > 400);
        batch
            .put_accounted(ColumnFamily::Utxo, b"key", b"replacement", 450)
            .unwrap();
        assert_eq!(batch.checkpoint_retained_charge(), retained);
        assert_eq!(batch.operation_charge(ColumnFamily::Utxo, b"key"), 450);
        for _ in 0..16 {
            assert_eq!(
                batch.checkpoint_replacement_charge(ColumnFamily::Utxo, b"key"),
                0
            );
            batch
                .delete_accounted(ColumnFamily::Utxo, b"key", 300)
                .unwrap();
            batch
                .put_accounted(ColumnFamily::Utxo, b"key", b"latest", 500)
                .unwrap();
            assert_eq!(batch.checkpoint_retained_charge(), retained);
        }
        batch.rollback_checkpoint().unwrap();
        assert_eq!(batch.checkpoint_retained_charge(), 0);
        assert_eq!(batch.operation_charge(ColumnFamily::Utxo, b"key"), 400);
        batch.begin_checkpoint().unwrap();
        assert_eq!(
            batch.checkpoint_replacement_charge(ColumnFamily::Utxo, b"key"),
            retained
        );
        batch
            .put_accounted(ColumnFamily::Utxo, b"key", b"committed", 475)
            .unwrap();
        batch.commit_checkpoint().unwrap();
        assert_eq!(batch.operation_charge(ColumnFamily::Utxo, b"key"), 475);
        assert_eq!(batch.checkpoint_retained_charge(), 0);
        batch.begin_checkpoint().unwrap();
        assert!(batch.checkpoint_replacement_charge(ColumnFamily::Utxo, b"key") > 475);
        batch.rollback_checkpoint().unwrap();
    }

    #[test]
    fn backend_checkpoints_coalesce_original_versions_and_restore_accounting() {
        exercise_backend_checkpoint_accounting::<MemoryBatch>();
        exercise_backend_checkpoint_accounting::<RocksBatch>();
    }

    #[test]
    fn deferred_checkpoint_restores_original_values_charges_and_absence() {
        let store = MemoryStore::new();
        let base = store.snapshot().unwrap();
        let overlay = StagingOverlay::new();
        let snapshot = overlay.snapshot(&base);
        let mut batch = overlay.batch_with_deferred_writes(store.batch());
        batch
            .put_accounted(ColumnFamily::Utxo, b"original", b"before", 600)
            .unwrap();
        batch.begin_checkpoint().unwrap();
        let first_retained = batch.checkpoint_replacement_charge(ColumnFamily::Utxo, b"original");
        batch
            .put_accounted(ColumnFamily::Utxo, b"original", b"after", 700)
            .unwrap();
        let fresh_retained = batch.checkpoint_replacement_charge(ColumnFamily::Utxo, b"fresh");
        batch
            .put_accounted(ColumnFamily::Utxo, b"fresh", b"new", 500)
            .unwrap();
        for _ in 0..64 {
            batch
                .delete_accounted(ColumnFamily::Utxo, b"original", 350)
                .unwrap();
            batch
                .put_accounted(ColumnFamily::Utxo, b"original", b"again", 700)
                .unwrap();
            batch
                .delete_accounted(ColumnFamily::Utxo, b"fresh", 350)
                .unwrap();
            assert_eq!(
                batch.checkpoint_retained_charge(),
                first_retained + fresh_retained
            );
        }
        assert_eq!(batch.checkpoint.as_ref().unwrap().journal.len(), 2);
        batch.rollback_checkpoint().unwrap();
        assert_eq!(
            snapshot.get(ColumnFamily::Utxo, b"original").unwrap(),
            Some(b"before".to_vec())
        );
        assert_eq!(snapshot.get(ColumnFamily::Utxo, b"fresh").unwrap(), None);
        assert_eq!(batch.operation_charge(ColumnFamily::Utxo, b"original"), 600);
        assert_eq!(batch.operation_charge(ColumnFamily::Utxo, b"fresh"), 0);
        batch
            .delete_accounted(ColumnFamily::Utxo, b"deleted", 300)
            .unwrap();
        drop(snapshot);
        let inner = batch.into_materialized_inner().unwrap();
        assert_eq!(inner.operation_charge(ColumnFamily::Utxo, b"original"), 600);
        assert_eq!(inner.operation_charge(ColumnFamily::Utxo, b"deleted"), 300);
        assert_eq!(overlay.memory_usage().operations, 0);
        store.commit(inner).unwrap();
    }

    #[test]
    fn deferred_materialization_transfers_value_allocation_and_charge() {
        let store = MemoryStore::new();
        let overlay = StagingOverlay::new();
        let mut batch = overlay.batch_with_deferred_writes(store.batch());
        let bytes = vec![9; 65_536];
        let pointer = bytes.as_ptr();
        batch
            .put_shared_accounted(
                ColumnFamily::Utxo,
                &[1; 36],
                SharedBytes::from(bytes),
                131_400,
            )
            .unwrap();
        assert_eq!(overlay.memory_usage().key_heap_bytes, 0);
        let inner = batch.into_materialized_inner().unwrap();
        let operation = inner.operations.values().next().unwrap();
        assert_eq!(operation.value.as_ref().unwrap().as_ptr(), pointer);
        assert_eq!(operation.charge, 131_400);
        store.commit(inner).unwrap();
    }

    #[test]
    fn deferred_materialization_reserves_once_and_preserves_all_families() {
        #[derive(Default)]
        struct ReservedBatch {
            inner: MemoryBatch,
            reservations: Vec<usize>,
            reserved_capacity: usize,
        }
        impl WriteBatch for ReservedBatch {
            fn reserve_operations(&mut self, additional: usize) {
                self.reservations.push(additional);
                self.inner.reserve_operations(additional);
                self.reserved_capacity = self.inner.operations.capacity();
            }
            fn put(
                &mut self,
                family: ColumnFamily,
                key: &[u8],
                value: &[u8],
            ) -> Result<(), StoreError> {
                self.inner.put(family, key, value)
            }
            fn put_shared_accounted(
                &mut self,
                family: ColumnFamily,
                key: &[u8],
                value: SharedBytes,
                charge: u64,
            ) -> Result<(), StoreError> {
                self.inner
                    .put_shared_accounted(family, key, value, charge)?;
                assert_eq!(self.inner.operations.capacity(), self.reserved_capacity);
                Ok(())
            }
            fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
                self.inner.delete(family, key)
            }
            fn delete_with_charge(
                &mut self,
                family: ColumnFamily,
                key: &[u8],
                charge: u64,
            ) -> Result<(), StoreError> {
                self.inner.delete_with_charge(family, key, charge)?;
                assert_eq!(self.inner.operations.capacity(), self.reserved_capacity);
                Ok(())
            }
        }
        let overlay = StagingOverlay::new();
        let mut batch = overlay.batch_with_deferred_writes(ReservedBatch::default());
        let families = [
            ColumnFamily::Utxo,
            ColumnFamily::Headers,
            ColumnFamily::Meta,
        ];
        for family in families {
            for index in 0_u32..129 {
                let key = index.to_le_bytes();
                batch
                    .put_shared_accounted(
                        family,
                        &key,
                        SharedBytes::from(vec![1; 32]),
                        u64::from(index + 500),
                    )
                    .unwrap();
            }
        }
        // A tombstone replaces an admitted key and does not add a reservation.
        batch
            .delete_with_charge(ColumnFamily::Utxo, &0_u32.to_le_bytes(), 300)
            .unwrap();
        let materialized = batch.into_materialized_inner().unwrap();
        assert_eq!(materialized.reservations, vec![387]);
        assert_eq!(materialized.inner.len(), 387);
        assert_eq!(
            materialized
                .inner
                .operation_charge(ColumnFamily::Utxo, &0_u32.to_le_bytes()),
            300
        );
        assert_eq!(
            materialized
                .inner
                .operation_charge(ColumnFamily::Headers, &128_u32.to_le_bytes()),
            628
        );
    }

    #[test]
    fn cache_admission_enforces_bytes_entries_capacity_duplicates_and_missing_values() {
        let mut cache = PointReadCache::default();
        let mut bytes = Vec::with_capacity(1_024);
        bytes.extend_from_slice(b"small");
        let value = SharedBytes::from(bytes);
        let charge = 1 + 1_024 + CACHE_ENTRY_FRAMING_BYTES + CACHE_FAMILY_FRAMING_BYTES;
        cache.insert(ColumnFamily::Utxo, b"a", Some(value.clone()), 2, charge - 1);
        assert_eq!(cache.usage, CacheUsage::default());
        cache.insert(ColumnFamily::Utxo, b"a", Some(value), 2, charge);
        assert_eq!(
            cache.usage,
            CacheUsage {
                entries: 1,
                retained_bytes: charge
            }
        );
        cache.insert(ColumnFamily::Utxo, b"a", None, 2, usize::MAX);
        assert_eq!(cache.usage.entries, 1);
        assert!(cache.get(ColumnFamily::Utxo, b"a").unwrap().is_some());
        cache.insert(ColumnFamily::NameState, b"a", None, 2, usize::MAX);
        assert_eq!(cache.usage.entries, 2);
        cache.insert(ColumnFamily::NameState, b"b", None, 2, usize::MAX);
        assert!(cache.get(ColumnFamily::NameState, b"b").is_none());
        assert_eq!(
            cache.usage.retained_bytes,
            charge + 1 + CACHE_ENTRY_FRAMING_BYTES + CACHE_FAMILY_FRAMING_BYTES
        );
    }

    #[test]
    fn first_cache_family_reserves_tables_before_admitting_a_near_limit_value() {
        let mut cache = PointReadCache::default();
        let value = SharedBytes::from(vec![3; 1_024]);
        let entry_bytes = 4 + value.retained_capacity() + CACHE_ENTRY_FRAMING_BYTES;
        cache.insert(
            ColumnFamily::Utxo,
            b"coin",
            Some(value.clone()),
            10,
            entry_bytes,
        );
        assert!(
            cache.values.is_empty(),
            "rejection must not create family tables"
        );
        assert_eq!(cache.usage, CacheUsage::default());
        let exact = entry_bytes + CACHE_FAMILY_FRAMING_BYTES;
        cache.insert(ColumnFamily::Utxo, b"coin", Some(value.clone()), 10, exact);
        assert_eq!(cache.usage.retained_bytes, exact);
        let before = cache.usage;
        // A second family must reserve its own structural overhead even when
        // there is enough remaining space for that family's value alone.
        cache.insert(
            ColumnFamily::NameState,
            b"name",
            Some(value),
            10,
            exact + entry_bytes,
        );
        assert_eq!(cache.usage, before);
        assert!(!cache.values.contains_key(&ColumnFamily::NameState));
    }

    #[test]
    fn shared_cache_multi_get_admits_duplicates_once_and_overlay_takes_precedence() {
        let store = MemoryStore::new();
        let mut initial = store.batch();
        initial.put(ColumnFamily::Utxo, b"a", b"value").unwrap();
        store.commit(initial).unwrap();
        let base = store.snapshot().unwrap();
        let overlay = StagingOverlay::new();
        let snapshot = overlay.snapshot(&base);
        let values = snapshot
            .get_many_shared(ColumnFamily::Utxo, &[b"a", b"a", b"missing", b"missing"])
            .unwrap();
        assert_eq!(values[0].as_deref(), Some(b"value".as_slice()));
        assert_eq!(values[2], None);
        assert_eq!(snapshot.cache_usage().state_points.entries, 2);
        let cached = snapshot
            .get_shared(ColumnFamily::Utxo, b"a")
            .unwrap()
            .unwrap();
        let reread = snapshot
            .get_shared(ColumnFamily::Utxo, b"a")
            .unwrap()
            .unwrap();
        assert_eq!(cached.as_ptr(), reread.as_ptr());
        let mut batch = overlay.batch_with_deferred_writes(store.batch());
        batch.delete(ColumnFamily::Utxo, b"a").unwrap();
        batch.put(ColumnFamily::Utxo, b"missing", b"new").unwrap();
        assert_eq!(snapshot.get_shared(ColumnFamily::Utxo, b"a").unwrap(), None);
        assert_eq!(
            snapshot
                .get_shared(ColumnFamily::Utxo, b"missing")
                .unwrap()
                .as_deref(),
            Some(b"new".as_slice())
        );
    }
}
