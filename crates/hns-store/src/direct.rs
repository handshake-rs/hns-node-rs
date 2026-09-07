//! Durable page store for the block-oriented chainstate path.
//!
//! `DirectStore` deliberately exposes HSRD's existing typed atomic-store
//! boundary while the higher-level schema is reduced to block transition
//! inputs and outputs. Its physical primitive is a single copy-on-write B+tree
//! database: there are no LSM levels, SST files, background compactions, or
//! write-ahead-log tuning knobs in HSRD. Large block and undo payloads continue
//! to use the sequential segment archive rather than entering the page tree.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use redb::{Database, Durability, ReadTransaction, ReadableDatabase, TableDefinition};

use crate::{
    authenticated_namespace::{SharedNamespaceArchiveRegistration, SharedNamespaceOwners},
    begin_batch_checkpoint, commit_batch_checkpoint, push_bounded_scan_entry,
    replace_batch_operation, rollback_batch_checkpoint, validate_prefix_scan_request,
    BatchCheckpoint, BatchOperations, CheckpointWriteBatch, ColumnFamily, DurabilityPolicy,
    PrefixScanBudget, PrefixScanPage, PrefixVisitor, ReadSnapshot, ScanEntry, Store, StoreError,
    StoreKey, WriteBatch,
};

const DATABASE_FILE: &str = "chainstate.redb";
const CHAINSTATE: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("chainstate");

/// Stable one-byte keyspace tags. Keeping all short chainstate records in one
/// B+tree eliminates sixteen independent table roots and lets one block batch
/// flow straight from the last-write-wins staging map into one write cursor.
fn family_tag(family: ColumnFamily) -> u8 {
    match family {
        ColumnFamily::Meta => 0,
        ColumnFamily::Headers => 1,
        ColumnFamily::HeightIndex => 2,
        ColumnFamily::BlockIndex => 3,
        ColumnFamily::Blocks => 4,
        ColumnFamily::TxIndex => 5,
        ColumnFamily::Utxo => 6,
        ColumnFamily::NameState => 7,
        ColumnFamily::NameTreeNodes => 8,
        ColumnFamily::Undo => 9,
        ColumnFamily::Peers => 10,
        ColumnFamily::Orphans => 11,
        ColumnFamily::MempoolPersist => 12,
        ColumnFamily::Snapshots => 13,
        ColumnFamily::WalletHistory => 14,
        ColumnFamily::WalletState => 15,
    }
}

fn physical_key(family: ColumnFamily, key: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(key.len().saturating_add(1));
    encoded.push(family_tag(family));
    encoded.extend_from_slice(key);
    encoded
}

fn backend(error: impl fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

#[derive(Clone)]
pub struct DirectStore {
    pub(crate) database: Arc<Database>,
    pub(crate) path: PathBuf,
    pub(crate) durability: DurabilityPolicy,
    pub(crate) reopen_required: Arc<AtomicBool>,
    pub(crate) publication_lock: Arc<Mutex<()>>,
    pub(crate) authenticated_namespaces: SharedNamespaceOwners,
    pub(crate) authenticated_namespace_archive: SharedNamespaceArchiveRegistration,
}

impl fmt::Debug for DirectStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectStore")
            .field("path", &self.path)
            .field("durability", &self.durability)
            .field("reopen_required", &self.reopen_required())
            .finish_non_exhaustive()
    }
}

impl DirectStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_durability(path, DurabilityPolicy::Sync)
    }

    pub fn open_with_durability(
        path: impl AsRef<Path>,
        durability: DurabilityPolicy,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        fs::create_dir_all(&path).map_err(|error| {
            StoreError::Io(format!(
                "failed to create direct store directory {}: {error}",
                path.display()
            ))
        })?;
        let database_path = path.join(DATABASE_FILE);
        let database = Database::create(&database_path).map_err(backend)?;

        // Physical initialization is one atomic transaction. Logical column
        // families are disjoint first-byte keyspaces inside this one tree.
        let initialization = database.begin_write().map_err(backend)?;
        initialization.open_table(CHAINSTATE).map_err(backend)?;
        initialization.commit().map_err(backend)?;

        Ok(Self {
            database: Arc::new(database),
            path,
            durability,
            reopen_required: Arc::new(AtomicBool::new(false)),
            publication_lock: Arc::new(Mutex::new(())),
            authenticated_namespaces: Arc::new(Mutex::new(Default::default())),
            authenticated_namespace_archive: Arc::new(Mutex::new(None)),
        })
    }

    pub fn reopen_required(&self) -> bool {
        if self.publication_lock.is_poisoned() {
            self.mark_commit_outcome_uncertain();
        }
        self.reopen_required.load(Ordering::Acquire)
    }

    pub(crate) fn ensure_operational(&self) -> Result<(), StoreError> {
        if self.reopen_required() {
            Err(StoreError::Backend(
                "direct-store publication outcome is uncertain; reopen required".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn mark_commit_outcome_uncertain(&self) {
        self.reopen_required.store(true, Ordering::Release);
    }

    pub(crate) fn lock_publication(&self) -> Result<std::sync::MutexGuard<'_, ()>, StoreError> {
        match self.publication_lock.lock() {
            Ok(guard) => Ok(guard),
            Err(_) => {
                self.mark_commit_outcome_uncertain();
                Err(StoreError::Backend(
                    "direct-store publication lock is poisoned; reopen required".to_owned(),
                ))
            }
        }
    }

    pub(crate) fn commit_operations_locked(
        &self,
        operations: BatchOperations,
    ) -> Result<(), StoreError> {
        if operations.is_empty() {
            return Ok(());
        }
        let mut transaction = self.database.begin_write().map_err(backend)?;
        transaction
            .set_durability(match self.durability {
                DurabilityPolicy::Sync => Durability::Immediate,
                DurabilityPolicy::Wal => Durability::None,
            })
            .map_err(backend)?;
        let mut destination = transaction.open_table(CHAINSTATE).map_err(backend)?;
        for (key, value) in operations {
            let key = physical_key(key.family, &key.key);
            match value {
                Some(value) => {
                    destination
                        .insert(key.as_slice(), value.as_slice())
                        .map_err(backend)?;
                }
                None => {
                    destination.remove(key.as_slice()).map_err(backend)?;
                }
            }
        }
        drop(destination);
        if let Err(error) = transaction.commit() {
            self.mark_commit_outcome_uncertain();
            return Err(StoreError::Backend(format!(
                "direct-store atomic commit outcome is uncertain; reopen required: {error}"
            )));
        }
        Ok(())
    }

    pub(crate) fn snapshot_unlocked(&self) -> Result<DirectSnapshot, StoreError> {
        Ok(DirectSnapshot {
            transaction: self.database.begin_read().map_err(backend)?,
        })
    }
}

impl Store for DirectStore {
    type Snapshot<'a> = DirectSnapshot;
    type Batch = DirectBatch;

    fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
        let _publication = self.lock_publication()?;
        self.ensure_operational()?;
        self.snapshot_unlocked()
    }

    fn batch(&self) -> Self::Batch {
        DirectBatch::default()
    }

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
        self.ensure_operational()?;
        for key in batch.operations.keys() {
            crate::authenticated_namespace::ensure_ordinary_key(key.family, &key.key)?;
        }
        let _publication = self.lock_publication()?;
        self.ensure_operational()?;
        self.commit_operations_locked(batch.operations)
    }
}

pub struct DirectSnapshot {
    transaction: ReadTransaction,
}

impl DirectSnapshot {
    fn physical_prefix(family: ColumnFamily, prefix: &[u8]) -> Vec<u8> {
        physical_key(family, prefix)
    }
}

impl ReadSnapshot for DirectSnapshot {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let source = self.transaction.open_table(CHAINSTATE).map_err(backend)?;
        let key = physical_key(family, key);
        source
            .get(key.as_slice())
            .map_err(backend)
            .map(|value| value.map(|value| value.value().to_vec()))
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let source = self.transaction.open_table(CHAINSTATE).map_err(backend)?;
        keys.iter()
            .map(|key| {
                let key = physical_key(family, key);
                source
                    .get(key.as_slice())
                    .map_err(backend)
                    .map(|value| value.map(|value| value.value().to_vec()))
            })
            .collect()
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        let source = self.transaction.open_table(CHAINSTATE).map_err(backend)?;
        let prefix = Self::physical_prefix(family, prefix);
        let mut entries = Vec::new();
        for entry in source.range(prefix.as_slice()..).map_err(backend)? {
            let (key, value) = entry.map_err(backend)?;
            let key = key.value();
            if !key.starts_with(&prefix) {
                break;
            }
            entries.push((key[1..].to_vec(), value.value().to_vec()));
        }
        Ok(entries)
    }

    fn scan_prefix_page(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        budget: PrefixScanBudget,
    ) -> Result<PrefixScanPage, StoreError> {
        let budget = validate_prefix_scan_request(prefix, start_after, budget)?;
        let source = self.transaction.open_table(CHAINSTATE).map_err(backend)?;
        let physical_prefix = Self::physical_prefix(family, prefix);
        let start = Self::physical_prefix(family, start_after.unwrap_or(prefix));
        let mut page = PrefixScanPage::default();
        for entry in source.range(start.as_slice()..).map_err(backend)? {
            let (key, value) = entry.map_err(backend)?;
            let physical_key = key.value();
            if !physical_key.starts_with(&physical_prefix) {
                break;
            }
            let key = &physical_key[1..];
            if start_after.is_some_and(|cursor| key <= cursor) {
                continue;
            }
            if !push_bounded_scan_entry(&mut page, key, value.value(), budget)? {
                break;
            }
        }
        Ok(page)
    }

    fn visit_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        visitor: &mut PrefixVisitor<'_>,
    ) -> Result<(), StoreError> {
        let source = self.transaction.open_table(CHAINSTATE).map_err(backend)?;
        let physical_prefix = Self::physical_prefix(family, prefix);
        for entry in source
            .range(physical_prefix.as_slice()..)
            .map_err(backend)?
        {
            let (key, value) = entry.map_err(backend)?;
            let key = key.value();
            if !key.starts_with(&physical_prefix) {
                break;
            }
            visitor(&key[1..], value.value())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct DirectBatch {
    pub(crate) operations: BatchOperations,
    checkpoint: Option<BatchCheckpoint>,
}

impl DirectBatch {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }
}

impl WriteBatch for DirectBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        crate::authenticated_namespace::ensure_ordinary_key(family, key)?;
        replace_batch_operation(
            &mut self.operations,
            &mut self.checkpoint,
            StoreKey::new(family, key),
            Some(value.to_vec()),
        );
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        crate::authenticated_namespace::ensure_ordinary_key(family, key)?;
        replace_batch_operation(
            &mut self.operations,
            &mut self.checkpoint,
            StoreKey::new(family, key),
            None,
        );
        Ok(())
    }
}

impl CheckpointWriteBatch for DirectBatch {
    fn begin_checkpoint(&mut self) -> Result<(), StoreError> {
        begin_batch_checkpoint(&mut self.checkpoint)
    }

    fn commit_checkpoint(&mut self) -> Result<(), StoreError> {
        commit_batch_checkpoint(&mut self.checkpoint)
    }

    fn rollback_checkpoint(&mut self) -> Result<(), StoreError> {
        rollback_batch_checkpoint(&mut self.operations, &mut self.checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "hsrd-direct-store-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn atomic_batch_survives_reopen_and_snapshot_isolation() {
        let path = test_directory();
        let store = DirectStore::open(&path).expect("open");
        let before = store.snapshot().expect("before");
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Utxo, b"coin", b"value")
            .expect("put");
        batch
            .put(ColumnFamily::NameState, b"name", b"state")
            .expect("put name");
        batch
            .put(ColumnFamily::Headers, b"coin", b"header")
            .expect("put same logical key in another family");
        store.commit(batch).expect("commit");
        assert_eq!(before.get(ColumnFamily::Utxo, b"coin").expect("old"), None);
        drop(before);
        drop(store);

        let reopened = DirectStore::open(&path).expect("reopen");
        let snapshot = reopened.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.get(ColumnFamily::Utxo, b"coin").expect("coin"),
            Some(b"value".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::NameState, b"name")
                .expect("name"),
            Some(b"state".to_vec())
        );
        assert_eq!(
            snapshot
                .get_many(ColumnFamily::Headers, &[b"missing", b"coin"])
                .expect("ordered multi-get"),
            vec![None, Some(b"header".to_vec())]
        );
        assert_eq!(
            snapshot
                .scan_prefix(ColumnFamily::Utxo, b"co")
                .expect("UTXO prefix"),
            vec![(b"coin".to_vec(), b"value".to_vec())]
        );
        assert_eq!(
            snapshot
                .scan_prefix(ColumnFamily::Headers, b"co")
                .expect("header prefix"),
            vec![(b"coin".to_vec(), b"header".to_vec())]
        );
        drop(snapshot);
        drop(reopened);
        fs::remove_dir_all(path).expect("remove fixture");
    }
}
