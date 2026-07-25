#![forbid(unsafe_code)]

mod name_page;
mod segment;

pub use name_page::{
    decode_name_page, encode_name_page, encode_name_subpage_page, inspect_name_page_file,
    plan_name_page_reads, read_name_page_directory, read_name_page_record,
    truncate_name_pages_to_committed_tail, NamePageAddress, NamePageAppender, NamePageBuilder,
    NamePageDirectory, NamePageError, NamePageFileInspection, NamePagePush, NamePageRecord,
    NamePageRecordLocation, NamePageRecordRef, NamePageRef, NAME_PAGE_BYTES, NAME_SUBPAGE_BYTES,
};
#[cfg(unix)]
pub use name_page::{
    prefetch_name_page_records_at, read_name_page_directory_at, read_name_page_record_at,
    NamePagePrefetch, PositionedNamePageReader,
};
pub use segment::{
    decode_segment_record, decode_segment_record_ref, encode_segment_record, inspect_segment_file,
    plan_segment_page_reads, scan_segment_prefix, truncate_segment_to_committed_tail,
    SegmentAppender, SegmentArchive, SegmentArchiveScrub, SegmentChannelScrub, SegmentError,
    SegmentFileInspection, SegmentKind, SegmentLocator, SegmentManifest, SegmentPageRead,
    SegmentRecord, SegmentRecordRef, SegmentScan, SegmentValueLocator, SEGMENT_MAX_HINTS,
    SEGMENT_PAGE_BYTES, SEGMENT_TARGET_BYTES,
};

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap},
    fmt,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 19;
pub const LEGACY_SCHEMA_VERSION: u32 = 18;
pub const INTERVAL_SCHEMA_VERSION: u32 = 17;
pub const PRE_INTERVAL_SCHEMA_VERSION: u32 = 16;

/// Durable database layout/profile identifier. A profile change is an explicit
/// migration boundary even when the low-level column families remain readable.
pub const STORAGE_PROFILE: &[u8] = b"hsrd-mining-v15";
pub const LEGACY_STORAGE_PROFILE: &[u8] = b"hsrd-mining-v14";
pub const INTERVAL_STORAGE_PROFILE: &[u8] = b"hsrd-mining-v13";
pub const PRE_INTERVAL_STORAGE_PROFILE: &[u8] = b"hsrd-mining-v12";
pub const BLOCK_SEGMENT_MANIFEST_KEY: &[u8] = b"block-segment-manifest/v1";
pub const UNDO_SEGMENT_MANIFEST_KEY: &[u8] = b"undo-segment-manifest/v1";
pub const SEGMENT_MIGRATION_MAX_BATCH_RECORDS: usize = 32;
pub const SEGMENT_MIGRATION_MAX_BATCH_BYTES: u64 = 64 * 1024 * 1024;

/// HSD's MSB-first spent-allocation field contains 216,199 airdrop positions
/// followed by 1,358 faucet positions.
pub const AIRDROP_FIELD_BITS: usize = 217_557;
pub const AIRDROP_FIELD_BYTES: usize = AIRDROP_FIELD_BITS.div_ceil(8);

#[cfg(feature = "rocksdb-backend")]
const ROCKS_POINT_CACHE_BYTES: usize = 192 * 1024 * 1024;
#[cfg(feature = "rocksdb-backend")]
const ROCKS_BULK_CACHE_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "rocksdb-backend")]
const ROCKS_BLOOM_BITS_PER_KEY: f64 = 10.0;
#[cfg(feature = "rocksdb-backend")]
const ROCKS_BACKGROUND_JOBS: i32 = 4;
/// Bound aggregate WAL retention across all column families. Without an
/// explicit limit RocksDB derives the allowance from every column family's
/// write buffers; a mainnet replay retained more than 4 GiB of WAL files.
#[cfg(feature = "rocksdb-backend")]
pub const ROCKS_MAX_TOTAL_WAL_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(feature = "rocksdb-backend")]
const ROCKS_BULK_BLOCK_BYTES: usize = 32 * 1024;

pub type ScanEntry = (Vec<u8>, Vec<u8>);
pub type PrefixVisitor<'a> = dyn FnMut(&[u8], &[u8]) -> Result<(), StoreError> + 'a;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum StoreBackend {
    RocksDb,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DurabilityPolicy {
    /// Keep the RocksDB WAL enabled and fsync the write before returning.
    #[default]
    Sync,
    /// Keep the WAL enabled but allow the operating system to schedule fsync.
    Wal,
}

impl DurabilityPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Wal => "wal",
        }
    }
}

impl fmt::Display for DurabilityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DurabilityPolicy {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sync" => Ok(Self::Sync),
            "wal" => Ok(Self::Wal),
            other => Err(StoreError::Schema(format!(
                "unknown durability policy `{other}`; expected `sync` or `wal`"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoreConfig {
    pub path: PathBuf,
    pub backend: StoreBackend,
    pub durability: DurabilityPolicy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ColumnFamily {
    Meta,
    Headers,
    HeightIndex,
    BlockIndex,
    Blocks,
    TxIndex,
    Utxo,
    NameState,
    NameTreeNodes,
    Undo,
    Peers,
    Orphans,
    MempoolPersist,
    Snapshots,
}

impl ColumnFamily {
    pub const ALL: [Self; 14] = [
        Self::Meta,
        Self::Headers,
        Self::HeightIndex,
        Self::BlockIndex,
        Self::Blocks,
        Self::TxIndex,
        Self::Utxo,
        Self::NameState,
        Self::NameTreeNodes,
        Self::Undo,
        Self::Peers,
        Self::Orphans,
        Self::MempoolPersist,
        Self::Snapshots,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Headers => "headers",
            Self::HeightIndex => "height_index",
            Self::BlockIndex => "block_index",
            Self::Blocks => "blocks",
            Self::TxIndex => "tx_index",
            Self::Utxo => "utxo",
            Self::NameState => "name_state",
            Self::NameTreeNodes => "name_tree_nodes",
            Self::Undo => "undo",
            Self::Peers => "peers",
            Self::Orphans => "orphans",
            Self::MempoolPersist => "mempool_persist",
            Self::Snapshots => "snapshots",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameTreePathRecord {
    pub root: [u8; 32],
    pub canonical: Vec<u8>,
}

pub trait ReadSnapshot {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        keys.iter().map(|key| self.get(family, key)).collect()
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError>;

    /// Storage-native union of authenticated paths for a set of name keys.
    /// Page-backed snapshots override this to visit each physical page once;
    /// ordinary stores return `None` and use generic content-hash MultiGet.
    fn prefetch_name_tree_paths(
        &self,
        _root: [u8; 32],
        _keys: &[[u8; 32]],
    ) -> Result<Option<Vec<NameTreePathRecord>>, StoreError> {
        Ok(None)
    }

    /// Visit a lexicographically ordered prefix range without requiring the
    /// caller to materialize the entire range. Backends should override this
    /// when they can stream from a stable snapshot; the default preserves the
    /// behavior of lightweight test snapshots.
    fn visit_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        visitor: &mut PrefixVisitor<'_>,
    ) -> Result<(), StoreError> {
        for (key, value) in self.scan_prefix(family, prefix)? {
            visitor(&key, &value)?;
        }
        Ok(())
    }
}

pub trait WriteBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError>;

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError>;
}

pub trait Store {
    type Snapshot<'a>: ReadSnapshot
    where
        Self: 'a;
    type Batch: WriteBatch;

    fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError>;

    fn batch(&self) -> Self::Batch;

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError>;
}

/// Read-your-writes overlay for staging one atomic multi-step mutation against
/// a single immutable base snapshot. The wrapped batch is committed only after
/// every staged operation has validated successfully.
type StagedChanges = HashMap<ColumnFamily, HashMap<Vec<u8>, Option<Vec<u8>>>>;
type SharedStagedChanges = Rc<RefCell<StagedChanges>>;
type NameNodeReadCache = HashMap<Vec<u8>, Vec<u8>>;
type StatePointReadCache = HashMap<ColumnFamily, HashMap<Vec<u8>, Option<Vec<u8>>>>;
/// Bound one active-state transaction's positive cache for content-addressed
/// name-tree nodes. The cache belongs to a single immutable base snapshot;
/// staged replacements and deletions are always resolved before it.
const STAGED_NAME_NODE_READ_CACHE_LIMIT: usize = 131_072;
/// Bound point values read from one immutable active-state base snapshot.
/// Missing values are cached too. Overlay writes always take precedence, so
/// caching cannot mask a later mutation in the same atomic transaction.
const STAGED_STATE_POINT_READ_CACHE_LIMIT: usize = 65_536;

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
            state_point_read_count: Cell::new(0),
        }
    }

    pub fn batch<B: WriteBatch>(&self, inner: B) -> StagedBatch<B> {
        StagedBatch {
            inner,
            changes: Rc::clone(&self.changes),
            defer_name_tree_nodes: false,
        }
    }

    /// Stage content-addressed name nodes for read-your-writes visibility
    /// without forwarding them to the underlying LSM batch. The caller must
    /// publish the captured records to its append-only page store before
    /// committing [`StagedBatch::into_inner`].
    pub fn batch_with_deferred_name_tree_nodes<B: WriteBatch>(&self, inner: B) -> StagedBatch<B> {
        StagedBatch {
            inner,
            changes: Rc::clone(&self.changes),
            defer_name_tree_nodes: true,
        }
    }

    pub fn staged_family(&self, family: ColumnFamily) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        self.changes
            .borrow()
            .get(&family)
            .map(|changes| {
                changes
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub struct StagedSnapshot<'a, S: ReadSnapshot> {
    base: &'a S,
    changes: SharedStagedChanges,
    name_node_reads: RefCell<NameNodeReadCache>,
    state_point_reads: RefCell<StatePointReadCache>,
    state_point_read_count: Cell<usize>,
}

impl<S: ReadSnapshot> ReadSnapshot for StagedSnapshot<'_, S> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let staged = self
            .changes
            .borrow()
            .get(&family)
            .and_then(|changes| changes.get(key))
            .cloned();
        if let Some(value) = staged {
            return Ok(value);
        }
        if family == ColumnFamily::NameTreeNodes {
            if let Some(value) = self.name_node_reads.borrow().get(key) {
                return Ok(Some(value.clone()));
            }
        } else if caches_staged_state_point_read(family) {
            if let Some(value) = self
                .state_point_reads
                .borrow()
                .get(&family)
                .and_then(|reads| reads.get(key))
            {
                return Ok(value.clone());
            }
        }
        let value = self.base.get(family, key)?;
        if family == ColumnFamily::NameTreeNodes {
            if let Some(value) = &value {
                let mut cache = self.name_node_reads.borrow_mut();
                if cache.len() < STAGED_NAME_NODE_READ_CACHE_LIMIT {
                    cache.insert(key.to_vec(), value.clone());
                }
            }
        } else if caches_staged_state_point_read(family)
            && self.state_point_read_count.get() < STAGED_STATE_POINT_READ_CACHE_LIMIT
        {
            let inserted = self
                .state_point_reads
                .borrow_mut()
                .entry(family)
                .or_default()
                .insert(key.to_vec(), value.clone())
                .is_none();
            if inserted {
                self.state_point_read_count
                    .set(self.state_point_read_count.get().saturating_add(1));
            }
        }
        Ok(value)
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let resolved = {
            let changes = self.changes.borrow();
            let name_node_reads = self.name_node_reads.borrow();
            let state_point_reads = self.state_point_reads.borrow();
            keys.iter()
                .map(|key| {
                    let staged = changes
                        .get(&family)
                        .and_then(|changes| changes.get(*key))
                        .cloned();
                    if staged.is_some() {
                        return staged;
                    }
                    if family == ColumnFamily::NameTreeNodes {
                        return name_node_reads.get(*key).cloned().map(Some);
                    }
                    if caches_staged_state_point_read(family) {
                        return state_point_reads
                            .get(&family)
                            .and_then(|reads| reads.get(*key))
                            .cloned();
                    }
                    None
                })
                .collect::<Vec<_>>()
        };
        let missing_keys = keys
            .iter()
            .zip(&resolved)
            .filter_map(|(key, value)| value.is_none().then_some(*key))
            .collect::<Vec<_>>();
        let missing_values = if missing_keys.is_empty() {
            Vec::new()
        } else {
            self.base.get_many(family, &missing_keys)?
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
                    if family == ColumnFamily::NameTreeNodes {
                        if let Some(value) = &value {
                            let mut cache = self.name_node_reads.borrow_mut();
                            if cache.len() < STAGED_NAME_NODE_READ_CACHE_LIMIT {
                                cache.insert(key.to_vec(), value.clone());
                            }
                        }
                    } else if caches_staged_state_point_read(family)
                        && self.state_point_read_count.get() < STAGED_STATE_POINT_READ_CACHE_LIMIT
                    {
                        let inserted = self
                            .state_point_reads
                            .borrow_mut()
                            .entry(family)
                            .or_default()
                            .insert(key.to_vec(), value.clone())
                            .is_none();
                        if inserted {
                            self.state_point_read_count
                                .set(self.state_point_read_count.get().saturating_add(1));
                        }
                    }
                    values.push(value);
                }
            }
        }
        if missing_values.next().is_some() {
            return Err(StoreError::Backend(
                "snapshot multi-get returned more values than requested".to_owned(),
            ));
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
            for (key, value) in changes {
                if !key.starts_with(prefix) {
                    continue;
                }
                match value {
                    Some(value) => {
                        entries.insert(key.clone(), value.clone());
                    }
                    None => {
                        entries.remove(key);
                    }
                }
            }
        }

        Ok(entries.into_iter().collect())
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
    inner: B,
    changes: SharedStagedChanges,
    defer_name_tree_nodes: bool,
}

impl<B: WriteBatch> StagedBatch<B> {
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: WriteBatch> WriteBatch for StagedBatch<B> {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        if !(self.defer_name_tree_nodes && family == ColumnFamily::NameTreeNodes) {
            self.inner.put(family, key, value)?;
        }
        self.changes
            .borrow_mut()
            .entry(family)
            .or_default()
            .insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        if !(self.defer_name_tree_nodes && family == ColumnFamily::NameTreeNodes) {
            self.inner.delete(family, key)?;
        }
        self.changes
            .borrow_mut()
            .entry(family)
            .or_default()
            .insert(key.to_vec(), None);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MetaKey {
    SchemaVersion,
    Network,
    GenesisHash,
    BestHeaderHash,
    BestBlockHash,
    MiningGeneration,
    StorageProfile,
    NameTreeRoot,
    NameTreeCommitRoot,
    AirdropField,
    SyncCheckpoint,
    ChainEpoch,
    CleanShutdown,
}

impl MetaKey {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::SchemaVersion => b"schema-version",
            Self::Network => b"network",
            Self::GenesisHash => b"genesis-hash",
            Self::BestHeaderHash => b"best-header-hash",
            Self::BestBlockHash => b"best-block-hash",
            Self::MiningGeneration => b"mining-generation",
            Self::StorageProfile => b"storage-profile",
            Self::NameTreeRoot => b"name-tree-root",
            Self::NameTreeCommitRoot => b"name-tree-commit-root",
            Self::AirdropField => b"airdrop-field",
            Self::SyncCheckpoint => b"sync-checkpoint",
            Self::ChainEpoch => b"chain-epoch",
            Self::CleanShutdown => b"clean-shutdown",
        }
    }
}

pub fn encode_height(height: u32) -> [u8; 4] {
    height.to_be_bytes()
}

pub fn encode_u32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

pub fn decode_u32(bytes: &[u8]) -> Result<u32, StoreError> {
    let array: [u8; 4] = bytes.try_into().map_err(|_| {
        StoreError::Schema(format!("expected 4 bytes for u32, got {}", bytes.len()))
    })?;
    Ok(u32::from_le_bytes(array))
}

pub fn encode_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

pub fn decode_u64(bytes: &[u8]) -> Result<u64, StoreError> {
    let array: [u8; 8] = bytes.try_into().map_err(|_| {
        StoreError::Schema(format!("expected 8 bytes for u64, got {}", bytes.len()))
    })?;
    Ok(u64::from_le_bytes(array))
}

pub fn initialize_schema<S: Store>(store: &S) -> Result<(), StoreError> {
    let snapshot = store.snapshot()?;
    let schema = snapshot.get(ColumnFamily::Meta, MetaKey::SchemaVersion.as_bytes())?;
    let profile = snapshot.get(ColumnFamily::Meta, MetaKey::StorageProfile.as_bytes())?;
    let name_tree_root = snapshot.get(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())?;
    let name_tree_commit_root =
        snapshot.get(ColumnFamily::Meta, MetaKey::NameTreeCommitRoot.as_bytes())?;
    let airdrop_field = snapshot.get(ColumnFamily::Meta, MetaKey::AirdropField.as_bytes())?;

    match schema {
        Some(bytes) => {
            let version = decode_u32(&bytes)?;
            if version != SCHEMA_VERSION {
                return Err(StoreError::Schema(format!(
                    "expected schema version {SCHEMA_VERSION}, got {version}; a clean reindex is required"
                )));
            }
            let profile = profile.ok_or_else(|| {
                StoreError::Schema(
                    "schema marker exists without a storage-profile marker; refusing ambiguous database"
                        .to_owned(),
                )
            })?;
            if profile.as_slice() != STORAGE_PROFILE {
                return Err(StoreError::Schema(format!(
                    "expected storage profile `{}`, got `{}`; a clean reindex is required",
                    String::from_utf8_lossy(STORAGE_PROFILE),
                    String::from_utf8_lossy(&profile),
                )));
            }
            let name_tree_root = name_tree_root.ok_or_else(|| {
                StoreError::Schema(
                    "schema marker exists without a durable name-tree-root binding; a clean reindex is required"
                        .to_owned(),
                )
            })?;
            if name_tree_root.len() != 32 {
                return Err(StoreError::Schema(format!(
                    "durable name-tree-root binding must contain 32 bytes, got {}; a clean reindex is required",
                    name_tree_root.len()
                )));
            }
            let name_tree_commit_root = name_tree_commit_root.ok_or_else(|| {
                StoreError::Schema(
                    "schema marker exists without a durable name-tree-commit-root binding; a clean reindex is required"
                        .to_owned(),
                )
            })?;
            if name_tree_commit_root.len() != 32 {
                return Err(StoreError::Schema(format!(
                    "durable name-tree-commit-root binding must contain 32 bytes, got {}; a clean reindex is required",
                    name_tree_commit_root.len()
                )));
            }
            let airdrop_field = airdrop_field.ok_or_else(|| {
                StoreError::Schema(
                    "schema marker exists without a durable airdrop-field binding; a clean reindex is required"
                        .to_owned(),
                )
            })?;
            if airdrop_field.len() != AIRDROP_FIELD_BYTES {
                return Err(StoreError::Schema(format!(
                    "durable airdrop-field binding must contain {AIRDROP_FIELD_BYTES} bytes, got {}; a clean reindex is required",
                    airdrop_field.len()
                )));
            }
            Ok(())
        }
        None => {
            if profile.is_some()
                || name_tree_root.is_some()
                || name_tree_commit_root.is_some()
                || airdrop_field.is_some()
                || !snapshot_is_empty(&snapshot)?
            {
                return Err(StoreError::Schema(
                    "database contains data but has no schema marker; refusing to stamp a potentially incompatible store"
                        .to_owned(),
                ));
            }

            let mut batch = store.batch();
            batch.put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )?;
            batch.put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )?;
            batch.put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                &[0; 32],
            )?;
            batch.put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                &[0; 32],
            )?;
            batch.put(
                ColumnFamily::Meta,
                MetaKey::AirdropField.as_bytes(),
                &[0; AIRDROP_FIELD_BYTES],
            )?;
            store.commit(batch)
        }
    }
}

fn snapshot_is_empty<S: ReadSnapshot>(snapshot: &S) -> Result<bool, StoreError> {
    for family in ColumnFamily::ALL {
        if !snapshot.scan_prefix(family, b"")?.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Return whether the previous process completed its explicit clean-shutdown
/// transition. Missing state is treated as unclean so recovery checks run on
/// first use and after abrupt termination.
pub fn was_clean_shutdown<S: Store>(store: &S) -> Result<bool, StoreError> {
    initialize_schema(store)?;
    let snapshot = store.snapshot()?;
    match snapshot.get(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes())? {
        Some(bytes) if bytes.as_slice() == [1] => Ok(true),
        Some(bytes) if bytes.as_slice() == [0] => Ok(false),
        Some(bytes) => Err(StoreError::Schema(format!(
            "invalid clean-shutdown marker length/value: {bytes:?}"
        ))),
        None => Ok(false),
    }
}

/// Mark the database as owned by a running process. This must be committed
/// before network or mining services are started.
pub fn mark_unclean_start<S: Store>(store: &S) -> Result<(), StoreError> {
    initialize_schema(store)?;
    let mut batch = store.batch();
    batch.put(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes(), &[0])?;
    store.commit(batch)
}

/// Mark the database clean only after all state and service shutdown work has
/// completed successfully.
pub fn mark_clean_shutdown<S: Store>(store: &S) -> Result<(), StoreError> {
    initialize_schema(store)?;
    let mut batch = store.batch();
    batch.put(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes(), &[1])?;
    store.commit(batch)
}

pub fn open_store(config: &StoreConfig) -> Result<StoreHandle, StoreError> {
    match config.backend {
        StoreBackend::RocksDb => {
            #[cfg(feature = "rocksdb-backend")]
            {
                RocksStore::open_with_durability(&config.path, config.durability)
                    .map(StoreHandle::Rocks)
            }

            #[cfg(not(feature = "rocksdb-backend"))]
            {
                let _ = &config.path;
                Err(StoreError::FeatureDisabled("rocksdb-backend"))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum StoreHandle {
    Memory(MemoryStore),
    #[cfg(feature = "rocksdb-backend")]
    Rocks(RocksStore),
    Archived {
        inner: Box<StoreHandle>,
        archive: Arc<SegmentArchive>,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SegmentFamilyInventory {
    pub inline_records: u64,
    pub inline_bytes: u64,
    pub archived_records: u64,
    pub archived_frame_bytes: u64,
    pub locator_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SegmentArchiveInventory {
    pub blocks: SegmentFamilyInventory,
    pub undo: SegmentFamilyInventory,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SegmentArchiveCompactionReport {
    pub previous_block_generation: u64,
    pub previous_undo_generation: u64,
    pub generation: u64,
    pub live_records: u64,
    pub live_payload_bytes: u64,
    pub before_frame_bytes: u64,
    pub after_frame_bytes: u64,
    pub reclaimed_frame_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SegmentMigrationReport {
    pub migrated_records: u64,
    pub migrated_bytes: u64,
    pub commits: u64,
}

impl StoreHandle {
    pub fn memory() -> Self {
        Self::Memory(MemoryStore::new())
    }

    pub const fn durability_policy(&self) -> DurabilityPolicy {
        match self {
            Self::Memory(_) => DurabilityPolicy::Sync,
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => store.durability,
            Self::Archived { inner, .. } => inner.durability_policy(),
        }
    }

    pub fn with_segment_archive(self, directory: PathBuf) -> Result<Self, StoreError> {
        if matches!(self, Self::Archived { .. }) {
            return Err(StoreError::Schema(
                "segment archive is already attached".to_owned(),
            ));
        }
        let snapshot = self.snapshot()?;
        let block = snapshot.get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)?;
        let undo = snapshot.get(ColumnFamily::Snapshots, UNDO_SEGMENT_MANIFEST_KEY)?;
        drop(snapshot);
        let archive = match (block, undo) {
            (None, None) => {
                let archive =
                    SegmentArchive::create_new(directory, 1).map_err(segment_store_error)?;
                let (block, undo) = archive.manifests().map_err(segment_store_error)?;
                let mut batch = self.batch();
                batch.put(
                    ColumnFamily::Snapshots,
                    BLOCK_SEGMENT_MANIFEST_KEY,
                    &block.encode(),
                )?;
                batch.put(
                    ColumnFamily::Snapshots,
                    UNDO_SEGMENT_MANIFEST_KEY,
                    &undo.encode(),
                )?;
                self.commit(batch)?;
                archive
            }
            (Some(block), Some(undo)) => SegmentArchive::recover(
                directory,
                SegmentManifest::decode(&block).map_err(segment_store_error)?,
                SegmentManifest::decode(&undo).map_err(segment_store_error)?,
            )
            .map_err(segment_store_error)?,
            _ => {
                return Err(StoreError::Schema(
                    "block/undo segment manifests are only partially initialized".to_owned(),
                ))
            }
        };
        Ok(Self::Archived {
            inner: Box::new(self),
            archive: Arc::new(archive),
        })
    }

    pub fn segment_archive_inventory(&self) -> Result<SegmentArchiveInventory, StoreError> {
        let Self::Archived { inner, .. } = self else {
            return Err(StoreError::Schema(
                "segment archive inventory requires an archived store".to_owned(),
            ));
        };
        Ok(SegmentArchiveInventory {
            blocks: segment_family_inventory(inner, ColumnFamily::Blocks)?,
            undo: segment_family_inventory(inner, ColumnFamily::Undo)?,
        })
    }

    pub fn scrub_segment_archive(&self) -> Result<SegmentArchiveScrub, StoreError> {
        let Self::Archived { archive, .. } = self else {
            return Err(StoreError::Schema(
                "segment archive scrub requires an archived store".to_owned(),
            ));
        };
        archive.scrub().map_err(segment_store_error)
    }

    pub fn segment_archive_frame_bytes(&self) -> Result<(u64, u64), StoreError> {
        let Self::Archived { archive, .. } = self else {
            return Err(StoreError::Schema(
                "segment archive footprint requires an archived store".to_owned(),
            ));
        };
        archive.committed_frame_bytes().map_err(segment_store_error)
    }

    /// Rewrite only live block/undo locators into a fresh segment generation
    /// and atomically publish every replacement locator with both manifests.
    /// The caller must hold exclusive database ownership. Crash recovery uses
    /// the committed manifests to discard either an unpublished new
    /// generation or the superseded old generation.
    pub fn compact_segment_archive(&self) -> Result<SegmentArchiveCompactionReport, StoreError> {
        let Self::Archived { inner, archive } = self else {
            return Err(StoreError::Schema(
                "segment compaction requires an archived store".to_owned(),
            ));
        };
        let (before_block_bytes, before_undo_bytes) = archive
            .committed_frame_bytes()
            .map_err(segment_store_error)?;
        let (previous_block, previous_undo) = archive.manifests().map_err(segment_store_error)?;
        let snapshot = inner.snapshot()?;
        let block_entries = snapshot.scan_prefix(ColumnFamily::Blocks, b"")?;
        let undo_entries = snapshot.scan_prefix(ColumnFamily::Undo, b"")?;
        drop(snapshot);

        let mut rewrite = archive.begin_rewrite().map_err(segment_store_error)?;
        let prepared = (|| {
            let mut batch = inner.batch();
            let mut live_records = 0u64;
            let mut live_payload_bytes = 0u64;
            for (family, kind, entries) in [
                (ColumnFamily::Blocks, SegmentKind::Block, block_entries),
                (ColumnFamily::Undo, SegmentKind::Undo, undo_entries),
            ] {
                for (key, raw) in entries {
                    let Some(locator) =
                        SegmentValueLocator::decode(&raw).map_err(segment_store_error)?
                    else {
                        continue;
                    };
                    if locator.kind != kind {
                        return Err(StoreError::Schema(format!(
                            "{} locator has kind {:?}; expected {kind:?}",
                            family.name(),
                            locator.kind
                        )));
                    }
                    let key_array: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                        StoreError::Schema(format!(
                            "{} archive key contains {} bytes; expected 32",
                            family.name(),
                            key.len()
                        ))
                    })?;
                    let payload = archive
                        .resolve(kind, &key, &raw)
                        .map_err(segment_store_error)?
                        .ok_or_else(|| {
                            StoreError::Schema(format!(
                                "{} locator did not resolve to an archived payload",
                                family.name()
                            ))
                        })?;
                    live_records = live_records.checked_add(1).ok_or_else(|| {
                        StoreError::Schema("segment compaction record count overflow".to_owned())
                    })?;
                    live_payload_bytes = live_payload_bytes
                        .checked_add(u64::try_from(payload.len()).map_err(|_| {
                            StoreError::Schema(
                                "segment compaction payload length overflow".to_owned(),
                            )
                        })?)
                        .ok_or_else(|| {
                            StoreError::Schema(
                                "segment compaction payload byte count overflow".to_owned(),
                            )
                        })?;
                    let replacement = archive
                        .append_rewrite(&mut rewrite, kind, key_array, payload)
                        .map_err(segment_store_error)?;
                    batch.put(family, &key, &replacement.encode())?;
                }
            }
            let (block_manifest, undo_manifest, after) = archive
                .finish_rewrite(&mut rewrite)
                .map_err(segment_store_error)?;
            batch.put(
                ColumnFamily::Snapshots,
                BLOCK_SEGMENT_MANIFEST_KEY,
                &block_manifest.encode(),
            )?;
            batch.put(
                ColumnFamily::Snapshots,
                UNDO_SEGMENT_MANIFEST_KEY,
                &undo_manifest.encode(),
            )?;
            Ok::<_, StoreError>((
                batch,
                block_manifest,
                undo_manifest,
                after,
                live_records,
                live_payload_bytes,
            ))
        })();
        let (batch, block_manifest, undo_manifest, after, live_records, live_payload_bytes) =
            match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    archive
                        .abort_rewrite(rewrite)
                        .map_err(segment_store_error)?;
                    return Err(error);
                }
            };
        if let Err(error) = inner.commit(batch) {
            archive
                .abort_rewrite(rewrite)
                .map_err(segment_store_error)?;
            return Err(error);
        }
        // After the atomic database commit the new generation is
        // authoritative. Never delete it on an installation/cleanup error;
        // reopening will select it from the manifests and remove predecessors.
        archive
            .install_rewrite(rewrite)
            .map_err(segment_store_error)?;

        let before_frame_bytes = before_block_bytes
            .checked_add(before_undo_bytes)
            .ok_or_else(|| {
                StoreError::Schema("pre-compaction frame byte count overflow".to_owned())
            })?;
        let after_frame_bytes = after
            .blocks
            .durable_bytes
            .checked_add(after.undo.durable_bytes)
            .ok_or_else(|| {
                StoreError::Schema("post-compaction frame byte count overflow".to_owned())
            })?;
        debug_assert_eq!(block_manifest.generation, undo_manifest.generation);
        Ok(SegmentArchiveCompactionReport {
            previous_block_generation: previous_block.generation,
            previous_undo_generation: previous_undo.generation,
            generation: block_manifest.generation,
            live_records,
            live_payload_bytes,
            before_frame_bytes,
            after_frame_bytes,
            reclaimed_frame_bytes: before_frame_bytes.saturating_sub(after_frame_bytes),
        })
    }

    /// Rewrite legacy inline block and undo values through the archive wrapper
    /// in bounded, idempotent transactions. The caller must hold exclusive
    /// ownership of the database (the maintenance CLI enforces this with the
    /// RocksDB lock and a clean-shutdown marker).
    pub fn migrate_inline_segment_payloads(
        &self,
        batch_records: usize,
    ) -> Result<SegmentMigrationReport, StoreError> {
        if !(1..=SEGMENT_MIGRATION_MAX_BATCH_RECORDS).contains(&batch_records) {
            return Err(StoreError::Schema(
                format!(
                    "segment migration batch size must be between 1 and {SEGMENT_MIGRATION_MAX_BATCH_RECORDS}"
                ),
            ));
        }
        let Self::Archived { inner, .. } = self else {
            return Err(StoreError::Schema(
                "segment migration requires an archived store".to_owned(),
            ));
        };
        let mut report = SegmentMigrationReport::default();
        for family in [ColumnFamily::Blocks, ColumnFamily::Undo] {
            for prefix in 0u8..=u8::MAX {
                let keys = inline_segment_keys(inner, family, &[prefix])?;
                for keys in keys.chunks(batch_records) {
                    let snapshot = inner.snapshot()?;
                    let key_refs = keys.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    let values = snapshot.get_many(family, &key_refs)?;
                    drop(snapshot);
                    if values.len() != keys.len() {
                        return Err(StoreError::Backend(format!(
                            "{} multi-get returned {} values for {} keys",
                            family.name(),
                            values.len(),
                            keys.len()
                        )));
                    }
                    let mut batch = self.batch();
                    let mut staged_records = 0u64;
                    let mut staged_bytes = 0u64;
                    for (key, value) in keys.iter().zip(values) {
                        let value = value.ok_or_else(|| {
                            StoreError::Schema(format!(
                                "{} value disappeared during offline segment migration",
                                family.name()
                            ))
                        })?;
                        if SegmentValueLocator::decode(&value)
                            .map_err(segment_store_error)?
                            .is_some()
                        {
                            continue;
                        }
                        let value_bytes = value.len() as u64;
                        if value_bytes > SEGMENT_MIGRATION_MAX_BATCH_BYTES {
                            return Err(StoreError::Schema(format!(
                                "{} inline value contains {value_bytes} bytes; migration bound is {SEGMENT_MIGRATION_MAX_BATCH_BYTES}",
                                family.name()
                            )));
                        }
                        if staged_records != 0
                            && staged_bytes
                                .checked_add(value_bytes)
                                .is_none_or(|bytes| bytes > SEGMENT_MIGRATION_MAX_BATCH_BYTES)
                        {
                            commit_segment_migration_batch(
                                self,
                                batch,
                                staged_records,
                                staged_bytes,
                                &mut report,
                            )?;
                            batch = self.batch();
                            staged_records = 0;
                            staged_bytes = 0;
                        }
                        batch.put(family, key, &value)?;
                        staged_records = staged_records.checked_add(1).ok_or_else(|| {
                            StoreError::Schema(
                                "segment migration staged record count overflow".to_owned(),
                            )
                        })?;
                        staged_bytes = staged_bytes.checked_add(value_bytes).ok_or_else(|| {
                            StoreError::Schema(
                                "segment migration staged byte count overflow".to_owned(),
                            )
                        })?;
                    }
                    commit_segment_migration_batch(
                        self,
                        batch,
                        staged_records,
                        staged_bytes,
                        &mut report,
                    )?;
                }
            }
        }
        Ok(report)
    }

    pub fn create_rocks_checkpoint(&self, directory: &Path) -> Result<(), StoreError> {
        #[cfg(feature = "rocksdb-backend")]
        {
            match self {
                Self::Rocks(store) => store.create_checkpoint(directory),
                Self::Archived { inner, .. } => inner.create_rocks_checkpoint(directory),
                Self::Memory(_) => Err(StoreError::Backend(
                    "RocksDB checkpoint requested for memory store".to_owned(),
                )),
            }
        }
        #[cfg(not(feature = "rocksdb-backend"))]
        {
            let _ = directory;
            Err(StoreError::Backend(
                "RocksDB checkpoint support is not compiled in".to_owned(),
            ))
        }
    }
}

fn commit_segment_migration_batch(
    store: &StoreHandle,
    batch: StoreHandleBatch,
    records: u64,
    bytes: u64,
    report: &mut SegmentMigrationReport,
) -> Result<(), StoreError> {
    if records == 0 {
        return Ok(());
    }
    store.commit(batch)?;
    report.migrated_records = report
        .migrated_records
        .checked_add(records)
        .ok_or_else(|| StoreError::Schema("segment migration record count overflow".to_owned()))?;
    report.migrated_bytes = report
        .migrated_bytes
        .checked_add(bytes)
        .ok_or_else(|| StoreError::Schema("segment migration byte count overflow".to_owned()))?;
    report.commits = report
        .commits
        .checked_add(1)
        .ok_or_else(|| StoreError::Schema("segment migration commit overflow".to_owned()))?;
    Ok(())
}

fn segment_family_inventory(
    store: &StoreHandle,
    family: ColumnFamily,
) -> Result<SegmentFamilyInventory, StoreError> {
    let snapshot = store.snapshot()?;
    let mut inventory = SegmentFamilyInventory::default();
    snapshot.visit_prefix(family, b"", &mut |key, value| {
        validate_segment_key(family, key)?;
        match SegmentValueLocator::decode(value).map_err(segment_store_error)? {
            Some(locator) => {
                let expected = segmented_kind(family).expect("archive family");
                if locator.kind != expected {
                    return Err(StoreError::Schema(format!(
                        "{} locator has {:?} kind",
                        family.name(),
                        locator.kind
                    )));
                }
                inventory.archived_records =
                    inventory.archived_records.checked_add(1).ok_or_else(|| {
                        StoreError::Schema("segment inventory record count overflow".to_owned())
                    })?;
                inventory.archived_frame_bytes = inventory
                    .archived_frame_bytes
                    .checked_add(u64::from(locator.locator.frame_length))
                    .ok_or_else(|| {
                        StoreError::Schema("segment inventory frame bytes overflow".to_owned())
                    })?;
                inventory.locator_bytes = inventory
                    .locator_bytes
                    .checked_add(value.len() as u64)
                    .ok_or_else(|| {
                    StoreError::Schema("segment inventory locator bytes overflow".to_owned())
                })?;
            }
            None => {
                inventory.inline_records =
                    inventory.inline_records.checked_add(1).ok_or_else(|| {
                        StoreError::Schema("segment inventory record count overflow".to_owned())
                    })?;
                inventory.inline_bytes = inventory
                    .inline_bytes
                    .checked_add(value.len() as u64)
                    .ok_or_else(|| {
                        StoreError::Schema("segment inventory inline bytes overflow".to_owned())
                    })?;
            }
        }
        Ok(())
    })?;
    Ok(inventory)
}

fn inline_segment_keys(
    store: &StoreHandle,
    family: ColumnFamily,
    prefix: &[u8],
) -> Result<Vec<Vec<u8>>, StoreError> {
    let snapshot = store.snapshot()?;
    let mut keys = Vec::new();
    snapshot.visit_prefix(family, prefix, &mut |key, value| {
        validate_segment_key(family, key)?;
        if SegmentValueLocator::decode(value)
            .map_err(segment_store_error)?
            .is_none()
        {
            keys.push(key.to_vec());
        }
        Ok(())
    })?;
    Ok(keys)
}

fn validate_segment_key(family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
    if key.len() != 32 {
        return Err(StoreError::Schema(format!(
            "{} segment key contains {} bytes; expected 32",
            family.name(),
            key.len()
        )));
    }
    Ok(())
}

impl Default for StoreHandle {
    fn default() -> Self {
        Self::memory()
    }
}

impl Store for StoreHandle {
    type Snapshot<'a> = StoreHandleSnapshot<'a>;
    type Batch = StoreHandleBatch;

    fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
        match self {
            Self::Memory(store) => store
                .snapshot()
                .map(|snapshot| StoreHandleSnapshot::Memory(snapshot, PhantomData)),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => store.snapshot().map(StoreHandleSnapshot::Rocks),
            Self::Archived { inner, archive } => inner.snapshot().map(|snapshot| {
                StoreHandleSnapshot::Archived(Box::new(snapshot), Arc::clone(archive))
            }),
        }
    }

    fn batch(&self) -> Self::Batch {
        match self {
            Self::Memory(store) => StoreHandleBatch::Memory(store.batch()),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => StoreHandleBatch::Rocks(store.batch()),
            Self::Archived { inner, .. } => inner.batch(),
        }
    }

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => commit_memory_store_handle(store, batch),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => commit_rocks_store_handle(store, batch),
            Self::Archived { inner, archive } => {
                commit_archived_store_handle(inner, archive, batch)
            }
        }
    }
}

fn commit_memory_store_handle(
    store: &MemoryStore,
    batch: StoreHandleBatch,
) -> Result<(), StoreError> {
    #[cfg(feature = "rocksdb-backend")]
    {
        match batch {
            StoreHandleBatch::Memory(batch) => store.commit(batch),
            StoreHandleBatch::Rocks(_) => Err(StoreError::BackendMismatch),
        }
    }

    #[cfg(not(feature = "rocksdb-backend"))]
    {
        let StoreHandleBatch::Memory(batch) = batch;
        store.commit(batch)
    }
}

fn segment_store_error(error: SegmentError) -> StoreError {
    StoreError::Backend(format!("segment archive failed: {error}"))
}

fn segmented_kind(family: ColumnFamily) -> Option<SegmentKind> {
    match family {
        ColumnFamily::Blocks => Some(SegmentKind::Block),
        ColumnFamily::Undo => Some(SegmentKind::Undo),
        _ => None,
    }
}

fn resolve_segmented_value(
    archive: &SegmentArchive,
    family: ColumnFamily,
    key: &[u8],
    raw: Vec<u8>,
) -> Result<Vec<u8>, StoreError> {
    let Some(kind) = segmented_kind(family) else {
        return Ok(raw);
    };
    archive
        .resolve(kind, key, &raw)
        .map_err(segment_store_error)
        .map(|resolved| resolved.unwrap_or(raw))
}

fn commit_archived_store_handle(
    inner: &StoreHandle,
    archive: &SegmentArchive,
    mut batch: StoreHandleBatch,
) -> Result<(), StoreError> {
    let mut payloads = batch.take_archive_payloads()?;
    if payloads.is_empty() {
        return inner.commit(batch);
    }
    let mut writer = archive.writer().map_err(segment_store_error)?;
    let prepared = match archive.prepare_locked(&mut writer, &mut payloads) {
        Ok(prepared) => prepared,
        Err(error) => {
            archive
                .rollback_locked(&mut writer)
                .map_err(segment_store_error)?;
            return Err(segment_store_error(error));
        }
    };
    if let Err(error) = batch.replace_archive_payloads(&prepared.locators) {
        archive
            .rollback_locked(&mut writer)
            .map_err(segment_store_error)?;
        return Err(error);
    }
    let stage_manifests = (|| {
        batch.put(
            ColumnFamily::Snapshots,
            BLOCK_SEGMENT_MANIFEST_KEY,
            &prepared.block_manifest.encode(),
        )?;
        batch.put(
            ColumnFamily::Snapshots,
            UNDO_SEGMENT_MANIFEST_KEY,
            &prepared.undo_manifest.encode(),
        )
    })();
    if let Err(error) = stage_manifests {
        archive
            .rollback_locked(&mut writer)
            .map_err(segment_store_error)?;
        return Err(error);
    }
    if let Err(error) = inner.commit(batch) {
        archive
            .rollback_locked(&mut writer)
            .map_err(segment_store_error)?;
        return Err(error);
    }
    writer.commit_prepared(&prepared);
    Ok(())
}

#[cfg(feature = "rocksdb-backend")]
fn commit_rocks_store_handle(
    store: &RocksStore,
    batch: StoreHandleBatch,
) -> Result<(), StoreError> {
    match batch {
        StoreHandleBatch::Rocks(batch) => store.commit(batch),
        StoreHandleBatch::Memory(_) => Err(StoreError::BackendMismatch),
    }
}

pub enum StoreHandleSnapshot<'a> {
    Memory(MemorySnapshot, PhantomData<&'a ()>),
    #[cfg(feature = "rocksdb-backend")]
    Rocks(RocksSnapshot<'a>),
    Archived(Box<StoreHandleSnapshot<'a>>, Arc<SegmentArchive>),
}

impl ReadSnapshot for StoreHandleSnapshot<'_> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        match self {
            Self::Memory(snapshot, _) => snapshot.get(family, key),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(snapshot) => snapshot.get(family, key),
            Self::Archived(snapshot, archive) => {
                let Some(raw) = snapshot.get(family, key)? else {
                    return Ok(None);
                };
                resolve_segmented_value(archive, family, key, raw).map(Some)
            }
        }
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        match self {
            Self::Memory(snapshot, _) => snapshot.get_many(family, keys),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(snapshot) => snapshot.get_many(family, keys),
            Self::Archived(snapshot, archive) => {
                let values = snapshot.get_many(family, keys)?;
                if segmented_kind(family).is_none() {
                    return Ok(values);
                }
                keys.iter()
                    .zip(values)
                    .map(|(key, value)| {
                        value
                            .map(|raw| resolve_segmented_value(archive, family, key, raw))
                            .transpose()
                    })
                    .collect()
            }
        }
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        match self {
            Self::Memory(snapshot, _) => snapshot.scan_prefix(family, prefix),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(snapshot) => snapshot.scan_prefix(family, prefix),
            Self::Archived(snapshot, archive) => {
                let entries = snapshot.scan_prefix(family, prefix)?;
                if segmented_kind(family).is_none() {
                    return Ok(entries);
                }
                entries
                    .into_iter()
                    .map(|(key, raw)| {
                        resolve_segmented_value(archive, family, &key, raw)
                            .map(|value| (key, value))
                    })
                    .collect()
            }
        }
    }

    fn visit_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        visitor: &mut PrefixVisitor<'_>,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(snapshot, _) => snapshot.visit_prefix(family, prefix, visitor),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(snapshot) => snapshot.visit_prefix(family, prefix, visitor),
            Self::Archived(snapshot, _) if segmented_kind(family).is_none() => {
                snapshot.visit_prefix(family, prefix, visitor)
            }
            Self::Archived(_, _) => {
                for (key, value) in self.scan_prefix(family, prefix)? {
                    visitor(&key, &value)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum StoreHandleBatch {
    Memory(MemoryBatch),
    #[cfg(feature = "rocksdb-backend")]
    Rocks(RocksBatch),
}

impl StoreHandleBatch {
    fn take_archive_payloads(&mut self) -> Result<Vec<segment::ArchivePayload>, StoreError> {
        let mut payloads = Vec::new();
        match self {
            Self::Memory(batch) => {
                for operation in &mut batch.operations {
                    let MemoryOperation::Put { key, value } = operation else {
                        continue;
                    };
                    collect_archive_payload(key.family, &key.key, value, &mut payloads)?;
                }
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => {
                for operation in &mut batch.operations {
                    let RocksOperation::Put { family, key, value } = operation else {
                        continue;
                    };
                    collect_archive_payload(*family, key, value, &mut payloads)?;
                }
            }
        }
        Ok(payloads)
    }

    fn replace_archive_payloads(
        &mut self,
        locators: &[SegmentValueLocator],
    ) -> Result<(), StoreError> {
        let mut locators = locators.iter();
        match self {
            Self::Memory(batch) => {
                for operation in &mut batch.operations {
                    let MemoryOperation::Put { key, value } = operation else {
                        continue;
                    };
                    replace_archive_payload(key.family, value, &mut locators)?;
                }
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => {
                for operation in &mut batch.operations {
                    let RocksOperation::Put { family, value, .. } = operation else {
                        continue;
                    };
                    replace_archive_payload(*family, value, &mut locators)?;
                }
            }
        }
        if locators.next().is_some() {
            return Err(StoreError::Backend(
                "segment archive produced excess value locators".to_owned(),
            ));
        }
        Ok(())
    }
}

fn collect_archive_payload(
    family: ColumnFamily,
    key: &[u8],
    value: &mut Vec<u8>,
    payloads: &mut Vec<segment::ArchivePayload>,
) -> Result<(), StoreError> {
    let Some(kind) = segmented_kind(family) else {
        return Ok(());
    };
    if SegmentValueLocator::decode(value)
        .map_err(segment_store_error)?
        .is_some()
    {
        return Ok(());
    }
    let key: [u8; 32] = key.try_into().map_err(|_| {
        StoreError::Schema(format!(
            "{} segment key contains {} bytes; expected 32",
            family.name(),
            key.len()
        ))
    })?;
    payloads.push(segment::ArchivePayload {
        kind,
        key,
        payload: std::mem::take(value),
    });
    Ok(())
}

fn replace_archive_payload<'a>(
    family: ColumnFamily,
    value: &mut Vec<u8>,
    locators: &mut impl Iterator<Item = &'a SegmentValueLocator>,
) -> Result<(), StoreError> {
    if segmented_kind(family).is_none()
        || SegmentValueLocator::decode(value)
            .map_err(segment_store_error)?
            .is_some()
    {
        return Ok(());
    }
    let locator = locators.next().ok_or_else(|| {
        StoreError::Backend("segment archive produced too few value locators".to_owned())
    })?;
    *value = locator.encode();
    Ok(())
}

impl WriteBatch for StoreHandleBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        match self {
            Self::Memory(batch) => batch.put(family, key, value),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => batch.put(family, key, value),
        }
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        match self {
            Self::Memory(batch) => batch.delete(family, key),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => batch.delete(family, key),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    inner: Arc<RwLock<HashMap<StoreKey, Vec<u8>>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    type Snapshot<'a> = MemorySnapshot;
    type Batch = MemoryBatch;

    fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
        let data = self
            .inner
            .read()
            .map_err(|_| StoreError::Io("memory store read lock poisoned".to_owned()))?
            .clone();

        Ok(MemorySnapshot { data })
    }

    fn batch(&self) -> Self::Batch {
        MemoryBatch::default()
    }

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
        let mut data = self
            .inner
            .write()
            .map_err(|_| StoreError::Io("memory store write lock poisoned".to_owned()))?;

        for operation in batch.operations {
            match operation {
                MemoryOperation::Put { key, value } => {
                    data.insert(key, value);
                }
                MemoryOperation::Delete { key } => {
                    data.remove(&key);
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemorySnapshot {
    data: HashMap<StoreKey, Vec<u8>>,
}

impl ReadSnapshot for MemorySnapshot {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.data.get(&StoreKey::new(family, key)).cloned())
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        let mut entries = self
            .data
            .iter()
            .filter(|(key, _)| key.family == family && key.key.starts_with(prefix))
            .map(|(key, value)| (key.key.clone(), value.clone()))
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryBatch {
    operations: Vec<MemoryOperation>,
}

impl MemoryBatch {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }
}

impl WriteBatch for MemoryBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.operations.push(MemoryOperation::Put {
            key: StoreKey::new(family, key),
            value: value.to_vec(),
        });
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        self.operations.push(MemoryOperation::Delete {
            key: StoreKey::new(family, key),
        });
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StoreKey {
    family: ColumnFamily,
    key: Vec<u8>,
}

impl StoreKey {
    fn new(family: ColumnFamily, key: &[u8]) -> Self {
        Self {
            family,
            key: key.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum MemoryOperation {
    Put { key: StoreKey, value: Vec<u8> },
    Delete { key: StoreKey },
}

#[cfg(feature = "rocksdb-backend")]
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<rocksdb::DB>,
    durability: DurabilityPolicy,
    // Keep both shared caches alive for exactly as long as the DB. Separating
    // large, mostly one-pass block/undo pages prevents them from evicting hot
    // UTXO, name-state, and Urkel point-lookup pages.
    point_cache: rocksdb::Cache,
    bulk_cache: rocksdb::Cache,
}

#[cfg(feature = "rocksdb-backend")]
impl fmt::Debug for RocksStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RocksStore")
            .field("durability", &self.durability)
            .field("point_cache_usage", &self.point_cache.get_usage())
            .field("bulk_cache_usage", &self.bulk_cache.get_usage())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "rocksdb-backend")]
impl RocksStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        Self::open_with_durability(path, DurabilityPolicy::Sync)
    }

    pub fn open_with_durability(
        path: impl AsRef<std::path::Path>,
        durability: DurabilityPolicy,
    ) -> Result<Self, StoreError> {
        use rocksdb::{Cache, ColumnFamilyDescriptor, Options};

        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        db_options.set_max_background_jobs(ROCKS_BACKGROUND_JOBS);
        db_options.set_max_total_wal_size(ROCKS_MAX_TOTAL_WAL_BYTES);

        let point_cache = Cache::new_lru_cache(ROCKS_POINT_CACHE_BYTES);
        let bulk_cache = Cache::new_lru_cache(ROCKS_BULK_CACHE_BYTES);

        let descriptors = ColumnFamily::ALL.into_iter().map(|family| {
            let cache = if matches!(family, ColumnFamily::Blocks | ColumnFamily::Undo) {
                &bulk_cache
            } else {
                &point_cache
            };
            ColumnFamilyDescriptor::new(family.name(), rocks_column_family_options(family, cache))
        });

        let db = rocksdb::DB::open_cf_descriptors(&db_options, path, descriptors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            durability,
            point_cache,
            bulk_cache,
        })
    }

    pub fn create_checkpoint(&self, path: impl AsRef<Path>) -> Result<(), StoreError> {
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        checkpoint
            .create_checkpoint(path)
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    fn cf(db: &rocksdb::DB, family: ColumnFamily) -> Result<&rocksdb::ColumnFamily, StoreError> {
        db.cf_handle(family.name())
            .ok_or_else(|| StoreError::MissingColumnFamily(family.name()))
    }
}

#[cfg(feature = "rocksdb-backend")]
fn rocks_column_family_options(family: ColumnFamily, cache: &rocksdb::Cache) -> rocksdb::Options {
    use rocksdb::{BlockBasedOptions, Options};

    let mut table = BlockBasedOptions::default();
    table.set_block_cache(cache);
    table.set_bloom_filter(ROCKS_BLOOM_BITS_PER_KEY, false);
    table.set_optimize_filters_for_memory(true);
    table.set_cache_index_and_filter_blocks(true);
    table.set_pin_l0_filter_and_index_blocks_in_cache(true);
    if matches!(family, ColumnFamily::Blocks | ColumnFamily::Undo) {
        table.set_block_size(ROCKS_BULK_BLOCK_BYTES);
    }

    let mut options = Options::default();
    options.set_block_based_table_factory(&table);
    options
}

#[cfg(feature = "rocksdb-backend")]
impl Store for RocksStore {
    type Snapshot<'a> = RocksSnapshot<'a>;
    type Batch = RocksBatch;

    fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
        let db = self.db.as_ref();
        Ok(RocksSnapshot {
            db,
            snapshot: db.snapshot(),
        })
    }

    fn batch(&self) -> Self::Batch {
        RocksBatch::default()
    }

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
        let mut write_batch = rocksdb::WriteBatch::default();

        for operation in batch.operations {
            match operation {
                RocksOperation::Put { family, key, value } => {
                    let cf = Self::cf(&self.db, family)?;
                    write_batch.put_cf(cf, key, value);
                }
                RocksOperation::Delete { family, key } => {
                    let cf = Self::cf(&self.db, family)?;
                    write_batch.delete_cf(cf, key);
                }
            }
        }

        let mut options = rocksdb::WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(matches!(self.durability, DurabilityPolicy::Sync));

        self.db
            .write_opt(write_batch, &options)
            .map_err(|error| StoreError::Backend(error.to_string()))
    }
}

#[cfg(feature = "rocksdb-backend")]
pub struct RocksSnapshot<'a> {
    db: &'a rocksdb::DB,
    snapshot: rocksdb::Snapshot<'a>,
}

#[cfg(feature = "rocksdb-backend")]
impl ReadSnapshot for RocksSnapshot<'_> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let cf = RocksStore::cf(self.db, family)?;
        self.snapshot
            .get_cf(cf, key)
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let cf = RocksStore::cf(self.db, family)?;
        self.snapshot
            .multi_get_cf(keys.iter().map(|key| (cf, *key)))
            .into_iter()
            .map(|value| value.map_err(|error| StoreError::Backend(error.to_string())))
            .collect()
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        use rocksdb::{Direction, IteratorMode};

        let cf = RocksStore::cf(self.db, family)?;
        let mut entries = Vec::new();

        for item in self
            .snapshot
            .iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward))
        {
            let (key, value) = item.map_err(|error| StoreError::Backend(error.to_string()))?;

            if !key.starts_with(prefix) {
                break;
            }

            entries.push((key.to_vec(), value.to_vec()));
        }

        Ok(entries)
    }

    fn visit_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        visitor: &mut PrefixVisitor<'_>,
    ) -> Result<(), StoreError> {
        use rocksdb::{Direction, IteratorMode};

        let cf = RocksStore::cf(self.db, family)?;
        for item in self
            .snapshot
            .iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward))
        {
            let (key, value) = item.map_err(|error| StoreError::Backend(error.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            visitor(&key, &value)?;
        }
        Ok(())
    }
}

#[cfg(feature = "rocksdb-backend")]
#[derive(Clone, Debug, Default)]
pub struct RocksBatch {
    operations: Vec<RocksOperation>,
}

#[cfg(feature = "rocksdb-backend")]
impl WriteBatch for RocksBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.operations.push(RocksOperation::Put {
            family,
            key: key.to_vec(),
            value: value.to_vec(),
        });
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        self.operations.push(RocksOperation::Delete {
            family,
            key: key.to_vec(),
        });
        Ok(())
    }
}

#[cfg(feature = "rocksdb-backend")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum RocksOperation {
    Put {
        family: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        family: ColumnFamily,
        key: Vec<u8>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store feature `{0}` is disabled")]
    FeatureDisabled(&'static str),
    #[error("store backend mismatch")]
    BackendMismatch,
    #[error("store backend failed: {0}")]
    Backend(String),
    #[error("missing column family `{0}`")]
    MissingColumnFamily(&'static str),
    #[error("store I/O failed: {0}")]
    Io(String),
    #[error("schema mismatch: {0}")]
    Schema(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct CountingSnapshot {
        inner: MemorySnapshot,
        gets: Cell<usize>,
        multi_gets: Cell<usize>,
    }

    impl CountingSnapshot {
        fn new(inner: MemorySnapshot) -> Self {
            Self {
                inner,
                gets: Cell::new(0),
                multi_gets: Cell::new(0),
            }
        }
    }

    impl ReadSnapshot for CountingSnapshot {
        fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
            self.gets.set(self.gets.get() + 1);
            self.inner.get(family, key)
        }

        fn get_many(
            &self,
            family: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
            self.multi_gets.set(self.multi_gets.get() + 1);
            self.inner.get_many(family, keys)
        }

        fn scan_prefix(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
        ) -> Result<Vec<ScanEntry>, StoreError> {
            self.inner.scan_prefix(family, prefix)
        }
    }

    #[test]
    fn memory_store_commits_batches_atomically() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch.put(ColumnFamily::Meta, b"best", b"one").expect("put");
        batch
            .put(ColumnFamily::Headers, b"hash", b"header")
            .expect("put");
        store.commit(batch).expect("commit");

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.get(ColumnFamily::Meta, b"best").expect("get"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            snapshot.get(ColumnFamily::Headers, b"hash").expect("get"),
            Some(b"header".to_vec())
        );
    }

    #[test]
    fn memory_store_delete_overrides_existing_value() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Meta, b"key", b"value")
            .expect("put");
        store.commit(batch).expect("commit");

        let mut batch = store.batch();
        batch.delete(ColumnFamily::Meta, b"key").expect("delete");
        store.commit(batch).expect("commit");

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.get(ColumnFamily::Meta, b"key").expect("get"), None);
    }

    #[test]
    fn memory_snapshot_scans_prefix_in_key_order() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Headers, b"b/2", b"two")
            .expect("put");
        batch
            .put(ColumnFamily::Headers, b"b/1", b"one")
            .expect("put");
        batch
            .put(ColumnFamily::BlockIndex, b"b/0", b"wrong-cf")
            .expect("put");
        batch
            .put(ColumnFamily::Headers, b"a/1", b"skip")
            .expect("put");
        store.commit(batch).expect("commit");

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .scan_prefix(ColumnFamily::Headers, b"b/")
                .expect("scan"),
            vec![
                (b"b/1".to_vec(), b"one".to_vec()),
                (b"b/2".to_vec(), b"two".to_vec())
            ]
        );
    }

    #[test]
    fn memory_snapshot_visits_prefix_in_key_order() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Headers, b"b/2", b"two")
            .expect("put");
        batch
            .put(ColumnFamily::Headers, b"b/1", b"one")
            .expect("put");
        batch
            .put(ColumnFamily::Headers, b"a/1", b"skip")
            .expect("put");
        store.commit(batch).expect("commit");

        let snapshot = store.snapshot().expect("snapshot");
        let mut visited = Vec::new();
        snapshot
            .visit_prefix(ColumnFamily::Headers, b"b/", &mut |key, value| {
                visited.push((key.to_vec(), value.to_vec()));
                Ok(())
            })
            .expect("visit");
        assert_eq!(
            visited,
            vec![
                (b"b/1".to_vec(), b"one".to_vec()),
                (b"b/2".to_vec(), b"two".to_vec())
            ]
        );
    }

    #[test]
    fn staging_overlay_reads_its_own_writes_without_committing() {
        let store = MemoryStore::new();
        let mut initial = store.batch();
        initial
            .put(ColumnFamily::Headers, b"b/1", b"old")
            .expect("put initial");
        initial
            .put(ColumnFamily::Headers, b"b/0", b"base")
            .expect("put base value");
        store.commit(initial).expect("commit initial");

        let base = store.snapshot().expect("base snapshot");
        let overlay = StagingOverlay::new();
        let staged_snapshot = overlay.snapshot(&base);
        let mut staged_batch = overlay.batch(store.batch());
        staged_batch
            .put(ColumnFamily::Headers, b"b/1", b"new")
            .expect("replace");
        staged_batch
            .put(ColumnFamily::Headers, b"b/2", b"two")
            .expect("insert");
        staged_batch
            .delete(ColumnFamily::Headers, b"b/3")
            .expect("delete absent");

        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::Headers, b"b/1")
                .expect("staged get"),
            Some(b"new".to_vec())
        );
        assert_eq!(
            staged_snapshot
                .get_many(ColumnFamily::Headers, &[b"b/0", b"b/1", b"b/2", b"b/3"],)
                .expect("staged multi-get"),
            vec![
                Some(b"base".to_vec()),
                Some(b"new".to_vec()),
                Some(b"two".to_vec()),
                None,
            ]
        );
        assert_eq!(
            staged_snapshot
                .scan_prefix(ColumnFamily::Headers, b"b/")
                .expect("staged scan"),
            vec![
                (b"b/0".to_vec(), b"base".to_vec()),
                (b"b/1".to_vec(), b"new".to_vec()),
                (b"b/2".to_vec(), b"two".to_vec())
            ]
        );

        let live = store.snapshot().expect("live snapshot");
        assert_eq!(
            live.get(ColumnFamily::Headers, b"b/1").expect("live get"),
            Some(b"old".to_vec())
        );
        assert_eq!(
            live.get(ColumnFamily::Headers, b"b/2").expect("live get"),
            None
        );

        store
            .commit(staged_batch.into_inner())
            .expect("commit staged batch");
        let committed = store.snapshot().expect("committed snapshot");
        assert_eq!(
            committed
                .get(ColumnFamily::Headers, b"b/1")
                .expect("committed get"),
            Some(b"new".to_vec())
        );
        assert_eq!(
            committed
                .get(ColumnFamily::Headers, b"b/2")
                .expect("committed get"),
            Some(b"two".to_vec())
        );
    }

    #[test]
    fn staging_overlay_caches_name_nodes_and_active_state_point_reads() {
        let store = MemoryStore::new();
        let mut initial = store.batch();
        initial
            .put(ColumnFamily::NameTreeNodes, b"node-a", b"value-a")
            .expect("put node a");
        initial
            .put(ColumnFamily::NameTreeNodes, b"node-b", b"value-b")
            .expect("put node b");
        initial
            .put(ColumnFamily::Headers, b"header", b"value")
            .expect("put header");
        initial
            .put(ColumnFamily::Utxo, b"coin-present", b"coin")
            .expect("put coin");
        initial
            .put(ColumnFamily::NameState, b"name-present", b"old-state")
            .expect("put name state");
        store.commit(initial).expect("commit initial");

        let base = CountingSnapshot::new(store.snapshot().expect("base snapshot"));
        let overlay = StagingOverlay::new();
        let staged_snapshot = overlay.snapshot(&base);
        let mut staged_batch = overlay.batch(store.batch());

        assert_eq!(
            staged_snapshot
                .get_many(
                    ColumnFamily::NameTreeNodes,
                    &[b"node-a".as_slice(), b"node-b".as_slice()],
                )
                .expect("initial node multi-get"),
            vec![Some(b"value-a".to_vec()), Some(b"value-b".to_vec())]
        );
        assert_eq!(base.multi_gets.get(), 1);
        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::NameTreeNodes, b"node-a")
                .expect("cached node get"),
            Some(b"value-a".to_vec())
        );
        assert_eq!(
            staged_snapshot
                .get_many(
                    ColumnFamily::NameTreeNodes,
                    &[b"node-b".as_slice(), b"node-a".as_slice()],
                )
                .expect("cached node multi-get"),
            vec![Some(b"value-b".to_vec()), Some(b"value-a".to_vec())]
        );
        assert_eq!(base.gets.get(), 0);
        assert_eq!(base.multi_gets.get(), 1);

        for _ in 0..2 {
            assert_eq!(
                staged_snapshot
                    .get(ColumnFamily::NameState, b"name-present")
                    .expect("cached present name state"),
                Some(b"old-state".to_vec())
            );
            assert_eq!(
                staged_snapshot
                    .get(ColumnFamily::NameState, b"name-absent")
                    .expect("cached absent name state"),
                None
            );
        }
        assert_eq!(
            base.gets.get(),
            2,
            "present and absent name state must each reach the base once"
        );

        staged_batch
            .put(ColumnFamily::NameTreeNodes, b"node-a", b"staged")
            .expect("replace cached node");
        staged_batch
            .delete(ColumnFamily::NameTreeNodes, b"node-b")
            .expect("delete cached node");
        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::NameTreeNodes, b"node-a")
                .expect("staged node get"),
            Some(b"staged".to_vec())
        );
        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::NameTreeNodes, b"node-b")
                .expect("staged node delete"),
            None
        );
        staged_batch
            .put(ColumnFamily::NameState, b"name-present", b"new-state")
            .expect("replace cached name state");
        staged_batch
            .put(ColumnFamily::NameState, b"name-absent", b"opened-state")
            .expect("insert cached absent name state");
        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::NameState, b"name-present")
                .expect("staged present name state"),
            Some(b"new-state".to_vec())
        );
        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::NameState, b"name-absent")
                .expect("staged absent name state"),
            Some(b"opened-state".to_vec())
        );
        assert_eq!(base.gets.get(), 2);
        assert_eq!(base.multi_gets.get(), 1);

        for _ in 0..2 {
            assert_eq!(
                staged_snapshot
                    .get(ColumnFamily::Headers, b"header")
                    .expect("cached header get"),
                Some(b"value".to_vec())
            );
            assert_eq!(
                staged_snapshot
                    .get(ColumnFamily::Utxo, b"coin-present")
                    .expect("cached present coin"),
                Some(b"coin".to_vec())
            );
            assert_eq!(
                staged_snapshot
                    .get(ColumnFamily::Utxo, b"coin-absent")
                    .expect("cached absent coin"),
                None
            );
        }
        assert_eq!(
            base.gets.get(),
            5,
            "each immutable point value, including misses, must reach the base once"
        );
    }

    #[test]
    fn dropping_staged_batch_discards_every_staged_write() {
        let store = MemoryStore::new();
        let base = store.snapshot().expect("base snapshot");
        let overlay = StagingOverlay::new();
        let staged_snapshot = overlay.snapshot(&base);
        {
            let mut staged_batch = overlay.batch(store.batch());
            staged_batch
                .put(ColumnFamily::Meta, b"temporary", b"value")
                .expect("put");
            assert_eq!(
                staged_snapshot
                    .get(ColumnFamily::Meta, b"temporary")
                    .expect("staged get"),
                Some(b"value".to_vec())
            );
        }

        assert_eq!(
            store
                .snapshot()
                .expect("live snapshot")
                .get(ColumnFamily::Meta, b"temporary")
                .expect("live get"),
            None
        );
    }

    #[test]
    fn deferred_name_nodes_remain_visible_but_never_enter_inner_batch() {
        let store = MemoryStore::new();
        let base = store.snapshot().expect("base snapshot");
        let overlay = StagingOverlay::new();
        let staged_snapshot = overlay.snapshot(&base);
        let mut staged_batch = overlay.batch_with_deferred_name_tree_nodes(store.batch());
        staged_batch
            .put(ColumnFamily::NameTreeNodes, b"node", b"canonical")
            .expect("stage node");
        staged_batch
            .put(ColumnFamily::Meta, b"root", b"bound")
            .expect("stage root");

        assert_eq!(
            staged_snapshot
                .get(ColumnFamily::NameTreeNodes, b"node")
                .expect("staged node"),
            Some(b"canonical".to_vec())
        );
        assert_eq!(
            overlay.staged_family(ColumnFamily::NameTreeNodes),
            BTreeMap::from([(b"node".to_vec(), Some(b"canonical".to_vec()))])
        );
        store
            .commit(staged_batch.into_inner())
            .expect("commit inner batch");
        let snapshot = store.snapshot().expect("committed snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::NameTreeNodes, b"node")
                .expect("deferred node"),
            None
        );
        assert_eq!(
            snapshot.get(ColumnFamily::Meta, b"root").expect("root"),
            Some(b"bound".to_vec())
        );
    }

    #[test]
    fn initialize_schema_writes_and_checks_version() {
        let store = MemoryStore::new();
        initialize_schema(&store).expect("initialize schema");
        initialize_schema(&store).expect("check schema");

        let snapshot = store.snapshot().expect("snapshot");
        let version = snapshot
            .get(ColumnFamily::Meta, MetaKey::SchemaVersion.as_bytes())
            .expect("get")
            .expect("version");
        assert_eq!(decode_u32(&version).expect("decode"), SCHEMA_VERSION);
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())
                .expect("root"),
            Some(vec![0; 32])
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::NameTreeCommitRoot.as_bytes())
                .expect("commit root"),
            Some(vec![0; 32])
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::AirdropField.as_bytes())
                .expect("airdrop field"),
            Some(vec![0; AIRDROP_FIELD_BYTES])
        );
    }

    #[test]
    fn initialize_schema_writes_profile_and_rejects_markerless_data() {
        let store = MemoryStore::new();
        initialize_schema(&store).expect("initialize");
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::StorageProfile.as_bytes())
                .expect("profile"),
            Some(STORAGE_PROFILE.to_vec())
        );

        let markerless = MemoryStore::new();
        let mut batch = markerless.batch();
        batch
            .put(ColumnFamily::Headers, b"orphan", b"header")
            .expect("put markerless data");
        markerless.commit(batch).expect("commit markerless data");
        assert!(matches!(
            initialize_schema(&markerless),
            Err(StoreError::Schema(message)) if message.contains("no schema marker")
        ));
    }

    #[test]
    fn initialize_schema_rejects_profile_drift() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                b"hsrd-obsolete-profile",
            )
            .expect("profile");
        store.commit(batch).expect("commit");
        assert!(matches!(
            initialize_schema(&store),
            Err(StoreError::Schema(message)) if message.contains("clean reindex")
        ));
    }

    #[test]
    fn initialize_schema_rejects_partial_marker_sets() {
        let schema_only = MemoryStore::new();
        let mut batch = schema_only.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        schema_only.commit(batch).expect("commit schema-only store");
        assert!(matches!(
            initialize_schema(&schema_only),
            Err(StoreError::Schema(message)) if message.contains("without a storage-profile")
        ));

        let profile_only = MemoryStore::new();
        let mut batch = profile_only.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        profile_only
            .commit(batch)
            .expect("commit profile-only store");
        assert!(matches!(
            initialize_schema(&profile_only),
            Err(StoreError::Schema(message)) if message.contains("no schema marker")
        ));
    }

    #[test]
    fn initialize_schema_rejects_missing_or_malformed_name_tree_root() {
        let missing = MemoryStore::new();
        let mut batch = missing.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        missing.commit(batch).expect("commit missing-root store");
        assert!(matches!(
            initialize_schema(&missing),
            Err(StoreError::Schema(message)) if message.contains("name-tree-root")
        ));

        let malformed = MemoryStore::new();
        let mut batch = malformed.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                &[0; 31],
            )
            .expect("root");
        malformed
            .commit(batch)
            .expect("commit malformed-root store");
        assert!(matches!(
            initialize_schema(&malformed),
            Err(StoreError::Schema(message)) if message.contains("32 bytes")
        ));
    }

    #[test]
    fn initialize_schema_rejects_missing_or_malformed_airdrop_field() {
        let missing = MemoryStore::new();
        let mut batch = missing.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                &[0; 32],
            )
            .expect("root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                &[0; 32],
            )
            .expect("commit root");
        missing.commit(batch).expect("commit missing-field store");
        assert!(matches!(
            initialize_schema(&missing),
            Err(StoreError::Schema(message)) if message.contains("airdrop-field")
        ));

        let malformed = MemoryStore::new();
        let mut batch = malformed.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                &[0; 32],
            )
            .expect("root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                &[0; 32],
            )
            .expect("commit root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::AirdropField.as_bytes(),
                &[0; AIRDROP_FIELD_BYTES - 1],
            )
            .expect("field");
        malformed
            .commit(batch)
            .expect("commit malformed-field store");
        assert!(matches!(
            initialize_schema(&malformed),
            Err(StoreError::Schema(message)) if message.contains(&AIRDROP_FIELD_BYTES.to_string())
        ));
    }

    #[test]
    fn initialize_schema_rejects_missing_or_malformed_name_tree_commit_root() {
        let missing = MemoryStore::new();
        let mut batch = missing.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                &[0; 32],
            )
            .expect("root");
        missing
            .commit(batch)
            .expect("commit missing commit-root store");
        assert!(matches!(
            initialize_schema(&missing),
            Err(StoreError::Schema(message)) if message.contains("name-tree-commit-root")
        ));

        let malformed = MemoryStore::new();
        let mut batch = malformed.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                &[0; 32],
            )
            .expect("root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                &[0; 31],
            )
            .expect("commit root");
        malformed
            .commit(batch)
            .expect("commit malformed commit-root store");
        assert!(matches!(
            initialize_schema(&malformed),
            Err(StoreError::Schema(message)) if message.contains("32 bytes")
        ));
    }

    #[test]
    fn initialize_schema_rejects_version_drift() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(SCHEMA_VERSION.saturating_sub(1)),
            )
            .expect("schema");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                STORAGE_PROFILE,
            )
            .expect("profile");
        store.commit(batch).expect("commit");
        assert!(matches!(
            initialize_schema(&store),
            Err(StoreError::Schema(message)) if message.contains("clean reindex")
        ));
    }

    #[test]
    fn clean_shutdown_marker_rejects_unknown_values() {
        let store = MemoryStore::new();
        initialize_schema(&store).expect("schema");
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes(), &[2])
            .expect("marker");
        store.commit(batch).expect("commit marker");
        assert!(matches!(
            was_clean_shutdown(&store),
            Err(StoreError::Schema(message)) if message.contains("invalid clean-shutdown marker")
        ));
    }

    #[test]
    fn clean_shutdown_marker_is_explicit_and_fail_closed() {
        let store = MemoryStore::new();
        initialize_schema(&store).expect("schema");
        assert!(!was_clean_shutdown(&store).expect("missing marker is unclean"));
        mark_clean_shutdown(&store).expect("mark clean");
        assert!(was_clean_shutdown(&store).expect("clean"));
        mark_unclean_start(&store).expect("mark running");
        assert!(!was_clean_shutdown(&store).expect("unclean"));
    }

    #[derive(Clone)]
    struct FailingStore {
        inner: MemoryStore,
        fail_next_commit: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                fail_next_commit: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        fn fail_next_commit(&self) {
            self.fail_next_commit
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Store for FailingStore {
        type Snapshot<'a> = MemorySnapshot;
        type Batch = MemoryBatch;

        fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
            self.inner.snapshot()
        }

        fn batch(&self) -> Self::Batch {
            self.inner.batch()
        }

        fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
            if self
                .fail_next_commit
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(StoreError::Io("injected commit failure".to_owned()));
            }
            self.inner.commit(batch)
        }
    }

    #[test]
    fn failed_commit_preserves_the_complete_old_state() {
        let store = FailingStore::new();
        let mut initial = store.batch();
        initial
            .put(ColumnFamily::Meta, b"tip", b"old")
            .expect("initial");
        initial
            .put(ColumnFamily::Headers, b"old", b"header")
            .expect("initial header");
        store.commit(initial).expect("initial commit");

        let mut replacement = store.batch();
        replacement
            .put(ColumnFamily::Meta, b"tip", b"new")
            .expect("replacement tip");
        replacement
            .put(ColumnFamily::Headers, b"new", b"header")
            .expect("replacement header");
        replacement
            .delete(ColumnFamily::Headers, b"old")
            .expect("replacement delete");
        store.fail_next_commit();
        assert!(store.commit(replacement).is_err());

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.get(ColumnFamily::Meta, b"tip").expect("tip"),
            Some(b"old".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Headers, b"old")
                .expect("old header"),
            Some(b"header".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Headers, b"new")
                .expect("new header"),
            None
        );
    }

    #[test]
    fn fixed_width_u64_round_trip_is_canonical() {
        let encoded = encode_u64(0x0102_0304_0506_0708);
        assert_eq!(encoded, [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(decode_u64(&encoded).expect("decode"), 0x0102_0304_0506_0708);
        assert!(decode_u64(&encoded[..7]).is_err());
    }

    #[test]
    fn durability_policy_is_explicit_and_strictly_parsed() {
        assert_eq!(
            "sync".parse::<DurabilityPolicy>().expect("sync"),
            DurabilityPolicy::Sync
        );
        assert_eq!(
            "wal".parse::<DurabilityPolicy>().expect("wal"),
            DurabilityPolicy::Wal
        );
        assert!("none".parse::<DurabilityPolicy>().is_err());
        assert_eq!(DurabilityPolicy::Sync.to_string(), "sync");
        assert_eq!(DurabilityPolicy::Wal.to_string(), "wal");
    }

    #[test]
    fn store_handle_dispatches_memory_backend() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");

        let snapshot = store.snapshot().expect("snapshot");
        assert!(snapshot
            .get(ColumnFamily::Meta, MetaKey::SchemaVersion.as_bytes())
            .expect("get")
            .is_some());
    }

    #[test]
    fn archived_store_publishes_locators_and_recovers_uncommitted_tails() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("hsrd-store-archive-{}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let raw = StoreHandle::memory();
        let archived = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("attach archive");
        let block_key = [0x41; 32];
        let undo_key = [0x42; 32];
        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Blocks, &block_key, b"raw block record")
            .expect("stage block");
        batch
            .put(ColumnFamily::Undo, &undo_key, b"raw undo record")
            .expect("stage undo");
        archived.commit(batch).expect("commit archived payloads");

        let snapshot = archived.snapshot().expect("archived snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &block_key)
                .expect("block"),
            Some(b"raw block record".to_vec())
        );
        assert_eq!(
            snapshot.get(ColumnFamily::Undo, &undo_key).expect("undo"),
            Some(b"raw undo record".to_vec())
        );
        drop(snapshot);
        let raw_snapshot = raw.snapshot().expect("raw snapshot");
        let raw_block = raw_snapshot
            .get(ColumnFamily::Blocks, &block_key)
            .expect("raw block")
            .expect("raw block locator");
        assert_eq!(
            SegmentValueLocator::decode(&raw_block)
                .expect("decode block locator")
                .expect("block locator")
                .kind,
            SegmentKind::Block
        );
        let block_manifest = SegmentManifest::decode(
            &raw_snapshot
                .get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)
                .expect("block manifest")
                .expect("block manifest"),
        )
        .expect("decode block manifest");
        drop(raw_snapshot);
        drop(archived);

        let block_path = directory.join(format!(
            "block-g{:016x}-s{:08x}.seg",
            block_manifest.generation, block_manifest.active_segment
        ));
        let mut appender = SegmentAppender::open_at_committed_tail(&block_path, block_manifest)
            .expect("open committed block tail");
        appender
            .append(&SegmentRecord {
                kind: SegmentKind::Block,
                key: [0x99; 32],
                hints: Vec::new(),
                payload: b"unpublished complete tail".to_vec(),
            })
            .expect("append unpublished tail");
        appender.sync_data().expect("sync unpublished tail");
        drop(appender);
        assert!(
            std::fs::metadata(&block_path)
                .expect("unpublished metadata")
                .len()
                > block_manifest.durable_bytes
        );

        let reopened = raw
            .with_segment_archive(directory.clone())
            .expect("recover archive");
        assert_eq!(
            std::fs::metadata(&block_path)
                .expect("recovered metadata")
                .len(),
            block_manifest.durable_bytes
        );
        assert_eq!(
            reopened
                .snapshot()
                .expect("reopened snapshot")
                .get(ColumnFamily::Blocks, &block_key)
                .expect("reopened block"),
            Some(b"raw block record".to_vec())
        );
        drop(reopened);
        std::fs::remove_dir_all(directory).expect("remove archive fixture");
    }

    #[test]
    fn segment_compaction_rewrites_only_live_locators_and_reclaims_old_generation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-segment-compaction-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let raw = StoreHandle::memory();
        let archived = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("attach archive");
        let live_block = [0x31; 32];
        let dead_block = [0x32; 32];
        let live_undo = [0x41; 32];
        let dead_undo = [0x42; 32];
        let mut batch = archived.batch();
        for (family, key, payload) in [
            (ColumnFamily::Blocks, live_block, b"live block".as_slice()),
            (ColumnFamily::Blocks, dead_block, b"dead block".as_slice()),
            (ColumnFamily::Undo, live_undo, b"live undo".as_slice()),
            (ColumnFamily::Undo, dead_undo, b"dead undo".as_slice()),
        ] {
            batch.put(family, &key, payload).expect("stage payload");
        }
        archived.commit(batch).expect("commit payloads");
        let mut batch = archived.batch();
        batch
            .delete(ColumnFamily::Blocks, &dead_block)
            .expect("delete dead block locator");
        batch
            .delete(ColumnFamily::Undo, &dead_undo)
            .expect("delete dead undo locator");
        archived
            .commit(batch)
            .expect("commit dead locator deletion");

        let before = archived.scrub_segment_archive().expect("pre scrub");
        assert_eq!(before.blocks.records, 2);
        assert_eq!(before.undo.records, 2);
        let report = archived
            .compact_segment_archive()
            .expect("compact segment archive");
        assert_eq!(report.previous_block_generation, 1);
        assert_eq!(report.previous_undo_generation, 1);
        assert_eq!(report.generation, 2);
        assert_eq!(report.live_records, 2);
        assert!(report.reclaimed_frame_bytes > 0);

        let after = archived.scrub_segment_archive().expect("post scrub");
        assert_eq!(after.blocks.records, 1);
        assert_eq!(after.undo.records, 1);
        let snapshot = archived.snapshot().expect("compacted snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &live_block)
                .expect("live block"),
            Some(b"live block".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Undo, &live_undo)
                .expect("live undo"),
            Some(b"live undo".to_vec())
        );
        assert!(snapshot
            .get(ColumnFamily::Blocks, &dead_block)
            .expect("dead block")
            .is_none());
        assert!(snapshot
            .get(ColumnFamily::Undo, &dead_undo)
            .expect("dead undo")
            .is_none());
        drop(snapshot);
        for entry in std::fs::read_dir(&directory).expect("segment directory") {
            let name = entry
                .expect("segment entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            assert!(name.contains("-g0000000000000002-"), "{name}");
        }

        drop(archived);
        for (kind, name, key) in [
            (SegmentKind::Block, "block", [0x71; 32]),
            (SegmentKind::Undo, "undo", [0x72; 32]),
        ] {
            let path = directory.join(format!("{name}-g0000000000000003-s00000000.seg"));
            let mut orphan =
                SegmentAppender::create_new(&path, 3, 0).expect("create crash-residue generation");
            orphan
                .append(&SegmentRecord {
                    kind,
                    key,
                    hints: Vec::new(),
                    payload: b"unpublished compaction payload".to_vec(),
                })
                .expect("append crash-residue payload");
            orphan.sync_data().expect("sync crash-residue payload");
        }
        std::fs::copy(
            directory.join("block-g0000000000000002-s00000000.seg"),
            directory.join("block-g0000000000000001-s00000000.seg"),
        )
        .expect("restore superseded block generation");
        std::fs::copy(
            directory.join("undo-g0000000000000002-s00000000.seg"),
            directory.join("undo-g0000000000000001-s00000000.seg"),
        )
        .expect("restore superseded undo generation");
        let reopened = raw
            .with_segment_archive(directory.clone())
            .expect("reopen compacted archive");
        assert_eq!(
            reopened
                .snapshot()
                .expect("reopened snapshot")
                .get(ColumnFamily::Blocks, &live_block)
                .expect("reopened live block"),
            Some(b"live block".to_vec())
        );
        for entry in std::fs::read_dir(&directory).expect("recovered segment directory") {
            let name = entry
                .expect("recovered segment entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            assert!(name.contains("-g0000000000000002-"), "{name}");
        }
        drop(reopened);
        std::fs::remove_dir_all(directory).expect("remove compaction fixture");
    }

    #[test]
    fn inline_archive_migration_is_bounded_idempotent_and_transparent() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-inline-archive-migration-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let raw = StoreHandle::memory();
        let records = [
            (ColumnFamily::Blocks, [0x11; 32], b"first block".as_slice()),
            (ColumnFamily::Blocks, [0x12; 32], b"second block".as_slice()),
            (ColumnFamily::Undo, [0x21; 32], b"first undo".as_slice()),
        ];
        let mut batch = raw.batch();
        for (family, key, value) in &records {
            batch.put(*family, key, value).expect("stage inline value");
        }
        raw.commit(batch).expect("commit inline values");
        let archived = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("attach archive");

        let before = archived
            .segment_archive_inventory()
            .expect("pre-migration inventory");
        assert_eq!(before.blocks.inline_records, 2);
        assert_eq!(before.undo.inline_records, 1);
        assert_eq!(before.blocks.archived_records, 0);
        assert_eq!(before.undo.archived_records, 0);

        let report = archived
            .migrate_inline_segment_payloads(1)
            .expect("migrate inline values");
        assert_eq!(report.migrated_records, 3);
        assert_eq!(report.commits, 3);
        let after = archived
            .segment_archive_inventory()
            .expect("post-migration inventory");
        assert_eq!(after.blocks.inline_records, 0);
        assert_eq!(after.undo.inline_records, 0);
        assert_eq!(after.blocks.archived_records, 2);
        assert_eq!(after.undo.archived_records, 1);
        for (family, key, value) in records {
            let stored = raw
                .snapshot()
                .expect("raw snapshot")
                .get(family, &key)
                .expect("raw value")
                .expect("raw locator");
            assert!(SegmentValueLocator::decode(&stored)
                .expect("decode locator")
                .is_some());
            assert_eq!(
                archived
                    .snapshot()
                    .expect("archived snapshot")
                    .get(family, &key)
                    .expect("resolved value"),
                Some(value.to_vec())
            );
        }
        assert_eq!(
            archived
                .migrate_inline_segment_payloads(2)
                .expect("repeat migration"),
            SegmentMigrationReport::default()
        );
        assert!(archived.migrate_inline_segment_payloads(0).is_err());
        assert!(archived
            .migrate_inline_segment_payloads(SEGMENT_MIGRATION_MAX_BATCH_RECORDS + 1)
            .is_err());
        drop(archived);
        std::fs::remove_dir_all(directory).expect("remove archive fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_store_persists_across_reopen() {
        let path =
            std::env::temp_dir().join(format!("hsrd-rocks-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);

        {
            let store = RocksStore::open(&path).expect("open rocksdb");
            initialize_schema(&store).expect("schema");
            let mut batch = store.batch();
            batch
                .put(ColumnFamily::Headers, b"hash", b"header")
                .expect("put");
            store.commit(batch).expect("commit");
        }

        {
            let store = RocksStore::open(&path).expect("reopen rocksdb");
            let snapshot = store.snapshot().expect("snapshot");
            assert_eq!(
                snapshot.get(ColumnFamily::Headers, b"hash").expect("get"),
                Some(b"header".to_vec())
            );
            assert_eq!(
                snapshot
                    .get_many(ColumnFamily::Headers, &[b"missing", b"hash"])
                    .expect("multi-get"),
                vec![None, Some(b"header".to_vec())]
            );
            assert_eq!(
                snapshot
                    .scan_prefix(ColumnFamily::Headers, b"ha")
                    .expect("scan"),
                vec![(b"hash".to_vec(), b"header".to_vec())]
            );
            let mut visited = Vec::new();
            snapshot
                .visit_prefix(ColumnFamily::Headers, b"ha", &mut |key, value| {
                    visited.push((key.to_vec(), value.to_vec()));
                    Ok(())
                })
                .expect("visit");
            assert_eq!(visited, vec![(b"hash".to_vec(), b"header".to_vec())]);
            initialize_schema(&store).expect("schema still valid");
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_archive_writes_locator_sized_lsm_values() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hsrd-rocks-archive-test-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let rocks = RocksStore::open(root.join("chain")).expect("open rocksdb");
        let raw = StoreHandle::Rocks(rocks.clone());
        let archived = raw
            .with_segment_archive(root.join("payloads"))
            .expect("attach archive");
        let key = [0x61; 32];
        let payload = vec![0xa5; 1024 * 1024];
        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Blocks, &key, &payload)
            .expect("stage payload");
        archived.commit(batch).expect("commit payload");

        let stored = rocks
            .snapshot()
            .expect("raw rocks snapshot")
            .get(ColumnFamily::Blocks, &key)
            .expect("raw rocks value")
            .expect("raw rocks value");
        assert!(stored.len() < 128);
        assert!(SegmentValueLocator::decode(&stored)
            .expect("decode locator")
            .is_some());
        assert_eq!(
            archived
                .snapshot()
                .expect("archive snapshot")
                .get(ColumnFamily::Blocks, &key)
                .expect("resolved payload"),
            Some(payload)
        );
        drop(archived);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove rocks archive fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_store_exposes_selected_wal_durability_policy() {
        let path =
            std::env::temp_dir().join(format!("hsrd-rocks-durability-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let store =
            RocksStore::open_with_durability(&path, DurabilityPolicy::Wal).expect("open rocksdb");
        assert_eq!(store.durability, DurabilityPolicy::Wal);
        drop(store);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_store_configures_bounded_cache_domains() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-rocks-cache-domain-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let store = RocksStore::open(&path).expect("open rocksdb");

        let point_cf = RocksStore::cf(&store.db, ColumnFamily::NameTreeNodes).expect("point cf");
        let bulk_cf = RocksStore::cf(&store.db, ColumnFamily::Blocks).expect("bulk cf");
        assert_eq!(
            store
                .db
                .property_int_value_cf(point_cf, rocksdb::properties::BLOCK_CACHE_CAPACITY)
                .expect("point cache capacity"),
            Some(ROCKS_POINT_CACHE_BYTES as u64)
        );
        assert_eq!(
            store
                .db
                .property_int_value_cf(bulk_cf, rocksdb::properties::BLOCK_CACHE_CAPACITY)
                .expect("bulk cache capacity"),
            Some(ROCKS_BULK_CACHE_BYTES as u64)
        );
        assert!(format!("{store:?}").contains("point_cache_usage"));

        drop(store);
        let log = std::fs::read_to_string(path.join("LOG")).expect("rocksdb option log");
        assert!(
            log.contains(&format!(
                "Options.max_total_wal_size: {ROCKS_MAX_TOTAL_WAL_BYTES}"
            )),
            "RocksDB did not apply the aggregate WAL cap"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_snapshot_is_sequence_consistent() {
        let path =
            std::env::temp_dir().join(format!("hsrd-rocks-snapshot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let store = RocksStore::open(&path).expect("open rocksdb");

        let mut initial = store.batch();
        initial
            .put(ColumnFamily::Meta, b"key", b"old")
            .expect("put initial");
        store.commit(initial).expect("commit initial");

        let snapshot = store.snapshot().expect("snapshot");
        let mut replacement = store.batch();
        replacement
            .put(ColumnFamily::Meta, b"key", b"new")
            .expect("put replacement");
        store.commit(replacement).expect("commit replacement");

        assert_eq!(
            snapshot.get(ColumnFamily::Meta, b"key").expect("get"),
            Some(b"old".to_vec())
        );
        assert_eq!(
            store
                .snapshot()
                .expect("new snapshot")
                .get(ColumnFamily::Meta, b"key")
                .expect("get"),
            Some(b"new".to_vec())
        );

        drop(snapshot);
        drop(store);
        let _ = std::fs::remove_dir_all(&path);
    }
}
