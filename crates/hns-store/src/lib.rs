#![forbid(unsafe_code)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt,
    marker::PhantomData,
    path::PathBuf,
    rc::Rc,
    str::FromStr,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 14;

/// Durable database layout/profile identifier. A profile change is an explicit
/// migration boundary even when the low-level column families remain readable.
pub const STORAGE_PROFILE: &[u8] = b"hsrd-mining-v10";

/// HSD's MSB-first spent-allocation field contains 216,199 airdrop positions
/// followed by 1,358 faucet positions.
pub const AIRDROP_FIELD_BITS: usize = 217_557;
pub const AIRDROP_FIELD_BYTES: usize = AIRDROP_FIELD_BITS.div_ceil(8);

pub type ScanEntry = (Vec<u8>, Vec<u8>);

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

pub trait ReadSnapshot {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError>;
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
        }
    }

    pub fn batch<B: WriteBatch>(&self, inner: B) -> StagedBatch<B> {
        StagedBatch {
            inner,
            changes: Rc::clone(&self.changes),
        }
    }
}

pub struct StagedSnapshot<'a, S: ReadSnapshot> {
    base: &'a S,
    changes: SharedStagedChanges,
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
        self.base.get(family, key)
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
}

pub struct StagedBatch<B: WriteBatch> {
    inner: B,
    changes: SharedStagedChanges,
}

impl<B: WriteBatch> StagedBatch<B> {
    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: WriteBatch> WriteBatch for StagedBatch<B> {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.inner.put(family, key, value)?;
        self.changes
            .borrow_mut()
            .entry(family)
            .or_default()
            .insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        self.inner.delete(family, key)?;
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
        }
    }
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
        }
    }

    fn batch(&self) -> Self::Batch {
        match self {
            Self::Memory(store) => StoreHandleBatch::Memory(store.batch()),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => StoreHandleBatch::Rocks(store.batch()),
        }
    }

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
        match self {
            Self::Memory(store) => commit_memory_store_handle(store, batch),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => commit_rocks_store_handle(store, batch),
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
}

impl ReadSnapshot for StoreHandleSnapshot<'_> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        match self {
            Self::Memory(snapshot, _) => snapshot.get(family, key),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(snapshot) => snapshot.get(family, key),
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
        }
    }
}

#[derive(Clone, Debug)]
pub enum StoreHandleBatch {
    Memory(MemoryBatch),
    #[cfg(feature = "rocksdb-backend")]
    Rocks(RocksBatch),
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
#[derive(Clone, Debug)]
pub struct RocksStore {
    db: Arc<rocksdb::DB>,
    durability: DurabilityPolicy,
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
        use rocksdb::{ColumnFamilyDescriptor, Options};

        let mut db_options = Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);

        let descriptors = ColumnFamily::ALL
            .into_iter()
            .map(|family| ColumnFamilyDescriptor::new(family.name(), Options::default()));

        let db = rocksdb::DB::open_cf_descriptors(&db_options, path, descriptors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            durability,
        })
    }

    fn cf(db: &rocksdb::DB, family: ColumnFamily) -> Result<&rocksdb::ColumnFamily, StoreError> {
        db.cf_handle(family.name())
            .ok_or_else(|| StoreError::MissingColumnFamily(family.name()))
    }
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
    fn staging_overlay_reads_its_own_writes_without_committing() {
        let store = MemoryStore::new();
        let mut initial = store.batch();
        initial
            .put(ColumnFamily::Headers, b"b/1", b"old")
            .expect("put initial");
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
                .scan_prefix(ColumnFamily::Headers, b"b/")
                .expect("staged scan"),
            vec![
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
                    .scan_prefix(ColumnFamily::Headers, b"ha")
                    .expect("scan"),
                vec![(b"hash".to_vec(), b"header".to_vec())]
            );
            initialize_schema(&store).expect("schema still valid");
        }

        let _ = std::fs::remove_dir_all(&path);
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
