//! Write-optimized durable chainstate backend.
//!
//! HSRD's small mutable records are an LSM workload: every connected block
//! creates and spends many randomly keyed UTXOs, updates name state, and adds
//! immutable index rows. RocksDB absorbs that transition once into a WAL and
//! memtables; compaction is asynchronous. Large block and undo values remain
//! in HSRD's authenticated sequential segment archive, so they never churn
//! through LSM levels.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use rocksdb::{
    BlockBasedIndexType, BlockBasedOptions, Cache, ColumnFamilyDescriptor, Direction, IteratorMode,
    Options, ReadOptions, Snapshot, WriteOptions, DB,
};

use crate::{
    authenticated_namespace::{SharedNamespaceArchiveRegistration, SharedNamespaceOwners},
    begin_batch_checkpoint, commit_batch_checkpoint, push_bounded_scan_entry,
    replace_batch_operation, rollback_batch_checkpoint, validate_prefix_scan_request,
    BatchCheckpoint, BatchOperations, CheckpointWriteBatch, ColumnFamily, DurabilityPolicy,
    PrefixScanBudget, PrefixScanPage, PrefixVisitor, ReadSnapshot, ScanEntry, Store, StoreError,
    StoreKey, WriteBatch,
};

const POINT_CACHE_BYTES: usize = 768 * 1024 * 1024;
const ARCHIVE_LOCATOR_CACHE_BYTES: usize = 32 * 1024 * 1024;
const DB_WRITE_BUFFER_BYTES: usize = 1536 * 1024 * 1024;
const MAX_TOTAL_WAL_BYTES: u64 = 1024 * 1024 * 1024;
const HOT_WRITE_BUFFER_BYTES: usize = 128 * 1024 * 1024;
const COLD_WRITE_BUFFER_BYTES: usize = 32 * 1024 * 1024;
const MAX_WRITE_BUFFERS: i32 = 4;
const MIN_WRITE_BUFFERS_TO_MERGE: i32 = 2;
const TARGET_FILE_BYTES: u64 = 256 * 1024 * 1024;
const LEVEL_BASE_BYTES: u64 = 1024 * 1024 * 1024;
const BLOOM_BITS_PER_KEY: f64 = 10.0;
const TABLE_BLOCK_BYTES: usize = 16 * 1024;

fn backend(error: impl fmt::Display) -> StoreError {
    StoreError::Backend(error.to_string())
}

fn high_churn(family: ColumnFamily) -> bool {
    matches!(
        family,
        ColumnFamily::Utxo
            | ColumnFamily::NameState
            | ColumnFamily::NameTreeNodes
            | ColumnFamily::TxIndex
            | ColumnFamily::WalletHistory
            | ColumnFamily::WalletState
    )
}

fn point_heavy(family: ColumnFamily) -> bool {
    high_churn(family)
        || matches!(
            family,
            ColumnFamily::Headers
                | ColumnFamily::BlockIndex
                | ColumnFamily::Peers
                | ColumnFamily::Snapshots
        )
}

fn family_options(family: ColumnFamily, cache: &Cache) -> Options {
    let mut table = BlockBasedOptions::default();
    table.set_block_cache(cache);
    table.set_block_size(TABLE_BLOCK_BYTES);
    table.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
    table.set_optimize_filters_for_memory(true);
    table.set_cache_index_and_filter_blocks(true);
    table.set_pin_l0_filter_and_index_blocks_in_cache(true);
    if point_heavy(family) {
        table.set_index_type(BlockBasedIndexType::TwoLevelIndexSearch);
        table.set_partition_filters(true);
        table.set_pin_top_level_index_and_filter(true);
    }

    let mut options = Options::default();
    options.set_block_based_table_factory(&table);
    options.set_write_buffer_size(if high_churn(family) {
        HOT_WRITE_BUFFER_BYTES
    } else {
        COLD_WRITE_BUFFER_BYTES
    });
    options.set_max_write_buffer_number(MAX_WRITE_BUFFERS);
    options.set_min_write_buffer_number_to_merge(MIN_WRITE_BUFFERS_TO_MERGE);
    options.set_target_file_size_base(TARGET_FILE_BYTES);
    options.set_max_bytes_for_level_base(LEVEL_BASE_BYTES);
    options.set_level_compaction_dynamic_level_bytes(true);
    options.set_memtable_whole_key_filtering(point_heavy(family));
    options.set_optimize_filters_for_hits(point_heavy(family));
    // The workspace-mandated optimized RocksDB archive was built without a
    // compression codec. Keep the physical contract explicit; requesting a
    // codec here would make DB::open fail instead of silently falling back.
    options.set_compression_type(rocksdb::DBCompressionType::None);
    options
}

#[derive(Clone)]
pub struct RocksStore {
    pub(crate) db: Arc<DB>,
    pub(crate) path: PathBuf,
    pub(crate) durability: DurabilityPolicy,
    point_cache: Cache,
    archive_locator_cache: Cache,
    pub(crate) reopen_required: Arc<AtomicBool>,
    pub(crate) publication_lock: Arc<Mutex<()>>,
    pub(crate) authenticated_namespaces: SharedNamespaceOwners,
    pub(crate) authenticated_namespace_archive: SharedNamespaceArchiveRegistration,
}

impl fmt::Debug for RocksStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RocksStore")
            .field("path", &self.path)
            .field("durability", &self.durability)
            .field("point_cache_usage", &self.point_cache.get_usage())
            .field(
                "archive_locator_cache_usage",
                &self.archive_locator_cache.get_usage(),
            )
            .field("reopen_required", &self.reopen_required())
            .finish_non_exhaustive()
    }
}

impl RocksStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_durability(path, DurabilityPolicy::Sync)
    }

    pub fn open_with_durability(
        path: impl AsRef<Path>,
        durability: DurabilityPolicy,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let mut database = Options::default();
        database.create_if_missing(true);
        database.create_missing_column_families(true);
        // Every mutation is WAL-protected. RocksDB's atomic-flush mode would
        // therefore add no recovery guarantee, while an automatic flush of
        // one busy chainstate family would force all sixteen families to
        // flush together. Let each family reach its own optimized SST size.
        database.set_atomic_flush(false);
        database.set_allow_concurrent_memtable_write(true);
        database.set_max_background_jobs(4);
        database.set_db_write_buffer_size(DB_WRITE_BUFFER_BYTES);
        database.set_max_total_wal_size(MAX_TOTAL_WAL_BYTES);
        database.set_bytes_per_sync(4 * 1024 * 1024);
        database.set_wal_bytes_per_sync(1024 * 1024);

        let point_cache = Cache::new_lru_cache(POINT_CACHE_BYTES);
        let archive_locator_cache = Cache::new_lru_cache(ARCHIVE_LOCATOR_CACHE_BYTES);
        let descriptors = ColumnFamily::ALL.into_iter().map(|family| {
            let cache = if matches!(family, ColumnFamily::Blocks | ColumnFamily::Undo) {
                &archive_locator_cache
            } else {
                &point_cache
            };
            ColumnFamilyDescriptor::new(family.name(), family_options(family, cache))
        });
        let db = DB::open_cf_descriptors(&database, &path, descriptors).map_err(backend)?;

        Ok(Self {
            db: Arc::new(db),
            path,
            durability,
            point_cache,
            archive_locator_cache,
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
                "RocksDB publication outcome is uncertain; reopen required".to_owned(),
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
                    "RocksDB publication lock is poisoned; reopen required".to_owned(),
                ))
            }
        }
    }

    fn cf(&self, family: ColumnFamily) -> Result<&rocksdb::ColumnFamily, StoreError> {
        self.db.cf_handle(family.name()).ok_or_else(|| {
            StoreError::Backend(format!(
                "RocksDB column family `{}` is unavailable",
                family.name()
            ))
        })
    }

    pub(crate) fn commit_operations_locked(
        &self,
        operations: BatchOperations,
    ) -> Result<(), StoreError> {
        if operations.is_empty() {
            return Ok(());
        }
        let mut batch = rocksdb::WriteBatch::default();
        for (key, value) in operations {
            let family = self.cf(key.family)?;
            match value {
                Some(value) => batch.put_cf(family, key.key, value),
                None => batch.delete_cf(family, key.key),
            }
        }
        let mut options = WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(matches!(self.durability, DurabilityPolicy::Sync));
        if let Err(error) = self.db.write_opt(batch, &options) {
            self.mark_commit_outcome_uncertain();
            return Err(StoreError::Backend(format!(
                "RocksDB atomic commit outcome is uncertain; reopen required: {error}"
            )));
        }
        Ok(())
    }

    pub(crate) fn snapshot_unlocked(&self) -> Result<RocksSnapshot<'_>, StoreError> {
        Ok(RocksSnapshot {
            store: self,
            snapshot: self.db.snapshot(),
        })
    }
}

impl Store for RocksStore {
    type Snapshot<'a> = RocksSnapshot<'a>;
    type Batch = RocksBatch;

    fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
        let _publication = self.lock_publication()?;
        self.ensure_operational()?;
        self.snapshot_unlocked()
    }

    fn batch(&self) -> Self::Batch {
        RocksBatch::default()
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

pub struct RocksSnapshot<'a> {
    store: &'a RocksStore,
    snapshot: Snapshot<'a>,
}

impl RocksSnapshot<'_> {
    fn read_options(&self) -> ReadOptions {
        let mut options = ReadOptions::default();
        options.set_snapshot(&self.snapshot);
        options
    }
}

impl ReadSnapshot for RocksSnapshot<'_> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot
            .get_cf(self.store.cf(family)?, key)
            .map_err(backend)
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let family = self.store.cf(family)?;
        self.store
            .db
            .batched_multi_get_cf_opt(family, keys.iter(), false, &self.read_options())
            .into_iter()
            .map(|value| {
                value
                    .map(|value| value.map(|value| value.to_vec()))
                    .map_err(backend)
            })
            .collect()
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        let family = self.store.cf(family)?;
        let mut entries = Vec::new();
        for entry in self
            .snapshot
            .iterator_cf(family, IteratorMode::From(prefix, Direction::Forward))
        {
            let (key, value) = entry.map_err(backend)?;
            if !key.starts_with(prefix) {
                break;
            }
            entries.push((key.to_vec(), value.to_vec()));
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
        let family = self.store.cf(family)?;
        let start = start_after.unwrap_or(prefix);
        let mut page = PrefixScanPage::default();
        for entry in self
            .snapshot
            .iterator_cf(family, IteratorMode::From(start, Direction::Forward))
        {
            let (key, value) = entry.map_err(backend)?;
            if !key.starts_with(prefix) {
                break;
            }
            if start_after.is_some_and(|cursor| key.as_ref() <= cursor) {
                continue;
            }
            if !push_bounded_scan_entry(&mut page, &key, &value, budget)? {
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
        let family = self.store.cf(family)?;
        for entry in self
            .snapshot
            .iterator_cf(family, IteratorMode::From(prefix, Direction::Forward))
        {
            let (key, value) = entry.map_err(backend)?;
            if !key.starts_with(prefix) {
                break;
            }
            visitor(&key, &value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct RocksBatch {
    pub(crate) operations: BatchOperations,
    checkpoint: Option<BatchCheckpoint>,
}

impl RocksBatch {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }
}

impl WriteBatch for RocksBatch {
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

impl CheckpointWriteBatch for RocksBatch {
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
            "hsrd-rocks-store-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn atomic_batch_survives_reopen_and_snapshot_isolation() {
        let path = test_directory();
        let store = RocksStore::open(&path).expect("open");
        let before = store.snapshot().expect("before");
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Utxo, b"coin", b"value")
            .expect("put");
        batch
            .put(ColumnFamily::Headers, b"coin", b"header")
            .expect("separate family");
        store.commit(batch).expect("commit");
        assert_eq!(before.get(ColumnFamily::Utxo, b"coin").expect("old"), None);
        drop(before);
        drop(store);

        let reopened = RocksStore::open(&path).expect("reopen");
        let snapshot = reopened.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.get(ColumnFamily::Utxo, b"coin").expect("coin"),
            Some(b"value".to_vec())
        );
        assert_eq!(
            snapshot
                .get_many(ColumnFamily::Headers, &[b"missing", b"coin"])
                .expect("ordered multi-get"),
            vec![None, Some(b"header".to_vec())]
        );
        drop(snapshot);
        drop(reopened);
        std::fs::remove_dir_all(path).expect("remove fixture");
    }
}
