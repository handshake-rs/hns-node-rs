#![forbid(unsafe_code)]

mod authenticated_namespace;
mod name_page;
mod segment;

pub use authenticated_namespace::{
    AuthenticatedNamespaceError, AuthenticatedNamespaceLease, AuthenticatedNamespaceState,
    AuthenticatedNamespaceWrite, OperationNamespaceId, StateExpectation,
    AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES,
};
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
    SegmentAppender, SegmentArchive, SegmentArchiveScrub, SegmentArchiveScrubLimits,
    SegmentChannelScrub, SegmentError, SegmentFileInspection, SegmentKind, SegmentLocator,
    SegmentManifest, SegmentPageRead, SegmentRecord, SegmentRecordRef, SegmentScan,
    SegmentValueLocator, SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_DURABLE_BYTES,
    SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_ELAPSED, SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_RECORDS,
    SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_SEGMENTS, SEGMENT_MAX_HINTS, SEGMENT_PAGE_BYTES,
    SEGMENT_TARGET_BYTES,
};

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fmt,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant},
};

#[cfg(all(test, feature = "rocksdb-backend"))]
use std::sync::atomic::AtomicU8;
#[cfg(feature = "rocksdb-backend")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "rocksdb-backend")]
use std::sync::Mutex;

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
/// Hard upper bounds for one storage-native prefix page. They protect callers
/// from accidentally turning a cursor API back into a full-column-family
/// materialization.
pub const PREFIX_SCAN_MAX_ENTRIES: usize = 4_096;
/// One maximum-size legacy inline payload plus key/iterator framing. Callers
/// should normally choose a much smaller operational page.
pub const PREFIX_SCAN_MAX_BYTES: usize = 64 * 1024 * 1024 + 4 * 1024;
pub const SEGMENT_COMPACTION_DEFAULT_SCAN_RECORDS: usize = 1_024;
/// A mixed archive may still contain one legitimate near-maximum inline undo;
/// the page must be able to inspect and skip it before migration completes.
pub const SEGMENT_COMPACTION_DEFAULT_SCAN_BYTES: usize = PREFIX_SCAN_MAX_BYTES;
pub const SEGMENT_COMPACTION_DEFAULT_MAX_LIVE_RECORDS: u64 = 1_000_000;
pub const SEGMENT_COMPACTION_DEFAULT_MAX_LIVE_FRAME_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const SEGMENT_COMPACTION_DEFAULT_MAX_ATOMIC_LOCATOR_BYTES: u64 = 128 * 1024 * 1024;
pub const SEGMENT_COMPACTION_DEFAULT_MAX_PHYSICAL_OUTPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const SEGMENT_COMPACTION_DEFAULT_MAX_ATOMIC_PUBLICATION_BYTES: u64 = 256 * 1024 * 1024;
pub const SEGMENT_COMPACTION_DEFAULT_FILESYSTEM_RESERVE_BYTES: u64 = 10_000_000_000;
pub const SEGMENT_COMPACTION_DEFAULT_MAX_ELAPSED: Duration = Duration::from_secs(4 * 60 * 60);
const SEGMENT_COMPACTION_BATCH_OPERATION_OVERHEAD_BYTES: u64 = 64;
const SEGMENT_COMPACTION_ROCKS_TEMPORARY_MULTIPLIER: u64 = 2;
const SNAPSHOT_EMPTY_PROBE_BYTES: usize = 4 * 1024;
// A raw archived value is moved into an `ArchivePayload` before its framed
// encoding is built. Charge the complete key/value representation once even
// though the value allocation moves: its operation-framing allowance covers
// the copied fixed key, ArchivePayload descriptor and exact-capacity Vec slot.
const ARCHIVE_EXTRACTED_PAYLOAD_COPIES: u64 = 1;
// Segment preparation retains the encoded userspace frame while writing the
// byte-identical durable frame. The raw payload remains live until encoding
// completes and is charged separately above.
const ARCHIVE_FRAME_COPIES: u64 = 2;
// Segment preparation first retains a locator descriptor in
// `PreparedArchive.locators`, locator substitution then retains its larger
// encoded value in `StoreHandleBatch`, and the backend finally copies the
// complete key/value operation into its native atomic batch. Charging the
// encoded key/value size for all three conservatively covers the smaller
// descriptor and its Vec slot without ABI-dependent `size_of` accounting.
const ARCHIVE_LOCATOR_PUBLICATION_COPIES: u64 = 3;
// `PreparedArchive` retains both manifest structs. Each is then encoded at the
// call site, copied into `StoreHandleBatch`, and finally copied into the
// backend's native atomic batch. Charging the complete encoded key/value for
// all four representations conservatively covers the smaller struct fields.
const ARCHIVE_MANIFEST_PUBLICATION_COPIES: u64 = 4;
// Empty-hint segment frames contain the format header, record key and checksum
// around the payload. A format-regression test below binds this local checked
// preflight constant to `encode_segment_record` without encoding real payloads
// before their budget has been accepted.
const ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES: u64 = 8 + 4 + 1 + 1 + 2 + 32 + 4 + 32;
// Manifests are fixed-width. The same format-regression test binds this value
// to `SegmentManifest::encode` without allocating during production preflight.
const ARCHIVE_MANIFEST_ENCODED_BYTES: usize = 8 + 4 + 8 + 4 + 8 + 32;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrefixScanBudget {
    pub max_entries: usize,
    /// Maximum combined key/value bytes returned in one page.
    pub max_bytes: usize,
}

impl PrefixScanBudget {
    pub fn validate(self) -> Result<Self, StoreError> {
        if !(1..=PREFIX_SCAN_MAX_ENTRIES).contains(&self.max_entries) {
            return Err(StoreError::Schema(format!(
                "prefix scan entry budget must be between 1 and {PREFIX_SCAN_MAX_ENTRIES}"
            )));
        }
        if !(1..=PREFIX_SCAN_MAX_BYTES).contains(&self.max_bytes) {
            return Err(StoreError::Schema(format!(
                "prefix scan byte budget must be between 1 and {PREFIX_SCAN_MAX_BYTES}"
            )));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrefixScanPage {
    pub entries: Vec<ScanEntry>,
    pub returned_bytes: usize,
    /// Exclusive continuation token. Pass this exact key as `start_after` to
    /// resume the same immutable snapshot without duplicates.
    pub continuation: Option<Vec<u8>>,
}

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

/// Return bytes available to an unprivileged writer on the filesystem that
/// contains `path`.
///
/// Capacity-sensitive maintenance must recheck this value immediately before
/// creating output and before its authoritative database publication; a
/// preflight observation is not a reservation.
pub fn filesystem_available_bytes(path: &Path) -> Result<u64, StoreError> {
    fs4::available_space(path).map_err(|error| {
        StoreError::Io(format!(
            "failed to query available filesystem bytes for {}: {error}",
            path.display()
        ))
    })
}

pub const FILESYSTEM_TREE_USAGE_DEFAULT_MAX_ENTRIES: u64 = 10_000_000;
pub const FILESYSTEM_TREE_USAGE_DEFAULT_MAX_DEPTH: u32 = 64;
pub const FILESYSTEM_TREE_USAGE_DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const FILESYSTEM_TREE_USAGE_DEFAULT_MAX_ELAPSED: Duration = Duration::from_secs(30 * 60);

/// Fail-closed envelope for measuring one production data root without
/// following links or silently crossing a mounted filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemTreeUsageLimits {
    pub max_entries: u64,
    pub max_depth: u32,
    pub max_apparent_bytes: u64,
    pub max_allocated_bytes: u64,
    pub deadline: Instant,
}

impl Default for FilesystemTreeUsageLimits {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            max_entries: FILESYSTEM_TREE_USAGE_DEFAULT_MAX_ENTRIES,
            max_depth: FILESYSTEM_TREE_USAGE_DEFAULT_MAX_DEPTH,
            max_apparent_bytes: FILESYSTEM_TREE_USAGE_DEFAULT_MAX_BYTES,
            max_allocated_bytes: FILESYSTEM_TREE_USAGE_DEFAULT_MAX_BYTES,
            deadline: now
                .checked_add(FILESYSTEM_TREE_USAGE_DEFAULT_MAX_ELAPSED)
                .unwrap_or(now),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FilesystemTreeUsage {
    /// Root plus every descendant file or directory inspected.
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub maximum_depth: u32,
    /// Sum of metadata lengths. Directory metadata is deliberately included.
    pub apparent_bytes: u64,
    /// Unix `st_blocks * 512`; apparent bytes on platforms without a safe
    /// standard-library allocated-block query.
    pub allocated_bytes: u64,
}

/// Measure one directory tree with checked arithmetic, an absolute deadline,
/// and no symlink, special-file, or cross-device traversal. For `E` entries
/// and maximum depth `D`, time is `O(E)` and retained traversal memory is
/// `O(D)`; directory contents are never collected into an aggregate vector.
pub fn filesystem_tree_usage_bounded(
    root: &Path,
    limits: FilesystemTreeUsageLimits,
) -> Result<FilesystemTreeUsage, StoreError> {
    if limits.max_entries == 0 {
        return Err(StoreError::Schema(
            "filesystem tree usage entry limit must be nonzero".to_owned(),
        ));
    }
    ensure_filesystem_tree_usage_deadline(limits.deadline)?;
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        StoreError::Io(format!(
            "failed to inspect filesystem usage root {}: {error}",
            root.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::Schema(format!(
            "filesystem usage root {} is a symlink",
            root.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(StoreError::Schema(format!(
            "filesystem usage root {} is not a directory",
            root.display()
        )));
    }
    let root_device = filesystem_metadata_device(&metadata);
    let mut usage = FilesystemTreeUsage::default();
    accumulate_filesystem_tree_usage(root, 0, root_device, limits, &mut usage)?;
    ensure_filesystem_tree_usage_deadline(limits.deadline)?;
    Ok(usage)
}

fn ensure_filesystem_tree_usage_deadline(deadline: Instant) -> Result<(), StoreError> {
    if Instant::now() >= deadline {
        return Err(StoreError::DeadlineExceeded {
            context: "filesystem tree usage",
        });
    }
    Ok(())
}

fn add_filesystem_tree_usage_resource(
    current: u64,
    additional: u64,
    limit: u64,
    context: &'static str,
) -> Result<u64, StoreError> {
    let actual = current.saturating_add(additional);
    if actual > limit {
        return Err(StoreError::LimitExceeded {
            context,
            limit,
            actual,
        });
    }
    Ok(actual)
}

#[cfg(unix)]
fn filesystem_metadata_device(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;

    Some(metadata.dev())
}

#[cfg(not(unix))]
fn filesystem_metadata_device(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

#[cfg(unix)]
fn filesystem_metadata_allocated_bytes(metadata: &std::fs::Metadata) -> Result<u64, StoreError> {
    use std::os::unix::fs::MetadataExt;

    metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| StoreError::Schema("filesystem allocated byte count overflow".to_owned()))
}

#[cfg(not(unix))]
fn filesystem_metadata_allocated_bytes(metadata: &std::fs::Metadata) -> Result<u64, StoreError> {
    Ok(metadata.len())
}

fn accumulate_filesystem_tree_usage(
    path: &Path,
    depth: u32,
    root_device: Option<u64>,
    limits: FilesystemTreeUsageLimits,
    usage: &mut FilesystemTreeUsage,
) -> Result<(), StoreError> {
    ensure_filesystem_tree_usage_deadline(limits.deadline)?;
    if depth > limits.max_depth {
        return Err(StoreError::LimitExceeded {
            context: "filesystem tree usage depth",
            limit: u64::from(limits.max_depth),
            actual: u64::from(depth),
        });
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        StoreError::Io(format!(
            "failed to inspect filesystem entry {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::Schema(format!(
            "refusing symlink in filesystem usage tree {}",
            path.display()
        )));
    }
    if let (Some(expected), Some(actual)) = (root_device, filesystem_metadata_device(&metadata)) {
        if actual != expected {
            return Err(StoreError::Schema(format!(
                "filesystem usage tree crossed devices at {}",
                path.display()
            )));
        }
    }
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(StoreError::Schema(format!(
            "refusing special file in filesystem usage tree {}",
            path.display()
        )));
    }

    usage.entries = add_filesystem_tree_usage_resource(
        usage.entries,
        1,
        limits.max_entries,
        "filesystem tree usage entries",
    )?;
    usage.maximum_depth = usage.maximum_depth.max(depth);
    usage.apparent_bytes = add_filesystem_tree_usage_resource(
        usage.apparent_bytes,
        metadata.len(),
        limits.max_apparent_bytes,
        "filesystem tree apparent bytes",
    )?;
    usage.allocated_bytes = add_filesystem_tree_usage_resource(
        usage.allocated_bytes,
        filesystem_metadata_allocated_bytes(&metadata)?,
        limits.max_allocated_bytes,
        "filesystem tree allocated bytes",
    )?;
    if metadata.is_file() {
        usage.files = usage
            .files
            .checked_add(1)
            .ok_or_else(|| StoreError::Schema("filesystem file count overflow".to_owned()))?;
        return Ok(());
    }
    usage.directories = usage
        .directories
        .checked_add(1)
        .ok_or_else(|| StoreError::Schema("filesystem directory count overflow".to_owned()))?;
    let entries = std::fs::read_dir(path).map_err(|error| {
        StoreError::Io(format!(
            "failed to read filesystem directory {}: {error}",
            path.display()
        ))
    })?;
    for entry in entries {
        ensure_filesystem_tree_usage_deadline(limits.deadline)?;
        let entry = entry.map_err(|error| {
            StoreError::Io(format!(
                "failed to enumerate filesystem directory {}: {error}",
                path.display()
            ))
        })?;
        let child_depth = depth.saturating_add(1);
        accumulate_filesystem_tree_usage(&entry.path(), child_depth, root_device, limits, usage)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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

    /// Read one bounded, ordered page from a prefix range. `start_after` is an
    /// exclusive continuation token previously returned for the same prefix.
    /// Production backends override this with a native iterator. The default
    /// exists for small test snapshots and may internally materialize.
    fn scan_prefix_page(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        budget: PrefixScanBudget,
    ) -> Result<PrefixScanPage, StoreError> {
        paginate_scan_entries(
            self.scan_prefix(family, prefix)?,
            prefix,
            start_after,
            budget,
        )
    }

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

fn validate_prefix_scan_request(
    prefix: &[u8],
    start_after: Option<&[u8]>,
    budget: PrefixScanBudget,
) -> Result<PrefixScanBudget, StoreError> {
    let budget = budget.validate()?;
    if start_after.is_some_and(|cursor| !cursor.starts_with(prefix)) {
        return Err(StoreError::Schema(
            "prefix scan continuation does not belong to the requested prefix".to_owned(),
        ));
    }
    Ok(budget)
}

fn scan_entry_bytes(key: &[u8], value: &[u8]) -> Result<usize, StoreError> {
    key.len()
        .checked_add(value.len())
        .ok_or_else(|| StoreError::Schema("prefix scan entry byte count overflow".to_owned()))
}

fn push_bounded_scan_entry(
    page: &mut PrefixScanPage,
    key: &[u8],
    value: &[u8],
    budget: PrefixScanBudget,
) -> Result<bool, StoreError> {
    if page.entries.len() == budget.max_entries {
        page.continuation = page.entries.last().map(|(key, _)| key.clone());
        return Ok(false);
    }
    let entry_bytes = scan_entry_bytes(key, value)?;
    if entry_bytes > budget.max_bytes {
        return Err(StoreError::LimitExceeded {
            context: "prefix scan page bytes",
            limit: u64::try_from(budget.max_bytes).unwrap_or(u64::MAX),
            actual: u64::try_from(entry_bytes).unwrap_or(u64::MAX),
        });
    }
    let next_bytes = page
        .returned_bytes
        .checked_add(entry_bytes)
        .ok_or_else(|| StoreError::Schema("prefix scan page byte count overflow".to_owned()))?;
    if next_bytes > budget.max_bytes {
        page.continuation = page.entries.last().map(|(key, _)| key.clone());
        return Ok(false);
    }
    page.entries.push((key.to_vec(), value.to_vec()));
    page.returned_bytes = next_bytes;
    Ok(true)
}

fn paginate_scan_entries(
    entries: Vec<ScanEntry>,
    prefix: &[u8],
    start_after: Option<&[u8]>,
    budget: PrefixScanBudget,
) -> Result<PrefixScanPage, StoreError> {
    let budget = validate_prefix_scan_request(prefix, start_after, budget)?;
    let mut page = PrefixScanPage::default();
    for (key, value) in entries {
        if !key.starts_with(prefix) || start_after.is_some_and(|cursor| key.as_slice() <= cursor) {
            continue;
        }
        if !push_bounded_scan_entry(&mut page, &key, &value, budget)? {
            break;
        }
    }
    Ok(page)
}

pub trait WriteBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError>;

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError>;
}

/// One-level reversible boundary used to keep the largest complete prefix of a
/// staged multi-block mutation. Implementations journal only operations written
/// after `begin_checkpoint`; accepted prefixes discard that short journal.
pub trait CheckpointWriteBatch: WriteBatch {
    fn begin_checkpoint(&mut self) -> Result<(), StoreError>;

    fn commit_checkpoint(&mut self) -> Result<(), StoreError>;

    fn rollback_checkpoint(&mut self) -> Result<(), StoreError>;
}

/// The cumulative resource budget shared by a higher-level atomic mutation
/// and the archive transformation performed during its final store commit.
///
/// The store computes one conservative, overflow-safe additional charge from
/// the actual batch while holding the archive publication lock. It invokes
/// [`Self::charge_additional`] exactly once and does not extract payloads,
/// append segment bytes, replace locator values, or add manifest operations
/// unless that call succeeds. Implementations must use saturating cumulative
/// addition, preserve their consumed value on rejection, and return the
/// caller's stable [`StoreError::LimitExceeded`] context.
pub trait AtomicWriteEffectBudget {
    /// Fixed allocation/backend framing allowance charged for each logical
    /// representation of a key/value operation.
    fn operation_framing_bytes(&self) -> u64;

    /// Atomically accept one already-saturated additional effect charge.
    fn charge_additional(&mut self, additional: u64) -> Result<(), StoreError>;
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
type StagedChanges = HashMap<ColumnFamily, BTreeMap<Vec<u8>, Option<Vec<u8>>>>;
type SharedStagedChanges = Rc<RefCell<StagedChanges>>;
type StagedCheckpointEntry = (ColumnFamily, Vec<u8>, Option<Option<Vec<u8>>>);
type StagedCheckpoint = Vec<StagedCheckpointEntry>;
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
            checkpoint: None,
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
            checkpoint: None,
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

    /// Remove and transfer one staged column family without cloning its keys or
    /// values. Callers must finish every read through snapshots backed by this
    /// overlay before consuming the family.
    pub fn take_staged_family(&self, family: ColumnFamily) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        self.changes
            .borrow_mut()
            .remove(&family)
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

        let start = start_after.unwrap_or(prefix).to_vec();
        let mut staged = changes
            .range(start..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .filter(|(key, _)| start_after.is_none_or(|cursor| key.as_slice() > cursor))
            .peekable();
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
                        value.as_ref().map(|value| (key.clone(), value.clone()))
                    })
                }
                std::cmp::Ordering::Greater => staged.next().and_then(|(key, value)| {
                    value.as_ref().map(|value| (key.clone(), value.clone()))
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
    inner: B,
    changes: SharedStagedChanges,
    defer_name_tree_nodes: bool,
    checkpoint: Option<StagedCheckpoint>,
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
        let key = key.to_vec();
        let previous = self
            .changes
            .borrow_mut()
            .entry(family)
            .or_default()
            .insert(key.clone(), Some(value.to_vec()));
        if let Some(checkpoint) = &mut self.checkpoint {
            checkpoint.push((family, key, previous));
        }
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        if !(self.defer_name_tree_nodes && family == ColumnFamily::NameTreeNodes) {
            self.inner.delete(family, key)?;
        }
        let key = key.to_vec();
        let previous = self
            .changes
            .borrow_mut()
            .entry(family)
            .or_default()
            .insert(key.clone(), None);
        if let Some(checkpoint) = &mut self.checkpoint {
            checkpoint.push((family, key, previous));
        }
        Ok(())
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
        self.checkpoint = Some(Vec::new());
        Ok(())
    }

    fn commit_checkpoint(&mut self) -> Result<(), StoreError> {
        if self.checkpoint.is_none() {
            return Err(StoreError::Backend(
                "staged batch checkpoint is not active".to_owned(),
            ));
        }
        self.inner.commit_checkpoint()?;
        self.checkpoint = None;
        Ok(())
    }

    fn rollback_checkpoint(&mut self) -> Result<(), StoreError> {
        if self.checkpoint.is_none() {
            return Err(StoreError::Backend(
                "staged batch checkpoint is not active".to_owned(),
            ));
        }
        self.inner.rollback_checkpoint()?;
        let Some(mut journal) = self.checkpoint.take() else {
            unreachable!("staged checkpoint was checked above");
        };
        let mut changes = self.changes.borrow_mut();
        while let Some((family, key, previous)) = journal.pop() {
            let family_empty = {
                let family_changes = changes.entry(family).or_default();
                match previous {
                    Some(previous) => {
                        family_changes.insert(key, previous);
                    }
                    None => {
                        family_changes.remove(&key);
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
        match snapshot.scan_prefix_page(
            family,
            b"",
            None,
            PrefixScanBudget {
                max_entries: 1,
                max_bytes: SNAPSHOT_EMPTY_PROBE_BYTES,
            },
        ) {
            Ok(page) if !page.entries.is_empty() => return Ok(false),
            Ok(_) => {}
            Err(StoreError::LimitExceeded {
                context: "prefix scan page bytes",
                ..
            }) => {
                // A value larger than the deliberately tiny probe still
                // proves the column family is non-empty.
                return Ok(false);
            }
            Err(error) => return Err(error),
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
        archive_directory: PathBuf,
        database_directory: PathBuf,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SegmentCompactionLimits {
    /// Maximum number of live block/undo locators placed in the final atomic
    /// publication batch.
    pub max_live_records: u64,
    /// Maximum number of live on-disk frame bytes copied into the replacement
    /// generation.
    pub max_live_frame_bytes: u64,
    /// Maximum combined key/locator bytes in the final atomic publication
    /// batch. RocksDB-internal WriteBatch overhead is additional and small.
    pub max_atomic_locator_bytes: u64,
    /// Record and key/value byte bounds for each immutable-snapshot iterator
    /// page used while preparing the rewrite.
    pub scan_page_records: usize,
    pub scan_page_bytes: usize,
}

impl Default for SegmentCompactionLimits {
    fn default() -> Self {
        Self {
            max_live_records: SEGMENT_COMPACTION_DEFAULT_MAX_LIVE_RECORDS,
            max_live_frame_bytes: SEGMENT_COMPACTION_DEFAULT_MAX_LIVE_FRAME_BYTES,
            max_atomic_locator_bytes: SEGMENT_COMPACTION_DEFAULT_MAX_ATOMIC_LOCATOR_BYTES,
            scan_page_records: SEGMENT_COMPACTION_DEFAULT_SCAN_RECORDS,
            scan_page_bytes: SEGMENT_COMPACTION_DEFAULT_SCAN_BYTES,
        }
    }
}

impl SegmentCompactionLimits {
    fn scan_budget(self) -> Result<PrefixScanBudget, StoreError> {
        if self.max_live_records == 0
            || self.max_live_frame_bytes == 0
            || self.max_atomic_locator_bytes == 0
        {
            return Err(StoreError::Schema(
                "segment compaction record and byte budgets must be nonzero".to_owned(),
            ));
        }
        PrefixScanBudget {
            max_entries: self.scan_page_records,
            max_bytes: self.scan_page_bytes,
        }
        .validate()
    }
}

/// Physical, publication, reserve, and absolute time envelope for one segment
/// generation rewrite. The reserve is applied once when the payload archive
/// and RocksDB share a filesystem, or independently to each filesystem when
/// they reside on different mounts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentCompactionExecutionLimits {
    pub max_physical_output_bytes: u64,
    pub max_atomic_publication_bytes: u64,
    pub minimum_filesystem_reserve_bytes: u64,
    pub deadline: Instant,
}

impl Default for SegmentCompactionExecutionLimits {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            max_physical_output_bytes: SEGMENT_COMPACTION_DEFAULT_MAX_PHYSICAL_OUTPUT_BYTES,
            max_atomic_publication_bytes: SEGMENT_COMPACTION_DEFAULT_MAX_ATOMIC_PUBLICATION_BYTES,
            minimum_filesystem_reserve_bytes: SEGMENT_COMPACTION_DEFAULT_FILESYSTEM_RESERVE_BYTES,
            deadline: now
                .checked_add(SEGMENT_COMPACTION_DEFAULT_MAX_ELAPSED)
                .unwrap_or(now),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SegmentArchiveCompactionPlan {
    pub live_records: u64,
    pub live_frame_bytes: u64,
    pub physical_frame_bytes: u64,
    pub reclaimable_frame_bytes: u64,
    pub estimated_atomic_locator_bytes: u64,
    /// Conservative serialized RocksDB WriteBatch size including fixed
    /// per-operation framing and the two manifest replacements.
    pub estimated_atomic_publication_bytes: u64,
    /// Conservative filesystem allowance for WAL plus an equivalent
    /// publication-sized RocksDB staging/flush copy.
    pub estimated_rocks_temporary_bytes: u64,
    /// New segment generation plus RocksDB temporary publication allowance.
    /// The caller-configured persistent reserve is additional.
    pub required_temporary_bytes: u64,
    pub scan_page_records: usize,
    pub scan_page_bytes: usize,
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
    pub scan_pages: u64,
    pub peak_scan_records: usize,
    pub peak_scan_bytes: usize,
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

    /// Whether an atomic database publication returned an error whose durable
    /// outcome can only be resolved by closing and reopening the store.
    pub fn reopen_required(&self) -> bool {
        match self {
            Self::Memory(_) => false,
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => store.reopen_required(),
            Self::Archived { inner, archive, .. } => {
                archive.reopen_required() || inner.reopen_required()
            }
        }
    }

    /// Reject authority-bearing reads, writes, and maintenance after an
    /// ambiguous publication. Reopen constructs fresh backend/archive state
    /// from the database's atomic manifests.
    pub fn ensure_operational(&self) -> Result<(), StoreError> {
        if self.reopen_required() {
            return Err(StoreError::Backend(
                "store publication outcome is uncertain; reopen required".to_owned(),
            ));
        }
        Ok(())
    }

    pub const fn durability_policy(&self) -> DurabilityPolicy {
        match self {
            Self::Memory(_) => DurabilityPolicy::Sync,
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => store.durability,
            Self::Archived { inner, .. } => inner.durability_policy(),
        }
    }

    /// Commit one already-metered atomic mutation while carrying the same
    /// cumulative budget through any payload-archive transformation.
    ///
    /// Memory and non-archived RocksDB handles are transparent and leave the
    /// budget untouched. An archived handle performs and charges a read-only
    /// preflight before moving payload values, appending frames, replacing
    /// locators, or extending the backend batch with its two manifests.
    pub fn commit_with_effect_budget(
        &self,
        batch: StoreHandleBatch,
        budget: &mut impl AtomicWriteEffectBudget,
    ) -> Result<(), StoreError> {
        self.commit_with_optional_effect_budget(batch, Some(budget))
    }

    fn commit_with_optional_effect_budget(
        &self,
        batch: StoreHandleBatch,
        budget: Option<&mut dyn AtomicWriteEffectBudget>,
    ) -> Result<(), StoreError> {
        self.ensure_operational()?;
        match self {
            Self::Memory(store) => commit_memory_store_handle(store, batch),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => commit_rocks_store_handle(store, batch),
            Self::Archived { inner, archive, .. } => {
                commit_archived_store_handle(inner, archive, batch, budget)
            }
        }
    }

    pub fn with_segment_archive(self, directory: PathBuf) -> Result<Self, StoreError> {
        if matches!(self, Self::Archived { .. }) {
            return Err(StoreError::Schema(
                "segment archive is already attached".to_owned(),
            ));
        }
        let mut namespace_archive_registration = self
            .authenticated_namespace_archive_registration()
            .lock()
            .map_err(|_| {
                StoreError::Backend(
                    "authenticated namespace archive registry is poisoned".to_owned(),
                )
            })?;
        if namespace_archive_registration
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some()
        {
            return Err(StoreError::Schema(
                "a live segment archive is already attached to this physical backend".to_owned(),
            ));
        }
        let database_directory = match &self {
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => store.path.clone(),
            Self::Memory(_) => directory.clone(),
            Self::Archived { .. } => unreachable!("archive attachment was rejected above"),
        };
        let snapshot = self.snapshot()?;
        let block = snapshot.get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)?;
        let undo = snapshot.get(ColumnFamily::Snapshots, UNDO_SEGMENT_MANIFEST_KEY)?;
        drop(snapshot);
        let archive_directory = directory.clone();
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
        let archive = Arc::new(archive);
        *namespace_archive_registration = Some(Arc::downgrade(&archive));
        drop(namespace_archive_registration);
        Ok(Self::Archived {
            inner: Box::new(self),
            archive,
            archive_directory,
            database_directory,
        })
    }

    pub fn segment_archive_inventory(&self) -> Result<SegmentArchiveInventory, StoreError> {
        self.ensure_operational()?;
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

    /// Cursor-paged, aggregate-bounded inventory for automatic maintenance due
    /// detection. This performs no filesystem-capacity or publication check.
    pub fn segment_archive_inventory_bounded(
        &self,
        limits: SegmentCompactionLimits,
        deadline: Instant,
    ) -> Result<SegmentArchiveInventory, StoreError> {
        self.ensure_operational()?;
        let scan_budget = limits.scan_budget()?;
        ensure_segment_compaction_deadline(deadline, "segment archive inventory")?;
        let Self::Archived { inner, .. } = self else {
            return Err(StoreError::Schema(
                "bounded segment archive inventory requires an archived store".to_owned(),
            ));
        };
        let snapshot = inner.snapshot()?;
        let execution = SegmentCompactionExecutionLimits {
            max_physical_output_bytes: limits.max_live_frame_bytes,
            max_atomic_publication_bytes: u64::MAX,
            minimum_filesystem_reserve_bytes: 0,
            deadline,
        };
        let mut totals = SegmentCompactionInventoryTotals::default();
        let inventory = SegmentArchiveInventory {
            blocks: segment_family_inventory_bounded(
                &snapshot,
                ColumnFamily::Blocks,
                scan_budget,
                limits,
                execution,
                &mut totals,
            )?,
            undo: segment_family_inventory_bounded(
                &snapshot,
                ColumnFamily::Undo,
                scan_budget,
                limits,
                execution,
                &mut totals,
            )?,
        };
        ensure_segment_compaction_deadline(deadline, "segment archive inventory")?;
        Ok(inventory)
    }

    pub fn scrub_segment_archive(&self) -> Result<SegmentArchiveScrub, StoreError> {
        self.ensure_operational()?;
        let Self::Archived { archive, .. } = self else {
            return Err(StoreError::Schema(
                "segment archive scrub requires an archived store".to_owned(),
            ));
        };
        archive.scrub().map_err(segment_store_error)
    }

    pub fn scrub_segment_archive_bounded(
        &self,
        limits: SegmentArchiveScrubLimits,
    ) -> Result<SegmentArchiveScrub, StoreError> {
        self.ensure_operational()?;
        let Self::Archived { archive, .. } = self else {
            return Err(StoreError::Schema(
                "bounded segment archive scrub requires an archived store".to_owned(),
            ));
        };
        archive
            .scrub_with_limits(limits)
            .map_err(segment_store_error)
    }

    pub fn segment_archive_frame_bytes(&self) -> Result<(u64, u64), StoreError> {
        self.ensure_operational()?;
        let Self::Archived { archive, .. } = self else {
            return Err(StoreError::Schema(
                "segment archive footprint requires an archived store".to_owned(),
            ));
        };
        archive.committed_frame_bytes().map_err(segment_store_error)
    }

    /// Compute and validate the exact record/byte budget for one atomic
    /// generation replacement without reading historical payload bytes.
    pub fn plan_segment_archive_compaction(
        &self,
        limits: SegmentCompactionLimits,
    ) -> Result<SegmentArchiveCompactionPlan, StoreError> {
        self.plan_segment_archive_compaction_with_execution_limits(
            limits,
            SegmentCompactionExecutionLimits::default(),
        )
    }

    /// Capacity- and deadline-qualified compaction plan.
    pub fn plan_segment_archive_compaction_with_execution_limits(
        &self,
        limits: SegmentCompactionLimits,
        execution: SegmentCompactionExecutionLimits,
    ) -> Result<SegmentArchiveCompactionPlan, StoreError> {
        let plan =
            self.inspect_segment_archive_compaction_with_execution_limits(limits, execution)?;
        let Self::Archived {
            archive_directory,
            database_directory,
            ..
        } = self
        else {
            return Err(StoreError::Schema(
                "segment compaction planning requires an archived store".to_owned(),
            ));
        };
        ensure_segment_compaction_filesystem_capacity(
            archive_directory,
            database_directory,
            SegmentCompactionCapacityRequest {
                payload_output_bytes: plan.live_frame_bytes,
                rocks_temporary_bytes: plan.estimated_rocks_temporary_bytes,
                reserve: execution.minimum_filesystem_reserve_bytes,
                shared_context: "segment compaction preflight shared filesystem",
                payload_context: "segment compaction preflight payload filesystem",
                rocks_context: "segment compaction preflight RocksDB filesystem",
            },
        )?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction planning")?;
        Ok(plan)
    }

    /// Read-only bounded footprint inspection for automatic due detection.
    /// Inventory pages, physical segment metadata reads, and all ceiling
    /// checks share the supplied absolute deadline, but filesystem capacity is
    /// deliberately not required until a rewrite is actually due.
    pub fn inspect_segment_archive_compaction_with_execution_limits(
        &self,
        limits: SegmentCompactionLimits,
        execution: SegmentCompactionExecutionLimits,
    ) -> Result<SegmentArchiveCompactionPlan, StoreError> {
        self.ensure_operational()?;
        let scan_budget = limits.scan_budget()?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction planning")?;
        let Self::Archived { inner, archive, .. } = self else {
            return Err(StoreError::Schema(
                "segment compaction planning requires an archived store".to_owned(),
            ));
        };
        let snapshot = inner.snapshot()?;
        let mut running_inventory = SegmentCompactionInventoryTotals::default();
        let inventory = SegmentArchiveInventory {
            blocks: segment_family_inventory_bounded(
                &snapshot,
                ColumnFamily::Blocks,
                scan_budget,
                limits,
                execution,
                &mut running_inventory,
            )?,
            undo: segment_family_inventory_bounded(
                &snapshot,
                ColumnFamily::Undo,
                scan_budget,
                limits,
                execution,
                &mut running_inventory,
            )?,
        };
        drop(snapshot);
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction planning")?;
        let live_records = inventory
            .blocks
            .archived_records
            .checked_add(inventory.undo.archived_records)
            .ok_or_else(|| {
                StoreError::Schema("segment compaction live record count overflow".to_owned())
            })?;
        let live_frame_bytes = inventory
            .blocks
            .archived_frame_bytes
            .checked_add(inventory.undo.archived_frame_bytes)
            .ok_or_else(|| {
                StoreError::Schema("segment compaction live frame byte count overflow".to_owned())
            })?;
        let (block_bytes, undo_bytes) = archive
            .committed_frame_bytes()
            .map_err(segment_store_error)?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction planning")?;
        let physical_frame_bytes = block_bytes.checked_add(undo_bytes).ok_or_else(|| {
            StoreError::Schema("segment compaction physical byte count overflow".to_owned())
        })?;
        let publication = segment_compaction_publication_estimate(live_records)?;
        let required_temporary_bytes = live_frame_bytes
            .checked_add(publication.rocks_temporary_bytes)
            .ok_or_else(|| {
                StoreError::Schema("segment compaction total temporary size overflow".to_owned())
            })?;
        let plan = SegmentArchiveCompactionPlan {
            live_records,
            live_frame_bytes,
            physical_frame_bytes,
            reclaimable_frame_bytes: physical_frame_bytes.saturating_sub(live_frame_bytes),
            estimated_atomic_locator_bytes: publication.atomic_locator_bytes,
            estimated_atomic_publication_bytes: publication.atomic_publication_bytes,
            estimated_rocks_temporary_bytes: publication.rocks_temporary_bytes,
            required_temporary_bytes,
            scan_page_records: limits.scan_page_records,
            scan_page_bytes: limits.scan_page_bytes,
        };
        validate_segment_compaction_plan(plan, limits, execution)?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction planning")?;
        Ok(plan)
    }

    /// Rewrite only live block/undo locators into a fresh segment generation
    /// and atomically publish every replacement locator with both manifests.
    /// The caller must hold exclusive database ownership. Crash recovery uses
    /// the committed manifests to discard either an unpublished new
    /// generation or the superseded old generation.
    pub fn compact_segment_archive(&self) -> Result<SegmentArchiveCompactionReport, StoreError> {
        self.compact_segment_archive_with_limits(SegmentCompactionLimits::default())
    }

    /// Budgeted variant of [`Self::compact_segment_archive`]. Preparation
    /// streams stable snapshot pages with O(page bytes + one payload) working
    /// memory. Final publication remains one atomic locator/manifest batch, so
    /// `max_live_records` and `max_atomic_locator_bytes` bound that necessary
    /// O(live records) commit structure.
    pub fn compact_segment_archive_with_limits(
        &self,
        limits: SegmentCompactionLimits,
    ) -> Result<SegmentArchiveCompactionReport, StoreError> {
        self.compact_segment_archive_with_execution_limits(
            limits,
            SegmentCompactionExecutionLimits::default(),
        )
    }

    /// Execute a rewrite under one absolute deadline, physical/publication
    /// ceilings, and a filesystem reserve. Capacity failures before the
    /// database commit attempt safely delete the unpublished generation and
    /// remain retryable.
    pub fn compact_segment_archive_with_execution_limits(
        &self,
        limits: SegmentCompactionLimits,
        execution: SegmentCompactionExecutionLimits,
    ) -> Result<SegmentArchiveCompactionReport, StoreError> {
        self.ensure_operational()?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction execution")?;
        let Self::Archived {
            inner,
            archive,
            archive_directory,
            database_directory,
        } = self
        else {
            return Err(StoreError::Schema(
                "segment compaction requires an archived store".to_owned(),
            ));
        };
        let plan = self.plan_segment_archive_compaction_with_execution_limits(limits, execution)?;
        let scan_budget = limits.scan_budget()?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction execution")?;
        let (previous_block, previous_undo) = archive.manifests().map_err(segment_store_error)?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction execution")?;
        let snapshot = inner.snapshot()?;

        ensure_segment_compaction_filesystem_capacity(
            archive_directory,
            database_directory,
            SegmentCompactionCapacityRequest {
                payload_output_bytes: plan.live_frame_bytes,
                rocks_temporary_bytes: plan.estimated_rocks_temporary_bytes,
                reserve: execution.minimum_filesystem_reserve_bytes,
                shared_context: "segment compaction before output creation on shared filesystem",
                payload_context: "segment compaction before output creation on payload filesystem",
                rocks_context: "segment compaction before output creation on RocksDB filesystem",
            },
        )?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction execution")?;
        let mut rewrite = archive.begin_rewrite().map_err(segment_store_error)?;
        if let Err(error) =
            ensure_segment_compaction_deadline(execution.deadline, "segment compaction execution")
        {
            drop(snapshot);
            archive
                .abort_rewrite(rewrite)
                .map_err(segment_store_error)?;
            return Err(error);
        }
        let prepared = (|| {
            let mut batch = inner.batch();
            let mut live_records = 0u64;
            let mut live_payload_bytes = 0u64;
            let mut live_frame_bytes = 0u64;
            let mut scan_pages = 0u64;
            let mut peak_scan_records = 0usize;
            let mut peak_scan_bytes = 0usize;
            for (family, kind) in [
                (ColumnFamily::Blocks, SegmentKind::Block),
                (ColumnFamily::Undo, SegmentKind::Undo),
            ] {
                let mut continuation = None::<Vec<u8>>;
                loop {
                    ensure_segment_compaction_deadline(
                        execution.deadline,
                        "segment compaction inventory read",
                    )?;
                    let page = snapshot.scan_prefix_page(
                        family,
                        b"",
                        continuation.as_deref(),
                        scan_budget,
                    )?;
                    ensure_segment_compaction_deadline(
                        execution.deadline,
                        "segment compaction inventory read",
                    )?;
                    validate_segment_scan_page(
                        &page,
                        continuation.as_deref(),
                        scan_budget,
                        "segment compaction inventory read",
                    )?;
                    if !page.entries.is_empty() {
                        scan_pages = scan_pages.checked_add(1).ok_or_else(|| {
                            StoreError::Schema(
                                "segment compaction scan page count overflow".to_owned(),
                            )
                        })?;
                        peak_scan_records = peak_scan_records.max(page.entries.len());
                        peak_scan_bytes = peak_scan_bytes.max(page.returned_bytes);
                    }
                    for (key, raw) in page.entries {
                        ensure_segment_compaction_deadline(
                            execution.deadline,
                            "segment compaction payload read",
                        )?;
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
                        live_frame_bytes = live_frame_bytes
                            .checked_add(u64::from(locator.locator.frame_length))
                            .ok_or_else(|| {
                                StoreError::Schema(
                                    "segment compaction live frame byte count overflow".to_owned(),
                                )
                            })?;
                        ensure_segment_compaction_limit(
                            live_frame_bytes,
                            execution.max_physical_output_bytes,
                            "segment compaction physical output bytes",
                        )?;
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
                        ensure_segment_compaction_deadline(
                            execution.deadline,
                            "segment compaction payload read",
                        )?;
                        live_records = live_records.checked_add(1).ok_or_else(|| {
                            StoreError::Schema(
                                "segment compaction record count overflow".to_owned(),
                            )
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
                        ensure_segment_compaction_limit(
                            live_records,
                            limits.max_live_records,
                            "segment compaction live records",
                        )?;
                        ensure_segment_compaction_deadline(
                            execution.deadline,
                            "segment compaction payload append",
                        )?;
                        let replacement = archive
                            .append_rewrite(&mut rewrite, kind, key_array, payload)
                            .map_err(segment_store_error)?;
                        ensure_segment_compaction_deadline(
                            execution.deadline,
                            "segment compaction payload append",
                        )?;
                        batch.put(family, &key, &replacement.encode())?;
                    }
                    let Some(next) = page.continuation else {
                        break;
                    };
                    if continuation
                        .as_ref()
                        .is_some_and(|previous| next.as_slice() <= previous.as_slice())
                    {
                        return Err(StoreError::Backend(format!(
                            "{} prefix scan continuation did not advance",
                            family.name()
                        )));
                    }
                    continuation = Some(next);
                }
            }
            if live_records != plan.live_records || live_frame_bytes != plan.live_frame_bytes {
                return Err(StoreError::Schema(format!(
                    "segment compaction snapshot changed after preflight: planned {}/{} records/frame-bytes, found {live_records}/{live_frame_bytes}",
                    plan.live_records, plan.live_frame_bytes
                )));
            }
            ensure_segment_compaction_deadline(
                execution.deadline,
                "segment compaction output fsync",
            )?;
            let (block_manifest, undo_manifest, after) = archive
                .finish_rewrite(
                    &mut rewrite,
                    SegmentArchiveScrubLimits {
                        max_segments: SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_SEGMENTS,
                        max_records: limits.max_live_records,
                        max_durable_bytes: execution.max_physical_output_bytes,
                        deadline: execution.deadline,
                    },
                )
                .map_err(segment_store_error)?;
            ensure_segment_compaction_deadline(
                execution.deadline,
                "segment compaction output fsync",
            )?;
            let physical_output_bytes = after
                .blocks
                .durable_bytes
                .checked_add(after.undo.durable_bytes)
                .ok_or_else(|| {
                    StoreError::Schema(
                        "segment compaction physical output byte count overflow".to_owned(),
                    )
                })?;
            ensure_segment_compaction_limit(
                physical_output_bytes,
                execution.max_physical_output_bytes,
                "segment compaction physical output bytes",
            )?;
            if physical_output_bytes != live_frame_bytes {
                return Err(StoreError::Schema(format!(
                    "segment compaction wrote {physical_output_bytes} physical bytes for {live_frame_bytes} planned live frame bytes"
                )));
            }
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
                scan_pages,
                peak_scan_records,
                peak_scan_bytes,
            ))
        })();
        let (
            batch,
            block_manifest,
            undo_manifest,
            after,
            live_records,
            live_payload_bytes,
            scan_pages,
            peak_scan_records,
            peak_scan_bytes,
        ) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                drop(snapshot);
                archive
                    .abort_rewrite(rewrite)
                    .map_err(segment_store_error)?;
                return Err(error);
            }
        };
        drop(snapshot);
        let precommit_check = (|| {
            ensure_segment_compaction_deadline(execution.deadline, "segment compaction precommit")?;
            ensure_segment_compaction_filesystem_capacity(
                archive_directory,
                database_directory,
                SegmentCompactionCapacityRequest {
                    payload_output_bytes: 0,
                    rocks_temporary_bytes: plan.estimated_rocks_temporary_bytes,
                    reserve: execution.minimum_filesystem_reserve_bytes,
                    shared_context: "segment compaction precommit shared filesystem",
                    payload_context: "segment compaction precommit payload filesystem",
                    rocks_context: "segment compaction precommit RocksDB filesystem",
                },
            )?;
            ensure_segment_compaction_deadline(execution.deadline, "segment compaction precommit")
        })();
        if let Err(error) = precommit_check {
            archive
                .abort_rewrite(rewrite)
                .map_err(segment_store_error)?;
            return Err(error);
        }
        if let Err(error) = inner.commit(batch) {
            // Once write_opt has been invoked, an error does not prove that
            // RocksDB rejected the atomic batch. Preserve both generations and
            // fence this process; reopen will select the old or new manifests
            // and remove only the generation they do not reference.
            archive.mark_commit_outcome_uncertain();
            drop(rewrite);
            return Err(StoreError::Backend(format!(
                "segment compaction database publication outcome is uncertain; reopen required: {error}"
            )));
        }
        if Instant::now() >= execution.deadline {
            // Publication succeeded but the in-memory archive has not yet
            // installed the authoritative generation. Preserve both
            // generations and require reopen; this is never a safe deferral.
            archive.mark_commit_outcome_uncertain();
            drop(rewrite);
            return Err(StoreError::Backend(
                "segment compaction deadline elapsed after database publication; reopen required"
                    .to_owned(),
            ));
        }
        // After the atomic database commit the new generation is
        // authoritative. Never delete it on an installation/cleanup error;
        // reopening will select it from the manifests and remove predecessors.
        if let Err(error) = archive.install_rewrite(rewrite) {
            // The locator and manifest batch is already committed. The archive
            // marks every installation/cleanup failure reopen-required so no
            // in-process read or write can observe a partially installed
            // generation.
            archive.mark_commit_outcome_uncertain();
            return Err(StoreError::Backend(format!(
                "segment compaction database publication committed but archive installation is incomplete; reopen required: {error}"
            )));
        }
        if Instant::now() >= execution.deadline {
            archive.mark_commit_outcome_uncertain();
            return Err(StoreError::Backend(
                "segment compaction deadline elapsed after committed archive installation; reopen required"
                    .to_owned(),
            ));
        }

        let before_frame_bytes = plan.physical_frame_bytes;
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
            scan_pages,
            peak_scan_records,
            peak_scan_bytes,
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
        self.ensure_operational()?;
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
        let scan_budget = PrefixScanBudget {
            max_entries: batch_records,
            max_bytes: PREFIX_SCAN_MAX_BYTES,
        }
        .validate()?;
        let mut report = SegmentMigrationReport::default();
        for family in [ColumnFamily::Blocks, ColumnFamily::Undo] {
            for prefix in 0u8..=u8::MAX {
                let snapshot = inner.snapshot()?;
                let mut continuation = None::<Vec<u8>>;
                loop {
                    let page = snapshot.scan_prefix_page(
                        family,
                        &[prefix],
                        continuation.as_deref(),
                        scan_budget,
                    )?;
                    if page.entries.is_empty() && page.continuation.is_some() {
                        return Err(StoreError::Backend(format!(
                            "{} migration prefix scan returned a continuation without progress",
                            family.name()
                        )));
                    }
                    let mut batch = self.batch();
                    let mut staged_records = 0u64;
                    let mut staged_bytes = 0u64;
                    for (key, value) in page.entries {
                        validate_segment_key(family, &key)?;
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
                        batch.put(family, &key, &value)?;
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
                    let Some(next) = page.continuation else {
                        break;
                    };
                    if continuation
                        .as_ref()
                        .is_some_and(|previous| next.as_slice() <= previous.as_slice())
                    {
                        return Err(StoreError::Backend(format!(
                            "{} migration prefix scan continuation did not advance",
                            family.name()
                        )));
                    }
                    continuation = Some(next);
                }
            }
        }
        Ok(report)
    }

    pub fn create_rocks_checkpoint(&self, directory: &Path) -> Result<(), StoreError> {
        self.ensure_operational()?;
        #[cfg(feature = "rocksdb-backend")]
        {
            match self {
                Self::Rocks(store) => store.create_checkpoint(directory),
                Self::Archived { inner, archive, .. } => {
                    let writer = archive.writer().map_err(segment_store_error)?;
                    let result = inner.create_rocks_checkpoint(directory);
                    drop(writer);
                    result
                }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SegmentCompactionPublicationEstimate {
    atomic_locator_bytes: u64,
    atomic_publication_bytes: u64,
    rocks_temporary_bytes: u64,
}

fn segment_compaction_publication_estimate(
    live_records: u64,
) -> Result<SegmentCompactionPublicationEstimate, StoreError> {
    let locator_bytes_per_record = u64::try_from(
        32usize
            .checked_add(SegmentValueLocator::encoded_len())
            .ok_or_else(|| {
                StoreError::Schema(
                    "segment compaction locator publication size overflow".to_owned(),
                )
            })?,
    )
    .map_err(|_| {
        StoreError::Schema("segment compaction locator publication size overflow".to_owned())
    })?;
    let atomic_locator_bytes = live_records
        .checked_mul(locator_bytes_per_record)
        .ok_or_else(|| {
            StoreError::Schema("segment compaction atomic locator byte count overflow".to_owned())
        })?;
    let locator_operation_overhead = live_records
        .checked_mul(SEGMENT_COMPACTION_BATCH_OPERATION_OVERHEAD_BYTES)
        .ok_or_else(|| {
            StoreError::Schema("segment compaction locator operation overhead overflow".to_owned())
        })?;
    let manifest_bytes = u64::try_from(
        SegmentManifest {
            generation: 0,
            active_segment: 0,
            durable_bytes: 0,
        }
        .encode()
        .len(),
    )
    .map_err(|_| StoreError::Schema("segment compaction manifest length overflow".to_owned()))?;
    let manifest_publication_bytes = [
        BLOCK_SEGMENT_MANIFEST_KEY.len(),
        UNDO_SEGMENT_MANIFEST_KEY.len(),
    ]
    .into_iter()
    .try_fold(0u64, |total, key_len| {
        total
            .checked_add(u64::try_from(key_len).map_err(|_| {
                StoreError::Schema("segment compaction manifest key length overflow".to_owned())
            })?)
            .and_then(|value| value.checked_add(manifest_bytes))
            .and_then(|value| value.checked_add(SEGMENT_COMPACTION_BATCH_OPERATION_OVERHEAD_BYTES))
            .ok_or_else(|| {
                StoreError::Schema(
                    "segment compaction manifest publication size overflow".to_owned(),
                )
            })
    })?;
    let atomic_publication_bytes = atomic_locator_bytes
        .checked_add(locator_operation_overhead)
        .and_then(|value| value.checked_add(manifest_publication_bytes))
        .ok_or_else(|| {
            StoreError::Schema("segment compaction atomic publication size overflow".to_owned())
        })?;
    let rocks_temporary_bytes = atomic_publication_bytes
        .checked_mul(SEGMENT_COMPACTION_ROCKS_TEMPORARY_MULTIPLIER)
        .ok_or_else(|| {
            StoreError::Schema("segment compaction RocksDB temporary size overflow".to_owned())
        })?;
    Ok(SegmentCompactionPublicationEstimate {
        atomic_locator_bytes,
        atomic_publication_bytes,
        rocks_temporary_bytes,
    })
}

fn validate_segment_compaction_plan(
    plan: SegmentArchiveCompactionPlan,
    limits: SegmentCompactionLimits,
    execution: SegmentCompactionExecutionLimits,
) -> Result<(), StoreError> {
    ensure_segment_compaction_limit(
        plan.live_records,
        limits.max_live_records,
        "segment compaction live records",
    )?;
    ensure_segment_compaction_limit(
        plan.live_frame_bytes,
        limits.max_live_frame_bytes,
        "segment compaction live frame bytes",
    )?;
    ensure_segment_compaction_limit(
        plan.estimated_atomic_locator_bytes,
        limits.max_atomic_locator_bytes,
        "segment compaction atomic locator bytes",
    )?;
    ensure_segment_compaction_limit(
        plan.live_frame_bytes,
        execution.max_physical_output_bytes,
        "segment compaction physical output bytes",
    )?;
    ensure_segment_compaction_limit(
        plan.estimated_atomic_publication_bytes,
        execution.max_atomic_publication_bytes,
        "segment compaction atomic publication bytes",
    )?;
    Ok(())
}

fn ensure_segment_compaction_limit(
    actual: u64,
    limit: u64,
    context: &'static str,
) -> Result<(), StoreError> {
    if actual > limit {
        return Err(StoreError::LimitExceeded {
            context,
            limit,
            actual,
        });
    }
    Ok(())
}

fn ensure_segment_compaction_deadline(
    deadline: Instant,
    context: &'static str,
) -> Result<(), StoreError> {
    if Instant::now() >= deadline {
        return Err(StoreError::DeadlineExceeded { context });
    }
    Ok(())
}

fn ensure_segment_compaction_capacity(
    available: u64,
    temporary_bytes: u64,
    reserve: u64,
    context: &'static str,
) -> Result<(), StoreError> {
    let required = temporary_bytes.saturating_add(reserve);
    if available < required {
        return Err(StoreError::InsufficientSpace {
            context,
            available,
            required,
            reserve,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SegmentCompactionCapacityRequest {
    payload_output_bytes: u64,
    rocks_temporary_bytes: u64,
    reserve: u64,
    shared_context: &'static str,
    payload_context: &'static str,
    rocks_context: &'static str,
}

fn ensure_segment_compaction_filesystem_capacity(
    archive_directory: &Path,
    database_directory: &Path,
    request: SegmentCompactionCapacityRequest,
) -> Result<(), StoreError> {
    if paths_share_filesystem(archive_directory, database_directory)? {
        let available = filesystem_available_bytes(archive_directory)?;
        return ensure_segment_compaction_capacity_values(true, available, available, request);
    }
    ensure_segment_compaction_capacity_values(
        false,
        filesystem_available_bytes(archive_directory)?,
        filesystem_available_bytes(database_directory)?,
        request,
    )
}

fn ensure_segment_compaction_capacity_values(
    shared_filesystem: bool,
    archive_available: u64,
    database_available: u64,
    request: SegmentCompactionCapacityRequest,
) -> Result<(), StoreError> {
    if shared_filesystem {
        let temporary_bytes = request
            .payload_output_bytes
            .saturating_add(request.rocks_temporary_bytes);
        return ensure_segment_compaction_capacity(
            archive_available,
            temporary_bytes,
            request.reserve,
            request.shared_context,
        );
    }
    ensure_segment_compaction_capacity(
        archive_available,
        request.payload_output_bytes,
        request.reserve,
        request.payload_context,
    )?;
    ensure_segment_compaction_capacity(
        database_available,
        request.rocks_temporary_bytes,
        request.reserve,
        request.rocks_context,
    )
}

fn paths_share_filesystem(left: &Path, right: &Path) -> Result<bool, StoreError> {
    let left_canonical = std::fs::canonicalize(left).map_err(|error| {
        StoreError::Io(format!(
            "failed to resolve filesystem path {}: {error}",
            left.display()
        ))
    })?;
    let right_canonical = std::fs::canonicalize(right).map_err(|error| {
        StoreError::Io(format!(
            "failed to resolve filesystem path {}: {error}",
            right.display()
        ))
    })?;
    if left_canonical == right_canonical {
        return Ok(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let left_metadata = std::fs::metadata(&left_canonical).map_err(|error| {
            StoreError::Io(format!(
                "failed to inspect filesystem path {}: {error}",
                left_canonical.display()
            ))
        })?;
        let right_metadata = std::fs::metadata(&right_canonical).map_err(|error| {
            StoreError::Io(format!(
                "failed to inspect filesystem path {}: {error}",
                right_canonical.display()
            ))
        })?;
        Ok(left_metadata.dev() == right_metadata.dev())
    }

    #[cfg(windows)]
    {
        use std::path::Component;

        let left_prefix = left_canonical
            .components()
            .find_map(|component| match component {
                Component::Prefix(prefix) => Some(prefix.as_os_str().to_owned()),
                _ => None,
            });
        let right_prefix = right_canonical
            .components()
            .find_map(|component| match component {
                Component::Prefix(prefix) => Some(prefix.as_os_str().to_owned()),
                _ => None,
            });
        Ok(left_prefix.is_some() && left_prefix == right_prefix)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(false)
    }
}

fn validate_segment_scan_page(
    page: &PrefixScanPage,
    start_after: Option<&[u8]>,
    budget: PrefixScanBudget,
    context: &'static str,
) -> Result<(), StoreError> {
    if page.entries.len() > budget.max_entries {
        return Err(StoreError::LimitExceeded {
            context,
            limit: u64::try_from(budget.max_entries).unwrap_or(u64::MAX),
            actual: u64::try_from(page.entries.len()).unwrap_or(u64::MAX),
        });
    }
    let mut returned_bytes = 0usize;
    let mut previous = start_after;
    for (key, value) in &page.entries {
        if previous.is_some_and(|cursor| key.as_slice() <= cursor) {
            return Err(StoreError::Backend(format!(
                "{context} returned non-increasing keys"
            )));
        }
        returned_bytes = returned_bytes
            .checked_add(scan_entry_bytes(key, value)?)
            .ok_or_else(|| StoreError::Schema(format!("{context} byte count overflow")))?;
        previous = Some(key);
    }
    if returned_bytes != page.returned_bytes {
        return Err(StoreError::Backend(format!(
            "{context} reported {} bytes for {returned_bytes} returned bytes",
            page.returned_bytes
        )));
    }
    if returned_bytes > budget.max_bytes {
        return Err(StoreError::LimitExceeded {
            context,
            limit: u64::try_from(budget.max_bytes).unwrap_or(u64::MAX),
            actual: u64::try_from(returned_bytes).unwrap_or(u64::MAX),
        });
    }
    if let Some(continuation) = &page.continuation {
        let Some((last_key, _)) = page.entries.last() else {
            return Err(StoreError::Backend(format!(
                "{context} returned a continuation without progress"
            )));
        };
        if continuation != last_key {
            return Err(StoreError::Backend(format!(
                "{context} continuation does not equal its last returned key"
            )));
        }
        if start_after.is_some_and(|cursor| continuation.as_slice() <= cursor) {
            return Err(StoreError::Backend(format!(
                "{context} continuation did not advance"
            )));
        }
    }
    Ok(())
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
        accumulate_segment_inventory(&mut inventory, family, key, value).map(|_| ())
    })?;
    Ok(inventory)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SegmentCompactionInventoryTotals {
    live_records: u64,
    live_frame_bytes: u64,
}

fn segment_family_inventory_bounded<S: ReadSnapshot>(
    snapshot: &S,
    family: ColumnFamily,
    budget: PrefixScanBudget,
    limits: SegmentCompactionLimits,
    execution: SegmentCompactionExecutionLimits,
    totals: &mut SegmentCompactionInventoryTotals,
) -> Result<SegmentFamilyInventory, StoreError> {
    let mut inventory = SegmentFamilyInventory::default();
    let mut continuation = None::<Vec<u8>>;
    loop {
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction inventory")?;
        let page = snapshot.scan_prefix_page(family, b"", continuation.as_deref(), budget)?;
        ensure_segment_compaction_deadline(execution.deadline, "segment compaction inventory")?;
        validate_segment_scan_page(
            &page,
            continuation.as_deref(),
            budget,
            "segment compaction inventory",
        )?;
        let next = page.continuation.clone();
        for (key, value) in page.entries {
            ensure_segment_compaction_deadline(execution.deadline, "segment compaction inventory")?;
            if let Some(locator) =
                accumulate_segment_inventory(&mut inventory, family, &key, &value)?
            {
                totals.live_records = totals.live_records.checked_add(1).ok_or_else(|| {
                    StoreError::Schema(
                        "segment compaction inventory record count overflow".to_owned(),
                    )
                })?;
                totals.live_frame_bytes = totals
                    .live_frame_bytes
                    .checked_add(u64::from(locator.locator.frame_length))
                    .ok_or_else(|| {
                        StoreError::Schema(
                            "segment compaction inventory frame byte count overflow".to_owned(),
                        )
                    })?;
                ensure_segment_compaction_limit(
                    totals.live_records,
                    limits.max_live_records,
                    "segment compaction live records",
                )?;
                ensure_segment_compaction_limit(
                    totals.live_frame_bytes,
                    limits.max_live_frame_bytes,
                    "segment compaction live frame bytes",
                )?;
                ensure_segment_compaction_limit(
                    totals.live_frame_bytes,
                    execution.max_physical_output_bytes,
                    "segment compaction physical output bytes",
                )?;
                let publication = segment_compaction_publication_estimate(totals.live_records)?;
                ensure_segment_compaction_limit(
                    publication.atomic_locator_bytes,
                    limits.max_atomic_locator_bytes,
                    "segment compaction atomic locator bytes",
                )?;
                ensure_segment_compaction_limit(
                    publication.atomic_publication_bytes,
                    execution.max_atomic_publication_bytes,
                    "segment compaction atomic publication bytes",
                )?;
            }
        }
        let Some(next) = next else {
            break;
        };
        continuation = Some(next);
    }
    Ok(inventory)
}

fn accumulate_segment_inventory(
    inventory: &mut SegmentFamilyInventory,
    family: ColumnFamily,
    key: &[u8],
    value: &[u8],
) -> Result<Option<SegmentValueLocator>, StoreError> {
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
                .checked_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    StoreError::Schema("segment inventory locator bytes overflow".to_owned())
                })?;
            Ok(Some(locator))
        }
        None => {
            inventory.inline_records =
                inventory.inline_records.checked_add(1).ok_or_else(|| {
                    StoreError::Schema("segment inventory record count overflow".to_owned())
                })?;
            inventory.inline_bytes = inventory
                .inline_bytes
                .checked_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    StoreError::Schema("segment inventory inline bytes overflow".to_owned())
                })?;
            Ok(None)
        }
    }
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
        self.ensure_operational()?;
        match self {
            Self::Memory(store) => store
                .snapshot()
                .map(|snapshot| StoreHandleSnapshot::Memory(snapshot, PhantomData)),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => store.snapshot().map(StoreHandleSnapshot::Rocks),
            Self::Archived { inner, archive, .. } => {
                // Linearize snapshot creation with segment publication. The
                // guard is released immediately; the backend snapshot itself
                // remains immutable and archive reads re-check the fence.
                let writer = archive.writer().map_err(segment_store_error)?;
                let snapshot = inner.snapshot()?;
                drop(writer);
                Ok(StoreHandleSnapshot::Archived(
                    Box::new(snapshot),
                    Arc::clone(archive),
                ))
            }
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
        self.commit_with_optional_effect_budget(batch, None)
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
    budget: Option<&mut dyn AtomicWriteEffectBudget>,
) -> Result<(), StoreError> {
    // Serialize every database publication, including metadata-only batches,
    // with external segment publication. Once a payload commit fences the
    // archive, no later batch can slip through the inner backend.
    let mut writer = archive.writer().map_err(segment_store_error)?;
    let operation_framing_bytes = budget
        .as_ref()
        .map(|budget| budget.operation_framing_bytes());
    let effects = batch.archive_commit_effects(operation_framing_bytes)?;
    if effects.payloads == 0 {
        return inner.commit(batch);
    }
    if let Some(budget) = budget {
        budget.charge_additional(effects.total())?;
    }
    let mut payloads = batch.take_archive_payloads(effects.payloads)?;
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
        // The database may have atomically installed the locators/manifests
        // even though the write returned an error. Rolling the synced segment
        // tail back here could therefore destroy committed state. Retain the
        // bytes, poison this archive instance, and let reopen choose old or new
        // state from the database manifests.
        archive.mark_commit_outcome_uncertain();
        drop(writer);
        return Err(StoreError::Backend(format!(
            "segment publication database outcome is uncertain; reopen required: {error}"
        )));
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

    fn scan_prefix_page(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        budget: PrefixScanBudget,
    ) -> Result<PrefixScanPage, StoreError> {
        match self {
            Self::Memory(snapshot, _) => {
                snapshot.scan_prefix_page(family, prefix, start_after, budget)
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(snapshot) => snapshot.scan_prefix_page(family, prefix, start_after, budget),
            Self::Archived(snapshot, _) if segmented_kind(family).is_none() => {
                snapshot.scan_prefix_page(family, prefix, start_after, budget)
            }
            Self::Archived(snapshot, archive) => {
                let budget = validate_prefix_scan_request(prefix, start_after, budget)?;
                let raw = snapshot.scan_prefix_page(family, prefix, start_after, budget)?;
                let mut page = PrefixScanPage::default();
                for (key, value) in raw.entries {
                    let value = resolve_segmented_value(archive, family, &key, value)?;
                    if !push_bounded_scan_entry(&mut page, &key, &value, budget)? {
                        return Ok(page);
                    }
                }
                page.continuation = raw.continuation;
                Ok(page)
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ArchiveCommitEffects {
    payloads: usize,
    extracted_payload_bytes: u64,
    framed_segment_bytes: u64,
    locator_publication_bytes: u64,
    manifest_publication_bytes: u64,
}

impl ArchiveCommitEffects {
    fn total(self) -> u64 {
        self.extracted_payload_bytes
            .saturating_add(self.framed_segment_bytes)
            .saturating_add(self.locator_publication_bytes)
            .saturating_add(self.manifest_publication_bytes)
    }

    fn add_payload(
        &mut self,
        key_bytes: usize,
        payload_bytes: usize,
        operation_framing_bytes: u64,
    ) -> Result<(), StoreError> {
        self.payloads = self
            .payloads
            .checked_add(1)
            .ok_or_else(|| StoreError::Schema("archive payload count overflow".to_owned()))?;
        self.extracted_payload_bytes =
            self.extracted_payload_bytes
                .saturating_add(atomic_write_operation_charge(
                    key_bytes,
                    payload_bytes,
                    operation_framing_bytes,
                    ARCHIVE_EXTRACTED_PAYLOAD_COPIES,
                ));
        let frame_bytes = u64::try_from(payload_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES);
        self.framed_segment_bytes =
            self.framed_segment_bytes
                .saturating_add(atomic_write_operation_charge_u64(
                    0,
                    frame_bytes,
                    operation_framing_bytes,
                    ARCHIVE_FRAME_COPIES,
                ));
        self.locator_publication_bytes =
            self.locator_publication_bytes
                .saturating_add(atomic_write_operation_charge(
                    key_bytes,
                    SegmentValueLocator::encoded_len(),
                    operation_framing_bytes,
                    ARCHIVE_LOCATOR_PUBLICATION_COPIES,
                ));
        Ok(())
    }

    fn add_manifests(&mut self, operation_framing_bytes: u64) {
        // Segment manifests have a fixed encoding. Keep the calculation local
        // to the store format and bind it to `SegmentManifest::encode` in the
        // regression test so production preflight does not allocate even a
        // dummy encoding before the budget decision.
        for key in [BLOCK_SEGMENT_MANIFEST_KEY, UNDO_SEGMENT_MANIFEST_KEY] {
            self.manifest_publication_bytes =
                self.manifest_publication_bytes
                    .saturating_add(atomic_write_operation_charge(
                        key.len(),
                        ARCHIVE_MANIFEST_ENCODED_BYTES,
                        operation_framing_bytes,
                        ARCHIVE_MANIFEST_PUBLICATION_COPIES,
                    ));
        }
    }
}

fn atomic_write_operation_charge(
    key_bytes: usize,
    value_bytes: usize,
    operation_framing_bytes: u64,
    copies: u64,
) -> u64 {
    atomic_write_operation_charge_u64(
        u64::try_from(key_bytes).unwrap_or(u64::MAX),
        u64::try_from(value_bytes).unwrap_or(u64::MAX),
        operation_framing_bytes,
        copies,
    )
}

fn atomic_write_operation_charge_u64(
    key_bytes: u64,
    value_bytes: u64,
    operation_framing_bytes: u64,
    copies: u64,
) -> u64 {
    key_bytes
        .saturating_add(value_bytes)
        .saturating_add(operation_framing_bytes)
        .saturating_mul(copies)
}

impl StoreHandleBatch {
    fn archive_commit_effects(
        &self,
        operation_framing_bytes: Option<u64>,
    ) -> Result<ArchiveCommitEffects, StoreError> {
        let mut effects = ArchiveCommitEffects::default();
        let framing = operation_framing_bytes.unwrap_or(0);
        self.visit_archive_payloads(&mut |_, key, value| {
            effects.add_payload(key.len(), value.len(), framing)
        })?;
        if effects.payloads != 0 && operation_framing_bytes.is_some() {
            effects.add_manifests(framing);
        }
        Ok(effects)
    }

    fn visit_archive_payloads(
        &self,
        visitor: &mut impl FnMut(ColumnFamily, &[u8], &[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        match self {
            Self::Memory(batch) => {
                for (key, value) in &batch.operations {
                    let Some(value) = value else {
                        continue;
                    };
                    visit_archive_payload(key.family, &key.key, value, visitor)?;
                }
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => {
                for (key, value) in &batch.operations {
                    let Some(value) = value else {
                        continue;
                    };
                    visit_archive_payload(key.family, &key.key, value, visitor)?;
                }
            }
        }
        Ok(())
    }

    fn take_archive_payloads(
        &mut self,
        expected_payloads: usize,
    ) -> Result<Vec<segment::ArchivePayload>, StoreError> {
        let mut payloads = Vec::with_capacity(expected_payloads);
        match self {
            Self::Memory(batch) => {
                for (key, value) in &mut batch.operations {
                    let Some(value) = value else {
                        continue;
                    };
                    collect_archive_payload(key.family, &key.key, value, &mut payloads)?;
                }
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => {
                for (key, value) in &mut batch.operations {
                    let Some(value) = value else {
                        continue;
                    };
                    collect_archive_payload(key.family, &key.key, value, &mut payloads)?;
                }
            }
        }
        if payloads.len() != expected_payloads {
            return Err(StoreError::Backend(format!(
                "archive payload preflight counted {expected_payloads} values but extraction found {}",
                payloads.len()
            )));
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
                for (key, value) in &mut batch.operations {
                    let Some(value) = value else {
                        continue;
                    };
                    replace_archive_payload(key.family, value, &mut locators)?;
                }
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => {
                for (key, value) in &mut batch.operations {
                    let Some(value) = value else {
                        continue;
                    };
                    replace_archive_payload(key.family, value, &mut locators)?;
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

fn visit_archive_payload(
    family: ColumnFamily,
    key: &[u8],
    value: &[u8],
    visitor: &mut impl FnMut(ColumnFamily, &[u8], &[u8]) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    if segmented_kind(family).is_none()
        || SegmentValueLocator::decode(value)
            .map_err(segment_store_error)?
            .is_some()
    {
        return Ok(());
    }
    validate_segment_key(family, key)?;
    visitor(family, key, value)
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

impl CheckpointWriteBatch for StoreHandleBatch {
    fn begin_checkpoint(&mut self) -> Result<(), StoreError> {
        match self {
            Self::Memory(batch) => batch.begin_checkpoint(),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => batch.begin_checkpoint(),
        }
    }

    fn commit_checkpoint(&mut self) -> Result<(), StoreError> {
        match self {
            Self::Memory(batch) => batch.commit_checkpoint(),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => batch.commit_checkpoint(),
        }
    }

    fn rollback_checkpoint(&mut self) -> Result<(), StoreError> {
        match self {
            Self::Memory(batch) => batch.rollback_checkpoint(),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(batch) => batch.rollback_checkpoint(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    inner: Arc<RwLock<MemoryStoreState>>,
    authenticated_namespaces: authenticated_namespace::SharedNamespaceOwners,
    authenticated_namespace_archive: authenticated_namespace::SharedNamespaceArchiveRegistration,
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
        let generation = {
            let mut state = self
                .inner
                .write()
                .map_err(|_| StoreError::Io("memory store write lock poisoned".to_owned()))?;
            let generation = state.generation;
            let active = state.active_snapshots.entry(generation).or_default();
            *active = active.saturating_add(1);
            generation
        };
        Ok(MemorySnapshot {
            inner: Arc::clone(&self.inner),
            generation,
            lease: Arc::new(MemorySnapshotLease {
                generation,
                inner: Arc::downgrade(&self.inner),
            }),
        })
    }

    fn batch(&self) -> Self::Batch {
        MemoryBatch::default()
    }

    fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
        let changes = batch.operations;
        if changes.is_empty() {
            return Ok(());
        }

        for key in changes.keys() {
            authenticated_namespace::ensure_ordinary_key(key.family, &key.key)?;
        }

        let mut state = self
            .inner
            .write()
            .map_err(|_| StoreError::Io("memory store write lock poisoned".to_owned()))?;
        apply_memory_changes(&mut state, changes)
    }
}

fn apply_memory_changes(
    state: &mut MemoryStoreState,
    changes: BatchOperations,
) -> Result<(), StoreError> {
    if changes.is_empty() {
        return Ok(());
    }
    let generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| StoreError::Schema("memory store generation exhausted".to_owned()))?;
    let oldest_snapshot = state
        .active_snapshots
        .first_key_value()
        .map(|(value, _)| *value);
    let change_count = changes.len();
    let mut gc_candidates = Vec::with_capacity(change_count);

    for (key, value) in changes {
        if oldest_snapshot.is_none() {
            match value {
                Some(value) => {
                    state.data.insert(
                        key,
                        vec![MemoryVersion {
                            generation,
                            value: Some(value),
                        }],
                    );
                }
                None => {
                    state.data.remove(&key);
                }
            }
            continue;
        }
        let history = state.data.entry(key.clone()).or_default();
        compact_memory_history(history, oldest_snapshot);
        history.push(MemoryVersion { generation, value });
        gc_candidates.push(key);
    }
    state.generation = generation;
    state.gc_candidates.extend(gc_candidates);
    let gc_budget = change_count.saturating_add(64);
    let pending_gc = (0..gc_budget)
        .filter_map(|_| state.gc_candidates.pop_first())
        .collect::<Vec<_>>();
    for key in pending_gc {
        let remove = state.data.get_mut(&key).is_some_and(|history| {
            compact_memory_history(history, oldest_snapshot);
            history.is_empty()
        });
        if remove {
            state.data.remove(&key);
        } else if state.data.get(&key).is_some_and(|history| {
            history.len() > 1
                || history
                    .last()
                    .is_some_and(|version| version.value.is_none())
        }) {
            state.gc_candidates.insert(key);
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct MemorySnapshot {
    inner: Arc<RwLock<MemoryStoreState>>,
    generation: u64,
    #[allow(dead_code)]
    lease: Arc<MemorySnapshotLease>,
}

impl ReadSnapshot for MemorySnapshot {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let state = self
            .inner
            .read()
            .map_err(|_| StoreError::Io("memory store read lock poisoned".to_owned()))?;
        Ok(state
            .data
            .get(&StoreKey::new(family, key))
            .and_then(|history| memory_value_at(history, self.generation))
            .cloned())
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let state = self
            .inner
            .read()
            .map_err(|_| StoreError::Io("memory store read lock poisoned".to_owned()))?;
        Ok(keys
            .iter()
            .map(|key| {
                state
                    .data
                    .get(&StoreKey::new(family, key))
                    .and_then(|history| memory_value_at(history, self.generation))
                    .cloned()
            })
            .collect())
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        let state = self
            .inner
            .read()
            .map_err(|_| StoreError::Io("memory store read lock poisoned".to_owned()))?;
        let mut entries = Vec::new();
        for (key, history) in state.data.range(StoreKey::new(family, prefix)..) {
            if key.family != family || !key.key.starts_with(prefix) {
                break;
            }
            if let Some(value) = memory_value_at(history, self.generation) {
                entries.push((key.key.clone(), value.clone()));
            }
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
        let state = self
            .inner
            .read()
            .map_err(|_| StoreError::Io("memory store read lock poisoned".to_owned()))?;
        let start = start_after.unwrap_or(prefix);
        let mut page = PrefixScanPage::default();
        for (key, history) in state.data.range(StoreKey::new(family, start)..) {
            if key.family != family || !key.key.starts_with(prefix) {
                break;
            }
            if start_after.is_some_and(|cursor| key.key.as_slice() <= cursor) {
                continue;
            }
            let Some(value) = memory_value_at(history, self.generation) else {
                continue;
            };
            if !push_bounded_scan_entry(&mut page, &key.key, value, budget)? {
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
        // A visitor may commit bounded work back to the same store. Copy one
        // bounded immutable page at a time so no callback executes while the
        // memory store's read lock is held.
        let budget = PrefixScanBudget {
            max_entries: PREFIX_SCAN_MAX_ENTRIES,
            max_bytes: PREFIX_SCAN_MAX_BYTES,
        };
        let mut continuation = None::<Vec<u8>>;
        loop {
            let page = self.scan_prefix_page(family, prefix, continuation.as_deref(), budget)?;
            for (key, value) in page.entries {
                visitor(&key, &value)?;
            }
            let Some(next) = page.continuation else {
                break;
            };
            if continuation
                .as_ref()
                .is_some_and(|current| current.as_slice() >= next.as_slice())
            {
                return Err(StoreError::Backend(
                    "prefix page continuation did not advance".to_owned(),
                ));
            }
            continuation = Some(next);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct MemoryVersion {
    generation: u64,
    value: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct MemoryStoreState {
    generation: u64,
    data: BTreeMap<StoreKey, Vec<MemoryVersion>>,
    active_snapshots: BTreeMap<u64, usize>,
    gc_candidates: BTreeSet<StoreKey>,
}

#[derive(Debug)]
struct MemorySnapshotLease {
    generation: u64,
    inner: Weak<RwLock<MemoryStoreState>>,
}

impl Drop for MemorySnapshotLease {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut state = inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove = state
            .active_snapshots
            .get_mut(&self.generation)
            .is_some_and(|active| {
                *active = active.saturating_sub(1);
                *active == 0
            });
        if remove {
            state.active_snapshots.remove(&self.generation);
        }
    }
}

fn memory_value_at(history: &[MemoryVersion], generation: u64) -> Option<&Vec<u8>> {
    let end = history.partition_point(|version| version.generation <= generation);
    end.checked_sub(1)
        .and_then(|index| history.get(index))
        .and_then(|version| version.value.as_ref())
}

fn compact_memory_history(history: &mut Vec<MemoryVersion>, oldest_snapshot: Option<u64>) {
    let Some(oldest_snapshot) = oldest_snapshot else {
        let latest = history.pop();
        history.clear();
        if let Some(latest) = latest.filter(|version| version.value.is_some()) {
            history.push(latest);
        }
        return;
    };
    let baseline_end = history.partition_point(|version| version.generation <= oldest_snapshot);
    if baseline_end > 1 {
        history.drain(..baseline_end - 1);
    }
    if history
        .last()
        .is_some_and(|version| version.generation <= oldest_snapshot && version.value.is_none())
    {
        history.clear();
    }
}

type BatchOperation = Option<Vec<u8>>;
type BatchOperations = BTreeMap<StoreKey, BatchOperation>;
type BatchCheckpointEntry = (StoreKey, Option<BatchOperation>);
type BatchCheckpoint = Vec<BatchCheckpointEntry>;

#[derive(Clone, Debug, Default)]
pub struct MemoryBatch {
    operations: BatchOperations,
    checkpoint: Option<BatchCheckpoint>,
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
        authenticated_namespace::ensure_ordinary_key(family, key)?;
        replace_batch_operation(
            &mut self.operations,
            &mut self.checkpoint,
            StoreKey::new(family, key),
            Some(value.to_vec()),
        );
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        authenticated_namespace::ensure_ordinary_key(family, key)?;
        replace_batch_operation(
            &mut self.operations,
            &mut self.checkpoint,
            StoreKey::new(family, key),
            None,
        );
        Ok(())
    }
}

impl CheckpointWriteBatch for MemoryBatch {
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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

fn replace_batch_operation(
    operations: &mut BatchOperations,
    checkpoint: &mut Option<BatchCheckpoint>,
    key: StoreKey,
    value: BatchOperation,
) {
    let previous = operations.insert(key.clone(), value);
    if let Some(journal) = checkpoint {
        journal.push((key, previous));
    }
}

fn begin_batch_checkpoint(checkpoint: &mut Option<BatchCheckpoint>) -> Result<(), StoreError> {
    if checkpoint.is_some() {
        return Err(StoreError::Backend(
            "write batch checkpoint is already active".to_owned(),
        ));
    }
    *checkpoint = Some(Vec::new());
    Ok(())
}

fn commit_batch_checkpoint(checkpoint: &mut Option<BatchCheckpoint>) -> Result<(), StoreError> {
    if checkpoint.take().is_none() {
        return Err(StoreError::Backend(
            "write batch checkpoint is not active".to_owned(),
        ));
    }
    Ok(())
}

fn rollback_batch_checkpoint(
    operations: &mut BatchOperations,
    checkpoint: &mut Option<BatchCheckpoint>,
) -> Result<(), StoreError> {
    let Some(mut journal) = checkpoint.take() else {
        return Err(StoreError::Backend(
            "write batch checkpoint is not active".to_owned(),
        ));
    };
    while let Some((key, previous)) = journal.pop() {
        match previous {
            Some(previous) => {
                operations.insert(key, previous);
            }
            None => {
                operations.remove(&key);
            }
        }
    }
    Ok(())
}

#[cfg(feature = "rocksdb-backend")]
#[derive(Clone)]
pub struct RocksStore {
    db: Arc<rocksdb::DB>,
    path: PathBuf,
    durability: DurabilityPolicy,
    // Keep both shared caches alive for exactly as long as the DB. Separating
    // large, mostly one-pass block/undo pages prevents them from evicting hot
    // UTXO, name-state, and Urkel point-lookup pages.
    point_cache: rocksdb::Cache,
    bulk_cache: rocksdb::Cache,
    reopen_required: Arc<AtomicBool>,
    /// Linearizes snapshot creation and atomic publication without holding a
    /// lock for the snapshot's subsequent reads.
    publication_lock: Arc<Mutex<()>>,
    authenticated_namespaces: authenticated_namespace::SharedNamespaceOwners,
    authenticated_namespace_archive: authenticated_namespace::SharedNamespaceArchiveRegistration,
    #[cfg(test)]
    commit_fault: Arc<AtomicU8>,
}

#[cfg(feature = "rocksdb-backend")]
impl fmt::Debug for RocksStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RocksStore")
            .field("durability", &self.durability)
            .field("point_cache_usage", &self.point_cache.get_usage())
            .field("bulk_cache_usage", &self.bulk_cache.get_usage())
            .field("reopen_required", &self.reopen_required())
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

        let path = path.as_ref().to_path_buf();
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

        let db = rocksdb::DB::open_cf_descriptors(&db_options, &path, descriptors)
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            path,
            durability,
            point_cache,
            bulk_cache,
            reopen_required: Arc::new(AtomicBool::new(false)),
            publication_lock: Arc::new(Mutex::new(())),
            authenticated_namespaces: Arc::new(Mutex::new(BTreeMap::new())),
            authenticated_namespace_archive: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            commit_fault: Arc::new(AtomicU8::new(RocksCommitFault::None as u8)),
        })
    }

    pub fn create_checkpoint(&self, path: impl AsRef<Path>) -> Result<(), StoreError> {
        let _publication = self.lock_publication()?;
        self.ensure_operational()?;
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        checkpoint
            .create_checkpoint(path)
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    pub fn reopen_required(&self) -> bool {
        if self.publication_lock.is_poisoned() {
            self.mark_commit_outcome_uncertain();
        }
        self.reopen_required.load(Ordering::Acquire)
    }

    fn ensure_operational(&self) -> Result<(), StoreError> {
        if self.reopen_required() {
            return Err(StoreError::Backend(
                "RocksDB publication outcome is uncertain; reopen required".to_owned(),
            ));
        }
        Ok(())
    }

    fn lock_publication(&self) -> Result<std::sync::MutexGuard<'_, ()>, StoreError> {
        match self.publication_lock.lock() {
            Ok(publication) => Ok(publication),
            Err(_) => {
                // The panicking thread may have crossed write_opt before
                // unwinding. Every clone must report the same fail-stop state.
                self.mark_commit_outcome_uncertain();
                Err(StoreError::Backend(
                    "RocksDB publication lock is poisoned; reopen required".to_owned(),
                ))
            }
        }
    }

    fn mark_commit_outcome_uncertain(&self) {
        self.reopen_required.store(true, Ordering::Release);
    }

    fn cf(db: &rocksdb::DB, family: ColumnFamily) -> Result<&rocksdb::ColumnFamily, StoreError> {
        db.cf_handle(family.name())
            .ok_or_else(|| StoreError::MissingColumnFamily(family.name()))
    }

    #[cfg(test)]
    fn inject_next_commit_fault(&self, fault: RocksCommitFault) {
        self.commit_fault.store(fault as u8, Ordering::Release);
    }

    #[cfg(test)]
    fn take_commit_fault(&self) -> RocksCommitFault {
        match self.commit_fault.swap(0, Ordering::AcqRel) {
            1 => RocksCommitFault::BeforeWrite,
            2 => RocksCommitFault::AfterWrite,
            _ => RocksCommitFault::None,
        }
    }

    /// Publish already validated operations while the caller retains the
    /// backend's publication lock. Namespace CAS uses this private path so its
    /// live reads, fence comparison, and write form one critical section.
    fn commit_operations_locked(&self, operations: BatchOperations) -> Result<(), StoreError> {
        let mut write_batch = rocksdb::WriteBatch::default();
        for (key, value) in operations {
            let cf = Self::cf(&self.db, key.family)?;
            match value {
                Some(value) => write_batch.put_cf(cf, key.key, value),
                None => write_batch.delete_cf(cf, key.key),
            }
        }

        let mut options = rocksdb::WriteOptions::default();
        options.disable_wal(false);
        options.set_sync(matches!(self.durability, DurabilityPolicy::Sync));

        #[cfg(test)]
        let fault = self.take_commit_fault();
        #[cfg(test)]
        if fault == RocksCommitFault::BeforeWrite {
            return Err(StoreError::Io(
                "injected RocksDB failure before atomic write".to_owned(),
            ));
        }

        if let Err(error) = self.db.write_opt(write_batch, &options) {
            // RocksDB's error acknowledgement does not prove that an atomic
            // WAL/memtable publication is absent. Fence every clone before
            // releasing the publication lock; reopen establishes the actual
            // durable sequence.
            self.mark_commit_outcome_uncertain();
            return Err(StoreError::Backend(format!(
                "RocksDB atomic write outcome is uncertain; reopen required: {error}"
            )));
        }

        #[cfg(test)]
        if fault == RocksCommitFault::AfterWrite {
            self.mark_commit_outcome_uncertain();
            return Err(StoreError::Io(
                "injected RocksDB failure after atomic write; reopen required".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "rocksdb-backend"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RocksCommitFault {
    None = 0,
    BeforeWrite = 1,
    AfterWrite = 2,
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
        let _publication = self.lock_publication()?;
        self.ensure_operational()?;
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
        self.ensure_operational()?;
        if batch.operations.is_empty() {
            return Ok(());
        }
        for key in batch.operations.keys() {
            authenticated_namespace::ensure_ordinary_key(key.family, &key.key)?;
        }

        let _publication = self.lock_publication()?;
        self.ensure_operational()?;
        self.commit_operations_locked(batch.operations)
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

    fn scan_prefix_page(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        budget: PrefixScanBudget,
    ) -> Result<PrefixScanPage, StoreError> {
        use rocksdb::{Direction, IteratorMode};

        let budget = validate_prefix_scan_request(prefix, start_after, budget)?;
        let cf = RocksStore::cf(self.db, family)?;
        let start = start_after.unwrap_or(prefix);
        let mut page = PrefixScanPage::default();
        for item in self
            .snapshot
            .iterator_cf(cf, IteratorMode::From(start, Direction::Forward))
        {
            let (key, value) = item.map_err(|error| StoreError::Backend(error.to_string()))?;
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
    // Both the staging overlay and the durable backend are last-write-wins.
    // Retaining only the final operation avoids allocating and submitting every
    // intermediate mutation produced by a multi-block activation.
    operations: BatchOperations,
    checkpoint: Option<BatchCheckpoint>,
}

#[cfg(feature = "rocksdb-backend")]
impl WriteBatch for RocksBatch {
    fn put(&mut self, family: ColumnFamily, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        authenticated_namespace::ensure_ordinary_key(family, key)?;
        replace_batch_operation(
            &mut self.operations,
            &mut self.checkpoint,
            StoreKey::new(family, key),
            Some(value.to_vec()),
        );
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
        authenticated_namespace::ensure_ordinary_key(family, key)?;
        replace_batch_operation(
            &mut self.operations,
            &mut self.checkpoint,
            StoreKey::new(family, key),
            None,
        );
        Ok(())
    }
}

#[cfg(feature = "rocksdb-backend")]
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
    #[error("{context} exceeded its resource limit: limit {limit}, actual {actual}")]
    LimitExceeded {
        context: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error(
        "{context} has insufficient filesystem space: available {available}, required {required} including reserve {reserve}"
    )]
    InsufficientSpace {
        context: &'static str,
        available: u64,
        required: u64,
        reserve: u64,
    },
    #[error("{context} exceeded its monotonic deadline")]
    DeadlineExceeded { context: &'static str },
    #[error("schema mismatch: {0}")]
    Schema(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const TEST_ATOMIC_WRITE_CONTEXT: &str = "reorganization staged effect bytes";
    const TEST_ATOMIC_WRITE_FRAMING_BYTES: u64 = 128;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestAtomicWriteEffectBudget {
        consumed: u64,
        limit: u64,
    }

    impl AtomicWriteEffectBudget for TestAtomicWriteEffectBudget {
        fn operation_framing_bytes(&self) -> u64 {
            TEST_ATOMIC_WRITE_FRAMING_BYTES
        }

        fn charge_additional(&mut self, additional: u64) -> Result<(), StoreError> {
            let actual = self.consumed.saturating_add(additional);
            if actual > self.limit {
                return Err(StoreError::LimitExceeded {
                    context: TEST_ATOMIC_WRITE_CONTEXT,
                    limit: self.limit,
                    actual,
                });
            }
            self.consumed = actual;
            Ok(())
        }
    }

    fn test_segment_compaction_execution_limits() -> SegmentCompactionExecutionLimits {
        SegmentCompactionExecutionLimits {
            minimum_filesystem_reserve_bytes: 0,
            ..SegmentCompactionExecutionLimits::default()
        }
    }

    struct CountingSnapshot {
        inner: MemorySnapshot,
        gets: Cell<usize>,
        multi_gets: Cell<usize>,
        full_scans: Cell<usize>,
        paged_scans: Cell<usize>,
        maximum_page_entries: Cell<usize>,
        maximum_page_bytes: Cell<usize>,
    }

    impl CountingSnapshot {
        fn new(inner: MemorySnapshot) -> Self {
            Self {
                inner,
                gets: Cell::new(0),
                multi_gets: Cell::new(0),
                full_scans: Cell::new(0),
                paged_scans: Cell::new(0),
                maximum_page_entries: Cell::new(0),
                maximum_page_bytes: Cell::new(0),
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
            self.full_scans.set(self.full_scans.get() + 1);
            self.inner.scan_prefix(family, prefix)
        }

        fn scan_prefix_page(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
            start_after: Option<&[u8]>,
            budget: PrefixScanBudget,
        ) -> Result<PrefixScanPage, StoreError> {
            self.paged_scans.set(self.paged_scans.get() + 1);
            self.maximum_page_entries
                .set(self.maximum_page_entries.get().max(budget.max_entries));
            self.maximum_page_bytes
                .set(self.maximum_page_bytes.get().max(budget.max_bytes));
            self.inner
                .scan_prefix_page(family, prefix, start_after, budget)
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
    fn memory_batch_retains_only_the_final_operation_per_key() {
        let mut batch = MemoryBatch::default();
        batch
            .put(ColumnFamily::Meta, b"shared", b"first")
            .expect("first put");
        batch.delete(ColumnFamily::Meta, b"shared").expect("delete");
        batch
            .put(ColumnFamily::Meta, b"shared", b"final")
            .expect("final put");
        batch
            .put(ColumnFamily::Headers, b"shared", b"other-family")
            .expect("other family");

        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch
                .operations
                .get(&StoreKey::new(ColumnFamily::Meta, b"shared")),
            Some(&Some(b"final".to_vec()))
        );
    }

    #[test]
    fn staged_batch_checkpoint_restores_overlay_and_final_operations() {
        let store = MemoryStore::new();
        let base = store.snapshot().expect("checkpoint base");
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let mut batch = overlay.batch(store.batch());
        batch
            .put(ColumnFamily::Meta, b"retained", b"before")
            .expect("retained put");

        batch.begin_checkpoint().expect("begin checkpoint");
        batch
            .put(ColumnFamily::Meta, b"retained", b"oversized-block")
            .expect("replacement put");
        batch
            .put(ColumnFamily::Meta, b"transient", b"discarded")
            .expect("transient put");
        batch.rollback_checkpoint().expect("rollback checkpoint");

        assert_eq!(
            staged
                .get(ColumnFamily::Meta, b"retained")
                .expect("retained staged value"),
            Some(b"before".to_vec())
        );
        assert_eq!(
            staged
                .get(ColumnFamily::Meta, b"transient")
                .expect("transient staged value"),
            None
        );
        let inner = batch.into_inner();
        assert_eq!(inner.operations.len(), 1);
        drop(staged);
        drop(base);
        drop(overlay);
        store.commit(inner).expect("commit retained prefix");
        let committed = store.snapshot().expect("checkpoint committed snapshot");
        assert_eq!(
            committed
                .get(ColumnFamily::Meta, b"retained")
                .expect("retained committed value"),
            Some(b"before".to_vec())
        );
        assert_eq!(
            committed
                .get(ColumnFamily::Meta, b"transient")
                .expect("transient committed value"),
            None
        );
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_batch_retains_only_the_final_operation_per_family_and_key() {
        let mut batch = RocksBatch::default();
        batch
            .put(ColumnFamily::Blocks, &[0x11; 32], b"archived-body")
            .expect("body put");
        batch
            .delete(ColumnFamily::Blocks, &[0x11; 32])
            .expect("body delete");
        batch
            .put(ColumnFamily::Blocks, &[0x11; 32], b"replacement-body")
            .expect("replacement body");
        batch
            .put(ColumnFamily::Undo, &[0x11; 32], b"undo")
            .expect("undo put");

        assert_eq!(batch.operations.len(), 2);
        assert_eq!(
            batch
                .operations
                .get(&StoreKey::new(ColumnFamily::Blocks, &[0x11; 32])),
            Some(&Some(b"replacement-body".to_vec()))
        );
    }

    #[test]
    fn memory_snapshots_share_versioned_storage_and_collect_old_values() {
        let store = MemoryStore::new();
        let mut first = store.batch();
        first
            .put(ColumnFamily::Meta, b"versioned", b"one")
            .expect("first put");
        store.commit(first).expect("first commit");

        let old = store.snapshot().expect("old snapshot");
        let mut second = store.batch();
        second
            .put(ColumnFamily::Meta, b"versioned", b"two")
            .expect("second put");
        store.commit(second).expect("second commit");
        let current = store.snapshot().expect("current snapshot");

        assert!(Arc::ptr_eq(&old.inner, &current.inner));
        assert_eq!(
            old.get(ColumnFamily::Meta, b"versioned").expect("old get"),
            Some(b"one".to_vec())
        );
        assert_eq!(
            current
                .get(ColumnFamily::Meta, b"versioned")
                .expect("current get"),
            Some(b"two".to_vec())
        );
        assert_eq!(
            store
                .inner
                .read()
                .expect("state")
                .data
                .get(&StoreKey::new(ColumnFamily::Meta, b"versioned"))
                .expect("history")
                .len(),
            2
        );

        drop(old);
        drop(current);
        let mut third = store.batch();
        third
            .put(ColumnFamily::Meta, b"versioned", b"three")
            .expect("third put");
        store.commit(third).expect("third commit");
        assert_eq!(
            store
                .inner
                .read()
                .expect("state")
                .data
                .get(&StoreKey::new(ColumnFamily::Meta, b"versioned"))
                .expect("compacted history")
                .len(),
            1,
            "without live snapshots a commit retains only the current value"
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
    fn prefix_pages_enforce_record_and_byte_budgets_with_exclusive_continuations() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        for index in 0..7u8 {
            batch
                .put(ColumnFamily::Headers, &[b'p', b'/', index], &[index; 4])
                .expect("put page fixture");
        }
        store.commit(batch).expect("commit page fixture");
        let snapshot = store.snapshot().expect("snapshot");
        let budget = PrefixScanBudget {
            max_entries: 2,
            max_bytes: 32,
        };
        let mut continuation = None::<Vec<u8>>;
        let mut keys = Vec::new();
        let mut pages = 0usize;
        loop {
            let page = snapshot
                .scan_prefix_page(
                    ColumnFamily::Headers,
                    b"p/",
                    continuation.as_deref(),
                    budget,
                )
                .expect("bounded page");
            assert!(page.entries.len() <= budget.max_entries);
            assert!(page.returned_bytes <= budget.max_bytes);
            keys.extend(page.entries.into_iter().map(|(key, _)| key));
            pages += 1;
            let Some(next) = page.continuation else {
                break;
            };
            assert!(continuation
                .as_ref()
                .is_none_or(|previous| next > *previous));
            continuation = Some(next);
        }
        assert_eq!(pages, 4);
        assert_eq!(
            keys,
            (0..7u8)
                .map(|index| vec![b'p', b'/', index])
                .collect::<Vec<_>>()
        );
        assert!(snapshot
            .scan_prefix_page(
                ColumnFamily::Headers,
                b"p/",
                None,
                PrefixScanBudget {
                    max_entries: 1,
                    max_bytes: 6,
                },
            )
            .is_err());
        assert!(snapshot
            .scan_prefix_page(ColumnFamily::Headers, b"p/", Some(b"other"), budget,)
            .is_err());
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
    fn memory_snapshot_prefix_visitor_can_commit_to_the_same_store() {
        let store = MemoryStore::new();
        let mut initial = store.batch();
        initial
            .put(ColumnFamily::Headers, b"p/1", b"one")
            .expect("put one");
        initial
            .put(ColumnFamily::Headers, b"p/2", b"two")
            .expect("put two");
        store.commit(initial).expect("commit initial");

        let snapshot = store.snapshot().expect("snapshot");
        let mut visited = Vec::new();
        snapshot
            .visit_prefix(ColumnFamily::Headers, b"p/", &mut |key, _| {
                visited.push(key.to_vec());
                let mut deletion = store.batch();
                deletion
                    .delete(ColumnFamily::Headers, key)
                    .expect("stage deletion");
                store.commit(deletion).expect("commit from visitor");
                Ok(())
            })
            .expect("visit while committing");
        assert_eq!(visited, vec![b"p/1".to_vec(), b"p/2".to_vec()]);
        drop(snapshot);
        assert!(store
            .snapshot()
            .expect("current snapshot")
            .scan_prefix(ColumnFamily::Headers, b"p/")
            .expect("current prefix")
            .is_empty());
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
        initial
            .put(ColumnFamily::Headers, b"b/3", b"deleted")
            .expect("put deleted value");
        store.commit(initial).expect("commit initial");

        let base = CountingSnapshot::new(store.snapshot().expect("base snapshot"));
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
        let mut continuation = None::<Vec<u8>>;
        let mut paged = Vec::new();
        loop {
            let page = staged_snapshot
                .scan_prefix_page(
                    ColumnFamily::Headers,
                    b"b/",
                    continuation.as_deref(),
                    PrefixScanBudget {
                        max_entries: 1,
                        max_bytes: 64,
                    },
                )
                .expect("staged page");
            paged.extend(page.entries);
            let Some(next) = page.continuation else {
                break;
            };
            continuation = Some(next);
        }
        assert_eq!(
            paged,
            vec![
                (b"b/0".to_vec(), b"base".to_vec()),
                (b"b/1".to_vec(), b"new".to_vec()),
                (b"b/2".to_vec(), b"two".to_vec())
            ]
        );
        assert_eq!(base.full_scans.get(), 0);
        assert_eq!(base.maximum_page_entries.get(), 1);
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
        drop(staged_snapshot);
        assert_eq!(
            overlay.take_staged_family(ColumnFamily::NameTreeNodes),
            BTreeMap::from([(b"node".to_vec(), Some(b"canonical".to_vec()))])
        );
        assert!(overlay
            .staged_family(ColumnFamily::NameTreeNodes)
            .is_empty());
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
    fn snapshot_empty_probe_uses_only_one_record_small_pages() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Snapshots, b"last-family", b"value")
            .expect("put marker");
        store.commit(batch).expect("commit marker");
        let snapshot = CountingSnapshot::new(store.snapshot().expect("snapshot"));

        assert!(!snapshot_is_empty(&snapshot).expect("probe non-empty snapshot"));
        assert_eq!(snapshot.full_scans.get(), 0);
        assert_eq!(snapshot.paged_scans.get(), ColumnFamily::ALL.len());
        assert_eq!(snapshot.maximum_page_entries.get(), 1);
        assert_eq!(
            snapshot.maximum_page_bytes.get(),
            SNAPSHOT_EMPTY_PROBE_BYTES
        );
    }

    #[test]
    fn snapshot_empty_probe_treats_an_oversize_first_value_as_nonempty() {
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                b"oversize",
                &vec![0; SNAPSHOT_EMPTY_PROBE_BYTES + 1],
            )
            .expect("put oversize marker");
        store.commit(batch).expect("commit oversize marker");
        let snapshot = CountingSnapshot::new(store.snapshot().expect("snapshot"));

        assert!(!snapshot_is_empty(&snapshot).expect("probe oversize snapshot"));
        assert_eq!(snapshot.full_scans.get(), 0);
        assert_eq!(snapshot.paged_scans.get(), 1);
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
    fn filesystem_available_bytes_is_safe_and_fail_closed() {
        let directory = std::env::temp_dir();
        filesystem_available_bytes(&directory).expect("available bytes for existing filesystem");
        let missing = directory.join(format!("hsrd-missing-capacity-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        assert!(matches!(
            filesystem_available_bytes(&missing),
            Err(StoreError::Io(message))
                if message.contains("failed to query available filesystem bytes")
        ));
    }

    #[test]
    fn filesystem_tree_usage_is_bounded_exact_and_symlink_refusing() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hsrd-filesystem-usage-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("level-one/level-two")).expect("usage fixture");
        std::fs::write(root.join("level-one/level-two/data"), vec![0x5a; 8_192])
            .expect("usage data");
        let usage = filesystem_tree_usage_bounded(
            &root,
            FilesystemTreeUsageLimits {
                deadline: Instant::now() + Duration::from_secs(30),
                ..FilesystemTreeUsageLimits::default()
            },
        )
        .expect("bounded usage");
        assert_eq!(usage.entries, 4);
        assert_eq!(usage.files, 1);
        assert_eq!(usage.directories, 3);
        assert_eq!(usage.maximum_depth, 3);
        assert!(usage.apparent_bytes >= 8_192);
        assert!(usage.allocated_bytes > 0);

        let exact = FilesystemTreeUsageLimits {
            max_entries: usage.entries,
            max_depth: usage.maximum_depth,
            max_apparent_bytes: usage.apparent_bytes,
            max_allocated_bytes: usage.allocated_bytes,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        assert_eq!(
            filesystem_tree_usage_bounded(&root, exact).expect("exact usage limits"),
            usage
        );
        assert!(matches!(
            filesystem_tree_usage_bounded(
                &root,
                FilesystemTreeUsageLimits {
                    max_entries: usage.entries - 1,
                    ..exact
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "filesystem tree usage entries",
                limit,
                actual,
            }) if limit == usage.entries - 1 && actual == usage.entries
        ));
        assert!(matches!(
            filesystem_tree_usage_bounded(
                &root,
                FilesystemTreeUsageLimits {
                    max_depth: usage.maximum_depth - 1,
                    ..exact
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "filesystem tree usage depth",
                limit,
                actual,
            }) if limit == u64::from(usage.maximum_depth - 1)
                && actual == u64::from(usage.maximum_depth)
        ));
        assert!(matches!(
            filesystem_tree_usage_bounded(
                &root,
                FilesystemTreeUsageLimits {
                    max_apparent_bytes: usage.apparent_bytes - 1,
                    ..exact
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "filesystem tree apparent bytes",
                limit,
                actual,
            }) if limit == usage.apparent_bytes - 1 && actual == usage.apparent_bytes
        ));
        assert!(matches!(
            filesystem_tree_usage_bounded(
                &root,
                FilesystemTreeUsageLimits {
                    max_allocated_bytes: usage.allocated_bytes - 1,
                    ..exact
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "filesystem tree allocated bytes",
                limit,
                actual,
            }) if limit == usage.allocated_bytes - 1 && actual == usage.allocated_bytes
        ));
        assert!(matches!(
            filesystem_tree_usage_bounded(
                &root,
                FilesystemTreeUsageLimits {
                    deadline: Instant::now(),
                    ..exact
                },
            ),
            Err(StoreError::DeadlineExceeded {
                context: "filesystem tree usage"
            })
        ));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                root.join("level-one/level-two/data"),
                root.join("linked-data"),
            )
            .expect("usage symlink");
            assert!(matches!(
                filesystem_tree_usage_bounded(
                    &root,
                    FilesystemTreeUsageLimits {
                        deadline: Instant::now() + Duration::from_secs(30),
                        ..exact
                    },
                ),
                Err(StoreError::Schema(message)) if message.contains("refusing symlink")
            ));
        }
        std::fs::remove_dir_all(root).expect("remove usage fixture");
    }

    #[test]
    fn segment_compaction_capacity_accepts_exact_bounds_and_rejects_one_under() {
        const SHARED: &str = "test shared filesystem";
        const PAYLOAD: &str = "test payload filesystem";
        const ROCKS: &str = "test RocksDB filesystem";
        assert_eq!(
            SegmentCompactionExecutionLimits::default().minimum_filesystem_reserve_bytes,
            10_000_000_000
        );
        let request = SegmentCompactionCapacityRequest {
            payload_output_bytes: 40,
            rocks_temporary_bytes: 30,
            reserve: 30,
            shared_context: SHARED,
            payload_context: PAYLOAD,
            rocks_context: ROCKS,
        };

        ensure_segment_compaction_capacity_values(true, 100, 100, request)
            .expect("exact shared capacity");
        assert!(matches!(
            ensure_segment_compaction_capacity_values(true, 99, 99, request),
            Err(StoreError::InsufficientSpace {
                context: SHARED,
                available: 99,
                required: 100,
                reserve: 30,
            })
        ));

        ensure_segment_compaction_capacity_values(false, 70, 60, request)
            .expect("exact split capacity");
        assert!(matches!(
            ensure_segment_compaction_capacity_values(false, 69, 60, request),
            Err(StoreError::InsufficientSpace {
                context: PAYLOAD,
                available: 69,
                required: 70,
                reserve: 30,
            })
        ));
        assert!(matches!(
            ensure_segment_compaction_capacity_values(false, 70, 59, request),
            Err(StoreError::InsufficientSpace {
                context: ROCKS,
                available: 59,
                required: 60,
                reserve: 30,
            })
        ));
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
    fn effect_budget_is_transparent_for_non_archived_store_handles() {
        let store = StoreHandle::memory();
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Meta, b"transparent", b"committed")
            .expect("stage transparent value");
        let mut budget = TestAtomicWriteEffectBudget {
            consumed: 7,
            limit: 7,
        };
        store
            .commit_with_effect_budget(batch, &mut budget)
            .expect("commit non-archived batch without an archive charge");
        assert_eq!(budget.consumed, 7);
        assert_eq!(
            store
                .snapshot()
                .expect("snapshot")
                .get(ColumnFamily::Meta, b"transparent")
                .expect("transparent value"),
            Some(b"committed".to_vec())
        );
    }

    #[test]
    fn archive_effect_preflight_constants_match_durable_encodings() {
        let empty_frame = encode_segment_record(&SegmentRecord {
            kind: SegmentKind::Block,
            key: [0; 32],
            hints: Vec::new(),
            payload: Vec::new(),
        })
        .expect("encode empty frame");
        assert_eq!(
            u64::try_from(empty_frame.len()).expect("frame overhead"),
            ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES
        );
        assert_eq!(
            SegmentManifest {
                generation: 1,
                active_segment: 2,
                durable_bytes: 3,
            }
            .encode()
            .len(),
            ARCHIVE_MANIFEST_ENCODED_BYTES
        );
        assert_eq!(
            SegmentValueLocator {
                kind: SegmentKind::Undo,
                locator: SegmentLocator {
                    generation: 1,
                    segment: 2,
                    offset: 3,
                    frame_length: 4,
                },
            }
            .encode()
            .len(),
            SegmentValueLocator::encoded_len()
        );
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
    fn archived_batch_publishes_only_final_block_and_undo_values() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-store-coalesced-archive-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let archived = StoreHandle::memory()
            .with_segment_archive(directory.clone())
            .expect("attach coalesced archive");
        let block_key = [0x51; 32];
        let undo_key = [0x52; 32];
        let mut batch = archived.batch();
        for (family, key, first, final_value) in [
            (
                ColumnFamily::Blocks,
                block_key,
                b"obsolete block".as_slice(),
                b"final block".as_slice(),
            ),
            (
                ColumnFamily::Undo,
                undo_key,
                b"obsolete undo".as_slice(),
                b"final undo".as_slice(),
            ),
        ] {
            batch
                .put(family, &key, first)
                .expect("stage obsolete value");
            batch
                .delete(family, &key)
                .expect("stage intermediate delete");
            batch
                .put(family, &key, final_value)
                .expect("stage final value");
        }
        archived.commit(batch).expect("commit coalesced archive");

        let snapshot = archived.snapshot().expect("coalesced archive snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &block_key)
                .expect("final block"),
            Some(b"final block".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Undo, &undo_key)
                .expect("final undo"),
            Some(b"final undo".to_vec())
        );
        drop(snapshot);
        let inventory = archived
            .scrub_segment_archive()
            .expect("scrub final values");
        assert_eq!(inventory.blocks.records, 1);
        assert_eq!(inventory.undo.records, 1);

        drop(archived);
        std::fs::remove_dir_all(directory).expect("remove coalesced archive fixture");
    }

    #[test]
    fn archived_prefix_pages_bound_resolved_payloads_one_record_at_a_time() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-archive-prefix-page-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let archived = StoreHandle::memory()
            .with_segment_archive(directory.clone())
            .expect("attach archive");
        let first_key = [0x31; 32];
        let second_key = [0x32; 32];
        let first_payload = vec![0xa1; 8 * 1024];
        let second_payload = vec![0xb2; 8 * 1024];
        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Undo, &first_key, &first_payload)
            .expect("stage first undo");
        batch
            .put(ColumnFamily::Undo, &second_key, &second_payload)
            .expect("stage second undo");
        archived.commit(batch).expect("commit archived undos");

        let snapshot = archived.snapshot().expect("archived snapshot");
        let page_bytes = first_key.len() + first_payload.len();
        let budget = PrefixScanBudget {
            max_entries: 1,
            max_bytes: page_bytes,
        };
        let first = snapshot
            .scan_prefix_page(ColumnFamily::Undo, b"", None, budget)
            .expect("first resolved page");
        assert_eq!(first.entries, vec![(first_key.to_vec(), first_payload)]);
        assert_eq!(first.returned_bytes, page_bytes);
        assert_eq!(first.continuation, Some(first_key.to_vec()));

        let second = snapshot
            .scan_prefix_page(
                ColumnFamily::Undo,
                b"",
                first.continuation.as_deref(),
                budget,
            )
            .expect("second resolved page");
        assert_eq!(second.entries, vec![(second_key.to_vec(), second_payload)]);
        assert_eq!(second.returned_bytes, page_bytes);
        assert_eq!(second.continuation, None);

        assert!(matches!(
            snapshot.scan_prefix_page(
                ColumnFamily::Undo,
                b"",
                None,
                PrefixScanBudget {
                    max_entries: 1,
                    max_bytes: page_bytes - 1,
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "prefix scan page bytes",
                limit,
                actual,
            }) if limit == (page_bytes - 1) as u64 && actual == page_bytes as u64
        ));
        drop(snapshot);
        drop(archived);
        std::fs::remove_dir_all(directory).expect("remove archive page fixture");
    }

    #[test]
    fn segment_compaction_default_page_traverses_a_near_max_inline_undo() {
        const NEAR_MAX_BLOCK_UNDO_BYTES: usize = 32_000_000;
        const UNDO_KEY_BYTES: usize = 32;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-segment-inline-max-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let raw = StoreHandle::memory();
        let mut batch = raw.batch();
        batch
            .put(
                ColumnFamily::Undo,
                &[0x5a; 32],
                &vec![0; NEAR_MAX_BLOCK_UNDO_BYTES],
            )
            .expect("stage near-max inline undo");
        raw.commit(batch).expect("commit near-max inline undo");
        let archived = raw
            .with_segment_archive(directory.clone())
            .expect("attach archive");

        let exact_page_bytes = NEAR_MAX_BLOCK_UNDO_BYTES + UNDO_KEY_BYTES;
        assert!(SEGMENT_COMPACTION_DEFAULT_SCAN_BYTES >= exact_page_bytes);
        let one_record_limits = SegmentCompactionLimits {
            scan_page_records: 1,
            scan_page_bytes: exact_page_bytes,
            ..SegmentCompactionLimits::default()
        };
        let plan = archived
            .plan_segment_archive_compaction_with_execution_limits(
                one_record_limits,
                test_segment_compaction_execution_limits(),
            )
            .expect("plan through one near-maximum inline undo at the exact page bound");
        assert_eq!(plan.live_records, 0);
        assert_eq!(plan.live_frame_bytes, 0);
        assert_eq!(plan.scan_page_records, 1);
        assert_eq!(plan.scan_page_bytes, exact_page_bytes);
        assert!(matches!(
            archived.plan_segment_archive_compaction_with_execution_limits(
                SegmentCompactionLimits {
                    scan_page_bytes: exact_page_bytes - 1,
                    ..one_record_limits
                },
                test_segment_compaction_execution_limits(),
            ),
            Err(StoreError::LimitExceeded {
                context: "prefix scan page bytes",
                limit,
                actual,
            }) if limit == (exact_page_bytes - 1) as u64
                && actual == exact_page_bytes as u64
        ));

        drop(archived);
        std::fs::remove_dir_all(directory).expect("remove near-max inline fixture");
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
        let limits = SegmentCompactionLimits {
            scan_page_records: 1,
            scan_page_bytes: 1_024,
            ..SegmentCompactionLimits::default()
        };
        let execution = test_segment_compaction_execution_limits();
        let plan = archived
            .plan_segment_archive_compaction_with_execution_limits(limits, execution)
            .expect("bounded compaction plan");
        assert_eq!(plan.live_records, 2);
        assert!(plan.reclaimable_frame_bytes > 0);
        let exact_limits = SegmentCompactionLimits {
            max_live_records: plan.live_records,
            max_live_frame_bytes: plan.live_frame_bytes,
            max_atomic_locator_bytes: plan.estimated_atomic_locator_bytes,
            ..limits
        };
        let exact_execution = SegmentCompactionExecutionLimits {
            max_physical_output_bytes: plan.live_frame_bytes,
            max_atomic_publication_bytes: plan.estimated_atomic_publication_bytes,
            ..execution
        };
        assert_eq!(
            archived
                .plan_segment_archive_compaction_with_execution_limits(
                    exact_limits,
                    exact_execution,
                )
                .expect("exact compaction ceilings"),
            plan
        );
        assert!(matches!(
            archived.plan_segment_archive_compaction_with_execution_limits(
                SegmentCompactionLimits {
                    max_live_records: 1,
                    ..limits
                },
                execution,
            ),
            Err(StoreError::LimitExceeded {
                context: "segment compaction live records",
                limit: 1,
                actual: 2,
            })
        ));
        assert!(matches!(
            archived.plan_segment_archive_compaction_with_execution_limits(
                SegmentCompactionLimits {
                    max_live_frame_bytes: plan.live_frame_bytes - 1,
                    ..exact_limits
                },
                exact_execution,
            ),
            Err(StoreError::LimitExceeded {
                context: "segment compaction live frame bytes",
                limit,
                actual,
            }) if limit == plan.live_frame_bytes - 1 && actual == plan.live_frame_bytes
        ));
        assert!(matches!(
            archived.plan_segment_archive_compaction_with_execution_limits(
                exact_limits,
                SegmentCompactionExecutionLimits {
                    max_atomic_publication_bytes: plan.estimated_atomic_publication_bytes - 1,
                    ..exact_execution
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "segment compaction atomic publication bytes",
                limit,
                actual,
            }) if limit == plan.estimated_atomic_publication_bytes - 1
                && actual == plan.estimated_atomic_publication_bytes
        ));
        assert!(matches!(
            archived.plan_segment_archive_compaction_with_execution_limits(
                exact_limits,
                SegmentCompactionExecutionLimits {
                    max_physical_output_bytes: plan.live_frame_bytes - 1,
                    ..exact_execution
                },
            ),
            Err(StoreError::LimitExceeded {
                context: "segment compaction physical output bytes",
                limit,
                actual,
            }) if limit == plan.live_frame_bytes - 1 && actual == plan.live_frame_bytes
        ));
        assert_eq!(
            archived
                .scrub_segment_archive()
                .expect("failed plan is read-only"),
            before
        );
        assert!(matches!(
            archived.plan_segment_archive_compaction_with_execution_limits(
                limits,
                SegmentCompactionExecutionLimits {
                    deadline: Instant::now(),
                    ..execution
                },
            ),
            Err(StoreError::DeadlineExceeded {
                context: "segment compaction planning"
            })
        ));
        assert_eq!(
            archived
                .scrub_segment_archive()
                .expect("expired plan is read-only"),
            before
        );
        let report = archived
            .compact_segment_archive_with_execution_limits(limits, execution)
            .expect("compact segment archive");
        assert_eq!(report.previous_block_generation, 1);
        assert_eq!(report.previous_undo_generation, 1);
        assert_eq!(report.generation, 2);
        assert_eq!(report.live_records, 2);
        assert!(report.reclaimed_frame_bytes > 0);
        assert_eq!(report.scan_pages, 2);
        assert_eq!(report.peak_scan_records, 1);
        assert!(report.peak_scan_bytes <= limits.scan_page_bytes);

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

    #[test]
    fn inline_archive_migration_pages_through_a_dense_hash_prefix() {
        const RECORDS: u16 = 257;
        const BATCH_RECORDS: usize = 17;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-inline-archive-dense-prefix-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let raw = StoreHandle::memory();
        let mut batch = raw.batch();
        for index in 0..RECORDS {
            let mut key = [0x5a; 32];
            key[1..3].copy_from_slice(&index.to_be_bytes());
            batch
                .put(ColumnFamily::Blocks, &key, &index.to_be_bytes())
                .expect("stage dense-prefix value");
        }
        raw.commit(batch).expect("commit dense-prefix values");
        let archived = raw
            .with_segment_archive(directory.clone())
            .expect("attach archive");
        let report = archived
            .migrate_inline_segment_payloads(BATCH_RECORDS)
            .expect("migrate dense prefix");
        assert_eq!(report.migrated_records, u64::from(RECORDS));
        assert_eq!(
            report.commits,
            u64::from(RECORDS).div_ceil(BATCH_RECORDS as u64)
        );
        let inventory = archived
            .segment_archive_inventory()
            .expect("dense-prefix inventory");
        assert_eq!(inventory.blocks.inline_records, 0);
        assert_eq!(inventory.blocks.archived_records, u64::from(RECORDS));
        for index in [0, RECORDS / 2, RECORDS - 1] {
            let mut key = [0x5a; 32];
            key[1..3].copy_from_slice(&index.to_be_bytes());
            assert_eq!(
                archived
                    .snapshot()
                    .expect("snapshot")
                    .get(ColumnFamily::Blocks, &key)
                    .expect("resolved value"),
                Some(index.to_be_bytes().to_vec())
            );
        }
        drop(archived);
        std::fs::remove_dir_all(directory).expect("remove dense-prefix fixture");
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
    fn archived_rocks_effect_budget_is_exact_and_rejects_before_any_publication() {
        const INITIAL_CONSUMED: u64 = 4_096;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hsrd-rocks-archive-budget-test-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let chain_path = root.join("chain");
        let archive_path = root.join("payloads");
        let rocks = RocksStore::open(&chain_path).expect("open RocksDB");
        let archived = StoreHandle::Rocks(rocks.clone())
            .with_segment_archive(archive_path.clone())
            .expect("attach archive");
        let block_key = [0x91; 32];
        let undo_key = [0x92; 32];
        let block_payload = vec![0xa1; 4_097];
        let undo_payload = vec![0xb2; 8_193];

        let segment_lengths = || {
            std::fs::read_dir(&archive_path)
                .expect("read archive directory")
                .map(|entry| {
                    let entry = entry.expect("archive entry");
                    let metadata = entry.metadata().expect("archive entry metadata");
                    (entry.file_name(), metadata.len())
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before_segment_lengths = segment_lengths();
        let raw_before = rocks.snapshot().expect("raw preflight snapshot");
        let before_block_manifest = raw_before
            .get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)
            .expect("block manifest read")
            .expect("block manifest");
        let before_undo_manifest = raw_before
            .get(ColumnFamily::Snapshots, UNDO_SEGMENT_MANIFEST_KEY)
            .expect("undo manifest read")
            .expect("undo manifest");
        assert_eq!(
            raw_before
                .get(ColumnFamily::Blocks, &block_key)
                .expect("absent block"),
            None
        );
        assert_eq!(
            raw_before
                .get(ColumnFamily::Undo, &undo_key)
                .expect("absent undo"),
            None
        );
        drop(raw_before);

        let make_batch = || {
            let mut batch = archived.batch();
            batch
                .put(ColumnFamily::Blocks, &block_key, &block_payload)
                .expect("stage block payload");
            batch
                .put(ColumnFamily::Undo, &undo_key, &undo_payload)
                .expect("stage undo payload");
            batch
                .put(ColumnFamily::Meta, b"archive-budget", b"published")
                .expect("stage metadata");
            batch
        };
        let rejected_batch = make_batch();
        let effects = rejected_batch
            .archive_commit_effects(Some(TEST_ATOMIC_WRITE_FRAMING_BYTES))
            .expect("preflight effects");
        assert_eq!(effects.payloads, 2);

        let empty_frame = encode_segment_record(&SegmentRecord {
            kind: SegmentKind::Block,
            key: [0; 32],
            hints: Vec::new(),
            payload: Vec::new(),
        })
        .expect("encode empty frame");
        assert_eq!(
            u64::try_from(empty_frame.len()).expect("frame overhead"),
            ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES
        );
        let manifest_bytes = SegmentManifest::decode(&before_block_manifest)
            .expect("decode block manifest")
            .encode()
            .len();
        assert_eq!(
            SegmentManifest::decode(&before_undo_manifest)
                .expect("decode undo manifest")
                .encode()
                .len(),
            manifest_bytes
        );
        assert_eq!(manifest_bytes, ARCHIVE_MANIFEST_ENCODED_BYTES);

        let expected_operation_charge = |key_bytes: u64, value_bytes: u64, copies: u64| {
            key_bytes
                .saturating_add(value_bytes)
                .saturating_add(TEST_ATOMIC_WRITE_FRAMING_BYTES)
                .saturating_mul(copies)
        };
        let expected_extracted = expected_operation_charge(
            u64::try_from(block_key.len()).expect("block key length"),
            u64::try_from(block_payload.len()).expect("block payload length"),
            ARCHIVE_EXTRACTED_PAYLOAD_COPIES,
        )
        .saturating_add(expected_operation_charge(
            u64::try_from(undo_key.len()).expect("undo key length"),
            u64::try_from(undo_payload.len()).expect("undo payload length"),
            ARCHIVE_EXTRACTED_PAYLOAD_COPIES,
        ));
        let expected_frames = expected_operation_charge(
            0,
            u64::try_from(block_payload.len())
                .expect("block length")
                .saturating_add(ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES),
            ARCHIVE_FRAME_COPIES,
        )
        .saturating_add(expected_operation_charge(
            0,
            u64::try_from(undo_payload.len())
                .expect("undo length")
                .saturating_add(ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES),
            ARCHIVE_FRAME_COPIES,
        ));
        let expected_locators = expected_operation_charge(
            u64::try_from(block_key.len()).expect("block key length"),
            u64::try_from(SegmentValueLocator::encoded_len()).expect("locator length"),
            ARCHIVE_LOCATOR_PUBLICATION_COPIES,
        )
        .saturating_add(expected_operation_charge(
            u64::try_from(undo_key.len()).expect("undo key length"),
            u64::try_from(SegmentValueLocator::encoded_len()).expect("locator length"),
            ARCHIVE_LOCATOR_PUBLICATION_COPIES,
        ));
        let expected_manifests = expected_operation_charge(
            u64::try_from(BLOCK_SEGMENT_MANIFEST_KEY.len()).expect("block manifest key length"),
            u64::try_from(manifest_bytes).expect("manifest length"),
            ARCHIVE_MANIFEST_PUBLICATION_COPIES,
        )
        .saturating_add(expected_operation_charge(
            u64::try_from(UNDO_SEGMENT_MANIFEST_KEY.len()).expect("undo manifest key length"),
            u64::try_from(manifest_bytes).expect("manifest length"),
            ARCHIVE_MANIFEST_PUBLICATION_COPIES,
        ));
        assert_eq!(effects.extracted_payload_bytes, expected_extracted);
        assert_eq!(effects.framed_segment_bytes, expected_frames);
        assert_eq!(effects.locator_publication_bytes, expected_locators);
        assert_eq!(effects.manifest_publication_bytes, expected_manifests);
        let exact_additional = expected_extracted
            .saturating_add(expected_frames)
            .saturating_add(expected_locators)
            .saturating_add(expected_manifests);
        assert_eq!(effects.total(), exact_additional);
        let exact_cumulative = INITIAL_CONSUMED.saturating_add(exact_additional);

        let mut one_short = TestAtomicWriteEffectBudget {
            consumed: INITIAL_CONSUMED,
            limit: exact_cumulative - 1,
        };
        let error = archived
            .commit_with_effect_budget(rejected_batch, &mut one_short)
            .expect_err("one-byte-short budget must reject");
        assert!(matches!(
            error,
            StoreError::LimitExceeded {
                context: TEST_ATOMIC_WRITE_CONTEXT,
                limit,
                actual,
            } if limit == exact_cumulative - 1 && actual == exact_cumulative
        ));
        assert_eq!(one_short.consumed, INITIAL_CONSUMED);
        assert_eq!(segment_lengths(), before_segment_lengths);
        let raw_rejected = rocks.snapshot().expect("raw rejected snapshot");
        assert_eq!(
            raw_rejected
                .get(ColumnFamily::Blocks, &block_key)
                .expect("rejected block"),
            None
        );
        assert_eq!(
            raw_rejected
                .get(ColumnFamily::Undo, &undo_key)
                .expect("rejected undo"),
            None
        );
        assert_eq!(
            raw_rejected
                .get(ColumnFamily::Meta, b"archive-budget")
                .expect("rejected metadata"),
            None
        );
        assert_eq!(
            raw_rejected
                .get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)
                .expect("rejected block manifest"),
            Some(before_block_manifest.clone())
        );
        assert_eq!(
            raw_rejected
                .get(ColumnFamily::Snapshots, UNDO_SEGMENT_MANIFEST_KEY)
                .expect("rejected undo manifest"),
            Some(before_undo_manifest.clone())
        );
        drop(raw_rejected);

        let mut exact = TestAtomicWriteEffectBudget {
            consumed: INITIAL_CONSUMED,
            limit: exact_cumulative,
        };
        archived
            .commit_with_effect_budget(make_batch(), &mut exact)
            .expect("exact cumulative archive budget");
        assert_eq!(exact.consumed, exact_cumulative);

        let raw_committed = rocks.snapshot().expect("raw committed snapshot");
        let raw_block = raw_committed
            .get(ColumnFamily::Blocks, &block_key)
            .expect("raw block")
            .expect("block locator");
        let raw_undo = raw_committed
            .get(ColumnFamily::Undo, &undo_key)
            .expect("raw undo")
            .expect("undo locator");
        let block_locator = SegmentValueLocator::decode(&raw_block)
            .expect("decode block locator")
            .expect("block locator");
        let undo_locator = SegmentValueLocator::decode(&raw_undo)
            .expect("decode undo locator")
            .expect("undo locator");
        assert_eq!(
            u64::from(block_locator.locator.frame_length),
            u64::try_from(block_payload.len())
                .expect("block payload length")
                .saturating_add(ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES)
        );
        assert_eq!(
            u64::from(undo_locator.locator.frame_length),
            u64::try_from(undo_payload.len())
                .expect("undo payload length")
                .saturating_add(ARCHIVE_EMPTY_HINT_FRAME_OVERHEAD_BYTES)
        );
        let block_path = archive_path.join(format!(
            "block-g{:016x}-s{:08x}.seg",
            block_locator.locator.generation, block_locator.locator.segment
        ));
        let undo_path = archive_path.join(format!(
            "undo-g{:016x}-s{:08x}.seg",
            undo_locator.locator.generation, undo_locator.locator.segment
        ));
        assert_eq!(
            std::fs::metadata(block_path)
                .expect("committed block segment metadata")
                .len(),
            block_locator
                .locator
                .offset
                .saturating_add(u64::from(block_locator.locator.frame_length))
        );
        assert_eq!(
            std::fs::metadata(undo_path)
                .expect("committed undo segment metadata")
                .len(),
            undo_locator
                .locator
                .offset
                .saturating_add(u64::from(undo_locator.locator.frame_length))
        );
        assert_eq!(
            raw_committed
                .get(ColumnFamily::Meta, b"archive-budget")
                .expect("committed metadata"),
            Some(b"published".to_vec())
        );
        drop(raw_committed);
        assert_eq!(
            archived
                .snapshot()
                .expect("resolved committed snapshot")
                .get(ColumnFamily::Blocks, &block_key)
                .expect("resolved block"),
            Some(block_payload)
        );
        assert_eq!(
            archived
                .snapshot()
                .expect("resolved committed snapshot")
                .get(ColumnFamily::Undo, &undo_key)
                .expect("resolved undo"),
            Some(undo_payload)
        );

        drop(archived);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove RocksDB archive budget fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_commit_fault_fences_shared_clones_until_true_reopen() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-rocks-publication-fence-test-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let rocks = RocksStore::open(&path).expect("open rocksdb");
        let clone = rocks.clone();

        let mut rejected = rocks.batch();
        rejected
            .put(ColumnFamily::Meta, b"before-write", b"rejected")
            .expect("stage before-write fault");
        rocks.inject_next_commit_fault(RocksCommitFault::BeforeWrite);
        assert!(rocks.commit(rejected).is_err());
        assert!(!rocks.reopen_required());
        assert!(!clone.reopen_required());

        let mut accepted = clone.batch();
        accepted
            .put(ColumnFamily::Meta, b"after-before", b"accepted")
            .expect("stage safe retry");
        clone
            .commit(accepted)
            .expect("commit after known rejection");

        let mut ambiguous = rocks.batch();
        ambiguous
            .put(ColumnFamily::Meta, b"after-write", b"committed")
            .expect("stage after-write fault");
        rocks.inject_next_commit_fault(RocksCommitFault::AfterWrite);
        assert!(rocks.commit(ambiguous).is_err());
        assert!(rocks.reopen_required());
        assert!(clone.reopen_required());
        assert!(rocks.snapshot().is_err());
        assert!(clone
            .create_checkpoint(path.with_extension("blocked-checkpoint"))
            .is_err());
        let mut bypass = clone.batch();
        bypass
            .put(ColumnFamily::Meta, b"fenced-bypass", b"rejected")
            .expect("stage fenced bypass");
        assert!(clone.commit(bypass).is_err());
        drop(clone);
        drop(rocks);

        let reopened = RocksStore::open(&path).expect("truly reopen RocksDB");
        assert!(!reopened.reopen_required());
        let snapshot = reopened.snapshot().expect("reopened snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, b"before-write")
                .expect("rejected value"),
            None
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, b"after-before")
                .expect("accepted value"),
            Some(b"accepted".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, b"after-write")
                .expect("ambiguous applied value"),
            Some(b"committed".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, b"fenced-bypass")
                .expect("fenced bypass value"),
            None
        );
        drop(snapshot);
        let poison = reopened.clone();
        assert!(std::thread::spawn(move || {
            let _publication = poison.publication_lock.lock().expect("publication lock");
            panic!("inject RocksDB publication-lock poison");
        })
        .join()
        .is_err());
        assert!(reopened.reopen_required());
        assert!(reopened.snapshot().is_err());
        drop(reopened);
        std::fs::remove_dir_all(path).expect("remove RocksDB fence fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_segment_publication_faults_recover_the_complete_old_or_new_batch() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hsrd-rocks-segment-fault-test-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let chain_path = root.join("chain");
        let rocks = RocksStore::open(&chain_path).expect("open rocksdb");
        let raw = StoreHandle::Rocks(rocks.clone());
        let archive_path = root.join("payloads");
        let archived = raw
            .clone()
            .with_segment_archive(archive_path.clone())
            .expect("attach archive");
        let retained = [0x81; 32];
        let rejected = [0x82; 32];
        let accepted = [0x83; 32];
        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Blocks, &retained, b"retained")
            .expect("stage retained");
        archived.commit(batch).expect("commit retained");

        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Blocks, &rejected, b"must remain absent")
            .expect("stage rejected");
        rocks.inject_next_commit_fault(RocksCommitFault::BeforeWrite);
        assert!(archived.commit(batch).is_err());
        assert!(archived.reopen_required());
        assert!(!rocks.reopen_required());
        assert!(archived.snapshot().is_err());
        assert!(archived.segment_archive_inventory().is_err());
        let mut metadata = archived.batch();
        metadata
            .put(ColumnFamily::Meta, b"must-not-bypass", b"rejected")
            .expect("stage fenced metadata");
        assert!(archived.commit(metadata).is_err());
        drop(archived);

        let archived = raw
            .clone()
            .with_segment_archive(archive_path.clone())
            .expect("recover old publication");
        let snapshot = archived.snapshot().expect("old snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &retained)
                .expect("retained block"),
            Some(b"retained".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &rejected)
                .expect("rejected block"),
            None
        );
        drop(snapshot);

        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Blocks, &accepted, b"committed before error")
            .expect("stage accepted");
        rocks.inject_next_commit_fault(RocksCommitFault::AfterWrite);
        assert!(archived.commit(batch).is_err());
        assert!(archived.reopen_required());
        assert!(rocks.reopen_required());
        assert!(raw.reopen_required());
        assert!(archived.snapshot().is_err());
        let mut metadata = archived.batch();
        metadata
            .put(ColumnFamily::Meta, b"post-write-bypass", b"rejected")
            .expect("stage post-write metadata");
        assert!(archived.commit(metadata).is_err());
        drop(archived);
        drop(raw);
        drop(rocks);

        let rocks = RocksStore::open(&chain_path).expect("truly reopen RocksDB");
        let recovered = StoreHandle::Rocks(rocks.clone())
            .with_segment_archive(archive_path)
            .expect("recover committed publication");
        let snapshot = recovered.snapshot().expect("new snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &retained)
                .expect("retained block"),
            Some(b"retained".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &accepted)
                .expect("accepted block"),
            Some(b"committed before error".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &rejected)
                .expect("rejected block"),
            None
        );
        drop(snapshot);
        drop(recovered);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove segment fault fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn compaction_post_write_error_reopens_the_new_generation_without_data_loss() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hsrd-rocks-compaction-fault-test-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let chain_path = root.join("chain");
        let rocks = RocksStore::open(&chain_path).expect("open rocksdb");
        let raw = StoreHandle::Rocks(rocks.clone());
        let archive_path = root.join("payloads");
        let archived = raw
            .clone()
            .with_segment_archive(archive_path.clone())
            .expect("attach archive");
        let live = [0x91; 32];
        let dead = [0x92; 32];
        let mut batch = archived.batch();
        batch
            .put(ColumnFamily::Blocks, &live, b"live after compaction")
            .expect("stage live");
        batch
            .put(ColumnFamily::Blocks, &dead, b"dead before compaction")
            .expect("stage dead");
        archived.commit(batch).expect("commit fixtures");
        let mut batch = archived.batch();
        batch
            .delete(ColumnFamily::Blocks, &dead)
            .expect("retire dead locator");
        archived.commit(batch).expect("commit retirement");

        rocks.inject_next_commit_fault(RocksCommitFault::AfterWrite);
        let error = archived
            .compact_segment_archive()
            .expect_err("post-write acknowledgement fault");
        assert!(error.to_string().contains("outcome is uncertain"));
        assert!(archived.reopen_required());
        assert!(raw.reopen_required());
        assert!(rocks.reopen_required());
        assert!(archived.snapshot().is_err());
        assert!(archived.scrub_segment_archive().is_err());
        let mut metadata = archived.batch();
        metadata
            .put(ColumnFamily::Meta, b"compaction-bypass", b"rejected")
            .expect("stage fenced compaction metadata");
        assert!(archived.commit(metadata).is_err());
        drop(archived);
        drop(raw);
        drop(rocks);

        let rocks = RocksStore::open(&chain_path).expect("truly reopen RocksDB");
        let recovered = StoreHandle::Rocks(rocks.clone())
            .with_segment_archive(archive_path.clone())
            .expect("recover new generation");
        let snapshot = recovered.snapshot().expect("recovered snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &live)
                .expect("live block"),
            Some(b"live after compaction".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &dead)
                .expect("dead block"),
            None
        );
        drop(snapshot);
        assert_eq!(
            recovered
                .scrub_segment_archive()
                .expect("scrub recovered generation")
                .blocks
                .records,
            1
        );
        for entry in std::fs::read_dir(&archive_path).expect("read archive") {
            let name = entry
                .expect("archive entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            assert!(name.contains("-g0000000000000002-"), "{name}");
        }
        drop(recovered);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove compaction fault fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn compaction_post_commit_install_poison_fences_and_recovers_new_generation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hsrd-rocks-compaction-install-fault-test-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let chain_path = root.join("chain");
        let rocks = RocksStore::open(&chain_path).expect("open rocksdb");
        let raw = StoreHandle::Rocks(rocks.clone());
        let archive_path = root.join("payloads");
        let archived = raw
            .clone()
            .with_segment_archive(archive_path.clone())
            .expect("attach archive");
        let live = [0xa1; 32];
        let mut batch = archived.batch();
        batch
            .put(
                ColumnFamily::Blocks,
                &live,
                b"committed replacement generation",
            )
            .expect("stage live block");
        archived.commit(batch).expect("commit live block");
        let snapshot_before = archived.snapshot().expect("snapshot before compaction");

        let StoreHandle::Archived { archive, .. } = &archived else {
            panic!("expected archived store");
        };
        archive.inject_next_install_reader_poison();
        let error = archived
            .compact_segment_archive()
            .expect_err("post-commit installation poison");
        let message = error.to_string();
        assert!(
            message
                .contains("database publication committed but archive installation is incomplete"),
            "{message}"
        );
        assert!(message.contains("reopen required"), "{message}");
        assert!(archived.reopen_required());
        assert!(!raw.reopen_required());
        assert!(!rocks.reopen_required());
        assert!(archived.snapshot().is_err());
        assert!(snapshot_before.get(ColumnFamily::Blocks, &live).is_err());
        let mut fenced = archived.batch();
        fenced
            .put(ColumnFamily::Meta, b"install-fault-bypass", b"rejected")
            .expect("stage fenced metadata");
        assert!(archived.commit(fenced).is_err());

        let names = std::fs::read_dir(&archive_path)
            .expect("read preserved generations")
            .map(|entry| {
                entry
                    .expect("archive entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        for expected in [
            "block-g0000000000000001-",
            "undo-g0000000000000001-",
            "block-g0000000000000002-",
            "undo-g0000000000000002-",
        ] {
            assert!(
                names.iter().any(|name| name.contains(expected)),
                "missing {expected} in {names:?}"
            );
        }
        drop(snapshot_before);
        drop(archived);
        drop(raw);
        drop(rocks);

        let rocks = RocksStore::open(&chain_path).expect("truly reopen RocksDB");
        let recovered = StoreHandle::Rocks(rocks.clone())
            .with_segment_archive(archive_path.clone())
            .expect("recover committed generation");
        assert!(!recovered.reopen_required());
        let snapshot = recovered.snapshot().expect("recovered snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Blocks, &live)
                .expect("resolved replacement locator"),
            Some(b"committed replacement generation".to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, b"install-fault-bypass")
                .expect("fenced metadata"),
            None
        );
        drop(snapshot);
        assert_eq!(
            recovered
                .scrub_segment_archive()
                .expect("scrub recovered generation")
                .blocks
                .records,
            1
        );
        for entry in std::fs::read_dir(&archive_path).expect("read recovered archive") {
            let name = entry
                .expect("archive entry")
                .file_name()
                .to_string_lossy()
                .into_owned();
            assert!(name.contains("-g0000000000000002-"), "{name}");
        }
        drop(recovered);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove compaction install-fault fixture");
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
