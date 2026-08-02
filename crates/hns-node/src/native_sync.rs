use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use hns_chain::{
    prepare_header_record, read_canonical_hash, BlockIndexRecord, ChainTip, HeaderImport,
    HeaderIndex, HeaderRecord,
};
use hns_consensus::{
    advance_threshold_state, block_merkle_root, block_witness_root,
    compute_block_version_from_state, is_hsd_historical_block, validate_coinbase_height,
    validate_transaction_start, ConsensusError, ConsensusParams, DeploymentState, HeaderConsensus,
    HeaderParent, HeaderValidationContext, Network, ThresholdState, MAX_FUTURE_BLOCK_TIME,
};
use hns_mempool::{Admission, AirdropAdmission, ClaimAdmission};
use hns_p2p::{
    generate_private_key, normalize_peer_ip, peer_address_group, BrontideIdentity, CompactBlock,
    CompactBlockError, CompactBlockReconstruction, CompactBlockRequest, CompactBlockResponse,
    Inventory, InventoryKind, LivePeerConfig, LivePeerManager, LocatorPacket, OutboundPriority,
    P2pError, Packet, PeerDirection, PeerEvent, PeerId, PeerSnapshot, PeerTransport,
    SERVICE_NETWORK,
};
use hns_primitives::{
    blake2b_256, Block, BlockHash, CovenantKind, Header, Height, Reader, Txid, Writer,
};
use hns_rpc::{
    BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcExperimentalRegistryInfo, RpcHip76Info,
    RpcMethod, RpcService, RpcSnapshot,
};
#[cfg(all(test, feature = "rocksdb-backend"))]
use hns_store::mark_clean_shutdown;
use hns_store::{ColumnFamily, ReadSnapshot, Store, StoreError, StoreHandle, WriteBatch};
use hns_sync::{
    spawn_validation_pipeline,
    validation::{spawn_ordered_work_pipeline, OrderedWorkError},
    BlockDownloadRequest, BoundedOrphanPool, OrderedValidationResult, OrphanLimits, OrphanSnapshot,
    StatelessBlockValidator, StoredSyncCheckpoint, SyncAction, SyncCheckpoint, SyncError,
    SyncLimits, SyncScheduler, SyncSnapshot, ValidatedBlock, ValidationFailure,
    ValidationFailureKind, ValidationRejection, ValidationRequest, ValidationSubmitter,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch, RwLock},
    task::JoinHandle,
    time::{Instant, Interval, MissedTickBehavior},
};

use super::{
    authority_info, best_block_tip_from_snapshot, completed_deployment_period_with_lookup,
    current_unix_time, enforce_rpc_resource_limits, expected_bits_with_lookup, json_rpc_error,
    load_block as load_block_from_snapshot, load_block_index_record, load_header_record,
    median_time_past_with_lookup, mining_generation_from_snapshot, mining_snapshot_for_hash,
    preflight_reorg_reconciliation_budget, require_rpc_authorization,
    rpc_experimental_registry_info, rpc_hip76_info, rpc_immediately_unsupported,
    rpc_point_read_method, AuthorityMode, CanonicalChainEpoch, CanonicalStateWriter,
    CanonicalWriterError, ChainActivationFailure, DurableMiningState, FailedBlockMutation,
    FailedBlockStage, HeaderSummary, NativeRuntimeExtension, NodeBlockImport, NodeReadHandle,
    NodeReorg, NodeReorgLimits, NodeRuntime, NodeService, PreparedNativeActivation,
    ReorgStagedEffectMeter, RpcAuthorizationHeader, RpcLimits, RpcReadContext, RpcRuntimeLimits,
    ShutdownSignal, StatelessBodyValidation, HSRD_DIAGNOSTIC_API_VERSION,
    MAX_CANONICAL_WRITER_QUEUE_CAPACITY,
};
use super::{wallet_rpc, WalletBackend};
use crate::peer_bans::{
    load_peer_bans, persist_peer_bans, PeerBanBook, PeerBanLoad, HSD_BAN_SCORE,
    HSD_BAN_TIME_SECONDS, MAX_PEER_BANS,
};

const MAX_LOCATOR_ENTRIES: usize = 32;
const MAX_SERVED_HEADERS: usize = hns_p2p::MAX_HEADERS;
const MAX_GETDATA_ITEMS: usize = 1_024;
const LOCAL_ORPHAN_PEER: PeerId = PeerId(0);
const MAX_RECONNECT_DELAY_SECONDS: u64 = 60;
const MAX_DISCOVERY_CONNECT_FAILURES: u32 = 3;
const MAX_PENDING_COMPACT_BLOCKS_PER_PEER: usize = 15;
const MAX_PENDING_COMPACT_BLOCKS: usize = 128;
const COMPACT_BLOCK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_KNOWN_PEER_ADDRESSES: usize = 16_384;
const DEFAULT_KNOWN_PEER_ADDRESSES: usize = 4_096;
const ADDRESS_BOOK_KEY: &[u8] = b"address-book/v1";
const ADDRESS_BOOK_MAGIC: &[u8; 4] = b"HAB1";
const ADDRESS_BOOK_VERSION: u8 = 2;
const ADDRESS_BOOK_CHECKSUM_SIZE: usize = 32;
const ADDRESS_BOOK_ENTRY_SIZE: usize = 96;
const ADDRESS_BOOK_HEADER_SIZE: usize = 26;
const MAX_ADDRESS_BOOK_RECORD_SIZE: usize = ADDRESS_BOOK_HEADER_SIZE
    + MAX_KNOWN_PEER_ADDRESSES * ADDRESS_BOOK_ENTRY_SIZE
    + ADDRESS_BOOK_CHECKSUM_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MissingHeaderParent {
    parent: BlockHash,
}

impl fmt::Display for MissingHeaderParent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "missing header parent {}", self.parent.to_hex())
    }
}

impl Error for MissingHeaderParent {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerHeaderBatchLimit {
    limit: usize,
    actual: usize,
}

impl fmt::Display for PeerHeaderBatchLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "peer sent {} headers above the {}-header limit",
            self.actual, self.limit
        )
    }
}

impl Error for PeerHeaderBatchLimit {}
const ADDRESS_BOOK_FLUSH_INTERVAL: Duration = Duration::from_secs(120);
const HSD_ADDRESS_HORIZON_SECONDS: u64 = 30 * 24 * 60 * 60;
const HSD_ADDRESS_MIN_FAIL_SECONDS: u64 = 7 * 24 * 60 * 60;
const HSD_ADDRESS_MAX_FAILURES: u32 = 10;
const HSD_ADDRESS_RECENT_ATTEMPT_SECONDS: u64 = 60;
const HSD_ADDRESS_TIMESTAMP_REFRESH_SECONDS: u64 = 20 * 60;
const MAX_ADDR_FUTURE_SECONDS: u64 = 10 * 60;
const FALLBACK_ADDR_AGE_SECONDS: u64 = 5 * 24 * 60 * 60;
const MIN_ADDR_TIMESTAMP: u64 = 100_000_000;
const MAX_NATIVE_SYNC_PEERS: usize = 256;
const MAX_NATIVE_SYNC_VALIDATION_WORKERS: usize = 128;
const MAX_NATIVE_SYNC_VALIDATION_QUEUE: usize = 8_192;
const MAX_VALIDATED_BODY_COMMIT_BATCH: usize = 32;
const MAX_CANONICAL_BODY_CANDIDATE_SCAN_SLICE: usize = 256;
const MAX_CANONICAL_STALE_RETRIES: usize = 8;
const MAX_HEADER_DEPLOYMENT_READS: usize = 2_000_000;
const MAX_NATIVE_SYNC_ORPHAN_BLOCKS: usize = 8_192;
const MAX_NATIVE_SYNC_ORPHAN_BYTES: usize = 1024 * 1024 * 1024;
const MAX_ACTIVE_STATE_CONNECT_BATCH: usize = 1_024;
pub(super) const MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE: usize = 288;
const MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE: usize = hns_p2p::MAX_HEADERS;
const MIN_NATIVE_SYNC_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_NATIVE_SYNC_CONTENTION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const NATIVE_RUNTIME_EXTENSION_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const NATIVE_RUNTIME_EXTENSION_ABORT_GRACE: Duration = Duration::from_secs(1);
// Native IBD deliberately fails over stalled body reservations sooner than
// HSD's conservative two-minute connection timeout. The request remains
// single-flight, bounded, and independently validated after reassignment.
const NATIVE_BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const NATIVE_MAX_INFLIGHT_PER_PEER: usize = 32;
const BRONTIDE_IDENTITY_FILE: &str = "p2p-identity-v1.key";

#[derive(Clone, Debug)]
struct OwnedOrphan {
    block: Block,
    height: Height,
}

#[derive(Debug)]
struct OwnedOrphanInvariant(String);

impl fmt::Display for OwnedOrphanInvariant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for OwnedOrphanInvariant {}

fn owned_orphan_invariant(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<OwnedOrphanInvariant>())
}

#[derive(Debug, Default)]
struct OwnedOrphanInsertOutcome {
    evicted: Vec<OwnedOrphan>,
}

#[derive(Debug, Default)]
struct OwnedOrphanChildrenOutcome {
    children: Vec<OwnedOrphan>,
    children_remain: bool,
}

/// Retains the scheduler height with every in-memory orphan body.
///
/// The underlying bounded pool deliberately owns only wire blocks. Keeping the
/// height sidecar here lets eviction and release reconcile scheduler ownership
/// synchronously, without a stable canonical read that can race the writer.
#[derive(Debug)]
struct OwnedOrphanPool {
    inner: BoundedOrphanPool,
    heights: HashMap<BlockHash, Height>,
    child_counts: HashMap<BlockHash, usize>,
    indexed_children: usize,
}

impl OwnedOrphanPool {
    fn new(limits: OrphanLimits) -> std::result::Result<Self, SyncError> {
        Ok(Self {
            inner: BoundedOrphanPool::new(limits)?,
            heights: HashMap::new(),
            child_counts: HashMap::new(),
            indexed_children: 0,
        })
    }

    fn contains(&self, hash: &BlockHash) -> bool {
        self.inner.contains(hash)
    }

    fn ensure_sidecar_exact(&self) -> Result<()> {
        let blocks = self.inner.snapshot().blocks;
        if blocks != self.heights.len() || blocks != self.indexed_children {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                "owned orphan sidecars have {} heights and {} child indexes for {blocks} retained blocks",
                self.heights.len(),
                self.indexed_children,
            ))));
        }
        Ok(())
    }

    fn has_children(&self, parent: BlockHash) -> bool {
        self.child_counts.contains_key(&parent)
    }

    fn index_child(&mut self, parent: BlockHash) -> Result<()> {
        let parent_children = self
            .child_counts
            .get(&parent)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                anyhow::Error::new(OwnedOrphanInvariant(format!(
                    "orphan parent {} child count overflowed",
                    parent.to_hex()
                )))
            })?;
        let indexed_children = self.indexed_children.checked_add(1).ok_or_else(|| {
            anyhow::Error::new(OwnedOrphanInvariant(
                "owned orphan child index overflowed".to_owned(),
            ))
        })?;
        self.child_counts.insert(parent, parent_children);
        self.indexed_children = indexed_children;
        Ok(())
    }

    fn unindex_child(&mut self, parent: BlockHash) -> Result<()> {
        let remove_parent = {
            let count = self.child_counts.get_mut(&parent).ok_or_else(|| {
                anyhow::Error::new(OwnedOrphanInvariant(format!(
                    "orphan parent {} has no child-count entry",
                    parent.to_hex()
                )))
            })?;
            *count = count.checked_sub(1).ok_or_else(|| {
                anyhow::Error::new(OwnedOrphanInvariant(format!(
                    "orphan parent {} child count underflowed",
                    parent.to_hex()
                )))
            })?;
            *count == 0
        };
        if remove_parent {
            self.child_counts.remove(&parent);
        }
        self.indexed_children = self.indexed_children.checked_sub(1).ok_or_else(|| {
            anyhow::Error::new(OwnedOrphanInvariant(
                "owned orphan child index underflowed".to_owned(),
            ))
        })?;
        Ok(())
    }

    #[cfg(test)]
    fn insert(&mut self, orphan: OwnedOrphan) -> Result<()> {
        let outcome = self.insert_with_evictions(orphan)?;
        if !outcome.evicted.is_empty() {
            anyhow::bail!(
                "owned orphan insertion unexpectedly evicted {} blocks",
                outcome.evicted.len()
            );
        }
        Ok(())
    }

    fn insert_with_evictions(&mut self, orphan: OwnedOrphan) -> Result<OwnedOrphanInsertOutcome> {
        self.ensure_sidecar_exact()?;
        let hash = orphan.block.hash();
        if self.inner.contains(&hash) {
            if self.heights.get(&hash) != Some(&orphan.height) {
                return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                    "owned orphan {} changed height while retained",
                    hash.to_hex()
                ))));
            }
            return Ok(OwnedOrphanInsertOutcome::default());
        }
        let parent = orphan.block.header.prev_block;
        let outcome = self
            .inner
            .insert_with_evictions(orphan.block)
            .context("failed to insert bounded owned orphan")?;
        let mut evicted = Vec::with_capacity(outcome.evicted.len());
        for block in outcome.evicted {
            let evicted_hash = block.hash();
            let height = self.heights.remove(&evicted_hash).ok_or_else(|| {
                anyhow::Error::new(OwnedOrphanInvariant(format!(
                    "evicted orphan {} has no owned height",
                    evicted_hash.to_hex()
                )))
            })?;
            self.unindex_child(block.header.prev_block)?;
            evicted.push(OwnedOrphan { block, height });
        }
        if outcome.inserted && self.heights.insert(hash, orphan.height).is_some() {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                "new orphan {} replaced an owned height",
                hash.to_hex()
            ))));
        }
        if outcome.inserted {
            self.index_child(parent)?;
        }
        self.ensure_sidecar_exact()?;
        Ok(OwnedOrphanInsertOutcome { evicted })
    }

    #[cfg(test)]
    fn take_children(&mut self, parent: BlockHash) -> Result<Vec<OwnedOrphan>> {
        let outcome = self.take_children_bounded(parent, usize::MAX)?;
        if outcome.children_remain {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                "unbounded orphan release left children for parent {}",
                parent.to_hex()
            ))));
        }
        Ok(outcome.children)
    }

    fn take_children_bounded(
        &mut self,
        parent: BlockHash,
        maximum_children: usize,
    ) -> Result<OwnedOrphanChildrenOutcome> {
        self.ensure_sidecar_exact()?;
        let outcome = self
            .inner
            .take_children_bounded(parent, maximum_children)
            .context("failed to take bounded orphan children")?;
        let mut children = Vec::with_capacity(outcome.children.len());
        for block in outcome.children {
            let hash = block.hash();
            let height = self.heights.remove(&hash).ok_or_else(|| {
                anyhow::Error::new(OwnedOrphanInvariant(format!(
                    "released orphan {} has no owned height",
                    hash.to_hex()
                )))
            })?;
            self.unindex_child(block.header.prev_block)?;
            children.push(OwnedOrphan { block, height });
        }
        if outcome.children_remain != self.has_children(parent) {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                "orphan parent {} bounded-release remainder disagrees with its owned child index",
                parent.to_hex()
            ))));
        }
        self.ensure_sidecar_exact()?;
        Ok(OwnedOrphanChildrenOutcome {
            children,
            children_remain: outcome.children_remain,
        })
    }

    fn snapshot(&self) -> OrphanSnapshot {
        self.inner.snapshot()
    }
}

trait ActiveStateOrphanPool {
    fn active_state_snapshot(&self) -> OrphanSnapshot;
    #[cfg(test)]
    fn take_child_hashes(&mut self, parent: BlockHash) -> Result<Vec<BlockHash>>;
}

impl ActiveStateOrphanPool for OwnedOrphanPool {
    fn active_state_snapshot(&self) -> OrphanSnapshot {
        self.snapshot()
    }

    #[cfg(test)]
    fn take_child_hashes(&mut self, parent: BlockHash) -> Result<Vec<BlockHash>> {
        Ok(self
            .take_children(parent)?
            .into_iter()
            .map(|orphan| orphan.block.hash())
            .collect())
    }
}

#[cfg(test)]
impl ActiveStateOrphanPool for BoundedOrphanPool {
    fn active_state_snapshot(&self) -> OrphanSnapshot {
        self.snapshot()
    }

    fn take_child_hashes(&mut self, parent: BlockHash) -> Result<Vec<BlockHash>> {
        Ok(self
            .take_children(parent)
            .into_iter()
            .map(|block| block.hash())
            .collect())
    }
}

#[derive(Debug)]
struct ReadyOrphanParents {
    queue: BTreeMap<u64, BlockHash>,
    queued: HashMap<BlockHash, u64>,
    next_id: u64,
    maximum: usize,
}

impl ReadyOrphanParents {
    fn new(maximum: usize) -> Self {
        Self {
            queue: BTreeMap::new(),
            queued: HashMap::new(),
            next_id: 0,
            maximum,
        }
    }

    fn enqueue(&mut self, parent: BlockHash) -> Result<()> {
        if self.queued.contains_key(&parent) {
            return Ok(());
        }
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or_else(|| {
            anyhow::Error::new(OwnedOrphanInvariant(
                "ready orphan-parent sequence overflowed".to_owned(),
            ))
        })?;
        if self.queued.len() >= self.maximum {
            anyhow::bail!(
                "ready orphan-parent queue exceeds its {}-parent bound",
                self.maximum
            );
        }
        let previous_parent = self.queued.insert(parent, id);
        let previous_id = self.queue.insert(id, parent);
        debug_assert_eq!(previous_parent, None);
        debug_assert_eq!(previous_id, None);
        self.next_id = next_id;
        Ok(())
    }

    fn preflight_enqueue(&self, parent: BlockHash) -> Result<()> {
        if !self.queued.contains_key(&parent) && self.next_id.checked_add(1).is_none() {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(
                "ready orphan-parent sequence overflowed".to_owned(),
            )));
        }
        Ok(())
    }

    fn remove(&mut self, parent: BlockHash) -> bool {
        let Some(id) = self.queued.remove(&parent) else {
            return false;
        };
        let removed = self.queue.remove(&id);
        debug_assert_eq!(removed, Some(parent));
        true
    }

    fn retain_live(&mut self, orphans: &OwnedOrphanPool, discards: &DeferredOrphanDiscards) {
        self.queued
            .retain(|parent, _| orphans.has_children(*parent) && !discards.contains(*parent));
        self.queue
            .retain(|id, parent| self.queued.get(parent).is_some_and(|queued| queued == id));
    }

    fn pop_front(&mut self) -> Option<BlockHash> {
        let (id, parent) = self.queue.pop_first()?;
        let removed = self.queued.remove(&parent);
        debug_assert_eq!(removed, Some(id));
        Some(parent)
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Debug)]
struct DeferredOrphanDiscards {
    queue: BTreeMap<u64, BlockHash>,
    queued: HashMap<BlockHash, u64>,
    next_id: u64,
    maximum: usize,
}

impl DeferredOrphanDiscards {
    fn new(maximum: usize) -> Self {
        Self {
            queue: BTreeMap::new(),
            queued: HashMap::new(),
            next_id: 0,
            maximum,
        }
    }

    fn enqueue(&mut self, parent: BlockHash, orphans: &OwnedOrphanPool) -> Result<()> {
        if !orphans.has_children(parent) || self.queued.contains_key(&parent) {
            return Ok(());
        }
        self.preflight_enqueue(parent, orphans)?;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or_else(|| {
            anyhow::Error::new(OwnedOrphanInvariant(
                "deferred orphan-discard sequence overflowed".to_owned(),
            ))
        })?;
        if self.queued.len() >= self.maximum {
            self.retain_live(orphans);
        }
        if self.queued.len() >= self.maximum {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                "deferred orphan-discard queue exceeds its {}-parent bound",
                self.maximum
            ))));
        }
        let previous_parent = self.queued.insert(parent, id);
        let previous_id = self.queue.insert(id, parent);
        debug_assert_eq!(previous_parent, None);
        debug_assert_eq!(previous_id, None);
        self.next_id = next_id;
        Ok(())
    }

    fn preflight_enqueue(&self, parent: BlockHash, orphans: &OwnedOrphanPool) -> Result<()> {
        if orphans.has_children(parent)
            && !self.queued.contains_key(&parent)
            && self.next_id.checked_add(1).is_none()
        {
            return Err(anyhow::Error::new(OwnedOrphanInvariant(
                "deferred orphan-discard sequence overflowed".to_owned(),
            )));
        }
        Ok(())
    }

    fn remove(&mut self, parent: BlockHash) -> bool {
        let Some(id) = self.queued.remove(&parent) else {
            return false;
        };
        let removed = self.queue.remove(&id);
        debug_assert_eq!(removed, Some(parent));
        true
    }

    fn retain_live(&mut self, orphans: &OwnedOrphanPool) {
        self.queued
            .retain(|parent, _| orphans.has_children(*parent));
        self.queue
            .retain(|id, parent| self.queued.get(parent).is_some_and(|queued| queued == id));
    }

    fn contains(&self, parent: BlockHash) -> bool {
        self.queued.contains_key(&parent)
    }

    fn pop_front(&mut self) -> Option<BlockHash> {
        let (id, parent) = self.queue.pop_first()?;
        let removed = self.queued.remove(&parent);
        debug_assert_eq!(removed, Some(id));
        Some(parent)
    }

    fn len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrphanWorkLane {
    Release,
    Discard,
}

impl OrphanWorkLane {
    fn alternate(self) -> Self {
        match self {
            Self::Release => Self::Discard,
            Self::Discard => Self::Release,
        }
    }
}

#[derive(Debug)]
struct OrphanWorkSchedule {
    next: OrphanWorkLane,
}

impl Default for OrphanWorkSchedule {
    fn default() -> Self {
        Self {
            next: OrphanWorkLane::Discard,
        }
    }
}

fn ensure_orphan_work_queues_exact(
    ready: &ReadyOrphanParents,
    discards: &DeferredOrphanDiscards,
) -> Result<()> {
    if ready.queue.len() != ready.queued.len() || discards.queue.len() != discards.queued.len() {
        return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
            "orphan work queue indexes disagree: ready {}/{}, discard {}/{}",
            ready.queue.len(),
            ready.queued.len(),
            discards.queue.len(),
            discards.queued.len()
        ))));
    }
    let indexed_parents = ready.len().checked_add(discards.len()).ok_or_else(|| {
        anyhow::Error::new(OwnedOrphanInvariant(
            "combined orphan-parent work queues overflowed".to_owned(),
        ))
    })?;
    if ready.maximum != discards.maximum
        || ready.len() > ready.maximum
        || discards.len() > discards.maximum
        || indexed_parents > ready.maximum
    {
        return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
            "orphan-parent work queues exceed their exact bounds: ready {}/{}, discard {}/{}, combined {indexed_parents}",
            ready.len(),
            ready.maximum,
            discards.len(),
            discards.maximum,
        ))));
    }
    Ok(())
}

#[cfg(test)]
fn assert_orphan_work_membership_exact(
    orphans: &OwnedOrphanPool,
    ready: &ReadyOrphanParents,
    discards: &DeferredOrphanDiscards,
) {
    for (id, parent) in &ready.queue {
        assert_eq!(ready.queued.get(parent), Some(id));
        assert!(orphans.has_children(*parent));
        assert!(!discards.contains(*parent));
    }
    for (parent, id) in &ready.queued {
        assert_eq!(ready.queue.get(id), Some(parent));
    }
    for (id, parent) in &discards.queue {
        assert_eq!(discards.queued.get(parent), Some(id));
        assert!(orphans.has_children(*parent));
        assert!(!ready.queued.contains_key(parent));
    }
    for (parent, id) in &discards.queued {
        assert_eq!(discards.queue.get(id), Some(parent));
    }
    assert!(ready.len().saturating_add(discards.len()) <= orphans.snapshot().blocks);
}

fn charge_header_deployment_read(
    reads: &mut usize,
    maximum_reads: usize,
    deadline: StdInstant,
) -> Result<()> {
    if StdInstant::now() >= deadline {
        anyhow::bail!("header deployment read exceeded its execution deadline");
    }
    *reads = reads.saturating_add(1);
    if *reads > maximum_reads {
        anyhow::bail!("header deployment read exceeded its {maximum_reads}-record budget");
    }
    Ok(())
}

// Key-bearing fixed seeds from the pinned HSD `lib/net/seeds` tables. HSD's
// DNS seed answers expose unauthenticated plaintext endpoints without static keys, so a
// native Brontide bootstrap must begin from these authenticated records and
// then learn more key-bearing peers through ADDR.
const HSD_MAINNET_BRONTIDE_SEEDS: &[(&str, &str)] = &[
    (
        "129.153.177.220",
        "02a58318ea330487308b1a4bd90bd196a466e99be64a3cf2f1fe7b5352154a25c2",
    ),
    (
        "159.69.46.23",
        "03e7c897432e08b0a2a6f6e9cfdb0aa8d3392f8abe4a3c2d40013b2ee06b1adb6a",
    ),
    (
        "173.255.209.126",
        "024798bdd795240b711787273406f7950fd2a943a0bb096701720682eb3aea37ed",
    ),
    (
        "74.207.247.120",
        "0290c11c1d0895f96f9c1b0c4f2b6034ee3d4ee8f5f90c9b6c76bd27d4bd0a5cbd",
    ),
    (
        "172.104.214.189",
        "039078400609f39f5ae6e6d132161561860e52d35637ed3f5a5050c160dd28dfde",
    ),
    (
        "45.79.134.225",
        "03fb5a5801cdb19f01472480d00c1c928e498f49955eab5217cd00e755bd267973",
    ),
    (
        "35.154.209.88",
        "022d850f3bfb951c6de1d2f239183721bfaa2b1ac89576200fcca6f84181d1da62",
    ),
    (
        "194.50.5.26",
        "023e3322d4221160923ea1dc481523a26ef3fa8483da062f7e92040534cc6b3606",
    ),
    (
        "194.50.5.27",
        "03949fede42b27117d0a75e08cf1b139a37241ad4bebcb5c8a9928fdec7469107d",
    ),
    (
        "194.50.5.28",
        "0247eb646fdf05bd470c5ad380d42e936ffe8278e46cc9bd5791ea58c28587ab45",
    ),
];

const HSD_TESTNET_BRONTIDE_SEEDS: &[(&str, &str)] = &[
    (
        "172.104.214.189",
        "039078400609f39f5ae6e6d132161561860e52d35637ed3f5a5050c160dd28dfde",
    ),
    (
        "173.255.209.126",
        "024798bdd795240b711787273406f7950fd2a943a0bb096701720682eb3aea37ed",
    ),
    (
        "172.104.177.177",
        "0255dfda9369ca3cd616844c00eed63f2d7740cd56780a856def1e64f536214539",
    ),
    (
        "139.162.183.168",
        "0334b93039cdda203e704bb5a4831b66665b2f7b0dcea7fd022dfea623b1aa4081",
    ),
];

const fn hsd_brontide_seeds(network: Network) -> &'static [(&'static str, &'static str)] {
    match network {
        Network::Mainnet => HSD_MAINNET_BRONTIDE_SEEDS,
        Network::Testnet => HSD_TESTNET_BRONTIDE_SEEDS,
        Network::Regtest | Network::Simnet => &[],
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSyncConfig {
    pub enabled: bool,
    /// Acquire and validate canonical headers without scheduling block bodies.
    pub headers_only: bool,
    pub connect_active_state: bool,
    pub active_state_connect_batch: usize,
    pub listen: Option<SocketAddr>,
    pub connect: Vec<SocketAddr>,
    /// Authenticated remote static keys for configured public-network peers.
    pub connect_keys: BTreeMap<SocketAddr, [u8; 33]>,
    /// Bootstrap from HSD's key-bearing fixed seeds and learn bounded peers
    /// from GETADDR/ADDR. Explicit `connect` peers remain pinned reconnect targets.
    pub discovery: bool,
    pub maximum_known_addresses: usize,
    pub maximum_inbound: usize,
    pub maximum_outbound: usize,
    pub validation_workers: usize,
    pub validation_queue: usize,
    pub orphan_blocks: usize,
    pub orphan_bytes: usize,
    pub poll_interval: Duration,
}

impl Default for NativeSyncConfig {
    fn default() -> Self {
        let validation_workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(MAX_NATIVE_SYNC_VALIDATION_WORKERS);
        let validation_queue = validation_workers
            .saturating_mul(32)
            .clamp(128, MAX_NATIVE_SYNC_VALIDATION_QUEUE);
        Self {
            enabled: false,
            headers_only: false,
            connect_active_state: false,
            active_state_connect_batch: 288,
            listen: None,
            connect: Vec::new(),
            connect_keys: BTreeMap::new(),
            discovery: false,
            maximum_known_addresses: DEFAULT_KNOWN_PEER_ADDRESSES,
            maximum_inbound: 32,
            maximum_outbound: 8,
            validation_workers,
            validation_queue,
            orphan_blocks: 1_024,
            orphan_bytes: 64 * 1024 * 1024,
            poll_interval: Duration::from_millis(250),
        }
    }
}

impl NativeSyncConfig {
    pub fn validate(&self, authority_mode: AuthorityMode, network: Network) -> Result<()> {
        if self.connect_active_state && !self.enabled {
            anyhow::bail!("active-state synchronization requires native sync to be enabled");
        }
        if self.headers_only && !self.enabled {
            anyhow::bail!("headers-only synchronization requires native sync to be enabled");
        }
        if self.headers_only && self.connect_active_state {
            anyhow::bail!("headers-only native sync cannot connect active state");
        }
        if !self.enabled {
            return Ok(());
        }
        if !matches!(
            authority_mode,
            AuthorityMode::Disabled | AuthorityMode::Native
        ) {
            anyhow::bail!("native sync live P2P requires disabled or native authority mode");
        }
        if self.active_state_connect_batch == 0
            || self.active_state_connect_batch > MAX_ACTIVE_STATE_CONNECT_BATCH
        {
            anyhow::bail!(
                "active-state connector batch {} must be within 1..={MAX_ACTIVE_STATE_CONNECT_BATCH}",
                self.active_state_connect_batch
            );
        }
        let has_discovery_endpoint = self.discovery && !hsd_brontide_seeds(network).is_empty();
        if self.listen.is_none() && self.connect.is_empty() && !has_discovery_endpoint {
            anyhow::bail!(
                "Native sync requires an inbound listener, an explicit outbound peer, or DNS discovery on a seeded network"
            );
        }
        if self.listen.is_some() && self.maximum_inbound == 0 {
            anyhow::bail!("Native sync listener requires a non-zero maximum-inbound value");
        }
        if (!self.connect.is_empty() || self.discovery) && self.maximum_outbound == 0 {
            anyhow::bail!("Native sync outbound peers require a non-zero maximum-outbound value");
        }
        if self.connect.len() > self.maximum_outbound {
            anyhow::bail!(
                "{} configured outbound peers exceed the maximum-outbound value {}",
                self.connect.len(),
                self.maximum_outbound
            );
        }
        if self
            .connect_keys
            .keys()
            .any(|address| !self.connect.contains(address))
        {
            anyhow::bail!("native sync has a static key for an unconfigured outbound peer");
        }
        if self
            .connect_keys
            .values()
            .any(|key| !matches!(key[0], 0x02 | 0x03))
        {
            anyhow::bail!("native sync configured peer has an invalid compressed static key");
        }
        if matches!(network, Network::Mainnet | Network::Testnet)
            && self
                .connect
                .iter()
                .any(|address| !self.connect_keys.contains_key(address))
        {
            anyhow::bail!("public-network configured peers require key@address Brontide endpoints");
        }
        if self.maximum_known_addresses == 0
            || self.maximum_known_addresses > MAX_KNOWN_PEER_ADDRESSES
        {
            anyhow::bail!(
                "Native sync known-address limit {} must be within 1..={MAX_KNOWN_PEER_ADDRESSES}",
                self.maximum_known_addresses
            );
        }
        if self.connect.len() > self.maximum_known_addresses {
            anyhow::bail!(
                "{} configured outbound peers exceed the known-address limit {}",
                self.connect.len(),
                self.maximum_known_addresses
            );
        }
        if self.validation_workers == 0 || self.validation_queue == 0 {
            anyhow::bail!("Native sync validation workers and queue must be non-zero");
        }
        if self.validation_workers > MAX_NATIVE_SYNC_VALIDATION_WORKERS {
            anyhow::bail!(
                "Native sync validation workers {} exceed the hard limit {}",
                self.validation_workers,
                MAX_NATIVE_SYNC_VALIDATION_WORKERS
            );
        }
        if self.validation_queue > MAX_NATIVE_SYNC_VALIDATION_QUEUE {
            anyhow::bail!(
                "Native sync validation queue {} exceeds the hard limit {}",
                self.validation_queue,
                MAX_NATIVE_SYNC_VALIDATION_QUEUE
            );
        }
        if self.orphan_blocks == 0 || self.orphan_bytes == 0 {
            anyhow::bail!("Native sync orphan bounds must be non-zero");
        }
        if self.orphan_blocks > MAX_NATIVE_SYNC_ORPHAN_BLOCKS {
            anyhow::bail!(
                "Native sync orphan block limit {} exceeds the hard limit {}",
                self.orphan_blocks,
                MAX_NATIVE_SYNC_ORPHAN_BLOCKS
            );
        }
        if self.orphan_bytes > MAX_NATIVE_SYNC_ORPHAN_BYTES {
            anyhow::bail!(
                "Native sync orphan byte limit {} exceeds the hard limit {}",
                self.orphan_bytes,
                MAX_NATIVE_SYNC_ORPHAN_BYTES
            );
        }
        if self.poll_interval < MIN_NATIVE_SYNC_POLL_INTERVAL {
            anyhow::bail!(
                "Native sync poll interval must be at least {} ms",
                MIN_NATIVE_SYNC_POLL_INTERVAL.as_millis()
            );
        }
        let maximum_peers = self
            .maximum_inbound
            .checked_add(self.maximum_outbound)
            .ok_or_else(|| anyhow::anyhow!("Native sync peer limits overflow usize"))?;
        if maximum_peers > MAX_NATIVE_SYNC_PEERS {
            anyhow::bail!(
                "Native sync total peer limit {maximum_peers} exceeds the hard limit {MAX_NATIVE_SYNC_PEERS}"
            );
        }

        let mut unique = HashSet::with_capacity(self.connect.len());
        for address in &self.connect {
            if !unique.insert(*address) {
                anyhow::bail!("duplicate native-sync outbound peer {address}");
            }
            if self.listen == Some(*address) {
                anyhow::bail!("Native-sync outbound peer {address} is the configured listener");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NativeSyncDiagnostics {
    pub api_version: u32,
    pub enabled: bool,
    pub headers_only: bool,
    pub observation_only: bool,
    pub active_state: bool,
    /// Opaque process-local identifier used only to correlate qualification
    /// observations across runtime restarts.
    pub runtime_instance: String,
    pub listen: Option<SocketAddr>,
    pub configured_outbound: Vec<SocketAddr>,
    pub discovery_enabled: bool,
    pub address_book_persistent: bool,
    pub known_addresses: usize,
    pub loaded_addresses: u64,
    pub pruned_addresses: u64,
    pub address_book_sequence: u64,
    pub address_book_flushes: u64,
    pub address_book_flush_failures: u64,
    pub address_book_decode_failures: u64,
    pub address_book_dirty: bool,
    pub last_address_book_flush: Option<u64>,
    pub address_book_last_error: Option<String>,
    pub ban_list_persistent: bool,
    pub banned_addresses: usize,
    pub loaded_bans: u64,
    pub pruned_bans: u64,
    pub expired_bans: u64,
    pub ban_events: u64,
    pub ban_list_sequence: u64,
    pub ban_list_flushes: u64,
    pub ban_list_flush_failures: u64,
    pub ban_list_decode_failures: u64,
    pub ban_list_dirty: bool,
    pub last_ban_list_flush: Option<u64>,
    pub ban_list_last_error: Option<String>,
    pub dns_seed_addresses: u64,
    pub dns_seed_failures: u64,
    pub discovery_connection_failures: u64,
    pub received_addresses: u64,
    pub accepted_addresses: u64,
    pub rejected_addresses: u64,
    pub served_addresses: u64,
    pub outbound_connected: usize,
    pub outbound_connecting: usize,
    pub outbound_address_groups: usize,
    pub outbound_reconnect_attempts: u64,
    pub compact_peers: usize,
    pub pending_compact_blocks: usize,
    pub received_compact_blocks: u64,
    pub reconstructed_compact_blocks: u64,
    pub compact_block_fallbacks: u64,
    pub served_compact_blocks: u64,
    pub served_block_transactions: u64,
    pub started_at: u64,
    /// Monotonic process-lifetime totals, including disconnected peers.
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peers: Vec<PeerSnapshot>,
    pub experimental_registry: RpcExperimentalRegistryInfo,
    #[serde(default)]
    pub hip76: RpcHip76Info,
    pub sync: SyncSnapshot,
    pub orphans: OrphanSnapshot,
    pub checkpoint_sequence: u64,
    pub served_headers: u64,
    pub served_blocks: u64,
    pub received_headers: u64,
    pub received_blocks: u64,
    pub stored_bodies: u64,
    pub stored_failed_bodies: u64,
    pub connected_blocks: u64,
    pub active_state_slices: u64,
    pub active_state_last_slice_blocks: usize,
    pub active_state_last_slice_millis: u64,
    pub active_state_max_slice_millis: u64,
    pub active_state_last_planning_micros: u64,
    pub active_state_last_commit_micros: u64,
    pub active_state_last_post_commit_micros: u64,
    pub active_state_last_prepared_blocks: usize,
    pub active_state_last_preparation_micros: u64,
    pub active_state_last_worker_micros: u64,
    pub active_state_max_preparation_in_flight: usize,
    pub active_state_stale_retries: u64,
    pub active_state_last_transactions: usize,
    pub active_state_last_non_coinbase_inputs: usize,
    pub active_state_last_outputs: usize,
    pub active_state_last_name_actions: usize,
    pub peer_event_backlog: usize,
    pub validation_result_backlog: usize,
    pub reorganizations: u64,
    pub contextual_failed_bodies: u64,
    pub received_transactions: u64,
    pub served_transactions: u64,
    pub rejected_transactions: u64,
    pub received_claims: u64,
    pub served_claims: u64,
    pub rejected_claims: u64,
    pub received_airdrops: u64,
    pub served_airdrops: u64,
    pub rejected_airdrops: u64,
    pub served_mempool_inventories: u64,
    pub rejected_messages: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderDeploymentEntry {
    pub name: String,
    pub state: ThresholdState,
    pub bit: u8,
    pub start_time: u64,
    pub timeout: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderCheckpointEvidence {
    pub height: Height,
    pub hash: BlockHash,
    pub anchored: bool,
}

/// Deployment and historical-script policy derived independently from the
/// complete canonical header ancestry. This does not claim that block bodies
/// or active state have been replayed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderDeploymentDiagnostics {
    pub best_header: ChainTip,
    pub next_height: Height,
    pub deployments: Vec<HeaderDeploymentEntry>,
    pub script_flags: u32,
    pub lock_flags: u32,
    pub name_flags: u32,
    pub has_airstop: bool,
    pub next_block_version: u32,
    pub final_checkpoint: Option<HeaderCheckpointEvidence>,
    pub historical_script_assumption_through: Option<Height>,
}

#[derive(Clone, Debug)]
struct HnsBodyValidator {
    network: Network,
    consensus: HeaderConsensus,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ActiveStateConnectOutcome {
    pub(super) connected: usize,
    pub(super) disconnected: usize,
    pub(super) contextual_failure: Option<FailedBlockMutation>,
    pub(super) planning_micros: u64,
    pub(super) state_commit_micros: u64,
    pub(super) post_commit_micros: u64,
    pub(super) workload: ActiveStateWorkload,
}

#[derive(Clone, Copy, Debug, Default)]
struct ActiveStatePreparationMetrics {
    blocks: usize,
    wall_micros: u64,
    aggregate_worker_micros: u64,
    maximum_in_flight: usize,
    stale_retries: usize,
}

#[derive(Debug)]
struct NativeActiveStatePlan {
    epoch: CanonicalChainEpoch,
    activation: NodeReorg,
    maximum_connect: usize,
    planning_micros: u64,
}

#[derive(Debug)]
struct NativeActiveStatePreparationInput {
    ordinal: usize,
    import: NodeBlockImport,
}

#[derive(Clone, Copy, Debug)]
struct NativeActiveStatePreparationOutput {
    proof: StatelessBodyValidation,
    worker_micros: u64,
    workload: ActiveStateWorkload,
}

#[derive(Debug)]
struct PreparedActiveStatePlan {
    epoch: CanonicalChainEpoch,
    activation: NodeReorg,
    prepared: PreparedNativeActivation,
    maximum_connect: usize,
    planning_micros: u64,
    preparation: ActiveStatePreparationMetrics,
    workload: ActiveStateWorkload,
}

#[derive(Debug, Default)]
struct NativeActiveStateSliceResult {
    outcome: ActiveStateConnectOutcome,
    preparation: ActiveStatePreparationMetrics,
    wall_millis: u64,
}

struct ActiveStateWorkerPermit {
    in_flight: Arc<AtomicUsize>,
}

impl ActiveStateWorkerPermit {
    fn acquire(in_flight: Arc<AtomicUsize>, maximum: &AtomicUsize) -> Self {
        let active = in_flight.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        maximum.fetch_max(active, Ordering::AcqRel);
        Self { in_flight }
    }
}

impl Drop for ActiveStateWorkerPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

struct DirectStagedEffectLimit {
    retry_connect: usize,
    limit: u64,
    actual: u64,
}

type ActiveStateConnectAttempt =
    std::ops::ControlFlow<DirectStagedEffectLimit, ActiveStateConnectOutcome>;

fn reorg_staged_effect_limit(error: &anyhow::Error) -> Option<(u64, u64)> {
    error
        .chain()
        .find_map(|cause| match cause.downcast_ref::<StoreError>() {
            Some(StoreError::LimitExceeded {
                context,
                limit,
                actual,
            }) if *context == ReorgStagedEffectMeter::CONTEXT => Some((*limit, *actual)),
            _ => None,
        })
}

fn canonical_writer_stale(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CanonicalWriterError>(),
            Some(
                CanonicalWriterError::StaleEpoch { .. }
                    | CanonicalWriterError::StaleChainEpoch { .. }
                    | CanonicalWriterError::Busy
            )
        )
    })
}

fn canonical_writer_busy(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CanonicalWriterError>(),
            Some(CanonicalWriterError::Busy)
        )
    })
}

fn canonical_writer_contention(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CanonicalWriterError>(),
            Some(
                CanonicalWriterError::Busy
                    | CanonicalWriterError::StaleEpoch { .. }
                    | CanonicalWriterError::StaleChainEpoch { .. }
                    | CanonicalWriterError::QueueFull { .. }
            )
        )
    })
}

fn peer_header_import_penalty(error: &anyhow::Error) -> Option<u32> {
    error
        .chain()
        .any(|cause| {
            cause.is::<PeerHeaderBatchLimit>()
                || matches!(
                    cause.downcast_ref::<ConsensusError>(),
                    Some(ConsensusError::InvalidHeader(_))
                )
        })
        .then_some(100)
}

fn peer_block_header_import_penalty(error: &anyhow::Error) -> Option<u32> {
    error
        .chain()
        .any(|cause| {
            cause.is::<PeerHeaderBatchLimit>()
                || matches!(
                    cause.downcast_ref::<ConsensusError>(),
                    Some(ConsensusError::InvalidHeader(_))
                )
        })
        .then_some(50)
}

fn canonical_writer_shutting_down(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CanonicalWriterError>(),
            Some(CanonicalWriterError::ShuttingDown)
        )
    })
}

fn native_sync_contention_retry_interval(base: Duration, consecutive: usize) -> Duration {
    let maximum = MAX_NATIVE_SYNC_CONTENTION_RETRY_INTERVAL.max(base);
    let doublings = consecutive
        .saturating_sub(1)
        .min(MAX_CANONICAL_STALE_RETRIES.saturating_sub(1));
    let mut delay = base;
    for _ in 0..doublings {
        delay = delay.saturating_mul(2).min(maximum);
    }
    delay
}

fn active_state_contention_retry_interval(consecutive: usize) -> Duration {
    native_sync_contention_retry_interval(MIN_NATIVE_SYNC_POLL_INTERVAL, consecutive)
}

fn trace_native_sync_contention_retry(
    operation: &'static str,
    consecutive: usize,
    retry_after: Duration,
    error: &anyhow::Error,
) {
    if consecutive.is_power_of_two() {
        tracing::warn!(
            operation,
            consecutive,
            retry_millis = retry_after.as_millis(),
            error = %error,
            "native-sync canonical contention; rescheduling"
        );
    } else {
        tracing::debug!(
            operation,
            consecutive,
            retry_millis = retry_after.as_millis(),
            error = %error,
            "native-sync canonical contention; rescheduling"
        );
    }
}

fn direct_staged_effect_retry(
    error: &anyhow::Error,
    is_reorg: bool,
    attempted_connect: usize,
) -> Option<(usize, u64, u64)> {
    if is_reorg || attempted_connect <= 1 {
        return None;
    }
    let (limit, actual) = reorg_staged_effect_limit(error)?;
    Some((attempted_connect.div_ceil(2), limit, actual))
}

#[cfg(test)]
fn drive_active_state_connect_retries<T>(
    initial_limit: usize,
    mut attempt: impl FnMut(usize) -> Result<std::ops::ControlFlow<DirectStagedEffectLimit, T>>,
) -> Result<T> {
    let mut attempt_limit = initial_limit;
    loop {
        match attempt(attempt_limit)? {
            std::ops::ControlFlow::Continue(outcome) => return Ok(outcome),
            std::ops::ControlFlow::Break(DirectStagedEffectLimit {
                retry_connect,
                limit,
                actual,
            }) => {
                if retry_connect == 0 || retry_connect >= attempt_limit {
                    anyhow::bail!(
                        "direct active-state retry limit {retry_connect} does not reduce attempted limit {attempt_limit}"
                    );
                }
                tracing::warn!(
                    retry_connect,
                    limit,
                    actual,
                    "direct active-state slice exceeded its atomic effect budget; retrying a smaller rollback-safe slice"
                );
                attempt_limit = retry_connect;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ActiveStateWorkload {
    transactions: usize,
    non_coinbase_inputs: usize,
    outputs: usize,
    name_actions: usize,
}

impl ActiveStateWorkload {
    fn for_block(block: &Block) -> Self {
        let mut workload = Self {
            transactions: block.transactions.len(),
            ..Self::default()
        };
        for (transaction_index, transaction) in block.transactions.iter().enumerate() {
            if transaction_index != 0 {
                workload.non_coinbase_inputs = workload
                    .non_coinbase_inputs
                    .saturating_add(transaction.inputs.len());
            }
            workload.outputs = workload.outputs.saturating_add(transaction.outputs.len());
            workload.name_actions = workload.name_actions.saturating_add(
                transaction
                    .outputs
                    .iter()
                    .filter(|output| output.covenant.kind != CovenantKind::None)
                    .count(),
            );
        }
        workload
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            transactions: self.transactions.saturating_add(other.transactions),
            non_coinbase_inputs: self
                .non_coinbase_inputs
                .saturating_add(other.non_coinbase_inputs),
            outputs: self.outputs.saturating_add(other.outputs),
            name_actions: self.name_actions.saturating_add(other.name_actions),
        }
    }
}

impl HnsBodyValidator {
    fn new(network: Network) -> Self {
        Self {
            network,
            consensus: HeaderConsensus::new(ConsensusParams::for_network(network)),
        }
    }
}

impl StatelessBlockValidator for HnsBodyValidator {
    fn validate(
        &self,
        block: &Block,
        height: Height,
    ) -> std::result::Result<(), ValidationRejection> {
        if block_merkle_root(block) != block.header.merkle_root {
            return Err(ValidationRejection::invalid_response(
                "body does not match the header merkle root",
            ));
        }
        if block_witness_root(block) != block.header.witness_root {
            return Err(ValidationRejection::invalid_response(
                "body does not match the header witness root",
            ));
        }
        validate_transaction_start(block, height, self.network)
            .map_err(|error| ValidationRejection::invalid_block(error.to_string()))?;
        if is_hsd_historical_block(self.network, true, height) {
            self.consensus
                .validate_block_name_limits(block)
                .map_err(|error| ValidationRejection::invalid_block(error.to_string()))?;
        } else {
            self.consensus
                .validate_block_body(block)
                .map_err(|error| ValidationRejection::invalid_block(error.to_string()))?;
        }
        validate_coinbase_height(block, height)
            .map_err(|error| ValidationRejection::invalid_block(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressAdmission {
    Added,
    Updated,
    Rejected,
}

impl AddressAdmission {
    const fn accepted(self) -> bool {
        matches!(self, Self::Added | Self::Updated)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedPeerAddress {
    address: SocketAddr,
    key: [u8; 33],
    services: u64,
    time: u64,
    failures: u32,
    last_success: u64,
    last_attempt: u64,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AddressBookRecord {
    network: Network,
    generation: u64,
    updated_at: u64,
    entries: Vec<PersistedPeerAddress>,
}

#[derive(Clone, Debug)]
struct KnownPeerAddress {
    wire: hns_p2p::NetAddress,
    configured: bool,
    failures: u32,
    last_success: u64,
    last_attempt: u64,
    eligible_at: Instant,
    sequence: u64,
}

#[derive(Debug)]
struct BoundedAddressBook {
    network: Network,
    listen: Option<SocketAddr>,
    maximum: usize,
    sequence: u64,
    durable_sequence: u64,
    dirty: bool,
    entries: BTreeMap<SocketAddr, KnownPeerAddress>,
    /// Exact eviction rank for every non-configured entry. Saturated insertion
    /// removes the first key in O(log N) instead of rescanning the address book.
    eviction_order: BTreeSet<(u64, u64, SocketAddr)>,
}

impl BoundedAddressBook {
    fn new(network: Network, listen: Option<SocketAddr>, maximum: usize) -> Result<Self> {
        if maximum == 0 || maximum > MAX_KNOWN_PEER_ADDRESSES {
            anyhow::bail!(
                "known-address limit {maximum} must be within 1..={MAX_KNOWN_PEER_ADDRESSES}"
            );
        }
        Ok(Self {
            network,
            listen,
            maximum,
            sequence: 0,
            durable_sequence: 0,
            dirty: false,
            entries: BTreeMap::new(),
            eviction_order: BTreeSet::new(),
        })
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn insert_configured(
        &mut self,
        address: SocketAddr,
        now: Instant,
        timestamp: u64,
    ) -> Result<()> {
        if self.entries.len() >= self.maximum && !self.entries.contains_key(&address) {
            anyhow::bail!("configured outbound peers exceed the bounded address book");
        }
        self.sequence = self.sequence.saturating_add(1);
        if let Some(existing) = self.entries.get(&address) {
            if !existing.configured {
                self.eviction_order
                    .remove(&(existing.wire.time, existing.sequence, address));
            }
        }
        let replaced = self.entries.insert(
            address,
            KnownPeerAddress {
                wire: hns_p2p::NetAddress::from_socket_addr(address, timestamp, SERVICE_NETWORK),
                configured: true,
                failures: 0,
                last_success: 0,
                last_attempt: 0,
                eligible_at: now,
                sequence: self.sequence,
            },
        );
        if replaced.is_some_and(|entry| !entry.configured) {
            self.dirty = true;
        }
        Ok(())
    }

    fn insert_discovered(
        &mut self,
        mut wire: hns_p2p::NetAddress,
        now: Instant,
        timestamp: u64,
    ) -> AddressAdmission {
        let Some(address) = wire.socket_addr() else {
            return AddressAdmission::Rejected;
        };
        let transport_key_valid = match self.network {
            Network::Mainnet | Network::Testnet => matches!(wire.key[0], 0x02 | 0x03),
            Network::Regtest | Network::Simnet => {
                wire.key == [0; 33] || matches!(wire.key[0], 0x02 | 0x03)
            }
        };
        if !transport_key_valid
            || wire.services & SERVICE_NETWORK == 0
            || !is_discoverable_address(self.network, self.listen, address)
        {
            return AddressAdmission::Rejected;
        }
        wire.time = normalize_peer_timestamp(wire.time, timestamp);

        if let Some(existing) = self.entries.get_mut(&address) {
            if existing.configured {
                return AddressAdmission::Updated;
            }
            let old_eviction = (existing.wire.time, existing.sequence, address);
            let old_services = existing.wire.services;
            let old_time = existing.wire.time;
            let old_key = existing.wire.key;
            existing.wire.services |= wire.services;
            if wire.time > existing.wire.time {
                existing.wire.time = wire.time;
                existing.wire.key = wire.key;
            }
            if existing.wire.services != old_services
                || existing.wire.time != old_time
                || existing.wire.key != old_key
            {
                self.dirty = true;
            }
            let new_eviction = (existing.wire.time, existing.sequence, address);
            if old_eviction != new_eviction {
                let removed = self.eviction_order.remove(&old_eviction);
                debug_assert!(removed, "updated address has an eviction-order key");
                self.eviction_order.insert(new_eviction);
            }
            return AddressAdmission::Updated;
        }

        if self.entries.len() >= self.maximum {
            let Some(eviction_key) = self.eviction_order.first().copied() else {
                return AddressAdmission::Rejected;
            };
            let removed = self.eviction_order.remove(&eviction_key);
            debug_assert!(removed, "selected eviction key exists");
            let eviction = eviction_key.2;
            self.entries.remove(&eviction);
            self.dirty = true;
        }

        self.sequence = self.sequence.saturating_add(1);
        let entry = KnownPeerAddress {
            wire,
            configured: false,
            failures: 0,
            last_success: 0,
            last_attempt: 0,
            eligible_at: now,
            sequence: self.sequence,
        };
        self.eviction_order
            .insert((entry.wire.time, entry.sequence, address));
        self.entries.insert(address, entry);
        self.dirty = true;
        AddressAdmission::Added
    }

    fn connection_candidates(
        &self,
        tracked: &HashMap<SocketAddr, ReconnectState>,
        bans: &PeerBanBook,
        now: Instant,
        timestamp: u64,
        maximum: usize,
    ) -> Vec<SocketAddr> {
        if maximum == 0 {
            return Vec::new();
        }
        let mut occupied_groups = tracked
            .iter()
            .filter(|(address, state)| {
                state.connected
                    || state.connecting
                    || (state.persistent
                        && state.next_attempt <= now
                        && !bans.is_banned(address.ip(), timestamp))
            })
            .map(|(address, _)| peer_address_group(address.ip()))
            .collect::<HashSet<_>>();
        let mut candidates = self
            .entries
            .iter()
            .filter(|(address, entry)| {
                !entry.configured
                    && entry.eligible_at <= now
                    && !tracked.contains_key(address)
                    && !bans.is_banned(address.ip(), timestamp)
            })
            .map(|(address, entry)| {
                (
                    entry.failures,
                    std::cmp::Reverse(entry.wire.time),
                    entry.sequence,
                    *address,
                )
            })
            .collect::<Vec<_>>();
        candidates.sort();
        let mut selected = Vec::with_capacity(maximum.min(candidates.len()));
        for (_, _, _, address) in candidates {
            if occupied_groups.insert(peer_address_group(address.ip())) {
                selected.push(address);
                if selected.len() == maximum {
                    break;
                }
            }
        }
        selected
    }

    fn wire_address(&self, address: SocketAddr) -> Option<hns_p2p::NetAddress> {
        self.entries.get(&address).map(|entry| entry.wire.clone())
    }

    fn remove_discovered_ip(&mut self, address: IpAddr) -> usize {
        let address = normalize_peer_ip(address);
        let removals = self
            .entries
            .iter()
            .filter(|(candidate, entry)| {
                !entry.configured && normalize_peer_ip(candidate.ip()) == address
            })
            .map(|(candidate, entry)| (*candidate, (entry.wire.time, entry.sequence, *candidate)))
            .collect::<Vec<_>>();
        for (candidate, eviction_key) in &removals {
            self.entries.remove(candidate);
            let removed = self.eviction_order.remove(eviction_key);
            debug_assert!(removed, "removed address has an eviction-order key");
        }
        let removed = removals.len();
        self.dirty |= removed > 0;
        removed
    }

    fn note_attempt(&mut self, address: SocketAddr, now: Instant, timestamp: u64) {
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        entry.failures = entry.failures.saturating_add(1);
        entry.last_attempt = timestamp;
        entry.eligible_at = now + reconnect_delay(entry.failures);
        if !entry.configured {
            self.dirty = true;
        }
    }

    fn note_transport_success(&mut self, address: SocketAddr, timestamp: u64) {
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        if timestamp.saturating_sub(entry.wire.time) > HSD_ADDRESS_TIMESTAMP_REFRESH_SECONDS {
            let old_eviction =
                (!entry.configured).then_some((entry.wire.time, entry.sequence, address));
            entry.wire.time = timestamp;
            if !entry.configured {
                let removed = self
                    .eviction_order
                    .remove(&old_eviction.expect("non-configured eviction key"));
                debug_assert!(removed, "refreshed address has an eviction-order key");
                self.eviction_order
                    .insert((entry.wire.time, entry.sequence, address));
                self.dirty = true;
            }
        }
    }

    fn note_success(&mut self, address: SocketAddr, now: Instant, timestamp: u64, services: u64) {
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        entry.wire.services |= services;
        entry.failures = 0;
        entry.last_success = timestamp;
        entry.last_attempt = timestamp;
        entry.eligible_at = now;
        if !entry.configured {
            self.dirty = true;
        }
    }

    fn advertised(
        &self,
        maximum: usize,
        bans: &PeerBanBook,
        timestamp: u64,
    ) -> Vec<hns_p2p::NetAddress> {
        let mut entries = self
            .entries
            .values()
            .filter(|entry| {
                let address = entry
                    .wire
                    .socket_addr()
                    .expect("address-book key is an IP socket");
                is_discoverable_address(self.network, self.listen, address)
                    && !bans.is_banned(address.ip(), timestamp)
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| {
            (
                std::cmp::Reverse(entry.wire.time),
                entry.sequence,
                entry.wire.socket_addr(),
            )
        });
        entries
            .into_iter()
            .take(maximum)
            .map(|entry| entry.wire.clone())
            .collect()
    }

    fn durable_entries(&self) -> Vec<PersistedPeerAddress> {
        self.entries
            .iter()
            .filter(|(_, entry)| !entry.configured)
            .map(|(address, entry)| PersistedPeerAddress {
                address: *address,
                key: entry.wire.key,
                services: entry.wire.services,
                time: entry.wire.time,
                failures: entry.failures,
                last_success: entry.last_success,
                last_attempt: entry.last_attempt,
                sequence: entry.sequence,
            })
            .collect()
    }

    fn restore(
        &mut self,
        mut record: AddressBookRecord,
        now: Instant,
        timestamp: u64,
    ) -> Result<(usize, usize)> {
        if record.network != self.network {
            anyhow::bail!(
                "address-book network {} does not match configured {}",
                record.network,
                self.network
            );
        }
        let original = record.entries.len();
        record.entries.retain(|entry| {
            is_discoverable_address(self.network, self.listen, entry.address)
                && entry.services & SERVICE_NETWORK != 0
                && !persisted_address_is_stale(entry, timestamp)
        });
        record.entries.sort_by_key(|entry| {
            (
                entry.failures,
                std::cmp::Reverse(entry.last_success),
                std::cmp::Reverse(entry.time),
                entry.sequence,
                entry.address,
            )
        });

        let mut loaded = 0usize;
        let mut seen = BTreeSet::new();
        for entry in record.entries {
            if !seen.insert(entry.address) || self.entries.contains_key(&entry.address) {
                continue;
            }
            if self.entries.len() >= self.maximum {
                break;
            }
            let retry_at = entry
                .last_attempt
                .saturating_add(reconnect_delay(entry.failures).as_secs());
            let delay = retry_at
                .saturating_sub(timestamp)
                .min(MAX_RECONNECT_DELAY_SECONDS);
            self.sequence = self.sequence.max(entry.sequence);
            let address = entry.address;
            let known = KnownPeerAddress {
                wire: {
                    let mut wire = hns_p2p::NetAddress::from_socket_addr(
                        entry.address,
                        entry.time,
                        entry.services,
                    );
                    wire.key = entry.key;
                    wire
                },
                configured: false,
                failures: entry.failures,
                last_success: entry.last_success,
                last_attempt: entry.last_attempt,
                eligible_at: now + Duration::from_secs(delay),
                sequence: entry.sequence,
            };
            self.eviction_order
                .insert((known.wire.time, known.sequence, address));
            self.entries.insert(address, known);
            loaded = loaded.saturating_add(1);
        }
        self.durable_sequence = record.generation;
        let pruned = original.saturating_sub(loaded);
        self.dirty = pruned > 0;
        Ok((loaded, pruned))
    }
}

impl AddressBookRecord {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.entries.len() > MAX_KNOWN_PEER_ADDRESSES {
            anyhow::bail!(
                "address-book record has {} entries; maximum is {MAX_KNOWN_PEER_ADDRESSES}",
                self.entries.len()
            );
        }
        let count = u32::try_from(self.entries.len())
            .map_err(|_| anyhow::anyhow!("address-book entry count exceeds u32"))?;
        let mut writer = Writer::with_capacity(
            ADDRESS_BOOK_HEADER_SIZE
                + self.entries.len() * ADDRESS_BOOK_ENTRY_SIZE
                + ADDRESS_BOOK_CHECKSUM_SIZE,
        );
        writer.write_bytes(ADDRESS_BOOK_MAGIC);
        writer.write_u8(ADDRESS_BOOK_VERSION);
        writer.write_u8(self.network.canonical_id());
        writer.write_u64(self.generation);
        writer.write_u64(self.updated_at);
        writer.write_u32(count);
        for entry in &self.entries {
            match entry.address.ip() {
                IpAddr::V4(ip) => {
                    writer.write_u8(4);
                    writer.write_bytes(&ip.octets());
                    writer.write_bytes(&[0; 12]);
                }
                IpAddr::V6(ip) => {
                    writer.write_u8(6);
                    writer.write_bytes(&ip.octets());
                }
            }
            writer.write_u16(entry.address.port());
            writer.write_bytes(&entry.key);
            writer.write_u64(entry.services);
            writer.write_u64(entry.time);
            writer.write_u32(entry.failures);
            writer.write_u64(entry.last_success);
            writer.write_u64(entry.last_attempt);
            writer.write_u64(entry.sequence);
        }
        let mut raw = writer.finish();
        raw.extend_from_slice(&blake2b_256(&raw));
        Ok(raw)
    }

    fn decode(raw: &[u8], expected_network: Network) -> Result<Self> {
        if raw.len() < ADDRESS_BOOK_HEADER_SIZE + ADDRESS_BOOK_CHECKSUM_SIZE
            || raw.len() > MAX_ADDRESS_BOOK_RECORD_SIZE
        {
            anyhow::bail!("address-book record has invalid length {}", raw.len());
        }
        let body_len = raw.len() - ADDRESS_BOOK_CHECKSUM_SIZE;
        let (body, checksum) = raw.split_at(body_len);
        if checksum != blake2b_256(body) {
            anyhow::bail!("address-book checksum mismatch");
        }
        let mut reader = Reader::new(body, MAX_ADDRESS_BOOK_RECORD_SIZE)?;
        if reader.read_vec(ADDRESS_BOOK_MAGIC.len())? != ADDRESS_BOOK_MAGIC {
            anyhow::bail!("address-book magic mismatch");
        }
        let version = reader.read_u8()?;
        if version != ADDRESS_BOOK_VERSION {
            anyhow::bail!("unsupported address-book version {version}");
        }
        let network_id = reader.read_u8()?;
        let network = Network::from_canonical_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("unknown address-book network ID {network_id}"))?;
        if network != expected_network {
            anyhow::bail!(
                "address-book network {network} does not match configured {expected_network}"
            );
        }
        let generation = reader.read_u64()?;
        let updated_at = reader.read_u64()?;
        let count = usize::try_from(reader.read_u32()?)
            .map_err(|_| anyhow::anyhow!("address-book count exceeds usize"))?;
        if count > MAX_KNOWN_PEER_ADDRESSES {
            anyhow::bail!(
                "address-book record has {count} entries; maximum is {MAX_KNOWN_PEER_ADDRESSES}"
            );
        }
        let expected_body_len = ADDRESS_BOOK_HEADER_SIZE
            .checked_add(count.saturating_mul(ADDRESS_BOOK_ENTRY_SIZE))
            .ok_or_else(|| anyhow::anyhow!("address-book record length overflow"))?;
        if body.len() != expected_body_len {
            anyhow::bail!(
                "address-book body has {} bytes; expected {expected_body_len}",
                body.len()
            );
        }
        let mut entries = Vec::with_capacity(count);
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let family = reader.read_u8()?;
            let ip_bytes = reader.read_vec(16)?;
            let ip = match family {
                4 => {
                    if ip_bytes[4..] != [0; 12] {
                        anyhow::bail!("address-book IPv4 padding is nonzero");
                    }
                    IpAddr::V4(Ipv4Addr::new(
                        ip_bytes[0],
                        ip_bytes[1],
                        ip_bytes[2],
                        ip_bytes[3],
                    ))
                }
                6 => {
                    let bytes: [u8; 16] = ip_bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("address-book IPv6 length mismatch"))?;
                    IpAddr::V6(Ipv6Addr::from(bytes))
                }
                other => anyhow::bail!("unknown address-book address family {other}"),
            };
            let address = SocketAddr::new(ip, reader.read_u16()?);
            if !seen.insert(address) {
                anyhow::bail!("address-book contains duplicate address {address}");
            }
            entries.push(PersistedPeerAddress {
                address,
                key: reader
                    .read_vec(33)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("address-book public key length mismatch"))?,
                services: reader.read_u64()?,
                time: reader.read_u64()?,
                failures: reader.read_u32()?,
                last_success: reader.read_u64()?,
                last_attempt: reader.read_u64()?,
                sequence: reader.read_u64()?,
            });
        }
        reader.ensure_finished()?;
        Ok(Self {
            network,
            generation,
            updated_at,
            entries,
        })
    }
}

fn persisted_address_is_stale(entry: &PersistedPeerAddress, now: u64) -> bool {
    if entry.last_attempt != 0
        && entry.last_attempt >= now.saturating_sub(HSD_ADDRESS_RECENT_ATTEMPT_SECONDS)
    {
        return false;
    }
    if entry.time == 0 || entry.time > now.saturating_add(MAX_ADDR_FUTURE_SECONDS) {
        return true;
    }
    if now.saturating_sub(entry.time) > HSD_ADDRESS_HORIZON_SECONDS {
        return true;
    }
    if entry.last_success == 0 && entry.failures >= MAX_DISCOVERY_CONNECT_FAILURES {
        return true;
    }
    entry.failures >= HSD_ADDRESS_MAX_FAILURES
        && now.saturating_sub(entry.last_success) > HSD_ADDRESS_MIN_FAIL_SECONDS
}

fn persist_address_book(
    store: &StoreHandle,
    addresses: &mut BoundedAddressBook,
    timestamp: u64,
) -> Result<bool> {
    if !addresses.dirty {
        return Ok(false);
    }
    let generation = addresses
        .durable_sequence
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("address-book generation exhausted"))?;
    let record = AddressBookRecord {
        network: addresses.network,
        generation,
        updated_at: timestamp,
        entries: addresses.durable_entries(),
    };
    let raw = record.encode()?;
    let mut batch = store.batch();
    batch.put(ColumnFamily::Peers, ADDRESS_BOOK_KEY, &raw)?;
    store.commit(batch)?;
    addresses.durable_sequence = generation;
    addresses.dirty = false;
    Ok(true)
}

fn normalize_peer_timestamp(timestamp: u64, now: u64) -> u64 {
    if timestamp <= MIN_ADDR_TIMESTAMP || timestamp > now.saturating_add(MAX_ADDR_FUTURE_SECONDS) {
        now.saturating_sub(FALLBACK_ADDR_AGE_SECONDS)
    } else {
        timestamp
    }
}

fn is_discoverable_address(
    network: Network,
    listen: Option<SocketAddr>,
    address: SocketAddr,
) -> bool {
    if address.port() == 0 || listen == Some(address) {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => is_discoverable_ipv4(network, ip),
        IpAddr::V6(ip) => is_discoverable_ipv6(network, ip),
    }
}

fn is_discoverable_ipv4(network: Network, ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if a == 0 || a >= 224 || ip.is_broadcast() {
        return false;
    }
    if matches!(network, Network::Regtest | Network::Simnet) {
        return true;
    }
    !(a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_discoverable_ipv6(network: Network, ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if matches!(network, Network::Regtest | Network::Simnet) {
        return true;
    }
    let segments = ip.segments();
    let unique_local = segments[0] & 0xfe00 == 0xfc00;
    let link_or_site_local = segments[0] & 0xffc0 == 0xfe80 || segments[0] & 0xffc0 == 0xfec0;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    !(unique_local || link_or_site_local || documentation)
}

const fn supports_addr_protocol(version: u32) -> bool {
    version >= 3
}

fn admit_getaddr(peer: PeerId, inbound: bool, served: &mut HashSet<PeerId>) -> bool {
    inbound && served.insert(peer)
}

#[derive(Clone, Debug)]
struct ReconnectState {
    persistent: bool,
    connected: bool,
    connecting: bool,
    failures: u32,
    next_attempt: Instant,
}

#[derive(Clone, Debug)]
struct PendingCompactBlock {
    peer: PeerId,
    received_at: Instant,
    reconstruction: CompactBlockReconstruction,
}

impl ReconnectState {
    fn new(now: Instant, persistent: bool) -> Self {
        Self {
            persistent,
            connected: false,
            connecting: false,
            failures: 0,
            next_attempt: now,
        }
    }

    fn transport_connected(&mut self, now: Instant) {
        self.connected = true;
        self.connecting = false;
        self.next_attempt = now + Duration::from_secs(MAX_RECONNECT_DELAY_SECONDS);
    }

    fn ready(&mut self, now: Instant) {
        self.connected = true;
        self.connecting = false;
        self.failures = 0;
        self.next_attempt = now + Duration::from_secs(MAX_RECONNECT_DELAY_SECONDS);
    }

    fn failed(&mut self, now: Instant) {
        self.connected = false;
        self.connecting = false;
        self.failures = self.failures.saturating_add(1);
        self.next_attempt = now + reconnect_delay(self.failures);
    }
}

#[derive(Debug)]
struct ConnectAttemptResult {
    address: SocketAddr,
    result: std::result::Result<PeerId, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeSupervisorLane {
    Maintenance,
    Connection,
    Peer,
    Validation,
}

impl NativeSupervisorLane {
    const fn next(self) -> Self {
        match self {
            Self::Maintenance => Self::Connection,
            Self::Connection => Self::Peer,
            Self::Peer => Self::Validation,
            Self::Validation => Self::Maintenance,
        }
    }
}

enum NativeSupervisorEvent {
    Maintenance,
    Connection(Option<ConnectAttemptResult>),
    Peer(Option<PeerEvent>),
    Validation(Option<OrderedValidationResult>),
}

impl NativeSupervisorEvent {
    const fn lane(&self) -> NativeSupervisorLane {
        match self {
            Self::Maintenance => NativeSupervisorLane::Maintenance,
            Self::Connection(_) => NativeSupervisorLane::Connection,
            Self::Peer(_) => NativeSupervisorLane::Peer,
            Self::Validation(_) => NativeSupervisorLane::Validation,
        }
    }
}

/// Select supervisor work in deterministic round-robin priority order.
///
/// Every receive and interval tick used here is cancellation safe. The caller
/// keeps shutdown in an outer, biased select so shutdown remains strict first
/// priority without allowing an overdue maintenance tick or a hot channel to
/// permanently starve another ready lane.
async fn next_native_supervisor_event(
    next_lane: &mut NativeSupervisorLane,
    poll: &mut Interval,
    connect_results: &mut mpsc::Receiver<ConnectAttemptResult>,
    peer_events: &mut mpsc::Receiver<PeerEvent>,
    validation_results: &mut mpsc::Receiver<OrderedValidationResult>,
) -> NativeSupervisorEvent {
    let event = match *next_lane {
        NativeSupervisorLane::Maintenance => {
            tokio::select! {
                biased;
                _ = poll.tick() => NativeSupervisorEvent::Maintenance,
                result = connect_results.recv() => NativeSupervisorEvent::Connection(result),
                event = peer_events.recv() => NativeSupervisorEvent::Peer(event),
                result = validation_results.recv() => NativeSupervisorEvent::Validation(result),
            }
        }
        NativeSupervisorLane::Connection => {
            tokio::select! {
                biased;
                result = connect_results.recv() => NativeSupervisorEvent::Connection(result),
                event = peer_events.recv() => NativeSupervisorEvent::Peer(event),
                result = validation_results.recv() => NativeSupervisorEvent::Validation(result),
                _ = poll.tick() => NativeSupervisorEvent::Maintenance,
            }
        }
        NativeSupervisorLane::Peer => {
            tokio::select! {
                biased;
                event = peer_events.recv() => NativeSupervisorEvent::Peer(event),
                result = validation_results.recv() => NativeSupervisorEvent::Validation(result),
                _ = poll.tick() => NativeSupervisorEvent::Maintenance,
                result = connect_results.recv() => NativeSupervisorEvent::Connection(result),
            }
        }
        NativeSupervisorLane::Validation => {
            tokio::select! {
                biased;
                result = validation_results.recv() => NativeSupervisorEvent::Validation(result),
                _ = poll.tick() => NativeSupervisorEvent::Maintenance,
                result = connect_results.recv() => NativeSupervisorEvent::Connection(result),
                event = peer_events.recv() => NativeSupervisorEvent::Peer(event),
            }
        }
    };
    *next_lane = event.lane().next();
    event
}

fn reset_native_supervisor_poll(poll: &mut Interval, interval: Duration) {
    poll.reset_after(interval);
}

fn native_body_candidate_scan_window(config: &NativeSyncConfig) -> usize {
    let validation_capacity = config
        .validation_queue
        .saturating_add(config.validation_workers);
    let network_capacity = config
        .maximum_outbound
        .saturating_mul(NATIVE_MAX_INFLIGHT_PER_PEER);
    config
        .orphan_blocks
        .min(validation_capacity.max(network_capacity).max(1))
        .min(MAX_CANONICAL_BODY_CANDIDATE_SCAN_SLICE)
}

#[derive(Debug, Default)]
struct DnsSeedResolution {
    addresses: Vec<hns_p2p::NetAddress>,
    errors: Vec<String>,
}

async fn resolve_hsd_dns_seeds(network: Network) -> DnsSeedResolution {
    let seeds = hsd_brontide_seeds(network);
    let mut resolved = Vec::with_capacity(seeds.len());
    let mut errors = Vec::new();
    for (host, encoded_key) in seeds {
        let parsed = host
            .parse::<IpAddr>()
            .map_err(|error| format!("invalid pinned HSD seed IP {host}: {error}"))
            .and_then(|ip| decode_compressed_public_key(encoded_key).map(|key| (ip, key)));
        match parsed {
            Ok((ip, key)) => {
                let mut wire = hns_p2p::NetAddress::from_socket_addr(
                    SocketAddr::new(ip, network.params().brontide_port),
                    0,
                    SERVICE_NETWORK,
                );
                wire.key = key;
                resolved.push(wire);
            }
            Err(error) => errors.push(error),
        }
    }
    DnsSeedResolution {
        addresses: resolved,
        errors,
    }
}

fn decode_compressed_public_key(encoded: &str) -> std::result::Result<[u8; 33], String> {
    if encoded.len() != 66 {
        return Err(format!(
            "compressed public key has {} hex characters; expected 66",
            encoded.len()
        ));
    }
    let mut key = [0u8; 33];
    for (index, output) in key.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|error| format!("invalid compressed public key hex: {error}"))?;
    }
    if !matches!(key[0], 0x02 | 0x03) {
        return Err("compressed public key has an invalid prefix".to_owned());
    }
    Ok(key)
}

fn load_or_create_brontide_identity(data_dir: Option<&Path>) -> Result<BrontideIdentity> {
    let Some(data_dir) = data_dir else {
        return Ok(BrontideIdentity::generate());
    };
    fs::create_dir_all(data_dir).with_context(|| {
        format!(
            "failed to create Brontide identity directory {}",
            data_dir.display()
        )
    })?;
    let path = data_dir.join(BRONTIDE_IDENTITY_FILE);
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let private_key = generate_private_key();
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(&private_key).with_context(|| {
                        format!("failed to write Brontide identity {}", path.display())
                    })?;
                    file.sync_all().with_context(|| {
                        format!("failed to sync Brontide identity {}", path.display())
                    })?;
                    private_key.to_vec()
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => fs::read(&path)
                    .with_context(|| {
                        format!("failed to read raced Brontide identity {}", path.display())
                    })?,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to create Brontide identity {}", path.display())
                    });
                }
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read Brontide identity {}", path.display()));
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path)
            .with_context(|| format!("failed to stat Brontide identity {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "Brontide identity {} must not be accessible by group or other users",
                path.display()
            );
        }
    }

    let private_key: [u8; 32] = raw.try_into().map_err(|raw: Vec<u8>| {
        anyhow::anyhow!(
            "Brontide identity {} has {} bytes; expected 32",
            path.display(),
            raw.len()
        )
    })?;
    BrontideIdentity::from_private_key(private_key)
        .map_err(|error| anyhow::anyhow!("invalid Brontide identity {}: {error}", path.display()))
}

impl NodeService {
    pub async fn run_native_sync_until_shutdown(self, shutdown: ShutdownSignal) -> Result<()> {
        self.run_native_sync_until_shutdown_with_extension(shutdown, None)
            .await
    }

    pub(crate) async fn run_native_sync_until_shutdown_with_extension(
        self,
        shutdown: ShutdownSignal,
        extension: Option<Box<dyn NativeRuntimeExtension>>,
    ) -> Result<()> {
        self.config
            .native_sync
            .validate(self.config.authority_mode, self.config.network)?;
        if !self.config.native_sync.enabled {
            return self.run_rpc_until_shutdown(shutdown).await;
        }

        let native_sync_config = self.config.native_sync.clone();
        let rpc_bind = self.config.rpc_bind;
        let rpc_authorization = self.config.rpc_authorization.clone();
        let rpc_limits = self.config.rpc_limits;
        let network = self.config.network;
        let data_dir = self.config.data_dir.clone();
        let ban_list_persistent = self.config.data_dir.is_some();
        let address_book_persistent = native_sync_config.discovery && ban_list_persistent;
        let store = self.state.store.clone();
        let runtime = NodeRuntime::spawn(
            self,
            native_sync_config
                .validation_queue
                .min(MAX_CANONICAL_WRITER_QUEUE_CAPACITY),
        )?;
        let node = runtime.read();
        let writer = runtime.writer();
        let rpc_read_context = node.rpc_read_context()?;
        writer
            .execute(None, "ensure native-sync genesis header", |node| {
                node.native_sync_ensure_genesis_header()
            })
            .await?;

        let checkpoint_store = StoredSyncCheckpoint::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize sync checkpoint: {error}"))?;
        let durable_checkpoint = checkpoint_store
            .load()
            .map_err(|error| anyhow::anyhow!("failed to load sync checkpoint: {error}"))?;
        let scheduler_now = StdInstant::now();
        let maximum_peers = native_sync_config
            .maximum_inbound
            .checked_add(native_sync_config.maximum_outbound)
            .ok_or_else(|| anyhow::anyhow!("Native sync peer limits overflow usize"))?;
        let sync_limits = SyncLimits {
            maximum_peers,
            maximum_inflight_per_peer: NATIVE_MAX_INFLIGHT_PER_PEER,
            block_request_timeout: NATIVE_BLOCK_REQUEST_TIMEOUT,
            ..SyncLimits::default()
        };
        let mut scheduler = match durable_checkpoint.as_ref() {
            Some(checkpoint) => SyncScheduler::restore(sync_limits, scheduler_now, checkpoint),
            None => SyncScheduler::new(sync_limits, scheduler_now),
        }
        .map_err(|error| anyhow::anyhow!("failed to initialize sync scheduler: {error}"))?;
        scheduler.set_headers_only(native_sync_config.headers_only);

        let best_header = node.native_sync_best_header_tip()?;
        let active_tip = node.native_sync_active_tip()?;
        let stored_tip = node.native_sync_contiguous_body_tip(
            durable_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.stored_tip.as_ref()),
        )?;
        scheduler.set_best_header(best_header);
        scheduler.set_active_tip(active_tip.clone());
        scheduler.set_stored_tip(stored_tip);

        let mut peer_config = LivePeerConfig::for_network(network);
        if matches!(network, Network::Mainnet | Network::Testnet) {
            peer_config.transport =
                PeerTransport::Brontide(load_or_create_brontide_identity(data_dir.as_deref())?);
        }
        peer_config.maximum_inbound = native_sync_config.maximum_inbound;
        peer_config.maximum_outbound = native_sync_config.maximum_outbound;
        peer_config.ban_score = HSD_BAN_SCORE;
        peer_config.ban_time = Duration::from_secs(HSD_BAN_TIME_SECONDS);
        let (peers, mut peer_events) = LivePeerManager::new(peer_config)
            .map_err(|error| anyhow::anyhow!("failed to initialize live peers: {error}"))?;
        peers.set_local_height(active_tip.as_ref().map_or(0, |tip| tip.height));

        let ban_timestamp = unix_time();
        let mut ban_list = PeerBanBook::new(network, MAX_PEER_BANS)?;
        let mut loaded_bans = 0u64;
        let mut pruned_bans = 0u64;
        let mut ban_list_decode_failures = 0u64;
        if ban_list_persistent {
            let PeerBanLoad {
                book,
                loaded,
                pruned,
                decode_error,
            } = load_peer_bans(&store, network, MAX_PEER_BANS, ban_timestamp)?;
            ban_list = book;
            loaded_bans = loaded as u64;
            pruned_bans = pruned as u64;
            if let Some(error) = decode_error {
                ban_list_decode_failures = 1;
                tracing::warn!(%error, "discarding invalid durable HNS peer-ban list");
            }
        }
        peers
            .replace_bans(ban_list.active_bans(ban_timestamp))
            .await;

        node.native_sync_queue_missing_canonical_bodies(&mut scheduler)?;

        let mut orphan_pool = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: native_sync_config.orphan_blocks,
            maximum_bytes: native_sync_config.orphan_bytes,
        })
        .map_err(|error| anyhow::anyhow!("failed to initialize orphan pool: {error}"))?;
        let mut ready_orphan_parents = ReadyOrphanParents::new(native_sync_config.orphan_blocks);
        let mut deferred_orphan_discards =
            DeferredOrphanDiscards::new(native_sync_config.orphan_blocks);
        let mut orphan_work_schedule = OrphanWorkSchedule::default();
        let (validation, mut validated) = spawn_validation_pipeline(
            Arc::new(HnsBodyValidator::new(network)),
            native_sync_config.validation_workers,
            native_sync_config.validation_queue,
        )
        .map_err(|error| anyhow::anyhow!("failed to initialize validation pipeline: {error}"))?;

        let address_now = Instant::now();
        let address_timestamp = unix_time();
        let mut address_book = BoundedAddressBook::new(
            network,
            native_sync_config.listen,
            native_sync_config.maximum_known_addresses,
        )?;
        for address in &native_sync_config.connect {
            address_book.insert_configured(*address, address_now, address_timestamp)?;
            if let Some(key) = native_sync_config.connect_keys.get(address) {
                address_book
                    .entries
                    .get_mut(address)
                    .expect("configured address was inserted")
                    .wire
                    .key = *key;
            }
        }
        let mut loaded_addresses = 0u64;
        let mut pruned_addresses = 0u64;
        let mut address_book_decode_failures = 0u64;
        let mut dns_seed_addresses = 0u64;
        let mut dns_seed_failures = 0u64;
        if address_book_persistent {
            let durable_address_book = {
                let snapshot = store
                    .snapshot()
                    .context("failed to open address-book snapshot")?;
                snapshot
                    .get(ColumnFamily::Peers, ADDRESS_BOOK_KEY)
                    .context("failed to read durable address book")?
            };
            if let Some(raw) = durable_address_book {
                match AddressBookRecord::decode(&raw, network)
                    .and_then(|record| address_book.restore(record, address_now, address_timestamp))
                {
                    Ok((loaded, pruned)) => {
                        loaded_addresses = loaded as u64;
                        pruned_addresses = pruned as u64;
                    }
                    Err(error) => {
                        address_book_decode_failures = 1;
                        address_book.dirty = true;
                        tracing::warn!(%error, "discarding invalid durable HNS address book");
                    }
                }
            }
        }
        if native_sync_config.discovery {
            let resolution = resolve_hsd_dns_seeds(network).await;
            dns_seed_failures = resolution.errors.len() as u64;
            for error in resolution.errors {
                tracing::warn!(%error, "HNS fixed-seed bootstrap failed");
            }
            for mut wire in resolution.addresses {
                wire.time = address_timestamp;
                if address_book
                    .insert_discovered(wire, address_now, address_timestamp)
                    .accepted()
                {
                    dns_seed_addresses = dns_seed_addresses.saturating_add(1);
                }
            }
            if native_sync_config.connect.is_empty()
                && native_sync_config.listen.is_none()
                && address_book.len() == 0
            {
                anyhow::bail!("HNS DNS discovery resolved no admissible peer addresses");
            }
        }

        let mut reconnects = native_sync_config
            .connect
            .iter()
            .copied()
            .map(|address| (address, ReconnectState::new(address_now, true)))
            .collect::<HashMap<_, _>>();
        fill_discovery_slots(
            &address_book,
            &mut reconnects,
            &ban_list,
            native_sync_config.maximum_outbound,
            address_now,
            address_timestamp,
        );

        let initial_sequence = durable_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.sequence);
        let initial_experimental_registry =
            rpc_experimental_registry_info(&peers.denuo_summary().await);
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics {
            api_version: HSRD_DIAGNOSTIC_API_VERSION,
            enabled: true,
            headers_only: native_sync_config.headers_only,
            observation_only: !native_sync_config.connect_active_state,
            active_state: native_sync_config.connect_active_state,
            runtime_instance: runtime_instance_id(),
            listen: native_sync_config.listen,
            configured_outbound: native_sync_config.connect.clone(),
            discovery_enabled: native_sync_config.discovery,
            address_book_persistent,
            known_addresses: address_book.len(),
            loaded_addresses,
            pruned_addresses,
            address_book_sequence: address_book.durable_sequence,
            address_book_decode_failures,
            address_book_dirty: address_book.dirty,
            ban_list_persistent,
            banned_addresses: ban_list.len(),
            loaded_bans,
            pruned_bans,
            ban_list_sequence: ban_list.durable_sequence(),
            ban_list_decode_failures,
            ban_list_dirty: ban_list.is_dirty(),
            dns_seed_addresses,
            dns_seed_failures,
            started_at: unix_time(),
            experimental_registry: initial_experimental_registry,
            hip76: rpc_hip76_info(&[]),
            sync: scheduler.snapshot(),
            orphans: orphan_pool.snapshot(),
            checkpoint_sequence: initial_sequence,
            ..NativeSyncDiagnostics::default()
        }));
        let diagnostic_rpc = initialize_cached_diagnostic_rpc(&node, &diagnostics).await?;
        let wallet_rpc_authenticated = rpc_authorization.is_some();
        let wallet_rpc_profile_enabled = node.wallet_index_profile().wallet;
        let wallet_rpc_active_state_enabled =
            native_sync_config.connect_active_state && !native_sync_config.headers_only;
        let wallet_backend = (wallet_rpc_authenticated
            && wallet_rpc_profile_enabled
            && wallet_rpc_active_state_enabled)
            .then(|| runtime.wallet_backend(peers.clone()));

        // Bind diagnostics before startup replay/compaction. The cached,
        // explicitly timestamped snapshot remains readable while the
        // canonical writer is busy; authoritative parent reads use stable
        // generations from the live node.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let rpc_listener = TcpListener::bind(rpc_bind)
            .await
            .with_context(|| format!("failed to bind RPC listener on {rpc_bind}"))?;
        let rpc_state = NativeSyncHttpState {
            node: node.clone(),
            diagnostics: Arc::clone(&diagnostics),
            diagnostic_rpc: Arc::clone(&diagnostic_rpc),
            read_context: rpc_read_context,
            wallet_backend,
            wallet_rpc_authenticated,
            wallet_rpc_profile_enabled,
            limits: rpc_limits,
        };
        let rpc_task = tokio::spawn(serve_native_sync_rpc(
            rpc_listener,
            rpc_state,
            rpc_authorization,
            shutdown_rx.clone(),
        ));

        if native_sync_config.connect_active_state {
            let context = ActiveStateConnectionContext {
                node: &node,
                writer: &writer,
                peers: &peers,
                diagnostics: &diagnostics,
                diagnostic_rpc: &diagnostic_rpc,
            };
            let startup_affected = connect_stored_active_state_with_diagnostic_rpc(
                &context,
                &mut scheduler,
                &mut orphan_pool,
                native_sync_config.active_state_connect_batch,
            )
            .await
            .map_err(|error| error.context("failed to resume active-state synchronization"));
            let startup_affected = match startup_affected {
                Ok(affected) => affected,
                Err(error) => {
                    let _ = shutdown_tx.send(true);
                    let _ = rpc_task.await;
                    return Err(error);
                }
            };
            enqueue_affected_orphan_discards(
                &startup_affected,
                &orphan_pool,
                &mut ready_orphan_parents,
                &mut deferred_orphan_discards,
            )?;
        }

        let listener_task = if let Some(address) = native_sync_config.listen {
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("failed to bind HNS P2P listener on {address}"))?;
            let peers = peers.clone();
            let mut shutdown = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                peers
                    .serve_listener(listener, async move {
                        let _ = shutdown.changed().await;
                    })
                    .await
            }))
        } else {
            None
        };
        let mut extension_task = extension
            .map(|extension| extension.spawn(runtime.clone(), peers.clone(), shutdown_rx.clone()));

        let (connect_results_tx, mut connect_results_rx) =
            mpsc::channel::<ConnectAttemptResult>(native_sync_config.maximum_outbound.max(1));

        tracing::info!(
            rpc = %rpc_bind,
            p2p = ?native_sync_config.listen,
            outbound = reconnects.len(),
            discovery = native_sync_config.discovery,
            known_addresses = address_book.len(),
            "hsrd native-sync runtime started"
        );

        let mut checkpoint_sequence = initial_sequence;
        let mut poll = tokio::time::interval(native_sync_config.poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        poll.tick().await;
        let mut active_state_poll = tokio::time::interval(MIN_NATIVE_SYNC_POLL_INTERVAL);
        active_state_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        active_state_poll.tick().await;
        let mut peer_state_flush = tokio::time::interval(ADDRESS_BOOK_FLUSH_INTERVAL);
        peer_state_flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
        peer_state_flush.tick().await;
        let mut served_getaddr = HashSet::new();
        let mut compact_peers = HashSet::new();
        let mut pending_compact_blocks = HashMap::new();
        let mut shutdown_wait = Box::pin(shutdown.wait());
        let mut terminal_error: Option<anyhow::Error> = None;
        let mut active_state_task: Option<JoinHandle<Result<NativeActiveStateSliceResult>>> = None;
        let mut active_state_completion: Option<NativeActiveStateSliceResult> = None;
        let mut consecutive_active_state_contention = 0usize;
        let mut consecutive_maintenance_busy = 0usize;
        let mut next_supervisor_lane = NativeSupervisorLane::Maintenance;

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_wait => break,
                result = async {
                    extension_task
                        .as_mut()
                        .expect("native extension task select guard")
                        .await
                }, if extension_task.is_some() => {
                    let _finished = extension_task
                        .take()
                        .expect("completed native extension task remains present");
                    let error = unexpected_extension_exit(result);
                    record_error(&diagnostics, format!("{error:#}")).await;
                    terminal_error = Some(error);
                    break;
                }
                _ = peer_state_flush.tick(), if ban_list_persistent => {
                    if address_book_persistent {
                        flush_address_book(&store, &mut address_book, &diagnostics).await;
                    }
                    flush_peer_bans(&store, &mut ban_list, &diagnostics).await;
                }
                _ = active_state_poll.tick(),
                    if native_sync_config.connect_active_state
                        && active_state_task.is_none()
                        && (active_state_completion.is_some()
                            || active_state_work_ready(&scheduler)) =>
                {
                    if active_state_completion.is_some() {
                        let context = ActiveStateConnectionContext {
                            node: &node,
                            writer: &writer,
                            peers: &peers,
                            diagnostics: &diagnostics,
                            diagnostic_rpc: &diagnostic_rpc,
                        };
                        let completion_result = {
                            let completed = active_state_completion
                                .as_ref()
                                .expect("active-state completion remains retained");
                            complete_stored_active_state_slice(
                                completed,
                                &context,
                                &mut scheduler,
                                &mut orphan_pool,
                            )
                            .await
                        };
                        match completion_result {
                            Ok(()) => {
                                // Canonical completion and its scheduler/
                                // diagnostic publication are irreversible.
                                // Relinquish the retained completion before
                                // fallible deferred-orphan bookkeeping so a
                                // terminal shutdown cannot publish it twice.
                                let completed = active_state_completion
                                    .take()
                                    .expect("published active-state completion remains retained");
                                let orphan_result = (|| -> Result<()> {
                                    if let Some(failed) = &completed.outcome.contextual_failure {
                                        enqueue_affected_orphan_discards(
                                            &failed.affected,
                                            &orphan_pool,
                                            &mut ready_orphan_parents,
                                            &mut deferred_orphan_discards,
                                        )?;
                                    }
                                    drain_orphan_work(
                                        MAX_VALIDATED_BODY_COMMIT_BATCH,
                                        &validation,
                                        &mut scheduler,
                                        &mut orphan_pool,
                                        &mut ready_orphan_parents,
                                        &mut deferred_orphan_discards,
                                        &mut orphan_work_schedule,
                                    )?;
                                    Ok(())
                                })();
                                if let Err(error) = orphan_result {
                                    let error = error.context(
                                        "failed to schedule contextual orphan cleanup",
                                    );
                                    record_error(&diagnostics, format!("{error:#}")).await;
                                    terminal_error = Some(error);
                                    break;
                                }
                                consecutive_active_state_contention = 0;
                                active_state_poll.reset_after(MIN_NATIVE_SYNC_POLL_INTERVAL);
                                refresh_diagnostics(
                                    &diagnostics,
                                    &peers,
                                    &scheduler,
                                    &orphan_pool,
                                    &reconnects,
                                    &address_book,
                                    &ban_list,
                                    &compact_peers,
                                    &pending_compact_blocks,
                                    checkpoint_sequence,
                                )
                                .await;
                            }
                            Err(error) if canonical_writer_contention(&error) => {
                                consecutive_active_state_contention =
                                    consecutive_active_state_contention.saturating_add(1);
                                let retry_after = active_state_contention_retry_interval(
                                    consecutive_active_state_contention,
                                );
                                trace_native_sync_contention_retry(
                                    "active-state completion",
                                    consecutive_active_state_contention,
                                    retry_after,
                                    &error,
                                );
                                active_state_poll.reset_after(retry_after);
                            }
                            Err(error) => {
                                let error = error.context("active-state completion failed");
                                record_error(&diagnostics, format!("{error:#}")).await;
                                terminal_error = Some(error);
                                break;
                            }
                        }
                    } else {
                        // Preparation is pure, bounded CPU work and remains
                        // independent of the network supervisor. Exactly one
                        // job may be in flight, and a completed job remains
                        // owned here until all scheduler effects are published.
                        active_state_task = Some(tokio::spawn(execute_native_active_state_slice(
                            node.clone(),
                            writer.clone(),
                            native_sync_config.active_state_connect_batch,
                            scheduler.stored_tip().cloned(),
                            native_sync_config.validation_workers,
                            native_sync_config.validation_queue,
                        )));
                        active_state_poll.reset_after(MIN_NATIVE_SYNC_POLL_INTERVAL);
                    }
                }
                result = async {
                    active_state_task
                        .as_mut()
                        .expect("active-state task select guard")
                        .await
                }, if active_state_task.is_some() => {
                    let _finished = active_state_task
                        .take()
                        .expect("completed active-state task remains present");
                    match result {
                        Ok(Ok(completed)) => {
                            active_state_completion = Some(completed);
                            active_state_poll.reset_after(MIN_NATIVE_SYNC_POLL_INTERVAL);
                        }
                        Ok(Err(error)) if canonical_writer_contention(&error) => {
                            consecutive_active_state_contention =
                                consecutive_active_state_contention.saturating_add(1);
                            let retry_after = active_state_contention_retry_interval(
                                consecutive_active_state_contention,
                            );
                            trace_native_sync_contention_retry(
                                "active-state preparation/commit",
                                consecutive_active_state_contention,
                                retry_after,
                                &error,
                            );
                            active_state_poll.reset_after(retry_after);
                        }
                        Ok(Err(error)) => {
                            let error = error.context("active-state synchronization failed");
                            record_error(&diagnostics, format!("{error:#}")).await;
                            terminal_error = Some(error);
                            break;
                        }
                        Err(error) => {
                            let error = anyhow::Error::new(error)
                                .context("active-state synchronization task failed");
                            record_error(&diagnostics, format!("{error:#}")).await;
                            terminal_error = Some(error);
                            break;
                        }
                    }
                }
                event = next_native_supervisor_event(
                    &mut next_supervisor_lane,
                    &mut poll,
                    &mut connect_results_rx,
                    &mut peer_events,
                    &mut validated,
                ) => match event {
                NativeSupervisorEvent::Maintenance => {
                    if rpc_task.is_finished() {
                        let message = "Native sync RPC task terminated unexpectedly".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    }
                    if listener_task.as_ref().is_some_and(|task| task.is_finished()) {
                        let message = "Native sync P2P listener terminated unexpectedly".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    }

                    let compact_now = Instant::now();
                    let expired_peers = pending_compact_blocks
                        .values()
                        .filter_map(|pending: &PendingCompactBlock| {
                            (compact_now.duration_since(pending.received_at)
                                >= COMPACT_BLOCK_RESPONSE_TIMEOUT)
                                .then_some(pending.peer)
                        })
                        .collect::<HashSet<_>>();
                    if !expired_peers.is_empty() {
                        let before = pending_compact_blocks.len();
                        pending_compact_blocks
                            .retain(|_, pending| !expired_peers.contains(&pending.peer));
                        let expired = before.saturating_sub(pending_compact_blocks.len());
                        update_diagnostics(&diagnostics, |state| {
                            state.compact_block_fallbacks = state
                                .compact_block_fallbacks
                                .saturating_add(expired as u64);
                        })
                        .await;
                        for peer in expired_peers {
                            scheduler.remove_peer(peer);
                            if let Err(error) = peers.disconnect(peer).await {
                                tracing::debug!(
                                    ?peer,
                                    %error,
                                    "compact-block response timeout raced peer disconnect"
                                );
                            }
                        }
                    }

                    // Start due sockets before potentially expensive local
                    // active-state and canonical-body scans. Historical replay
                    // must not starve peer bootstrap or reconnect scheduling.
                    let connection_now = Instant::now();
                    if native_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            &ban_list,
                            native_sync_config.maximum_outbound,
                            connection_now,
                            unix_time(),
                        );
                    }
                    let attempts = spawn_due_connections(
                        &mut reconnects,
                        &mut address_book,
                        &ban_list,
                        &peers,
                        &connect_results_tx,
                        connection_now,
                        native_sync_config.maximum_outbound,
                    );
                    if attempts > 0 {
                        update_diagnostics(&diagnostics, |state| {
                            state.outbound_reconnect_attempts = state
                                .outbound_reconnect_attempts
                                .saturating_add(attempts as u64);
                        })
                        .await;
                    }

                    if let Err(error) = drain_orphan_work(
                        MAX_VALIDATED_BODY_COMMIT_BATCH,
                        &validation,
                        &mut scheduler,
                        &mut orphan_pool,
                        &mut ready_orphan_parents,
                        &mut deferred_orphan_discards,
                        &mut orphan_work_schedule,
                    ) {
                        let error = error.context("failed to drain bounded orphan work");
                        record_error(&diagnostics, format!("{error:#}")).await;
                        terminal_error = Some(error);
                        break;
                    }

                    let queue_result =
                        node.native_sync_queue_missing_canonical_bodies(&mut scheduler);
                    match queue_result {
                        Ok(_) => {}
                        Err(error) if canonical_writer_busy(&error) => {
                            consecutive_maintenance_busy =
                                consecutive_maintenance_busy.saturating_add(1);
                            let retry_after = native_sync_contention_retry_interval(
                                native_sync_config.poll_interval,
                                consecutive_maintenance_busy,
                            );
                            trace_native_sync_contention_retry(
                                "canonical body-queue refresh",
                                consecutive_maintenance_busy,
                                retry_after,
                                &error,
                            );
                            reset_native_supervisor_poll(&mut poll, retry_after);
                            continue;
                        }
                        Err(error) => {
                            let error = error.context(
                                "failed to refresh canonical block-body work queue",
                            );
                            record_error(&diagnostics, format!("{error:#}")).await;
                            terminal_error = Some(error);
                            break;
                        }
                    }
                    let locator_result = node.native_sync_block_locator(MAX_LOCATOR_ENTRIES);
                    let locator = match locator_result {
                        Ok(locator) => locator,
                        Err(error) if canonical_writer_busy(&error) => {
                            consecutive_maintenance_busy =
                                consecutive_maintenance_busy.saturating_add(1);
                            let retry_after = native_sync_contention_retry_interval(
                                native_sync_config.poll_interval,
                                consecutive_maintenance_busy,
                            );
                            trace_native_sync_contention_retry(
                                "synchronization locator read",
                                consecutive_maintenance_busy,
                                retry_after,
                                &error,
                            );
                            reset_native_supervisor_poll(&mut poll, retry_after);
                            continue;
                        }
                        Err(error) => {
                            let error = error.context("failed to build synchronization locator");
                            record_error(&diagnostics, format!("{error:#}")).await;
                            terminal_error = Some(error);
                            break;
                        }
                    };
                    consecutive_maintenance_busy = 0;
                    let dispatches = match batch_sync_actions(
                        scheduler.poll(StdInstant::now(), &locator),
                    ) {
                        Ok(dispatches) => dispatches,
                        Err(error) => {
                            let error = error.context("failed to batch synchronization actions");
                            record_error(&diagnostics, format!("{error:#}")).await;
                            terminal_error = Some(error);
                            break;
                        }
                    };
                    for dispatch in dispatches {
                        if let Err(error) = apply_sync_dispatch(
                            dispatch,
                            &peers,
                            &compact_peers,
                            &checkpoint_store,
                            &mut scheduler,
                            &mut checkpoint_sequence,
                        )
                        .await
                        {
                            record_warning(format!("{error:#}"));
                        }
                    }

                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        &address_book,
                        &ban_list,
                        &compact_peers,
                        &pending_compact_blocks,
                        checkpoint_sequence,
                    )
                    .await;
                    // Maintenance includes stable RocksDB/header scans. If it
                    // exceeded the period, an already-expired next tick would
                    // otherwise remain permanently ready in the biased outer
                    // supervisor select.
                    reset_native_supervisor_poll(&mut poll, native_sync_config.poll_interval);
                }
                NativeSupervisorEvent::Connection(result) => {
                    let Some(result) = result else {
                        let message = "outbound connection result channel closed".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    };
                    handle_connect_attempt_result(
                        result,
                        &mut reconnects,
                        &diagnostics,
                    )
                    .await;
                    if native_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            &ban_list,
                            native_sync_config.maximum_outbound,
                            Instant::now(),
                            unix_time(),
                        );
                    }
                }
                NativeSupervisorEvent::Peer(event) => {
                    let Some(event) = event else {
                        let message = "peer event channel closed".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    };
                    // Each maximum-size header packet is one atomic durable
                    // batch. Once started it completes as a unit; the event
                    // loop observes shutdown before starting another packet.
                    let handled = tokio::select! {
                        _ = &mut shutdown_wait => None,
                        result = handle_peer_event(
                            event,
                            &node,
                            &writer,
                            &peers,
                            &validation,
                            &mut scheduler,
                            &mut reconnects,
                            &mut address_book,
                            &ban_list,
                            &mut served_getaddr,
                            &mut compact_peers,
                            &mut pending_compact_blocks,
                            native_sync_config.discovery,
                            native_sync_config.headers_only,
                            &diagnostics,
                        ) => Some(result),
                    };
                    let Some(handled) = handled else {
                        break;
                    };
                    if let Err(error) = handled {
                        record_warning(format!("{error:#}"));
                    }
                    if native_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            &ban_list,
                            native_sync_config.maximum_outbound,
                            Instant::now(),
                            unix_time(),
                        );
                    }
                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        &address_book,
                        &ban_list,
                        &compact_peers,
                        &pending_compact_blocks,
                        checkpoint_sequence,
                    )
                    .await;
                }
                NativeSupervisorEvent::Validation(result) => {
                    let Some(result) = result else {
                        let message = "validation result channel closed".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    };
                    let mut results = Vec::with_capacity(MAX_VALIDATED_BODY_COMMIT_BATCH);
                    results.push(result);
                    while results.len() < MAX_VALIDATED_BODY_COMMIT_BATCH {
                        match validated.try_recv() {
                            Ok(result) => results.push(result),
                            Err(_) => break,
                        }
                    }
                    let context = ValidationResultContext {
                        node: &node,
                        writer: &writer,
                        peers: &peers,
                        diagnostics: &diagnostics,
                    };
                    let validation_result = handle_validation_results(
                        results,
                        &context,
                        &mut scheduler,
                        &mut orphan_pool,
                        &mut ready_orphan_parents,
                        &mut deferred_orphan_discards,
                    )
                    .await;
                    if let Err(error) = validation_result {
                        if terminal_validation_error(&error) {
                            record_error(&diagnostics, format!("{error:#}")).await;
                            terminal_error = Some(error);
                            break;
                        }
                        record_warning(format!("{error:#}"));
                    }
                    if let Err(error) = drain_orphan_work(
                        MAX_VALIDATED_BODY_COMMIT_BATCH,
                        &validation,
                        &mut scheduler,
                        &mut orphan_pool,
                        &mut ready_orphan_parents,
                        &mut deferred_orphan_discards,
                        &mut orphan_work_schedule,
                    ) {
                        record_error(&diagnostics, format!("{error:#}")).await;
                        terminal_error = Some(error);
                        break;
                    }
                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        &address_book,
                        &ban_list,
                        &compact_peers,
                        &pending_compact_blocks,
                        checkpoint_sequence,
                    )
                    .await;
                }
                },
            }
            refresh_supervisor_backlog_diagnostics(
                &diagnostics,
                peer_events.len(),
                validated.len(),
            )
            .await;
            let storage_operational = node.ensure_storage_operational();
            if let Err(error) = storage_operational {
                let error =
                    error.context("native-sync storage requires reopen after a commit failure");
                record_error(&diagnostics, format!("{error:#}")).await;
                terminal_error = Some(error);
                break;
            }
            maintain_peer_bans(
                &store,
                &peers,
                &mut ban_list,
                &mut address_book,
                &mut reconnects,
                &diagnostics,
                ban_list_persistent,
            )
            .await;
        }
        // Tell every subordinate runtime, including external extensions, to
        // stop before draining accepted writer work. This prevents new work
        // from racing the final checkpoint while preserving the invariant
        // that an admitted canonical command runs to completion.
        let _ = shutdown_tx.send(true);

        // A writer command is non-cancellable once admitted. Finish any
        // accepted preparation/commit job and publish its scheduler effects
        // before the final checkpoint and canonical-runtime shutdown. This
        // drain is work-bounded: at most one task exists, its connect count is
        // capped by the validated `active_state_connect_batch`, and planning
        // charges every materialized body against `NodeReorgLimits`' bounded
        // production body-byte envelope before a worker is admitted.
        if let Some(task) = active_state_task.take() {
            match task.await {
                Ok(Ok(completed)) => active_state_completion = Some(completed),
                Ok(Err(error))
                    if canonical_writer_contention(&error)
                        || canonical_writer_shutting_down(&error) =>
                {
                    tracing::debug!(
                        error = %error,
                        "discarding uncommitted active-state work during shutdown"
                    );
                }
                Ok(Err(error)) => {
                    let error = error.context("active-state shutdown drain failed");
                    record_error(&diagnostics, format!("{error:#}")).await;
                    if terminal_error.is_none() {
                        terminal_error = Some(error);
                    }
                }
                Err(error) => {
                    let error = anyhow::Error::new(error)
                        .context("active-state shutdown-drain task failed");
                    record_error(&diagnostics, format!("{error:#}")).await;
                    if terminal_error.is_none() {
                        terminal_error = Some(error);
                    }
                }
            }
        }
        if let Some(completed) = active_state_completion.take() {
            let context = ActiveStateConnectionContext {
                node: &node,
                writer: &writer,
                peers: &peers,
                diagnostics: &diagnostics,
                diagnostic_rpc: &diagnostic_rpc,
            };
            for attempt in 0..MAX_CANONICAL_STALE_RETRIES {
                match complete_stored_active_state_slice(
                    &completed,
                    &context,
                    &mut scheduler,
                    &mut orphan_pool,
                )
                .await
                {
                    Ok(()) => {
                        let orphan_result = (|| -> Result<()> {
                            if let Some(failed) = &completed.outcome.contextual_failure {
                                enqueue_affected_orphan_discards(
                                    &failed.affected,
                                    &orphan_pool,
                                    &mut ready_orphan_parents,
                                    &mut deferred_orphan_discards,
                                )?;
                            }
                            drain_orphan_work(
                                MAX_VALIDATED_BODY_COMMIT_BATCH,
                                &validation,
                                &mut scheduler,
                                &mut orphan_pool,
                                &mut ready_orphan_parents,
                                &mut deferred_orphan_discards,
                                &mut orphan_work_schedule,
                            )?;
                            Ok(())
                        })();
                        if let Err(error) = orphan_result {
                            let error = error
                                .context("failed to schedule shutdown contextual orphan cleanup");
                            record_error(&diagnostics, format!("{error:#}")).await;
                            if terminal_error.is_none() {
                                terminal_error = Some(error);
                            }
                        }
                        break;
                    }
                    Err(error)
                        if canonical_writer_contention(&error)
                            && attempt + 1 < MAX_CANONICAL_STALE_RETRIES =>
                    {
                        tokio::time::sleep(active_state_contention_retry_interval(attempt + 1))
                            .await;
                    }
                    Err(error)
                        if canonical_writer_contention(&error)
                            || canonical_writer_shutting_down(&error) =>
                    {
                        tracing::warn!(
                            error = %error,
                            "deferred active-state scheduler publication during shutdown; durable state will be recovered on restart"
                        );
                        break;
                    }
                    Err(error) => {
                        let error = error.context("active-state shutdown completion failed");
                        record_error(&diagnostics, format!("{error:#}")).await;
                        if terminal_error.is_none() {
                            terminal_error = Some(error);
                        }
                        break;
                    }
                }
            }
        }

        // Quiesce the extension before final persistence. A cooperative task
        // is joined; an unresponsive task is asked to abort and its
        // cancellation is itself joined for a bounded interval.
        let extension_result = match extension_task {
            Some(task) => {
                await_extension_shutdown(
                    task,
                    NATIVE_RUNTIME_EXTENSION_SHUTDOWN_GRACE,
                    NATIVE_RUNTIME_EXTENSION_ABORT_GRACE,
                )
                .await
            }
            None => Ok(()),
        };

        let shutdown_persistence = node.ensure_storage_operational();
        if let Err(error) = shutdown_persistence {
            record_warning(format!(
                "skipped final peer/checkpoint persistence while storage requires reopen: {error:#}"
            ));
            if terminal_error.is_none() {
                terminal_error =
                    Some(error.context("native-sync storage was fenced before shutdown"));
            }
        } else {
            maintain_peer_bans(
                &store,
                &peers,
                &mut ban_list,
                &mut address_book,
                &mut reconnects,
                &diagnostics,
                ban_list_persistent,
            )
            .await;
            if address_book_persistent {
                flush_address_book(&store, &mut address_book, &diagnostics).await;
            }
            if ban_list_persistent {
                flush_peer_bans(&store, &mut ban_list, &diagnostics).await;
            }
            checkpoint_sequence = checkpoint_sequence.saturating_add(1);
            if let Err(error) =
                persist_checkpoint(&checkpoint_store, &scheduler, checkpoint_sequence)
            {
                record_error(&diagnostics, format!("{error:#}")).await;
                if terminal_error.is_none() {
                    terminal_error = Some(error);
                }
            }
            let final_storage_state = node.ensure_storage_operational();
            if let Err(error) = final_storage_state {
                let error =
                    error.context("native-sync storage was fenced during shutdown persistence");
                record_error(&diagnostics, format!("{error:#}")).await;
                if terminal_error.is_none() {
                    terminal_error = Some(error);
                }
            }
        }
        peers.disconnect_all().await;

        let rpc_result = await_task("RPC", rpc_task).await;
        let listener_result = match listener_task {
            Some(task) => await_p2p_task("P2P listener", task).await,
            None => Ok(()),
        };
        let clean_shutdown_eligible = terminal_error.is_none()
            && rpc_result.is_ok()
            && listener_result.is_ok()
            && extension_result.is_ok();
        let writer_result = shutdown_native_runtime(runtime, clean_shutdown_eligible).await;
        if let Some(error) = terminal_error {
            return Err(error);
        }
        rpc_result?;
        listener_result?;
        extension_result?;
        writer_result?;
        tracing::info!("hsrd native-sync runtime stopped");
        Ok(())
    }

    pub(super) fn native_sync_ensure_genesis_header(&mut self) -> Result<HeaderRecord> {
        self.state.ensure_storage_operational()?;
        let params = self.config.network.params();
        if let Some(record) = self
            .state
            .chain
            .load_record(&params.genesis_hash)
            .map_err(|error| anyhow::anyhow!("failed to load genesis header: {error}"))?
        {
            return Ok(record);
        }

        let header = params.genesis_header();
        HeaderConsensus::new(ConsensusParams::for_network(self.config.network))
            .validate_header(
                &header,
                &HeaderValidationContext {
                    height: 0,
                    previous: None,
                    enforce_checkpoints: true,
                    expected_bits: Some(params.pow.bits),
                    median_time_past: None,
                    maximum_time: None,
                    require_pow: false,
                },
            )
            .map_err(|error| anyhow::anyhow!("genesis header validation failed: {error}"))?;
        let result = self
            .state
            .chain
            .import_header(HeaderImport {
                header,
                height: 0,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .map_err(|error| anyhow::anyhow!("failed to persist genesis header: {error}"));
        if result.is_err() {
            self.fail_closed_after_ambiguous_commit();
        }
        result
    }

    fn native_sync_import_headers(&mut self, headers: Vec<Header>) -> Result<Vec<HeaderRecord>> {
        self.state.ensure_storage_operational()?;
        if headers.len() > MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE {
            return Err(anyhow::Error::new(PeerHeaderBatchLimit {
                limit: MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE,
                actual: headers.len(),
            }));
        }

        let maximum_time = current_unix_time()?.saturating_add(MAX_FUTURE_BLOCK_TIME);
        let mut imported = Vec::with_capacity(headers.len());
        let mut requests = Vec::with_capacity(headers.len());
        let mut pending_records = Vec::with_capacity(headers.len());
        let mut staged_headers = HashMap::<BlockHash, HeaderRecord>::with_capacity(headers.len());
        for header in headers {
            let hash = header.hash();
            let mut lookup = |candidate: &BlockHash| -> Result<Option<HeaderRecord>> {
                if let Some(record) = staged_headers.get(candidate) {
                    return Ok(Some(record.clone()));
                }
                self.state
                    .chain
                    .header(candidate)
                    .map_err(|error| anyhow::anyhow!("failed to read staged header: {error}"))
            };
            if let Some(record) = lookup(&hash)? {
                imported.push(record);
                continue;
            }

            let parent = if header == self.config.network.params().genesis_header() {
                None
            } else {
                Some(
                    lookup(&header.prev_block)?
                        .ok_or(MissingHeaderParent {
                            parent: header.prev_block,
                        })
                        .map_err(anyhow::Error::new)?,
                )
            };
            let height = parent
                .as_ref()
                .map_or(0, |record| record.height.saturating_add(1));
            let median_time_past = parent
                .as_ref()
                .map(|record| median_time_past_with_lookup(record, &mut lookup))
                .transpose()?;
            let expected_bits = expected_bits_with_lookup(
                self.config.network,
                header.time,
                parent.as_ref(),
                &mut lookup,
            );
            let expected_bits = expected_bits?;
            let network_params = self.config.network.params();
            let is_canonical_genesis = height == 0
                && header == network_params.genesis_header()
                && hash == network_params.genesis_hash;
            HeaderConsensus::new(ConsensusParams::for_network(self.config.network))
                .validate_header(
                    &header,
                    &HeaderValidationContext {
                        height,
                        previous: parent.as_ref().map(|record| HeaderParent {
                            hash: record.hash,
                            height: record.height,
                            bits: record.header.bits,
                            chainwork: record.chainwork,
                        }),
                        enforce_checkpoints: true,
                        expected_bits: Some(expected_bits),
                        median_time_past,
                        maximum_time: Some(maximum_time),
                        require_pow: !is_canonical_genesis,
                    },
                )
                .map_err(anyhow::Error::new)
                .context("header validation failed")?;

            let request = HeaderImport {
                header,
                height,
                verify_pow: !is_canonical_genesis,
                checkpoint_valid: true,
            };
            let record = prepare_header_record(&request, parent.as_ref())
                .map_err(|error| anyhow::anyhow!("failed to stage header: {error}"))?;
            requests.push(request);
            pending_records.push(record.clone());
            staged_headers.insert(record.hash, record.clone());
            imported.push(record);
        }

        let committed = self.state.chain.import_headers(requests);
        if committed.is_err() {
            self.fail_closed_after_ambiguous_commit();
        }
        let committed = committed
            .map_err(|error| anyhow::anyhow!("failed to persist header batch: {error}"))?;
        if committed != pending_records {
            anyhow::bail!("committed header batch differs from its staged validation view");
        }
        Ok(imported)
    }
}

impl NodeReadHandle {
    fn native_sync_best_header_tip(&self) -> Result<Option<ChainTip>> {
        self.with_stable_read(|_store, headers| {
            headers
                .best_tip()
                .map_err(|error| anyhow::anyhow!("failed to read best native-sync header: {error}"))
        })
    }

    fn native_sync_header_deployments(
        &self,
        deadline: StdInstant,
        maximum_reads: usize,
    ) -> Result<HeaderDeploymentDiagnostics> {
        if maximum_reads == 0 || maximum_reads > MAX_HEADER_DEPLOYMENT_READS {
            anyhow::bail!(
                "header deployment read budget must be within 1..={MAX_HEADER_DEPLOYMENT_READS}"
            );
        }
        let config = self.config();
        self.with_stable_read(|store, headers| {
            let snapshot = store.snapshot()?;
            let mut reads = 0usize;
            charge_header_deployment_read(&mut reads, maximum_reads, deadline)?;
            let best_header = headers
                .best_tip()
                .map_err(|error| anyhow::anyhow!("failed to read best deployment header: {error}"))?
                .ok_or_else(|| anyhow::anyhow!("best header is unavailable"))?;
            let next_height = best_header
                .height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("best-header height exhausted"))?;
            let params = config.network.params();
            let mut state = DeploymentState::from_states([ThresholdState::Defined; 4]);

            for deployment in config.network.deployments() {
                let window = deployment.effective_window(params.miner_window);
                if window == 0 {
                    anyhow::bail!("deployment {} has a zero window", deployment.name());
                }
                let mut threshold = ThresholdState::Defined;
                let mut boundary = window;
                while boundary <= next_height {
                    let parent_height = boundary
                        .checked_sub(1)
                        .ok_or_else(|| anyhow::anyhow!("deployment boundary underflow"))?;
                    charge_header_deployment_read(&mut reads, maximum_reads, deadline)?;
                    let parent_hash = headers
                        .canonical_hash(parent_height)
                        .map_err(|error| {
                            anyhow::anyhow!(
                            "failed to read canonical deployment parent at {parent_height}: {error}"
                        )
                        })?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "canonical deployment parent at height {parent_height} is missing"
                            )
                        })?;
                    charge_header_deployment_read(&mut reads, maximum_reads, deadline)?;
                    let parent = load_header_record(&snapshot, &parent_hash)
                        .map_err(|error| {
                            anyhow::anyhow!("failed to read deployment parent header: {error}")
                        })?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "canonical deployment parent {} is missing",
                                parent_hash.to_hex()
                            )
                        })?;
                    if parent.height != parent_height || parent.status.failed {
                        anyhow::bail!(
                            "canonical deployment parent {} is invalid at height {parent_height}",
                            parent_hash.to_hex()
                        );
                    }
                    let mut lookup = |hash: &BlockHash| {
                        charge_header_deployment_read(&mut reads, maximum_reads, deadline)?;
                        load_header_record(&snapshot, hash)
                    };
                    let period = completed_deployment_period_with_lookup(
                        &parent,
                        *deployment,
                        window,
                        &mut lookup,
                    )?;
                    threshold = advance_threshold_state(
                        params.activation_threshold,
                        params.miner_window,
                        *deployment,
                        boundary,
                        threshold,
                        Some(period),
                    )
                    .with_context(|| {
                        format!(
                            "failed to derive deployment {} at height {boundary}",
                            deployment.name()
                        )
                    })?;
                    boundary = match boundary.checked_add(window) {
                        Some(boundary) => boundary,
                        None => break,
                    };
                }
                state = state.with_state(deployment.id, threshold);
            }

            let deployments = config
                .network
                .deployments()
                .iter()
                .map(|deployment| HeaderDeploymentEntry {
                    name: deployment.name().to_owned(),
                    state: state.state(deployment.id),
                    bit: deployment.bit,
                    start_time: deployment.start_time,
                    timeout: deployment.timeout,
                })
                .collect::<Vec<_>>();
            let final_checkpoint = config
                .network
                .checkpoints()
                .last()
                .map(|checkpoint| {
                    let anchored = if best_header.height < checkpoint.height {
                        false
                    } else {
                        charge_header_deployment_read(&mut reads, maximum_reads, deadline)?;
                        let canonical =
                            headers.canonical_hash(checkpoint.height).map_err(|error| {
                                anyhow::anyhow!("failed to read final checkpoint ancestry: {error}")
                            })?;
                        charge_header_deployment_read(&mut reads, maximum_reads, deadline)?;
                        let record =
                            load_header_record(&snapshot, &checkpoint.hash).map_err(|error| {
                                anyhow::anyhow!("failed to read final checkpoint header: {error}")
                            })?;
                        canonical == Some(checkpoint.hash)
                            && record.is_some_and(|record| {
                                record.height == checkpoint.height
                                    && record.hash == checkpoint.hash
                                    && record.status.header_context_valid
                                    && record.status.checkpoint_valid
                                    && !record.status.failed
                            })
                    };
                    Ok::<_, anyhow::Error>(HeaderCheckpointEvidence {
                        height: checkpoint.height,
                        hash: checkpoint.hash,
                        anchored,
                    })
                })
                .transpose()?;
            let historical_script_assumption_through = final_checkpoint
                .as_ref()
                .filter(|checkpoint| checkpoint.anchored)
                .map(|checkpoint| checkpoint.height);

            Ok(HeaderDeploymentDiagnostics {
                best_header,
                next_height,
                deployments,
                script_flags: state.script_flags.bits(),
                lock_flags: state.lock_flags,
                name_flags: state.name_flags.bits(),
                has_airstop: state.has_airstop,
                next_block_version: compute_block_version_from_state(
                    config.network.deployments(),
                    state,
                )
                .context("failed to derive next-block deployment version")?,
                final_checkpoint,
                historical_script_assumption_through,
            })
        })
    }

    fn native_sync_active_tip(&self) -> Result<Option<ChainTip>> {
        self.with_stable_read(|store, _headers| {
            let snapshot = store.snapshot()?;
            best_block_tip_from_snapshot(&snapshot).context("failed to read active native-sync tip")
        })
    }

    fn native_sync_has_block(&self, hash: &BlockHash) -> Result<bool> {
        self.with_stable_read(|store, _headers| {
            let snapshot = store.snapshot()?;
            Self::native_sync_has_block_from_snapshot(&snapshot, hash)
        })
    }

    fn native_sync_has_block_from_snapshot(
        snapshot: &impl ReadSnapshot,
        hash: &BlockHash,
    ) -> Result<bool> {
        let Some(record) =
            load_block_index_record(snapshot, hash).context("failed to read block availability")?
        else {
            return Ok(false);
        };
        if !record.status.body_present {
            return Ok(false);
        }
        let Some(block) = load_block_from_snapshot(snapshot, hash)
            .context("failed to authenticate stored block body")?
        else {
            return Ok(false);
        };
        let Some(header) = load_header_record(snapshot, hash)
            .context("failed to authenticate stored block header")?
        else {
            anyhow::bail!(
                "stored block body {} has no matching header record",
                hash.to_hex()
            );
        };
        if block.header != header.header
            || record.hash != header.hash
            || record.height != header.height
            || record.prev_hash != block.header.prev_block
            || record.chainwork != header.chainwork
            || record.status != header.status
        {
            anyhow::bail!(
                "stored block availability metadata disagrees for {}",
                hash.to_hex()
            );
        }
        Ok(true)
    }

    fn native_sync_header_record(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>> {
        self.with_stable_read(|store, _headers| {
            let snapshot = store.snapshot()?;
            Self::native_sync_header_record_from_snapshot(&snapshot, hash)
        })
    }

    fn native_sync_header_record_from_snapshot(
        snapshot: &impl ReadSnapshot,
        hash: &BlockHash,
    ) -> Result<Option<HeaderRecord>> {
        load_header_record(snapshot, hash).context("failed to load native-sync header")
    }

    fn native_sync_is_canonical_header(&self, hash: BlockHash, height: Height) -> Result<bool> {
        self.with_stable_read(|_store, headers| {
            headers
                .canonical_hash(height)
                .map(|canonical| canonical == Some(hash))
                .context("failed to read canonical native-sync header")
        })
    }

    fn native_sync_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        self.with_stable_read(|store, _headers| {
            let snapshot = store.snapshot()?;
            load_block_from_snapshot(&snapshot, hash).context("failed to load native-sync block")
        })
    }
}

impl NodeService {
    #[cfg(test)]
    fn native_sync_best_header_tip(&self) -> Result<Option<ChainTip>> {
        self.state
            .chain
            .best_tip()
            .map_err(|error| anyhow::anyhow!("failed to read best test header: {error}"))
    }

    #[cfg(test)]
    fn native_sync_has_block(&self, hash: &BlockHash) -> Result<bool> {
        let snapshot = self.state.store.snapshot()?;
        NodeReadHandle::native_sync_has_block_from_snapshot(&snapshot, hash)
    }

    #[cfg(test)]
    fn native_sync_header_record(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>> {
        let snapshot = self.state.store.snapshot()?;
        NodeReadHandle::native_sync_header_record_from_snapshot(&snapshot, hash)
    }

    #[cfg(test)]
    fn native_sync_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        let snapshot = self.state.store.snapshot()?;
        load_block_from_snapshot(&snapshot, hash).context("failed to load test block")
    }

    fn native_sync_store_validated_blocks(
        &mut self,
        blocks: Vec<(ValidatedBlock, bool)>,
    ) -> Result<Vec<BlockIndexRecord>> {
        self.state.ensure_storage_operational()?;
        let mut candidates = Vec::with_capacity(blocks.len());
        for (validated, canonical) in blocks {
            let stateless = super::StatelessBodyValidation::for_block(
                &validated.block,
                validated.height,
                self.config.network,
            );
            let request = NodeBlockImport::from_peer(validated.block, validated.height);
            let import = self
                .state
                .validate_prevalidated_native_import(&request, canonical, stateless)?;
            candidates.push((request, import));
        }
        let result = self
            .state
            .store_validated_alternates(candidates)
            .map(|mutations| {
                mutations
                    .into_iter()
                    .map(|mutation| mutation.record)
                    .collect()
            });
        if result.is_err() {
            self.fail_closed_after_ambiguous_commit();
        }
        result
    }

    fn native_sync_store_failed_block(
        &mut self,
        block: Block,
        height: Height,
    ) -> Result<super::FailedBlockMutation> {
        self.state.ensure_storage_operational()?;
        let result = self.state.store_failed_block(
            NodeBlockImport::from_peer(block, height),
            FailedBlockStage::BodySyntax,
        );
        if result.is_err() {
            self.fail_closed_after_ambiguous_commit();
        }
        result
    }

    #[cfg(test)]
    pub(super) fn native_sync_connect_stored_state(
        &mut self,
        maximum_connect: usize,
    ) -> Result<ActiveStateConnectOutcome> {
        self.native_sync_connect_stored_state_with_hint(maximum_connect, None)
    }

    #[cfg(test)]
    fn native_sync_connect_stored_state_with_hint(
        &mut self,
        maximum_connect: usize,
        stored_tip_hint: Option<&ChainTip>,
    ) -> Result<ActiveStateConnectOutcome> {
        drive_active_state_connect_retries(maximum_connect, |attempt_limit| {
            self.native_sync_connect_stored_state_once_with_hint(attempt_limit, stored_tip_hint)
        })
    }

    #[cfg(test)]
    fn native_sync_connect_stored_state_once_with_hint(
        &mut self,
        maximum_connect: usize,
        stored_tip_hint: Option<&ChainTip>,
    ) -> Result<ActiveStateConnectAttempt> {
        let Some(plan) =
            self.native_sync_plan_stored_state_once_with_hint(maximum_connect, stored_tip_hint)?
        else {
            return Ok(std::ops::ControlFlow::Continue(
                ActiveStateConnectOutcome::default(),
            ));
        };
        let validator = HnsBodyValidator::new(self.config.network);
        let proofs = plan
            .activation
            .connect
            .iter()
            .map(|connect| {
                validator
                    .validate(connect.block(), connect.height())
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "stored block {} at height {} failed stateless replay validation: {}",
                            connect.block().hash().to_hex(),
                            connect.height(),
                            error.reason
                        )
                    })?;
                Ok(StatelessBodyValidation::for_block(
                    connect.block(),
                    connect.height(),
                    self.config.network,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let workload = plan
            .activation
            .connect
            .iter()
            .fold(ActiveStateWorkload::default(), |total, connect| {
                total.saturating_add(ActiveStateWorkload::for_block(connect.block()))
            });
        let prepared = PreparedNativeActivation::new(proofs)?;
        self.native_sync_apply_prepared_active_state(PreparedActiveStatePlan {
            epoch: plan.epoch,
            activation: plan.activation,
            prepared,
            maximum_connect: plan.maximum_connect,
            planning_micros: plan.planning_micros,
            preparation: ActiveStatePreparationMetrics::default(),
            workload,
        })
    }

    #[cfg(test)]
    fn native_sync_plan_stored_state_once_with_hint(
        &self,
        maximum_connect: usize,
        stored_tip_hint: Option<&ChainTip>,
    ) -> Result<Option<NativeActiveStatePlan>> {
        self.state.ensure_storage_operational()?;
        let planning_started = StdInstant::now();
        if maximum_connect == 0 || maximum_connect > MAX_ACTIVE_STATE_CONNECT_BATCH {
            anyhow::bail!(
                "active-state connector batch {maximum_connect} is outside 1..={MAX_ACTIVE_STATE_CONNECT_BATCH}"
            );
        }

        let stored_tip = {
            let snapshot = self.state.store.snapshot()?;
            NodeReadHandle::native_sync_contiguous_body_tip_from_snapshot(
                &snapshot,
                &self.state.chain,
                stored_tip_hint,
            )?
        };
        let Some(stored_tip) = stored_tip else {
            return Ok(None);
        };
        let active_tip = self.state.best_block_tip()?;
        if active_tip.as_ref() == Some(&stored_tip) {
            return Ok(None);
        }
        // Direct IBD progress amortizes the ordered name-page durability
        // barrier across one HSD mainnet rollback horizon. The connector still
        // returns to the shutdown/network select loop between slices, while a
        // divergent best-work branch uses the operator's full configured bound
        // below so its disconnect/connect transition remains one atomic commit.
        let direct_connect_limit = maximum_connect.min(MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE);

        let candidate_hash = match active_tip.as_ref() {
            None => {
                let connect_count = direct_connect_limit.min(stored_tip.height as usize + 1);
                let height = Height::try_from(connect_count.saturating_sub(1))?;
                self.state
                    .chain
                    .canonical_hash(height)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to read initial connector target: {error}")
                    })?
                    .ok_or_else(|| {
                        anyhow::anyhow!("initial connector target height {height} is missing")
                    })?
            }
            Some(active) => {
                let canonical_active =
                    self.state
                        .chain
                        .canonical_hash(active.height)
                        .map_err(|error| {
                            anyhow::anyhow!("failed to compare active and header chains: {error}")
                        })?;
                if canonical_active == Some(active.hash) {
                    if stored_tip.height <= active.height {
                        return Ok(None);
                    }
                    let advance =
                        direct_connect_limit.min((stored_tip.height - active.height) as usize);
                    let height = active
                        .height
                        .checked_add(Height::try_from(advance)?)
                        .ok_or_else(|| anyhow::anyhow!("active-state connector height overflow"))?;
                    self.state
                        .chain
                        .canonical_hash(height)
                        .map_err(|error| {
                            anyhow::anyhow!("failed to read connector target: {error}")
                        })?
                        .ok_or_else(|| {
                            anyhow::anyhow!("connector target height {height} is missing")
                        })?
                } else {
                    stored_tip.hash
                }
            }
        };

        let Some(activation) = self.state.best_chain_activation_plan(
            candidate_hash,
            NodeReorgLimits::with_maximum_connect(maximum_connect),
        )?
        else {
            return Ok(None);
        };
        let planning_micros =
            u64::try_from(planning_started.elapsed().as_micros()).unwrap_or(u64::MAX);

        // The immutable inspector which calls this method runs in canonical
        // writer order, so this chain epoch identifies the exact state used to
        // materialize the activation. Mempool-only publications intentionally
        // do not invalidate stateless block preparation.
        let epoch = super::canonical_epoch_for_node(self, 0)?.chain();
        Ok(Some(NativeActiveStatePlan {
            epoch,
            activation,
            maximum_connect,
            planning_micros,
        }))
    }

    fn native_sync_apply_prepared_active_state(
        &mut self,
        plan: PreparedActiveStatePlan,
    ) -> Result<ActiveStateConnectAttempt> {
        let PreparedActiveStatePlan {
            activation,
            prepared,
            maximum_connect,
            planning_micros,
            workload,
            ..
        } = plan;
        let attempted_connect = activation.connect.len();

        for connect in &activation.connect {
            let summary = HeaderSummary::from_block(connect.block(), connect.height());
            self.mining_events.candidate_tip_seen(summary.clone());
            self.mining_events.block_syntax_validated(summary);
        }

        let reconciliation_snapshot = self.state.store.snapshot()?;
        preflight_reorg_reconciliation_budget(
            &reconciliation_snapshot,
            &activation,
            NodeReorgLimits::with_maximum_connect(maximum_connect),
        )?;
        drop(reconciliation_snapshot);
        let disconnected_transactions =
            self.disconnected_mempool_transactions(&activation.disconnect)?;
        let connected_transactions = activation
            .connect
            .iter()
            .flat_map(|connect| connect.block.transactions.iter().cloned())
            .collect::<Vec<_>>();
        let is_reorg = !activation.disconnect.is_empty();
        if is_reorg {
            self.mining_events
                .reorg_started(activation.disconnect.len(), activation.connect.len());
        }
        let state_commit_started = StdInstant::now();
        let mutation = self.apply_reorg_classified_prepared(activation, prepared);
        let state_commit_micros =
            u64::try_from(state_commit_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let post_commit_started = StdInstant::now();
        match mutation {
            Ok(reorg) => {
                let mining_publication = self.publish_durable_mining_state(&reorg.mining);
                let mempool_generation = self.mining_engine_reconcile_chain_transition(
                    &disconnected_transactions,
                    &connected_transactions,
                );
                mining_publication?;
                self.mining_engine_publish_mempool_reconciled(
                    reorg.mining.generation,
                    mempool_generation,
                )?;
                let post_commit_micros =
                    u64::try_from(post_commit_started.elapsed().as_micros()).unwrap_or(u64::MAX);
                Ok(std::ops::ControlFlow::Continue(ActiveStateConnectOutcome {
                    connected: reorg.summary.connected.len(),
                    disconnected: reorg.summary.disconnected.len(),
                    contextual_failure: None,
                    planning_micros,
                    state_commit_micros,
                    post_commit_micros,
                    workload,
                }))
            }
            Err(ChainActivationFailure::ContextualInvalid(failure)) => {
                if is_reorg {
                    self.mining_events.reorg_aborted();
                }
                tracing::warn!(
                    block = %failure.request.block.hash().to_hex(),
                    height = failure.request.height,
                    reason = %failure.error,
                    "durably rejecting contextual-invalid native branch"
                );
                let failed = self
                    .state
                    .store_failed_block(failure.request, FailedBlockStage::ContextualState);
                if failed.is_err() {
                    self.fail_closed_after_ambiguous_commit();
                }
                let failed = failed?;
                let post_commit_micros =
                    u64::try_from(post_commit_started.elapsed().as_micros()).unwrap_or(u64::MAX);
                Ok(std::ops::ControlFlow::Continue(ActiveStateConnectOutcome {
                    contextual_failure: Some(failed),
                    planning_micros,
                    state_commit_micros,
                    post_commit_micros,
                    workload,
                    ..ActiveStateConnectOutcome::default()
                }))
            }
            Err(ChainActivationFailure::Internal(error)) => {
                self.fail_closed_after_ambiguous_commit();
                if is_reorg {
                    self.mining_events.reorg_aborted();
                }
                let error =
                    error.context("active-state connector failed without block-invalid evidence");
                if let Some((retry_connect, limit, actual)) =
                    direct_staged_effect_retry(&error, is_reorg, attempted_connect)
                {
                    return Ok(std::ops::ControlFlow::Break(DirectStagedEffectLimit {
                        retry_connect,
                        limit,
                        actual,
                    }));
                }
                Err(error)
            }
        }
    }
}

impl NodeReadHandle {
    fn native_sync_plan_stored_state_with_hint(
        &self,
        maximum_connect: usize,
        stored_tip_hint: Option<&ChainTip>,
    ) -> Result<Option<NativeActiveStatePlan>> {
        let planning_started = StdInstant::now();
        if maximum_connect == 0 || maximum_connect > MAX_ACTIVE_STATE_CONNECT_BATCH {
            anyhow::bail!(
                "active-state connector batch {maximum_connect} is outside 1..={MAX_ACTIVE_STATE_CONNECT_BATCH}"
            );
        }
        let (epoch, activation) = self.with_stable_epoch_read(|store, headers| {
            let snapshot = store.snapshot()?;
            let stored_tip = Self::native_sync_contiguous_body_tip_from_snapshot(
                &snapshot,
                headers,
                stored_tip_hint,
            )?;
            let Some(stored_tip) = stored_tip else {
                return Ok(None);
            };
            let active_tip = best_block_tip_from_snapshot(&snapshot)?;
            if active_tip.as_ref() == Some(&stored_tip) {
                return Ok(None);
            }

            let direct_connect_limit = maximum_connect.min(MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE);
            let candidate_hash = match active_tip.as_ref() {
                None => {
                    let connect_count = direct_connect_limit.min(stored_tip.height as usize + 1);
                    let height = Height::try_from(connect_count.saturating_sub(1))?;
                    headers
                        .canonical_hash(height)
                        .context("failed to read initial connector target")?
                        .ok_or_else(|| {
                            anyhow::anyhow!("initial connector target height {height} is missing")
                        })?
                }
                Some(active) => {
                    let canonical_active = headers
                        .canonical_hash(active.height)
                        .context("failed to compare active and header chains")?;
                    if canonical_active == Some(active.hash) {
                        if stored_tip.height <= active.height {
                            return Ok(None);
                        }
                        let advance =
                            direct_connect_limit.min((stored_tip.height - active.height) as usize);
                        let height = active
                            .height
                            .checked_add(Height::try_from(advance)?)
                            .ok_or_else(|| {
                                anyhow::anyhow!("active-state connector height overflow")
                            })?;
                        headers
                            .canonical_hash(height)
                            .context("failed to read connector target")?
                            .ok_or_else(|| {
                                anyhow::anyhow!("connector target height {height} is missing")
                            })?
                    } else {
                        stored_tip.hash
                    }
                }
            };

            Self::native_sync_best_chain_activation_plan_from_snapshot(
                &snapshot,
                headers,
                candidate_hash,
                NodeReorgLimits::with_maximum_connect(maximum_connect),
            )
        })?;
        Ok(activation.map(|activation| NativeActiveStatePlan {
            epoch: epoch.chain(),
            activation,
            maximum_connect,
            planning_micros: u64::try_from(planning_started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
        }))
    }

    fn native_sync_best_chain_activation_plan_from_snapshot(
        base: &impl ReadSnapshot,
        headers: &impl HeaderIndex,
        candidate: BlockHash,
        limits: NodeReorgLimits,
    ) -> Result<Option<NodeReorg>> {
        let reads = super::StagingOverlay::new();
        let snapshot = reads.snapshot(base);
        let candidate_record = load_block_index_record(&snapshot, &candidate)?
            .ok_or_else(|| anyhow::anyhow!("candidate block index is missing"))?;
        super::validate_block_header_binding(&snapshot, &candidate_record)?;
        if candidate_record.status.failed || candidate_record.status.active_chain {
            return Ok(None);
        }
        if !candidate_record.status.header_context_valid
            || !candidate_record.status.body_present
            || !candidate_record.status.body_syntax_valid
            || !candidate_record.status.absolute_finality_valid
        {
            anyhow::bail!("candidate block is not eligible for best-chain activation");
        }

        let active = best_block_tip_from_snapshot(&snapshot)?;
        if active
            .as_ref()
            .is_some_and(|tip| candidate_record.chainwork <= tip.chainwork)
        {
            return Ok(None);
        }
        let plan = match active.as_ref() {
            Some(tip) => headers
                .plan_reorg_between_bounded(
                    &tip.hash,
                    &candidate,
                    NodeReorgLimits::PRODUCTION.header_limits(),
                )
                .map_err(|error| {
                    anyhow::anyhow!("failed to plan bounded best-chain reorg: {error}")
                })?,
            None => hns_chain::ReorgPlan {
                disconnect: Vec::new(),
                connect: super::stored_path_from_genesis_bounded(
                    &snapshot,
                    candidate,
                    limits.maximum_connect,
                )?,
            },
        };
        super::validate_reorg_plan(&snapshot, active.as_ref(), candidate, &plan)?;
        if plan.connect.len() > limits.maximum_connect {
            anyhow::bail!(
                "active-state reorganization needs more than {} replacement blocks before exceeding the active tip",
                limits.maximum_connect
            );
        }

        let disconnect = plan
            .disconnect
            .iter()
            .map(|hash| {
                let record = load_block_index_record(&snapshot, hash)?.ok_or_else(|| {
                    anyhow::anyhow!("disconnect block index {} is missing", hash.to_hex())
                })?;
                Ok(super::NodeBlockDisconnect {
                    block_hash: *hash,
                    height: record.height,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut body_bytes = 0u64;
        let mut connect = Vec::with_capacity(plan.connect.len());
        for hash in &plan.connect {
            connect.push(super::node_import_from_stored_bounded(
                &snapshot,
                hash,
                &mut body_bytes,
                limits.maximum_body_bytes,
            )?);
        }
        Ok(Some(NodeReorg {
            disconnect,
            connect,
        }))
    }

    fn native_sync_contiguous_body_tip(&self, hint: Option<&ChainTip>) -> Result<Option<ChainTip>> {
        self.with_stable_read(|store, headers| {
            let snapshot = store.snapshot()?;
            Self::native_sync_contiguous_body_tip_from_snapshot(&snapshot, headers, hint)
        })
    }

    fn native_sync_contiguous_body_tip_from_snapshot(
        snapshot: &impl ReadSnapshot,
        headers: &impl HeaderIndex,
        hint: Option<&ChainTip>,
    ) -> Result<Option<ChainTip>> {
        let Some(best) = headers.best_tip().map_err(|error| {
            anyhow::anyhow!("failed to read contiguous-body header tip: {error}")
        })?
        else {
            return Ok(None);
        };

        let mut current = None;
        let mut start_height = 0;
        if let Some(hint) = hint {
            if hint.height <= best.height
                && headers
                    .canonical_hash(hint.height)
                    .context("failed to validate stored-tip hint")?
                    == Some(hint.hash)
                && Self::native_sync_has_block_from_snapshot(snapshot, &hint.hash)?
            {
                current = Some(hint.clone());
                start_height = hint.height.saturating_add(1);
            }
        }

        for height in start_height..=best.height {
            let Some(hash) = headers
                .canonical_hash(height)
                .context("failed to inspect canonical body chain")?
            else {
                break;
            };
            if !Self::native_sync_has_block_from_snapshot(snapshot, &hash)? {
                break;
            }
            let record = Self::native_sync_header_record_from_snapshot(snapshot, &hash)?
                .ok_or_else(|| anyhow::anyhow!("canonical header {} is missing", hash.to_hex()))?;
            current = Some(ChainTip {
                hash,
                height: record.height,
                chainwork: record.chainwork,
            });
        }
        Ok(current)
    }

    fn native_sync_queue_missing_canonical_bodies(
        &self,
        scheduler: &mut SyncScheduler,
    ) -> Result<usize> {
        let config = self.config();
        if config.native_sync.headers_only {
            return Ok(0);
        }
        let hint = scheduler.stored_tip().cloned();
        // Never scan farther than the bounded validation pipeline can admit.
        // The orphan horizon remains the durable out-of-order storage bound,
        // while this smaller window prevents every supervisor tick from
        // rereading a production-scale horizon on low-core hosts.
        let candidate_scan_window = native_body_candidate_scan_window(&config.native_sync);
        let body_window = Height::try_from(candidate_scan_window)
            .context("orphan block horizon exceeds the canonical height range")?;
        if body_window == 0 {
            anyhow::bail!("orphan block horizon is zero");
        }
        let (contiguous, candidates) = self.with_stable_read(|store, headers| {
            let snapshot = store.snapshot()?;
            let contiguous = Self::native_sync_contiguous_body_tip_from_snapshot(
                &snapshot,
                headers,
                hint.as_ref(),
            )?;
            let Some(best) = headers.best_tip().map_err(|error| {
                anyhow::anyhow!("failed to read body-queue header tip: {error}")
            })?
            else {
                return Ok((contiguous, Vec::new()));
            };
            let start_height = contiguous
                .as_ref()
                .map_or(0, |tip| tip.height.saturating_add(1));
            // Canonical validated bodies are durable even when a lower parent
            // body has not arrived, but this bounded horizon prevents an
            // unbounded future-body range on disk.
            let last_height = start_height
                .saturating_add(body_window.saturating_sub(1))
                .min(best.height);
            let mut candidates = Vec::new();
            for height in start_height..=last_height {
                let Some(hash) = headers
                    .canonical_hash(height)
                    .context("failed to read canonical body target")?
                else {
                    break;
                };
                if !Self::native_sync_has_block_from_snapshot(&snapshot, &hash)? {
                    candidates.push((hash, height));
                }
            }
            Ok((contiguous, candidates))
        })?;
        if scheduler.stored_tip() != contiguous.as_ref() {
            scheduler.set_stored_tip(contiguous.clone());
        }
        let mut queued = 0usize;
        let mut available = scheduler.available_pending_slots();
        if available == 0 {
            return Ok(0);
        }
        for (hash, height) in candidates {
            if available == 0 {
                break;
            }
            if scheduler.is_tracked_block(&hash) {
                continue;
            }
            if scheduler
                .queue_block(hash, height)
                .map_err(|error| anyhow::anyhow!("failed to queue canonical block body: {error}"))?
            {
                queued = queued.saturating_add(1);
                available = available.saturating_sub(1);
            }
        }
        Ok(queued)
    }

    fn native_sync_block_locator(&self, maximum: usize) -> Result<Vec<BlockHash>> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        let config = self.config();
        self.with_stable_read(|_store, headers| {
            let Some(tip) = headers
                .best_tip()
                .map_err(|error| anyhow::anyhow!("failed to read locator header tip: {error}"))?
            else {
                return Ok(vec![config.network.params().genesis_hash]);
            };

            let mut locator = Vec::with_capacity(maximum.min(MAX_LOCATOR_ENTRIES));
            let mut height = tip.height;
            let mut step = 1u32;
            while locator.len() < maximum {
                if let Some(hash) = headers
                    .canonical_hash(height)
                    .context("failed to read locator header")?
                {
                    locator.push(hash);
                }
                if height == 0 {
                    break;
                }
                if locator.len() >= 10 {
                    step = step.saturating_mul(2);
                }
                height = height.saturating_sub(step);
            }
            if !locator.contains(&config.network.params().genesis_hash) {
                locator.push(config.network.params().genesis_hash);
            }
            locator.truncate(maximum);
            Ok(locator)
        })
    }

    fn native_sync_headers_after_locator(
        &self,
        locator: &[BlockHash],
        stop: BlockHash,
        maximum: usize,
    ) -> Result<Vec<Header>> {
        let maximum = maximum.min(MAX_SERVED_HEADERS);
        self.with_stable_read(|store, headers| {
            let snapshot = store.snapshot()?;
            let Some(best) = headers
                .best_tip()
                .map_err(|error| anyhow::anyhow!("failed to read served-header tip: {error}"))?
            else {
                return Ok(Vec::new());
            };

            let mut start_height = 0;
            'locator: for hash in locator {
                if let Some(record) =
                    Self::native_sync_header_record_from_snapshot(&snapshot, hash)?
                {
                    if headers
                        .canonical_hash(record.height)
                        .context("failed to inspect canonical header")?
                        == Some(*hash)
                    {
                        start_height = record.height.saturating_add(1);
                        break 'locator;
                    }
                }
            }

            let mut served = Vec::with_capacity(maximum);
            for height in start_height..=best.height {
                if served.len() >= maximum {
                    break;
                }
                let Some(hash) = headers
                    .canonical_hash(height)
                    .context("failed to read canonical header")?
                else {
                    break;
                };
                let record = Self::native_sync_header_record_from_snapshot(&snapshot, &hash)?
                    .ok_or_else(|| {
                        anyhow::anyhow!("canonical header {} is missing", hash.to_hex())
                    })?;
                served.push(record.header);
                if stop != BlockHash::ZERO && hash == stop {
                    break;
                }
            }
            Ok(served)
        })
    }

    /// Build Core's parent-authority response with O(1) keyed reads from one
    /// immutable store snapshot and its matching published generation.
    fn parent_authority_value(&self, hash: BlockHash) -> Result<serde_json::Value> {
        let config = self.config();
        for _ in 0..8 {
            let result = self.with_stable_read(|store, headers| {
                let published = self.published();
                let snapshot = store.snapshot()?;
                let active_tip = best_block_tip_from_snapshot(&snapshot)?;
                let best_header = headers.best_tip().map_err(|error| {
                    anyhow::anyhow!("failed to read parent-authority header tip: {error}")
                })?;
                let generation = mining_generation_from_snapshot(&snapshot)?;
                if published.canonical_epoch().tip != active_tip
                    || published.mining_generation() != generation
                {
                    anyhow::bail!(
                        "published parent-authority generation disagrees with durable state"
                    );
                }

                let header = load_header_record(&snapshot, &hash)?
                    .ok_or_else(|| anyhow::anyhow!("block header not found"))?;
                if read_canonical_hash(&snapshot, header.height)? != Some(hash) {
                    anyhow::bail!("block header is not canonical");
                }
                let (mining_snapshot, authoritative) = match active_tip.as_ref() {
                    Some(tip) => {
                        let (mining_snapshot, authoritative) = mining_snapshot_for_hash(
                            &snapshot,
                            config.network.canonical_id(),
                            tip.hash,
                            generation,
                        )?;
                        (Some(mining_snapshot), authoritative)
                    }
                    None => (None, false),
                };
                let durable = DurableMiningState {
                    generation,
                    snapshot: mining_snapshot,
                    authoritative,
                    synchronized: match (&best_header, &active_tip) {
                        (Some(best), Some(active)) => best == active,
                        _ => false,
                    },
                };
                let authority = authority_info(&config, &durable);
                let tip_validation = match active_tip.as_ref() {
                    Some(tip) => {
                        load_block_index_record(&snapshot, &tip.hash)?.map(|record| record.status)
                    }
                    None => None,
                };
                let confirmations = active_tip
                    .as_ref()
                    .and_then(|tip| tip.height.checked_sub(header.height))
                    .map_or(0, |depth| depth.saturating_add(1));
                let pending_best_chain_activation = match (&best_header, &active_tip) {
                    (Some(best), Some(active)) => {
                        best.hash != active.hash && best.chainwork > active.chainwork
                    }
                    (Some(_), None) => true,
                    _ => false,
                };

                Ok(serde_json::json!({
                "api_version": HSRD_DIAGNOSTIC_API_VERSION,
                "network": config.network.to_string(),
                "rpc_authentication_required": config.rpc_authorization.is_some(),
                "chain": {
                    "blocks": active_tip.as_ref().map_or(0, |tip| tip.height),
                    "headers": best_header.as_ref().map_or(0, |tip| tip.height),
                    "bestblockhash": active_tip.as_ref().map(|tip| tip.hash.to_hex()),
                    "chainwork": active_tip.as_ref().map(|tip| format!("{:x}", tip.chainwork)).unwrap_or_else(|| "0".to_owned()),
                },
                "header": {
                    "hash": header.hash.to_hex(),
                    "confirmations": confirmations,
                    "height": header.height,
                    "time": header.header.time,
                    "chainwork": format!("{:x}", header.chainwork),
                },
                "authority": authority,
                "authoritative_mining_tip": published.authoritative_mining_snapshot().is_some(),
                "pending_best_chain_activation": pending_best_chain_activation,
                "tip_validation": tip_validation,
                }))
            });
            match result {
                Err(error) if canonical_writer_stale(&error) => continue,
                result => return result,
            }
        }
        anyhow::bail!("canonical state changed repeatedly during parent-authority read")
    }
}

fn decode_rpc_block_hash(value: &str) -> Result<BlockHash> {
    if value.len() != 64 {
        anyhow::bail!("block hash must contain exactly 64 hexadecimal characters");
    }
    let mut raw = [0u8; 32];
    for (index, output) in raw.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| anyhow::anyhow!("block hash is not hexadecimal"))?;
    }
    Ok(BlockHash::new(raw))
}

#[derive(Clone)]
struct NativeSyncHttpState {
    node: NodeReadHandle,
    diagnostics: Arc<RwLock<NativeSyncDiagnostics>>,
    diagnostic_rpc: Arc<RwLock<CachedDiagnosticRpc>>,
    read_context: RpcReadContext,
    wallet_backend: Option<WalletBackend>,
    wallet_rpc_authenticated: bool,
    wallet_rpc_profile_enabled: bool,
    limits: RpcLimits,
}

#[derive(Clone)]
struct CachedDiagnosticRpc {
    service: BasicRpcService,
    captured_at: u64,
}

async fn serve_native_sync_rpc(
    listener: TcpListener,
    state: NativeSyncHttpState,
    authorization: Option<RpcAuthorizationHeader>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let limits = state.limits;
    limits.validate()?;
    let runtime_limits = RpcRuntimeLimits::new(limits);
    let wallet_rpc_enabled = authorization.is_some()
        && state.wallet_backend.is_some()
        && state.wallet_rpc_authenticated
        && state.wallet_rpc_profile_enabled;
    let app = Router::new()
        .route("/", post(handle_native_sync_rpc))
        .route("/rpc", post(handle_native_sync_rpc))
        .route("/api/v1/status", get(handle_native_sync_status))
        .route("/api/v1/authority", get(handle_native_sync_authority))
        .route("/api/v1/parity", get(handle_native_sync_parity))
        .route("/api/v1/peers", get(handle_native_sync_peers))
        .route("/api/v1/sync", get(handle_native_sync_sync))
        .route("/api/v1/native-sync", get(handle_native_sync_diagnostics))
        .route("/api/v1/header-deployments", get(handle_header_deployments))
        .route(
            "/api/v1/mining-engine",
            get(handle_mining_engine_diagnostics),
        );
    let app = if wallet_rpc_enabled {
        app.route("/api/v1/wallet", post(handle_native_sync_wallet))
    } else {
        app
    };
    let app = app
        .with_state(state)
        .layer(DefaultBodyLimit::max(limits.maximum_request_bytes))
        .layer(middleware::from_fn_with_state(
            runtime_limits,
            enforce_rpc_resource_limits,
        ));
    let app = match authorization {
        Some(expected) => app.layer(middleware::from_fn_with_state(
            expected,
            require_rpc_authorization,
        )),
        None => app,
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .context("Native sync RPC server failed")
}

async fn compose_native_sync_rpc_service(
    node: &NodeReadHandle,
    diagnostics: &NativeSyncDiagnostics,
) -> Result<BasicRpcService> {
    let config = node.config();
    let diagnostic = node.rpc_diagnostic_service().await?;
    let mut snapshot = diagnostic.snapshot().clone();
    snapshot.network_active = diagnostics.enabled;
    snapshot.peer_count = diagnostics.peers.len();
    snapshot.node_status.experimental_registry = diagnostics.experimental_registry.clone();
    snapshot.node_status.hip76 = rpc_hip76_info(&diagnostics.peers);
    snapshot.node_status.release_stage = if config.mainnet_canary {
        "mainnet-canary-gated".to_owned()
    } else if config.mining_engine.enabled {
        "mining-engine-observe".to_owned()
    } else {
        "native-sync-live-p2p".to_owned()
    };
    Ok(BasicRpcService::new(snapshot))
}

async fn initialize_cached_diagnostic_rpc(
    node: &NodeReadHandle,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) -> Result<Arc<RwLock<CachedDiagnosticRpc>>> {
    let diagnostics = diagnostics.read().await.clone();
    Ok(Arc::new(RwLock::new(CachedDiagnosticRpc {
        service: compose_native_sync_rpc_service(node, &diagnostics).await?,
        captured_at: unix_time(),
    })))
}

async fn refresh_cached_diagnostic_rpc(
    node: &NodeReadHandle,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
    diagnostic_rpc: &Arc<RwLock<CachedDiagnosticRpc>>,
) -> Result<()> {
    let diagnostics = diagnostics.read().await.clone();
    let service = compose_native_sync_rpc_service(node, &diagnostics).await?;
    *diagnostic_rpc.write().await = CachedDiagnosticRpc {
        service,
        captured_at: unix_time(),
    };
    Ok(())
}

async fn available_mempool_info_rpc(state: &NativeSyncHttpState) -> Result<BasicRpcService> {
    // Aggregate reads are O(1): never clone the transaction collection merely
    // because its generation changed.
    let base = state.diagnostic_rpc.read().await.service.clone();
    let mempool_info = state.node.published_mempool()?.info;
    let mut snapshot = base.snapshot().clone();
    snapshot.mempool_info = mempool_info;
    snapshot.mempool_entries.clear();
    Ok(BasicRpcService::new(snapshot))
}

async fn available_diagnostic_rpc(
    state: &NativeSyncHttpState,
) -> Result<(BasicRpcService, bool, u64)> {
    // The storage-derived base remains a sync-loop capture. Overlay only the
    // already-bounded live diagnostic fields so peer/network RPCs do not stay
    // frozen at startup and request handling does not enqueue a writer command
    // or scan durable state.
    let cached = state.diagnostic_rpc.read().await.clone();
    let diagnostics = state.diagnostics.read().await;
    let mut snapshot: RpcSnapshot = cached.service.snapshot().clone();
    snapshot.network_active = diagnostics.enabled;
    snapshot.peer_count = diagnostics.peers.len();
    snapshot.node_status.experimental_registry = diagnostics.experimental_registry.clone();
    snapshot.node_status.hip76 = diagnostics.hip76.clone();
    if let Some(best_header) = diagnostics.sync.best_header.as_ref() {
        snapshot.node_status.best_header_hash = Some(best_header.hash);
        snapshot.node_status.best_header_height = Some(best_header.height);
    }
    Ok((BasicRpcService::new(snapshot), true, cached.captured_at))
}

async fn handle_native_sync_rpc(
    State(state): State<NativeSyncHttpState>,
    body: Bytes,
) -> Json<JsonRpcResponse> {
    let request = match serde_json::from_slice::<JsonRpcRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return Json(json_rpc_error(
                None,
                -32700,
                format!("parse error: {error}"),
            ))
        }
    };
    let id = request.id.clone();
    let Some(method) = RpcMethod::from_hsd_name(&request.method) else {
        return Json(json_rpc_error(id, -32601, "method not found".to_owned()));
    };
    if rpc_immediately_unsupported(method) {
        return Json(
            BasicRpcService::default()
                .handle(request)
                .unwrap_or_else(|error| json_rpc_error(id, -32603, error.to_string())),
        );
    }

    if matches!(
        method,
        RpcMethod::GetHsrdStatus
            | RpcMethod::GetAuthorityInfo
            | RpcMethod::GetParityInfo
            | RpcMethod::GetMiningEngineInfo
    ) {
        return cached_json_rpc_diagnostic(&state, request).await;
    }

    if method == RpcMethod::GetMempoolInfo {
        let service = match available_mempool_info_rpc(&state).await {
            Ok(service) => service,
            Err(error) => {
                return Json(json_rpc_error(
                    id,
                    -32603,
                    format!("failed to capture live mempool state: {error}"),
                ));
            }
        };
        return Json(
            service
                .handle(request)
                .unwrap_or_else(|error| json_rpc_error(id, -32603, error.to_string())),
        );
    }

    if method == RpcMethod::GetRawMempool {
        let Some(collection_permit) = state.read_context.try_acquire_collection() else {
            return Json(json_rpc_error(
                id,
                -32005,
                "RPC collection-worker concurrency limit exceeded".to_owned(),
            ));
        };
        let limits = state.limits;
        let base = state.diagnostic_rpc.read().await.service.snapshot().clone();
        let mempool = match state.node.rpc_request_mempool(&request).await {
            Ok(mempool) => mempool,
            Err(error) => {
                return Json(json_rpc_error(
                    id,
                    -32603,
                    format!("failed to inspect mempool: {error}"),
                ));
            }
        };
        let worker_request = request;
        let worker_id = id.clone();
        let response = tokio::task::spawn_blocking(move || {
            let _collection_permit = collection_permit;
            if mempool.info.transaction_count > limits.maximum_collection_entries {
                return json_rpc_error(
                    worker_id,
                    -8,
                    format!(
                        "mempool collection exceeds the RPC limit of {} entries",
                        limits.maximum_collection_entries
                    ),
                );
            }
            let Some(ordered_txids) = mempool.ordered_txids else {
                return json_rpc_error(
                    worker_id,
                    -32603,
                    "mempool transaction-id view was not captured".to_owned(),
                );
            };
            if ordered_txids.len() != mempool.info.transaction_count {
                return json_rpc_error(
                    worker_id,
                    -32603,
                    "mempool transaction-id view does not match aggregate count".to_owned(),
                );
            }
            let mut snapshot = base;
            snapshot.mempool_info = mempool.info;
            snapshot.mempool_entries.clear();
            BasicRpcService::new(snapshot)
                .handle_raw_mempool(worker_request, ordered_txids.txids())
                .unwrap_or_else(|error| json_rpc_error(worker_id, -32603, error.to_string()))
        })
        .await;
        return Json(match response {
            Ok(response) => response,
            Err(error) => {
                json_rpc_error(id, -32603, format!("RPC collection worker failed: {error}"))
            }
        });
    }

    if method == RpcMethod::GetParentAuthority {
        let Some(encoded_hash) = request
            .params
            .as_array()
            .and_then(|params| params.first())
            .and_then(serde_json::Value::as_str)
        else {
            return Json(json_rpc_error(id, -32602, "missing parent hash".to_owned()));
        };
        let hash = match decode_rpc_block_hash(encoded_hash) {
            Ok(hash) => hash,
            Err(error) => return Json(json_rpc_error(id, -32602, error.to_string())),
        };
        let Some(point_read_permit) = state.read_context.try_acquire_point_read() else {
            return Json(json_rpc_error(
                id,
                -32005,
                "RPC point-read concurrency limit exceeded".to_owned(),
            ));
        };
        let node = state.node.clone();
        let result = match tokio::task::spawn_blocking(move || {
            let _point_read_permit = point_read_permit;
            node.parent_authority_value(hash)
        })
        .await
        {
            Ok(result) => result,
            Err(error) => {
                return Json(json_rpc_error(
                    id,
                    -32603,
                    format!("RPC parent-authority worker failed: {error}"),
                ));
            }
        };
        return match result {
            Ok(result) => Json(JsonRpcResponse {
                jsonrpc: "2.0".to_owned(),
                result: Some(result),
                error: None,
                id,
            }),
            Err(error) => Json(json_rpc_error(id, -32603, error.to_string())),
        };
    }

    if rpc_point_read_method(method) {
        let Some(point_read_permit) = state.read_context.try_acquire_point_read() else {
            return Json(json_rpc_error(
                id,
                -32005,
                "RPC point-read concurrency limit exceeded".to_owned(),
            ));
        };
        let mempool = if method == RpcMethod::GetRawTransaction {
            match state.node.rpc_request_mempool(&request).await {
                Ok(mempool) => mempool,
                Err(error) => {
                    return Json(json_rpc_error(
                        id,
                        -32603,
                        format!("failed to inspect mempool: {error}"),
                    ));
                }
            }
        } else {
            Default::default()
        };
        let diagnostics = state.diagnostics.read().await;
        let network_active = diagnostics.enabled;
        let peer_count = diagnostics.peers.len();
        drop(diagnostics);
        let read_context = state.read_context.clone();
        let read_request = request;
        let response = match tokio::task::spawn_blocking(move || -> Result<JsonRpcResponse> {
            let _point_read_permit = point_read_permit;
            let service = read_context.service_for_request(
                &read_request,
                mempool,
                network_active,
                peer_count,
                None,
            )?;
            service
                .handle(read_request)
                .map_err(|error| anyhow::anyhow!("RPC response construction failed: {error}"))
        })
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return Json(json_rpc_error(id, -32603, error.to_string()));
            }
            Err(error) => {
                return Json(json_rpc_error(
                    id,
                    -32603,
                    format!("RPC point-read worker failed: {error}"),
                ));
            }
        };
        return Json(response);
    }

    match available_diagnostic_rpc(&state).await {
        Ok((service, _, _)) => Json(
            service
                .handle(request)
                .unwrap_or_else(|error| json_rpc_error(id, -32603, error.to_string())),
        ),
        Err(error) => Json(json_rpc_error(id, -32603, error.to_string())),
    }
}

async fn handle_native_sync_wallet(
    State(state): State<NativeSyncHttpState>,
    body: Bytes,
) -> axum::response::Response {
    wallet_rpc::dispatch_wallet_rpc(
        state.wallet_backend.as_ref(),
        state.wallet_rpc_authenticated,
        state.wallet_rpc_profile_enabled,
        &body,
    )
    .await
    .into_response()
}

async fn diagnostic_method(state: &NativeSyncHttpState, method: &str) -> serde_json::Value {
    match available_diagnostic_rpc(state).await {
        Ok((service, cached, captured_at)) => {
            let response = service.handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: method.to_owned(),
                params: serde_json::Value::Null,
                id: None,
            });
            match response {
                Ok(response) => {
                    let mut result = response.result.unwrap_or_else(|| {
                        serde_json::json!({
                            "error": response
                                .error
                                .map(|error| error.message)
                                .unwrap_or_else(|| "missing result".to_owned())
                        })
                    });
                    if let Some(object) = result.as_object_mut() {
                        object.insert(
                            "diagnostic_snapshot_cached".to_owned(),
                            serde_json::Value::Bool(cached),
                        );
                        object.insert(
                            "diagnostic_snapshot_captured_at".to_owned(),
                            serde_json::json!(captured_at),
                        );
                    }
                    result
                }
                Err(error) => serde_json::json!({ "error": error.to_string() }),
            }
        }
        Err(error) => serde_json::json!({ "error": error.to_string() }),
    }
}

async fn cached_json_rpc_diagnostic(
    state: &NativeSyncHttpState,
    request: JsonRpcRequest,
) -> Json<JsonRpcResponse> {
    let id = request.id.clone();
    match available_diagnostic_rpc(state).await {
        Ok((service, cached, captured_at)) => {
            let mut response = service
                .handle(request)
                .unwrap_or_else(|error| json_rpc_error(id, -32603, error.to_string()));
            if let Some(serde_json::Value::Object(result)) = response.result.as_mut() {
                result.insert(
                    "diagnostic_snapshot_cached".to_owned(),
                    serde_json::Value::Bool(cached),
                );
                result.insert(
                    "diagnostic_snapshot_captured_at".to_owned(),
                    serde_json::json!(captured_at),
                );
            }
            Json(response)
        }
        Err(error) => Json(json_rpc_error(id, -32603, error.to_string())),
    }
}

async fn handle_native_sync_status(
    State(state): State<NativeSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "gethsrdstatus").await)
}

async fn handle_native_sync_authority(
    State(state): State<NativeSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "getauthorityinfo").await)
}

async fn handle_native_sync_parity(
    State(state): State<NativeSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "getparityinfo").await)
}

async fn handle_native_sync_peers(
    State(state): State<NativeSyncHttpState>,
) -> Json<Vec<PeerSnapshot>> {
    Json(state.diagnostics.read().await.peers.clone())
}

async fn handle_native_sync_sync(State(state): State<NativeSyncHttpState>) -> Json<SyncSnapshot> {
    Json(state.diagnostics.read().await.sync.clone())
}

async fn handle_native_sync_diagnostics(
    State(state): State<NativeSyncHttpState>,
) -> Json<NativeSyncDiagnostics> {
    Json(state.diagnostics.read().await.clone())
}

async fn handle_header_deployments(
    State(state): State<NativeSyncHttpState>,
) -> Json<serde_json::Value> {
    let Some(point_read_permit) = state.read_context.try_acquire_point_read() else {
        return Json(serde_json::json!({
            "error": "RPC point-read concurrency limit exceeded"
        }));
    };
    let node = state.node.clone();
    let now = StdInstant::now();
    let deadline = now
        .checked_add(state.limits.execution_timeout)
        .unwrap_or(now);
    let result = tokio::task::spawn_blocking(move || {
        let _point_read_permit = point_read_permit;
        node.native_sync_header_deployments(deadline, MAX_HEADER_DEPLOYMENT_READS)
    })
    .await;
    Json(match result {
        Ok(Ok(diagnostics)) => serde_json::to_value(diagnostics)
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() })),
        Ok(Err(error)) => serde_json::json!({ "error": error.to_string() }),
        Err(error) => {
            serde_json::json!({ "error": format!("header deployment worker failed: {error}") })
        }
    })
}

async fn handle_mining_engine_diagnostics(
    State(state): State<NativeSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "getminingengineinfo").await)
}

#[allow(clippy::too_many_arguments)]
async fn handle_peer_event(
    event: PeerEvent,
    node: &NodeReadHandle,
    writer: &CanonicalStateWriter,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    addresses: &mut BoundedAddressBook,
    bans: &PeerBanBook,
    served_getaddr: &mut HashSet<PeerId>,
    compact_peers: &mut HashSet<PeerId>,
    pending_compact_blocks: &mut HashMap<BlockHash, PendingCompactBlock>,
    discovery: bool,
    headers_only: bool,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) -> Result<()> {
    match event {
        PeerEvent::Connected {
            address, direction, ..
        } => {
            if direction == PeerDirection::Outbound {
                if let Some(state) = reconnects.get_mut(&address) {
                    state.transport_connected(Instant::now());
                    addresses.note_transport_success(address, unix_time());
                }
            }
        }
        PeerEvent::Ready { peer, version } => {
            scheduler
                .register_peer(peer, version.services, version.height)
                .map_err(|error| anyhow::anyhow!("failed to register sync peer: {error}"))?;
            let snapshot = peers
                .snapshots()
                .await
                .into_iter()
                .find(|snapshot| snapshot.id == peer);
            if let Some(snapshot) = snapshot
                .as_ref()
                .filter(|snapshot| snapshot.direction == PeerDirection::Outbound)
            {
                let now = Instant::now();
                if let Some(state) = reconnects.get_mut(&snapshot.address) {
                    state.ready(now);
                    addresses.note_success(snapshot.address, now, unix_time(), version.services);
                }
            }
            peers
                .try_send(
                    peer,
                    Arc::new(Packet::SendCmpct {
                        mode: 0,
                        version: 1,
                    }),
                    OutboundPriority::Control,
                )
                .await
                .map_err(|error| anyhow::anyhow!("failed to negotiate compact blocks: {error}"))?;
            if discovery
                && supports_addr_protocol(version.version)
                && snapshot.is_some_and(|snapshot| snapshot.direction == PeerDirection::Outbound)
            {
                peers
                    .try_send(peer, Arc::new(Packet::GetAddr), OutboundPriority::Control)
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("failed to request peer addresses: {error}")
                    })?;
            }
        }
        PeerEvent::Disconnected {
            peer,
            address,
            direction,
            reason,
        } => {
            scheduler.remove_peer(peer);
            served_getaddr.remove(&peer);
            compact_peers.remove(&peer);
            pending_compact_blocks.retain(|_, pending| pending.peer != peer);
            if direction == PeerDirection::Outbound {
                note_reconnect_failure(address, reconnects, Instant::now());
            }
            tracing::debug!(?peer, %address, %reason, "HNS peer disconnected");
        }
        PeerEvent::InboundRejected { address, reason } => {
            update_diagnostics(diagnostics, |state| {
                state.rejected_messages = state.rejected_messages.saturating_add(1);
            })
            .await;
            tracing::debug!(%address, %reason, "inbound HNS peer rejected");
        }
        PeerEvent::Hip76CapabilityChanged { .. } => {
            // Redacted HIP-76 capability is exposed by the manager's
            // snapshot/watch surface and is intentionally not logged here.
        }
        PeerEvent::Hip76ProviderRequest { .. } => {
            // Provider policy defaults off. A future explicitly configured
            // resolver backend must consume this typed event without logging
            // its DNS query.
        }
        PeerEvent::Packet { peer, packet } => match packet {
            Packet::Headers(headers) => {
                let header_count = headers.len();
                let imported = import_header_packet(writer, headers).await;
                let imported = match imported {
                    Ok(imported) => imported,
                    Err(error) if error.downcast_ref::<MissingHeaderParent>().is_some() => {
                        // SENDHEADERS peers relay a fresh tip header even while
                        // this node is far behind. Its parent is intentionally
                        // outside our local index and can race an outstanding
                        // GETHEADERS response from the same peer. Ignore the
                        // detached announcement without consuming that request
                        // or banning every healthy peer at the network tip.
                        tracing::debug!(
                            ?peer,
                            %error,
                            "ignored detached live header announcement while synchronizing"
                        );
                        return Ok(());
                    }
                    Err(error) if canonical_writer_contention(&error) => {
                        // The peer supplied a complete response; only local
                        // writer admission prevented its atomic import. Clear
                        // the request so the next maintenance poll can issue
                        // a fresh locator without attributing local pressure
                        // to the remote peer.
                        scheduler.note_headers_response(peer, header_count);
                        tracing::debug!(
                            ?peer,
                            %error,
                            "deferred peer header batch after local canonical contention"
                        );
                        return Ok(());
                    }
                    Err(error) => {
                        // A connecting response consumes the outstanding
                        // request even if its consensus validation fails.
                        // Otherwise a malicious peer can pin the request slot
                        // until the timeout fires.
                        scheduler.note_headers_response(peer, header_count);
                        if let Some(penalty) = peer_header_import_penalty(&error) {
                            // Proven-invalid header packets commit atomically.
                            // Refresh from the unchanged durable index before
                            // scoring the sender so retries start from the
                            // last complete protocol batch.
                            scheduler.set_best_header(node.native_sync_best_header_tip()?);
                            node.native_sync_queue_missing_canonical_bodies(scheduler)?;
                            penalize_peer(peers, peer, penalty, "peer header batch rejected")
                                .await?;
                            update_diagnostics(diagnostics, |state| {
                                state.rejected_messages = state.rejected_messages.saturating_add(1);
                            })
                            .await;
                            return Err(error.context("peer header batch rejected"));
                        }
                        return Err(error
                            .context("local dependency failed while importing peer header batch"));
                    }
                };
                scheduler.note_headers_response(peer, header_count);
                scheduler.set_best_header(node.native_sync_best_header_tip()?);
                node.native_sync_queue_missing_canonical_bodies(scheduler)?;
                update_diagnostics(diagnostics, |state| {
                    state.received_headers =
                        state.received_headers.saturating_add(imported.len() as u64);
                })
                .await;
            }
            Packet::Inv(items) => {
                let mut unknown_header_seen = false;
                let mut relay_requests = Vec::new();
                let mut relay_seen = HashSet::new();
                for item in items {
                    if matches!(
                        item.kind,
                        InventoryKind::Transaction | InventoryKind::Claim | InventoryKind::Airdrop
                    ) {
                        if relay_seen.len() >= MAX_GETDATA_ITEMS || !relay_seen.insert(item.clone())
                        {
                            continue;
                        }
                        let config = node.config();
                        let missing = if !config.mining_engine.enabled
                            || !config.mining_engine.transaction_relay
                        {
                            false
                        } else {
                            match item.kind {
                                InventoryKind::Transaction => node
                                    .mempool_transaction(Txid::new(item.hash))
                                    .await?
                                    .is_none(),
                                InventoryKind::Claim => {
                                    node.mempool_claim(item.hash).await?.is_none()
                                }
                                InventoryKind::Airdrop => {
                                    node.mempool_airdrop(item.hash).await?.is_none()
                                }
                                _ => false,
                            }
                        };
                        if missing {
                            relay_requests.push(item);
                        }
                        continue;
                    }
                    if !matches!(
                        item.kind,
                        InventoryKind::Block
                            | InventoryKind::FilteredBlock
                            | InventoryKind::CompactBlock
                    ) {
                        continue;
                    }
                    let hash = BlockHash::new(item.hash);
                    let record = node.native_sync_header_record(&hash)?;
                    match record {
                        Some(record) if !headers_only => {
                            let has_body = node.native_sync_has_block(&hash)?;
                            if !has_body {
                                scheduler
                                    .announce_block(peer, hash, record.height)
                                    .map_err(|error| {
                                        anyhow::anyhow!("failed to queue announced block: {error}")
                                    })?;
                            }
                        }
                        Some(_) => {}
                        None => unknown_header_seen = true,
                    }
                }
                if unknown_header_seen {
                    request_headers_from_peer(peer, node, peers, scheduler).await?;
                }
                if !relay_requests.is_empty() {
                    peers
                        .try_send(
                            peer,
                            Arc::new(Packet::GetData(relay_requests)),
                            OutboundPriority::Control,
                        )
                        .await
                        .map_err(|error| {
                            anyhow::anyhow!("failed to request relayed mempool item: {error}")
                        })?;
                }
            }
            Packet::Block(block) => {
                let hash = block.hash();
                if pending_compact_blocks
                    .get(&hash)
                    .is_some_and(|pending| pending.peer == peer)
                {
                    pending_compact_blocks.remove(&hash);
                }
                update_diagnostics(diagnostics, |state| {
                    state.received_blocks = state.received_blocks.saturating_add(1);
                    if headers_only {
                        state.rejected_messages = state.rejected_messages.saturating_add(1);
                    }
                })
                .await;
                if !headers_only {
                    accept_peer_block(peer, block, node, writer, peers, validation, scheduler)
                        .await?;
                }
            }
            Packet::GetHeaders(locator) => {
                let headers = node.native_sync_headers_after_locator(
                    &locator.locator,
                    locator.stop,
                    MAX_SERVED_HEADERS,
                )?;
                update_diagnostics(diagnostics, |state| {
                    state.served_headers =
                        state.served_headers.saturating_add(headers.len() as u64);
                })
                .await;
                peers
                    .try_send(
                        peer,
                        Arc::new(Packet::Headers(headers)),
                        OutboundPriority::Control,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("failed to serve headers: {error}"))?;
            }
            Packet::GetBlocks(locator) => {
                let headers = node.native_sync_headers_after_locator(
                    &locator.locator,
                    locator.stop,
                    MAX_GETDATA_ITEMS,
                )?;
                let inventory = headers
                    .into_iter()
                    .map(|header| Inventory::block(header.hash()))
                    .collect();
                peers
                    .try_send(
                        peer,
                        Arc::new(Packet::Inv(inventory)),
                        OutboundPriority::Control,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("failed to serve block inventory: {error}"))?;
            }
            Packet::GetData(items) => {
                if items.len() > MAX_GETDATA_ITEMS {
                    penalize_peer(peers, peer, 20, "peer requested too many inventory items")
                        .await?;
                    anyhow::bail!("peer requested too many inventory items: {}", items.len());
                }
                let mut not_found = Vec::new();
                for item in items {
                    match item.kind {
                        InventoryKind::Transaction => {
                            let config = node.config();
                            let transaction = if config.mining_engine.enabled
                                && config.mining_engine.transaction_relay
                            {
                                node.mempool_transaction(Txid::new(item.hash)).await?
                            } else {
                                None
                            };
                            match transaction {
                                Some(transaction) => {
                                    peers
                                        .try_send(
                                            peer,
                                            Arc::new(Packet::Tx(transaction)),
                                            OutboundPriority::Normal,
                                        )
                                        .await
                                        .map_err(|error| {
                                            anyhow::anyhow!("failed to serve transaction: {error}")
                                        })?;
                                    update_diagnostics(diagnostics, |state| {
                                        state.served_transactions =
                                            state.served_transactions.saturating_add(1);
                                    })
                                    .await;
                                }
                                None => not_found.push(item),
                            }
                        }
                        InventoryKind::Claim => {
                            let config = node.config();
                            let claim = if config.mining_engine.enabled
                                && config.mining_engine.transaction_relay
                            {
                                node.mempool_claim(item.hash).await?
                            } else {
                                None
                            };
                            match claim {
                                Some(claim) => {
                                    peers
                                        .try_send(
                                            peer,
                                            Arc::new(Packet::Claim(claim)),
                                            OutboundPriority::Normal,
                                        )
                                        .await
                                        .map_err(|error| {
                                            anyhow::anyhow!("failed to serve claim: {error}")
                                        })?;
                                    update_diagnostics(diagnostics, |state| {
                                        state.served_claims = state.served_claims.saturating_add(1);
                                    })
                                    .await;
                                }
                                None => not_found.push(item),
                            }
                        }
                        InventoryKind::Airdrop => {
                            let config = node.config();
                            let proof = if config.mining_engine.enabled
                                && config.mining_engine.transaction_relay
                            {
                                node.mempool_airdrop(item.hash).await?
                            } else {
                                None
                            };
                            match proof {
                                Some(proof) => {
                                    peers
                                        .try_send(
                                            peer,
                                            Arc::new(Packet::Airdrop(proof)),
                                            OutboundPriority::Normal,
                                        )
                                        .await
                                        .map_err(|error| {
                                            anyhow::anyhow!("failed to serve airdrop: {error}")
                                        })?;
                                    update_diagnostics(diagnostics, |state| {
                                        state.served_airdrops =
                                            state.served_airdrops.saturating_add(1);
                                    })
                                    .await;
                                }
                                None => not_found.push(item),
                            }
                        }
                        InventoryKind::Block | InventoryKind::FilteredBlock => {
                            let hash = BlockHash::new(item.hash);
                            let block = node.native_sync_block(&hash)?;
                            match block {
                                Some(block) => {
                                    peers
                                        .try_send(
                                            peer,
                                            Arc::new(Packet::Block(block)),
                                            OutboundPriority::Normal,
                                        )
                                        .await
                                        .map_err(|error| {
                                            anyhow::anyhow!("failed to serve block: {error}")
                                        })?;
                                    update_diagnostics(diagnostics, |state| {
                                        state.served_blocks = state.served_blocks.saturating_add(1);
                                    })
                                    .await;
                                }
                                None => not_found.push(item),
                            }
                        }
                        InventoryKind::CompactBlock => {
                            let hash = BlockHash::new(item.hash);
                            let block = node.native_sync_block(&hash)?;
                            match block {
                                Some(block) if compact_peers.contains(&peer) => {
                                    peers
                                        .try_send(
                                            peer,
                                            Arc::new(Packet::CmpctBlock(CompactBlock::from_block(
                                                &block,
                                            ))),
                                            OutboundPriority::Normal,
                                        )
                                        .await
                                        .map_err(|error| {
                                            anyhow::anyhow!(
                                                "failed to serve compact block: {error}"
                                            )
                                        })?;
                                    update_diagnostics(diagnostics, |state| {
                                        state.served_compact_blocks =
                                            state.served_compact_blocks.saturating_add(1);
                                    })
                                    .await;
                                }
                                Some(block) => {
                                    peers
                                        .try_send(
                                            peer,
                                            Arc::new(Packet::Block(block)),
                                            OutboundPriority::Normal,
                                        )
                                        .await
                                        .map_err(|error| {
                                            anyhow::anyhow!("failed to serve block: {error}")
                                        })?;
                                    update_diagnostics(diagnostics, |state| {
                                        state.served_blocks = state.served_blocks.saturating_add(1);
                                    })
                                    .await;
                                }
                                None => not_found.push(item),
                            }
                        }
                        _ => not_found.push(item),
                    }
                }
                if !not_found.is_empty() {
                    peers
                        .try_send(
                            peer,
                            Arc::new(Packet::NotFound(not_found)),
                            OutboundPriority::Control,
                        )
                        .await
                        .map_err(|error| anyhow::anyhow!("failed to serve notfound: {error}"))?;
                }
            }
            Packet::GetAddr => {
                let inbound = peers.snapshots().await.iter().any(|snapshot| {
                    snapshot.id == peer && snapshot.direction == PeerDirection::Inbound
                });
                if !admit_getaddr(peer, inbound, served_getaddr) {
                    return Ok(());
                }
                let advertised = addresses.advertised(hns_p2p::MAX_ADDR_ITEMS, bans, unix_time());
                if advertised.is_empty() {
                    return Ok(());
                }
                let count = advertised.len();
                peers
                    .try_send(
                        peer,
                        Arc::new(Packet::Addr(advertised)),
                        OutboundPriority::Control,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("failed to answer getaddr: {error}"))?;
                update_diagnostics(diagnostics, |state| {
                    state.served_addresses = state.served_addresses.saturating_add(count as u64);
                })
                .await;
            }
            Packet::Mempool => {
                let config = node.config();
                let inventory =
                    if config.mining_engine.enabled && config.mining_engine.transaction_relay {
                        node.mempool_inventory(MAX_GETDATA_ITEMS).await?
                    } else {
                        Vec::new()
                    };
                peers
                    .try_send(
                        peer,
                        Arc::new(Packet::Inv(inventory)),
                        OutboundPriority::Control,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("failed to answer mempool: {error}"))?;
                update_diagnostics(diagnostics, |state| {
                    state.served_mempool_inventories =
                        state.served_mempool_inventories.saturating_add(1);
                })
                .await;
            }
            Packet::Tx(transaction) => {
                update_diagnostics(diagnostics, |state| {
                    state.received_transactions = state.received_transactions.saturating_add(1);
                })
                .await;
                let admission = writer
                    .mining_engine_accept_peer_transaction(transaction)
                    .await?;
                match admission {
                    Admission::Accepted(txid) => {
                        let report = peers
                            .broadcast(
                                Arc::new(Packet::Inv(vec![Inventory::transaction(txid)])),
                                OutboundPriority::Normal,
                            )
                            .await;
                        if report.failed.len() == report.attempted && report.attempted > 0 {
                            tracing::debug!(
                                ?peer,
                                "transaction inventory relay reached no peer queue"
                            );
                        }
                    }
                    Admission::Rejected { reason } => {
                        update_diagnostics(diagnostics, |state| {
                            state.rejected_transactions =
                                state.rejected_transactions.saturating_add(1);
                        })
                        .await;
                        tracing::debug!(?peer, %reason, "peer transaction rejected");
                    }
                    Admission::Orphan(txid) => {
                        tracing::debug!(?peer, txid = %txid.to_hex(), "peer transaction retained as orphan");
                    }
                }
            }
            Packet::Claim(claim) => {
                update_diagnostics(diagnostics, |state| {
                    state.received_claims = state.received_claims.saturating_add(1);
                })
                .await;
                let admission = writer.mining_engine_accept_peer_claim(claim).await?;
                match admission {
                    ClaimAdmission::Accepted(hash) => {
                        let report = peers
                            .broadcast(
                                Arc::new(Packet::Inv(vec![Inventory::claim(hash)])),
                                OutboundPriority::Normal,
                            )
                            .await;
                        if report.failed.len() == report.attempted && report.attempted > 0 {
                            tracing::debug!(?peer, "claim inventory relay reached no peer queue");
                        }
                    }
                    ClaimAdmission::Rejected { reason } => {
                        update_diagnostics(diagnostics, |state| {
                            state.rejected_claims = state.rejected_claims.saturating_add(1);
                        })
                        .await;
                        tracing::debug!(?peer, %reason, "peer claim rejected");
                    }
                }
            }
            Packet::Airdrop(proof) => {
                update_diagnostics(diagnostics, |state| {
                    state.received_airdrops = state.received_airdrops.saturating_add(1);
                })
                .await;
                let admission = writer.mining_engine_accept_peer_airdrop(proof).await?;
                match admission {
                    AirdropAdmission::Accepted(hash) => {
                        let report = peers
                            .broadcast(
                                Arc::new(Packet::Inv(vec![Inventory::airdrop(hash)])),
                                OutboundPriority::Normal,
                            )
                            .await;
                        if report.failed.len() == report.attempted && report.attempted > 0 {
                            tracing::debug!(?peer, "airdrop inventory relay reached no peer queue");
                        }
                    }
                    AirdropAdmission::Rejected { reason } => {
                        update_diagnostics(diagnostics, |state| {
                            state.rejected_airdrops = state.rejected_airdrops.saturating_add(1);
                        })
                        .await;
                        tracing::debug!(?peer, %reason, "peer airdrop rejected");
                    }
                }
            }
            Packet::SendCmpct { mode, version } => {
                if mode <= 1 && version <= 1 {
                    compact_peers.insert(peer);
                }
            }
            Packet::CmpctBlock(compact) => {
                handle_compact_block(
                    peer,
                    compact,
                    node,
                    writer,
                    peers,
                    validation,
                    scheduler,
                    compact_peers,
                    pending_compact_blocks,
                    headers_only,
                    diagnostics,
                )
                .await?;
            }
            Packet::GetBlockTxn(request) => {
                serve_block_transactions(peer, request, node, peers, diagnostics).await?;
            }
            Packet::BlockTxn(response) => {
                handle_block_transactions(
                    peer,
                    response,
                    node,
                    writer,
                    peers,
                    validation,
                    scheduler,
                    pending_compact_blocks,
                    diagnostics,
                )
                .await?;
            }
            Packet::Reject(reject) => {
                tracing::debug!(
                    ?peer,
                    code = reject.code,
                    reason = %reject.reason,
                    "peer rejected message"
                );
            }
            Packet::NotFound(items) => {
                for item in items {
                    if let Some(hash) = item.block_hash() {
                        scheduler
                            .note_block_unavailable(peer, hash)
                            .map_err(|error| {
                                anyhow::anyhow!("peer returned invalid notfound response: {error}")
                            })?;
                    }
                }
            }
            Packet::Addr(items) => {
                let version_supports_addr = peers.snapshots().await.iter().any(|snapshot| {
                    snapshot.id == peer
                        && snapshot
                            .protocol_version
                            .is_some_and(supports_addr_protocol)
                });
                if discovery && version_supports_addr {
                    let received = items.len() as u64;
                    let now = Instant::now();
                    let timestamp = unix_time();
                    let mut accepted = 0u64;
                    for item in items {
                        let banned = item
                            .socket_addr()
                            .is_some_and(|address| bans.is_banned(address.ip(), timestamp));
                        if !banned && addresses.insert_discovered(item, now, timestamp).accepted() {
                            accepted = accepted.saturating_add(1);
                        }
                    }
                    update_diagnostics(diagnostics, |state| {
                        state.received_addresses =
                            state.received_addresses.saturating_add(received);
                        state.accepted_addresses =
                            state.accepted_addresses.saturating_add(accepted);
                        state.rejected_addresses = state
                            .rejected_addresses
                            .saturating_add(received.saturating_sub(accepted));
                    })
                    .await;
                }
            }
            Packet::SendHeaders
            | Packet::FeeFilter(_)
            | Packet::Unknown { .. }
            | Packet::Version(_)
            | Packet::Verack
            | Packet::Ping(_)
            | Packet::Pong(_) => {}
        },
    }
    Ok(())
}

async fn import_header_packet(
    writer: &CanonicalStateWriter,
    headers: Vec<Header>,
) -> Result<Vec<HeaderRecord>> {
    if headers.len() > MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE {
        return Err(anyhow::Error::new(PeerHeaderBatchLimit {
            limit: MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE,
            actual: headers.len(),
        }));
    }

    writer
        .execute(None, "import native-sync header packet", move |node| {
            node.native_sync_import_headers(headers)
        })
        .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_compact_block(
    peer: PeerId,
    compact: CompactBlock,
    node: &NodeReadHandle,
    writer: &CanonicalStateWriter,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    compact_peers: &HashSet<PeerId>,
    pending: &mut HashMap<BlockHash, PendingCompactBlock>,
    headers_only: bool,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) -> Result<()> {
    let hash = compact.hash();
    update_diagnostics(diagnostics, |state| {
        state.received_compact_blocks = state.received_compact_blocks.saturating_add(1);
        if headers_only {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
        }
    })
    .await;
    if headers_only {
        return Ok(());
    }
    if !compact_peers.contains(&peer) {
        scheduler.remove_peer(peer);
        peers.disconnect(peer).await?;
        anyhow::bail!("peer {peer:?} sent compact block without negotiation");
    }
    if !scheduler.peer_can_deliver_block(peer, &hash) {
        scheduler.remove_peer(peer);
        peers.disconnect(peer).await?;
        anyhow::bail!(
            "peer {peer:?} sent unsolicited compact block {}",
            hash.to_hex()
        );
    }
    if pending.contains_key(&hash) {
        return Ok(());
    }
    let per_peer = pending.values().filter(|item| item.peer == peer).count();
    if per_peer >= MAX_PENDING_COMPACT_BLOCKS_PER_PEER
        || pending.len() >= MAX_PENDING_COMPACT_BLOCKS
    {
        peers.disconnect(peer).await?;
        anyhow::bail!("peer {peer:?} exceeded the pending compact-block bound");
    }

    let mempool = node
        .mempool_transactions(hns_p2p::MAX_COMPACT_BLOCK_TRANSACTIONS)
        .await?;
    let reconstruction = match compact.reconstruct(&mempool) {
        Ok(reconstruction) => reconstruction,
        Err(CompactBlockError::ShortIdCollision(short_id)) => {
            penalize_peer(peers, peer, 10, "compact-block short-id collision").await?;
            request_full_block_fallback(peer, hash, peers, diagnostics).await?;
            tracing::debug!(?peer, %short_id, block = %hash.to_hex(), "compact-block short-id collision");
            return Ok(());
        }
        Err(error) => {
            penalize_peer(peers, peer, 100, "malformed compact block").await?;
            anyhow::bail!("peer {peer:?} sent malformed compact block: {error}");
        }
    };

    if reconstruction.is_complete() {
        let block = reconstruction
            .into_block()
            .map_err(|error| anyhow::anyhow!("failed to finalize compact block: {error}"))?;
        update_diagnostics(diagnostics, |state| {
            state.reconstructed_compact_blocks =
                state.reconstructed_compact_blocks.saturating_add(1);
            state.received_blocks = state.received_blocks.saturating_add(1);
        })
        .await;
        return accept_peer_block(peer, block, node, writer, peers, validation, scheduler).await;
    }

    let request = reconstruction.missing_request();
    pending.insert(
        hash,
        PendingCompactBlock {
            peer,
            received_at: Instant::now(),
            reconstruction,
        },
    );
    if let Err(error) = peers
        .try_send(
            peer,
            Arc::new(Packet::GetBlockTxn(request)),
            OutboundPriority::Control,
        )
        .await
    {
        pending.remove(&hash);
        request_full_block_fallback(peer, hash, peers, diagnostics).await?;
        tracing::debug!(?peer, block = %hash.to_hex(), %error, "compact transaction request fell back to full body");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_block_transactions(
    peer: PeerId,
    response: CompactBlockResponse,
    node: &NodeReadHandle,
    writer: &CanonicalStateWriter,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    pending: &mut HashMap<BlockHash, PendingCompactBlock>,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) -> Result<()> {
    let hash = response.block_hash;
    let Some(expected_peer) = pending.get(&hash).map(|pending| pending.peer) else {
        return Ok(());
    };
    if expected_peer != peer {
        tracing::debug!(?peer, ?expected_peer, block = %hash.to_hex(), "ignoring unsolicited blocktxn response");
        return Ok(());
    }
    let mut item = pending
        .remove(&hash)
        .expect("pending compact block remains present");
    if let Err(error) = item.reconstruction.fill_missing(response) {
        penalize_peer(peers, peer, 10, "incomplete blocktxn response").await?;
        request_full_block_fallback(peer, hash, peers, diagnostics).await?;
        tracing::debug!(?peer, block = %hash.to_hex(), %error, "compact block fell back to full body");
        return Ok(());
    }
    let block = item
        .reconstruction
        .into_block()
        .map_err(|error| anyhow::anyhow!("failed to finalize compact block: {error}"))?;
    update_diagnostics(diagnostics, |state| {
        state.reconstructed_compact_blocks = state.reconstructed_compact_blocks.saturating_add(1);
        state.received_blocks = state.received_blocks.saturating_add(1);
    })
    .await;
    accept_peer_block(peer, block, node, writer, peers, validation, scheduler).await
}

async fn request_full_block_fallback(
    peer: PeerId,
    hash: BlockHash,
    peers: &LivePeerManager,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) -> Result<()> {
    peers
        .try_send(
            peer,
            Arc::new(Packet::GetData(vec![Inventory::block(hash)])),
            OutboundPriority::Control,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to request full-block fallback: {error}"))?;
    update_diagnostics(diagnostics, |state| {
        state.compact_block_fallbacks = state.compact_block_fallbacks.saturating_add(1);
    })
    .await;
    Ok(())
}

async fn serve_block_transactions(
    peer: PeerId,
    request: CompactBlockRequest,
    node: &NodeReadHandle,
    peers: &LivePeerManager,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) -> Result<()> {
    let block_hash = request.block_hash;
    let (known, too_old, block) = node.with_stable_read(|store, _headers| {
        let snapshot = store.snapshot()?;
        let Some(record) = load_header_record(&snapshot, &block_hash)? else {
            return Ok((false, false, None));
        };
        let active_height = best_block_tip_from_snapshot(&snapshot)?.map_or(0, |tip| tip.height);
        if record.height.saturating_add(15) < active_height {
            return Ok((true, true, None));
        }
        Ok((
            true,
            false,
            load_block_from_snapshot(&snapshot, &block_hash)?,
        ))
    })?;
    if !known {
        penalize_peer(peers, peer, 100, "getblocktxn requested an unknown block").await?;
        anyhow::bail!("peer {peer:?} requested transactions for unknown block");
    }
    if too_old {
        return Ok(());
    }
    let Some(block) = block else {
        penalize_peer(
            peers,
            peer,
            100,
            "getblocktxn requested an unavailable block",
        )
        .await?;
        anyhow::bail!("peer {peer:?} requested transactions for unavailable block");
    };
    let response = CompactBlockResponse::from_block(&block, &request);
    let count = response.transactions.len();
    peers
        .try_send(
            peer,
            Arc::new(Packet::BlockTxn(response)),
            OutboundPriority::Normal,
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to serve blocktxn: {error}"))?;
    update_diagnostics(diagnostics, |state| {
        state.served_block_transactions =
            state.served_block_transactions.saturating_add(count as u64);
    })
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn accept_peer_block(
    peer: PeerId,
    block: Block,
    node: &NodeReadHandle,
    writer: &CanonicalStateWriter,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
) -> Result<()> {
    let hash = block.hash();
    let (mut record, has_body) = node.with_stable_read(|store, _headers| {
        let snapshot = store.snapshot()?;
        let record = NodeReadHandle::native_sync_header_record_from_snapshot(&snapshot, &hash)?;
        let has_body = NodeReadHandle::native_sync_has_block_from_snapshot(&snapshot, &hash)?;
        Ok((record, has_body))
    })?;
    if record.as_ref().is_some_and(|record| record.status.failed) {
        scheduler.reject_block(Some(peer), hash, false, StdInstant::now());
        penalize_peer(peers, peer, 100, "known invalid block branch").await?;
        anyhow::bail!("peer {:?} sent known invalid block {}", peer, hash.to_hex());
    }
    if has_body {
        scheduler.complete_block(hash);
        return Ok(());
    }
    if record.is_none() {
        let parent_known = {
            let config = node.config();
            if block.header == config.network.params().genesis_header() {
                true
            } else {
                node.native_sync_header_record(&block.header.prev_block)?
                    .is_some()
            }
        };
        if !parent_known {
            // Native sync is headers-first. A body without known header context is
            // neither requested nor eligible for retention. Ask for headers,
            // apply a small protocol penalty, and drop the body. Once its own
            // header is canonical, a validated body can be durably retained even
            // if network delivery has not supplied its parent body yet.
            request_headers_from_peer(peer, node, peers, scheduler).await?;
            penalize_peer(peers, peer, 10, "block arrived before header context").await?;
            anyhow::bail!(
                "peer {:?} sent block {} before its header context was known",
                peer,
                hash.to_hex()
            );
        }

        let header = block.header.clone();
        let imported = writer
            .execute(
                None,
                "import delivered native-sync block header",
                move |node| node.native_sync_import_headers(vec![header]),
            )
            .await;
        record = match imported {
            Ok(imported) => imported.into_iter().next(),
            Err(error) if canonical_writer_contention(&error) => {
                // Height is not authoritative until the header import
                // succeeds, so leave the existing bounded body reservation
                // in flight for scheduler timeout/reassignment. The body can
                // be requested again without scoring the delivering peer.
                tracing::debug!(
                    ?peer,
                    block = %hash.to_hex(),
                    %error,
                    "deferred delivered block header after local canonical contention"
                );
                return Err(
                    error.context("local canonical contention deferred delivered block header")
                );
            }
            Err(error) => {
                if let Some(penalty) = peer_block_header_import_penalty(&error) {
                    penalize_peer(peers, peer, penalty, "peer block header rejected").await?;
                    return Err(error.context("peer block header rejected"));
                }
                return Err(
                    error.context("local dependency failed while importing delivered block header")
                );
            }
        };
        scheduler.set_best_header(node.native_sync_best_header_tip()?);
        node.native_sync_queue_missing_canonical_bodies(scheduler)?;
    }

    let record = record.ok_or_else(|| anyhow::anyhow!("imported block header has no record"))?;
    if record.status.failed {
        scheduler.reject_block(Some(peer), hash, false, StdInstant::now());
        penalize_peer(peers, peer, 100, "invalid-branch descendant").await?;
        anyhow::bail!(
            "peer {:?} sent descendant {} of a failed branch",
            peer,
            hash.to_hex()
        );
    }
    if !scheduler.is_tracked_block(&hash) {
        scheduler
            .announce_block(peer, hash, record.height)
            .map_err(|error| anyhow::anyhow!("failed to queue delivered block: {error}"))?;
    }
    let request = scheduler
        .receive_block(peer, hash, StdInstant::now())
        .map_err(|error| anyhow::anyhow!("peer block was not eligible: {error}"))?;
    if let Err(error) = validation.try_submit(ValidationRequest {
        peer,
        height: record.height,
        attempt: request.attempt,
        block,
    }) {
        scheduler
            .requeue_tracked_block(hash, record.height)
            .context("failed to preserve body work after validation queue rejection")?;
        return Err(anyhow::anyhow!("validation queue rejected block: {error}"));
    }
    Ok(())
}

async fn request_headers_from_peer(
    peer: PeerId,
    node: &NodeReadHandle,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
) -> Result<()> {
    let locator = node.native_sync_block_locator(MAX_LOCATOR_ENTRIES)?;
    let action = scheduler
        .request_headers_from(peer, StdInstant::now(), &locator, BlockHash::ZERO)
        .map_err(|error| anyhow::anyhow!("failed to schedule headers request: {error}"))?;
    if let Some(SyncAction::RequestHeaders {
        peer,
        locator,
        stop,
    }) = action
    {
        peers
            .try_send(
                peer,
                Arc::new(Packet::GetHeaders(LocatorPacket { locator, stop })),
                OutboundPriority::Control,
            )
            .await
            .map_err(|error| anyhow::anyhow!("failed to request headers: {error}"))?;
    }
    Ok(())
}

fn validation_queue_full(error: &SyncError) -> bool {
    matches!(
        error,
        SyncError::LimitExceeded {
            context: "validation input queue",
            ..
        }
    )
}

/// Try every child released by one newly durable parent exactly once.
///
/// A full validation queue restores the exact `(block, height)` into capacity
/// freed by `take_children` and asks the bounded ready-parent queue to retry on
/// a later supervisor opportunity. A closed pipeline is not retryable during
/// normal runtime, but all not-submitted children are still restored first.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OrphanReleaseOutcome {
    attempted: usize,
    retry_parent: bool,
}

fn release_parent_orphans(
    parent: BlockHash,
    maximum_children: usize,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
) -> Result<OrphanReleaseOutcome> {
    let mut terminal_error = None;
    let mut terminal_recovery_failure = None;
    let outcome = match orphans.take_children_bounded(parent, maximum_children) {
        Ok(outcome) => outcome,
        Err(error) if owned_orphan_invariant(&error) => {
            return Err(anyhow::Error::new(UnreconciledValidationBatch {
                handling_error: error.context("failed to release owned orphan children"),
                reconciliation_error: anyhow::anyhow!(
                    "owned orphan sidecar invariant prevents exact child recovery"
                ),
            }));
        }
        Err(error) => return Err(error),
    };
    let attempted = outcome.children.len();
    let mut retry_parent = outcome.children_remain;
    for orphan in outcome.children {
        let hash = orphan.block.hash();
        scheduler.begin_local_validation(hash);
        let retry = orphan.clone();
        if let Err(error) = validation.try_submit(ValidationRequest {
            peer: LOCAL_ORPHAN_PEER,
            height: orphan.height,
            attempt: 0,
            block: orphan.block,
        }) {
            let queue_full = validation_queue_full(&error);
            let handling_error =
                anyhow::Error::new(error).context("failed to submit released native-sync orphan");
            if let Err(reconciliation_error) = restore_released_orphan(retry, scheduler, orphans) {
                terminal_recovery_failure.get_or_insert((handling_error, reconciliation_error));
            } else if queue_full {
                retry_parent = true;
            } else {
                terminal_error.get_or_insert(handling_error);
            }
        }
    }
    match (terminal_recovery_failure, terminal_error) {
        (Some((handling_error, reconciliation_error)), _) => {
            Err(anyhow::Error::new(UnreconciledValidationBatch {
                handling_error,
                reconciliation_error,
            }))
        }
        (None, Some(error)) => Err(error),
        (None, None) => Ok(OrphanReleaseOutcome {
            attempted,
            retry_parent,
        }),
    }
}

fn restore_released_orphan(
    orphan: OwnedOrphan,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
) -> Result<()> {
    let outcome = orphans
        .insert_with_evictions(orphan)
        .context("failed to restore released orphan ownership")?;
    if !outcome.evicted.is_empty() {
        anyhow::bail!(
            "restoring released orphan unexpectedly evicted {} owned blocks",
            outcome.evicted.len()
        );
    }
    scheduler.complete_orphan_validation();
    Ok(())
}

fn enqueue_ready_orphan_parent(
    parent: BlockHash,
    orphans: &OwnedOrphanPool,
    discards: &DeferredOrphanDiscards,
    ready: &mut ReadyOrphanParents,
) -> Result<()> {
    if !orphans.has_children(parent) || discards.contains(parent) {
        ready.remove(parent);
        return Ok(());
    }
    ready.preflight_enqueue(parent)?;
    // Exact eager cleanup keeps this path O(log N). The full bounded prune is
    // a capacity backstop for future removal paths, not an O(N) tax on every
    // durable parent in a maximum-size result batch.
    if ready.len() >= ready.maximum {
        ready.retain_live(orphans, discards);
    }
    ready.enqueue(parent).map_err(|reconciliation_error| {
        anyhow::Error::new(UnreconciledValidationBatch {
            handling_error: anyhow::anyhow!(
                "released children of durable parent {} require a validation retry",
                parent.to_hex()
            ),
            reconciliation_error,
        })
    })
}

fn enqueue_deferred_orphan_discard(
    parent: BlockHash,
    orphans: &OwnedOrphanPool,
    ready: &mut ReadyOrphanParents,
    discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    discards.preflight_enqueue(parent, orphans)?;
    ready.remove(parent);
    discards.enqueue(parent, orphans)
}

fn drain_orphan_work(
    maximum_units: usize,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
    ready: &mut ReadyOrphanParents,
    discards: &mut DeferredOrphanDiscards,
    schedule: &mut OrphanWorkSchedule,
) -> Result<usize> {
    if maximum_units == 0 {
        return Ok(0);
    }
    ensure_orphan_work_queues_exact(ready, discards)?;

    let mut spent = 0usize;
    while spent < maximum_units {
        let lane = match schedule.next {
            OrphanWorkLane::Release if ready.len() != 0 => Some(OrphanWorkLane::Release),
            OrphanWorkLane::Discard if discards.len() != 0 => Some(OrphanWorkLane::Discard),
            OrphanWorkLane::Release if discards.len() != 0 => Some(OrphanWorkLane::Discard),
            OrphanWorkLane::Discard if ready.len() != 0 => Some(OrphanWorkLane::Release),
            _ => None,
        };
        let Some(lane) = lane else {
            break;
        };
        schedule.next = lane.alternate();
        spent = spent.saturating_add(1);

        match lane {
            OrphanWorkLane::Release => {
                let parent = ready
                    .pop_front()
                    .expect("ready orphan-parent queue remains non-empty");
                if discards.contains(parent) {
                    return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                        "discard-fenced parent {} entered ready release",
                        parent.to_hex()
                    ))));
                }
                if !orphans.has_children(parent) {
                    continue;
                }
                let outcome = release_parent_orphans(parent, 1, validation, scheduler, orphans)?;
                if outcome.attempted != 1 {
                    return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                        "live ready parent {} released {} children for one work unit",
                        parent.to_hex(),
                        outcome.attempted
                    ))));
                }
                if outcome.retry_parent {
                    enqueue_ready_orphan_parent(parent, orphans, discards, ready)?;
                }
            }
            OrphanWorkLane::Discard => {
                let parent = discards
                    .pop_front()
                    .expect("deferred orphan-discard queue remains non-empty");
                ready.remove(parent);
                if !orphans.has_children(parent) {
                    continue;
                }
                let outcome = orphans
                    .take_children_bounded(parent, 1)
                    .context("failed to discard one bounded orphan child")?;
                if outcome.children.len() != 1 {
                    return Err(anyhow::Error::new(OwnedOrphanInvariant(format!(
                        "live discard parent {} removed {} children for one work unit",
                        parent.to_hex(),
                        outcome.children.len()
                    ))));
                }
                if outcome.children_remain {
                    enqueue_deferred_orphan_discard(parent, orphans, ready, discards)?;
                }
                let child = outcome
                    .children
                    .into_iter()
                    .next()
                    .expect("one bounded discarded orphan child remains exact");
                let child_hash = child.block.hash();
                if scheduler.is_tracked_block(&child_hash) {
                    scheduler.reject_block(None, child_hash, false, StdInstant::now());
                }
                enqueue_deferred_orphan_discard(child_hash, orphans, ready, discards)?;
            }
        }
    }
    ensure_orphan_work_queues_exact(ready, discards)?;
    Ok(spent)
}

struct ValidationResultContext<'a> {
    node: &'a NodeReadHandle,
    writer: &'a CanonicalStateWriter,
    peers: &'a LivePeerManager,
    diagnostics: &'a Arc<RwLock<NativeSyncDiagnostics>>,
}

#[derive(Debug)]
struct UnreconciledValidationBatch {
    handling_error: anyhow::Error,
    reconciliation_error: anyhow::Error,
}

impl fmt::Display for UnreconciledValidationBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "validated block batch lost scheduler ownership: {}; reconciliation failed: {}",
            self.handling_error, self.reconciliation_error
        )
    }
}

impl Error for UnreconciledValidationBatch {}

fn unreconciled_validation_batch(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<UnreconciledValidationBatch>())
}

fn validation_pipeline_closed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<SyncError>(),
            Some(SyncError::ValidationPipelineClosed)
        )
    })
}

fn terminal_validation_error(error: &anyhow::Error) -> bool {
    unreconciled_validation_batch(error)
        || validation_pipeline_closed(error)
        || owned_orphan_invariant(error)
}

async fn handle_validation_results(
    results: Vec<OrderedValidationResult>,
    context: &ValidationResultContext<'_>,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
    ready_orphan_parents: &mut ReadyOrphanParents,
    deferred_orphan_discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    let mut validated = Vec::new();
    let mut first_warning = None;
    let mut terminal_failure = None;

    for result in results {
        let hash = match &result {
            Ok(validated) => validated.block.hash(),
            Err(failure) => failure.block.hash(),
        };
        // Invalid-branch persistence rejects every affected scheduler hash
        // before bounded body cleanup begins. Results already queued by a
        // worker are therefore stale ownership notifications, not new work:
        // dropping both Ok and Err variants prevents them from recreating or
        // retrying a branch behind the deferred-discard cursor.
        if !scheduler.is_tracked_block(&hash) {
            continue;
        }
        match result {
            Ok(block) => validated.push(block),
            Err(failure) => {
                if !validated.is_empty() {
                    if let Err(error) = handle_validated_blocks(
                        std::mem::take(&mut validated),
                        context,
                        scheduler,
                        orphans,
                        ready_orphan_parents,
                        deferred_orphan_discards,
                    )
                    .await
                    {
                        if terminal_validation_error(&error) {
                            terminal_failure.get_or_insert(error);
                        } else {
                            first_warning.get_or_insert(error);
                        }
                    }
                }
                if let Err(error) = handle_validation_failure(
                    failure,
                    context,
                    scheduler,
                    orphans,
                    ready_orphan_parents,
                    deferred_orphan_discards,
                )
                .await
                {
                    if terminal_validation_error(&error) {
                        terminal_failure.get_or_insert(error);
                    } else {
                        first_warning.get_or_insert(error);
                    }
                }
            }
        }
    }

    if !validated.is_empty() {
        if let Err(error) = handle_validated_blocks(
            validated,
            context,
            scheduler,
            orphans,
            ready_orphan_parents,
            deferred_orphan_discards,
        )
        .await
        {
            if terminal_validation_error(&error) {
                terminal_failure.get_or_insert(error);
            } else {
                first_warning.get_or_insert(error);
            }
        }
    }

    match (terminal_failure, first_warning) {
        (Some(error), _) | (None, Some(error)) => Err(error),
        (None, None) => Ok(()),
    }
}

async fn handle_validated_blocks(
    validated: Vec<ValidatedBlock>,
    context: &ValidationResultContext<'_>,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
    ready_orphan_parents: &mut ReadyOrphanParents,
    deferred_orphan_discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    let reservations = validated
        .iter()
        .map(|validated| (validated.block.hash(), validated.height))
        .collect::<Vec<_>>();
    let result = handle_validated_blocks_inner(
        validated,
        context,
        scheduler,
        orphans,
        ready_orphan_parents,
        deferred_orphan_discards,
    )
    .await;
    let Err(handling_error) = result else {
        return Ok(());
    };

    if let Err(reconciliation_error) =
        reconcile_validated_reservations(&reservations, scheduler, orphans)
    {
        return Err(anyhow::Error::new(UnreconciledValidationBatch {
            handling_error,
            reconciliation_error,
        }));
    }
    Err(handling_error.context("validated block reservations were reconciled after batch failure"))
}

fn reconcile_validated_reservations(
    reservations: &[(BlockHash, Height)],
    scheduler: &mut SyncScheduler,
    orphans: &OwnedOrphanPool,
) -> Result<()> {
    for (hash, height) in reservations {
        if !scheduler.is_tracked_block(hash) || orphans.contains(hash) {
            continue;
        }
        // Do not perform another stable storage read here: the batch commonly
        // failed because a canonical writer generation was active, so that
        // read could immediately fail for the same reason. If the body became
        // durable before the error, the duplicate response's existing-body
        // fast path completes this reservation without storing it again.
        scheduler
            .requeue_tracked_block(*hash, *height)
            .context("failed to return validated body reservation to the pending queue")?;
    }
    Ok(())
}

fn retain_validated_orphan(
    block: Block,
    height: Height,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
    ready_orphan_parents: &mut ReadyOrphanParents,
    deferred_orphan_discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    let hash = block.hash();
    let outcome = match orphans.insert_with_evictions(OwnedOrphan { block, height }) {
        Ok(outcome) => outcome,
        Err(error) => {
            let invariant = owned_orphan_invariant(&error);
            if let Err(reconciliation_error) = scheduler
                .requeue_tracked_block(hash, height)
                .context("failed to requeue unretained validated orphan")
            {
                return Err(anyhow::Error::new(UnreconciledValidationBatch {
                    handling_error: error.context("failed to retain validated orphan"),
                    reconciliation_error,
                }));
            }
            if invariant {
                return Err(anyhow::Error::new(UnreconciledValidationBatch {
                    handling_error: error.context("owned orphan sidecar invariant failed"),
                    reconciliation_error: anyhow::anyhow!(
                        "retained orphan ownership cannot be audited after a sidecar invariant failure"
                    ),
                }));
            }
            return Err(error.context("failed to retain validated orphan"));
        }
    };
    let mut eviction_reconciliation_failure = None;
    for evicted in outcome.evicted {
        let evicted_hash = evicted.block.hash();
        let evicted_parent = evicted.block.header.prev_block;
        // Invalid-branch descendants are rejected before their bodies are
        // removed by the bounded discard cursor. If normal capacity eviction
        // reaches one first, its absent scheduler reservation is intentional
        // and must not be resurrected or treated as lost valid ownership.
        if scheduler.is_tracked_block(&evicted_hash) {
            if let Err(error) = scheduler
                .requeue_tracked_block(evicted_hash, evicted.height)
                .context("failed to requeue evicted owned orphan body")
            {
                eviction_reconciliation_failure.get_or_insert(error);
            }
        }
        if !orphans.has_children(evicted_parent) {
            ready_orphan_parents.remove(evicted_parent);
            deferred_orphan_discards.remove(evicted_parent);
        }
    }
    if let Some(reconciliation_error) = eviction_reconciliation_failure {
        return Err(anyhow::Error::new(UnreconciledValidationBatch {
            handling_error: anyhow::anyhow!(
                "bounded orphan insertion evicted scheduler-owned body work"
            ),
            reconciliation_error,
        }));
    }
    scheduler.complete_orphan_validation();
    Ok(())
}

async fn handle_validated_blocks_inner(
    validated: Vec<ValidatedBlock>,
    context: &ValidationResultContext<'_>,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
    ready_orphan_parents: &mut ReadyOrphanParents,
    deferred_orphan_discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    let node = context.node;
    let mut eligible = Vec::with_capacity(validated.len());
    for validated in validated {
        let hash = validated.block.hash();
        if !scheduler.is_tracked_block(&hash) {
            continue;
        }
        if deferred_orphan_discards.contains(hash)
            || deferred_orphan_discards.contains(validated.block.header.prev_block)
        {
            scheduler.reject_block(None, hash, false, StdInstant::now());
            continue;
        }
        let parent_available = validated.block.header == node.network().params().genesis_header()
            || node.native_sync_has_block(&validated.block.header.prev_block)?;
        let canonical = node.native_sync_is_canonical_header(hash, validated.height)?;
        if parent_available || canonical {
            eligible.push((validated, canonical));
            continue;
        }

        retain_validated_orphan(
            validated.block,
            validated.height,
            scheduler,
            orphans,
            ready_orphan_parents,
            deferred_orphan_discards,
        )?;
    }

    if eligible.is_empty() {
        return Ok(());
    }

    // Canonical header ancestry is independently validated. Persist all
    // available worker-validated bodies in one atomic transaction, then move
    // scheduler state as a group. A crash can expose either none or all of the
    // records, never a partially acknowledged validation batch.
    let expected = eligible
        .iter()
        .map(|(validated, _)| validated.block.hash())
        .collect::<Vec<_>>();
    let mut stored = None;
    for attempt in 0..MAX_CANONICAL_STALE_RETRIES {
        if attempt != 0 {
            for (validated, canonical) in &mut eligible {
                *canonical =
                    node.native_sync_is_canonical_header(validated.block.hash(), validated.height)?;
            }
        }
        let epoch = node.canonical_epoch();
        let batch = eligible.clone();
        match context
            .writer
            .execute_at_chain(
                epoch.chain(),
                "store validated native-sync body batch",
                move |node| node.native_sync_store_validated_blocks(batch),
            )
            .await
        {
            Ok(records) => {
                stored = Some(records);
                break;
            }
            Err(error)
                if canonical_writer_contention(&error)
                    && attempt + 1 < MAX_CANONICAL_STALE_RETRIES =>
            {
                tokio::time::sleep(active_state_contention_retry_interval(attempt + 1)).await;
            }
            Err(error) => return Err(error),
        }
    }
    let stored = stored.ok_or_else(|| {
        anyhow::anyhow!("validated native-sync body batch exhausted stale-epoch retries")
    })?;
    if stored.len() != expected.len()
        || stored
            .iter()
            .zip(&expected)
            .any(|(record, hash)| record.hash != *hash)
    {
        anyhow::bail!("durable validated-body batch result is not input-order exact");
    }
    for hash in &expected {
        scheduler.complete_block(*hash);
    }
    let stored_count = u64::try_from(stored.len()).unwrap_or(u64::MAX);
    update_diagnostics(context.diagnostics, |state| {
        state.stored_bodies = state.stored_bodies.saturating_add(stored_count);
    })
    .await;
    // Make retained children ready before the stable tip scan; the event-level
    // orphan drain below shares one bounded budget across the entire result
    // batch. Queue saturation preserves deduplicated future supervisor work.
    for record in &stored {
        enqueue_ready_orphan_parent(
            record.hash,
            orphans,
            deferred_orphan_discards,
            ready_orphan_parents,
        )?;
    }
    let stored_tip = node.native_sync_contiguous_body_tip(scheduler.stored_tip())?;
    if scheduler.stored_tip() != stored_tip.as_ref() {
        scheduler.set_stored_tip(stored_tip);
    }
    node.native_sync_queue_missing_canonical_bodies(scheduler)?;
    Ok(())
}

async fn handle_validation_failure(
    failure: ValidationFailure,
    context: &ValidationResultContext<'_>,
    scheduler: &mut SyncScheduler,
    orphans: &mut OwnedOrphanPool,
    ready_orphan_parents: &mut ReadyOrphanParents,
    deferred_orphan_discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    let hash = failure.block.hash();
    if !scheduler.is_tracked_block(&hash) {
        return Ok(());
    }
    match failure.kind {
        ValidationFailureKind::WorkerFailure => {
            scheduler.retry_validation_failure(
                hash,
                failure.height,
                failure.attempt,
                None,
                StdInstant::now(),
            );
            anyhow::bail!(
                "stateless block validation worker failed at {}: {}",
                failure.height,
                failure.reason
            );
        }
        ValidationFailureKind::InvalidResponse => {
            scheduler.retry_validation_failure(
                hash,
                failure.height,
                failure.attempt,
                (failure.peer != LOCAL_ORPHAN_PEER).then_some(failure.peer),
                StdInstant::now(),
            );
            if failure.peer != LOCAL_ORPHAN_PEER {
                penalize_peer(
                    context.peers,
                    failure.peer,
                    100,
                    "block body did not match its header",
                )
                .await?;
            }
            update_diagnostics(context.diagnostics, |state| {
                state.rejected_messages = state.rejected_messages.saturating_add(1);
            })
            .await;
            anyhow::bail!(
                "peer body response failed header commitments at {}: {}",
                failure.height,
                failure.reason
            );
        }
        ValidationFailureKind::InvalidBlock => {}
    }

    let failed_height = failure.height;
    let failed_block = failure.block;
    let stored = context
        .writer
        .execute(None, "store failed native-sync block", move |node| {
            node.native_sync_store_failed_block(failed_block, failed_height)
        })
        .await;
    let stored = match stored {
        Ok(stored) => stored,
        Err(error) => {
            scheduler.retry_validation_failure(
                hash,
                failure.height,
                failure.attempt,
                None,
                StdInstant::now(),
            );
            return Err(error.context("failed to persist invalid block branch"));
        }
    };
    for affected in &stored.affected {
        if scheduler.is_tracked_block(affected) {
            scheduler.reject_block(
                (*affected == hash).then_some(failure.peer),
                *affected,
                false,
                StdInstant::now(),
            );
        }
    }
    enqueue_affected_orphan_discards(
        &stored.affected,
        orphans,
        ready_orphan_parents,
        deferred_orphan_discards,
    )?;
    if failure.peer != LOCAL_ORPHAN_PEER {
        penalize_peer(
            context.peers,
            failure.peer,
            100,
            "stateless block validation failed",
        )
        .await?;
    }
    update_diagnostics(context.diagnostics, |state| {
        state.rejected_messages = state.rejected_messages.saturating_add(1);
        state.stored_failed_bodies = state.stored_failed_bodies.saturating_add(1);
    })
    .await;
    anyhow::bail!(
        "stateless block validation failed and block {} was durably marked failed at {}: {}",
        stored.record.hash.to_hex(),
        failure.height,
        failure.reason
    );
}

fn accumulate_active_state_preparation(
    total: &mut ActiveStatePreparationMetrics,
    attempt: ActiveStatePreparationMetrics,
) {
    total.blocks = total.blocks.saturating_add(attempt.blocks);
    total.wall_micros = total.wall_micros.saturating_add(attempt.wall_micros);
    total.aggregate_worker_micros = total
        .aggregate_worker_micros
        .saturating_add(attempt.aggregate_worker_micros);
    total.maximum_in_flight = total.maximum_in_flight.max(attempt.maximum_in_flight);
}

type ActiveStateValidator =
    Arc<dyn Fn(&Block, Height) -> std::result::Result<(), ValidationRejection> + Send + Sync>;

async fn prepare_native_active_state_plan_with_validator(
    plan: NativeActiveStatePlan,
    network: Network,
    workers: usize,
    queue_capacity: usize,
    validate: ActiveStateValidator,
) -> Result<PreparedActiveStatePlan> {
    let NativeActiveStatePlan {
        epoch,
        activation,
        maximum_connect,
        planning_micros,
    } = plan;
    let NodeReorg {
        disconnect,
        connect,
    } = activation;
    let block_count = connect.len();
    let started = StdInstant::now();
    if block_count == 0 {
        return Ok(PreparedActiveStatePlan {
            epoch,
            activation: NodeReorg {
                disconnect,
                connect,
            },
            prepared: PreparedNativeActivation::new(Vec::new())?,
            maximum_connect,
            planning_micros,
            preparation: ActiveStatePreparationMetrics::default(),
            workload: ActiveStateWorkload::default(),
        });
    }

    let in_flight = Arc::new(AtomicUsize::new(0));
    let maximum_in_flight = Arc::new(AtomicUsize::new(0));
    let work = Arc::new({
        let in_flight = Arc::clone(&in_flight);
        let maximum_in_flight = Arc::clone(&maximum_in_flight);
        let validate = Arc::clone(&validate);
        move |input: &NativeActiveStatePreparationInput| {
            let _permit =
                ActiveStateWorkerPermit::acquire(Arc::clone(&in_flight), &maximum_in_flight);
            let worker_started = StdInstant::now();
            validate(input.import.block(), input.import.height())?;
            Ok::<_, ValidationRejection>(NativeActiveStatePreparationOutput {
                proof: StatelessBodyValidation::for_block(
                    input.import.block(),
                    input.import.height(),
                    network,
                ),
                worker_micros: u64::try_from(worker_started.elapsed().as_micros())
                    .unwrap_or(u64::MAX),
                workload: ActiveStateWorkload::for_block(input.import.block()),
            })
        }
    });
    let (submitter, mut results) = spawn_ordered_work_pipeline(work, workers, queue_capacity)
        .map_err(|error| {
            anyhow::anyhow!("failed to start ordered active-state preparation: {error}")
        })?;
    let cancellation = submitter.clone();
    let producer = tokio::spawn(async move {
        for (ordinal, import) in connect.into_iter().enumerate() {
            if let Err(error) = submitter
                .submit(NativeActiveStatePreparationInput { ordinal, import })
                .await
            {
                submitter.cancel();
                return Err(anyhow::anyhow!(
                    "ordered active-state preparation rejected block {ordinal}: {error}"
                ));
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    let mut prepared_connect = Vec::with_capacity(block_count);
    let mut proofs = Vec::with_capacity(block_count);
    let mut aggregate_worker_micros = 0u64;
    let mut workload = ActiveStateWorkload::default();
    for ordinal in 0..block_count {
        let Some(result) = results.recv().await else {
            cancellation.cancel();
            let producer_result = producer.await;
            if let Ok(Err(error)) = producer_result {
                return Err(error);
            }
            return Err(anyhow::anyhow!(
                "ordered active-state preparation closed after {ordinal} of {block_count} blocks"
            ));
        };
        match result {
            Ok(success) => {
                if success.sequence != ordinal as u64 || success.input.ordinal != ordinal {
                    cancellation.cancel();
                    let _ = producer.await;
                    anyhow::bail!(
                        "ordered active-state preparation emitted sequence {} / input {} at ordinal {ordinal}",
                        success.sequence,
                        success.input.ordinal
                    );
                }
                let input = match Arc::try_unwrap(success.input) {
                    Ok(input) => input,
                    Err(_) => {
                        cancellation.cancel();
                        let _ = producer.await;
                        anyhow::bail!(
                            "ordered active-state preparation retained input {ordinal} after completion"
                        );
                    }
                };
                aggregate_worker_micros =
                    aggregate_worker_micros.saturating_add(success.output.worker_micros);
                workload = workload.saturating_add(success.output.workload);
                prepared_connect.push(input.import);
                proofs.push(success.output.proof);
            }
            Err(failure) => {
                cancellation.cancel();
                let _ = producer.await;
                let hash = failure.input.import.block().hash();
                let height = failure.input.import.height();
                match failure.error {
                    OrderedWorkError::Work(rejection) => anyhow::bail!(
                        "local stored-body integrity failure: block {} at height {} failed ordered stateless replay validation ({:?}): {}",
                        hash.to_hex(),
                        height,
                        rejection.kind,
                        rejection.reason
                    ),
                    OrderedWorkError::Panicked(message) => anyhow::bail!(
                        "ordered stateless replay worker panicked for block {} at height {}: {message}",
                        hash.to_hex(),
                        height
                    ),
                    OrderedWorkError::Cancelled => anyhow::bail!(
                        "ordered stateless replay worker was cancelled for block {} at height {}",
                        hash.to_hex(),
                        height
                    ),
                }
            }
        }
    }
    producer
        .await
        .context("ordered active-state producer task failed")??;
    drop(cancellation);

    Ok(PreparedActiveStatePlan {
        epoch,
        activation: NodeReorg {
            disconnect,
            connect: prepared_connect,
        },
        prepared: PreparedNativeActivation::new(proofs)?,
        maximum_connect,
        planning_micros,
        preparation: ActiveStatePreparationMetrics {
            blocks: block_count,
            wall_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            aggregate_worker_micros,
            maximum_in_flight: maximum_in_flight.load(Ordering::Acquire),
            stale_retries: 0,
        },
        workload,
    })
}

async fn execute_native_active_state_slice(
    node: NodeReadHandle,
    writer: CanonicalStateWriter,
    maximum_connect: usize,
    stored_tip_hint: Option<ChainTip>,
    workers: usize,
    queue_capacity: usize,
) -> Result<NativeActiveStateSliceResult> {
    let network = node.network();
    let validator = HnsBodyValidator::new(network);
    execute_native_active_state_slice_with_validator(
        node,
        writer,
        maximum_connect,
        stored_tip_hint,
        workers,
        queue_capacity,
        Arc::new(move |block: &Block, height: Height| validator.validate(block, height)),
    )
    .await
}

async fn execute_native_active_state_slice_with_validator(
    node: NodeReadHandle,
    writer: CanonicalStateWriter,
    maximum_connect: usize,
    stored_tip_hint: Option<ChainTip>,
    workers: usize,
    queue_capacity: usize,
    validate: ActiveStateValidator,
) -> Result<NativeActiveStateSliceResult> {
    let slice_started = StdInstant::now();
    let mut attempt_limit = maximum_connect;
    let mut stale_retries = 0usize;
    let mut preparation = ActiveStatePreparationMetrics::default();
    loop {
        let plan = match node
            .native_sync_plan_stored_state_with_hint(attempt_limit, stored_tip_hint.as_ref())
        {
            Ok(plan) => plan,
            Err(error)
                if canonical_writer_contention(&error)
                    && stale_retries + 1 < MAX_CANONICAL_STALE_RETRIES =>
            {
                stale_retries = stale_retries.saturating_add(1);
                tokio::time::sleep(active_state_contention_retry_interval(stale_retries)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(plan) = plan else {
            preparation.stale_retries = stale_retries;
            return Ok(NativeActiveStateSliceResult {
                outcome: ActiveStateConnectOutcome::default(),
                preparation,
                wall_millis: u64::try_from(slice_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            });
        };
        let prepared = prepare_native_active_state_plan_with_validator(
            plan,
            node.network(),
            workers,
            queue_capacity,
            Arc::clone(&validate),
        )
        .await
        .context(
            "local stored-body preparation failed; canonical state was not mutated and no peer is attributable",
        )?;
        let attempt_preparation = prepared.preparation;
        let expected = prepared.epoch.clone();
        let result = writer
            .execute_at_chain(
                expected,
                "commit prepared native-sync active-state slice",
                move |service| service.native_sync_apply_prepared_active_state(prepared),
            )
            .await;
        accumulate_active_state_preparation(&mut preparation, attempt_preparation);
        match result {
            Ok(std::ops::ControlFlow::Continue(outcome)) => {
                preparation.stale_retries = stale_retries;
                return Ok(NativeActiveStateSliceResult {
                    outcome,
                    preparation,
                    wall_millis: u64::try_from(slice_started.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                });
            }
            Ok(std::ops::ControlFlow::Break(DirectStagedEffectLimit {
                retry_connect,
                limit,
                actual,
            })) => {
                if retry_connect == 0 || retry_connect >= attempt_limit {
                    anyhow::bail!(
                        "direct active-state retry limit {retry_connect} does not reduce attempted limit {attempt_limit}"
                    );
                }
                tracing::warn!(
                    retry_connect,
                    limit,
                    actual,
                    "prepared active-state slice exceeded its atomic effect budget; replanning a smaller rollback-safe slice"
                );
                attempt_limit = retry_connect;
            }
            Err(error)
                if canonical_writer_contention(&error)
                    && stale_retries + 1 < MAX_CANONICAL_STALE_RETRIES =>
            {
                stale_retries = stale_retries.saturating_add(1);
                tokio::time::sleep(active_state_contention_retry_interval(stale_retries)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

struct ActiveStateConnectionContext<'a> {
    node: &'a NodeReadHandle,
    writer: &'a CanonicalStateWriter,
    peers: &'a LivePeerManager,
    diagnostics: &'a Arc<RwLock<NativeSyncDiagnostics>>,
    diagnostic_rpc: &'a Arc<RwLock<CachedDiagnosticRpc>>,
}

#[cfg(test)]
pub(super) async fn connect_stored_active_state(
    node: &NodeReadHandle,
    writer: &CanonicalStateWriter,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
    maximum_connect: usize,
) -> Result<()> {
    let diagnostic_rpc = initialize_cached_diagnostic_rpc(node, diagnostics).await?;
    let context = ActiveStateConnectionContext {
        node,
        writer,
        peers,
        diagnostics,
        diagnostic_rpc: &diagnostic_rpc,
    };
    let affected = connect_stored_active_state_with_diagnostic_rpc(
        &context,
        scheduler,
        orphans,
        maximum_connect,
    )
    .await?;
    for root in affected {
        discard_orphan_descendants(root, orphans)?;
    }
    Ok(())
}

async fn connect_stored_active_state_with_diagnostic_rpc<P: ActiveStateOrphanPool>(
    context: &ActiveStateConnectionContext<'_>,
    scheduler: &mut SyncScheduler,
    orphans: &mut P,
    maximum_connect: usize,
) -> Result<Vec<BlockHash>> {
    let config = context.node.config();
    let completed = execute_native_active_state_slice(
        context.node.clone(),
        context.writer.clone(),
        maximum_connect,
        scheduler.stored_tip().cloned(),
        config.native_sync.validation_workers,
        config.native_sync.validation_queue,
    )
    .await?;
    complete_stored_active_state_slice(&completed, context, scheduler, orphans).await?;
    Ok(completed
        .outcome
        .contextual_failure
        .as_ref()
        .map_or_else(Vec::new, |failed| failed.affected.clone()))
}

async fn complete_stored_active_state_slice<P: ActiveStateOrphanPool>(
    completed: &NativeActiveStateSliceResult,
    context: &ActiveStateConnectionContext<'_>,
    scheduler: &mut SyncScheduler,
    orphans: &mut P,
) -> Result<()> {
    let outcome = &completed.outcome;
    let preparation = &completed.preparation;
    let slice_millis = completed.wall_millis;
    let slice_blocks = outcome.connected.saturating_add(outcome.disconnected);
    // Publish the newly committed tip before a due compaction enters the
    // canonical writer for its long, stable-snapshot deletion pass. RPC keeps
    // serving immutable published state throughout that command.
    refresh_cached_diagnostic_rpc(context.node, context.diagnostics, context.diagnostic_rpc)
        .await?;
    let compaction = context
        .writer
        .execute(None, "compact pruned native-sync name tree", |node| {
            node.compact_pruned_name_tree_nodes_if_due()
        })
        .await?;
    if let Some(checkpoint) = compaction {
        tracing::info!(
            height = checkpoint.height,
            tip = %checkpoint.tip.to_hex(),
            nodes_before = checkpoint.summary.nodes_before,
            nodes_retained = checkpoint.summary.nodes_retained,
            nodes_deleted = checkpoint.summary.nodes_deleted,
            "compacted pruned durable name tree during native sync"
        );
        refresh_cached_diagnostic_rpc(context.node, context.diagnostics, context.diagnostic_rpc)
            .await?;
    }

    let best_header = context.node.native_sync_best_header_tip()?;
    let active_tip = context.node.native_sync_active_tip()?;
    context
        .node
        .native_sync_queue_missing_canonical_bodies(scheduler)?;
    scheduler.set_best_header(best_header);
    scheduler.set_active_tip(active_tip.clone());
    if let Some(failed) = &outcome.contextual_failure {
        for hash in &failed.affected {
            if scheduler.is_tracked_block(hash) {
                scheduler.reject_block(None, *hash, false, StdInstant::now());
            }
        }
    }
    context
        .peers
        .set_local_height(active_tip.as_ref().map_or(0, |tip| tip.height));

    // Publish diagnostic counters only after every fallible completion step.
    // This keeps the retained completion idempotent across contention retries.
    if slice_blocks != 0 || outcome.contextual_failure.is_some() || preparation.blocks != 0 {
        update_diagnostics(context.diagnostics, |state| {
            state.active_state_slices = state.active_state_slices.saturating_add(1);
            state.active_state_last_slice_blocks = slice_blocks;
            state.active_state_last_slice_millis = slice_millis;
            state.active_state_max_slice_millis =
                state.active_state_max_slice_millis.max(slice_millis);
            state.active_state_last_planning_micros = outcome.planning_micros;
            state.active_state_last_commit_micros = outcome.state_commit_micros;
            state.active_state_last_post_commit_micros = outcome.post_commit_micros;
            state.active_state_last_prepared_blocks = preparation.blocks;
            state.active_state_last_preparation_micros = preparation.wall_micros;
            state.active_state_last_worker_micros = preparation.aggregate_worker_micros;
            state.active_state_max_preparation_in_flight = state
                .active_state_max_preparation_in_flight
                .max(preparation.maximum_in_flight);
            state.active_state_stale_retries = state
                .active_state_stale_retries
                .saturating_add(preparation.stale_retries as u64);
            state.active_state_last_transactions = outcome.workload.transactions;
            state.active_state_last_non_coinbase_inputs = outcome.workload.non_coinbase_inputs;
            state.active_state_last_outputs = outcome.workload.outputs;
            state.active_state_last_name_actions = outcome.workload.name_actions;
        })
        .await;
    }

    if outcome.connected != 0 || outcome.disconnected != 0 || outcome.contextual_failure.is_some() {
        let sync_snapshot = scheduler.snapshot();
        let orphan_snapshot = orphans.active_state_snapshot();
        update_diagnostics(context.diagnostics, |state| {
            state.sync = sync_snapshot;
            state.orphans = orphan_snapshot;
            state.connected_blocks = state
                .connected_blocks
                .saturating_add(outcome.connected as u64);
            if outcome.disconnected != 0 {
                state.reorganizations = state.reorganizations.saturating_add(1);
            }
            if outcome.contextual_failure.is_some() {
                state.contextual_failed_bodies = state.contextual_failed_bodies.saturating_add(1);
                state.stored_failed_bodies = state.stored_failed_bodies.saturating_add(1);
                state.rejected_messages = state.rejected_messages.saturating_add(1);
            }
        })
        .await;
    }
    Ok(())
}

fn active_state_work_ready(scheduler: &SyncScheduler) -> bool {
    match (scheduler.stored_tip(), scheduler.active_tip()) {
        (Some(stored), Some(active)) => stored != active,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
fn discard_orphan_descendants<P: ActiveStateOrphanPool>(
    root: BlockHash,
    orphans: &mut P,
) -> Result<()> {
    let mut pending = vec![root];
    while let Some(parent) = pending.pop() {
        pending.extend(orphans.take_child_hashes(parent)?);
    }
    Ok(())
}

fn enqueue_affected_orphan_discards(
    affected: &[BlockHash],
    orphans: &OwnedOrphanPool,
    ready_orphan_parents: &mut ReadyOrphanParents,
    deferred_orphan_discards: &mut DeferredOrphanDiscards,
) -> Result<()> {
    for hash in affected {
        if orphans.has_children(*hash) {
            enqueue_deferred_orphan_discard(
                *hash,
                orphans,
                ready_orphan_parents,
                deferred_orphan_discards,
            )?;
        }
    }
    ensure_orphan_work_queues_exact(ready_orphan_parents, deferred_orphan_discards)
}

async fn penalize_peer(
    peers: &LivePeerManager,
    peer: PeerId,
    score: u32,
    reason: &str,
) -> Result<i32> {
    let total = peers.penalize(peer, score).await?;
    tracing::debug!(?peer, score, total, %reason, "penalized HNS peer");
    Ok(total)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SyncDispatch {
    Action(SyncAction),
    BlockBatch {
        peer: PeerId,
        requests: Vec<BlockDownloadRequest>,
    },
}

fn flush_block_dispatches(
    dispatches: &mut Vec<SyncDispatch>,
    batches: &mut Vec<(PeerId, Vec<BlockDownloadRequest>)>,
) {
    for (peer, requests) in batches.drain(..) {
        dispatches.extend(requests.chunks(MAX_GETDATA_ITEMS).map(|requests| {
            SyncDispatch::BlockBatch {
                peer,
                requests: requests.to_vec(),
            }
        }));
    }
}

/// HSD's `Peer#getBlock` sends one `GETDATA` inventory per peer for a selected
/// hash batch. Preserve non-block action boundaries while coalescing the
/// scheduler's per-hash reservations into the same bounded wire shape.
fn batch_sync_actions(actions: Vec<SyncAction>) -> Result<Vec<SyncDispatch>> {
    let mut dispatches = Vec::with_capacity(actions.len());
    let mut batches: Vec<(PeerId, Vec<BlockDownloadRequest>)> = Vec::new();

    for action in actions {
        match action {
            SyncAction::RequestBlock(request) => {
                let peer = request
                    .peer
                    .ok_or_else(|| anyhow::anyhow!("block request has no selected peer"))?;
                if let Some((_, requests)) = batches
                    .iter_mut()
                    .find(|(batch_peer, _)| *batch_peer == peer)
                {
                    requests.push(request);
                } else {
                    batches.push((peer, vec![request]));
                }
            }
            action => {
                flush_block_dispatches(&mut dispatches, &mut batches);
                dispatches.push(SyncDispatch::Action(action));
            }
        }
    }
    flush_block_dispatches(&mut dispatches, &mut batches);
    Ok(dispatches)
}

fn dispatch_failure_is_stale(error: &P2pError) -> bool {
    matches!(
        error,
        P2pError::PeerUnavailable(_) | P2pError::Disconnected(_)
    )
}

async fn apply_sync_dispatch(
    dispatch: SyncDispatch,
    peers: &LivePeerManager,
    compact_peers: &HashSet<PeerId>,
    checkpoints: &StoredSyncCheckpoint<hns_store::StoreHandle>,
    scheduler: &mut SyncScheduler,
    checkpoint_sequence: &mut u64,
) -> Result<()> {
    match dispatch {
        SyncDispatch::Action(SyncAction::RequestHeaders {
            peer,
            locator,
            stop,
        }) => {
            if !scheduler.contains_peer(peer) {
                return Ok(());
            }
            let result = peers
                .try_send(
                    peer,
                    Arc::new(Packet::GetHeaders(LocatorPacket { locator, stop })),
                    OutboundPriority::Control,
                )
                .await;
            if let Err(error) = result {
                scheduler.rollback_header_dispatch(peer);
                if dispatch_failure_is_stale(&error) {
                    scheduler.remove_peer(peer);
                }
                anyhow::bail!("failed to request headers: {error}");
            }
            Ok(())
        }
        SyncDispatch::BlockBatch { peer, requests } => {
            // An earlier action in this poll may have discovered that the
            // transport already dropped the peer. `remove_peer` atomically
            // requeued all of its reservations, so this stale batch is done.
            if !scheduler.contains_peer(peer) {
                return Ok(());
            }
            if requests.is_empty() {
                anyhow::bail!("block request batch is empty");
            }
            if requests.len() > MAX_GETDATA_ITEMS {
                anyhow::bail!(
                    "block request batch has {} items; maximum is {MAX_GETDATA_ITEMS}",
                    requests.len()
                );
            }
            if requests.iter().any(|request| request.peer != Some(peer)) {
                anyhow::bail!("block request batch contains a mismatched peer");
            }
            let inventory = requests
                .iter()
                .map(|request| Inventory {
                    kind: if compact_peers.contains(&peer) {
                        InventoryKind::CompactBlock
                    } else {
                        InventoryKind::Block
                    },
                    hash: request.hash.into_inner(),
                })
                .collect::<Vec<_>>();
            let result = peers
                .try_send(
                    peer,
                    Arc::new(Packet::GetData(inventory)),
                    OutboundPriority::Control,
                )
                .await;
            if let Err(error) = result {
                let rollback = scheduler.rollback_block_dispatch(peer, &requests);
                if dispatch_failure_is_stale(&error) {
                    scheduler.remove_peer(peer);
                }
                if let Err(rollback) = rollback {
                    anyhow::bail!(
                        "failed to request block batch ({error}) and roll back scheduler state: {rollback}"
                    );
                }
                anyhow::bail!(
                    "failed to request {}-block batch from {peer:?}: {error}",
                    requests.len()
                );
            }
            Ok(())
        }
        SyncDispatch::Action(SyncAction::Penalize {
            peer,
            score,
            reason,
        }) => {
            if !scheduler.contains_peer(peer) {
                return Ok(());
            }
            if let Err(error) = penalize_peer(peers, peer, score, &reason).await {
                if error
                    .downcast_ref::<P2pError>()
                    .is_some_and(dispatch_failure_is_stale)
                {
                    scheduler.remove_peer(peer);
                }
                return Err(error);
            }
            Ok(())
        }
        SyncDispatch::Action(SyncAction::Disconnect { peer, reason }) => {
            if !scheduler.contains_peer(peer) {
                return Ok(());
            }
            tracing::debug!(?peer, %reason, "disconnecting HNS peer");
            let result = peers.disconnect(peer).await;
            scheduler.remove_peer(peer);
            result.map_err(|error| anyhow::anyhow!("failed to disconnect peer: {error}"))
        }
        SyncDispatch::Action(SyncAction::PersistCheckpoint) => {
            *checkpoint_sequence = checkpoint_sequence.saturating_add(1);
            persist_checkpoint(checkpoints, scheduler, *checkpoint_sequence)
        }
        SyncDispatch::Action(SyncAction::RequestBlock(_)) => {
            anyhow::bail!("unbatched block request reached the dispatcher")
        }
    }
}

fn persist_checkpoint(
    checkpoints: &StoredSyncCheckpoint<hns_store::StoreHandle>,
    scheduler: &SyncScheduler,
    sequence: u64,
) -> Result<()> {
    let snapshot = scheduler.snapshot();
    checkpoints
        .save(&SyncCheckpoint {
            sequence,
            stage: snapshot.stage,
            best_header: snapshot.best_header,
            active_tip: snapshot.active_tip,
            stored_tip: snapshot.stored_tip,
            target_height: snapshot.target_height,
            updated_at: unix_time(),
        })
        .map_err(|error| anyhow::anyhow!("failed to persist sync checkpoint: {error}"))
}

fn spawn_due_connections(
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    addresses: &mut BoundedAddressBook,
    bans: &PeerBanBook,
    peers: &LivePeerManager,
    results: &mpsc::Sender<ConnectAttemptResult>,
    now: Instant,
    maximum_outbound: usize,
) -> usize {
    let timestamp = unix_time();
    let due = take_due_connection_targets(reconnects, bans, now, timestamp, maximum_outbound);

    for address in &due {
        addresses.note_attempt(*address, now, timestamp);
    }
    for address in &due {
        let address = *address;
        let Some(wire) = addresses.wire_address(address) else {
            continue;
        };
        let peers = peers.clone();
        let results = results.clone();
        tokio::spawn(async move {
            let result = peers
                .connect_net_address(&wire)
                .await
                .map_err(|error| error.to_string());
            let _ = results.send(ConnectAttemptResult { address, result }).await;
        });
    }
    due.len()
}

fn take_due_connection_targets(
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    bans: &PeerBanBook,
    now: Instant,
    timestamp: u64,
    maximum_outbound: usize,
) -> Vec<SocketAddr> {
    let occupied = reconnects
        .values()
        .filter(|state| state.connected || state.connecting)
        .count();
    let available = maximum_outbound.saturating_sub(occupied);
    if available == 0 {
        return Vec::new();
    }
    let mut eligible = reconnects
        .iter()
        .filter_map(|(address, state)| {
            if state.connected
                || state.connecting
                || state.next_attempt > now
                || bans.is_banned(address.ip(), timestamp)
            {
                return None;
            }
            Some((!state.persistent, state.next_attempt, *address))
        })
        .collect::<Vec<_>>();
    eligible.sort();
    let mut occupied_groups = reconnects
        .iter()
        .filter(|(_, state)| state.connected || state.connecting)
        .map(|(address, _)| peer_address_group(address.ip()))
        .collect::<HashSet<_>>();
    let mut due = Vec::with_capacity(available.min(eligible.len()));
    for (discovered, _, address) in eligible {
        let group = peer_address_group(address.ip());
        if discovered && !occupied_groups.insert(group) {
            continue;
        }
        occupied_groups.insert(group);
        due.push(address);
        if due.len() == available {
            break;
        }
    }

    for address in &due {
        reconnects
            .get_mut(address)
            .expect("due connection target remains tracked")
            .connecting = true;
    }
    due
}

fn fill_discovery_slots(
    addresses: &BoundedAddressBook,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    bans: &PeerBanBook,
    maximum_outbound: usize,
    now: Instant,
    timestamp: u64,
) -> usize {
    let active_targets = reconnects
        .keys()
        .filter(|address| !bans.is_banned(address.ip(), timestamp))
        .count();
    let available = maximum_outbound.saturating_sub(active_targets);
    let candidates = addresses.connection_candidates(reconnects, bans, now, timestamp, available);
    let added = candidates.len();
    for address in candidates {
        let mut state = ReconnectState::new(now, false);
        state.failures = addresses.entries[&address].failures;
        reconnects.insert(address, state);
    }
    added
}

fn note_reconnect_failure(
    address: SocketAddr,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    now: Instant,
) {
    let retire = reconnects.get_mut(&address).is_some_and(|state| {
        state.failed(now);
        !state.persistent && state.failures >= MAX_DISCOVERY_CONNECT_FAILURES
    });
    if retire {
        reconnects.remove(&address);
    }
}

async fn handle_connect_attempt_result(
    result: ConnectAttemptResult,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) {
    let Some(persistent) = reconnects
        .get(&result.address)
        .map(|state| state.persistent)
    else {
        return;
    };
    match result.result {
        Ok(peer) => {
            tracing::debug!(?peer, address = %result.address, "outbound HNS peer connected");
        }
        Err(error) => {
            note_reconnect_failure(result.address, reconnects, Instant::now());
            if persistent {
                record_warning(format!("outbound peer {} failed: {error}", result.address));
            } else {
                update_diagnostics(diagnostics, |state| {
                    state.discovery_connection_failures =
                        state.discovery_connection_failures.saturating_add(1);
                })
                .await;
                tracing::debug!(address = %result.address, %error, "discovered HNS peer failed");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn refresh_diagnostics(
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
    peers: &LivePeerManager,
    scheduler: &SyncScheduler,
    orphans: &OwnedOrphanPool,
    reconnects: &HashMap<SocketAddr, ReconnectState>,
    addresses: &BoundedAddressBook,
    bans: &PeerBanBook,
    compact_peers: &HashSet<PeerId>,
    pending_compact_blocks: &HashMap<BlockHash, PendingCompactBlock>,
    checkpoint_sequence: u64,
) {
    let traffic = peers.traffic_totals().await;
    let (snapshots, experimental_registry) = peers.snapshots_with_denuo_summary().await;
    let mut state = diagnostics.write().await;
    state.bytes_sent = traffic.bytes_sent;
    state.bytes_received = traffic.bytes_received;
    state.hip76 = rpc_hip76_info(&snapshots);
    state.peers = snapshots;
    state.experimental_registry = rpc_experimental_registry_info(&experimental_registry);
    state.sync = scheduler.snapshot();
    state.orphans = orphans.snapshot();
    state.checkpoint_sequence = checkpoint_sequence;
    state.known_addresses = addresses.len();
    state.address_book_sequence = addresses.durable_sequence;
    state.address_book_dirty = addresses.dirty;
    state.banned_addresses = bans.len();
    state.ban_list_sequence = bans.durable_sequence();
    state.ban_list_dirty = bans.is_dirty();
    state.outbound_connected = reconnects.values().filter(|item| item.connected).count();
    state.outbound_connecting = reconnects.values().filter(|item| item.connecting).count();
    state.outbound_address_groups = reconnects
        .iter()
        .filter(|(_, item)| item.connected || item.connecting)
        .map(|(address, _)| peer_address_group(address.ip()))
        .collect::<HashSet<_>>()
        .len();
    state.compact_peers = compact_peers.len();
    state.pending_compact_blocks = pending_compact_blocks.len();
}

async fn refresh_supervisor_backlog_diagnostics(
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
    peer_event_backlog: usize,
    validation_result_backlog: usize,
) {
    update_diagnostics(diagnostics, |state| {
        state.peer_event_backlog = peer_event_backlog;
        state.validation_result_backlog = validation_result_backlog;
    })
    .await;
}

async fn flush_address_book(
    store: &StoreHandle,
    addresses: &mut BoundedAddressBook,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) {
    let timestamp = unix_time();
    match persist_address_book(store, addresses, timestamp) {
        Ok(flushed) => {
            let sequence = addresses.durable_sequence;
            let dirty = addresses.dirty;
            update_diagnostics(diagnostics, |state| {
                state.address_book_sequence = sequence;
                state.address_book_dirty = dirty;
                if flushed {
                    state.address_book_flushes = state.address_book_flushes.saturating_add(1);
                    state.last_address_book_flush = Some(timestamp);
                    state.address_book_last_error = None;
                }
            })
            .await;
        }
        Err(error) => {
            let error = error.to_string();
            update_diagnostics(diagnostics, |state| {
                state.address_book_flush_failures =
                    state.address_book_flush_failures.saturating_add(1);
                state.address_book_dirty = true;
                state.address_book_last_error = Some(error.clone());
            })
            .await;
            tracing::warn!(%error, "failed to persist HNS address book");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn maintain_peer_bans(
    store: &StoreHandle,
    peers: &LivePeerManager,
    bans: &mut PeerBanBook,
    addresses: &mut BoundedAddressBook,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
    persistent: bool,
) {
    let timestamp = unix_time();
    let pending = peers.take_pending_bans().await;
    let expired = bans.remove_expired(timestamp);
    let mut accepted = 0u64;
    let mut banned_addresses = BTreeSet::new();

    for ban in pending {
        match bans.ban(&ban) {
            Ok(_) => {
                accepted = accepted.saturating_add(1);
                banned_addresses.insert(normalize_peer_ip(ban.address));
                tracing::warn!(
                    address = %ban.address,
                    score = ban.score,
                    ban_until = ban.ban_until,
                    "banned HNS peer IP"
                );
            }
            Err(error) => {
                let error = error.to_string();
                update_diagnostics(diagnostics, |state| {
                    state.ban_list_last_error = Some(error.clone());
                })
                .await;
                tracing::warn!(%error, "discarding invalid HNS peer-ban event");
            }
        }
    }

    for address in &banned_addresses {
        addresses.remove_discovered_ip(*address);
    }
    if !banned_addresses.is_empty() {
        reconnects.retain(|address, state| {
            state.persistent || !banned_addresses.contains(&normalize_peer_ip(address.ip()))
        });
    }

    let changed = accepted > 0 || expired > 0;
    if changed {
        peers.replace_bans(bans.active_bans(timestamp)).await;
        let banned = bans.len();
        let sequence = bans.durable_sequence();
        let dirty = bans.is_dirty();
        let known_addresses = addresses.len();
        update_diagnostics(diagnostics, |state| {
            state.ban_events = state.ban_events.saturating_add(accepted);
            state.expired_bans = state.expired_bans.saturating_add(expired as u64);
            state.banned_addresses = banned;
            state.ban_list_sequence = sequence;
            state.ban_list_dirty = dirty;
            state.known_addresses = known_addresses;
        })
        .await;
        if persistent {
            flush_peer_bans(store, bans, diagnostics).await;
        }
    }
}

async fn flush_peer_bans(
    store: &StoreHandle,
    bans: &mut PeerBanBook,
    diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>,
) {
    let timestamp = unix_time();
    match persist_peer_bans(store, bans, timestamp) {
        Ok(flushed) => {
            let count = bans.len();
            let sequence = bans.durable_sequence();
            let dirty = bans.is_dirty();
            update_diagnostics(diagnostics, |state| {
                state.banned_addresses = count;
                state.ban_list_sequence = sequence;
                state.ban_list_dirty = dirty;
                if flushed {
                    state.ban_list_flushes = state.ban_list_flushes.saturating_add(1);
                    state.last_ban_list_flush = Some(timestamp);
                    state.ban_list_last_error = None;
                }
            })
            .await;
        }
        Err(error) => {
            let error = error.to_string();
            update_diagnostics(diagnostics, |state| {
                state.ban_list_flush_failures = state.ban_list_flush_failures.saturating_add(1);
                state.ban_list_dirty = true;
                state.ban_list_last_error = Some(error.clone());
            })
            .await;
            tracing::warn!(%error, "failed to persist HNS peer-ban list");
        }
    }
}

async fn update_diagnostics<F>(diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>, update: F)
where
    F: FnOnce(&mut NativeSyncDiagnostics),
{
    let mut state = diagnostics.write().await;
    update(&mut state);
}

async fn record_error(diagnostics: &Arc<RwLock<NativeSyncDiagnostics>>, error: String) {
    tracing::warn!(%error, "Native sync runtime error");
    update_diagnostics(diagnostics, |state| state.last_error = Some(error)).await;
}

fn record_warning(warning: String) {
    tracing::warn!(%warning, "Native sync peer/runtime warning");
}

fn unexpected_extension_exit(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow::anyhow!("native runtime extension terminated unexpectedly"),
        Ok(Err(error)) => anyhow::anyhow!("native runtime extension failed: {error:#}"),
        Err(error) => anyhow::anyhow!("native runtime extension task failed: {error}"),
    }
}

async fn shutdown_native_runtime(
    runtime: NodeRuntime,
    clean_shutdown_eligible: bool,
) -> Result<()> {
    if clean_shutdown_eligible {
        runtime.shutdown().await
    } else {
        runtime.shutdown_unclean().await
    }
}

async fn await_extension_shutdown(
    mut task: JoinHandle<Result<()>>,
    shutdown_grace: Duration,
    abort_grace: Duration,
) -> Result<()> {
    match tokio::time::timeout(shutdown_grace, &mut task).await {
        Ok(result) => result
            .context("native runtime extension task join failed")?
            .context("native runtime extension task failed"),
        Err(_) => {
            task.abort();
            // Tokio cancellation is cooperative. Join the cancelled task so
            // yielding extensions have definitely dropped their NodeRuntime
            // capability, but keep this second wait bounded because blocking
            // or non-yielding extension code cannot be forcibly stopped.
            let cancellation_joined = tokio::time::timeout(abort_grace, &mut task).await.is_ok();
            if cancellation_joined {
                anyhow::bail!(
                    "native runtime extension did not stop within {} ms of shutdown; cancellation requested and task joined",
                    shutdown_grace.as_millis()
                )
            }
            anyhow::bail!(
                "native runtime extension did not stop within {} ms of shutdown; cancellation was not observed within a further {} ms",
                shutdown_grace.as_millis(),
                abort_grace.as_millis()
            )
        }
    }
}

async fn await_task(name: &str, task: JoinHandle<Result<()>>) -> Result<()> {
    task.await
        .with_context(|| format!("{name} task join failed"))?
        .with_context(|| format!("{name} task failed"))
}

async fn await_p2p_task(
    name: &str,
    task: JoinHandle<std::result::Result<(), hns_p2p::P2pError>>,
) -> Result<()> {
    task.await
        .with_context(|| format!("{name} task join failed"))?
        .map_err(|error| anyhow::anyhow!("{name} task failed: {error}"))
}

fn reconnect_delay(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(6);
    let seconds = (1u64 << exponent).min(MAX_RECONNECT_DELAY_SECONDS);
    Duration::from_secs(seconds)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn runtime_instance_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:032x}-{:08x}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NamePageStorage, NodeConfig, NodeState};
    use hns_consensus::{ConsensusError, SequenceLockView, TransactionInputVerifier};
    use hns_mempool::{ContextualTransactionVerifier, MempoolContext, MempoolView};
    use hns_primitives::{
        Address, Coin, Covenant, CovenantKind, Input, Outpoint, Output, Transaction, Txid, Uint256,
        Witness,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct RuntimeExtensionBoundaryProbe;

    impl NativeRuntimeExtension for RuntimeExtensionBoundaryProbe {
        fn spawn(
            self: Box<Self>,
            node: NodeRuntime,
            peers: LivePeerManager,
            shutdown: watch::Receiver<bool>,
        ) -> JoinHandle<Result<()>> {
            drop((self, node, peers, shutdown));
            tokio::spawn(async { Ok(()) })
        }
    }

    struct DropNotifier(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropNotifier {
        fn drop(&mut self) {
            if let Some(notify) = self.0.take() {
                let _ = notify.send(());
            }
        }
    }

    struct AcceptAllBlocks;

    impl StatelessBlockValidator for AcceptAllBlocks {
        fn validate(
            &self,
            _block: &Block,
            _height: Height,
        ) -> std::result::Result<(), ValidationRejection> {
            Ok(())
        }
    }

    #[test]
    fn native_runtime_extension_boundary_is_object_safe() {
        let extension: Box<dyn NativeRuntimeExtension> = Box::new(RuntimeExtensionBoundaryProbe);
        drop(extension);
        let _entrypoint = NodeService::run_until_shutdown_with_extension;
    }

    #[tokio::test]
    async fn native_supervisor_rotates_permanently_ready_lanes() {
        let (connect_tx, mut connect_rx) = mpsc::channel(2);
        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        let (validation_tx, mut validation_rx) = mpsc::channel(2);
        let address: SocketAddr = "127.0.0.1:14038".parse().expect("address");
        for sequence in 0..2 {
            connect_tx
                .send(ConnectAttemptResult {
                    address,
                    result: Err("fixture".to_owned()),
                })
                .await
                .expect("connection result");
            peer_tx
                .send(PeerEvent::InboundRejected {
                    address,
                    reason: "fixture".to_owned(),
                })
                .await
                .expect("peer event");
            validation_tx
                .send(Ok(ValidatedBlock {
                    sequence,
                    peer: PeerId(1),
                    height: sequence as Height,
                    block: Block {
                        header: Header::default(),
                        transactions: Vec::new(),
                    },
                }))
                .await
                .expect("validation result");
        }

        let mut poll = tokio::time::interval(Duration::from_secs(60));
        let mut next_lane = NativeSupervisorLane::Maintenance;
        let expected = [
            NativeSupervisorLane::Maintenance,
            NativeSupervisorLane::Connection,
            NativeSupervisorLane::Peer,
            NativeSupervisorLane::Validation,
            NativeSupervisorLane::Maintenance,
            NativeSupervisorLane::Connection,
            NativeSupervisorLane::Peer,
            NativeSupervisorLane::Validation,
        ];
        for expected_lane in expected {
            poll.reset_at(Instant::now() - Duration::from_secs(1));
            let event = next_native_supervisor_event(
                &mut next_lane,
                &mut poll,
                &mut connect_rx,
                &mut peer_rx,
                &mut validation_rx,
            )
            .await;
            assert_eq!(event.lane(), expected_lane);
        }
    }

    #[tokio::test]
    async fn overdue_supervisor_poll_is_reset_after_maintenance() {
        let mut poll = tokio::time::interval(Duration::from_secs(60));
        let overdue = Instant::now() - Duration::from_secs(1);
        poll.reset_at(overdue);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(poll.poll_tick(&mut context).is_ready());

        poll.reset_at(overdue);
        reset_native_supervisor_poll(&mut poll, Duration::from_secs(60));
        assert!(poll.poll_tick(&mut context).is_pending());
    }

    #[test]
    fn failed_validated_batch_restores_every_unowned_reservation() {
        let now = StdInstant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        let first = BlockHash::new([1; 32]);
        let second = BlockHash::new([2; 32]);
        let orphan = validator_coinbase_block(3, 1);
        let orphan_hash = orphan.hash();
        for (hash, height) in [(first, 1), (second, 2), (orphan_hash, 3)] {
            scheduler.queue_block(hash, height).expect("body work");
            scheduler.begin_local_validation(hash);
        }
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        orphans
            .insert(OwnedOrphan {
                block: orphan,
                height: 3,
            })
            .expect("retained orphan");

        reconcile_validated_reservations(
            &[(first, 1), (second, 2), (orphan_hash, 3)],
            &mut scheduler,
            &orphans,
        )
        .expect("reconcile consumed validation results");

        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 2);
        assert_eq!(snapshot.inflight_blocks, 0);
        assert_eq!(snapshot.tracked_blocks, 3);
        assert!(orphans.contains(&orphan_hash));
    }

    #[test]
    fn owned_orphan_eviction_requeues_without_a_canonical_read() {
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        let old_parent = BlockHash::new([0x41; 32]);
        let new_parent = BlockHash::new([0x42; 32]);
        let mut old = validator_coinbase_block(1, 1);
        old.header.prev_block = old_parent;
        let mut new = validator_coinbase_block(2, 1);
        new.header.prev_block = new_parent;
        let old_hash = old.hash();
        let new_hash = new.hash();
        for (hash, height) in [(old_hash, 1), (new_hash, 2)] {
            scheduler.queue_block(hash, height).expect("body work");
            scheduler.begin_local_validation(hash);
        }
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 1,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        let mut ready = ReadyOrphanParents::new(1);
        let mut discards = DeferredOrphanDiscards::new(1);

        retain_validated_orphan(
            old,
            1,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
        )
        .expect("retain first orphan");
        enqueue_ready_orphan_parent(old_parent, &orphans, &discards, &mut ready)
            .expect("queue first parent");
        assert_eq!(ready.len(), 1);
        retain_validated_orphan(
            new,
            2,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
        )
        .expect("evict and synchronously requeue first orphan");

        assert!(!orphans.contains(&old_hash));
        assert!(orphans.contains(&new_hash));
        assert_eq!(ready.len(), 0, "eviction removes the last-child tombstone");
        enqueue_ready_orphan_parent(new_parent, &orphans, &discards, &mut ready)
            .expect("replacement parent fits the exact one-parent bound");
        assert_eq!(ready.len(), 1);
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 1);
        assert_eq!(snapshot.tracked_blocks, 2);
    }

    #[tokio::test]
    async fn invalid_branch_discard_prunes_ready_parent_at_capacity() {
        struct AcceptValidator;

        impl StatelessBlockValidator for AcceptValidator {
            fn validate(
                &self,
                _block: &Block,
                _height: Height,
            ) -> std::result::Result<(), ValidationRejection> {
                Ok(())
            }
        }

        let (validation, _results) = spawn_validation_pipeline(Arc::new(AcceptValidator), 1, 2)
            .expect("validation pipeline");
        let failed_parent = BlockHash::new([0x43; 32]);
        let replacement_parent = BlockHash::new([0x44; 32]);
        let mut child = validator_coinbase_block(1, 1);
        child.header.prev_block = failed_parent;
        let mut replacement = validator_coinbase_block(2, 1);
        replacement.header.prev_block = replacement_parent;
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        orphans
            .insert(OwnedOrphan {
                block: child,
                height: 1,
            })
            .expect("failed branch child");
        let mut ready = ReadyOrphanParents::new(1);
        let mut discards = DeferredOrphanDiscards::new(1);
        let mut schedule = OrphanWorkSchedule::default();
        enqueue_ready_orphan_parent(failed_parent, &orphans, &discards, &mut ready)
            .expect("queue failed parent");

        enqueue_affected_orphan_discards(&[failed_parent], &orphans, &mut ready, &mut discards)
            .expect("schedule failed branch");
        assert_eq!(ready.len(), 0);
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        assert_eq!(
            drain_orphan_work(
                1,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("discard one child"),
            1
        );
        assert_eq!(discards.len(), 0);
        orphans
            .insert(OwnedOrphan {
                block: replacement,
                height: 2,
            })
            .expect("replacement child");
        enqueue_ready_orphan_parent(replacement_parent, &orphans, &discards, &mut ready)
            .expect("replacement parent fits after eager cleanup");
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn ready_enqueue_prunes_contextual_discard_tombstone_at_capacity() {
        let failed_parent = BlockHash::new([0x45; 32]);
        let replacement_parent = BlockHash::new([0x46; 32]);
        let mut child = validator_coinbase_block(1, 1);
        child.header.prev_block = failed_parent;
        let mut replacement = validator_coinbase_block(2, 1);
        replacement.header.prev_block = replacement_parent;
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        orphans
            .insert(OwnedOrphan {
                block: child,
                height: 1,
            })
            .expect("contextual branch child");
        let mut ready = ReadyOrphanParents::new(1);
        let discards = DeferredOrphanDiscards::new(1);
        enqueue_ready_orphan_parent(failed_parent, &orphans, &discards, &mut ready)
            .expect("queue contextual parent");

        // Active-state completion owns only the generic orphan-pool trait.
        // The universal enqueue boundary must therefore remove its tombstone.
        discard_orphan_descendants(failed_parent, &mut orphans).expect("discard contextual branch");
        assert_eq!(ready.len(), 1, "fixture retains a stale ready key");
        orphans
            .insert(OwnedOrphan {
                block: replacement,
                height: 2,
            })
            .expect("replacement child");
        enqueue_ready_orphan_parent(replacement_parent, &orphans, &discards, &mut ready)
            .expect("replacement parent fits after universal cleanup");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready.queue.values().next(), Some(&replacement_parent));
    }

    #[tokio::test]
    async fn ready_parent_drain_bounds_children_and_rotates_busy_parents() {
        struct AcceptValidator;

        impl StatelessBlockValidator for AcceptValidator {
            fn validate(
                &self,
                _block: &Block,
                _height: Height,
            ) -> std::result::Result<(), ValidationRejection> {
                Ok(())
            }
        }

        let (validation, _results) = spawn_validation_pipeline(Arc::new(AcceptValidator), 1, 8)
            .expect("validation pipeline");
        let first_parent = BlockHash::new([0x47; 32]);
        let second_parent = BlockHash::new([0x48; 32]);
        let mut retained = Vec::new();
        for (height, parent) in [(1, first_parent), (2, first_parent), (3, second_parent)] {
            let mut child = validator_coinbase_block(height, 1);
            child.header.prev_block = parent;
            retained.push((child, height));
        }
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 3,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        for (block, height) in retained {
            let hash = block.hash();
            scheduler
                .queue_block(hash, height)
                .expect("child body work");
            scheduler.begin_local_validation(hash);
            orphans
                .insert(OwnedOrphan { block, height })
                .expect("retained child");
            scheduler.complete_orphan_validation();
        }
        let mut ready = ReadyOrphanParents::new(3);
        let mut discards = DeferredOrphanDiscards::new(3);
        let mut schedule = OrphanWorkSchedule::default();
        enqueue_ready_orphan_parent(first_parent, &orphans, &discards, &mut ready)
            .expect("queue first parent");
        enqueue_ready_orphan_parent(second_parent, &orphans, &discards, &mut ready)
            .expect("queue second parent");

        assert_eq!(
            drain_orphan_work(
                1,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("first bounded drain"),
            1
        );
        assert_eq!(orphans.snapshot().blocks, 2);
        assert_eq!(
            ready.queue.values().copied().collect::<Vec<_>>(),
            [second_parent, first_parent]
        );

        assert_eq!(
            drain_orphan_work(
                1,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("second bounded drain"),
            1
        );
        assert_eq!(orphans.snapshot().blocks, 1);
        assert_eq!(
            ready.queue.values().copied().collect::<Vec<_>>(),
            [first_parent]
        );
    }

    #[tokio::test]
    async fn orphan_work_alternates_release_and_discard_lanes() {
        let (validation, _results) = spawn_validation_pipeline(Arc::new(AcceptAllBlocks), 1, 4)
            .expect("validation pipeline");
        let release_parent = BlockHash::new([0x49; 32]);
        let discard_parent = BlockHash::new([0x4a; 32]);
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 4,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        for (height, parent) in [
            (1, release_parent),
            (2, release_parent),
            (3, discard_parent),
            (4, discard_parent),
        ] {
            let mut block = validator_coinbase_block(height, 1);
            block.header.prev_block = parent;
            retain_test_owned_orphan(block, height, &mut scheduler, &mut orphans);
        }
        let mut ready = ReadyOrphanParents::new(4);
        let mut discards = DeferredOrphanDiscards::new(4);
        enqueue_ready_orphan_parent(release_parent, &orphans, &discards, &mut ready)
            .expect("queue release parent");
        enqueue_affected_orphan_discards(&[discard_parent], &orphans, &mut ready, &mut discards)
            .expect("queue discard parent");
        let mut schedule = OrphanWorkSchedule::default();

        for (expected_next, expected_ready, expected_discards) in [
            (OrphanWorkLane::Release, 1, 1),
            (OrphanWorkLane::Discard, 1, 1),
            (OrphanWorkLane::Release, 1, 0),
            (OrphanWorkLane::Discard, 0, 0),
        ] {
            assert_eq!(
                drain_orphan_work(
                    1,
                    &validation,
                    &mut scheduler,
                    &mut orphans,
                    &mut ready,
                    &mut discards,
                    &mut schedule,
                )
                .expect("one alternating orphan unit"),
                1
            );
            assert_eq!(schedule.next, expected_next);
            assert_eq!(ready.len(), expected_ready);
            assert_eq!(discards.len(), expected_discards);
            assert_orphan_work_membership_exact(&orphans, &ready, &discards);
        }
        assert_eq!(orphans.snapshot().blocks, 0);
    }

    #[tokio::test]
    async fn stale_orphan_parent_probe_consumes_the_shared_unit() {
        let (validation, _results) = spawn_validation_pipeline(Arc::new(AcceptAllBlocks), 1, 2)
            .expect("validation pipeline");
        let stale_parent = BlockHash::new([0x4b; 32]);
        let live_parent = BlockHash::new([0x4c; 32]);
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        let mut stale_child = validator_coinbase_block(1, 1);
        stale_child.header.prev_block = stale_parent;
        retain_test_owned_orphan(stale_child, 1, &mut scheduler, &mut orphans);
        let mut ready = ReadyOrphanParents::new(2);
        let mut discards = DeferredOrphanDiscards::new(2);
        enqueue_ready_orphan_parent(stale_parent, &orphans, &discards, &mut ready)
            .expect("queue stale fixture parent");
        let removed = orphans
            .take_children_bounded(stale_parent, 1)
            .expect("remove child behind ready queue");
        assert_eq!(removed.children.len(), 1);

        let mut live_child = validator_coinbase_block(2, 1);
        live_child.header.prev_block = live_parent;
        retain_test_owned_orphan(live_child, 2, &mut scheduler, &mut orphans);
        enqueue_ready_orphan_parent(live_parent, &orphans, &discards, &mut ready)
            .expect("queue live fixture parent");
        let mut schedule = OrphanWorkSchedule {
            next: OrphanWorkLane::Release,
        };

        assert_eq!(
            drain_orphan_work(
                1,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("bounded stale probe"),
            1
        );
        assert_eq!(orphans.snapshot().blocks, 1);
        assert_eq!(ready.len(), 1, "live parent waits for another opportunity");
        assert_eq!(
            drain_orphan_work(
                1,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("release live parent"),
            1
        );
        assert_eq!(orphans.snapshot().blocks, 0);
    }

    #[test]
    fn orphan_lane_sequence_overflow_fails_before_capacity_cleanup() {
        let stale_parent = BlockHash::new([0x5a; 32]);
        let new_parent = BlockHash::new([0x5b; 32]);
        let mut stale_child = validator_coinbase_block(1, 1);
        stale_child.header.prev_block = stale_parent;
        let mut new_child = validator_coinbase_block(2, 1);
        new_child.header.prev_block = new_parent;

        let mut ready_orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 1,
            maximum_bytes: 1_000_000,
        })
        .expect("ready orphan pool");
        ready_orphans
            .insert(OwnedOrphan {
                block: stale_child.clone(),
                height: 1,
            })
            .expect("ready stale child");
        let empty_discards = DeferredOrphanDiscards::new(1);
        let mut ready = ReadyOrphanParents::new(1);
        enqueue_ready_orphan_parent(stale_parent, &ready_orphans, &empty_discards, &mut ready)
            .expect("ready stale parent");
        ready_orphans
            .take_children_bounded(stale_parent, 1)
            .expect("remove ready stale child");
        ready_orphans
            .insert(OwnedOrphan {
                block: new_child.clone(),
                height: 2,
            })
            .expect("ready replacement child");
        ready.next_id = u64::MAX;
        let ready_before = ready.queue.clone();
        let error =
            enqueue_ready_orphan_parent(new_parent, &ready_orphans, &empty_discards, &mut ready)
                .expect_err("ready sequence overflow");
        assert!(owned_orphan_invariant(&error));
        assert_eq!(ready.queue, ready_before);

        let mut discard_orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 1,
            maximum_bytes: 1_000_000,
        })
        .expect("discard orphan pool");
        discard_orphans
            .insert(OwnedOrphan {
                block: stale_child,
                height: 1,
            })
            .expect("discard stale child");
        let mut discards = DeferredOrphanDiscards::new(1);
        discards
            .enqueue(stale_parent, &discard_orphans)
            .expect("discard stale parent");
        discard_orphans
            .take_children_bounded(stale_parent, 1)
            .expect("remove discard stale child");
        discard_orphans
            .insert(OwnedOrphan {
                block: new_child,
                height: 2,
            })
            .expect("discard replacement child");
        discards.next_id = u64::MAX;
        let discards_before = discards.queue.clone();
        let mut discard_ready = ReadyOrphanParents::new(1);
        enqueue_ready_orphan_parent(new_parent, &discard_orphans, &discards, &mut discard_ready)
            .expect("ready parent before discard transfer");
        let ready_before = discard_ready.queue.clone();
        let error = enqueue_deferred_orphan_discard(
            new_parent,
            &discard_orphans,
            &mut discard_ready,
            &mut discards,
        )
        .expect_err("discard sequence overflow");
        assert!(owned_orphan_invariant(&error));
        assert_eq!(discards.queue, discards_before);
        assert_eq!(discard_ready.queue, ready_before);
    }

    #[tokio::test]
    async fn deferred_discard_bounds_deep_and_wide_tree_per_opportunity() {
        const WIDE: Height = 32;
        const DEEP: Height = 64;
        let (validation, _results) = spawn_validation_pipeline(Arc::new(AcceptAllBlocks), 1, 2)
            .expect("validation pipeline");
        let root = BlockHash::new([0x4d; 32]);
        let total = usize::try_from(WIDE + DEEP).expect("fixture size");
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: total,
            maximum_bytes: 4_000_000,
        })
        .expect("orphan pool");
        let mut deep_parent = None;
        for height in 1..=WIDE {
            let mut block = validator_coinbase_block(height, 1);
            block.header.prev_block = root;
            if height == 1 {
                deep_parent = Some(block.hash());
            }
            retain_test_owned_orphan(block, height, &mut scheduler, &mut orphans);
        }
        let mut parent = deep_parent.expect("wide branch root");
        for offset in 1..=DEEP {
            let height = WIDE.saturating_add(offset);
            let mut block = validator_coinbase_block(height, 1);
            block.header.prev_block = parent;
            parent = block.hash();
            retain_test_owned_orphan(block, height, &mut scheduler, &mut orphans);
        }
        let mut ready = ReadyOrphanParents::new(total);
        let mut discards = DeferredOrphanDiscards::new(total);
        enqueue_ready_orphan_parent(root, &orphans, &discards, &mut ready)
            .expect("queue tree root");
        enqueue_affected_orphan_discards(&[root], &orphans, &mut ready, &mut discards)
            .expect("fence tree root");
        let mut schedule = OrphanWorkSchedule::default();
        let mut opportunities = 0usize;
        while orphans.snapshot().blocks != 0 {
            let before = orphans.snapshot().blocks;
            let spent = drain_orphan_work(
                MAX_VALIDATED_BODY_COMMIT_BATCH,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("bounded tree discard");
            opportunities = opportunities.saturating_add(1);
            assert!((1..=MAX_VALIDATED_BODY_COMMIT_BATCH).contains(&spent));
            assert_eq!(before.saturating_sub(orphans.snapshot().blocks), spent);
            assert_orphan_work_membership_exact(&orphans, &ready, &discards);
            assert!(opportunities <= total);
        }
        assert_eq!(
            opportunities,
            total.div_ceil(MAX_VALIDATED_BODY_COMMIT_BATCH)
        );
        assert_eq!(scheduler.snapshot().tracked_blocks, 0);
        assert_eq!(ready.len(), 0);
        assert_eq!(discards.len(), 0);
    }

    #[tokio::test]
    async fn affected_seed_reaches_grandchild_across_evicted_body_bridge() {
        let (validation, _results) = spawn_validation_pipeline(Arc::new(AcceptAllBlocks), 1, 2)
            .expect("validation pipeline");
        let root = BlockHash::new([0x4e; 32]);
        let filler_parent = BlockHash::new([0x4f; 32]);
        let mut bridge = validator_coinbase_block(1, 1);
        bridge.header.prev_block = root;
        let bridge_hash = bridge.hash();
        let mut grandchild = validator_coinbase_block(2, 1);
        grandchild.header.prev_block = bridge_hash;
        let grandchild_hash = grandchild.hash();
        let mut filler = validator_coinbase_block(3, 1);
        filler.header.prev_block = filler_parent;
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        orphans
            .insert(OwnedOrphan {
                block: bridge,
                height: 1,
            })
            .expect("bridge body");
        orphans
            .insert(OwnedOrphan {
                block: grandchild,
                height: 2,
            })
            .expect("grandchild body");
        let outcome = orphans
            .insert_with_evictions(OwnedOrphan {
                block: filler,
                height: 3,
            })
            .expect("evict bridge body");
        assert_eq!(outcome.evicted.len(), 1);
        assert_eq!(outcome.evicted[0].block.hash(), bridge_hash);
        assert!(orphans.contains(&grandchild_hash));
        assert!(!orphans.has_children(root));
        assert!(orphans.has_children(bridge_hash));

        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        scheduler
            .queue_block(grandchild_hash, 2)
            .expect("grandchild ownership");
        scheduler.begin_local_validation(grandchild_hash);
        scheduler.complete_orphan_validation();
        let mut ready = ReadyOrphanParents::new(2);
        let mut discards = DeferredOrphanDiscards::new(2);
        enqueue_ready_orphan_parent(bridge_hash, &orphans, &discards, &mut ready)
            .expect("queue durable bridge parent");
        enqueue_affected_orphan_discards(&[root, bridge_hash], &orphans, &mut ready, &mut discards)
            .expect("seed every affected hash");
        assert_eq!(ready.len(), 0);
        assert!(discards.contains(bridge_hash));
        let mut schedule = OrphanWorkSchedule::default();
        assert_eq!(
            drain_orphan_work(
                1,
                &validation,
                &mut scheduler,
                &mut orphans,
                &mut ready,
                &mut discards,
                &mut schedule,
            )
            .expect("discard bridged grandchild"),
            1
        );
        assert!(!orphans.contains(&grandchild_hash));
        assert_eq!(scheduler.snapshot().tracked_blocks, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_validation_queue_restores_child_and_retries_ready_parent() {
        struct GateValidator {
            started: Arc<AtomicUsize>,
            release: Arc<std::sync::atomic::AtomicBool>,
        }

        impl StatelessBlockValidator for GateValidator {
            fn validate(
                &self,
                _block: &Block,
                _height: Height,
            ) -> std::result::Result<(), ValidationRejection> {
                let ordinal = self.started.fetch_add(1, Ordering::AcqRel);
                if ordinal == 0 {
                    while !self.release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                }
                Ok(())
            }
        }

        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (validation, mut results) = spawn_validation_pipeline(
            Arc::new(GateValidator {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            }),
            1,
            1,
        )
        .expect("validation pipeline");
        validation
            .try_submit(ValidationRequest {
                peer: PeerId(1),
                height: 1,
                attempt: 0,
                block: validator_coinbase_block(1, 1),
            })
            .expect("running validation");
        tokio::time::timeout(Duration::from_secs(2), async {
            while started.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first validation did not start");
        validation
            .try_submit(ValidationRequest {
                peer: PeerId(1),
                height: 2,
                attempt: 0,
                block: validator_coinbase_block(2, 1),
            })
            .expect("fill validation input queue");

        let parent = BlockHash::new([0x55; 32]);
        let mut child = validator_coinbase_block(3, 1);
        child.header.prev_block = parent;
        let child_hash = child.hash();
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        scheduler
            .queue_block(child_hash, 3)
            .expect("child body work");
        scheduler.begin_local_validation(child_hash);
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 1,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        orphans
            .insert(OwnedOrphan {
                block: child,
                height: 3,
            })
            .expect("retained child");
        scheduler.complete_orphan_validation();
        let mut ready = ReadyOrphanParents::new(1);
        let mut discards = DeferredOrphanDiscards::new(1);
        let mut schedule = OrphanWorkSchedule::default();

        enqueue_ready_orphan_parent(parent, &orphans, &discards, &mut ready)
            .expect("queue releasable parent");
        drain_orphan_work(
            1,
            &validation,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
            &mut schedule,
        )
        .expect("queue-full release remains owned");
        assert!(orphans.contains(&child_hash));
        assert_eq!(ready.len(), 1);

        release.store(true, Ordering::Release);
        let _ = tokio::time::timeout(Duration::from_secs(2), results.recv())
            .await
            .expect("first validation result timeout")
            .expect("first validation result channel");
        tokio::time::timeout(Duration::from_secs(2), async {
            while ready.len() != 0 {
                drain_orphan_work(
                    1,
                    &validation,
                    &mut scheduler,
                    &mut orphans,
                    &mut ready,
                    &mut discards,
                    &mut schedule,
                )
                .expect("retry ready parent");
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ready parent did not submit after capacity freed");
        assert!(!orphans.contains(&child_hash));
        assert_eq!(ready.len(), 0);
    }

    #[tokio::test]
    async fn closed_validation_pipeline_restores_exact_orphan_before_terminal_error() {
        let (validation, results) = spawn_validation_pipeline(Arc::new(AcceptAllBlocks), 1, 1)
            .expect("validation pipeline");
        drop(results);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let probe = validation.try_submit(ValidationRequest {
                    peer: PeerId(1),
                    height: 1,
                    attempt: 0,
                    block: validator_coinbase_block(1, 1),
                });
                if matches!(probe, Err(SyncError::ValidationPipelineClosed)) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("validation pipeline did not close");

        let parent = BlockHash::new([0x56; 32]);
        let height = 77;
        let mut child = validator_coinbase_block(height, 1);
        child.header.prev_block = parent;
        let child_hash = child.hash();
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 1,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        retain_test_owned_orphan(child, height, &mut scheduler, &mut orphans);
        let mut ready = ReadyOrphanParents::new(1);
        let mut discards = DeferredOrphanDiscards::new(1);
        enqueue_ready_orphan_parent(parent, &orphans, &discards, &mut ready)
            .expect("queue orphan parent");
        let mut schedule = OrphanWorkSchedule {
            next: OrphanWorkLane::Release,
        };

        let error = drain_orphan_work(
            1,
            &validation,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
            &mut schedule,
        )
        .expect_err("closed validation pipeline is terminal");
        assert!(validation_pipeline_closed(&error), "{error:#}");
        assert!(orphans.contains(&child_hash));
        assert_eq!(scheduler.snapshot().tracked_blocks, 1);
        let restored = orphans
            .take_children_bounded(parent, 1)
            .expect("inspect restored child");
        assert_eq!(restored.children.len(), 1);
        assert_eq!(restored.children[0].block.hash(), child_hash);
        assert_eq!(restored.children[0].height, height);
    }

    #[tokio::test]
    async fn busy_validated_batch_is_reconciled_to_pending_work() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let block = linked_validator_block(1, &genesis.header);
        let hash = block.hash();
        service
            .native_sync_import_headers(vec![block.header.clone()])
            .expect("canonical header");
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let (_validation, _validation_results) =
            spawn_validation_pipeline(Arc::new(HnsBodyValidator::new(Network::Regtest)), 1, 2)
                .expect("validation pipeline");
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        scheduler.queue_block(hash, 1).expect("body reservation");
        scheduler.begin_local_validation(hash);
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        let mut ready_orphan_parents = ReadyOrphanParents::new(2);
        let mut deferred_orphan_discards = DeferredOrphanDiscards::new(2);
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));
        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest))
                .expect("peer manager");
        let context = ValidationResultContext {
            node: &node,
            writer: &writer,
            peers: &peers,
            diagnostics: &diagnostics,
        };

        let previous = node
            .state
            .publication_sequence
            .fetch_add(1, Ordering::AcqRel);
        assert_eq!(previous & 1, 0, "fixture starts from a stable generation");
        let result = handle_validated_blocks(
            vec![ValidatedBlock {
                sequence: 0,
                peer: PeerId(1),
                height: 1,
                block,
            }],
            &context,
            &mut scheduler,
            &mut orphans,
            &mut ready_orphan_parents,
            &mut deferred_orphan_discards,
        )
        .await;
        node.state
            .publication_sequence
            .store(previous, Ordering::Release);

        let error = result.expect_err("overlapping stable read is reconciled");
        assert!(!unreconciled_validation_batch(&error), "{error:#}");
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 1);
        assert_eq!(snapshot.inflight_blocks, 0);
        assert_eq!(snapshot.tracked_blocks, 1);
        assert_eq!(snapshot.validated_blocks, 0);
        assert!(!node.native_sync_has_block(&hash).expect("body lookup"));
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[tokio::test]
    async fn rejected_branch_late_ok_and_err_results_are_dropped_exactly() {
        let runtime = NodeRuntime::spawn(
            NodeService::new(NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            }),
            4,
        )
        .expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest))
                .expect("peer manager");
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));
        let context = ValidationResultContext {
            node: &node,
            writer: &writer,
            peers: &peers,
            diagnostics: &diagnostics,
        };
        let ok_block = validator_coinbase_block(40, 1);
        let err_block = validator_coinbase_block(41, 1);
        let ok_hash = ok_block.hash();
        let err_hash = err_block.hash();
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        for (hash, height) in [(ok_hash, 40), (err_hash, 41)] {
            scheduler.queue_block(hash, height).expect("late body work");
            scheduler.begin_local_validation(hash);
            scheduler.reject_block(None, hash, false, StdInstant::now());
        }
        let before = scheduler.snapshot();
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("orphan pool");
        let mut ready = ReadyOrphanParents::new(2);
        let mut discards = DeferredOrphanDiscards::new(2);

        handle_validation_results(
            vec![
                Ok(ValidatedBlock {
                    sequence: 0,
                    peer: PeerId(7),
                    height: 40,
                    block: ok_block,
                }),
                Err(ValidationFailure {
                    sequence: 1,
                    peer: PeerId(7),
                    height: 41,
                    attempt: 1,
                    block: err_block,
                    kind: ValidationFailureKind::InvalidBlock,
                    reason: "late invalid result".to_owned(),
                }),
            ],
            &context,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
        )
        .await
        .expect("stale results are ignored");

        let after = scheduler.snapshot();
        assert_eq!(after.pending_blocks, before.pending_blocks);
        assert_eq!(after.inflight_blocks, before.inflight_blocks);
        assert_eq!(after.tracked_blocks, before.tracked_blocks);
        assert_eq!(after.failed_blocks, before.failed_blocks);
        assert_eq!(orphans.snapshot().blocks, 0);
        assert_eq!(ready.len(), 0);
        assert_eq!(discards.len(), 0);
        assert_eq!(diagnostics.read().await.rejected_messages, 0);
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn canonical_body_scan_is_capped_by_validation_capacity() {
        let mut config = NativeSyncConfig {
            validation_queue: 7,
            validation_workers: 3,
            maximum_outbound: 2,
            orphan_blocks: 1_024,
            ..NativeSyncConfig::default()
        };
        assert_eq!(native_body_candidate_scan_window(&config), 64);
        config.validation_queue = 2_048;
        assert_eq!(native_body_candidate_scan_window(&config), 256);
    }

    #[tokio::test]
    async fn supervisor_backlogs_refresh_on_every_observation() {
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics {
            peer_event_backlog: 99,
            validation_result_backlog: 99,
            ..NativeSyncDiagnostics::default()
        }));
        refresh_supervisor_backlog_diagnostics(&diagnostics, 3, 7).await;
        assert_eq!(diagnostics.read().await.peer_event_backlog, 3);
        assert_eq!(diagnostics.read().await.validation_result_backlog, 7);
        refresh_supervisor_backlog_diagnostics(&diagnostics, 0, 2).await;
        assert_eq!(diagnostics.read().await.peer_event_backlog, 0);
        assert_eq!(diagnostics.read().await.validation_result_backlog, 2);
    }

    #[test]
    fn native_runtime_extension_early_exit_is_fail_closed() {
        let error = unexpected_extension_exit(Ok(Ok(())));
        assert_eq!(
            error.to_string(),
            "native runtime extension terminated unexpectedly"
        );

        let error = unexpected_extension_exit(Ok(Err(anyhow::anyhow!("extension fault"))));
        assert_eq!(
            error.to_string(),
            "native runtime extension failed: extension fault"
        );
    }

    #[tokio::test]
    async fn native_runtime_extension_observes_shutdown_watch() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            shutdown_rx
                .changed()
                .await
                .context("extension shutdown watch closed")?;
            if !*shutdown_rx.borrow() {
                anyhow::bail!("extension received a non-shutdown watch update");
            }
            Ok(())
        });

        shutdown_tx
            .send(true)
            .expect("broadcast extension shutdown");
        await_extension_shutdown(task, Duration::from_secs(1), Duration::from_secs(1))
            .await
            .expect("extension exits during its shutdown grace");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_supervisor_failure_shutdown_leaves_store_unclean() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        assert!(
            !hns_store::was_clean_shutdown(&store).expect("running store marker"),
            "a running supervisor must be marked unclean"
        );

        let runtime = NodeRuntime::spawn(node, 2).expect("node runtime");
        shutdown_native_runtime(runtime, false)
            .await
            .expect("failure shutdown drains accepted writer commands");

        assert!(
            !hns_store::was_clean_shutdown(&store).expect("failure shutdown marker"),
            "a failed native supervisor must not claim a clean shutdown"
        );
    }

    #[tokio::test]
    async fn native_runtime_extension_shutdown_is_bounded() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, mut dropped_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _drop_notifier = DropNotifier(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
            Ok(())
        });
        started_rx.await.expect("extension task started");

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            await_extension_shutdown(task, Duration::from_millis(20), Duration::from_secs(1)),
        )
        .await
        .expect("bounded extension shutdown returned")
        .expect_err("non-cooperative extension fails shutdown");
        assert!(
            error
                .to_string()
                .contains("native runtime extension did not stop within 20 ms"),
            "{error:#}"
        );
        dropped_rx
            .try_recv()
            .expect("cooperatively aborted extension was joined before helper returned");
    }

    #[derive(Clone, Default)]
    struct RpcMempoolView {
        coins: HashMap<Outpoint, Coin>,
    }

    impl SequenceLockView for RpcMempoolView {
        fn coin_height(
            &self,
            outpoint: &Outpoint,
        ) -> std::result::Result<Option<Height>, ConsensusError> {
            Ok(self.coins.get(outpoint).map(|coin| coin.height))
        }

        fn median_time_past(&self, height: Height) -> std::result::Result<u64, ConsensusError> {
            Ok(u64::from(height))
        }
    }

    impl MempoolView for RpcMempoolView {
        fn coin(&self, outpoint: &Outpoint) -> std::result::Result<Option<Coin>, ConsensusError> {
            Ok(self.coins.get(outpoint).cloned())
        }
    }

    struct AllowRpcMempoolInputs;

    impl TransactionInputVerifier for AllowRpcMempoolInputs {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> std::result::Result<(), ConsensusError> {
            Ok(())
        }
    }

    struct AllowRpcMempoolContext;

    impl ContextualTransactionVerifier for AllowRpcMempoolContext {
        fn verify(
            &self,
            _transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            _accepted_name_transactions: &hns_mempool::AcceptedNameTransactions<'_>,
        ) -> std::result::Result<(), ConsensusError> {
            Ok(())
        }
    }

    fn rpc_mempool_transaction(tag: u8) -> (Transaction, Coin) {
        let outpoint = Outpoint {
            txid: Txid::new([tag; 32]),
            index: 0,
        };
        let address = Address::new(0, vec![tag; 20]).expect("test address");
        let covenant = Covenant {
            kind: CovenantKind::None,
            items: Vec::new(),
        };
        let coin = Coin {
            outpoint: outpoint.clone(),
            value: 20,
            height: 1,
            coinbase: false,
            address: address.clone(),
            covenant: covenant.clone(),
        };
        (
            Transaction {
                version: 0,
                inputs: vec![Input {
                    previous_output: outpoint,
                    sequence: u32::MAX,
                    witness: Witness::default(),
                }],
                outputs: vec![Output {
                    value: 15,
                    address,
                    covenant,
                }],
                locktime: 0,
            },
            coin,
        )
    }

    async fn call_native_rpc(
        state: &NativeSyncHttpState,
        id: &str,
        method: &str,
    ) -> serde_json::Value {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": [],
        });
        let response =
            handle_native_sync_rpc(State(state.clone()), Bytes::from(request.to_string())).await;
        serde_json::to_value(response.0).expect("serialize RPC response")
    }

    fn keyed_net_address(address: SocketAddr, time: u64, services: u64) -> hns_p2p::NetAddress {
        let mut wire = hns_p2p::NetAddress::from_socket_addr(address, time, services);
        wire.key = [2; 33];
        wire
    }

    fn scheduler_tip(height: Height, tag: u8) -> ChainTip {
        ChainTip {
            hash: BlockHash::new([tag; 32]),
            height,
            chainwork: Uint256::from_u64(u64::from(height).saturating_add(1)),
        }
    }

    fn decode_fixture_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let encoded = std::str::from_utf8(pair).expect("fixture hex");
                u8::from_str_radix(encoded, 16).expect("fixture hex byte")
            })
            .collect()
    }

    fn staged_effect_test_error(context: &'static str) -> anyhow::Error {
        anyhow::Error::new(StoreError::LimitExceeded {
            context,
            limit: super::super::MAX_REORG_STAGED_EFFECT_BYTES,
            actual: super::super::MAX_REORG_STAGED_EFFECT_BYTES.saturating_add(1),
        })
        .context("active-state connector failed without block-invalid evidence")
    }

    fn staged_effect_retry_break(attempted_connect: usize) -> DirectStagedEffectLimit {
        let error = staged_effect_test_error(ReorgStagedEffectMeter::CONTEXT);
        let (retry_connect, limit, actual) =
            direct_staged_effect_retry(&error, false, attempted_connect)
                .expect("multi-block direct limit is retryable");
        DirectStagedEffectLimit {
            retry_connect,
            limit,
            actual,
        }
    }

    #[test]
    fn direct_staged_effect_limit_driver_retries_288_as_144_then_succeeds() {
        let mut attempts = Vec::new();
        let connected = drive_active_state_connect_retries(288, |attempted_connect| {
            attempts.push(attempted_connect);
            Ok::<_, anyhow::Error>(if attempted_connect == 288 {
                std::ops::ControlFlow::Break(staged_effect_retry_break(attempted_connect))
            } else {
                std::ops::ControlFlow::Continue(attempted_connect)
            })
        })
        .expect("smaller direct slice succeeds");
        assert_eq!(attempts, vec![288, 144]);
        assert_eq!(connected, 144);
    }

    #[test]
    fn direct_staged_effect_limit_driver_repeats_odd_ceil_halving() {
        let mut attempts = Vec::new();
        let connected = drive_active_state_connect_retries(5, |attempted_connect| {
            attempts.push(attempted_connect);
            Ok::<_, anyhow::Error>(if attempted_connect > 2 {
                std::ops::ControlFlow::Break(staged_effect_retry_break(attempted_connect))
            } else {
                std::ops::ControlFlow::Continue(attempted_connect)
            })
        })
        .expect("bounded repeated retry succeeds");
        assert_eq!(attempts, vec![5, 3, 2]);
        assert_eq!(connected, 2);
    }

    #[test]
    fn single_block_staged_effect_limit_driver_propagates_terminal_error() {
        let mut attempts = Vec::new();
        let error = drive_active_state_connect_retries::<()>(1, |attempted_connect| {
            attempts.push(attempted_connect);
            Err(staged_effect_test_error(ReorgStagedEffectMeter::CONTEXT))
        })
        .expect_err("one block cannot be bisected");
        assert_eq!(attempts, vec![1]);
        assert_eq!(
            reorg_staged_effect_limit(&error),
            Some((
                super::super::MAX_REORG_STAGED_EFFECT_BYTES,
                super::super::MAX_REORG_STAGED_EFFECT_BYTES.saturating_add(1),
            ))
        );
    }

    #[test]
    fn staged_effect_retry_classifier_rejects_reorg_and_unrelated_context() {
        let error = staged_effect_test_error(ReorgStagedEffectMeter::CONTEXT);
        assert_eq!(direct_staged_effect_retry(&error, true, 288), None);

        let unrelated = staged_effect_test_error("unrelated atomic write bytes");
        assert_eq!(direct_staged_effect_retry(&unrelated, false, 288), None);
    }

    #[tokio::test]
    async fn parent_authority_fast_path_is_coherent_and_fail_closed() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/blocks/genesis-v1.json"))
                .expect("genesis fixture");
        let case = fixture["networks"]
            .as_array()
            .expect("networks")
            .iter()
            .find(|case| case["network"] == "regtest")
            .expect("regtest fixture");
        let block = Block::decode(&decode_fixture_hex(
            case["raw"].as_str().expect("raw genesis"),
        ))
        .expect("decode genesis");
        let hash = block.hash();
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            rpc_authorization: Some(
                RpcAuthorizationHeader::new("Bearer test").expect("authorization"),
            ),
            ..NodeConfig::default()
        });
        node.accept_block(NodeBlockImport::from_peer(block, 0))
            .expect("connect genesis");
        let runtime = NodeRuntime::spawn(node, 8).expect("node runtime");
        let node = runtime.read();

        let value = node.parent_authority_value(hash).expect("parent authority");
        assert_eq!(value["network"], "regtest");
        assert_eq!(value["rpc_authentication_required"], true);
        assert_eq!(value["chain"]["bestblockhash"], hash.to_hex());
        assert_eq!(value["header"]["hash"], hash.to_hex());
        assert_eq!(value["header"]["confirmations"], 1);
        assert_eq!(value["authority"]["mode"], "native");
        assert_eq!(value["authority"]["consensus_complete"], true);
        assert_eq!(value["authoritative_mining_tip"], true);
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn active_state_cadence_runs_only_for_a_distinct_stored_frontier() {
        let now = StdInstant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        assert!(!active_state_work_ready(&scheduler));

        let stored = scheduler_tip(7, 1);
        scheduler.set_stored_tip(Some(stored.clone()));
        assert!(active_state_work_ready(&scheduler));

        scheduler.set_active_tip(Some(stored));
        assert!(!active_state_work_ready(&scheduler));

        scheduler.set_stored_tip(Some(scheduler_tip(7, 2)));
        assert!(
            active_state_work_ready(&scheduler),
            "a same-height divergent stored frontier still requires reorg evaluation"
        );
    }

    #[test]
    fn brontide_identity_is_restart_durable_and_private() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-brontide-identity-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let first = load_or_create_brontide_identity(Some(&path)).expect("create identity");
        let second = load_or_create_brontide_identity(Some(&path)).expect("reload identity");
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(
            fs::read(path.join(BRONTIDE_IDENTITY_FILE))
                .expect("identity file")
                .len(),
            32
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path.join(BRONTIDE_IDENTITY_FILE))
                    .expect("identity metadata")
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        fs::remove_dir_all(&path).expect("remove identity fixture");
    }

    fn validator_coinbase_block(height: Height, output_count: usize) -> Block {
        let output = Output {
            value: 0,
            address: Address::new(0, vec![0; 20]).expect("validator fixture address"),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output; output_count],
            locktime: height,
        };
        let mut block = Block {
            header: Header::default(),
            transactions: vec![transaction],
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        block
    }

    fn retain_test_owned_orphan(
        block: Block,
        height: Height,
        scheduler: &mut SyncScheduler,
        orphans: &mut OwnedOrphanPool,
    ) {
        let hash = block.hash();
        scheduler
            .queue_block(hash, height)
            .expect("queue retained orphan body");
        scheduler.begin_local_validation(hash);
        orphans
            .insert(OwnedOrphan { block, height })
            .expect("retain owned orphan body");
        scheduler.complete_orphan_validation();
    }

    fn linked_validator_block(height: Height, parent: &Header) -> Block {
        let mut block = validator_coinbase_block(height, 1);
        block.header.prev_block = parent.hash();
        block.header.time = parent.time.saturating_add(1);
        block.header.bits = Network::Regtest.params().pow.bits;
        while !block.header.verify_pow() {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .expect("regtest nonce space");
        }
        block
    }

    fn active_state_preparation_fixture(block_count: usize) -> NativeActiveStatePlan {
        NativeActiveStatePlan {
            epoch: CanonicalChainEpoch::default(),
            activation: NodeReorg {
                disconnect: Vec::new(),
                connect: (1..=block_count)
                    .map(|height| {
                        let height = Height::try_from(height).expect("fixture height");
                        NodeBlockImport::from_peer(validator_coinbase_block(height, 1), height)
                    })
                    .collect(),
            },
            maximum_connect: block_count.max(1),
            planning_micros: 0,
        }
    }

    fn strict_stored_genesis_service() -> (NodeService, BlockHash) {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/blocks/genesis-v1.json"))
                .expect("genesis fixture");
        let case = fixture["networks"]
            .as_array()
            .expect("networks")
            .iter()
            .find(|case| case["network"] == "regtest")
            .expect("regtest fixture");
        let block = Block::decode(&decode_fixture_hex(
            case["raw"].as_str().expect("raw genesis"),
        ))
        .expect("decode genesis");
        let hash = block.hash();
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            acknowledge_incomplete_consensus: true,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect_active_state: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let header = service
            .native_sync_ensure_genesis_header()
            .expect("genesis header");
        assert_eq!(header.hash, hash);
        service
            .native_sync_store_validated_blocks(vec![(
                ValidatedBlock {
                    sequence: 0,
                    peer: PeerId(1),
                    height: 0,
                    block,
                },
                true,
            )])
            .expect("strict stored genesis body");
        assert_eq!(
            service.state.best_block_tip().expect("active tip"),
            None,
            "storing a validated body must not activate state"
        );
        (service, hash)
    }

    #[tokio::test]
    async fn prepared_activation_matches_serial_activation_and_commits_atomically() {
        let (mut serial, hash) = strict_stored_genesis_service();
        let serial_outcome = serial
            .native_sync_connect_stored_state(1)
            .expect("serial reference activation");
        assert_eq!(serial_outcome.connected, 1);
        assert_eq!(serial_outcome.disconnected, 0);
        assert!(serial_outcome.contextual_failure.is_none());
        let mut serial_evidence = {
            let snapshot = serial.state.store.snapshot().expect("serial snapshot");
            (
                best_block_tip_from_snapshot(&snapshot).expect("serial tip"),
                load_block_index_record(&snapshot, &hash).expect("serial block index"),
                load_header_record(&snapshot, &hash).expect("serial header"),
                mining_generation_from_snapshot(&snapshot).expect("serial mining generation"),
                crate::chain_epoch_from_snapshot(&snapshot).expect("serial chain epoch"),
                crate::load_stored_name_tree_root(&snapshot).expect("serial name root"),
            )
        };

        let (prepared_service, prepared_hash) = strict_stored_genesis_service();
        assert_eq!(prepared_hash, hash);
        let runtime = NodeRuntime::spawn(prepared_service, 8).expect("prepared runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let before = node.canonical_epoch();
        assert!(before.tip.is_none());
        let prepared = execute_native_active_state_slice(node.clone(), writer, 1, None, 4, 8)
            .await
            .expect("prepared activation");
        assert_eq!(prepared.outcome.connected, serial_outcome.connected);
        assert_eq!(prepared.outcome.disconnected, serial_outcome.disconnected);
        assert!(prepared.outcome.contextual_failure.is_none());
        assert_eq!(prepared.preparation.blocks, 1);

        let after = node.canonical_epoch();
        assert_eq!(
            after.chain_epoch,
            before.chain_epoch.checked_add(1).expect("chain epoch"),
            "the complete prepared activation must publish one atomic chain generation"
        );
        assert_eq!(after.tip, serial_evidence.0);
        let mut prepared_evidence = node
            .with_stable_read(|store, _headers| {
                let snapshot = store.snapshot()?;
                Ok((
                    best_block_tip_from_snapshot(&snapshot)?,
                    load_block_index_record(&snapshot, &hash)?,
                    load_header_record(&snapshot, &hash)?,
                    mining_generation_from_snapshot(&snapshot)?,
                    crate::chain_epoch_from_snapshot(&snapshot)?,
                    crate::load_stored_name_tree_root(&snapshot)?,
                ))
            })
            .expect("prepared durable evidence");
        // `validated_at` records the wall-clock second at which each independent
        // service performed validation. Require both paths to populate it, then
        // exclude only that observational timestamp from the exact durable-state
        // equivalence comparison.
        let serial_validated_at = serial_evidence
            .1
            .as_mut()
            .and_then(|record| record.validated_at.take());
        let prepared_validated_at = prepared_evidence
            .1
            .as_mut()
            .and_then(|record| record.validated_at.take());
        assert!(serial_validated_at.is_some());
        assert!(prepared_validated_at.is_some());
        assert_eq!(prepared_evidence, serial_evidence);
        runtime.shutdown().await.expect("prepared runtime shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prepared_activation_replans_after_a_stale_chain_epoch() {
        let (service, hash) = strict_stored_genesis_service();
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let before = node.canonical_epoch();

        let worker_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_paused = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let validator = HnsBodyValidator::new(Network::Regtest);
        let replay = tokio::spawn(execute_native_active_state_slice_with_validator(
            node.clone(),
            writer.clone(),
            1,
            None,
            2,
            4,
            Arc::new({
                let worker_started = Arc::clone(&worker_started);
                let worker_release = Arc::clone(&worker_release);
                let worker_paused = Arc::clone(&worker_paused);
                move |block: &Block, height: Height| {
                    if !worker_paused.swap(true, Ordering::AcqRel) {
                        worker_started.store(true, Ordering::Release);
                        while !worker_release.load(Ordering::Acquire) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                    validator.validate(block, height)
                }
            }),
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !worker_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("prepared worker did not start");

        let competing = writer
            .execute(None, "test competing serial activation", |service| {
                service.native_sync_connect_stored_state(1)
            })
            .await
            .expect("competing activation");
        assert_eq!(competing.connected, 1);
        worker_release.store(true, Ordering::Release);

        let replay = replay
            .await
            .expect("prepared replay task join")
            .expect("prepared replay retry");
        assert_eq!(replay.outcome.connected, 0);
        assert_eq!(replay.outcome.disconnected, 0);
        assert_eq!(replay.preparation.blocks, 1);
        assert_eq!(replay.preparation.stale_retries, 1);
        let after = node.canonical_epoch();
        assert_eq!(after.tip.as_ref().map(|tip| tip.hash), Some(hash));
        assert_eq!(
            after.chain_epoch,
            before.chain_epoch.checked_add(1).expect("chain epoch"),
            "stale prepared work must not publish a duplicate chain mutation"
        );
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[tokio::test]
    async fn stored_byte_worker_failure_is_local_terminal_and_non_mutating() {
        let (service, _hash) = strict_stored_genesis_service();
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let before = node.canonical_epoch();
        let error = execute_native_active_state_slice_with_validator(
            node.clone(),
            writer,
            1,
            None,
            2,
            4,
            Arc::new(|_block: &Block, _height: Height| {
                Err(ValidationRejection::invalid_block(
                    "simulated local stored-byte corruption",
                ))
            }),
        )
        .await
        .expect_err("stored-byte corruption must terminate the replay slice");
        let message = format!("{error:#}");
        assert!(
            message.contains("local stored-body integrity failure"),
            "{message}"
        );
        assert!(
            message.contains("canonical state was not mutated"),
            "{message}"
        );
        assert!(message.contains("no peer is attributable"), "{message}");
        assert_eq!(
            node.canonical_epoch(),
            before,
            "a worker failure must never enter the canonical writer"
        );
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn default_validation_parallelism_tracks_available_processors() {
        let expected_workers = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(MAX_NATIVE_SYNC_VALIDATION_WORKERS);
        let expected_queue = expected_workers
            .saturating_mul(32)
            .clamp(128, MAX_NATIVE_SYNC_VALIDATION_QUEUE);
        let config = NativeSyncConfig::default();
        assert_eq!(config.validation_workers, expected_workers);
        assert_eq!(config.validation_queue, expected_queue);
    }

    #[tokio::test]
    async fn ordered_active_state_preparation_is_multicore_and_order_preserving() {
        const BLOCKS: usize = 12;
        const DELAY: Duration = Duration::from_millis(25);
        let expected = active_state_preparation_fixture(BLOCKS)
            .activation
            .connect
            .iter()
            .map(|import| import.block().hash())
            .collect::<Vec<_>>();

        let serial_validator = HnsBodyValidator::new(Network::Regtest);
        let serial = tokio::time::timeout(
            Duration::from_secs(10),
            prepare_native_active_state_plan_with_validator(
                active_state_preparation_fixture(BLOCKS),
                Network::Regtest,
                1,
                2,
                Arc::new(move |block: &Block, height: Height| {
                    std::thread::sleep(DELAY);
                    serial_validator.validate(block, height)
                }),
            ),
        )
        .await
        .expect("one-worker replay did not deadlock")
        .expect("one-worker replay");

        let parallel_validator = HnsBodyValidator::new(Network::Regtest);
        let parallel = tokio::time::timeout(
            Duration::from_secs(10),
            prepare_native_active_state_plan_with_validator(
                active_state_preparation_fixture(BLOCKS),
                Network::Regtest,
                4,
                2,
                Arc::new(move |block: &Block, height: Height| {
                    std::thread::sleep(DELAY);
                    parallel_validator.validate(block, height)
                }),
            ),
        )
        .await
        .expect("four-worker replay did not deadlock")
        .expect("four-worker replay");

        let actual = parallel
            .activation
            .connect
            .iter()
            .map(|import| import.block().hash())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "prepared activation order changed");
        assert_eq!(parallel.prepared.stateless.len(), BLOCKS);
        assert_eq!(parallel.preparation.blocks, BLOCKS);
        assert_eq!(serial.preparation.maximum_in_flight, 1);
        assert!(
            parallel.preparation.maximum_in_flight >= 2,
            "parallel replay never overlapped workers: {:?}",
            parallel.preparation
        );
        assert!(
            parallel.preparation.wall_micros.saturating_mul(18)
                <= serial.preparation.wall_micros.saturating_mul(10),
            "four-worker replay must be at least 1.8x faster (serial={}us, parallel={}us)",
            serial.preparation.wall_micros,
            parallel.preparation.wall_micros
        );
    }

    #[tokio::test]
    async fn ordered_active_state_preparation_reports_earliest_failure_and_cancels() {
        const BLOCKS: usize = 32;
        let started = Arc::new(AtomicUsize::new(0));
        let validator = HnsBodyValidator::new(Network::Regtest);
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            prepare_native_active_state_plan_with_validator(
                active_state_preparation_fixture(BLOCKS),
                Network::Regtest,
                4,
                2,
                Arc::new({
                    let started = Arc::clone(&started);
                    move |block: &Block, height: Height| {
                        started.fetch_add(1, Ordering::AcqRel);
                        match height {
                            1 => std::thread::sleep(Duration::from_millis(60)),
                            2 => {
                                std::thread::sleep(Duration::from_millis(30));
                                return Err(ValidationRejection::invalid_block(
                                    "earliest stored-byte failure",
                                ));
                            }
                            3 => {
                                return Err(ValidationRejection::invalid_block(
                                    "later stored-byte failure",
                                ));
                            }
                            _ => std::thread::sleep(Duration::from_millis(100)),
                        }
                        validator.validate(block, height)
                    }
                }),
            ),
        )
        .await
        .expect("failing ordered replay did not deadlock")
        .expect_err("stored-byte validation failure must abort preparation");
        let message = format!("{error:#}");
        assert!(message.contains("height 2"), "{message}");
        assert!(
            message.contains("earliest stored-byte failure"),
            "{message}"
        );
        assert!(!message.contains("later stored-byte failure"), "{message}");

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            started.load(Ordering::Acquire) < BLOCKS,
            "cancellation admitted every queued replay block"
        );
    }

    #[test]
    fn native_sync_rejects_authority_modes_and_duplicate_peers() {
        let peer: SocketAddr = "127.0.0.1:14038".parse().expect("peer");
        let config = NativeSyncConfig {
            enabled: true,
            connect: vec![peer],
            ..NativeSyncConfig::default()
        };
        assert!(config
            .validate(AuthorityMode::NativeExperimental, Network::Regtest)
            .is_err());

        let duplicate = NativeSyncConfig {
            connect: vec![peer, peer],
            ..config
        };
        assert!(duplicate
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());
    }

    #[test]
    fn native_sync_requires_a_real_network_endpoint() {
        let config = NativeSyncConfig {
            enabled: true,
            ..NativeSyncConfig::default()
        };
        assert!(config
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let active_without_network = NativeSyncConfig {
            connect_active_state: true,
            ..NativeSyncConfig::default()
        };
        assert!(active_without_network
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let headers_without_network = NativeSyncConfig {
            headers_only: true,
            ..NativeSyncConfig::default()
        };
        assert!(headers_without_network
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let headers_only_active_state = NativeSyncConfig {
            enabled: true,
            headers_only: true,
            connect_active_state: true,
            connect: vec!["127.0.0.1:14038".parse().expect("peer")],
            ..NativeSyncConfig::default()
        };
        assert!(headers_only_active_state
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(1));
        assert_eq!(reconnect_delay(2), Duration::from_secs(2));
        assert_eq!(reconnect_delay(20), Duration::from_secs(60));
    }

    #[test]
    fn native_sync_contention_retry_is_typed_exponential_and_bounded() {
        let busy = anyhow::Error::new(CanonicalWriterError::Busy)
            .context("active-state synchronization failed");
        assert!(canonical_writer_busy(&busy));
        assert!(canonical_writer_contention(&busy));
        assert_eq!(
            active_state_contention_retry_interval(1),
            MIN_NATIVE_SYNC_POLL_INTERVAL
        );
        assert_eq!(
            active_state_contention_retry_interval(2),
            MIN_NATIVE_SYNC_POLL_INTERVAL.saturating_mul(2)
        );
        assert_eq!(
            active_state_contention_retry_interval(3),
            MIN_NATIVE_SYNC_POLL_INTERVAL.saturating_mul(4)
        );
        assert_eq!(
            active_state_contention_retry_interval(usize::MAX),
            MAX_NATIVE_SYNC_CONTENTION_RETRY_INTERVAL
        );

        let stale = anyhow::Error::new(CanonicalWriterError::StaleChainEpoch {
            operation: "test active-state commit",
            expected: CanonicalChainEpoch::default(),
            actual: CanonicalChainEpoch::default(),
        });
        assert!(canonical_writer_contention(&stale));
        let queue_full = anyhow::Error::new(CanonicalWriterError::QueueFull { capacity: 8 });
        assert!(canonical_writer_contention(&queue_full));

        let stopped = anyhow::Error::new(CanonicalWriterError::Stopped)
            .context("active-state synchronization failed");
        assert!(
            !canonical_writer_contention(&stopped),
            "non-transient writer failures must retain the terminal path"
        );
        let shutting_down = anyhow::Error::new(CanonicalWriterError::ShuttingDown);
        assert!(!canonical_writer_contention(&shutting_down));
        assert!(canonical_writer_shutting_down(&shutting_down));
        assert!(!canonical_writer_busy(&anyhow::anyhow!(
            "simulated storage failure"
        )));
    }

    #[test]
    fn only_typed_peer_header_faults_enter_peer_scoring() {
        let queue_full = anyhow::Error::new(CanonicalWriterError::QueueFull { capacity: 8 })
            .context("simulated native-sync writer saturation");
        assert_eq!(peer_header_import_penalty(&queue_full), None);
        assert_eq!(peer_block_header_import_penalty(&queue_full), None);

        let invalid_header = anyhow::Error::new(ConsensusError::InvalidHeader("invalid proof"))
            .context("header validation failed");
        assert_eq!(peer_header_import_penalty(&invalid_header), Some(100));
        assert_eq!(peer_block_header_import_penalty(&invalid_header), Some(50));
        let oversized = anyhow::Error::new(PeerHeaderBatchLimit {
            limit: MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE,
            actual: MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE + 1,
        });
        assert_eq!(peer_header_import_penalty(&oversized), Some(100));

        for local in [
            anyhow::Error::new(StoreError::Backend("fault injection".to_owned()))
                .context("failed to persist header batch"),
            anyhow::Error::new(ConsensusError::View("header lookup failed".to_owned()))
                .context("header validation failed"),
            anyhow::anyhow!("committed header batch differs from staged view"),
        ] {
            assert_eq!(peer_header_import_penalty(&local), None, "{local:#}");
            assert_eq!(peer_block_header_import_penalty(&local), None, "{local:#}");
        }
        let detached = anyhow::Error::new(MissingHeaderParent {
            parent: BlockHash::new([0x44; 32]),
        });
        assert_eq!(peer_header_import_penalty(&detached), None);
    }

    #[test]
    fn tcp_success_refreshes_time_but_only_ready_resets_attempts() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let address: SocketAddr = "8.8.8.8:12038".parse().expect("peer");
        let mut addresses = BoundedAddressBook::new(Network::Mainnet, None, 1).expect("book");
        assert!(addresses
            .insert_discovered(
                keyed_net_address(
                    address,
                    timestamp - HSD_ADDRESS_TIMESTAMP_REFRESH_SECONDS - 1,
                    SERVICE_NETWORK,
                ),
                now,
                timestamp,
            )
            .accepted());
        addresses.note_attempt(address, now, timestamp);
        addresses.note_transport_success(address, timestamp);
        assert_eq!(addresses.entries[&address].wire.time, timestamp);
        assert_eq!(addresses.entries[&address].failures, 1);
        assert_eq!(addresses.entries[&address].last_success, 0);

        addresses.note_success(address, now, timestamp, SERVICE_NETWORK | 2);
        assert_eq!(addresses.entries[&address].failures, 0);
        assert_eq!(addresses.entries[&address].last_success, timestamp);
        assert_eq!(
            addresses.entries[&address].wire.services,
            SERVICE_NETWORK | 2
        );
    }

    #[test]
    fn discovery_uses_pinned_hsd_key_bearing_seeds() {
        assert_eq!(hsd_brontide_seeds(Network::Mainnet).len(), 10);
        assert_eq!(hsd_brontide_seeds(Network::Testnet).len(), 4);
        assert!(hsd_brontide_seeds(Network::Regtest).is_empty());
        assert_eq!(
            decode_compressed_public_key(hsd_brontide_seeds(Network::Mainnet)[0].1)
                .expect("pinned key")[0],
            0x02
        );

        let discovery = NativeSyncConfig {
            enabled: true,
            discovery: true,
            ..NativeSyncConfig::default()
        };
        discovery
            .validate(AuthorityMode::Native, Network::Mainnet)
            .expect("mainnet has HSD Brontide seeds");
        assert!(discovery
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let address = "129.153.177.220:44806".parse().expect("seed socket");
        let mut explicit = NativeSyncConfig {
            enabled: true,
            connect: vec![address],
            ..NativeSyncConfig::default()
        };
        assert!(explicit
            .validate(AuthorityMode::Native, Network::Mainnet)
            .is_err());
        explicit.connect_keys.insert(
            address,
            decode_compressed_public_key(HSD_MAINNET_BRONTIDE_SEEDS[0].1).expect("seed key"),
        );
        explicit
            .validate(AuthorityMode::Native, Network::Mainnet)
            .expect("keyed public peer");
    }

    #[test]
    fn addr_exchange_requires_v3_and_serves_one_inbound_request() {
        assert!(!supports_addr_protocol(2));
        assert!(supports_addr_protocol(3));

        let peer = PeerId(7);
        let mut served = HashSet::new();
        assert!(!admit_getaddr(peer, false, &mut served));
        assert!(served.is_empty());
        assert!(admit_getaddr(peer, true, &mut served));
        assert!(!admit_getaddr(peer, true, &mut served));
        served.remove(&peer);
        assert!(admit_getaddr(peer, true, &mut served));
    }

    #[test]
    fn address_book_record_is_versioned_network_bound_and_checksummed() {
        let record = AddressBookRecord {
            network: Network::Mainnet,
            generation: 7,
            updated_at: 1_800_000_000,
            entries: vec![
                PersistedPeerAddress {
                    address: "8.8.8.8:12038".parse().expect("IPv4 peer"),
                    key: [2; 33],
                    services: SERVICE_NETWORK,
                    time: 1_799_999_900,
                    failures: 2,
                    last_success: 1_799_999_800,
                    last_attempt: 1_799_999_900,
                    sequence: 11,
                },
                PersistedPeerAddress {
                    address: "[2606:4700:4700::1111]:12038".parse().expect("IPv6 peer"),
                    key: [3; 33],
                    services: SERVICE_NETWORK,
                    time: 1_799_999_700,
                    failures: 0,
                    last_success: 1_799_999_700,
                    last_attempt: 1_799_999_700,
                    sequence: 12,
                },
            ],
        };
        let raw = record.encode().expect("encode record");
        assert_eq!(
            raw.len(),
            ADDRESS_BOOK_HEADER_SIZE + 2 * ADDRESS_BOOK_ENTRY_SIZE + ADDRESS_BOOK_CHECKSUM_SIZE
        );
        assert_eq!(
            AddressBookRecord::decode(&raw, Network::Mainnet).expect("decode record"),
            record
        );

        let network_error =
            AddressBookRecord::decode(&raw, Network::Testnet).expect_err("network-bound record");
        assert!(network_error.to_string().contains("network"));

        let mut corrupt = raw.clone();
        corrupt[ADDRESS_BOOK_HEADER_SIZE] ^= 1;
        let checksum_error =
            AddressBookRecord::decode(&corrupt, Network::Mainnet).expect_err("checksummed record");
        assert!(checksum_error.to_string().contains("checksum"));

        let mut unknown_family = raw;
        unknown_family[ADDRESS_BOOK_HEADER_SIZE] = 5;
        let body_len = unknown_family.len() - ADDRESS_BOOK_CHECKSUM_SIZE;
        let checksum = blake2b_256(&unknown_family[..body_len]);
        unknown_family[body_len..].copy_from_slice(&checksum);
        let family_error = AddressBookRecord::decode(&unknown_family, Network::Mainnet)
            .expect_err("known IP family");
        assert!(family_error.to_string().contains("family"));
    }

    #[test]
    fn durable_address_book_round_trips_attempts_and_prunes_hsd_stale_entries() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let configured: SocketAddr = "8.8.4.4:12038".parse().expect("configured peer");
        let valid: SocketAddr = "8.8.8.8:12038".parse().expect("valid peer");
        let stale: SocketAddr = "1.1.1.1:12038".parse().expect("stale peer");
        let store = StoreHandle::memory();
        let mut addresses = BoundedAddressBook::new(Network::Mainnet, None, 4).expect("book");
        addresses
            .insert_configured(configured, now, timestamp)
            .expect("configured address");
        for address in [valid, stale] {
            assert_eq!(
                addresses.insert_discovered(
                    keyed_net_address(address, timestamp - 100, SERVICE_NETWORK,),
                    now,
                    timestamp,
                ),
                AddressAdmission::Added
            );
        }
        {
            let entry = addresses.entries.get_mut(&valid).expect("valid entry");
            entry.failures = 2;
            entry.last_success = timestamp - 200;
            entry.last_attempt = timestamp - 100;
        }
        {
            let entry = addresses.entries.get_mut(&stale).expect("stale entry");
            entry.failures = MAX_DISCOVERY_CONNECT_FAILURES;
            entry.last_attempt = timestamp - HSD_ADDRESS_RECENT_ATTEMPT_SECONDS - 1;
        }

        assert!(persist_address_book(&store, &mut addresses, timestamp).expect("first persist"));
        assert!(!persist_address_book(&store, &mut addresses, timestamp).expect("clean no-op"));
        let raw = store
            .snapshot()
            .expect("snapshot")
            .get(ColumnFamily::Peers, ADDRESS_BOOK_KEY)
            .expect("address-book read")
            .expect("address-book record");
        let record = AddressBookRecord::decode(&raw, Network::Mainnet).expect("decode persisted");
        assert_eq!(record.generation, 1);
        assert_eq!(record.entries.len(), 2);
        assert!(record
            .entries
            .iter()
            .all(|entry| entry.address != configured));

        let mut restored = BoundedAddressBook::new(Network::Mainnet, None, 4).expect("restored");
        let (loaded, pruned) = restored
            .restore(record, now, timestamp)
            .expect("restore record");
        assert_eq!((loaded, pruned), (1, 1));
        assert!(restored.entries.contains_key(&valid));
        assert!(!restored.entries.contains_key(&stale));
        assert_eq!(restored.entries[&valid].failures, 2);
        assert_eq!(restored.entries[&valid].last_success, timestamp - 200);
        assert_eq!(restored.durable_sequence, 1);
        assert!(restored.dirty, "pruning must schedule a compacted flush");

        let mut reconnects = HashMap::new();
        let bans = PeerBanBook::new(Network::Mainnet, 4).expect("bans");
        assert_eq!(
            fill_discovery_slots(&restored, &mut reconnects, &bans, 1, now, timestamp),
            1
        );
        assert_eq!(reconnects[&valid].failures, 2);
        restored.note_attempt(valid, now, timestamp);
        note_reconnect_failure(valid, &mut reconnects, now);
        assert!(
            !reconnects.contains_key(&valid),
            "restored failure history must rotate a target at HSD's limit"
        );

        assert!(persist_address_book(&store, &mut restored, timestamp + 1)
            .expect("persist pruned record"));
        let compacted = store
            .snapshot()
            .expect("compacted snapshot")
            .get(ColumnFamily::Peers, ADDRESS_BOOK_KEY)
            .expect("compacted read")
            .expect("compacted record");
        let compacted =
            AddressBookRecord::decode(&compacted, Network::Mainnet).expect("decode compacted");
        assert_eq!(compacted.generation, 2);
        assert_eq!(compacted.entries.len(), 1);
        assert_eq!(compacted.entries[0].address, valid);
    }

    #[test]
    fn saturated_address_book_keeps_an_exact_logarithmic_eviction_index() {
        const CAPACITY: usize = 64;
        const INSERTIONS: usize = 512;
        let now = Instant::now();
        let timestamp = 1_800_000_000u64;
        let mut addresses =
            BoundedAddressBook::new(Network::Mainnet, None, CAPACITY).expect("address book");

        for index in 0..INSERTIONS {
            let second = u8::try_from(index / (254 * 254)).expect("second octet");
            let third = u8::try_from(index / 254 % 254).expect("third octet");
            let fourth = u8::try_from(index % 254 + 1).expect("fourth octet");
            let address = SocketAddr::from(([23, second, third, fourth], 12_038));
            let wire = keyed_net_address(
                address,
                timestamp.saturating_sub(u64::try_from(index % 32).expect("timestamp delta")),
                SERVICE_NETWORK,
            );
            assert_eq!(
                addresses.insert_discovered(wire, now, timestamp),
                AddressAdmission::Added
            );
            assert_eq!(addresses.len(), (index + 1).min(CAPACITY));
            assert_eq!(addresses.eviction_order.len(), addresses.len());
        }

        let expected = addresses
            .entries
            .iter()
            .map(|(address, entry)| (entry.wire.time, entry.sequence, *address))
            .min()
            .expect("retained eviction candidate");
        assert_eq!(addresses.eviction_order.first().copied(), Some(expected));
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn durable_address_book_survives_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-address-book-reopen-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = hns_store::StoreConfig {
            path: path.clone(),
            backend: hns_store::StoreBackend::RocksDb,
            durability: hns_store::DurabilityPolicy::Sync,
        };
        let address: SocketAddr = "9.9.9.9:12038".parse().expect("peer");
        let timestamp = 1_800_000_000;

        {
            let store = hns_store::open_store(&config).expect("open store");
            let now = Instant::now();
            let mut addresses = BoundedAddressBook::new(Network::Mainnet, None, 4).expect("book");
            assert!(addresses
                .insert_discovered(
                    keyed_net_address(address, timestamp, SERVICE_NETWORK),
                    now,
                    timestamp,
                )
                .accepted());
            addresses.note_attempt(address, now, timestamp);
            assert!(persist_address_book(&store, &mut addresses, timestamp).expect("persist"));
        }

        {
            let store = hns_store::open_store(&config).expect("reopen store");
            let raw = store
                .snapshot()
                .expect("snapshot")
                .get(ColumnFamily::Peers, ADDRESS_BOOK_KEY)
                .expect("address-book read")
                .expect("address-book record");
            let record = AddressBookRecord::decode(&raw, Network::Mainnet).expect("decode record");
            let mut restored =
                BoundedAddressBook::new(Network::Mainnet, None, 4).expect("restored book");
            assert_eq!(
                restored
                    .restore(record, Instant::now(), timestamp)
                    .expect("restore"),
                (1, 0)
            );
            assert_eq!(restored.entries[&address].failures, 1);
            assert_eq!(restored.entries[&address].last_attempt, timestamp);
        }

        std::fs::remove_dir_all(&path).expect("remove test store");
    }

    #[test]
    fn bounded_address_book_applies_hsd_admission_and_eviction_rules() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let mut addresses = BoundedAddressBook::new(Network::Mainnet, None, 2).expect("book");
        let first: SocketAddr = "8.8.8.8:12038".parse().expect("first");
        let second: SocketAddr = "1.1.1.1:12038".parse().expect("second");
        let third: SocketAddr = "9.9.9.9:12038".parse().expect("third");

        let mut first_wire = keyed_net_address(
            first,
            timestamp + MAX_ADDR_FUTURE_SECONDS + 1,
            SERVICE_NETWORK,
        );
        assert_eq!(
            addresses.insert_discovered(first_wire.clone(), now, timestamp),
            AddressAdmission::Added
        );
        assert_eq!(
            addresses.entries[&first].wire.time,
            timestamp - FALLBACK_ADDR_AGE_SECONDS
        );

        first_wire.services = 0;
        assert_eq!(
            addresses.insert_discovered(first_wire, now, timestamp),
            AddressAdmission::Rejected
        );
        let private = keyed_net_address(
            "192.168.1.1:12038".parse().expect("private"),
            timestamp,
            SERVICE_NETWORK,
        );
        assert_eq!(
            addresses.insert_discovered(private, now, timestamp),
            AddressAdmission::Rejected
        );
        let mut keyed = keyed_net_address(second, timestamp, SERVICE_NETWORK);
        keyed.key[0] = 1;
        assert_eq!(
            addresses.insert_discovered(keyed, now, timestamp),
            AddressAdmission::Rejected
        );

        assert!(addresses
            .insert_discovered(
                keyed_net_address(second, timestamp - 2, SERVICE_NETWORK),
                now,
                timestamp,
            )
            .accepted());
        assert!(addresses
            .insert_discovered(
                keyed_net_address(third, timestamp - 1, SERVICE_NETWORK),
                now,
                timestamp,
            )
            .accepted());
        assert_eq!(addresses.len(), 2);
        assert!(!addresses.entries.contains_key(&first));
        assert!(addresses.entries.contains_key(&second));
        assert!(addresses.entries.contains_key(&third));
        let bans = PeerBanBook::new(Network::Mainnet, 4).expect("bans");
        assert_eq!(addresses.advertised(1, &bans, timestamp).len(), 1);
    }

    #[test]
    fn failed_discovery_targets_rotate_without_displacing_configured_peers() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let configured: SocketAddr = "127.0.0.1:14038".parse().expect("configured");
        let mut addresses = BoundedAddressBook::new(Network::Regtest, None, 4).expect("book");
        addresses
            .insert_configured(configured, now, timestamp)
            .expect("configured address");
        for value in [1, 2, 3] {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, value)), 14038);
            assert!(addresses
                .insert_discovered(
                    keyed_net_address(address, timestamp, SERVICE_NETWORK),
                    now,
                    timestamp,
                )
                .accepted());
        }
        let mut reconnects = HashMap::from([(configured, ReconnectState::new(now, true))]);
        let bans = PeerBanBook::new(Network::Regtest, 4).expect("bans");
        assert_eq!(
            fill_discovery_slots(&addresses, &mut reconnects, &bans, 2, now, timestamp),
            1
        );
        let discovered = reconnects
            .iter()
            .find_map(|(address, state)| (!state.persistent).then_some(*address))
            .expect("discovered target");
        let state = reconnects.get_mut(&discovered).expect("discovered state");
        state.failed(now);
        state.transport_connected(now);
        assert_eq!(state.failures, 1, "TCP alone is not a successful peer");
        state.ready(now);
        assert_eq!(state.failures, 0, "a ready handshake resets failures");
        for _ in 0..MAX_DISCOVERY_CONNECT_FAILURES {
            addresses.note_attempt(discovered, now, timestamp);
            note_reconnect_failure(discovered, &mut reconnects, now);
        }
        assert!(!reconnects.contains_key(&discovered));
        assert!(reconnects.contains_key(&configured));
        assert_eq!(
            fill_discovery_slots(&addresses, &mut reconnects, &bans, 2, now, timestamp),
            1
        );
        assert_eq!(reconnects.len(), 2);
        assert!(!reconnects.contains_key(&discovered));
    }

    #[test]
    fn outbound_selection_enforces_hsd_groups_without_overriding_explicit_peers() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let explicit: SocketAddr = "8.8.4.4:12038".parse().expect("explicit peer");
        let same_group: SocketAddr = "8.8.200.1:12038".parse().expect("same group");
        let second_group: SocketAddr = "9.9.9.9:12038".parse().expect("second group");
        let third_group: SocketAddr = "1.1.1.1:12038".parse().expect("third group");
        let mut addresses = BoundedAddressBook::new(Network::Mainnet, None, 8).expect("book");
        addresses
            .insert_configured(explicit, now, timestamp)
            .expect("configured address");
        for address in [same_group, second_group, third_group] {
            assert!(addresses
                .insert_discovered(
                    keyed_net_address(address, timestamp, SERVICE_NETWORK),
                    now,
                    timestamp,
                )
                .accepted());
        }

        let bans = PeerBanBook::new(Network::Mainnet, 8).expect("bans");
        let mut reconnects = HashMap::from([(explicit, ReconnectState::new(now, true))]);
        assert_eq!(
            fill_discovery_slots(&addresses, &mut reconnects, &bans, 3, now, timestamp),
            2
        );
        assert!(!reconnects.contains_key(&same_group));
        assert!(reconnects.contains_key(&second_group));
        assert!(reconnects.contains_key(&third_group));
        assert_eq!(
            take_due_connection_targets(&mut reconnects, &bans, now, timestamp, 3),
            vec![explicit, third_group, second_group]
        );

        let mut explicit_reconnects = HashMap::from([
            (explicit, ReconnectState::new(now, true)),
            (same_group, ReconnectState::new(now, true)),
        ]);
        assert_eq!(
            take_due_connection_targets(&mut explicit_reconnects, &bans, now, timestamp, 2),
            vec![explicit, same_group],
            "configured peers must retain operator-selected priority"
        );

        let mut discovered_reconnects = HashMap::from([
            (explicit, ReconnectState::new(now, false)),
            (same_group, ReconnectState::new(now, false)),
            (second_group, ReconnectState::new(now, false)),
        ]);
        assert_eq!(
            take_due_connection_targets(&mut discovered_reconnects, &bans, now, timestamp, 3),
            vec![explicit, second_group],
            "simultaneous discovered attempts must reserve unique groups"
        );
    }

    #[tokio::test]
    async fn compact_block_requests_missing_transactions_over_peer_and_reconstructs() {
        assert_eq!(
            COMPACT_BLOCK_RESPONSE_TIMEOUT,
            Duration::from_secs(30),
            "HSD disconnects a peer after a 30-second blocktxn stall"
        );
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis header");
        let mut block = linked_validator_block(1, &genesis.header);
        block.transactions.push(Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([0x44; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: block.transactions[0].outputs.clone(),
            locktime: 0,
        });
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        block.header.nonce = 0;
        while !block.header.verify_pow() {
            block.header.nonce = block.header.nonce.checked_add(1).expect("regtest nonce");
        }
        service
            .native_sync_import_headers(vec![block.header.clone()])
            .expect("block header");
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let accepted = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let (peers, _events) = LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest))
            .expect("peer manager");
        let peer = peers.connect(address).await.expect("connect");
        let server = accepted.await.expect("accept task");
        let mut reader = hns_p2p::AsyncFrameReader::new(server, hns_p2p::NetworkMagic::Regtest);
        assert!(matches!(
            reader.read_packet().await.expect("version packet"),
            Packet::Version(_)
        ));

        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        scheduler
            .register_peer(peer, SERVICE_NETWORK, 1)
            .expect("register peer");
        scheduler
            .announce_block(peer, block.hash(), 1)
            .expect("announce block");
        let (validation, mut results) =
            spawn_validation_pipeline(Arc::new(HnsBodyValidator::new(Network::Regtest)), 1, 8)
                .expect("validation pipeline");
        let compact = CompactBlock::from_block_with_nonce(&block, [1, 2, 3, 4, 5, 6, 7, 8]);
        let compact_peers = HashSet::from([peer]);
        let mut pending = HashMap::new();
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));

        handle_compact_block(
            peer,
            compact,
            &node,
            &writer,
            &peers,
            &validation,
            &mut scheduler,
            &compact_peers,
            &mut pending,
            false,
            &diagnostics,
        )
        .await
        .expect("partial compact block");
        assert_eq!(pending.len(), 1);
        let request = match tokio::time::timeout(Duration::from_secs(1), reader.read_packet())
            .await
            .expect("getblocktxn timeout")
            .expect("getblocktxn packet")
        {
            Packet::GetBlockTxn(request) => request,
            packet => panic!("expected getblocktxn, got {packet:?}"),
        };
        assert_eq!(request.block_hash, block.hash());
        assert_eq!(request.indexes, vec![1]);

        let response = CompactBlockResponse::from_block(&block, &request);
        handle_block_transactions(
            PeerId(u64::MAX),
            response.clone(),
            &node,
            &writer,
            &peers,
            &validation,
            &mut scheduler,
            &mut pending,
            &diagnostics,
        )
        .await
        .expect("ignore another peer's blocktxn response");
        assert_eq!(pending.len(), 1);

        handle_block_transactions(
            peer,
            response,
            &node,
            &writer,
            &peers,
            &validation,
            &mut scheduler,
            &mut pending,
            &diagnostics,
        )
        .await
        .expect("blocktxn response");
        assert!(pending.is_empty());
        let validated = tokio::time::timeout(Duration::from_secs(1), results.recv())
            .await
            .expect("validation timeout")
            .expect("validation result")
            .expect("valid reconstructed block");
        assert_eq!(validated.block, block);
        let state = diagnostics.read().await.clone();
        assert_eq!(state.received_compact_blocks, 1);
        assert_eq!(state.reconstructed_compact_blocks, 1);
        assert_eq!(state.received_blocks, 1);
        assert_eq!(state.compact_block_fallbacks, 0);

        peers.disconnect_all().await;
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn banned_ips_are_not_discovered_reconnected_or_advertised() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let banned: SocketAddr = "10.0.0.1:14038".parse().expect("banned peer");
        let allowed: SocketAddr = "10.0.0.2:14038".parse().expect("allowed peer");
        let configured: SocketAddr = "10.0.0.1:15038".parse().expect("configured peer");
        let mut addresses = BoundedAddressBook::new(Network::Regtest, None, 4).expect("book");
        addresses
            .insert_configured(configured, now, timestamp)
            .expect("configured address");
        for address in [banned, allowed] {
            assert!(addresses
                .insert_discovered(
                    keyed_net_address(address, timestamp, SERVICE_NETWORK),
                    now,
                    timestamp,
                )
                .accepted());
        }

        let mut bans = PeerBanBook::new(Network::Regtest, 4).expect("bans");
        bans.ban(&hns_p2p::PeerBan {
            address: banned.ip(),
            banned_at: timestamp,
            ban_until: timestamp + HSD_BAN_TIME_SECONDS,
            score: HSD_BAN_SCORE as i32,
        })
        .expect("ban");

        let mut reconnects = HashMap::from([(configured, ReconnectState::new(now, true))]);
        assert_eq!(
            fill_discovery_slots(&addresses, &mut reconnects, &bans, 2, now, timestamp),
            1
        );
        assert_eq!(reconnects.len(), 2);
        assert!(reconnects.contains_key(&configured));
        assert!(reconnects.contains_key(&allowed));
        assert!(!reconnects.contains_key(&banned));
        assert_eq!(
            take_due_connection_targets(&mut reconnects, &bans, now, timestamp, 1),
            vec![allowed]
        );
        reconnects
            .get_mut(&allowed)
            .expect("allowed target")
            .connecting = false;
        assert_eq!(
            take_due_connection_targets(
                &mut reconnects,
                &bans,
                now,
                timestamp + HSD_BAN_TIME_SECONDS + 1,
                1,
            ),
            vec![configured],
            "the explicit target must regain priority after its ban expires"
        );
        let advertised = addresses.advertised(4, &bans, timestamp);
        assert!(advertised.iter().all(|address| address
            .socket_addr()
            .is_some_and(|address| address.ip() != banned.ip())));

        assert_eq!(addresses.remove_discovered_ip(banned.ip()), 1);
        assert!(addresses.entries.contains_key(&configured));
        assert!(!addresses.entries.contains_key(&banned));
    }

    #[tokio::test]
    async fn threshold_peer_ban_is_applied_flushed_and_restored() {
        let timestamp = unix_time();
        let now = Instant::now();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let accepted = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let (manager, _events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest)).expect("manager");
        let peer = manager.connect(address).await.expect("connect");
        let server = accepted.await.expect("accept task");

        let store = StoreHandle::memory();
        let mut bans = PeerBanBook::new(Network::Regtest, 4).expect("bans");
        let mut addresses = BoundedAddressBook::new(Network::Regtest, None, 4).expect("book");
        assert!(addresses
            .insert_discovered(
                keyed_net_address(address, timestamp, SERVICE_NETWORK),
                now,
                timestamp,
            )
            .accepted());
        let mut reconnects = HashMap::from([(address, ReconnectState::new(now, false))]);
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));

        assert_eq!(
            manager.penalize(peer, HSD_BAN_SCORE).await.expect("ban"),
            100
        );
        maintain_peer_bans(
            &store,
            &manager,
            &mut bans,
            &mut addresses,
            &mut reconnects,
            &diagnostics,
            true,
        )
        .await;

        assert!(bans.is_banned(address.ip(), timestamp));
        assert!(!addresses.entries.contains_key(&address));
        assert!(!reconnects.contains_key(&address));
        let state = diagnostics.read().await.clone();
        assert_eq!(state.ban_events, 1);
        assert_eq!(state.ban_list_flushes, 1);
        assert_eq!(state.banned_addresses, 1);
        assert!(!state.ban_list_dirty);
        let restored = load_peer_bans(&store, Network::Regtest, 4, unix_time()).expect("restore");
        assert_eq!((restored.loaded, restored.pruned), (1, 0));
        assert!(restored.book.is_banned(address.ip(), unix_time()));

        drop(server);
        manager.disconnect_all().await;
    }

    #[test]
    fn body_validator_only_marks_header_committed_invalidity_permanent() {
        let validator = HnsBodyValidator::new(Network::Regtest);
        let mut committed_invalid = Block {
            header: Header::default(),
            transactions: Vec::new(),
        };
        committed_invalid.header.merkle_root = block_merkle_root(&committed_invalid);
        committed_invalid.header.witness_root = block_witness_root(&committed_invalid);
        assert_eq!(
            validator
                .validate(&committed_invalid, 1)
                .expect_err("committed invalid block")
                .kind,
            ValidationFailureKind::InvalidBlock
        );

        let mut mismatched_response = committed_invalid;
        mismatched_response.header.merkle_root = [0x55; 32];
        assert_eq!(
            validator
                .validate(&mismatched_response, 1)
                .expect_err("mismatched body response")
                .kind,
            ValidationFailureKind::InvalidResponse
        );
    }

    #[test]
    fn body_validator_marks_always_on_height_rules_permanent() {
        let pre_start = validator_coinbase_block(2_015, 2);
        let rejection = HnsBodyValidator::new(Network::Mainnet)
            .validate(&pre_start, 2_015)
            .expect_err("special issuance before mainnet txStart");
        assert_eq!(rejection.kind, ValidationFailureKind::InvalidBlock);
        assert!(rejection.reason.contains("network tx start"));

        let wrong_height = validator_coinbase_block(2, 1);
        let rejection = HnsBodyValidator::new(Network::Regtest)
            .validate(&wrong_height, 1)
            .expect_err("wrong coinbase height");
        assert_eq!(rejection.kind, ValidationFailureKind::InvalidBlock);
        assert!(rejection.reason.contains("coinbase height"));
    }

    #[test]
    fn body_validator_defers_historical_sanity_to_checkpoint_bound_import() {
        let historical_height = Network::Mainnet.params().tx_start;
        let mut historical = validator_coinbase_block(historical_height, 1);
        historical.transactions[0].inputs[0].previous_output = Outpoint {
            txid: Txid::new([0x44; 32]),
            index: 0,
        };
        historical.header.merkle_root = block_merkle_root(&historical);
        historical.header.witness_root = block_witness_root(&historical);
        HnsBodyValidator::new(Network::Mainnet)
            .validate(&historical, historical_height)
            .expect("historical worker retains commitments, limits, and height rules");

        let current_height = Network::Mainnet.last_checkpoint() + 1;
        let mut current = historical;
        current.transactions[0].locktime = current_height;
        current.header.merkle_root = block_merkle_root(&current);
        current.header.witness_root = block_witness_root(&current);
        let rejection = HnsBodyValidator::new(Network::Mainnet)
            .validate(&current, current_height)
            .expect_err("post-checkpoint body sanity remains mandatory");
        assert_eq!(rejection.kind, ValidationFailureKind::InvalidBlock);
        assert!(rejection
            .reason
            .contains("first transaction is not coinbase"));
    }

    #[tokio::test]
    async fn canonical_body_is_stored_out_of_parent_body_order() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let first = linked_validator_block(1, &genesis.header);
        let second = linked_validator_block(2, &first.header);
        service
            .native_sync_import_headers(vec![first.header.clone(), second.header.clone()])
            .expect("canonical headers");
        let second_hash = second.hash();
        let first_hash = first.hash();
        let ordinary_error = service
            .accept_block(NodeBlockImport::from_peer(second.clone(), 2))
            .expect_err("ordinary import still requires the parent body");
        assert!(ordinary_error.to_string().contains("parent index"));
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();

        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest))
                .expect("peer manager");
        let (_validation, _validation_results) =
            spawn_validation_pipeline(Arc::new(HnsBodyValidator::new(Network::Regtest)), 1, 8)
                .expect("validation pipeline");
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        scheduler
            .queue_block(second_hash, 2)
            .expect("second body reservation");
        scheduler.begin_local_validation(second_hash);
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: 8,
            maximum_bytes: 1_024 * 1_024,
        })
        .expect("orphan pool");
        let mut ready_orphan_parents = ReadyOrphanParents::new(8);
        let mut deferred_orphan_discards = DeferredOrphanDiscards::new(8);
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));

        let context = ValidationResultContext {
            node: &node,
            writer: &writer,
            peers: &peers,
            diagnostics: &diagnostics,
        };
        handle_validation_results(
            vec![Ok(hns_sync::ValidatedBlock {
                sequence: 0,
                peer: PeerId(1),
                height: 2,
                block: second,
            })],
            &context,
            &mut scheduler,
            &mut orphans,
            &mut ready_orphan_parents,
            &mut deferred_orphan_discards,
        )
        .await
        .expect("store out-of-order canonical body");

        assert!(node
            .native_sync_has_block(&second_hash)
            .expect("second body lookup"));
        assert!(!node
            .native_sync_has_block(&first_hash)
            .expect("first body lookup"));
        assert_eq!(
            node.native_sync_contiguous_body_tip(None)
                .expect("contiguous body tip"),
            None
        );
        assert!(!scheduler.is_tracked_block(&second_hash));
        assert_eq!(orphans.snapshot().blocks, 0);
        assert_eq!(diagnostics.read().await.stored_bodies, 1);
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[tokio::test]
    async fn split_validation_runs_share_one_32_unit_orphan_budget() {
        const CHILDREN_PER_PARENT: Height = 20;
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let first = linked_validator_block(1, &genesis.header);
        let second = linked_validator_block(2, &first.header);
        service
            .native_sync_import_headers(vec![first.header.clone(), second.header.clone()])
            .expect("canonical headers");
        let first_hash = first.hash();
        let second_hash = second.hash();
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest))
                .expect("peer manager");
        let (validation, _validation_results) =
            spawn_validation_pipeline(Arc::new(AcceptAllBlocks), 1, 64)
                .expect("validation pipeline");
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));
        let context = ValidationResultContext {
            node: &node,
            writer: &writer,
            peers: &peers,
            diagnostics: &diagnostics,
        };
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        for (hash, height) in [(first_hash, 1), (second_hash, 2)] {
            scheduler
                .queue_block(hash, height)
                .expect("parent body work");
            scheduler.begin_local_validation(hash);
        }
        let failure_block = validator_coinbase_block(500, 2);
        let failure_hash = failure_block.hash();
        scheduler
            .queue_block(failure_hash, 500)
            .expect("worker-failure body work");
        scheduler.begin_local_validation(failure_hash);

        let orphan_count =
            usize::try_from(CHILDREN_PER_PARENT.saturating_mul(2)).expect("orphan fixture count");
        let mut orphans = OwnedOrphanPool::new(OrphanLimits {
            maximum_blocks: orphan_count,
            maximum_bytes: 4_000_000,
        })
        .expect("orphan pool");
        for (ordinal, parent) in [first_hash, second_hash]
            .into_iter()
            .flat_map(|parent| (0..CHILDREN_PER_PARENT).map(move |ordinal| (ordinal, parent)))
        {
            let height = 100u32
                .saturating_add(ordinal)
                .saturating_add(if parent == second_hash { 100 } else { 0 });
            let mut child = validator_coinbase_block(height, 1);
            child.header.prev_block = parent;
            retain_test_owned_orphan(child, height, &mut scheduler, &mut orphans);
        }
        let mut ready = ReadyOrphanParents::new(orphan_count);
        let mut discards = DeferredOrphanDiscards::new(orphan_count);
        let result = handle_validation_results(
            vec![
                Ok(ValidatedBlock {
                    sequence: 0,
                    peer: PeerId(1),
                    height: 1,
                    block: first,
                }),
                Err(ValidationFailure {
                    sequence: 1,
                    peer: PeerId(1),
                    height: 500,
                    attempt: 1,
                    block: failure_block,
                    kind: ValidationFailureKind::WorkerFailure,
                    reason: "split valid runs".to_owned(),
                }),
                Ok(ValidatedBlock {
                    sequence: 2,
                    peer: PeerId(1),
                    height: 2,
                    block: second,
                }),
            ],
            &context,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
        )
        .await;
        let error = result.expect_err("worker failure remains a warning result");
        assert!(!terminal_validation_error(&error));
        assert_eq!(ready.len(), 2);

        let mut schedule = OrphanWorkSchedule::default();
        let spent = drain_orphan_work(
            MAX_VALIDATED_BODY_COMMIT_BATCH,
            &validation,
            &mut scheduler,
            &mut orphans,
            &mut ready,
            &mut discards,
            &mut schedule,
        )
        .expect("one supervisor orphan budget");
        assert_eq!(spent, MAX_VALIDATED_BODY_COMMIT_BATCH);
        assert_eq!(orphans.snapshot().blocks, orphan_count - spent);
        assert_eq!(ready.len(), 2);
        assert_orphan_work_membership_exact(&orphans, &ready, &discards);
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn body_present_index_without_raw_payload_is_not_available() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let block = linked_validator_block(1, &genesis.header);
        let hash = block.hash();
        service
            .native_sync_import_headers(vec![block.header.clone()])
            .expect("canonical header");
        service
            .native_sync_store_validated_blocks(vec![(
                ValidatedBlock {
                    sequence: 0,
                    peer: PeerId(1),
                    height: 1,
                    block,
                },
                true,
            )])
            .expect("stored body");
        assert!(service
            .native_sync_has_block(&hash)
            .expect("complete body availability"));

        let mut batch = service.state.store.batch();
        batch
            .delete(ColumnFamily::Blocks, hash.as_bytes())
            .expect("delete raw payload");
        service
            .state
            .store
            .commit(batch)
            .expect("commit missing raw payload");

        assert!(
            !service
                .native_sync_has_block(&hash)
                .expect("missing raw payload availability"),
            "body_present metadata alone must never suppress redownload"
        );
    }

    #[test]
    fn validated_body_batch_is_all_or_nothing_before_durable_commit() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let first = linked_validator_block(1, &genesis.header);
        let second = linked_validator_block(2, &first.header);
        let first_hash = first.hash();
        let second_hash = second.hash();
        service
            .native_sync_import_headers(vec![first.header.clone(), second.header.clone()])
            .expect("canonical headers");

        let invalid_batch = vec![
            (
                ValidatedBlock {
                    sequence: 0,
                    peer: PeerId(1),
                    height: 1,
                    block: first.clone(),
                },
                true,
            ),
            (
                ValidatedBlock {
                    sequence: 1,
                    peer: PeerId(1),
                    height: 3,
                    block: second.clone(),
                },
                true,
            ),
        ];
        service
            .native_sync_store_validated_blocks(invalid_batch)
            .expect_err("one mismatched member rejects the complete batch");
        assert!(!service
            .native_sync_has_block(&first_hash)
            .expect("first body after rejected batch"));
        assert!(!service
            .native_sync_has_block(&second_hash)
            .expect("second body after rejected batch"));

        let stored = service
            .native_sync_store_validated_blocks(vec![
                (
                    ValidatedBlock {
                        sequence: 0,
                        peer: PeerId(1),
                        height: 1,
                        block: first,
                    },
                    true,
                ),
                (
                    ValidatedBlock {
                        sequence: 1,
                        peer: PeerId(1),
                        height: 2,
                        block: second,
                    },
                    true,
                ),
            ])
            .expect("valid body batch");
        assert_eq!(
            stored.iter().map(|record| record.hash).collect::<Vec<_>>(),
            vec![first_hash, second_hash]
        );
        assert!(service
            .native_sync_has_block(&first_hash)
            .expect("first stored body"));
        assert!(service
            .native_sync_has_block(&second_hash)
            .expect("second stored body"));
    }

    #[test]
    fn ambiguous_name_page_fence_blocks_native_header_body_and_compaction_writes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-native-name-page-fence-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let mut state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("pages"),
        );
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        node.state
            .name_pages
            .as_mut()
            .expect("page storage")
            .fence_after_commit_attempt();
        node.fail_closed_after_ambiguous_commit();

        let params = Network::Regtest.params();
        let header_error = node
            .native_sync_import_headers(vec![params.genesis_header()])
            .expect_err("fenced header persistence");
        assert!(
            header_error.to_string().contains("restart and reopen"),
            "{header_error}"
        );
        assert!(node
            .state
            .chain
            .load_record(&params.genesis_hash)
            .expect("genesis header lookup")
            .is_none());

        let alternate = linked_validator_block(1, &params.genesis_header());
        let alternate_hash = alternate.hash();
        let body_error = node
            .native_sync_store_validated_blocks(vec![(
                ValidatedBlock {
                    sequence: 0,
                    peer: PeerId(1),
                    height: 1,
                    block: alternate,
                },
                true,
            )])
            .expect_err("fenced alternate-body persistence");
        assert!(
            body_error.to_string().contains("restart and reopen"),
            "{body_error}"
        );
        assert!(node
            .native_sync_block(&alternate_hash)
            .expect("alternate body lookup")
            .is_none());

        let compaction_error = node
            .compact_name_tree_nodes()
            .expect_err("fenced public compaction");
        assert!(
            compaction_error.to_string().contains("restart and reopen"),
            "{compaction_error}"
        );

        drop(node);
        fs::remove_dir_all(directory).expect("remove native fence fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn out_of_order_canonical_body_survives_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-native-out-of-order-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = NodeConfig {
            network: Network::Regtest,
            data_dir: Some(path.clone()),
            authority_mode: AuthorityMode::Native,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        };
        let second_hash;
        let first_hash;

        {
            let mut service = NodeService::try_new(config.clone()).expect("open first node");
            let genesis = service
                .native_sync_ensure_genesis_header()
                .expect("genesis");
            let first = linked_validator_block(1, &genesis.header);
            let second = linked_validator_block(2, &first.header);
            second_hash = second.hash();
            first_hash = first.hash();
            service
                .native_sync_import_headers(vec![first.header.clone(), second.header.clone()])
                .expect("canonical headers");
            service
                .native_sync_store_validated_blocks(vec![(
                    ValidatedBlock {
                        sequence: 0,
                        peer: PeerId(1),
                        height: 2,
                        block: second,
                    },
                    true,
                )])
                .expect("store out-of-order canonical body");
            mark_clean_shutdown(&service.state.store).expect("clean first shutdown");
        }

        {
            let service = NodeService::try_new(config).expect("reopen node");
            assert!(service
                .native_sync_has_block(&second_hash)
                .expect("reopened second body"));
            assert!(!service
                .native_sync_has_block(&first_hash)
                .expect("reopened first body"));
            mark_clean_shutdown(&service.state.store).expect("clean second shutdown");
        }

        std::fs::remove_dir_all(&path).expect("remove test store");
    }

    #[test]
    fn native_header_slice_validation_is_atomic() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let params = Network::Regtest.params();
        let mut first = Header {
            prev_block: genesis.hash,
            time: genesis.header.time + 1,
            bits: params.pow.bits,
            ..Header::default()
        };
        while !first.verify_pow() {
            first.nonce = first.nonce.checked_add(1).expect("regtest nonce space");
        }
        let first_hash = first.hash();
        let mut invalid_second = Header {
            prev_block: first_hash,
            time: 0,
            bits: params.pow.bits,
            ..Header::default()
        };
        while !invalid_second.verify_pow() {
            invalid_second.nonce = invalid_second
                .nonce
                .checked_add(1)
                .expect("regtest nonce space");
        }

        service
            .native_sync_import_headers(vec![first, invalid_second])
            .expect_err("late invalid header rejects the slice");

        assert_eq!(
            service
                .native_sync_best_header_tip()
                .expect("best header")
                .expect("tip")
                .hash,
            genesis.hash
        );
        assert_eq!(
            service
                .native_sync_header_record(&first_hash)
                .expect("first header lookup"),
            None
        );
    }

    #[test]
    fn detached_live_header_is_classified_without_mutating_the_header_tip() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let parent = BlockHash::new([0x91; 32]);
        let error = service
            .native_sync_import_headers(vec![Header {
                prev_block: parent,
                ..Header::default()
            }])
            .expect_err("detached live header");
        assert_eq!(
            error.downcast_ref::<MissingHeaderParent>(),
            Some(&MissingHeaderParent { parent })
        );
        let tip = service
            .native_sync_best_header_tip()
            .expect("best header")
            .expect("tip");
        assert_eq!(tip.hash, genesis.hash);
        assert_eq!(tip.height, genesis.height);
        assert_eq!(tip.chainwork, genesis.chainwork);
    }

    #[tokio::test]
    async fn maximum_header_packet_imports_as_one_durable_batch() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let params = Network::Regtest.params();
        let mut previous = genesis.header;
        let mut headers = Vec::new();
        for _ in 0..MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE {
            let mut header = Header {
                prev_block: previous.hash(),
                time: previous.time + 1,
                bits: params.pow.bits,
                ..Header::default()
            };
            while !header.verify_pow() {
                header.nonce = header.nonce.checked_add(1).expect("regtest nonce space");
            }
            previous = header.clone();
            headers.push(header);
        }
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();

        let imported = import_header_packet(&writer, headers)
            .await
            .expect("maximum header packet");
        assert_eq!(imported.len(), MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE);

        assert_eq!(
            node.native_sync_best_header_tip()
                .expect("best header")
                .expect("durable imported tip")
                .height as usize,
            MAX_NATIVE_SYNC_HEADER_IMPORT_SLICE
        );
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[tokio::test]
    async fn canonical_body_queue_is_bounded_to_orphan_horizon() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                orphan_blocks: 2,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..NativeSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let params = Network::Regtest.params();
        let mut previous = genesis.header;
        let mut headers = Vec::new();
        for _ in 0..4 {
            let mut header = Header {
                prev_block: previous.hash(),
                time: previous.time + 1,
                bits: params.pow.bits,
                ..Header::default()
            };
            while !header.verify_pow() {
                header.nonce = header.nonce.checked_add(1).expect("regtest nonce space");
            }
            previous = header.clone();
            headers.push(header);
        }
        service
            .native_sync_import_headers(headers)
            .expect("canonical headers");
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();

        let now = StdInstant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), hns_p2p::SERVICE_NETWORK, 4)
            .expect("peer");
        scheduler.set_best_header(node.native_sync_best_header_tip().expect("best header"));
        assert_eq!(
            node.native_sync_queue_missing_canonical_bodies(&mut scheduler)
                .expect("body queue"),
            2
        );
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 2);
        assert_eq!(snapshot.tracked_blocks, 2);

        let requested = scheduler
            .poll(now, &[])
            .into_iter()
            .filter_map(|action| match action {
                SyncAction::RequestBlock(request) => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            requested
                .iter()
                .map(|request| request.height)
                .collect::<Vec<_>>(),
            vec![0]
        );
        scheduler
            .receive_block(PeerId(1), requested[0].hash, now + Duration::from_millis(1))
            .expect("body probe");
        scheduler.complete_block(requested[0].hash);
        let expanded = scheduler
            .poll(now + Duration::from_millis(1), &[])
            .into_iter()
            .filter_map(|action| match action {
                SyncAction::RequestBlock(request) => Some(request.height),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(expanded, vec![1]);
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn block_download_actions_batch_by_peer_without_crossing_action_boundaries() {
        let first_peer = PeerId(1);
        let second_peer = PeerId(2);
        let request = |peer, byte, height| BlockDownloadRequest {
            hash: BlockHash::new([byte; 32]),
            height,
            peer: Some(peer),
            attempt: 1,
        };
        let actions = vec![
            SyncAction::RequestHeaders {
                peer: first_peer,
                locator: vec![BlockHash::new([9; 32])],
                stop: BlockHash::ZERO,
            },
            SyncAction::RequestBlock(request(first_peer, 1, 1)),
            SyncAction::RequestBlock(request(second_peer, 2, 2)),
            SyncAction::RequestBlock(request(first_peer, 3, 3)),
            SyncAction::PersistCheckpoint,
        ];

        let dispatches = batch_sync_actions(actions).expect("batched actions");
        assert_eq!(dispatches.len(), 4);
        assert!(matches!(
            &dispatches[0],
            SyncDispatch::Action(SyncAction::RequestHeaders { peer, .. })
                if *peer == first_peer
        ));
        assert!(matches!(
            &dispatches[1],
            SyncDispatch::BlockBatch { peer, requests }
                if *peer == first_peer
                    && requests.iter().map(|request| request.height).collect::<Vec<_>>()
                        == vec![1, 3]
        ));
        assert!(matches!(
            &dispatches[2],
            SyncDispatch::BlockBatch { peer, requests }
                if *peer == second_peer
                    && requests.iter().map(|request| request.height).collect::<Vec<_>>()
                        == vec![2]
        ));
        assert!(matches!(
            &dispatches[3],
            SyncDispatch::Action(SyncAction::PersistCheckpoint)
        ));
    }

    #[tokio::test]
    async fn canonical_headers_derive_hsd_deployment_and_script_policy() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .native_sync_ensure_genesis_header()
            .expect("genesis");
        let params = Network::Regtest.params();
        let mut previous = genesis.header;
        let mut headers = Vec::new();
        // HSD's regtest testdummy deployment is STARTED at 144, LOCKED_IN at
        // 288, and ACTIVE for the candidate at height 432 when every header
        // signals bit 28.
        for _ in 1..432 {
            let mut header = Header {
                version: 1 << 28,
                prev_block: previous.hash(),
                time: previous.time + 1,
                bits: params.pow.bits,
                ..Header::default()
            };
            while !header.verify_pow() {
                header.nonce = header.nonce.checked_add(1).expect("regtest nonce space");
            }
            previous = header.clone();
            headers.push(header);
        }
        service
            .native_sync_import_headers(headers)
            .expect("deployment header ancestry");
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();

        let diagnostics = node
            .native_sync_header_deployments(
                StdInstant::now() + Duration::from_secs(5),
                MAX_HEADER_DEPLOYMENT_READS,
            )
            .expect("header deployment diagnostics");
        assert_eq!(diagnostics.best_header.height, 431);
        assert_eq!(diagnostics.next_height, 432);
        assert_eq!(diagnostics.script_flags, 50);
        assert_eq!(diagnostics.lock_flags, 0);
        assert_eq!(diagnostics.name_flags, 0);
        assert!(!diagnostics.has_airstop);
        assert_eq!(diagnostics.next_block_version, 0);
        assert_eq!(diagnostics.final_checkpoint, None);
        assert_eq!(diagnostics.historical_script_assumption_through, None);
        assert_eq!(
            diagnostics
                .deployments
                .iter()
                .find(|deployment| deployment.name == "testdummy")
                .map(|deployment| deployment.state),
            Some(ThresholdState::Active)
        );
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[test]
    fn native_sync_resource_limits_fail_closed() {
        let peer: SocketAddr = "127.0.0.1:14038".parse().expect("peer");
        let too_many_peers = NativeSyncConfig {
            enabled: true,
            connect: vec![peer],
            maximum_inbound: MAX_NATIVE_SYNC_PEERS,
            maximum_outbound: 1,
            ..NativeSyncConfig::default()
        };
        assert!(too_many_peers
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let too_fast = NativeSyncConfig {
            poll_interval: Duration::from_millis(1),
            ..too_many_peers
        };
        assert!(too_fast
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let zero_connector_batch = NativeSyncConfig {
            active_state_connect_batch: 0,
            ..too_fast
        };
        assert!(zero_connector_batch
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());

        let oversized_connector_batch = NativeSyncConfig {
            active_state_connect_batch: MAX_ACTIVE_STATE_CONNECT_BATCH + 1,
            ..zero_connector_batch
        };
        assert!(oversized_connector_batch
            .validate(AuthorityMode::Native, Network::Regtest)
            .is_err());
    }

    #[tokio::test]
    async fn native_mempool_rpc_refreshes_by_generation_and_enforces_live_cap() {
        let rpc_limits = RpcLimits {
            maximum_collection_entries: 1,
            maximum_concurrent_requests: 1,
            ..RpcLimits::default()
        };
        let service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            rpc_limits,
            ..NodeConfig::default()
        });
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let read_context = node.rpc_read_context().expect("RPC read context");
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics::default()));
        let diagnostic_rpc = initialize_cached_diagnostic_rpc(&node, &diagnostics)
            .await
            .expect("initial empty RPC cache");
        let state = NativeSyncHttpState {
            node: node.clone(),
            diagnostics,
            diagnostic_rpc,
            read_context,
            wallet_backend: None,
            wallet_rpc_authenticated: false,
            wallet_rpc_profile_enabled: false,
            limits: rpc_limits,
        };

        let (first, first_coin) = rpc_mempool_transaction(0x31);
        let first_txid = first.txid();
        let (second, second_coin) = rpc_mempool_transaction(0x32);
        let mut view = RpcMempoolView::default();
        view.coins.insert(first_coin.outpoint.clone(), first_coin);
        view.coins.insert(second_coin.outpoint.clone(), second_coin);
        let first_view = view.clone();
        writer
            .execute(None, "test first native mempool admission", move |node| {
                assert_eq!(
                    node.state
                        .mempool
                        .submit_with_context(
                            first,
                            &MempoolContext::testing(2, 2),
                            &first_view,
                            &AllowRpcMempoolInputs,
                            &AllowRpcMempoolContext,
                        )
                        .expect("first mempool admission"),
                    Admission::Accepted(first_txid)
                );
                Ok(())
            })
            .await
            .expect("first writer admission");
        let direct = node
            .published_mempool()
            .expect("published mempool")
            .ordered_txids;
        let captured = node
            .rpc_request_mempool(&JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getrawmempool".to_owned(),
                params: serde_json::json!([]),
                id: Some(serde_json::json!("capture")),
            })
            .await
            .expect("captured mempool request");
        let captured_generation = captured
            .ordered_txids
            .expect("bounded immutable transaction-id view");
        assert!(
            direct.is_same_generation(&captured_generation),
            "capturing the published RPC collection view must be O(1)"
        );

        let info = call_native_rpc(&state, "live-info-one", "getmempoolinfo").await;
        assert_eq!(info["result"]["size"], 1, "{info}");
        let collection_guard = state
            .read_context
            .try_acquire_collection()
            .expect("collection guard");
        let info_while_collection_busy =
            call_native_rpc(&state, "info-while-collection-busy", "getmempoolinfo").await;
        assert_eq!(
            info_while_collection_busy["result"]["size"], 1,
            "{info_while_collection_busy}"
        );
        let busy = call_native_rpc(&state, "busy-list", "getrawmempool").await;
        assert_eq!(busy["error"]["code"], -32005, "{busy}");
        drop(collection_guard);
        let entries = call_native_rpc(&state, "live-list-one", "getrawmempool").await;
        assert_eq!(
            entries["result"],
            serde_json::json!([first_txid.to_hex()]),
            "{entries}"
        );

        writer
            .execute(None, "test second native mempool admission", move |node| {
                assert!(matches!(
                    node.state
                        .mempool
                        .submit_with_context(
                            second,
                            &MempoolContext::testing(2, 2),
                            &view,
                            &AllowRpcMempoolInputs,
                            &AllowRpcMempoolContext,
                        )
                        .expect("second mempool admission"),
                    Admission::Accepted(_)
                ));
                Ok(())
            })
            .await
            .expect("second writer admission");
        let retained_response = BasicRpcService::default()
            .handle_raw_mempool(
                JsonRpcRequest {
                    jsonrpc: Some("2.0".to_owned()),
                    method: "getrawmempool".to_owned(),
                    params: serde_json::json!([]),
                    id: Some(serde_json::json!("retained-generation")),
                },
                captured_generation.txids(),
            )
            .expect("retained generation response");
        assert_eq!(
            retained_response.result,
            Some(serde_json::json!([first_txid.to_hex()])),
            "materialization after releasing NodeService must stay on the captured generation"
        );

        let capped = call_native_rpc(&state, "live-list-capped", "getrawmempool").await;
        assert_eq!(capped["error"]["code"], -8, "{capped}");
        assert_eq!(
            capped["error"]["message"], "mempool collection exceeds the RPC limit of 1 entries",
            "{capped}"
        );
        let info = call_native_rpc(&state, "live-info-two", "getmempoolinfo").await;
        assert_eq!(info["result"]["size"], 2, "{info}");
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[tokio::test]
    async fn native_sync_serves_capability_named_diagnostic_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let rpc_limits = RpcLimits {
            maximum_concurrent_requests: 1,
            ..RpcLimits::default()
        };
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            rpc_limits,
            ..NodeConfig::default()
        });
        service
            .native_sync_ensure_genesis_header()
            .expect("genesis header");
        let runtime = NodeRuntime::spawn(service, 8).expect("node runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let read_context = node.rpc_read_context().expect("RPC read context");
        let diagnostics = Arc::new(RwLock::new(NativeSyncDiagnostics {
            api_version: HSRD_DIAGNOSTIC_API_VERSION,
            enabled: true,
            observation_only: true,
            runtime_instance: "test-runtime".to_owned(),
            experimental_registry: rpc_experimental_registry_info(&hns_p2p::DenuoSummary::default()),
            ..NativeSyncDiagnostics::default()
        }));
        let diagnostic_rpc = initialize_cached_diagnostic_rpc(&node, &diagnostics)
            .await
            .expect("initial diagnostic snapshot");
        let live_peer = PeerSnapshot::new(
            PeerId(7),
            "127.0.0.1:14039".parse().expect("live peer address"),
            PeerDirection::Outbound,
        );
        let live_hip76 = rpc_hip76_info(std::slice::from_ref(&live_peer));
        {
            let mut live_diagnostics = diagnostics.write().await;
            live_diagnostics.peers.push(live_peer);
            live_diagnostics.hip76 = live_hip76;
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let authorization =
            RpcAuthorizationHeader::new("Bearer native-sync-test").expect("authorization");
        let read_context_probe = read_context.clone();
        let server = tokio::spawn(serve_native_sync_rpc(
            listener,
            NativeSyncHttpState {
                node: node.clone(),
                diagnostics,
                diagnostic_rpc,
                read_context,
                wallet_backend: None,
                wallet_rpc_authenticated: true,
                wallet_rpc_profile_enabled: false,
                limits: rpc_limits,
            },
            Some(authorization),
            shutdown_rx,
        ));

        let mut native_registry = None;
        let mut status_registry = None;
        for path in [
            "/api/v1/native-sync",
            "/api/v1/header-deployments",
            "/api/v1/mining-engine",
            "/api/v1/status",
        ] {
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer native-sync-test\r\nConnection: close\r\n\r\n"
            );
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect");
            stream
                .write_all(request.as_bytes())
                .await
                .expect("write request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read response");
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
            let (_, body) = response.split_once("\r\n\r\n").expect("body split");
            let json: serde_json::Value = serde_json::from_str(body).expect("json response");
            assert!(json.is_object(), "{json}");
            if path == "/api/v1/native-sync" {
                assert_eq!(json["api_version"], HSRD_DIAGNOSTIC_API_VERSION);
                assert_eq!(json["observation_only"], true);
                assert_eq!(json["active_state"], false);
                assert_eq!(json["runtime_instance"], "test-runtime");
                assert_eq!(json["connected_blocks"], 0);
                assert_eq!(json["contextual_failed_bodies"], 0);
                native_registry = Some(json["experimental_registry"].clone());
            } else if path == "/api/v1/header-deployments" {
                assert_eq!(json["best_header"]["height"], 0);
                assert_eq!(json["next_height"], 1);
                assert_eq!(json["script_flags"], 50);
            } else if path == "/api/v1/status" {
                assert_eq!(json["api_version"], HSRD_DIAGNOSTIC_API_VERSION);
                assert_eq!(json["diagnostic_snapshot_cached"], true);
                assert!(json["diagnostic_snapshot_captured_at"].is_u64());
                status_registry = Some(json["experimental_registry"].clone());
            }
        }
        assert_eq!(
            native_registry.expect("native registry diagnostics"),
            status_registry.expect("status registry diagnostics")
        );

        let (writer_started_tx, writer_started_rx) = tokio::sync::oneshot::channel();
        let (writer_release_tx, writer_release_rx) = std::sync::mpsc::channel();
        let blocked_writer = writer.clone();
        let writer_task = tokio::spawn(async move {
            blocked_writer
                .execute(None, "test blocked canonical writer", move |_node| {
                    let _ = writer_started_tx.send(());
                    writer_release_rx
                        .recv()
                        .context("test canonical writer release channel closed")?;
                    Ok(())
                })
                .await
        });
        writer_started_rx
            .await
            .expect("canonical writer entered test command");
        let cached_request = format!(
            "GET /api/v1/status HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer native-sync-test\r\nConnection: close\r\n\r\n"
        );
        let cached_response = tokio::time::timeout(Duration::from_secs(1), async {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect cached status");
            stream
                .write_all(cached_request.as_bytes())
                .await
                .expect("write cached status");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read cached status");
            response
        })
        .await
        .expect("cached diagnostic status must not wait for the canonical writer");
        assert!(
            cached_response.starts_with("HTTP/1.1 200 OK"),
            "{cached_response}"
        );
        let (_, cached_body) = cached_response
            .split_once("\r\n\r\n")
            .expect("cached body split");
        let cached_json: serde_json::Value =
            serde_json::from_str(cached_body).expect("cached status response");
        assert_eq!(cached_json["diagnostic_snapshot_cached"], true);
        assert!(cached_json["diagnostic_snapshot_captured_at"].is_u64());

        let live_network_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "live-network-overlay",
            "method": "getnetworkinfo",
            "params": [],
        })
        .to_string();
        let live_network_request = format!(
            "POST /rpc HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer native-sync-test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{live_network_body}",
            live_network_body.len()
        );
        let live_network_response = tokio::time::timeout(Duration::from_secs(1), async {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect live network overlay");
            stream
                .write_all(live_network_request.as_bytes())
                .await
                .expect("write live network overlay");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read live network overlay");
            response
        })
        .await
        .expect("live network overlay must not wait for the canonical writer");
        let (_, live_network_body) = live_network_response
            .split_once("\r\n\r\n")
            .expect("live network body split");
        let live_network_json: serde_json::Value =
            serde_json::from_str(live_network_body).expect("live network response");
        assert_eq!(live_network_json["result"]["connections"], 1);
        assert_eq!(live_network_json["result"]["networkactive"], true);

        let cached_rpc_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "cached-authority",
            "method": "getauthorityinfo",
            "params": [],
        })
        .to_string();
        let cached_rpc_request = format!(
            "POST /rpc HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer native-sync-test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cached_rpc_body}",
            cached_rpc_body.len()
        );
        let cached_rpc_response = tokio::time::timeout(Duration::from_secs(1), async {
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect cached authority");
            stream
                .write_all(cached_rpc_request.as_bytes())
                .await
                .expect("write cached authority");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read cached authority");
            response
        })
        .await
        .expect("cached JSON-RPC diagnostics must not wait for the canonical writer");
        let (_, cached_rpc_body) = cached_rpc_response
            .split_once("\r\n\r\n")
            .expect("cached RPC body split");
        let cached_rpc_json: serde_json::Value =
            serde_json::from_str(cached_rpc_body).expect("cached RPC response");
        assert_eq!(
            cached_rpc_json["result"]["diagnostic_snapshot_cached"],
            true
        );
        assert!(cached_rpc_json["result"]["diagnostic_snapshot_captured_at"].is_u64());

        // Saturate both state-access paths. Unknown and known unsupported
        // methods must still reject immediately, proving classification occurs
        // before the canonical writer, point-read permit, or durable snapshot.
        let _point_read_guard = read_context_probe
            .try_acquire_point_read()
            .expect("point-read guard");
        for (method, expected_message) in [
            ("not-a-method", "method not found"),
            (
                "sendrawtransaction",
                "sendrawtransaction requires a mutable mempool service",
            ),
            (
                "getpeerinfo",
                "getpeerinfo requires the live peer diagnostics service",
            ),
        ] {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": method,
                "method": method,
                "params": [],
            })
            .to_string();
            let request = format!(
                "POST /rpc HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer native-sync-test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let response = tokio::time::timeout(Duration::from_secs(1), async {
                let mut stream = tokio::net::TcpStream::connect(address)
                    .await
                    .expect("connect unsupported RPC");
                stream
                    .write_all(request.as_bytes())
                    .await
                    .expect("write unsupported RPC");
                let mut response = String::new();
                stream
                    .read_to_string(&mut response)
                    .await
                    .expect("read unsupported RPC");
                response
            })
            .await
            .expect("unsupported RPC must not wait for state");
            let (_, response_body) = response.split_once("\r\n\r\n").expect("body split");
            let json: serde_json::Value =
                serde_json::from_str(response_body).expect("unsupported RPC response");
            assert_eq!(json["error"]["code"], -32601, "{json}");
            assert_eq!(json["error"]["message"], expected_message, "{json}");
        }
        drop(_point_read_guard);
        writer_release_tx
            .send(())
            .expect("release canonical writer");
        writer_task
            .await
            .expect("canonical writer task join")
            .expect("canonical writer task result");

        let genesis_hash = Network::Regtest.params().genesis_hash.to_hex();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "point-read",
            "method": "getblockhash",
            "params": [0],
        })
        .to_string();
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer native-sync-test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect point RPC");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write point RPC");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read point RPC");
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").expect("body split");
        let json: serde_json::Value = serde_json::from_str(body).expect("point RPC response");
        assert_eq!(json["result"], genesis_hash, "{json}");

        shutdown_tx.send(true).expect("shutdown");
        server.await.expect("server join").expect("server result");
        runtime.shutdown().await.expect("node runtime shutdown");
    }

    #[tokio::test]
    async fn block_locator_uses_exponential_backoff_and_genesis() {
        let config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let mut node = NodeService::new(config);
        node.native_sync_ensure_genesis_header().expect("genesis");
        let runtime = NodeRuntime::spawn(node, 8).expect("node runtime");
        let node = runtime.read();
        assert_eq!(
            node.native_sync_block_locator(MAX_LOCATOR_ENTRIES)
                .expect("locator"),
            vec![Network::Regtest.params().genesis_hash]
        );
        runtime.shutdown().await.expect("node runtime shutdown");
    }
}
