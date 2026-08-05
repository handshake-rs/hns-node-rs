#![forbid(unsafe_code)]

mod denuo_market;
mod mining_engine;
mod native_sync;
mod peer_bans;
mod wallet_backend;
mod wallet_rpc;

pub use denuo_market::{DenuoRelayHandle, DenuoRelayHandleError};
pub use hns_denuo_market_relay::{
    Announcement as DenuoAnnouncement, AnnouncementAdmission as DenuoAnnouncementAdmission,
    ObjectAdmission as DenuoObjectAdmission, ObjectHash as DenuoObjectHash,
    RelayError as DenuoRelayError, RelayKind as DenuoRelayKind, RelayLimits as DenuoRelayLimits,
    RelayObject as DenuoRelayObject, RelayRoles as DenuoRelayRoles,
    RelayStatus as DenuoRelayStatus, RelayStore as DenuoRelayStore,
    SignerPolicy as DenuoSignerPolicy,
};
pub use hns_p2p::LivePeerManager;
pub use hns_wallet_index::{
    CompletedContractRetirement, CompletedContractRetirementOutcome, ContractId,
    ContractRegistration, ContractRegistrationOutcome, ContractRetirementOutcome,
    ContractRollbackBoundary, HnsHtlcDescriptor, RetiredRevealedPreimage, RevealedPreimage,
    ScriptHistoryCursor, ScriptHistoryDirection, ScriptHistoryEntry, ScriptHistoryPage, ScriptId,
    ScriptUtxo, ScriptUtxoCursor, ScriptUtxoPage, ShakedexV2Descriptor, SpendingTransaction,
    TrackedContractEvent, TrackedContractFunding, TrackedContractKind, TrackedContractSpendKind,
    WalletIndexProfile,
};
pub use mining_engine::{
    recommended_template_build_limits, MiningEngineConfig, MiningEngineDiagnostics,
    MiningPublicationAttempt, MiningPublicationResult, MiningTemplateRequest, NativeMiningJob,
    NativeMiningJobRequest,
};
pub use native_sync::{NativeSyncConfig, NativeSyncDiagnostics};
pub use wallet_backend::{
    BlockHashEvidence, BroadcastResult, CompletedTrackedContractRetirement,
    CompletedTrackedContractRetirementContext, CompletedTrackedContractRetirementRequest,
    ConfirmedScriptHistory, ConfirmedScriptUtxo, ConfirmedScriptsCursor, ConfirmedScriptsPage,
    FeeEstimate, FeeEstimateSource, MempoolContractActivity, MempoolContractEvent,
    MempoolContractPage, MempoolScriptActivity, MempoolScriptOutput, MempoolScriptPage,
    MempoolScriptSpend, NameAction, NameActionContext, NameActionIneligibility, NameEvidence,
    NameOwnerTransaction, NameProofResult, NameRenewalContext, NameTransferContext,
    OutpointSpendingEntry, OutpointSpendingEvidence, TrackedContractRetirement,
    TrackedContractRetirementContext, TrackedContractRetirementRequest, TransactionEvidence,
    TransactionFeeQuote, TransactionInclusion, TransactionPayload, TransactionStatus,
    WalletBackend, WalletBackendError, WalletChainTip, WalletContractEventCursor,
    WalletContractEventPage, WalletContractFundingCursor, WalletContractFundingPage,
    WalletMempoolCursor, MAX_NAME_ACTION_INELIGIBILITY_REASONS, MAX_WALLET_CONFIRMED_PAGE_ITEMS,
    MAX_WALLET_CONFIRMED_SCRIPT_EXAMINATIONS, MAX_WALLET_FEE_QUOTE_INPUTS,
    MAX_WALLET_OUTPOINT_SPEND_BATCH, NAME_ACTION_CONTEXT_VERSION,
};
pub use wallet_rpc::WALLET_RPC_API_VERSION;

use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error as StdError,
    fmt::{self as std_fmt, Display},
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use clap::ValueEnum;
#[cfg(test)]
use hns_chain::MAX_RESIDENT_ALTERNATE_HEADERS;
use hns_chain::{
    delete_canonical_height_from_batch, delete_tx_index_for_block_from_batch, read_canonical_hash,
    write_block_index_to_batch, write_canonical_height_to_batch, write_raw_block_to_batch,
    write_record_to_batch, write_tx_index_for_block_to_batch, BlockIndexCacheUpdate,
    BlockIndexRecord, BlockStatus, ChainError, ChainTip, FailedHeaderPlan, HeaderImport,
    HeaderIndex, HeaderIndexCacheUpdate, HeaderRecord, RawBlockRecord, RawBlockSource, ReorgPlan,
    ReorgPlanLimits, StoredBlockIndex, StoredHeaderIndex, TxIndexEntry,
};
use hns_consensus::{
    advance_threshold_state, expected_next_bits, validate_block_finality, validate_coinbase_height,
    validate_transaction_start, Checkpoint, ConsensusParams, Deployment, DeploymentPeriod,
    DeploymentState, DifficultyPoint, HeaderConsensus, HeaderParent, HeaderValidationContext,
    HistoricalScriptPolicy, HistoricalValidationPlan, NameFlags, NativeAirdropSignatureVerifier,
    Network, OpenSslDnssecVerifier, ThresholdState, MAX_FUTURE_BLOCK_TIME, MEDIAN_TIMESPAN,
};
use hns_mempool::{MemoryMempool, Mempool, MempoolInfo, MempoolSnapshot, OrderedTxidSnapshot};
use hns_mining::{
    HeaderSummary, MiningEventHub, MiningGeneration, MiningSnapshot, MiningSubscriptions,
    SolvedMiningCandidate, TemplateCoordinator,
};
use hns_p2p::{
    DenuoSummary, Hip76Summary, HnsrCoordinator, HnsrCoordinatorConfig, HnsrCoordinatorStatus,
    OdohNetworkBinding, OdohRequesterConfig, OdohRequesterRuntime, OdohRequesterStatus,
    PeerSnapshot,
};
use hns_primitives::{
    blake2b_256, hex_encode, sha3_256, Block, BlockHash, Coin, CompactTarget, Height, NameHash,
    NameState, Outpoint, Reader, Transaction, Txid, Uint256, Writer,
};
use hns_rpc::{
    BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcAuthorityInfo, RpcBlockEntry,
    RpcConsensusReadiness, RpcErrorObject, RpcExperimentalRegistryInfo,
    RpcExperimentalRejectionCount, RpcHeaderEntry, RpcHip76Info, RpcHnsrInfo, RpcMethod,
    RpcMiningEngineInfo, RpcNameTreeCompactionInfo, RpcNodeStatus, RpcOdohInfo, RpcParityInfo,
    RpcService, RpcSnapshot, RpcTransactionEntry, RpcUndoRetentionInfo,
};
use hns_state::{
    compact_name_tree_nodes_streaming, connect_block_to_batch_with_services, decode_coin,
    decode_name_state, disconnect_block_to_batch, encode_outpoint_key,
    load_persisted_name_tree_records, load_stored_name_tree_commit_root,
    load_stored_name_tree_root, migrate_name_tree_interval_accumulator_bounded, name_page_root_key,
    maximum_name_page_validation_records, name_tree_snapshot_pin_key, pack_name_page_records,
    NAME_PAGE_VALIDATION_RECORD_BYTES,
    plan_name_tree_interval_accumulator_migration_bounded, retained_name_tree_roots_bounded,
    stage_remove_name_tree_snapshot_pin, stream_name_page_tree_delta_with_limits,
    stream_name_page_tree_delta_with_limits_and_progress,
    stream_name_page_tree_with_limits, stream_name_page_tree_with_limits_and_progress,
    validate_persisted_name_tree_overlays,
    validate_persisted_name_tree_root, validate_persisted_name_trees,
    verify_name_tree_interval_state_bounded, verify_stored_name_tree_root_metadata_binding,
    visit_name_tree_snapshot_pins_bounded, AirdropCoinbaseIssuanceVerifier, BlockUndo,
    ConnectBlock, DisconnectBlock, NamePageRootLocator, NamePageRootRecord, NamePageSnapshot,
    NamePageState, NamePageStreamLimits, NamePageTraversalLimits, NamePageTreeReader,
    NamePageValidationLimits, NameTreeCompactionSummary, NameTreeIntervalMigrationLimits,
    NameTreeMaterializationLimits, NameTreeSnapshotPin, NameTreeSnapshotPinScanLimits,
    PageTreeError, RetainedNameTreeRootLimits, StateError, StateServices, StoredStateEngine,
    TreeRoot, NAME_PAGE_ROOT_PREFIX, NAME_PAGE_SEGMENT_BLOCKS, NAME_PAGE_STATE_KEY,
    NAME_TREE_SNAPSHOT_PIN_PREFIX,
};
#[cfg(test)]
use hns_state::{load_name_tree_snapshot_pins, verify_stored_name_tree_root};
use hns_store::{
    decode_u64, encode_u64, filesystem_available_bytes, filesystem_tree_usage_bounded,
    mark_unclean_start, open_store, truncate_name_pages_to_committed_tail, was_clean_shutdown,
    AtomicWriteEffectBudget, ColumnFamily, DurabilityPolicy, FilesystemTreeUsageLimits, MetaKey,
    NamePageAppender, NamePageError, PrefixScanBudget, ReadSnapshot, ScanEntry,
    SegmentArchiveScrubLimits, SegmentCompactionExecutionLimits, SegmentCompactionLimits,
    StagingOverlay, Store, StoreBackend, StoreConfig, StoreError, StoreHandle, StoreHandleBatch,
    WriteBatch, SCHEMA_VERSION, SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_DURABLE_BYTES,
    SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_ELAPSED, SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_RECORDS,
    SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_SEGMENTS, STORAGE_PROFILE,
};
use hns_wallet_index::{
    decode_index_profile, encode_index_profile, index_profile_is_current,
    register_tracked_contract, retire_completed_tracked_contract,
    retire_never_confirmed_tracked_contract, stage_connect as stage_wallet_index_connect,
    stage_disconnect as stage_wallet_index_disconnect,
    validate_completed_tracked_contract_retirements, validate_tracked_contract_registry,
    INDEX_PROFILE_MODE_KEY,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
use tracing_subscriber::{fmt, EnvFilter};

pub const HSRD_DIAGNOSTIC_API_VERSION: u32 = 15;
pub const HSD_ORACLE_REVISION: &str = "698e252ebc7b5c1dd0a9587e342fdd153d020ae4";
pub const HISTORICAL_REPLAY_QUALIFICATION_HEIGHT: Height = 339_660;
pub const HISTORICAL_REPLAY_QUALIFICATION_BLOCK: BlockHash = BlockHash::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x23, 0x84, 0xd1, 0xb4, 0x8e, 0x18, 0x5a, 0x0e,
    0x43, 0x69, 0x63, 0x85, 0x15, 0x63, 0x55, 0x86, 0x2e, 0x5f, 0xc2, 0x99, 0x14, 0xca, 0x72, 0x00,
]);
pub const MAX_RPC_AUTHORIZATION_BYTES: usize = 4_096;
pub const DEFAULT_RPC_MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const DEFAULT_RPC_MAX_CONCURRENT_REQUESTS: usize = 32;
pub const DEFAULT_RPC_EXECUTION_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_RPC_MAX_COLLECTION_ENTRIES: usize = 50_000;
pub const MAX_RPC_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RPC_CONCURRENT_REQUESTS: usize = 256;
pub const MAX_RPC_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RPC_COLLECTION_ENTRIES: usize = 250_000;
pub const STORAGE_MAINTENANCE_MARKER: &str = ".hsrd-storage-maintenance";
pub const STORAGE_MAINTENANCE_MARKER_BODY: &str = "hsrd-storage-maintenance-v1\n";

const DEPLOYMENT_STATE_CACHE_PREFIX: &[u8] = b"deployment-state/v1/";
const DEPLOYMENT_STATE_CACHE_VERSION: u8 = 1;
const DEPLOYMENT_STATE_CACHE_SIZE: usize = 1 + 4 + 4;
const TRANSACTION_INDEX_MODE_KEY: &[u8] = b"transaction-index-mode/v1";
const PAGE_BACKED_STARTUP_VALIDATION_BATCH: usize = 65_536;
const TRANSACTION_INDEX_MODE_VERSION: u8 = 1;
const TRANSACTION_INDEX_MODE_BODY_BYTES: usize = 2;
const TRANSACTION_INDEX_MODE_BYTES: usize = TRANSACTION_INDEX_MODE_BODY_BYTES + 32;
const NAME_TREE_COMPACTION_CHECKPOINT_KEY: &[u8] = b"name-tree-compaction/v1";
const NAME_TREE_COMPACTION_CHECKPOINT_VERSION: u32 = 1;
const NAME_TREE_COMPACTION_DELETE_BATCH: usize = 65_536;
const NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE: usize = 4 + 4 + 32 + (4 * 8);
const NAME_TREE_COMPACTION_CHECKPOINT_SIZE: usize = NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE + 32;
pub const DEFAULT_NAME_TREE_COMPACTION_INTERVAL: Height = 10_000;
const UNDO_PRUNING_CHECKPOINT_KEY: &[u8] = b"undo-pruning/v1";
const UNDO_PRUNING_CHECKPOINT_LEGACY_VERSION: u32 = 1;
const UNDO_PRUNING_CHECKPOINT_LEGACY_BODY_SIZE: usize = 4 + 4 + 32 + 8;
const UNDO_PRUNING_CHECKPOINT_LEGACY_SIZE: usize = UNDO_PRUNING_CHECKPOINT_LEGACY_BODY_SIZE + 32;
const UNDO_PRUNING_CHECKPOINT_VERSION: u32 = 2;
const UNDO_PRUNING_CHECKPOINT_BODY_SIZE: usize = 4 + 4 + 32 + 8 + 4 + 32 + 8;
const UNDO_PRUNING_CHECKPOINT_SIZE: usize = UNDO_PRUNING_CHECKPOINT_BODY_SIZE + 32;
const MAX_UNDO_PRUNES_PER_BATCH: usize = 1_024;
const PAYLOAD_SEGMENT_COMPACTION_MIN_DEAD_BYTES: u64 = 256 * 1024 * 1024;
const NAME_PAGE_COMPACTION_SEGMENT_THRESHOLD: u32 = 16;
const MAX_NAME_PAGE_GENERATION_BYTES: u64 = 150_000_000_000;
const MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES: u64 = 10_000_000_000;
const MAX_NAME_PAGE_VALIDATION_SPILL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_NAME_PAGE_VALIDATION_RECORDS: u64 =
    maximum_name_page_validation_records(MAX_NAME_PAGE_VALIDATION_SPILL_BYTES);
const MAX_NAME_PAGE_SEGMENTS: u64 = 1_000_000;
const MAX_NAME_PAGE_VALIDATION_ELAPSED: Duration = Duration::from_secs(60 * 60);
const MAX_NAME_PAGE_COMPACTION_ELAPSED: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_NAME_PAGE_COMPACTION_CLEANUP_ELAPSED: Duration = Duration::from_secs(10 * 60);
const NAME_PAGE_VALIDATION_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
// Mainnet currently has roughly thirteen million materialized names. A binary
// authenticated tree can contain almost twice as many leaf/internal records,
// and retained rollback roots add a bounded delta. These production limits
// leave measured headroom without accepting the compatibility API's 100M-entry
// in-memory maps. The 8 GiB RSS qualification gate remains mandatory whenever
// these constants or the address-map representation change.
const MAX_NAME_PAGE_COMPACTION_RECORDS: u64 = 40_000_000;

const _: () = {
    assert!(MAX_NAME_PAGE_VALIDATION_RECORDS > 100_000_000);
    assert!(MAX_NAME_PAGE_VALIDATION_RECORDS > MAX_NAME_PAGE_COMPACTION_RECORDS);
};
const MAX_NAME_PAGE_COMPACTION_KNOWN_ADDRESSES: u64 = 40_000_000;
const MAX_NAME_PAGE_COMPACTION_FRONTIER: u64 = 8_192;
const MAX_NAME_PAGE_ROOT_LOCATORS: u64 = 16_384;
const MAX_NAME_PAGE_ROOT_LOCATOR_BYTES: u64 = 8 * 1024 * 1024;
const NAME_PAGE_ROOT_LOCATOR_SCAN_PAGE_ENTRIES: usize = 1_024;
const NAME_PAGE_ROOT_LOCATOR_SCAN_PAGE_BYTES: usize = 1024 * 1024;
const MAX_NAME_PAGE_PUBLICATION_OPERATIONS: u64 = (MAX_NAME_PAGE_ROOT_LOCATORS * 2) + 1;
const MAX_NAME_PAGE_PUBLICATION_BYTES: u64 = 8 * 1024 * 1024;
const STARTUP_AUDIT_CHECKPOINT_KEY: &[u8] = b"startup-audit/v1";
const PRODUCTION_SAFETY_FENCE_KEY: &[u8] = b"production-safety-fence/v1";
const PRODUCTION_SAFETY_FENCE_VERSION: u32 = 1;
const MAX_PRODUCTION_SAFETY_FENCE_BYTES: usize = 4_096;
const MAX_PRODUCTION_SAFETY_CONTEXT_BYTES: usize = 256;
const MAX_PRODUCTION_SAFETY_DETAIL_BYTES: usize = 2_048;
const STARTUP_AUDIT_CHECKPOINT_VERSION: u32 = 1;
const STARTUP_AUDIT_CHECKPOINT_BODY_SIZE: usize = 4 + 32;
const STARTUP_AUDIT_CHECKPOINT_SIZE: usize = STARTUP_AUDIT_CHECKPOINT_BODY_SIZE + 32;
const BLOCK_INDEX_AUDIT_PAGE_ENTRIES: usize = 4_096;
const BLOCK_INDEX_AUDIT_PAGE_BYTES: usize = 4 * 1024 * 1024;
const STARTUP_HEIGHT_SCAN_PAGE_ENTRIES: usize = 4_096;
const STARTUP_HEIGHT_SCAN_PAGE_BYTES: usize = 512 * 1024;
const STARTUP_PIN_SCAN_MAX_ELAPSED: Duration = Duration::from_secs(30 * 60);
const NAME_TREE_SNAPSHOT_PIN_ENCODED_BYTES: u64 = 4 + 4 + 32 + 32 + 32;
const MAX_REORG_DISCONNECT_BLOCKS: usize = 1_024;
const MAX_REORG_CONNECT_BLOCKS: usize = 1_024;
const MAX_REORG_BODY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REORG_STAGED_EFFECT_BYTES: u64 = 256 * 1024 * 1024;
// Charge more than the current Rust enum/Vec/hash-table metadata for every
// logical copy. This also leaves deterministic headroom for allocator and
// backend write-batch framing without depending on a particular target ABI.
const REORG_STAGED_OPERATION_FRAMING_BYTES: u64 = 128;
// During state staging, the write's source encoding coexists with the backend
// batch and the read-your-writes overlay. Deferred name nodes omit the backend
// copy, but later coexist in the staged page map and `PackedNamePages` logical
// records. Packing receives an additional pre-allocation charge below, so the
// three-copy charge remains deliberately conservative for both routes.
const REORG_STAGING_OPERATION_COPIES: u64 = 3;
// After the overlay has been consumed, page publication retains one backend
// copy while the source encoding is submitted to it.
const REORG_PUBLICATION_OPERATION_COPIES: u64 = 2;
// Packing retains the canonical fixed-size page while its byte-identical
// physical output is appended and synced. Charge both representations plus a
// conservative per-page framing/allocation allowance before any file write.
const REORG_NAME_PAGE_OUTPUT_COPIES: u64 = 2;
// `pack_name_page_records` clones each canonical node once and builds bounded
// lookup/order/visited/address/page-record metadata before the fixed-size page
// encoder runs. Precharge the raw clone plus a deliberately ABI-independent
// 1 KiB per-record envelope before any of those pack allocations.
const REORG_NAME_PAGE_PACKING_METADATA_BYTES_PER_RECORD: u64 = 1024;
const MAX_REORG_RECONCILIATION_TRANSACTIONS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum AuthorityMode {
    Disabled,
    /// Native consensus and active-state operation. Mining remains fail closed
    /// until every readiness gate is complete and the durable tip itself has
    /// the full mining-authoritative status.
    #[default]
    Native,
    NativeExperimental,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum StorageMode {
    /// Retain headers and consensus state while keeping only the network's
    /// bounded raw-block and undo reorganization horizon.
    #[default]
    Pruned,
    /// Retain every raw block and undo record for historical peer serving and
    /// offline analysis. A store that has already pruned cannot be reopened in
    /// this mode.
    Archive,
}

impl StorageMode {
    pub const fn prunes_payload_history(self) -> bool {
        matches!(self, Self::Pruned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionSafetyFenceKind {
    LiveHeaderOperation,
    LiveHeaderReorganization,
    FailedBranchDescendants,
    NamePageValidation,
    NamePageCompaction,
    PayloadSegmentCompaction,
    Storage,
}

impl ProductionSafetyFenceKind {
    const fn code(self) -> u8 {
        match self {
            Self::LiveHeaderOperation => 1,
            Self::LiveHeaderReorganization => 2,
            Self::FailedBranchDescendants => 3,
            Self::NamePageValidation => 4,
            Self::NamePageCompaction => 5,
            Self::PayloadSegmentCompaction => 6,
            Self::Storage => 7,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::LiveHeaderOperation),
            2 => Ok(Self::LiveHeaderReorganization),
            3 => Ok(Self::FailedBranchDescendants),
            4 => Ok(Self::NamePageValidation),
            5 => Ok(Self::NamePageCompaction),
            6 => Ok(Self::PayloadSegmentCompaction),
            7 => Ok(Self::Storage),
            _ => anyhow::bail!("unknown production safety-fence kind {code}"),
        }
    }

    pub const fn requires_name_page_directory(self) -> bool {
        matches!(self, Self::NamePageValidation | Self::NamePageCompaction)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProductionSafetyFence {
    pub version: u32,
    pub kind: ProductionSafetyFenceKind,
    pub context: String,
    pub limit: u64,
    pub actual: u64,
    pub root: Option<BlockHash>,
    pub candidate: Option<BlockHash>,
    pub detail: String,
}

impl ProductionSafetyFence {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.version != PRODUCTION_SAFETY_FENCE_VERSION
            || self.context.is_empty()
            || self.context.len() > MAX_PRODUCTION_SAFETY_CONTEXT_BYTES
            || self.detail.len() > MAX_PRODUCTION_SAFETY_DETAIL_BYTES
        {
            anyhow::bail!("production safety-fence fields exceed their codec envelope");
        }
        let mut writer = Writer::new();
        writer.write_u32(self.version);
        writer.write_u8(self.kind.code());
        writer.write_u16(u16::try_from(self.context.len())?);
        writer.write_bytes(self.context.as_bytes());
        writer.write_u64(self.limit);
        writer.write_u64(self.actual);
        write_optional_fence_hash(&mut writer, self.root);
        write_optional_fence_hash(&mut writer, self.candidate);
        writer.write_u16(u16::try_from(self.detail.len())?);
        writer.write_bytes(self.detail.as_bytes());
        let mut encoded = writer.finish();
        if encoded.len().saturating_add(32) > MAX_PRODUCTION_SAFETY_FENCE_BYTES {
            anyhow::bail!("production safety-fence encoding exceeds its durable envelope");
        }
        encoded.extend_from_slice(&blake2b_256(&encoded));
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self> {
        if encoded.len() < 32 || encoded.len() > MAX_PRODUCTION_SAFETY_FENCE_BYTES {
            anyhow::bail!(
                "production safety-fence contains invalid encoded length {}",
                encoded.len()
            );
        }
        let (body, checksum) = encoded.split_at(encoded.len() - 32);
        if checksum != blake2b_256(body) {
            anyhow::bail!("production safety-fence checksum mismatch");
        }
        let mut reader = Reader::new(body, MAX_PRODUCTION_SAFETY_FENCE_BYTES)?;
        let version = reader.read_u32()?;
        if version != PRODUCTION_SAFETY_FENCE_VERSION {
            anyhow::bail!("unsupported production safety-fence version {version}");
        }
        let kind = ProductionSafetyFenceKind::from_code(reader.read_u8()?)?;
        let context_len = usize::from(reader.read_u16()?);
        if context_len == 0 || context_len > MAX_PRODUCTION_SAFETY_CONTEXT_BYTES {
            anyhow::bail!("production safety-fence context length is invalid");
        }
        let context = String::from_utf8(reader.read_vec(context_len)?)
            .context("production safety-fence context is not UTF-8")?;
        let limit = reader.read_u64()?;
        let actual = reader.read_u64()?;
        let root = read_optional_fence_hash(&mut reader)?;
        let candidate = read_optional_fence_hash(&mut reader)?;
        let detail_len = usize::from(reader.read_u16()?);
        if detail_len > MAX_PRODUCTION_SAFETY_DETAIL_BYTES {
            anyhow::bail!("production safety-fence detail length is invalid");
        }
        let detail = String::from_utf8(reader.read_vec(detail_len)?)
            .context("production safety-fence detail is not UTF-8")?;
        reader.ensure_finished()?;
        Ok(Self {
            version,
            kind,
            context,
            limit,
            actual,
            root,
            candidate,
            detail,
        })
    }

    fn reason(&self) -> String {
        format!(
            "{} (kind {:?}, limit {}, actual {})",
            self.detail, self.kind, self.limit, self.actual
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProductionSafetyFenceEvidence {
    pub fence: ProductionSafetyFence,
    pub encoded: Vec<u8>,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionSafetyFenceClearAcknowledgement {
    OfflineRecoveryCompletedAndVerified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionSafetyFenceClearRequest {
    pub expected_digest: [u8; 32],
    pub acknowledgement: ProductionSafetyFenceClearAcknowledgement,
    pub name_page_directory: Option<PathBuf>,
}

fn write_optional_fence_hash(writer: &mut Writer, hash: Option<BlockHash>) {
    match hash {
        Some(hash) => {
            writer.write_u8(1);
            writer.write_bytes(hash.as_bytes());
        }
        None => writer.write_u8(0),
    }
}

fn read_optional_fence_hash(reader: &mut Reader<'_>) -> Result<Option<BlockHash>> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(BlockHash::new(reader.read_hash()?))),
        value => anyhow::bail!("production safety-fence hash flag {value} is invalid"),
    }
}

/// Exact HTTP Authorization value required by the hsrd RPC listener.
///
/// The value is deliberately redacted from diagnostics and comparisons use a
/// length-independent byte loop so a rejected local client does not receive a
/// useful early-mismatch timing signal.
#[derive(Clone, Eq, PartialEq)]
pub struct RpcAuthorizationHeader(Arc<str>);

impl RpcAuthorizationHeader {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_RPC_AUTHORIZATION_BYTES
            || matches!(bytes.first(), Some(b' ' | b'\t'))
            || matches!(bytes.last(), Some(b' ' | b'\t'))
            || bytes.iter().any(|byte| !(0x20..=0x7e).contains(byte))
        {
            anyhow::bail!(
                "RPC Authorization value must be 1..={MAX_RPC_AUTHORIZATION_BYTES} visible ASCII bytes with no leading or trailing whitespace"
            );
        }
        Ok(Self(Arc::from(value)))
    }

    fn matches(&self, candidate: Option<&[u8]>) -> bool {
        let expected = self.0.as_bytes();
        let candidate = candidate.unwrap_or_default();
        let maximum = expected.len().max(candidate.len());
        let mut difference = expected.len() ^ candidate.len();
        for index in 0..maximum {
            difference |= usize::from(
                expected.get(index).copied().unwrap_or(0)
                    ^ candidate.get(index).copied().unwrap_or(0),
            );
        }
        difference == 0
    }
}

impl std::fmt::Debug for RpcAuthorizationHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RpcAuthorizationHeader([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NameTreeCompactionConfig {
    pub compact_on_startup: bool,
    pub startup_interval: Height,
}

impl Default for NameTreeCompactionConfig {
    fn default() -> Self {
        Self {
            compact_on_startup: false,
            startup_interval: DEFAULT_NAME_TREE_COMPACTION_INTERVAL,
        }
    }
}

impl NameTreeCompactionConfig {
    fn validate(self) -> Result<()> {
        if self.startup_interval == 0 {
            anyhow::bail!("name-tree compaction startup interval must be non-zero");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UndoRetentionConfig {
    pub prune_history: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UndoRetentionPolicy {
    prune_after_height: Height,
    keep_blocks: u32,
}

impl UndoRetentionPolicy {
    fn for_network(network: Network) -> Self {
        let params = network.params().block;
        Self {
            prune_after_height: params.prune_after_height,
            keep_blocks: params.keep_blocks,
        }
    }

    fn validate(self) -> Result<()> {
        if self.keep_blocks == 0 {
            anyhow::bail!("network undo retention window must be non-zero");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UndoPruningCheckpoint {
    pub pruned_through: Height,
    pub block_hash: BlockHash,
    pub pruned_undos: u64,
    pub blocks_pruned_through: Height,
    pub blocks_checkpoint: BlockHash,
    pub pruned_blocks: u64,
}

impl UndoPruningCheckpoint {
    fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(UNDO_PRUNING_CHECKPOINT_SIZE);
        writer.write_u32(UNDO_PRUNING_CHECKPOINT_VERSION);
        writer.write_u32(self.pruned_through);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u64(self.pruned_undos);
        writer.write_u32(self.blocks_pruned_through);
        writer.write_bytes(self.blocks_checkpoint.as_bytes());
        writer.write_u64(self.pruned_blocks);
        let mut raw = writer.finish();
        debug_assert_eq!(raw.len(), UNDO_PRUNING_CHECKPOINT_BODY_SIZE);
        raw.extend_from_slice(&blake2b_256(&raw));
        raw
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != UNDO_PRUNING_CHECKPOINT_SIZE
            && raw.len() != UNDO_PRUNING_CHECKPOINT_LEGACY_SIZE
        {
            anyhow::bail!(
                "undo-pruning checkpoint contains {} bytes; expected {UNDO_PRUNING_CHECKPOINT_SIZE} or legacy {UNDO_PRUNING_CHECKPOINT_LEGACY_SIZE}",
                raw.len()
            );
        }
        let body_size = raw.len() - 32;
        let (body, checksum) = raw.split_at(body_size);
        if checksum != blake2b_256(body) {
            anyhow::bail!("undo-pruning checkpoint checksum mismatch");
        }
        let mut reader = Reader::new(body, body_size)?;
        let version = reader.read_u32()?;
        if version == UNDO_PRUNING_CHECKPOINT_LEGACY_VERSION {
            if body_size != UNDO_PRUNING_CHECKPOINT_LEGACY_BODY_SIZE {
                anyhow::bail!("legacy undo-pruning checkpoint has an invalid size");
            }
            let checkpoint = Self {
                pruned_through: reader.read_u32()?,
                block_hash: BlockHash::new(reader.read_hash()?),
                pruned_undos: reader.read_u64()?,
                blocks_pruned_through: 0,
                blocks_checkpoint: BlockHash::ZERO,
                pruned_blocks: 0,
            };
            reader.ensure_finished()?;
            return Ok(checkpoint);
        }
        if version != UNDO_PRUNING_CHECKPOINT_VERSION
            || body_size != UNDO_PRUNING_CHECKPOINT_BODY_SIZE
        {
            anyhow::bail!("unsupported undo-pruning checkpoint version {version}");
        }
        let checkpoint = Self {
            pruned_through: reader.read_u32()?,
            block_hash: BlockHash::new(reader.read_hash()?),
            pruned_undos: reader.read_u64()?,
            blocks_pruned_through: reader.read_u32()?,
            blocks_checkpoint: BlockHash::new(reader.read_hash()?),
            pruned_blocks: reader.read_u64()?,
        };
        reader.ensure_finished()?;
        Ok(checkpoint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameTreeCompactionCheckpoint {
    pub height: Height,
    pub tip: BlockHash,
    pub summary: NameTreeCompactionSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamePageCompactionReport {
    pub previous_generation: u64,
    pub generation: u64,
    pub retained_roots: usize,
    pub records_written: u64,
    pub pages_written: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub reclaimed_bytes: u64,
}

type StagedNamePageCompaction = (
    NamePageState,
    NamePageAppender,
    u64,
    u64,
    BTreeMap<TreeRoot, hns_store::NamePageAddress>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamePageRootTarget {
    root: TreeRoot,
    height: Option<Height>,
}

impl NameTreeCompactionCheckpoint {
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::with_capacity(NAME_TREE_COMPACTION_CHECKPOINT_SIZE);
        writer.write_u32(NAME_TREE_COMPACTION_CHECKPOINT_VERSION);
        writer.write_u32(self.height);
        writer.write_bytes(self.tip.as_bytes());
        writer.write_u64(u64::try_from(self.summary.retained_roots)?);
        writer.write_u64(u64::try_from(self.summary.nodes_before)?);
        writer.write_u64(u64::try_from(self.summary.nodes_retained)?);
        writer.write_u64(u64::try_from(self.summary.nodes_deleted)?);
        let mut raw = writer.finish();
        debug_assert_eq!(raw.len(), NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE);
        raw.extend_from_slice(&blake2b_256(&raw));
        Ok(raw)
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != NAME_TREE_COMPACTION_CHECKPOINT_SIZE {
            anyhow::bail!(
                "name-tree compaction checkpoint contains {} bytes; expected {NAME_TREE_COMPACTION_CHECKPOINT_SIZE}",
                raw.len()
            );
        }
        let (body, checksum) = raw.split_at(NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE);
        if checksum != blake2b_256(body) {
            anyhow::bail!("name-tree compaction checkpoint checksum mismatch");
        }
        let mut reader = Reader::new(body, NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE)?;
        let version = reader.read_u32()?;
        if version != NAME_TREE_COMPACTION_CHECKPOINT_VERSION {
            anyhow::bail!("unsupported name-tree compaction checkpoint version {version}");
        }
        let height = reader.read_u32()?;
        let tip = BlockHash::new(reader.read_hash()?);
        let retained_roots = usize::try_from(reader.read_u64()?)?;
        let nodes_before = usize::try_from(reader.read_u64()?)?;
        let nodes_retained = usize::try_from(reader.read_u64()?)?;
        let nodes_deleted = usize::try_from(reader.read_u64()?)?;
        reader.ensure_finished()?;
        let checkpoint = Self {
            height,
            tip,
            summary: NameTreeCompactionSummary {
                retained_roots,
                nodes_before,
                nodes_retained,
                nodes_deleted,
            },
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn validate(&self) -> Result<()> {
        if self.summary.retained_roots == 0 {
            anyhow::bail!("name-tree compaction checkpoint retained no roots");
        }
        if self
            .summary
            .nodes_retained
            .checked_add(self.summary.nodes_deleted)
            != Some(self.summary.nodes_before)
        {
            anyhow::bail!("name-tree compaction checkpoint node counts are inconsistent");
        }
        Ok(())
    }
}

/// Checksummed commitment to the exact durable identity whose expensive
/// materialized-name and retained-Urkel traversals completed during an earlier
/// process lifetime. The clean-shutdown marker and this checkpoint are written
/// in the same atomic batch. Unclean starts and any identity mismatch retain
/// the exhaustive audit.
struct PagedPrefixCursor<'a, S: ReadSnapshot> {
    snapshot: &'a S,
    family: ColumnFamily,
    prefix: &'static [u8],
    budget: PrefixScanBudget,
    context: &'static str,
    continuation: Option<Vec<u8>>,
    buffered: std::vec::IntoIter<ScanEntry>,
    exhausted: bool,
}

impl<'a, S: ReadSnapshot> PagedPrefixCursor<'a, S> {
    fn new(
        snapshot: &'a S,
        family: ColumnFamily,
        prefix: &'static [u8],
        budget: PrefixScanBudget,
        context: &'static str,
    ) -> Result<Self> {
        budget
            .validate()
            .map_err(|error| anyhow::anyhow!("{context} has invalid page limits: {error}"))?;
        Ok(Self {
            snapshot,
            family,
            prefix,
            budget,
            context,
            continuation: None,
            buffered: Vec::new().into_iter(),
            exhausted: false,
        })
    }

    fn next_entry(&mut self) -> Result<Option<ScanEntry>> {
        loop {
            if let Some(entry) = self.buffered.next() {
                return Ok(Some(entry));
            }
            if self.exhausted {
                return Ok(None);
            }

            let start_after = self.continuation.as_deref();
            let page = self
                .snapshot
                .scan_prefix_page(self.family, self.prefix, start_after, self.budget)
                .with_context(|| format!("failed to page {}", self.context))?;
            if page.entries.len() > self.budget.max_entries {
                anyhow::bail!(
                    "{} returned {} entries; page limit is {}",
                    self.context,
                    page.entries.len(),
                    self.budget.max_entries
                );
            }
            let mut returned_bytes = 0usize;
            let mut previous = start_after;
            for (key, value) in &page.entries {
                if !key.starts_with(self.prefix) {
                    anyhow::bail!("{} returned a key outside its prefix", self.context);
                }
                if previous.is_some_and(|previous| key.as_slice() <= previous) {
                    anyhow::bail!("{} returned non-increasing keys", self.context);
                }
                returned_bytes = returned_bytes
                    .checked_add(key.len())
                    .and_then(|bytes| bytes.checked_add(value.len()))
                    .ok_or_else(|| anyhow::anyhow!("{} byte count overflow", self.context))?;
                previous = Some(key);
            }
            if returned_bytes != page.returned_bytes || returned_bytes > self.budget.max_bytes {
                anyhow::bail!(
                    "{} reported {} bytes for {returned_bytes} returned bytes with page limit {}",
                    self.context,
                    page.returned_bytes,
                    self.budget.max_bytes
                );
            }
            if let Some(next) = page.continuation.as_ref() {
                let Some((last, _)) = page.entries.last() else {
                    anyhow::bail!("{} returned a continuation without progress", self.context);
                };
                if next != last
                    || self
                        .continuation
                        .as_ref()
                        .is_some_and(|previous| next <= previous)
                {
                    anyhow::bail!("{} continuation did not advance", self.context);
                }
            }

            self.continuation = page.continuation;
            self.exhausted = self.continuation.is_none();
            self.buffered = page.entries.into_iter();
            if self.buffered.len() == 0 && !self.exhausted {
                anyhow::bail!("{} returned an empty continuing page", self.context);
            }
        }
    }
}

enum StartupHeightCursor<'a, S: ReadSnapshot> {
    PointRange {
        snapshot: &'a S,
        next: Height,
        end: Height,
        finished: bool,
    },
    Paged(PagedPrefixCursor<'a, S>),
}

impl<'a, S: ReadSnapshot> StartupHeightCursor<'a, S> {
    fn point_range(snapshot: &'a S, start: Height, end: Height) -> Self {
        Self::PointRange {
            snapshot,
            next: start,
            end,
            finished: false,
        }
    }

    fn paged(snapshot: &'a S) -> Result<Self> {
        Ok(Self::Paged(PagedPrefixCursor::new(
            snapshot,
            ColumnFamily::HeightIndex,
            b"",
            PrefixScanBudget {
                max_entries: STARTUP_HEIGHT_SCAN_PAGE_ENTRIES,
                max_bytes: STARTUP_HEIGHT_SCAN_PAGE_BYTES,
            },
            "startup active height index",
        )?))
    }

    fn next_entry(&mut self) -> Result<Option<ScanEntry>> {
        match self {
            Self::PointRange {
                snapshot,
                next,
                end,
                finished,
            } => {
                if *finished {
                    return Ok(None);
                }
                let height = *next;
                let hash = read_canonical_hash(*snapshot, height)?.ok_or_else(|| {
                    anyhow::anyhow!("clean startup audit is missing canonical height {height}")
                })?;
                if height == *end {
                    *finished = true;
                } else {
                    *next = height
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("startup height range overflow"))?;
                }
                Ok(Some((
                    height.to_be_bytes().to_vec(),
                    hash.as_bytes().to_vec(),
                )))
            }
            Self::Paged(cursor) => cursor.next_entry(),
        }
    }
}

fn startup_pin_scan_limits(
    snapshot: &impl ReadSnapshot,
    network: Network,
) -> Result<NameTreeSnapshotPinScanLimits> {
    let tree_interval = network.params().names.tree_interval;
    if tree_interval == 0 {
        anyhow::bail!("network name-tree snapshot interval is zero");
    }
    let maximum_records = best_block_tip_from_snapshot(snapshot)?
        .map(|tip| u64::from(tip.height / tree_interval) + 1)
        .unwrap_or(0);
    let maximum_bytes = maximum_records
        .checked_mul(NAME_TREE_SNAPSHOT_PIN_ENCODED_BYTES)
        .ok_or_else(|| anyhow::anyhow!("startup name-tree pin byte limit overflow"))?;
    let now = Instant::now();
    Ok(NameTreeSnapshotPinScanLimits {
        max_records: maximum_records,
        max_bytes: maximum_bytes,
        deadline: now.checked_add(STARTUP_PIN_SCAN_MAX_ELAPSED).unwrap_or(now),
        ..NameTreeSnapshotPinScanLimits::default()
    })
}

struct StartupPinCursor<'a, S: ReadSnapshot> {
    entries: PagedPrefixCursor<'a, S>,
    limits: NameTreeSnapshotPinScanLimits,
    records: u64,
    bytes: u64,
}

impl<'a, S: ReadSnapshot> StartupPinCursor<'a, S> {
    fn new(snapshot: &'a S, network: Network) -> Result<Self> {
        let limits = startup_pin_scan_limits(snapshot, network)?;
        Ok(Self {
            entries: PagedPrefixCursor::new(
                snapshot,
                ColumnFamily::Snapshots,
                NAME_TREE_SNAPSHOT_PIN_PREFIX,
                limits.page_budget,
                "startup name-tree snapshot pins",
            )?,
            limits,
            records: 0,
            bytes: 0,
        })
    }

    fn next_pin(&mut self) -> Result<Option<NameTreeSnapshotPin>> {
        if Instant::now() >= self.limits.deadline {
            anyhow::bail!("startup name-tree snapshot pin scan exceeded its deadline");
        }
        let Some((key, raw)) = self.entries.next_entry()? else {
            return Ok(None);
        };
        self.records = add_reorg_resource(
            self.records,
            1,
            self.limits.max_records,
            "startup name-tree snapshot pin records",
        )?;
        self.bytes = add_reorg_resource(
            self.bytes,
            u64::try_from(raw.len()).unwrap_or(u64::MAX),
            self.limits.max_bytes,
            "startup name-tree snapshot pin bytes",
        )?;
        let pin = NameTreeSnapshotPin::decode(&raw)
            .map_err(|error| anyhow::anyhow!("failed to decode startup name-tree pin: {error}"))?;
        if key != name_tree_snapshot_pin_key(pin.height) {
            anyhow::bail!(
                "startup name-tree snapshot pin key disagrees with height {}",
                pin.height
            );
        }
        if Instant::now() >= self.limits.deadline {
            anyhow::bail!("startup name-tree snapshot pin scan exceeded its deadline");
        }
        Ok(Some(pin))
    }
}

fn startup_pin_minimum_root_heights(
    snapshot: &impl ReadSnapshot,
    network: Network,
    retained_roots: &BTreeSet<TreeRoot>,
) -> Result<BTreeMap<TreeRoot, Height>> {
    let mut pins = StartupPinCursor::new(snapshot, network)?;
    let mut heights = BTreeMap::<TreeRoot, Height>::new();
    while let Some(pin) = pins.next_pin()? {
        if pin.root == TreeRoot::ZERO || !retained_roots.contains(&pin.root) {
            continue;
        }
        if let Some(height) = heights.get_mut(&pin.root) {
            *height = (*height).min(pin.height);
            continue;
        }
        let actual = u64::try_from(heights.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if actual > MAX_NAME_PAGE_ROOT_LOCATORS {
            return Err(PageTreeError::ResourceLimit {
                context: "startup snapshot-pin root locators",
                limit: MAX_NAME_PAGE_ROOT_LOCATORS,
                actual,
            }
            .into());
        }
        heights.insert(pin.root, pin.height);
    }
    Ok(heights)
}

fn plan_name_page_pin_height_repairs(
    snapshot: &impl ReadSnapshot,
    network: Network,
) -> Result<Vec<NamePageRootRecord>> {
    let mut pins = StartupPinCursor::new(snapshot, network)?;
    let mut repairs = BTreeMap::<TreeRoot, NamePageRootRecord>::new();
    while let Some(pin) = pins.next_pin()? {
        if pin.root == TreeRoot::ZERO {
            continue;
        }
        let Some(mut record) = load_name_page_root_record(snapshot, pin.root)? else {
            continue;
        };
        if record.root != pin.root {
            anyhow::bail!("name-page root locator key does not match its record");
        }
        if record.height <= pin.height {
            continue;
        }
        record.height = pin.height;
        if let Some(planned) = repairs.get_mut(&pin.root) {
            planned.height = planned.height.min(record.height);
            continue;
        }
        let actual = u64::try_from(repairs.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if actual > MAX_NAME_PAGE_ROOT_LOCATORS {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page pin-height repair records",
                limit: MAX_NAME_PAGE_ROOT_LOCATORS,
                actual,
            }
            .into());
        }
        repairs.insert(pin.root, record);
    }

    let mut publication_bytes = 0u64;
    for record in repairs.values() {
        let record_bytes = u64::try_from(name_page_root_key(record.root).len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(record.encode().len()).unwrap_or(u64::MAX));
        publication_bytes = publication_bytes.saturating_add(record_bytes);
        if publication_bytes > MAX_NAME_PAGE_PUBLICATION_BYTES {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page pin-height repair publication bytes",
                limit: MAX_NAME_PAGE_PUBLICATION_BYTES,
                actual: publication_bytes,
            }
            .into());
        }
    }
    Ok(repairs.into_values().collect())
}

fn validate_name_page_pin_height_repairs(
    directory: &std::path::Path,
    state: &NamePageState,
    repairs: &[NamePageRootRecord],
) -> Result<()> {
    let Some(first) = repairs.first() else {
        return Ok(());
    };
    let maximum_addresses = u64::try_from(repairs.len())
        .unwrap_or(u64::MAX)
        .checked_mul(3)
        .ok_or_else(|| anyhow::anyhow!("name-page pin-height repair address limit overflow"))?;
    let reader = NamePageTreeReader::open_generation(
        directory,
        state.manifest.generation,
        state.manifest.active_segment,
        first.root,
        first.locator,
    )
    .context("failed to open name pages for pin-height repair validation")?;
    for record in repairs {
        reader
            .insert_root_bounded(record.root, record.locator, maximum_addresses)
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to seed pin-height repair root {:?}: {error}",
                    record.root
                )
            })?;
        if reader
            .load_bounded(record.root, maximum_addresses)
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to validate pin-height repair root {:?}: {error}",
                    record.root
                )
            })?
            .is_none()
        {
            anyhow::bail!(
                "pin-height repair root {:?} is absent from its authenticated page",
                record.root
            );
        }
    }
    Ok(())
}

fn minimum_name_page_root_height(
    snapshot: &impl ReadSnapshot,
    network: Network,
    root: TreeRoot,
    proposed_height: Height,
    staged_pins: &[NameTreeSnapshotPin],
) -> Result<Height> {
    let mut minimum = proposed_height;
    if let Some(record) = load_name_page_root_record(snapshot, root)? {
        if record.root != root {
            anyhow::bail!("name-page root locator key does not match its record");
        }
        minimum = minimum.min(record.height);
    }
    let mut pins = StartupPinCursor::new(snapshot, network)?;
    while let Some(pin) = pins.next_pin()? {
        if pin.root == root {
            minimum = minimum.min(pin.height);
        }
    }
    for pin in staged_pins.iter().filter(|pin| pin.root == root) {
        minimum = minimum.min(pin.height);
    }
    Ok(minimum)
}

fn seed_startup_pin_page_roots(
    snapshot: &impl ReadSnapshot,
    network: Network,
    reader: &NamePageTreeReader,
) -> Result<bool> {
    let mut pins = StartupPinCursor::new(snapshot, network)?;
    let maximum_addresses = pins
        .limits
        .max_records
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("startup name-page root limit overflow"))?;
    let mut legacy_missing = false;
    while let Some(pin) = pins.next_pin()? {
        if pin.root == TreeRoot::ZERO {
            continue;
        }
        let Some(record) = load_name_page_root_record(snapshot, pin.root)? else {
            legacy_missing = true;
            continue;
        };
        if record.root != pin.root || record.height > pin.height {
            anyhow::bail!(
                "snapshot pin at height {} has an inconsistent name-page root locator",
                pin.height
            );
        }
        reader
            .insert_root_bounded(record.root, record.locator, maximum_addresses)
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to seed snapshot-pin page root {:?}: {error}",
                    record.root
                )
            })?;
    }
    Ok(legacy_missing)
}

fn production_name_page_validation_limits(
    snapshot: &impl ReadSnapshot,
    network: Network,
) -> Result<NamePageValidationLimits> {
    let now = Instant::now();
    name_page_validation_limits_with_spill(
        snapshot,
        network,
        MAX_NAME_PAGE_VALIDATION_SPILL_BYTES,
        now.checked_add(MAX_NAME_PAGE_VALIDATION_ELAPSED)
            .unwrap_or(now),
    )
}

fn name_page_validation_limits_with_spill(
    snapshot: &impl ReadSnapshot,
    network: Network,
    maximum_spill_bytes: u64,
    deadline: Instant,
) -> Result<NamePageValidationLimits> {
    let pin_limits = startup_pin_scan_limits(snapshot, network)?;
    Ok(NamePageValidationLimits {
        max_segments: MAX_NAME_PAGE_SEGMENTS,
        max_pages: MAX_NAME_PAGE_GENERATION_BYTES / hns_store::NAME_PAGE_BYTES as u64,
        max_records: maximum_name_page_validation_records(maximum_spill_bytes),
        max_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
        max_spill_bytes: maximum_spill_bytes,
        max_published_roots: pin_limits
            .max_records
            .checked_add(2)
            .ok_or_else(|| anyhow::anyhow!("startup published name-page root limit overflow"))?,
        minimum_filesystem_reserve_bytes: 0,
        deadline,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartupAuditCheckpoint {
    state_digest: [u8; 32],
}

impl StartupAuditCheckpoint {
    fn capture(snapshot: &impl ReadSnapshot, network: Network) -> Result<Self> {
        let mut writer = Writer::new();
        writer.write_u32(SCHEMA_VERSION);
        writer.write_u8(network.canonical_id());
        writer.write_bytes(network.params().genesis_hash.as_bytes());
        writer.write_varbytes(STORAGE_PROFILE);
        writer.write_u64(chain_epoch_from_snapshot(snapshot)?);
        writer.write_u64(mining_generation_from_snapshot(snapshot)?);
        write_startup_audit_tip(&mut writer, best_header_tip_from_snapshot(snapshot)?);
        write_startup_audit_tip(&mut writer, best_block_tip_from_snapshot(snapshot)?);

        let name_tree_root = load_stored_name_tree_root(snapshot)
            .map_err(|error| anyhow::anyhow!("failed to capture name-tree root: {error}"))?;
        let committed_tree_root = load_stored_name_tree_commit_root(snapshot).map_err(|error| {
            anyhow::anyhow!("failed to capture committed name-tree root: {error}")
        })?;
        writer.write_bytes(name_tree_root.as_bytes());
        writer.write_bytes(committed_tree_root.as_bytes());

        let airdrop_field = snapshot
            .get(ColumnFamily::Meta, MetaKey::AirdropField.as_bytes())
            .context("failed to capture durable airdrop field")?
            .ok_or_else(|| anyhow::anyhow!("durable airdrop field is missing"))?;
        writer.write_varbytes(&airdrop_field);

        let mut pin_hasher = Blake2bVar::new(32)
            .map_err(|error| anyhow::anyhow!("failed to initialize pin digest: {error}"))?;
        pin_hasher.update(b"hsrd/startup-audit/name-tree-pins/v2");
        let pin_summary = visit_name_tree_snapshot_pins_bounded(
            snapshot,
            startup_pin_scan_limits(snapshot, network)?,
            |pin| {
                pin_hasher.update(&pin.encode());
                Ok(())
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to capture name-tree pins: {error}"))?;
        let mut pin_digest = [0u8; 32];
        pin_hasher
            .finalize_variable(&mut pin_digest)
            .map_err(|error| anyhow::anyhow!("failed to finalize pin digest: {error}"))?;
        writer.write_u64(pin_summary.records);
        writer.write_u64(pin_summary.bytes);
        writer.write_bytes(&pin_digest);

        write_startup_audit_optional_digest(
            &mut writer,
            snapshot
                .get(ColumnFamily::Snapshots, UNDO_PRUNING_CHECKPOINT_KEY)
                .context("failed to capture undo-pruning checkpoint")?,
        );
        write_startup_audit_optional_digest(
            &mut writer,
            snapshot
                .get(ColumnFamily::Snapshots, NAME_TREE_COMPACTION_CHECKPOINT_KEY)
                .context("failed to capture name-tree compaction checkpoint")?,
        );

        Ok(Self {
            state_digest: blake2b_256(&writer.finish()),
        })
    }

    fn encode(self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(STARTUP_AUDIT_CHECKPOINT_SIZE);
        writer.write_u32(STARTUP_AUDIT_CHECKPOINT_VERSION);
        writer.write_bytes(&self.state_digest);
        let mut raw = writer.finish();
        debug_assert_eq!(raw.len(), STARTUP_AUDIT_CHECKPOINT_BODY_SIZE);
        raw.extend_from_slice(&blake2b_256(&raw));
        raw
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != STARTUP_AUDIT_CHECKPOINT_SIZE {
            anyhow::bail!(
                "startup-audit checkpoint contains {} bytes; expected {STARTUP_AUDIT_CHECKPOINT_SIZE}",
                raw.len()
            );
        }
        let (body, checksum) = raw.split_at(STARTUP_AUDIT_CHECKPOINT_BODY_SIZE);
        if checksum != blake2b_256(body) {
            anyhow::bail!("startup-audit checkpoint checksum mismatch");
        }
        let mut reader = Reader::new(body, STARTUP_AUDIT_CHECKPOINT_BODY_SIZE)?;
        let version = reader.read_u32()?;
        if version != STARTUP_AUDIT_CHECKPOINT_VERSION {
            anyhow::bail!("unsupported startup-audit checkpoint version {version}");
        }
        let checkpoint = Self {
            state_digest: reader.read_hash()?,
        };
        reader.ensure_finished()?;
        Ok(checkpoint)
    }
}

fn write_startup_audit_tip(writer: &mut Writer, tip: Option<ChainTip>) {
    match tip {
        Some(tip) => {
            writer.write_u8(1);
            writer.write_bytes(tip.hash.as_bytes());
            writer.write_u32(tip.height);
            writer.write_bytes(tip.chainwork.as_be_bytes());
        }
        None => writer.write_u8(0),
    }
}

fn write_startup_audit_optional_digest(writer: &mut Writer, value: Option<Vec<u8>>) {
    match value {
        Some(value) => {
            writer.write_u8(1);
            writer.write_bytes(&blake2b_256(&value));
        }
        None => writer.write_u8(0),
    }
}

fn load_startup_audit_checkpoint(
    snapshot: &impl ReadSnapshot,
) -> Result<Option<StartupAuditCheckpoint>> {
    snapshot
        .get(ColumnFamily::Snapshots, STARTUP_AUDIT_CHECKPOINT_KEY)
        .context("failed to read startup-audit checkpoint")?
        .map(|raw| StartupAuditCheckpoint::decode(&raw))
        .transpose()
}

fn mark_node_store_clean(store: &StoreHandle, network: Network) -> Result<()> {
    let snapshot = store.snapshot()?;
    let checkpoint = StartupAuditCheckpoint::capture(&snapshot, network)?.encode();
    drop(snapshot);

    // Publish the checkpoint and clean marker atomically. A clean marker can
    // therefore never refer to a missing or older audit identity.
    let mut batch = store.batch();
    batch
        .put(
            ColumnFamily::Snapshots,
            STARTUP_AUDIT_CHECKPOINT_KEY,
            &checkpoint,
        )
        .context("failed to stage startup-audit checkpoint")?;
    batch
        .put(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes(), &[1])
        .context("failed to stage clean-shutdown marker")?;
    store
        .commit(batch)
        .context("failed to commit clean startup-audit checkpoint")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupAuditKind {
    Exhaustive,
    CleanCheckpoint,
}

#[derive(Clone, Debug)]
struct StartupLifecycle {
    previous_shutdown_clean: bool,
    audit: StartupAuditKind,
    checkpoint_warning: Option<String>,
}

impl AuthorityMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Native => "native",
            Self::NativeExperimental => "native-experimental",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcLimits {
    pub maximum_request_bytes: usize,
    pub maximum_concurrent_requests: usize,
    pub execution_timeout: Duration,
    /// Maximum number of already-memory-resident entries returned by one
    /// collection RPC. Point reads do not consume this budget.
    pub maximum_collection_entries: usize,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            maximum_request_bytes: DEFAULT_RPC_MAX_REQUEST_BYTES,
            maximum_concurrent_requests: DEFAULT_RPC_MAX_CONCURRENT_REQUESTS,
            execution_timeout: DEFAULT_RPC_EXECUTION_TIMEOUT,
            maximum_collection_entries: DEFAULT_RPC_MAX_COLLECTION_ENTRIES,
        }
    }
}

impl RpcLimits {
    fn validate(self) -> Result<()> {
        if self.maximum_request_bytes == 0 || self.maximum_request_bytes > MAX_RPC_REQUEST_BYTES {
            anyhow::bail!(
                "RPC maximum request bytes must be between 1 and {MAX_RPC_REQUEST_BYTES}"
            );
        }
        if self.maximum_concurrent_requests == 0
            || self.maximum_concurrent_requests > MAX_RPC_CONCURRENT_REQUESTS
        {
            anyhow::bail!(
                "RPC maximum concurrent requests must be between 1 and {MAX_RPC_CONCURRENT_REQUESTS}"
            );
        }
        if self.execution_timeout.is_zero() || self.execution_timeout > MAX_RPC_EXECUTION_TIMEOUT {
            anyhow::bail!(
                "RPC execution timeout must be non-zero and at most {} milliseconds",
                MAX_RPC_EXECUTION_TIMEOUT.as_millis()
            );
        }
        if self.maximum_collection_entries == 0
            || self.maximum_collection_entries > MAX_RPC_COLLECTION_ENTRIES
        {
            anyhow::bail!(
                "RPC maximum collection entries must be between 1 and {MAX_RPC_COLLECTION_ENTRIES}"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub network: Network,
    pub data_dir: Option<PathBuf>,
    pub rpc_bind: SocketAddr,
    pub rpc_authorization: Option<RpcAuthorizationHeader>,
    pub rpc_limits: RpcLimits,
    pub log_filter: String,
    pub authority_mode: AuthorityMode,
    /// Explicit operator opt-in for the native mainnet mining canary. This is
    /// necessary but never sufficient to issue a mining authority permit.
    pub mainnet_canary: bool,
    pub acknowledge_incomplete_consensus: bool,
    pub storage_durability: DurabilityPolicy,
    /// Maintain the active-chain transaction lookup index used by historical
    /// diagnostics. Consensus, mining, block relay, and UTXO validation do not
    /// depend on this index.
    pub transaction_index: bool,
    /// Maintain active-chain transaction history by canonical output script.
    pub script_history_index: bool,
    /// Maintain active-chain outpoint-to-spending-transaction mappings.
    pub spender_index: bool,
    /// Maintain the complete wallet restoration profile (script history,
    /// spender lookup, and script UTXOs).
    pub wallet_index: bool,
    /// Explicit Denuo marketplace relay roles. Empty is requester-only.
    pub denuo_relay_roles: DenuoRelayRoles,
    pub name_tree_compaction: NameTreeCompactionConfig,
    pub undo_retention: UndoRetentionConfig,
    pub native_sync: NativeSyncConfig,
    pub mining_engine: MiningEngineConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            data_dir: None,
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], 12037)),
            rpc_authorization: None,
            rpc_limits: RpcLimits::default(),
            log_filter: "info".to_owned(),
            authority_mode: AuthorityMode::Native,
            mainnet_canary: false,
            acknowledge_incomplete_consensus: false,
            storage_durability: DurabilityPolicy::Sync,
            transaction_index: false,
            script_history_index: false,
            spender_index: false,
            wallet_index: false,
            denuo_relay_roles: DenuoRelayRoles::NONE,
            name_tree_compaction: NameTreeCompactionConfig::default(),
            undo_retention: UndoRetentionConfig::default(),
            native_sync: NativeSyncConfig::default(),
            mining_engine: MiningEngineConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Effective optional wallet index profile.
    #[must_use]
    pub const fn wallet_index_profile(&self) -> WalletIndexProfile {
        WalletIndexProfile {
            script_history: self.script_history_index,
            spender: self.spender_index,
            wallet: self.wallet_index,
        }
    }
}

fn encode_transaction_index_mode(enabled: bool) -> Vec<u8> {
    let mut writer = Writer::with_capacity(TRANSACTION_INDEX_MODE_BYTES);
    writer.write_u8(TRANSACTION_INDEX_MODE_VERSION);
    writer.write_u8(u8::from(enabled));
    let mut raw = writer.finish();
    raw.extend_from_slice(&blake2b_256(&raw));
    raw
}

fn decode_transaction_index_mode(raw: &[u8]) -> Result<bool> {
    if raw.len() != TRANSACTION_INDEX_MODE_BYTES {
        anyhow::bail!(
            "transaction-index mode contains {} bytes; expected {TRANSACTION_INDEX_MODE_BYTES}",
            raw.len()
        );
    }
    let (body, checksum) = raw.split_at(TRANSACTION_INDEX_MODE_BODY_BYTES);
    if checksum != blake2b_256(body) {
        anyhow::bail!("transaction-index mode checksum mismatch");
    }
    let mut reader = Reader::new(body, TRANSACTION_INDEX_MODE_BODY_BYTES)
        .map_err(|error| anyhow::anyhow!("invalid transaction-index mode: {error}"))?;
    let version = reader
        .read_u8()
        .map_err(|error| anyhow::anyhow!("invalid transaction-index mode: {error}"))?;
    if version != TRANSACTION_INDEX_MODE_VERSION {
        anyhow::bail!("unsupported transaction-index mode version {version}");
    }
    let enabled = match reader
        .read_u8()
        .map_err(|error| anyhow::anyhow!("invalid transaction-index mode: {error}"))?
    {
        0 => false,
        1 => true,
        value => anyhow::bail!("invalid transaction-index mode flag {value}"),
    };
    reader
        .ensure_finished()
        .map_err(|error| anyhow::anyhow!("invalid transaction-index mode: {error}"))?;
    Ok(enabled)
}

pub fn validate_node_config(config: &NodeConfig) -> Result<()> {
    config.rpc_limits.validate()?;

    match config.authority_mode {
        AuthorityMode::Disabled | AuthorityMode::Native => {}
        AuthorityMode::NativeExperimental => {
            if !cfg!(any(feature = "experimental-authority", test)) {
                anyhow::bail!(
                    "native experimental authority requires the `experimental-authority` Cargo feature"
                );
            }
            if !config.acknowledge_incomplete_consensus {
                anyhow::bail!(
                    "native experimental authority requires --acknowledge-incomplete-consensus"
                );
            }
            if !matches!(config.network, Network::Regtest | Network::Simnet) {
                anyhow::bail!(
                    "native experimental authority is restricted to regtest and simnet until every documented parity gate passes"
                );
            }
        }
    }

    validate_mainnet_canary_config(config)?;

    if config.native_sync.connect_active_state
        && !config.acknowledge_incomplete_consensus
        && config.authority_mode != AuthorityMode::Native
    {
        anyhow::bail!(
            "active-state synchronization requires --acknowledge-incomplete-consensus until historical and live parity gates pass"
        );
    }

    config.name_tree_compaction.validate()?;
    config
        .native_sync
        .validate(config.authority_mode, config.network)?;
    config
        .mining_engine
        .validate(&config.native_sync, config.authority_mode)
}

fn validate_mainnet_canary_config(config: &NodeConfig) -> Result<()> {
    if !config.mainnet_canary {
        return Ok(());
    }
    if config.network != Network::Mainnet
        || config.authority_mode != AuthorityMode::Native
        || config.acknowledge_incomplete_consensus
        || config.data_dir.as_ref().is_none_or(|path| {
            !path.is_absolute()
                || path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
        })
        || !config.rpc_bind.ip().is_loopback()
        || config.rpc_authorization.is_none()
        || config.storage_durability != DurabilityPolicy::Sync
        || !config.native_sync.enabled
        || config.native_sync.headers_only
        || !config.native_sync.connect_active_state
        || config.native_sync.maximum_outbound < 4
        || (!config.native_sync.discovery && config.native_sync.connect_keys.len() < 2)
        || !config.mining_engine.enabled
        || !config.mining_engine.transaction_relay
    {
        anyhow::bail!(
            "mainnet canary requires native authority, persistent sync-durable state, authenticated loopback RPC, full native active-state sync, at least four outbound slots with discovery or two pinned peers, the mining engine with transaction relay, HSD-compatible rollback history, and no incomplete-consensus bypass"
        );
    }
    Ok(())
}

fn authority_can_mine_with_readiness(config: &NodeConfig, consensus_complete: bool) -> bool {
    match config.authority_mode {
        AuthorityMode::Native => {
            consensus_complete
                && validate_node_config(config).is_ok()
                && (config.network != Network::Mainnet || config.mainnet_canary)
        }
        AuthorityMode::NativeExperimental => validate_node_config(config).is_ok(),
        AuthorityMode::Disabled => false,
    }
}

fn authority_can_mine(config: &NodeConfig) -> bool {
    authority_can_mine_with_readiness(config, consensus_readiness().complete())
}

#[derive(Clone, Debug)]
struct MiningAuthorityPermit {
    generation: MiningGeneration,
    tip: BlockHash,
    experimental_bypass: bool,
    _private: (),
}

fn issue_authority_permit(
    config: &NodeConfig,
    durable: &DurableMiningState,
) -> Option<MiningAuthorityPermit> {
    if !authority_can_mine(config) {
        return None;
    }
    let snapshot = durable.snapshot.as_ref()?;

    // The regtest/simnet experimental path may bypass completeness only behind
    // its compile-time/runtime gates. Native mainnet never bypasses readiness,
    // synchronization, or `durable.authoritative`.
    let experimental_bypass = matches!(config.authority_mode, AuthorityMode::NativeExperimental)
        && matches!(config.network, Network::Regtest | Network::Simnet)
        && config.acknowledge_incomplete_consensus;
    if (!durable.authoritative || (config.network == Network::Mainnet && !durable.synchronized))
        && !experimental_bypass
    {
        return None;
    }

    Some(MiningAuthorityPermit {
        generation: durable.generation,
        tip: snapshot.tip.hash,
        experimental_bypass,
        _private: (),
    })
}

fn durable_tip_can_authorize(config: &NodeConfig, durable: &DurableMiningState) -> bool {
    issue_authority_permit(config, durable).is_some()
}

fn consensus_readiness() -> RpcConsensusReadiness {
    RpcConsensusReadiness {
        header_pow_difficulty: true,
        checkpoints_and_deployments: true,
        block_syntax: true,
        absolute_finality: true,
        sighash_primitives: true,
        relative_lock_primitives: true,
        witness_program_foundation: true,
        signature_backend: true,
        input_authorization_fail_closed: true,
        relative_sequence_locks: true,
        scripts: true,
        covenant_linkage: true,
        contextual_covenants: true,
        claims_and_airdrops: true,
        name_state: true,
        urkel_roots: true,
        sequence_consistent_snapshots: true,
        durable_store_identity: true,
        side_chain_storage: true,
        best_work_fork_choice: true,
        validated_reorg_planning: true,
        atomic_reorganizations: true,
        wal_durability: true,
        // Qualified by the stopped-state pass at height 339,654 plus the
        // exact read-only 288-block disconnect/reconnect transcript ending at
        // HISTORICAL_REPLAY_QUALIFICATION_BLOCK.
        historical_replay: true,
        // Qualified by the independently generated pinned-HSD corpora consumed
        // by hns-consensus and hns-state. The generators cover 24
        // noncontextual transaction/block cases and 12 contextual
        // state-boundary cases, including atomic rejection controls.
        invalid_corpus: true,
    }
}

fn readiness_blockers(readiness: &RpcConsensusReadiness) -> Vec<String> {
    let checks = [
        (
            readiness.header_pow_difficulty,
            "header PoW and difficulty parity",
        ),
        (
            readiness.checkpoints_and_deployments,
            "checkpoints and deployment-state parity",
        ),
        (readiness.block_syntax, "block syntax and commitments"),
        (readiness.absolute_finality, "absolute locktime finality"),
        (readiness.sighash_primitives, "signature-hash oracle parity"),
        (
            readiness.relative_lock_primitives,
            "relative-lock primitive parity",
        ),
        (
            readiness.witness_program_foundation,
            "fail-closed witness-program foundation",
        ),
        (
            readiness.signature_backend,
            "native pinned secp256k1 verification backend",
        ),
        (
            readiness.input_authorization_fail_closed,
            "fail-closed UTXO input authorization",
        ),
        (
            readiness.relative_sequence_locks,
            "relative sequence-lock validation",
        ),
        (readiness.scripts, "complete script and witness validation"),
        (
            readiness.covenant_linkage,
            "non-coinbase covenant linkage oracle parity",
        ),
        (
            readiness.contextual_covenants,
            "contextual covenant transition validation",
        ),
        (
            readiness.claims_and_airdrops,
            "claim and airdrop proof/accounting parity",
        ),
        (readiness.name_state, "complete name-state transitions"),
        (readiness.urkel_roots, "Urkel root and proof parity"),
        (
            readiness.sequence_consistent_snapshots,
            "sequence-consistent storage snapshots",
        ),
        (
            readiness.durable_store_identity,
            "durable network/genesis/storage-profile binding",
        ),
        (
            readiness.side_chain_storage,
            "durable side-chain block storage",
        ),
        (
            readiness.best_work_fork_choice,
            "strict best-work fork choice",
        ),
        (
            readiness.validated_reorg_planning,
            "validated reorganization planning",
        ),
        (
            readiness.atomic_reorganizations,
            "atomic reorganization storage",
        ),
        (
            readiness.wal_durability,
            "explicit WAL/sync durability policy",
        ),
        (
            readiness.historical_replay,
            "complete historical mainnet replay",
        ),
        (
            readiness.invalid_corpus,
            "invalid and mutated corpus parity",
        ),
    ];

    checks
        .into_iter()
        .filter(|(ready, _)| !*ready)
        .map(|(_, label)| label.to_owned())
        .collect()
}

fn authority_info(config: &NodeConfig, durable: &DurableMiningState) -> RpcAuthorityInfo {
    let readiness = consensus_readiness();
    let consensus_complete = readiness.complete();
    let experimental_bypass_active = issue_authority_permit(config, durable)
        .is_some_and(|permit| permit.experimental_bypass)
        && !consensus_complete;
    let permit = issue_authority_permit(config, durable);
    let can_authorize = permit.is_some();
    let mut blockers = readiness_blockers(&readiness);

    match config.authority_mode {
        AuthorityMode::Disabled => blockers.push("authority mode is disabled".to_owned()),
        AuthorityMode::Native => {}
        AuthorityMode::NativeExperimental
            if !cfg!(any(feature = "experimental-authority", test)) =>
        {
            blockers.push("experimental-authority feature is not enabled".to_owned())
        }
        AuthorityMode::NativeExperimental if !config.acknowledge_incomplete_consensus => {
            blockers.push("incomplete consensus has not been acknowledged".to_owned())
        }
        AuthorityMode::NativeExperimental => {}
    }

    if durable.snapshot.is_some() && !durable.authoritative {
        blockers.push("current tip is staged but not consensus-authoritative".to_owned());
    }
    if config.network == Network::Mainnet && !config.mainnet_canary {
        blockers.push("mainnet mining canary is not explicitly enabled".to_owned());
    }
    if config.network == Network::Mainnet && !durable.synchronized {
        blockers.push("best header and active-state tip are not synchronized".to_owned());
    }

    blockers.sort();
    blockers.dedup();

    RpcAuthorityInfo {
        mode: config.authority_mode.as_str().to_owned(),
        synchronized: durable.synchronized,
        mainnet_canary_enabled: config.network == Network::Mainnet && config.mainnet_canary,
        mainnet_canary_active: config.network == Network::Mainnet
            && config.mainnet_canary
            && can_authorize,
        experimental_feature_enabled: cfg!(any(feature = "experimental-authority", test)),
        experimental_bypass_active,
        incomplete_consensus_acknowledged: config.acknowledge_incomplete_consensus,
        consensus_complete,
        can_authorize_mining_templates: can_authorize,
        can_accept_mining_candidates: can_authorize,
        blockers,
        readiness,
    }
}

fn rpc_mining_engine_info(diagnostics: MiningEngineDiagnostics) -> RpcMiningEngineInfo {
    RpcMiningEngineInfo {
        enabled: diagnostics.enabled,
        observation_only: diagnostics.observation_only,
        transaction_relay_enabled: diagnostics.transaction_relay_enabled,
        mempool: diagnostics.mempool,
        maximum_template_variants: diagnostics.maximum_template_variants,
        template_build_workers: diagnostics.template_build_workers,
        template_build_queue_capacity: diagnostics.template_build_queue_capacity,
        cached_template_variants: diagnostics.cached_template_variants,
        pending_publications: diagnostics.pending_publications,
        maximum_pending_publications: diagnostics.maximum_pending_publications,
        publication_retry_interval_ms: diagnostics.publication_retry_interval_ms,
        can_build_templates: diagnostics.can_build_templates,
        can_publish_solved_blocks: diagnostics.can_publish_solved_blocks,
        blockers: diagnostics.blockers,
    }
}

pub(crate) fn rpc_experimental_registry_info(
    summary: &DenuoSummary,
) -> RpcExperimentalRegistryInfo {
    RpcExperimentalRegistryInfo {
        name: summary.identity.name.clone(),
        registry_id: summary.identity.registry_id.clone(),
        registry_version: summary.identity.registry_version,
        registry_protocol_version: summary.identity.registry_protocol_version,
        fingerprint: summary.identity.fingerprint.clone(),
        wire_profile: summary.identity.wire_profile.clone(),
        assignment_status: summary.identity.status.clone(),
        service_bit: summary.identity.service_bit,
        local_service_mask: summary.local_service_mask,
        packet_type: summary.identity.packet_type,
        advertised: summary.advertised,
        maximum_packet_payload: summary.identity.maximum_packet_payload,
        maximum_nested_payload: summary.identity.maximum_nested_payload,
        maximum_registry_payload: summary.identity.maximum_registry_negotiation_payload,
        awaiting_version_peers: summary.live.awaiting_version,
        local_disabled_peers: summary.live.local_disabled,
        eligible_peers: summary.live.eligible,
        negotiating_peers: summary.live.pending,
        negotiated_peers: summary.live.negotiated,
        not_advertised_peers: summary.live.not_advertised,
        disabled_peers: summary.live.disabled,
        outbound_messages_admitted: summary.process.admitted(),
        inbound_messages_received: summary.process.received(),
        rejected_messages: summary.process.rejected(),
        agreements_computed: summary.process.agreements_computed,
        disabled_sessions: summary.process.disabled,
        rejection_reasons: summary
            .rejection_reasons
            .iter()
            .map(|reason| RpcExperimentalRejectionCount {
                reason: reason.reason.as_str().to_owned(),
                count: reason.count,
            })
            .collect(),
    }
}

pub(crate) fn rpc_hip76_info(peers: &[PeerSnapshot]) -> RpcHip76Info {
    let mut hip76 = Hip76Summary::default();
    let mut remote_provider_advertised_peers = 0u64;
    let mut registry_negotiated_peers = 0u64;
    let mut peer_faulted_peers = 0u64;
    for peer in peers {
        let diagnostics = &peer.hip76;
        hip76.observe(diagnostics);
        remote_provider_advertised_peers = remote_provider_advertised_peers
            .saturating_add(u64::from(diagnostics.remote_provider_advertised));
        registry_negotiated_peers =
            registry_negotiated_peers.saturating_add(u64::from(diagnostics.registry_negotiated));
        peer_faulted_peers = peer_faulted_peers.saturating_add(u64::from(diagnostics.peer_faulted));
    }
    RpcHip76Info {
        semantic_version: hip76.identity.semantic_version,
        service_bit: hip76.identity.service_bit,
        request_packet_type: hip76.identity.request_packet_type,
        response_packet_type: hip76.identity.response_packet_type,
        maximum_query_body_size: hip76.identity.maximum_query_body_size,
        maximum_request_payload_size: hip76.identity.maximum_request_payload_size,
        maximum_response_body_size: hip76.identity.maximum_response_body_size,
        maximum_response_payload_size: hip76.identity.maximum_response_payload_size,
        registry_fingerprint: hip76.identity.registry_fingerprint,
        registry_wire_profile: hip76.identity.registry_wire_profile,
        experimental_status: hip76.identity.experimental_status,
        requester_default: hip76.identity.requester_default,
        provider_default_opted_in: hip76.identity.provider_default_opted_in,
        live_peers: hip76.peers,
        awaiting_registry_peers: hip76.phases.awaiting_registry,
        active_peers: hip76.phases.active,
        revoked_peers: hip76.phases.revoked,
        faulted_peers: hip76.phases.faulted,
        disconnected_peers: hip76.phases.disconnected,
        requester_enabled_peers: hip76.requester_enabled_peers,
        requester_eligible_peers: hip76.requester_eligible_peers,
        provider_opted_in_peers: hip76.provider_opted_in_peers,
        provider_backend_ready_peers: hip76.provider_backend_ready_peers,
        provider_available_peers: hip76.provider_available_peers,
        local_provider_advertised_peers: hip76.provider_advertised_peers,
        remote_provider_advertised_peers,
        registry_negotiated_peers,
        peer_faulted_peers,
        outbound_live_requests: hip76.outbound_live_requests,
        inbound_live_requests: hip76.inbound_live_requests,
        outbound_requests_created: hip76.process.outbound_requests_created,
        outbound_requests_queue_admitted: hip76.process.outbound_requests_queue_admitted,
        outbound_requests_socket_written: hip76.process.outbound_requests_socket_written,
        inbound_requests_received: hip76.process.inbound_requests_received,
        inbound_requests_accepted: hip76.process.inbound_requests_accepted,
        provider_responses_created: hip76.process.provider_responses_created,
        provider_responses_queue_admitted: hip76.process.provider_responses_queue_admitted,
        provider_responses_socket_written: hip76.process.provider_responses_socket_written,
        requester_responses_received: hip76.process.requester_responses_received,
        outbound_socket_write_failures: hip76.process.outbound_socket_write_failures,
        outbound_queue_dropped_stale: hip76.process.outbound_queue_dropped_stale,
        expired_requests: hip76.process.expired_requests,
        revoked_requests: hip76.process.revoked_requests,
        rejected_operations: hip76.process.rejected_operations,
    }
}

pub(crate) fn rpc_odoh_info(status: &OdohRequesterStatus) -> RpcOdohInfo {
    RpcOdohInfo {
        schema_version: status.schema_version,
        phase: status.phase.as_str().to_owned(),
        policy_generation: status.policy_generation,
        requester_enabled: status.requester_enabled,
        requester_default_enabled: status.requester_default_enabled,
        service_bit: status.service_bit,
        packet_type: status.packet_type,
        registry_fingerprint: status.registry_fingerprint.clone(),
        registry_wire_profile: status.registry_wire_profile.clone(),
        eligible_authenticated_proxies: status.eligible_authenticated_proxies,
        faulted_proxies: status.faulted_proxies,
        target_slots: status.target_slots,
        current_targets: status.current_targets,
        earliest_target_expiry: status.earliest_target_expiry,
        live_requests: status.live_requests,
        maximum_live_requests: status.maximum_live_requests,
        cache_generation: status.cache_generation,
        cache_dirty: status.cache_dirty,
        policy_dirty: status.policy_dirty,
        durable_state_dirty: status.durable_state_dirty,
        trusted_time_high_water: status.trusted_time_high_water,
        proxy_provider_available: status.proxy_provider_available,
        target_provider_available: status.target_provider_available,
        output_provider_available: status.output_provider_available,
        requests_created: status.process.requests_created,
        requests_socket_written: status.process.requests_socket_written,
        responses_received: status.process.responses_received,
        configurations_installed: status.process.configurations_installed,
        socket_write_failures: status.process.socket_write_failures,
        expired_requests: status.process.expired_requests,
        revoked_requests: status.process.revoked_requests,
        rejected_packets: status.process.rejected_packets,
    }
}

pub(crate) fn rpc_hnsr_info(status: &HnsrCoordinatorStatus) -> RpcHnsrInfo {
    let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    RpcHnsrInfo {
        schema_version: status.schema_version,
        state_generation: status.state_generation,
        requester_generation: status.requester.generation,
        relay_generation: status.relay.generation,
        requester_enabled: status.requester.enabled,
        requester_default_enabled: status.requester_default_enabled,
        opaque_relay_enabled: status.relay.enabled,
        opaque_relay_default_enabled: status.opaque_relay_default_enabled,
        relay_service_available: status.relay_service_available,
        relay_service_advertised: status.relay_service_advertised,
        endpoint_role_available: status.endpoint_role_available,
        rendezvous_role_available: status.rendezvous_role_available,
        plaintext_transport_available: status.plaintext_transport_available,
        service_bit: status.service_bit,
        packet_type: status.packet_type,
        profile: status.profile,
        profile_registry_fingerprint: status.profile_registry_fingerprint.clone(),
        profile_registry_version: status.profile_registry_version,
        profile_registry_protocol_version: status.profile_registry_protocol_version,
        profile_registry_wire_profile: status.profile_registry_wire_profile.clone(),
        eligible_authenticated_relays: count(status.eligible_authenticated_relays),
        faulted_peers: count(status.faulted_peers),
        reservations: count(status.reservations),
        requester_pending_circuits: count(status.requester.pending_circuits),
        requester_active_circuits: count(status.requester.active_circuits),
        relay_pending_circuits: count(status.relay.pending_circuits),
        relay_active_circuits: count(status.relay.active_circuits),
        queued_bytes: count(
            status
                .requester
                .queued_bytes
                .saturating_add(status.relay.queued_bytes),
        ),
        queued_actions: count(
            status
                .requester
                .queued_actions
                .saturating_add(status.relay.queued_actions),
        ),
        trusted_time_high_water: status.trusted_time_high_water,
        durable_state_dirty: status.durable_state_dirty,
        admitted_opens: status
            .requester
            .admitted_opens
            .saturating_add(status.relay.admitted_opens),
        opened_circuits: status
            .requester
            .opened_circuits
            .saturating_add(status.relay.opened_circuits),
        bytes_sent: status
            .requester
            .bytes_sent
            .saturating_add(status.relay.bytes_sent),
        bytes_received: status
            .requester
            .bytes_received
            .saturating_add(status.relay.bytes_received),
        socket_write_failures: status.process.socket_write_failures,
        expired_work: status.process.expired_work,
        revoked_work: status
            .requester
            .revoked_work
            .saturating_add(status.relay.revoked_work),
        rejected_packets: status.process.rejected_packets,
    }
}

fn rpc_inactive_odoh_info(network: Network, requester_enabled: bool) -> RpcOdohInfo {
    let config = OdohRequesterConfig {
        enabled: requester_enabled,
        allow_private_targets: matches!(network, Network::Regtest | Network::Simnet),
        ..OdohRequesterConfig::default()
    };
    let now = current_unix_time().unwrap_or_default();
    let mut runtime =
        OdohRequesterRuntime::new(OdohNetworkBinding::for_network(network), config, 1, now)
            .expect("built-in ODoH requester defaults are valid");
    rpc_odoh_info(&runtime.status(now, 0))
}

fn rpc_inactive_hnsr_info(
    network: Network,
    requester_enabled: bool,
    relay_enabled: bool,
) -> RpcHnsrInfo {
    let mut config = HnsrCoordinatorConfig::for_network(network);
    config.requester_enabled = requester_enabled;
    config.opaque_relay_enabled = relay_enabled;
    let coordinator = HnsrCoordinator::fresh(config, current_unix_time().unwrap_or_default())
        .expect("built-in HNSR coordinator defaults are valid");
    rpc_hnsr_info(&coordinator.status(0))
}

fn parity_info() -> RpcParityInfo {
    RpcParityInfo {
        oracle: "handshake-org/hsd".to_owned(),
        oracle_revision: HSD_ORACLE_REVISION.to_owned(),
        state: "historical-replay-qualified-offline".to_owned(),
        configured: false,
        historical_replay_complete: true,
        invalid_corpus_complete: true,
        last_compared_height: Some(HISTORICAL_REPLAY_QUALIFICATION_HEIGHT),
        last_matching_block: Some(HISTORICAL_REPLAY_QUALIFICATION_BLOCK),
        divergence: None,
    }
}

#[derive(Debug)]
pub struct NodeService {
    config: NodeConfig,
    state: NodeState,
    mining_events: MiningEventHub,
    mining_engine_templates: Arc<Mutex<TemplateCoordinator>>,
    mempool_name_context: Mutex<mining_engine::ActiveMempoolNameCache>,
    claim_dnssec: OpenSslDnssecVerifier,
    airdrop_signatures: NativeAirdropSignatureVerifier,
    denuo_relay: DenuoRelayHandle,
}

/// Maximum number of canonical-state commands that may wait behind the
/// dedicated writer. Keeping this ceiling in the node crate prevents a caller
/// from turning writer serialization into an unbounded memory queue.
pub const MAX_CANONICAL_WRITER_QUEUE_CAPACITY: usize = 1_024;
pub const DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY: usize = 64;

/// Exact durable chain generation used to reject work prepared against an old
/// canonical view. The epoch and tip are captured from one store snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalEpoch {
    /// Process-local generation advanced after every accepted mutation,
    /// including a closure that changes memory before returning an error.
    pub writer_sequence: u64,
    pub chain_epoch: u64,
    pub tip: Option<ChainTip>,
}

impl CanonicalEpoch {
    pub fn chain(&self) -> CanonicalChainEpoch {
        CanonicalChainEpoch {
            chain_epoch: self.chain_epoch,
            tip: self.tip.clone(),
        }
    }
}

/// Chain-only stale guard for work that is independent of mempool and other
/// process-local writer mutations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanonicalChainEpoch {
    pub chain_epoch: u64,
    pub tip: Option<ChainTip>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamePageCompactionDue {
    pub epoch: CanonicalChainEpoch,
    pub generation: u64,
    pub active_segment: u32,
}

#[derive(Clone, Debug)]
enum ExpectedCanonicalState {
    Exact(CanonicalEpoch),
    Chain(CanonicalChainEpoch),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalWriterError {
    StaleEpoch {
        operation: &'static str,
        expected: CanonicalEpoch,
        actual: CanonicalEpoch,
    },
    StaleChainEpoch {
        operation: &'static str,
        expected: CanonicalChainEpoch,
        actual: CanonicalChainEpoch,
    },
    QueueFull {
        capacity: usize,
    },
    Busy,
    ShuttingDown,
    Stopped,
    Terminal {
        reason: String,
    },
    ResponseType {
        operation: &'static str,
    },
}

impl Display for CanonicalWriterError {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        match self {
            Self::StaleEpoch {
                operation,
                expected,
                actual,
            } => write!(
                formatter,
                "canonical writer rejected stale {operation} operation: expected writer/chain epoch {}/{} at {:?}, current writer/chain epoch {}/{} at {:?}",
                expected.writer_sequence,
                expected.chain_epoch,
                expected.tip,
                actual.writer_sequence,
                actual.chain_epoch,
                actual.tip
            ),
            Self::StaleChainEpoch {
                operation,
                expected,
                actual,
            } => write!(
                formatter,
                "canonical writer rejected stale chain-scoped {operation} operation: expected chain epoch {} at {:?}, current chain epoch {} at {:?}",
                expected.chain_epoch, expected.tip, actual.chain_epoch, actual.tip
            ),
            Self::QueueFull { capacity } => write!(
                formatter,
                "canonical writer queue is full at its {capacity}-command bound"
            ),
            Self::Busy => write!(formatter, "canonical writer generation changed during read"),
            Self::ShuttingDown => write!(formatter, "canonical writer is shutting down"),
            Self::Stopped => write!(formatter, "canonical writer has stopped"),
            Self::Terminal { reason } => {
                write!(formatter, "canonical writer stopped fail-closed: {reason}")
            }
            Self::ResponseType { operation } => write!(
                formatter,
                "canonical writer returned an unexpected response type for {operation}"
            ),
        }
    }
}

impl StdError for CanonicalWriterError {}

/// One atomically published, immutable view of the state that must agree when
/// mining, RPC, and mempool readers make an authorization decision.
#[derive(Clone, Debug)]
pub struct PublishedNodeView {
    canonical_epoch: CanonicalEpoch,
    mining_generation: MiningGeneration,
    observed_mining_snapshot: Option<Arc<MiningSnapshot>>,
    authoritative_mining_snapshot: Option<Arc<MiningSnapshot>>,
    mining_authoritative: bool,
    mining_synchronized: bool,
    mempool: PublishedMempoolView,
    storage_operational: bool,
    storage_fence_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PublishedMempoolView {
    pub info: MempoolInfo,
    pub ordered_txids: OrderedTxidSnapshot,
    snapshot: MempoolSnapshot,
    ordered_txids_generation: u64,
}

pub(crate) type PublishedMiningInputs = (
    CanonicalEpoch,
    Option<Arc<MiningSnapshot>>,
    Option<Arc<MiningSnapshot>>,
    bool,
    MempoolInfo,
    MempoolSnapshot,
);

impl PublishedMempoolView {
    fn capture(mempool: &MemoryMempool) -> Result<Self> {
        let before = mempool.info();
        let snapshot = mempool.snapshot();
        let ordered_txids = mempool.ordered_txids_snapshot();
        let after = mempool.info();
        if before != after {
            anyhow::bail!("mempool changed while its immutable publication was being captured");
        }
        Self::new(after, snapshot, ordered_txids, before.generation)
    }

    fn new(
        info: MempoolInfo,
        snapshot: MempoolSnapshot,
        ordered_txids: OrderedTxidSnapshot,
        ordered_txids_generation: u64,
    ) -> Result<Self> {
        let published = Self {
            info,
            ordered_txids,
            snapshot,
            ordered_txids_generation,
        };
        published.validate()?;
        Ok(published)
    }

    fn validate(&self) -> Result<()> {
        if self.info.generation != self.snapshot.generation()
            || self.info.generation != self.ordered_txids_generation
        {
            anyhow::bail!(
                "published mempool generations disagree: info={}, snapshot={}, ordered={}",
                self.info.generation,
                self.snapshot.generation(),
                self.ordered_txids_generation
            );
        }
        if self.info.transaction_count != self.snapshot.len()
            || self.info.transaction_count != self.ordered_txids.len()
        {
            anyhow::bail!(
                "published mempool transaction counts disagree: info={}, snapshot={}, ordered={}",
                self.info.transaction_count,
                self.snapshot.len(),
                self.ordered_txids.len()
            );
        }
        Ok(())
    }

    /// O(1) clone of the persistent maps for this exact published generation.
    pub fn snapshot(&self) -> MempoolSnapshot {
        self.snapshot.clone()
    }
}

impl PublishedNodeView {
    pub fn canonical_epoch(&self) -> &CanonicalEpoch {
        &self.canonical_epoch
    }

    pub const fn mining_generation(&self) -> MiningGeneration {
        self.mining_generation
    }

    pub fn observed_mining_snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        self.observed_mining_snapshot.clone()
    }

    pub fn authoritative_mining_snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        self.authoritative_mining_snapshot.clone()
    }

    pub const fn mining_authoritative(&self) -> bool {
        self.mining_authoritative
    }

    pub const fn mining_synchronized(&self) -> bool {
        self.mining_synchronized
    }

    pub fn mempool_info(&self) -> &MempoolInfo {
        &self.mempool.info
    }

    pub fn ordered_txids(&self) -> &OrderedTxidSnapshot {
        &self.mempool.ordered_txids
    }

    pub fn mempool_snapshot(&self) -> MempoolSnapshot {
        self.mempool.snapshot()
    }

    pub fn mempool_view(&self) -> &PublishedMempoolView {
        &self.mempool
    }

    pub const fn storage_operational(&self) -> bool {
        self.storage_operational
    }

    pub fn storage_fence_reason(&self) -> Option<&str> {
        self.storage_fence_reason.as_deref()
    }
}

#[derive(Debug)]
struct NodeRuntimeState {
    published: RwLock<Arc<PublishedNodeView>>,
    /// Even values identify stable published generations. The writer stores
    /// an odd value before invoking any mutation closure and returns to even
    /// only after the corresponding immutable view is published.
    publication_sequence: AtomicU64,
    accepting: AtomicBool,
    terminal: Mutex<Option<String>>,
}

impl NodeRuntimeState {
    fn published_unchecked(&self) -> Arc<PublishedNodeView> {
        Arc::clone(
            &self
                .published
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    fn published(&self) -> Arc<PublishedNodeView> {
        // The last published Arc is immutable and remains a valid committed
        // generation while a bounded writer slice is in flight. Callers that
        // must bind new durable reads to an epoch use `with_stable_epoch_read`.
        self.published_unchecked()
    }

    fn publish(&self, view: PublishedNodeView) {
        *self
            .published
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(view);
    }

    fn terminal_reason(&self) -> Option<String> {
        self.terminal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn stop_fail_closed(&self, reason: impl Into<String>) -> String {
        self.accepting.store(false, Ordering::Release);
        let mut terminal = self
            .terminal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if terminal.is_none() {
            *terminal = Some(reason.into());
        }
        terminal.clone().expect("terminal reason was initialized")
    }
}

type CanonicalCommandValue = Box<dyn Any + Send>;
type CanonicalCommandOperation =
    Box<dyn FnOnce(&mut NodeService) -> Result<CanonicalCommandValue> + Send + 'static>;
type CanonicalReadOperation =
    Box<dyn FnOnce(&NodeService) -> Result<CanonicalCommandValue> + Send + 'static>;

enum CanonicalWriterCommand {
    Execute {
        expected: Option<ExpectedCanonicalState>,
        operation: &'static str,
        execute: CanonicalCommandOperation,
        _admission: OwnedSemaphorePermit,
        reply: oneshot::Sender<Result<CanonicalCommandValue>>,
    },
    Inspect {
        operation: &'static str,
        inspect: CanonicalReadOperation,
        _admission: OwnedSemaphorePermit,
        reply: oneshot::Sender<Result<CanonicalCommandValue>>,
    },
    Shutdown {
        mark_clean: bool,
        reply: oneshot::Sender<Result<()>>,
    },
}

struct NodeRuntimeInner {
    state: Arc<NodeRuntimeState>,
    sender: mpsc::Sender<CanonicalWriterCommand>,
    admission_slots: Arc<Semaphore>,
    admission: Mutex<()>,
    join: AsyncMutex<Option<thread::JoinHandle<()>>>,
    queue_capacity: usize,
}

/// Cloneable immutable access to durable state and the coherent published
/// chain/mempool/mining generation. This handle never exposes a mutable store
/// or mutable header index.
#[derive(Clone)]
pub struct NodeReadHandle {
    config: Arc<NodeConfig>,
    store: StoreHandle,
    headers: SharedHeaderIndex,
    transaction_index: bool,
    wallet_index_profile: WalletIndexProfile,
    mining_events: MiningEventHub,
    mining_engine_templates: Arc<Mutex<TemplateCoordinator>>,
    state: Arc<NodeRuntimeState>,
    runtime: Weak<NodeRuntimeInner>,
    point_read_concurrency: Arc<Semaphore>,
    collection_concurrency: Arc<Semaphore>,
    template_build_admission: Arc<Semaphore>,
    template_build_workers: Arc<Semaphore>,
}

impl NodeReadHandle {
    pub fn config(&self) -> Arc<NodeConfig> {
        Arc::clone(&self.config)
    }

    pub fn network(&self) -> Network {
        self.config.network
    }

    /// Effective durable wallet-index profile for this runtime.
    #[must_use]
    pub const fn wallet_index_profile(&self) -> WalletIndexProfile {
        self.wallet_index_profile
    }

    /// Return the last immutable publication for observation. This remains
    /// available while a writer generation is in flight and may be stale
    /// after shutdown; authority-bearing callers must use a checked accessor
    /// such as [`Self::published_mempool`] or [`Self::stable_canonical_epoch`].
    pub fn published(&self) -> Arc<PublishedNodeView> {
        self.state.published()
    }

    pub fn canonical_epoch(&self) -> CanonicalEpoch {
        self.published().canonical_epoch.clone()
    }

    pub fn ensure_storage_operational(&self) -> Result<()> {
        if let Some(reason) = self.state.terminal_reason() {
            return Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                reason,
            }));
        }
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(anyhow::Error::new(CanonicalWriterError::ShuttingDown));
        }
        let _runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        if let Some(reason) = self.state.terminal_reason() {
            return Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                reason,
            }));
        }
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(anyhow::Error::new(CanonicalWriterError::ShuttingDown));
        }
        let published = self.published();
        if published.storage_operational {
            Ok(())
        } else {
            anyhow::bail!(
                "node is fail-closed: {}",
                published
                    .storage_fence_reason
                    .as_deref()
                    .unwrap_or("canonical writer is unavailable")
            )
        }
    }

    pub fn mining_snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        self.ensure_storage_operational().ok()?;
        let snapshot = self.published().authoritative_mining_snapshot();
        self.ensure_storage_operational().ok()?;
        snapshot
    }

    pub fn observed_mining_snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        self.published().observed_mining_snapshot()
    }

    pub fn subscribe_observed_mining_events(&self) -> MiningSubscriptions {
        self.mining_events.subscribe()
    }

    pub fn subscribe_mining_events(&self) -> Result<MiningSubscriptions> {
        self.ensure_storage_operational()?;
        if self.published().mining_authoritative {
            let subscriptions = self.mining_events.subscribe();
            self.ensure_storage_operational()?;
            Ok(subscriptions)
        } else {
            anyhow::bail!("authoritative mining subscriptions are disabled")
        }
    }

    pub async fn rpc_diagnostic_service(&self) -> Result<BasicRpcService> {
        self.inspect_bounded("RPC diagnostic snapshot", |node| {
            node.rpc_diagnostic_service()
        })
        .await
    }

    pub(crate) fn rpc_read_context(&self) -> Result<RpcReadContext> {
        self.ensure_storage_operational()?;
        Ok(RpcReadContext {
            store: self.store.clone(),
            headers: self.headers.clone(),
            network: self.config.network,
            transaction_index: self.transaction_index,
            point_read_concurrency: Arc::clone(&self.point_read_concurrency),
            collection_concurrency: Arc::clone(&self.collection_concurrency),
        })
    }

    /// Checked O(1) clone of the last committed immutable mempool generation.
    /// That generation deliberately remains readable while a writer mutation
    /// is in flight. Terminal, stopped, and shutting-down runtimes do not
    /// expose their last stale generation through this authority-bearing
    /// accessor.
    pub fn published_mempool(&self) -> Result<PublishedMempoolView> {
        Ok(self.checked_published()?.mempool.clone())
    }

    fn checked_published(&self) -> Result<Arc<PublishedNodeView>> {
        self.ensure_storage_operational()?;
        let published = self.published();
        published.mempool.validate()?;
        self.ensure_storage_operational()?;
        Ok(published)
    }

    pub(crate) fn published_mempool_snapshot(&self) -> Result<MempoolSnapshot> {
        Ok(self.checked_published()?.mempool_snapshot())
    }

    pub(crate) fn published_mining_inputs(&self) -> Result<PublishedMiningInputs> {
        let published = self.checked_published()?;
        let inputs = (
            published.canonical_epoch.clone(),
            published.observed_mining_snapshot.clone(),
            published.authoritative_mining_snapshot.clone(),
            published.mining_authoritative,
            published.mempool.info.clone(),
            published.mempool.snapshot(),
        );
        self.ensure_storage_operational()?;
        Ok(inputs)
    }

    pub(crate) fn template_coordinator_handle(&self) -> Arc<Mutex<TemplateCoordinator>> {
        Arc::clone(&self.mining_engine_templates)
    }

    pub(crate) fn canonical_generation_is_stable(&self, expected: &CanonicalEpoch) -> bool {
        if self.ensure_storage_operational().is_err() {
            return false;
        }
        let before = self.state.publication_sequence.load(Ordering::Acquire);
        if before & 1 != 0 || expected.writer_sequence != before / 2 {
            return false;
        }
        let published = self.state.published_unchecked();
        if !published.storage_operational || &published.canonical_epoch != expected {
            return false;
        }
        let after = self.state.publication_sequence.load(Ordering::Acquire);
        if before != after || after & 1 != 0 || self.ensure_storage_operational().is_err() {
            return false;
        }
        let current = self.state.published_unchecked();
        let final_sequence = self.state.publication_sequence.load(Ordering::Acquire);
        before == final_sequence
            && final_sequence & 1 == 0
            && Arc::ptr_eq(&published, &current)
            && current.storage_operational
            && &current.canonical_epoch == expected
    }

    /// Verify that the published durable chain generation remained unchanged.
    /// Completed mempool-only writer generations are allowed; an in-flight
    /// writer or any chain epoch/tip change fails the check.
    pub(crate) fn canonical_chain_generation_is_stable(
        &self,
        expected: &CanonicalChainEpoch,
    ) -> bool {
        if self.ensure_storage_operational().is_err() {
            return false;
        }
        let before = self.state.publication_sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            return false;
        }
        let published = self.state.published_unchecked();
        if !published.storage_operational || &published.canonical_epoch.chain() != expected {
            return false;
        }
        let after = self.state.publication_sequence.load(Ordering::Acquire);
        if before != after || after & 1 != 0 || self.ensure_storage_operational().is_err() {
            return false;
        }
        let current = self.state.published_unchecked();
        let final_sequence = self.state.publication_sequence.load(Ordering::Acquire);
        before == final_sequence
            && final_sequence & 1 == 0
            && Arc::ptr_eq(&published, &current)
            && current.storage_operational
            && &current.canonical_epoch.chain() == expected
    }

    pub(crate) async fn rpc_request_mempool(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<RpcRequestMempool> {
        let method = RpcMethod::from_hsd_name(&request.method);
        let published = self.checked_published()?;
        let ordered_txids = (method == Some(RpcMethod::GetRawMempool)
            && published.mempool.info.transaction_count
                <= self.config.rpc_limits.maximum_collection_entries)
            .then(|| published.mempool.ordered_txids.clone());
        let transaction_lookup = if method == Some(RpcMethod::GetRawTransaction) {
            rpc_string_param(request, 0)
                .and_then(|encoded| decode_rpc_txid(encoded).ok())
                .map(|txid| (published.mempool.snapshot(), txid))
        } else {
            None
        };
        self.ensure_storage_operational()?;
        Ok(RpcRequestMempool {
            info: published.mempool.info.clone(),
            ordered_txids,
            transaction_lookup,
        })
    }

    pub(crate) async fn mempool_transaction(&self, txid: Txid) -> Result<Option<Transaction>> {
        let permit = Arc::clone(&self.point_read_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))?;
        let snapshot = self.published_mempool_snapshot()?;
        let transaction = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            snapshot.transaction(&txid).cloned()
        })
        .await
        .context("mempool transaction worker failed")?;
        self.ensure_storage_operational()?;
        Ok(transaction)
    }

    pub(crate) async fn mempool_claim(
        &self,
        hash: [u8; 32],
    ) -> Result<Option<hns_primitives::Claim>> {
        let permit = Arc::clone(&self.point_read_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))?;
        let snapshot = self.published_mempool_snapshot()?;
        let claim = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            snapshot.claim(&hash).map(|entry| entry.claim.clone())
        })
        .await
        .context("mempool claim worker failed")?;
        self.ensure_storage_operational()?;
        Ok(claim)
    }

    pub(crate) async fn mempool_airdrop(
        &self,
        hash: [u8; 32],
    ) -> Result<Option<hns_primitives::AirdropProof>> {
        let permit = Arc::clone(&self.point_read_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))?;
        let snapshot = self.published_mempool_snapshot()?;
        let proof = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            snapshot.airdrop(&hash).map(|entry| entry.proof.clone())
        })
        .await
        .context("mempool airdrop worker failed")?;
        self.ensure_storage_operational()?;
        Ok(proof)
    }

    pub(crate) async fn mempool_inventory(
        &self,
        maximum: usize,
    ) -> Result<Vec<hns_p2p::Inventory>> {
        if maximum > MAX_RPC_COLLECTION_ENTRIES {
            anyhow::bail!(
                "mempool inventory request {maximum} exceeds {MAX_RPC_COLLECTION_ENTRIES} entries"
            );
        }
        let permit = Arc::clone(&self.collection_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))?;
        let published = self.checked_published()?;
        let snapshot = published.mempool.snapshot();
        let ordered_txids = published.mempool.ordered_txids.clone();
        let inventory = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut inventory = Vec::with_capacity(
                maximum.min(
                    ordered_txids
                        .len()
                        .saturating_add(published.mempool.info.claim_count)
                        .saturating_add(published.mempool.info.airdrop_count),
                ),
            );
            inventory.extend(
                ordered_txids
                    .txids()
                    .take(maximum)
                    .map(hns_p2p::Inventory::transaction),
            );
            let remaining = maximum.saturating_sub(inventory.len());
            inventory.extend(
                snapshot
                    .claims_in_sequence()
                    .take(remaining)
                    .map(|entry| hns_p2p::Inventory::claim(entry.hash)),
            );
            let remaining = maximum.saturating_sub(inventory.len());
            inventory.extend(
                snapshot
                    .airdrops_in_sequence()
                    .take(remaining)
                    .map(|entry| hns_p2p::Inventory::airdrop(entry.hash)),
            );
            inventory
        })
        .await
        .context("mempool inventory worker failed")?;
        self.ensure_storage_operational()?;
        Ok(inventory)
    }

    pub(crate) async fn mempool_transactions(&self, maximum: usize) -> Result<Vec<Transaction>> {
        if maximum > MAX_RPC_COLLECTION_ENTRIES {
            anyhow::bail!(
                "mempool transaction request {maximum} exceeds {MAX_RPC_COLLECTION_ENTRIES} entries"
            );
        }
        let permit = Arc::clone(&self.collection_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))?;
        let published = self.checked_published()?;
        let snapshot = published.mempool.snapshot();
        let ordered_txids = published.mempool.ordered_txids.clone();
        let transactions = tokio::task::spawn_blocking(move || -> Result<Vec<Transaction>> {
            let _permit = permit;
            let mut transactions = Vec::with_capacity(maximum.min(ordered_txids.len()));
            for txid in ordered_txids.txids().take(maximum) {
                let transaction = snapshot.transaction(&txid).ok_or_else(|| {
                    anyhow::anyhow!(
                        "published mempool order references absent transaction {}",
                        txid.to_hex()
                    )
                })?;
                transactions.push(transaction.clone());
            }
            Ok(transactions)
        })
        .await
        .context("mempool transaction collection worker failed")??;
        self.ensure_storage_operational()?;
        Ok(transactions)
    }

    /// Execute a short actor-owned diagnostic read in canonical-writer order.
    /// Durable reads use stable snapshots, and mempool/template payloads use
    /// their structurally shared published generations; neither scans nor
    /// payload construction belong on this path.
    async fn inspect_bounded<T, F>(&self, operation: &'static str, inspect: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&NodeService) -> Result<T> + Send + 'static,
    {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        if let Some(reason) = self.state.terminal_reason() {
            return Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                reason,
            }));
        }
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(anyhow::Error::new(CanonicalWriterError::ShuttingDown));
        }
        let admission = Arc::clone(&runtime.admission_slots)
            .try_acquire_owned()
            .map_err(|_| {
                anyhow::Error::new(CanonicalWriterError::QueueFull {
                    capacity: runtime.queue_capacity,
                })
            })?;
        let (reply, response) = oneshot::channel();
        let command = CanonicalWriterCommand::Inspect {
            operation,
            inspect: Box::new(move |node| {
                inspect(node).map(|value| Box::new(value) as CanonicalCommandValue)
            }),
            _admission: admission,
            reply,
        };
        let permit = runtime
            .sender
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        {
            let _admission = runtime
                .admission
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(reason) = self.state.terminal_reason() {
                return Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                    reason,
                }));
            }
            if !self.state.accepting.load(Ordering::Acquire) {
                return Err(anyhow::Error::new(CanonicalWriterError::ShuttingDown));
            }
            permit.send(command);
        }
        decode_canonical_response(operation, response.await)
    }

    /// Run a durable immutable read against one stable writer generation. If
    /// a mutation overlaps the read, discard its result and retry after the
    /// writer publishes the matching even generation.
    pub(crate) fn with_stable_read<T, F>(&self, read: F) -> Result<T>
    where
        F: FnOnce(&StoreHandle, &SharedHeaderIndex) -> Result<T>,
    {
        self.with_stable_epoch_read(read).map(|(_, value)| value)
    }

    /// Capture a prepare result and its exact canonical epoch without waiting
    /// on an in-flight mutation. Busy callers may yield and retry or submit an
    /// ordered inspector command instead.
    pub(crate) fn with_stable_epoch_read<T, F>(&self, read: F) -> Result<(CanonicalEpoch, T)>
    where
        F: FnOnce(&StoreHandle, &SharedHeaderIndex) -> Result<T>,
    {
        self.ensure_storage_operational()?;
        let before = self.state.publication_sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            return Err(anyhow::Error::new(CanonicalWriterError::Busy));
        }
        let epoch = self.state.published_unchecked().canonical_epoch.clone();
        let result = read(&self.store, &self.headers);
        let after = self.state.publication_sequence.load(Ordering::Acquire);
        if before != after || after & 1 != 0 || epoch.writer_sequence != after / 2 {
            return Err(anyhow::Error::new(CanonicalWriterError::Busy));
        }
        self.ensure_storage_operational()?;
        result.map(|value| (epoch, value))
    }

    pub fn stable_canonical_epoch(&self) -> Result<CanonicalEpoch> {
        self.ensure_storage_operational()?;
        Ok(self.canonical_epoch())
    }

    pub(crate) fn name_page_compaction_due(
        &self,
    ) -> Result<Option<NamePageCompactionDue>> {
        if !self.config.undo_retention.prune_history
            || self.config.data_dir.is_none()
        {
            return Ok(None);
        }

        let (epoch, page_identity) = self.with_stable_epoch_read(|store, _headers| {
            let snapshot = store.snapshot()?;

            let Some(raw) = snapshot.get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)? else {
                return Ok(None);
            };

            let state = NamePageState::decode(&raw)
                .map_err(anyhow::Error::new)
                .context("failed to decode name-page state for online maintenance")?;

            Ok(Some((
                state.manifest.generation,
                state.manifest.active_segment,
            )))
        })?;

        let Some((generation, active_segment)) = page_identity else {
            return Ok(None);
        };

        if active_segment < NAME_PAGE_COMPACTION_SEGMENT_THRESHOLD {
            return Ok(None);
        }

        Ok(Some(NamePageCompactionDue {
            epoch: epoch.chain(),
            generation,
            active_segment,
        }))
    }

    /// Reserve one configured template slot before capturing the mempool. The
    /// permit must be held through capture and construction so admitted
    /// snapshots remain inside the aggregate memory envelope.
    pub(crate) fn try_acquire_template_build_admission(&self) -> Result<OwnedSemaphorePermit> {
        self.ensure_storage_operational()?;
        Arc::clone(&self.template_build_admission)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))
    }

    /// Wait for bounded CPU capacity before the off-actor state capture. The
    /// permit covers capture and construction without blocking the writer.
    pub(crate) async fn acquire_template_build_worker(&self) -> Result<OwnedSemaphorePermit> {
        self.ensure_storage_operational()?;
        let worker = Arc::clone(&self.template_build_workers)
            .acquire_owned()
            .await
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        self.ensure_storage_operational()?;
        Ok(worker)
    }
}

impl std_fmt::Debug for NodeReadHandle {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        formatter
            .debug_struct("NodeReadHandle")
            .field("network", &self.config.network)
            .field("canonical_epoch", &self.canonical_epoch())
            .field("accepting", &self.state.accepting.load(Ordering::Acquire))
            .field("terminal", &self.state.terminal_reason())
            .finish()
    }
}

/// Bounded command admission to the one OS thread that exclusively owns the
/// mutable [`NodeService`]. Once accepted, a command runs even if its caller
/// drops the response future.
#[derive(Clone)]
pub struct CanonicalStateWriter {
    inner: Arc<NodeRuntimeInner>,
}

impl std_fmt::Debug for CanonicalStateWriter {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        formatter
            .debug_struct("CanonicalStateWriter")
            .field("queue_capacity", &self.inner.queue_capacity)
            .field(
                "accepting",
                &self.inner.state.accepting.load(Ordering::Acquire),
            )
            .field("terminal", &self.inner.state.terminal_reason())
            .finish()
    }
}

impl CanonicalStateWriter {
    pub async fn execute<T, F>(
        &self,
        expected: Option<CanonicalEpoch>,
        operation: &'static str,
        execute: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeService) -> Result<T> + Send + 'static,
    {
        let admission = self.try_admission()?;
        let (reply, response) = oneshot::channel();
        let command = CanonicalWriterCommand::Execute {
            expected: expected.map(ExpectedCanonicalState::Exact),
            operation,
            execute: Box::new(move |node| {
                execute(node).map(|value| Box::new(value) as CanonicalCommandValue)
            }),
            _admission: admission,
            reply,
        };
        let permit = self
            .inner
            .sender
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        {
            let _admission = self
                .inner
                .admission
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.ensure_accepting()?;
            permit.send(command);
        }
        decode_canonical_response(operation, response.await)
    }

    pub async fn execute_at<T, F>(
        &self,
        expected: CanonicalEpoch,
        operation: &'static str,
        execute: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeService) -> Result<T> + Send + 'static,
    {
        self.execute(Some(expected), operation, execute).await
    }

    pub async fn execute_at_chain<T, F>(
        &self,
        expected: CanonicalChainEpoch,
        operation: &'static str,
        execute: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeService) -> Result<T> + Send + 'static,
    {
        self.execute_expected(
            Some(ExpectedCanonicalState::Chain(expected)),
            operation,
            execute,
        )
        .await
    }

    pub async fn try_execute<T, F>(
        &self,
        expected: Option<CanonicalEpoch>,
        operation: &'static str,
        execute: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeService) -> Result<T> + Send + 'static,
    {
        let admission = self.try_admission()?;
        let permit = self
            .inner
            .sender
            .clone()
            .try_reserve_owned()
            .map_err(|error| {
                let kind = match error {
                    mpsc::error::TrySendError::Full(_) => CanonicalWriterError::QueueFull {
                        capacity: self.inner.queue_capacity,
                    },
                    mpsc::error::TrySendError::Closed(_) => CanonicalWriterError::Stopped,
                };
                anyhow::Error::new(kind)
            })?;
        let (reply, response) = oneshot::channel();
        let command = CanonicalWriterCommand::Execute {
            expected: expected.map(ExpectedCanonicalState::Exact),
            operation,
            execute: Box::new(move |node| {
                execute(node).map(|value| Box::new(value) as CanonicalCommandValue)
            }),
            _admission: admission,
            reply,
        };
        {
            let _admission = self
                .inner
                .admission
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.ensure_accepting()?;
            permit.send(command);
        }
        decode_canonical_response(operation, response.await)
    }

    pub async fn try_execute_at<T, F>(
        &self,
        expected: CanonicalEpoch,
        operation: &'static str,
        execute: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeService) -> Result<T> + Send + 'static,
    {
        self.try_execute(Some(expected), operation, execute).await
    }

    async fn execute_expected<T, F>(
        &self,
        expected: Option<ExpectedCanonicalState>,
        operation: &'static str,
        execute: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut NodeService) -> Result<T> + Send + 'static,
    {
        let admission = self.try_admission()?;
        let (reply, response) = oneshot::channel();
        let command = CanonicalWriterCommand::Execute {
            expected,
            operation,
            execute: Box::new(move |node| {
                execute(node).map(|value| Box::new(value) as CanonicalCommandValue)
            }),
            _admission: admission,
            reply,
        };
        let permit = self
            .inner
            .sender
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        {
            let _admission = self
                .inner
                .admission
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.ensure_accepting()?;
            permit.send(command);
        }
        decode_canonical_response(operation, response.await)
    }

    fn ensure_accepting(&self) -> Result<()> {
        if let Some(reason) = self.inner.state.terminal_reason() {
            return Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                reason,
            }));
        }
        if !self.inner.state.accepting.load(Ordering::Acquire) {
            return Err(anyhow::Error::new(CanonicalWriterError::ShuttingDown));
        }
        Ok(())
    }

    fn try_admission(&self) -> Result<OwnedSemaphorePermit> {
        self.ensure_accepting()?;
        Arc::clone(&self.inner.admission_slots)
            .try_acquire_owned()
            .map_err(|_| {
                anyhow::Error::new(CanonicalWriterError::QueueFull {
                    capacity: self.inner.queue_capacity,
                })
            })
    }
}

fn decode_canonical_response<T: Send + 'static>(
    operation: &'static str,
    response: std::result::Result<Result<CanonicalCommandValue>, oneshot::error::RecvError>,
) -> Result<T> {
    let value = response.map_err(|_| anyhow::Error::new(CanonicalWriterError::Stopped))??;
    value
        .downcast::<T>()
        .map(|value| *value)
        .map_err(|_| anyhow::Error::new(CanonicalWriterError::ResponseType { operation }))
}

/// Process-local owner for the dedicated canonical writer and all immutable
/// read handles derived from it.
#[derive(Clone)]
pub struct NodeRuntime {
    inner: Arc<NodeRuntimeInner>,
    read: NodeReadHandle,
    denuo_relay: DenuoRelayHandle,
}

impl std_fmt::Debug for NodeRuntime {
    fn fmt(&self, formatter: &mut std_fmt::Formatter<'_>) -> std_fmt::Result {
        formatter
            .debug_struct("NodeRuntime")
            .field("queue_capacity", &self.inner.queue_capacity)
            .field(
                "accepting",
                &self.inner.state.accepting.load(Ordering::Acquire),
            )
            .field("terminal", &self.inner.state.terminal_reason())
            .finish()
    }
}

impl NodeRuntime {
    pub fn spawn(mut node: NodeService, queue_capacity: usize) -> Result<Self> {
        if queue_capacity == 0 || queue_capacity > MAX_CANONICAL_WRITER_QUEUE_CAPACITY {
            anyhow::bail!(
                "canonical writer queue capacity must be between 1 and {MAX_CANONICAL_WRITER_QUEUE_CAPACITY}"
            );
        }
        node.state.ensure_storage_operational()?;
        node.mining_engine_initialize_publication_queue()?;
        let initial = capture_published_node_view(&node, 0)?;
        let config = Arc::new(node.config.clone());
        let store = node.state.store.clone();
        let headers = node.state.chain.clone();
        let transaction_index = node.state.transaction_index;
        let wallet_index_profile = node.state.wallet_index_profile;
        let denuo_relay = node.denuo_relay.clone();
        let mining_events = node.mining_events.clone();
        let mining_engine_templates = Arc::clone(&node.mining_engine_templates);
        let maximum_concurrent_requests = node.config.rpc_limits.maximum_concurrent_requests;
        let template_build_workers = node.config.mining_engine.template_build_workers();
        let template_build_queue_capacity =
            node.config.mining_engine.template_build_queue_capacity();
        let state = Arc::new(NodeRuntimeState {
            published: RwLock::new(Arc::new(initial)),
            publication_sequence: AtomicU64::new(0),
            accepting: AtomicBool::new(true),
            terminal: Mutex::new(None),
        });
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let actor_state = Arc::clone(&state);
        let join = thread::Builder::new()
            .name("hsrd-canonical-writer".to_owned())
            .spawn(move || canonical_writer_thread(node, receiver, actor_state))
            .context("failed to spawn canonical writer thread")?;
        let inner = Arc::new(NodeRuntimeInner {
            state,
            sender,
            admission_slots: Arc::new(Semaphore::new(queue_capacity.saturating_add(1))),
            admission: Mutex::new(()),
            join: AsyncMutex::new(Some(join)),
            queue_capacity,
        });
        let read = NodeReadHandle {
            config,
            store,
            headers,
            transaction_index,
            wallet_index_profile,
            mining_events,
            mining_engine_templates,
            state: Arc::clone(&inner.state),
            runtime: Arc::downgrade(&inner),
            point_read_concurrency: Arc::new(Semaphore::new(maximum_concurrent_requests)),
            collection_concurrency: Arc::new(Semaphore::new(maximum_concurrent_requests)),
            template_build_admission: Arc::new(Semaphore::new(template_build_queue_capacity)),
            template_build_workers: Arc::new(Semaphore::new(template_build_workers)),
        };
        Ok(Self {
            inner,
            read,
            denuo_relay,
        })
    }

    pub fn read(&self) -> NodeReadHandle {
        self.read.clone()
    }

    pub fn writer(&self) -> CanonicalStateWriter {
        CanonicalStateWriter {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Bounded Denuo marketplace relay capability for native adapters.
    #[must_use]
    pub fn denuo_relay(&self) -> DenuoRelayHandle {
        self.denuo_relay.clone()
    }

    /// Authorize a clean marker only from the crate-owned runtime supervisor.
    /// Public extensions receive read and writer capabilities, but never node
    /// lifecycle authority.
    pub(crate) async fn shutdown(self) -> Result<()> {
        self.shutdown_inner(true).await
    }

    /// Drain accepted writer work and stop without authorizing a clean-store
    /// marker. Runtime supervisors must use this path after any failed
    /// extension, checkpoint, listener, or shutdown phase so the next process
    /// performs exhaustive startup validation.
    pub(crate) async fn shutdown_unclean(self) -> Result<()> {
        self.shutdown_inner(false).await
    }

    async fn shutdown_inner(self, mark_clean: bool) -> Result<()> {
        // Serializing on the join handle makes cloned shutdown attempts
        // deterministic. In particular, an unclean correction cannot race a
        // preceding clean shutdown and be overwritten by its final marker.
        let mut join_guard = self.inner.join.lock().await;
        let marker_result = if mark_clean {
            Ok(())
        } else {
            mark_unclean_start(&self.read.store)
                .map_err(anyhow::Error::new)
                .context("failed to durably preserve the unclean runtime marker")
        };
        if join_guard.is_none() {
            return if mark_clean {
                Err(anyhow::Error::new(CanonicalWriterError::Stopped))
            } else {
                marker_result
            };
        }

        let (reply, response) = oneshot::channel();
        {
            let _admission = self
                .inner
                .admission
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.inner.state.accepting.store(false, Ordering::Release);
        }
        // Send even when another path already stopped admission. A cancelled
        // shutdown may have flipped `accepting` without ever queuing the stop
        // command, and this caller still owns the live join handle.
        let actor_result = match self.inner.sender.clone().reserve_owned().await {
            Ok(permit) => {
                permit.send(CanonicalWriterCommand::Shutdown { mark_clean, reply });
                match response.await {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::Error::new(CanonicalWriterError::Stopped)),
                }
            }
            Err(_) => Err(anyhow::Error::new(CanonicalWriterError::Stopped)),
        };
        // Keep the handle recoverable in shared state across both await
        // points above. If this future is cancelled before or after enqueue,
        // another lifecycle owner can still stop and join the actor.
        let join = join_guard
            .take()
            .expect("canonical writer join handle remained serialized");
        let join_result = match tokio::task::spawn_blocking(move || join.join()).await {
            Ok(result) => result.map_err(|_| anyhow::anyhow!("canonical writer thread panicked")),
            Err(error) => Err(anyhow::anyhow!(
                "failed to join canonical writer task: {error}"
            )),
        };
        drop(join_guard);

        let result = combine_shutdown_phase(marker_result, "canonical writer stop", actor_result);
        let result = combine_shutdown_phase(result, "canonical writer join", join_result);
        if mark_clean {
            result
        } else {
            // A clean shutdown command may already have been queued by a
            // cancelled clone. It can overwrite the pre-stop unclean marker,
            // exit, and discard this correction command. Reassert only after
            // joining so no actor-owned clean write can win afterward.
            let final_marker_result = mark_unclean_start(&self.read.store)
                .map_err(anyhow::Error::new)
                .context("failed to reassert the unclean marker after canonical writer exit");
            combine_shutdown_phase(
                result,
                "post-join unclean-marker reassertion",
                final_marker_result,
            )
        }
    }

    pub fn terminal_error(&self) -> Option<CanonicalWriterError> {
        self.inner
            .state
            .terminal_reason()
            .map(|reason| CanonicalWriterError::Terminal { reason })
    }
}

fn combine_shutdown_phase(
    accumulated: Result<()>,
    phase: &'static str,
    phase_result: Result<()>,
) -> Result<()> {
    match (accumulated, phase_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error.context(phase)),
        (Err(error), Err(additional)) => Err(error.context(format!(
            "{phase} also failed during shutdown: {additional:#}"
        ))),
    }
}

fn canonical_epoch_for_node(node: &NodeService, writer_sequence: u64) -> Result<CanonicalEpoch> {
    let snapshot = node.state.store.snapshot()?;
    Ok(CanonicalEpoch {
        writer_sequence,
        chain_epoch: chain_epoch_from_snapshot(&snapshot)?,
        tip: best_block_tip_from_snapshot(&snapshot)?,
    })
}

fn capture_published_node_view(
    node: &NodeService,
    writer_sequence: u64,
) -> Result<PublishedNodeView> {
    node.state.ensure_storage_operational()?;
    let canonical_epoch = canonical_epoch_for_node(node, writer_sequence)?;
    let durable = node.state.durable_mining_state()?;
    let mempool = PublishedMempoolView::capture(&node.state.mempool)?;
    let authority_permit = issue_authority_permit(&node.config, &durable);
    let authoritative_mining_snapshot = authority_permit.as_ref().and_then(|permit| {
        node.mining_events.snapshot().filter(|snapshot| {
            snapshot.generation == permit.generation && snapshot.tip.hash == permit.tip
        })
    });
    let mining_authoritative = authority_permit.is_some()
        && authoritative_mining_snapshot.is_some()
        && durable.authoritative;
    Ok(PublishedNodeView {
        canonical_epoch,
        mining_generation: durable.generation,
        observed_mining_snapshot: durable.snapshot,
        authoritative_mining_snapshot,
        mining_authoritative,
        mining_synchronized: durable.synchronized,
        mempool,
        storage_operational: true,
        storage_fence_reason: None,
    })
}

fn fail_closed_published_node_view(
    node: &NodeService,
    previous: &PublishedNodeView,
    writer_sequence: u64,
    reason: String,
) -> PublishedNodeView {
    let canonical_epoch = canonical_epoch_for_node(node, writer_sequence)
        .unwrap_or_else(|_| previous.canonical_epoch.clone());
    PublishedNodeView {
        canonical_epoch,
        mining_generation: previous.mining_generation,
        observed_mining_snapshot: None,
        authoritative_mining_snapshot: None,
        mining_authoritative: false,
        mining_synchronized: false,
        mempool: previous.mempool.clone(),
        storage_operational: false,
        storage_fence_reason: Some(reason),
    }
}

fn next_writer_sequence(current: u64) -> Option<u64> {
    // Each writer generation consumes an odd "write in progress" value and
    // the following even "published" value in the seqlock counter.
    current.checked_add(1).filter(|next| *next <= u64::MAX / 2)
}

fn canonical_writer_thread(
    mut node: NodeService,
    mut receiver: mpsc::Receiver<CanonicalWriterCommand>,
    state: Arc<NodeRuntimeState>,
) {
    let mut writer_sequence = 0u64;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        while let Some(command) = receiver.blocking_recv() {
            match command {
                CanonicalWriterCommand::Execute {
                    expected,
                    operation,
                    execute,
                    _admission,
                    reply,
                } => {
                    if let Some(reason) = state.terminal_reason() {
                        let _ =
                            reply.send(Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                                reason,
                            })));
                        continue;
                    }
                    let actual = match canonical_epoch_for_node(&node, writer_sequence) {
                        Ok(actual) => actual,
                        Err(error) => {
                            let reason = state.stop_fail_closed(format!(
                                "failed to capture canonical epoch before {operation}: {error:#}"
                            ));
                            let previous = state.published();
                            state.publish(fail_closed_published_node_view(
                                &node,
                                &previous,
                                writer_sequence,
                                reason.clone(),
                            ));
                            let _ = reply.send(Err(anyhow::Error::new(
                                CanonicalWriterError::Terminal { reason },
                            )));
                            break;
                        }
                    };
                    if let Some(expected) = expected {
                        let stale = match expected {
                            ExpectedCanonicalState::Exact(expected) if expected != actual => {
                                Some(CanonicalWriterError::StaleEpoch {
                                    operation,
                                    expected,
                                    actual: actual.clone(),
                                })
                            }
                            ExpectedCanonicalState::Chain(expected)
                                if expected != actual.chain() =>
                            {
                                Some(CanonicalWriterError::StaleChainEpoch {
                                    operation,
                                    expected,
                                    actual: actual.chain(),
                                })
                            }
                            _ => None,
                        };
                        if let Some(stale) = stale {
                            let _ = reply.send(Err(anyhow::Error::new(stale)));
                            continue;
                        }
                    }

                    let Some(next_writer_sequence) = next_writer_sequence(writer_sequence) else {
                        let reason = state.stop_fail_closed("canonical writer sequence exhausted");
                        let previous = state.published();
                        state.publish(fail_closed_published_node_view(
                            &node,
                            &previous,
                            writer_sequence,
                            reason.clone(),
                        ));
                        let _ =
                            reply.send(Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                                reason,
                            })));
                        break;
                    };
                    writer_sequence = next_writer_sequence;
                    let previous_publication_sequence =
                        state.publication_sequence.fetch_add(1, Ordering::AcqRel);
                    if previous_publication_sequence & 1 != 0 {
                        let reason = state.stop_fail_closed(
                            "canonical publication sequence was already write-locked",
                        );
                        let _ =
                            reply.send(Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                                reason,
                            })));
                        break;
                    }
                    let operation_result = execute(&mut node);
                    node.fail_closed_after_ambiguous_commit();
                    let previous = state.published_unchecked();
                    let publication = capture_published_node_view(&node, writer_sequence);
                    let terminal = match publication {
                        Ok(view) => {
                            state.publish(view);
                            None
                        }
                        Err(error) => {
                            let reason = state.stop_fail_closed(format!(
                                "failed to publish state after {operation}: {error:#}"
                            ));
                            state.publish(fail_closed_published_node_view(
                                &node,
                                &previous,
                                writer_sequence,
                                reason.clone(),
                            ));
                            Some(reason)
                        }
                    };
                    state.publication_sequence.fetch_add(1, Ordering::Release);
                    let response = match terminal {
                        Some(reason) => Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                            reason,
                        })),
                        None => operation_result,
                    };
                    let _ = reply.send(response);
                    if state.terminal_reason().is_some() {
                        break;
                    }
                }
                CanonicalWriterCommand::Inspect {
                    operation,
                    inspect,
                    _admission,
                    reply,
                } => {
                    let response = match state.terminal_reason() {
                        Some(reason) => Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                            reason,
                        })),
                        None => inspect(&node),
                    };
                    let _ = reply.send(response.with_context(|| {
                        format!("canonical immutable inspection failed during {operation}")
                    }));
                }
                CanonicalWriterCommand::Shutdown { mark_clean, reply } => {
                    let result = match state.terminal_reason() {
                        Some(reason) => Err(anyhow::Error::new(CanonicalWriterError::Terminal {
                            reason,
                        })),
                        None => node.state.ensure_storage_operational().and_then(|()| {
                            if mark_clean {
                                mark_node_store_clean(&node.state.store, node.config.network)
                            } else {
                                Ok(())
                            }
                        }),
                    }
                    .context(if mark_clean {
                        "failed to mark canonical store clean before writer exit"
                    } else {
                        "failed to validate canonical store before unclean writer exit"
                    });
                    if let Err(error) = &result {
                        node.revoke_runtime_authority();
                        let reason = state.stop_fail_closed(format!(
                            "canonical writer shutdown failed: {error:#}"
                        ));
                        let previous = state.published_unchecked();
                        state.publish(fail_closed_published_node_view(
                            &node,
                            &previous,
                            writer_sequence,
                            reason,
                        ));
                    }
                    let _ = reply.send(result);
                    break;
                }
            }
        }
    }));
    node.revoke_runtime_authority();
    let fallback_reason = if result.is_err() {
        "canonical writer thread panicked"
    } else {
        "canonical writer stopped"
    };
    let reason = state
        .terminal_reason()
        .unwrap_or_else(|| fallback_reason.to_owned());
    state.accepting.store(false, Ordering::Release);
    let previous = state.published_unchecked();
    state.publish(fail_closed_published_node_view(
        &node,
        &previous,
        writer_sequence,
        reason.clone(),
    ));
    if state.publication_sequence.load(Ordering::Acquire) & 1 != 0 {
        state.publication_sequence.fetch_add(1, Ordering::Release);
    }
    // Publish the terminal view and close any interrupted seqlock generation
    // before exposing a new terminal reason. Thus observing `terminal_error`
    // after an actor panic also synchronizes with fail-closed publication.
    state.stop_fail_closed(reason);
}

/// Process-local extension capability for a unified MeshMine mining runtime.
///
/// The node supplies a runtime capability with immutable reads and bounded
/// canonical-writer submission, plus the live peer publication manager and
/// shutdown watch. It never exposes mutable [`NodeService`] access or node
/// lifecycle authority. Shutdown is owned by the crate's native supervisor:
///
/// ```compile_fail
/// use hns_node::NodeRuntime;
///
/// async fn extension_cannot_end_node_lifecycle(runtime: NodeRuntime) {
///     runtime.shutdown().await.unwrap();
/// }
/// ```
pub trait NativeRuntimeExtension: Send {
    fn spawn(
        self: Box<Self>,
        node: NodeRuntime,
        peers: LivePeerManager,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>>;
}

impl NodeService {
    pub fn new(config: NodeConfig) -> Self {
        let state = NodeState::memory_for_network(config.network);
        Self::with_state(config, state)
    }

    pub fn try_new(config: NodeConfig) -> Result<Self> {
        validate_node_config(&config)?;
        let state = NodeState::from_config(&config)?;
        Self::try_with_state(config, state)
    }

    pub fn with_state(config: NodeConfig, state: NodeState) -> Self {
        Self::try_with_state(config, state).expect("node mining state initializes")
    }

    pub fn try_with_state(config: NodeConfig, mut state: NodeState) -> Result<Self> {
        validate_node_config(&config)?;
        if state.network() != config.network {
            anyhow::bail!(
                "node state network {} does not match configured network {}",
                state.network(),
                config.network
            );
        }
        state.configure_transaction_index(config.transaction_index || config.wallet_index)?;
        state.configure_wallet_indexes(config.wallet_index_profile())?;
        let pruning_checkpoint = {
            let snapshot = state.store.snapshot()?;
            load_undo_pruning_checkpoint(&snapshot)?
        };
        if pruning_checkpoint.is_some() && !config.undo_retention.prune_history {
            anyhow::bail!(
                "block/undo history was previously pruned; storage mode cannot be changed to archive"
            );
        }
        state.undo_retention_policy = config
            .undo_retention
            .prune_history
            .then(|| UndoRetentionPolicy::for_network(config.network));

        let mempool_info = state.mempool.info();
        if mempool_info.transaction_count == 0
            && mempool_info.claim_count == 0
            && mempool_info.airdrop_count == 0
            && mempool_info.orphan_count == 0
        {
            state.mempool = MemoryMempool::with_limits(config.mining_engine.mempool_limits.clone())
                .map_err(|error| {
                    anyhow::anyhow!("failed to configure mining-engine mempool: {error}")
                })?;
        } else if state.mempool.limits() != &config.mining_engine.mempool_limits {
            anyhow::bail!(
                "non-empty node mempool limits do not match the configured mining-engine limits"
            );
        }

        // Recover a fully stored higher-work branch only when the authority
        // policy itself is complete. Native mainnet remains off unless its
        // explicit canary and every readiness gate pass. Active-state recovery
        // is driven by the bounded sync coordinator so it cannot bypass
        // contextual-failure handling or the configured batch limit.
        if authority_can_mine(&config) {
            state.recover_best_stored_chain()?;
        }

        if config.undo_retention.prune_history {
            state.prune_undo_history_to_policy()?;
            if config.data_dir.is_some() {
                state.compact_pruned_payload_segments_if_due()?;
                if let Some(report) = state.compact_pruned_name_pages_if_due()? {
                    tracing::info!(
                        previous_generation = report.previous_generation,
                        generation = report.generation,
                        retained_roots = report.retained_roots,
                        records_written = report.records_written,
                        pages_written = report.pages_written,
                        bytes_before = report.bytes_before,
                        bytes_after = report.bytes_after,
                        reclaimed_bytes = report.reclaimed_bytes,
                        "startup pruned name-page compaction completed"
                    );
                }
            }
        }

        if config.name_tree_compaction.compact_on_startup {
            if let Some(checkpoint) = state
                .compact_name_tree_nodes_if_due(config.name_tree_compaction.startup_interval)?
            {
                tracing::info!(
                    height = checkpoint.height,
                    tip = %checkpoint.tip.to_hex(),
                    nodes_before = checkpoint.summary.nodes_before,
                    nodes_retained = checkpoint.summary.nodes_retained,
                    nodes_deleted = checkpoint.summary.nodes_deleted,
                    "compacted durable name tree during startup"
                );
            }
        }

        if let Some(lifecycle) = state.startup_lifecycle.take() {
            if let Some(warning) = lifecycle.checkpoint_warning {
                tracing::warn!(
                    warning,
                    "clean startup checkpoint was unreadable; exhaustive durable invariants were revalidated"
                );
            }
            match (lifecycle.previous_shutdown_clean, lifecycle.audit) {
                (true, StartupAuditKind::CleanCheckpoint) => tracing::info!(
                    "clean startup checkpoint matched; durable roots received targeted validation"
                ),
                (true, StartupAuditKind::Exhaustive) => tracing::warn!(
                    "clean startup checkpoint was missing or stale; durable invariants were exhaustively revalidated"
                ),
                (false, _) => tracing::warn!(
                    "hsrd store was not marked clean at the previous shutdown; durable invariants were exhaustively revalidated"
                ),
            }
        } else {
            // Caller-supplied state already received exhaustive validation, but
            // it did not claim the process lifecycle during construction.
            let previous_shutdown_clean = was_clean_shutdown(&state.store)
                .map_err(|error| anyhow::anyhow!("failed to read shutdown marker: {error}"))?;
            if !previous_shutdown_clean {
                tracing::warn!(
                    "hsrd store was not marked clean at the previous shutdown; durable invariants were exhaustively revalidated"
                );
            }
            mark_unclean_start(&state.store).map_err(|error| {
                anyhow::anyhow!("failed to mark running store unclean: {error}")
            })?;
        }

        let durable = state.durable_mining_state()?;
        let initial = if durable_tip_can_authorize(&config, &durable) {
            durable.snapshot.clone()
        } else {
            None
        };
        let mining_events = MiningEventHub::from_durable(durable.generation, initial)
            .map_err(|error| anyhow::anyhow!("failed to initialize mining events: {error}"))?;
        let mining_engine_templates = Arc::new(Mutex::new(
            TemplateCoordinator::new(config.mining_engine.maximum_template_variants).map_err(
                |error| anyhow::anyhow!("failed to initialize mining-engine templates: {error}"),
            )?,
        ));
        let airdrop_signatures = NativeAirdropSignatureVerifier::new().map_err(|error| {
            anyhow::anyhow!("failed to initialize airdrop relay verifier: {error}")
        })?;
        let denuo_relay =
            DenuoRelayHandle::new(config.denuo_relay_roles, DenuoRelayLimits::default()).map_err(
                |error| anyhow::anyhow!("failed to initialize Denuo market relay: {error}"),
            )?;
        Ok(Self {
            config,
            state,
            mining_events,
            mining_engine_templates,
            mempool_name_context: Mutex::new(mining_engine::ActiveMempoolNameCache::default()),
            claim_dnssec: OpenSslDnssecVerifier,
            airdrop_signatures,
            denuo_relay,
        })
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn state(&self) -> &NodeState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    pub fn block_cache_occupancy(&self) -> usize {
        self.state.blocks.cache_occupancy()
    }

    pub fn block_cache_capacity(&self) -> usize {
        self.state.blocks.cache_capacity()
    }

    /// Run name-tree maintenance under the node's mutable coordinator. The
    /// compaction checkpoint and all record deletions share one atomic batch.
    pub fn compact_name_tree_nodes(&mut self) -> Result<NameTreeCompactionCheckpoint> {
        self.state.ensure_storage_operational()?;
        let result = self.state.compact_name_tree_nodes();
        if result.is_err() {
            self.fail_closed_after_ambiguous_commit();
        }
        result
    }

    /// Mining-mode maintenance retires unreachable historical nodes on the
    /// configured interval after their rollback authority has been pruned.
    fn compact_pruned_name_tree_nodes_if_due(
        &mut self,
    ) -> Result<Option<NameTreeCompactionCheckpoint>> {
        if !self.config.undo_retention.prune_history {
            return Ok(None);
        }
        self.state
            .compact_name_tree_nodes_if_due(self.config.name_tree_compaction.startup_interval)
    }

    pub fn name_tree_compaction_checkpoint(&self) -> Result<Option<NameTreeCompactionCheckpoint>> {
        let snapshot = self.state.store.snapshot()?;
        load_name_tree_compaction_checkpoint(&snapshot)
    }

    pub fn undo_pruning_checkpoint(&self) -> Result<Option<UndoPruningCheckpoint>> {
        let snapshot = self.state.store.snapshot()?;
        load_undo_pruning_checkpoint(&snapshot)
    }

    pub fn mining_snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        if self.state.storage_reopen_required()
            || self.state.production_safety_fence_reason().is_some()
        {
            None
        } else {
            self.mining_events.snapshot()
        }
    }

    pub(crate) fn register_wallet_contract(
        &mut self,
        registration: ContractRegistration,
    ) -> Result<ContractRegistrationOutcome> {
        self.state.ensure_storage_operational()?;
        let snapshot = self.state.store.snapshot()?;
        let mut batch = self.state.store.batch();
        let outcome = register_tracked_contract(
            &snapshot,
            &mut batch,
            self.state.wallet_index_profile,
            &registration,
        )
        .map_err(anyhow::Error::new)?;
        drop(snapshot);
        self.state.store.commit(batch)?;
        Ok(outcome)
    }

    pub(crate) fn retire_never_confirmed_wallet_contract(
        &mut self,
        registration: ContractRegistration,
        expected_lifecycle_revision: u64,
    ) -> Result<ContractRetirementOutcome> {
        self.state.ensure_storage_operational()?;
        let snapshot = self.state.store.snapshot()?;
        let mut batch = self.state.store.batch();
        let outcome = retire_never_confirmed_tracked_contract(
            &snapshot,
            &mut batch,
            self.state.wallet_index_profile,
            &registration,
            expected_lifecycle_revision,
        )
        .map_err(anyhow::Error::new)?;
        drop(snapshot);
        self.state.store.commit(batch)?;
        Ok(outcome)
    }

    pub(crate) fn retire_completed_wallet_contract(
        &mut self,
        registration: ContractRegistration,
        expected_lifecycle_revision: u64,
        expected_rollback_boundary: ContractRollbackBoundary,
        permanent_abandonment_acknowledged: bool,
    ) -> Result<(
        CompletedContractRetirementOutcome,
        CompletedContractRetirement,
    )> {
        self.state.ensure_storage_operational()?;
        let snapshot = self.state.store.snapshot()?;
        let checkpoint = load_undo_pruning_checkpoint(&snapshot)?.ok_or_else(|| {
            anyhow::Error::new(hns_wallet_index::IndexError::ContractRollbackRequired)
        })?;
        let rollback_boundary = ContractRollbackBoundary {
            pruned_through: checkpoint.pruned_through,
            block_hash: checkpoint.block_hash,
        };
        if rollback_boundary != expected_rollback_boundary {
            return Err(anyhow::Error::new(
                hns_wallet_index::IndexError::ContractRollbackRequired,
            ));
        }
        let mut batch = self.state.store.batch();
        let retirement = retire_completed_tracked_contract(
            &snapshot,
            &mut batch,
            self.state.wallet_index_profile,
            &registration,
            expected_lifecycle_revision,
            rollback_boundary,
            permanent_abandonment_acknowledged,
        )
        .map_err(anyhow::Error::new)?;
        if read_canonical_hash(&snapshot, rollback_boundary.pruned_through)?
            != Some(rollback_boundary.block_hash)
        {
            return Err(anyhow::Error::new(hns_wallet_index::IndexError::Corrupt(
                "completed retirement rollback block is not canonical",
            )));
        }
        let TrackedContractEvent::Spend {
            height, block_hash, ..
        } = &retirement.1.terminal_event
        else {
            return Err(anyhow::Error::new(hns_wallet_index::IndexError::Corrupt(
                "completed retirement terminal evidence is not a spend",
            )));
        };
        if read_canonical_hash(&snapshot, *height)? != Some(*block_hash) {
            return Err(anyhow::Error::new(hns_wallet_index::IndexError::Corrupt(
                "completed retirement terminal block is not canonical",
            )));
        }
        drop(snapshot);
        self.state.store.commit(batch)?;
        Ok(retirement)
    }

    pub fn observed_mining_snapshot(&self) -> Result<Option<Arc<MiningSnapshot>>> {
        Ok(self.state.durable_mining_state()?.snapshot)
    }

    pub fn subscribe_observed_mining_events(&self) -> MiningSubscriptions {
        self.mining_events.subscribe()
    }

    pub fn subscribe_mining_events(&self) -> Result<MiningSubscriptions> {
        let durable = self.state.durable_mining_state()?;
        issue_authority_permit(&self.config, &durable).ok_or_else(|| {
            anyhow::anyhow!(
                "authoritative mining subscriptions are disabled or no authority permit is available in {} mode",
                self.config.authority_mode.as_str()
            )
        })?;
        Ok(self.mining_events.subscribe())
    }

    /// Aggregate fixture service used only by in-crate compatibility tests.
    /// Production listeners construct a diagnostic snapshot and dispatch
    /// bounded point/collection reads after method selection.
    #[cfg(test)]
    pub(crate) fn rpc_service(&self) -> Result<BasicRpcService> {
        Ok(BasicRpcService::new(self.rpc_snapshot()?))
    }

    fn rpc_diagnostic_service(&self) -> Result<BasicRpcService> {
        Ok(BasicRpcService::new(self.rpc_diagnostic_snapshot()?))
    }

    pub fn accept_block(&mut self, request: NodeBlockImport) -> Result<BlockAcceptance> {
        let active_transactions = request.block.transactions.clone();
        let summary = HeaderSummary::from_block(&request.block, request.height);
        self.mining_events.candidate_tip_seen(summary.clone());
        let validated = self.state.validate_import(&request)?;
        self.mining_events.block_syntax_validated(summary);
        let block_hash = request.block.hash();

        if let Some(existing) = self.state.load_block_record(&block_hash)? {
            if existing.status.active_chain {
                let snapshot = self.state.store.snapshot()?;
                let header = load_header_record(&snapshot, &block_hash)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "active block {} is missing its header record",
                        block_hash.to_hex()
                    )
                })?;
                if read_canonical_hash(&snapshot, existing.height)? != Some(block_hash)
                    || header.hash != existing.hash
                    || header.height != existing.height
                    || header.header != request.block.header
                    || header.chainwork != existing.chainwork
                    || header.status != existing.status
                {
                    anyhow::bail!(
                        "active block index {} is not authenticated by canonical header state",
                        block_hash.to_hex()
                    );
                }
                return Ok(BlockAcceptance {
                    record: existing,
                    disposition: BlockDisposition::AlreadyKnown { active: true },
                });
            }
        } else if self.state.is_direct_active_extension(&request)? {
            let committed = match self.state.commit_staged_block(request, validated, true) {
                Ok(committed) => committed,
                Err(error) => {
                    self.fail_closed_after_ambiguous_commit();
                    return Err(error);
                }
            };
            let mining_publication = self.publish_durable_mining_state(&committed.mining);
            let mempool_generation =
                self.mining_engine_reconcile_connected_transactions(&active_transactions);
            mining_publication?;
            self.mining_engine_publish_mempool_reconciled(
                committed.mining.generation,
                mempool_generation,
            )?;
            return Ok(BlockAcceptance {
                record: committed.record,
                disposition: BlockDisposition::Connected,
            });
        }

        let stored = match self.state.store_validated_alternate(request, validated) {
            Ok(stored) => stored,
            Err(error) => {
                self.fail_closed_after_ambiguous_commit();
                return Err(error);
            }
        };
        let Some(activation) = self
            .state
            .best_chain_activation_plan(stored.record.hash, NodeReorgLimits::PRODUCTION)?
        else {
            return Ok(BlockAcceptance {
                record: stored.record.clone(),
                disposition: if stored.already_known {
                    BlockDisposition::AlreadyKnown {
                        active: stored.record.status.active_chain,
                    }
                } else {
                    BlockDisposition::StoredAlternate
                },
            });
        };

        let reconciliation_snapshot = self.state.store.snapshot()?;
        preflight_reorg_reconciliation_budget(
            &reconciliation_snapshot,
            &activation,
            NodeReorgLimits::PRODUCTION,
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

        match self.state.apply_reorg(activation) {
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
                let record =
                    reorg.summary.connected.last().cloned().ok_or_else(|| {
                        anyhow::anyhow!("best-chain activation connected no blocks")
                    })?;
                let disposition = if is_reorg {
                    BlockDisposition::Reorganized {
                        disconnected: reorg.summary.disconnected.len(),
                        connected: reorg.summary.connected.len(),
                    }
                } else {
                    BlockDisposition::Connected
                };
                Ok(BlockAcceptance {
                    record,
                    disposition,
                })
            }
            Err(error) => {
                self.fail_closed_after_ambiguous_commit();
                if is_reorg {
                    self.mining_events.reorg_aborted();
                }
                Err(error)
            }
        }
    }

    pub fn connect_block(&mut self, request: NodeBlockImport) -> Result<BlockIndexRecord> {
        self.accept_block(request)
            .map(|acceptance| acceptance.record)
    }

    fn disconnected_mempool_transactions(
        &self,
        disconnects: &[NodeBlockDisconnect],
    ) -> Result<Vec<Transaction>> {
        if !self.config.mining_engine.enabled {
            return Ok(Vec::new());
        }
        let snapshot = self.state.store.snapshot()?;
        let mut transactions = Vec::new();
        for disconnect in disconnects.iter().rev() {
            let record =
                load_block_index_record(&snapshot, &disconnect.block_hash)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "disconnect block index {} is missing",
                        disconnect.block_hash.to_hex()
                    )
                })?;
            if record.height != disconnect.height {
                anyhow::bail!(
                    "disconnect block {} height mismatch: expected {}, got {}",
                    disconnect.block_hash.to_hex(),
                    disconnect.height,
                    record.height
                );
            }
            let block = load_block(&snapshot, &disconnect.block_hash)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "disconnect block body {} is missing",
                    disconnect.block_hash.to_hex()
                )
            })?;
            // Retain coinbases for dedicated claim/airdrop reconciliation.
            // Ordinary admission still rejects coinbases themselves.
            transactions.extend(block.transactions);
        }
        Ok(transactions)
    }

    pub fn submit_mining_candidate(
        &mut self,
        candidate: SolvedMiningCandidate,
    ) -> Result<BlockIndexRecord> {
        let durable = self.state.durable_mining_state()?;
        let permit = issue_authority_permit(&self.config, &durable).ok_or_else(|| {
            anyhow::anyhow!(
                "hsrd cannot accept mining candidates without an authority permit in {} mode",
                self.config.authority_mode.as_str()
            )
        })?;
        let snapshot = durable.snapshot.as_ref().ok_or_else(|| {
            anyhow::anyhow!("authority permit exists without a durable mining snapshot")
        })?;
        if candidate.snapshot_generation() != permit.generation
            || candidate.parent_height() != snapshot.tip.height
            || candidate.block().header.prev_block != permit.tip
            || candidate.block().header.tree_root != snapshot.next_tree_root
        {
            anyhow::bail!("mining candidate is stale for the authority permit");
        }
        self.connect_block(NodeBlockImport::from_mining_candidate(candidate)?)
    }

    pub fn disconnect_block(&mut self, request: NodeBlockDisconnect) -> Result<BlockIndexRecord> {
        let disconnected_transactions =
            self.disconnected_mempool_transactions(std::slice::from_ref(&request))?;
        let disconnected = match self.state.disconnect_block(request) {
            Ok(disconnected) => disconnected,
            Err(error) => {
                self.fail_closed_after_ambiguous_commit();
                return Err(error);
            }
        };
        let mining_publication = self.publish_durable_mining_state(&disconnected.mining);
        let mempool_generation =
            self.mining_engine_reconcile_chain_transition(&disconnected_transactions, &[]);
        mining_publication?;
        self.mining_engine_publish_mempool_reconciled(
            disconnected.mining.generation,
            mempool_generation,
        )?;
        Ok(disconnected.record)
    }

    pub fn apply_reorg(&mut self, request: NodeReorg) -> Result<NodeReorgSummary> {
        self.apply_reorg_with_limits(request, NodeReorgLimits::PRODUCTION)
    }

    /// Writer-only native activation boundary. The returned mutation has not
    /// yet been published to mining or reconciled with the mempool; callers
    /// must preserve the existing commit -> mining publication -> mempool
    /// reconciliation -> template-clear sequence in the same writer closure.
    pub(crate) fn apply_reorg_classified_prepared(
        &mut self,
        request: NodeReorg,
        prepared: PreparedNativeActivation,
    ) -> std::result::Result<NodeReorgMutation, ChainActivationFailure> {
        self.state
            .apply_reorg_classified_prepared(request, prepared)
    }

    /// Commit one already-stored canonical successor through the same atomic
    /// direct-extension path used for a live block.
    ///
    /// A one-block forward activation is not a reorganization and cannot be
    /// bisected further. Routing it through the bounded multi-block reorg
    /// transaction can turn that batching limit into a permanent IBD liveness
    /// failure. This path remains fully contextual, atomic, page-tail rollback
    /// safe, and fail-closed; it only avoids re-persisting the body that native
    /// sync has already durably authenticated and stored.
    pub(crate) fn apply_prepared_stored_direct_extension(
        &mut self,
        request: NodeBlockImport,
        prepared: PreparedNativeActivation,
    ) -> std::result::Result<NodeReorgMutation, ChainActivationFailure> {
        let stateless = prepared
            .into_single_for(&request)
            .map_err(ChainActivationFailure::Internal)?;
        let mutation = self
            .state
            .commit_prepared_stored_direct_extension(request, stateless)?;
        Ok(NodeReorgMutation {
            summary: NodeReorgSummary {
                disconnected: Vec::new(),
                connected: vec![mutation.record],
            },
            mining: mutation.mining,
        })
    }

    fn apply_reorg_with_limits(
        &mut self,
        request: NodeReorg,
        limits: NodeReorgLimits,
    ) -> Result<NodeReorgSummary> {
        // Reject cardinality and aggregate body envelopes before syntax
        // validation, undo reads, page discovery, transaction cloning, or any
        // staging allocation. NodeState repeats this at the mutation boundary.
        let reconciliation_snapshot = self.state.store.snapshot()?;
        preflight_reorg_reconciliation_budget(&reconciliation_snapshot, &request, limits)?;
        drop(reconciliation_snapshot);
        for connect in &request.connect {
            let summary = HeaderSummary::from_block(&connect.block, connect.height);
            self.mining_events.candidate_tip_seen(summary.clone());
            self.state
                .validate_import_syntax(connect)
                .map_err(|error| {
                    anyhow::anyhow!("reorg block syntax validation failed before staging: {error}")
                })?;
            self.mining_events.block_syntax_validated(summary);
        }

        if request.disconnect.is_empty() && request.connect.is_empty() {
            return Ok(NodeReorgSummary::default());
        }
        let disconnected_transactions =
            self.disconnected_mempool_transactions(&request.disconnect)?;
        let connected_transactions = request
            .connect
            .iter()
            .flat_map(|connect| connect.block.transactions.iter().cloned())
            .collect::<Vec<_>>();

        self.mining_events
            .reorg_started(request.disconnect.len(), request.connect.len());
        match self.state.apply_reorg_with_limits(request, limits) {
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
                Ok(reorg.summary)
            }
            Err(error) => {
                self.fail_closed_after_ambiguous_commit();
                if let Ok(durable) = self.state.durable_mining_state() {
                    let _ = self.publish_durable_mining_state(&durable);
                }
                self.mining_events.reorg_aborted();
                Err(error)
            }
        }
    }

    fn fail_closed_after_ambiguous_commit(&self) {
        if !self.state.storage_reopen_required() {
            return;
        }
        self.revoke_runtime_authority();
    }

    fn revoke_runtime_authority(&self) {
        if self.config.mining_engine.enabled {
            self.mining_engine_templates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
        }
        let generation = self.mining_events.committed_generation().saturating_add(1);
        if let Err(error) = self.mining_events.tip_staged(None, generation) {
            tracing::error!(
                %error,
                generation,
                "failed to revoke runtime mining authority"
            );
        }
    }

    fn publish_durable_mining_state(&self, durable: &DurableMiningState) -> Result<()> {
        if durable.generation <= self.mining_events.committed_generation() {
            return Ok(());
        }
        if self.config.mining_engine.enabled {
            let mut templates = self
                .mining_engine_templates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            templates.clear();
        }
        if durable_tip_can_authorize(&self.config, durable) {
            match &durable.snapshot {
                Some(snapshot) => self
                    .mining_events
                    .tip_committed(Arc::clone(snapshot))
                    .map_err(|error| {
                        anyhow::anyhow!("failed to publish committed mining tip: {error}")
                    }),
                None => self
                    .mining_events
                    .tip_cleared(durable.generation)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to publish cleared mining tip: {error}")
                    }),
            }
        } else {
            self.mining_events
                .tip_staged(durable.snapshot.clone(), durable.generation)
                .map_err(|error| anyhow::anyhow!("failed to publish staged chain tip: {error}"))
        }
    }

    pub async fn run_until_shutdown(self, shutdown: ShutdownSignal) -> Result<()> {
        if self.config.native_sync.enabled {
            self.run_native_sync_until_shutdown(shutdown).await
        } else {
            self.run_rpc_until_shutdown(shutdown).await
        }
    }

    pub async fn run_until_shutdown_with_extension(
        self,
        shutdown: ShutdownSignal,
        extension: Box<dyn NativeRuntimeExtension>,
    ) -> Result<()> {
        if !self.config.native_sync.enabled {
            anyhow::bail!("native runtime extensions require native sync");
        }
        self.run_native_sync_until_shutdown_with_extension(shutdown, Some(extension))
            .await
    }

    pub(crate) async fn run_rpc_until_shutdown(self, shutdown: ShutdownSignal) -> Result<()> {
        let node = Arc::new(self);
        // The runtime listener starts from bounded diagnostic/collection
        // snapshots. Historical block, transaction, UTXO, and name data is
        // loaded only after method dispatch through RpcReadContext.
        let rpc_service = node.rpc_diagnostic_service()?;
        // Collection responses are captured on their bounded worker after
        // method dispatch. Do not clone the entire mempool while starting the
        // listener.
        let collection_service = rpc_service.clone();
        let read_context = node.rpc_read_context();
        let listener = TcpListener::bind(node.config.rpc_bind)
            .await
            .with_context(|| format!("failed to bind RPC listener on {}", node.config.rpc_bind))?;
        let local_addr = listener
            .local_addr()
            .context("failed to read RPC listener address")?;

        tracing::info!(
            network = %node.config.network,
            rpc_bind = %local_addr,
            mempool_size = rpc_service.snapshot().mempool_info.transaction_count,
            "hsrd rpc server started"
        );
        let result = serve_rpc_listener_with_state(
            listener,
            RpcHttpState::new(
                rpc_service,
                collection_service,
                Some(read_context),
                Some(Arc::clone(&node)),
                node.config.rpc_limits,
            ),
            node.config.rpc_authorization.clone(),
            shutdown.wait(),
        )
        .await;
        if result.is_ok() {
            mark_node_store_clean(&node.state.store, node.config.network)?;
        }
        result?;
        tracing::info!("hsrd rpc server stopped");
        Ok(())
    }

    #[cfg(test)]
    fn rpc_snapshot(&self) -> Result<RpcSnapshot> {
        self.rpc_snapshot_with_entries(true, true)
    }

    fn rpc_diagnostic_snapshot(&self) -> Result<RpcSnapshot> {
        self.rpc_snapshot_with_entries(false, false)
    }

    fn rpc_snapshot_with_entries(
        &self,
        include_entries: bool,
        include_mempool_entries: bool,
    ) -> Result<RpcSnapshot> {
        let chain_tip = self.state.best_block_tip()?;
        let entries = if include_entries {
            self.state.rpc_entries()?
        } else {
            RpcStoreEntries::default()
        };
        let durable = self.state.durable_mining_state()?;
        let tip_validation = match chain_tip.as_ref() {
            Some(tip) => self
                .state
                .blocks
                .load_block_record(&tip.hash)
                .map_err(|error| anyhow::anyhow!("failed to load tip validation status: {error}"))?
                .map(|record| record.status),
            None => None,
        };
        let metadata = self.state.store.snapshot()?;
        let best_header = best_header_tip_from_snapshot(&metadata)?;
        let chain_epoch = chain_epoch_from_snapshot(&metadata)?;
        let (alternate_block_count, failed_block_count) = self.state.blocks.status_counts();
        let name_tree_compaction_checkpoint = load_name_tree_compaction_checkpoint(&metadata)?;
        let undo_pruning_checkpoint = load_undo_pruning_checkpoint(&metadata)?;
        let pending_best_chain_activation = match (&best_header, &chain_tip) {
            (Some(header), Some(active)) => {
                header.hash != active.hash && header.chainwork > active.chainwork
            }
            (Some(_), None) => true,
            _ => false,
        };
        drop(metadata);

        let production_safety_kind = self.state.production_safety_fence_kind();
        let production_safety_reason = self.state.production_safety_fence_reason();
        let mut authority = authority_info(&self.config, &durable);
        if let Some(reason) = production_safety_reason.as_ref() {
            authority.synchronized = false;
            authority.can_authorize_mining_templates = false;
            authority.can_accept_mining_candidates = false;
            authority.mainnet_canary_active = false;
            authority
                .blockers
                .push(format!("durable production safety fence: {reason}"));
            authority.blockers.sort();
            authority.blockers.dedup();
        }
        let parity = parity_info();
        let name_tree_compaction = RpcNameTreeCompactionInfo {
            compact_on_startup: self.config.name_tree_compaction.compact_on_startup,
            startup_interval: self.config.name_tree_compaction.startup_interval,
            last_height: name_tree_compaction_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.height),
            last_tip: name_tree_compaction_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.tip),
            last_retained_roots: name_tree_compaction_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.summary.retained_roots),
            last_nodes_before: name_tree_compaction_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.summary.nodes_before),
            last_nodes_retained: name_tree_compaction_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.summary.nodes_retained),
            last_nodes_deleted: name_tree_compaction_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.summary.nodes_deleted),
            name_page_compaction_overdue: matches!(
                production_safety_kind,
                Some(ProductionSafetyFenceKind::NamePageCompaction)
            ),
            payload_segment_compaction_overdue: matches!(
                production_safety_kind,
                Some(ProductionSafetyFenceKind::PayloadSegmentCompaction)
            ),
            production_safety_reason,
        };
        let retention = self.config.network.params().block;
        let undo_retention = RpcUndoRetentionInfo {
            prune_history: self.config.undo_retention.prune_history,
            prune_after_height: retention.prune_after_height,
            keep_blocks: retention.keep_blocks,
            pruned_through: undo_pruning_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.pruned_through),
            checkpoint_block: undo_pruning_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.block_hash),
            pruned_undos: undo_pruning_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.pruned_undos),
            blocks_pruned_through: undo_pruning_checkpoint.as_ref().and_then(|checkpoint| {
                (checkpoint.blocks_pruned_through != 0).then_some(checkpoint.blocks_pruned_through)
            }),
            blocks_checkpoint: undo_pruning_checkpoint.as_ref().and_then(|checkpoint| {
                (checkpoint.blocks_pruned_through != 0).then_some(checkpoint.blocks_checkpoint)
            }),
            pruned_blocks: undo_pruning_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.pruned_blocks),
        };
        let node_status = RpcNodeStatus {
            api_version: HSRD_DIAGNOSTIC_API_VERSION,
            release_stage: "pre-authority".to_owned(),
            schema_version: SCHEMA_VERSION,
            network: self.config.network.to_string(),
            storage_profile: String::from_utf8_lossy(STORAGE_PROFILE).into_owned(),
            storage_durability: self.state.store.durability_policy().to_string(),
            rpc_authentication_required: self.config.rpc_authorization.is_some(),
            best_header_hash: best_header.as_ref().map(|tip| tip.hash),
            best_header_height: best_header.as_ref().map(|tip| tip.height),
            best_block_hash: chain_tip.as_ref().map(|tip| tip.hash),
            height: chain_tip.as_ref().map(|tip| tip.height),
            active_state_resulting_root: durable
                .snapshot
                .as_ref()
                .map(|snapshot| hex_encode(&snapshot.next_tree_root)),
            active_state_resulting_root_height: durable
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.tip.height),
            chain_epoch,
            mining_generation: durable.generation,
            alternate_block_count,
            failed_block_count,
            active_state_sync_enabled: self.config.native_sync.connect_active_state,
            active_state_connect_batch: self.config.native_sync.active_state_connect_batch,
            pending_best_chain_activation,
            staged_chain_tip: durable.snapshot.is_some(),
            authoritative_mining_tip: self.mining_events.snapshot().is_some(),
            tip_validation,
            name_tree_compaction,
            undo_retention,
            experimental_registry: rpc_experimental_registry_info(&DenuoSummary::default()),
            hip76: rpc_hip76_info(&[]),
            odoh: rpc_inactive_odoh_info(
                self.config.network,
                self.config.native_sync.enabled
                    && self.config.native_sync.odoh_requester
                    && self
                        .config
                        .native_sync
                        .odoh_requester_override
                        .unwrap_or(true),
            ),
            hnsr: rpc_inactive_hnsr_info(
                self.config.network,
                self.config.native_sync.enabled
                    && self.config.native_sync.hnsr_requester
                    && self
                        .config
                        .native_sync
                        .hnsr_requester_override
                        .unwrap_or(true),
                self.config.native_sync.enabled
                    && self.config.native_sync.hnsr_opaque_relay
                    && self
                        .config
                        .native_sync
                        .hnsr_opaque_relay_override
                        .unwrap_or(true),
            ),
            authority,
            parity,
        };

        let mempool_info = self.state.mempool.info();
        let mempool_entries = if include_mempool_entries
            && mempool_info.transaction_count <= self.config.rpc_limits.maximum_collection_entries
        {
            self.state.mempool.entries()
        } else {
            Vec::new()
        };

        Ok(RpcSnapshot {
            network: self.config.network.to_string(),
            chain_tip,
            headers: entries.headers,
            blocks: entries.blocks,
            transactions: entries.transactions,
            coins: entries.coins,
            names: entries.names,
            mempool_info,
            mempool_entries,
            network_active: false,
            peer_count: 0,
            mining_engine: rpc_mining_engine_info(self.mining_engine_diagnostics()?),
            node_status,
            dns_context: None,
        })
    }
}

#[derive(Clone, Debug)]
struct RpcHttpState {
    service: Arc<BasicRpcService>,
    collection_service: Arc<BasicRpcService>,
    read_context: Option<RpcReadContext>,
    standalone_node: Option<Arc<NodeService>>,
    fallback_point_read_concurrency: Arc<Semaphore>,
    fallback_collection_concurrency: Arc<Semaphore>,
    limits: RpcLimits,
}

impl RpcHttpState {
    fn new(
        service: BasicRpcService,
        collection_service: BasicRpcService,
        read_context: Option<RpcReadContext>,
        standalone_node: Option<Arc<NodeService>>,
        limits: RpcLimits,
    ) -> Self {
        Self {
            service: Arc::new(service),
            collection_service: Arc::new(collection_service),
            read_context,
            standalone_node,
            fallback_point_read_concurrency: Arc::new(Semaphore::new(
                limits.maximum_concurrent_requests,
            )),
            fallback_collection_concurrency: Arc::new(Semaphore::new(
                limits.maximum_concurrent_requests,
            )),
            limits,
        }
    }

    fn try_acquire_point_read(&self) -> Option<OwnedSemaphorePermit> {
        match self.read_context.as_ref() {
            Some(read_context) => read_context.try_acquire_point_read(),
            None => Arc::clone(&self.fallback_point_read_concurrency)
                .try_acquire_owned()
                .ok(),
        }
    }

    fn try_acquire_collection(&self) -> Option<OwnedSemaphorePermit> {
        match self.read_context.as_ref() {
            Some(read_context) => read_context.try_acquire_collection(),
            None => Arc::clone(&self.fallback_collection_concurrency)
                .try_acquire_owned()
                .ok(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RpcRuntimeLimits {
    concurrency: Arc<Semaphore>,
    execution_timeout: Duration,
}

impl RpcRuntimeLimits {
    pub(crate) fn new(limits: RpcLimits) -> Self {
        Self {
            concurrency: Arc::new(Semaphore::new(limits.maximum_concurrent_requests)),
            execution_timeout: limits.execution_timeout,
        }
    }

    fn try_acquire(&self) -> Result<OwnedSemaphorePermit, RpcAdmissionError> {
        Arc::clone(&self.concurrency)
            .try_acquire_owned()
            .map_err(|_| RpcAdmissionError::Busy)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RpcAdmissionError {
    Busy,
    TimedOut,
}

#[derive(Clone, Debug, Default)]
struct RpcStoreEntries {
    headers: Vec<RpcHeaderEntry>,
    blocks: Vec<RpcBlockEntry>,
    transactions: Vec<RpcTransactionEntry>,
    coins: Vec<Coin>,
    names: Vec<NameState>,
}

/// Cloneable, immutable access to the durable RPC read model. Creating this
/// handle while the native-sync coordinator is locked is O(1); all RocksDB
/// snapshot acquisition, decoding, and bounded block reads happen after that
/// lock has been released.
#[derive(Clone, Debug)]
pub(crate) struct RpcReadContext {
    store: StoreHandle,
    headers: SharedHeaderIndex,
    network: Network,
    transaction_index: bool,
    point_read_concurrency: Arc<Semaphore>,
    collection_concurrency: Arc<Semaphore>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RpcRequestMempool {
    info: MempoolInfo,
    ordered_txids: Option<OrderedTxidSnapshot>,
    transaction_lookup: Option<(MempoolSnapshot, Txid)>,
}

impl NodeService {
    pub(crate) fn rpc_read_context(&self) -> RpcReadContext {
        RpcReadContext {
            store: self.state.store.clone(),
            headers: self.state.chain.clone(),
            network: self.config.network,
            transaction_index: self.state.transaction_index,
            point_read_concurrency: Arc::new(Semaphore::new(
                self.config.rpc_limits.maximum_concurrent_requests,
            )),
            collection_concurrency: Arc::new(Semaphore::new(
                self.config.rpc_limits.maximum_concurrent_requests,
            )),
        }
    }

    pub(crate) fn rpc_request_mempool(&self, request: &JsonRpcRequest) -> RpcRequestMempool {
        rpc_request_mempool(&self.state.mempool, request, self.config.rpc_limits)
    }
}

fn rpc_request_mempool(
    mempool: &MemoryMempool,
    request: &JsonRpcRequest,
    limits: RpcLimits,
) -> RpcRequestMempool {
    let info = mempool.info();
    let snapshot = mempool.snapshot();
    let method = RpcMethod::from_hsd_name(&request.method);
    let ordered_txids = if method == Some(RpcMethod::GetRawMempool)
        && info.transaction_count <= limits.maximum_collection_entries
    {
        Some(mempool.ordered_txids_snapshot())
    } else {
        None
    };
    let transaction_lookup = if method == Some(RpcMethod::GetRawTransaction) {
        rpc_string_param(request, 0)
            .and_then(|encoded| decode_rpc_txid(encoded).ok())
            .map(|txid| (snapshot, txid))
    } else {
        None
    };
    RpcRequestMempool {
        info,
        ordered_txids,
        transaction_lookup,
    }
}

impl RpcReadContext {
    pub(crate) fn try_acquire_point_read(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.point_read_concurrency)
            .try_acquire_owned()
            .ok()
    }

    pub(crate) fn try_acquire_collection(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.collection_concurrency)
            .try_acquire_owned()
            .ok()
    }

    pub(crate) fn service_for_request(
        &self,
        request: &JsonRpcRequest,
        mempool: RpcRequestMempool,
        network_active: bool,
        peer_count: usize,
        diagnostic_base: Option<&RpcSnapshot>,
    ) -> Result<BasicRpcService> {
        let method = RpcMethod::from_hsd_name(&request.method)
            .ok_or_else(|| anyhow::anyhow!("unsupported RPC method reached point-read dispatch"))?;
        let RpcRequestMempool {
            info: mempool_info,
            ordered_txids: _,
            transaction_lookup,
        } = mempool;
        // Keep the index read lock until the durable snapshot is established.
        // Writers hold the matching exclusive lock across commit and cache
        // publication, so the pair is wholly before or wholly after one index
        // generation; neither old-index/new-store nor new-index/old-store
        // combinations are observable.
        let (canonical_header, snapshot) = self
            .headers
            .read(|index| {
                let canonical_header = Self::canonical_header_from_index(index, method, request)?;
                let snapshot = self.store.snapshot()?;
                Ok((canonical_header, snapshot))
            })
            .map_err(|error| anyhow::anyhow!("failed to bind RPC read generation: {error}"))?;
        let chain_tip = best_block_tip_from_snapshot(&snapshot)?;
        let mut rpc = diagnostic_base.cloned().unwrap_or_default();
        rpc.network = self.network.to_string();
        rpc.chain_tip = chain_tip;
        rpc.headers.clear();
        rpc.blocks.clear();
        rpc.transactions.clear();
        rpc.coins.clear();
        rpc.names.clear();
        rpc.mempool_info = mempool_info;
        rpc.mempool_entries.clear();
        rpc.network_active = network_active;
        rpc.peer_count = peer_count;

        match method {
            RpcMethod::GetBlockHash => {
                if let Some(record) = canonical_header {
                    rpc.headers.push(RpcHeaderEntry::new(record));
                }
            }
            RpcMethod::GetBlockHeader => {
                if let Some(record) = canonical_header {
                    rpc.headers.push(RpcHeaderEntry::new(record));
                }
            }
            RpcMethod::GetParentAuthority => {
                if let Some(hash) = rpc_block_hash_param(request, 0) {
                    if let Some(record) = load_header_record(&snapshot, &hash)? {
                        if read_canonical_hash(&snapshot, record.height)? == Some(hash) {
                            rpc.headers.push(RpcHeaderEntry::new(record));
                        }
                    }
                }
            }
            RpcMethod::GetBlock => {
                if let Some(hash) = rpc_block_hash_param(request, 0) {
                    if let Some(record) = load_block_index_record(&snapshot, &hash)? {
                        if record.status.active_chain
                            && record.status.utxo_connected
                            && read_canonical_hash(&snapshot, record.height)? == Some(hash)
                        {
                            if let Some(block) = load_block(&snapshot, &hash)? {
                                rpc.blocks.push(RpcBlockEntry::from_block(record, &block));
                            }
                        }
                    }
                }
            }
            RpcMethod::GetRawTransaction => {
                if let Some(transaction) = transaction_lookup
                    .as_ref()
                    .and_then(|(snapshot, txid)| snapshot.transaction(txid))
                {
                    rpc.transactions.push(RpcTransactionEntry::from_transaction(
                        transaction,
                        None,
                        None,
                    ));
                } else if self.transaction_index {
                    self.load_indexed_transaction(&snapshot, request, &mut rpc)?;
                }
            }
            RpcMethod::GetTxOut => {
                if let (Some(txid), Some(index)) =
                    (rpc_txid_param(request, 0), rpc_u32_param(request, 1))
                {
                    let outpoint = Outpoint { txid, index };
                    if let Some(bytes) = snapshot
                        .get(ColumnFamily::Utxo, &encode_outpoint_key(&outpoint))
                        .context("failed to read RPC UTXO")?
                    {
                        rpc.coins.push(decode_coin(&bytes).map_err(|error| {
                            anyhow::anyhow!("failed to decode RPC UTXO: {error}")
                        })?);
                    }
                }
            }
            RpcMethod::GetNameInfo | RpcMethod::GetNameResource | RpcMethod::GetDnsResource => {
                if let Some(name) = rpc_string_param(request, 0) {
                    let name_hash = NameHash::new(sha3_256(name.as_bytes()));
                    if let Some(state) = load_rpc_name_state(&snapshot, name_hash)? {
                        if state.name.as_slice() == name.as_bytes() {
                            rpc.names.push(state);
                        }
                    }
                }

                if method == RpcMethod::GetDnsResource {
                    let best_header = best_header_tip_from_snapshot(&snapshot)?;
                    let active_height = rpc.chain_tip.as_ref().map(|tip| tip.height);
                    let synchronized = match (best_header.as_ref(), rpc.chain_tip.as_ref()) {
                        (Some(header), Some(active)) => {
                            header.hash == active.hash
                                && header.height == active.height
                                && header.chainwork == active.chainwork
                        }
                        _ => false,
                    };
                    let active_state_root = rpc
                        .chain_tip
                        .as_ref()
                        .map(|_| load_stored_name_tree_root(&snapshot))
                        .transpose()
                        .map_err(|error| {
                            anyhow::anyhow!("failed to read active DNS name-tree root: {error}")
                        })?
                        .map(|root| hex_encode(root.as_bytes()));
                    rpc.dns_context = Some(hns_rpc::RpcDnsContext {
                        network: self.network.to_string(),
                        active_height,
                        best_header_height: best_header.as_ref().map(|tip| tip.height),
                        active_state_root,
                        chain_epoch: chain_epoch_from_snapshot(&snapshot)?,
                        synchronized,
                    });
                }
            }
            RpcMethod::GetNameByHash => {
                if let Some(name_hash) = rpc_name_hash_param(request, 0) {
                    if let Some(state) = load_rpc_name_state(&snapshot, name_hash)? {
                        rpc.names.push(state);
                    }
                }
            }
            RpcMethod::GetBlockchainInfo
            | RpcMethod::GetBestBlockHash
            | RpcMethod::GetBlockCount
            | RpcMethod::GetMempoolInfo
            | RpcMethod::GetRawMempool
            | RpcMethod::GetNetworkInfo
            | RpcMethod::GetConnectionCount
            | RpcMethod::GetHsrdStatus
            | RpcMethod::GetAuthorityInfo
            | RpcMethod::GetParityInfo
            | RpcMethod::GetMiningEngineInfo => {}
            RpcMethod::SendRawTransaction | RpcMethod::GetPeerInfo => {
                anyhow::bail!("known unsupported RPC method reached point-read dispatch");
            }
        }
        drop(snapshot);
        Ok(BasicRpcService::new(rpc))
    }

    #[cfg(test)]
    fn canonical_header_for_request(
        &self,
        method: RpcMethod,
        request: &JsonRpcRequest,
    ) -> Result<Option<HeaderRecord>> {
        self.headers
            .read(|index| Self::canonical_header_from_index(index, method, request))
            .map_err(|error| anyhow::anyhow!("failed to read canonical RPC header: {error}"))
    }

    fn canonical_header_from_index(
        index: &StoredHeaderIndex<StoreHandle>,
        method: RpcMethod,
        request: &JsonRpcRequest,
    ) -> std::result::Result<Option<HeaderRecord>, ChainError> {
        match method {
            RpcMethod::GetBlockHash => rpc_height_param(request, 0)
                .map(|height| {
                    let Some(hash) = index.canonical_hash(height)? else {
                        return Ok(None);
                    };
                    index.header(&hash)
                })
                .transpose()
                .map(|record| record.flatten()),
            RpcMethod::GetBlockHeader => rpc_block_hash_param(request, 0)
                .map(|hash| {
                    let Some(record) = index.header(&hash)? else {
                        return Ok(None);
                    };
                    if index.canonical_hash(record.height)? == Some(hash) {
                        Ok(Some(record))
                    } else {
                        Ok(None)
                    }
                })
                .transpose()
                .map(|record| record.flatten()),
            _ => Ok(None),
        }
    }

    fn load_indexed_transaction(
        &self,
        snapshot: &impl ReadSnapshot,
        request: &JsonRpcRequest,
        rpc: &mut RpcSnapshot,
    ) -> Result<()> {
        let Some(txid) = rpc_txid_param(request, 0) else {
            return Ok(());
        };
        let Some(raw_index) = snapshot
            .get(ColumnFamily::TxIndex, txid.as_bytes())
            .context("failed to read transaction index")?
        else {
            return Ok(());
        };
        let index = TxIndexEntry::decode(&raw_index)
            .map_err(|error| anyhow::anyhow!("failed to decode transaction index: {error}"))?;
        if index.txid != txid
            || read_canonical_hash(snapshot, index.height)? != Some(index.block_hash)
        {
            return Ok(());
        }
        let Some(record) = load_block_index_record(snapshot, &index.block_hash)? else {
            return Ok(());
        };
        if !record.status.active_chain || !record.status.utxo_connected {
            return Ok(());
        }
        let Some(block) = load_block(snapshot, &index.block_hash)? else {
            return Ok(());
        };
        let Some(transaction) = block
            .transactions
            .iter()
            .find(|transaction| transaction.txid() == txid)
        else {
            anyhow::bail!(
                "transaction index {} does not resolve inside block {}",
                txid.to_hex(),
                index.block_hash.to_hex()
            );
        };
        rpc.transactions.push(RpcTransactionEntry::from_transaction(
            transaction,
            Some(index.block_hash),
            Some(index.height),
        ));
        Ok(())
    }
}

fn load_rpc_name_state(
    snapshot: &impl ReadSnapshot,
    name_hash: NameHash,
) -> Result<Option<NameState>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::NameState, name_hash.as_bytes())
        .context("failed to read RPC name state")?
    else {
        return Ok(None);
    };
    decode_name_state(&name_hash, &bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("failed to decode RPC name state: {error}"))
}

fn rpc_params(request: &JsonRpcRequest) -> Option<&[serde_json::Value]> {
    match &request.params {
        serde_json::Value::Null => Some(&[]),
        serde_json::Value::Array(params) => Some(params),
        _ => None,
    }
}

fn rpc_string_param(request: &JsonRpcRequest, index: usize) -> Option<&str> {
    rpc_params(request)?.get(index)?.as_str()
}

fn rpc_u32_param(request: &JsonRpcRequest, index: usize) -> Option<u32> {
    rpc_params(request)?
        .get(index)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
}

fn rpc_height_param(request: &JsonRpcRequest, index: usize) -> Option<Height> {
    rpc_u32_param(request, index)
}

fn rpc_block_hash_param(request: &JsonRpcRequest, index: usize) -> Option<BlockHash> {
    rpc_string_param(request, index)
        .and_then(|encoded| decode_rpc_hash(encoded).ok())
        .map(BlockHash::new)
}

fn rpc_txid_param(request: &JsonRpcRequest, index: usize) -> Option<Txid> {
    rpc_string_param(request, index).and_then(|encoded| decode_rpc_txid(encoded).ok())
}

fn rpc_name_hash_param(request: &JsonRpcRequest, index: usize) -> Option<NameHash> {
    rpc_string_param(request, index)
        .and_then(|encoded| decode_rpc_hash(encoded).ok())
        .map(NameHash::new)
}

fn decode_rpc_txid(encoded: &str) -> Result<Txid> {
    decode_rpc_hash(encoded).map(Txid::new)
}

fn decode_rpc_hash(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != 64 {
        anyhow::bail!("hash must contain exactly 64 hexadecimal characters");
    }
    let mut raw = [0u8; 32];
    for (index, output) in raw.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|_| anyhow::anyhow!("hash is not hexadecimal"))?;
    }
    Ok(raw)
}

pub async fn serve_rpc_listener<F>(
    listener: TcpListener,
    service: BasicRpcService,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_rpc_listener_with_authorization(listener, service, None, shutdown).await
}

pub async fn serve_rpc_listener_with_authorization<F>(
    listener: TcpListener,
    service: BasicRpcService,
    authorization: Option<RpcAuthorizationHeader>,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_rpc_listener_with_state(
        listener,
        RpcHttpState::new(service.clone(), service, None, None, RpcLimits::default()),
        authorization,
        shutdown,
    )
    .await
}

async fn serve_rpc_listener_with_state<F>(
    listener: TcpListener,
    state: RpcHttpState,
    authorization: Option<RpcAuthorizationHeader>,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let limits = state.limits;
    limits.validate()?;
    let runtime_limits = RpcRuntimeLimits::new(limits);
    let app = Router::new()
        .route("/", post(handle_rpc_http))
        .route("/rpc", post(handle_rpc_http))
        .route("/api/v1/status", get(handle_status_http))
        .route("/api/v1/authority", get(handle_authority_http))
        .route("/api/v1/parity", get(handle_parity_http))
        .route("/api/v1/mining-engine", get(handle_mining_engine_http))
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
        .with_graceful_shutdown(shutdown)
        .await
        .context("RPC server failed")
}

pub(crate) async fn enforce_rpc_resource_limits(
    State(limits): State<RpcRuntimeLimits>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    match execute_with_rpc_limits(&limits, next.run(request)).await {
        Ok(response) => response,
        Err(RpcAdmissionError::Busy) => (
            StatusCode::TOO_MANY_REQUESTS,
            "RPC concurrent request limit exceeded",
        )
            .into_response(),
        Err(RpcAdmissionError::TimedOut) => (
            StatusCode::GATEWAY_TIMEOUT,
            "RPC request execution timed out",
        )
            .into_response(),
    }
}

async fn execute_with_rpc_limits<T, F>(
    limits: &RpcRuntimeLimits,
    future: F,
) -> std::result::Result<T, RpcAdmissionError>
where
    F: Future<Output = T>,
{
    let _permit = limits.try_acquire()?;
    tokio::time::timeout(limits.execution_timeout, future)
        .await
        .map_err(|_| RpcAdmissionError::TimedOut)
}

pub(crate) async fn require_rpc_authorization(
    State(expected): State<RpcAuthorizationHeader>,
    headers: HeaderMap,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let candidate = headers.get(AUTHORIZATION).map(|value| value.as_bytes());
    if !expected.matches(candidate) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

async fn handle_status_http(State(state): State<RpcHttpState>) -> Json<serde_json::Value> {
    Json(handle_diagnostic_read(&state.service, "gethsrdstatus"))
}

async fn handle_authority_http(State(state): State<RpcHttpState>) -> Json<serde_json::Value> {
    Json(handle_diagnostic_read(&state.service, "getauthorityinfo"))
}

async fn handle_parity_http(State(state): State<RpcHttpState>) -> Json<serde_json::Value> {
    Json(handle_diagnostic_read(&state.service, "getparityinfo"))
}

async fn handle_mining_engine_http(State(state): State<RpcHttpState>) -> Json<serde_json::Value> {
    Json(handle_diagnostic_read(
        &state.service,
        "getminingengineinfo",
    ))
}

fn handle_diagnostic_read(service: &BasicRpcService, method: &str) -> serde_json::Value {
    let response = service.handle(JsonRpcRequest {
        jsonrpc: Some("2.0".to_owned()),
        method: method.to_owned(),
        params: serde_json::Value::Null,
        id: None,
    });

    match response {
        Ok(response) => response.result.unwrap_or_else(|| {
            serde_json::json!({
                "error": response.error.map(|error| error.message).unwrap_or_else(|| "missing result".to_owned())
            })
        }),
        Err(error) => serde_json::json!({ "error": error.to_string() }),
    }
}

async fn handle_rpc_http(State(state): State<RpcHttpState>, body: Bytes) -> Json<JsonRpcResponse> {
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
                .unwrap_or_else(|error| {
                    json_rpc_error(id, -32603, format!("internal error: {error}"))
                }),
        );
    }

    if method == RpcMethod::GetRawMempool {
        let Some(collection_permit) = state.try_acquire_collection() else {
            return Json(json_rpc_error(
                id,
                -32005,
                "RPC collection-worker concurrency limit exceeded".to_owned(),
            ));
        };
        let standalone_node = state.standalone_node.clone();
        let collection_service = Arc::clone(&state.collection_service);
        let diagnostic_service = Arc::clone(&state.service);
        let limits = state.limits;
        let worker_request = request;
        let worker_id = id.clone();
        let response = tokio::task::spawn_blocking(move || {
            let _collection_permit = collection_permit;
            if let Some(node) = standalone_node {
                let mempool = node.rpc_request_mempool(&worker_request);
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
                let mut snapshot = diagnostic_service.snapshot().clone();
                snapshot.mempool_info = mempool.info;
                snapshot.mempool_entries.clear();
                return BasicRpcService::new(snapshot)
                    .handle_raw_mempool(worker_request, ordered_txids.txids())
                    .unwrap_or_else(|error| {
                        json_rpc_error(worker_id, -32603, format!("internal error: {error}"))
                    });
            }
            if rpc_collection_exceeds(&collection_service, limits) {
                return json_rpc_error(
                    worker_id,
                    -8,
                    format!(
                        "mempool collection exceeds the RPC limit of {} entries",
                        limits.maximum_collection_entries
                    ),
                );
            }
            collection_service
                .handle(worker_request)
                .unwrap_or_else(|error| {
                    json_rpc_error(worker_id, -32603, format!("internal error: {error}"))
                })
        })
        .await;
        return Json(match response {
            Ok(response) => response,
            Err(error) => {
                json_rpc_error(id, -32603, format!("RPC collection worker failed: {error}"))
            }
        });
    }

    if rpc_point_read_method(method) {
        let Some(point_read_permit) = state.try_acquire_point_read() else {
            return Json(json_rpc_error(
                id,
                -32005,
                "RPC point-read concurrency limit exceeded".to_owned(),
            ));
        };
        if let Some(read_context) = state.read_context.clone() {
            let standalone_node = state.standalone_node.clone();
            let diagnostic_service =
                (method == RpcMethod::GetParentAuthority).then(|| Arc::clone(&state.service));
            let read_request = request;
            let response = match tokio::task::spawn_blocking(move || -> Result<JsonRpcResponse> {
                let _point_read_permit = point_read_permit;
                let mempool = standalone_node
                    .as_deref()
                    .map(|node| node.rpc_request_mempool(&read_request))
                    .unwrap_or_default();
                let diagnostic_base = diagnostic_service
                    .as_ref()
                    .map(|service| service.snapshot().clone());
                let service = read_context.service_for_request(
                    &read_request,
                    mempool,
                    false,
                    0,
                    diagnostic_base.as_ref(),
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
        } else {
            let service = Arc::clone(&state.service);
            let worker_request = request;
            let worker_id = id.clone();
            let response = tokio::task::spawn_blocking(move || {
                let _point_read_permit = point_read_permit;
                service.handle(worker_request).unwrap_or_else(|error| {
                    json_rpc_error(worker_id, -32603, format!("internal error: {error}"))
                })
            })
            .await;
            return Json(match response {
                Ok(response) => response,
                Err(error) => {
                    json_rpc_error(id, -32603, format!("RPC point-read worker failed: {error}"))
                }
            });
        }
    }

    Json(
        state
            .service
            .handle(request)
            .unwrap_or_else(|error| json_rpc_error(id, -32603, format!("internal error: {error}"))),
    )
}

pub(crate) const fn rpc_immediately_unsupported(method: RpcMethod) -> bool {
    matches!(
        method,
        RpcMethod::SendRawTransaction | RpcMethod::GetPeerInfo
    )
}

pub(crate) const fn rpc_point_read_method(method: RpcMethod) -> bool {
    matches!(
        method,
        RpcMethod::GetBlockHash
            | RpcMethod::GetBlockHeader
            | RpcMethod::GetBlock
            | RpcMethod::GetRawTransaction
            | RpcMethod::GetTxOut
            | RpcMethod::GetNameInfo
            | RpcMethod::GetNameResource
            | RpcMethod::GetDnsResource
            | RpcMethod::GetNameByHash
            | RpcMethod::GetParentAuthority
    )
}

pub(crate) fn rpc_collection_exceeds(service: &BasicRpcService, limits: RpcLimits) -> bool {
    service.snapshot().mempool_info.transaction_count > limits.maximum_collection_entries
}

fn json_rpc_error(id: Option<serde_json::Value>, code: i64, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        result: None,
        error: Some(RpcErrorObject { code, message }),
        id,
    }
}

#[derive(Clone, Debug)]
pub struct NodeBlockImport {
    block: Block,
    height: Height,
    validation: ImportValidationPolicy,
    source: RawBlockSource,
}

#[derive(Clone, Copy, Debug)]
enum ImportValidationPolicy {
    Strict,
    #[cfg(test)]
    Fixture {
        chainwork: Uint256,
    },
}

impl NodeBlockImport {
    #[cfg(test)]
    fn fixture(block: Block, height: Height, chainwork: u64) -> Self {
        Self {
            block,
            height,
            validation: ImportValidationPolicy::Fixture {
                chainwork: Uint256::from(chainwork),
            },
            source: RawBlockSource::Fixture,
        }
    }

    pub fn from_peer(block: Block, height: Height) -> Self {
        Self {
            block,
            height,
            validation: ImportValidationPolicy::Strict,
            source: RawBlockSource::Peer,
        }
    }

    pub fn from_mining_candidate(candidate: SolvedMiningCandidate) -> Result<Self> {
        let height = candidate
            .parent_height()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("mining candidate height overflow"))?;
        Ok(Self {
            block: candidate.into_block(),
            height,
            validation: ImportValidationPolicy::Strict,
            source: RawBlockSource::Mining,
        })
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn height(&self) -> Height {
        self.height
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeBlockDisconnect {
    pub block_hash: hns_primitives::BlockHash,
    pub height: Height,
}

#[derive(Clone, Debug)]
pub struct NodeReorg {
    pub disconnect: Vec<NodeBlockDisconnect>,
    pub connect: Vec<NodeBlockImport>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeReorgLimits {
    maximum_disconnect: usize,
    maximum_connect: usize,
    maximum_body_bytes: u64,
    maximum_staged_effect_bytes: u64,
}

impl NodeReorgLimits {
    const PRODUCTION: Self = Self {
        maximum_disconnect: MAX_REORG_DISCONNECT_BLOCKS,
        maximum_connect: MAX_REORG_CONNECT_BLOCKS,
        maximum_body_bytes: MAX_REORG_BODY_BYTES,
        maximum_staged_effect_bytes: MAX_REORG_STAGED_EFFECT_BYTES,
    };

    const fn with_maximum_connect(maximum_connect: usize) -> Self {
        Self {
            maximum_connect,
            ..Self::PRODUCTION
        }
    }

    const fn header_limits(self) -> ReorgPlanLimits {
        ReorgPlanLimits {
            maximum_disconnect: self.maximum_disconnect,
            maximum_connect: self.maximum_connect,
        }
    }
}

/// Cumulative, fail-closed accounting for one reorganization's atomic write.
///
/// The meter is deliberately attached to the `WriteBatch` boundary instead of
/// predicting state effects from block bodies. Every key, value, deletion and
/// operation frame is charged before the underlying batch or overlay may copy
/// it. Repeated writes to one logical key remain cumulative: the backend batch
/// still retains each operation even when the overlay replaces its visible
/// value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReorgStagedEffectMeter {
    consumed: u64,
    limit: u64,
}

#[cfg(test)]
thread_local! {
    /// Deterministic fault injection for the production archived-store
    /// boundary. The limit is clamped only after a reorg has physically
    /// appended at least one name page, so the archive's next accounted charge
    /// must reject and exercise safe page-tail rollback.
    static TEST_REORG_REJECT_AT_ARCHIVE_PREFLIGHT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static TEST_REORG_APPENDED_NAME_PAGE_BYTES: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_REORG_MAX_GENERATED_UNDO_BYTES: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
    static TEST_REORG_NAME_STATE_WRITES: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

impl ReorgStagedEffectMeter {
    const CONTEXT: &'static str = "reorganization staged effect bytes";

    const fn new(limit: u64) -> Self {
        Self { consumed: 0, limit }
    }

    fn operation_charge(key_bytes: usize, value_bytes: usize, copies: u64) -> u64 {
        u64::try_from(key_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(value_bytes).unwrap_or(u64::MAX))
            .saturating_add(REORG_STAGED_OPERATION_FRAMING_BYTES)
            .saturating_mul(copies)
    }

    fn charge(
        &mut self,
        key_bytes: usize,
        value_bytes: usize,
        copies: u64,
    ) -> std::result::Result<(), StoreError> {
        self.charge_amount(Self::operation_charge(key_bytes, value_bytes, copies))
    }

    fn charge_amount(&mut self, additional: u64) -> std::result::Result<(), StoreError> {
        let actual = self.consumed.saturating_add(additional);
        if actual > self.limit {
            return Err(StoreError::LimitExceeded {
                context: Self::CONTEXT,
                limit: self.limit,
                actual,
            });
        }
        self.consumed = actual;
        Ok(())
    }

    fn name_page_output_charge(page_count: usize) -> u64 {
        u64::try_from(page_count)
            .unwrap_or(u64::MAX)
            .saturating_mul(
                (hns_store::NAME_PAGE_BYTES as u64)
                    .saturating_add(REORG_STAGED_OPERATION_FRAMING_BYTES),
            )
            .saturating_mul(REORG_NAME_PAGE_OUTPUT_COPIES)
    }

    fn charge_name_page_output(
        &mut self,
        page_count: usize,
    ) -> std::result::Result<(), StoreError> {
        self.charge_amount(Self::name_page_output_charge(page_count))
    }

    fn name_page_packing_charge(records: &BTreeMap<TreeRoot, Vec<u8>>) -> u64 {
        records.values().fold(0u64, |total, canonical| {
            total.saturating_add(
                u64::try_from(canonical.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(REORG_NAME_PAGE_PACKING_METADATA_BYTES_PER_RECORD),
            )
        })
    }

    fn charge_name_page_packing(
        &mut self,
        records: &BTreeMap<TreeRoot, Vec<u8>>,
    ) -> std::result::Result<(), StoreError> {
        self.charge_amount(Self::name_page_packing_charge(records))
    }
}

impl AtomicWriteEffectBudget for ReorgStagedEffectMeter {
    fn operation_framing_bytes(&self) -> u64 {
        REORG_STAGED_OPERATION_FRAMING_BYTES
    }

    fn charge_additional(&mut self, additional: u64) -> std::result::Result<(), StoreError> {
        self.charge_amount(additional)
    }
}

/// A transparent write-batch decorator carrying the authoritative reorg
/// budget across both overlay staging and the later name-page publication
/// writes made after `StagedBatch::into_inner`.
struct ReorgMeteredBatch<B> {
    inner: B,
    meter: ReorgStagedEffectMeter,
    copies: u64,
}

impl<B> ReorgMeteredBatch<B> {
    const fn new(inner: B, meter: ReorgStagedEffectMeter, copies: u64) -> Self {
        Self {
            inner,
            meter,
            copies,
        }
    }

    fn into_parts(self) -> (B, ReorgStagedEffectMeter) {
        (self.inner, self.meter)
    }
}

impl<B: WriteBatch> WriteBatch for ReorgMeteredBatch<B> {
    fn put(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        value: &[u8],
    ) -> std::result::Result<(), StoreError> {
        self.meter.charge(key.len(), value.len(), self.copies)?;
        self.inner.put(family, key, value)?;
        #[cfg(test)]
        if family == ColumnFamily::Undo {
            TEST_REORG_MAX_GENERATED_UNDO_BYTES.with(|observed| {
                observed.set(
                    observed
                        .get()
                        .max(u64::try_from(value.len()).unwrap_or(u64::MAX)),
                );
            });
        }
        #[cfg(test)]
        if family == ColumnFamily::NameState {
            TEST_REORG_NAME_STATE_WRITES.with(|writes| writes.set(writes.get().saturating_add(1)));
        }
        Ok(())
    }

    fn delete(&mut self, family: ColumnFamily, key: &[u8]) -> std::result::Result<(), StoreError> {
        self.meter.charge(key.len(), 0, self.copies)?;
        self.inner.delete(family, key)
    }
}

/// The ordinary page-backed connect/disconnect path has no reorganization
/// budget. Reorganization publication supplies the specialized implementation
/// below so pack scratch, physical page bytes, and database writes share one
/// cumulative ceiling without duplicating `prepare_root`.
///
/// `PackedNamePages` retains cloned logical records, not encoded 64 KiB page
/// buffers. `charge_name_page_packing` runs before those logical clones and
/// their lookup/order/visited/address maps are allocated. After packing reveals
/// the exact page count, `charge_name_page_output` runs before
/// `NamePageAppender::append_with_reserve`, whose first step allocates the
/// fixed-size encoded page. Thus both allocation boundaries reject before the
/// newly charged representation exists.
trait NamePagePublicationBatch: WriteBatch {
    fn charge_name_page_packing(
        &mut self,
        _records: &BTreeMap<TreeRoot, Vec<u8>>,
    ) -> std::result::Result<(), StoreError> {
        Ok(())
    }

    fn charge_name_page_output(
        &mut self,
        _page_count: usize,
    ) -> std::result::Result<(), StoreError> {
        Ok(())
    }

    fn record_name_page_append(&self, _page_count: usize) {}
}

impl NamePagePublicationBatch for StoreHandleBatch {}

impl<B: WriteBatch> NamePagePublicationBatch for ReorgMeteredBatch<B> {
    fn charge_name_page_packing(
        &mut self,
        records: &BTreeMap<TreeRoot, Vec<u8>>,
    ) -> std::result::Result<(), StoreError> {
        self.meter.charge_name_page_packing(records)
    }

    fn charge_name_page_output(
        &mut self,
        page_count: usize,
    ) -> std::result::Result<(), StoreError> {
        self.meter.charge_name_page_output(page_count)
    }

    fn record_name_page_append(&self, page_count: usize) {
        #[cfg(not(test))]
        let _ = page_count;

        #[cfg(test)]
        TEST_REORG_APPENDED_NAME_PAGE_BYTES.with(|observed| {
            observed.set(
                u64::try_from(page_count)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(hns_store::NAME_PAGE_BYTES as u64),
            );
        });
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeReorgSummary {
    pub disconnected: Vec<BlockIndexRecord>,
    pub connected: Vec<BlockIndexRecord>,
}

#[derive(Clone, Debug)]
struct StagedIndexRecord {
    block: BlockIndexRecord,
    header: HeaderRecord,
}

#[derive(Clone, Debug)]
struct IndexStatusUpdate {
    previous_block: Option<BlockIndexRecord>,
    current: StagedIndexRecord,
}

#[derive(Clone, Debug)]
struct StagedConnect {
    current: StagedIndexRecord,
    pruned: Vec<IndexStatusUpdate>,
}

#[derive(Debug)]
struct PreparedIndexPublication {
    headers: HeaderIndexCacheUpdate,
    blocks: BlockIndexCacheUpdate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockDisposition {
    AlreadyKnown {
        active: bool,
    },
    StoredAlternate,
    Connected,
    Reorganized {
        disconnected: usize,
        connected: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockAcceptance {
    pub record: BlockIndexRecord,
    pub disposition: BlockDisposition,
}

#[derive(Clone, Debug)]
struct DurableMiningState {
    generation: MiningGeneration,
    snapshot: Option<Arc<MiningSnapshot>>,
    authoritative: bool,
    synchronized: bool,
}

#[derive(Clone, Debug)]
struct ValidatedImport {
    chainwork: Uint256,
    status: BlockStatus,
    historical_validation: HistoricalValidationPlan,
}

/// In-process evidence that the bounded native-sync validation pipeline has
/// already completed every context-independent body check for this exact
/// block and height. The type is private to the node crate so an RPC/P2P
/// caller cannot manufacture the fast-path capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatelessBodyValidation {
    hash: BlockHash,
    height: Height,
    transaction_start_validated: bool,
    body_sanity_validated: bool,
    body_commitments_validated: bool,
    name_limits_validated: bool,
    coinbase_height_validated: bool,
}

impl StatelessBodyValidation {
    pub(crate) fn for_block(block: &Block, height: Height, network: Network) -> Self {
        Self {
            hash: block.hash(),
            height,
            transaction_start_validated: true,
            body_sanity_validated: !hns_consensus::is_hsd_historical_block(network, true, height),
            body_commitments_validated: true,
            name_limits_validated: true,
            coinbase_height_validated: true,
        }
    }

    fn verify(self, request: &NodeBlockImport) -> Result<()> {
        match request.validation {
            ImportValidationPolicy::Strict => {}
            // Synthetic stored-chain tests retain fixture header/chainwork
            // policy, but still run the production body validator before this
            // exact hash+height capability is created. This variant does not
            // exist in production builds.
            #[cfg(test)]
            ImportValidationPolicy::Fixture { .. } => {}
        }
        if self.height != request.height || self.hash != request.block.hash() {
            anyhow::bail!("stateless body evidence does not match the imported block");
        }
        if !self.transaction_start_validated || !self.coinbase_height_validated {
            anyhow::bail!("stateless body evidence omits a required validation stage");
        }
        Ok(())
    }

    const fn covers(self, plan: HistoricalValidationPlan) -> bool {
        (!plan.body_sanity || self.body_sanity_validated)
            && (!plan.body_commitments || self.body_commitments_validated)
            && (!plan.name_limits || self.name_limits_validated)
    }
}

/// Process-private capability assembled only from successful ordered native
/// body-worker results. Every proof remains bound to an exact block hash and
/// height; the writer reauthenticates it against the final activation request.
#[derive(Clone, Debug, Default)]
pub(crate) struct PreparedNativeActivation {
    stateless: Vec<StatelessBodyValidation>,
}

impl PreparedNativeActivation {
    pub(crate) fn new(stateless: Vec<StatelessBodyValidation>) -> Result<Self> {
        let mut identities = HashSet::with_capacity(stateless.len());
        for proof in &stateless {
            if !identities.insert((proof.hash, proof.height)) {
                anyhow::bail!(
                    "prepared native activation repeats block {} at height {}",
                    proof.hash.to_hex(),
                    proof.height
                );
            }
        }
        Ok(Self { stateless })
    }

    fn authenticate(&self, request: &NodeReorg) -> Result<()> {
        if self.stateless.len() != request.connect.len() {
            anyhow::bail!(
                "prepared native activation has {} proofs for {} connected blocks",
                self.stateless.len(),
                request.connect.len()
            );
        }
        for (proof, connect) in self.stateless.iter().zip(&request.connect) {
            proof.verify(connect)?;
        }
        Ok(())
    }

    /// Consume the exact stateless proof for a one-block direct extension.
    ///
    /// Multi-block activation authenticates the whole proof vector at the
    /// reorganization boundary. When native replay has backed off to one
    /// block, it uses the ordinary direct-extension commit boundary instead;
    /// preserve the same process-private hash-and-height binding there.
    fn into_single_for(mut self, request: &NodeBlockImport) -> Result<StatelessBodyValidation> {
        if self.stateless.len() != 1 {
            anyhow::bail!(
                "prepared direct extension has {} proofs instead of one",
                self.stateless.len()
            );
        }
        let proof = self
            .stateless
            .pop()
            .expect("single prepared direct-extension proof checked above");
        proof.verify(request)?;
        Ok(proof)
    }

    fn into_by_identity(self) -> HashMap<(BlockHash, Height), StatelessBodyValidation> {
        self.stateless
            .into_iter()
            .map(|proof| ((proof.hash, proof.height), proof))
            .collect()
    }
}

#[derive(Clone, Debug)]
struct NodeBlockMutation {
    record: BlockIndexRecord,
    mining: DurableMiningState,
}

#[derive(Clone, Debug)]
struct StoredBlockMutation {
    record: BlockIndexRecord,
    already_known: bool,
}

#[derive(Clone, Debug)]
struct FailedBlockMutation {
    record: BlockIndexRecord,
    affected: Vec<BlockHash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailedBlockStage {
    BodySyntax,
    ContextualState,
}

#[derive(Debug)]
struct StateConnectError(StateError);

impl std::fmt::Display for StateConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "failed to stage state update: {}", self.0)
    }
}

impl std::error::Error for StateConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug)]
struct ContextualActivationFailure {
    request: NodeBlockImport,
    error: anyhow::Error,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "name-page compaction was deferred before publication: {detail}"
)]
struct NamePageCompactionDeferred {
    detail: String,
}

#[derive(Debug)]
enum ChainActivationFailure {
    ContextualInvalid(Box<ContextualActivationFailure>),
    Internal(anyhow::Error),
}

impl ChainActivationFailure {
    fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::ContextualInvalid(failure) => anyhow::anyhow!(
                "contextual validation failed for block {} at height {}: {:#}",
                failure.request.block.hash().to_hex(),
                failure.request.height,
                failure.error
            ),
            Self::Internal(error) => error,
        }
    }
}

#[derive(Clone, Debug)]
struct NodeReorgMutation {
    summary: NodeReorgSummary,
    mining: DurableMiningState,
}

#[derive(Debug)]
struct NamePageStorage {
    network: Network,
    directory: PathBuf,
    file_path: PathBuf,
    state: NamePageState,
    appender: Option<NamePageAppender>,
    reopen_required: bool,
    committed_generation_bytes: u64,
    generation_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct NamePageFilesystemLimits {
    max_segments: u64,
    max_directory_entries: u64,
    max_generation_bytes: u64,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug)]
struct NamePageRootLocatorScanLimits {
    max_records: u64,
    max_bytes: u64,
    page_budget: PrefixScanBudget,
    deadline: Instant,
}

fn production_name_page_filesystem_limits_with_elapsed(
    maximum_elapsed: Duration,
) -> NamePageFilesystemLimits {
    let now = Instant::now();
    NamePageFilesystemLimits {
        max_segments: MAX_NAME_PAGE_SEGMENTS,
        max_directory_entries: MAX_NAME_PAGE_SEGMENTS.saturating_add(16),
        max_generation_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
        deadline: now
            .checked_add(maximum_elapsed)
            .unwrap_or(now),
    }
}

fn production_name_page_filesystem_limits() -> NamePageFilesystemLimits {
    production_name_page_filesystem_limits_with_elapsed(
        MAX_NAME_PAGE_VALIDATION_ELAPSED,
    )
}

fn production_name_page_compaction_filesystem_limits() -> NamePageFilesystemLimits {
    production_name_page_filesystem_limits_with_elapsed(
        MAX_NAME_PAGE_COMPACTION_ELAPSED,
    )
}

fn production_name_page_compaction_cleanup_limits() -> NamePageFilesystemLimits {
    production_name_page_filesystem_limits_with_elapsed(
        MAX_NAME_PAGE_COMPACTION_CLEANUP_ELAPSED,
    )
}

fn name_page_error_contains_deadline(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<PageTreeError>(),
            Some(PageTreeError::DeadlineExceeded { .. })
        )
    })
}

fn production_name_page_stream_limits(deadline: Instant) -> NamePageStreamLimits {
    NamePageStreamLimits {
        max_records: MAX_NAME_PAGE_COMPACTION_RECORDS,
        max_pages: MAX_NAME_PAGE_GENERATION_BYTES / hns_store::NAME_PAGE_BYTES as u64,
        max_frontier: MAX_NAME_PAGE_COMPACTION_FRONTIER,
        max_known_addresses: MAX_NAME_PAGE_COMPACTION_KNOWN_ADDRESSES,
        minimum_filesystem_reserve_bytes: MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES,
        deadline,
    }
}

fn production_name_page_traversal_limits(deadline: Instant) -> NamePageTraversalLimits {
    NamePageTraversalLimits {
        max_records: MAX_NAME_PAGE_COMPACTION_RECORDS,
        max_frontier: MAX_NAME_PAGE_COMPACTION_FRONTIER,
        max_known_addresses: MAX_NAME_PAGE_COMPACTION_KNOWN_ADDRESSES,
        deadline,
    }
}

fn production_name_page_root_locator_scan_limits(
    deadline: Instant,
) -> NamePageRootLocatorScanLimits {
    NamePageRootLocatorScanLimits {
        max_records: MAX_NAME_PAGE_ROOT_LOCATORS,
        max_bytes: MAX_NAME_PAGE_ROOT_LOCATOR_BYTES,
        page_budget: PrefixScanBudget {
            max_entries: NAME_PAGE_ROOT_LOCATOR_SCAN_PAGE_ENTRIES,
            max_bytes: NAME_PAGE_ROOT_LOCATOR_SCAN_PAGE_BYTES,
        },
        deadline,
    }
}

fn ensure_name_page_filesystem_deadline(
    limits: NamePageFilesystemLimits,
    context: &'static str,
) -> Result<()> {
    if Instant::now() >= limits.deadline {
        return Err(PageTreeError::DeadlineExceeded { context }.into());
    }
    Ok(())
}

fn collect_name_page_root_locators(
    snapshot: &impl ReadSnapshot,
    limits: NamePageRootLocatorScanLimits,
) -> Result<BTreeMap<TreeRoot, NamePageRootRecord>> {
    if Instant::now() >= limits.deadline {
        return Err(PageTreeError::DeadlineExceeded {
            context: "name-page root locator scan",
        }
        .into());
    }
    let mut cursor = PagedPrefixCursor::new(
        snapshot,
        ColumnFamily::Snapshots,
        NAME_PAGE_ROOT_PREFIX,
        limits.page_budget,
        "name-page root locator scan",
    )?;
    let mut records = BTreeMap::new();
    let mut encoded_bytes = 0u64;
    while let Some((key, raw)) = cursor.next_entry()? {
        if Instant::now() >= limits.deadline {
            return Err(PageTreeError::DeadlineExceeded {
                context: "name-page root locator scan",
            }
            .into());
        }
        let actual_records = u64::try_from(records.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if actual_records > limits.max_records {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page root locator records",
                limit: limits.max_records,
                actual: actual_records,
            }
            .into());
        }
        let entry_bytes = u64::try_from(key.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(raw.len()).unwrap_or(u64::MAX));
        let actual_bytes = encoded_bytes.saturating_add(entry_bytes);
        if actual_bytes > limits.max_bytes {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page root locator bytes",
                limit: limits.max_bytes,
                actual: actual_bytes,
            }
            .into());
        }
        let record = NamePageRootRecord::decode(&raw)
            .map_err(anyhow::Error::new)
            .context("failed to decode name-page root locator")?;
        if key != name_page_root_key(record.root) {
            anyhow::bail!("name-page root locator key does not match its record");
        }
        if records.insert(record.root, record).is_some() {
            anyhow::bail!("duplicate name-page root locator");
        }
        encoded_bytes = actual_bytes;
    }
    if Instant::now() >= limits.deadline {
        return Err(PageTreeError::DeadlineExceeded {
            context: "name-page root locator scan",
        }
        .into());
    }
    Ok(records)
}

fn ensure_name_page_output_capacity(
    directory: &std::path::Path,
    output_bytes: u64,
    context: &'static str,
) -> Result<()> {
    let available = filesystem_available_bytes(directory)?;
    let required = output_bytes.saturating_add(MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES);
    if available < required {
        return Err(StoreError::InsufficientSpace {
            context,
            available,
            required,
            reserve: MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES,
        }
        .into());
    }
    Ok(())
}

fn preflight_migration_data_ceiling(current_bytes: u64, temporary_bytes: u64) -> Result<u64> {
    let aggregate_bytes = current_bytes.saturating_add(temporary_bytes);
    if aggregate_bytes > MAX_NAME_PAGE_GENERATION_BYTES {
        return Err(StoreError::LimitExceeded {
            context: "schema migration data-root and temporary bytes",
            limit: MAX_NAME_PAGE_GENERATION_BYTES,
            actual: aggregate_bytes,
        }
        .into());
    }
    Ok(aggregate_bytes)
}

fn preflight_name_page_publication(
    old_records: &BTreeMap<TreeRoot, NamePageRootRecord>,
    published_root_count: usize,
    encoded_state_bytes: usize,
) -> Result<(u64, u64)> {
    let old_count = u64::try_from(old_records.len()).unwrap_or(u64::MAX);
    let published_count = u64::try_from(published_root_count).unwrap_or(u64::MAX);
    let operations = old_count
        .checked_add(published_count)
        .and_then(|count| count.checked_add(1))
        .unwrap_or(u64::MAX);
    if operations > MAX_NAME_PAGE_PUBLICATION_OPERATIONS {
        return Err(PageTreeError::ResourceLimit {
            context: "name-page publication operations",
            limit: MAX_NAME_PAGE_PUBLICATION_OPERATIONS,
            actual: operations,
        }
        .into());
    }

    let root_key_bytes =
        u64::try_from(name_page_root_key(TreeRoot::ZERO).len()).unwrap_or(u64::MAX);
    let root_record_bytes = u64::try_from(
        NamePageRootRecord {
            root: TreeRoot::ZERO,
            locator: NamePageRootLocator {
                generation: 0,
                address: 0,
            },
            height: 0,
        }
        .encode()
        .len(),
    )
    .unwrap_or(u64::MAX);
    let delete_bytes = old_count.saturating_mul(root_key_bytes);
    let put_bytes =
        published_count.saturating_mul(root_key_bytes.saturating_add(root_record_bytes));
    let state_bytes = u64::try_from(NAME_PAGE_STATE_KEY.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(encoded_state_bytes).unwrap_or(u64::MAX));
    let encoded_bytes = delete_bytes
        .checked_add(put_bytes)
        .and_then(|bytes| bytes.checked_add(state_bytes))
        .unwrap_or(u64::MAX);
    if encoded_bytes > MAX_NAME_PAGE_PUBLICATION_BYTES {
        return Err(PageTreeError::ResourceLimit {
            context: "name-page publication bytes",
            limit: MAX_NAME_PAGE_PUBLICATION_BYTES,
            actual: encoded_bytes,
        }
        .into());
    }
    Ok((operations, encoded_bytes))
}

fn validate_name_page_active_segment(
    active_segment: u32,
    limits: NamePageFilesystemLimits,
) -> Result<()> {
    let segments = u64::from(active_segment) + 1;
    if segments > limits.max_segments {
        return Err(PageTreeError::ResourceLimit {
            context: "name-page generation segments",
            limit: limits.max_segments,
            actual: segments,
        }
        .into());
    }
    Ok(())
}

enum NodeReadSnapshot<'a, S: ReadSnapshot> {
    Base(&'a S),
    Pages(NamePageSnapshot<'a, S>),
}

impl<S: ReadSnapshot> ReadSnapshot for NodeReadSnapshot<'_, S> {
    fn get(
        &self,
        family: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, hns_store::StoreError> {
        match self {
            Self::Base(snapshot) => snapshot.get(family, key),
            Self::Pages(snapshot) => snapshot.get(family, key),
        }
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, hns_store::StoreError> {
        match self {
            Self::Base(snapshot) => snapshot.get_many(family, keys),
            Self::Pages(snapshot) => snapshot.get_many(family, keys),
        }
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<hns_store::ScanEntry>, hns_store::StoreError> {
        match self {
            Self::Base(snapshot) => snapshot.scan_prefix(family, prefix),
            Self::Pages(snapshot) => snapshot.scan_prefix(family, prefix),
        }
    }

    fn scan_prefix_page(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
        start_after: Option<&[u8]>,
        budget: PrefixScanBudget,
    ) -> Result<hns_store::PrefixScanPage, hns_store::StoreError> {
        match self {
            Self::Base(snapshot) => snapshot.scan_prefix_page(family, prefix, start_after, budget),
            Self::Pages(snapshot) => snapshot.scan_prefix_page(family, prefix, start_after, budget),
        }
    }

    fn prefetch_name_tree_paths(
        &self,
        root: [u8; 32],
        keys: &[[u8; 32]],
    ) -> Result<Option<Vec<hns_store::NameTreePathRecord>>, hns_store::StoreError> {
        match self {
            Self::Base(snapshot) => snapshot.prefetch_name_tree_paths(root, keys),
            Self::Pages(snapshot) => snapshot.prefetch_name_tree_paths(root, keys),
        }
    }
}

impl NamePageStorage {
    fn ensure_open(&self) -> Result<()> {
        if self.reopen_required {
            anyhow::bail!(
                "name-page storage is fenced after an ambiguous commit; restart and reopen the node"
            );
        }
        Ok(())
    }

    /// A Store::commit error does not prove that its atomic batch was
    /// rejected. Once publication was attempted, retain every synced page byte
    /// that either the old or new durable manifest may reference and prohibit
    /// all further in-process page access. Startup recovery reopens the actual
    /// committed manifest and truncates only bytes it proves unpublished.
    fn fence_after_commit_attempt(&mut self) {
        self.appender.take();
        self.reopen_required = true;
    }

    fn open_or_bootstrap(
        directory: PathBuf,
        store: &StoreHandle,
        network: Network,
    ) -> Result<Self> {
        let filesystem_limits = production_name_page_filesystem_limits();
        ensure_name_page_filesystem_deadline(filesystem_limits, "name-page startup recovery")?;
        std::fs::create_dir_all(&directory)
            .with_context(|| format!("failed to create {}", directory.display()))?;
        let snapshot = store.snapshot()?;
        let durable_root = load_stored_name_tree_commit_root(&snapshot)
            .map_err(|error| anyhow::anyhow!("failed to load page bootstrap root: {error}"))?;
        if let Some(raw) = snapshot
            .get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)
            .context("failed to read name-page state")?
        {
            let state = NamePageState::decode(&raw)
                .map_err(|error| anyhow::anyhow!("failed to decode name-page state: {error}"))?;
            validate_name_page_active_segment(state.manifest.active_segment, filesystem_limits)?;
            if state.root != durable_root {
                anyhow::bail!("name-page root does not match the durable committed name-tree root");
            }
            validate_name_page_root_record(&snapshot, &state)?;
            let pin_height_repairs = plan_name_page_pin_height_repairs(&snapshot, network)?;
            let file_path = name_page_file_path(
                &directory,
                state.manifest.generation,
                state.manifest.active_segment,
            );
            drop(snapshot);
            remove_unpublished_name_page_segments(
                &directory,
                state.manifest.generation,
                state.manifest.active_segment,
                filesystem_limits,
            )?;
            validate_name_page_segment_set(
                &directory,
                state.manifest.generation,
                state.manifest.active_segment,
                filesystem_limits,
            )?;
            truncate_name_pages_to_committed_tail(&file_path, state.manifest.durable_bytes)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to recover name-page file {}: {error}",
                        file_path.display()
                    )
                })?;
            let appender = NamePageAppender::open_at_committed_tail(&file_path, state.manifest)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to open name-page appender {}: {error}",
                        file_path.display()
                    )
                })?;
            let generation_bytes = name_page_generation_bytes(
                &directory,
                state.manifest.generation,
                filesystem_limits,
            )?;
            if generation_bytes > MAX_NAME_PAGE_GENERATION_BYTES {
                anyhow::bail!(
                    "name-page generation contains {generation_bytes} bytes; production ceiling is {MAX_NAME_PAGE_GENERATION_BYTES}"
                );
            }
            validate_name_page_pin_height_repairs(&directory, &state, &pin_height_repairs)?;
            if !pin_height_repairs.is_empty() {
                let mut batch = store.batch();
                for record in &pin_height_repairs {
                    batch.put(
                        ColumnFamily::Snapshots,
                        &name_page_root_key(record.root),
                        &record.encode(),
                    )?;
                }
                store
                    .commit(batch)
                    .context("failed to publish validated name-page pin-height repairs")?;
                tracing::warn!(
                    repaired = pin_height_repairs.len(),
                    "normalized name-page root locator heights to their earliest snapshot pins"
                );
            }
            return Ok(Self {
                network,
                directory,
                file_path,
                state,
                appender: Some(appender),
                reopen_required: false,
                committed_generation_bytes: generation_bytes,
                generation_bytes,
            });
        }

        let generation = 1;
        let segment = 0;
        let file_path = name_page_file_path(&directory, generation, segment);
        if file_path.exists() {
            std::fs::remove_file(&file_path).with_context(|| {
                format!(
                    "failed to discard uncommitted bootstrap page file {}",
                    file_path.display()
                )
            })?;
        }
        ensure_name_page_output_capacity(
            &directory,
            if durable_root == TreeRoot::ZERO {
                0
            } else {
                hns_store::NAME_PAGE_BYTES as u64
            },
            "name-page bootstrap output",
        )?;
        let mut appender =
            NamePageAppender::create_new(&file_path, generation, segment).map_err(|error| {
                anyhow::anyhow!(
                    "failed to create name-page file {}: {error}",
                    file_path.display()
                )
            })?;
        sync_directory(&directory)?;
        let height = best_block_tip_from_snapshot(&snapshot)?.map(|tip| tip.height);
        let streamed = stream_name_page_tree_with_limits(
            &snapshot,
            durable_root,
            &mut appender,
            production_name_page_stream_limits(filesystem_limits.deadline),
        )
        .map_err(anyhow::Error::new)
        .context("failed to stream bootstrap name pages")?;
        tracing::info!(
            records = streamed.record_count,
            pages = streamed.page_count,
            parallel_subtrees = streamed.parallel_subtrees,
            "streamed committed name tree into authenticated pages"
        );
        let manifest = streamed.manifest;
        let root_address = streamed.root_address;
        let state = NamePageState {
            manifest,
            root: durable_root,
            root_address,
            committed_height: height,
            last_sealed_height: None,
        };
        let mut batch = store.batch();
        batch.put(
            ColumnFamily::Snapshots,
            NAME_PAGE_STATE_KEY,
            &state.encode()?,
        )?;
        if let (Some(address), Some(height)) = (state.root_address, height) {
            let height =
                minimum_name_page_root_height(&snapshot, network, durable_root, height, &[])?;
            let record = NamePageRootRecord {
                root: durable_root,
                locator: NamePageRootLocator::new(generation, address),
                height,
            };
            batch.put(
                ColumnFamily::Snapshots,
                &name_page_root_key(durable_root),
                &record.encode(),
            )?;
        }
        drop(snapshot);
        ensure_name_page_filesystem_deadline(filesystem_limits, "name-page bootstrap publication")?;
        ensure_name_page_output_capacity(&directory, 0, "name-page bootstrap publication")?;
        store.commit(batch)?;
        let generation_bytes =
            name_page_generation_bytes(&directory, generation, filesystem_limits)?;
        if generation_bytes > MAX_NAME_PAGE_GENERATION_BYTES {
            anyhow::bail!(
                "bootstrapped name-page generation contains {generation_bytes} bytes; production ceiling is {MAX_NAME_PAGE_GENERATION_BYTES}"
            );
        }
        Ok(Self {
            network,
            directory,
            file_path,
            state,
            appender: Some(appender),
            reopen_required: false,
            committed_generation_bytes: generation_bytes,
            generation_bytes,
        })
    }

    fn reader_for_roots<I>(
        &self,
        snapshot: &impl ReadSnapshot,
        required_roots: I,
        allow_legacy_missing: bool,
    ) -> Result<(NamePageTreeReader, bool)>
    where
        I: IntoIterator<Item = TreeRoot>,
    {
        self.ensure_open()?;
        let locator = self.state.root_locator().unwrap_or_else(|| {
            NamePageRootLocator::new(
                self.state.manifest.generation,
                hns_store::NamePageAddress::new(self.state.manifest.active_segment, 0, 0)
                    .expect("zero page address fits"),
            )
        });
        let reader = NamePageTreeReader::open_generation(
            &self.directory,
            self.state.manifest.generation,
            self.state.manifest.active_segment,
            self.state.root,
            locator,
        )
        .map_err(|error| anyhow::anyhow!("failed to open name-page reader: {error}"))?;
        let mut legacy_missing = false;
        for root in required_roots.into_iter().collect::<BTreeSet<_>>() {
            if root == TreeRoot::ZERO || root == self.state.root {
                continue;
            }
            let Some(record) = load_name_page_root_record(snapshot, root)? else {
                if allow_legacy_missing {
                    legacy_missing = true;
                    continue;
                }
                anyhow::bail!("required name-page root {root:?} has no durable locator");
            };
            if record.root != root {
                anyhow::bail!("name-page root locator key does not match its record");
            }
            reader
                .insert_root(record.root, record.locator)
                .map_err(|error| anyhow::anyhow!("failed to seed page root locator: {error}"))?;
        }
        Ok((reader, legacy_missing))
    }

    fn compact_generation(&mut self, store: &StoreHandle) -> Result<NamePageCompactionReport> {
        let remaining_deadline_seconds = |deadline: Instant| {
            deadline
                .checked_duration_since(Instant::now())
                .map_or(0, |remaining| remaining.as_secs())
        };
        let progress_interval = Duration::from_secs(5);

        self.ensure_open()?;
        let filesystem_limits = production_name_page_compaction_filesystem_limits();
        let previous_generation = self.state.manifest.generation;
        let generation = previous_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("name-page generation number exhausted"))?;
        let source_segment_count = self.state.manifest.active_segment.saturating_add(1);
        let bytes_before =
            name_page_generation_bytes(&self.directory, previous_generation, filesystem_limits)?;
        remove_name_page_generation(&self.directory, generation, filesystem_limits)?;
        let start = Instant::now();
        tracing::info!(
            phase = "planning",
            previous_generation,
            generation,
            source_active_segment = self.state.manifest.active_segment,
            source_segment_count,
            source_bytes = bytes_before,
            retained_root_threshold = NAME_PAGE_COMPACTION_SEGMENT_THRESHOLD,
            compaction_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
            "starting pruned name-page generation compaction"
        );

        let snapshot = store.snapshot()?;
        let retained_limits = RetainedNameTreeRootLimits {
            deadline: filesystem_limits.deadline,
            ..RetainedNameTreeRootLimits::default()
        };
        let retained_roots = retained_name_tree_roots_bounded(&snapshot, retained_limits)
            .map_err(anyhow::Error::new)
            .context("failed to select retained name roots")?
            .roots;
        if !retained_roots.contains(&self.state.root) {
            anyhow::bail!("retained name roots omit the committed page root");
        }

        let old_records = collect_name_page_root_locators(
            &snapshot,
            production_name_page_root_locator_scan_limits(filesystem_limits.deadline),
        )?;
        let pin_heights =
            startup_pin_minimum_root_heights(&snapshot, self.network, &retained_roots)?;
        let file_path = name_page_file_path(&self.directory, generation, 0);
        let mut commit_attempted = false;
        let staged = (|| -> Result<StagedNamePageCompaction> {
            ensure_name_page_filesystem_deadline(filesystem_limits, "name-page compaction output")?;
            ensure_name_page_output_capacity(
                &self.directory,
                if retained_roots.iter().any(|root| *root != TreeRoot::ZERO) {
                    hns_store::NAME_PAGE_BYTES as u64
                } else {
                    0
                },
                "name-page compaction output",
            )?;
            let mut appender =
                NamePageAppender::create_new(&file_path, generation, 0).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to create compacted name-page generation {}: {error}",
                        file_path.display()
                    )
                })?;
            sync_directory(&self.directory)?;

            let base = {
                let (source_reader, _) =
                    self.reader_for_roots(&snapshot, std::iter::empty(), false)?;
                let source_snapshot = NamePageSnapshot::new(&snapshot, &source_reader);
                stream_name_page_tree_with_limits_and_progress(
                    &source_snapshot,
                    self.state.root,
                    &mut appender,
                    production_name_page_stream_limits(filesystem_limits.deadline),
                    progress_interval,
                    move |progress| {
                        tracing::info!(
                            phase = "streaming-base",
                            previous_generation,
                            generation,
                            records_written = progress.records_completed,
                            pages_written = progress.pages_completed,
                            bytes_written = progress.bytes_completed,
                            elapsed_seconds = start.elapsed().as_secs(),
                            remaining_deadline_seconds =
                                remaining_deadline_seconds(filesystem_limits.deadline),
                            "compacting authenticated name pages"
                        );
                    },
                )
                .map_err(anyhow::Error::new)
                .context("failed to stream compacted name-page base")?
            };
            tracing::info!(
                phase = "streaming-base",
                previous_generation,
                generation,
                records_written = base.record_count,
                pages_written = base.page_count,
                bytes_written = base
                    .page_count
                    .saturating_mul(hns_store::NAME_PAGE_BYTES as u64),
                elapsed_seconds = start.elapsed().as_secs(),
                remaining_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
                "completed compacted name-page base stream"
            );
            let mut manifest = base.manifest;
            let mut records_written = base.record_count;
            let mut pages_written = base.page_count;

            let paths = BTreeMap::from([(0, file_path.clone())]);
            let locator = base.root_address.map_or_else(
                || {
                    NamePageRootLocator::new(
                        generation,
                        hns_store::NamePageAddress::new(0, 0, 0).expect("zero page address fits"),
                    )
                },
                |address| NamePageRootLocator::new(generation, address),
            );
            let output_reader = NamePageTreeReader::open_segments(&paths, self.state.root, locator)
                .map_err(|error| anyhow::anyhow!("failed to open compacted name pages: {error}"))?;
            tracing::info!(
                phase = "indexing-base",
                output_generation = generation,
                base_records = records_written,
                base_pages = pages_written,
                resulting_known_addresses = 0_u64,
                elapsed_seconds = start.elapsed().as_secs(),
                remaining_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
                "discovering compacted name-page base addresses"
            );
            output_reader
                .discover_tree_addresses_bounded(
                    self.state.root,
                    production_name_page_traversal_limits(filesystem_limits.deadline),
                )
                .map_err(anyhow::Error::new)
                .context("failed to index compacted name-page base")?;
            let mut known = output_reader
                .into_known_addresses()
                .map_err(anyhow::Error::new)
                .context("failed to collect compacted name-page addresses")?;
            tracing::info!(
                phase = "indexing-base",
                output_generation = generation,
                base_records = records_written,
                base_pages = pages_written,
                resulting_known_addresses = known.len(),
                elapsed_seconds = start.elapsed().as_secs(),
                remaining_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
                "completed compacted name-page base address indexing"
            );

            let (source_reader, legacy_fallback) =
                self.reader_for_roots(&snapshot, retained_roots.iter().copied(), true)?;
            let source_snapshot = if legacy_fallback {
                NamePageSnapshot::with_legacy_fallback(&snapshot, &source_reader)
            } else {
                NamePageSnapshot::new(&snapshot, &source_reader)
            };
            let retained_roots_to_stream = retained_roots
                .iter()
                .copied()
                .filter(|root| *root != TreeRoot::ZERO && *root != self.state.root)
                .collect::<Vec<_>>();
            let retained_roots_total = retained_roots_to_stream.len();
            for (index, root) in retained_roots_to_stream.iter().copied().enumerate() {
                let mut stream_limits =
                    production_name_page_stream_limits(filesystem_limits.deadline);
                stream_limits.max_records = stream_limits
                    .max_records
                    .checked_sub(records_written)
                    .ok_or(PageTreeError::ResourceLimit {
                        context: "name-page compacted records",
                        limit: MAX_NAME_PAGE_COMPACTION_RECORDS,
                        actual: records_written,
                    })?;
                stream_limits.max_pages = stream_limits
                    .max_pages
                    .checked_sub(pages_written)
                    .ok_or_else(|| PageTreeError::ResourceLimit {
                        context: "name-page compacted pages",
                        limit: MAX_NAME_PAGE_GENERATION_BYTES / hns_store::NAME_PAGE_BYTES as u64,
                        actual: pages_written,
                    })?;
                let records_before_delta = records_written;
                let pages_before_delta = pages_written;
                let bytes_before_delta = pages_before_delta
                    .saturating_mul(hns_store::NAME_PAGE_BYTES as u64);
                let retained_roots_completed = u64::try_from(index + 1)
                    .expect("retained root index fits u64");
                let delta = stream_name_page_tree_delta_with_limits_and_progress(
                    &source_snapshot,
                    root,
                    &mut appender,
                    &mut known,
                    stream_limits,
                    progress_interval,
                    move |progress| {
                        tracing::info!(
                            phase = "streaming-retained-roots",
                            retained_roots_completed,
                            retained_roots_total,
                            current_root = ?root,
                            records_completed = records_before_delta
                                .saturating_add(progress.records_completed),
                            pages_completed = pages_before_delta
                                .saturating_add(progress.pages_completed),
                            bytes_completed = bytes_before_delta
                                .saturating_add(progress.bytes_completed),
                            elapsed_seconds = start.elapsed().as_secs(),
                            remaining_deadline_seconds =
                                remaining_deadline_seconds(filesystem_limits.deadline),
                            "compacting retained name-page roots"
                        );
                    },
                )
                .map_err(anyhow::Error::new)
                .with_context(|| format!("failed to stream retained name root {root:?}"))?;
                manifest = delta.manifest;
                records_written = records_written
                    .checked_add(delta.record_count)
                    .ok_or_else(|| anyhow::anyhow!("compacted name record count overflow"))?;
                pages_written = pages_written
                    .checked_add(delta.page_count)
                    .ok_or_else(|| anyhow::anyhow!("compacted name page count overflow"))?;
            }

            let root_address =
                if self.state.root == TreeRoot::ZERO {
                    None
                } else {
                    Some(known.get(&self.state.root).copied().ok_or_else(|| {
                        anyhow::anyhow!("compacted committed root has no address")
                    })?)
                };
            let next = NamePageState {
                manifest,
                root: self.state.root,
                root_address,
                committed_height: self.state.committed_height,
                last_sealed_height: self.state.last_sealed_height,
            };
            let encoded_state = next
                .encode()
                .map_err(anyhow::Error::new)
                .context("failed to encode compacted name-page state")?;
            let published_root_count = retained_roots
                .iter()
                .filter(|root| **root != TreeRoot::ZERO)
                .count();
            tracing::info!(
                phase = "publishing",
                roots_published = published_root_count,
                records_written,
                pages_written,
                output_bytes = pages_written.saturating_mul(hns_store::NAME_PAGE_BYTES as u64),
                elapsed_seconds = start.elapsed().as_secs(),
                remaining_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
                "publishing compacted name-page generation"
            );
            preflight_name_page_publication(
                &old_records,
                published_root_count,
                encoded_state.len(),
            )?;
            ensure_name_page_filesystem_deadline(
                filesystem_limits,
                "name-page compaction publication",
            )?;
            ensure_name_page_output_capacity(
                &self.directory,
                0,
                "name-page compaction publication",
            )?;

            let mut batch = store.batch();
            for root in old_records.keys().copied() {
                batch.delete(ColumnFamily::Snapshots, &name_page_root_key(root))?;
            }
            let fallback_height = self.state.committed_height.unwrap_or(0);
            let mut published = BTreeMap::new();
            for root in retained_roots
                .iter()
                .copied()
                .filter(|root| *root != TreeRoot::ZERO)
            {
                let address = known.get(&root).copied().ok_or_else(|| {
                    anyhow::anyhow!("compacted retained root {root:?} has no address")
                })?;
                let record = NamePageRootRecord {
                    root,
                    locator: NamePageRootLocator::new(generation, address),
                    height: old_records
                        .get(&root)
                        .map(|record| record.height)
                        .unwrap_or(fallback_height)
                        .min(pin_heights.get(&root).copied().unwrap_or(fallback_height)),
                };
                batch.put(
                    ColumnFamily::Snapshots,
                    &name_page_root_key(root),
                    &record.encode(),
                )?;
                published.insert(root, address);
            }
            batch.put(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY, &encoded_state)?;
            commit_attempted = true;
            store.commit(batch)?;
            Ok((next, appender, records_written, pages_written, published))
        })();

        let (next, appender, records_written, pages_written, published) = match staged {
            Ok(staged) => staged,
            Err(error) if !commit_attempted => {
                remove_name_page_generation(
                    &self.directory,
                    generation,
                    production_name_page_compaction_cleanup_limits(),
                )
                .with_context(|| {
                    format!(
                        "failed to discard unpublished name-page generation {generation} after compaction failure: {error:#}"
                    )
                })?;

                if name_page_error_contains_deadline(&error) {
                    return Err(anyhow::Error::new(NamePageCompactionDeferred {
                        detail: format!("{error:#}"),
                    }));
                }

                return Err(error);
            }
            Err(error) => {
                self.fence_after_commit_attempt();
                return Err(error);
            }
        };
        drop(snapshot);

        self.appender.take();
        self.file_path = file_path;
        self.state = next;
        self.appender = Some(appender);
        tracing::info!(
            phase = "cleaning-old-generation",
            generation,
            previous_generation,
            elapsed_seconds = start.elapsed().as_secs(),
            remaining_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
            "cleaning old name-page generation after compacting"
        );
        remove_name_page_generations_except(&self.directory, generation, filesystem_limits)?;

        let bytes_after =
            name_page_generation_bytes(&self.directory, generation, filesystem_limits)?;
        self.committed_generation_bytes = bytes_after;
        self.generation_bytes = bytes_after;
        let report = NamePageCompactionReport {
            previous_generation,
            generation,
            retained_roots: published.len(),
            records_written,
            pages_written,
            bytes_before,
            bytes_after,
            reclaimed_bytes: bytes_before.saturating_sub(bytes_after),
        };
        tracing::info!(
            phase = "complete",
            previous_generation = report.previous_generation,
            generation = report.generation,
            retained_roots = report.retained_roots,
            records_written = report.records_written,
            pages_written = report.pages_written,
            bytes_before = report.bytes_before,
            bytes_after = report.bytes_after,
            reclaimed_bytes = report.reclaimed_bytes,
            elapsed_seconds = start.elapsed().as_secs(),
            remaining_deadline_seconds = remaining_deadline_seconds(filesystem_limits.deadline),
            "completed pruned name-page generation compaction"
        );
        Ok(report)
    }

    fn preflight_append_pages(&self, page_count: usize) -> Result<u64> {
        let additional = u64::try_from(page_count)
            .ok()
            .and_then(|pages| pages.checked_mul(hns_store::NAME_PAGE_BYTES as u64))
            .ok_or_else(|| anyhow::anyhow!("name-page append byte count overflow"))?;
        let actual = self
            .generation_bytes
            .checked_add(additional)
            .ok_or_else(|| anyhow::anyhow!("name-page generation byte count overflow"))?;
        if actual > MAX_NAME_PAGE_GENERATION_BYTES {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page generation bytes",
                limit: MAX_NAME_PAGE_GENERATION_BYTES,
                actual,
            }
            .into());
        }
        ensure_name_page_output_capacity(&self.directory, additional, "name-page append output")?;
        Ok(actual)
    }

    fn prepare_root<B: NamePagePublicationBatch, S: ReadSnapshot>(
        &mut self,
        snapshot: &S,
        batch: &mut B,
        reader: &NamePageTreeReader,
        staged_nodes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
        snapshot_pins: &[NameTreeSnapshotPin],
        target: NamePageRootTarget,
    ) -> Result<NamePageState> {
        self.ensure_open()?;
        let NamePageRootTarget { root, height } = target;
        let mut records = BTreeMap::new();
        for (key, value) in staged_nodes {
            let raw_root: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!(
                    "deferred name-page node key has {} bytes; expected 32",
                    key.len()
                )
            })?;
            let value = value.ok_or_else(|| {
                anyhow::anyhow!("deferred name-page transaction deletes an immutable node")
            })?;
            records.insert(TreeRoot::new(raw_root), value);
        }
        // A multi-block activation can cross several name-tree intervals.
        // Retain records for the final root and every intermediate root pinned
        // for rollback; unrelated intermediate working roots need no pages.
        if !records.contains_key(&root)
            && !snapshot_pins
                .iter()
                .any(|pin| records.contains_key(&pin.root))
        {
            records.clear();
        }

        let mut next = self.state.clone();
        if records.is_empty() {
            if root == self.state.root {
                if let Some(height) = height {
                    if self.prepare_segment_seal(&mut next, height)? {
                        batch.put(
                            ColumnFamily::Snapshots,
                            NAME_PAGE_STATE_KEY,
                            &next.encode()?,
                        )?;
                    }
                }
                return Ok(next);
            }
            if root == TreeRoot::ZERO {
                next.root = root;
                next.root_address = None;
                next.committed_height = height;
            } else {
                let height = height.ok_or_else(|| {
                    anyhow::anyhow!("restored non-empty name-page root has no active height")
                })?;
                if let Some(record) = load_name_page_root_record(snapshot, root)? {
                    next.root = root;
                    next.root_address = Some(record.locator.page_address());
                    next.committed_height = Some(height);
                } else {
                    let legacy_records =
                        load_persisted_name_tree_records(snapshot, root).map_err(|error| {
                            anyhow::anyhow!(
                                "restored root has neither a page locator nor complete legacy records: {error}"
                            )
                        })?;
                    batch.charge_name_page_packing(&legacy_records)?;
                    let next_page = self
                        .appender
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("name-page appender is unavailable"))?;
                    let packed = pack_name_page_records(
                        self.state.manifest.generation,
                        self.state.manifest.active_segment,
                        next_page.next_page(),
                        &legacy_records,
                        &HashMap::new(),
                    )
                    .map_err(|error| {
                        anyhow::anyhow!("failed to pack restored legacy root: {error}")
                    })?;
                    let address = packed.address(root).ok_or_else(|| {
                        anyhow::anyhow!("restored legacy pack did not assign its root")
                    })?;
                    let record_height = minimum_name_page_root_height(
                        snapshot,
                        self.network,
                        root,
                        height,
                        snapshot_pins,
                    )?;
                    let page_count = packed.page_count();
                    let next_generation_bytes = self.preflight_append_pages(page_count)?;
                    batch.charge_name_page_output(page_count)?;
                    let appender = self
                        .appender
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("name-page appender is unavailable"))?;
                    let manifest = packed
                        .append_with_reserve(appender, MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES)
                        .map_err(|error| {
                            anyhow::anyhow!("failed to append restored legacy root: {error}")
                        })?;
                    batch.record_name_page_append(page_count);
                    self.generation_bytes = next_generation_bytes;
                    next = NamePageState {
                        manifest,
                        root,
                        root_address: Some(address),
                        committed_height: Some(height),
                        last_sealed_height: self.state.last_sealed_height,
                    };
                    let record = NamePageRootRecord {
                        root,
                        locator: NamePageRootLocator::new(next.manifest.generation, address),
                        height: record_height,
                    };
                    batch.put(
                        ColumnFamily::Snapshots,
                        &name_page_root_key(root),
                        &record.encode(),
                    )?;
                }
            }
        } else {
            let height = height.ok_or_else(|| {
                anyhow::anyhow!("non-empty name-page root has no committed height")
            })?;
            batch.charge_name_page_packing(&records)?;
            let known = reader.known_addresses().map_err(|error| {
                anyhow::anyhow!("failed to collect traversal page addresses: {error}")
            })?;
            let next_page = self
                .appender
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("name-page appender is unavailable"))?;
            let packed = pack_name_page_records(
                self.state.manifest.generation,
                self.state.manifest.active_segment,
                next_page.next_page(),
                &records,
                &known,
            )
            .map_err(|error| anyhow::anyhow!("failed to pack name-page update: {error}"))?;
            let address = packed
                .address(root)
                .or_else(|| known.get(&root).copied())
                .ok_or_else(|| {
                    anyhow::anyhow!("name-page update did not resolve its resulting root")
                })?;
            let record_height =
                minimum_name_page_root_height(snapshot, self.network, root, height, snapshot_pins)?;
            let mut published_pins = BTreeMap::<TreeRoot, Height>::new();
            for pin in snapshot_pins {
                if pin.root != TreeRoot::ZERO && pin.root != root {
                    published_pins
                        .entry(pin.root)
                        .and_modify(|height| *height = (*height).min(pin.height))
                        .or_insert(pin.height);
                }
            }
            for (pin_root, pin_height) in published_pins {
                if load_name_page_root_record(snapshot, pin_root)?.is_some() {
                    continue;
                }
                let pin_address = packed
                    .address(pin_root)
                    .or_else(|| known.get(&pin_root).copied())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "snapshot-pinned name root {pin_root:?} has no page address"
                        )
                    })?;
                let record = NamePageRootRecord {
                    root: pin_root,
                    locator: NamePageRootLocator::new(self.state.manifest.generation, pin_address),
                    height: pin_height,
                };
                batch.put(
                    ColumnFamily::Snapshots,
                    &name_page_root_key(pin_root),
                    &record.encode(),
                )?;
            }
            let page_count = packed.page_count();
            let next_generation_bytes = self.preflight_append_pages(page_count)?;
            batch.charge_name_page_output(page_count)?;
            let appender = self
                .appender
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("name-page appender is unavailable"))?;
            let manifest = packed
                .append_with_reserve(appender, MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES)
                .map_err(|error| anyhow::anyhow!("failed to append name-page update: {error}"))?;
            batch.record_name_page_append(page_count);
            self.generation_bytes = next_generation_bytes;
            next = NamePageState {
                manifest,
                root,
                root_address: Some(address),
                committed_height: Some(height),
                last_sealed_height: self.state.last_sealed_height,
            };
            let record = NamePageRootRecord {
                root,
                locator: NamePageRootLocator::new(next.manifest.generation, address),
                height: record_height,
            };
            batch.put(
                ColumnFamily::Snapshots,
                &name_page_root_key(root),
                &record.encode(),
            )?;
        }
        if let Some(height) = height {
            self.prepare_segment_seal(&mut next, height)?;
        }
        batch.put(
            ColumnFamily::Snapshots,
            NAME_PAGE_STATE_KEY,
            &next.encode()?,
        )?;
        Ok(next)
    }

    fn prepare_segment_seal(&mut self, next: &mut NamePageState, height: Height) -> Result<bool> {
        let seal_height = height - (height % NAME_PAGE_SEGMENT_BLOCKS);
        if seal_height == 0
            || next
                .last_sealed_height
                .is_some_and(|sealed| sealed >= seal_height)
        {
            return Ok(false);
        }
        let next_segment = next
            .manifest
            .active_segment
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("name-page segment number exhausted"))?;
        let file_path =
            name_page_file_path(&self.directory, next.manifest.generation, next_segment);
        ensure_name_page_output_capacity(&self.directory, 0, "name-page segment seal")?;
        let mut appender =
            NamePageAppender::create_new(&file_path, next.manifest.generation, next_segment)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to create sealed successor {}: {error}",
                        file_path.display()
                    )
                })?;
        let manifest = appender
            .sync_data()
            .map_err(|error| anyhow::anyhow!("failed to sync sealed successor: {error}"))?;
        sync_directory(&self.directory)?;
        self.appender.take();
        self.file_path = file_path;
        self.appender = Some(appender);
        next.manifest = manifest;
        next.last_sealed_height = Some(seal_height);
        Ok(true)
    }

    fn commit_prepared(&mut self, prepared: NamePageState) {
        self.state = prepared;
        self.committed_generation_bytes = self.generation_bytes;
    }

    fn rollback_uncommitted_tail(&mut self) -> Result<()> {
        self.ensure_open()?;
        self.appender.take();
        let rollback: Result<()> = (|| {
            remove_unpublished_name_page_segments(
                &self.directory,
                self.state.manifest.generation,
                self.state.manifest.active_segment,
                production_name_page_filesystem_limits(),
            )?;
            self.file_path = name_page_file_path(
                &self.directory,
                self.state.manifest.generation,
                self.state.manifest.active_segment,
            );
            truncate_name_pages_to_committed_tail(
                &self.file_path,
                self.state.manifest.durable_bytes,
            )
            .map_err(|error| anyhow::anyhow!("failed to roll back name-page tail: {error}"))?;
            self.appender = Some(
                NamePageAppender::open_at_committed_tail(&self.file_path, self.state.manifest)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to reopen name-page appender: {error}")
                    })?,
            );
            self.generation_bytes = self.committed_generation_bytes;
            Ok(())
        })();
        if let Err(error) = rollback {
            // A failed truncate/reopen means this process cannot prove which
            // page bytes remain usable. Fence before propagating so the outer
            // NodeService error path revokes authority instead of treating a
            // failed cleanup as an ordinary rejected mutation.
            self.fence_after_commit_attempt();
            return Err(error
                .context("failed to prove name-page rollback; storage is fenced until restart"));
        }
        Ok(())
    }
}

fn staged_name_tree_snapshot_pins(
    snapshot: &impl ReadSnapshot,
    heights: impl IntoIterator<Item = Height>,
) -> Result<Vec<NameTreeSnapshotPin>> {
    let mut pins = Vec::new();
    let mut seen = BTreeSet::new();
    for height in heights {
        if !seen.insert(height) {
            continue;
        }
        let key = name_tree_snapshot_pin_key(height);
        let Some(raw) = snapshot
            .get(ColumnFamily::Snapshots, &key)
            .context("failed to read staged name-tree snapshot pin")?
        else {
            continue;
        };
        let pin = NameTreeSnapshotPin::decode(&raw)
            .map_err(|error| anyhow::anyhow!("failed to decode staged name-tree pin: {error}"))?;
        if pin.height != height || key != name_tree_snapshot_pin_key(pin.height) {
            anyhow::bail!(
                "staged name-tree pin at height {} has a mismatched key",
                pin.height
            );
        }
        pins.push(pin);
    }
    pins.sort_unstable_by_key(|pin| pin.height);
    Ok(pins)
}

fn name_page_file_path(directory: &std::path::Path, generation: u64, segment: u32) -> PathBuf {
    directory.join(format!("name-g{generation:016x}-s{segment:08x}.pages"))
}

fn parse_name_page_file_name(name: &str) -> Option<(u64, u32)> {
    let raw = name.strip_prefix("name-g")?.strip_suffix(".pages")?;
    let (generation, segment) = raw.split_once("-s")?;
    Some((
        u64::from_str_radix(generation, 16).ok()?,
        u32::from_str_radix(segment, 16).ok()?,
    ))
}

fn name_page_segment_paths(
    directory: &std::path::Path,
    generation: u64,
    active_segment: u32,
    limits: NamePageFilesystemLimits,
) -> Result<BTreeMap<u32, PathBuf>> {
    validate_name_page_active_segment(active_segment, limits)?;
    ensure_name_page_filesystem_deadline(limits, "name-page segment validation")?;
    let mut paths = BTreeMap::new();
    for segment in 0..=active_segment {
        ensure_name_page_filesystem_deadline(limits, "name-page segment validation")?;
        let path = name_page_file_path(directory, generation, segment);
        if !path.is_file() {
            anyhow::bail!("name-page segment {} is missing", path.display());
        }
        paths.insert(segment, path);
    }
    Ok(paths)
}

fn validate_name_page_segment_set(
    directory: &std::path::Path,
    generation: u64,
    active_segment: u32,
    limits: NamePageFilesystemLimits,
) -> Result<()> {
    for (segment, path) in name_page_segment_paths(directory, generation, active_segment, limits)? {
        ensure_name_page_filesystem_deadline(limits, "name-page segment validation")?;
        if segment == active_segment {
            continue;
        }
        let bytes = std::fs::metadata(&path)
            .with_context(|| format!("failed to inspect sealed segment {}", path.display()))?
            .len();
        if !bytes.is_multiple_of(hns_store::NAME_PAGE_BYTES as u64) {
            anyhow::bail!(
                "sealed name-page segment {} has a non-page-aligned length",
                path.display()
            );
        }
    }
    Ok(())
}

fn remove_unpublished_name_page_segments(
    directory: &std::path::Path,
    generation: u64,
    active_segment: u32,
    limits: NamePageFilesystemLimits,
) -> Result<()> {
    validate_name_page_active_segment(active_segment, limits)?;
    let mut removed = false;
    let mut entries = 0u64;
    let mut discard = Vec::new();
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("failed to scan {}", directory.display()))?
    {
        ensure_name_page_filesystem_deadline(limits, "name-page recovery directory scan")?;
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("name-page directory entry count overflow"))?;
        if entries > limits.max_directory_entries {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page recovery directory entries",
                limit: limits.max_directory_entries,
                actual: entries,
            }
            .into());
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((candidate_generation, segment)) = parse_name_page_file_name(&name) else {
            continue;
        };
        if candidate_generation != generation || segment > active_segment {
            discard.push(entry.path());
        }
    }
    for path in discard {
        ensure_name_page_filesystem_deadline(limits, "name-page recovery cleanup")?;
        std::fs::remove_file(&path).with_context(|| {
            format!(
                "failed to discard non-authoritative name-page segment {}",
                path.display()
            )
        })?;
        removed = true;
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

fn remove_name_page_generation(
    directory: &std::path::Path,
    generation: u64,
    limits: NamePageFilesystemLimits,
) -> Result<()> {
    let mut removed = false;
    let mut entries = 0u64;
    let mut discard = Vec::new();
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("failed to scan {}", directory.display()))?
    {
        ensure_name_page_filesystem_deadline(limits, "name-page generation directory scan")?;
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("name-page directory entry count overflow"))?;
        if entries > limits.max_directory_entries {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page generation directory entries",
                limit: limits.max_directory_entries,
                actual: entries,
            }
            .into());
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((candidate_generation, _)) = parse_name_page_file_name(&name) else {
            continue;
        };
        if candidate_generation == generation {
            discard.push(entry.path());
        }
    }
    for path in discard {
        ensure_name_page_filesystem_deadline(limits, "name-page generation cleanup")?;
        std::fs::remove_file(&path).with_context(|| {
            format!(
                "failed to discard name-page generation file {}",
                path.display()
            )
        })?;
        removed = true;
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

fn remove_name_page_generations_except(
    directory: &std::path::Path,
    generation: u64,
    limits: NamePageFilesystemLimits,
) -> Result<()> {
    let mut removed = false;
    let mut entries = 0u64;
    let mut discard = Vec::new();
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("failed to scan {}", directory.display()))?
    {
        ensure_name_page_filesystem_deadline(limits, "name-page generation directory scan")?;
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("name-page directory entry count overflow"))?;
        if entries > limits.max_directory_entries {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page generation directory entries",
                limit: limits.max_directory_entries,
                actual: entries,
            }
            .into());
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((candidate_generation, _)) = parse_name_page_file_name(&name) else {
            continue;
        };
        if candidate_generation != generation {
            discard.push(entry.path());
        }
    }
    for path in discard {
        ensure_name_page_filesystem_deadline(limits, "name-page generation cleanup")?;
        std::fs::remove_file(&path).with_context(|| {
            format!(
                "failed to discard superseded name-page generation file {}",
                path.display()
            )
        })?;
        removed = true;
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

fn name_page_generation_bytes(
    directory: &std::path::Path,
    generation: u64,
    limits: NamePageFilesystemLimits,
) -> Result<u64> {
    let mut bytes = 0u64;
    let mut entries = 0u64;
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("failed to scan {}", directory.display()))?
    {
        ensure_name_page_filesystem_deadline(limits, "name-page generation byte scan")?;
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("name-page directory entry count overflow"))?;
        if entries > limits.max_directory_entries {
            return Err(PageTreeError::ResourceLimit {
                context: "name-page generation byte-scan entries",
                limit: limits.max_directory_entries,
                actual: entries,
            }
            .into());
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((candidate_generation, _)) = parse_name_page_file_name(&name) else {
            continue;
        };
        if candidate_generation == generation {
            bytes = bytes
                .checked_add(entry.metadata()?.len())
                .ok_or_else(|| anyhow::anyhow!("name-page byte count overflow"))?;
            if bytes > limits.max_generation_bytes {
                return Err(PageTreeError::ResourceLimit {
                    context: "name-page generation bytes",
                    limit: limits.max_generation_bytes,
                    actual: bytes,
                }
                .into());
            }
        }
    }
    Ok(bytes)
}

fn sync_directory(directory: &std::path::Path) -> Result<()> {
    std::fs::File::open(directory)
        .with_context(|| format!("failed to open directory {}", directory.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", directory.display()))
}

fn load_name_page_root_record(
    snapshot: &impl ReadSnapshot,
    root: TreeRoot,
) -> Result<Option<NamePageRootRecord>> {
    snapshot
        .get(ColumnFamily::Snapshots, &name_page_root_key(root))?
        .map(|raw| NamePageRootRecord::decode(&raw).map_err(anyhow::Error::from))
        .transpose()
}

fn validate_reorg_counts(request: &NodeReorg, limits: NodeReorgLimits) -> Result<()> {
    if request.disconnect.len() > limits.maximum_disconnect {
        anyhow::bail!(
            "reorganization disconnect count {} exceeds production limit {}",
            request.disconnect.len(),
            limits.maximum_disconnect
        );
    }
    if request.connect.len() > limits.maximum_connect {
        anyhow::bail!(
            "reorganization connect count {} exceeds production limit {}",
            request.connect.len(),
            limits.maximum_connect
        );
    }
    Ok(())
}

fn add_reorg_resource(
    current: u64,
    additional: u64,
    limit: u64,
    context: &'static str,
) -> Result<u64> {
    let actual = current.saturating_add(additional);
    if actual > limit {
        anyhow::bail!("{context} {actual} exceeds production limit {limit}");
    }
    Ok(actual)
}

fn validate_reorg_connect_body_budget(request: &NodeReorg, limits: NodeReorgLimits) -> Result<u64> {
    validate_reorg_counts(request, limits)?;
    let mut body_bytes = 0u64;
    for connect in &request.connect {
        body_bytes = add_reorg_resource(
            body_bytes,
            u64::try_from(connect.block.encode().len()).unwrap_or(u64::MAX),
            limits.maximum_body_bytes,
            "reorganization encoded body bytes",
        )?;
    }
    Ok(body_bytes)
}

fn preflight_reorg_reconciliation_budget(
    snapshot: &impl ReadSnapshot,
    request: &NodeReorg,
    limits: NodeReorgLimits,
) -> Result<u64> {
    let mut body_bytes = validate_reorg_connect_body_budget(request, limits)?;
    let mut transaction_count = request.connect.iter().try_fold(0u64, |count, connect| {
        add_reorg_resource(
            count,
            u64::try_from(connect.block.transactions.len()).unwrap_or(u64::MAX),
            MAX_REORG_RECONCILIATION_TRANSACTIONS,
            "reorganization reconciliation transactions",
        )
    })?;
    for disconnect in &request.disconnect {
        let encoded = snapshot
            .get(ColumnFamily::Blocks, disconnect.block_hash.as_bytes())
            .context("failed to read disconnect block during reconciliation preflight")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "disconnect block {} is unavailable for mempool reconciliation",
                    disconnect.block_hash.to_hex()
                )
            })?;
        body_bytes = add_reorg_resource(
            body_bytes,
            u64::try_from(encoded.len()).unwrap_or(u64::MAX),
            limits.maximum_body_bytes,
            "reorganization reconciliation body bytes",
        )?;
        let raw = RawBlockRecord::decode(&encoded).map_err(|error| {
            anyhow::anyhow!(
                "disconnect block record {} is corrupt during reconciliation preflight: {error}",
                disconnect.block_hash.to_hex()
            )
        })?;
        if raw.hash != disconnect.block_hash {
            anyhow::bail!(
                "disconnect block key {} disagrees with embedded hash {}",
                disconnect.block_hash.to_hex(),
                raw.hash.to_hex()
            );
        }
        let block = raw.decode_block().map_err(|error| {
            anyhow::anyhow!(
                "disconnect block {} is corrupt during reconciliation preflight: {error}",
                disconnect.block_hash.to_hex()
            )
        })?;
        transaction_count = add_reorg_resource(
            transaction_count,
            u64::try_from(block.transactions.len()).unwrap_or(u64::MAX),
            MAX_REORG_RECONCILIATION_TRANSACTIONS,
            "reorganization reconciliation transactions",
        )?;
    }
    Ok(body_bytes)
}

fn preflight_reorg_page_roots(
    snapshot: &impl ReadSnapshot,
    request: &NodeReorg,
    limits: NodeReorgLimits,
) -> Result<BTreeSet<TreeRoot>> {
    // Body and transaction materialization have an independent input budget.
    // Actual atomic write effects are metered at every WriteBatch mutation in
    // `apply_reorg_classified_with_limits`; no input-derived estimate is used
    // as a substitute for the generated state/index/page writes.
    preflight_reorg_reconciliation_budget(snapshot, request, limits)?;
    let mut roots = BTreeSet::new();
    for disconnect in &request.disconnect {
        let raw = snapshot
            .get(ColumnFamily::Undo, disconnect.block_hash.as_bytes())
            .context("failed to read block undo during reorganization preflight")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "undo is missing for requested disconnect {}",
                    disconnect.block_hash.to_hex()
                )
            })?;
        let undo = BlockUndo::decode(&raw).map_err(|error| {
            anyhow::anyhow!(
                "failed to decode disconnect undo {} during reorganization preflight: {error}",
                disconnect.block_hash.to_hex()
            )
        })?;
        if undo.block_hash != disconnect.block_hash || undo.height != disconnect.height {
            anyhow::bail!(
                "disconnect undo identity mismatch for {} at height {}",
                disconnect.block_hash.to_hex(),
                disconnect.height
            );
        }
        roots.extend([
            undo.previous_tree_root,
            undo.resulting_tree_root,
            undo.previous_committed_tree_root,
            undo.resulting_committed_tree_root,
        ]);
    }
    roots.remove(&TreeRoot::ZERO);
    Ok(roots)
}

fn required_name_page_rollback_roots(
    snapshot: &impl ReadSnapshot,
    disconnects: &[NodeBlockDisconnect],
) -> Result<BTreeSet<TreeRoot>> {
    let request = NodeReorg {
        disconnect: disconnects.to_vec(),
        connect: Vec::new(),
    };
    preflight_reorg_page_roots(snapshot, &request, NodeReorgLimits::PRODUCTION)
}

fn validate_name_page_root_record(
    snapshot: &impl ReadSnapshot,
    state: &NamePageState,
) -> Result<()> {
    match (state.root, state.root_locator(), state.committed_height) {
        (TreeRoot::ZERO, None, _) => Ok(()),
        (root, Some(locator), Some(height)) => {
            let record = load_name_page_root_record(snapshot, root)?.ok_or_else(|| {
                anyhow::anyhow!("current name-page root has no durable locator record")
            })?;
            if record.root != root || record.locator != locator || record.height > height {
                anyhow::bail!("current name-page root locator record is inconsistent");
            }
            Ok(())
        }
        _ => anyhow::bail!("current name-page state is incomplete"),
    }
}

fn production_fence_from_store_error(
    kind: ProductionSafetyFenceKind,
    error: &StoreError,
) -> Option<ProductionSafetyFence> {
    let (context, limit, actual) = match error {
        StoreError::LimitExceeded {
            context,
            limit,
            actual,
        } => (*context, *limit, *actual),
        StoreError::InsufficientSpace {
            context,
            available,
            required,
            ..
        } => (*context, *required, *available),
        StoreError::DeadlineExceeded { context } => (*context, 1, 2),
        _ => return None,
    };
    Some(ProductionSafetyFence {
        version: PRODUCTION_SAFETY_FENCE_VERSION,
        kind,
        context: context.to_owned(),
        limit,
        actual,
        root: None,
        candidate: None,
        detail: error.to_string(),
    })
}

fn production_fence_from_name_page_error(
    kind: ProductionSafetyFenceKind,
    error: &anyhow::Error,
) -> Option<ProductionSafetyFence> {
    for cause in error.chain() {
        if let Some(store) = cause.downcast_ref::<StoreError>() {
            if let Some(fence) = production_fence_from_store_error(kind, store) {
                return Some(fence);
            }
        }
        if let Some(state) = cause.downcast_ref::<StateError>() {
            let resource = match state {
                StateError::ResourceLimit {
                    context,
                    limit,
                    actual,
                } => Some((*context, *limit, *actual)),
                StateError::DeadlineExceeded { context } => Some((*context, 1, 2)),
                _ => None,
            };
            if let Some((context, limit, actual)) = resource {
                return Some(ProductionSafetyFence {
                    version: PRODUCTION_SAFETY_FENCE_VERSION,
                    kind,
                    context: context.to_owned(),
                    limit,
                    actual,
                    root: None,
                    candidate: None,
                    detail: state.to_string(),
                });
            }
        }
        let Some(page) = cause.downcast_ref::<PageTreeError>() else {
            continue;
        };
        let (context, limit, actual) = match page {
            PageTreeError::Page(NamePageError::InsufficientCapacity {
                available,
                required,
                ..
            }) => (
                "name-page generation append capacity",
                *required,
                *available,
            ),
            PageTreeError::ResourceLimit {
                context,
                limit,
                actual,
            } => (*context, *limit, *actual),
            PageTreeError::InsufficientSpace {
                context,
                available,
                required,
                reserve,
            } => (
                *context,
                required.checked_add(*reserve).unwrap_or(u64::MAX),
                *available,
            ),
            PageTreeError::DeadlineExceeded { context } => (*context, 1, 2),
            _ => continue,
        };
        return Some(ProductionSafetyFence {
            version: PRODUCTION_SAFETY_FENCE_VERSION,
            kind,
            context: context.to_owned(),
            limit,
            actual,
            root: None,
            candidate: None,
            detail: page.to_string(),
        });
    }
    None
}

fn load_production_safety_fence(
    store: &StoreHandle,
) -> std::result::Result<Option<ProductionSafetyFenceEvidence>, ChainError> {
    let snapshot = store.snapshot()?;
    snapshot
        .get(ColumnFamily::Snapshots, PRODUCTION_SAFETY_FENCE_KEY)?
        .map(|encoded| {
            let fence = ProductionSafetyFence::decode(&encoded)
                .map_err(|error| ChainError::Store(error.to_string()))?;
            let digest = blake2b_256(&encoded);
            Ok(ProductionSafetyFenceEvidence {
                fence,
                encoded,
                digest,
            })
        })
        .transpose()
}

pub fn inspect_production_safety_fence(
    store: &StoreHandle,
) -> Result<Option<ProductionSafetyFenceEvidence>> {
    load_production_safety_fence(store)
        .map_err(|error| anyhow::anyhow!("failed to inspect production safety fence: {error}"))
}

pub fn clear_production_safety_fence_validated(
    store: &StoreHandle,
    network: Network,
    request: ProductionSafetyFenceClearRequest,
) -> Result<ProductionSafetyFenceEvidence> {
    let ProductionSafetyFenceClearRequest {
        expected_digest,
        acknowledgement,
        name_page_directory,
    } = request;
    match acknowledgement {
        ProductionSafetyFenceClearAcknowledgement::OfflineRecoveryCompletedAndVerified => {}
    }
    store
        .ensure_operational()
        .context("cannot clear a safety fence while store recovery is required")?;
    validate_existing_store_identity(store, network)?;
    let evidence = inspect_production_safety_fence(store)?
        .ok_or_else(|| anyhow::anyhow!("no production safety fence is present"))?;
    if evidence.digest != expected_digest {
        anyhow::bail!(
            "production safety-fence digest changed; expected {}, found {}",
            hex_encode(&expected_digest),
            hex_encode(&evidence.digest)
        );
    }

    match evidence.fence.kind {
        ProductionSafetyFenceKind::LiveHeaderOperation => {
            anyhow::bail!(
                "generic live-header fence context `{}` has no safe automatic recovery proof; perform typed offline recovery before clearing",
                evidence.fence.context
            );
        }
        ProductionSafetyFenceKind::LiveHeaderReorganization => {
            let candidate = evidence.fence.candidate.ok_or_else(|| {
                anyhow::anyhow!(
                    "reorganization safety fence is missing its typed candidate identity"
                )
            })?;
            let index = StoredHeaderIndex::new(store.clone())
                .map_err(|error| anyhow::anyhow!("header recovery validation failed: {error}"))?;
            match index.header(&candidate)? {
                None => {
                    // Offline recovery removed the exact fenced candidate.
                }
                Some(record) if record.status.failed => {
                    // Offline recovery durably invalidated the exact candidate.
                }
                Some(_) => {
                    let maximum = usize::try_from(evidence.fence.limit).unwrap_or(usize::MAX);
                    index
                        .plan_reorg_bounded(
                            &candidate,
                            ReorgPlanLimits {
                                maximum_disconnect: maximum,
                                maximum_connect: maximum,
                            },
                        )
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "fenced reorganization candidate remains unresolved: {error}"
                            )
                        })?;
                }
            }
        }
        ProductionSafetyFenceKind::FailedBranchDescendants => {
            let root = evidence.fence.root.ok_or_else(|| {
                anyhow::anyhow!("failed-branch safety fence is missing its invalid root")
            })?;
            let index = StoredHeaderIndex::new(store.clone())
                .map_err(|error| anyhow::anyhow!("header recovery validation failed: {error}"))?;
            let record = index.header(&root)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "failed-branch root {} is missing; explicit header recovery is required",
                    root.to_hex()
                )
            })?;
            if !record.status.failed {
                anyhow::bail!(
                    "failed-branch root {} is not durably failed; refusing to clear fence",
                    root.to_hex()
                );
            }
            // StoredHeaderIndex construction validates that every descendant
            // of a failed ancestor is also failed, so the root status plus a
            // successful strict reconstruction proves the whole condition.
        }
        ProductionSafetyFenceKind::NamePageValidation
        | ProductionSafetyFenceKind::NamePageCompaction => {
            let directory = name_page_directory.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "name-page safety-fence recovery requires the canonical name-page directory"
                )
            })?;
            let pages = NamePageStorage::open_or_bootstrap(directory.to_path_buf(), store, network)
                .context("failed to reopen name pages for safety-fence validation")?;
            let snapshot = store.snapshot()?;
            let required_roots = [
                load_stored_name_tree_root(&snapshot).map_err(|error| {
                    anyhow::anyhow!("failed to load working name root: {error}")
                })?,
                load_stored_name_tree_commit_root(&snapshot).map_err(|error| {
                    anyhow::anyhow!("failed to load committed name root: {error}")
                })?,
            ];
            let (reader, _) = pages.reader_for_roots(&snapshot, required_roots, true)?;
            seed_startup_pin_page_roots(&snapshot, network, &reader)?;
            reader
                .validate_committed_pages_with_limits(production_name_page_validation_limits(
                    &snapshot, network,
                )?)
                .map_err(|error| {
                    anyhow::anyhow!("name-page safety-fence validation failed: {error}")
                })?;
        }
        ProductionSafetyFenceKind::PayloadSegmentCompaction => {
            let now = Instant::now();
            let scrub = store
                .scrub_segment_archive_bounded(SegmentArchiveScrubLimits {
                    max_segments: SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_SEGMENTS,
                    max_records: SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_RECORDS,
                    max_durable_bytes: SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_DURABLE_BYTES,
                    deadline: now
                        .checked_add(SEGMENT_ARCHIVE_SCRUB_DEFAULT_MAX_ELAPSED)
                        .unwrap_or(now),
                })
                .context(
                    "payload-segment fence requires a successful bounded authenticated scrub",
                )?;
            tracing::info!(
                block_segments = scrub.blocks.segments,
                block_records = scrub.blocks.records,
                block_bytes = scrub.blocks.durable_bytes,
                undo_segments = scrub.undo.segments,
                undo_records = scrub.undo.records,
                undo_bytes = scrub.undo.durable_bytes,
                "validated payload archive before clearing its production safety fence"
            );
        }
        ProductionSafetyFenceKind::Storage => {
            anyhow::bail!(
                "generic storage fence context `{}` has no operation-specific automatic recovery proof; perform typed offline recovery before clearing",
                evidence.fence.context
            );
        }
    }

    let current = inspect_production_safety_fence(store)?
        .ok_or_else(|| anyhow::anyhow!("production safety fence disappeared during validation"))?;
    if current.digest != expected_digest || current.encoded != evidence.encoded {
        anyhow::bail!("production safety fence changed during recovery validation");
    }
    let mut batch = store.batch();
    batch.delete(ColumnFamily::Snapshots, PRODUCTION_SAFETY_FENCE_KEY)?;
    store
        .commit(batch)
        .context("failed to durably clear production safety fence")?;
    Ok(evidence)
}

fn persist_production_safety_fence(
    store: &StoreHandle,
    fence: ProductionSafetyFence,
) -> std::result::Result<ProductionSafetyFenceEvidence, ChainError> {
    if let Some(existing) = load_production_safety_fence(store)? {
        return Ok(existing);
    }
    let encoded = fence
        .encode()
        .map_err(|error| ChainError::Store(error.to_string()))?;
    let digest = blake2b_256(&encoded);
    let mut batch = store.batch();
    batch.put(
        ColumnFamily::Snapshots,
        PRODUCTION_SAFETY_FENCE_KEY,
        &encoded,
    )?;
    store.commit(batch).map_err(ChainError::from)?;
    Ok(ProductionSafetyFenceEvidence {
        fence,
        encoded,
        digest,
    })
}

/// Cloneable access to the in-memory canonical header index.
///
/// Header synchronization already keeps this complete index beside the
/// durable header records. Sharing it lets RPC resolve one canonical height
/// in O(1) without taking the global node coordinator lock or scanning the
/// hash-keyed header column.
#[derive(Clone, Debug)]
pub struct SharedHeaderIndex {
    inner: Arc<RwLock<StoredHeaderIndex<StoreHandle>>>,
    safety_fence: Arc<Mutex<Option<ProductionSafetyFenceEvidence>>>,
}

impl SharedHeaderIndex {
    fn new(store: StoreHandle) -> std::result::Result<Self, ChainError> {
        let safety_fence = load_production_safety_fence(&store)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(StoredHeaderIndex::new(store)?)),
            safety_fence: Arc::new(Mutex::new(safety_fence)),
        })
    }

    #[cfg(test)]
    fn new_for_test_fixtures(store: StoreHandle) -> std::result::Result<Self, ChainError> {
        let safety_fence = load_production_safety_fence(&store)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(StoredHeaderIndex::new_for_test_fixtures(
                store,
            )?)),
            safety_fence: Arc::new(Mutex::new(safety_fence)),
        })
    }

    fn record_resource_fence(
        &self,
        index: &StoredHeaderIndex<StoreHandle>,
        error: &ChainError,
        kind: ProductionSafetyFenceKind,
        root: Option<BlockHash>,
        candidate: Option<BlockHash>,
    ) -> std::result::Result<(), ChainError> {
        let (context, limit, actual) = match error {
            ChainError::ReorgPlanLimit {
                phase,
                limit,
                actual,
            } => (*phase, *limit, *actual),
            ChainError::LiveWorkLimit {
                context,
                limit,
                actual,
            } => (*context, *limit, *actual),
            ChainError::LiveWorkDeadline { context } => (*context, 1, 2),
            _ => return Ok(()),
        };
        let mut detail =
            format!("bounded live header operation requires offline recovery: {error}");
        if detail.len() > MAX_PRODUCTION_SAFETY_DETAIL_BYTES {
            let mut end = MAX_PRODUCTION_SAFETY_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        self.persist_first_cause(
            index.store(),
            ProductionSafetyFence {
                version: PRODUCTION_SAFETY_FENCE_VERSION,
                kind,
                context: context.to_owned(),
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
                actual: u64::try_from(actual).unwrap_or(u64::MAX),
                root,
                candidate,
                detail,
            },
        )?;
        Ok(())
    }

    fn persist_first_cause(
        &self,
        store: &StoreHandle,
        fence: ProductionSafetyFence,
    ) -> std::result::Result<ProductionSafetyFenceEvidence, ChainError> {
        // Reader-side planners may fail concurrently. Cover the entire
        // durable load/check/put and in-memory publication so only the first
        // cause can ever establish the record and digest.
        let mut cached = self.safety_fence.lock().map_err(|_| {
            ChainError::Store("production safety-fence lock is poisoned".to_owned())
        })?;
        if let Some(existing) = cached.as_ref() {
            return Ok(existing.clone());
        }
        let evidence = persist_production_safety_fence(store, fence)?;
        *cached = Some(evidence.clone());
        Ok(evidence)
    }

    fn safety_fence_reason(&self) -> Option<String> {
        self.safety_fence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|evidence| evidence.fence.reason())
    }

    fn safety_fence_kind(&self) -> Option<ProductionSafetyFenceKind> {
        self.safety_fence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|evidence| evidence.fence.kind)
    }

    fn record_external_safety_fence(&self, fence: ProductionSafetyFence) -> Result<()> {
        let index = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("shared header-index lock is poisoned"))?;
        self.persist_first_cause(index.store(), fence)
            .map_err(|error| {
                anyhow::anyhow!("failed to persist production safety fence: {error}")
            })?;
        Ok(())
    }

    fn ensure_mutation_unfenced(&self) -> std::result::Result<(), ChainError> {
        if let Some(reason) = self.safety_fence_reason() {
            return Err(ChainError::Store(format!(
                "durable production safety fence blocks header mutation: {reason}"
            )));
        }
        Ok(())
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&StoredHeaderIndex<StoreHandle>) -> std::result::Result<T, ChainError>,
    ) -> std::result::Result<T, ChainError> {
        let index = self
            .inner
            .read()
            .map_err(|_| ChainError::Store("shared header-index lock is poisoned".to_owned()))?;
        operation(&index)
    }

    fn read_fenced<T>(
        &self,
        kind: ProductionSafetyFenceKind,
        root: Option<BlockHash>,
        candidate: Option<BlockHash>,
        operation: impl FnOnce(&StoredHeaderIndex<StoreHandle>) -> std::result::Result<T, ChainError>,
    ) -> std::result::Result<T, ChainError> {
        let index = self
            .inner
            .read()
            .map_err(|_| ChainError::Store("shared header-index lock is poisoned".to_owned()))?;
        let result = operation(&index);
        if let Err(error) = &result {
            self.record_resource_fence(&index, error, kind, root, candidate)?;
        }
        result
    }

    fn acquire_unfenced_write_after(
        &self,
        after_initial_check: impl FnOnce(),
    ) -> std::result::Result<
        std::sync::RwLockWriteGuard<'_, StoredHeaderIndex<StoreHandle>>,
        ChainError,
    > {
        // The first check is a cheap rejection path. The second is the
        // authoritative admission point: fence recorders retain an inner
        // read/write guard through durable and cached publication, so no new
        // fence can race after this writer owns the inner lock.
        self.ensure_mutation_unfenced()?;
        after_initial_check();
        let index = self
            .inner
            .write()
            .map_err(|_| ChainError::Store("shared header-index lock is poisoned".to_owned()))?;
        self.ensure_mutation_unfenced()?;
        Ok(index)
    }

    fn write_after_initial_check<T>(
        &self,
        after_initial_check: impl FnOnce(),
        operation: impl FnOnce(
            &mut StoredHeaderIndex<StoreHandle>,
        ) -> std::result::Result<T, ChainError>,
    ) -> std::result::Result<T, ChainError> {
        let mut index = self.acquire_unfenced_write_after(after_initial_check)?;
        operation(&mut index)
    }

    fn write<T>(
        &self,
        operation: impl FnOnce(
            &mut StoredHeaderIndex<StoreHandle>,
        ) -> std::result::Result<T, ChainError>,
    ) -> std::result::Result<T, ChainError> {
        self.write_after_initial_check(|| {}, operation)
    }

    fn write_fenced<T>(
        &self,
        kind: ProductionSafetyFenceKind,
        root: Option<BlockHash>,
        candidate: Option<BlockHash>,
        operation: impl FnOnce(
            &mut StoredHeaderIndex<StoreHandle>,
        ) -> std::result::Result<T, ChainError>,
    ) -> std::result::Result<T, ChainError> {
        self.write(|index| {
            let result = operation(index);
            if let Err(error) = &result {
                self.record_resource_fence(index, error, kind, root, candidate)?;
            }
            result
        })
    }

    fn write_exclusive<T>(
        &self,
        operation: impl FnOnce(&mut StoredHeaderIndex<StoreHandle>) -> Result<T>,
    ) -> Result<T> {
        let mut index = self
            .acquire_unfenced_write_after(|| {})
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        operation(&mut index)
    }

    fn validate_network_consensus(&self, network: Network) -> Result<()> {
        let maximum_time = current_unix_time()?.saturating_add(MAX_FUTURE_BLOCK_TIME);
        let index = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("shared header-index lock is poisoned"))?;
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(network));
        for record in index.records() {
            if !record.status.header_context_valid || !record.status.checkpoint_valid {
                anyhow::bail!(
                    "stored header {} lacks durable contextual-validation status",
                    record.hash.to_hex()
                );
            }
            let parent = if record.height == 0 {
                None
            } else {
                Some(index.header(&record.header.prev_block)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "stored header {} is missing parent {}",
                        record.hash.to_hex(),
                        record.header.prev_block.to_hex()
                    )
                })?)
            };
            let mut lookup = |hash: &BlockHash| {
                index
                    .header(hash)
                    .map_err(|error| anyhow::anyhow!("header ancestry lookup failed: {error}"))
            };
            let expected_bits = expected_bits_with_lookup(
                network,
                record.header.time,
                parent.as_ref(),
                &mut lookup,
            )
            .with_context(|| {
                format!(
                    "failed to derive difficulty for stored header {} at height {}",
                    record.hash.to_hex(),
                    record.height
                )
            })?;
            let median_time_past = parent
                .as_ref()
                .map(|parent| median_time_past_with_lookup(parent, &mut lookup))
                .transpose()
                .with_context(|| {
                    format!(
                        "failed to derive median time for stored header {} at height {}",
                        record.hash.to_hex(),
                        record.height
                    )
                })?;
            let params = network.params();
            let is_genesis = record.height == 0
                && record.header == params.genesis_header()
                && record.hash == params.genesis_hash;
            consensus
                .validate_header(
                    &record.header,
                    &HeaderValidationContext {
                        height: record.height,
                        previous: parent.as_ref().map(|parent| HeaderParent {
                            hash: parent.hash,
                            height: parent.height,
                            bits: parent.header.bits,
                            chainwork: parent.chainwork,
                        }),
                        enforce_checkpoints: true,
                        expected_bits: Some(expected_bits),
                        median_time_past,
                        maximum_time: Some(maximum_time),
                        require_pow: !is_genesis,
                    },
                )
                .map_err(|error| {
                    anyhow::anyhow!(
                        "stored header {} at height {} failed recovery consensus: {error}",
                        record.hash.to_hex(),
                        record.height
                    )
                })?;
            let proof = CompactTarget::from_bits(record.header.bits)
                .proof()
                .ok_or_else(|| anyhow::anyhow!("stored header has an invalid target"))?;
            let expected_work = parent
                .as_ref()
                .map(|parent| parent.chainwork)
                .unwrap_or(Uint256::ZERO)
                .checked_add(proof)
                .ok_or_else(|| anyhow::anyhow!("stored header chainwork overflow"))?;
            if record.chainwork != expected_work {
                anyhow::bail!(
                    "stored header {} has non-proof-derived chainwork",
                    record.hash.to_hex()
                );
            }
        }

        let params = network.params();
        match index.canonical_hash(0)? {
            Some(hash) if hash == params.genesis_hash => {}
            Some(hash) => anyhow::bail!(
                "canonical header root {} is not the configured {} genesis",
                hash.to_hex(),
                network
            ),
            None if index.best_tip()?.is_none() => {}
            None => anyhow::bail!("non-empty header index has no canonical genesis root"),
        }
        Ok(())
    }

    pub fn import_header(
        &self,
        request: HeaderImport,
    ) -> std::result::Result<HeaderRecord, ChainError> {
        let candidate = request.header.hash();
        self.write_fenced(
            ProductionSafetyFenceKind::LiveHeaderOperation,
            None,
            Some(candidate),
            |index| index.import_header(request),
        )
    }

    pub fn import_headers(
        &self,
        requests: Vec<HeaderImport>,
    ) -> std::result::Result<Vec<HeaderRecord>, ChainError> {
        let candidate = requests.last().map(|request| request.header.hash());
        self.write_fenced(
            ProductionSafetyFenceKind::LiveHeaderOperation,
            None,
            candidate,
            |index| index.import_headers(requests),
        )
    }

    pub fn load_record(
        &self,
        hash: &BlockHash,
    ) -> std::result::Result<Option<HeaderRecord>, ChainError> {
        self.read(|index| index.load_record(hash))
    }

    pub fn cache_record(&self, record: HeaderRecord) -> std::result::Result<(), ChainError> {
        let candidate = record.hash;
        self.write_fenced(
            ProductionSafetyFenceKind::LiveHeaderOperation,
            None,
            Some(candidate),
            |index| index.cache_record(record),
        )
    }

    fn prepare_cache_update(
        &self,
        records: &[HeaderRecord],
    ) -> std::result::Result<HeaderIndexCacheUpdate, ChainError> {
        self.read_fenced(
            ProductionSafetyFenceKind::LiveHeaderOperation,
            None,
            records.last().map(|record| record.hash),
            |index| index.prepare_cache_update(records),
        )
    }

    pub fn plan_failed_branch(
        &self,
        root: BlockHash,
    ) -> std::result::Result<FailedHeaderPlan, ChainError> {
        self.read_fenced(
            ProductionSafetyFenceKind::FailedBranchDescendants,
            Some(root),
            None,
            |index| index.plan_failed_branch(root),
        )
    }
}

impl HeaderIndex for SharedHeaderIndex {
    fn best_tip(&self) -> std::result::Result<Option<ChainTip>, ChainError> {
        self.read(HeaderIndex::best_tip)
    }

    fn header(&self, hash: &BlockHash) -> std::result::Result<Option<HeaderRecord>, ChainError> {
        self.read(|index| index.header(hash))
    }

    fn canonical_hash(&self, height: Height) -> std::result::Result<Option<BlockHash>, ChainError> {
        self.read(|index| index.canonical_hash(height))
    }

    fn plan_reorg(&self, candidate: &BlockHash) -> std::result::Result<ReorgPlan, ChainError> {
        self.read(|index| index.plan_reorg(candidate))
    }

    fn plan_reorg_between(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
    ) -> std::result::Result<ReorgPlan, ChainError> {
        self.read(|index| index.plan_reorg_between(current, candidate))
    }

    fn plan_reorg_bounded(
        &self,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
    ) -> std::result::Result<ReorgPlan, ChainError> {
        self.read_fenced(
            ProductionSafetyFenceKind::LiveHeaderReorganization,
            None,
            Some(*candidate),
            |index| index.plan_reorg_bounded(candidate, limits),
        )
    }

    fn plan_reorg_between_bounded(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
    ) -> std::result::Result<ReorgPlan, ChainError> {
        self.read_fenced(
            ProductionSafetyFenceKind::LiveHeaderReorganization,
            Some(*current),
            Some(*candidate),
            |index| index.plan_reorg_between_bounded(current, candidate, limits),
        )
    }
}

#[derive(Debug)]
pub struct NodeState {
    network: Network,
    undo_retention_policy: Option<UndoRetentionPolicy>,
    startup_lifecycle: Option<StartupLifecycle>,
    pub store: StoreHandle,
    pub chain: SharedHeaderIndex,
    pub blocks: StoredBlockIndex<StoreHandle>,
    pub state_engine: StoredStateEngine<StoreHandle>,
    pub mempool: MemoryMempool,
    name_pages: Option<NamePageStorage>,
    transaction_index: bool,
    wallet_index_profile: WalletIndexProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupIndexValidation {
    Strict,
    #[cfg(test)]
    TestFixtures,
}

impl NodeState {
    pub fn memory() -> Self {
        Self::memory_for_network(Network::Mainnet)
    }

    pub fn memory_for_network(network: Network) -> Self {
        Self::from_store_for_network(StoreHandle::memory(), network)
            .expect("memory node state initializes")
    }

    pub fn from_config(config: &NodeConfig) -> Result<Self> {
        if let Some(data_dir) = &config.data_dir {
            let marker = data_dir.join(STORAGE_MAINTENANCE_MARKER);
            if marker
                .try_exists()
                .with_context(|| format!("failed to inspect {}", marker.display()))?
            {
                anyhow::bail!(
                    "offline storage maintenance marker {} is present; remove it only after maintenance and verification complete",
                    marker.display()
                );
            }
        }
        let store = match &config.data_dir {
            Some(data_dir) => open_store(&StoreConfig {
                path: data_dir.join("chain"),
                backend: StoreBackend::RocksDb,
                durability: config.storage_durability,
            })
            .map_err(|error| anyhow::anyhow!("failed to open node store: {error}"))?,
            None => StoreHandle::memory(),
        };
        validate_existing_store_identity(&store, config.network)?;
        let migration_limits = NameTreeIntervalMigrationLimits::default();
        let migration_plan = plan_name_tree_interval_accumulator_migration_bounded(
            &store,
            config.network.params().names.tree_interval,
            migration_limits,
        )
        .map_err(|error| {
            anyhow::anyhow!("failed to preflight node state storage migration: {error}")
        })?;
        if let Some(plan) = migration_plan.as_ref() {
            for (context, bytes) in [
                ("height-index input", plan.height_index_bytes),
                ("undo input", plan.undo_input_bytes),
                ("legacy backup output", plan.backup_output_bytes),
                ("undo rewrite output", plan.rewrite_output_bytes),
                ("atomic publication", plan.publication_bytes),
                ("temporary migration storage", plan.required_temporary_bytes),
            ] {
                if bytes > MAX_NAME_PAGE_GENERATION_BYTES {
                    anyhow::bail!(
                        "{context} requires {bytes} bytes, exceeding the 150,000,000,000-byte production data ceiling; run qualified offline maintenance"
                    );
                }
            }
            if let Some(data_dir) = &config.data_dir {
                let chain_directory = data_dir.join("chain");
                let usage = filesystem_tree_usage_bounded(
                    data_dir,
                    FilesystemTreeUsageLimits {
                        max_apparent_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
                        max_allocated_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
                        deadline: migration_limits.deadline,
                        ..FilesystemTreeUsageLimits::default()
                    },
                )
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to measure bounded migration data-root usage {}: {error}",
                        data_dir.display()
                    )
                })?;
                let current_bytes = usage.apparent_bytes.max(usage.allocated_bytes);
                preflight_migration_data_ceiling(
                    current_bytes,
                    plan.required_temporary_bytes,
                )
                .with_context(|| {
                    format!(
                        "schema migration current data root ({current_bytes} bytes) plus temporary output ({} bytes) exceeds the exact production ceiling; run qualified offline maintenance",
                        plan.required_temporary_bytes
                    )
                })?;
                let available = filesystem_available_bytes(&chain_directory).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to inspect migration filesystem {}: {error}",
                        chain_directory.display()
                    )
                })?;
                let required = plan
                    .required_temporary_bytes
                    .checked_add(MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES)
                    .ok_or_else(|| {
                        anyhow::anyhow!("migration temporary storage requirement overflow")
                    })?;
                if available < required {
                    anyhow::bail!(
                        "schema migration requires {} temporary bytes plus {} reserve, but {} bytes are available; run qualified offline maintenance",
                        plan.required_temporary_bytes,
                        MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES,
                        available
                    );
                }
            }
        }
        if let Some(migration) = migrate_name_tree_interval_accumulator_bounded(
            &store,
            config.network.params().names.tree_interval,
            migration_limits,
        )
        .map_err(|error| anyhow::anyhow!("failed to migrate node state storage: {error}"))?
        {
            tracing::info!(
                active_heights = migration.active_heights,
                undos_rewritten = migration.undos_rewritten,
                legacy_undos_backed_up = migration.legacy_undos_backed_up,
                pending_names = migration.pending_names,
                tip_height = migration.tip_height,
                height_index_bytes = migration.height_index_bytes,
                undo_input_bytes = migration.undo_input_bytes,
                backup_output_bytes = migration.backup_output_bytes,
                rewrite_output_bytes = migration.rewrite_output_bytes,
                publication_bytes = migration.publication_bytes,
                required_temporary_bytes = migration.required_temporary_bytes,
                peak_pending_names = migration.peak_pending_names,
                peak_pending_name_bytes = migration.peak_pending_name_bytes,
                peak_batch_bytes = migration.peak_batch_bytes,
                batch_commits = migration.batch_commits,
                "migrated name-tree state to consensus-interval accumulation"
            );
        }
        bind_store_identity(&store, config.network)?;
        let store = match &config.data_dir {
            Some(data_dir) => store
                .with_segment_archive(data_dir.join("payload-segments"))
                .map_err(|error| anyhow::anyhow!("failed to open block/undo segments: {error}"))?,
            None => store,
        };
        let previous_shutdown_clean = was_clean_shutdown(&store)
            .map_err(|error| anyhow::anyhow!("failed to read shutdown marker: {error}"))?;

        // Claim the store before any potentially long recovery validation. A
        // crash during the audit must never preserve the preceding process's
        // clean marker and incorrectly authorize the next fast path.
        mark_unclean_start(&store)
            .map_err(|error| anyhow::anyhow!("failed to mark running store unclean: {error}"))?;

        let (checkpoint, checkpoint_warning) = if previous_shutdown_clean {
            let snapshot = store.snapshot()?;
            match load_startup_audit_checkpoint(&snapshot) {
                Ok(checkpoint) => (checkpoint, None),
                Err(error) => (None, Some(format!("{error:#}"))),
            }
        } else {
            (None, None)
        };
        let name_pages = match &config.data_dir {
            Some(data_dir) => Some(NamePageStorage::open_or_bootstrap(
                data_dir.join("name-pages"),
                &store,
                config.network,
            )?),
            None => None,
        };
        let (mut state, audit) = Self::from_store_for_network_with_startup_audit(
            store,
            config.network,
            None,
            checkpoint.as_ref(),
            name_pages,
        )?;
        state.startup_lifecycle = Some(StartupLifecycle {
            previous_shutdown_clean,
            audit,
            checkpoint_warning,
        });
        Ok(state)
    }

    pub fn from_store_for_network(store: StoreHandle, network: Network) -> Result<Self> {
        Self::from_store_for_network_with_undo_policy(store, network, None)
    }

    #[cfg(test)]
    fn from_store_for_network_strict_for_test(
        store: StoreHandle,
        network: Network,
    ) -> Result<Self> {
        Self::from_store_for_network_with_startup_audit_and_validation(
            store,
            network,
            None,
            None,
            None,
            StartupIndexValidation::Strict,
        )
        .map(|(state, _)| state)
    }

    fn from_store_for_network_with_undo_policy(
        store: StoreHandle,
        network: Network,
        undo_retention_policy: Option<UndoRetentionPolicy>,
    ) -> Result<Self> {
        Self::from_store_for_network_with_startup_audit(
            store,
            network,
            undo_retention_policy,
            None,
            None,
        )
        .map(|(state, _)| state)
    }

    fn from_store_for_network_with_startup_audit(
        store: StoreHandle,
        network: Network,
        undo_retention_policy: Option<UndoRetentionPolicy>,
        checkpoint: Option<&StartupAuditCheckpoint>,
        name_pages: Option<NamePageStorage>,
    ) -> Result<(Self, StartupAuditKind)> {
        #[cfg(test)]
        let validation = StartupIndexValidation::TestFixtures;
        #[cfg(not(test))]
        let validation = StartupIndexValidation::Strict;
        Self::from_store_for_network_with_startup_audit_and_validation(
            store,
            network,
            undo_retention_policy,
            checkpoint,
            name_pages,
            validation,
        )
    }

    fn from_store_for_network_with_startup_audit_and_validation(
        store: StoreHandle,
        network: Network,
        undo_retention_policy: Option<UndoRetentionPolicy>,
        checkpoint: Option<&StartupAuditCheckpoint>,
        name_pages: Option<NamePageStorage>,
        validation: StartupIndexValidation,
    ) -> Result<(Self, StartupAuditKind)> {
        bind_store_identity(&store, network)?;
        let chain = match validation {
            StartupIndexValidation::Strict => SharedHeaderIndex::new(store.clone()),
            #[cfg(test)]
            StartupIndexValidation::TestFixtures => {
                SharedHeaderIndex::new_for_test_fixtures(store.clone())
            }
        }
        .map_err(|error| anyhow::anyhow!("failed to initialize header index: {error}"))?;
        if validation == StartupIndexValidation::Strict {
            chain.validate_network_consensus(network)?;
        }
        let blocks = StoredBlockIndex::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize block index: {error}"))?;
        let state_engine =
            StoredStateEngine::with_native_authorization(store.clone(), network, NameFlags::NONE)
                .map_err(|error| anyhow::anyhow!("failed to initialize state engine: {error}"))?;

        let state = Self {
            network,
            undo_retention_policy,
            startup_lifecycle: None,
            store,
            chain,
            blocks,
            state_engine,
            mempool: MemoryMempool::new()
                .map_err(|error| anyhow::anyhow!("failed to initialize mempool: {error}"))?,
            name_pages,
            transaction_index: true,
            wallet_index_profile: WalletIndexProfile::default(),
        };
        let audit = state.validate_durable_chain_invariants(
            checkpoint,
            validation == StartupIndexValidation::Strict,
        )?;
        Ok((state, audit))
    }

    fn validate_durable_chain_invariants(
        &self,
        checkpoint: Option<&StartupAuditCheckpoint>,
        validate_all_indexes: bool,
    ) -> Result<StartupAuditKind> {
        let raw_snapshot = self.store.snapshot()?;
        let (page_reader, mut legacy_page_fallback) = match self.name_pages.as_ref() {
            Some(pages) => {
                let required_roots = [
                    load_stored_name_tree_root(&raw_snapshot).map_err(|error| {
                        anyhow::anyhow!("failed to select startup working name root: {error}")
                    })?,
                    load_stored_name_tree_commit_root(&raw_snapshot).map_err(|error| {
                        anyhow::anyhow!("failed to select startup committed name root: {error}")
                    })?,
                ];
                let (reader, legacy_fallback) =
                    pages.reader_for_roots(&raw_snapshot, required_roots, true)?;
                (Some(reader), legacy_fallback)
            }
            None => (None, false),
        };
        if let Some(reader) = page_reader.as_ref() {
            legacy_page_fallback |=
                seed_startup_pin_page_roots(&raw_snapshot, self.network, reader)?;
        }
        let snapshot = match page_reader.as_ref() {
            Some(reader) if legacy_page_fallback => NodeReadSnapshot::Pages(
                NamePageSnapshot::with_legacy_fallback(&raw_snapshot, reader),
            ),
            Some(reader) => NodeReadSnapshot::Pages(NamePageSnapshot::new(&raw_snapshot, reader)),
            None => NodeReadSnapshot::Base(&raw_snapshot),
        };
        if validate_all_indexes {
            validate_durable_block_index_bindings(&snapshot)?;
        }
        let checkpoint_matches = checkpoint
            .map(|checkpoint| {
                StartupAuditCheckpoint::capture(&snapshot, self.network)
                    .map(|current| current == *checkpoint)
            })
            .transpose()?
            .unwrap_or(false);
        if let Some(checkpoint) = load_name_tree_compaction_checkpoint(&snapshot)? {
            let record = load_block_index_record(&snapshot, &checkpoint.tip)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "name-tree compaction checkpoint tip {} is missing its block index",
                    checkpoint.tip.to_hex()
                )
            })?;
            if record.height != checkpoint.height {
                anyhow::bail!(
                    "name-tree compaction checkpoint height {} disagrees with tip index height {}",
                    checkpoint.height,
                    record.height
                );
            }
        }
        let name_tree_materialization_limits =
            (!checkpoint_matches).then(NameTreeMaterializationLimits::default);
        let durable_name_tree_root = if checkpoint_matches {
            load_stored_name_tree_root(&snapshot)
                .map_err(|error| anyhow::anyhow!("durable name-tree invariant failed: {error}"))?
        } else {
            verify_stored_name_tree_root_metadata_binding(&snapshot)
                .map_err(|error| anyhow::anyhow!("durable name-tree invariant failed: {error}"))?
        };
        let durable_name_tree_commit_root =
            load_stored_name_tree_commit_root(&snapshot).map_err(|error| {
                anyhow::anyhow!("durable name-tree commit invariant failed: {error}")
            })?;
        let active_tip = best_block_tip_from_snapshot(&snapshot)?;
        let best_header = best_header_tip_from_snapshot(&snapshot)?;
        let undo_pruning_checkpoint = load_undo_pruning_checkpoint(&snapshot)?;
        let tree_interval = self.network.params().names.tree_interval;
        let retention = self
            .undo_retention_policy
            .unwrap_or_else(|| UndoRetentionPolicy::for_network(self.network));
        retention.validate()?;
        let audit_start_height = active_tip
            .as_ref()
            .map(|tip| {
                if checkpoint_matches {
                    tip.height
                        .saturating_sub(retention.keep_blocks.saturating_sub(1))
                } else {
                    0
                }
            })
            .unwrap_or(0);
        let mut heights = if let (true, Some(tip)) = (checkpoint_matches, active_tip.as_ref()) {
            StartupHeightCursor::point_range(&snapshot, audit_start_height, tip.height)
        } else {
            StartupHeightCursor::paged(&snapshot)?
        };
        if tree_interval == 0 {
            anyhow::bail!("network name-tree snapshot interval is zero");
        }
        if !checkpoint_matches {
            verify_name_tree_interval_state_bounded(
                &snapshot,
                tree_interval,
                active_tip.as_ref().map_or(0, |tip| tip.height),
                name_tree_materialization_limits
                    .expect("checkpoint miss has materialization limits"),
            )
            .map_err(|error| {
                anyhow::anyhow!("durable name-tree interval accumulator invariant failed: {error}")
            })?;
        }
        if checkpoint_matches {
            for root in [durable_name_tree_root, durable_name_tree_commit_root] {
                validate_persisted_name_tree_root(&snapshot, root).map_err(|error| {
                    anyhow::anyhow!(
                        "durable content-addressed name-tree root invariant failed: {error}"
                    )
                })?;
            }
            let mut pins = StartupPinCursor::new(&raw_snapshot, self.network)?;
            while let Some(pin) = pins.next_pin()? {
                if let Some(pages) = self.name_pages.as_ref() {
                    if pin.root == TreeRoot::ZERO {
                        continue;
                    }
                    if let Some(record) = load_name_page_root_record(&raw_snapshot, pin.root)? {
                        if record.root != pin.root {
                            anyhow::bail!("name-page root locator key does not match its record");
                        }
                        let reader = NamePageTreeReader::open_generation(
                            &pages.directory,
                            pages.state.manifest.generation,
                            pages.state.manifest.active_segment,
                            pin.root,
                            record.locator,
                        )
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "failed to open targeted startup pin root {:?}: {error}",
                                pin.root
                            )
                        })?;
                        let pin_snapshot = NamePageSnapshot::new(&raw_snapshot, &reader);
                        validate_persisted_name_tree_root(&pin_snapshot, pin.root).map_err(
                            |error| {
                                anyhow::anyhow!(
                                    "targeted name-page pin root {:?} failed validation: {error}",
                                    pin.root
                                )
                            },
                        )?;
                    } else {
                        validate_persisted_name_tree_root(&raw_snapshot, pin.root).map_err(
                            |error| {
                                anyhow::anyhow!(
                                    "targeted legacy pin root {:?} failed validation: {error}",
                                    pin.root
                                )
                            },
                        )?;
                    }
                } else {
                    validate_persisted_name_tree_root(&raw_snapshot, pin.root).map_err(
                        |error| {
                            anyhow::anyhow!(
                                "targeted durable pin root {:?} failed validation: {error}",
                                pin.root
                            )
                        },
                    )?;
                }
            }
        } else if let Some(reader) = page_reader.as_ref() {
            let validation_limits =
                production_name_page_validation_limits(&raw_snapshot, self.network)?;
            let pages = reader
                .validate_committed_pages_with_limits_and_progress(
                    validation_limits,
                    NAME_PAGE_VALIDATION_PROGRESS_INTERVAL,
                    |progress| {
                        let percent = progress
                            .pages_completed
                            .saturating_mul(100)
                            .checked_div(progress.pages_total.max(1))
                            .unwrap_or(0);
                        tracing::info!(
                            segments_completed = progress.segments_completed,
                            segments_total = progress.segments_total,
                            pages_completed = progress.pages_completed,
                            pages_total = progress.pages_total,
                            records = progress.records_completed,
                            bytes_completed = progress.bytes_completed,
                            bytes_total = progress.bytes_total,
                            percent,
                            "validating authenticated name pages"
                        );
                    },
                )
                .map_err(|error| {
                    anyhow::anyhow!("authenticated name-page audit failed: {error}")
                })?;
            tracing::info!(
                segments = pages.segments,
                pages = pages.pages,
                records = pages.records,
                bytes = pages.bytes,
                "validated authenticated name pages in physical order"
            );
            let mut roots = Vec::with_capacity(PAGE_BACKED_STARTUP_VALIDATION_BATCH);
            roots.extend([durable_name_tree_root, durable_name_tree_commit_root]);
            let mut pins = StartupPinCursor::new(&raw_snapshot, self.network)?;
            while let Some(pin) = pins.next_pin()? {
                roots.push(pin.root);
                if roots.len() == PAGE_BACKED_STARTUP_VALIDATION_BATCH {
                    validate_persisted_name_tree_overlays(
                        &raw_snapshot,
                        roots.drain(..),
                        &pages,
                        PAGE_BACKED_STARTUP_VALIDATION_BATCH,
                    )
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "durable content-addressed name-tree invariant failed: {error}"
                        )
                    })?;
                }
            }
            if !roots.is_empty() {
                validate_persisted_name_tree_overlays(
                    &raw_snapshot,
                    roots.drain(..),
                    &pages,
                    PAGE_BACKED_STARTUP_VALIDATION_BATCH,
                )
                .map_err(|error| {
                    anyhow::anyhow!("durable content-addressed name-tree invariant failed: {error}")
                })?;
            }
        } else {
            let mut roots = Vec::with_capacity(PAGE_BACKED_STARTUP_VALIDATION_BATCH);
            roots.extend([durable_name_tree_root, durable_name_tree_commit_root]);
            let mut pins = StartupPinCursor::new(&raw_snapshot, self.network)?;
            while let Some(pin) = pins.next_pin()? {
                roots.push(pin.root);
                if roots.len() == PAGE_BACKED_STARTUP_VALIDATION_BATCH {
                    validate_persisted_name_trees(&snapshot, roots.drain(..)).map_err(|error| {
                        anyhow::anyhow!(
                            "durable content-addressed name-tree invariant failed: {error}"
                        )
                    })?;
                }
            }
            if !roots.is_empty() {
                validate_persisted_name_trees(&snapshot, roots.drain(..)).map_err(|error| {
                    anyhow::anyhow!("durable content-addressed name-tree invariant failed: {error}")
                })?;
            }
        }

        let mut name_tree_pins = StartupPinCursor::new(&raw_snapshot, self.network)?;
        let mut next_name_tree_pin = name_tree_pins.next_pin()?;
        while next_name_tree_pin
            .as_ref()
            .is_some_and(|pin| pin.height < audit_start_height)
        {
            if !checkpoint_matches {
                anyhow::bail!("durable name-tree snapshot pin precedes exhaustive audit");
            }
            let pin = next_name_tree_pin.as_ref().expect("pin exists");
            if !pin.height.is_multiple_of(tree_interval) {
                anyhow::bail!(
                    "durable name-tree snapshot pin at height {} is not an interval boundary",
                    pin.height
                );
            }
            next_name_tree_pin = name_tree_pins.next_pin()?;
        }

        match active_tip.as_ref() {
            None => {
                if heights.next_entry()?.is_some() {
                    anyhow::bail!("active height index exists without a best-block binding");
                }
                if undo_pruning_checkpoint.is_some() {
                    anyhow::bail!("empty active chain has an undo-pruning checkpoint");
                }
                if durable_name_tree_root.as_bytes() != &[0; 32] {
                    anyhow::bail!(
                        "empty active chain has non-empty durable name-tree root {:?}",
                        durable_name_tree_root
                    );
                }
                if durable_name_tree_commit_root.as_bytes() != &[0; 32] {
                    anyhow::bail!(
                        "empty active chain has non-empty durable committed name-tree root {:?}",
                        durable_name_tree_commit_root
                    );
                }
                if next_name_tree_pin.is_some() {
                    anyhow::bail!("empty active chain has durable name-tree snapshot pins");
                }
            }
            Some(tip) => {
                if let Some(checkpoint) = undo_pruning_checkpoint.as_ref() {
                    if checkpoint.pruned_through <= retention.prune_after_height {
                        anyhow::bail!(
                            "undo-pruning checkpoint height {} does not exceed prune-after height {}",
                            checkpoint.pruned_through,
                            retention.prune_after_height
                        );
                    }
                    if checkpoint.pruned_through > tip.height {
                        anyhow::bail!(
                            "undo-pruning checkpoint height {} exceeds active tip height {}",
                            checkpoint.pruned_through,
                            tip.height
                        );
                    }
                    let expected_pruned =
                        u64::from(checkpoint.pruned_through - retention.prune_after_height);
                    if checkpoint.pruned_undos != expected_pruned {
                        anyhow::bail!(
                            "undo-pruning checkpoint count {} disagrees with its retained boundary {expected_pruned}",
                            checkpoint.pruned_undos
                        );
                    }
                    if read_canonical_hash(&snapshot, checkpoint.pruned_through)?
                        != Some(checkpoint.block_hash)
                    {
                        anyhow::bail!(
                            "undo-pruning checkpoint block {} is not canonical at height {}",
                            checkpoint.block_hash.to_hex(),
                            checkpoint.pruned_through
                        );
                    }
                    if checkpoint.blocks_pruned_through == 0 {
                        if checkpoint.pruned_blocks != 0
                            || checkpoint.blocks_checkpoint != BlockHash::ZERO
                        {
                            anyhow::bail!(
                                "legacy block-pruning checkpoint has non-empty block progress"
                            );
                        }
                    } else {
                        if checkpoint.blocks_pruned_through <= retention.prune_after_height {
                            anyhow::bail!(
                                "block-pruning checkpoint height {} does not exceed prune-after height {}",
                                checkpoint.blocks_pruned_through,
                                retention.prune_after_height
                            );
                        }
                        if checkpoint.blocks_pruned_through > tip.height {
                            anyhow::bail!(
                                "block-pruning checkpoint height {} exceeds active tip height {}",
                                checkpoint.blocks_pruned_through,
                                tip.height
                            );
                        }
                        let expected_pruned = u64::from(
                            checkpoint.blocks_pruned_through - retention.prune_after_height,
                        );
                        if checkpoint.pruned_blocks != expected_pruned {
                            anyhow::bail!(
                                "block-pruning checkpoint count {} disagrees with its retained boundary {expected_pruned}",
                                checkpoint.pruned_blocks
                            );
                        }
                        if read_canonical_hash(&snapshot, checkpoint.blocks_pruned_through)?
                            != Some(checkpoint.blocks_checkpoint)
                        {
                            anyhow::bail!(
                                "block-pruning checkpoint block {} is not canonical at height {}",
                                checkpoint.blocks_checkpoint.to_hex(),
                                checkpoint.blocks_pruned_through
                            );
                        }
                    }
                }
                let expected_len = usize::try_from(tip.height - audit_start_height)
                    .ok()
                    .and_then(|height| height.checked_add(1))
                    .ok_or_else(|| anyhow::anyhow!("active height index length overflow"))?;

                let (mut previous_hash, mut previous_work) = if audit_start_height == 0 {
                    (BlockHash::ZERO, Uint256::ZERO)
                } else {
                    let previous_height = audit_start_height - 1;
                    let hash =
                        read_canonical_hash(&snapshot, previous_height)?.ok_or_else(|| {
                            anyhow::anyhow!(
                                "clean startup audit suffix is missing parent height {previous_height}"
                            )
                        })?;
                    let record = load_block_index_record(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "clean startup audit suffix parent {} is missing its block index",
                            hash.to_hex()
                        )
                    })?;
                    if record.hash != hash
                        || record.height != previous_height
                        || !record.status.active_chain
                        || !record.status.deployment_state_valid
                    {
                        anyhow::bail!(
                            "clean startup audit suffix parent {} has inconsistent status",
                            hash.to_hex()
                        );
                    }
                    let header = load_header_record(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "clean startup audit suffix parent {} is missing its header",
                            hash.to_hex()
                        )
                    })?;
                    if header.hash != hash
                        || header.height != previous_height
                        || header.chainwork != record.chainwork
                        || header.status != record.status
                    {
                        anyhow::bail!(
                            "clean startup audit suffix parent {} has inconsistent indexes",
                            hash.to_hex()
                        );
                    }
                    (hash, record.chainwork)
                };
                let mut previous_retained_tree_root = None;
                let mut previous_retained_committed_tree_root = None;
                let mut tip_resulting_tree_root = None;
                let mut tip_resulting_committed_tree_root = None;
                for position in 0..expected_len {
                    let (height_key, hash_bytes) = heights.next_entry()?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "active height audit ended before position {position} from height {audit_start_height}"
                        )
                    })?;
                    let height = decode_height_key(&height_key)?;
                    let expected_height = u32::try_from(position)
                        .ok()
                        .and_then(|position| audit_start_height.checked_add(position));
                    if expected_height != Some(height) {
                        anyhow::bail!(
                            "active height audit is not contiguous at position {position}"
                        );
                    }
                    let hash = block_hash_from_bytes(&hash_bytes)?;
                    let record = load_block_index_record(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!("active block index {} is missing", hash.to_hex())
                    })?;
                    if record.height != height
                        || !record.status.active_chain
                        || !record.status.deployment_state_valid
                    {
                        anyhow::bail!(
                            "active block index {} has inconsistent status",
                            hash.to_hex()
                        );
                    }
                    if height == 0 {
                        if record.prev_hash != BlockHash::ZERO {
                            anyhow::bail!("active genesis has a non-zero parent");
                        }
                    } else if record.prev_hash != previous_hash {
                        anyhow::bail!(
                            "active block chain is not parent-contiguous at height {height}"
                        );
                    }
                    if record.chainwork <= previous_work {
                        anyhow::bail!(
                            "active chainwork is not strictly increasing at height {height}"
                        );
                    }
                    let header = load_header_record(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!("active header index {} is missing", hash.to_hex())
                    })?;
                    if header.hash != hash
                        || header.height != height
                        || header.chainwork != record.chainwork
                        || header.status != record.status
                    {
                        anyhow::bail!(
                            "active header index {} disagrees with its block index",
                            hash.to_hex()
                        );
                    }
                    let block_should_be_pruned =
                        undo_pruning_checkpoint.as_ref().is_some_and(|checkpoint| {
                            height > retention.prune_after_height
                                && height <= checkpoint.blocks_pruned_through
                        });
                    let raw_block = load_raw_block_record(&snapshot, &hash)?;
                    if block_should_be_pruned {
                        if record.status.body_present || raw_block.is_some() {
                            anyhow::bail!(
                                "pruned active block {} still has body data",
                                hash.to_hex()
                            );
                        }
                    } else {
                        if !record.status.body_present {
                            anyhow::bail!(
                                "retained active block {} is missing body status",
                                hash.to_hex()
                            );
                        }
                        let raw = raw_block.ok_or_else(|| {
                            anyhow::anyhow!("active block body {} is missing", hash.to_hex())
                        })?;
                        let block = raw.decode_block().map_err(|error| {
                            anyhow::anyhow!(
                                "active block body {} is corrupt: {error}",
                                hash.to_hex()
                            )
                        })?;
                        if block.hash() != hash
                            || block.header.prev_block != record.prev_hash
                            || block.header != header.header
                        {
                            anyhow::bail!(
                                "active block body {} disagrees with its index",
                                hash.to_hex()
                            );
                        }
                    }
                    let expected_deployments = self.deployment_state_for_block(
                        &snapshot,
                        height,
                        header.header.prev_block,
                    )?;
                    let cached_deployments =
                        load_deployment_state(&snapshot, hash)?.ok_or_else(|| {
                            anyhow::anyhow!(
                                "active block {} is missing its deployment-state cache",
                                hash.to_hex()
                            )
                        })?;
                    if cached_deployments.height != height
                        || cached_deployments.state != expected_deployments
                    {
                        anyhow::bail!(
                            "active block {} has an invalid deployment-state cache",
                            hash.to_hex()
                        );
                    }
                    let undo_should_be_pruned =
                        undo_pruning_checkpoint.as_ref().is_some_and(|checkpoint| {
                            height > retention.prune_after_height
                                && height <= checkpoint.pruned_through
                        });
                    let raw_undo = snapshot
                        .get(ColumnFamily::Undo, hash.as_bytes())
                        .context("failed to read active block undo")?;
                    let undo = if undo_should_be_pruned {
                        if record.status.undo_present || raw_undo.is_some() {
                            anyhow::bail!(
                                "pruned active block {} still has undo history",
                                hash.to_hex()
                            );
                        }
                        previous_retained_tree_root = None;
                        previous_retained_committed_tree_root = None;
                        tip_resulting_tree_root = None;
                        tip_resulting_committed_tree_root = None;
                        None
                    } else {
                        if !record.status.undo_present {
                            anyhow::bail!(
                                "retained active block {} is missing undo status",
                                hash.to_hex()
                            );
                        }
                        let raw_undo = raw_undo.ok_or_else(|| {
                            anyhow::anyhow!(
                                "retained active block undo {} is missing",
                                hash.to_hex()
                            )
                        })?;
                        let undo = BlockUndo::decode(&raw_undo).map_err(|error| {
                            anyhow::anyhow!(
                                "retained active block undo {} is corrupt: {error}",
                                hash.to_hex()
                            )
                        })?;
                        if undo.block_hash != hash || undo.height != height {
                            anyhow::bail!(
                                "active block undo {} disagrees with its index",
                                hash.to_hex()
                            );
                        }
                        if header.header.tree_root != *undo.previous_committed_tree_root.as_bytes()
                        {
                            anyhow::bail!(
                                "active block {} header root disagrees with undo pre-state",
                                hash.to_hex()
                            );
                        }
                        if height == 0
                            && (undo.previous_tree_root.as_bytes() != &[0; 32]
                                || undo.previous_committed_tree_root.as_bytes() != &[0; 32])
                        {
                            anyhow::bail!("active genesis undo has a non-empty pre-state root");
                        }
                        let interval_boundary = height.is_multiple_of(tree_interval);
                        if undo.name_tree_interval_boundary != interval_boundary {
                            anyhow::bail!(
                                "active block {} has an invalid name-tree boundary marker",
                                hash.to_hex()
                            );
                        }
                        if undo.previous_tree_root != undo.previous_committed_tree_root
                            || undo.resulting_tree_root != undo.resulting_committed_tree_root
                        {
                            anyhow::bail!(
                                "active block {} retains a per-block working root under the interval-accumulator profile",
                                hash.to_hex()
                            );
                        }
                        if interval_boundary {
                            if let Some(previous) = &undo.previous_name_tree_accumulator {
                                if previous.base_root != undo.previous_committed_tree_root
                                    || previous.last_height >= height
                                    || undo.previous_name_tree_accumulator_last_height
                                        != Some(previous.last_height)
                                {
                                    anyhow::bail!(
                                        "active interval block {} has invalid accumulator rollback state",
                                        hash.to_hex()
                                    );
                                }
                            } else if undo.previous_name_tree_accumulator_last_height.is_some() {
                                anyhow::bail!(
                                    "active interval block {} has an accumulator height without rollback state",
                                    hash.to_hex()
                                );
                            }
                        } else if undo.previous_name_tree_accumulator.is_some() {
                            anyhow::bail!(
                                "active non-interval block {} stores a full accumulator rollback",
                                hash.to_hex()
                            );
                        }
                        if previous_retained_tree_root
                            .is_some_and(|root| undo.previous_tree_root.as_bytes() != &root)
                        {
                            anyhow::bail!(
                                "active block {} breaks retained name-tree root continuity",
                                hash.to_hex()
                            );
                        }
                        if previous_retained_committed_tree_root.is_some_and(|root| {
                            undo.previous_committed_tree_root.as_bytes() != &root
                        }) {
                            anyhow::bail!(
                                "active block {} breaks retained committed name-tree root continuity",
                                hash.to_hex()
                            );
                        }
                        let expected_resulting_committed = if interval_boundary {
                            undo.resulting_tree_root
                        } else {
                            undo.previous_committed_tree_root
                        };
                        if undo.resulting_committed_tree_root != expected_resulting_committed {
                            anyhow::bail!(
                                "active block {} has invalid name-tree interval commitment timing",
                                hash.to_hex()
                            );
                        }
                        let resulting_root = *undo.resulting_tree_root.as_bytes();
                        let resulting_committed_root =
                            *undo.resulting_committed_tree_root.as_bytes();
                        previous_retained_tree_root = Some(resulting_root);
                        previous_retained_committed_tree_root = Some(resulting_committed_root);
                        tip_resulting_tree_root = Some(resulting_root);
                        tip_resulting_committed_tree_root = Some(resulting_committed_root);
                        Some(undo)
                    };
                    if height.is_multiple_of(tree_interval) {
                        if next_name_tree_pin
                            .as_ref()
                            .is_some_and(|pin| pin.height < height)
                        {
                            anyhow::bail!(
                                "durable name-tree snapshot pin precedes active interval height {height}"
                            );
                        }
                        if undo_should_be_pruned {
                            if next_name_tree_pin
                                .as_ref()
                                .is_some_and(|pin| pin.height == height)
                            {
                                anyhow::bail!(
                                    "pruned interval height {height} still has a name-tree snapshot pin"
                                );
                            }
                        } else {
                            let pin = next_name_tree_pin.take().filter(|pin| pin.height == height)
                                .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "active interval height {height} is missing its name-tree snapshot pin"
                                )
                            })?;
                            let expected_pin_root = undo
                                .as_ref()
                                .map(|undo| *undo.resulting_committed_tree_root.as_bytes())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("retained interval height {height} has no undo")
                                })?;
                            if pin.block_hash != hash || pin.root.as_bytes() != &expected_pin_root {
                                anyhow::bail!(
                                    "active interval height {height} has an inconsistent name-tree snapshot pin"
                                );
                            }
                            next_name_tree_pin = name_tree_pins.next_pin()?;
                        }
                    }
                    previous_hash = hash;
                    previous_work = record.chainwork;
                }
                if heights.next_entry()?.is_some() {
                    anyhow::bail!(
                        "active height index contains an entry beyond tip height {}",
                        tip.height
                    );
                }

                if previous_hash != tip.hash || previous_work != tip.chainwork {
                    anyhow::bail!("best-block binding does not match the active height index tip");
                }
                if let Some(tip_resulting_tree_root) = tip_resulting_tree_root {
                    if durable_name_tree_root.as_bytes() != &tip_resulting_tree_root {
                        anyhow::bail!(
                            "durable name-tree root does not match the active tip's resulting root"
                        );
                    }
                }
                if let Some(tip_resulting_committed_tree_root) = tip_resulting_committed_tree_root {
                    if durable_name_tree_commit_root.as_bytes()
                        != &tip_resulting_committed_tree_root
                    {
                        anyhow::bail!(
                            "durable name-tree commit root does not match the active tip's resulting committed root"
                        );
                    }
                }
            }
        }
        if next_name_tree_pin.is_some() {
            anyhow::bail!("durable name-tree snapshot pins are not on active interval heights");
        }

        match (best_header.as_ref(), active_tip.as_ref()) {
            (None, Some(_)) => anyhow::bail!("active block chain exists without a best header"),
            (Some(header), Some(block)) if header.chainwork < block.chainwork => {
                anyhow::bail!("best header has less work than the active block tip")
            }
            _ => {}
        }

        // The key is initialized with the store identity. Decoding it here
        // catches partial/manual metadata edits before any mining interface is
        // exposed.
        let _ = chain_epoch_from_snapshot(&snapshot)?;
        let _ = mining_generation_from_snapshot(&snapshot)?;
        Ok(if checkpoint_matches {
            StartupAuditKind::CleanCheckpoint
        } else {
            StartupAuditKind::Exhaustive
        })
    }

    fn configure_transaction_index(&mut self, enabled: bool) -> Result<()> {
        self.ensure_storage_operational()?;
        let snapshot = self.store.snapshot()?;
        let persisted = snapshot
            .get(ColumnFamily::Snapshots, TRANSACTION_INDEX_MODE_KEY)
            .context("failed to read transaction-index mode")?
            .map(|raw| decode_transaction_index_mode(&raw))
            .transpose()?;
        if persisted == Some(false)
            && enabled
            && (best_block_tip_from_snapshot(&snapshot)?.is_some()
                || !snapshot
                    .scan_prefix_page(
                        ColumnFamily::TxIndex,
                        b"",
                        None,
                        PrefixScanBudget {
                            max_entries: 1,
                            max_bytes: 4 * 1024,
                        },
                    )
                    .context("failed to inspect disabled transaction index")?
                    .entries
                    .is_empty())
        {
            anyhow::bail!(
                "transaction index cannot be enabled after unindexed blocks exist; rebuild it offline or use a new data directory"
            );
        }
        drop(snapshot);
        if persisted != Some(enabled) {
            let mut batch = self.store.batch();
            batch.put(
                ColumnFamily::Snapshots,
                TRANSACTION_INDEX_MODE_KEY,
                &encode_transaction_index_mode(enabled),
            )?;
            self.store.commit(batch)?;
        }
        self.transaction_index = enabled;
        Ok(())
    }

    fn configure_wallet_indexes(&mut self, profile: WalletIndexProfile) -> Result<()> {
        self.ensure_storage_operational()?;
        let snapshot = self.store.snapshot()?;
        let persisted_raw = snapshot
            .get(ColumnFamily::Snapshots, INDEX_PROFILE_MODE_KEY)
            .context("failed to read wallet-index profile")?;
        let profile_is_current = persisted_raw
            .as_deref()
            .map(index_profile_is_current)
            .transpose()
            .map_err(|error| anyhow::anyhow!(error))?
            .unwrap_or(false);
        let persisted = persisted_raw
            .as_deref()
            .map(decode_index_profile)
            .transpose()
            .map_err(|error| anyhow::anyhow!(error))?;
        let adds_unbuilt_component = persisted.map_or(profile.enabled(), |available| {
            !profile.is_satisfied_by(available)
        });
        let has_wallet_keys = !snapshot
            .scan_prefix_page(
                ColumnFamily::TxIndex,
                b"wallet-index/v1/",
                None,
                PrefixScanBudget {
                    max_entries: 1,
                    max_bytes: 4 * 1024,
                },
            )
            .context("failed to inspect wallet indexes")?
            .entries
            .is_empty();
        if adds_unbuilt_component
            && (best_block_tip_from_snapshot(&snapshot)?.is_some() || has_wallet_keys)
        {
            anyhow::bail!(
                "wallet index profile cannot add components after indexed chain history exists; run the documented offline reindex or use a new data directory"
            );
        }
        if persisted.is_none() && !profile.enabled() && has_wallet_keys {
            anyhow::bail!(
                "wallet index keys exist without a persistent profile; run offline verification/reindex before startup"
            );
        }
        validate_tracked_contract_registry(&snapshot, profile)
            .map_err(anyhow::Error::new)
            .context("failed to validate tracked wallet contracts")?;
        let rollback_boundary =
            load_undo_pruning_checkpoint(&snapshot)?.map(|checkpoint| ContractRollbackBoundary {
                pruned_through: checkpoint.pruned_through,
                block_hash: checkpoint.block_hash,
            });
        validate_completed_tracked_contract_retirements(
            &snapshot,
            profile,
            rollback_boundary,
            |height| {
                read_canonical_hash(&snapshot, height).map_err(|_| {
                    hns_wallet_index::IndexError::Corrupt(
                        "failed to read canonical retirement proof height",
                    )
                })
            },
        )
        .map_err(anyhow::Error::new)
        .context("failed to validate completed wallet contract retirements")?;
        drop(snapshot);
        if persisted != Some(profile) || !profile_is_current {
            let mut batch = self.store.batch();
            batch.put(
                ColumnFamily::Snapshots,
                INDEX_PROFILE_MODE_KEY,
                &encode_index_profile(profile),
            )?;
            self.store.commit(batch)?;
        }
        self.wallet_index_profile = profile;
        Ok(())
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    fn storage_reopen_required(&self) -> bool {
        self.store.reopen_required()
            || self
                .name_pages
                .as_ref()
                .is_some_and(|pages| pages.reopen_required)
    }

    fn production_safety_fence_reason(&self) -> Option<String> {
        self.chain.safety_fence_reason()
    }

    fn production_safety_fence_kind(&self) -> Option<ProductionSafetyFenceKind> {
        self.chain.safety_fence_kind()
    }

    fn ensure_storage_operational(&self) -> Result<()> {
        if self.storage_reopen_required() {
            anyhow::bail!(
                "node storage is fenced after an ambiguous commit; restart and reopen before authority or mutation"
            );
        }
        if let Some(reason) = self.production_safety_fence_reason() {
            anyhow::bail!("node is fail-closed behind a durable production safety fence: {reason}");
        }
        Ok(())
    }

    fn best_block_tip(&self) -> Result<Option<ChainTip>> {
        let snapshot = self.store.snapshot()?;
        best_block_tip_from_snapshot(&snapshot)
    }

    fn durable_mining_state(&self) -> Result<DurableMiningState> {
        if self.storage_reopen_required() {
            anyhow::bail!(
                "node storage is fenced after an ambiguous commit; restart and reopen before authority"
            );
        }
        let production_safety_fenced = self.production_safety_fence_reason().is_some();
        let snapshot = self.store.snapshot()?;
        let generation = mining_generation_from_snapshot(&snapshot)?;
        let best_header = best_header_tip_from_snapshot(&snapshot)?;
        let best_hash = snapshot
            .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
            .context("failed to read durable mining tip")?
            .map(|bytes| block_hash_from_bytes(&bytes))
            .transpose()?;

        let (mining_snapshot, authoritative) = match best_hash {
            Some(hash) => {
                let (snapshot, authoritative) = mining_snapshot_for_hash(
                    &snapshot,
                    self.network.canonical_id(),
                    hash,
                    generation,
                )?;
                (Some(snapshot), authoritative)
            }
            None => (None, false),
        };
        let synchronized = match (&best_header, &mining_snapshot) {
            (Some(header), Some(mining)) => {
                header.hash == mining.tip.hash
                    && header.height == mining.tip.height
                    && header.chainwork == mining.chainwork
            }
            (None, None) => false,
            _ => false,
        };
        Ok(DurableMiningState {
            generation,
            snapshot: mining_snapshot,
            authoritative: authoritative && !production_safety_fenced,
            synchronized: synchronized && !production_safety_fenced,
        })
    }

    fn rpc_entries(&self) -> Result<RpcStoreEntries> {
        let snapshot = self.store.snapshot()?;
        let headers = self.rpc_headers(&snapshot)?;
        let canonical_hashes = headers
            .iter()
            .map(|entry| entry.record.hash)
            .collect::<HashSet<_>>();

        let mut block_records = snapshot
            .scan_prefix(ColumnFamily::BlockIndex, b"")
            .context("failed to scan block index")?
            .into_iter()
            .map(|(_, bytes)| {
                BlockIndexRecord::decode(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode block index: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        block_records.sort_by_key(|record| (record.height, record.hash));

        let mut blocks = Vec::new();
        let mut transactions = Vec::new();
        for record in block_records {
            if !record.status.active_chain
                || !record.status.utxo_connected
                || !canonical_hashes.contains(&record.hash)
            {
                continue;
            }

            let Some(block) = self
                .blocks
                .load_block(&record.hash)
                .map_err(|error| anyhow::anyhow!("failed to load RPC block: {error}"))?
            else {
                continue;
            };

            transactions.extend(block.transactions.iter().map(|transaction| {
                RpcTransactionEntry::from_transaction(
                    transaction,
                    Some(record.hash),
                    Some(record.height),
                )
            }));
            blocks.push(RpcBlockEntry::from_block(record, &block));
        }

        let coins = snapshot
            .scan_prefix(ColumnFamily::Utxo, b"")
            .context("failed to scan UTXO set")?
            .into_iter()
            .map(|(_, bytes)| {
                decode_coin(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode coin: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let names = snapshot
            .scan_prefix(ColumnFamily::NameState, b"")
            .context("failed to scan name state")?
            .into_iter()
            .map(|(key, bytes)| {
                let name_hash: [u8; 32] = key.as_slice().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "name-state key has invalid length {}; expected 32",
                        key.len()
                    )
                })?;
                decode_name_state(&NameHash::new(name_hash), &bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode name state: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(RpcStoreEntries {
            headers,
            blocks,
            transactions,
            coins,
            names,
        })
    }

    fn rpc_headers(&self, snapshot: &impl ReadSnapshot) -> Result<Vec<RpcHeaderEntry>> {
        let mut entries = snapshot
            .scan_prefix(ColumnFamily::HeightIndex, b"")
            .context("failed to scan canonical height index")?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut headers = Vec::with_capacity(entries.len());
        for (height_key, hash_bytes) in entries {
            let height = decode_height_key(&height_key)?;
            let hash = block_hash_from_bytes(&hash_bytes)?;

            if let Some(record) = self
                .chain
                .load_record(&hash)
                .map_err(|error| anyhow::anyhow!("failed to load header record: {error}"))?
            {
                headers.push(RpcHeaderEntry::new(record));
                continue;
            }

            let Some(block) = self.blocks.load_block(&hash).map_err(|error| {
                anyhow::anyhow!("failed to load block header fallback: {error}")
            })?
            else {
                continue;
            };
            let chainwork = self
                .blocks
                .load_block_record(&hash)
                .map_err(|error| anyhow::anyhow!("failed to load block header index: {error}"))?
                .map(|record| record.chainwork)
                .unwrap_or(Uint256::ZERO);
            headers.push(RpcHeaderEntry::new(HeaderRecord {
                hash,
                height,
                chainwork,
                header: block.header,
                status: BlockStatus {
                    header_context_valid: true,
                    active_chain: true,
                    ..BlockStatus::default()
                },
            }));
        }

        Ok(headers)
    }

    fn load_block_record(&self, hash: &BlockHash) -> Result<Option<BlockIndexRecord>> {
        self.blocks
            .load_block_record(hash)
            .map_err(|error| anyhow::anyhow!("failed to load block record: {error}"))
    }

    fn is_direct_active_extension(&self, request: &NodeBlockImport) -> Result<bool> {
        let tip = self.best_block_tip()?;
        match tip {
            None => Ok(request.height == 0),
            Some(tip) => Ok(request.block.header.prev_block == tip.hash
                && request.height == tip.height.saturating_add(1)),
        }
    }

    fn store_validated_alternate(
        &mut self,
        request: NodeBlockImport,
        validated: ValidatedImport,
    ) -> Result<StoredBlockMutation> {
        self.store_validated_alternates(vec![(request, validated)])?
            .pop()
            .ok_or_else(|| anyhow::anyhow!("single alternate-body store returned no result"))
    }

    /// Commit a group of independently body-validated blocks in one durable
    /// transaction. The overlay preserves read-your-writes behavior for a
    /// duplicate hash or best-header update inside the group; scheduler state
    /// is advanced only after this complete transaction returns successfully.
    fn store_validated_alternates(
        &mut self,
        candidates: Vec<(NodeBlockImport, ValidatedImport)>,
    ) -> Result<Vec<StoredBlockMutation>> {
        self.ensure_storage_operational()?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let base = self.store.snapshot()?;
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let mut batch = overlay.batch(self.store.batch());
        let mut mutations = Vec::with_capacity(candidates.len());
        let mut committed_records = Vec::with_capacity(candidates.len());

        for (request, validated) in candidates {
            let block_hash = request.block.hash();
            if let Some(existing) = load_block_index_record(&staged, &block_hash)? {
                let stored = load_block(&staged, &block_hash)?.ok_or_else(|| {
                    anyhow::anyhow!("known block {} has no raw body", block_hash.to_hex())
                })?;
                if stored.encode() != request.block.encode() {
                    anyhow::bail!(
                        "known block {} has conflicting raw bytes",
                        block_hash.to_hex()
                    );
                }
                mutations.push(StoredBlockMutation {
                    record: existing,
                    already_known: true,
                });
                continue;
            }

            let mut status = validated.status;
            status.utxo_connected = false;
            status.name_state_connected = false;
            status.tree_root_valid = false;
            status.undo_present = false;
            status.active_chain = false;

            let mut record =
                BlockIndexRecord::from_block(&request.block, request.height, validated.chainwork)
                    .map_err(|error| {
                    anyhow::anyhow!("failed to build alternate block index: {error}")
                })?;
            record.status = status.clone();
            record.validated_at = Some(current_unix_time()?);
            let header_record = HeaderRecord {
                hash: block_hash,
                height: request.height,
                chainwork: validated.chainwork,
                header: request.block.header.clone(),
                status,
            };
            let raw_record = RawBlockRecord::from_block(&request.block, request.source);
            write_record_to_batch(&mut batch, &header_record)
                .map_err(|error| anyhow::anyhow!("failed to stage alternate header: {error}"))?;
            write_block_index_to_batch(&mut batch, &record).map_err(|error| {
                anyhow::anyhow!("failed to stage alternate block index: {error}")
            })?;
            write_raw_block_to_batch(&mut batch, &raw_record).map_err(|error| {
                anyhow::anyhow!("failed to stage alternate block body: {error}")
            })?;
            stage_best_header_if_more_work(&staged, &mut batch, block_hash, validated.chainwork)?;
            committed_records.push(IndexStatusUpdate {
                previous_block: None,
                current: StagedIndexRecord {
                    block: record.clone(),
                    header: header_record,
                },
            });
            mutations.push(StoredBlockMutation {
                record,
                already_known: false,
            });
        }

        let batch = batch.into_inner();
        let publication = if committed_records.is_empty() {
            None
        } else {
            Some(self.prepare_index_publication(&committed_records)?)
        };
        drop(staged);
        drop(base);
        if let Some(publication) = publication {
            self.commit_index_publication(publication, move |state| {
                state.store.commit(batch)?;
                Ok(())
            })?;
        }
        Ok(mutations)
    }

    fn store_failed_block(
        &mut self,
        request: NodeBlockImport,
        stage: FailedBlockStage,
    ) -> Result<FailedBlockMutation> {
        self.ensure_storage_operational()?;
        let block_hash = request.block.hash();
        let snapshot = self.store.snapshot()?;
        let header = load_header_record(&snapshot, &block_hash)?.ok_or_else(|| {
            anyhow::anyhow!(
                "cannot persist failed block {} without its validated header",
                block_hash.to_hex()
            )
        })?;
        if header.height != request.height || header.header != request.block.header {
            anyhow::bail!(
                "failed block {} disagrees with its durable header context",
                block_hash.to_hex()
            );
        }

        let existing = load_block_index_record(&snapshot, &block_hash)?;
        if existing
            .as_ref()
            .is_some_and(|record| record.status.active_chain)
        {
            anyhow::bail!("cannot mark active block {} failed", block_hash.to_hex());
        }
        if stage == FailedBlockStage::BodySyntax
            && existing
                .as_ref()
                .is_some_and(|record| !record.status.failed)
        {
            anyhow::bail!(
                "cannot mark previously body-validated block {} syntax-invalid",
                block_hash.to_hex()
            );
        }
        if let Some(raw) = snapshot.get(ColumnFamily::Blocks, block_hash.as_bytes())? {
            let raw = RawBlockRecord::decode(&raw)
                .map_err(|error| anyhow::anyhow!("failed block body is corrupt: {error}"))?;
            if raw.bytes != request.block.encode() {
                anyhow::bail!(
                    "failed block {} has conflicting durable bytes",
                    block_hash.to_hex()
                );
            }
        }

        let chain = self.chain.clone();
        chain.write_exclusive(|header_index| {
            let mut failure_plan = header_index
                .plan_failed_branch(block_hash)
                .map_err(|error| anyhow::anyhow!("failed to plan invalid branch: {error}"))?;
            let target_header = failure_plan
                .affected
                .iter_mut()
                .find(|record| record.hash == block_hash)
                .ok_or_else(|| anyhow::anyhow!("invalid branch plan omitted its root"))?;
            target_header.status.body_present = true;
            match stage {
                FailedBlockStage::BodySyntax => {
                    target_header.status.body_syntax_valid = false;
                }
                FailedBlockStage::ContextualState => {
                    if !target_header.status.body_syntax_valid
                        || !target_header.status.absolute_finality_valid
                    {
                        anyhow::bail!(
                            "contextual failure root {} lacks prior body/finality validation",
                            block_hash.to_hex()
                        );
                    }
                }
            }

            let target_previous = existing.clone();
            let mut target = existing.unwrap_or(
                BlockIndexRecord::from_block(&request.block, request.height, header.chainwork)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to build invalid block index: {error}")
                    })?,
            );
            target.status = target_header.status.clone();
            target.status.utxo_connected = false;
            target.status.name_state_connected = false;
            target.status.tree_root_valid = false;
            target.status.undo_present = false;
            target.status.active_chain = false;
            target.status.failed = true;
            target.validated_at = Some(current_unix_time()?);

            let mut batch = self.store.batch();
            let mut block_replacements = Vec::new();
            for failed_header in &failure_plan.affected {
                write_record_to_batch(&mut batch, failed_header)
                    .map_err(|error| anyhow::anyhow!("failed to stage invalid header: {error}"))?;
                if failed_header.hash == block_hash {
                    continue;
                }
                if let Some(mut descendant) =
                    load_block_index_record(&snapshot, &failed_header.hash)?
                {
                    let previous = descendant.clone();
                    if descendant.status.active_chain {
                        anyhow::bail!(
                            "cannot invalidate active descendant {}",
                            descendant.hash.to_hex()
                        );
                    }
                    descendant.status.failed = true;
                    write_block_index_to_batch(&mut batch, &descendant).map_err(|error| {
                        anyhow::anyhow!("failed to stage invalid descendant block: {error}")
                    })?;
                    block_replacements.push((Some(previous), descendant));
                }
            }
            write_block_index_to_batch(&mut batch, &target)
                .map_err(|error| anyhow::anyhow!("failed to stage invalid block index: {error}"))?;
            block_replacements.push((target_previous, target.clone()));
            let raw_record = RawBlockRecord::from_block(&request.block, request.source);
            write_raw_block_to_batch(&mut batch, &raw_record)
                .map_err(|error| anyhow::anyhow!("failed to stage invalid block body: {error}"))?;
            batch.put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                failure_plan.best.hash.as_bytes(),
            )?;
            let failed_header_bytes =
                failure_plan
                    .affected
                    .iter()
                    .try_fold(0usize, |total, record| {
                        total
                            .checked_add(record.hash.as_bytes().len())
                            .and_then(|total| total.checked_add(record.encode().len()))
                            .ok_or_else(|| {
                                anyhow::anyhow!("invalid-branch header batch size overflow")
                            })
                    })?;
            let failed_block_bytes =
                block_replacements
                    .iter()
                    .try_fold(0usize, |total, (_, record)| {
                        total
                            .checked_add(record.hash.as_bytes().len())
                            .and_then(|total| total.checked_add(record.encode().len()))
                            .ok_or_else(|| {
                                anyhow::anyhow!("invalid-branch block batch size overflow")
                            })
                    })?;
            failed_header_bytes
                .checked_add(failed_block_bytes)
                .and_then(|total| total.checked_add(raw_record.hash.as_bytes().len()))
                .and_then(|total| total.checked_add(raw_record.encode().len()))
                .and_then(|total| total.checked_add(MetaKey::BestHeaderHash.as_bytes().len()))
                .and_then(|total| total.checked_add(failure_plan.best.hash.as_bytes().len()))
                .ok_or_else(|| anyhow::anyhow!("invalid-branch atomic batch size overflow"))?;
            header_index
                .validate_failed_plan(&failure_plan)
                .map_err(|error| anyhow::anyhow!("invalid branch cache plan is stale: {error}"))?;
            let block_cache_update = self
                .blocks
                .prepare_cache_update(&block_replacements)
                .map_err(|error| {
                    anyhow::anyhow!("failed to stage invalid block cache update: {error}")
                })?;
            let affected = failure_plan
                .affected
                .iter()
                .map(|record| record.hash)
                .collect();
            drop(snapshot);
            self.store.commit(batch)?;
            header_index.apply_validated_failed_plan(&failure_plan);
            self.blocks.publish_cache_update(block_cache_update);
            Ok(FailedBlockMutation {
                record: target,
                affected,
            })
        })
    }

    fn best_chain_activation_plan(
        &self,
        candidate: BlockHash,
        limits: NodeReorgLimits,
    ) -> Result<Option<NodeReorg>> {
        let base = self.store.snapshot()?;
        // Planning revisits candidate, fork, and connect-path records while it
        // proves eligibility, validates path shape, and materializes imports.
        // Reuse the same bounded immutable point cache as activation staging so
        // each logical record reaches the base snapshot at most once.
        let reads = StagingOverlay::new();
        let snapshot = reads.snapshot(&base);
        let candidate_record = load_block_index_record(&snapshot, &candidate)?
            .ok_or_else(|| anyhow::anyhow!("candidate block index is missing"))?;
        validate_block_header_binding(&snapshot, &candidate_record)?;
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
            Some(tip) => self
                .chain
                .plan_reorg_between_bounded(
                    &tip.hash,
                    &candidate,
                    NodeReorgLimits::PRODUCTION.header_limits(),
                )
                .map_err(|error| {
                    anyhow::anyhow!("failed to plan bounded best-chain reorg: {error}")
                })?,
            None => ReorgPlan {
                disconnect: Vec::new(),
                connect: stored_path_from_genesis_bounded(
                    &snapshot,
                    candidate,
                    limits.maximum_connect,
                )?,
            },
        };

        // Header synchronization and canonical body download are intentionally
        // allowed to advance out of order. A higher-work candidate can
        // therefore be complete while an earlier connect-path body is still
        // header-only. Defer activation until every connect record exists;
        // retain fail-closed behavior when a body exists without its index.
        for hash in &plan.connect {
            if load_block_index_record(&snapshot, hash)?.is_none() {
                if load_raw_block_record(&snapshot, hash)?.is_some() {
                    anyhow::bail!(
                        "stored block body {} is missing its block index",
                        hash.to_hex()
                    );
                }
                return Ok(None);
            }
        }

        validate_reorg_plan(&snapshot, active.as_ref(), candidate, &plan)?;
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
                Ok(NodeBlockDisconnect {
                    block_hash: *hash,
                    height: record.height,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut body_bytes = 0u64;
        let mut connect = Vec::with_capacity(plan.connect.len());
        for hash in &plan.connect {
            connect.push(node_import_from_stored_bounded(
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

    fn recover_best_stored_chain(&mut self) -> Result<Option<NodeReorgMutation>> {
        self.ensure_storage_operational()?;
        let Some(best_header) = self
            .chain
            .best_tip()
            .map_err(|error| anyhow::anyhow!("failed to read persisted best header: {error}"))?
        else {
            return Ok(None);
        };

        // Header synchronization is allowed to run ahead of block download.
        // Recovery is therefore attempted only when the best-work header has a
        // complete stored block body and index record.
        if self.load_block_record(&best_header.hash)?.is_none() {
            return Ok(None);
        }

        let Some(plan) =
            self.best_chain_activation_plan(best_header.hash, NodeReorgLimits::PRODUCTION)?
        else {
            return Ok(None);
        };
        self.apply_reorg(plan).map(Some)
    }

    fn validate_import(&self, request: &NodeBlockImport) -> Result<ValidatedImport> {
        self.ensure_storage_operational()?;
        let snapshot = self.store.snapshot()?;
        self.validate_import_against(&snapshot, request)
    }

    /// Validate a canonical native-sync body whose header ancestry is already
    /// durable even when network delivery has not supplied its parent body.
    /// Active connection still uses `validate_import` and therefore requires
    /// the complete parent index chain. Pruned active ancestors retain that
    /// index even though their raw bodies are intentionally unavailable.
    fn validate_prevalidated_native_import(
        &self,
        request: &NodeBlockImport,
        canonical: bool,
        stateless: StatelessBodyValidation,
    ) -> Result<ValidatedImport> {
        self.ensure_storage_operational()?;
        if canonical {
            let hash = request.block.hash();
            if self.chain.canonical_hash(request.height).map_err(|error| {
                anyhow::anyhow!("failed to read canonical native header: {error}")
            })? != Some(hash)
            {
                anyhow::bail!(
                    "native body {} is not the canonical header at height {}",
                    hash.to_hex(),
                    request.height
                );
            }
        }
        let snapshot = self.store.snapshot()?;
        self.validate_import_against_policy(&snapshot, request, !canonical, Some(stateless))
    }

    /// Preflight only the context-independent portion represented by the
    /// `BlockSyntaxValidated` event. Reorg parents may exist solely in the
    /// pending connect sequence, so parent/state checks remain in the staged
    /// overlay where they can see preceding candidates.
    fn validate_import_syntax(&self, request: &NodeBlockImport) -> Result<()> {
        self.ensure_storage_operational()?;
        let strict = matches!(request.validation, ImportValidationPolicy::Strict);
        if strict {
            validate_transaction_start(&request.block, request.height, self.network)
                .map_err(|error| anyhow::anyhow!("transaction-start validation failed: {error}"))?;
        }
        let status = BlockStatus {
            header_context_valid: true,
            checkpoint_valid: strict,
            body_present: true,
            ..BlockStatus::default()
        };
        let historical_validation = self.historical_validation_plan_for_block(
            request.height,
            request.block.hash(),
            &status,
        )?;
        self.validate_block_body_for_plan(&request.block, historical_validation)
    }

    fn validate_block_body_for_plan(
        &self,
        block: &Block,
        historical_validation: HistoricalValidationPlan,
    ) -> Result<()> {
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(self.network));
        if historical_validation.body_sanity {
            consensus
                .validate_block_body(block)
                .map_err(|error| anyhow::anyhow!("block body validation failed: {error}"))?;
        } else {
            if !historical_validation.body_commitments || !historical_validation.name_limits {
                anyhow::bail!("historical validation route omits a required body stage");
            }
            consensus
                .validate_block_commitments(block)
                .map_err(|error| anyhow::anyhow!("block commitment validation failed: {error}"))?;
            consensus
                .validate_block_name_limits(block)
                .map_err(|error| anyhow::anyhow!("block name-limit validation failed: {error}"))?;
        }
        Ok(())
    }

    fn validate_import_against<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        request: &NodeBlockImport,
    ) -> Result<ValidatedImport> {
        self.validate_import_against_policy(snapshot, request, true, None)
    }

    fn validate_import_against_policy<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        request: &NodeBlockImport,
        require_parent_index: bool,
        stateless: Option<StatelessBodyValidation>,
    ) -> Result<ValidatedImport> {
        if let Some(stateless) = stateless {
            stateless.verify(request)?;
        }
        let parent = if request.height == 0 {
            None
        } else {
            Some(
                load_header_record(snapshot, &request.block.header.prev_block)?.ok_or_else(
                    || {
                        anyhow::anyhow!(
                            "missing header parent {}",
                            request.block.header.prev_block.to_hex()
                        )
                    },
                )?,
            )
        };

        let median_time_past = parent
            .as_ref()
            .map(|record| self.median_time_past(snapshot, record))
            .transpose()?;

        let (chainwork, header_context_valid) = match request.validation {
            ImportValidationPolicy::Strict => {
                let expected_bits =
                    Some(self.expected_bits_for_import(snapshot, request, parent.as_ref())?);
                let maximum_time = current_unix_time()?.saturating_add(MAX_FUTURE_BLOCK_TIME);
                let network_params = self.network.params();
                let is_canonical_genesis = request.height == 0
                    && request.block.header == network_params.genesis_header()
                    && request.block.hash() == network_params.genesis_hash;
                HeaderConsensus::new(ConsensusParams::for_network(self.network))
                    .validate_header(
                        &request.block.header,
                        &HeaderValidationContext {
                            height: request.height,
                            previous: parent.as_ref().map(|record| HeaderParent {
                                hash: record.hash,
                                height: record.height,
                                bits: record.header.bits,
                                chainwork: record.chainwork,
                            }),
                            enforce_checkpoints: true,
                            expected_bits,
                            median_time_past,
                            maximum_time: Some(maximum_time),
                            require_pow: !is_canonical_genesis,
                        },
                    )
                    .map_err(|error| anyhow::anyhow!("header validation failed: {error}"))?;

                let proof = CompactTarget::from_bits(request.block.header.bits)
                    .proof()
                    .ok_or_else(|| anyhow::anyhow!("header has an invalid proof-of-work target"))?;
                let chainwork = parent
                    .as_ref()
                    .map(|record| record.chainwork)
                    .unwrap_or(Uint256::ZERO)
                    .checked_add(proof)
                    .ok_or_else(|| anyhow::anyhow!("header chainwork overflow"))?;
                (chainwork, true)
            }
            #[cfg(test)]
            ImportValidationPolicy::Fixture { chainwork } => (chainwork, true),
        };

        let strict = matches!(request.validation, ImportValidationPolicy::Strict);
        if strict && stateless.is_none() {
            validate_transaction_start(&request.block, request.height, self.network)
                .map_err(|error| anyhow::anyhow!("transaction-start validation failed: {error}"))?;
        }

        let mut status = BlockStatus {
            header_context_valid,
            checkpoint_valid: strict,
            body_present: true,
            ..BlockStatus::default()
        };
        let historical_validation = self.historical_validation_plan_for_block(
            request.height,
            request.block.hash(),
            &status,
        )?;
        if stateless.is_none_or(|proof| !proof.covers(historical_validation)) {
            self.validate_block_body_for_plan(&request.block, historical_validation)?;
        }
        status.body_syntax_valid = true;

        validate_block_finality(
            &request.block,
            request.height,
            median_time_past.unwrap_or(request.block.header.time),
        )
        .map_err(|error| anyhow::anyhow!("transaction finality validation failed: {error}"))?;

        if strict && stateless.is_none() {
            validate_coinbase_height(&request.block, request.height)
                .map_err(|error| anyhow::anyhow!("coinbase height validation failed: {error}"))?;
        }

        validate_branch_extension(
            snapshot,
            request,
            chainwork,
            self.network,
            require_parent_index,
        )?;

        Ok(ValidatedImport {
            chainwork,
            status: BlockStatus {
                absolute_finality_valid: true,
                ..status
            },
            historical_validation,
        })
    }

    fn validate_stored_activation_with_stateless<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        request: &NodeBlockImport,
        record: &BlockIndexRecord,
        stateless: Option<StatelessBodyValidation>,
    ) -> Result<ValidatedImport> {
        validate_stored_activation_status(record)?;
        let hash = request.block.hash();
        if record.hash != hash
            || record.height != request.height
            || record.prev_hash != request.block.header.prev_block
            || usize::try_from(record.tx_count).ok() != Some(request.block.transactions.len())
        {
            anyhow::bail!(
                "stored activation record does not identify block {} at height {}",
                hash.to_hex(),
                request.height
            );
        }
        let header = load_header_record(snapshot, &hash)?.ok_or_else(|| {
            anyhow::anyhow!("stored activation header {} is missing", hash.to_hex())
        })?;
        if header.hash != record.hash
            || header.height != record.height
            || header.chainwork != record.chainwork
            || header.header != request.block.header
            || header.status != record.status
        {
            anyhow::bail!(
                "stored activation header and block record disagree for {}",
                hash.to_hex()
            );
        }
        // Durable status is cacheable evidence, not authority: the local
        // database is untrusted. Re-run header, chainwork, activation-shape,
        // finality, and every contextual state rule over these exact bytes.
        // A process-private exact hash+height proof may skip only the
        // context-independent body/transaction-start/coinbase checks already
        // completed by the native worker.
        let validated = self.validate_import_against_policy(snapshot, request, true, stateless)?;
        if validated.chainwork != record.chainwork {
            anyhow::bail!(
                "stored activation chainwork changed during full revalidation for {}",
                hash.to_hex()
            );
        }
        Ok(validated)
    }

    fn expected_bits_for_import<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        request: &NodeBlockImport,
        parent: Option<&HeaderRecord>,
    ) -> Result<u32> {
        let mut lookup = |hash: &BlockHash| load_header_record(snapshot, hash);
        expected_bits_with_lookup(self.network, request.block.header.time, parent, &mut lookup)
    }

    fn median_time_past<T: ReadSnapshot>(&self, snapshot: &T, tip: &HeaderRecord) -> Result<u64> {
        let mut lookup = |hash: &BlockHash| load_header_record(snapshot, hash);
        median_time_past_with_lookup(tip, &mut lookup)
    }

    fn deployment_state_for_block<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        height: Height,
        previous_hash: BlockHash,
    ) -> Result<DeploymentState> {
        if height == 0 {
            if previous_hash != BlockHash::ZERO {
                anyhow::bail!("genesis deployment state has a non-zero parent");
            }
            return Ok(DeploymentState::from_states([ThresholdState::Defined; 4]));
        }

        let parent = load_header_record(snapshot, &previous_hash)?.ok_or_else(|| {
            anyhow::anyhow!(
                "deployment-state parent {} is missing",
                previous_hash.to_hex()
            )
        })?;
        if parent.height.checked_add(1) != Some(height) || parent.hash != previous_hash {
            anyhow::bail!(
                "deployment-state parent {} is not contiguous with height {height}",
                previous_hash.to_hex()
            );
        }
        let previous = load_deployment_state(snapshot, parent.hash)?.ok_or_else(|| {
            anyhow::anyhow!(
                "deployment-state cache is missing for parent {} at height {}",
                parent.hash.to_hex(),
                parent.height
            )
        })?;
        if previous.height != parent.height {
            anyhow::bail!(
                "deployment-state cache height {} disagrees with parent height {}",
                previous.height,
                parent.height
            );
        }

        let params = self.network.params();
        let mut state = previous.state;
        for deployment in self.network.deployments() {
            let window = deployment.effective_window(params.miner_window);
            if window == 0 {
                anyhow::bail!("deployment {} has a zero window", deployment.name());
            }
            let period = if height.is_multiple_of(window) {
                Some(self.completed_deployment_period(snapshot, &parent, *deployment, window)?)
            } else {
                None
            };
            let next = advance_threshold_state(
                params.activation_threshold,
                params.miner_window,
                *deployment,
                height,
                previous.state.state(deployment.id),
                period,
            )
            .with_context(|| {
                format!(
                    "failed to advance deployment {} for block height {height}",
                    deployment.name()
                )
            })?;
            state = state.with_state(deployment.id, next);
        }
        Ok(state)
    }

    fn completed_deployment_period<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        parent: &HeaderRecord,
        deployment: Deployment,
        window: u32,
    ) -> Result<DeploymentPeriod> {
        let mut lookup = |hash: &BlockHash| load_header_record(snapshot, hash);
        completed_deployment_period_with_lookup(parent, deployment, window, &mut lookup)
    }

    fn commit_staged_block(
        &mut self,
        request: NodeBlockImport,
        validated: ValidatedImport,
        persist_raw_body: bool,
    ) -> Result<NodeBlockMutation> {
        self.ensure_storage_operational()?;
        if self.name_pages.is_some() {
            return self.commit_staged_block_with_name_pages(request, validated, persist_raw_body);
        }
        let snapshot = self.store.snapshot()?;
        let generation = next_mining_generation(&snapshot)?;
        let chain_epoch = next_chain_epoch(&snapshot)?;
        let previous = load_block_index_record(&snapshot, &request.block.hash())?;
        let mut batch = self.store.batch();
        let staged_connect =
            self.stage_connect(&snapshot, &mut batch, &request, validated, persist_raw_body)?;
        let record = staged_connect.current.block.clone();
        let mut index_updates = Vec::with_capacity(staged_connect.pruned.len().saturating_add(1));
        index_updates.push(IndexStatusUpdate {
            previous_block: previous,
            current: staged_connect.current,
        });
        index_updates.extend(staged_connect.pruned);
        batch.put(
            ColumnFamily::Meta,
            MetaKey::MiningGeneration.as_bytes(),
            &encode_u64(generation),
        )?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::ChainEpoch.as_bytes(),
            &encode_u64(chain_epoch),
        )?;
        let publication = self.prepare_index_publication(&index_updates)?;
        drop(snapshot);
        self.commit_index_publication(publication, move |state| {
            state.store.commit(batch)?;
            Ok(())
        })?;

        Ok(NodeBlockMutation {
            record,
            mining: self.durable_mining_state()?,
        })
    }

    fn commit_staged_block_with_name_pages(
        &mut self,
        request: NodeBlockImport,
        validated: ValidatedImport,
        persist_raw_body: bool,
    ) -> Result<NodeBlockMutation> {
        let store = self.store.clone();
        let raw = store.snapshot()?;
        let (reader, legacy_fallback) = self
            .name_pages
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("name-page storage is unavailable"))?
            .reader_for_roots(&raw, std::iter::empty(), false)?;
        debug_assert!(!legacy_fallback);
        let page_base = NamePageSnapshot::new(&raw, &reader);
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&page_base);
        let generation = next_mining_generation(&staged)?;
        let chain_epoch = next_chain_epoch(&staged)?;
        let previous = load_block_index_record(&staged, &request.block.hash())?;
        let mut batch = overlay.batch_with_deferred_name_tree_nodes(store.batch());
        let staged_connect =
            self.stage_connect(&staged, &mut batch, &request, validated, persist_raw_body)?;
        let record = staged_connect.current.block.clone();
        let mut index_updates = Vec::with_capacity(staged_connect.pruned.len().saturating_add(1));
        index_updates.push(IndexStatusUpdate {
            previous_block: previous,
            current: staged_connect.current,
        });
        index_updates.extend(staged_connect.pruned);
        batch.put(
            ColumnFamily::Meta,
            MetaKey::MiningGeneration.as_bytes(),
            &encode_u64(generation),
        )?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::ChainEpoch.as_bytes(),
            &encode_u64(chain_epoch),
        )?;
        let root = load_stored_name_tree_commit_root(&staged)
            .map_err(|error| anyhow::anyhow!("failed to read staged page root: {error}"))?;
        let staged_nodes = overlay.staged_family(ColumnFamily::NameTreeNodes);
        let staged_pins = staged_name_tree_snapshot_pins(&staged, std::iter::once(request.height))?;
        let publication = self.prepare_index_publication(&index_updates)?;
        drop(staged);
        let mut inner = batch.into_inner();
        let prepared = match self
            .name_pages
            .as_mut()
            .expect("page storage checked above")
            .prepare_root(
                &raw,
                &mut inner,
                &reader,
                staged_nodes,
                &staged_pins,
                NamePageRootTarget {
                    root,
                    height: Some(request.height),
                },
            ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.name_pages
                    .as_mut()
                    .expect("page storage checked above")
                    .rollback_uncommitted_tail()?;
                return Err(error);
            }
        };
        drop(raw);
        let publication_result = self.commit_index_publication(publication, move |state| {
            if let Err(error) = store.commit(inner) {
                state
                    .name_pages
                    .as_mut()
                    .expect("page storage checked above")
                    .fence_after_commit_attempt();
                return Err(anyhow::anyhow!(
                    "page-backed block commit outcome is ambiguous and requires node restart: {error}"
                ));
            }
            state
                .name_pages
                .as_mut()
                .expect("page storage checked above")
                .commit_prepared(prepared);
            Ok(())
        });
        if let Err(error) = publication_result {
            self.rollback_uncommitted_name_page_tail_if_safe()?;
            return Err(error);
        }

        Ok(NodeBlockMutation {
            record,
            mining: self.durable_mining_state()?,
        })
    }

    fn commit_prepared_stored_direct_extension(
        &mut self,
        request: NodeBlockImport,
        stateless: StatelessBodyValidation,
    ) -> std::result::Result<NodeBlockMutation, ChainActivationFailure> {
        self.ensure_storage_operational()
            .map_err(ChainActivationFailure::Internal)?;
        let validated = {
            let snapshot = self
                .store
                .snapshot()
                .map_err(anyhow::Error::from)
                .map_err(ChainActivationFailure::Internal)?;
            let hash = request.block.hash();
            let stored = load_block_index_record(&snapshot, &hash)
                .map_err(ChainActivationFailure::Internal)?
                .ok_or_else(|| {
                    ChainActivationFailure::Internal(anyhow::anyhow!(
                        "prepared direct extension {} at height {} is not durably stored",
                        hash.to_hex(),
                        request.height
                    ))
                })?;
            self.validate_stored_activation_with_stateless(
                &snapshot,
                &request,
                &stored,
                Some(stateless),
            )
            .map_err(ChainActivationFailure::Internal)?
        };
        let failure_request = request.clone();
        match self.commit_staged_block(request, validated, false) {
            Ok(mutation) => Ok(mutation),
            Err(error)
                if error
                    .downcast_ref::<StateConnectError>()
                    .is_some_and(|error| error.0.is_consensus_invalid()) =>
            {
                Err(ChainActivationFailure::ContextualInvalid(Box::new(
                    ContextualActivationFailure {
                        request: failure_request,
                        error,
                    },
                )))
            }
            Err(error) => Err(ChainActivationFailure::Internal(error.context(format!(
                "failed to connect stored block {} at height {} through the direct-extension boundary",
                failure_request.block.hash().to_hex(),
                failure_request.height
            )))),
        }
    }

    fn stage_connect<T: ReadSnapshot, B: WriteBatch>(
        &self,
        snapshot: &T,
        batch: &mut B,
        request: &NodeBlockImport,
        validated: ValidatedImport,
        persist_raw_body: bool,
    ) -> Result<StagedConnect> {
        validate_active_extension(snapshot, request, validated.chainwork)?;

        let block_hash = request.block.hash();
        let historical_validation = validated.historical_validation;
        let mut status = validated.status;

        let deployments = self.deployment_state_for_block(
            snapshot,
            request.height,
            request.block.header.prev_block,
        )?;
        if let Some(cached) = load_deployment_state(snapshot, block_hash)? {
            if cached.height != request.height || cached.state != deployments {
                anyhow::bail!(
                    "deployment-state cache for {} disagrees with the active branch",
                    block_hash.to_hex()
                );
            }
        }
        let issuance = AirdropCoinbaseIssuanceVerifier::native(deployments)?;
        let services = StateServices {
            network: self.network,
            name_flags: deployments.name_flags,
            name_flags_valid: true,
            historical_validation,
            input_verifier: self.state_engine.input_verifier(),
            issuance_verifier: &issuance,
        };

        // Derivative indexes require the authenticated UTXO view immediately
        // before this block. In a reorg, `snapshot` already includes every
        // earlier staged disconnect/connect, but not this block's state writes.
        // Stage index writes first so the live overlay cannot hide inputs that
        // the state connector is about to spend. A later validation failure
        // discards the shared batch, so no derivative write is published alone.
        stage_wallet_index_connect(
            snapshot,
            batch,
            &request.block,
            request.height,
            self.wallet_index_profile,
        )
        .map_err(anyhow::Error::new)
        .context("failed to stage wallet indexes")?;

        let state_summary = connect_block_to_batch_with_services(
            snapshot,
            batch,
            ConnectBlock {
                block_hash,
                height: request.height,
                coinbase_maturity: self.network.params().coinbase_maturity,
                block_reward: self.network.params().block_reward(request.height),
                block: &request.block,
            },
            services,
        )
        .map_err(StateConnectError)?;
        if state_summary.historical_validation != historical_validation {
            anyhow::bail!("state engine returned a different historical validation route");
        }

        write_deployment_state(batch, block_hash, request.height, deployments)?;

        status.deployment_state_valid = true;
        status.relative_locks_valid = state_summary.validation.relative_locks_valid;
        status.scripts_valid = state_summary.validation.scripts_valid;
        status.covenant_links_valid = state_summary.validation.covenant_links_valid;
        status.covenants_context_valid = state_summary.validation.covenants_context_valid;
        status.claims_and_airdrops_valid = state_summary.validation.claims_and_airdrops_valid;
        status.utxo_connected = true;
        status.name_state_connected = state_summary.validation.name_state_connected;
        status.tree_root_valid = state_summary.validation.tree_root_valid;
        status.undo_present = true;
        status.active_chain = true;

        let mut record =
            BlockIndexRecord::from_block(&request.block, request.height, validated.chainwork)
                .map_err(|error| anyhow::anyhow!("failed to build block index record: {error}"))?;
        record.status = status.clone();
        record.validated_at = Some(current_unix_time()?);
        let header_record = HeaderRecord {
            hash: block_hash,
            height: request.height,
            chainwork: validated.chainwork,
            header: request.block.header.clone(),
            status,
        };

        write_record_to_batch(batch, &header_record)
            .map_err(anyhow::Error::new)
            .context("failed to stage header index")?;
        write_block_index_to_batch(batch, &record)
            .map_err(anyhow::Error::new)
            .context("failed to stage block index")?;
        if persist_raw_body {
            let raw_record = RawBlockRecord::from_block(&request.block, request.source);
            write_raw_block_to_batch(batch, &raw_record)
                .map_err(anyhow::Error::new)
                .context("failed to stage raw block")?;
        }
        if self.transaction_index {
            write_tx_index_for_block_to_batch(batch, &request.block, request.height)
                .map_err(anyhow::Error::new)
                .context("failed to stage tx index")?;
        }
        write_canonical_height_to_batch(batch, request.height, block_hash)
            .map_err(anyhow::Error::new)
            .context("failed to stage canonical height")?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestBlockHash.as_bytes(),
            block_hash.as_bytes(),
        )?;
        stage_best_header_if_more_work(snapshot, batch, block_hash, validated.chainwork)?;
        let pruned = if let Some(policy) = self.undo_retention_policy {
            stage_due_undo_prune(
                snapshot,
                batch,
                policy,
                request.height,
                self.network.params().names.tree_interval,
            )?
        } else {
            Vec::new()
        };

        Ok(StagedConnect {
            current: StagedIndexRecord {
                block: record,
                header: header_record,
            },
            pruned,
        })
    }

    fn historical_validation_plan_for_block(
        &self,
        height: Height,
        block_hash: BlockHash,
        validation_status: &BlockStatus,
    ) -> Result<HistoricalValidationPlan> {
        if height == 0 || height > self.network.last_checkpoint() {
            return Ok(HistoricalValidationPlan::full());
        }

        // The first configured checkpoint at or above the candidate is enough
        // to prove its ancestry. Waiting for the final network checkpoint made
        // early IBD re-run scripts on thousands of blocks even after a nearer
        // pinned descendant was already canonical.
        let Some(checkpoint) = self
            .network
            .checkpoints()
            .iter()
            .copied()
            .find(|checkpoint| checkpoint.height >= height)
        else {
            return Ok(HistoricalValidationPlan::full());
        };

        let candidate_canonical = self.chain.canonical_hash(height).map_err(|error| {
            anyhow::anyhow!("failed to read canonical header evidence: {error}")
        })?;
        let checkpoint_canonical =
            self.chain
                .canonical_hash(checkpoint.height)
                .map_err(|error| {
                    anyhow::anyhow!("failed to read checkpoint header evidence: {error}")
                })?;
        let checkpoint_record = self
            .chain
            .header(&checkpoint.hash)
            .map_err(|error| anyhow::anyhow!("failed to read checkpoint header: {error}"))?;

        Ok(checkpoint_backed_historical_validation_plan(
            self.network,
            checkpoint,
            height,
            block_hash,
            validation_status,
            candidate_canonical.zip(checkpoint_canonical),
            checkpoint_record.as_ref(),
        ))
    }

    fn disconnect_block(&mut self, request: NodeBlockDisconnect) -> Result<NodeBlockMutation> {
        self.ensure_storage_operational()?;
        if self.name_pages.is_some() {
            return self.disconnect_block_with_name_pages(request);
        }
        let snapshot = self.store.snapshot()?;
        let generation = next_mining_generation(&snapshot)?;
        let chain_epoch = next_chain_epoch(&snapshot)?;
        let previous = load_block_index_record(&snapshot, &request.block_hash)?;
        let mut batch = self.store.batch();
        let current = self.stage_disconnect(&snapshot, &mut batch, request)?;
        let record = current.block.clone();
        batch.put(
            ColumnFamily::Meta,
            MetaKey::MiningGeneration.as_bytes(),
            &encode_u64(generation),
        )?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::ChainEpoch.as_bytes(),
            &encode_u64(chain_epoch),
        )?;
        let publication = self.prepare_index_publication(&[IndexStatusUpdate {
            previous_block: previous,
            current,
        }])?;
        drop(snapshot);
        self.commit_index_publication(publication, move |state| {
            state.store.commit(batch)?;
            Ok(())
        })?;

        Ok(NodeBlockMutation {
            record,
            mining: self.durable_mining_state()?,
        })
    }

    fn disconnect_block_with_name_pages(
        &mut self,
        request: NodeBlockDisconnect,
    ) -> Result<NodeBlockMutation> {
        let store = self.store.clone();
        let raw = store.snapshot()?;
        let required_roots =
            required_name_page_rollback_roots(&raw, std::slice::from_ref(&request))?;
        let (reader, legacy_fallback) = self
            .name_pages
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("name-page storage is unavailable"))?
            .reader_for_roots(&raw, required_roots, true)?;
        let page_base = if legacy_fallback {
            NamePageSnapshot::with_legacy_fallback(&raw, &reader)
        } else {
            NamePageSnapshot::new(&raw, &reader)
        };
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&page_base);
        let generation = next_mining_generation(&staged)?;
        let chain_epoch = next_chain_epoch(&staged)?;
        let previous = load_block_index_record(&staged, &request.block_hash)?;
        let request_height = request.height;
        let mut batch = overlay.batch_with_deferred_name_tree_nodes(store.batch());
        let current = self.stage_disconnect(&staged, &mut batch, request)?;
        let record = current.block.clone();
        batch.put(
            ColumnFamily::Meta,
            MetaKey::MiningGeneration.as_bytes(),
            &encode_u64(generation),
        )?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::ChainEpoch.as_bytes(),
            &encode_u64(chain_epoch),
        )?;
        let root = load_stored_name_tree_commit_root(&staged)
            .map_err(|error| anyhow::anyhow!("failed to read restored page root: {error}"))?;
        let staged_nodes = overlay.staged_family(ColumnFamily::NameTreeNodes);
        // A disconnect can only remove a snapshot pin; page publication needs
        // newly staged pins, so there is no family-wide overlay clone here.
        let staged_pins = Vec::new();
        let publication = self.prepare_index_publication(&[IndexStatusUpdate {
            previous_block: previous,
            current,
        }])?;
        drop(staged);
        let mut inner = batch.into_inner();
        let resulting_height = request_height.checked_sub(1);
        let prepared = match self
            .name_pages
            .as_mut()
            .expect("page storage checked above")
            .prepare_root(
                &raw,
                &mut inner,
                &reader,
                staged_nodes,
                &staged_pins,
                NamePageRootTarget {
                    root,
                    height: resulting_height,
                },
            ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.name_pages
                    .as_mut()
                    .expect("page storage checked above")
                    .rollback_uncommitted_tail()?;
                return Err(error);
            }
        };
        drop(raw);
        let publication_result = self.commit_index_publication(publication, move |state| {
            if let Err(error) = store.commit(inner) {
                state
                    .name_pages
                    .as_mut()
                    .expect("page storage checked above")
                    .fence_after_commit_attempt();
                return Err(anyhow::anyhow!(
                    "page-backed disconnect commit outcome is ambiguous and requires node restart: {error}"
                ));
            }
            state
                .name_pages
                .as_mut()
                .expect("page storage checked above")
                .commit_prepared(prepared);
            Ok(())
        });
        if let Err(error) = publication_result {
            self.rollback_uncommitted_name_page_tail_if_safe()?;
            return Err(error);
        }
        Ok(NodeBlockMutation {
            record,
            mining: self.durable_mining_state()?,
        })
    }

    fn stage_disconnect<T: ReadSnapshot, B: WriteBatch>(
        &self,
        snapshot: &T,
        batch: &mut B,
        request: NodeBlockDisconnect,
    ) -> Result<StagedIndexRecord> {
        let best_hash = snapshot
            .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
            .context("failed to read best block before disconnect")?
            .ok_or_else(|| anyhow::anyhow!("cannot disconnect an empty chain"))
            .and_then(|bytes| block_hash_from_bytes(&bytes))?;
        if best_hash != request.block_hash {
            anyhow::bail!(
                "disconnect target {} is not the canonical tip {}",
                request.block_hash.to_hex(),
                best_hash.to_hex()
            );
        }

        let block = load_block(snapshot, &request.block_hash)?.ok_or_else(|| {
            anyhow::anyhow!("raw block is missing for {}", request.block_hash.to_hex())
        })?;
        let undo = load_block_undo(snapshot, &request.block_hash)?.ok_or_else(|| {
            anyhow::anyhow!("undo is missing for {}", request.block_hash.to_hex())
        })?;
        let mut record =
            load_block_index_record(snapshot, &request.block_hash)?.ok_or_else(|| {
                anyhow::anyhow!("block index is missing for {}", request.block_hash.to_hex())
            })?;

        if record.height != request.height {
            anyhow::bail!(
                "block height mismatch: expected {}, got {}",
                request.height,
                record.height
            );
        }

        if block.header.tree_root != *undo.previous_committed_tree_root.as_bytes() {
            anyhow::bail!("disconnect undo previous root does not match block header commitment");
        }

        record.status.utxo_connected = false;
        record.status.name_state_connected = false;
        record.status.tree_root_valid = false;
        record.status.undo_present = false;
        record.status.active_chain = false;
        let header_record = HeaderRecord {
            hash: request.block_hash,
            height: record.height,
            chainwork: record.chainwork,
            header: block.header.clone(),
            status: record.status.clone(),
        };

        disconnect_block_to_batch(
            snapshot,
            batch,
            DisconnectBlock {
                block_hash: request.block_hash,
                height: request.height,
            },
            &undo,
        )
        .map_err(anyhow::Error::new)
        .context("failed to stage state disconnect")?;
        if self.transaction_index {
            delete_tx_index_for_block_from_batch(batch, &block)
                .map_err(anyhow::Error::new)
                .context("failed to stage tx-index deletion")?;
        }
        stage_wallet_index_disconnect(snapshot, batch, &block, &undo, self.wallet_index_profile)
            .map_err(anyhow::Error::new)
            .context("failed to stage wallet-index disconnect")?;
        write_block_index_to_batch(batch, &record)
            .map_err(anyhow::Error::new)
            .context("failed to stage block index update")?;
        write_record_to_batch(batch, &header_record)
            .map_err(anyhow::Error::new)
            .context("failed to stage header index update")?;
        delete_canonical_height_from_batch(batch, request.height)
            .map_err(anyhow::Error::new)
            .context("failed to stage canonical height delete")?;

        if request.height == 0 {
            batch.delete(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())?;
        } else {
            batch.put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                block.header.prev_block.as_bytes(),
            )?;
        }

        Ok(StagedIndexRecord {
            block: record,
            header: header_record,
        })
    }

    fn apply_reorg(&mut self, request: NodeReorg) -> Result<NodeReorgMutation> {
        self.apply_reorg_with_limits(request, NodeReorgLimits::PRODUCTION)
    }

    fn apply_reorg_with_limits(
        &mut self,
        request: NodeReorg,
        limits: NodeReorgLimits,
    ) -> Result<NodeReorgMutation> {
        self.apply_reorg_classified_with_limits(request, limits)
            .map_err(ChainActivationFailure::into_anyhow)
    }

    fn apply_reorg_classified_prepared(
        &mut self,
        request: NodeReorg,
        prepared: PreparedNativeActivation,
    ) -> std::result::Result<NodeReorgMutation, ChainActivationFailure> {
        self.apply_reorg_classified_with_limits_and_prepared(
            request,
            NodeReorgLimits::PRODUCTION,
            Some(prepared),
        )
    }

    fn apply_reorg_classified_with_limits(
        &mut self,
        request: NodeReorg,
        limits: NodeReorgLimits,
    ) -> std::result::Result<NodeReorgMutation, ChainActivationFailure> {
        self.apply_reorg_classified_with_limits_and_prepared(request, limits, None)
    }

    fn apply_reorg_classified_with_limits_and_prepared(
        &mut self,
        request: NodeReorg,
        limits: NodeReorgLimits,
        prepared: Option<PreparedNativeActivation>,
    ) -> std::result::Result<NodeReorgMutation, ChainActivationFailure> {
        validate_reorg_counts(&request, limits).map_err(ChainActivationFailure::Internal)?;
        if let Some(prepared) = prepared.as_ref() {
            prepared
                .authenticate(&request)
                .context("prepared native activation proof mismatch")
                .map_err(ChainActivationFailure::Internal)?;
        }
        let mut prepared = prepared.map(PreparedNativeActivation::into_by_identity);
        self.ensure_storage_operational()
            .map_err(ChainActivationFailure::Internal)?;
        if request.disconnect.is_empty() && request.connect.is_empty() {
            return Ok(NodeReorgMutation {
                summary: NodeReorgSummary::default(),
                mining: self
                    .durable_mining_state()
                    .map_err(ChainActivationFailure::Internal)?,
            });
        }
        if request.connect.is_empty() {
            return Err(ChainActivationFailure::Internal(anyhow::anyhow!(
                "a best-chain reorganization must connect a replacement tip"
            )));
        }

        let store = self.store.clone();
        let raw_base = store
            .snapshot()
            .map_err(anyhow::Error::from)
            .map_err(ChainActivationFailure::Internal)?;
        let required_page_roots = preflight_reorg_page_roots(&raw_base, &request, limits)
            .map_err(ChainActivationFailure::Internal)?;
        let (page_reader, legacy_page_fallback) = match self.name_pages.as_ref() {
            Some(pages) => {
                let (reader, legacy_fallback) = pages
                    .reader_for_roots(&raw_base, required_page_roots, true)
                    .map_err(ChainActivationFailure::Internal)?;
                (Some(reader), legacy_fallback)
            }
            None => (None, false),
        };
        let base = match page_reader.as_ref() {
            Some(reader) if legacy_page_fallback => {
                NodeReadSnapshot::Pages(NamePageSnapshot::with_legacy_fallback(&raw_base, reader))
            }
            Some(reader) => NodeReadSnapshot::Pages(NamePageSnapshot::new(&raw_base, reader)),
            None => NodeReadSnapshot::Base(&raw_base),
        };
        let original_tip =
            best_block_tip_from_snapshot(&base).map_err(ChainActivationFailure::Internal)?;
        validate_reorg_request_shape(&base, &request, original_tip.as_ref())
            .map_err(ChainActivationFailure::Internal)?;
        let mut previous_block_records = HashMap::new();
        for hash in request
            .disconnect
            .iter()
            .map(|item| item.block_hash)
            .chain(request.connect.iter().map(|item| item.block.hash()))
        {
            if previous_block_records.contains_key(&hash) {
                return Err(ChainActivationFailure::Internal(anyhow::anyhow!(
                    "reorganization repeats block {}",
                    hash.to_hex()
                )));
            }
            let previous =
                load_block_index_record(&base, &hash).map_err(ChainActivationFailure::Internal)?;
            previous_block_records.insert(hash, previous);
        }

        let generation = next_mining_generation(&base).map_err(ChainActivationFailure::Internal)?;
        let chain_epoch = next_chain_epoch(&base).map_err(ChainActivationFailure::Internal)?;
        let staged_pin_heights = request
            .connect
            .iter()
            .map(NodeBlockImport::height)
            .collect::<Vec<_>>();
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let staged_batch = if self.name_pages.is_some() {
            overlay.batch_with_deferred_name_tree_nodes(store.batch())
        } else {
            overlay.batch(store.batch())
        };
        let mut batch = ReorgMeteredBatch::new(
            staged_batch,
            ReorgStagedEffectMeter::new(limits.maximum_staged_effect_bytes),
            REORG_STAGING_OPERATION_COPIES,
        );
        let mut summary = NodeReorgSummary::default();
        let mut index_updates = Vec::new();

        for disconnect in request.disconnect {
            let previous = previous_block_records
                .get(&disconnect.block_hash)
                .cloned()
                .ok_or_else(|| {
                    ChainActivationFailure::Internal(anyhow::anyhow!(
                        "reorganization cache plan omitted block {}",
                        disconnect.block_hash.to_hex()
                    ))
                })?;
            let current = self
                .stage_disconnect(&staged, &mut batch, disconnect)
                .map_err(ChainActivationFailure::Internal)?;
            summary.disconnected.push(current.block.clone());
            index_updates.push(IndexStatusUpdate {
                previous_block: previous,
                current,
            });
        }

        for connect in request.connect {
            let hash = connect.block.hash();
            let stateless = prepared
                .as_mut()
                .and_then(|proofs| proofs.remove(&(hash, connect.height)));
            // Strict stored bodies are fully revalidated here because durable
            // status and bytes are both forgeable under the local-DB threat
            // model. Fixture imports retain their explicit test-only policy.
            let stored_record = load_block_index_record(&staged, &hash)
                .map_err(ChainActivationFailure::Internal)?;
            let persist_raw_body = stored_record.is_none();
            let validated = match stored_record.as_ref() {
                Some(stored_record)
                    if matches!(connect.validation, ImportValidationPolicy::Strict) =>
                {
                    self.validate_stored_activation_with_stateless(
                        &staged,
                        &connect,
                        stored_record,
                        stateless,
                    )
                    .with_context(|| {
                        format!(
                            "failed to authenticate stored block {} at height {}",
                            hash.to_hex(),
                            connect.height
                        )
                    })
                }
                Some(_) | None => self
                    .validate_import_against_policy(&staged, &connect, true, stateless)
                    .with_context(|| {
                        format!(
                            "failed to validate unstored block {} at height {}",
                            hash.to_hex(),
                            connect.height
                        )
                    }),
            }
            .map_err(ChainActivationFailure::Internal)?;
            let staged_connect = match self.stage_connect(
                &staged,
                &mut batch,
                &connect,
                validated,
                persist_raw_body,
            ) {
                Ok(record) => record,
                Err(error)
                    if error
                        .downcast_ref::<StateConnectError>()
                        .is_some_and(|error| error.0.is_consensus_invalid()) =>
                {
                    return Err(ChainActivationFailure::ContextualInvalid(Box::new(
                        ContextualActivationFailure {
                            request: connect,
                            error,
                        },
                    )));
                }
                Err(error) => {
                    return Err(ChainActivationFailure::Internal(error.context(format!(
                        "failed to connect stored block {} at height {}",
                        hash.to_hex(),
                        connect.height
                    ))));
                }
            };
            let previous = previous_block_records.get(&hash).cloned().ok_or_else(|| {
                ChainActivationFailure::Internal(anyhow::anyhow!(
                    "reorganization cache plan omitted block {}",
                    hash.to_hex()
                ))
            })?;
            summary.connected.push(staged_connect.current.block.clone());
            index_updates.push(IndexStatusUpdate {
                previous_block: previous,
                current: staged_connect.current,
            });
            index_updates.extend(staged_connect.pruned);
        }

        if prepared.as_ref().is_some_and(|proofs| !proofs.is_empty()) {
            return Err(ChainActivationFailure::Internal(anyhow::anyhow!(
                "prepared native activation retained an unmatched proof"
            )));
        }

        let final_tip = best_block_tip_from_snapshot(&staged)
            .map_err(ChainActivationFailure::Internal)?
            .ok_or_else(|| {
                ChainActivationFailure::Internal(anyhow::anyhow!(
                    "reorganization produced an empty active chain"
                ))
            })?;
        if let Some(original_tip) = &original_tip {
            if final_tip.chainwork <= original_tip.chainwork {
                return Err(ChainActivationFailure::Internal(anyhow::anyhow!(
                    "replacement tip chainwork {} does not exceed active tip chainwork {}",
                    final_tip.chainwork.to_fixed_hex(),
                    original_tip.chainwork.to_fixed_hex()
                )));
            }
        }
        let connected_tip = summary.connected.last().ok_or_else(|| {
            ChainActivationFailure::Internal(anyhow::anyhow!(
                "reorganization connected no replacement block"
            ))
        })?;
        if connected_tip.hash != final_tip.hash {
            return Err(ChainActivationFailure::Internal(anyhow::anyhow!(
                "reorganization final tip does not match its last connected block"
            )));
        }

        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::MiningGeneration.as_bytes(),
                &encode_u64(generation),
            )
            .map_err(anyhow::Error::from)
            .map_err(ChainActivationFailure::Internal)?;
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::ChainEpoch.as_bytes(),
                &encode_u64(chain_epoch),
            )
            .map_err(anyhow::Error::from)
            .map_err(ChainActivationFailure::Internal)?;
        let root = load_stored_name_tree_commit_root(&staged)
            .map_err(anyhow::Error::from)
            .map_err(ChainActivationFailure::Internal)?;
        let staged_nodes = if self.name_pages.is_some() {
            overlay.staged_family(ColumnFamily::NameTreeNodes)
        } else {
            BTreeMap::new()
        };
        let staged_pins = if self.name_pages.is_some() {
            staged_name_tree_snapshot_pins(&staged, staged_pin_heights)
                .map_err(ChainActivationFailure::Internal)?
        } else {
            Vec::new()
        };
        let publication = self
            .prepare_index_publication(&index_updates)
            .map_err(ChainActivationFailure::Internal)?;
        let (batch, meter) = batch.into_parts();
        let mut batch = ReorgMeteredBatch::new(
            batch.into_inner(),
            meter,
            REORG_PUBLICATION_OPERATION_COPIES,
        );
        drop(staged);
        drop(overlay);
        let prepared_page_state =
            if let (Some(pages), Some(reader)) = (self.name_pages.as_mut(), page_reader.as_ref()) {
                match pages.prepare_root(
                    &raw_base,
                    &mut batch,
                    reader,
                    staged_nodes,
                    &staged_pins,
                    NamePageRootTarget {
                        root,
                        height: Some(final_tip.height),
                    },
                ) {
                    Ok(prepared) => Some(prepared),
                    Err(error) => {
                        pages
                            .rollback_uncommitted_tail()
                            .map_err(ChainActivationFailure::Internal)?;
                        return Err(ChainActivationFailure::Internal(error));
                    }
                }
            } else {
                None
            };
        let (batch, mut meter) = batch.into_parts();
        #[cfg(test)]
        {
            let reject = TEST_REORG_REJECT_AT_ARCHIVE_PREFLIGHT.with(|enabled| enabled.get())
                && TEST_REORG_APPENDED_NAME_PAGE_BYTES.with(|bytes| bytes.get() > 0);
            if reject {
                meter.limit = meter.consumed;
            }
        }
        drop(raw_base);
        let publication_result = self.commit_index_publication(publication, move |state| {
            match store.commit_with_effect_budget(batch, &mut meter) {
                Ok(()) => {}
                Err(
                    error @ StoreError::LimitExceeded {
                        context: ReorgStagedEffectMeter::CONTEXT,
                        ..
                    },
                ) => {
                    // The archive-aware budget boundary rejects before moving
                    // payloads, extending its batch, or appending a segment.
                    // The already-prepared name-page tail is therefore known
                    // uncommitted and the outer error path may truncate it.
                    return Err(error.into());
                }
                Err(error) => {
                    if let Some(pages) = state.name_pages.as_mut() {
                        pages.fence_after_commit_attempt();
                    }
                    return Err(anyhow::anyhow!(
                        "page-backed reorganization commit outcome is ambiguous and requires node restart: {error}"
                    ));
                }
            }
            if let (Some(pages), Some(prepared)) =
                (state.name_pages.as_mut(), prepared_page_state)
            {
                pages.commit_prepared(prepared);
            }
            Ok(())
        });
        if let Err(error) = publication_result {
            self.rollback_uncommitted_name_page_tail_if_safe()
                .map_err(ChainActivationFailure::Internal)?;
            return Err(ChainActivationFailure::Internal(error));
        }

        Ok(NodeReorgMutation {
            summary,
            mining: self
                .durable_mining_state()
                .map_err(ChainActivationFailure::Internal)?,
        })
    }

    /// Validate a bounded old/new index delta before its durable transaction
    /// commits. The block side is applied to a fixed-size staged cache clone;
    /// the header side stages only the new or status-changed records, so
    /// publication cannot rebuild or duplicate the complete resident index.
    fn prepare_index_publication(
        &self,
        records: &[IndexStatusUpdate],
    ) -> Result<PreparedIndexPublication> {
        if records.is_empty() {
            let headers = self
                .chain
                .prepare_cache_update(&[])
                .map_err(|error| anyhow::anyhow!("failed to stage empty header cache: {error}"))?;
            let blocks = self
                .blocks
                .prepare_cache_update(&[])
                .map_err(|error| anyhow::anyhow!("failed to stage empty block cache: {error}"))?;
            return Ok(PreparedIndexPublication { headers, blocks });
        }
        let headers = records
            .iter()
            .map(|record| record.current.header.clone())
            .collect::<Vec<_>>();
        let headers = self
            .chain
            .prepare_cache_update(&headers)
            .map_err(|error| anyhow::anyhow!("invalid header cache publication: {error}"))?;
        let replacements = records
            .iter()
            .map(|record| (record.previous_block.clone(), record.current.block.clone()))
            .collect::<Vec<_>>();
        let blocks = self
            .blocks
            .prepare_cache_update(&replacements)
            .map_err(|error| anyhow::anyhow!("invalid block cache publication: {error}"))?;
        Ok(PreparedIndexPublication { headers, blocks })
    }

    fn commit_index_publication<T>(
        &mut self,
        publication: PreparedIndexPublication,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let chain = self.chain.clone();
        chain.write_exclusive(|header_index| {
            header_index
                .validate_cache_update(&publication.headers)
                .map_err(|error| anyhow::anyhow!("stale header cache publication: {error}"))?;
            self.blocks
                .validate_cache_update(&publication.blocks)
                .map_err(|error| anyhow::anyhow!("stale block cache publication: {error}"))?;
            let result = operation(self)?;
            header_index.apply_validated_cache_update(publication.headers);
            self.blocks.publish_cache_update(publication.blocks);
            Ok(result)
        })
    }

    /// A stale generation is rejected before the durable operation runs. Page
    /// preparation may already have appended an uncommitted physical tail, so
    /// reclaim it on that path. An attempted database commit fences page
    /// storage first; an ambiguous outcome must never be truncated in-process.
    fn rollback_uncommitted_name_page_tail_if_safe(&mut self) -> Result<()> {
        let Some(pages) = self.name_pages.as_mut() else {
            return Ok(());
        };
        if pages.reopen_required {
            return Ok(());
        }
        pages.rollback_uncommitted_tail()
    }

    pub fn compact_name_tree_nodes(&mut self) -> Result<NameTreeCompactionCheckpoint> {
        self.ensure_storage_operational()?;
        if self.name_pages.is_some() {
            anyhow::bail!(
                "legacy RocksDB name-node compaction is disabled after append-only page storage is active"
            );
        }
        self.compact_name_tree_nodes_with_interval(None)?
            .ok_or_else(|| anyhow::anyhow!("name-tree compaction requires an active block tip"))
    }

    fn compact_name_tree_nodes_if_due(
        &mut self,
        interval: Height,
    ) -> Result<Option<NameTreeCompactionCheckpoint>> {
        self.ensure_storage_operational()?;
        if interval == 0 {
            anyhow::bail!("name-tree compaction startup interval must be non-zero");
        }
        // Page-backed nodes never add records to the legacy LSM column. Its
        // existing contents remain a migration/reorg fallback until the
        // explicit legacy-retirement pass has copied every retained root.
        if self.name_pages.is_some() {
            return Ok(None);
        }
        self.compact_name_tree_nodes_with_interval(Some(interval))
    }

    fn compact_name_tree_nodes_with_interval(
        &mut self,
        interval: Option<Height>,
    ) -> Result<Option<NameTreeCompactionCheckpoint>> {
        self.ensure_storage_operational()?;
        let snapshot = self.store.snapshot()?;
        let Some(tip) = best_block_tip_from_snapshot(&snapshot)? else {
            return Ok(None);
        };
        if let Some(interval) = interval {
            let previous = load_name_tree_compaction_checkpoint(&snapshot)?;
            let due = match previous {
                Some(previous) if tip.height >= previous.height => {
                    tip.height - previous.height >= interval
                }
                Some(_) => true,
                None => tip.height >= interval,
            };
            if !due {
                return Ok(None);
            }
        }

        drop(snapshot);
        let summary =
            compact_name_tree_nodes_streaming(&self.store, NAME_TREE_COMPACTION_DELETE_BATCH)
                .map_err(|error| anyhow::anyhow!("failed to compact durable name tree: {error}"))?;
        let snapshot = self.store.snapshot()?;
        if best_block_tip_from_snapshot(&snapshot)?.as_ref() != Some(&tip) {
            anyhow::bail!("active tip changed during name-tree compaction");
        }
        drop(snapshot);
        let checkpoint = NameTreeCompactionCheckpoint {
            height: tip.height,
            tip: tip.hash,
            summary,
        };
        let mut batch = self.store.batch();
        batch.put(
            ColumnFamily::Snapshots,
            NAME_TREE_COMPACTION_CHECKPOINT_KEY,
            &checkpoint.encode()?,
        )?;
        self.store.commit(batch)?;
        Ok(Some(checkpoint))
    }

    fn prune_undo_history_to_policy(&mut self) -> Result<()> {
        self.ensure_storage_operational()?;
        let policy = self.undo_retention_policy.ok_or_else(|| {
            anyhow::anyhow!("payload retention pruning requested without an active policy")
        })?;
        policy.validate()?;
        loop {
            let snapshot = self.store.snapshot()?;
            let Some(tip) = best_block_tip_from_snapshot(&snapshot)? else {
                break;
            };
            let Some(target) = undo_prune_target(
                tip.height,
                policy.prune_after_height,
                policy.keep_blocks,
                self.network.params().names.tree_interval,
            ) else {
                break;
            };
            let previous = load_undo_pruning_checkpoint(&snapshot)?;
            let first_prunable = policy
                .prune_after_height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("payload-pruning height exhausted"))?;
            let undo_start = previous
                .as_ref()
                .map(|state| state.pruned_through.saturating_add(1))
                .unwrap_or(first_prunable)
                .max(first_prunable);
            let block_start = previous
                .as_ref()
                .map(|state| state.blocks_pruned_through.saturating_add(1))
                .unwrap_or(first_prunable)
                .max(first_prunable);
            if undo_start > target && block_start > target {
                break;
            }
            let start = undo_start.min(block_start);
            let batch_end = start
                .saturating_add((MAX_UNDO_PRUNES_PER_BATCH - 1) as u32)
                .min(target);
            let mut batch = self.store.batch();
            let mut pruned_undos = previous.as_ref().map_or(0, |state| state.pruned_undos);
            let mut pruned_blocks = previous.as_ref().map_or(0, |state| state.pruned_blocks);
            let mut last_hash = None;
            let mut index_updates = Vec::new();
            for height in start..=batch_end {
                let (update, undo_pruned, block_pruned) =
                    stage_prune_payload_height(&snapshot, &mut batch, height)?;
                let hash = update.current.block.hash;
                if undo_pruned {
                    pruned_undos = pruned_undos
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("pruned undo count exhausted"))?;
                }
                if block_pruned {
                    pruned_blocks = pruned_blocks
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("pruned block count exhausted"))?;
                }
                last_hash = Some(hash);
                index_updates.push(update);
            }
            let last_hash = last_hash
                .ok_or_else(|| anyhow::anyhow!("payload-pruning batch contained no heights"))?;
            let previous_undo_through = previous
                .as_ref()
                .map_or(policy.prune_after_height, |state| state.pruned_through);
            let previous_block_through = previous
                .as_ref()
                .map_or(policy.prune_after_height, |state| {
                    state.blocks_pruned_through.max(policy.prune_after_height)
                });
            let pruned_through = previous_undo_through.max(batch_end);
            let blocks_pruned_through = previous_block_through.max(batch_end);
            let checkpoint = UndoPruningCheckpoint {
                pruned_through,
                block_hash: if pruned_through == batch_end {
                    last_hash
                } else {
                    previous
                        .as_ref()
                        .map(|state| state.block_hash)
                        .ok_or_else(|| anyhow::anyhow!("missing undo-pruning checkpoint hash"))?
                },
                pruned_undos,
                blocks_pruned_through,
                blocks_checkpoint: if blocks_pruned_through == batch_end {
                    last_hash
                } else {
                    previous
                        .as_ref()
                        .map(|state| state.blocks_checkpoint)
                        .ok_or_else(|| anyhow::anyhow!("missing block-pruning checkpoint hash"))?
                },
                pruned_blocks,
            };
            batch.put(
                ColumnFamily::Snapshots,
                UNDO_PRUNING_CHECKPOINT_KEY,
                &checkpoint.encode(),
            )?;
            let publication = self.prepare_index_publication(&index_updates)?;
            drop(snapshot);
            self.commit_index_publication(publication, move |state| {
                state.store.commit(batch)?;
                Ok(())
            })?;
        }
        Ok(())
    }

    fn compact_pruned_payload_segments_if_due(&self) -> Result<()> {
        self.ensure_storage_operational()?;
        let limits = SegmentCompactionLimits {
            max_live_frame_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
            ..SegmentCompactionLimits::default()
        };
        let execution = SegmentCompactionExecutionLimits {
            max_physical_output_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
            minimum_filesystem_reserve_bytes: MINIMUM_PRODUCTION_FILESYSTEM_RESERVE_BYTES,
            ..SegmentCompactionExecutionLimits::default()
        };
        let plan = match self
            .store
            .inspect_segment_archive_compaction_with_execution_limits(limits, execution)
        {
            Ok(plan) => plan,
            Err(error) => {
                if let Some(fence) = production_fence_from_store_error(
                    ProductionSafetyFenceKind::PayloadSegmentCompaction,
                    &error,
                ) {
                    self.chain.record_external_safety_fence(fence)?;
                    tracing::warn!(
                        error = %error,
                        "deferred payload-segment compaction behind a durable production safety fence"
                    );
                    return Ok(());
                }
                return Err(error).context("failed to inspect pruned payload segments");
            }
        };
        if plan.reclaimable_frame_bytes < PAYLOAD_SEGMENT_COMPACTION_MIN_DEAD_BYTES {
            return Ok(());
        }
        let report = match self
            .store
            .compact_segment_archive_with_execution_limits(limits, execution)
        {
            Ok(report) => report,
            Err(error) => {
                if let Some(fence) = production_fence_from_store_error(
                    ProductionSafetyFenceKind::PayloadSegmentCompaction,
                    &error,
                ) {
                    self.chain.record_external_safety_fence(fence)?;
                    tracing::warn!(
                        error = %error,
                        "deferred payload-segment compaction behind a durable production safety fence"
                    );
                    return Ok(());
                }
                return Err(error).context("failed to compact pruned payload segments");
            }
        };
        tracing::info!(
            previous_block_generation = report.previous_block_generation,
            previous_undo_generation = report.previous_undo_generation,
            generation = report.generation,
            live_records = report.live_records,
            reclaimed_frame_bytes = report.reclaimed_frame_bytes,
            "compacted pruned block/undo payload segments"
        );
        Ok(())
    }

    fn compact_pruned_name_pages_if_due(&mut self) -> Result<Option<NamePageCompactionReport>> {
        self.ensure_storage_operational()?;
        let Some(name_pages) = self.name_pages.as_mut() else {
            return Ok(None);
        };
        if name_pages.state.manifest.active_segment < NAME_PAGE_COMPACTION_SEGMENT_THRESHOLD {
            return Ok(None);
        }
        let report = match name_pages.compact_generation(&self.store) {
            Ok(report) => report,
            Err(error)
                if error
                    .downcast_ref::<NamePageCompactionDeferred>()
                    .is_some() =>
            {
                tracing::warn!(
                    error = %error,
                    generation =
                        name_pages.state.manifest.generation,
                    active_segment =
                        name_pages.state.manifest.active_segment,
                    "deferred name-page compaction after its bounded pre-publication deadline; the authoritative generation remains unchanged"
                );
                return Ok(None);
            }
            Err(error) => {
                if let Some(fence) = production_fence_from_name_page_error(
                    ProductionSafetyFenceKind::NamePageCompaction,
                    &error,
                ) {
                    self.chain.record_external_safety_fence(fence)?;
                    tracing::warn!(
                        error = %error,
                        "deferred name-page compaction behind a durable production safety fence"
                    );
                    return Ok(None);
                }
                return Err(error).context("failed to compact pruned name pages");
            }
        };
        Ok(Some(report))
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::memory()
    }
}

fn checkpoint_backed_historical_validation_plan(
    network: Network,
    checkpoint: Checkpoint,
    candidate_height: Height,
    candidate_hash: BlockHash,
    candidate_status: &BlockStatus,
    canonical_path: Option<(BlockHash, BlockHash)>,
    checkpoint_record: Option<&HeaderRecord>,
) -> HistoricalValidationPlan {
    let full = HistoricalValidationPlan::full();
    if candidate_height == 0
        || candidate_height > checkpoint.height
        || network.checkpoint(checkpoint.height) != Some(checkpoint)
        || !candidate_status.header_context_valid
        || !candidate_status.checkpoint_valid
        || candidate_status.failed
    {
        return full;
    }

    // At the checkpoint itself the strictly validated candidate hash supplies
    // the evidence even when block delivery did not follow headers-first sync.
    // Earlier candidates must be on the same best validated header path as the
    // exact selected checkpoint. Two canonical-height lookups make that ancestry
    // proof constant-time without consulting the active block-height index.
    let checkpoint_evidenced = if candidate_height == checkpoint.height {
        candidate_hash == checkpoint.hash
    } else {
        canonical_path == Some((candidate_hash, checkpoint.hash))
            && checkpoint_record.is_some_and(|record| {
                record.hash == checkpoint.hash
                    && record.height == checkpoint.height
                    && record.header.hash() == checkpoint.hash
                    && record.status.header_context_valid
                    && record.status.checkpoint_valid
                    && !record.status.failed
            })
    };
    if !checkpoint_evidenced {
        return full;
    }

    HistoricalScriptPolicy::new(network, true)
        .with_verified_checkpoint(checkpoint.height, &checkpoint.hash)
        .map_or(full, |policy| policy.validation_plan(candidate_height))
}

fn load_header_record(
    snapshot: &impl ReadSnapshot,
    hash: &BlockHash,
) -> Result<Option<HeaderRecord>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Headers, hash.as_bytes())
        .context("failed to read header record")?
    else {
        return Ok(None);
    };
    let record = HeaderRecord::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("failed to decode header record: {error}"))?;
    if record.hash != *hash || record.header.hash() != *hash {
        anyhow::bail!(
            "header record at key {} has inconsistent embedded identity {} / {}",
            hash.to_hex(),
            record.hash.to_hex(),
            record.header.hash().to_hex()
        );
    }
    Ok(Some(record))
}

fn load_block_index_record(
    snapshot: &impl ReadSnapshot,
    hash: &BlockHash,
) -> Result<Option<BlockIndexRecord>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::BlockIndex, hash.as_bytes())
        .context("failed to read block index record")?
    else {
        return Ok(None);
    };
    let record = BlockIndexRecord::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("failed to decode block index record: {error}"))?;
    if record.hash != *hash {
        anyhow::bail!(
            "block index record at key {} has embedded hash {}",
            hash.to_hex(),
            record.hash.to_hex()
        );
    }
    Ok(Some(record))
}

fn validate_durable_block_index_bindings(snapshot: &impl ReadSnapshot) -> Result<()> {
    let mut cursor = None;
    loop {
        let page = snapshot
            .scan_prefix_page(
                ColumnFamily::BlockIndex,
                b"",
                cursor.as_deref(),
                PrefixScanBudget {
                    max_entries: BLOCK_INDEX_AUDIT_PAGE_ENTRIES,
                    max_bytes: BLOCK_INDEX_AUDIT_PAGE_BYTES,
                },
            )
            .context("failed to page durable block index")?;
        for (key, bytes) in page.entries {
            let record = BlockIndexRecord::decode(&bytes)
                .map_err(|error| anyhow::anyhow!("failed to decode block index: {error}"))?;
            if key.as_slice() != record.hash.as_bytes() {
                anyhow::bail!(
                    "block index key disagrees with embedded hash {}",
                    record.hash.to_hex()
                );
            }
            validate_block_header_binding(snapshot, &record)?;
            let canonical = read_canonical_hash(snapshot, record.height)?;
            if record.status.active_chain {
                if canonical != Some(record.hash) {
                    anyhow::bail!(
                        "active block index {} is not reverse-bound at height {}",
                        record.hash.to_hex(),
                        record.height
                    );
                }
            } else if canonical == Some(record.hash) {
                anyhow::bail!(
                    "non-active block index {} occupies canonical height {}",
                    record.hash.to_hex(),
                    record.height
                );
            }
        }
        match page.continuation {
            Some(next) => {
                if cursor.as_ref().is_some_and(|previous| previous >= &next) {
                    anyhow::bail!("block-index audit page cursor did not advance");
                }
                cursor = Some(next);
            }
            None => break,
        }
    }

    let best = best_block_tip_from_snapshot(snapshot)?;
    let mut cursor = None;
    let mut expected_height = 0u32;
    let mut last = None;
    loop {
        let page = snapshot
            .scan_prefix_page(
                ColumnFamily::HeightIndex,
                b"",
                cursor.as_deref(),
                PrefixScanBudget {
                    max_entries: BLOCK_INDEX_AUDIT_PAGE_ENTRIES,
                    max_bytes: BLOCK_INDEX_AUDIT_PAGE_BYTES,
                },
            )
            .context("failed to page durable active-height index")?;
        for (height_key, hash_bytes) in page.entries {
            let height = decode_height_key(&height_key)?;
            if height != expected_height {
                anyhow::bail!(
                    "active-height index is not exactly contiguous at expected height {expected_height}"
                );
            }
            let hash = block_hash_from_bytes(&hash_bytes)?;
            let record = load_block_index_record(snapshot, &hash)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "active-height {} points to missing block index {}",
                    height,
                    hash.to_hex()
                )
            })?;
            validate_block_header_binding(snapshot, &record)?;
            if record.height != height || !record.status.active_chain {
                anyhow::bail!(
                    "active-height {} points to non-active block {}",
                    height,
                    hash.to_hex()
                );
            }
            last = Some((height, hash));
            expected_height = expected_height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("active-height index exhausted u32"))?;
        }
        match page.continuation {
            Some(next) => {
                if cursor.as_ref().is_some_and(|previous| previous >= &next) {
                    anyhow::bail!("active-height audit page cursor did not advance");
                }
                cursor = Some(next);
            }
            None => break,
        }
    }

    match (best, last) {
        (None, None) => Ok(()),
        (None, Some(_)) => anyhow::bail!("active-height index exists without a best-block binding"),
        (Some(_), None) => {
            anyhow::bail!("best-block binding exists without an active-height index")
        }
        (Some(best), Some((height, hash)))
            if best.height == height
                && best.hash == hash
                && expected_height == best.height.checked_add(1).unwrap_or(0) =>
        {
            Ok(())
        }
        (Some(best), Some((height, hash))) => anyhow::bail!(
            "active-height tip {} at height {} disagrees with best block {} at height {}",
            hash.to_hex(),
            height,
            best.hash.to_hex(),
            best.height
        ),
    }
}

fn validate_block_header_binding(
    snapshot: &impl ReadSnapshot,
    record: &BlockIndexRecord,
) -> Result<HeaderRecord> {
    let header = load_header_record(snapshot, &record.hash)?.ok_or_else(|| {
        anyhow::anyhow!(
            "block index {} has no matching header record",
            record.hash.to_hex()
        )
    })?;
    if header.hash != record.hash
        || header.height != record.height
        || header.header.prev_block != record.prev_hash
        || header.chainwork != record.chainwork
        || header.status != record.status
    {
        anyhow::bail!(
            "block index {} disagrees with its revalidated header",
            record.hash.to_hex()
        );
    }
    Ok(header)
}

fn load_block(snapshot: &impl ReadSnapshot, hash: &BlockHash) -> Result<Option<Block>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Blocks, hash.as_bytes())
        .context("failed to read raw block record")?
    else {
        return Ok(None);
    };
    let raw = RawBlockRecord::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("failed to decode raw block record: {error}"))?;
    if raw.hash != *hash {
        anyhow::bail!(
            "raw block record at key {} has embedded hash {}",
            hash.to_hex(),
            raw.hash.to_hex()
        );
    }
    raw.decode_block()
        .map(Some)
        .map_err(|error| anyhow::anyhow!("failed to decode raw block: {error}"))
}

fn load_block_undo(snapshot: &impl ReadSnapshot, hash: &BlockHash) -> Result<Option<BlockUndo>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Undo, hash.as_bytes())
        .context("failed to read block undo")?
    else {
        return Ok(None);
    };
    BlockUndo::decode(&bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("failed to decode block undo: {error}"))
}

pub fn load_name_tree_compaction_checkpoint(
    snapshot: &impl ReadSnapshot,
) -> Result<Option<NameTreeCompactionCheckpoint>> {
    snapshot
        .get(ColumnFamily::Snapshots, NAME_TREE_COMPACTION_CHECKPOINT_KEY)
        .context("failed to read name-tree compaction checkpoint")?
        .map(|raw| NameTreeCompactionCheckpoint::decode(&raw))
        .transpose()
}

pub fn load_undo_pruning_checkpoint(
    snapshot: &impl ReadSnapshot,
) -> Result<Option<UndoPruningCheckpoint>> {
    snapshot
        .get(ColumnFamily::Snapshots, UNDO_PRUNING_CHECKPOINT_KEY)
        .context("failed to read undo-pruning checkpoint")?
        .map(|raw| UndoPruningCheckpoint::decode(&raw))
        .transpose()
}

fn undo_prune_target(
    tip_height: Height,
    prune_after_height: Height,
    keep_blocks: u32,
    tree_interval: Height,
) -> Option<Height> {
    if tree_interval == 0 {
        return None;
    }
    let retention_target = tip_height.checked_sub(keep_blocks)?;
    // Pending interval changes are reconstructed and audited from undo. Never
    // retire those records before the next authenticated boundary commits.
    let last_committed_boundary = tip_height - (tip_height % tree_interval);
    let target = retention_target.min(last_committed_boundary);
    (target > prune_after_height).then_some(target)
}

fn stage_due_undo_prune<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    policy: UndoRetentionPolicy,
    tip_height: Height,
    tree_interval: Height,
) -> Result<Vec<IndexStatusUpdate>> {
    policy.validate()?;
    let Some(target) = undo_prune_target(
        tip_height,
        policy.prune_after_height,
        policy.keep_blocks,
        tree_interval,
    ) else {
        return Ok(Vec::new());
    };
    let previous = load_undo_pruning_checkpoint(snapshot)?;
    if previous.as_ref().is_some_and(|state| {
        state.pruned_through >= target && state.blocks_pruned_through >= target
    }) {
        return Ok(Vec::new());
    }
    let first_prunable = policy.prune_after_height.saturating_add(1);
    let undo_expected = previous
        .as_ref()
        .map(|state| state.pruned_through.saturating_add(1))
        .unwrap_or(first_prunable)
        .max(first_prunable);
    let block_expected = previous
        .as_ref()
        .map(|state| state.blocks_pruned_through.saturating_add(1))
        .unwrap_or(first_prunable)
        .max(first_prunable);
    let expected = undo_expected.min(block_expected);
    let due = target
        .checked_sub(expected)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("payload-pruning range is invalid"))?;
    if due > tree_interval {
        anyhow::bail!(
            "block/undo history requires startup catch-up through height {} before pruning height {target}",
            target.saturating_sub(1)
        );
    }
    // The accumulator makes the safe frontier advance at authenticated-tree
    // boundaries rather than one block at a time. Retire that bounded interval
    // atomically with the boundary block.
    let mut block_hash = None;
    let mut updates = Vec::new();
    let mut pruned_undos = previous.as_ref().map_or(0, |state| state.pruned_undos);
    let mut pruned_blocks = previous.as_ref().map_or(0, |state| state.pruned_blocks);
    for height in expected..=target {
        let (update, undo_pruned, block_pruned) =
            stage_prune_payload_height(snapshot, batch, height)?;
        let hash = update.current.block.hash;
        pruned_undos = pruned_undos
            .checked_add(u64::from(undo_pruned))
            .ok_or_else(|| anyhow::anyhow!("pruned undo count exhausted"))?;
        pruned_blocks = pruned_blocks
            .checked_add(u64::from(block_pruned))
            .ok_or_else(|| anyhow::anyhow!("pruned block count exhausted"))?;
        block_hash = Some(hash);
        updates.push(update);
    }
    let block_hash =
        block_hash.ok_or_else(|| anyhow::anyhow!("payload-pruning range contained no heights"))?;
    let checkpoint = UndoPruningCheckpoint {
        pruned_through: target,
        block_hash,
        pruned_undos,
        blocks_pruned_through: target,
        blocks_checkpoint: block_hash,
        pruned_blocks,
    };
    batch.put(
        ColumnFamily::Snapshots,
        UNDO_PRUNING_CHECKPOINT_KEY,
        &checkpoint.encode(),
    )?;
    Ok(updates)
}

fn stage_prune_payload_height<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    height: Height,
) -> Result<(IndexStatusUpdate, bool, bool)> {
    let hash = read_canonical_hash(snapshot, height)?
        .ok_or_else(|| anyhow::anyhow!("undo-pruning height {height} is not canonical"))?;
    let mut block = load_block_index_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("undo-pruning block index {} is missing", hash.to_hex()))?;
    let previous_block = block.clone();
    let mut header = load_header_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("undo-pruning header index {} is missing", hash.to_hex()))?;
    if block.height != height || header.height != height || !block.status.active_chain {
        anyhow::bail!("undo-pruning target at height {height} is not the active block");
    }
    if block.status != header.status {
        anyhow::bail!(
            "payload-pruning target {} has inconsistent header/block status",
            hash.to_hex()
        );
    }

    let block_pruned = if !block.status.body_present {
        false
    } else {
        // The body was authenticated when its status was committed. Retiring
        // an append-only locator must not read and decode the historical
        // payload again: startup backfill would otherwise turn pruning into a
        // full-chain I/O replay. The subsequent invariant audit checks that
        // status and logical presence agree on the retained/pruned boundary.
        block.status.body_present = false;
        header.status.body_present = false;
        batch.delete(ColumnFamily::Blocks, hash.as_bytes())?;
        true
    };

    let raw_undo = snapshot.get(ColumnFamily::Undo, hash.as_bytes())?;
    let undo_pruned = if !block.status.undo_present {
        if raw_undo.is_some() {
            anyhow::bail!(
                "undo-pruning target {} has undo bytes without status",
                hash.to_hex()
            );
        }
        if header.status.undo_present {
            anyhow::bail!(
                "undo-pruning target {} has inconsistent header undo status",
                hash.to_hex()
            );
        }
        false
    } else {
        let raw_undo = raw_undo.ok_or_else(|| {
            anyhow::anyhow!(
                "undo-pruning target {} is missing its undo bytes",
                hash.to_hex()
            )
        })?;
        let undo = BlockUndo::decode(&raw_undo)
            .map_err(|error| anyhow::anyhow!("undo-pruning target is corrupt: {error}"))?;
        if undo.block_hash != hash || undo.height != height || !header.status.undo_present {
            anyhow::bail!(
                "undo-pruning target {} disagrees with its undo metadata",
                hash.to_hex()
            );
        }
        stage_remove_name_tree_snapshot_pin(snapshot, batch, &undo)
            .map_err(anyhow::Error::new)
            .with_context(|| {
                format!(
                    "undo-pruning target {} could not retire its name-tree pin",
                    hash.to_hex()
                )
            })?;
        block.status.undo_present = false;
        header.status.undo_present = false;
        batch.delete(ColumnFamily::Undo, hash.as_bytes())?;
        true
    };
    write_block_index_to_batch(batch, &block)?;
    write_record_to_batch(batch, &header)?;
    Ok((
        IndexStatusUpdate {
            previous_block: Some(previous_block),
            current: StagedIndexRecord { block, header },
        },
        undo_pruned,
        block_pruned,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedDeploymentState {
    height: Height,
    state: DeploymentState,
}

fn deployment_state_cache_key(hash: BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(DEPLOYMENT_STATE_CACHE_PREFIX.len() + 32);
    key.extend_from_slice(DEPLOYMENT_STATE_CACHE_PREFIX);
    key.extend_from_slice(hash.as_bytes());
    key
}

fn load_deployment_state(
    snapshot: &impl ReadSnapshot,
    hash: BlockHash,
) -> Result<Option<CachedDeploymentState>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Snapshots, &deployment_state_cache_key(hash))
        .context("failed to read deployment-state cache")?
    else {
        return Ok(None);
    };
    if bytes.len() != DEPLOYMENT_STATE_CACHE_SIZE {
        anyhow::bail!(
            "deployment-state cache for {} has {} bytes; expected {}",
            hash.to_hex(),
            bytes.len(),
            DEPLOYMENT_STATE_CACHE_SIZE
        );
    }
    if bytes[0] != DEPLOYMENT_STATE_CACHE_VERSION {
        anyhow::bail!(
            "deployment-state cache for {} has unsupported version {}",
            hash.to_hex(),
            bytes[0]
        );
    }
    let height_bytes: [u8; 4] = bytes[1..5]
        .try_into()
        .map_err(|_| anyhow::anyhow!("deployment-state height has invalid length"))?;
    let state_bytes: [u8; 4] = bytes[5..9]
        .try_into()
        .map_err(|_| anyhow::anyhow!("deployment-state vector has invalid length"))?;
    let height = Height::from_le_bytes(height_bytes);
    let state = DeploymentState::decode_states(state_bytes)
        .map_err(|error| anyhow::anyhow!("invalid deployment-state cache: {error}"))?;
    Ok(Some(CachedDeploymentState { height, state }))
}

fn write_deployment_state(
    batch: &mut impl WriteBatch,
    hash: BlockHash,
    height: Height,
    state: DeploymentState,
) -> Result<()> {
    let mut bytes = [0u8; DEPLOYMENT_STATE_CACHE_SIZE];
    bytes[0] = DEPLOYMENT_STATE_CACHE_VERSION;
    bytes[1..5].copy_from_slice(&height.to_le_bytes());
    bytes[5..9].copy_from_slice(&state.encode_states());
    batch
        .put(
            ColumnFamily::Snapshots,
            &deployment_state_cache_key(hash),
            &bytes,
        )
        .context("failed to stage deployment-state cache")
}

fn block_hash_from_bytes(bytes: &[u8]) -> Result<BlockHash> {
    let hash: [u8; 32] = bytes
        .try_into()
        .with_context(|| format!("expected 32-byte block hash, got {}", bytes.len()))?;
    Ok(BlockHash::new(hash))
}

fn mining_generation_from_snapshot(snapshot: &impl ReadSnapshot) -> Result<MiningGeneration> {
    snapshot
        .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
        .context("failed to read mining generation")?
        .map(|bytes| {
            decode_u64(&bytes)
                .map_err(|error| anyhow::anyhow!("failed to decode mining generation: {error}"))
        })
        .transpose()
        .map(|generation| generation.unwrap_or(0))
}

fn next_mining_generation(snapshot: &impl ReadSnapshot) -> Result<MiningGeneration> {
    mining_generation_from_snapshot(snapshot)?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("mining generation exhausted"))
}

fn chain_epoch_from_snapshot(snapshot: &impl ReadSnapshot) -> Result<u64> {
    snapshot
        .get(ColumnFamily::Meta, MetaKey::ChainEpoch.as_bytes())
        .context("failed to read chain epoch")?
        .map(|bytes| {
            decode_u64(&bytes)
                .map_err(|error| anyhow::anyhow!("failed to decode chain epoch: {error}"))
        })
        .transpose()
        .map(|epoch| epoch.unwrap_or(0))
}

fn next_chain_epoch(snapshot: &impl ReadSnapshot) -> Result<u64> {
    chain_epoch_from_snapshot(snapshot)?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("chain epoch exhausted"))
}

fn mining_snapshot_for_hash(
    snapshot: &impl ReadSnapshot,
    network_id: u8,
    hash: BlockHash,
    generation: MiningGeneration,
) -> Result<(Arc<MiningSnapshot>, bool)> {
    if generation == 0 {
        anyhow::bail!("a durable mining tip cannot have generation zero");
    }
    let record = load_block_index_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("mining block index is missing for {}", hash.to_hex()))?;
    if record.hash != hash || !record.status.is_staged_state() {
        anyhow::bail!(
            "mining tip {} is not a committed active-chain state",
            hash.to_hex()
        );
    }
    let block = load_block(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("mining raw block is missing for {}", hash.to_hex()))?;
    let raw_tree_root = snapshot
        .get(ColumnFamily::Meta, MetaKey::NameTreeCommitRoot.as_bytes())
        .context("failed to read durable mining name-tree commit root")?
        .ok_or_else(|| anyhow::anyhow!("durable mining name-tree commit root is missing"))?;
    let next_tree_root: [u8; 32] = raw_tree_root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("durable mining name-tree root has invalid length"))?;
    let authoritative = record.status.is_mining_authoritative();
    let tip_record = load_header_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("mining header record is missing for {}", hash.to_hex()))?;
    if tip_record.hash != hash || tip_record.height != record.height {
        anyhow::bail!(
            "mining header record disagrees with {} at height {}",
            hash.to_hex(),
            record.height
        );
    }
    let mut lookup = |candidate: &BlockHash| load_header_record(snapshot, candidate);
    let parent_median_time = median_time_past_with_lookup(&tip_record, &mut lookup)?;

    Ok((
        Arc::new(MiningSnapshot {
            network_id,
            generation,
            tip: HeaderSummary::from_block(&block, record.height),
            parent_median_time,
            next_tree_root,
            chainwork: record.chainwork,
        }),
        authoritative,
    ))
}

fn bind_store_identity(store: &StoreHandle, network: Network) -> Result<()> {
    hns_store::initialize_schema(store)
        .map_err(|error| anyhow::anyhow!("failed to initialize node schema: {error}"))?;

    let expected_network = [network.canonical_id()];
    let network_params = network.params();
    let expected_genesis = network_params.genesis_hash.as_bytes();
    let snapshot = store.snapshot()?;
    let bindings = [
        (MetaKey::Network, expected_network.as_slice(), "network"),
        (
            MetaKey::GenesisHash,
            expected_genesis.as_slice(),
            "genesis hash",
        ),
        (MetaKey::StorageProfile, STORAGE_PROFILE, "storage profile"),
    ];
    let mut missing = Vec::new();

    for (key, expected, label) in bindings {
        match snapshot
            .get(ColumnFamily::Meta, key.as_bytes())
            .with_context(|| format!("failed to read node {label} binding"))?
        {
            Some(actual) if actual == expected => {}
            Some(actual) => anyhow::bail!(
                "node store {label} binding {:?} does not match expected {:?}",
                actual,
                expected
            ),
            None => missing.push((key, expected.to_vec())),
        }
    }

    let chain_epoch_missing = snapshot
        .get(ColumnFamily::Meta, MetaKey::ChainEpoch.as_bytes())
        .context("failed to read chain epoch")?
        .is_none();
    drop(snapshot);

    if missing.is_empty() && !chain_epoch_missing {
        return Ok(());
    }

    let mut batch = store.batch();
    for (key, value) in missing {
        batch.put(ColumnFamily::Meta, key.as_bytes(), &value)?;
    }
    if chain_epoch_missing {
        batch.put(
            ColumnFamily::Meta,
            MetaKey::ChainEpoch.as_bytes(),
            &encode_u64(0),
        )?;
    }
    store.commit(batch)?;
    Ok(())
}

fn validate_existing_store_identity(store: &StoreHandle, network: Network) -> Result<()> {
    let snapshot = store.snapshot()?;
    let expected_network = [network.canonical_id()];
    if let Some(actual) = snapshot.get(ColumnFamily::Meta, MetaKey::Network.as_bytes())? {
        if actual.as_slice() != expected_network {
            anyhow::bail!(
                "node network binding mismatch before storage migration: expected {}, got {:?}",
                network.canonical_id(),
                actual
            );
        }
    }
    let expected_genesis = network.params().genesis_hash;
    if let Some(actual) = snapshot.get(ColumnFamily::Meta, MetaKey::GenesisHash.as_bytes())? {
        if actual.as_slice() != expected_genesis.as_bytes() {
            anyhow::bail!("node genesis binding mismatch before storage migration");
        }
    }
    Ok(())
}

fn difficulty_point(record: &HeaderRecord) -> DifficultyPoint {
    DifficultyPoint {
        height: record.height,
        time: record.header.time,
        bits: record.header.bits,
        chainwork: record.chainwork,
    }
}

fn header_parent_with_lookup<F>(record: &HeaderRecord, lookup: &mut F) -> Result<HeaderRecord>
where
    F: FnMut(&BlockHash) -> Result<Option<HeaderRecord>>,
{
    if record.height == 0 {
        anyhow::bail!("genesis header has no parent");
    }
    let parent = lookup(&record.header.prev_block)?
        .ok_or_else(|| anyhow::anyhow!("difficulty parent header is missing"))?;
    if parent.height.checked_add(1) != Some(record.height)
        || parent.hash != record.header.prev_block
    {
        anyhow::bail!("difficulty parent linkage is invalid");
    }
    Ok(parent)
}

fn ancestor_with_lookup<F>(
    mut record: HeaderRecord,
    height: Height,
    lookup: &mut F,
) -> Result<HeaderRecord>
where
    F: FnMut(&BlockHash) -> Result<Option<HeaderRecord>>,
{
    if height > record.height {
        anyhow::bail!("difficulty ancestor is above the starting header");
    }
    while record.height > height {
        record = header_parent_with_lookup(&record, lookup)?;
    }
    if record.height != height {
        anyhow::bail!("difficulty ancestor chain is not contiguous");
    }
    Ok(record)
}

fn suitable_block_with_lookup<F>(tip: &HeaderRecord, lookup: &mut F) -> Result<HeaderRecord>
where
    F: FnMut(&BlockHash) -> Result<Option<HeaderRecord>>,
{
    let mut z = tip.clone();
    let mut y = header_parent_with_lookup(&z, lookup)?;
    let mut x = header_parent_with_lookup(&y, lookup)?;
    if x.header.time > z.header.time {
        std::mem::swap(&mut x, &mut z);
    }
    if x.header.time > y.header.time {
        std::mem::swap(&mut x, &mut y);
    }
    if y.header.time > z.header.time {
        std::mem::swap(&mut y, &mut z);
    }
    Ok(y)
}

fn median_time_past_with_lookup<F>(tip: &HeaderRecord, lookup: &mut F) -> Result<u64>
where
    F: FnMut(&BlockHash) -> Result<Option<HeaderRecord>>,
{
    let mut times = Vec::with_capacity(MEDIAN_TIMESPAN);
    let mut record = tip.clone();
    loop {
        times.push(record.header.time);
        if times.len() == MEDIAN_TIMESPAN || record.height == 0 {
            break;
        }
        record = header_parent_with_lookup(&record, lookup)?;
    }
    times.sort_unstable();
    Ok(times[times.len() / 2])
}

fn expected_bits_with_lookup<F>(
    network: Network,
    header_time: u64,
    parent: Option<&HeaderRecord>,
    lookup: &mut F,
) -> Result<u32>
where
    F: FnMut(&BlockHash) -> Result<Option<HeaderRecord>>,
{
    let pow = network.params().pow;
    let Some(parent) = parent else {
        return Ok(pow.bits);
    };
    let previous = difficulty_point(parent);
    let reset = pow.target_reset
        && header_time
            > parent
                .header
                .time
                .saturating_add(u64::from(pow.target_spacing).saturating_mul(2));
    if pow.no_retargeting || reset || parent.height < pow.target_window.saturating_add(2) {
        return expected_next_bits(pow, header_time, previous, None, None)
            .map_err(|error| anyhow::anyhow!("difficulty validation failed: {error}"));
    }

    let last = suitable_block_with_lookup(parent, lookup)?;
    let ancestor_height = parent
        .height
        .checked_sub(pow.target_window)
        .ok_or_else(|| anyhow::anyhow!("difficulty ancestor height underflow"))?;
    let ancestor = ancestor_with_lookup(parent.clone(), ancestor_height, lookup)?;
    let first = suitable_block_with_lookup(&ancestor, lookup)?;
    expected_next_bits(
        pow,
        header_time,
        previous,
        Some(difficulty_point(&first)),
        Some(difficulty_point(&last)),
    )
    .map_err(|error| anyhow::anyhow!("difficulty validation failed: {error}"))
}

fn completed_deployment_period_with_lookup<F>(
    parent: &HeaderRecord,
    deployment: Deployment,
    window: u32,
    lookup: &mut F,
) -> Result<DeploymentPeriod>
where
    F: FnMut(&BlockHash) -> Result<Option<HeaderRecord>>,
{
    let signal = 1u32
        .checked_shl(u32::from(deployment.bit))
        .ok_or_else(|| anyhow::anyhow!("deployment bit {} is invalid", deployment.bit))?;
    let mut entry = parent.clone();
    let mut signalling_blocks = 0u32;
    for offset in 0..window {
        if entry.header.version & signal != 0 {
            signalling_blocks = signalling_blocks
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("deployment signalling count overflow"))?;
        }
        if offset + 1 != window {
            entry = header_parent_with_lookup(&entry, lookup).with_context(|| {
                format!(
                    "deployment {} period is not parent-contiguous",
                    deployment.name()
                )
            })?;
        }
    }
    Ok(DeploymentPeriod {
        median_time_past: median_time_past_with_lookup(parent, lookup)?,
        signalling_blocks,
    })
}

fn current_unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("system clock is before the Unix epoch")
}

fn best_block_tip_from_snapshot(snapshot: &impl ReadSnapshot) -> Result<Option<ChainTip>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
        .context("failed to read active-chain tip")?
    else {
        return Ok(None);
    };
    let hash = block_hash_from_bytes(&bytes)?;
    let record = load_block_index_record(snapshot, &hash)?.ok_or_else(|| {
        anyhow::anyhow!("active-chain tip index is missing for {}", hash.to_hex())
    })?;
    if !record.status.active_chain {
        anyhow::bail!("active-chain tip {} is not marked active", hash.to_hex());
    }
    Ok(Some(ChainTip {
        hash,
        height: record.height,
        chainwork: record.chainwork,
    }))
}

fn best_header_tip_from_snapshot(snapshot: &impl ReadSnapshot) -> Result<Option<ChainTip>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())
        .context("failed to read best-header binding")?
    else {
        return Ok(None);
    };
    let hash = block_hash_from_bytes(&bytes)?;
    let record = load_header_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("best-header record is missing for {}", hash.to_hex()))?;
    Ok(Some(ChainTip {
        hash,
        height: record.height,
        chainwork: record.chainwork,
    }))
}

fn load_raw_block_record(
    snapshot: &impl ReadSnapshot,
    hash: &BlockHash,
) -> Result<Option<RawBlockRecord>> {
    let Some(bytes) = snapshot
        .get(ColumnFamily::Blocks, hash.as_bytes())
        .context("failed to read raw block record")?
    else {
        return Ok(None);
    };
    let record = RawBlockRecord::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("failed to decode raw block record: {error}"))?;
    if record.hash != *hash {
        anyhow::bail!("raw block record key/hash mismatch for {}", hash.to_hex());
    }
    Ok(Some(record))
}

fn stage_best_header_if_more_work<B: WriteBatch>(
    snapshot: &impl ReadSnapshot,
    batch: &mut B,
    candidate_hash: BlockHash,
    candidate_chainwork: Uint256,
) -> Result<()> {
    let current = snapshot
        .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())
        .context("failed to read best-header binding")?
        .map(|bytes| block_hash_from_bytes(&bytes))
        .transpose()?;

    let promote = match current {
        None => true,
        Some(current_hash) if current_hash == candidate_hash => false,
        Some(current_hash) => {
            let current_record = load_header_record(snapshot, &current_hash)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "best-header binding points to missing header {}",
                    current_hash.to_hex()
                )
            })?;
            candidate_chainwork > current_record.chainwork
        }
    };

    if promote {
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestHeaderHash.as_bytes(),
            candidate_hash.as_bytes(),
        )?;
    }
    Ok(())
}

fn validate_stored_activation_status(record: &BlockIndexRecord) -> Result<()> {
    if record.status.failed {
        anyhow::bail!("stored block {} is marked failed", record.hash.to_hex());
    }
    if !record.status.header_context_valid
        || !record.status.body_present
        || !record.status.body_syntax_valid
        || !record.status.absolute_finality_valid
    {
        anyhow::bail!(
            "stored block {} has not passed activation prerequisites",
            record.hash.to_hex()
        );
    }
    Ok(())
}

fn stored_path_from_genesis_bounded(
    snapshot: &impl ReadSnapshot,
    candidate: BlockHash,
    maximum_connect: usize,
) -> Result<Vec<BlockHash>> {
    let mut reverse = Vec::new();
    let mut current = candidate;

    loop {
        if reverse.len() >= maximum_connect {
            anyhow::bail!(
                "best-work activation needs more than {maximum_connect} replacement blocks"
            );
        }
        let record = load_header_record(snapshot, &current)?
            .ok_or_else(|| anyhow::anyhow!("stored header {} is missing", current.to_hex()))?;
        reverse.push(current);

        if record.height == 0 {
            if record.header.prev_block != BlockHash::ZERO {
                anyhow::bail!("stored genesis header has a non-zero parent");
            }
            break;
        }

        let parent = load_header_record(snapshot, &record.header.prev_block)?.ok_or_else(|| {
            anyhow::anyhow!(
                "stored header parent {} is missing",
                record.header.prev_block.to_hex()
            )
        })?;
        if parent.height.checked_add(1) != Some(record.height) {
            anyhow::bail!("stored header heights are not contiguous");
        }
        if record.chainwork <= parent.chainwork {
            anyhow::bail!("stored header chainwork does not increase");
        }
        current = parent.hash;
    }

    reverse.reverse();
    Ok(reverse)
}

fn validate_reorg_plan(
    snapshot: &impl ReadSnapshot,
    active: Option<&ChainTip>,
    candidate: BlockHash,
    plan: &ReorgPlan,
) -> Result<()> {
    if plan.connect.is_empty() {
        anyhow::bail!("best-work activation plan has no connect path");
    }
    if plan.connect.last().copied() != Some(candidate) {
        anyhow::bail!("best-work activation plan does not end at the candidate");
    }

    let candidate_record = load_block_index_record(snapshot, &candidate)?
        .ok_or_else(|| anyhow::anyhow!("candidate block index is missing"))?;
    validate_stored_activation_status(&candidate_record)?;
    if let Some(active) = active {
        if candidate_record.chainwork <= active.chainwork {
            anyhow::bail!("candidate does not have strictly more work than the active tip");
        }
    }

    let mut seen = HashSet::new();
    let mut fork_hash = active.map(|tip| tip.hash);
    let mut fork_height = active.map(|tip| tip.height);
    let mut fork_work = active.map(|tip| tip.chainwork).unwrap_or(Uint256::ZERO);

    if active.is_none() && !plan.disconnect.is_empty() {
        anyhow::bail!("an empty active chain cannot have a disconnect path");
    }

    if let Some(active_tip) = active {
        let mut expected_hash = active_tip.hash;
        let mut expected_height = active_tip.height;

        for hash in &plan.disconnect {
            if !seen.insert(*hash) {
                anyhow::bail!("reorganization plan repeats block {}", hash.to_hex());
            }
            if *hash != expected_hash {
                anyhow::bail!("reorganization disconnect path is not contiguous");
            }
            let record = load_block_index_record(snapshot, hash)?.ok_or_else(|| {
                anyhow::anyhow!("disconnect block index {} is missing", hash.to_hex())
            })?;
            if !record.status.active_chain || record.height != expected_height {
                anyhow::bail!(
                    "disconnect block {} is not the expected active block",
                    hash.to_hex()
                );
            }
            if hns_chain::read_canonical_hash(snapshot, record.height)? != Some(*hash) {
                anyhow::bail!(
                    "disconnect block {} is absent from the canonical height index",
                    hash.to_hex()
                );
            }
            if !record.status.undo_present {
                anyhow::bail!(
                    "reorganization disconnect path crosses pruned undo history at height {}",
                    record.height
                );
            }

            if record.height == 0 {
                fork_hash = None;
                fork_height = None;
                fork_work = Uint256::ZERO;
            } else {
                let parent =
                    load_block_index_record(snapshot, &record.prev_hash)?.ok_or_else(|| {
                        anyhow::anyhow!(
                            "disconnect parent {} is missing",
                            record.prev_hash.to_hex()
                        )
                    })?;
                fork_hash = Some(parent.hash);
                fork_height = Some(parent.height);
                fork_work = parent.chainwork;
                expected_hash = parent.hash;
                expected_height = parent.height;
            }
        }
    }

    let mut expected_parent = fork_hash;
    let mut expected_height = fork_height
        .map(|height| {
            height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("height exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    let mut parent_work = fork_work;

    for hash in &plan.connect {
        if !seen.insert(*hash) {
            anyhow::bail!("reorganization plan repeats block {}", hash.to_hex());
        }
        let record = load_block_index_record(snapshot, hash)?
            .ok_or_else(|| anyhow::anyhow!("connect block index {} is missing", hash.to_hex()))?;
        validate_stored_activation_status(&record)?;
        if record.height != expected_height {
            anyhow::bail!(
                "connect block {} has a non-contiguous height",
                hash.to_hex()
            );
        }
        match expected_parent {
            Some(parent) if record.prev_hash != parent => {
                anyhow::bail!(
                    "connect block {} does not extend the planned fork",
                    hash.to_hex()
                )
            }
            None if record.height != 0 || record.prev_hash != BlockHash::ZERO => {
                anyhow::bail!("connect path does not begin with a valid genesis block")
            }
            _ => {}
        }
        if record.chainwork <= parent_work {
            anyhow::bail!(
                "connect block {} does not increase chainwork",
                hash.to_hex()
            );
        }
        expected_parent = Some(*hash);
        expected_height = expected_height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("height exhausted"))?;
        parent_work = record.chainwork;
    }

    Ok(())
}

fn node_import_from_stored_bounded(
    snapshot: &impl ReadSnapshot,
    hash: &BlockHash,
    body_bytes: &mut u64,
    maximum_body_bytes: u64,
) -> Result<NodeBlockImport> {
    let record = load_block_index_record(snapshot, hash)?
        .ok_or_else(|| anyhow::anyhow!("stored block index {} is missing", hash.to_hex()))?;
    let encoded = snapshot
        .get(ColumnFamily::Blocks, hash.as_bytes())
        .context("failed to read stored block body during bounded activation planning")?
        .ok_or_else(|| anyhow::anyhow!("stored block body {} is missing", hash.to_hex()))?;
    *body_bytes = add_reorg_resource(
        *body_bytes,
        u64::try_from(encoded.len()).unwrap_or(u64::MAX),
        maximum_body_bytes,
        "reorganization stored body bytes",
    )?;
    let raw = RawBlockRecord::decode(&encoded)
        .map_err(|error| anyhow::anyhow!("stored block record is corrupt: {error}"))?;
    if raw.hash != *hash {
        anyhow::bail!(
            "stored block record key {} disagrees with embedded hash {}",
            hash.to_hex(),
            raw.hash.to_hex()
        );
    }
    let block = raw
        .decode_block()
        .map_err(|error| anyhow::anyhow!("stored block body is corrupt: {error}"))?;

    #[cfg(test)]
    let validation = if raw.source == RawBlockSource::Fixture {
        ImportValidationPolicy::Fixture {
            chainwork: record.chainwork,
        }
    } else {
        ImportValidationPolicy::Strict
    };
    #[cfg(not(test))]
    let validation = ImportValidationPolicy::Strict;

    Ok(NodeBlockImport {
        block,
        height: record.height,
        validation,
        source: raw.source,
    })
}

fn validate_branch_extension(
    snapshot: &impl ReadSnapshot,
    request: &NodeBlockImport,
    chainwork: Uint256,
    network: Network,
    require_parent_index: bool,
) -> Result<()> {
    if request.height == 0 {
        if matches!(request.validation, ImportValidationPolicy::Strict) {
            let params = network.params();
            if request.block.header != params.genesis_header()
                || request.block.hash() != params.genesis_hash
            {
                anyhow::bail!("strict height-zero block is not the canonical network genesis");
            }
        }
        if chainwork == Uint256::ZERO {
            anyhow::bail!("genesis chainwork must be positive");
        }
        if request.block.header.prev_block != BlockHash::ZERO {
            anyhow::bail!("genesis block must have a zero parent");
        }
        return Ok(());
    }

    let parent_hash = request.block.header.prev_block;
    let parent_header = load_header_record(snapshot, &parent_hash)?.ok_or_else(|| {
        anyhow::anyhow!("block parent header {} is missing", parent_hash.to_hex())
    })?;
    let expected_height = parent_header
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("branch height exhausted"))?;
    if request.height != expected_height {
        anyhow::bail!(
            "block height {} does not extend parent height {}",
            request.height,
            parent_header.height
        );
    }
    if chainwork <= parent_header.chainwork {
        anyhow::bail!("block chainwork must increase over its parent");
    }
    if !require_parent_index {
        return Ok(());
    }

    let parent = load_block_index_record(snapshot, &parent_hash)?
        .ok_or_else(|| anyhow::anyhow!("block parent index {} is missing", parent_hash.to_hex()))?;
    if parent.height != parent_header.height || parent.chainwork != parent_header.chainwork {
        anyhow::bail!("block parent index disagrees with its header record");
    }
    Ok(())
}

fn validate_active_extension(
    snapshot: &impl ReadSnapshot,
    request: &NodeBlockImport,
    chainwork: Uint256,
) -> Result<()> {
    let active = best_block_tip_from_snapshot(snapshot)?;

    match active {
        None if request.height == 0 && chainwork > Uint256::ZERO => Ok(()),
        None if request.height == 0 => anyhow::bail!("genesis chainwork must be positive"),
        None => anyhow::bail!("non-genesis block cannot connect to an empty active chain"),
        Some(_) if request.height == 0 => anyhow::bail!("cannot connect a second active genesis"),
        Some(parent) => {
            if request.block.header.prev_block != parent.hash {
                anyhow::bail!(
                    "block parent {} does not match active tip {}",
                    request.block.header.prev_block.to_hex(),
                    parent.hash.to_hex()
                );
            }
            if request.height
                != parent
                    .height
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("active height exhausted"))?
            {
                anyhow::bail!("block height does not extend the active tip");
            }
            if chainwork <= parent.chainwork {
                anyhow::bail!("block chainwork must increase over the active tip");
            }
            Ok(())
        }
    }
}

fn validate_reorg_request_shape(
    snapshot: &impl ReadSnapshot,
    request: &NodeReorg,
    active: Option<&ChainTip>,
) -> Result<()> {
    if request.connect.is_empty() {
        anyhow::bail!("a reorganization must connect a replacement branch");
    }

    let mut seen = HashSet::new();
    let mut fork_hash = active.map(|tip| tip.hash);
    let mut fork_height = active.map(|tip| tip.height);

    match (active, request.disconnect.first()) {
        (None, Some(_)) => anyhow::bail!("an empty active chain cannot be disconnected"),
        (Some(tip), Some(first)) if first.block_hash != tip.hash => {
            anyhow::bail!("reorganization disconnect path does not begin at the active tip")
        }
        _ => {}
    }

    if let Some(active_tip) = active {
        let mut expected_hash = active_tip.hash;
        let mut expected_height = active_tip.height;
        for disconnect in &request.disconnect {
            if !seen.insert(disconnect.block_hash) {
                anyhow::bail!("reorganization repeats a disconnect block");
            }
            if disconnect.block_hash != expected_hash || disconnect.height != expected_height {
                anyhow::bail!("reorganization disconnect path is not contiguous");
            }
            let record = load_block_index_record(snapshot, &disconnect.block_hash)?
                .ok_or_else(|| anyhow::anyhow!("disconnect block index is missing"))?;
            if !record.status.active_chain
                || hns_chain::read_canonical_hash(snapshot, record.height)? != Some(record.hash)
            {
                anyhow::bail!("reorganization disconnect path is not canonical");
            }
            if record.height == 0 {
                fork_hash = None;
                fork_height = None;
            } else {
                let parent = load_block_index_record(snapshot, &record.prev_hash)?
                    .ok_or_else(|| anyhow::anyhow!("disconnect parent index is missing"))?;
                expected_hash = parent.hash;
                expected_height = parent.height;
                fork_hash = Some(parent.hash);
                fork_height = Some(parent.height);
            }
        }
    }

    let mut expected_parent = fork_hash;
    let mut expected_height = fork_height
        .map(|height| {
            height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("height exhausted"))
        })
        .transpose()?
        .unwrap_or(0);
    for connect in &request.connect {
        let hash = connect.block.hash();
        if !seen.insert(hash) {
            anyhow::bail!("reorganization repeats a block across its paths");
        }
        if connect.height != expected_height {
            anyhow::bail!("reorganization connect heights are not contiguous");
        }
        match expected_parent {
            Some(parent) if connect.block.header.prev_block != parent => {
                anyhow::bail!("reorganization connect path does not extend the fork")
            }
            None if connect.height != 0 || connect.block.header.prev_block != BlockHash::ZERO => {
                anyhow::bail!("reorganization connect path does not begin at genesis")
            }
            _ => {}
        }
        expected_parent = Some(hash);
        expected_height = expected_height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("height exhausted"))?;
    }

    Ok(())
}

fn decode_height_key(bytes: &[u8]) -> Result<Height> {
    let height: [u8; 4] = bytes
        .try_into()
        .with_context(|| format!("expected 4-byte height key, got {}", bytes.len()))?;
    Ok(u32::from_be_bytes(height))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShutdownSignal;

impl ShutdownSignal {
    pub fn ctrl_c() -> Self {
        Self
    }

    pub async fn wait(self) {
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => {
                    tokio::select! {
                        result = tokio::signal::ctrl_c() => {
                            if let Err(error) = result {
                                tracing::warn!(%error, "failed to wait for ctrl-c shutdown signal");
                            }
                        }
                        signal = terminate.recv() => {
                            if signal.is_none() {
                                tracing::warn!("SIGTERM shutdown stream closed unexpectedly");
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to install SIGTERM shutdown handler");
                    if let Err(error) = tokio::signal::ctrl_c().await {
                        tracing::warn!(%error, "failed to wait for ctrl-c shutdown signal");
                    }
                }
            }
        }

        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to wait for ctrl-c shutdown signal");
        }
    }
}

pub fn init_logging(filter: &str) -> Result<()> {
    let env_filter =
        EnvFilter::try_new(filter).with_context(|| format!("invalid tracing filter `{filter}`"))?;

    fmt()
        .with_env_filter(env_filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Barrier;

    use hns_chain::{read_canonical_hash, BlockIndex, HeaderImport};
    use hns_consensus::{
        block_merkle_root, block_witness_root, ConsensusError, TransactionInputVerifier,
    };
    use hns_primitives::{
        sha3_256, Address, Amount, Covenant, CovenantKind, Header, Input, Outpoint, Output,
        Transaction, Txid, Witness,
    };
    use hns_rpc::{JsonRpcRequest, RpcService};
    #[cfg(feature = "rocksdb-backend")]
    use hns_state::StateEngine;
    use hns_state::{
        name_tree_snapshot_pin_key, write_coin_to_batch, RejectSpecialCoinbaseIssuance, StateView,
    };
    use hns_store::ReadSnapshot;
    use hns_urkel::MemoryUrkel;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(feature = "rocksdb-backend")]
    struct ReorgArchivePreflightRejectGuard;

    #[cfg(feature = "rocksdb-backend")]
    impl ReorgArchivePreflightRejectGuard {
        fn enable() -> Self {
            TEST_REORG_APPENDED_NAME_PAGE_BYTES.with(|bytes| bytes.set(0));
            TEST_REORG_MAX_GENERATED_UNDO_BYTES.with(|bytes| bytes.set(0));
            TEST_REORG_NAME_STATE_WRITES.with(|writes| writes.set(0));
            TEST_REORG_REJECT_AT_ARCHIVE_PREFLIGHT.with(|enabled| {
                assert!(
                    !enabled.replace(true),
                    "reorg archive fault already enabled"
                );
            });
            Self
        }

        fn appended_name_page_bytes(&self) -> u64 {
            TEST_REORG_APPENDED_NAME_PAGE_BYTES.with(std::cell::Cell::get)
        }

        fn maximum_generated_undo_bytes(&self) -> u64 {
            TEST_REORG_MAX_GENERATED_UNDO_BYTES.with(std::cell::Cell::get)
        }

        fn generated_name_state_writes(&self) -> u64 {
            TEST_REORG_NAME_STATE_WRITES.with(std::cell::Cell::get)
        }
    }

    #[cfg(feature = "rocksdb-backend")]
    impl Drop for ReorgArchivePreflightRejectGuard {
        fn drop(&mut self) {
            TEST_REORG_REJECT_AT_ARCHIVE_PREFLIGHT.with(|enabled| enabled.set(false));
            TEST_REORG_APPENDED_NAME_PAGE_BYTES.with(|bytes| bytes.set(0));
            TEST_REORG_MAX_GENERATED_UNDO_BYTES.with(|bytes| bytes.set(0));
            TEST_REORG_NAME_STATE_WRITES.with(|writes| writes.set(0));
        }
    }

    fn complete_store_image(store: &StoreHandle) -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
        let snapshot = store.snapshot().expect("complete store snapshot");
        let mut image = Vec::new();
        for family in ColumnFamily::ALL {
            image.extend(
                snapshot
                    .scan_prefix(family, b"")
                    .unwrap_or_else(|error| panic!("scan {}: {error}", family.name()))
                    .into_iter()
                    .map(|(key, value)| (family.name(), key, value)),
            );
        }
        image
    }

    fn commit_test_name_page_seal(
        state: &mut NodeState,
        height: Height,
    ) -> Result<()> {
        let store = state.store.clone();

        let pages = state
            .name_pages
            .as_mut()
            .ok_or_else(|| {
                anyhow::anyhow!("test state has no name-page storage")
            })?;

        let snapshot = store.snapshot()?;

        let (reader, legacy) = pages.reader_for_roots(
            &snapshot,
            std::iter::empty(),
            false,
        )?;

        if legacy {
            anyhow::bail!(
                "synthetic seal test unexpectedly needs \
                 legacy name nodes"
            );
        }

        let mut batch = store.batch();

        let prepared = pages.prepare_root(
            &snapshot,
            &mut batch,
            &reader,
            BTreeMap::new(),
            &[],
            NamePageRootTarget {
                root: pages.state.root,
                height: Some(height),
            },
        )?;

        drop(reader);
        drop(snapshot);

        store.commit(batch)?;
        pages.commit_prepared(prepared);

        Ok(())
    }

    struct NodePageGenerationFixture {
        live_state: NodeState,
        store: StoreHandle,
        directory: PathBuf,
    }

    fn build_test_node_page_generation(
        record_count: usize,
    ) -> NodePageGenerationFixture {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-name-page-generation-{}-{nonce}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let record_count = u32::try_from(record_count)
            .expect("record count fits in test fixture index");
        let mut entries = Vec::with_capacity(record_count as usize);
        for index in 0..record_count {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&index.to_le_bytes());
            entries.push((NameHash::new(key), index.to_le_bytes().to_vec()));
        }
        let tree = MemoryUrkel::from_entries(entries).expect("test fixture tree");
        let tree_root = tree.root();
        let tree_records = tree.node_records().expect("test fixture records");

        let store = StoreHandle::memory();
        let mut batch = store.batch();
        for (record_root, raw) in tree_records {
            batch
                .put(ColumnFamily::NameTreeNodes, record_root.as_bytes(), &raw)
                .expect("test fixture node");
        }
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                tree_root.as_bytes(),
            )
            .expect("test fixture tree root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                tree_root.as_bytes(),
            )
            .expect("test fixture commit tree root");
        store.commit(batch).expect("publish test fixture tree");

        let mut state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize fixture state");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("open test fixture pages"),
        );

        let snapshot = store.snapshot().expect("fixture snapshot");
        let pages = state
            .name_pages
            .as_mut()
            .expect("fixture state has name pages");
        let (reader, legacy) = pages
            .reader_for_roots(&snapshot, std::iter::empty(), false)
            .expect("fixture reader");
        assert!(!legacy);

        let mut batch = store.batch();
        let prepared = pages
            .prepare_root(
                &snapshot,
                &mut batch,
                &reader,
                BTreeMap::new(),
                &[],
                NamePageRootTarget {
                    root: tree_root,
                    height: Some(NAME_PAGE_SEGMENT_BLOCKS),
                },
            )
            .expect("publish fixture root");
        drop(reader);
        drop(snapshot);

        store.commit(batch).expect("publish fixture root");
        pages.commit_prepared(prepared);

        NodePageGenerationFixture {
            live_state: state,
            store: store.clone(),
            directory,
        }
    }

    #[cfg(feature = "rocksdb-backend")]
    fn flat_directory_file_image(directory: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut image = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
            .map(|entry| {
                let entry = entry.expect("read directory entry");
                let file_type = entry.file_type().expect("read directory entry type");
                assert!(file_type.is_file(), "unexpected non-file segment entry");
                let name = entry.file_name().to_string_lossy().into_owned();
                let bytes = std::fs::read(entry.path()).expect("read segment entry");
                (name, bytes)
            })
            .collect::<Vec<_>>();
        image.sort_by(|left, right| left.0.cmp(&right.0));
        image
    }

    #[test]
    fn reorg_index_staging_limit_preserves_typed_store_source() {
        let store = StoreHandle::memory();
        let record = regtest_genesis_record();
        let actual = ReorgStagedEffectMeter::operation_charge(
            record.hash.as_bytes().len(),
            record.encode().len(),
            REORG_STAGING_OPERATION_COPIES,
        );
        let limit = actual.checked_sub(1).expect("positive header write charge");
        let overlay = StagingOverlay::new();
        let staged_batch = overlay.batch(store.batch());
        let mut batch = ReorgMeteredBatch::new(
            staged_batch,
            ReorgStagedEffectMeter::new(limit),
            REORG_STAGING_OPERATION_COPIES,
        );

        let error = write_record_to_batch(&mut batch, &record)
            .map_err(anyhow::Error::new)
            .context("failed to stage header index")
            .expect_err("header index write must exceed the staged-effect budget");

        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<ChainError>().is_some()),
            "chain staging error must remain in the source chain: {error:#}"
        );
        let store_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<StoreError>())
            .expect("typed store limit must remain in the source chain");
        match store_error {
            StoreError::LimitExceeded {
                context,
                limit: error_limit,
                actual: error_actual,
            } => {
                assert_eq!(*context, ReorgStagedEffectMeter::CONTEXT);
                assert_eq!(*error_limit, limit);
                assert_eq!(*error_actual, actual);
            }
            other => panic!("unexpected typed store error: {other}"),
        }
        assert_eq!(batch.meter.consumed, 0);
        assert!(overlay.staged_family(ColumnFamily::Headers).is_empty());
    }

    #[test]
    fn undo_pruning_pin_limit_preserves_typed_store_source() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let hash = block.hash();
        node.connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect pruning fixture");
        let store = node.state.store.clone();
        let snapshot = store.snapshot().expect("pruning snapshot");
        let pin_key = name_tree_snapshot_pin_key(0);
        assert!(snapshot
            .get(ColumnFamily::Snapshots, &pin_key)
            .expect("read pruning pin")
            .is_some());

        let body_delete_charge = ReorgStagedEffectMeter::operation_charge(
            hash.as_bytes().len(),
            0,
            REORG_STAGING_OPERATION_COPIES,
        );
        let pin_delete_charge = ReorgStagedEffectMeter::operation_charge(
            pin_key.len(),
            0,
            REORG_STAGING_OPERATION_COPIES,
        );
        let mut batch = ReorgMeteredBatch::new(
            store.batch(),
            ReorgStagedEffectMeter::new(body_delete_charge),
            REORG_STAGING_OPERATION_COPIES,
        );

        let error = stage_prune_payload_height(&snapshot, &mut batch, 0)
            .expect_err("name-tree pin deletion must exceed the staged-effect budget");

        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<StateError>().is_some()),
            "state staging error must remain in the source chain: {error:#}"
        );
        let store_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<StoreError>())
            .expect("typed pin-deletion limit must remain in the source chain");
        match store_error {
            StoreError::LimitExceeded {
                context,
                limit,
                actual,
            } => {
                assert_eq!(*context, ReorgStagedEffectMeter::CONTEXT);
                assert_eq!(*limit, body_delete_charge);
                assert_eq!(
                    *actual,
                    body_delete_charge.saturating_add(pin_delete_charge)
                );
            }
            other => panic!("unexpected typed store error: {other}"),
        }
        assert_eq!(batch.meter.consumed, body_delete_charge);
    }

    #[test]
    fn reorg_meter_exact_limit_covers_generated_disconnect_index_name_and_page_writes() {
        let store = StoreHandle::memory();
        let old_undo_key = [0x11; 32];
        let new_undo_key = [0x22; 32];
        let shared_outpoint = [0x33; 36];
        let old_coin = b"old-coin";
        let replacement_coin = vec![0x44; 512];
        let generated_large_undo = vec![0x55; 2 * 1024 * 1024];
        let tx_index_key = [0x66; 32];
        let tx_index_value = vec![0x67; 96];
        let name_key = [0x77; 32];
        let name_state = vec![0x78; 4 * 1024];
        let name_node_key = [0x88; 32];
        let deferred_name_node = vec![0x89; 8 * 1024];
        let page_key = b"page-publication";
        let page_value = vec![0x99; 384];

        let mut seed = store.batch();
        seed.put(ColumnFamily::Undo, &old_undo_key, b"disconnect-undo")
            .expect("seed disconnect undo");
        seed.put(ColumnFamily::Utxo, &shared_outpoint, old_coin)
            .expect("seed replaced coin");
        store.commit(seed).expect("commit meter seed");

        let phase_one_charge = [
            (old_undo_key.len(), 0),
            (shared_outpoint.len(), 0),
            (shared_outpoint.len(), replacement_coin.len()),
            (new_undo_key.len(), generated_large_undo.len()),
            (tx_index_key.len(), tx_index_value.len()),
            (name_key.len(), name_state.len()),
            (name_node_key.len(), deferred_name_node.len()),
        ]
        .into_iter()
        .fold(0u64, |total, (key, value)| {
            total.saturating_add(ReorgStagedEffectMeter::operation_charge(
                key,
                value,
                REORG_STAGING_OPERATION_COPIES,
            ))
        });
        let page_charge = ReorgStagedEffectMeter::operation_charge(
            page_key.len(),
            page_value.len(),
            REORG_PUBLICATION_OPERATION_COPIES,
        );
        let packing_records =
            BTreeMap::from([(TreeRoot::new(name_node_key), deferred_name_node.clone())]);
        let packing_charge = ReorgStagedEffectMeter::name_page_packing_charge(&packing_records);
        let physical_page_charge = ReorgStagedEffectMeter::name_page_output_charge(1);
        let exact_limit = phase_one_charge
            .checked_add(packing_charge)
            .expect("exact page packing limit")
            .checked_add(physical_page_charge)
            .expect("exact physical page limit")
            .checked_add(page_charge)
            .expect("exact meter limit");

        let base = store.snapshot().expect("meter base");
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let staged_batch = overlay.batch_with_deferred_name_tree_nodes(store.batch());
        let mut batch = ReorgMeteredBatch::new(
            staged_batch,
            ReorgStagedEffectMeter::new(exact_limit),
            REORG_STAGING_OPERATION_COPIES,
        );
        batch
            .delete(ColumnFamily::Undo, &old_undo_key)
            .expect("meter disconnect undo deletion");
        batch
            .delete(ColumnFamily::Utxo, &shared_outpoint)
            .expect("meter disconnected coin deletion");
        batch
            .put(ColumnFamily::Utxo, &shared_outpoint, &replacement_coin)
            .expect("meter replacement coin");
        batch
            .put(ColumnFamily::Undo, &new_undo_key, &generated_large_undo)
            .expect("meter connect-generated undo");
        batch
            .put(ColumnFamily::TxIndex, &tx_index_key, &tx_index_value)
            .expect("meter transaction index");
        batch
            .put(ColumnFamily::NameState, &name_key, &name_state)
            .expect("meter name state");
        batch
            .put(
                ColumnFamily::NameTreeNodes,
                &name_node_key,
                &deferred_name_node,
            )
            .expect("meter deferred name node");

        assert_eq!(
            staged
                .get(ColumnFamily::Utxo, &shared_outpoint)
                .expect("staged replacement coin"),
            Some(replacement_coin.clone()),
            "disconnect/connect writes to one logical key must retain read-your-writes semantics"
        );
        assert_eq!(
            staged
                .get(ColumnFamily::Undo, &old_undo_key)
                .expect("staged disconnect undo"),
            None
        );
        assert_eq!(
            overlay
                .staged_family(ColumnFamily::NameTreeNodes)
                .get(name_node_key.as_slice())
                .cloned()
                .flatten(),
            Some(deferred_name_node.clone())
        );
        batch
            .charge_name_page_packing(&packing_records)
            .expect("exact-limit name-page packing");

        let (batch, meter) = batch.into_parts();
        assert_eq!(
            meter.consumed,
            phase_one_charge.saturating_add(packing_charge)
        );
        let mut batch = ReorgMeteredBatch::new(
            batch.into_inner(),
            meter,
            REORG_PUBLICATION_OPERATION_COPIES,
        );
        batch
            .charge_name_page_output(1)
            .expect("exact-limit physical name page");
        batch
            .put(ColumnFamily::Snapshots, page_key, &page_value)
            .expect("exact-limit page publication");
        assert_eq!(batch.meter.consumed, exact_limit);
        let error = batch
            .delete(ColumnFamily::Snapshots, b"one-operation-over")
            .expect_err("post-overlay page write must share the exhausted budget");
        assert!(matches!(
            error,
            StoreError::LimitExceeded {
                context: ReorgStagedEffectMeter::CONTEXT,
                limit,
                actual,
            } if limit == exact_limit && actual > limit
        ));
        assert_eq!(batch.meter.consumed, exact_limit);

        let (inner, _) = batch.into_parts();
        drop(staged);
        drop(base);
        drop(overlay);
        store.commit(inner).expect("commit exact-limit batch");
        let committed = store.snapshot().expect("committed meter snapshot");
        assert_eq!(
            committed
                .get(ColumnFamily::Utxo, &shared_outpoint)
                .expect("committed replacement coin"),
            Some(replacement_coin)
        );
        assert_eq!(
            committed
                .get(ColumnFamily::Undo, &old_undo_key)
                .expect("committed disconnect undo deletion"),
            None
        );
        assert_eq!(
            committed
                .get(ColumnFamily::Undo, &new_undo_key)
                .expect("committed generated undo"),
            Some(generated_large_undo)
        );
        assert_eq!(
            committed
                .get(ColumnFamily::NameTreeNodes, &name_node_key)
                .expect("deferred name node backend"),
            None,
            "deferred name nodes belong to the page map, not the backend batch"
        );
        assert_eq!(
            committed
                .get(ColumnFamily::Snapshots, page_key)
                .expect("committed page mutation"),
            Some(page_value)
        );
    }

    #[test]
    fn reorg_meter_rejects_one_budget_byte_over_before_any_staging_copy() {
        let store = StoreHandle::memory();
        let key = [0xa1; 32];
        let value = vec![0xa2; 64 * 1024];
        let charge = ReorgStagedEffectMeter::operation_charge(
            key.len(),
            value.len(),
            REORG_STAGING_OPERATION_COPIES,
        );
        let limit = charge.checked_sub(1).expect("positive operation charge");
        let overlay = StagingOverlay::new();
        let staged_batch = overlay.batch(store.batch());
        let mut batch = ReorgMeteredBatch::new(
            staged_batch,
            ReorgStagedEffectMeter::new(limit),
            REORG_STAGING_OPERATION_COPIES,
        );

        let error = batch
            .put(ColumnFamily::Undo, &key, &value)
            .expect_err("one budget byte over");
        assert!(matches!(
            error,
            StoreError::LimitExceeded {
                context: ReorgStagedEffectMeter::CONTEXT,
                limit: error_limit,
                actual,
            } if error_limit == limit && actual == charge
        ));
        assert_eq!(batch.meter.consumed, 0);
        assert!(overlay.staged_family(ColumnFamily::Undo).is_empty());
        let (batch, _) = batch.into_parts();
        store
            .commit(batch.into_inner())
            .expect("rejected batch remains empty");
        assert_eq!(
            store
                .snapshot()
                .expect("post-rejection snapshot")
                .get(ColumnFamily::Undo, &key)
                .expect("post-rejection lookup"),
            None
        );
    }

    #[test]
    fn reorg_meter_rejects_one_byte_over_physical_page_before_output() {
        let charge = ReorgStagedEffectMeter::name_page_output_charge(1);
        let limit = charge.checked_sub(1).expect("positive page charge");
        let mut meter = ReorgStagedEffectMeter::new(limit);
        let error = meter
            .charge_name_page_output(1)
            .expect_err("one byte over fixed-size page output");
        assert!(matches!(
            error,
            StoreError::LimitExceeded {
                context: ReorgStagedEffectMeter::CONTEXT,
                limit: error_limit,
                actual,
            } if error_limit == limit && actual == charge
        ));
        assert_eq!(meter.consumed, 0);
    }

    #[test]
    fn reorg_meter_rejects_one_byte_over_before_name_page_pack_allocations() {
        let modeled_per_record_metadata = std::mem::size_of::<(TreeRoot, Vec<u8>)>()
            .saturating_add(std::mem::size_of::<(TreeRoot, &[u8])>())
            .saturating_add(3usize.saturating_mul(std::mem::size_of::<TreeRoot>()))
            .saturating_add(std::mem::size_of::<(TreeRoot, hns_store::NamePageAddress)>())
            .saturating_add(std::mem::size_of::<hns_store::NamePageRecord>());
        assert!(
            modeled_per_record_metadata.saturating_mul(2)
                <= REORG_NAME_PAGE_PACKING_METADATA_BYTES_PER_RECORD as usize,
            "the 1 KiB packing allowance must cover modeled structs plus 2x container headroom"
        );
        let records = BTreeMap::from([(TreeRoot::new([0xb1; 32]), vec![0xb2; 8 * 1024])]);
        let charge = ReorgStagedEffectMeter::name_page_packing_charge(&records);
        let limit = charge.checked_sub(1).expect("positive packing charge");
        let mut meter = ReorgStagedEffectMeter::new(limit);
        let error = meter
            .charge_name_page_packing(&records)
            .expect_err("one byte over name-page packing budget");
        assert!(matches!(
            error,
            StoreError::LimitExceeded {
                context: ReorgStagedEffectMeter::CONTEXT,
                limit: error_limit,
                actual,
            } if error_limit == limit && actual == charge
        ));
        assert_eq!(meter.consumed, 0);
    }

    #[test]
    fn rollback_uncommitted_tail_removes_a_prepared_segment_seal() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-name-page-seal-rollback-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let initialized = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize seal rollback store");
        drop(initialized);
        let mut pages =
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("open pages");
        let state_before = pages.state.clone();
        let path_before = pages.file_path.clone();
        let store_before = complete_store_image(&store);
        let successor_path = name_page_file_path(
            &directory,
            state_before.manifest.generation,
            state_before.manifest.active_segment + 1,
        );

        let snapshot = store.snapshot().expect("seal rollback snapshot");
        let (reader, legacy) = pages
            .reader_for_roots(&snapshot, std::iter::empty(), false)
            .expect("seal rollback reader");
        assert!(!legacy);
        let mut batch = store.batch();
        let prepared = pages
            .prepare_root(
                &snapshot,
                &mut batch,
                &reader,
                BTreeMap::new(),
                &[],
                NamePageRootTarget {
                    root: state_before.root,
                    height: Some(NAME_PAGE_SEGMENT_BLOCKS),
                },
            )
            .expect("prepare unpublished segment seal");
        assert_eq!(
            prepared.manifest.active_segment,
            state_before.manifest.active_segment + 1
        );
        assert!(successor_path.exists());
        assert_eq!(pages.file_path, successor_path);
        drop(reader);
        drop(snapshot);
        drop(batch);

        pages
            .rollback_uncommitted_tail()
            .expect("roll back unpublished segment seal");
        assert!(!successor_path.exists());
        assert_eq!(pages.file_path, path_before);
        assert_eq!(pages.state, state_before);
        assert_eq!(pages.generation_bytes, pages.committed_generation_bytes);
        assert_eq!(complete_store_image(&store), store_before);

        drop(pages);
        std::fs::remove_dir_all(directory).expect("remove seal rollback fixture");
    }

    #[test]
    fn commits_name_page_synthetic_segment_seal() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-name-page-synthetic-seal-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let mut state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize synthetic seal state");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("open pages"),
        );

        let store_before = complete_store_image(&store);
        let before = state
            .name_pages
            .as_ref()
            .expect("page storage");
        let before_generation = before.state.manifest.generation;
        let before_active_segment = before.state.manifest.active_segment;
        let expected_path = name_page_file_path(
            &directory,
            before_generation,
            before_active_segment + 1,
        );

        commit_test_name_page_seal(&mut state, NAME_PAGE_SEGMENT_BLOCKS)
            .expect("commit synthetic segment seal");

        let after = state
            .name_pages
            .as_ref()
            .expect("page storage");
        let after_active_segment = after.state.manifest.active_segment;
        assert_eq!(after_active_segment, before_active_segment + 1);
        assert_eq!(after.state.manifest.generation, before_generation);
        assert!(expected_path.exists());
        let snapshot = store.snapshot().expect("store snapshot");
        assert!(snapshot
            .get(ColumnFamily::Snapshots, &NAME_PAGE_STATE_KEY)
            .expect("read page state")
            .is_some());
        drop(snapshot);

        assert_ne!(complete_store_image(&store), store_before);

        std::fs::remove_dir_all(directory).expect("remove synthetic seal fixture");
    }

    #[test]
    fn online_pruned_name_pages_compact_after_sixteen_segments() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();

        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));

        let directory = test_root.join(format!(
            "hsrd-online-name-page-compaction-{}-{nonce}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();

        let mut state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize state");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("open name pages"),
        );
        state.undo_retention_policy = Some(UndoRetentionPolicy::for_network(Network::Regtest));

        let initial_generation = state
            .name_pages
            .as_ref()
            .expect("name pages")
            .state
            .manifest
            .generation;

        let mut reports = Vec::new();

        // Nineteen seals means the process passes the normal
        // sixteen-segment threshold and continues operating
        // after the generation rewrite.
        for seal in 1_u32..=19 {
            let height = seal
                .checked_mul(NAME_PAGE_SEGMENT_BLOCKS)
                .expect("seal height");

            commit_test_name_page_seal(&mut state, height).expect("commit synthetic seal");

            if let Some(report) = state
                .compact_pruned_name_pages_if_due()
                .expect("run online compaction")
            {
                reports.push(report);
            }

            let pages = state.name_pages.as_ref().expect("pages");
            assert!(
                pages.state.manifest.active_segment
                    < NAME_PAGE_COMPACTION_SEGMENT_THRESHOLD,
                "maintenance must rewrite the generation before another committed operation can leave it at or above the threshold"
            );
        }

        assert_eq!(
            reports.len(),
            1,
            "nineteen seals should cross the threshold once"
        );

        let report = &reports[0];
        assert_eq!(report.previous_generation, initial_generation);
        assert!(report.generation > initial_generation);

        let pages = state.name_pages.as_ref().expect("pages");
        assert_eq!(pages.state.manifest.generation, report.generation);
        assert_eq!(pages.state.manifest.active_segment, 3);

        drop(state);
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn near_envelope_generation_audits_compacts_and_reopens() {
        const TEST_RECORDS: u64 = 512;

        let spill_bytes = TEST_RECORDS
            .checked_mul(
                NAME_PAGE_VALIDATION_RECORD_BYTES as u64,
            )
            .expect("spill bytes");

        let fixture = build_test_node_page_generation(
            TEST_RECORDS as usize,
        );

        // Simulate process exit.
        drop(fixture.live_state);

        let store = fixture.store.clone();
        let mut pages = NamePageStorage::open_or_bootstrap(
            fixture.directory.clone(),
            &store,
            Network::Regtest,
        )
        .expect("reopen near-envelope generation");

        let snapshot = store.snapshot().expect("near-envelope snapshot");
        let (reader, legacy) = pages
            .reader_for_roots(&snapshot, std::iter::empty(), false)
            .expect("open near-envelope reader");
        assert!(!legacy);

        let now = Instant::now();
        let limits = name_page_validation_limits_with_spill(
            &snapshot,
            Network::Regtest,
            spill_bytes,
            now
                .checked_add(Duration::from_secs(30))
                .unwrap_or(now),
        )
        .expect("test limits");

        let validation = reader
            .validate_committed_pages_with_limits(limits)
            .expect("audit near spill envelope");

        assert_eq!(
            validation.records,
            TEST_RECORDS,
        );

        drop(reader);
        drop(snapshot);

        let previous_generation = pages.state.manifest.generation;

        let report = pages
            .compact_generation(&store)
            .expect("compact near-envelope generation");

        assert_eq!(
            report.previous_generation,
            previous_generation,
        );
        assert!(
            report.generation > previous_generation,
        );

        drop(pages);

        // Second restart proves publication and cleanup left
        // a self-consistent generation.
        let reopened = NamePageStorage::open_or_bootstrap(
            fixture.directory.clone(),
            &store,
            Network::Regtest,
        )
        .expect("reopen compacted generation");

        assert_eq!(
            reopened.state.manifest.generation,
            report.generation,
        );
        assert_eq!(
            reopened.state.manifest.active_segment,
            0,
        );

        drop(reopened);
        std::fs::remove_dir_all(fixture.directory).expect("remove restart fixture");
    }

    #[test]
    fn failed_name_page_tail_rollback_fences_node_storage() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-name-page-rollback-fence-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let mut state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize rollback fence store");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("open pages"),
        );
        // Deterministically make truncate validation fail after the rollback
        // has surrendered its live appender. This models remove/truncate/reopen
        // failures without relying on platform-specific open-file semantics.
        state
            .name_pages
            .as_mut()
            .expect("page storage")
            .state
            .manifest
            .durable_bytes = 1;
        let error = state
            .name_pages
            .as_mut()
            .expect("page storage")
            .rollback_uncommitted_tail()
            .expect_err("invalid committed boundary must fail rollback");
        assert!(
            format!("{error:#}").contains("storage is fenced until restart"),
            "{error:#}"
        );
        let pages = state.name_pages.as_ref().expect("fenced pages");
        assert!(pages.reopen_required);
        assert!(pages.appender.is_none());
        assert!(state.storage_reopen_required());
        let authority_error = state
            .ensure_storage_operational()
            .expect_err("fenced rollback must revoke node storage authority");
        assert!(
            authority_error.to_string().contains("restart and reopen"),
            "{authority_error:#}"
        );

        drop(state);
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove rollback fence fixture");
    }

    struct CountingNamePageSnapshot<'a, S> {
        inner: &'a S,
        locator_gets: Cell<usize>,
        locator_scans: Cell<usize>,
    }

    #[test]
    fn concurrent_safety_fences_preserve_one_first_cause_record() {
        const WORKERS: usize = 8;

        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize fenced store");
        let chain = state.chain.clone();
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut workers = Vec::new();
        for index in 0..WORKERS {
            let store = store.clone();
            let chain = chain.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                chain
                    .record_external_safety_fence(ProductionSafetyFence {
                        version: PRODUCTION_SAFETY_FENCE_VERSION,
                        kind: ProductionSafetyFenceKind::Storage,
                        context: format!("concurrent-first-cause-{index}"),
                        limit: 100,
                        actual: 101 + index as u64,
                        root: None,
                        candidate: None,
                        detail: format!("concurrent fence candidate {index}"),
                    })
                    .expect("persist concurrent fence");
                inspect_production_safety_fence(&store)
                    .expect("inspect concurrent fence")
                    .expect("fence exists")
                    .digest
            }));
        }
        let digests = workers
            .into_iter()
            .map(|worker| worker.join().expect("fence worker"))
            .collect::<Vec<_>>();
        assert!(digests.windows(2).all(|pair| pair[0] == pair[1]));
        let first = inspect_production_safety_fence(&store)
            .expect("inspect first cause")
            .expect("first cause");

        chain
            .record_external_safety_fence(ProductionSafetyFence {
                version: PRODUCTION_SAFETY_FENCE_VERSION,
                kind: ProductionSafetyFenceKind::PayloadSegmentCompaction,
                context: "later-different-cause".to_owned(),
                limit: 1,
                actual: 2,
                root: None,
                candidate: None,
                detail: "must not replace first cause".to_owned(),
            })
            .expect("later fence remains idempotent");
        let final_evidence = inspect_production_safety_fence(&store)
            .expect("inspect final fence")
            .expect("final fence");
        assert_eq!(final_evidence.encoded, first.encoded);
        assert_eq!(final_evidence.digest, first.digest);
    }

    #[test]
    fn waiting_writer_rechecks_fence_after_acquiring_inner_lock() {
        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize writer-race store");
        let chain = state.chain.clone();
        let reader = chain.inner.read().expect("hold inner read lock");
        let (prechecked_tx, prechecked_rx) = std::sync::mpsc::sync_channel(0);
        let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
        let mutated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_mutated = Arc::clone(&mutated);
        let worker_chain = chain.clone();
        let worker = std::thread::spawn(move || {
            worker_chain.write_after_initial_check(
                || {
                    prechecked_tx.send(()).expect("announce initial precheck");
                    continue_rx.recv().expect("resume waiting writer");
                },
                |_index| {
                    worker_mutated.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            )
        });

        prechecked_rx.recv().expect("writer reached inner lock");
        chain
            .persist_first_cause(
                reader.store(),
                ProductionSafetyFence {
                    version: PRODUCTION_SAFETY_FENCE_VERSION,
                    kind: ProductionSafetyFenceKind::LiveHeaderOperation,
                    context: "deterministic writer admission race".to_owned(),
                    limit: 1,
                    actual: 2,
                    root: None,
                    candidate: Some(BlockHash::new([0x6a; 32])),
                    detail: "reader published while writer waited".to_owned(),
                },
            )
            .expect("reader publishes fence while retaining inner lock");
        continue_tx.send(()).expect("resume writer");
        drop(reader);

        let error = worker
            .join()
            .expect("writer thread")
            .expect_err("writer must reject the newly published fence");
        assert!(
            error
                .to_string()
                .contains("production safety fence blocks header mutation"),
            "unexpected writer error: {error}"
        );
        assert!(!mutated.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            inspect_production_safety_fence(&store)
                .expect("inspect writer-race fence")
                .expect("writer-race fence")
                .fence
                .context,
            "deterministic writer admission race"
        );
    }

    #[test]
    fn generic_header_fence_refuses_unproven_clear() {
        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize clear-refusal store");
        state
            .chain
            .record_external_safety_fence(ProductionSafetyFence {
                version: PRODUCTION_SAFETY_FENCE_VERSION,
                kind: ProductionSafetyFenceKind::LiveHeaderOperation,
                context: "header import records".to_owned(),
                limit: 2_000,
                actual: 2_001,
                root: None,
                candidate: Some(BlockHash::new([0x55; 32])),
                detail: "offline recovery required".to_owned(),
            })
            .expect("persist generic header fence");
        let evidence = inspect_production_safety_fence(&store)
            .expect("inspect generic fence")
            .expect("generic fence");
        let error = clear_production_safety_fence_validated(
            &store,
            Network::Regtest,
            ProductionSafetyFenceClearRequest {
                expected_digest: evidence.digest,
                acknowledgement:
                    ProductionSafetyFenceClearAcknowledgement::OfflineRecoveryCompletedAndVerified,
                name_page_directory: None,
            },
        )
        .expect_err("generic header clear lacks typed proof");
        assert!(error
            .to_string()
            .contains("no safe automatic recovery proof"));
        assert_eq!(
            inspect_production_safety_fence(&store)
                .expect("reinspect generic fence")
                .expect("generic fence remains")
                .encoded,
            evidence.encoded
        );
    }

    #[test]
    fn alternate_header_budget_failure_records_typed_live_header_fence() {
        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize alternate-header fence store");
        let candidate = BlockHash::new([0x4a; 32]);
        {
            let index = state.chain.inner.read().expect("header index read lock");
            state
                .chain
                .record_resource_fence(
                    &index,
                    &ChainError::LiveWorkLimit {
                        context: "resident alternate headers",
                        limit: MAX_RESIDENT_ALTERNATE_HEADERS,
                        actual: MAX_RESIDENT_ALTERNATE_HEADERS + 1,
                    },
                    ProductionSafetyFenceKind::LiveHeaderOperation,
                    None,
                    Some(candidate),
                )
                .expect("persist alternate-header fence");
        }

        let evidence = inspect_production_safety_fence(&store)
            .expect("inspect alternate-header fence")
            .expect("alternate-header fence");
        assert_eq!(
            evidence.fence.kind,
            ProductionSafetyFenceKind::LiveHeaderOperation
        );
        assert_eq!(evidence.fence.context, "resident alternate headers");
        assert_eq!(evidence.fence.limit, MAX_RESIDENT_ALTERNATE_HEADERS as u64);
        assert_eq!(
            evidence.fence.actual,
            MAX_RESIDENT_ALTERNATE_HEADERS as u64 + 1
        );
        assert_eq!(evidence.fence.candidate, Some(candidate));
    }

    #[test]
    fn reorganization_fence_without_candidate_and_generic_storage_fence_refuse_clear() {
        for (kind, context, expected) in [
            (
                ProductionSafetyFenceKind::LiveHeaderReorganization,
                "reorg disconnect",
                "typed candidate identity",
            ),
            (
                ProductionSafetyFenceKind::Storage,
                "unknown storage recovery",
                "operation-specific automatic recovery proof",
            ),
        ] {
            let store = StoreHandle::memory();
            let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
                .expect("initialize refusal store");
            state
                .chain
                .record_external_safety_fence(ProductionSafetyFence {
                    version: PRODUCTION_SAFETY_FENCE_VERSION,
                    kind,
                    context: context.to_owned(),
                    limit: 1,
                    actual: 2,
                    root: None,
                    candidate: None,
                    detail: "typed recovery evidence is unavailable".to_owned(),
                })
                .expect("persist refusal fence");
            let evidence = inspect_production_safety_fence(&store)
                .expect("inspect refusal fence")
                .expect("refusal fence");
            let error = clear_production_safety_fence_validated(
                &store,
                Network::Regtest,
                ProductionSafetyFenceClearRequest {
                    expected_digest: evidence.digest,
                    acknowledgement:
                        ProductionSafetyFenceClearAcknowledgement::OfflineRecoveryCompletedAndVerified,
                    name_page_directory: None,
                },
            )
            .expect_err("untyped fence must refuse clear");
            assert!(error.to_string().contains(expected), "{error:#}");
            assert_eq!(
                inspect_production_safety_fence(&store)
                    .expect("reinspect refusal fence")
                    .expect("refusal fence remains")
                    .digest,
                evidence.digest
            );
        }
    }

    #[test]
    fn reorganization_fence_clears_when_exact_candidate_was_removed_offline() {
        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize missing-candidate store");
        let candidate = BlockHash::new([0x73; 32]);
        state
            .chain
            .record_external_safety_fence(ProductionSafetyFence {
                version: PRODUCTION_SAFETY_FENCE_VERSION,
                kind: ProductionSafetyFenceKind::LiveHeaderReorganization,
                context: "reorg connect".to_owned(),
                limit: 1_024,
                actual: 1_025,
                root: None,
                candidate: Some(candidate),
                detail: "offline candidate removal required".to_owned(),
            })
            .expect("persist reorganization fence");
        let evidence = inspect_production_safety_fence(&store)
            .expect("inspect reorganization fence")
            .expect("reorganization fence");
        let cleared = clear_production_safety_fence_validated(
            &store,
            Network::Regtest,
            ProductionSafetyFenceClearRequest {
                expected_digest: evidence.digest,
                acknowledgement:
                    ProductionSafetyFenceClearAcknowledgement::OfflineRecoveryCompletedAndVerified,
                name_page_directory: None,
            },
        )
        .expect("removed exact candidate resolves reorganization fence");
        assert_eq!(cleared.digest, evidence.digest);
        assert!(inspect_production_safety_fence(&store)
            .expect("inspect cleared reorganization fence")
            .is_none());
    }

    #[test]
    fn payload_compaction_fence_refuses_clear_without_bounded_scrub() {
        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize payload-fence store");
        state
            .chain
            .record_external_safety_fence(ProductionSafetyFence {
                version: PRODUCTION_SAFETY_FENCE_VERSION,
                kind: ProductionSafetyFenceKind::PayloadSegmentCompaction,
                context: "segment compaction output bytes".to_owned(),
                limit: 150_000_000_000,
                actual: 150_000_000_001,
                root: None,
                candidate: None,
                detail: "bounded authenticated scrub required".to_owned(),
            })
            .expect("persist payload fence");
        let evidence = inspect_production_safety_fence(&store)
            .expect("inspect payload fence")
            .expect("payload fence");
        let error = clear_production_safety_fence_validated(
            &store,
            Network::Regtest,
            ProductionSafetyFenceClearRequest {
                expected_digest: evidence.digest,
                acknowledgement:
                    ProductionSafetyFenceClearAcknowledgement::OfflineRecoveryCompletedAndVerified,
                name_page_directory: None,
            },
        )
        .expect_err("payload clear requires a bounded scrub");
        assert!(
            error.to_string().contains("bounded authenticated scrub"),
            "{error:#}"
        );
        assert_eq!(
            inspect_production_safety_fence(&store)
                .expect("reinspect payload fence")
                .expect("payload fence remains")
                .digest,
            evidence.digest
        );
    }

    #[test]
    fn name_page_compaction_fence_clears_only_after_bounded_physical_audit() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-name-page-fence-clear-{}-{nonce}",
            std::process::id()
        ));
        let store = StoreHandle::memory();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize page-fence store");
        drop(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("bootstrap authoritative pages"),
        );
        state
            .chain
            .record_external_safety_fence(ProductionSafetyFence {
                version: PRODUCTION_SAFETY_FENCE_VERSION,
                kind: ProductionSafetyFenceKind::NamePageCompaction,
                context: "name-page root locator records".to_owned(),
                limit: MAX_NAME_PAGE_ROOT_LOCATORS,
                actual: MAX_NAME_PAGE_ROOT_LOCATORS + 1,
                root: None,
                candidate: None,
                detail: "offline compaction recovery required".to_owned(),
            })
            .expect("persist page fence");
        let evidence = inspect_production_safety_fence(&store)
            .expect("inspect page fence")
            .expect("page fence");

        let cleared = clear_production_safety_fence_validated(
            &store,
            Network::Regtest,
            ProductionSafetyFenceClearRequest {
                expected_digest: evidence.digest,
                acknowledgement:
                    ProductionSafetyFenceClearAcknowledgement::OfflineRecoveryCompletedAndVerified,
                name_page_directory: Some(directory.clone()),
            },
        )
        .expect("bounded physical audit clears recovered page fence");
        assert_eq!(cleared.digest, evidence.digest);
        assert!(inspect_production_safety_fence(&store)
            .expect("reinspect cleared page fence")
            .is_none());
        std::fs::remove_dir_all(directory).expect("remove page-fence directory");
    }

    impl<'a, S> CountingNamePageSnapshot<'a, S> {
        fn new(inner: &'a S) -> Self {
            Self {
                inner,
                locator_gets: Cell::new(0),
                locator_scans: Cell::new(0),
            }
        }
    }

    impl<S: ReadSnapshot> ReadSnapshot for CountingNamePageSnapshot<'_, S> {
        fn get(
            &self,
            family: ColumnFamily,
            key: &[u8],
        ) -> std::result::Result<Option<Vec<u8>>, hns_store::StoreError> {
            if family == ColumnFamily::Snapshots && key.starts_with(NAME_PAGE_ROOT_PREFIX) {
                self.locator_gets.set(self.locator_gets.get() + 1);
            }
            self.inner.get(family, key)
        }

        fn get_many(
            &self,
            family: ColumnFamily,
            keys: &[&[u8]],
        ) -> std::result::Result<Vec<Option<Vec<u8>>>, hns_store::StoreError> {
            self.inner.get_many(family, keys)
        }

        fn scan_prefix(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
        ) -> std::result::Result<Vec<hns_store::ScanEntry>, hns_store::StoreError> {
            if family == ColumnFamily::Snapshots && prefix == NAME_PAGE_ROOT_PREFIX {
                self.locator_scans.set(self.locator_scans.get() + 1);
            }
            self.inner.scan_prefix(family, prefix)
        }

        fn prefetch_name_tree_paths(
            &self,
            root: [u8; 32],
            keys: &[[u8; 32]],
        ) -> std::result::Result<Option<Vec<hns_store::NameTreePathRecord>>, hns_store::StoreError>
        {
            self.inner.prefetch_name_tree_paths(root, keys)
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct AllowAllInputVerifier;

    impl TransactionInputVerifier for AllowAllInputVerifier {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    #[test]
    fn experimental_registry_rpc_projection_preserves_bounded_totals() {
        let mut summary = DenuoSummary {
            local_service_mask: 0x1000_0001,
            advertised: true,
            ..DenuoSummary::default()
        };
        summary.live.awaiting_version = 1;
        summary.live.local_disabled = 2;
        summary.live.eligible = 3;
        summary.live.pending = 4;
        summary.live.negotiated = 5;
        summary.live.not_advertised = 6;
        summary.live.disabled = 7;
        summary.process.hello_admitted = 8;
        summary.process.hello_ack_admitted = 9;
        summary.process.hello_received = 10;
        summary.process.hello_ack_received = 11;
        summary.process.agreements_computed = 12;
        summary.process.rejected = 13;
        summary.process.disabled = 14;
        summary.rejection_reasons[9].count = 15;

        let projected = rpc_experimental_registry_info(&summary);

        assert_eq!(projected.local_service_mask, 0x1000_0001);
        assert!(projected.advertised);
        assert_eq!(projected.awaiting_version_peers, 1);
        assert_eq!(projected.local_disabled_peers, 2);
        assert_eq!(projected.eligible_peers, 3);
        assert_eq!(projected.negotiating_peers, 4);
        assert_eq!(projected.negotiated_peers, 5);
        assert_eq!(projected.not_advertised_peers, 6);
        assert_eq!(projected.disabled_peers, 7);
        assert_eq!(projected.outbound_messages_admitted, 17);
        assert_eq!(projected.inbound_messages_received, 21);
        assert_eq!(projected.agreements_computed, 12);
        assert_eq!(projected.rejected_messages, 13);
        assert_eq!(projected.disabled_sessions, 14);
        assert_eq!(projected.rejection_reasons.len(), 18);
        assert_eq!(projected.rejection_reasons[9].reason, "wrong-fingerprint");
        assert_eq!(projected.rejection_reasons[9].count, 15);
    }

    #[test]
    fn hip76_rpc_projection_is_qname_free_and_distinguishes_write_stages() {
        let mut peer = hns_p2p::PeerSnapshot::new(
            hns_p2p::PeerId(7),
            "127.0.0.1:12038".parse().expect("peer address"),
            hns_p2p::PeerDirection::Outbound,
        );
        peer.hip76.requester_eligible = true;
        peer.hip76.remote_provider_advertised = true;
        peer.hip76.registry_negotiated = true;
        peer.hip76.outbound_live_requests = 1;
        peer.hip76.process.outbound_requests_created = 3;
        peer.hip76.process.outbound_requests_queue_admitted = 2;
        peer.hip76.process.outbound_requests_socket_written = 1;
        peer.hip76.process.outbound_socket_write_failures = 1;
        peer.hip76.process.outbound_queue_dropped_stale = 1;

        let projected = rpc_hip76_info(&[peer]);

        assert_eq!(projected.request_packet_type, 0xf0);
        assert_eq!(projected.response_packet_type, 0xf1);
        assert_eq!(projected.requester_default, "auto");
        assert!(!projected.provider_default_opted_in);
        assert_eq!(projected.live_peers, 1);
        assert_eq!(projected.awaiting_registry_peers, 1);
        assert_eq!(projected.requester_eligible_peers, 1);
        assert_eq!(projected.remote_provider_advertised_peers, 1);
        assert_eq!(projected.registry_negotiated_peers, 1);
        assert_eq!(projected.outbound_live_requests, 1);
        assert_eq!(projected.outbound_requests_created, 3);
        assert_eq!(projected.outbound_requests_queue_admitted, 2);
        assert_eq!(projected.outbound_requests_socket_written, 1);
        assert_eq!(projected.outbound_socket_write_failures, 1);
        assert_eq!(projected.outbound_queue_dropped_stale, 1);

        let json = serde_json::to_string(&projected).expect("serialize HIP-76 diagnostics");
        for forbidden_key in [
            "\"qname\"",
            "\"request_id\"",
            "\"query\"",
            "\"response\"",
            "\"status\"",
            "\"deadline\"",
        ] {
            assert!(!json.contains(forbidden_key));
        }
    }

    #[test]
    fn odoh_rpc_projection_is_qname_free_and_exposes_false_provider_roles() {
        let mut runtime = OdohRequesterRuntime::new(
            OdohNetworkBinding::for_network(Network::Regtest),
            OdohRequesterConfig {
                allow_private_targets: true,
                ..OdohRequesterConfig::default()
            },
            7,
            1_700_000_000,
        )
        .expect("ODoH requester");
        let projected = rpc_odoh_info(&runtime.status(1_700_000_000, 2));

        assert_eq!(projected.phase, "awaiting-target");
        assert!(projected.requester_enabled);
        assert!(projected.requester_default_enabled);
        assert_eq!(projected.eligible_authenticated_proxies, 2);
        assert!(!projected.proxy_provider_available);
        assert!(!projected.target_provider_available);
        assert!(!projected.output_provider_available);

        let json = serde_json::to_string(&projected).expect("serialize HIP-77 diagnostics");
        for forbidden_key in [
            "\"qname\"",
            "\"request_id\"",
            "\"locator\"",
            "\"query\"",
            "\"response\"",
            "\"deadline\"",
            "\"hpke\"",
        ] {
            assert!(!json.contains(forbidden_key));
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid fixture hex"),
            }
        }

        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn mine_header(mut header: Header) -> Header {
        while !header.verify_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn unmined_header(mut header: Header) -> Header {
        while header.verify_pow() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        header
    }

    fn strict_header_record(
        header: Header,
        height: Height,
        parent: Option<&HeaderRecord>,
    ) -> HeaderRecord {
        hns_chain::prepare_header_record(
            &HeaderImport {
                header,
                height,
                verify_pow: false,
                checkpoint_valid: true,
            },
            parent,
        )
        .expect("strict fixture header record")
    }

    fn strict_header_store(records: &[HeaderRecord], best: BlockHash) -> StoreHandle {
        let store = StoreHandle::memory();
        hns_store::initialize_schema(&store).expect("initialize strict header store");
        let mut batch = store.batch();
        for record in records {
            write_record_to_batch(&mut batch, record).expect("stage strict header record");
        }
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                best.as_bytes(),
            )
            .expect("stage strict best header");
        store.commit(batch).expect("commit strict header store");
        store
    }

    fn regtest_genesis_record() -> HeaderRecord {
        strict_header_record(Network::Regtest.params().genesis_header(), 0, None)
    }

    fn regtest_child_record(
        parent: &HeaderRecord,
        time: u64,
        bits: u32,
        require_pow: bool,
    ) -> HeaderRecord {
        let header = Header {
            prev_block: parent.hash,
            time,
            bits,
            ..Header::default()
        };
        let header = if require_pow {
            mine_header(header)
        } else {
            unmined_header(header)
        };
        strict_header_record(header, parent.height + 1, Some(parent))
    }

    // Raw HSD `getblockheader <hash> false` response for mainnet height
    // 258,026. Decoding and hashing it independently pins the evidence record
    // used by the route-selection regression.
    fn mainnet_last_checkpoint_header() -> Header {
        Header::decode(&decode_hex(concat!(
            "ae1ebfdaa78774670000000000000000000000054d923439cdafbf40d980a448",
            "687053dedb9934d35a7085bd967da7195d1ae31a46bae2fe4cf90e2443cbf54e",
            "8540a78683d800169ec05af100000c161e202b1a000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000027c5674f4b376b4f42b6139200bbccf3749fffe73059343c87cb5e7b",
            "fb881199ab88ae44b219160ac32e82d68183580b2de7e3e0241b7573fdb03482",
            "416f883d0000000075ce05190000000000000000000000000000000000000000",
            "000000000000000000000000"
        )))
        .expect("decode mainnet checkpoint header")
    }

    #[test]
    fn historical_route_requires_branch_bound_checkpoint_evidence() {
        let checkpoint = *Network::Mainnet
            .checkpoints()
            .last()
            .expect("mainnet checkpoint");
        let header = mainnet_last_checkpoint_header();
        assert_eq!(header.hash(), checkpoint.hash);
        let status = BlockStatus {
            header_context_valid: true,
            checkpoint_valid: true,
            ..BlockStatus::default()
        };
        let checkpoint_record = HeaderRecord {
            hash: checkpoint.hash,
            height: checkpoint.height,
            chainwork: Uint256::from_u64(1),
            header,
            status: status.clone(),
        };
        let candidate_height = checkpoint.height - 1;
        let candidate_hash = BlockHash::new([0x42; 32]);
        let full = HistoricalValidationPlan::full();
        let historical = HistoricalValidationPlan::hsd_checkpointed();

        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                candidate_height,
                candidate_hash,
                &status,
                Some((candidate_hash, checkpoint.hash)),
                Some(&checkpoint_record),
            ),
            historical
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                candidate_height,
                candidate_hash,
                &status,
                Some((BlockHash::new([0x43; 32]), checkpoint.hash)),
                Some(&checkpoint_record),
            ),
            full,
            "a candidate on another header branch must fail closed"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                candidate_height,
                candidate_hash,
                &status,
                None,
                Some(&checkpoint_record),
            ),
            full,
            "missing canonical checkpoint evidence must fail closed"
        );

        let mut invalid_checkpoint_record = checkpoint_record.clone();
        invalid_checkpoint_record.status.checkpoint_valid = false;
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                candidate_height,
                candidate_hash,
                &status,
                Some((candidate_hash, checkpoint.hash)),
                Some(&invalid_checkpoint_record),
            ),
            full,
            "an unverified checkpoint record must fail closed"
        );

        let mut unverified = status.clone();
        unverified.checkpoint_valid = false;
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                candidate_height,
                candidate_hash,
                &unverified,
                Some((candidate_hash, checkpoint.hash)),
                Some(&checkpoint_record),
            ),
            full,
            "an unverified candidate must fail closed"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                checkpoint.height,
                checkpoint.hash,
                &status,
                None,
                None,
            ),
            historical,
            "the strictly validated checkpoint block supplies its own binding"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                checkpoint.height,
                BlockHash::new([0x45; 32]),
                &status,
                None,
                None,
            ),
            full,
            "a wrong hash at the selected checkpoint must fail closed"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint,
                checkpoint.height + 1,
                BlockHash::new([0x44; 32]),
                &status,
                None,
                None,
            ),
            full
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Regtest,
                checkpoint,
                1,
                candidate_hash,
                &status,
                None,
                None,
            ),
            full,
            "networks without checkpoints never select the shortcut"
        );

        let intermediate = Network::Mainnet.checkpoints()[2];
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                intermediate,
                intermediate.height,
                intermediate.hash,
                &status,
                None,
                None,
            ),
            historical,
            "an exact configured intermediate checkpoint must authorize its own height"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                intermediate,
                intermediate.height + 1,
                BlockHash::new([0x46; 32]),
                &status,
                None,
                None,
            ),
            full,
            "an intermediate checkpoint must not authorize later blocks"
        );

        let unknown = Checkpoint {
            height: intermediate.height,
            hash: BlockHash::new([0x47; 32]),
        };
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                unknown,
                unknown.height,
                unknown.hash,
                &status,
                None,
                None,
            ),
            full,
            "an unconfigured checkpoint value must fail closed"
        );
    }

    fn transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([9; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 10,
                address: Address::new(0, vec![4; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn coinbase_transaction() -> Transaction {
        coinbase_transaction_with_address(6, 50)
    }

    fn coinbase_transaction_with_address(address_byte: u8, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value,
                address: Address::new(0, vec![address_byte; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn coinbase_transaction_with_tag(tag: u32, value: u64) -> Transaction {
        let mut program = vec![0x51; 20];
        program[..4].copy_from_slice(&tag.to_le_bytes());
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value,
                address: Address::new(0, program).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn open_coinbase_transaction(name: &[u8]) -> Transaction {
        let mut transaction = coinbase_transaction();
        let name_hash = NameHash::new(hns_primitives::sha3_256(name));
        transaction.outputs.push(Output {
            value: 0,
            address: Address::new(0, vec![7; 20]).expect("address"),
            covenant: Covenant {
                kind: CovenantKind::Open,
                items: vec![
                    name_hash.as_bytes().to_vec(),
                    0u32.to_le_bytes().to_vec(),
                    name.to_vec(),
                ],
            },
        });
        transaction
    }

    fn open_transaction(name: &[u8], previous_output: Outpoint) -> Transaction {
        let mut transaction = open_coinbase_transaction(name);
        transaction.inputs[0].previous_output = previous_output;
        transaction.outputs.remove(0);
        transaction
    }

    fn block_with_commitments(transactions: Vec<Transaction>) -> hns_primitives::Block {
        let mut block = hns_primitives::Block {
            header: Header {
                nonce: 10,
                ..Header::default()
            },
            transactions,
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        block
    }

    #[test]
    fn stateless_body_validation_evidence_is_bound_to_exact_block_and_height() {
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let proof = StatelessBodyValidation::for_block(&block, 17, Network::Regtest);
        let request = NodeBlockImport::from_peer(block.clone(), 17);
        proof.verify(&request).expect("matching worker evidence");
        proof
            .verify(&NodeBlockImport::fixture(block.clone(), 17, 1))
            .expect("test-only fixture policy accepts exact worker evidence");
        let prepared = PreparedNativeActivation::new(vec![proof]).expect("prepared activation");
        prepared
            .authenticate(&NodeReorg {
                disconnect: Vec::new(),
                connect: vec![request.clone()],
            })
            .expect("prepared activation identity");
        prepared
            .clone()
            .into_single_for(&request)
            .expect("prepared direct-extension identity");
        assert!(PreparedNativeActivation::default()
            .into_single_for(&request)
            .is_err());
        assert!(PreparedNativeActivation::new(vec![proof, proof]).is_err());

        let wrong_height = NodeBlockImport::from_peer(block.clone(), 18);
        assert!(proof.verify(&wrong_height).is_err());
        assert!(prepared
            .authenticate(&NodeReorg {
                disconnect: Vec::new(),
                connect: vec![wrong_height.clone()],
            })
            .is_err());
        assert!(prepared.clone().into_single_for(&wrong_height).is_err());

        let mut mutated = block;
        mutated.header.nonce = mutated.header.nonce.saturating_add(1);
        let mutated = NodeBlockImport::from_peer(mutated, 17);
        assert!(proof.verify(&mutated).is_err());

        let historical = StatelessBodyValidation::for_block(
            request.block(),
            Network::Mainnet.params().tx_start,
            Network::Mainnet,
        );
        assert!(historical.covers(HistoricalValidationPlan::hsd_checkpointed()));
        assert!(!historical.covers(HistoricalValidationPlan::full()));
    }

    fn connect_empty_chain_to_height_one(node: &mut NodeService) -> BlockIndexRecord {
        let first = block_with_commitments(vec![coinbase_transaction_with_address(60, 50)]);
        let first = node
            .connect_block(NodeBlockImport::fixture(first, 0, 1))
            .expect("connect first block");
        let mut second = block_with_commitments(vec![coinbase_transaction_with_address(61, 50)]);
        second.header.prev_block = first.hash;
        node.connect_block(NodeBlockImport::fixture(second, 1, 2))
            .expect("connect second block")
    }

    fn connect_fixture_chain(
        node: &mut NodeService,
        tip_height: Height,
        open_name_at: Option<Height>,
    ) -> Vec<BlockIndexRecord> {
        let mut records = Vec::new();
        let mut coinbase_txids = Vec::new();
        let mut previous = BlockHash::ZERO;
        for height in 0..=tip_height {
            let coinbase = coinbase_transaction_with_tag(height, 50);
            let mut transactions = vec![coinbase.clone()];
            if open_name_at == Some(height) {
                let spend_height = height.checked_sub(3).expect("mature OPEN input height");
                transactions.push(open_transaction(
                    b"undo-retention",
                    Outpoint {
                        txid: coinbase_txids[usize::try_from(spend_height).expect("spend height")],
                        index: 0,
                    },
                ));
            }
            let snapshot = node.state.store.snapshot().expect("name-tree snapshot");
            let tree_root =
                load_stored_name_tree_commit_root(&snapshot).expect("name-tree commit root");
            drop(snapshot);
            let mut block = block_with_commitments(transactions);
            block.header.prev_block = previous;
            block.header.tree_root = *tree_root.as_bytes();
            block.header.nonce = height.saturating_add(10);
            let record = node
                .connect_block(NodeBlockImport::fixture(
                    block,
                    height,
                    u64::from(height) + 1,
                ))
                .unwrap_or_else(|error| panic!("connect fixture height {height}: {error}"));
            previous = record.hash;
            records.push(record);
            coinbase_txids.push(coinbase.txid());
        }
        records
    }

    fn peer_transaction_node(tip_height: Height) -> NodeService {
        let config = NodeConfig {
            network: Network::Regtest,
            native_sync: NativeSyncConfig {
                enabled: true,
                listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
                ..NativeSyncConfig::default()
            },
            mining_engine: MiningEngineConfig {
                enabled: true,
                transaction_relay: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        };
        let mut node = NodeService::new(config);
        connect_fixture_chain(&mut node, tip_height, None);
        node
    }

    fn install_script_coin(node: &NodeService, outpoint: Outpoint, value: Amount, height: Height) {
        install_script_coin_with_script(node, outpoint, value, height, &[0x51]);
    }

    fn install_script_coin_with_script(
        node: &NodeService,
        outpoint: Outpoint,
        value: Amount,
        height: Height,
        script: &[u8],
    ) {
        let coin = Coin {
            outpoint,
            value,
            height,
            coinbase: false,
            address: Address::new(0, sha3_256(script).to_vec()).expect("script address"),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let mut batch = node.state.store.batch();
        write_coin_to_batch(&mut batch, &coin).expect("stage funding coin");
        node.state.store.commit(batch).expect("commit funding coin");
    }

    fn script_spend(previous_output: Outpoint, output_value: Amount) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output,
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![vec![0x51]],
                },
            }],
            outputs: vec![Output {
                value: output_value,
                address: Address::new(0, sha3_256(&[0x51]).to_vec()).expect("script address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn put_unreachable_name_node(store: &StoreHandle, byte: u8) -> [u8; 32] {
        let key = [byte; 32];
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::NameTreeNodes,
                &key,
                b"deliberately unreachable node",
            )
            .expect("stage unreachable node");
        store.commit(batch).expect("commit unreachable node");
        key
    }

    #[derive(serde::Deserialize)]
    struct AirdropFixture {
        faucet: AirdropFixtureProof,
        airdrop: AirdropFixtureProof,
    }

    #[derive(serde::Deserialize)]
    struct AirdropFixtureProof {
        raw: String,
        value: u64,
        version: u8,
        address: String,
        fee: u64,
        position: u32,
    }

    fn decode_fixture_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("fixture hex"))
            .collect()
    }

    fn fixture_airdrop_coinbase(proof: AirdropFixtureProof) -> (Transaction, u32) {
        let position = proof.position;
        let mut transaction =
            coinbase_transaction_with_address(6, Network::Regtest.params().block_reward(0));
        transaction.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![decode_fixture_hex(&proof.raw)],
            },
        });
        transaction.outputs.push(Output {
            value: proof.value - proof.fee,
            address: Address::new(proof.version, decode_fixture_hex(&proof.address))
                .expect("airdrop address"),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        });
        (transaction, position)
    }

    fn faucet_coinbase() -> (Transaction, u32) {
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        fixture_airdrop_coinbase(fixture.faucet)
    }

    fn goosig_airdrop_coinbase() -> (Transaction, u32) {
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        fixture_airdrop_coinbase(fixture.airdrop)
    }

    fn experimental_authority_config() -> NodeConfig {
        NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::NativeExperimental,
            acknowledge_incomplete_consensus: true,
            ..NodeConfig::default()
        }
    }

    fn active_state_native_config() -> NodeConfig {
        NodeConfig {
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
        }
    }

    fn mainnet_canary_config() -> NodeConfig {
        NodeConfig {
            network: Network::Mainnet,
            data_dir: Some(PathBuf::from("/tmp/hsrd-mainnet-canary-test")),
            rpc_authorization: Some(
                RpcAuthorizationHeader::new("Bearer mainnet-canary-test").expect("authorization"),
            ),
            authority_mode: AuthorityMode::Native,
            mainnet_canary: true,
            storage_durability: DurabilityPolicy::Sync,
            native_sync: NativeSyncConfig {
                enabled: true,
                connect_active_state: true,
                discovery: true,
                maximum_outbound: 4,
                ..NativeSyncConfig::default()
            },
            mining_engine: MiningEngineConfig {
                enabled: true,
                transaction_relay: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        }
    }

    fn store_fixture_alternate(
        node: &mut NodeService,
        mut block: Block,
        height: Height,
        chainwork: u64,
    ) -> BlockIndexRecord {
        let coinbase = block
            .transactions
            .first_mut()
            .expect("stored alternate fixture has a coinbase");
        assert!(
            hns_consensus::is_coinbase(coinbase),
            "stored alternate fixture begins with a coinbase"
        );
        coinbase.locktime = height;
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        let request = NodeBlockImport::fixture(block, height, chainwork);
        let validated = node
            .state()
            .validate_import(&request)
            .expect("validate alternate");
        node.state_mut()
            .store_validated_alternate(request, validated)
            .expect("store alternate")
            .record
    }

    #[test]
    fn valid_block_commit_publishes_targeted_caches_without_full_index_rescan() {
        let store = StoreHandle::memory();
        let mut state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let block = block_with_commitments(vec![coinbase_transaction_with_address(49, 50)]);
        let hash = block.hash();
        let request = NodeBlockImport::fixture(block, 0, 1);
        let validated = state.validate_import(&request).expect("validated block");

        // This unrelated malformed record makes a complete header-index reload
        // fail. A valid committed block only needs to publish its own durable
        // header/block records into the already validated in-memory indexes.
        let mut poison = store.batch();
        poison
            .put(ColumnFamily::Headers, &[0xfe; 32], &[0x01])
            .expect("poison header");
        store.commit(poison).expect("commit poison");

        let stored = state
            .store_validated_alternate(request, validated)
            .expect("targeted cache publication");
        assert_eq!(stored.record.hash, hash);
        assert_eq!(
            state
                .chain
                .header(&hash)
                .expect("cached header")
                .unwrap()
                .hash,
            hash
        );
        assert_eq!(
            state.blocks.block(&hash).expect("cached block").unwrap(),
            stored.record
        );
        assert!(
            StoredHeaderIndex::new(store).is_err(),
            "poison must prove that a full durable-index scan would fail"
        );
    }

    #[test]
    fn node_rpc_snapshot_reflects_fail_closed_mempool_admission() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        node.state_mut()
            .chain
            .import_header(HeaderImport {
                header: Header {
                    bits: Network::Regtest.params().pow.bits,
                    ..Header::default()
                },
                height: 0,
                verify_pow: false,
                checkpoint_valid: false,
            })
            .expect("header");
        let admission = node
            .state_mut()
            .mempool
            .submit(transaction())
            .expect("submit");
        assert!(matches!(
            admission,
            hns_mempool::Admission::Rejected { reason }
                if reason == "verified-mempool-context-required"
        ));

        let rpc = node.rpc_service().expect("rpc service");
        let response = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getmempoolinfo".to_owned(),
                params: Value::Null,
                id: Some(json!(1)),
            })
            .expect("response");

        assert_eq!(response.result.expect("result")["size"], 0);
    }

    #[test]
    fn peer_transaction_admission_uses_active_utxos_and_native_scripts() {
        let mut node = peer_transaction_node(0);
        let valid_outpoint = Outpoint {
            txid: Txid::new([0xa1; 32]),
            index: 0,
        };
        let invalid_outpoint = Outpoint {
            txid: Txid::new([0xa2; 32]),
            index: 0,
        };
        install_script_coin(&node, valid_outpoint.clone(), 10_000, 0);
        install_script_coin(&node, invalid_outpoint.clone(), 10_000, 0);

        let valid = script_spend(valid_outpoint, 9_000);
        let valid_txid = valid.txid();
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(valid)
                .expect("valid peer admission"),
            hns_mempool::Admission::Accepted(txid) if txid == valid_txid
        ));

        let mut invalid = script_spend(invalid_outpoint, 9_000);
        invalid.inputs[0].witness.items[0] = vec![0x00];
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(invalid)
                .expect("invalid peer admission"),
            hns_mempool::Admission::Rejected { reason }
                if reason.contains("witness program")
        ));
        assert_eq!(node.state.mempool.info().transaction_count, 1);
    }

    #[test]
    fn peer_airdrop_admission_populates_special_inventory_and_getdata_view() {
        let mut node = peer_transaction_node(0);
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let proof = hns_primitives::AirdropProof::decode(&decode_fixture_hex(&fixture.faucet.raw))
            .expect("faucet proof");
        let hash = proof.hash().expect("faucet hash");
        assert_eq!(
            node.mining_engine_accept_peer_airdrop(proof.clone())
                .expect("peer airdrop admission"),
            hns_mempool::AirdropAdmission::Accepted(hash)
        );
        assert_eq!(node.state.mempool.info().airdrop_count, 1);
        assert_eq!(node.mining_engine_mempool_airdrop(&hash), Some(proof));
        assert!(node
            .mining_engine_mempool_inventory(10)
            .contains(&hns_p2p::Inventory::airdrop(hash)));
        assert!(matches!(
            node.mining_engine_accept_peer_airdrop(
                node.mining_engine_mempool_airdrop(&hash)
                    .expect("retained proof")
            )
            .expect("duplicate peer airdrop"),
            hns_mempool::AirdropAdmission::Rejected { reason }
                if reason == "txn-already-in-mempool"
        ));
    }

    #[test]
    fn connected_and_disconnected_airdrop_coinbase_reconciles_special_pool() {
        let mut node = peer_transaction_node(0);
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let proof = hns_primitives::AirdropProof::decode(&decode_fixture_hex(&fixture.faucet.raw))
            .expect("faucet proof");
        let hash = proof.hash().expect("faucet hash");
        assert!(matches!(
            node.mining_engine_accept_peer_airdrop(proof)
                .expect("peer airdrop admission"),
            hns_mempool::AirdropAdmission::Accepted(accepted) if accepted == hash
        ));

        let tip = node
            .state()
            .best_block_tip()
            .expect("tip read")
            .expect("tip");
        let (mut coinbase, _) = faucet_coinbase();
        coinbase.locktime = 1;
        let mut block = block_with_commitments(vec![coinbase]);
        block.header.prev_block = tip.hash;
        block.header.nonce = 12;
        let record = node
            .connect_block(NodeBlockImport::fixture(block, 1, 2))
            .expect("connect airdrop block");
        assert_eq!(node.state.mempool.info().airdrop_count, 0);

        node.disconnect_block(NodeBlockDisconnect {
            block_hash: record.hash,
            height: 1,
        })
        .expect("disconnect airdrop block");
        assert_eq!(node.state.mempool.info().airdrop_count, 1);
        assert!(node.mining_engine_mempool_airdrop(&hash).is_some());
    }

    #[test]
    fn peer_transaction_admission_uses_hsd_standard_script_flags() {
        let mut node = peer_transaction_node(0);
        let outpoint = Outpoint {
            txid: Txid::new([0xa3; 32]),
            index: 0,
        };
        let script = [0xb3, 0x51];
        install_script_coin_with_script(&node, outpoint.clone(), 10_000, 0, &script);
        let mut transaction = script_spend(outpoint, 9_000);
        transaction.inputs[0].witness.items = vec![script.to_vec()];
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(transaction)
                .expect("standard script admission"),
            hns_mempool::Admission::Rejected { reason }
                if reason.contains("upgradable NOP is discouraged")
        ));
        assert_eq!(node.state.mempool.info().transaction_count, 0);
    }

    #[test]
    fn peer_transaction_admission_promotes_dependency_ordered_orphans() {
        let mut node = peer_transaction_node(0);
        let funding = Outpoint {
            txid: Txid::new([0xb1; 32]),
            index: 0,
        };
        install_script_coin(&node, funding.clone(), 30_000, 0);
        let parent = script_spend(funding, 28_000);
        let parent_txid = parent.txid();
        let child = script_spend(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            26_000,
        );
        let child_txid = child.txid();

        assert_eq!(
            node.mining_engine_accept_peer_transaction(child)
                .expect("orphan admission"),
            hns_mempool::Admission::Orphan(child_txid)
        );
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(parent)
                .expect("parent admission"),
            hns_mempool::Admission::Accepted(txid) if txid == parent_txid
        ));
        assert!(node.state.mempool.orphan(&child_txid).is_none());
        assert!(node.state.mempool.transaction(&child_txid).is_some());
        assert_eq!(node.state.mempool.info().transaction_count, 2);
    }

    #[test]
    fn peer_transaction_admission_enforces_hsd_exclusive_name_contracts() {
        let mut node = peer_transaction_node(200);
        let first_outpoint = Outpoint {
            txid: Txid::new([0xc1; 32]),
            index: 0,
        };
        let second_outpoint = Outpoint {
            txid: Txid::new([0xc2; 32]),
            index: 0,
        };
        install_script_coin(&node, first_outpoint.clone(), 10_000, 1);
        install_script_coin(&node, second_outpoint.clone(), 10_000, 1);
        let name = b"peercontextoverlay";
        let mut first = open_transaction(name, first_outpoint);
        first.inputs[0].witness.items = vec![vec![0x51]];
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(first)
                .expect("first OPEN admission"),
            hns_mempool::Admission::Accepted(_)
        ));

        let mut duplicate = open_transaction(name, second_outpoint);
        duplicate.inputs[0].witness.items = vec![vec![0x51]];
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(duplicate)
                .expect("duplicate OPEN admission"),
            hns_mempool::Admission::Rejected { reason }
                if reason == "name-already-in-mempool"
        ));
    }

    #[test]
    fn active_tip_revalidation_evicts_stale_name_transaction() {
        let mut node = peer_transaction_node(200);
        let mempool_outpoint = Outpoint {
            txid: Txid::new([0xd1; 32]),
            index: 0,
        };
        let block_outpoint = Outpoint {
            txid: Txid::new([0xd2; 32]),
            index: 0,
        };
        install_script_coin(&node, mempool_outpoint.clone(), 10_000, 1);
        install_script_coin(&node, block_outpoint.clone(), 10_000, 1);
        let name = b"posttiprevalidation";
        let mut mempool_open = open_transaction(name, mempool_outpoint);
        mempool_open.inputs[0].witness.items = vec![vec![0x51]];
        let mempool_txid = mempool_open.txid();
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(mempool_open)
                .expect("mempool OPEN admission"),
            hns_mempool::Admission::Accepted(_)
        ));
        let previous_generation = node.state.mempool.info().generation;

        let mut confirmed_open = open_transaction(name, block_outpoint);
        confirmed_open.inputs[0].witness.items = vec![vec![0x51]];
        let snapshot = node.state.store.snapshot().expect("active snapshot");
        let tip = best_block_tip_from_snapshot(&snapshot)
            .expect("active tip read")
            .expect("active tip");
        let tree_root = load_stored_name_tree_commit_root(&snapshot).expect("committed root");
        drop(snapshot);
        let mut block =
            block_with_commitments(vec![coinbase_transaction_with_tag(201, 50), confirmed_open]);
        block.header.prev_block = tip.hash;
        block.header.tree_root = *tree_root.as_bytes();
        block.header.nonce = 211;
        node.connect_block(NodeBlockImport::fixture(block, 201, 202))
            .expect("connect conflicting name block");

        assert!(node.state.mempool.transaction(&mempool_txid).is_none());
        assert_eq!(node.state.mempool.info().transaction_count, 0);
        assert_eq!(
            node.state.mempool.info().generation,
            previous_generation + 1
        );
    }

    #[test]
    fn reorg_readmits_disconnected_transaction_before_retained_child() {
        let mut node = peer_transaction_node(200);
        let funding = Outpoint {
            txid: Txid::new([0xd3; 32]),
            index: 0,
        };
        install_script_coin(&node, funding.clone(), 10_000, 1);
        let snapshot = node.state.store.snapshot().expect("active snapshot");
        let tip = best_block_tip_from_snapshot(&snapshot)
            .expect("active tip read")
            .expect("active tip");
        let tree_root = load_stored_name_tree_commit_root(&snapshot).expect("committed root");
        drop(snapshot);

        let parent = script_spend(funding, 9_000);
        let parent_txid = parent.txid();
        let mut old_block =
            block_with_commitments(vec![coinbase_transaction_with_tag(201, 50), parent]);
        old_block.header.prev_block = tip.hash;
        old_block.header.tree_root = *tree_root.as_bytes();
        old_block.header.nonce = 212;
        let old_record = node
            .connect_block(NodeBlockImport::fixture(old_block, 201, 202))
            .expect("connect old tip");

        let child = script_spend(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            8_000,
        );
        let child_txid = child.txid();
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(child)
                .expect("child admission"),
            hns_mempool::Admission::Accepted(txid) if txid == child_txid
        ));
        let previous_generation = node.state.mempool.info().generation;

        let mut replacement = block_with_commitments(vec![coinbase_transaction_with_tag(202, 50)]);
        replacement.header.prev_block = tip.hash;
        replacement.header.tree_root = *tree_root.as_bytes();
        replacement.header.nonce = 213;
        node.apply_reorg(NodeReorg {
            disconnect: vec![NodeBlockDisconnect {
                block_hash: old_record.hash,
                height: 201,
            }],
            connect: vec![NodeBlockImport::fixture(replacement, 201, 203)],
        })
        .expect("replace old tip");

        assert_eq!(node.state.mempool.info().transaction_count, 2);
        assert_eq!(
            node.state.mempool.info().generation,
            previous_generation + 1
        );
        assert!(node.state.mempool.transaction(&parent_txid).is_some());
        assert!(node.state.mempool.transaction(&child_txid).is_some());
        assert_eq!(
            node.state
                .mempool
                .snapshot()
                .entry(&child_txid)
                .expect("retained child")
                .parents,
            vec![parent_txid]
        );
    }

    #[test]
    fn strict_height_zero_import_rejects_mutated_genesis() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let mut block = hns_primitives::Block {
            header: Network::Regtest.params().genesis_header(),
            transactions: vec![coinbase_transaction()],
        };
        block.header.nonce ^= 1;

        let error = node
            .accept_block(NodeBlockImport::from_peer(block, 0))
            .expect_err("mutated genesis");
        assert!(
            error
                .to_string()
                .contains("genesis header does not match the selected HNS network"),
            "{error}"
        );
    }

    #[test]
    fn strict_startup_accepts_network_genesis_and_valid_header_branches() {
        let genesis = regtest_genesis_record();
        let child = regtest_child_record(
            &genesis,
            genesis.header.time + 1,
            Network::Regtest.params().pow.bits,
            true,
        );
        let store = strict_header_store(&[genesis, child.clone()], child.hash);

        let state = NodeState::from_store_for_network_strict_for_test(store, Network::Regtest)
            .expect("strict valid header recovery");
        assert_eq!(
            state.chain.best_tip().expect("best").expect("tip").hash,
            child.hash
        );
    }

    #[test]
    fn strict_startup_rejects_wrong_network_root_and_invalid_side_headers() {
        let mut wrong_header = Network::Regtest.params().genesis_header();
        wrong_header.nonce ^= 1;
        let wrong = strict_header_record(wrong_header, 0, None);
        let error = NodeState::from_store_for_network_strict_for_test(
            strict_header_store(std::slice::from_ref(&wrong), wrong.hash),
            Network::Regtest,
        )
        .expect_err("wrong genesis must fail recovery");
        assert!(
            format!("{error:#}").contains("genesis header does not match"),
            "{error:#}"
        );

        let cases = [
            (
                "difficulty",
                regtest_child_record(
                    &regtest_genesis_record(),
                    Network::Regtest.params().genesis_time + 1,
                    0x207f_fffe,
                    true,
                ),
                "unexpected difficulty bits",
            ),
            (
                "median-time",
                regtest_child_record(
                    &regtest_genesis_record(),
                    Network::Regtest.params().genesis_time,
                    Network::Regtest.params().pow.bits,
                    true,
                ),
                "median time",
            ),
            (
                "proof-of-work",
                regtest_child_record(
                    &regtest_genesis_record(),
                    Network::Regtest.params().genesis_time + 1,
                    Network::Regtest.params().pow.bits,
                    false,
                ),
                "proof of work",
            ),
            (
                "future-time",
                regtest_child_record(
                    &regtest_genesis_record(),
                    current_unix_time()
                        .expect("current time")
                        .saturating_add(MAX_FUTURE_BLOCK_TIME)
                        .saturating_add(60),
                    Network::Regtest.params().pow.bits,
                    true,
                ),
                "too far in the future",
            ),
        ];
        for (name, mut invalid, expected) in cases {
            let genesis = regtest_genesis_record();
            invalid.status.failed = true;
            let store = strict_header_store(&[genesis.clone(), invalid], genesis.hash);
            let error = NodeState::from_store_for_network_strict_for_test(store, Network::Regtest)
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{name} corruption returned {error:#}"
            );
        }
    }

    #[test]
    fn strict_startup_rejects_block_header_and_bidirectional_height_mismatches() {
        let cases = [
            ("status", false, false),
            ("active-reverse", true, false),
            ("height-forward", false, true),
        ];
        for (name, active, forged_height) in cases {
            let mut genesis = regtest_genesis_record();
            genesis.status.active_chain = active;
            let store = strict_header_store(std::slice::from_ref(&genesis), genesis.hash);
            let mut block = BlockIndexRecord {
                hash: genesis.hash,
                height: genesis.height,
                prev_hash: genesis.header.prev_block,
                chainwork: genesis.chainwork,
                status: genesis.status.clone(),
                tx_count: 0,
                validated_at: None,
            };
            if name == "status" {
                block.status.body_present = true;
            }
            let mut batch = store.batch();
            write_block_index_to_batch(&mut batch, &block).expect("stage block index");
            if forged_height {
                write_canonical_height_to_batch(&mut batch, 0, block.hash)
                    .expect("stage forged active height");
            }
            store.commit(batch).expect("commit corrupt block binding");

            let error = NodeState::from_store_for_network_strict_for_test(store, Network::Regtest)
                .unwrap_err();
            let detail = format!("{error:#}");
            assert!(
                detail.contains("disagrees")
                    || detail.contains("reverse-bound")
                    || detail.contains("non-active"),
                "{name} corruption returned {detail}"
            );
        }

        let genesis = regtest_genesis_record();
        let store = strict_header_store(std::slice::from_ref(&genesis), genesis.hash);
        let missing = BlockHash::new([0x5a; 32]);
        let mut batch = store.batch();
        write_canonical_height_to_batch(&mut batch, 0, missing)
            .expect("stage missing forward binding");
        store.commit(batch).expect("commit missing forward binding");
        let error = NodeState::from_store_for_network_strict_for_test(store, Network::Regtest)
            .expect_err("height index to missing block must fail");
        assert!(
            format!("{error:#}").contains("points to missing block index"),
            "{error:#}"
        );
    }

    #[test]
    fn strict_import_accepts_every_canonical_hsd_genesis_block() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/blocks/genesis-v1.json"))
                .expect("HSD genesis fixture");
        let cases = fixture["networks"].as_array().expect("genesis networks");
        assert_eq!(cases.len(), 4);

        for case in cases {
            let network = match case["network"].as_str().expect("network") {
                "main" => Network::Mainnet,
                "testnet" => Network::Testnet,
                "regtest" => Network::Regtest,
                "simnet" => Network::Simnet,
                name => panic!("unexpected HSD network {name}"),
            };
            let raw = decode_hex(case["raw"].as_str().expect("raw genesis"));
            assert_eq!(raw.len(), case["size"].as_u64().expect("size") as usize);
            let block = Block::decode(&raw).expect("canonical HSD genesis block");
            let hash = block.hash();

            assert_eq!(block.encode(), raw);
            assert_eq!(block.header, network.params().genesis_header());
            assert_eq!(hash, network.params().genesis_hash);
            assert_eq!(hash.to_hex(), case["hash"].as_str().expect("hash"));
            assert_eq!(block.transactions.len(), 1);
            assert_eq!(
                block.transactions[0].txid().to_hex(),
                case["coinbaseTxid"].as_str().expect("coinbase txid")
            );
            assert_eq!(
                block.transactions[0].outputs[0].value,
                network.params().block_reward(0)
            );

            let mut node = NodeService::new(NodeConfig {
                network,
                ..NodeConfig::default()
            });
            let acceptance = node
                .accept_block(NodeBlockImport::from_peer(block.clone(), 0))
                .unwrap_or_else(|error| panic!("{network:?} genesis import failed: {error}"));
            assert_eq!(acceptance.disposition, BlockDisposition::Connected);
            assert_eq!(acceptance.record.hash, hash);
            assert_eq!(acceptance.record.height, 0);
            assert_eq!(acceptance.record.prev_hash, BlockHash::ZERO);
            assert_eq!(acceptance.record.tx_count, 1);
            assert!(acceptance.record.status.active_chain);
            assert!(acceptance.record.status.body_syntax_valid);
            assert!(acceptance.record.status.utxo_connected);
            assert!(acceptance.record.status.undo_present);

            let store = node.state.store.clone();
            drop(node);
            let restarted = NodeState::from_store_for_network(store, network)
                .unwrap_or_else(|error| panic!("{network:?} genesis restart failed: {error}"));
            assert_eq!(
                restarted
                    .best_block_tip()
                    .expect("tip")
                    .expect("genesis")
                    .hash,
                hash
            );
        }
    }

    #[test]
    fn strict_mainnet_block_one_keeps_coinbase_finality_and_height_distinct() {
        let genesis_fixture: Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/blocks/genesis-v1.json"))
                .expect("HSD genesis fixture");
        let genesis_case = genesis_fixture["networks"]
            .as_array()
            .expect("genesis networks")
            .iter()
            .find(|case| case["network"] == "main")
            .expect("mainnet genesis");
        let genesis = Block::decode(&decode_hex(
            genesis_case["raw"].as_str().expect("raw genesis"),
        ))
        .expect("canonical mainnet genesis");
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/chains/mainnet-deployment-history-v1.json"
        ))
        .expect("mainnet deployment fixture");
        let case = &fixture["historicalFinalityCases"][0];
        let block = Block::decode(&decode_hex(case["raw"].as_str().expect("raw block one")))
            .expect("canonical mainnet block one");
        assert_eq!(block.transactions[0].locktime, 1);
        assert!(!hns_consensus::is_final_transaction(
            &block.transactions[0],
            1,
            0
        ));

        let mut node = NodeService::new(NodeConfig {
            network: Network::Mainnet,
            ..NodeConfig::default()
        });
        node.accept_block(NodeBlockImport::from_peer(genesis, 0))
            .expect("strict canonical mainnet genesis import");
        let acceptance = node
            .accept_block(NodeBlockImport::from_peer(block, 1))
            .expect("strict canonical mainnet block-one import");
        assert_eq!(acceptance.disposition, BlockDisposition::Connected);
        assert_eq!(acceptance.record.height, 1);
        assert!(acceptance.record.status.absolute_finality_valid);
        assert!(acceptance.record.status.utxo_connected);
    }

    #[test]
    fn strict_mainnet_block_one_retains_transaction_start_under_checkpoints() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/chains/mainnet-deployment-history-v1.json"
        ))
        .expect("mainnet deployment fixture");
        let case = &fixture["historicalFinalityCases"][0];
        let mut block = Block::decode(&decode_hex(case["raw"].as_str().expect("raw block one")))
            .expect("canonical mainnet block one");
        block.transactions.push(block.transactions[0].clone());

        let mut node = NodeService::new(NodeConfig {
            network: Network::Mainnet,
            ..NodeConfig::default()
        });
        node.native_sync_ensure_genesis_header()
            .expect("canonical mainnet genesis header");
        let error = node
            .state
            .validate_import(&NodeBlockImport::from_peer(block, 1))
            .expect_err("pre-txStart transaction must be rejected");
        assert!(
            error.to_string().contains("transaction-start validation"),
            "checkpoint-backed historical validation must retain txStart: {error}"
        );
    }

    #[test]
    fn node_connect_block_commits_indexes_state_and_metadata_atomically() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            transaction_index: true,
            ..NodeConfig::default()
        });
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let txid = block.transactions[0].txid();
        let outpoint = Outpoint { txid, index: 0 };

        let record = node
            .connect_block(NodeBlockImport::fixture(block.clone(), 0, 1))
            .expect("connect block");

        assert!(record.status.body_syntax_valid);
        assert!(record.status.absolute_finality_valid);
        assert!(record.status.utxo_connected);
        assert_eq!(
            node.state()
                .blocks
                .load_block(&record.hash)
                .expect("load block"),
            Some(block)
        );
        assert_eq!(
            node.state()
                .blocks
                .load_tx_index(&txid)
                .expect("tx index")
                .expect("tx")
                .block_hash,
            record.hash
        );
        assert!(node
            .state()
            .state_engine
            .coin(&outpoint)
            .expect("coin")
            .is_some());
        assert!(node
            .state()
            .state_engine
            .load_undo(&record.hash)
            .expect("undo")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            read_canonical_hash(&snapshot, 0).expect("height"),
            Some(record.hash)
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block"),
            Some(record.hash.as_bytes().to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
                .expect("mining generation")
                .map(|bytes| decode_u64(&bytes).expect("decode generation")),
            Some(1)
        );
        drop(snapshot);
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("observed state")
                .expect("mining snapshot")
                .generation,
            1
        );

        let disconnected = node
            .disconnect_block(NodeBlockDisconnect {
                block_hash: record.hash,
                height: 0,
            })
            .expect("disconnect block");

        assert!(!disconnected.status.utxo_connected);
        assert!(!disconnected.status.undo_present);
        assert!(node
            .state()
            .state_engine
            .coin(&outpoint)
            .expect("coin removed")
            .is_none());
        assert!(node
            .state()
            .state_engine
            .load_undo(&record.hash)
            .expect("undo removed")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&txid)
            .expect("tx index removed")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_block(&record.hash)
            .expect("raw block retained")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(read_canonical_hash(&snapshot, 0).expect("height"), None);
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block removed"),
            None
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
                .expect("mining generation")
                .map(|bytes| decode_u64(&bytes).expect("decode generation")),
            Some(2)
        );
        assert!(node.mining_snapshot().is_none());
    }

    #[test]
    fn mining_snapshot_uses_interval_committed_name_root() {
        let mut node = NodeService::new(active_state_native_config());
        let store = node.state.store.clone();
        node.state.state_engine = StoredStateEngine::with_services(
            store,
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("fixture input verifier");
        let records = connect_fixture_chain(&mut node, 200, None);
        let spend_txid = node
            .state
            .blocks
            .load_block(&records[198].hash)
            .expect("load spend source")
            .expect("spend source block")
            .transactions[0]
            .txid();

        let mut opening = block_with_commitments(vec![
            coinbase_transaction_with_tag(201, 50),
            open_transaction(
                b"mining-interval-root",
                Outpoint {
                    txid: spend_txid,
                    index: 0,
                },
            ),
        ]);
        opening.header.prev_block = records[200].hash;
        opening.header.nonce = 211;
        let opening = node
            .connect_block(NodeBlockImport::fixture(opening, 201, 202))
            .expect("connect non-interval OPEN");

        let snapshot = node.state.store.snapshot().expect("post-OPEN snapshot");
        let committed_root = verify_stored_name_tree_root(&snapshot).expect("committed root");
        let pending_root =
            hns_state::rebuild_name_tree_root(&snapshot).expect("pending materialized root");
        assert_ne!(pending_root, committed_root);
        assert_eq!(committed_root.as_bytes(), &[0; 32]);
        drop(snapshot);
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("observed snapshot")
                .expect("active mining snapshot")
                .next_tree_root,
            *committed_root.as_bytes()
        );

        let mut previous = opening.hash;
        for height in 202..=205 {
            let snapshot = node.state.store.snapshot().expect("pre-block snapshot");
            let header_root =
                load_stored_name_tree_commit_root(&snapshot).expect("header commit root");
            drop(snapshot);
            let mut block = block_with_commitments(vec![coinbase_transaction_with_tag(height, 50)]);
            block.header.prev_block = previous;
            block.header.tree_root = *header_root.as_bytes();
            block.header.nonce = height.saturating_add(10);
            previous = node
                .connect_block(NodeBlockImport::fixture(
                    block,
                    height,
                    u64::from(height) + 1,
                ))
                .unwrap_or_else(|error| panic!("connect interval height {height}: {error}"))
                .hash;
        }

        let snapshot = node.state.store.snapshot().expect("interval snapshot");
        let resulting_commit =
            load_stored_name_tree_commit_root(&snapshot).expect("resulting commit root");
        assert_eq!(resulting_commit, pending_root);
        drop(snapshot);
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("observed snapshot")
                .expect("active mining snapshot")
                .next_tree_root,
            *pending_root.as_bytes()
        );
    }

    #[test]
    fn ordinary_page_reader_does_not_scan_historical_root_locators() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-name-page-point-roots-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let store = StoreHandle::memory();
        drop(
            NodeState::from_store_for_network(store.clone(), Network::Regtest)
                .expect("initialize page store"),
        );
        let pages = NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
            .expect("open pages");
        let locator = NamePageRootLocator::new(
            pages.state.manifest.generation,
            hns_store::NamePageAddress::new(0, 0, 0).expect("test locator"),
        );
        let mut historical_roots = Vec::new();
        let mut batch = store.batch();
        for index in 1u32..=1_024 {
            let mut raw_root = [0u8; 32];
            raw_root[..4].copy_from_slice(&index.to_le_bytes());
            let root = TreeRoot::new(raw_root);
            historical_roots.push(root);
            batch
                .put(
                    ColumnFamily::Snapshots,
                    &name_page_root_key(root),
                    &NamePageRootRecord {
                        root,
                        locator,
                        height: index,
                    }
                    .encode(),
                )
                .expect("stage historical locator");
        }
        store.commit(batch).expect("publish historical locators");

        let snapshot = store.snapshot().expect("counted snapshot");
        {
            let counted = CountingNamePageSnapshot::new(&snapshot);
            let (_reader, legacy_fallback) = pages
                .reader_for_roots(&counted, std::iter::empty(), false)
                .expect("ordinary connect reader");
            assert!(!legacy_fallback);
            assert_eq!(counted.locator_scans.get(), 0);
            assert_eq!(counted.locator_gets.get(), 0);

            let (_reader, legacy_fallback) = pages
                .reader_for_roots(&counted, [historical_roots[731]], false)
                .expect("rollback root reader");
            assert!(!legacy_fallback);
            assert_eq!(counted.locator_scans.get(), 0);
            assert_eq!(
                counted.locator_gets.get(),
                1,
                "one requested rollback root must cost one point lookup"
            );
        }
        drop(snapshot);
        drop(pages);
        std::fs::remove_dir_all(directory).expect("remove page directory");
    }

    #[test]
    fn startup_page_segment_limit_is_checked_before_range_collection() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-name-page-segment-bound-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("create segment fixture");
        for segment in 0..=1 {
            std::fs::File::create(name_page_file_path(&directory, 1, segment))
                .expect("create segment");
        }
        let now = Instant::now();
        let limits = NamePageFilesystemLimits {
            max_segments: 2,
            max_directory_entries: 4,
            max_generation_bytes: MAX_NAME_PAGE_GENERATION_BYTES,
            deadline: now.checked_add(Duration::from_secs(30)).unwrap_or(now),
        };
        assert_eq!(
            name_page_segment_paths(&directory, 1, 1, limits)
                .expect("exact segment limit")
                .len(),
            2
        );
        let error = name_page_segment_paths(&directory, 1, 2, limits)
            .expect_err("one-over active segment must fail before path collection");
        assert!(
            error.to_string().contains("reached 3, exceeding limit 2"),
            "{error:#}"
        );

        let expired = NamePageFilesystemLimits {
            deadline: Instant::now(),
            ..limits
        };
        let error = name_page_segment_paths(&directory, 1, 1, expired)
            .expect_err("expired startup segment deadline");
        assert!(error.to_string().contains("deadline"));

        std::fs::remove_dir_all(directory).expect("remove segment fixture");
    }

    #[test]
    fn name_page_locator_scan_accepts_exact_limits_and_rejects_one_over_or_expired() {
        let store = StoreHandle::memory();
        let mut batch = store.batch();
        let mut encoded_bytes = 0u64;
        for index in 1u32..=2 {
            let mut raw_root = [0u8; 32];
            raw_root[..4].copy_from_slice(&index.to_le_bytes());
            let root = TreeRoot::new(raw_root);
            let key = name_page_root_key(root);
            let value = NamePageRootRecord {
                root,
                locator: NamePageRootLocator {
                    generation: 7,
                    address: u64::from(index),
                },
                height: index,
            }
            .encode();
            encoded_bytes += u64::try_from(key.len() + value.len()).expect("fixture byte count");
            batch
                .put(ColumnFamily::Snapshots, &key, &value)
                .expect("stage locator");
        }
        store.commit(batch).expect("commit locators");
        let snapshot = store.snapshot().expect("locator snapshot");
        let now = Instant::now();
        let exact = NamePageRootLocatorScanLimits {
            max_records: 2,
            max_bytes: encoded_bytes,
            page_budget: PrefixScanBudget {
                max_entries: 1,
                max_bytes: 1024,
            },
            deadline: now.checked_add(Duration::from_secs(30)).unwrap_or(now),
        };
        assert_eq!(
            collect_name_page_root_locators(&snapshot, exact)
                .expect("exact locator limits")
                .len(),
            2
        );

        let error = collect_name_page_root_locators(
            &snapshot,
            NamePageRootLocatorScanLimits {
                max_records: 1,
                ..exact
            },
        )
        .expect_err("one-over locator count");
        assert!(error.to_string().contains("locator records"), "{error:#}");

        let error = collect_name_page_root_locators(
            &snapshot,
            NamePageRootLocatorScanLimits {
                max_bytes: encoded_bytes - 1,
                ..exact
            },
        )
        .expect_err("one-over locator bytes");
        assert!(error.to_string().contains("locator bytes"), "{error:#}");

        let error = collect_name_page_root_locators(
            &snapshot,
            NamePageRootLocatorScanLimits {
                deadline: Instant::now(),
                ..exact
            },
        )
        .expect_err("expired locator deadline");
        assert!(error.to_string().contains("deadline"), "{error:#}");
    }

    #[test]
    fn name_page_publication_accepts_exact_operations_and_rejects_one_over_or_bytes() {
        let mut old_records = BTreeMap::new();
        for index in 1..=MAX_NAME_PAGE_ROOT_LOCATORS {
            let mut raw_root = [0u8; 32];
            raw_root[..8].copy_from_slice(&index.to_le_bytes());
            let root = TreeRoot::new(raw_root);
            old_records.insert(
                root,
                NamePageRootRecord {
                    root,
                    locator: NamePageRootLocator {
                        generation: 1,
                        address: index,
                    },
                    height: u32::try_from(index).expect("fixture height"),
                },
            );
        }
        let (operations, bytes) = preflight_name_page_publication(
            &old_records,
            usize::try_from(MAX_NAME_PAGE_ROOT_LOCATORS).expect("root count"),
            128,
        )
        .expect("exact publication operation count");
        assert_eq!(operations, MAX_NAME_PAGE_PUBLICATION_OPERATIONS);
        assert!(bytes <= MAX_NAME_PAGE_PUBLICATION_BYTES);

        let error = preflight_name_page_publication(
            &old_records,
            usize::try_from(MAX_NAME_PAGE_ROOT_LOCATORS + 1).expect("one-over root count"),
            128,
        )
        .expect_err("one-over publication operations");
        assert!(
            error.to_string().contains("publication operations"),
            "{error:#}"
        );

        let error = preflight_name_page_publication(
            &BTreeMap::new(),
            0,
            usize::try_from(MAX_NAME_PAGE_PUBLICATION_BYTES).expect("byte ceiling"),
        )
        .expect_err("one-over publication bytes");
        assert!(error.to_string().contains("publication bytes"), "{error:#}");
    }

    #[test]
    fn migration_data_ceiling_accepts_exact_and_rejects_one_over() {
        assert_eq!(
            preflight_migration_data_ceiling(MAX_NAME_PAGE_GENERATION_BYTES - 1, 1)
                .expect("exact migration data ceiling"),
            MAX_NAME_PAGE_GENERATION_BYTES
        );
        let error = preflight_migration_data_ceiling(MAX_NAME_PAGE_GENERATION_BYTES - 1, 2)
            .expect_err("one-over migration data ceiling");
        assert!(
            error.to_string().contains("schema migration data-root"),
            "{error:#}"
        );
        let error = preflight_migration_data_ceiling(u64::MAX, 1)
            .expect_err("overflowed migration data ceiling");
        assert!(
            error.to_string().contains(&u64::MAX.to_string()),
            "{error:#}"
        );
    }

    #[test]
    fn startup_pin_cursor_rejects_an_expired_deadline_before_reading() {
        let store = StoreHandle::memory();
        drop(
            NodeState::from_store_for_network(store.clone(), Network::Regtest)
                .expect("initialize pin cursor store"),
        );
        let snapshot = store.snapshot().expect("pin cursor snapshot");
        let mut cursor =
            StartupPinCursor::new(&snapshot, Network::Regtest).expect("startup pin cursor");
        cursor.limits.deadline = Instant::now();
        let error = cursor
            .next_pin()
            .expect_err("expired pin cursor must fail before scanning");
        assert!(error.to_string().contains("deadline"));
    }

    #[test]
    fn name_page_bootstrap_and_reopen_use_earliest_reused_pin_height() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-name-page-reused-pin-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let tree = MemoryUrkel::from_entries([
            (NameHash::new([0x21; 32]), b"reused-left".to_vec()),
            (NameHash::new([0xa1; 32]), b"reused-right".to_vec()),
        ])
        .expect("reused pin tree");
        let root = tree.root();
        let tip_height = 3_205;
        let tip_hash = BlockHash::new([0x72; 32]);
        let tip = BlockIndexRecord {
            hash: tip_hash,
            height: tip_height,
            prev_hash: BlockHash::ZERO,
            chainwork: Uint256::ONE,
            status: BlockStatus {
                active_chain: true,
                ..BlockStatus::default()
            },
            tx_count: 0,
            validated_at: None,
        };
        let mut batch = store.batch();
        for (node_root, raw) in tree.node_records().expect("reused pin records") {
            batch
                .put(ColumnFamily::NameTreeNodes, node_root.as_bytes(), &raw)
                .expect("stage reused pin record");
        }
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                root.as_bytes(),
            )
            .expect("stage working root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                root.as_bytes(),
            )
            .expect("stage committed root");
        write_block_index_to_batch(&mut batch, &tip).expect("stage reused pin tip");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                tip_hash.as_bytes(),
            )
            .expect("bind reused pin tip");
        for (height, tag) in [(2_952, 0x73), (3_204, 0x74)] {
            batch
                .put(
                    ColumnFamily::Snapshots,
                    &name_tree_snapshot_pin_key(height),
                    &NameTreeSnapshotPin {
                        height,
                        block_hash: BlockHash::new([tag; 32]),
                        root,
                    }
                    .encode(),
                )
                .expect("stage reused snapshot pin");
        }
        store.commit(batch).expect("publish reused pin fixture");

        let pages = NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Mainnet)
            .expect("bootstrap reused pin pages");
        let snapshot = store.snapshot().expect("bootstrapped reused pin snapshot");
        let record = load_name_page_root_record(&snapshot, root)
            .expect("read bootstrap locator")
            .expect("bootstrap locator");
        assert_eq!(record.height, 2_952);
        let locator = record.locator;
        drop(snapshot);
        drop(pages);

        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                &name_page_root_key(root),
                &NamePageRootRecord {
                    root,
                    locator,
                    height: tip_height,
                }
                .encode(),
            )
            .expect("stage legacy inconsistent locator height");
        store
            .commit(batch)
            .expect("publish legacy inconsistent locator height");

        let pages = NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Mainnet)
            .expect("repair reused pin locator height on reopen");
        let snapshot = store.snapshot().expect("repaired reused pin snapshot");
        let record = load_name_page_root_record(&snapshot, root)
            .expect("read repaired locator")
            .expect("repaired locator");
        assert_eq!(record.height, 2_952);
        let (reader, legacy_missing) = pages
            .reader_for_roots(&snapshot, std::iter::empty(), false)
            .expect("open repaired reused pin reader");
        assert!(!legacy_missing);
        assert!(
            !seed_startup_pin_page_roots(&snapshot, Network::Mainnet, &reader)
                .expect("seed reused pin roots after repair")
        );

        drop(reader);
        drop(snapshot);
        drop(pages);
        std::fs::remove_dir_all(directory).expect("remove reused pin pages");
    }

    #[test]
    fn exhaustive_page_audit_seeds_more_than_4096_historical_pin_roots() {
        const PIN_COUNT: u32 = 4_097;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-node-name-page-many-pins-{}-{nonce}.pages",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let store = StoreHandle::memory();
        drop(
            NodeState::from_store_for_network(store.clone(), Network::Simnet)
                .expect("initialize pin store"),
        );
        let tip_hash = BlockHash::new([0x42; 32]);
        let tip_height = (PIN_COUNT - 1) * Network::Simnet.params().names.tree_interval;
        let mut records = BTreeMap::new();
        let mut roots = Vec::with_capacity(PIN_COUNT as usize);
        for index in 0..PIN_COUNT {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&index.to_be_bytes());
            key[31] = 0xa5;
            let tree =
                MemoryUrkel::from_entries([(NameHash::new(key), index.to_le_bytes().to_vec())])
                    .expect("single-leaf historical tree");
            let root = tree.root();
            roots.push(root);
            records.extend(tree.node_records().expect("historical leaf record"));
        }
        let packed = pack_name_page_records(1, 0, 0, &records, &HashMap::new())
            .expect("pack historical roots");
        let mut appender = NamePageAppender::create_new(&path, 1, 0).expect("create pin pages");
        let manifest = packed.append(&mut appender).expect("append pin pages");
        drop(appender);

        let mut batch = store.batch();
        let tip = BlockIndexRecord {
            hash: tip_hash,
            height: tip_height,
            prev_hash: BlockHash::ZERO,
            chainwork: Uint256::ONE,
            status: BlockStatus {
                active_chain: true,
                ..BlockStatus::default()
            },
            tx_count: 0,
            validated_at: None,
        };
        write_block_index_to_batch(&mut batch, &tip).expect("stage high pin tip");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                tip_hash.as_bytes(),
            )
            .expect("bind high pin tip");
        for (index, root) in roots.iter().copied().enumerate() {
            let height = u32::try_from(index).expect("pin index")
                * Network::Simnet.params().names.tree_interval;
            let block_hash = BlockHash::new(blake2b_256(&height.to_le_bytes()));
            let locator = packed.root_locator(root).expect("historical root locator");
            batch
                .put(
                    ColumnFamily::Snapshots,
                    &name_tree_snapshot_pin_key(height),
                    &NameTreeSnapshotPin {
                        height,
                        block_hash,
                        root,
                    }
                    .encode(),
                )
                .expect("stage historical pin");
            batch
                .put(
                    ColumnFamily::Snapshots,
                    &name_page_root_key(root),
                    &NamePageRootRecord {
                        root,
                        locator,
                        height,
                    }
                    .encode(),
                )
                .expect("stage historical root locator");
        }
        store.commit(batch).expect("publish historical pins");

        let snapshot = store.snapshot().expect("pin snapshot");
        let first_root = roots[0];
        let reader = NamePageTreeReader::open(
            &path,
            first_root,
            packed.root_locator(first_root).expect("first root locator"),
        )
        .expect("open historical pin pages");
        assert!(
            !seed_startup_pin_page_roots(&snapshot, Network::Simnet, &reader)
                .expect("seed every historical pin")
        );
        assert_eq!(
            reader.known_addresses().expect("seeded addresses").len(),
            PIN_COUNT as usize
        );

        let now = Instant::now();
        let validation = reader
            .validate_committed_pages_with_limits(NamePageValidationLimits {
                max_segments: 1,
                max_pages: u64::try_from(packed.page_count()).expect("page count"),
                max_records: u64::from(PIN_COUNT),
                max_bytes: manifest.durable_bytes,
                max_spill_bytes: u64::from(PIN_COUNT) * 34,
                max_published_roots: u64::from(PIN_COUNT),
                minimum_filesystem_reserve_bytes: 0,
                deadline: now.checked_add(Duration::from_secs(60)).unwrap_or(now),
            })
            .expect("physically validate every historical pin");
        validate_persisted_name_tree_overlays(&snapshot, roots, &validation, PIN_COUNT as usize)
            .expect("validate historical page roots without legacy LSM nodes");

        drop(reader);
        drop(snapshot);
        std::fs::remove_file(path).expect("remove pin pages");
    }

    #[test]
    fn page_compaction_materializes_pre_page_retained_roots_and_fails_closed_if_missing() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-name-page-upgrade-roots-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let store = StoreHandle::memory();
        drop(
            NodeState::from_store_for_network(store.clone(), Network::Regtest)
                .expect("initialize upgrade store"),
        );
        let historical = MemoryUrkel::from_entries([
            (NameHash::new([0x11; 32]), b"historical-left".to_vec()),
            (NameHash::new([0x91; 32]), b"historical-right".to_vec()),
        ])
        .expect("historical tree");
        let current = MemoryUrkel::from_entries([
            (NameHash::new([0x11; 32]), b"current-left".to_vec()),
            (NameHash::new([0x91; 32]), b"historical-right".to_vec()),
        ])
        .expect("current tree");
        let historical_root = historical.root();
        let current_root = current.root();
        let undo_hash = BlockHash::new([0x61; 32]);
        let undo = BlockUndo {
            block_hash: undo_hash,
            height: 1,
            previous_tree_root: historical_root,
            resulting_tree_root: current_root,
            previous_committed_tree_root: historical_root,
            resulting_committed_tree_root: current_root,
            spent_coins: Vec::new(),
            created_coins: Vec::new(),
            airdrop_positions: Vec::new(),
            previous_name_states: Vec::new(),
            name_tree_interval_boundary: false,
            previous_name_tree_accumulator_last_height: None,
            previous_name_tree_accumulator: None,
        };
        let mut batch = store.batch();
        for tree in [&historical, &current] {
            for (root, raw) in tree.node_records().expect("tree records") {
                batch
                    .put(ColumnFamily::NameTreeNodes, root.as_bytes(), &raw)
                    .expect("stage legacy tree record");
            }
        }
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                current_root.as_bytes(),
            )
            .expect("stage working root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                current_root.as_bytes(),
            )
            .expect("stage committed root");
        batch
            .put(
                ColumnFamily::Undo,
                undo_hash.as_bytes(),
                &undo.encode().expect("encode retained undo"),
            )
            .expect("stage retained undo");
        store.commit(batch).expect("publish pre-page state");

        let mut pages =
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("bootstrap pages");
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                &name_page_root_key(current_root),
                &NamePageRootRecord {
                    root: current_root,
                    locator: pages.state.root_locator().expect("current root locator"),
                    height: 1,
                }
                .encode(),
            )
            .expect("stage current page locator");
        store.commit(batch).expect("publish current page locator");
        let snapshot = store.snapshot().expect("bootstrap snapshot");
        assert!(load_name_page_root_record(&snapshot, current_root)
            .expect("current locator")
            .is_some());
        assert!(
            load_name_page_root_record(&snapshot, historical_root)
                .expect("historical locator")
                .is_none(),
            "pre-page historical undo roots begin without page locators"
        );
        drop(snapshot);

        let report = pages
            .compact_generation(&store)
            .expect("materialize retained upgrade root");
        assert_eq!(report.generation, 2);
        let snapshot = store.snapshot().expect("compacted snapshot");
        for root in [current_root, historical_root] {
            let record = load_name_page_root_record(&snapshot, root)
                .expect("retained locator")
                .expect("published retained locator");
            assert_eq!(record.locator.generation, report.generation);
        }
        let (reader, legacy_fallback) = pages
            .reader_for_roots(&snapshot, [current_root, historical_root], false)
            .expect("compacted retained readers");
        assert!(!legacy_fallback);
        let page_snapshot = NamePageSnapshot::new(&snapshot, &reader);
        validate_persisted_name_trees(&page_snapshot, [current_root, historical_root])
            .expect("validate materialized retained roots");
        drop(reader);
        drop(snapshot);

        let missing_root = TreeRoot::new([0xee; 32]);
        let missing_hash = BlockHash::new([0x62; 32]);
        let missing_undo = BlockUndo {
            block_hash: missing_hash,
            height: 2,
            previous_tree_root: missing_root,
            resulting_tree_root: current_root,
            previous_committed_tree_root: missing_root,
            resulting_committed_tree_root: current_root,
            spent_coins: Vec::new(),
            created_coins: Vec::new(),
            airdrop_positions: Vec::new(),
            previous_name_states: Vec::new(),
            name_tree_interval_boundary: false,
            previous_name_tree_accumulator_last_height: None,
            previous_name_tree_accumulator: None,
        };
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Undo,
                missing_hash.as_bytes(),
                &missing_undo.encode().expect("encode missing undo"),
            )
            .expect("stage missing retained undo");
        store.commit(batch).expect("publish missing retained root");
        let generation_before = pages.state.manifest.generation;
        assert!(pages.compact_generation(&store).is_err());
        assert_eq!(pages.state.manifest.generation, generation_before);
        assert!(!pages.reopen_required);

        drop(pages);
        std::fs::remove_dir_all(directory).expect("remove upgrade page directory");
    }

    #[test]
    fn ambiguous_name_page_commit_fence_preserves_old_or_new_recovery_bytes() {
        fn append_synced_page(pages: &mut NamePageStorage, tag: u8) -> hns_store::SegmentManifest {
            pages
                .appender
                .as_mut()
                .expect("page appender")
                .append(&[hns_store::NamePageRecord {
                    key: [tag; 32],
                    children: Vec::new(),
                    canonical: vec![tag],
                }])
                .expect("append page");
            pages
                .appender
                .as_mut()
                .expect("page appender")
                .sync_data()
                .expect("sync page")
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let rejected_directory = std::env::temp_dir().join(format!(
            "hsrd-name-page-rejected-fence-{}-{nonce}",
            std::process::id()
        ));
        let applied_directory = std::env::temp_dir().join(format!(
            "hsrd-name-page-applied-fence-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&rejected_directory);
        let _ = std::fs::remove_dir_all(&applied_directory);

        // Simulate Store::commit rejecting before its write. The synced tail
        // remains untouched while the process is fenced; reopening the old
        // durable manifest is the only operation allowed to truncate it.
        let rejected_store = StoreHandle::memory();
        let _rejected_state =
            NodeState::from_store_for_network(rejected_store.clone(), Network::Regtest)
                .expect("initialize rejected store");
        let mut rejected_pages = NamePageStorage::open_or_bootstrap(
            rejected_directory.clone(),
            &rejected_store,
            Network::Regtest,
        )
        .expect("rejected pages");
        let rejected_committed = rejected_pages.state.manifest.durable_bytes;
        let _ = append_synced_page(&mut rejected_pages, 0x41);
        let rejected_tail = std::fs::metadata(&rejected_pages.file_path)
            .expect("rejected tail metadata")
            .len();
        assert!(rejected_tail > rejected_committed);
        rejected_pages.fence_after_commit_attempt();
        assert!(rejected_pages.reopen_required);
        assert!(rejected_pages.appender.is_none());
        assert_eq!(
            std::fs::metadata(&rejected_pages.file_path)
                .expect("fenced rejected metadata")
                .len(),
            rejected_tail
        );
        assert!(rejected_pages
            .reader_for_roots(
                &rejected_store.snapshot().expect("rejected snapshot"),
                std::iter::empty(),
                false,
            )
            .is_err());
        drop(rejected_pages);
        let rejected_reopened = NamePageStorage::open_or_bootstrap(
            rejected_directory.clone(),
            &rejected_store,
            Network::Regtest,
        )
        .expect("reopen rejected pages");
        assert_eq!(
            std::fs::metadata(&rejected_reopened.file_path)
                .expect("reopened rejected metadata")
                .len(),
            rejected_committed
        );

        // Simulate Store::commit applying its batch and then returning Err.
        // Reopening must follow the new durable manifest and preserve every
        // page byte referenced by that applied batch.
        let applied_store = StoreHandle::memory();
        let _applied_state =
            NodeState::from_store_for_network(applied_store.clone(), Network::Regtest)
                .expect("initialize applied store");
        let mut applied_pages = NamePageStorage::open_or_bootstrap(
            applied_directory.clone(),
            &applied_store,
            Network::Regtest,
        )
        .expect("applied pages");
        let applied_manifest = append_synced_page(&mut applied_pages, 0x42);
        let applied_tail = std::fs::metadata(&applied_pages.file_path)
            .expect("applied tail metadata")
            .len();
        let mut applied_state = applied_pages.state.clone();
        applied_state.manifest = applied_manifest;
        let mut batch = applied_store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                NAME_PAGE_STATE_KEY,
                &applied_state.encode().expect("encode applied page state"),
            )
            .expect("stage applied page state");
        applied_store
            .commit(batch)
            .expect("simulate applied commit batch");
        applied_pages.fence_after_commit_attempt();
        assert_eq!(
            std::fs::metadata(&applied_pages.file_path)
                .expect("fenced applied metadata")
                .len(),
            applied_tail
        );
        drop(applied_pages);
        let applied_reopened = NamePageStorage::open_or_bootstrap(
            applied_directory.clone(),
            &applied_store,
            Network::Regtest,
        )
        .expect("reopen applied pages");
        assert_eq!(applied_reopened.state.manifest, applied_manifest);
        assert_eq!(
            std::fs::metadata(&applied_reopened.file_path)
                .expect("reopened applied metadata")
                .len(),
            applied_tail
        );

        drop(rejected_reopened);
        drop(applied_reopened);
        std::fs::remove_dir_all(rejected_directory).expect("remove rejected fence fixture");
        std::fs::remove_dir_all(applied_directory).expect("remove applied fence fixture");
    }

    #[test]
    fn ambiguous_name_page_fence_revokes_node_authority_and_mutation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-name-page-authority-fence-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
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
        let publication_hash = BlockHash::new([0x55; 32]);
        let mut publication_key = Vec::with_capacity(hns_mining::PUBLICATION_KEY_PREFIX.len() + 32);
        publication_key.extend_from_slice(hns_mining::PUBLICATION_KEY_PREFIX);
        publication_key.extend_from_slice(publication_hash.as_bytes());
        let mut publication_batch = store.batch();
        publication_batch
            .put(
                ColumnFamily::Snapshots,
                &publication_key,
                b"fenced-publication-intent",
            )
            .expect("stage publication intent");
        store
            .commit(publication_batch)
            .expect("commit publication intent");
        node.state
            .name_pages
            .as_mut()
            .expect("page storage")
            .fence_after_commit_attempt();
        node.fail_closed_after_ambiguous_commit();

        assert!(node.state.storage_reopen_required());
        assert!(node.observed_mining_snapshot().is_err());
        assert!(node.subscribe_mining_events().is_err());
        assert!(node.mining_snapshot().is_none());
        assert_eq!(node.mining_events.committed_generation(), 1);
        let mempool_before = node.state.mempool.info();
        for error in [
            node.mining_engine_accept_peer_transaction(coinbase_transaction())
                .expect_err("fenced peer transaction"),
            node.mining_engine_accept_peer_claim(hns_primitives::Claim::default())
                .expect_err("fenced peer claim"),
            node.mining_engine_accept_peer_airdrop(hns_primitives::AirdropProof {
                index: 0,
                proof: Vec::new(),
                subindex: 0,
                subproof: Vec::new(),
                key: Vec::new(),
                version: 0,
                address: Vec::new(),
                fee: 0,
                signature: Vec::new(),
            })
            .expect_err("fenced peer airdrop"),
        ] {
            assert!(error.to_string().contains("restart and reopen"), "{error}");
        }
        assert_eq!(node.state.mempool.info(), mempool_before);
        let publication_error = node
            .mining_engine_complete_publication(publication_hash)
            .expect_err("fenced publication-intent deletion");
        assert!(
            publication_error.to_string().contains("restart and reopen"),
            "{publication_error}"
        );
        assert_eq!(
            store
                .snapshot()
                .expect("publication snapshot")
                .get(ColumnFamily::Snapshots, &publication_key)
                .expect("publication lookup")
                .as_deref(),
            Some(b"fenced-publication-intent".as_slice())
        );
        let error = node
            .connect_block(NodeBlockImport::fixture(
                block_with_commitments(vec![coinbase_transaction()]),
                0,
                1,
            ))
            .expect_err("fenced mutation");
        assert!(error.to_string().contains("restart and reopen"), "{error}");

        drop(node);
        std::fs::remove_dir_all(directory).expect("remove authority fence fixture");
    }

    #[test]
    fn page_backed_node_commits_interval_root_without_lsm_name_nodes_and_restarts() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-name-pages-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let mut state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("pages"),
        );
        state.state_engine = StoredStateEngine::with_services(
            store.clone(),
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("fixture verifier");
        let mut node =
            NodeService::try_with_state(active_state_native_config(), state).expect("node");
        let records = connect_fixture_chain(&mut node, 200, None);
        let spend_txid = node
            .state
            .blocks
            .load_block(&records[198].hash)
            .expect("load spend source")
            .expect("spend source")
            .transactions[0]
            .txid();

        let mut opening = block_with_commitments(vec![
            coinbase_transaction_with_tag(201, 50),
            open_transaction(
                b"page-backed-name",
                Outpoint {
                    txid: spend_txid,
                    index: 0,
                },
            ),
        ]);
        opening.header.prev_block = records[200].hash;
        opening.header.nonce = 221;
        let opening = node
            .connect_block(NodeBlockImport::fixture(opening, 201, 202))
            .expect("connect pending OPEN");

        let mut previous = opening.hash;
        let mut boundary_block = None;
        for height in 202..=205 {
            let snapshot = store.snapshot().expect("pre-boundary snapshot");
            let root = load_stored_name_tree_commit_root(&snapshot).expect("header root");
            drop(snapshot);
            let mut block = block_with_commitments(vec![coinbase_transaction_with_tag(height, 50)]);
            block.header.prev_block = previous;
            block.header.tree_root = *root.as_bytes();
            block.header.nonce = height.saturating_add(20);
            if height == 205 {
                boundary_block = Some(block.clone());
            }
            previous = node
                .connect_block(NodeBlockImport::fixture(
                    block,
                    height,
                    u64::from(height) + 1,
                ))
                .unwrap_or_else(|error| panic!("connect page boundary {height}: {error}"))
                .hash;
        }

        let snapshot = store.snapshot().expect("page-backed snapshot");
        assert!(snapshot
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("LSM name nodes")
            .is_empty());
        let page_state = NamePageState::decode(
            &snapshot
                .get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)
                .expect("page state read")
                .expect("page state"),
        )
        .expect("decode page state");
        assert_ne!(page_state.root, TreeRoot::ZERO);
        assert!(page_state.manifest.durable_bytes > 0);
        assert_eq!(page_state.committed_height, Some(205));
        let (reader, _) = node
            .state
            .name_pages
            .as_ref()
            .expect("page storage")
            .reader_for_roots(&snapshot, std::iter::empty(), false)
            .expect("page reader");
        let duplicate = reader
            .load(page_state.root)
            .expect("load current root")
            .expect("current root record");
        drop(snapshot);
        drop(reader);

        let pages = node.state.name_pages.as_mut().expect("page storage");
        pages
            .appender
            .as_mut()
            .expect("page appender")
            .append(&[hns_store::NamePageRecord {
                key: *page_state.root.as_bytes(),
                children: Vec::new(),
                canonical: duplicate.clone(),
            }])
            .expect("append simulated uncommitted page");
        pages
            .appender
            .as_mut()
            .expect("page appender")
            .sync_data()
            .expect("sync simulated tail");
        assert!(
            std::fs::metadata(&pages.file_path)
                .expect("page metadata")
                .len()
                > page_state.manifest.durable_bytes
        );
        pages
            .rollback_uncommitted_tail()
            .expect("truncate uncommitted page");
        assert_eq!(
            std::fs::metadata(&pages.file_path)
                .expect("recovered page metadata")
                .len(),
            page_state.manifest.durable_bytes
        );

        node.disconnect_block(NodeBlockDisconnect {
            block_hash: previous,
            height: 205,
        })
        .expect("disconnect page boundary");
        let snapshot = store.snapshot().expect("disconnected page snapshot");
        let disconnected_page_state = NamePageState::decode(
            &snapshot
                .get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)
                .expect("disconnected page state read")
                .expect("disconnected page state"),
        )
        .expect("decode disconnected page state");
        assert_eq!(disconnected_page_state.root, TreeRoot::ZERO);
        assert!(snapshot
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("disconnected LSM name nodes")
            .is_empty());
        drop(snapshot);

        node.connect_block(NodeBlockImport::fixture(
            boundary_block.expect("boundary block"),
            205,
            206,
        ))
        .expect("reconnect page boundary");

        let raw = store.snapshot().expect("pre-seal snapshot");
        let root = load_stored_name_tree_commit_root(&raw).expect("pre-seal root");
        let (reader, _) = node
            .state
            .name_pages
            .as_ref()
            .expect("page storage")
            .reader_for_roots(&raw, std::iter::empty(), false)
            .expect("pre-seal reader");
        let mut batch = store.batch();
        let skipped_seal_height = NAME_PAGE_SEGMENT_BLOCKS
            .checked_mul(2)
            .and_then(|height| height.checked_add(17))
            .expect("skipped seal height");
        let prepared = node
            .state
            .name_pages
            .as_mut()
            .expect("page storage")
            .prepare_root(
                &raw,
                &mut batch,
                &reader,
                BTreeMap::new(),
                &[],
                NamePageRootTarget {
                    root,
                    height: Some(skipped_seal_height),
                },
            )
            .expect("prepare physical seal");
        drop(reader);
        drop(raw);
        store.commit(batch).expect("publish physical seal");
        node.state
            .name_pages
            .as_mut()
            .expect("page storage")
            .commit_prepared(prepared.clone());
        assert_eq!(prepared.manifest.active_segment, 1);
        assert_eq!(prepared.manifest.durable_bytes, 0);
        assert_eq!(
            prepared.last_sealed_height,
            Some(NAME_PAGE_SEGMENT_BLOCKS * 2)
        );
        assert_eq!(
            prepared
                .root_address
                .expect("sealed root address")
                .segment(),
            0
        );
        let unpublished_path = name_page_file_path(&directory, prepared.manifest.generation, 2);
        let mut unpublished =
            NamePageAppender::create_new(&unpublished_path, prepared.manifest.generation, 2)
                .expect("create unpublished successor");
        unpublished
            .append(&[hns_store::NamePageRecord {
                key: *prepared.root.as_bytes(),
                children: Vec::new(),
                canonical: duplicate,
            }])
            .expect("append unpublished successor page");
        unpublished
            .sync_data()
            .expect("sync unpublished successor page");
        drop(unpublished);
        drop(node);

        let pages = NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
            .expect("reopen pages");
        assert!(!unpublished_path.exists());
        let snapshot = store.snapshot().expect("sealed snapshot");
        let (reader, _) = pages
            .reader_for_roots(&snapshot, std::iter::empty(), false)
            .expect("sealed multi-segment reader");
        assert!(reader
            .load(prepared.root)
            .expect("load sealed root")
            .is_some());
        drop(reader);
        drop(snapshot);
        let (_reopened, audit) = NodeState::from_store_for_network_with_startup_audit(
            store,
            Network::Regtest,
            None,
            None,
            Some(pages),
        )
        .expect("restart page-backed node");
        assert_eq!(audit, StartupAuditKind::Exhaustive);
        std::fs::remove_dir_all(directory).expect("remove page fixture");
    }

    #[test]
    fn page_batch_publishes_every_intermediate_snapshot_pin_locator() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-name-page-pins-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        drop(state);
        let mut pages =
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("pages");
        let first = MemoryUrkel::from_entries([
            (NameHash::new([0x11; 32]), b"alpha".to_vec()),
            (NameHash::new([0x91; 32]), b"beta".to_vec()),
        ])
        .expect("first tree");
        let second = MemoryUrkel::from_entries([
            (NameHash::new([0x11; 32]), b"alpha-updated".to_vec()),
            (NameHash::new([0x91; 32]), b"beta".to_vec()),
            (NameHash::new([0xe1; 32]), b"gamma".to_vec()),
        ])
        .expect("second tree");
        let first_root = first.root();
        let second_root = second.root();
        let mut records = first.node_records().expect("first records");
        records.extend(second.node_records().expect("second records"));
        let staged_nodes = records
            .into_iter()
            .map(|(root, raw)| (root.as_bytes().to_vec(), Some(raw)))
            .collect::<BTreeMap<_, _>>();
        let pins = [
            NameTreeSnapshotPin {
                height: 5,
                block_hash: BlockHash::new([0x51; 32]),
                root: first_root,
            },
            NameTreeSnapshotPin {
                height: 10,
                block_hash: BlockHash::new([0x52; 32]),
                root: second_root,
            },
        ];

        let raw = store.snapshot().expect("base snapshot");
        let (reader, _) = pages
            .reader_for_roots(&raw, std::iter::empty(), false)
            .expect("base reader");
        let mut batch = store.batch();
        let prepared = pages
            .prepare_root(
                &raw,
                &mut batch,
                &reader,
                staged_nodes,
                &pins,
                NamePageRootTarget {
                    root: second_root,
                    height: Some(12),
                },
            )
            .expect("prepare multi-boundary page batch");
        drop(reader);
        drop(raw);
        store.commit(batch).expect("publish page batch");
        pages.commit_prepared(prepared);

        let snapshot = store.snapshot().expect("published snapshot");
        for (root, expected_height) in [(first_root, 5), (second_root, 10)] {
            let record = load_name_page_root_record(&snapshot, root)
                .expect("load locator")
                .expect("published locator");
            assert_eq!(record.height, expected_height);
            let (reader, _) = pages
                .reader_for_roots(&snapshot, [root], false)
                .expect("published reader");
            assert!(reader.load(root).expect("load pinned root").is_some());
        }
        drop(snapshot);

        let stale_root = TreeRoot::new([0x77; 32]);
        let first_locator = store
            .snapshot()
            .expect("locator snapshot")
            .get(ColumnFamily::Snapshots, &name_page_root_key(first_root))
            .expect("first locator read")
            .map(|raw| NamePageRootRecord::decode(&raw).expect("first locator decode"))
            .expect("first locator");
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                first_root.as_bytes(),
            )
            .expect("bind working root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                second_root.as_bytes(),
            )
            .expect("bind committed root");
        batch
            .put(
                ColumnFamily::Snapshots,
                &name_page_root_key(stale_root),
                &NamePageRootRecord {
                    root: stale_root,
                    locator: first_locator.locator,
                    height: 1,
                }
                .encode(),
            )
            .expect("stage stale locator");
        store.commit(batch).expect("publish retained root bindings");

        let report = pages
            .compact_generation(&store)
            .expect("compact page generation");
        assert_eq!(report.previous_generation, 1);
        assert_eq!(report.generation, 2);
        assert_eq!(report.retained_roots, 2);
        assert!(report.records_written > 0);
        {
            let snapshot = store.snapshot().expect("compacted snapshot");
            assert!(load_name_page_root_record(&snapshot, stale_root)
                .expect("stale locator read")
                .is_none());
            let (reader, _) = pages
                .reader_for_roots(&snapshot, [first_root, second_root], false)
                .expect("compacted reader");
            let page_snapshot = NamePageSnapshot::new(&snapshot, &reader);
            assert!(
                validate_persisted_name_trees(&page_snapshot, [first_root, second_root])
                    .expect("validate compacted retained roots")
                    >= 2
            );
        }

        let orphan_path = name_page_file_path(&directory, 3, 0);
        let superseded_path = name_page_file_path(&directory, 1, 0);
        drop(
            NamePageAppender::create_new(&orphan_path, 3, 0)
                .expect("create orphan future generation"),
        );
        drop(
            NamePageAppender::create_new(&superseded_path, 1, 0)
                .expect("restore superseded generation"),
        );
        drop(pages);
        let reopened =
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("recover pages");
        assert!(!orphan_path.exists());
        assert!(!superseded_path.exists());
        assert_eq!(reopened.state.manifest.generation, 2);
        drop(reopened);
        std::fs::remove_dir_all(directory).expect("remove page fixture");
    }

    #[test]
    fn active_node_verifies_faucet_issuance_from_parent_deployments() {
        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        let (coinbase, position) = faucet_coinbase();
        let block = block_with_commitments(vec![coinbase.clone()]);
        let record = node
            .connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("faucet block");
        assert!(record.status.deployment_state_valid);
        assert!(record.status.claims_and_airdrops_valid);

        let snapshot = store.snapshot().expect("snapshot");
        let cached = load_deployment_state(&snapshot, record.hash)
            .expect("deployment state read")
            .expect("deployment state");
        assert_eq!(cached.height, 0);
        assert_eq!(cached.state.encode_states(), [0; 4]);
        drop(snapshot);

        let mut duplicate = block_with_commitments(vec![coinbase]);
        duplicate.header.prev_block = record.hash;
        duplicate.header.nonce = 11;
        let error = node
            .connect_block(NodeBlockImport::fixture(duplicate, 1, 2))
            .expect_err("duplicate faucet");
        assert!(error.to_string().contains(&position.to_string()), "{error}");

        drop(node);
        NodeState::from_store_for_network(store, Network::Regtest).expect("faucet state restarts");
    }

    #[test]
    fn active_node_verifies_upstream_goosig_airdrop() {
        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        let (coinbase, position) = goosig_airdrop_coinbase();
        let block = block_with_commitments(vec![coinbase.clone()]);
        let record = node
            .connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("valid upstream GooSig airdrop");
        assert!(record.status.deployment_state_valid);
        assert!(record.status.claims_and_airdrops_valid);

        let mut duplicate = block_with_commitments(vec![coinbase]);
        duplicate.header.prev_block = record.hash;
        duplicate.header.nonce = 11;
        let error = node
            .connect_block(NodeBlockImport::fixture(duplicate, 1, 2))
            .expect_err("duplicate GooSig allocation");
        assert!(error.to_string().contains(&position.to_string()), "{error}");

        drop(node);
        NodeState::from_store_for_network(store, Network::Regtest)
            .expect("GooSig airdrop state restarts");
    }

    #[test]
    fn node_rejects_non_final_block_without_advancing_the_tip() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(21, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("parent");

        let mut non_final = transaction();
        non_final.locktime = 1;
        non_final.inputs[0].sequence = u32::MAX - 1;
        let mut child =
            block_with_commitments(vec![coinbase_transaction_with_address(22, 50), non_final]);
        child.header.prev_block = parent_record.hash;
        let child_hash = child.hash();
        let error = node
            .connect_block(NodeBlockImport::fixture(child, 1, 2))
            .expect_err("non-final block");

        assert!(error.to_string().contains("non-final transaction"));
        assert_eq!(
            node.state().best_block_tip().expect("tip").expect("tip"),
            ChainTip {
                hash: parent_record.hash,
                height: 0,
                chainwork: Uint256::ONE,
            }
        );
        assert!(node
            .state()
            .blocks
            .load_block(&child_hash)
            .expect("child lookup")
            .is_none());
    }

    #[test]
    fn peer_block_chainwork_is_derived_from_the_header_target() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(11, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("fixture parent");

        let mut coinbase = coinbase_transaction_with_address(12, 50);
        coinbase.locktime = 1;
        let mut child = block_with_commitments(vec![coinbase]);
        child.header.prev_block = parent_record.hash;
        child.header.bits = Network::Regtest.params().pow.bits;
        child.header.time = 1;
        while !child.header.verify_pow() {
            child.header.nonce = child.header.nonce.checked_add(1).expect("nonce space");
        }

        let child_record = node
            .connect_block(NodeBlockImport::from_peer(child, 1))
            .expect("peer child");
        assert_eq!(child_record.chainwork, Uint256::from(3u64));
    }

    #[test]
    fn peer_block_rejects_wrong_coinbase_height_before_storage() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(15, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("fixture parent");

        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(16, 50)]);
        child.header.prev_block = parent_record.hash;
        child.header.bits = Network::Regtest.params().pow.bits;
        child.header.time = 1;
        while !child.header.verify_pow() {
            child.header.nonce = child.header.nonce.checked_add(1).expect("nonce space");
        }
        let child_hash = child.hash();

        let error = node
            .connect_block(NodeBlockImport::from_peer(child, 1))
            .expect_err("wrong coinbase height");
        assert!(error.to_string().contains("coinbase height"), "{error}");
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("tip")
                .expect("tip")
                .hash,
            parent_record.hash
        );
        assert!(node
            .state()
            .blocks
            .load_block(&child_hash)
            .expect("child lookup")
            .is_none());
    }

    #[test]
    fn peer_block_cannot_select_its_own_difficulty_bits() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(13, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("fixture parent");
        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(14, 50)]);
        child.header.prev_block = parent_record.hash;
        child.header.bits = Network::Mainnet.params().pow.bits;
        child.header.time = 1;

        assert!(node
            .connect_block(NodeBlockImport::from_peer(child, 1))
            .is_err());
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("observed state")
                .expect("parent snapshot")
                .tip
                .hash,
            parent_record.hash
        );
    }

    #[tokio::test]
    async fn mining_events_are_staged_and_only_commit_after_durable_storage() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let mut subscription = node.subscribe_observed_mining_events();
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let block_hash = block.hash();

        node.connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect block");

        assert!(matches!(
            subscription.events.recv().await.expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            subscription.events.recv().await.expect("validated"),
            hns_mining::ChainEvent::BlockSyntaxValidated { .. }
        ));
        let staged_snapshot = match subscription.events.recv().await.expect("staged") {
            hns_mining::ChainEvent::TipStaged {
                snapshot: Some(snapshot),
                ..
            } => snapshot,
            event => panic!("unexpected staged event: {event:?}"),
        };
        assert_eq!(staged_snapshot.tip.hash, block_hash);

        let snapshot = node.state().store.snapshot().expect("store snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("durable tip"),
            Some(block_hash.as_bytes().to_vec())
        );
        assert!(subscription.latest_snapshot.borrow().is_none());
    }

    #[test]
    fn mining_profile_omits_transaction_history_without_changing_consensus_state() {
        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("lean node");
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let txid = block.transactions[0].txid();
        let record = node
            .connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect without transaction index");
        let snapshot = store.snapshot().expect("lean snapshot");
        assert!(snapshot
            .scan_prefix(ColumnFamily::TxIndex, b"")
            .expect("transaction index")
            .is_empty());
        drop(snapshot);
        assert!(node
            .state()
            .state_engine
            .coin(&Outpoint { txid, index: 0 })
            .expect("coin read")
            .is_some());
        drop(node);

        let state =
            NodeState::from_store_for_network(store, Network::Regtest).expect("reopen state");
        let error = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                transaction_index: true,
                ..NodeConfig::default()
            },
            state,
        )
        .expect_err("partial historical index must fail closed");
        assert!(
            error
                .to_string()
                .contains("cannot be enabled after unindexed blocks"),
            "{error}"
        );
        assert!(record.status.active_chain);
    }

    #[test]
    fn archived_block_and_undo_payloads_survive_reorg_and_restart() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-node-payload-segments-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let raw = StoreHandle::memory();
        drop(
            NodeState::from_store_for_network(raw.clone(), Network::Regtest)
                .expect("initialize raw schema"),
        );
        let archived = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("attach payload archive");
        let state = NodeState::from_store_for_network(archived, Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("archived node");
        let old_block = block_with_commitments(vec![coinbase_transaction_with_address(81, 50)]);
        let old_record = node
            .connect_block(NodeBlockImport::fixture(old_block, 0, 1))
            .expect("connect old archived block");
        let snapshot = raw.snapshot().expect("raw locator snapshot");
        for family in [ColumnFamily::Blocks, ColumnFamily::Undo] {
            let locator = snapshot
                .get(family, old_record.hash.as_bytes())
                .expect("raw locator")
                .expect("locator");
            assert!(hns_store::SegmentValueLocator::decode(&locator)
                .expect("decode locator")
                .is_some());
        }
        drop(snapshot);

        let new_block = block_with_commitments(vec![coinbase_transaction_with_address(82, 60)]);
        let new_hash = new_block.hash();
        node.apply_reorg(NodeReorg {
            disconnect: vec![NodeBlockDisconnect {
                block_hash: old_record.hash,
                height: 0,
            }],
            connect: vec![NodeBlockImport::fixture(new_block.clone(), 0, 2)],
        })
        .expect("archived reorg");
        assert_eq!(
            node.state()
                .blocks
                .load_block(&new_hash)
                .expect("load archived replacement"),
            Some(new_block)
        );
        let snapshot = raw.snapshot().expect("post-reorg raw snapshot");
        assert!(snapshot
            .get(ColumnFamily::Undo, old_record.hash.as_bytes())
            .expect("old undo")
            .is_none());
        for family in [ColumnFamily::Blocks, ColumnFamily::Undo] {
            let locator = snapshot
                .get(family, new_hash.as_bytes())
                .expect("replacement locator")
                .expect("replacement locator");
            assert!(hns_store::SegmentValueLocator::decode(&locator)
                .expect("decode replacement locator")
                .is_some());
        }
        drop(snapshot);
        drop(node);

        let archived = raw
            .with_segment_archive(directory.clone())
            .expect("reopen payload archive");
        let reopened =
            NodeState::from_store_for_network(archived, Network::Regtest).expect("restart state");
        assert!(reopened
            .blocks
            .load_block(&new_hash)
            .expect("restart block")
            .is_some());
        assert!(reopened
            .state_engine
            .load_undo(&new_hash)
            .expect("restart undo")
            .is_some());
        drop(reopened);
        std::fs::remove_dir_all(directory).expect("remove payload archive fixture");
    }

    #[test]
    fn invalid_block_never_reaches_validated_or_committed_stage() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let mut subscription = node.subscribe_observed_mining_events();
        let mut block = block_with_commitments(vec![coinbase_transaction()]);
        block.header.merkle_root[0] ^= 1;

        assert!(node
            .connect_block(NodeBlockImport::fixture(block, 0, 1))
            .is_err());
        assert!(matches!(
            subscription.events.try_recv().expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            subscription.events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(node.mining_snapshot().is_none());
    }

    #[test]
    fn restart_recovers_the_exact_durable_mining_generation_and_tip() {
        let store = StoreHandle::memory();
        let config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(config.clone(), state).expect("node");
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let expected_hash = block.hash();
        node.connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect block");
        drop(node);

        let state =
            NodeState::from_store_for_network(store, Network::Regtest).expect("reloaded state");
        let restarted = NodeService::try_with_state(config, state).expect("restarted node");
        let snapshot = restarted
            .observed_mining_snapshot()
            .expect("observed state")
            .expect("recovered snapshot");
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.tip.hash, expected_hash);
        assert_eq!(snapshot.chainwork, Uint256::ONE);
        assert_eq!(snapshot.network_id, Network::Regtest.canonical_id());
    }

    #[test]
    fn startup_name_tree_compaction_is_due_bounded_and_checksummed() {
        assert!(validate_node_config(&NodeConfig {
            name_tree_compaction: NameTreeCompactionConfig {
                compact_on_startup: true,
                startup_interval: 0,
            },
            ..NodeConfig::default()
        })
        .is_err());

        let store = StoreHandle::memory();
        let base_config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(base_config.clone(), state).expect("node");
        let tip = connect_empty_chain_to_height_one(&mut node);
        let first_orphan = put_unreachable_name_node(&store, 0x71);
        drop(node);

        let startup_config = NodeConfig {
            name_tree_compaction: NameTreeCompactionConfig {
                compact_on_startup: true,
                startup_interval: 1,
            },
            ..base_config
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("restart");
        let mut node =
            NodeService::try_with_state(startup_config.clone(), state).expect("compact startup");
        assert!(store
            .snapshot()
            .expect("compacted snapshot")
            .get(ColumnFamily::NameTreeNodes, &first_orphan)
            .expect("first orphan read")
            .is_none());
        let first_checkpoint = node
            .name_tree_compaction_checkpoint()
            .expect("checkpoint read")
            .expect("checkpoint");
        assert_eq!(first_checkpoint.height, 1);
        assert_eq!(first_checkpoint.tip, tip.hash);
        assert_eq!(first_checkpoint.summary.nodes_deleted, 1);

        let second_orphan = put_unreachable_name_node(&store, 0x72);
        drop(node);
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("restart");
        node = NodeService::try_with_state(startup_config, state).expect("not-due startup");
        assert!(store
            .snapshot()
            .expect("not-due snapshot")
            .get(ColumnFamily::NameTreeNodes, &second_orphan)
            .expect("second orphan read")
            .is_some());
        assert_eq!(
            node.name_tree_compaction_checkpoint()
                .expect("unchanged checkpoint")
                .expect("checkpoint"),
            first_checkpoint
        );

        let forced = node.compact_name_tree_nodes().expect("manual compaction");
        assert_eq!(forced.height, 1);
        assert_eq!(forced.summary.nodes_deleted, 1);
        assert!(store
            .snapshot()
            .expect("forced snapshot")
            .get(ColumnFamily::NameTreeNodes, &second_orphan)
            .expect("second orphan after force")
            .is_none());
        drop(node);

        let snapshot = store.snapshot().expect("checkpoint snapshot");
        let mut raw = snapshot
            .get(ColumnFamily::Snapshots, NAME_TREE_COMPACTION_CHECKPOINT_KEY)
            .expect("checkpoint bytes")
            .expect("checkpoint bytes");
        drop(snapshot);
        *raw.last_mut().expect("checksum byte") ^= 1;
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                NAME_TREE_COMPACTION_CHECKPOINT_KEY,
                &raw,
            )
            .expect("corrupt checkpoint");
        store.commit(batch).expect("commit corrupt checkpoint");
        let error = NodeState::from_store_for_network(store, Network::Regtest)
            .expect_err("corrupt compaction checkpoint");
        assert!(
            error.to_string().contains("compaction checkpoint"),
            "{error}"
        );
    }

    #[test]
    fn undo_retention_retires_expired_pins_compacts_nodes_and_rejects_deep_reorgs() {
        let store = StoreHandle::memory();
        let policy = UndoRetentionPolicy {
            prune_after_height: 0,
            keep_blocks: 2,
        };
        let state = NodeState::from_store_for_network_with_undo_policy(
            store.clone(),
            Network::Regtest,
            Some(policy),
        )
        .expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        node.state.undo_retention_policy = Some(policy);
        node.state.state_engine = StoredStateEngine::with_services(
            store.clone(),
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("fixture input verifier");

        let mut records = connect_fixture_chain(&mut node, 195, Some(195));
        let snapshot = store.snapshot().expect("pre-prune snapshot");
        let expired_pin = load_name_tree_snapshot_pins(&snapshot)
            .expect("pins")
            .into_iter()
            .find(|pin| pin.height == 195)
            .expect("height-195 pin before pruning");
        assert_ne!(expired_pin.root.as_bytes(), &[0; 32]);
        assert_eq!(expired_pin.block_hash, records[195].hash);
        hns_state::validate_persisted_name_tree(&snapshot, expired_pin.root)
            .expect("pinned tree before pruning");
        drop(snapshot);

        for height in 196..=202 {
            let snapshot = store.snapshot().expect("name-tree snapshot");
            let tree_root =
                load_stored_name_tree_commit_root(&snapshot).expect("name-tree commit root");
            drop(snapshot);
            let coinbase = coinbase_transaction_with_tag(height, 50);
            let mut transactions = vec![coinbase];
            if height == 200 {
                transactions.push(open_transaction(
                    b"undo-retention-next",
                    Outpoint {
                        txid: coinbase_transaction_with_tag(197, 50).txid(),
                        index: 0,
                    },
                ));
            }
            let mut block = block_with_commitments(transactions);
            block.header.prev_block = records.last().expect("previous block").hash;
            block.header.tree_root = *tree_root.as_bytes();
            block.header.nonce = height.saturating_add(10);
            let record = node
                .connect_block(NodeBlockImport::fixture(
                    block,
                    height,
                    u64::from(height) + 1,
                ))
                .unwrap_or_else(|error| panic!("connect fixture height {height}: {error}"));
            records.push(record);
        }
        let checkpoint = node
            .undo_pruning_checkpoint()
            .expect("checkpoint read")
            .expect("checkpoint");
        assert_eq!(checkpoint.pruned_through, 200);
        assert_eq!(checkpoint.block_hash, records[200].hash);
        assert_eq!(checkpoint.pruned_undos, 200);
        assert_eq!(checkpoint.blocks_pruned_through, 200);
        assert_eq!(checkpoint.blocks_checkpoint, records[200].hash);
        assert_eq!(checkpoint.pruned_blocks, 200);

        let snapshot = store.snapshot().expect("retention snapshot");
        for (height, record) in records.iter().enumerate() {
            let retained = height == 0 || height > 200;
            let stored = load_block_index_record(&snapshot, &record.hash)
                .expect("block index read")
                .expect("block index");
            let header = load_header_record(&snapshot, &record.hash)
                .expect("header read")
                .expect("header");
            assert_eq!(stored.status.undo_present, retained, "height {height}");
            assert_eq!(header.status.undo_present, retained, "height {height}");
            assert_eq!(stored.status.body_present, retained, "height {height}");
            assert_eq!(header.status.body_present, retained, "height {height}");
            let live_block = node
                .state()
                .blocks
                .block(&record.hash)
                .expect("live block cache")
                .expect("live block");
            let live_header = node
                .state()
                .chain
                .header(&record.hash)
                .expect("live header cache")
                .expect("live header");
            assert_eq!(
                live_block.status.undo_present, retained,
                "live block undo height {height}"
            );
            assert_eq!(
                live_header.status.undo_present, retained,
                "live header undo height {height}"
            );
            assert_eq!(
                live_block.status.body_present, retained,
                "live block body height {height}"
            );
            assert_eq!(
                live_header.status.body_present, retained,
                "live header body height {height}"
            );
            assert_eq!(
                snapshot
                    .get(ColumnFamily::Undo, record.hash.as_bytes())
                    .expect("undo read")
                    .is_some(),
                retained,
                "height {height}"
            );
            assert_eq!(
                snapshot
                    .get(ColumnFamily::Blocks, record.hash.as_bytes())
                    .expect("block read")
                    .is_some(),
                retained,
                "height {height}"
            );
        }
        assert!(
            load_name_tree_snapshot_pins(&snapshot)
                .expect("pins")
                .into_iter()
                .all(|pin| pin.height != 195),
            "pruned interval pin must retire with its undo"
        );
        hns_state::validate_persisted_name_tree(&snapshot, expired_pin.root)
            .expect("expired tree nodes remain until compaction");
        let mut expected_retained_roots = HashSet::from([
            load_stored_name_tree_root(&snapshot).expect("current name-tree root"),
            load_stored_name_tree_commit_root(&snapshot).expect("committed name-tree root"),
        ]);
        for (_, raw) in snapshot
            .scan_prefix(ColumnFamily::Undo, b"")
            .expect("retained undo scan")
        {
            let undo = BlockUndo::decode(&raw).expect("retained undo");
            expected_retained_roots.insert(undo.previous_tree_root);
            expected_retained_roots.insert(undo.resulting_tree_root);
            expected_retained_roots.insert(undo.previous_committed_tree_root);
            expected_retained_roots.insert(undo.resulting_committed_tree_root);
        }
        assert!(
            !expected_retained_roots.contains(&expired_pin.root),
            "expired pin root must not remain an external retention authority"
        );
        let fork_root = load_header_record(&snapshot, &records[200].hash)
            .expect("fork child header read")
            .expect("fork child header")
            .header
            .tree_root;
        drop(snapshot);
        let unreachable = put_unreachable_name_node(&store, 0x73);

        node.config.undo_retention.prune_history = true;
        node.config.name_tree_compaction.startup_interval = 1;
        let compacted = node
            .compact_pruned_name_tree_nodes_if_due()
            .expect("compact pruned tree")
            .expect("due compaction");
        assert_eq!(
            compacted.summary.retained_roots,
            expected_retained_roots.len()
        );
        assert!(compacted.summary.nodes_deleted >= 1);
        let snapshot = store.snapshot().expect("compacted snapshot");
        assert!(
            snapshot
                .get(ColumnFamily::NameTreeNodes, &unreachable)
                .expect("unreachable node read")
                .is_none(),
            "scheduled compaction must delete unreachable nodes"
        );
        let current_root =
            load_stored_name_tree_root(&snapshot).expect("current name-tree root after compaction");
        hns_state::validate_persisted_name_tree(&snapshot, current_root)
            .expect("current tree survives compaction");
        drop(snapshot);

        let mut side_parent = records[199].hash;
        for height in 200..=203 {
            let mut block =
                block_with_commitments(vec![coinbase_transaction_with_tag(10_000 + height, 50)]);
            block.header.prev_block = side_parent;
            block.header.tree_root = fork_root;
            block.header.nonce = 20_000 + height;
            side_parent = block.hash();
            let result = node.accept_block(NodeBlockImport::fixture(
                block,
                height,
                u64::from(height) + 1,
            ));
            if height < 203 {
                assert_eq!(
                    result.expect("store side block").disposition,
                    BlockDisposition::StoredAlternate
                );
            } else {
                let error = result.expect_err("deep reorganization");
                assert!(
                    error.to_string().contains("crosses pruned undo history"),
                    "{error}"
                );
            }
        }
        assert_eq!(
            node.state
                .best_block_tip()
                .expect("tip")
                .expect("active tip")
                .hash,
            records[202].hash
        );
        assert_eq!(
            node.undo_pruning_checkpoint()
                .expect("checkpoint reread")
                .expect("checkpoint"),
            checkpoint
        );
        drop(node);

        NodeState::from_store_for_network_with_undo_policy(
            store.clone(),
            Network::Regtest,
            Some(policy),
        )
        .expect("pruned state reopens");
        let state = NodeState::from_store_for_network_with_undo_policy(
            store,
            Network::Regtest,
            Some(policy),
        )
        .expect("state for disabled-policy check");
        let error = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect_err("disabled pruning after retirement");
        assert!(
            error.to_string().contains("cannot be changed to archive"),
            "{error}"
        );
    }

    #[test]
    fn undo_pruning_checkpoint_is_checksummed() {
        let store = StoreHandle::memory();
        NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut raw = UndoPruningCheckpoint {
            pruned_through: 1_001,
            block_hash: BlockHash::new([0x91; 32]),
            pruned_undos: 1,
            blocks_pruned_through: 1_001,
            blocks_checkpoint: BlockHash::new([0x91; 32]),
            pruned_blocks: 1,
        }
        .encode();
        *raw.last_mut().expect("checksum byte") ^= 1;
        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Snapshots, UNDO_PRUNING_CHECKPOINT_KEY, &raw)
            .expect("stage corrupt checkpoint");
        store.commit(batch).expect("commit corrupt checkpoint");
        let error = NodeState::from_store_for_network(store, Network::Regtest)
            .expect_err("corrupt undo-pruning checkpoint");
        assert!(error.to_string().contains("checksum mismatch"), "{error}");
    }

    #[test]
    fn legacy_undo_only_checkpoint_upgrades_with_block_backfill_pending() {
        let block_hash = BlockHash::new([0x52; 32]);
        let mut writer = Writer::with_capacity(UNDO_PRUNING_CHECKPOINT_LEGACY_BODY_SIZE);
        writer.write_u32(UNDO_PRUNING_CHECKPOINT_LEGACY_VERSION);
        writer.write_u32(1_234);
        writer.write_bytes(block_hash.as_bytes());
        writer.write_u64(234);
        let mut raw = writer.finish();
        raw.extend_from_slice(&blake2b_256(&raw));

        let legacy = UndoPruningCheckpoint::decode(&raw).expect("decode legacy checkpoint");
        assert_eq!(legacy.pruned_through, 1_234);
        assert_eq!(legacy.block_hash, block_hash);
        assert_eq!(legacy.pruned_undos, 234);
        assert_eq!(legacy.blocks_pruned_through, 0);
        assert_eq!(legacy.blocks_checkpoint, BlockHash::ZERO);
        assert_eq!(legacy.pruned_blocks, 0);

        let upgraded =
            UndoPruningCheckpoint::decode(&legacy.encode()).expect("decode upgraded checkpoint");
        assert_eq!(upgraded, legacy);
    }

    #[test]
    fn legacy_undo_only_store_backfills_pruned_blocks_without_replaying_undos() {
        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        let records = connect_fixture_chain(&mut node, 7, None);
        drop(node);

        let snapshot = store.snapshot().expect("legacy snapshot");
        let mut batch = store.batch();
        for record in records.iter().take(6).skip(1) {
            let raw_undo = snapshot
                .get(ColumnFamily::Undo, record.hash.as_bytes())
                .expect("undo read")
                .expect("undo bytes");
            let undo = BlockUndo::decode(&raw_undo).expect("undo decode");
            stage_remove_name_tree_snapshot_pin(&snapshot, &mut batch, &undo)
                .expect("retire legacy pin");
            let mut block = load_block_index_record(&snapshot, &record.hash)
                .expect("block index read")
                .expect("block index");
            let mut header = load_header_record(&snapshot, &record.hash)
                .expect("header read")
                .expect("header");
            block.status.undo_present = false;
            header.status.undo_present = false;
            write_block_index_to_batch(&mut batch, &block).expect("stage block index");
            write_record_to_batch(&mut batch, &header).expect("stage header");
            batch
                .delete(ColumnFamily::Undo, record.hash.as_bytes())
                .expect("delete legacy undo");
        }
        let mut writer = Writer::with_capacity(UNDO_PRUNING_CHECKPOINT_LEGACY_BODY_SIZE);
        writer.write_u32(UNDO_PRUNING_CHECKPOINT_LEGACY_VERSION);
        writer.write_u32(5);
        writer.write_bytes(records[5].hash.as_bytes());
        writer.write_u64(5);
        let mut legacy = writer.finish();
        legacy.extend_from_slice(&blake2b_256(&legacy));
        batch
            .put(
                ColumnFamily::Snapshots,
                UNDO_PRUNING_CHECKPOINT_KEY,
                &legacy,
            )
            .expect("stage legacy checkpoint");
        drop(snapshot);
        store.commit(batch).expect("commit legacy store");

        let policy = UndoRetentionPolicy {
            prune_after_height: 0,
            keep_blocks: 2,
        };
        let mut state = NodeState::from_store_for_network_with_undo_policy(
            store.clone(),
            Network::Regtest,
            Some(policy),
        )
        .expect("open legacy store");
        state
            .prune_undo_history_to_policy()
            .expect("backfill block pruning");

        let checkpoint = {
            let snapshot = store.snapshot().expect("checkpoint snapshot");
            load_undo_pruning_checkpoint(&snapshot)
                .expect("checkpoint read")
                .expect("checkpoint")
        };
        assert_eq!(checkpoint.pruned_through, 5);
        assert_eq!(checkpoint.pruned_undos, 5);
        assert_eq!(checkpoint.blocks_pruned_through, 5);
        assert_eq!(checkpoint.blocks_checkpoint, records[5].hash);
        assert_eq!(checkpoint.pruned_blocks, 5);
        let snapshot = store.snapshot().expect("backfilled snapshot");
        for record in records.iter().take(6).skip(1) {
            assert!(
                snapshot
                    .get(ColumnFamily::Blocks, record.hash.as_bytes())
                    .expect("block read")
                    .is_none(),
                "legacy body {} was not pruned",
                record.hash.to_hex()
            );
        }
    }

    #[test]
    fn startup_undo_retention_catches_up_an_existing_chain() {
        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        let records = connect_fixture_chain(&mut node, 7, None);
        assert!(node
            .undo_pruning_checkpoint()
            .expect("checkpoint read")
            .is_none());
        drop(node);

        let policy = UndoRetentionPolicy {
            prune_after_height: 0,
            keep_blocks: 2,
        };
        let mut state = NodeState::from_store_for_network_with_undo_policy(
            store.clone(),
            Network::Regtest,
            Some(policy),
        )
        .expect("unpruned state");
        state
            .prune_undo_history_to_policy()
            .expect("startup catch-up");
        let snapshot = store.snapshot().expect("pruned snapshot");
        let checkpoint = load_undo_pruning_checkpoint(&snapshot)
            .expect("checkpoint read")
            .expect("checkpoint");
        assert_eq!(checkpoint.pruned_through, 5);
        assert_eq!(checkpoint.block_hash, records[5].hash);
        assert_eq!(checkpoint.pruned_undos, 5);
        assert_eq!(checkpoint.blocks_pruned_through, 5);
        assert_eq!(checkpoint.blocks_checkpoint, records[5].hash);
        assert_eq!(checkpoint.pruned_blocks, 5);
        for record in records.iter().take(6).skip(1) {
            let live_block = state
                .blocks
                .block(&record.hash)
                .expect("startup live block")
                .expect("startup block record");
            let live_header = state
                .chain
                .header(&record.hash)
                .expect("startup live header")
                .expect("startup header record");
            assert!(!live_block.status.undo_present);
            assert!(!live_header.status.undo_present);
            assert!(!live_block.status.body_present);
            assert!(!live_header.status.body_present);
        }
        drop(snapshot);
        NodeState::from_store_for_network_with_undo_policy(store, Network::Regtest, Some(policy))
            .expect("caught-up state reopens");
    }

    #[test]
    fn startup_rejects_active_tip_undo_root_drift() {
        let store = StoreHandle::memory();
        let config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(config, state).expect("node");
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let block_hash = block.hash();
        node.connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect block");
        drop(node);

        let snapshot = store.snapshot().expect("snapshot");
        let mut encoded = snapshot
            .get(ColumnFamily::Undo, block_hash.as_bytes())
            .expect("undo lookup")
            .expect("undo payload");
        drop(snapshot);
        assert!(encoded.len() >= 104);
        encoded[72..104].fill(0x55);

        let mut batch = store.batch();
        batch
            .put(ColumnFamily::Undo, block_hash.as_bytes(), &encoded)
            .expect("corrupt undo root");
        store.commit(batch).expect("commit corrupt undo root");

        assert!(NodeState::from_store_for_network(store, Network::Regtest).is_err());
    }

    #[test]
    fn startup_rejects_missing_or_corrupt_deployment_state_cache() {
        for corrupt in [false, true] {
            let store = StoreHandle::memory();
            let state =
                NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
            let mut node = NodeService::try_with_state(
                NodeConfig {
                    network: Network::Regtest,
                    ..NodeConfig::default()
                },
                state,
            )
            .expect("node");
            let block = block_with_commitments(vec![coinbase_transaction()]);
            let block_hash = block.hash();
            node.connect_block(NodeBlockImport::fixture(block, 0, 1))
                .expect("connect block");
            drop(node);

            let key = deployment_state_cache_key(block_hash);
            let mut batch = store.batch();
            if corrupt {
                batch
                    .put(
                        ColumnFamily::Snapshots,
                        &key,
                        &[DEPLOYMENT_STATE_CACHE_VERSION, 0, 0, 0, 0, 0, 0, 0, 9],
                    )
                    .expect("corrupt deployment state");
            } else {
                batch
                    .delete(ColumnFamily::Snapshots, &key)
                    .expect("delete deployment state");
            }
            store.commit(batch).expect("commit cache fault");

            let error = NodeState::from_store_for_network(store, Network::Regtest)
                .expect_err("deployment-state corruption");
            assert!(error.to_string().contains("deployment-state"), "{error}");
        }
    }

    #[test]
    fn startup_rejects_missing_or_corrupt_name_tree_snapshot_pin() {
        for missing in [true, false] {
            let store = StoreHandle::memory();
            let state =
                NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
            let mut node = NodeService::try_with_state(
                NodeConfig {
                    network: Network::Regtest,
                    ..NodeConfig::default()
                },
                state,
            )
            .expect("node");
            let block = block_with_commitments(vec![coinbase_transaction()]);
            node.connect_block(NodeBlockImport::fixture(block, 0, 1))
                .expect("connect interval block");
            drop(node);

            let key = name_tree_snapshot_pin_key(0);
            let snapshot = store.snapshot().expect("snapshot");
            let mut raw = snapshot
                .get(ColumnFamily::Snapshots, &key)
                .expect("pin read")
                .expect("pin");
            drop(snapshot);
            let mut batch = store.batch();
            if missing {
                batch
                    .delete(ColumnFamily::Snapshots, &key)
                    .expect("delete pin");
            } else {
                *raw.last_mut().expect("checksum byte") ^= 1;
                batch
                    .put(ColumnFamily::Snapshots, &key, &raw)
                    .expect("corrupt pin");
            }
            store.commit(batch).expect("commit pin fault");

            let error = NodeState::from_store_for_network(store, Network::Regtest)
                .expect_err("snapshot pin corruption");
            assert!(error.to_string().contains("snapshot pin"), "{error}");
        }
    }

    #[test]
    fn startup_rejects_missing_or_corrupt_content_addressed_name_nodes() {
        for missing in [true, false] {
            let store = StoreHandle::memory();
            let state =
                NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
            let mut node = NodeService::try_with_state(
                NodeConfig {
                    network: Network::Regtest,
                    ..NodeConfig::default()
                },
                state,
            )
            .expect("node");
            node.state.state_engine = StoredStateEngine::with_services(
                store.clone(),
                Network::Regtest,
                NameFlags::NONE,
                true,
                Arc::new(AllowAllInputVerifier),
                Arc::new(RejectSpecialCoinbaseIssuance),
            )
            .expect("fixture input verifier");
            connect_fixture_chain(&mut node, 200, Some(200));
            drop(node);

            let snapshot = store.snapshot().expect("snapshot");
            let root = snapshot
                .get(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())
                .expect("root read")
                .expect("root");
            let mut record = snapshot
                .get(ColumnFamily::NameTreeNodes, &root)
                .expect("record read")
                .expect("record");
            drop(snapshot);

            let mut batch = store.batch();
            if missing {
                batch
                    .delete(ColumnFamily::NameTreeNodes, &root)
                    .expect("delete record");
            } else {
                *record.last_mut().expect("record byte") ^= 1;
                batch
                    .put(ColumnFamily::NameTreeNodes, &root, &record)
                    .expect("corrupt record");
            }
            store.commit(batch).expect("commit node fault");

            let error = NodeState::from_store_for_network(store, Network::Regtest)
                .expect_err("content-addressed name-tree corruption");
            let message = error.to_string();
            assert!(
                message.contains("name-tree")
                    && (message.contains("missing") || message.contains("hash mismatch")),
                "{error}"
            );
        }
    }

    #[test]
    fn startup_audit_checkpoint_is_checksummed_and_bound_to_durable_identity() {
        let store = StoreHandle::memory();
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let snapshot = store.snapshot().expect("snapshot");
        let checkpoint =
            StartupAuditCheckpoint::capture(&snapshot, Network::Regtest).expect("checkpoint");
        drop(snapshot);

        let raw = checkpoint.encode();
        assert_eq!(
            StartupAuditCheckpoint::decode(&raw).expect("decode checkpoint"),
            checkpoint
        );
        assert_eq!(
            state
                .validate_durable_chain_invariants(Some(&checkpoint), false)
                .expect("matching audit"),
            StartupAuditKind::CleanCheckpoint
        );

        let mut corrupt = raw;
        *corrupt.last_mut().expect("checksum byte") ^= 1;
        let error = StartupAuditCheckpoint::decode(&corrupt).expect_err("checksum corruption");
        assert!(error.to_string().contains("checksum mismatch"), "{error}");

        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::ChainEpoch.as_bytes(),
                &encode_u64(1),
            )
            .expect("chain epoch");
        store.commit(batch).expect("commit identity drift");
        assert_eq!(
            state
                .validate_durable_chain_invariants(Some(&checkpoint), false)
                .expect("mismatch falls back to exhaustive audit"),
            StartupAuditKind::Exhaustive
        );
    }

    #[test]
    fn clean_checkpoint_audits_reorganization_suffix_while_unclean_audits_history() {
        let store = StoreHandle::memory();
        let policy = UndoRetentionPolicy {
            prune_after_height: 0,
            keep_blocks: 2,
        };
        let state = NodeState::from_store_for_network_with_undo_policy(
            store.clone(),
            Network::Regtest,
            Some(policy),
        )
        .expect("state");
        let mut node = NodeService::try_with_state(
            NodeConfig {
                network: Network::Regtest,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("node");
        node.state.undo_retention_policy = Some(policy);
        let records = connect_fixture_chain(&mut node, 4, None);
        let snapshot = store.snapshot().expect("checkpoint snapshot");
        let checkpoint =
            StartupAuditCheckpoint::capture(&snapshot, Network::Regtest).expect("checkpoint");
        drop(snapshot);

        let mut batch = store.batch();
        batch
            .delete(ColumnFamily::Blocks, records[0].hash.as_bytes())
            .expect("delete dormant historical body");
        store.commit(batch).expect("commit historical fault");

        assert_eq!(
            node.state
                .validate_durable_chain_invariants(Some(&checkpoint), false)
                .expect("bounded clean audit"),
            StartupAuditKind::CleanCheckpoint
        );
        let error = node
            .state
            .validate_durable_chain_invariants(None, false)
            .expect_err("unclean audit must inspect complete history");
        assert!(error.to_string().contains("body"), "{error}");
    }

    #[test]
    fn clean_marker_and_startup_audit_checkpoint_commit_atomically() {
        let store = StoreHandle::memory();
        NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        mark_node_store_clean(&store, Network::Regtest).expect("clean checkpoint");

        assert!(was_clean_shutdown(&store).expect("clean marker"));
        let snapshot = store.snapshot().expect("snapshot");
        let stored = load_startup_audit_checkpoint(&snapshot)
            .expect("checkpoint read")
            .expect("checkpoint");
        let current =
            StartupAuditCheckpoint::capture(&snapshot, Network::Regtest).expect("current identity");
        assert_eq!(stored, current);
    }

    #[test]
    fn offline_storage_maintenance_marker_blocks_node_startup() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-maintenance-marker-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create data root");
        std::fs::write(
            path.join(STORAGE_MAINTENANCE_MARKER),
            STORAGE_MAINTENANCE_MARKER_BODY,
        )
        .expect("write maintenance marker");
        let error = NodeState::from_config(&NodeConfig {
            network: Network::Regtest,
            data_dir: Some(path.clone()),
            ..NodeConfig::default()
        })
        .expect_err("maintenance marker must block startup");
        assert!(error.to_string().contains("maintenance marker"), "{error}");
        std::fs::remove_dir_all(path).expect("remove marker fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn clean_restart_uses_checkpoint_and_failed_startup_stays_unclean() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-startup-audit-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = NodeConfig {
            network: Network::Regtest,
            data_dir: Some(path.clone()),
            ..NodeConfig::default()
        };
        let block_hash;

        {
            let mut node = NodeService::try_new(config.clone()).expect("initial node");
            let block = block_with_commitments(vec![coinbase_transaction()]);
            block_hash = block.hash();
            node.connect_block(NodeBlockImport::fixture(block, 0, 1))
                .expect("connect block");
            mark_node_store_clean(&node.state.store, Network::Regtest)
                .expect("clean first process");
        }

        {
            let state = NodeState::from_config(&config).expect("clean checkpoint restart");
            let lifecycle = state.startup_lifecycle.as_ref().expect("service lifecycle");
            assert!(lifecycle.previous_shutdown_clean);
            assert_eq!(lifecycle.audit, StartupAuditKind::CleanCheckpoint);
            assert!(!was_clean_shutdown(&state.store).expect("claimed store is unclean"));
            mark_node_store_clean(&state.store, Network::Regtest).expect("clean second process");
        }

        {
            let store = open_store(&StoreConfig {
                path: path.join("chain"),
                backend: StoreBackend::RocksDb,
                durability: DurabilityPolicy::Sync,
            })
            .expect("open fault store");
            let mut batch = store.batch();
            batch
                .delete(ColumnFamily::Blocks, block_hash.as_bytes())
                .expect("delete active body");
            store.commit(batch).expect("commit active-body fault");
        }

        let error = NodeState::from_config(&config).expect_err("startup body audit");
        assert!(error.to_string().contains("body"), "{error}");
        let store = open_store(&StoreConfig {
            path: path.join("chain"),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        })
        .expect("reopen failed-start store");
        assert!(!was_clean_shutdown(&store).expect("failed startup marker"));
        drop(store);
        std::fs::remove_dir_all(path).expect("remove startup-audit store");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn content_addressed_name_proofs_survive_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-name-proof-reopen-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = StoreConfig {
            path: path.clone(),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        };
        let name = b"persistedrocksproof";
        let name_hash = NameHash::new(hns_primitives::sha3_256(name));
        let expected;

        {
            let store = open_store(&config).expect("open store");
            let mut state = StoredStateEngine::with_native_authorization_and_verified_name_flags(
                store,
                Network::Regtest,
                NameFlags::NONE,
            )
            .expect("state");
            let block = block_with_commitments(vec![open_coinbase_transaction(name)]);
            state
                .connect_block(ConnectBlock {
                    block_hash: block.hash(),
                    height: 200,
                    coinbase_maturity: 0,
                    block_reward: 50,
                    block: &block,
                })
                .expect("connect name state");
            let (root, proof) = state.name_proof(name_hash).expect("proof");
            proof.verify_value(root).expect("verify proof");
            expected = (root, proof.raw);
        }

        {
            let store = open_store(&config).expect("reopen store");
            let state = StoredStateEngine::with_native_authorization_and_verified_name_flags(
                store,
                Network::Regtest,
                NameFlags::NONE,
            )
            .expect("reopened state");
            let (root, proof) = state.name_proof(name_hash).expect("reopened proof");
            assert_eq!(root, expected.0);
            assert_eq!(proof.raw, expected.1);
            assert!(proof
                .verify_value(root)
                .expect("verify reopened proof")
                .is_some());
        }

        std::fs::remove_dir_all(&path).expect("remove test store");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn startup_name_tree_compaction_survives_unclean_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-name-compaction-reopen-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let store_config = StoreConfig {
            path: path.clone(),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        };
        let node_config = NodeConfig {
            network: Network::Regtest,
            name_tree_compaction: NameTreeCompactionConfig {
                compact_on_startup: true,
                startup_interval: 1,
            },
            ..NodeConfig::default()
        };
        let orphan = [0x73; 32];
        let expected_tip;

        {
            let store = open_store(&store_config).expect("open store");
            let state =
                NodeState::from_store_for_network(store, Network::Regtest).expect("initial state");
            let mut node = NodeService::try_with_state(
                NodeConfig {
                    name_tree_compaction: NameTreeCompactionConfig::default(),
                    ..node_config.clone()
                },
                state,
            )
            .expect("initial node");
            expected_tip = connect_empty_chain_to_height_one(&mut node).hash;
            put_unreachable_name_node(&node.state().store, orphan[0]);
            assert!(!was_clean_shutdown(&node.state().store).expect("unclean marker"));
        }

        {
            let store = open_store(&store_config).expect("first reopen");
            let state =
                NodeState::from_store_for_network(store, Network::Regtest).expect("reopened state");
            let node = NodeService::try_with_state(node_config.clone(), state)
                .expect("startup compaction");
            let snapshot = node.state().store.snapshot().expect("compacted snapshot");
            assert!(snapshot
                .get(ColumnFamily::NameTreeNodes, &orphan)
                .expect("orphan read")
                .is_none());
            drop(snapshot);
            let checkpoint = node
                .name_tree_compaction_checkpoint()
                .expect("checkpoint read")
                .expect("checkpoint");
            assert_eq!(checkpoint.height, 1);
            assert_eq!(checkpoint.tip, expected_tip);
            assert_eq!(checkpoint.summary.nodes_deleted, 1);
            assert!(!was_clean_shutdown(&node.state().store).expect("still unclean"));
        }

        {
            let store = open_store(&store_config).expect("second reopen");
            let state = NodeState::from_store_for_network(store, Network::Regtest)
                .expect("second reopened state");
            let node = NodeService::try_with_state(node_config, state).expect("idempotent startup");
            let checkpoint = node
                .name_tree_compaction_checkpoint()
                .expect("checkpoint read")
                .expect("checkpoint");
            assert_eq!(checkpoint.height, 1);
            assert_eq!(checkpoint.tip, expected_tip);
            assert_eq!(checkpoint.summary.nodes_deleted, 1);
        }

        std::fs::remove_dir_all(&path).expect("remove test store");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn undo_retention_survives_unclean_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-undo-retention-reopen-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let store_config = StoreConfig {
            path: path.clone(),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        };
        let policy = UndoRetentionPolicy {
            prune_after_height: 0,
            keep_blocks: 2,
        };
        let expected_checkpoint;

        {
            let store = open_store(&store_config).expect("open store");
            let state = NodeState::from_store_for_network_with_undo_policy(
                store,
                Network::Regtest,
                Some(policy),
            )
            .expect("initial state");
            let mut node = NodeService::try_with_state(
                NodeConfig {
                    network: Network::Regtest,
                    ..NodeConfig::default()
                },
                state,
            )
            .expect("initial node");
            node.state.undo_retention_policy = Some(policy);
            let records = connect_fixture_chain(&mut node, 7, None);
            expected_checkpoint = UndoPruningCheckpoint {
                pruned_through: 5,
                block_hash: records[5].hash,
                pruned_undos: 5,
                blocks_pruned_through: 5,
                blocks_checkpoint: records[5].hash,
                pruned_blocks: 5,
            };
            assert_eq!(
                node.undo_pruning_checkpoint()
                    .expect("checkpoint read")
                    .expect("checkpoint"),
                expected_checkpoint
            );
            assert!(!was_clean_shutdown(&node.state.store).expect("unclean marker"));
        }

        {
            let store = open_store(&store_config).expect("reopen store");
            let mut state = NodeState::from_store_for_network_with_undo_policy(
                store,
                Network::Regtest,
                Some(policy),
            )
            .expect("reopened pruned state");
            let snapshot = state.store.snapshot().expect("reopened snapshot");
            assert_eq!(
                load_undo_pruning_checkpoint(&snapshot)
                    .expect("checkpoint read")
                    .expect("checkpoint"),
                expected_checkpoint
            );
            assert!(!was_clean_shutdown(&state.store).expect("unclean marker"));
            drop(snapshot);
            state
                .compact_name_tree_nodes()
                .expect("compact reopened pruned state");
        }

        {
            let store = open_store(&store_config).expect("second reopen");
            NodeState::from_store_for_network_with_undo_policy(
                store,
                Network::Regtest,
                Some(policy),
            )
            .expect("compacted pruned state reopens");
        }

        std::fs::remove_dir_all(&path).expect("remove test store");
    }

    #[test]
    fn durable_store_rejects_cross_network_reopen() {
        let store = StoreHandle::memory();
        NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("bind regtest");
        assert!(NodeState::from_store_for_network(store, Network::Mainnet).is_err());
    }

    #[test]
    fn durable_store_rejects_storage_profile_drift() {
        let store = StoreHandle::memory();
        NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("bind storage profile");
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                b"different-profile",
            )
            .expect("corrupt profile");
        store.commit(batch).expect("commit profile drift");

        assert!(NodeState::from_store_for_network(store, Network::Regtest).is_err());
    }

    #[test]
    fn node_rpc_snapshot_reads_committed_block_state() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let record = node
            .connect_block(NodeBlockImport::fixture(block.clone(), 0, 1))
            .expect("connect block");
        let txid = block.transactions[0].txid();

        let rpc = node.rpc_service().expect("rpc service");
        let block_count = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockcount".to_owned(),
                params: Value::Null,
                id: Some(json!(1)),
            })
            .expect("block count");
        assert_eq!(block_count.result.expect("height"), json!(0));

        let height_hash = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockhash".to_owned(),
                params: json!([0]),
                id: Some(json!(2)),
            })
            .expect("block hash");
        assert_eq!(
            height_hash.result.expect("hash"),
            json!(record.hash.to_hex())
        );

        let raw_tx = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getrawtransaction".to_owned(),
                params: json!([txid.to_hex(), true]),
                id: Some(json!(3)),
            })
            .expect("raw tx");
        assert_eq!(raw_tx.result.expect("tx")["confirmations"], 1);

        let coin = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "gettxout".to_owned(),
                params: json!([txid.to_hex(), 0]),
                id: Some(json!(4)),
            })
            .expect("coin");
        assert_eq!(coin.result.expect("coin")["value"], 50);
    }

    #[test]
    fn rpc_point_reads_materialize_only_requested_records() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            transaction_index: true,
            ..NodeConfig::default()
        });
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let record = node
            .connect_block(NodeBlockImport::fixture(block.clone(), 0, 1))
            .expect("connect block");
        let txid = block.transactions[0].txid();
        let context = node.rpc_read_context();

        for (method, params, expected_collection) in [
            (
                RpcMethod::GetBlockHash,
                json!([0]),
                (1usize, 0usize, 0usize, 0usize),
            ),
            (
                RpcMethod::GetBlock,
                json!([record.hash.to_hex(), true]),
                (0, 1, 0, 0),
            ),
            (
                RpcMethod::GetRawTransaction,
                json!([txid.to_hex(), true]),
                (0, 0, 1, 0),
            ),
            (RpcMethod::GetTxOut, json!([txid.to_hex(), 0]), (0, 0, 0, 1)),
            (RpcMethod::GetDnsResource, json!(["missing"]), (0, 0, 0, 0)),
        ] {
            let request = JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: match method {
                    RpcMethod::GetBlockHash => "getblockhash",
                    RpcMethod::GetBlock => "getblock",
                    RpcMethod::GetRawTransaction => "getrawtransaction",
                    RpcMethod::GetTxOut => "gettxout",
                    RpcMethod::GetDnsResource => "getdnsresource",
                    _ => unreachable!(),
                }
                .to_owned(),
                params,
                id: Some(json!(method)),
            };
            let service = context
                .service_for_request(&request, node.rpc_request_mempool(&request), false, 0, None)
                .expect("bounded point-read service");
            let snapshot = service.snapshot();
            assert_eq!(
                (
                    snapshot.headers.len(),
                    snapshot.blocks.len(),
                    snapshot.transactions.len(),
                    snapshot.coins.len(),
                ),
                expected_collection
            );
            assert_eq!(
                snapshot.dns_context.is_some(),
                method == RpcMethod::GetDnsResource
            );
            let response = service.handle(request).expect("RPC response");
            assert!(response.error.is_none(), "{response:?}");
            if method == RpcMethod::GetDnsResource {
                let result = response.result.expect("DNS resource result");
                assert_eq!(result["name"], "missing");
                assert!(result["resource"].is_null());
                assert_eq!(result["context"]["active_height"], 0);
                assert_eq!(result["context"]["best_header_height"], 0);
                assert_eq!(result["context"]["synchronized"], true);
            }
        }
    }

    #[test]
    fn rpc_header_selection_never_reloads_a_new_index_generation_from_an_old_snapshot() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let context = node.rpc_read_context();
        let stale_snapshot = context.store.snapshot().expect("pre-import snapshot");
        let record = node
            .state_mut()
            .chain
            .import_header(HeaderImport {
                header: Header {
                    bits: Network::Regtest.params().pow.bits,
                    ..Header::default()
                },
                height: 0,
                verify_pow: false,
                checkpoint_valid: false,
            })
            .expect("publish header after snapshot");
        assert!(
            load_header_record(&stale_snapshot, &record.hash)
                .expect("stale header lookup")
                .is_none(),
            "the barrier fixture must retain a snapshot from before publication"
        );

        let request = JsonRpcRequest {
            jsonrpc: Some("2.0".to_owned()),
            method: "getblockhash".to_owned(),
            params: json!([0]),
            id: Some(json!("header-generation")),
        };
        assert_eq!(
            context
                .canonical_header_for_request(RpcMethod::GetBlockHash, &request)
                .expect("atomic header selection")
                .map(|selected| selected.hash),
            Some(record.hash)
        );
        let service = context
            .service_for_request(&request, node.rpc_request_mempool(&request), false, 0, None)
            .expect("coherent header RPC");
        let response = service.handle(request).expect("header RPC response");
        assert_eq!(response.result, Some(json!(record.hash.to_hex())));
        assert!(response.error.is_none());
    }

    #[test]
    fn rpc_generation_read_blocks_between_durable_commit_and_cache_publication() {
        let mut state = NodeState::from_store_for_network(StoreHandle::memory(), Network::Regtest)
            .expect("empty state");
        let context = RpcReadContext {
            store: state.store.clone(),
            headers: state.chain.clone(),
            network: Network::Regtest,
            transaction_index: false,
            point_read_concurrency: Arc::new(Semaphore::new(1)),
            collection_concurrency: Arc::new(Semaphore::new(1)),
        };
        let block = block_with_commitments(vec![coinbase_transaction_with_address(0x71, 50)]);
        let hash = block.hash();
        let status = BlockStatus {
            header_context_valid: true,
            body_present: true,
            body_syntax_valid: true,
            active_chain: true,
            ..BlockStatus::default()
        };
        let mut block_record =
            BlockIndexRecord::from_block(&block, 0, Uint256::ONE).expect("block record");
        block_record.status = status.clone();
        let header_record = HeaderRecord {
            hash,
            height: 0,
            chainwork: Uint256::ONE,
            header: block.header,
            status,
        };
        let publication = state
            .prepare_index_publication(&[IndexStatusUpdate {
                previous_block: None,
                current: StagedIndexRecord {
                    block: block_record.clone(),
                    header: header_record.clone(),
                },
            }])
            .expect("prepare publication");
        let mut batch = state.store.batch();
        write_record_to_batch(&mut batch, &header_record).expect("stage header");
        write_block_index_to_batch(&mut batch, &block_record).expect("stage block index");
        write_canonical_height_to_batch(&mut batch, 0, hash).expect("stage canonical height");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                hash.as_bytes(),
            )
            .expect("stage best header");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                hash.as_bytes(),
            )
            .expect("stage best block");

        let (committed_tx, committed_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            state
                .commit_index_publication(publication, move |state| {
                    state.store.commit(batch)?;
                    committed_tx
                        .send(())
                        .map_err(|_| anyhow::anyhow!("commit signal receiver dropped"))?;
                    release_rx
                        .recv()
                        .map_err(|_| anyhow::anyhow!("publication release sender dropped"))?;
                    Ok(())
                })
                .expect("commit and publish generation");
        });
        committed_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("durable commit signal");

        assert!(matches!(
            context.headers.inner.try_read(),
            Err(std::sync::TryLockError::WouldBlock)
        ));

        let request = JsonRpcRequest {
            jsonrpc: Some("2.0".to_owned()),
            method: "getblockhash".to_owned(),
            params: json!([0]),
            id: Some(json!("atomic-generation")),
        };
        let (reader_started_tx, reader_started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            reader_started_tx.send(()).expect("signal reader start");
            let service = context
                .service_for_request(&request, RpcRequestMempool::default(), false, 0, None)
                .expect("coherent request service");
            let response = service.handle(request).expect("header response");
            result_tx.send(response.result).expect("send RPC result");
        });
        reader_started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("reader start");
        assert!(matches!(
            result_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        release_tx.send(()).expect("release publication");
        assert_eq!(
            result_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("post-publication RPC result"),
            Some(json!(hash.to_hex()))
        );
        writer.join().expect("writer thread");
        reader.join().expect("reader thread");
    }

    #[tokio::test]
    async fn node_serves_json_rpc_over_http() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let service = node.rpc_service().expect("rpc service");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_rpc_listener(listener, service, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let body = r#"{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":7}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
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
        let (_, response_body) = response.split_once("\r\n\r\n").expect("body split");
        let json: Value = serde_json::from_str(response_body).expect("json response");
        assert_eq!(json["id"], 7);
        assert_eq!(json["result"]["networkactive"], false);

        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server join").expect("server result");
    }

    #[tokio::test]
    async fn rpc_http_rejects_oversized_request_bodies() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let service = node.rpc_diagnostic_service().expect("RPC service");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let limits = RpcLimits {
            maximum_request_bytes: 64,
            ..RpcLimits::default()
        };
        let server = tokio::spawn(async move {
            serve_rpc_listener_with_state(
                listener,
                RpcHttpState::new(service.clone(), service, None, None, limits),
                None,
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });

        let body = "x".repeat(65);
        let request = format!(
            "POST /rpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write oversized request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        assert!(
            response.starts_with("HTTP/1.1 413 Payload Too Large"),
            "{response}"
        );

        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server join").expect("server result");
    }

    #[tokio::test]
    async fn timed_out_point_read_retains_worker_capacity_until_completion() {
        let config = NodeConfig {
            network: Network::Regtest,
            rpc_limits: RpcLimits {
                maximum_concurrent_requests: 1,
                execution_timeout: Duration::from_millis(10),
                ..RpcLimits::default()
            },
            ..NodeConfig::default()
        };
        let node = NodeService::new(config.clone());
        let read_context = node.rpc_read_context();
        let permit = read_context
            .try_acquire_point_read()
            .expect("first point-read permit");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let permit = permit;
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            drop(permit);
            let _ = done_tx.send(());
        });
        started_rx.await.expect("point-read worker started");

        let runtime_limits = RpcRuntimeLimits::new(config.rpc_limits);
        let result = execute_with_rpc_limits(&runtime_limits, async move {
            let _ = worker.await;
        })
        .await;
        assert_eq!(result, Err(RpcAdmissionError::TimedOut));
        assert!(
            read_context.try_acquire_point_read().is_none(),
            "timed-out blocking worker must retain point-read capacity"
        );
        assert_eq!(
            execute_with_rpc_limits(&runtime_limits, async { 7 }).await,
            Ok(7),
            "outer request capacity must be released after timeout"
        );

        release_tx.send(()).expect("release point-read worker");
        tokio::time::timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("worker completion timeout")
            .expect("worker completion");
        assert!(
            read_context.try_acquire_point_read().is_some(),
            "point-read capacity must return when detached worker completes"
        );
    }

    #[tokio::test]
    async fn timed_out_collection_retains_worker_capacity_until_completion() {
        let config = NodeConfig {
            network: Network::Regtest,
            rpc_limits: RpcLimits {
                maximum_concurrent_requests: 1,
                execution_timeout: Duration::from_millis(10),
                ..RpcLimits::default()
            },
            ..NodeConfig::default()
        };
        let node = NodeService::new(config.clone());
        let read_context = node.rpc_read_context();
        let permit = read_context
            .try_acquire_collection()
            .expect("first collection permit");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let permit = permit;
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            drop(permit);
            let _ = done_tx.send(());
        });
        started_rx.await.expect("collection worker started");

        let runtime_limits = RpcRuntimeLimits::new(config.rpc_limits);
        let result = execute_with_rpc_limits(&runtime_limits, async move {
            let _ = worker.await;
        })
        .await;
        assert_eq!(result, Err(RpcAdmissionError::TimedOut));
        assert!(
            read_context.try_acquire_collection().is_none(),
            "timed-out blocking worker must retain collection capacity"
        );
        assert_eq!(
            execute_with_rpc_limits(&runtime_limits, async { 7 }).await,
            Ok(7),
            "outer request capacity must be released after timeout"
        );

        release_tx.send(()).expect("release collection worker");
        tokio::time::timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("worker completion timeout")
            .expect("worker completion");
        assert!(
            read_context.try_acquire_collection().is_some(),
            "collection capacity must return when detached worker completes"
        );
    }

    #[tokio::test]
    async fn rpc_authorization_rejects_missing_and_wrong_values() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let service = node.rpc_service().expect("rpc service");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let expected = RpcAuthorizationHeader::new("Bearer exact-secret").expect("authorization");
        let server = tokio::spawn(async move {
            serve_rpc_listener_with_authorization(listener, service, Some(expected), async move {
                let _ = shutdown_rx.await;
            })
            .await
        });

        for (authorization, expected_status) in [
            (None, "HTTP/1.1 401 Unauthorized"),
            (Some("Bearer wrong"), "HTTP/1.1 401 Unauthorized"),
            (Some("Bearer exact-secret"), "HTTP/1.1 200 OK"),
        ] {
            let authorization = authorization
                .map(|value| format!("Authorization: {value}\r\n"))
                .unwrap_or_default();
            let request = format!(
                "GET /api/v1/authority HTTP/1.1\r\nHost: {addr}\r\n{authorization}Connection: close\r\n\r\n"
            );
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            stream
                .write_all(request.as_bytes())
                .await
                .expect("write request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("read response");
            assert!(response.starts_with(expected_status), "{response}");
        }

        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server join").expect("server result");
    }

    #[test]
    fn rpc_authorization_accepts_only_exact_wire_safe_values() {
        assert!(RpcAuthorizationHeader::new("Bearer exact-secret").is_ok());
        for invalid in [
            "",
            " Bearer exact-secret",
            "Bearer exact-secret ",
            "Bearer\texact-secret",
            "Bearer\nexact-secret",
            "Bearer\rexact-secret",
            "Bearer\0exact-secret",
            "Bearer café",
        ] {
            assert!(RpcAuthorizationHeader::new(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn node_apply_reorg_disconnects_then_connects_new_tip() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            transaction_index: true,
            ..NodeConfig::default()
        });
        let old_block = block_with_commitments(vec![coinbase_transaction_with_address(7, 50)]);
        let old_txid = old_block.transactions[0].txid();
        let old_outpoint = Outpoint {
            txid: old_txid,
            index: 0,
        };
        let old_record = node
            .connect_block(NodeBlockImport::fixture(old_block.clone(), 0, 1))
            .expect("connect old");
        let mut mining = node.subscribe_observed_mining_events();

        let new_block = block_with_commitments(vec![coinbase_transaction_with_address(8, 60)]);
        let new_txid = new_block.transactions[0].txid();
        let new_outpoint = Outpoint {
            txid: new_txid,
            index: 0,
        };
        let summary = node
            .apply_reorg(NodeReorg {
                disconnect: vec![NodeBlockDisconnect {
                    block_hash: old_record.hash,
                    height: 0,
                }],
                connect: vec![NodeBlockImport::fixture(new_block.clone(), 0, 2)],
            })
            .expect("reorg");

        assert_eq!(summary.disconnected.len(), 1);
        assert_eq!(summary.connected.len(), 1);
        assert!(!summary.disconnected[0].status.utxo_connected);
        assert!(summary.connected[0].status.utxo_connected);
        assert!(node
            .state()
            .state_engine
            .coin(&old_outpoint)
            .expect("old coin")
            .is_none());
        assert!(node
            .state()
            .state_engine
            .coin(&new_outpoint)
            .expect("new coin")
            .is_some());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&old_txid)
            .expect("old tx index")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&new_txid)
            .expect("new tx index")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            read_canonical_hash(&snapshot, 0).expect("height"),
            Some(summary.connected[0].hash)
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block"),
            Some(summary.connected[0].hash.as_bytes().to_vec())
        );
        assert_eq!(
            load_deployment_state(&snapshot, old_record.hash)
                .expect("old deployment cache")
                .expect("retained old deployment state")
                .state
                .encode_states(),
            [0; 4]
        );
        assert_eq!(
            load_deployment_state(&snapshot, summary.connected[0].hash)
                .expect("new deployment cache")
                .expect("new deployment state")
                .state
                .encode_states(),
            [0; 4]
        );
        assert!(summary.connected[0].status.deployment_state_valid);
        assert!(matches!(
            mining.events.try_recv().expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            mining.events.try_recv().expect("validated"),
            hns_mining::ChainEvent::BlockSyntaxValidated { .. }
        ));
        assert!(matches!(
            mining.events.try_recv().expect("reorg start"),
            hns_mining::ChainEvent::ReorgStarted { .. }
        ));
        assert!(matches!(
            mining.events.try_recv().expect("final tip"),
            hns_mining::ChainEvent::TipStaged { .. }
        ));
        assert!(matches!(
            mining.events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("observed state")
                .expect("final mining snapshot")
                .generation,
            2
        );
    }

    #[test]
    fn equal_work_side_chain_is_stored_without_replacing_first_seen_tip() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(40, 50)]);
        let genesis_record = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("genesis");

        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(41, 50)]);
        active.header.prev_block = genesis_record.hash;
        let active_record = node
            .connect_block(NodeBlockImport::fixture(active, 1, 2))
            .expect("active child");

        let mut alternate = block_with_commitments(vec![coinbase_transaction_with_address(42, 50)]);
        alternate.header.prev_block = genesis_record.hash;
        let alternate_hash = alternate.hash();
        let acceptance = node
            .accept_block(NodeBlockImport::fixture(alternate.clone(), 1, 2))
            .expect("store alternate");

        assert_eq!(acceptance.disposition, BlockDisposition::StoredAlternate);
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("tip")
                .expect("active")
                .hash,
            active_record.hash
        );
        let alternate_record = node
            .state()
            .blocks
            .load_block_record(&alternate_hash)
            .expect("alternate index")
            .expect("alternate");
        assert!(!alternate_record.status.active_chain);
        assert_eq!(
            node.state()
                .blocks
                .load_block(&alternate_hash)
                .expect("alternate body"),
            Some(alternate)
        );
        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())
                .expect("best header"),
            Some(active_record.hash.as_bytes().to_vec()),
            "equal-work candidates must not replace the first-seen best header"
        );
    }

    #[test]
    fn invalid_branch_is_durable_falls_back_and_taints_descendants() {
        let config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let mut node = NodeService::new(config.clone());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(80, 50)]);
        let genesis = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("active genesis");

        let mut fallback = block_with_commitments(vec![coinbase_transaction_with_address(81, 50)]);
        fallback.header.prev_block = genesis.hash;
        fallback.header.bits = Network::Regtest.params().pow.bits;
        let fallback = node
            .state_mut()
            .chain
            .import_header(HeaderImport {
                header: fallback.header,
                height: 1,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .expect("fallback header");

        let mut invalid = block_with_commitments(vec![coinbase_transaction_with_address(82, 50)]);
        invalid.header.prev_block = genesis.hash;
        invalid.header.bits = Network::Regtest.params().pow.bits;
        invalid
            .transactions
            .push(coinbase_transaction_with_address(85, 1));
        invalid.header.merkle_root = block_merkle_root(&invalid);
        invalid.header.witness_root = block_witness_root(&invalid);
        assert!(
            HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest))
                .validate_block_body(&invalid)
                .is_err()
        );
        let invalid_hash = invalid.hash();
        node.state_mut()
            .chain
            .import_header(HeaderImport {
                header: invalid.header.clone(),
                height: 1,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .expect("invalid branch header");

        let mut descendant =
            block_with_commitments(vec![coinbase_transaction_with_address(83, 50)]);
        descendant.header.prev_block = invalid_hash;
        descendant.header.bits = Network::Regtest.params().pow.bits;
        let descendant = node
            .state_mut()
            .chain
            .import_header(HeaderImport {
                header: descendant.header,
                height: 2,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .expect("invalid branch descendant");
        assert_eq!(
            node.state()
                .chain
                .best_tip()
                .expect("best")
                .expect("tip")
                .hash,
            descendant.hash
        );

        let mutation = node
            .state_mut()
            .store_failed_block(
                NodeBlockImport::fixture(invalid.clone(), 1, 2),
                FailedBlockStage::BodySyntax,
            )
            .expect("persist invalid branch");
        assert_eq!(mutation.record.hash, invalid_hash);
        assert_eq!(
            mutation.affected.into_iter().collect::<HashSet<_>>(),
            HashSet::from([invalid_hash, descendant.hash])
        );
        assert_eq!(
            node.state()
                .chain
                .best_tip()
                .expect("best")
                .expect("tip")
                .hash,
            fallback.hash
        );
        let invalid_record = node
            .state()
            .blocks
            .load_block_record(&invalid_hash)
            .expect("invalid block index")
            .expect("invalid block");
        assert!(invalid_record.status.failed);
        assert!(invalid_record.status.body_present);
        assert!(!invalid_record.status.body_syntax_valid);
        assert_eq!(
            node.state()
                .blocks
                .load_block(&invalid_hash)
                .expect("invalid body"),
            Some(invalid)
        );
        assert!(
            node.state()
                .chain
                .load_record(&descendant.hash)
                .expect("descendant header")
                .expect("descendant")
                .status
                .failed
        );
        assert!(
            node.state()
                .chain
                .header(&descendant.hash)
                .expect("live descendant header")
                .expect("live descendant")
                .status
                .failed
        );
        assert!(
            node.state()
                .blocks
                .block(&invalid_hash)
                .expect("live invalid block")
                .expect("live invalid record")
                .status
                .failed
        );

        let store = node.state().store.clone();
        drop(node);
        let restarted =
            NodeState::from_store_for_network(store, Network::Regtest).expect("restart");
        assert_eq!(
            restarted.chain.best_tip().expect("best").expect("tip").hash,
            fallback.hash
        );
        assert!(
            restarted
                .blocks
                .load_block_record(&invalid_hash)
                .expect("invalid block index")
                .expect("invalid block")
                .status
                .failed
        );
        let mut restarted = NodeService::with_state(config, restarted);
        let rpc = restarted.rpc_service().expect("rpc");
        assert_eq!(rpc.snapshot().node_status.failed_block_count, 1);
        assert_eq!(rpc.snapshot().node_status.alternate_block_count, 0);
        let diagnostics = restarted
            .rpc_diagnostic_snapshot()
            .expect("diagnostic snapshot");
        assert_eq!(diagnostics.node_status.failed_block_count, 1);
        assert_eq!(diagnostics.node_status.alternate_block_count, 0);
        assert!(diagnostics.headers.is_empty());
        assert!(diagnostics.blocks.is_empty());
        assert!(diagnostics.transactions.is_empty());
        assert!(diagnostics.coins.is_empty());
        assert!(diagnostics.names.is_empty());

        let mut later = block_with_commitments(vec![coinbase_transaction_with_address(84, 50)]);
        later.header.prev_block = descendant.hash;
        later.header.bits = Network::Regtest.params().pow.bits;
        let later = restarted
            .state_mut()
            .chain
            .import_header(HeaderImport {
                header: later.header,
                height: 3,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .expect("later invalid descendant");
        assert!(later.status.failed);
        assert_eq!(
            restarted
                .state()
                .chain
                .best_tip()
                .expect("best")
                .expect("tip")
                .hash,
            fallback.hash
        );
    }

    #[test]
    fn native_active_state_connector_resumes_in_bounded_batches_without_authority() {
        let store = StoreHandle::memory();
        let config = active_state_native_config();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initial state");
        let mut node = NodeService::try_with_state(config.clone(), state).expect("native node");

        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(90, 50)]);
        let genesis = store_fixture_alternate(&mut node, genesis, 0, 1);
        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(91, 50)]);
        child.header.prev_block = genesis.hash;
        let child = store_fixture_alternate(&mut node, child, 1, 2);
        assert!(node.state().best_block_tip().expect("active tip").is_none());
        drop(node);

        let state = NodeState::from_store_for_network(store, Network::Regtest).expect("restart");
        let mut restarted = NodeService::try_with_state(config, state).expect("restarted native");
        assert!(restarted
            .state()
            .best_block_tip()
            .expect("active tip")
            .is_none());

        let first = restarted
            .native_sync_connect_stored_state(1)
            .expect("first connector batch");
        assert_eq!(first.connected, 1);
        assert_eq!(first.disconnected, 0);
        assert_eq!(
            restarted
                .state()
                .best_block_tip()
                .expect("active tip")
                .expect("genesis")
                .hash,
            genesis.hash
        );
        let second = restarted
            .native_sync_connect_stored_state(1)
            .expect("second connector batch");
        assert_eq!(second.connected, 1);
        assert_eq!(
            restarted
                .state()
                .best_block_tip()
                .expect("active tip")
                .expect("child")
                .hash,
            child.hash
        );
        assert!(restarted.subscribe_mining_events().is_err());
        let rpc = restarted.rpc_service().expect("rpc");
        let status = &rpc.snapshot().node_status;
        assert!(status.active_state_sync_enabled);
        assert_eq!(status.active_state_connect_batch, 288);
        assert_eq!(status.active_state_resulting_root_height, Some(1));
        assert_eq!(
            status
                .active_state_resulting_root
                .as_ref()
                .expect("resulting root")
                .len(),
            64
        );
        assert!(!status.authority.can_authorize_mining_templates);
    }

    #[test]
    fn native_active_state_direct_progress_yields_between_bounded_atomic_slices() {
        let mut node = NodeService::new(active_state_native_config());
        let mut previous = BlockHash::ZERO;
        let mut records = Vec::new();
        for height in 0..320 {
            let mut block = block_with_commitments(vec![coinbase_transaction_with_tag(height, 50)]);
            block.header.prev_block = previous;
            let record = store_fixture_alternate(
                &mut node,
                block,
                height,
                u64::from(height).saturating_add(1),
            );
            previous = record.hash;
            records.push(record);
        }

        let first = node
            .native_sync_connect_stored_state(320)
            .expect("first direct connector slice");
        assert_eq!(
            first.connected,
            native_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE
        );
        assert_eq!(first.disconnected, 0);
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("active tip")
                .expect("first slice tip")
                .hash,
            records[native_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE - 1].hash
        );

        let second = node
            .native_sync_connect_stored_state(320)
            .expect("second direct connector slice");
        assert_eq!(second.connected, 32);
        assert_eq!(second.disconnected, 0);
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("active tip")
                .expect("second slice tip")
                .hash,
            records.last().expect("stored tip").hash
        );
    }

    #[test]
    fn stored_activation_revalidates_full_body_despite_coordinated_status_forgery() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/blocks/genesis-v1.json"))
                .expect("HSD genesis fixture");
        let genesis_case = fixture["networks"]
            .as_array()
            .expect("genesis networks")
            .iter()
            .find(|case| case["network"] == "regtest")
            .expect("regtest genesis");
        let genesis_block = Block::decode(&decode_hex(
            genesis_case["raw"].as_str().expect("raw genesis"),
        ))
        .expect("canonical regtest genesis");
        let mut genesis = strict_header_record(genesis_block.header.clone(), 0, None);

        let duplicate = coinbase_transaction();
        let mut invalid = block_with_commitments(vec![duplicate.clone(), duplicate]);
        invalid.header.prev_block = genesis.hash;
        invalid.header.time = genesis.header.time + 1;
        invalid.header.bits = Network::Regtest.params().pow.bits;
        invalid.header = mine_header(invalid.header);
        HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest))
            .validate_block_commitments(&invalid)
            .expect("invalid body remains commitment-consistent");
        let mut candidate = strict_header_record(invalid.header.clone(), 1, Some(&genesis));

        let forged = BlockStatus {
            header_context_valid: true,
            checkpoint_valid: true,
            body_present: true,
            body_syntax_valid: true,
            absolute_finality_valid: true,
            ..BlockStatus::default()
        };
        genesis.status = forged.clone();
        candidate.status = forged.clone();
        let store = strict_header_store(&[genesis.clone(), candidate.clone()], candidate.hash);
        let genesis_index = BlockIndexRecord {
            hash: genesis.hash,
            height: genesis.height,
            prev_hash: genesis.header.prev_block,
            chainwork: genesis.chainwork,
            status: forged.clone(),
            tx_count: genesis_block.transactions.len() as u32,
            validated_at: None,
        };
        let candidate_index = BlockIndexRecord {
            hash: candidate.hash,
            height: candidate.height,
            prev_hash: candidate.header.prev_block,
            chainwork: candidate.chainwork,
            status: forged,
            tx_count: invalid.transactions.len() as u32,
            validated_at: None,
        };
        let mut batch = store.batch();
        write_block_index_to_batch(&mut batch, &genesis_index).expect("stage genesis index");
        write_block_index_to_batch(&mut batch, &candidate_index).expect("stage candidate index");
        write_raw_block_to_batch(
            &mut batch,
            &RawBlockRecord::from_block(&genesis_block, RawBlockSource::Peer),
        )
        .expect("stage genesis body");
        write_raw_block_to_batch(
            &mut batch,
            &RawBlockRecord::from_block(&invalid, RawBlockSource::Peer),
        )
        .expect("stage invalid body");
        store.commit(batch).expect("commit forged stored branch");

        let state = NodeState::from_store_for_network(store, Network::Regtest)
            .expect("fixture-mode restart for corruption activation");
        let mut node =
            NodeService::try_with_state(active_state_native_config(), state).expect("native node");
        let error = node
            .native_sync_connect_stored_state(2)
            .expect_err("forged body-valid status must not authorize activation");
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("block body validation")
                || error_chain.contains("coinbase height validation")
                || error_chain.contains("multiple coinbase transactions"),
            "unexpected error: {error_chain}"
        );
        assert_eq!(
            node.state.best_block_tip().expect("active tip"),
            None,
            "failed activation must preserve the empty active chain"
        );
    }

    #[tokio::test]
    async fn native_active_state_runtime_updates_scheduler_and_diagnostics() {
        let config = active_state_native_config();
        let mut node = NodeService::new(config.clone());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(102, 50)]);
        let genesis = store_fixture_alternate(&mut node, genesis, 0, 1);
        let runtime = NodeRuntime::spawn(node, DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY)
            .expect("native runtime");
        let node = runtime.read();
        let writer = runtime.writer();
        let (peers, _events) =
            hns_p2p::LivePeerManager::new(hns_p2p::LivePeerConfig::for_network(Network::Regtest))
                .expect("peers");
        let mut scheduler = hns_sync::SyncScheduler::new(
            hns_sync::SyncLimits::default(),
            std::time::Instant::now(),
        )
        .expect("scheduler");
        let mut orphans = hns_sync::BoundedOrphanPool::new(hns_sync::OrphanLimits {
            maximum_blocks: 8,
            maximum_bytes: 1_024 * 1_024,
        })
        .expect("orphans");
        let diagnostics = Arc::new(tokio::sync::RwLock::new(NativeSyncDiagnostics {
            api_version: HSRD_DIAGNOSTIC_API_VERSION,
            enabled: true,
            observation_only: false,
            active_state: true,
            ..NativeSyncDiagnostics::default()
        }));

        native_sync::connect_stored_active_state(
            &node,
            &writer,
            &peers,
            &mut scheduler,
            &mut orphans,
            &diagnostics,
            config.native_sync.active_state_connect_batch,
        )
        .await
        .expect("runtime connector");

        assert_eq!(
            node.canonical_epoch().tip.expect("canonical tip").hash,
            genesis.hash
        );
        assert_eq!(
            scheduler
                .snapshot()
                .active_tip
                .expect("scheduler active tip")
                .hash,
            genesis.hash
        );
        {
            let diagnostics = diagnostics.read().await;
            assert_eq!(diagnostics.connected_blocks, 1);
            assert_eq!(diagnostics.active_state_slices, 1);
            assert_eq!(diagnostics.active_state_last_slice_blocks, 1);
            assert_eq!(diagnostics.active_state_last_transactions, 1);
            assert_eq!(diagnostics.active_state_last_non_coinbase_inputs, 0);
            assert_eq!(diagnostics.active_state_last_outputs, 1);
            assert_eq!(diagnostics.active_state_last_name_actions, 0);
            assert!(
                diagnostics.active_state_max_slice_millis
                    >= diagnostics.active_state_last_slice_millis
            );
            assert!(!diagnostics.observation_only);
            assert!(diagnostics.active_state);
            assert_eq!(
                diagnostics
                    .sync
                    .active_tip
                    .as_ref()
                    .expect("diagnostic tip")
                    .hash,
                genesis.hash
            );
        }
        runtime.shutdown().await.expect("shutdown native runtime");
    }

    #[test]
    fn native_active_state_connector_reorganizes_a_stored_best_branch() {
        let mut node = NodeService::new(active_state_native_config());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(92, 50)]);
        let genesis = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("active genesis");
        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(93, 50)]);
        active.header.prev_block = genesis.hash;
        let active = node
            .connect_block(NodeBlockImport::fixture(active, 1, 3))
            .expect("active child");

        let mut side_one = block_with_commitments(vec![coinbase_transaction_with_address(94, 50)]);
        side_one.header.prev_block = genesis.hash;
        let side_one = store_fixture_alternate(&mut node, side_one, 1, 2);
        let mut side_two = block_with_commitments(vec![coinbase_transaction_with_address(95, 50)]);
        side_two.header.prev_block = side_one.hash;
        let side_two = store_fixture_alternate(&mut node, side_two, 2, 4);

        let bounded_error = node
            .native_sync_connect_stored_state(1)
            .expect_err("insufficient atomic reorg batch must fail closed");
        assert!(bounded_error
            .to_string()
            .contains("needs more than 1 replacement blocks"));
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("unchanged active tip")
                .expect("active child")
                .hash,
            active.hash
        );
        assert!(
            !node
                .state()
                .load_block_record(&side_one.hash)
                .expect("side one")
                .expect("side one record")
                .status
                .failed
        );

        let outcome = node
            .native_sync_connect_stored_state(64)
            .expect("stored branch activation");
        assert_eq!(outcome.connected, 2);
        assert_eq!(outcome.disconnected, 1);
        assert!(outcome.contextual_failure.is_none());
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("active tip")
                .expect("side tip")
                .hash,
            side_two.hash
        );
        assert!(
            !node
                .state()
                .load_block_record(&active.hash)
                .expect("old active")
                .expect("old record")
                .status
                .active_chain
        );
    }

    #[test]
    fn native_active_state_reorg_keeps_the_full_configured_atomic_bound() {
        let mut node = NodeService::new(active_state_native_config());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_tag(200, 50)]);
        let genesis = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("active genesis");
        let mut active = block_with_commitments(vec![coinbase_transaction_with_tag(201, 50)]);
        active.header.prev_block = genesis.hash;
        node.connect_block(NodeBlockImport::fixture(active, 1, 3))
            .expect("active child");

        let mut previous = genesis.hash;
        let mut side = Vec::new();
        for offset in 0..=u32::try_from(native_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE)
            .expect("direct slice fits u32")
        {
            let height = offset + 1;
            let mut block =
                block_with_commitments(vec![coinbase_transaction_with_tag(202 + offset, 50)]);
            block.header.prev_block = previous;
            let chainwork = if offset == 0 {
                2
            } else {
                u64::from(offset) + 3
            };
            let record = store_fixture_alternate(&mut node, block, height, chainwork);
            previous = record.hash;
            side.push(record);
        }

        assert!(side.len() > native_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE);
        let outcome = node
            .native_sync_connect_stored_state(side.len())
            .expect("deep stored reorganization");
        assert_eq!(outcome.connected, side.len());
        assert_eq!(outcome.disconnected, 1);
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("active tip")
                .expect("side tip")
                .hash,
            side.last().expect("side tip record").hash
        );
    }

    #[test]
    fn contextual_invalid_ancestor_is_durable_and_exact() {
        let config = active_state_native_config();
        let mut node = NodeService::new(config.clone());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(96, 50)]);
        let genesis = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("active genesis");
        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(97, 50)]);
        active.header.prev_block = genesis.hash;
        let active = node
            .connect_block(NodeBlockImport::fixture(active, 1, 3))
            .expect("active child");

        let mut invalid = block_with_commitments(vec![
            coinbase_transaction_with_address(98, 50),
            transaction(),
        ]);
        invalid.header.prev_block = genesis.hash;
        let invalid = store_fixture_alternate(&mut node, invalid, 1, 2);
        let mut descendant =
            block_with_commitments(vec![coinbase_transaction_with_address(99, 50)]);
        descendant.header.prev_block = invalid.hash;
        let descendant = store_fixture_alternate(&mut node, descendant, 2, 4);

        let outcome = node
            .native_sync_connect_stored_state(64)
            .expect("contextual failure classification");
        let failure = outcome.contextual_failure.expect("failed branch");
        assert_eq!(failure.record.hash, invalid.hash);
        assert_eq!(
            failure.affected.into_iter().collect::<HashSet<_>>(),
            HashSet::from([invalid.hash, descendant.hash])
        );
        assert!(failure.record.status.failed);
        assert!(failure.record.status.body_syntax_valid);
        assert!(failure.record.status.absolute_finality_valid);
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("active tip")
                .expect("active child")
                .hash,
            active.hash
        );
        assert_eq!(
            node.state()
                .chain
                .best_tip()
                .expect("best header")
                .expect("fallback")
                .hash,
            active.hash
        );
        assert!(
            node.state()
                .load_block_record(&descendant.hash)
                .expect("descendant")
                .expect("descendant record")
                .status
                .failed
        );

        let store = node.state().store.clone();
        drop(node);
        let state = NodeState::from_store_for_network(store, Network::Regtest).expect("restart");
        let mut restarted = NodeService::try_with_state(config, state).expect("restarted native");
        assert_eq!(
            restarted
                .state()
                .best_block_tip()
                .expect("active tip")
                .expect("active child")
                .hash,
            active.hash
        );
        assert!(restarted
            .native_sync_connect_stored_state(64)
            .expect("idempotent connector")
            .contextual_failure
            .is_none());
    }

    #[test]
    fn local_state_fault_does_not_poison_a_stored_branch() {
        let mut node = NodeService::new(active_state_native_config());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(100, 50)]);
        let genesis = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("active genesis");
        let mut candidate =
            block_with_commitments(vec![coinbase_transaction_with_address(101, 50)]);
        candidate.header.prev_block = genesis.hash;
        let candidate = store_fixture_alternate(&mut node, candidate, 1, 2);

        let mut batch = node.state().store.batch();
        batch
            .delete(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())
            .expect("stage local fault");
        node.state()
            .store
            .commit(batch)
            .expect("commit local fault");

        let error = node
            .native_sync_connect_stored_state(64)
            .expect_err("missing local state root must stop the connector");
        assert!(
            format!("{error:#}").contains("durable name-tree-root metadata is missing"),
            "{error:#}"
        );
        let record = node
            .state()
            .load_block_record(&candidate.hash)
            .expect("candidate")
            .expect("candidate record");
        assert!(!record.status.failed);
        assert!(!record.status.active_chain);
        assert!(
            !node
                .state()
                .chain
                .load_record(&candidate.hash)
                .expect("candidate header")
                .expect("header")
                .status
                .failed
        );
    }

    #[test]
    fn higher_work_side_chain_is_reorganized_atomically() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            transaction_index: true,
            ..NodeConfig::default()
        });
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(43, 50)]);
        let genesis_record = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("genesis");

        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(44, 50)]);
        active.header.prev_block = genesis_record.hash;
        let active_txid = active.transactions[0].txid();
        let active_record = node
            .connect_block(NodeBlockImport::fixture(active, 1, 2))
            .expect("active child");

        let mut alternate = block_with_commitments(vec![coinbase_transaction_with_address(45, 50)]);
        alternate.header.prev_block = genesis_record.hash;
        let alternate_txid = alternate.transactions[0].txid();
        let alternate_hash = alternate.hash();
        let acceptance = node
            .accept_block(NodeBlockImport::fixture(alternate, 1, 3))
            .expect("activate alternate");

        assert_eq!(
            acceptance.disposition,
            BlockDisposition::Reorganized {
                disconnected: 1,
                connected: 1,
            }
        );
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("tip")
                .expect("active")
                .hash,
            alternate_hash
        );
        assert!(
            !node
                .state()
                .blocks
                .load_block_record(&active_record.hash)
                .expect("old index")
                .expect("old block")
                .status
                .active_chain
        );
        assert!(
            node.state()
                .blocks
                .load_block_record(&alternate_hash)
                .expect("new index")
                .expect("new block")
                .status
                .active_chain
        );
        assert!(node
            .state()
            .blocks
            .load_tx_index(&active_txid)
            .expect("old tx lookup")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&alternate_txid)
            .expect("new tx lookup")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            chain_epoch_from_snapshot(&snapshot).expect("chain epoch"),
            3,
            "two connects plus one complete reorg must advance three epochs"
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())
                .expect("best header"),
            Some(alternate_hash.as_bytes().to_vec())
        );
    }

    #[test]
    fn longer_stored_side_chain_activates_from_its_common_ancestor() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(46, 50)]);
        let genesis_record = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("genesis");

        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(47, 50)]);
        active.header.prev_block = genesis_record.hash;
        let active_record = node
            .connect_block(NodeBlockImport::fixture(active, 1, 3))
            .expect("active child");

        let mut side_one = block_with_commitments(vec![coinbase_transaction_with_address(48, 50)]);
        side_one.header.prev_block = genesis_record.hash;
        let side_one_hash = side_one.hash();
        let side_one_acceptance = node
            .accept_block(NodeBlockImport::fixture(side_one, 1, 2))
            .expect("store first side block");
        assert_eq!(
            side_one_acceptance.disposition,
            BlockDisposition::StoredAlternate
        );

        let mut side_two = block_with_commitments(vec![coinbase_transaction_with_address(49, 50)]);
        side_two.header.prev_block = side_one_hash;
        let side_two_hash = side_two.hash();
        let acceptance = node
            .accept_block(NodeBlockImport::fixture(side_two, 2, 4))
            .expect("activate longer side chain");

        assert_eq!(
            acceptance.disposition,
            BlockDisposition::Reorganized {
                disconnected: 1,
                connected: 2,
            }
        );
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("tip")
                .expect("active")
                .hash,
            side_two_hash
        );
        assert!(
            !node
                .state()
                .blocks
                .load_block_record(&active_record.hash)
                .expect("old record")
                .expect("old")
                .status
                .active_chain
        );
        assert!(
            node.state()
                .blocks
                .load_block_record(&side_one_hash)
                .expect("side one")
                .expect("side one record")
                .status
                .active_chain
        );
    }

    #[test]
    fn experimental_restart_recovers_fully_stored_best_work_branch() {
        let store = StoreHandle::memory();
        let native_config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut native = NodeService::try_with_state(native_config, state).expect("native node");

        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(50, 50)]);
        let genesis_record = native
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("genesis");
        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(51, 50)]);
        active.header.prev_block = genesis_record.hash;
        native
            .connect_block(NodeBlockImport::fixture(active, 1, 2))
            .expect("active child");

        let mut side = block_with_commitments(vec![coinbase_transaction_with_address(52, 50)]);
        side.header.prev_block = genesis_record.hash;
        let side_hash = side.hash();
        let import = NodeBlockImport::fixture(side, 1, 3);
        let validated = native
            .state()
            .validate_import(&import)
            .expect("validate side");
        native
            .state_mut()
            .store_validated_alternate(import, validated)
            .expect("persist side before simulated crash");
        drop(native);

        let state =
            NodeState::from_store_for_network(store, Network::Regtest).expect("reloaded state");
        let restarted = NodeService::try_with_state(experimental_authority_config(), state)
            .expect("experimental recovery");
        assert_eq!(
            restarted
                .state()
                .best_block_tip()
                .expect("tip")
                .expect("active")
                .hash,
            side_hash
        );
        assert_eq!(
            restarted
                .observed_mining_snapshot()
                .expect("observed")
                .expect("snapshot")
                .generation,
            3
        );
    }

    #[test]
    fn reorganization_rejects_a_lower_work_replacement_without_mutation() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let original = block_with_commitments(vec![coinbase_transaction_with_address(53, 50)]);
        let original_record = node
            .connect_block(NodeBlockImport::fixture(original, 0, 2))
            .expect("original");
        let replacement = block_with_commitments(vec![coinbase_transaction_with_address(54, 50)]);

        let error = node
            .apply_reorg(NodeReorg {
                disconnect: vec![NodeBlockDisconnect {
                    block_hash: original_record.hash,
                    height: 0,
                }],
                connect: vec![NodeBlockImport::fixture(replacement, 0, 1)],
            })
            .expect_err("lower-work replacement must fail");
        assert!(error
            .to_string()
            .contains("does not exceed active tip chainwork"));
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("tip")
                .expect("active")
                .hash,
            original_record.hash
        );
        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(chain_epoch_from_snapshot(&snapshot).expect("epoch"), 1);
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
                .expect("generation")
                .map(|bytes| decode_u64(&bytes).expect("decode")),
            Some(1)
        );
    }

    #[test]
    fn authority_modes_fail_closed_except_explicit_regtest_experiment() {
        let native = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        assert!(native.subscribe_mining_events().is_err());
        assert!(
            !native
                .rpc_service()
                .expect("rpc")
                .snapshot()
                .node_status
                .authority
                .can_authorize_mining_templates
        );

        assert!(validate_node_config(&NodeConfig {
            network: Network::Mainnet,
            authority_mode: AuthorityMode::NativeExperimental,
            acknowledge_incomplete_consensus: true,
            ..NodeConfig::default()
        })
        .is_err());
        let mut unacknowledged_active_sync = active_state_native_config();
        unacknowledged_active_sync.acknowledge_incomplete_consensus = false;
        unacknowledged_active_sync.authority_mode = AuthorityMode::Disabled;
        assert!(validate_node_config(&unacknowledged_active_sync).is_err());
        unacknowledged_active_sync.authority_mode = AuthorityMode::Native;
        assert!(validate_node_config(&unacknowledged_active_sync).is_ok());

        let mut experimental = NodeService::new(experimental_authority_config());
        assert!(experimental.subscribe_mining_events().is_err());
        let mut events = experimental.subscribe_observed_mining_events();
        experimental
            .connect_block(NodeBlockImport::fixture(
                block_with_commitments(vec![coinbase_transaction()]),
                0,
                1,
            ))
            .expect("experimental staged block");
        assert!(experimental.subscribe_mining_events().is_ok());
        assert!(experimental.mining_snapshot().is_some());
        assert!(matches!(
            events.events.try_recv().expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            events.events.try_recv().expect("syntax"),
            hns_mining::ChainEvent::BlockSyntaxValidated { .. }
        ));
        assert!(matches!(
            events.events.try_recv().expect("experimental commit"),
            hns_mining::ChainEvent::TipCommitted { .. }
        ));

        let rpc_service = experimental.rpc_service().expect("rpc");
        let authority = &rpc_service.snapshot().node_status.authority;
        assert!(authority.consensus_complete);
        assert!(!authority.experimental_bypass_active);
        assert!(authority.can_authorize_mining_templates);
        assert!(authority.can_accept_mining_candidates);
    }

    #[test]
    fn mainnet_canary_requires_explicit_hardened_config_and_complete_readiness() {
        let config = mainnet_canary_config();
        validate_node_config(&config).expect("hardened canary config");
        assert!(authority_can_mine(&config));
        assert!(authority_can_mine_with_readiness(&config, true));

        let mut pruned = config.clone();
        pruned.undo_retention.prune_history = true;
        validate_node_config(&pruned).expect("HSD-horizon pruned canary config");
        assert!(authority_can_mine_with_readiness(&pruned, true));

        let mut not_enabled = config.clone();
        not_enabled.mainnet_canary = false;
        assert!(!authority_can_mine_with_readiness(&not_enabled, true));

        for mut invalid in [
            {
                let mut value = config.clone();
                value.rpc_authorization = None;
                value
            },
            {
                let mut value = config.clone();
                value.rpc_bind = "0.0.0.0:12037".parse().expect("public RPC bind");
                value
            },
            {
                let mut value = config.clone();
                value.data_dir = Some(PathBuf::from("relative-mainnet-state"));
                value
            },
            {
                let mut value = config.clone();
                value.native_sync.connect_active_state = false;
                value
            },
            {
                let mut value = config.clone();
                value.mining_engine.transaction_relay = false;
                value
            },
            {
                let mut value = config.clone();
                value.acknowledge_incomplete_consensus = true;
                value
            },
        ] {
            assert!(validate_node_config(&invalid).is_err());
            invalid.mainnet_canary = false;
            assert!(validate_node_config(&invalid).is_ok());
        }

        let durable = DurableMiningState {
            generation: 1,
            snapshot: None,
            authoritative: true,
            synchronized: false,
        };
        let authority = authority_info(&config, &durable);
        assert!(authority
            .blockers
            .iter()
            .any(|blocker| blocker.contains("not synchronized")));
        assert!(!authority.mainnet_canary_active);
    }

    #[test]
    fn native_functional_readiness_is_complete_after_external_qualification() {
        let readiness = consensus_readiness();
        assert!(readiness.scripts);
        assert!(readiness.contextual_covenants);
        assert!(readiness.claims_and_airdrops);
        assert!(readiness.name_state);
        assert!(readiness.urkel_roots);
        assert!(readiness.historical_replay);
        assert!(readiness.invalid_corpus);
        assert!(readiness.complete());
        assert!(readiness_blockers(&readiness).is_empty());
    }

    #[test]
    fn mining_templates_require_the_durable_hsd_header_context() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            mining_engine: MiningEngineConfig {
                enabled: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        });
        node.connect_block(NodeBlockImport::fixture(
            block_with_commitments(vec![coinbase_transaction()]),
            0,
            1,
        ))
        .expect("fixture genesis");

        let mut request = MiningTemplateRequest {
            variant: 0,
            payout_address: Address::new(0, vec![0x72; 20]).expect("payout address"),
            coinbase_flags: b"hsrd-deployment-version".to_vec(),
            version: 1,
            bits: Network::Regtest.params().pow.bits,
            minimum_time: 1,
            reserved_root: [0; 32],
            mask_hash: [0x73; 32],
            policy: hns_mining::TemplatePolicy::default(),
        };
        let error = node
            .mining_engine_build_template(request.clone())
            .expect_err("caller-selected deployment version");
        assert!(
            error
                .to_string()
                .contains("disagrees with HSD deployment version 0"),
            "{error}"
        );

        request.version = 0;
        let template = node
            .mining_engine_build_template(request.clone())
            .expect("HSD deployment version template");
        assert_eq!(template.header().version, 0);
        assert_eq!(template.header().bits, Network::Regtest.params().pow.bits);
        assert_eq!(template.header().minimum_time, 1);
        assert_eq!(
            node.mining_engine_diagnostics()
                .expect("mining diagnostics")
                .cached_template_variants,
            1
        );

        request.bits ^= 1;
        let error = node
            .mining_engine_build_template(request.clone())
            .expect_err("caller-selected difficulty bits");
        assert!(
            error
                .to_string()
                .contains("disagree with HSD target 0x207fffff"),
            "{error}"
        );
        assert_eq!(
            node.mining_engine_diagnostics()
                .expect("diagnostics after rejected bits")
                .cached_template_variants,
            1,
            "a rejected rebuild must preserve the prior template set"
        );

        request.bits = Network::Regtest.params().pow.bits;
        request.minimum_time = 0;
        let error = node
            .mining_engine_build_template(request.clone())
            .expect_err("time at parent median");
        assert!(
            error
                .to_string()
                .contains("does not exceed HSD parent median time 0"),
            "{error}"
        );

        request.minimum_time = current_unix_time()
            .expect("current time")
            .saturating_add(MAX_FUTURE_BLOCK_TIME)
            .saturating_add(60);
        let error = node
            .mining_engine_build_template(request)
            .expect_err("far-future template time");
        assert!(
            error.to_string().contains("exceeds maximum consensus time"),
            "{error}"
        );
    }

    #[test]
    fn process_local_native_job_derives_header_context_and_zero_mask_commitment() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::NativeExperimental,
            acknowledge_incomplete_consensus: true,
            mining_engine: MiningEngineConfig {
                enabled: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = block_with_commitments(vec![coinbase_transaction()]);
        node.connect_block(NodeBlockImport::fixture(genesis.clone(), 0, 1))
            .expect("fixture genesis");

        let job = node
            .mining_engine_build_native_job(NativeMiningJobRequest {
                variant: 0,
                payout_address: Address::new(0, vec![0x74; 20]).expect("payout address"),
                coinbase_flags: b"meshmine-native-job".to_vec(),
                reserved_root: [0; 32],
                mask: [0; 32],
                policy: hns_mining::TemplatePolicy::default(),
            })
            .expect("native job");
        assert_eq!(job.snapshot.tip.hash, genesis.hash());
        assert_eq!(job.prepared.header().parent_hash, job.snapshot.tip.hash);
        assert_eq!(
            job.prepared.header().mask_hash,
            hns_primitives::blake2b_256_many([
                job.snapshot.tip.hash.as_bytes().as_slice(),
                [0u8; 32].as_slice(),
            ])
        );
        job.prepared
            .validate_for_snapshot(&job.snapshot)
            .expect("job matches authoritative snapshot");
    }

    #[test]
    fn failed_multi_step_reorg_leaves_every_durable_value_unchanged() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let original = block_with_commitments(vec![coinbase_transaction_with_address(31, 50)]);
        let original_outpoint = Outpoint {
            txid: original.transactions[0].txid(),
            index: 0,
        };
        let original_record = node
            .connect_block(NodeBlockImport::fixture(original.clone(), 0, 1))
            .expect("original block");

        let replacement = block_with_commitments(vec![coinbase_transaction_with_address(32, 50)]);
        let replacement_hash = replacement.hash();
        let mut invalid_child = block_with_commitments(vec![
            coinbase_transaction_with_address(33, 50),
            transaction(),
        ]);
        invalid_child.header.prev_block = replacement_hash;

        let error = node
            .apply_reorg(NodeReorg {
                disconnect: vec![NodeBlockDisconnect {
                    block_hash: original_record.hash,
                    height: 0,
                }],
                connect: vec![
                    NodeBlockImport::fixture(replacement, 0, 2),
                    NodeBlockImport::fixture(invalid_child, 1, 3),
                ],
            })
            .expect_err("reorg must fail on missing input");
        assert!(error.to_string().contains("missing coin"));

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block"),
            Some(original_record.hash.as_bytes().to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
                .expect("generation")
                .map(|bytes| decode_u64(&bytes).expect("decode")),
            Some(1)
        );
        assert_eq!(
            read_canonical_hash(&snapshot, 0).expect("canonical"),
            Some(original_record.hash)
        );
        assert!(node
            .state()
            .state_engine
            .coin(&original_outpoint)
            .expect("original coin")
            .is_some());
        assert!(node
            .state()
            .blocks
            .load_block(&replacement_hash)
            .expect("replacement lookup")
            .is_none());
    }

    #[test]
    fn staged_effect_rejection_preserves_database_pages_indexes_mining_and_mempool() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        // Page storage deliberately enforces the production 10 GB reserve;
        // `/tmp` is commonly a much smaller tmpfs. Keep this fixture on the
        // build-target filesystem that already hosts the test artifacts.
        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-reorg-staged-effect-rejection-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

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
                transaction_index: true,
                ..NodeConfig::default()
            },
            state,
        )
        .expect("page-backed indexed node");
        let old_block = block_with_commitments(vec![coinbase_transaction_with_address(0xb1, 50)]);
        let old_record = node
            .connect_block(NodeBlockImport::fixture(old_block.clone(), 0, 1))
            .expect("connect old tip");
        let disconnect = NodeBlockDisconnect {
            block_hash: old_record.hash,
            height: 0,
        };

        // Measure the exact disconnect prefix with the same boundary wrapper.
        // The integrated attempt receives exactly this allowance, proving all
        // disconnect undo/UTXO/tx-index writes fit and the first connect-side
        // generated write is rejected before it can enter either retained
        // staging copy.
        let raw = store.snapshot().expect("disconnect charge snapshot");
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&raw);
        let staged_batch = overlay.batch_with_deferred_name_tree_nodes(store.batch());
        let mut charged = ReorgMeteredBatch::new(
            staged_batch,
            ReorgStagedEffectMeter::new(u64::MAX),
            REORG_STAGING_OPERATION_COPIES,
        );
        node.state
            .stage_disconnect(&staged, &mut charged, disconnect)
            .expect("measure disconnect staging prefix");
        let disconnect_limit = charged.meter.consumed;
        assert!(disconnect_limit > 0);
        drop(charged);
        drop(staged);
        drop(raw);
        drop(overlay);

        let durable_before = complete_store_image(&store);
        let block_tip_before = node.state.best_block_tip().expect("block tip before");
        let header_tip_before = node.state.chain.best_tip().expect("header tip before");
        let mining_before = node
            .observed_mining_snapshot()
            .expect("mining state before")
            .map(|snapshot| (snapshot.generation, snapshot.tip.hash));
        let mining_generation_before = node.mining_events.committed_generation();
        let mempool_before = node.state.mempool.info();
        let (page_path, page_state_before, page_generation_before, page_bytes_before) = {
            let pages = node.state.name_pages.as_ref().expect("page storage");
            (
                pages.file_path.clone(),
                pages.state.clone(),
                (pages.committed_generation_bytes, pages.generation_bytes),
                std::fs::read(&pages.file_path).expect("page bytes before"),
            )
        };

        let replacement = block_with_commitments(vec![coinbase_transaction_with_address(0xb2, 60)]);
        let replacement_hash = replacement.hash();
        let error = node
            .apply_reorg_with_limits(
                NodeReorg {
                    disconnect: vec![disconnect],
                    connect: vec![NodeBlockImport::fixture(replacement, 0, 2)],
                },
                NodeReorgLimits {
                    maximum_staged_effect_bytes: disconnect_limit,
                    ..NodeReorgLimits::PRODUCTION
                },
            )
            .expect_err("first connect write exceeds exact disconnect allowance");
        assert!(
            format!("{error:#}").contains(ReorgStagedEffectMeter::CONTEXT),
            "{error:#}"
        );

        assert_eq!(complete_store_image(&store), durable_before);
        assert_eq!(
            node.state.best_block_tip().expect("block tip after"),
            block_tip_before
        );
        assert_eq!(
            node.state.chain.best_tip().expect("header tip after"),
            header_tip_before
        );
        assert!(
            node.state
                .blocks
                .load_block_record(&old_record.hash)
                .expect("old index after")
                .expect("old index")
                .status
                .active_chain
        );
        assert!(node
            .state
            .blocks
            .load_block_record(&replacement_hash)
            .expect("replacement index after")
            .is_none());
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("mining state after")
                .map(|snapshot| (snapshot.generation, snapshot.tip.hash)),
            mining_before
        );
        assert_eq!(
            node.mining_events.committed_generation(),
            mining_generation_before
        );
        assert_eq!(node.state.mempool.info(), mempool_before);
        let pages = node.state.name_pages.as_ref().expect("page storage after");
        assert_eq!(pages.file_path, page_path);
        assert_eq!(pages.state, page_state_before);
        assert_eq!(
            (pages.committed_generation_bytes, pages.generation_bytes),
            page_generation_before
        );
        assert_eq!(
            std::fs::read(&pages.file_path).expect("page bytes after"),
            page_bytes_before
        );

        drop(node);
        std::fs::remove_dir_all(directory).expect("remove staged-effect fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn archive_budget_rejection_after_name_page_append_rolls_back_entire_reorg() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        // Name-page publication preserves a 10 GB filesystem reserve, so keep
        // the real RocksDB/archive fixture beside the configured build target
        // instead of assuming `/tmp` has production-scale free space.
        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-reorg-archive-page-budget-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create archived reorg fixture");

        let mut node = NodeService::try_new(NodeConfig {
            network: Network::Regtest,
            data_dir: Some(directory.clone()),
            transaction_index: true,
            storage_durability: DurabilityPolicy::Sync,
            native_sync: NativeSyncConfig {
                enabled: true,
                listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
                ..NativeSyncConfig::default()
            },
            mining_engine: MiningEngineConfig {
                enabled: true,
                transaction_relay: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        })
        .expect("open archived RocksDB node");
        let store = node.state.store.clone();
        node.state.state_engine = StoredStateEngine::with_services(
            store.clone(),
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("fixture state services");

        let genesis = block_with_commitments(vec![coinbase_transaction_with_tag(0, 50)]);
        let genesis = node
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("connect archived genesis");
        let names = (0u32..10_000)
            .map(|index| format!("archive-reorg-page-{index}"))
            .filter(|name| {
                let hash = NameHash::new(sha3_256(name.as_bytes()));
                hns_consensus::rollout_height(&hash, Network::Regtest.params().names) == 0
                    && !hns_consensus::is_reserved(&hash, 1, Network::Regtest.params().names)
            })
            .take(2)
            .collect::<Vec<_>>();
        assert_eq!(
            names.len(),
            2,
            "find two immediately rolled-out unreserved names"
        );
        let name_funding = Outpoint {
            txid: Txid::new([0xd4; 32]),
            index: 0,
        };
        install_script_coin(&node, name_funding.clone(), 10_000, 0);
        let mut opening = block_with_commitments(vec![
            coinbase_transaction_with_tag(1, 50),
            open_transaction(names[0].as_bytes(), name_funding),
        ]);
        opening.header.prev_block = genesis.hash;
        opening.header.nonce = 101;
        let opening = node
            .connect_block(NodeBlockImport::fixture(opening, 1, 2))
            .expect("connect pending OPEN");

        let mut previous = opening.hash;
        let mut height_three = None;
        let mut old_tip = None;
        for height in 2..=4 {
            let snapshot = store.snapshot().expect("pre-boundary root snapshot");
            let root = load_stored_name_tree_commit_root(&snapshot).expect("pre-boundary root");
            drop(snapshot);
            let mut block = block_with_commitments(vec![coinbase_transaction_with_tag(height, 50)]);
            block.header.prev_block = previous;
            block.header.tree_root = *root.as_bytes();
            block.header.nonce = height.saturating_add(100);
            let record = node
                .connect_block(NodeBlockImport::fixture(
                    block,
                    height,
                    u64::from(height) + 1,
                ))
                .unwrap_or_else(|error| panic!("connect active height {height}: {error}"));
            previous = record.hash;
            if height == 3 {
                height_three = Some(record.clone());
            }
            if height == 4 {
                old_tip = Some(record);
            }
        }
        let height_three = height_three.expect("height-three ancestor");
        let old_tip = old_tip.expect("old height-four tip");

        // The second replacement block spends an output created by the first.
        // This forces the production StagingOverlay read-your-writes path while
        // the 2,048-output parent generates a nontrivial real undo and tx index.
        let replacement_funding = Outpoint {
            txid: Txid::new([0xe4; 32]),
            index: 0,
        };
        install_script_coin(&node, replacement_funding.clone(), 1_000_000, 0);
        let mempool_funding = Outpoint {
            txid: Txid::new([0xf4; 32]),
            index: 0,
        };
        install_script_coin(&node, mempool_funding.clone(), 10_000, 0);
        let mempool_transaction = script_spend(mempool_funding, 9_000);
        let mempool_txid = mempool_transaction.txid();
        assert!(matches!(
            node.mining_engine_accept_peer_transaction(mempool_transaction)
                .expect("seed unrelated mempool transaction"),
            hns_mempool::Admission::Accepted(txid) if txid == mempool_txid
        ));
        let replacement_name_funding = Outpoint {
            txid: Txid::new([0xa4; 32]),
            index: 0,
        };
        install_script_coin(&node, replacement_name_funding.clone(), 10_000, 0);
        let replacement_name_transaction =
            open_transaction(names[1].as_bytes(), replacement_name_funding);
        let mut parent = script_spend(replacement_funding, 900_000);
        parent.outputs = (0..2_048)
            .map(|index| Output {
                value: 100,
                address: Address::new(0, vec![(index % 251) as u8; 20])
                    .expect("replacement output address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            })
            .collect();
        let parent_txid = parent.txid();
        let current_root = {
            let snapshot = store.snapshot().expect("replacement root snapshot");
            let root = load_stored_name_tree_commit_root(&snapshot).expect("replacement root");
            drop(snapshot);
            root
        };
        let mut replacement = block_with_commitments(vec![
            coinbase_transaction_with_tag(0x400, 50),
            parent,
            replacement_name_transaction,
        ]);
        replacement.header.prev_block = height_three.hash;
        replacement.header.tree_root = *current_root.as_bytes();
        replacement.header.nonce = 0x404;
        let replacement_hash = replacement.hash();

        let child_transaction = script_spend(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            90,
        );
        let child_txid = child_transaction.txid();
        let mut child = block_with_commitments(vec![
            coinbase_transaction_with_tag(0x500, 50),
            child_transaction,
        ]);
        child.header.prev_block = replacement_hash;
        child.header.tree_root = *current_root.as_bytes();
        child.header.nonce = 0x505;
        let child_hash = child.hash();

        let durable_before = complete_store_image(&store);
        let block_tip_before = node.state.best_block_tip().expect("block tip before");
        let header_tip_before = node.state.chain.best_tip().expect("header tip before");
        let mining_before = node
            .observed_mining_snapshot()
            .expect("mining state before")
            .map(|snapshot| (snapshot.generation, snapshot.tip.hash));
        let mining_generation_before = node.mining_events.committed_generation();
        let mempool_before = node.state.mempool.info();
        let (page_path, page_state_before, page_generation_before, page_bytes_before) = {
            let pages = node.state.name_pages.as_ref().expect("page storage");
            (
                pages.file_path.clone(),
                pages.state.clone(),
                (pages.committed_generation_bytes, pages.generation_bytes),
                std::fs::read(&pages.file_path).expect("page bytes before"),
            )
        };
        let payload_directory = directory.join("payload-segments");
        let payload_bytes_before = flat_directory_file_image(&payload_directory);

        let fault = ReorgArchivePreflightRejectGuard::enable();
        let error = node
            .apply_reorg(NodeReorg {
                disconnect: vec![NodeBlockDisconnect {
                    block_hash: old_tip.hash,
                    height: old_tip.height,
                }],
                connect: vec![
                    NodeBlockImport::fixture(replacement, 4, 6),
                    NodeBlockImport::fixture(child, 5, 7),
                ],
            })
            .expect_err("archive budget must reject after page append");
        assert!(
            format!("{error:#}").contains(ReorgStagedEffectMeter::CONTEXT),
            "{error:#}"
        );
        assert!(
            fault.appended_name_page_bytes() >= hns_store::NAME_PAGE_BYTES as u64,
            "the fault must be armed only after a real fixed-size page append"
        );
        assert!(
            fault.maximum_generated_undo_bytes() >= 64 * 1024,
            "the replacement must generate and stage a substantial encoded undo"
        );
        assert!(
            fault.generated_name_state_writes() > 0,
            "a replacement OPEN must generate a real NameState batch write"
        );
        assert!(
            !node.state.storage_reopen_required(),
            "read-only archive budget rejection is unambiguous"
        );

        assert_eq!(complete_store_image(&store), durable_before);
        assert_eq!(
            flat_directory_file_image(&payload_directory),
            payload_bytes_before,
            "archive preflight rejection must happen before segment append"
        );
        assert_eq!(
            node.state.best_block_tip().expect("block tip after"),
            block_tip_before
        );
        assert_eq!(
            node.state.chain.best_tip().expect("header tip after"),
            header_tip_before
        );
        assert!(
            node.state
                .blocks
                .load_block_record(&old_tip.hash)
                .expect("old index after")
                .expect("old index")
                .status
                .active_chain
        );
        for hash in [replacement_hash, child_hash] {
            assert!(node
                .state
                .blocks
                .load_block_record(&hash)
                .expect("replacement index after")
                .is_none());
        }
        assert!(node
            .state
            .blocks
            .load_tx_index(&parent_txid)
            .expect("parent tx index after")
            .is_none());
        assert!(node
            .state
            .blocks
            .load_tx_index(&child_txid)
            .expect("child tx index after")
            .is_none());
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("mining state after")
                .map(|snapshot| (snapshot.generation, snapshot.tip.hash)),
            mining_before
        );
        assert_eq!(
            node.mining_events.committed_generation(),
            mining_generation_before
        );
        assert_eq!(node.state.mempool.info(), mempool_before);
        assert_eq!(
            node.mining_engine_mempool_transaction(&mempool_txid)
                .as_ref()
                .map(Transaction::txid),
            Some(mempool_txid),
            "unrelated live mempool content must survive the rejected reorg"
        );
        let pages = node.state.name_pages.as_ref().expect("page storage after");
        assert_eq!(pages.file_path, page_path);
        assert_eq!(pages.state, page_state_before);
        assert_eq!(
            (pages.committed_generation_bytes, pages.generation_bytes),
            page_generation_before
        );
        assert_eq!(
            std::fs::read(&pages.file_path).expect("page bytes after"),
            page_bytes_before,
            "late rejection must truncate the uncommitted page tail"
        );

        drop(fault);
        drop(node);
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove archived reorg fixture");
    }

    #[tokio::test]
    async fn node_serves_read_only_diagnostics() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let service = node.rpc_service().expect("rpc service");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_rpc_listener(listener, service, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let request =
            format!("GET /api/v1/status HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
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
        let (_, response_body) = response.split_once("\r\n\r\n").expect("body split");
        let json: Value = serde_json::from_str(response_body).expect("json response");
        assert_eq!(json["api_version"], HSRD_DIAGNOSTIC_API_VERSION);
        assert_eq!(json["release_stage"], "pre-authority");
        assert_eq!(json["authority"]["mode"], "native");
        assert_eq!(json["parity"]["oracle_revision"], HSD_ORACLE_REVISION);
        assert_eq!(json["name_tree_compaction"]["compact_on_startup"], false);
        assert_eq!(
            json["name_tree_compaction"]["startup_interval"],
            DEFAULT_NAME_TREE_COMPACTION_INTERVAL
        );
        assert!(json["name_tree_compaction"]["last_height"].is_null());
        assert_eq!(json["undo_retention"]["prune_history"], false);
        assert_eq!(json["undo_retention"]["prune_after_height"], 1_000);
        assert_eq!(json["undo_retention"]["keep_blocks"], 10_000);
        assert!(json["undo_retention"]["pruned_through"].is_null());
        assert!(json["undo_retention"]["blocks_pruned_through"].is_null());
        assert!(json["undo_retention"]["blocks_checkpoint"].is_null());
        assert!(json["undo_retention"]["pruned_blocks"].is_null());
        assert!(json["active_state_resulting_root"].is_null());
        assert!(json["active_state_resulting_root_height"].is_null());
        let registry = &json["experimental_registry"];
        assert_eq!(
            registry["name"],
            "Denuo Experimental Handshake P2P Registry"
        );
        assert_eq!(registry["registry_id"], registry["fingerprint"]);
        assert_eq!(
            registry["fingerprint"],
            "95774db08c569b36fa7b7e4a071930f563b7251fc30934ba986732379a6e542d"
        );
        assert_eq!(registry["registry_version"], 1);
        assert_eq!(registry["registry_protocol_version"], 1);
        assert_eq!(registry["wire_profile"], "denuo-v1");
        assert_eq!(
            registry["assignment_status"],
            "Denuo Experimental V1 — Not an official Handshake protocol assignment"
        );
        assert_eq!(registry["service_bit"], 0x1000_0000_u64);
        assert_eq!(registry["local_service_mask"], 0);
        assert_eq!(registry["packet_type"], 0xf4);
        assert_eq!(registry["advertised"], false);
        assert_eq!(registry["maximum_packet_payload"], 1_048_576);
        assert_eq!(registry["maximum_nested_payload"], 1_048_550);
        assert_eq!(registry["maximum_registry_payload"], 16_384);
        assert_eq!(registry["outbound_messages_admitted"], 0);
        assert_eq!(registry["inbound_messages_received"], 0);
        assert_eq!(registry["rejected_messages"], 0);
        assert_eq!(registry["agreements_computed"], 0);
        assert_eq!(registry["disabled_sessions"], 0);
        let rejection_reasons = registry["rejection_reasons"]
            .as_array()
            .expect("fixed rejection reasons");
        assert_eq!(rejection_reasons.len(), 18);
        assert_eq!(rejection_reasons[0]["reason"], "local-service-disabled");
        assert_eq!(rejection_reasons[17]["reason"], "local-send-unavailable");
        assert!(rejection_reasons.iter().all(|reason| reason["count"] == 0));

        let request = format!(
            "GET /api/v1/mining-engine HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
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
        let (_, response_body) = response.split_once("\r\n\r\n").expect("body split");
        let json: Value = serde_json::from_str(response_body).expect("json response");
        assert_eq!(json["enabled"], false);

        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server join").expect("server result");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_runs_accepted_work_after_caller_cancellation() {
        let runtime = NodeRuntime::spawn(
            NodeService::new(NodeConfig {
                network: Network::Regtest,
                authority_mode: AuthorityMode::Disabled,
                ..NodeConfig::default()
            }),
            2,
        )
        .expect("runtime");
        let writer = runtime.writer();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            first_writer
                .execute(None, "blocking runtime test command", move |_| {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release writer");
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("writer command entered");

        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let executed_in_command = Arc::clone(&executed);
        let second_writer = writer.clone();
        let second = tokio::spawn(async move {
            second_writer
                .execute(None, "cancelled runtime test command", move |_| {
                    executed_in_command.store(true, Ordering::Release);
                    Ok(())
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if writer.inner.sender.capacity() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second command admission timeout");
        assert_eq!(writer.inner.sender.capacity(), 1, "second command admitted");
        second.abort();
        release_tx.send(()).expect("release first command");
        first.await.expect("first join").expect("first command");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if executed.load(Ordering::Acquire) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted command execution timeout");
        assert!(
            executed.load(Ordering::Acquire),
            "dropping a reply future must not cancel accepted work"
        );
        runtime.shutdown().await.expect("drain and join runtime");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_success_shutdown_marks_store_clean() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        assert!(!was_clean_shutdown(&store).expect("running store starts unclean"));

        NodeRuntime::spawn(node, 2)
            .expect("runtime")
            .shutdown()
            .await
            .expect("successful shutdown");

        assert!(was_clean_shutdown(&store).expect("successful shutdown marker"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_failure_shutdown_leaves_store_unclean() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        assert!(!was_clean_shutdown(&store).expect("running store starts unclean"));

        NodeRuntime::spawn(node, 2)
            .expect("runtime")
            .shutdown_unclean()
            .await
            .expect("failure shutdown drains writer");

        assert!(!was_clean_shutdown(&store).expect("failure shutdown marker"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_unclean_shutdown_corrects_prior_clean_clone() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        let runtime = NodeRuntime::spawn(node, 2).expect("runtime");
        let failure_correction = runtime.clone();

        runtime.shutdown().await.expect("clean clone shutdown");
        assert!(was_clean_shutdown(&store).expect("clean clone marker"));

        failure_correction
            .shutdown_unclean()
            .await
            .expect("unclean clone correction");
        assert!(!was_clean_shutdown(&store).expect("corrected unclean marker"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_cancelled_enqueued_clean_shutdown_finishes_unclean() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        let runtime = NodeRuntime::spawn(node, 2).expect("runtime");
        let writer = runtime.writer();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocking_command = tokio::spawn(async move {
            writer
                .execute(None, "clean-shutdown cancellation blocker", move |_| {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release writer");
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("writer command entered");

        let clean_runtime = runtime.clone();
        let clean_shutdown = tokio::spawn(clean_runtime.shutdown());
        tokio::time::timeout(Duration::from_secs(5), async {
            while runtime.inner.sender.capacity() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("clean shutdown was not enqueued behind blocker");
        clean_shutdown.abort();
        assert!(clean_shutdown
            .await
            .expect_err("clean shutdown task is cancelled")
            .is_cancelled());

        let unclean_runtime = runtime.clone();
        let unclean_shutdown = tokio::spawn(unclean_runtime.shutdown_unclean());
        tokio::time::timeout(Duration::from_secs(5), async {
            while runtime.inner.sender.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unclean correction was not enqueued behind cancelled clean shutdown");
        assert!(!was_clean_shutdown(&store).expect("pre-stop unclean correction"));

        release_tx.send(()).expect("release writer");
        blocking_command
            .await
            .expect("blocking command join")
            .expect("blocking command");
        unclean_shutdown
            .await
            .expect("unclean shutdown join")
            .expect_err("the prior clean command exits before the correction is processed");

        assert!(
            !was_clean_shutdown(&store).expect("post-join unclean correction"),
            "an enqueued clean command must not overwrite the final failure marker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_cancelled_shutdown_retains_join_authority() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        let runtime = NodeRuntime::spawn(node, 1).expect("runtime");
        let writer = runtime.writer();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            first_writer
                .execute(None, "shutdown cancellation blocker", move |_| {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release writer");
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("writer command entered");

        let second = tokio::spawn(async move {
            writer
                .execute(None, "shutdown cancellation queued command", |_| Ok(()))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while runtime.inner.sender.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued command admission timeout");

        let interrupted_runtime = runtime.clone();
        let interrupted = tokio::spawn(interrupted_runtime.shutdown_unclean());
        tokio::time::timeout(Duration::from_secs(5), async {
            while runtime.inner.state.accepting.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown did not stop admission");
        interrupted.abort();
        assert!(interrupted
            .await
            .expect_err("shutdown task is cancelled")
            .is_cancelled());
        assert!(
            runtime.inner.join.lock().await.is_some(),
            "cancellation before enqueue must retain the OS-thread join handle"
        );

        release_tx.send(()).expect("release first command");
        first.await.expect("first join").expect("first command");
        second.await.expect("second join").expect("second command");
        runtime
            .shutdown_unclean()
            .await
            .expect("replacement shutdown drains and joins actor");
        assert!(!was_clean_shutdown(&store).expect("cancelled shutdown remains unclean"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_epochs_are_exact_and_chain_scoped() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        let runtime = NodeRuntime::spawn(node, 4).expect("runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let initial = read.canonical_epoch();
        let initial_mempool = read.published_mempool().expect("initial mempool");

        let error = writer
            .execute::<(), _>(None, "erroring runtime test command", |_| {
                anyhow::bail!("intentional command failure")
            })
            .await
            .expect_err("command error");
        assert!(error.to_string().contains("intentional command failure"));
        let after_error = read.canonical_epoch();
        assert_eq!(after_error.writer_sequence, initial.writer_sequence + 1);
        assert_eq!(after_error.chain(), initial.chain());
        assert!(initial_mempool.ordered_txids.is_same_generation(
            &read
                .published_mempool()
                .expect("mempool after command error")
                .ordered_txids
        ));

        let stale = writer
            .execute_at(initial.clone(), "stale exact command", |_| Ok(()))
            .await
            .expect_err("exact sequence must be stale");
        assert!(stale.chain().any(|cause| cause
            .downcast_ref::<CanonicalWriterError>()
            .is_some_and(|error| { matches!(error, CanonicalWriterError::StaleEpoch { .. }) })));

        writer
            .execute_at_chain(initial.chain(), "chain-scoped command", |_| Ok(()))
            .await
            .expect("unrelated writer generation does not stale chain work");
        runtime.shutdown().await.expect("shutdown");
        assert!(was_clean_shutdown(&store).expect("clean shutdown marker"));
        assert!(read.ensure_storage_operational().is_err());
        assert!(read.published_mempool().is_err());
        assert!(!read.published().storage_operational());
        assert!(read.mining_snapshot().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn online_pruned_name_pages_compact_after_sixteen_segments_with_scheduler_writer() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();

        let test_root = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let directory = test_root.join(format!(
            "hsrd-online-name-page-compaction-runtime-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let store = StoreHandle::memory();
        let mut state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initialize runtime state");
        state.name_pages = Some(
            NamePageStorage::open_or_bootstrap(directory.clone(), &store, Network::Regtest)
                .expect("open name pages"),
        );
        let initial_generation = state
            .name_pages
            .as_ref()
            .expect("name pages")
            .state
            .manifest
            .generation;

        let node = NodeService::with_state(
            NodeConfig {
                network: Network::Regtest,
                data_dir: Some(directory.clone()),
                authority_mode: AuthorityMode::Disabled,
                undo_retention: UndoRetentionConfig {
                    prune_history: true,
                },
                ..NodeConfig::default()
            },
            state,
        );
        let runtime = NodeRuntime::spawn(node, 2).expect("runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let mut reports = Vec::new();

        // Nineteen seals means the process passes the normal
        // sixteen-segment threshold and continues operating
        // after the generation rewrite.
        for seal in 1_u32..=19 {
            let height = seal
                .checked_mul(NAME_PAGE_SEGMENT_BLOCKS)
                .expect("seal height");

            writer
                .execute(None, "test online name-page compaction commit", move |service| {
                    commit_test_name_page_seal(&mut service.state, height)
                })
                .await
                .expect("commit synthetic seal");

            if let Some(due) = read
                .name_page_compaction_due()
                .expect("read due state")
            {
                let report = writer
                    .execute_at_chain(
                        due.epoch,
                        "test online name-page compaction",
                        |service| {
                            service
                                .state
                                .compact_pruned_name_pages_if_due()
                        },
                    )
                    .await
                    .expect("writer compaction")
                    .expect("generation rewrite");
                assert_eq!(report.previous_generation, due.generation);
                reports.push(report);
            }

            let active_segment = writer
                .execute(None, "read active segment", |service| {
                    Ok(service
                        .state
                        .name_pages
                        .as_ref()
                        .expect("pages")
                        .state
                        .manifest
                        .active_segment)
                })
                .await
                .expect("read pages");
            assert!(
                active_segment < NAME_PAGE_COMPACTION_SEGMENT_THRESHOLD,
                "maintenance should rewrite generation as soon as the threshold is crossed"
            );
        }

        assert_eq!(reports.len(), 1, "nineteen seals should cross the threshold once");

        let final_report = &reports[0];
        assert_eq!(final_report.previous_generation, initial_generation);
        assert!(final_report.generation > initial_generation);

        let (final_active_segment, final_generation) = writer
            .execute(None, "read final state", |service| {
                let pages = service
                    .state
                    .name_pages
                    .as_ref()
                    .expect("pages");
                Ok((pages.state.manifest.active_segment, pages.state.manifest.generation))
            })
            .await
            .expect("read final state");
        assert_eq!(final_generation, final_report.generation);
        assert_eq!(final_active_segment, 3);

        runtime.shutdown().await.expect("runtime shutdown");
        drop(store);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stable_read_returns_busy_without_waiting_for_a_writer_slice() {
        let runtime = NodeRuntime::spawn(
            NodeService::new(NodeConfig {
                network: Network::Regtest,
                authority_mode: AuthorityMode::Disabled,
                ..NodeConfig::default()
            }),
            2,
        )
        .expect("runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let command = tokio::spawn(async move {
            writer
                .execute(None, "stable-read overlap", move |_| {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release writer");
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("writer entered");
        let started = Instant::now();
        let error = read
            .with_stable_read(|_, _| Ok(()))
            .expect_err("overlapping read is busy");
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(error
            .downcast_ref::<CanonicalWriterError>()
            .is_some_and(|error| matches!(error, CanonicalWriterError::Busy)));
        let _last_committed = read.published();

        release_tx.send(()).expect("release writer");
        command.await.expect("command join").expect("command");
        runtime.shutdown().await.expect("shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_panic_publishes_fail_closed_and_joins() {
        let runtime = NodeRuntime::spawn(
            NodeService::new(NodeConfig {
                network: Network::Regtest,
                authority_mode: AuthorityMode::Disabled,
                ..NodeConfig::default()
            }),
            2,
        )
        .expect("runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let error = writer
            .execute::<(), _>(None, "panicking runtime test command", |_| {
                panic!("intentional canonical writer panic")
            })
            .await
            .expect_err("panicking command loses its reply");
        assert!(error
            .downcast_ref::<CanonicalWriterError>()
            .is_some_and(|error| matches!(error, CanonicalWriterError::Stopped)));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if runtime.terminal_error().is_some()
                    && !read.published().storage_operational()
                    && runtime
                        .inner
                        .state
                        .publication_sequence
                        .load(Ordering::Acquire)
                        & 1
                        == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("panic fail-closed publication timeout");
        assert!(matches!(
            runtime.terminal_error(),
            Some(CanonicalWriterError::Terminal { .. })
        ));
        assert!(!read.published().storage_operational());
        assert_eq!(
            runtime
                .inner
                .state
                .publication_sequence
                .load(Ordering::Acquire)
                & 1,
            0,
            "panic recovery must close the seqlock generation"
        );
        assert!(read.ensure_storage_operational().is_err());
        assert!(runtime.shutdown().await.is_err());
    }

    #[test]
    fn canonical_publication_sequence_refuses_two_step_wrap() {
        assert_eq!(next_writer_sequence((u64::MAX / 2) - 1), Some(u64::MAX / 2));
        assert_eq!(next_writer_sequence(u64::MAX / 2), None);
        assert_eq!(next_writer_sequence(u64::MAX), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_runtime_admission_is_fail_fast_and_hard_bounded() {
        let runtime = NodeRuntime::spawn(
            NodeService::new(NodeConfig {
                network: Network::Regtest,
                authority_mode: AuthorityMode::Disabled,
                ..NodeConfig::default()
            }),
            1,
        )
        .expect("runtime");
        let writer = runtime.writer();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            first_writer
                .execute(None, "saturation blocker", move |_| {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release writer");
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("blocker entered");
        let second_writer = writer.clone();
        let second = tokio::spawn(async move {
            second_writer
                .execute(None, "saturation queued command", |_| Ok(()))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if writer.inner.sender.capacity() == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued command admission timeout");
        assert_eq!(writer.inner.sender.capacity(), 0, "queue is saturated");

        let started = Instant::now();
        let error = writer
            .execute(None, "saturation rejected command", |_| Ok(()))
            .await
            .expect_err("third outstanding command exceeds hard cap");
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(error
            .downcast_ref::<CanonicalWriterError>()
            .is_some_and(|error| matches!(error, CanonicalWriterError::QueueFull { .. })));

        release_tx.send(()).expect("release writer");
        first.await.expect("first join").expect("first command");
        second.await.expect("second join").expect("second command");
        runtime.shutdown().await.expect("shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_revokes_read_authority_before_the_actor_drains() {
        let runtime = NodeRuntime::spawn(
            NodeService::new(NodeConfig {
                network: Network::Regtest,
                authority_mode: AuthorityMode::Disabled,
                ..NodeConfig::default()
            }),
            2,
        )
        .expect("runtime");
        let read = runtime.read();
        let mut published = (*read.published()).clone();
        published.authoritative_mining_snapshot = Some(Arc::new(MiningSnapshot {
            network_id: Network::Regtest.canonical_id(),
            generation: published.mining_generation,
            tip: HeaderSummary {
                hash: BlockHash::ZERO,
                parent_hash: BlockHash::ZERO,
                height: 0,
                tree_root: [0; 32],
                time: 0,
                bits: 0,
            },
            parent_median_time: 0,
            next_tree_root: [0; 32],
            chainwork: Uint256::ZERO,
        }));
        published.mining_authoritative = true;
        read.state.publish(published);
        assert!(read.mining_snapshot().is_some());
        assert!(read.subscribe_mining_events().is_ok());

        let actor_read = read.clone();
        let (actor_entered_tx, actor_entered_rx) = tokio::sync::oneshot::channel();
        let (actor_release_tx, actor_release_rx) = std::sync::mpsc::channel();
        let inspection = tokio::spawn(async move {
            actor_read
                .inspect_bounded("shutdown authority blocker", move |_| {
                    let _ = actor_entered_tx.send(());
                    actor_release_rx.recv().expect("release actor");
                    Ok(())
                })
                .await
        });
        actor_entered_rx.await.expect("actor entered");

        let stable_read = read.clone();
        let (read_entered_tx, read_entered_rx) = tokio::sync::oneshot::channel();
        let (read_release_tx, read_release_rx) = std::sync::mpsc::channel();
        let stable = tokio::task::spawn_blocking(move || {
            stable_read.with_stable_epoch_read(|_, _| {
                let _ = read_entered_tx.send(());
                read_release_rx.recv().expect("release stable read");
                Ok(())
            })
        });
        read_entered_rx.await.expect("stable read entered");

        let state = Arc::clone(&read.state);
        let shutdown = tokio::spawn(runtime.shutdown());
        while state.accepting.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        assert!(state.terminal_reason().is_none(), "actor remains in flight");
        assert!(read.published().storage_operational());
        assert!(read.ensure_storage_operational().is_err());
        assert!(read.published_mempool().is_err());
        assert!(read.mining_snapshot().is_none());
        assert!(read.subscribe_mining_events().is_err());

        read_release_tx.send(()).expect("release stable read");
        let stable_error = stable
            .await
            .expect("stable read join")
            .expect_err("shutdown must reject a read that began while active");
        assert!(stable_error
            .downcast_ref::<CanonicalWriterError>()
            .is_some_and(|error| matches!(error, CanonicalWriterError::ShuttingDown)));

        actor_release_tx.send(()).expect("release actor");
        inspection
            .await
            .expect("inspection join")
            .expect("accepted inspection");
        shutdown.await.expect("shutdown join").expect("shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unexpected_runtime_drop_fail_closes_surviving_reads_without_clean_marker() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            ..NodeConfig::default()
        });
        let store = node.state.store.clone();
        let runtime = NodeRuntime::spawn(node, 2).expect("runtime");
        let read = runtime.read();
        let stable_read = read.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let stable = tokio::task::spawn_blocking(move || {
            stable_read.with_stable_epoch_read(|_, _| {
                let _ = entered_tx.send(());
                release_rx.recv().expect("release stable read");
                Ok(())
            })
        });
        entered_rx.await.expect("stable read entered");
        drop(runtime);

        assert!(read.ensure_storage_operational().is_err());
        assert!(read.mining_snapshot().is_none());
        assert!(read.subscribe_mining_events().is_err());
        release_tx.send(()).expect("release stable read");
        stable
            .await
            .expect("stable read join")
            .expect_err("lost runtime must reject a read that began while active");

        tokio::time::timeout(Duration::from_secs(1), async {
            while read.published().storage_operational() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer observes receiver closure");
        assert!(!read.published().storage_operational());
        assert!(read.mining_snapshot().is_none());
        assert!(read.rpc_diagnostic_service().await.is_err());
        assert!(!was_clean_shutdown(&store).expect("unexpected exit stays unclean"));
    }

    #[test]
    fn published_mempool_view_rejects_mixed_generations_and_counts() {
        let generation_error = PublishedMempoolView::new(
            MempoolInfo {
                generation: 1,
                ..MempoolInfo::default()
            },
            MemoryMempool::new()
                .expect("test mempool initialization")
                .snapshot(),
            OrderedTxidSnapshot::default(),
            1,
        )
        .expect_err("snapshot generation must match aggregate generation");
        assert!(generation_error
            .to_string()
            .contains("published mempool generations disagree"));

        let ordered_generation_error = PublishedMempoolView::new(
            MempoolInfo::default(),
            MemoryMempool::new()
                .expect("test mempool initialization")
                .snapshot(),
            OrderedTxidSnapshot::default(),
            1,
        )
        .expect_err("ordered generation must match aggregate generation");
        assert!(ordered_generation_error
            .to_string()
            .contains("published mempool generations disagree"));

        let count_error = PublishedMempoolView::new(
            MempoolInfo {
                transaction_count: 1,
                ..MempoolInfo::default()
            },
            MemoryMempool::new()
                .expect("test mempool initialization")
                .snapshot(),
            OrderedTxidSnapshot::default(),
            0,
        )
        .expect_err("snapshot and order counts must match aggregate count");
        assert!(count_error
            .to_string()
            .contains("published mempool transaction counts disagree"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_mempool_reads_retain_generations_and_bypass_a_blocked_writer() {
        let node = peer_transaction_node(0);
        let first_outpoint = Outpoint {
            txid: Txid::new([0xd1; 32]),
            index: 0,
        };
        let second_outpoint = Outpoint {
            txid: Txid::new([0xd2; 32]),
            index: 0,
        };
        install_script_coin(&node, first_outpoint.clone(), 10_000, 0);
        install_script_coin(&node, second_outpoint.clone(), 10_000, 0);
        let first = script_spend(first_outpoint, 9_000);
        let first_txid = first.txid();
        let second = script_spend(second_outpoint, 8_000);
        let second_txid = second.txid();

        let runtime = NodeRuntime::spawn(node, 2).expect("runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let first_admission = writer
            .execute(None, "first persistent-view admission", move |node| {
                node.mining_engine_accept_peer_transaction(first)
            })
            .await
            .expect("first admission");
        assert!(matches!(
            first_admission,
            hns_mempool::Admission::Accepted(txid) if txid == first_txid
        ));
        let retained = read
            .published_mempool()
            .expect("retained mempool generation");
        let retained_snapshot = retained.snapshot();

        let second_admission = writer
            .execute(None, "second persistent-view admission", move |node| {
                node.mining_engine_accept_peer_transaction(second)
            })
            .await
            .expect("second admission");
        assert!(matches!(
            second_admission,
            hns_mempool::Admission::Accepted(txid) if txid == second_txid
        ));
        let current = read
            .published_mempool()
            .expect("current mempool generation");
        let current_snapshot = current.snapshot();
        assert_eq!(retained.info.transaction_count, 1);
        assert_eq!(current.info.transaction_count, 2);
        assert!(retained_snapshot.transaction(&first_txid).is_some());
        assert!(retained_snapshot.transaction(&second_txid).is_none());
        assert!(current_snapshot.transaction(&second_txid).is_some());
        assert!(std::ptr::eq(
            retained_snapshot
                .transaction(&first_txid)
                .expect("retained transaction"),
            current_snapshot
                .transaction(&first_txid)
                .expect("shared current transaction"),
        ));

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocked_writer = writer.clone();
        let command = tokio::spawn(async move {
            blocked_writer
                .execute(None, "blocked persistent-view writer", move |_| {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release blocked writer");
                    Ok(())
                })
                .await
        });
        entered_rx.await.expect("writer entered");
        assert_eq!(
            read.state.publication_sequence.load(Ordering::Acquire) & 1,
            1,
            "fixture must hold an in-progress canonical generation"
        );

        let transaction_read = read.clone();
        let inventory_read = read.clone();
        let reads = tokio::time::timeout(Duration::from_secs(2), async move {
            tokio::join!(
                transaction_read.mempool_transactions(MAX_RPC_COLLECTION_ENTRIES),
                inventory_read.mempool_inventory(MAX_RPC_COLLECTION_ENTRIES),
            )
        })
        .await;
        release_tx.send(()).expect("release writer");
        let (transactions, inventory) = reads
            .expect("persistent mempool collection workers must not wait for the canonical writer");
        let transactions = transactions.expect("persistent transaction collection");
        let inventory = inventory.expect("persistent inventory collection");
        assert_eq!(
            transactions
                .iter()
                .map(Transaction::txid)
                .collect::<Vec<_>>(),
            vec![first_txid, second_txid]
        );
        assert_eq!(
            inventory,
            vec![
                hns_p2p::Inventory::transaction(first_txid),
                hns_p2p::Inventory::transaction(second_txid),
            ]
        );
        command.await.expect("writer join").expect("writer command");
        runtime.shutdown().await.expect("shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_initializes_publication_queue_and_shares_template_cache_lock() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::Disabled,
            mining_engine: MiningEngineConfig {
                enabled: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        });
        let service_cache = Arc::clone(&node.mining_engine_templates);
        let runtime = NodeRuntime::spawn(node, 2).expect("runtime startup");
        let read = runtime.read();
        let read_cache = read.template_coordinator_handle();
        assert!(Arc::ptr_eq(&service_cache, &read_cache));

        let diagnostics = read
            .mining_engine_diagnostics()
            .await
            .expect("mining diagnostics after startup migration");
        assert!(!diagnostics
            .blockers
            .iter()
            .any(|blocker| blocker.contains("publication queue index is not initialized")));

        let stable_before = read.canonical_epoch();
        assert!(read.canonical_generation_is_stable(&stable_before));
        let cache_guard = service_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let writer = runtime.writer();
        let cache_clear = tokio::spawn(async move {
            writer
                .execute(None, "shared template-cache clear", move |node| {
                    entered_tx.send(()).expect("signal cache clear");
                    node.revoke_runtime_authority();
                    Ok(())
                })
                .await
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("writer reached shared cache");
        assert!(!read.canonical_generation_is_stable(&stable_before));
        drop(cache_guard);
        cache_clear
            .await
            .expect("cache-clear writer join")
            .expect("cache-clear writer command");
        assert!(!read.canonical_generation_is_stable(&stable_before));
        assert!(read.canonical_generation_is_stable(&read.canonical_epoch()));
        runtime.shutdown().await.expect("shutdown");
    }
}
