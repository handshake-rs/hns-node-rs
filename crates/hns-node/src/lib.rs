#![forbid(unsafe_code)]

mod mining_engine;
mod shadow_sync;

pub use mining_engine::{
    MiningEngineConfig, MiningEngineDiagnostics, MiningPublicationAttempt, MiningPublicationResult,
    MiningTemplateRequest,
};
pub use shadow_sync::{ShadowSyncConfig, ShadowSyncDiagnostics};

use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    routing::{get, post},
    Json, Router,
};
use clap::ValueEnum;
use hns_chain::{
    delete_canonical_height_from_batch, delete_tx_index_for_block_from_batch, read_canonical_hash,
    write_block_index_to_batch, write_canonical_height_to_batch, write_raw_block_to_batch,
    write_record_to_batch, write_tx_index_for_block_to_batch, BlockIndexRecord, BlockStatus,
    ChainTip, HeaderIndex, HeaderRecord, RawBlockRecord, RawBlockSource, ReorgPlan,
    StoredBlockIndex, StoredHeaderIndex,
};
use hns_consensus::{
    advance_threshold_state, expected_next_bits, validate_block_finality, validate_coinbase_height,
    validate_transaction_start, ConsensusParams, Deployment, DeploymentPeriod, DeploymentState,
    DifficultyPoint, HeaderConsensus, HeaderParent, HeaderValidationContext,
    HistoricalScriptPolicy, HistoricalValidationPlan, NameFlags, Network, ThresholdState,
    MAX_FUTURE_BLOCK_TIME, MEDIAN_TIMESPAN,
};
use hns_mempool::{MemoryMempool, Mempool};
use hns_mining::{
    HeaderSummary, MiningEventHub, MiningGeneration, MiningSnapshot, MiningSubscriptions,
    SolvedMiningCandidate, TemplateCoordinator,
};
use hns_primitives::{
    blake2b_256, hex_encode, Block, BlockHash, Coin, CompactTarget, Height, NameHash, NameState,
    Reader, Uint256, Writer,
};
use hns_rpc::{
    BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcAuthorityInfo, RpcBlockEntry,
    RpcConsensusReadiness, RpcErrorObject, RpcHeaderEntry, RpcMiningEngineInfo,
    RpcNameTreeCompactionInfo, RpcNodeStatus, RpcParityInfo, RpcService, RpcSnapshot,
    RpcTransactionEntry, RpcUndoRetentionInfo,
};
use hns_state::{
    connect_block_to_batch_with_services, decode_coin, decode_name_state,
    disconnect_block_to_batch, load_name_tree_snapshot_pins, load_stored_name_tree_commit_root,
    stage_name_tree_node_compaction, validate_persisted_name_tree, verify_stored_name_tree_root,
    AirdropCoinbaseIssuanceVerifier, BlockUndo, ConnectBlock, DisconnectBlock,
    NameTreeCompactionSummary, NameTreeSnapshotPin, StateError, StateServices, StoredStateEngine,
};
use hns_store::{
    decode_u64, encode_u64, mark_clean_shutdown, mark_unclean_start, open_store,
    was_clean_shutdown, ColumnFamily, DurabilityPolicy, MetaKey, ReadSnapshot, StagingOverlay,
    Store, StoreBackend, StoreConfig, StoreHandle, WriteBatch, SCHEMA_VERSION, STORAGE_PROFILE,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

pub const HSRD_DIAGNOSTIC_API_VERSION: u32 = 9;
pub const HSD_ORACLE_REVISION: &str = "698e252ebc7b5c1dd0a9587e342fdd153d020ae4";

const DEPLOYMENT_STATE_CACHE_PREFIX: &[u8] = b"deployment-state/v1/";
const DEPLOYMENT_STATE_CACHE_VERSION: u8 = 1;
const DEPLOYMENT_STATE_CACHE_SIZE: usize = 1 + 4 + 4;
const NAME_TREE_COMPACTION_CHECKPOINT_KEY: &[u8] = b"name-tree-compaction/v1";
const NAME_TREE_COMPACTION_CHECKPOINT_VERSION: u32 = 1;
const NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE: usize = 4 + 4 + 32 + (4 * 8);
const NAME_TREE_COMPACTION_CHECKPOINT_SIZE: usize = NAME_TREE_COMPACTION_CHECKPOINT_BODY_SIZE + 32;
pub const DEFAULT_NAME_TREE_COMPACTION_INTERVAL: Height = 10_000;
const UNDO_PRUNING_CHECKPOINT_KEY: &[u8] = b"undo-pruning/v1";
const UNDO_PRUNING_CHECKPOINT_VERSION: u32 = 1;
const UNDO_PRUNING_CHECKPOINT_BODY_SIZE: usize = 4 + 4 + 32 + 8;
const UNDO_PRUNING_CHECKPOINT_SIZE: usize = UNDO_PRUNING_CHECKPOINT_BODY_SIZE + 32;
const MAX_UNDO_PRUNES_PER_BATCH: usize = 1_024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum AuthorityMode {
    Disabled,
    #[default]
    Shadow,
    HsdVerified,
    NativeExperimental,
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
}

impl UndoPruningCheckpoint {
    fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(UNDO_PRUNING_CHECKPOINT_SIZE);
        writer.write_u32(UNDO_PRUNING_CHECKPOINT_VERSION);
        writer.write_u32(self.pruned_through);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u64(self.pruned_undos);
        let mut raw = writer.finish();
        debug_assert_eq!(raw.len(), UNDO_PRUNING_CHECKPOINT_BODY_SIZE);
        raw.extend_from_slice(&blake2b_256(&raw));
        raw
    }

    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != UNDO_PRUNING_CHECKPOINT_SIZE {
            anyhow::bail!(
                "undo-pruning checkpoint contains {} bytes; expected {UNDO_PRUNING_CHECKPOINT_SIZE}",
                raw.len()
            );
        }
        let (body, checksum) = raw.split_at(UNDO_PRUNING_CHECKPOINT_BODY_SIZE);
        if checksum != blake2b_256(body) {
            anyhow::bail!("undo-pruning checkpoint checksum mismatch");
        }
        let mut reader = Reader::new(body, UNDO_PRUNING_CHECKPOINT_BODY_SIZE)?;
        let version = reader.read_u32()?;
        if version != UNDO_PRUNING_CHECKPOINT_VERSION {
            anyhow::bail!("unsupported undo-pruning checkpoint version {version}");
        }
        let checkpoint = Self {
            pruned_through: reader.read_u32()?,
            block_hash: BlockHash::new(reader.read_hash()?),
            pruned_undos: reader.read_u64()?,
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

impl AuthorityMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Shadow => "shadow",
            Self::HsdVerified => "hsd-verified",
            Self::NativeExperimental => "native-experimental",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub network: Network,
    pub data_dir: Option<PathBuf>,
    pub rpc_bind: SocketAddr,
    pub log_filter: String,
    pub authority_mode: AuthorityMode,
    pub acknowledge_incomplete_consensus: bool,
    pub storage_durability: DurabilityPolicy,
    pub name_tree_compaction: NameTreeCompactionConfig,
    pub undo_retention: UndoRetentionConfig,
    pub shadow_sync: ShadowSyncConfig,
    pub mining_engine: MiningEngineConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            data_dir: None,
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], 12037)),
            log_filter: "info".to_owned(),
            authority_mode: AuthorityMode::Shadow,
            acknowledge_incomplete_consensus: false,
            storage_durability: DurabilityPolicy::Sync,
            name_tree_compaction: NameTreeCompactionConfig::default(),
            undo_retention: UndoRetentionConfig::default(),
            shadow_sync: ShadowSyncConfig::default(),
            mining_engine: MiningEngineConfig::default(),
        }
    }
}

pub fn validate_node_config(config: &NodeConfig) -> Result<()> {
    match config.authority_mode {
        AuthorityMode::Disabled | AuthorityMode::Shadow => {}
        AuthorityMode::HsdVerified => anyhow::bail!(
            "hsd-verified authority is not composed yet; use shadow mode until the independent verifier boundary exists"
        ),
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

    if config.shadow_sync.connect_active_state && !config.acknowledge_incomplete_consensus {
        anyhow::bail!(
            "active-state synchronization requires --acknowledge-incomplete-consensus until historical and live parity gates pass"
        );
    }

    config.name_tree_compaction.validate()?;
    config.shadow_sync.validate(config.authority_mode)?;
    config
        .mining_engine
        .validate(&config.shadow_sync, config.authority_mode)
}

fn authority_can_mine(config: &NodeConfig) -> bool {
    matches!(config.authority_mode, AuthorityMode::NativeExperimental)
        && validate_node_config(config).is_ok()
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

    // The only currently composed authority mode is the explicitly gated
    // regtest/simnet experimental path. Future HSD-verified or native authority
    // modes must require `durable.authoritative` and issue the same capability.
    let experimental_bypass = matches!(config.authority_mode, AuthorityMode::NativeExperimental)
        && matches!(config.network, Network::Regtest | Network::Simnet)
        && config.acknowledge_incomplete_consensus;
    if !durable.authoritative && !experimental_bypass {
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
        scripts: false,
        covenant_linkage: true,
        contextual_covenants: false,
        claims_and_airdrops: false,
        name_state: false,
        urkel_roots: false,
        sequence_consistent_snapshots: true,
        durable_store_identity: true,
        side_chain_storage: true,
        best_work_fork_choice: true,
        validated_reorg_planning: true,
        atomic_reorganizations: true,
        wal_durability: true,
        historical_replay: false,
        invalid_corpus: false,
        live_shadow: false,
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
        (readiness.live_shadow, "sustained live shadow-node parity"),
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
        AuthorityMode::Shadow => blockers.push("shadow mode never authorizes mining".to_owned()),
        AuthorityMode::HsdVerified => {
            blockers.push("hsd-verified authority boundary is not composed".to_owned())
        }
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

    blockers.sort();
    blockers.dedup();

    RpcAuthorityInfo {
        mode: config.authority_mode.as_str().to_owned(),
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
        cached_template_variants: diagnostics.cached_template_variants,
        pending_publications: diagnostics.pending_publications,
        maximum_pending_publications: diagnostics.maximum_pending_publications,
        publication_retry_interval_ms: diagnostics.publication_retry_interval_ms,
        can_build_shadow_templates: diagnostics.can_build_shadow_templates,
        can_publish_solved_blocks: diagnostics.can_publish_solved_blocks,
        blockers: diagnostics.blockers,
    }
}

fn parity_info() -> RpcParityInfo {
    RpcParityInfo {
        oracle: "handshake-org/hsd".to_owned(),
        oracle_revision: HSD_ORACLE_REVISION.to_owned(),
        state: "not-configured".to_owned(),
        configured: false,
        historical_replay_complete: false,
        invalid_corpus_complete: false,
        live_shadow_active: false,
        last_compared_height: None,
        last_matching_block: None,
        divergence: None,
    }
}

#[derive(Debug)]
pub struct NodeService {
    config: NodeConfig,
    state: NodeState,
    mining_events: MiningEventHub,
    mining_engine_templates: Mutex<TemplateCoordinator>,
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
        let pruning_checkpoint = {
            let snapshot = state.store.snapshot()?;
            load_undo_pruning_checkpoint(&snapshot)?
        };
        if pruning_checkpoint.is_some() && !config.undo_retention.prune_history {
            anyhow::bail!(
                "undo history was previously pruned; --prune-undo-history cannot be disabled"
            );
        }
        state.undo_retention_policy = config
            .undo_retention
            .prune_history
            .then(|| UndoRetentionPolicy::for_network(config.network));

        let mempool_info = state.mempool.info();
        if mempool_info.transaction_count == 0 && mempool_info.orphan_count == 0 {
            state.mempool = MemoryMempool::with_limits(config.mining_engine.mempool_limits.clone())
                .map_err(|error| {
                    anyhow::anyhow!("failed to configure mining-engine mempool: {error}")
                })?;
        } else if state.mempool.limits() != &config.mining_engine.mempool_limits {
            anyhow::bail!(
                "non-empty node mempool limits do not match the configured mining-engine limits"
            );
        }

        // Production authority remains disabled. On the explicitly gated
        // regtest/simnet experimental path, recover a fully stored higher-work
        // branch before exposing any mining generation. Shadow active-state
        // recovery is driven by the bounded sync coordinator so it cannot
        // bypass contextual-failure handling or the configured batch limit.
        if authority_can_mine(&config) {
            state.recover_best_stored_chain()?;
        }

        if config.undo_retention.prune_history {
            state.prune_undo_history_to_policy()?;
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

        let previous_shutdown_clean = was_clean_shutdown(&state.store)
            .map_err(|error| anyhow::anyhow!("failed to read shutdown marker: {error}"))?;
        if !previous_shutdown_clean {
            // Durable invariants were checked by NodeState construction. Keep the
            // signal visible while still allowing deterministic recovery paths.
            tracing::warn!(
                "hsrd store was not marked clean at the previous shutdown; durable invariants were revalidated"
            );
        }
        mark_unclean_start(&state.store)
            .map_err(|error| anyhow::anyhow!("failed to mark running store unclean: {error}"))?;

        let durable = state.durable_mining_state()?;
        let initial = if durable_tip_can_authorize(&config, &durable) {
            durable.snapshot.clone()
        } else {
            None
        };
        let mining_events = MiningEventHub::from_durable(durable.generation, initial)
            .map_err(|error| anyhow::anyhow!("failed to initialize mining events: {error}"))?;
        let mining_engine_templates = Mutex::new(
            TemplateCoordinator::new(config.mining_engine.maximum_template_variants).map_err(
                |error| anyhow::anyhow!("failed to initialize mining-engine templates: {error}"),
            )?,
        );
        Ok(Self {
            config,
            state,
            mining_events,
            mining_engine_templates,
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

    /// Run name-tree maintenance under the node's mutable coordinator. The
    /// compaction checkpoint and all record deletions share one atomic batch.
    pub fn compact_name_tree_nodes(&mut self) -> Result<NameTreeCompactionCheckpoint> {
        self.state.compact_name_tree_nodes()
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
        self.mining_events.snapshot()
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

    pub fn rpc_service(&self) -> Result<BasicRpcService> {
        Ok(BasicRpcService::new(self.rpc_snapshot()?))
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
                return Ok(BlockAcceptance {
                    record: existing,
                    disposition: BlockDisposition::AlreadyKnown { active: true },
                });
            }
        } else if self.state.is_direct_active_extension(&request)? {
            let committed = self.state.commit_staged_block(request, validated)?;
            let mempool_generation =
                self.mining_engine_reconcile_connected_transactions(&active_transactions);
            self.publish_durable_mining_state(&committed.mining)?;
            self.mining_engine_publish_mempool_reconciled(
                committed.mining.generation,
                mempool_generation,
            )?;
            return Ok(BlockAcceptance {
                record: committed.record,
                disposition: BlockDisposition::Connected,
            });
        }

        let stored = self.state.store_validated_alternate(request, validated)?;
        let Some(activation) = self.state.best_chain_activation_plan(stored.record.hash)? else {
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

        let is_reorg = !activation.disconnect.is_empty();
        if is_reorg {
            self.mining_events
                .reorg_started(activation.disconnect.len(), activation.connect.len());
        }

        match self.state.apply_reorg(activation) {
            Ok(reorg) => {
                let mempool_generation = self.mining_engine_clear_mempool_for_chain_transition();
                self.publish_durable_mining_state(&reorg.mining)?;
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
        let disconnected = self.state.disconnect_block(request)?;
        let mempool_generation = self.mining_engine_clear_mempool_for_chain_transition();
        self.publish_durable_mining_state(&disconnected.mining)?;
        self.mining_engine_publish_mempool_reconciled(
            disconnected.mining.generation,
            mempool_generation,
        )?;
        Ok(disconnected.record)
    }

    pub fn apply_reorg(&mut self, request: NodeReorg) -> Result<NodeReorgSummary> {
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

        self.mining_events
            .reorg_started(request.disconnect.len(), request.connect.len());
        match self.state.apply_reorg(request) {
            Ok(reorg) => {
                let mempool_generation = self.mining_engine_clear_mempool_for_chain_transition();
                self.publish_durable_mining_state(&reorg.mining)?;
                self.mining_engine_publish_mempool_reconciled(
                    reorg.mining.generation,
                    mempool_generation,
                )?;
                Ok(reorg.summary)
            }
            Err(error) => {
                if let Ok(durable) = self.state.durable_mining_state() {
                    let _ = self.publish_durable_mining_state(&durable);
                }
                self.mining_events.reorg_aborted();
                Err(error)
            }
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
        if self.config.shadow_sync.enabled {
            self.run_shadow_sync_until_shutdown(shutdown).await
        } else {
            self.run_rpc_until_shutdown(shutdown).await
        }
    }

    pub(crate) async fn run_rpc_until_shutdown(&self, shutdown: ShutdownSignal) -> Result<()> {
        let rpc_service = self.rpc_service()?;
        let listener = TcpListener::bind(self.config.rpc_bind)
            .await
            .with_context(|| format!("failed to bind RPC listener on {}", self.config.rpc_bind))?;
        let local_addr = listener
            .local_addr()
            .context("failed to read RPC listener address")?;

        tracing::info!(
            network = %self.config.network,
            rpc_bind = %local_addr,
            mempool_size = rpc_service.snapshot().mempool_info.transaction_count,
            "hsrd rpc server started"
        );
        let result = serve_rpc_listener(listener, rpc_service, shutdown.wait()).await;
        if result.is_ok() {
            mark_clean_shutdown(&self.state.store).map_err(|error| {
                anyhow::anyhow!("failed to mark node store clean at shutdown: {error}")
            })?;
        }
        result?;
        tracing::info!("hsrd rpc server stopped");
        Ok(())
    }

    fn rpc_snapshot(&self) -> Result<RpcSnapshot> {
        let chain_tip = self.state.best_block_tip()?;
        let entries = self.state.rpc_entries()?;
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
        let stored_block_records = metadata
            .scan_prefix(ColumnFamily::BlockIndex, b"")
            .context("failed to scan durable block statuses")?
            .into_iter()
            .map(|(_, bytes)| {
                BlockIndexRecord::decode(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode block index: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let alternate_block_count = stored_block_records
            .iter()
            .filter(|record| !record.status.active_chain && !record.status.failed)
            .count();
        let failed_block_count = stored_block_records
            .into_iter()
            .filter(|record| record.status.failed)
            .count();
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

        let authority = authority_info(&self.config, &durable);
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
        };
        let node_status = RpcNodeStatus {
            api_version: HSRD_DIAGNOSTIC_API_VERSION,
            release_stage: "pre-authority".to_owned(),
            schema_version: SCHEMA_VERSION,
            network: self.config.network.to_string(),
            storage_profile: String::from_utf8_lossy(STORAGE_PROFILE).into_owned(),
            storage_durability: self.state.store.durability_policy().to_string(),
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
            active_state_sync_enabled: self.config.shadow_sync.connect_active_state,
            active_state_connect_batch: self.config.shadow_sync.active_state_connect_batch,
            pending_best_chain_activation,
            staged_chain_tip: durable.snapshot.is_some(),
            authoritative_mining_tip: self.mining_events.snapshot().is_some(),
            tip_validation,
            name_tree_compaction,
            undo_retention,
            authority,
            parity,
        };

        Ok(RpcSnapshot {
            network: self.config.network.to_string(),
            chain_tip,
            headers: entries.headers,
            blocks: entries.blocks,
            transactions: entries.transactions,
            coins: entries.coins,
            names: entries.names,
            mempool_info: self.state.mempool.info(),
            mempool_entries: self.state.mempool.entries(),
            network_active: false,
            peer_count: 0,
            mining_engine: rpc_mining_engine_info(self.mining_engine_diagnostics()?),
            node_status,
        })
    }
}

#[derive(Clone, Debug)]
struct RpcHttpState {
    service: Arc<BasicRpcService>,
}

#[derive(Clone, Debug, Default)]
struct RpcStoreEntries {
    headers: Vec<RpcHeaderEntry>,
    blocks: Vec<RpcBlockEntry>,
    transactions: Vec<RpcTransactionEntry>,
    coins: Vec<Coin>,
    names: Vec<NameState>,
}

pub async fn serve_rpc_listener<F>(
    listener: TcpListener,
    service: BasicRpcService,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let state = RpcHttpState {
        service: Arc::new(service),
    };
    let app = Router::new()
        .route("/", post(handle_rpc_http))
        .route("/rpc", post(handle_rpc_http))
        .route("/api/v1/status", get(handle_status_http))
        .route("/api/v1/authority", get(handle_authority_http))
        .route("/api/v1/parity", get(handle_parity_http))
        .route("/api/v1/mining-engine", get(handle_mining_engine_http))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("RPC server failed")
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

    Json(
        state
            .service
            .handle(request)
            .unwrap_or_else(|error| json_rpc_error(id, -32603, format!("internal error: {error}"))),
    )
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeReorgSummary {
    pub disconnected: Vec<BlockIndexRecord>,
    pub connected: Vec<BlockIndexRecord>,
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
}

#[derive(Clone, Debug)]
struct ValidatedImport {
    chainwork: Uint256,
    status: BlockStatus,
    historical_validation: HistoricalValidationPlan,
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

#[derive(Clone, Debug)]
pub struct NodeState {
    network: Network,
    undo_retention_policy: Option<UndoRetentionPolicy>,
    pub store: StoreHandle,
    pub chain: StoredHeaderIndex<StoreHandle>,
    pub blocks: StoredBlockIndex<StoreHandle>,
    pub state_engine: StoredStateEngine<StoreHandle>,
    pub mempool: MemoryMempool,
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
        let store = match &config.data_dir {
            Some(data_dir) => open_store(&StoreConfig {
                path: data_dir.join("chain"),
                backend: StoreBackend::RocksDb,
                durability: config.storage_durability,
            })
            .map_err(|error| anyhow::anyhow!("failed to open node store: {error}"))?,
            None => StoreHandle::memory(),
        };

        Self::from_store_for_network(store, config.network)
    }

    pub fn from_store_for_network(store: StoreHandle, network: Network) -> Result<Self> {
        Self::from_store_for_network_with_undo_policy(store, network, None)
    }

    fn from_store_for_network_with_undo_policy(
        store: StoreHandle,
        network: Network,
        undo_retention_policy: Option<UndoRetentionPolicy>,
    ) -> Result<Self> {
        bind_store_identity(&store, network)?;
        let chain = StoredHeaderIndex::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize header index: {error}"))?;
        let blocks = StoredBlockIndex::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize block index: {error}"))?;
        let state_engine =
            StoredStateEngine::with_native_authorization(store.clone(), network, NameFlags::NONE)
                .map_err(|error| anyhow::anyhow!("failed to initialize state engine: {error}"))?;

        let state = Self {
            network,
            undo_retention_policy,
            store,
            chain,
            blocks,
            state_engine,
            mempool: MemoryMempool::new(),
        };
        state.validate_durable_chain_invariants()?;
        Ok(state)
    }

    fn validate_durable_chain_invariants(&self) -> Result<()> {
        let snapshot = self.store.snapshot()?;
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
        let durable_name_tree_root = verify_stored_name_tree_root(&snapshot)
            .map_err(|error| anyhow::anyhow!("durable name-tree invariant failed: {error}"))?;
        validate_persisted_name_tree(&snapshot, durable_name_tree_root).map_err(|error| {
            anyhow::anyhow!("durable content-addressed name-tree invariant failed: {error}")
        })?;
        let durable_name_tree_commit_root =
            load_stored_name_tree_commit_root(&snapshot).map_err(|error| {
                anyhow::anyhow!("durable name-tree commit invariant failed: {error}")
            })?;
        validate_persisted_name_tree(&snapshot, durable_name_tree_commit_root).map_err(
            |error| anyhow::anyhow!("durable committed name-tree invariant failed: {error}"),
        )?;
        let active_tip = best_block_tip_from_snapshot(&snapshot)?;
        let best_header = best_header_tip_from_snapshot(&snapshot)?;
        let undo_pruning_checkpoint = load_undo_pruning_checkpoint(&snapshot)?;
        let mut heights = snapshot
            .scan_prefix(ColumnFamily::HeightIndex, b"")
            .context("failed to scan active height index")?;
        heights.sort_by(|left, right| left.0.cmp(&right.0));
        let tree_interval = self.network.params().names.tree_interval;
        let retention = self
            .undo_retention_policy
            .unwrap_or_else(|| UndoRetentionPolicy::for_network(self.network));
        retention.validate()?;
        if tree_interval == 0 {
            anyhow::bail!("network name-tree snapshot interval is zero");
        }
        let pins = load_name_tree_snapshot_pins(&snapshot)
            .map_err(|error| anyhow::anyhow!("durable name-tree snapshot pin failed: {error}"))?;
        let pin_count = pins.len();
        let mut name_tree_pins = pins
            .into_iter()
            .map(|pin| (pin.height, pin))
            .collect::<BTreeMap<_, NameTreeSnapshotPin>>();
        if name_tree_pins.len() != pin_count {
            anyhow::bail!("durable name-tree snapshot pins contain duplicate heights");
        }

        match active_tip.as_ref() {
            None if !heights.is_empty() => {
                anyhow::bail!("active height index exists without a best-block binding")
            }
            None => {
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
                if !name_tree_pins.is_empty() {
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
                }
                let expected_len = usize::try_from(tip.height)
                    .ok()
                    .and_then(|height| height.checked_add(1))
                    .ok_or_else(|| anyhow::anyhow!("active height index length overflow"))?;
                if heights.len() != expected_len {
                    anyhow::bail!(
                        "active height index has {} entries for tip height {}",
                        heights.len(),
                        tip.height
                    );
                }

                let mut previous_hash = BlockHash::ZERO;
                let mut previous_work = Uint256::ZERO;
                let mut previous_retained_tree_root = None;
                let mut previous_retained_committed_tree_root = None;
                let mut tip_resulting_tree_root = None;
                let mut tip_resulting_committed_tree_root = None;
                for (position, (height_key, hash_bytes)) in heights.iter().enumerate() {
                    let height = decode_height_key(height_key)?;
                    if usize::try_from(height).ok() != Some(position) {
                        anyhow::bail!(
                            "active height index is not contiguous at position {position}"
                        );
                    }
                    let hash = block_hash_from_bytes(hash_bytes)?;
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
                    let raw = load_raw_block_record(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!("active block body {} is missing", hash.to_hex())
                    })?;
                    let block = raw.decode_block().map_err(|error| {
                        anyhow::anyhow!("active block body {} is corrupt: {error}", hash.to_hex())
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
                    let expected_deployments = self.deployment_state_for_block(
                        &snapshot,
                        height,
                        block.header.prev_block,
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
                        if block.header.tree_root != *undo.previous_committed_tree_root.as_bytes() {
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
                        let expected_resulting_committed = if height % tree_interval == 0 {
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
                    if height % tree_interval == 0 {
                        let pin = name_tree_pins.remove(&height).ok_or_else(|| {
                            anyhow::anyhow!(
                                "active interval height {height} is missing its name-tree snapshot pin"
                            )
                        })?;
                        let expected_pin_root = match undo.as_ref() {
                            Some(undo) => *undo.resulting_committed_tree_root.as_bytes(),
                            None if position + 1 < heights.len() => {
                                let next_hash = block_hash_from_bytes(&heights[position + 1].1)?;
                                let next = load_header_record(&snapshot, &next_hash)?.ok_or_else(
                                    || {
                                        anyhow::anyhow!(
                                            "active header after snapshot height {height} is missing"
                                        )
                                    },
                                )?;
                                if next.height != height.saturating_add(1) {
                                    anyhow::bail!(
                                        "active header after snapshot height {height} is non-contiguous"
                                    );
                                }
                                next.header.tree_root
                            }
                            None => *durable_name_tree_commit_root.as_bytes(),
                        };
                        if pin.block_hash != hash || pin.root.as_bytes() != &expected_pin_root {
                            anyhow::bail!(
                                "active interval height {height} has an inconsistent name-tree snapshot pin"
                            );
                        }
                        validate_persisted_name_tree(&snapshot, pin.root).map_err(|error| {
                            anyhow::anyhow!(
                                "durable name-tree snapshot at height {height} is invalid: {error}"
                            )
                        })?;
                    }
                    previous_hash = hash;
                    previous_work = record.chainwork;
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
        if !name_tree_pins.is_empty() {
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
        Ok(())
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    fn best_block_tip(&self) -> Result<Option<ChainTip>> {
        let snapshot = self.store.snapshot()?;
        best_block_tip_from_snapshot(&snapshot)
    }

    fn durable_mining_state(&self) -> Result<DurableMiningState> {
        let snapshot = self.store.snapshot()?;
        let generation = mining_generation_from_snapshot(&snapshot)?;
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
        Ok(DurableMiningState {
            generation,
            snapshot: mining_snapshot,
            authoritative,
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
        let block_hash = request.block.hash();
        let snapshot = self.store.snapshot()?;

        if let Some(existing) = load_block_index_record(&snapshot, &block_hash)? {
            let stored = load_block(&snapshot, &block_hash)?.ok_or_else(|| {
                anyhow::anyhow!("known block {} has no raw body", block_hash.to_hex())
            })?;
            if stored.encode() != request.block.encode() {
                anyhow::bail!(
                    "known block {} has conflicting raw bytes",
                    block_hash.to_hex()
                );
            }
            return Ok(StoredBlockMutation {
                record: existing,
                already_known: true,
            });
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
        let mut batch = self.store.batch();
        write_record_to_batch(&mut batch, &header_record)
            .map_err(|error| anyhow::anyhow!("failed to stage alternate header: {error}"))?;
        write_block_index_to_batch(&mut batch, &record)
            .map_err(|error| anyhow::anyhow!("failed to stage alternate block index: {error}"))?;
        write_raw_block_to_batch(&mut batch, &raw_record)
            .map_err(|error| anyhow::anyhow!("failed to stage alternate block body: {error}"))?;
        stage_best_header_if_more_work(&snapshot, &mut batch, block_hash, validated.chainwork)?;
        drop(snapshot);
        self.store.commit(batch)?;
        self.cache_committed_block_records(std::slice::from_ref(&record))?;

        Ok(StoredBlockMutation {
            record,
            already_known: false,
        })
    }

    fn store_failed_block(
        &mut self,
        request: NodeBlockImport,
        stage: FailedBlockStage,
    ) -> Result<FailedBlockMutation> {
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

        let mut failure_plan = self
            .chain
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

        let mut target = existing.unwrap_or(
            BlockIndexRecord::from_block(&request.block, request.height, header.chainwork)
                .map_err(|error| anyhow::anyhow!("failed to build invalid block index: {error}"))?,
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
        for failed_header in &failure_plan.affected {
            write_record_to_batch(&mut batch, failed_header)
                .map_err(|error| anyhow::anyhow!("failed to stage invalid header: {error}"))?;
            if failed_header.hash == block_hash {
                continue;
            }
            if let Some(mut descendant) = load_block_index_record(&snapshot, &failed_header.hash)? {
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
            }
        }
        write_block_index_to_batch(&mut batch, &target)
            .map_err(|error| anyhow::anyhow!("failed to stage invalid block index: {error}"))?;
        write_raw_block_to_batch(
            &mut batch,
            &RawBlockRecord::from_block(&request.block, request.source),
        )
        .map_err(|error| anyhow::anyhow!("failed to stage invalid block body: {error}"))?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestHeaderHash.as_bytes(),
            failure_plan.best.hash.as_bytes(),
        )?;
        drop(snapshot);
        let affected = failure_plan
            .affected
            .iter()
            .map(|record| record.hash)
            .collect();
        self.store.commit(batch)?;
        self.refresh_indexes()?;
        Ok(FailedBlockMutation {
            record: target,
            affected,
        })
    }

    fn best_chain_activation_plan(&self, candidate: BlockHash) -> Result<Option<NodeReorg>> {
        let snapshot = self.store.snapshot()?;
        let candidate_record = load_block_index_record(&snapshot, &candidate)?
            .ok_or_else(|| anyhow::anyhow!("candidate block index is missing"))?;
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
                .plan_reorg_between(&tip.hash, &candidate)
                .map_err(|error| anyhow::anyhow!("failed to plan best-chain reorg: {error}"))?,
            None => ReorgPlan {
                disconnect: Vec::new(),
                connect: stored_path_from_genesis(&snapshot, candidate)?,
            },
        };
        validate_reorg_plan(&snapshot, active.as_ref(), candidate, &plan)?;

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
        let connect = plan
            .connect
            .iter()
            .map(|hash| node_import_from_stored(&snapshot, hash))
            .collect::<Result<Vec<_>>>()?;

        Ok(Some(NodeReorg {
            disconnect,
            connect,
        }))
    }

    fn recover_best_stored_chain(&mut self) -> Result<Option<NodeReorgMutation>> {
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

        let Some(plan) = self.best_chain_activation_plan(best_header.hash)? else {
            return Ok(None);
        };
        self.apply_reorg(plan).map(Some)
    }

    fn validate_import(&self, request: &NodeBlockImport) -> Result<ValidatedImport> {
        let snapshot = self.store.snapshot()?;
        self.validate_import_against(&snapshot, request)
    }

    /// Preflight only the context-independent portion represented by the
    /// `BlockSyntaxValidated` event. Reorg parents may exist solely in the
    /// pending connect sequence, so parent/state checks remain in the staged
    /// overlay where they can see preceding candidates.
    fn validate_import_syntax(&self, request: &NodeBlockImport) -> Result<()> {
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
        if strict {
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
        self.validate_block_body_for_plan(&request.block, historical_validation)?;
        status.body_syntax_valid = true;

        validate_block_finality(
            &request.block,
            request.height,
            median_time_past.unwrap_or(request.block.header.time),
        )
        .map_err(|error| anyhow::anyhow!("transaction finality validation failed: {error}"))?;

        if strict {
            validate_coinbase_height(&request.block, request.height)
                .map_err(|error| anyhow::anyhow!("coinbase height validation failed: {error}"))?;
        }

        validate_branch_extension(snapshot, request, chainwork, self.network)?;

        Ok(ValidatedImport {
            chainwork,
            status: BlockStatus {
                absolute_finality_valid: true,
                ..status
            },
            historical_validation,
        })
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
            let period = if height % window == 0 {
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
    ) -> Result<NodeBlockMutation> {
        let snapshot = self.store.snapshot()?;
        let generation = next_mining_generation(&snapshot)?;
        let chain_epoch = next_chain_epoch(&snapshot)?;
        let mut batch = self.store.batch();
        let record = self.stage_connect(&snapshot, &mut batch, &request, validated)?;
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
        drop(snapshot);
        self.store.commit(batch)?;
        self.cache_committed_block_records(std::slice::from_ref(&record))?;

        Ok(NodeBlockMutation {
            record,
            mining: self.durable_mining_state()?,
        })
    }

    fn stage_connect<T: ReadSnapshot, B: WriteBatch>(
        &self,
        snapshot: &T,
        batch: &mut B,
        request: &NodeBlockImport,
        validated: ValidatedImport,
    ) -> Result<BlockIndexRecord> {
        validate_active_extension(snapshot, request, validated.chainwork)?;

        let block_hash = request.block.hash();
        let historical_validation = validated.historical_validation;
        let mut status = validated.status;
        let raw_record = RawBlockRecord::from_block(&request.block, request.source);

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
            .map_err(|error| anyhow::anyhow!("failed to stage header index: {error}"))?;
        write_block_index_to_batch(batch, &record)
            .map_err(|error| anyhow::anyhow!("failed to stage block index: {error}"))?;
        write_raw_block_to_batch(batch, &raw_record)
            .map_err(|error| anyhow::anyhow!("failed to stage raw block: {error}"))?;
        write_tx_index_for_block_to_batch(batch, &request.block, request.height)
            .map_err(|error| anyhow::anyhow!("failed to stage tx index: {error}"))?;
        write_canonical_height_to_batch(batch, request.height, block_hash)
            .map_err(|error| anyhow::anyhow!("failed to stage canonical height: {error}"))?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestBlockHash.as_bytes(),
            block_hash.as_bytes(),
        )?;
        stage_best_header_if_more_work(snapshot, batch, block_hash, validated.chainwork)?;
        if let Some(policy) = self.undo_retention_policy {
            stage_due_undo_prune(snapshot, batch, policy, request.height)?;
        }

        Ok(record)
    }

    fn historical_validation_plan_for_block(
        &self,
        height: Height,
        block_hash: BlockHash,
        validation_status: &BlockStatus,
    ) -> Result<HistoricalValidationPlan> {
        let Some(checkpoint) = self.network.checkpoints().last().copied() else {
            return Ok(HistoricalValidationPlan::full());
        };
        if height == 0 || height > checkpoint.height {
            return Ok(HistoricalValidationPlan::full());
        }

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
            height,
            block_hash,
            validation_status,
            candidate_canonical,
            checkpoint_canonical,
            checkpoint_record.as_ref(),
        ))
    }

    fn disconnect_block(&mut self, request: NodeBlockDisconnect) -> Result<NodeBlockMutation> {
        let snapshot = self.store.snapshot()?;
        let generation = next_mining_generation(&snapshot)?;
        let chain_epoch = next_chain_epoch(&snapshot)?;
        let mut batch = self.store.batch();
        let record = self.stage_disconnect(&snapshot, &mut batch, request)?;
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
        drop(snapshot);
        self.store.commit(batch)?;
        self.cache_committed_block_records(std::slice::from_ref(&record))?;

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
    ) -> Result<BlockIndexRecord> {
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
        .map_err(|error| anyhow::anyhow!("failed to stage state disconnect: {error}"))?;
        delete_tx_index_for_block_from_batch(batch, &block)
            .map_err(|error| anyhow::anyhow!("failed to stage tx-index deletion: {error}"))?;
        write_block_index_to_batch(batch, &record)
            .map_err(|error| anyhow::anyhow!("failed to stage block index update: {error}"))?;
        write_record_to_batch(batch, &header_record)
            .map_err(|error| anyhow::anyhow!("failed to stage header index update: {error}"))?;
        delete_canonical_height_from_batch(batch, request.height)
            .map_err(|error| anyhow::anyhow!("failed to stage canonical height delete: {error}"))?;

        if request.height == 0 {
            batch.delete(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())?;
        } else {
            batch.put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                block.header.prev_block.as_bytes(),
            )?;
        }

        Ok(record)
    }

    fn apply_reorg(&mut self, request: NodeReorg) -> Result<NodeReorgMutation> {
        self.apply_reorg_classified(request)
            .map_err(ChainActivationFailure::into_anyhow)
    }

    fn apply_reorg_classified(
        &mut self,
        request: NodeReorg,
    ) -> std::result::Result<NodeReorgMutation, ChainActivationFailure> {
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

        let base = self
            .store
            .snapshot()
            .map_err(anyhow::Error::from)
            .map_err(ChainActivationFailure::Internal)?;
        let original_tip =
            best_block_tip_from_snapshot(&base).map_err(ChainActivationFailure::Internal)?;
        validate_reorg_request_shape(&base, &request, original_tip.as_ref())
            .map_err(ChainActivationFailure::Internal)?;

        let generation = next_mining_generation(&base).map_err(ChainActivationFailure::Internal)?;
        let chain_epoch = next_chain_epoch(&base).map_err(ChainActivationFailure::Internal)?;
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let mut batch = overlay.batch(self.store.batch());
        let mut summary = NodeReorgSummary::default();

        for disconnect in request.disconnect {
            let record = self
                .stage_disconnect(&staged, &mut batch, disconnect)
                .map_err(ChainActivationFailure::Internal)?;
            summary.disconnected.push(record);
        }

        for connect in request.connect {
            let hash = connect.block.hash();
            let validated = self
                .validate_import_against(&staged, &connect)
                .with_context(|| {
                    format!(
                        "failed to revalidate stored block {} at height {}",
                        hash.to_hex(),
                        connect.height
                    )
                })
                .map_err(ChainActivationFailure::Internal)?;
            let record = match self.stage_connect(&staged, &mut batch, &connect, validated) {
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
            summary.connected.push(record);
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
        let batch = batch.into_inner();
        drop(staged);
        drop(base);
        self.store
            .commit(batch)
            .map_err(anyhow::Error::from)
            .map_err(ChainActivationFailure::Internal)?;
        let committed_records = summary
            .disconnected
            .iter()
            .chain(&summary.connected)
            .cloned()
            .collect::<Vec<_>>();
        self.cache_committed_block_records(&committed_records)
            .map_err(ChainActivationFailure::Internal)?;

        Ok(NodeReorgMutation {
            summary,
            mining: self
                .durable_mining_state()
                .map_err(ChainActivationFailure::Internal)?,
        })
    }

    fn refresh_indexes(&mut self) -> Result<()> {
        self.chain = StoredHeaderIndex::new(self.store.clone())
            .map_err(|error| anyhow::anyhow!("failed to refresh header index: {error}"))?;
        self.blocks = StoredBlockIndex::new(self.store.clone())
            .map_err(|error| anyhow::anyhow!("failed to refresh block index: {error}"))?;
        Ok(())
    }

    /// Publish the exact records written by a successful block commit into the
    /// in-memory indexes without rebuilding them from the complete durable
    /// header/block sets. The durable batch is already authoritative here. If
    /// an incremental cache invariant ever rejects a committed record, reload
    /// both indexes as a correctness-first recovery path.
    fn cache_committed_block_records(&mut self, records: &[BlockIndexRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let headers = records
            .iter()
            .map(|record| {
                let block = self
                    .blocks
                    .load_block(&record.hash)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "failed to load committed block {} for cache publication: {error}",
                            record.hash.to_hex()
                        )
                    })?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "committed block {} has no durable body for cache publication",
                            record.hash.to_hex()
                        )
                    })?;
                if block.hash() != record.hash {
                    anyhow::bail!(
                        "committed block body hash {} disagrees with index {}",
                        block.hash().to_hex(),
                        record.hash.to_hex()
                    );
                }
                Ok(HeaderRecord {
                    hash: record.hash,
                    height: record.height,
                    chainwork: record.chainwork,
                    header: block.header,
                    status: record.status.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let incremental = (|| -> Result<()> {
            for header in headers {
                self.chain.cache_record(header).map_err(|error| {
                    anyhow::anyhow!("failed to publish committed header cache record: {error}")
                })?;
            }
            for record in records {
                self.blocks.cache_record(record.clone()).map_err(|error| {
                    anyhow::anyhow!("failed to publish committed block cache record: {error}")
                })?;
            }
            Ok(())
        })();

        if let Err(incremental_error) = incremental {
            tracing::warn!(
                error = %incremental_error,
                records = records.len(),
                "incremental index publication failed; rebuilding durable indexes"
            );
            self.refresh_indexes().with_context(|| {
                format!(
                    "failed to rebuild indexes after incremental publication error: {incremental_error}"
                )
            })?;
        }
        Ok(())
    }

    pub fn compact_name_tree_nodes(&mut self) -> Result<NameTreeCompactionCheckpoint> {
        self.compact_name_tree_nodes_with_interval(None)?
            .ok_or_else(|| anyhow::anyhow!("name-tree compaction requires an active block tip"))
    }

    fn compact_name_tree_nodes_if_due(
        &mut self,
        interval: Height,
    ) -> Result<Option<NameTreeCompactionCheckpoint>> {
        if interval == 0 {
            anyhow::bail!("name-tree compaction startup interval must be non-zero");
        }
        self.compact_name_tree_nodes_with_interval(Some(interval))
    }

    fn compact_name_tree_nodes_with_interval(
        &mut self,
        interval: Option<Height>,
    ) -> Result<Option<NameTreeCompactionCheckpoint>> {
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

        let mut batch = self.store.batch();
        let summary = stage_name_tree_node_compaction(&snapshot, &mut batch)
            .map_err(|error| anyhow::anyhow!("failed to compact durable name tree: {error}"))?;
        let checkpoint = NameTreeCompactionCheckpoint {
            height: tip.height,
            tip: tip.hash,
            summary,
        };
        batch.put(
            ColumnFamily::Snapshots,
            NAME_TREE_COMPACTION_CHECKPOINT_KEY,
            &checkpoint.encode()?,
        )?;
        drop(snapshot);
        self.store.commit(batch)?;
        Ok(Some(checkpoint))
    }

    fn prune_undo_history_to_policy(&mut self) -> Result<()> {
        let policy = self.undo_retention_policy.ok_or_else(|| {
            anyhow::anyhow!("undo retention pruning requested without an active policy")
        })?;
        policy.validate()?;
        let mut changed = false;
        loop {
            let snapshot = self.store.snapshot()?;
            let Some(tip) = best_block_tip_from_snapshot(&snapshot)? else {
                break;
            };
            let Some(target) =
                undo_prune_target(tip.height, policy.prune_after_height, policy.keep_blocks)
            else {
                break;
            };
            let previous = load_undo_pruning_checkpoint(&snapshot)?;
            let start = match previous.as_ref() {
                Some(previous) if previous.pruned_through >= target => break,
                Some(previous) => previous
                    .pruned_through
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("undo-pruning height exhausted"))?,
                None => policy
                    .prune_after_height
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("undo-pruning height exhausted"))?,
            };
            let batch_end = start
                .saturating_add((MAX_UNDO_PRUNES_PER_BATCH - 1) as u32)
                .min(target);
            let mut batch = self.store.batch();
            let mut pruned_undos = previous.as_ref().map_or(0, |state| state.pruned_undos);
            let mut last_hash = None;
            for height in start..=batch_end {
                let (hash, pruned) = stage_prune_undo_height(&snapshot, &mut batch, height)?;
                if pruned {
                    pruned_undos = pruned_undos
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("pruned undo count exhausted"))?;
                }
                last_hash = Some(hash);
            }
            let checkpoint = UndoPruningCheckpoint {
                pruned_through: batch_end,
                block_hash: last_hash.ok_or_else(|| {
                    anyhow::anyhow!("undo-pruning batch contained no active heights")
                })?,
                pruned_undos,
            };
            batch.put(
                ColumnFamily::Snapshots,
                UNDO_PRUNING_CHECKPOINT_KEY,
                &checkpoint.encode(),
            )?;
            drop(snapshot);
            self.store.commit(batch)?;
            changed = true;
        }
        if changed {
            self.refresh_indexes()?;
        }
        Ok(())
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::memory()
    }
}

fn checkpoint_backed_historical_validation_plan(
    network: Network,
    candidate_height: Height,
    candidate_hash: BlockHash,
    candidate_status: &BlockStatus,
    canonical_candidate: Option<BlockHash>,
    canonical_checkpoint: Option<BlockHash>,
    checkpoint_record: Option<&HeaderRecord>,
) -> HistoricalValidationPlan {
    let full = HistoricalValidationPlan::full();
    let Some(checkpoint) = network.checkpoints().last().copied() else {
        return full;
    };
    if candidate_height == 0
        || candidate_height > checkpoint.height
        || !candidate_status.header_context_valid
        || !candidate_status.checkpoint_valid
        || candidate_status.failed
    {
        return full;
    }

    // At the checkpoint itself the strictly validated candidate hash supplies
    // the evidence even when block delivery did not follow headers-first sync.
    // Earlier candidates must be on the same best validated header path as the
    // exact final checkpoint. Two canonical-height lookups make that ancestry
    // proof constant-time without consulting the active block-height index.
    let checkpoint_evidenced = if candidate_height == checkpoint.height {
        candidate_hash == checkpoint.hash
    } else {
        canonical_candidate == Some(candidate_hash)
            && canonical_checkpoint == Some(checkpoint.hash)
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
    HeaderRecord::decode(&bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("failed to decode header record: {error}"))
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
    BlockIndexRecord::decode(&bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("failed to decode block index record: {error}"))
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
) -> Option<Height> {
    let target = tip_height.checked_sub(keep_blocks)?;
    (target > prune_after_height).then_some(target)
}

fn stage_due_undo_prune<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    policy: UndoRetentionPolicy,
    tip_height: Height,
) -> Result<()> {
    policy.validate()?;
    let Some(target) = undo_prune_target(tip_height, policy.prune_after_height, policy.keep_blocks)
    else {
        return Ok(());
    };
    let previous = load_undo_pruning_checkpoint(snapshot)?;
    if previous
        .as_ref()
        .is_some_and(|state| state.pruned_through >= target)
    {
        return Ok(());
    }
    let expected = previous
        .as_ref()
        .map(|state| state.pruned_through.saturating_add(1))
        .unwrap_or_else(|| policy.prune_after_height.saturating_add(1));
    if target != expected {
        anyhow::bail!(
            "undo history requires startup catch-up through height {} before pruning height {target}",
            target.saturating_sub(1)
        );
    }
    let (block_hash, pruned) = stage_prune_undo_height(snapshot, batch, target)?;
    let pruned_undos = previous
        .as_ref()
        .map_or(0, |state| state.pruned_undos)
        .checked_add(u64::from(pruned))
        .ok_or_else(|| anyhow::anyhow!("pruned undo count exhausted"))?;
    let checkpoint = UndoPruningCheckpoint {
        pruned_through: target,
        block_hash,
        pruned_undos,
    };
    batch.put(
        ColumnFamily::Snapshots,
        UNDO_PRUNING_CHECKPOINT_KEY,
        &checkpoint.encode(),
    )?;
    Ok(())
}

fn stage_prune_undo_height<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    height: Height,
) -> Result<(BlockHash, bool)> {
    let hash = read_canonical_hash(snapshot, height)?
        .ok_or_else(|| anyhow::anyhow!("undo-pruning height {height} is not canonical"))?;
    let mut block = load_block_index_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("undo-pruning block index {} is missing", hash.to_hex()))?;
    let mut header = load_header_record(snapshot, &hash)?
        .ok_or_else(|| anyhow::anyhow!("undo-pruning header index {} is missing", hash.to_hex()))?;
    if block.height != height || header.height != height || !block.status.active_chain {
        anyhow::bail!("undo-pruning target at height {height} is not the active block");
    }
    let raw_undo = snapshot.get(ColumnFamily::Undo, hash.as_bytes())?;
    if !block.status.undo_present {
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
        return Ok((hash, false));
    }
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
    block.status.undo_present = false;
    header.status.undo_present = false;
    batch.delete(ColumnFamily::Undo, hash.as_bytes())?;
    write_block_index_to_batch(batch, &block)?;
    write_record_to_batch(batch, &header)?;
    Ok((hash, true))
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

    Ok((
        Arc::new(MiningSnapshot {
            network_id,
            generation,
            tip: HeaderSummary::from_block(&block, record.height),
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

fn stored_path_from_genesis(
    snapshot: &impl ReadSnapshot,
    candidate: BlockHash,
) -> Result<Vec<BlockHash>> {
    let mut reverse = Vec::new();
    let mut seen = HashSet::new();
    let mut current = candidate;

    loop {
        if !seen.insert(current) {
            anyhow::bail!(
                "stored header chain contains a cycle at {}",
                current.to_hex()
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
        let raw = load_raw_block_record(snapshot, hash)?
            .ok_or_else(|| anyhow::anyhow!("connect block body {} is missing", hash.to_hex()))?;
        raw.decode_block()
            .map_err(|error| anyhow::anyhow!("connect block body is corrupt: {error}"))?;

        expected_parent = Some(*hash);
        expected_height = expected_height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("height exhausted"))?;
        parent_work = record.chainwork;
    }

    Ok(())
}

fn node_import_from_stored(
    snapshot: &impl ReadSnapshot,
    hash: &BlockHash,
) -> Result<NodeBlockImport> {
    let record = load_block_index_record(snapshot, hash)?
        .ok_or_else(|| anyhow::anyhow!("stored block index {} is missing", hash.to_hex()))?;
    let raw = load_raw_block_record(snapshot, hash)?
        .ok_or_else(|| anyhow::anyhow!("stored block body {} is missing", hash.to_hex()))?;
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
    let parent = load_block_index_record(snapshot, &parent_hash)?
        .ok_or_else(|| anyhow::anyhow!("block parent index {} is missing", parent_hash.to_hex()))?;
    let expected_height = parent
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("branch height exhausted"))?;
    if request.height != expected_height {
        anyhow::bail!(
            "block height {} does not extend parent height {}",
            request.height,
            parent.height
        );
    }
    if chainwork <= parent.chainwork {
        anyhow::bail!("block chainwork must increase over its parent");
    }
    if load_raw_block_record(snapshot, &parent_hash)?.is_none() {
        anyhow::bail!("block parent body {} is missing", parent_hash.to_hex());
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
    use hns_chain::{read_canonical_hash, BlockIndex, HeaderImport};
    use hns_consensus::{
        block_merkle_root, block_witness_root, ConsensusError, TransactionInputVerifier,
    };
    use hns_primitives::{
        Address, Covenant, CovenantKind, Header, Input, Outpoint, Output, Transaction, Txid,
        Witness,
    };
    use hns_rpc::{JsonRpcRequest, RpcService};
    use hns_state::{
        name_tree_snapshot_pin_key, RejectSpecialCoinbaseIssuance, StateEngine, StateView,
    };
    use hns_store::ReadSnapshot;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    fn historical_route_requires_branch_bound_final_checkpoint_evidence() {
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
                candidate_height,
                candidate_hash,
                &status,
                Some(candidate_hash),
                Some(checkpoint.hash),
                Some(&checkpoint_record),
            ),
            historical
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                candidate_height,
                candidate_hash,
                &status,
                Some(BlockHash::new([0x43; 32])),
                Some(checkpoint.hash),
                Some(&checkpoint_record),
            ),
            full,
            "a candidate on another header branch must fail closed"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                candidate_height,
                candidate_hash,
                &status,
                Some(candidate_hash),
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
                candidate_height,
                candidate_hash,
                &status,
                Some(candidate_hash),
                Some(checkpoint.hash),
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
                candidate_height,
                candidate_hash,
                &unverified,
                Some(candidate_hash),
                Some(checkpoint.hash),
                Some(&checkpoint_record),
            ),
            full,
            "an unverified candidate must fail closed"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint.height,
                checkpoint.hash,
                &status,
                None,
                None,
                None,
            ),
            historical,
            "the strictly validated checkpoint block supplies its own binding"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint.height,
                BlockHash::new([0x45; 32]),
                &status,
                None,
                None,
                None,
            ),
            full,
            "a wrong hash at the final checkpoint must fail closed"
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Mainnet,
                checkpoint.height + 1,
                BlockHash::new([0x44; 32]),
                &status,
                None,
                None,
                None,
            ),
            full
        );
        assert_eq!(
            checkpoint_backed_historical_validation_plan(
                Network::Regtest,
                1,
                candidate_hash,
                &status,
                Some(candidate_hash),
                None,
                None,
            ),
            full,
            "networks without checkpoints never select the shortcut"
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

    fn active_state_shadow_config() -> NodeConfig {
        NodeConfig {
            network: Network::Regtest,
            acknowledge_incomplete_consensus: true,
            shadow_sync: ShadowSyncConfig {
                enabled: true,
                connect_active_state: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..ShadowSyncConfig::default()
            },
            ..NodeConfig::default()
        }
    }

    fn store_fixture_alternate(
        node: &mut NodeService,
        block: Block,
        height: Height,
        chainwork: u64,
    ) -> BlockIndexRecord {
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
    fn strict_mainnet_block_one_keeps_coinbase_finality_and_height_distinct() {
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
        node.shadow_sync_ensure_genesis_header()
            .expect("canonical mainnet genesis header");
        let error = node
            .state
            .validate_import(&NodeBlockImport::from_peer(block, 1))
            .expect_err("the parent block body was not seeded");
        assert!(
            error.to_string().contains("block parent index"),
            "canonical block one must pass strict header, body, finality, and coinbase-height checks before parent-body activation context: {error}"
        );
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
        node.shadow_sync_ensure_genesis_header()
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
        let mut node = NodeService::new(active_state_shadow_config());
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
        let working_root = verify_stored_name_tree_root(&snapshot).expect("working root");
        let committed_root = load_stored_name_tree_commit_root(&snapshot).expect("committed root");
        assert_ne!(working_root, committed_root);
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
        assert_eq!(resulting_commit, working_root);
        drop(snapshot);
        assert_eq!(
            node.observed_mining_snapshot()
                .expect("observed snapshot")
                .expect("active mining snapshot")
                .next_tree_root,
            *working_root.as_bytes()
        );
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
    fn undo_retention_preserves_pinned_roots_and_rejects_deep_reorgs() {
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

        let records = connect_fixture_chain(&mut node, 202, Some(200));
        let checkpoint = node
            .undo_pruning_checkpoint()
            .expect("checkpoint read")
            .expect("checkpoint");
        assert_eq!(checkpoint.pruned_through, 200);
        assert_eq!(checkpoint.block_hash, records[200].hash);
        assert_eq!(checkpoint.pruned_undos, 200);

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
            assert_eq!(
                snapshot
                    .get(ColumnFamily::Undo, record.hash.as_bytes())
                    .expect("undo read")
                    .is_some(),
                retained,
                "height {height}"
            );
        }
        let pin = load_name_tree_snapshot_pins(&snapshot)
            .expect("pins")
            .into_iter()
            .find(|pin| pin.height == 200)
            .expect("height-200 pin");
        assert_ne!(pin.root.as_bytes(), &[0; 32]);
        assert_eq!(pin.block_hash, records[200].hash);
        validate_persisted_name_tree(&snapshot, pin.root).expect("pinned tree before compaction");
        let fork_root = load_header_record(&snapshot, &records[200].hash)
            .expect("fork child header read")
            .expect("fork child header")
            .header
            .tree_root;
        drop(snapshot);

        let compacted = node.compact_name_tree_nodes().expect("compact pruned tree");
        assert!(compacted.summary.retained_roots >= 2);
        let snapshot = store.snapshot().expect("compacted snapshot");
        validate_persisted_name_tree(&snapshot, pin.root).expect("pinned tree after compaction");
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
        assert!(error.to_string().contains("cannot be disabled"), "{error}");
    }

    #[test]
    fn undo_pruning_checkpoint_is_checksummed() {
        let store = StoreHandle::memory();
        NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut raw = UndoPruningCheckpoint {
            pruned_through: 1_001,
            block_hash: BlockHash::new([0x91; 32]),
            pruned_undos: 1,
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
            let active = block_with_commitments(vec![coinbase_transaction()]);
            node.connect_block(NodeBlockImport::fixture(active, 0, 1))
                .expect("connect active block");
            drop(node);
            let name_block =
                block_with_commitments(vec![open_coinbase_transaction(b"persistedstartupnode")]);
            let mut proof_state =
                StoredStateEngine::with_native_authorization_and_verified_name_flags(
                    store.clone(),
                    Network::Regtest,
                    NameFlags::NONE,
                )
                .expect("proof state");
            proof_state
                .connect_block(ConnectBlock {
                    block_hash: name_block.hash(),
                    height: 201,
                    coinbase_maturity: 0,
                    block_reward: 50,
                    block: &name_block,
                })
                .expect("stage authenticated name state");
            drop(proof_state);

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
            assert!(error.to_string().contains("content-addressed"), "{error}");
        }
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

    #[test]
    fn node_apply_reorg_disconnects_then_connects_new_tip() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
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
    fn shadow_active_state_connector_resumes_in_bounded_batches_without_authority() {
        let store = StoreHandle::memory();
        let config = active_state_shadow_config();
        let state = NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("initial state");
        let mut node = NodeService::try_with_state(config.clone(), state).expect("shadow node");

        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(90, 50)]);
        let genesis = store_fixture_alternate(&mut node, genesis, 0, 1);
        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(91, 50)]);
        child.header.prev_block = genesis.hash;
        let child = store_fixture_alternate(&mut node, child, 1, 2);
        assert!(node.state().best_block_tip().expect("active tip").is_none());
        drop(node);

        let state = NodeState::from_store_for_network(store, Network::Regtest).expect("restart");
        let mut restarted = NodeService::try_with_state(config, state).expect("restarted shadow");
        assert!(restarted
            .state()
            .best_block_tip()
            .expect("active tip")
            .is_none());

        let first = restarted
            .shadow_sync_connect_stored_state(1)
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
            .shadow_sync_connect_stored_state(1)
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
    fn shadow_active_state_direct_progress_yields_between_small_atomic_slices() {
        let mut node = NodeService::new(active_state_shadow_config());
        let mut previous = BlockHash::ZERO;
        let mut records = Vec::new();
        for height in 0..10 {
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
            .shadow_sync_connect_stored_state(64)
            .expect("first direct connector slice");
        assert_eq!(
            first.connected,
            shadow_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE
        );
        assert_eq!(first.disconnected, 0);
        assert_eq!(
            node.state()
                .best_block_tip()
                .expect("active tip")
                .expect("first slice tip")
                .hash,
            records[shadow_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE - 1].hash
        );

        let second = node
            .shadow_sync_connect_stored_state(64)
            .expect("second direct connector slice");
        assert_eq!(second.connected, 2);
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

    #[tokio::test]
    async fn shadow_active_state_runtime_updates_scheduler_and_diagnostics() {
        let config = active_state_shadow_config();
        let mut node = NodeService::new(config.clone());
        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(102, 50)]);
        let genesis = store_fixture_alternate(&mut node, genesis, 0, 1);
        let node = Arc::new(tokio::sync::Mutex::new(node));
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
        let diagnostics = Arc::new(tokio::sync::RwLock::new(ShadowSyncDiagnostics {
            enabled: true,
            observation_only: false,
            active_state: true,
            ..ShadowSyncDiagnostics::default()
        }));

        shadow_sync::connect_stored_active_state(
            &node,
            &peers,
            &mut scheduler,
            &mut orphans,
            &diagnostics,
            config.shadow_sync.active_state_connect_batch,
        )
        .await
        .expect("runtime connector");

        assert_eq!(
            scheduler
                .snapshot()
                .active_tip
                .expect("scheduler active tip")
                .hash,
            genesis.hash
        );
        let diagnostics = diagnostics.read().await;
        assert_eq!(diagnostics.connected_blocks, 1);
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

    #[test]
    fn shadow_active_state_connector_reorganizes_a_stored_best_branch() {
        let mut node = NodeService::new(active_state_shadow_config());
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
            .shadow_sync_connect_stored_state(1)
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
            .shadow_sync_connect_stored_state(64)
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
    fn shadow_active_state_reorg_keeps_the_full_configured_atomic_bound() {
        let mut node = NodeService::new(active_state_shadow_config());
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
        for offset in 0..10u32 {
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

        assert!(side.len() > shadow_sync::MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE);
        let outcome = node
            .shadow_sync_connect_stored_state(64)
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
        let config = active_state_shadow_config();
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
            .shadow_sync_connect_stored_state(64)
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
        let mut restarted = NodeService::try_with_state(config, state).expect("restarted shadow");
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
            .shadow_sync_connect_stored_state(64)
            .expect("idempotent connector")
            .contextual_failure
            .is_none());
    }

    #[test]
    fn local_state_fault_does_not_poison_a_stored_branch() {
        let mut node = NodeService::new(active_state_shadow_config());
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
            .shadow_sync_connect_stored_state(64)
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
        let shadow_config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut shadow = NodeService::try_with_state(shadow_config, state).expect("shadow node");

        let genesis = block_with_commitments(vec![coinbase_transaction_with_address(50, 50)]);
        let genesis_record = shadow
            .connect_block(NodeBlockImport::fixture(genesis, 0, 1))
            .expect("genesis");
        let mut active = block_with_commitments(vec![coinbase_transaction_with_address(51, 50)]);
        active.header.prev_block = genesis_record.hash;
        shadow
            .connect_block(NodeBlockImport::fixture(active, 1, 2))
            .expect("active child");

        let mut side = block_with_commitments(vec![coinbase_transaction_with_address(52, 50)]);
        side.header.prev_block = genesis_record.hash;
        let side_hash = side.hash();
        let import = NodeBlockImport::fixture(side, 1, 3);
        let validated = shadow
            .state()
            .validate_import(&import)
            .expect("validate side");
        shadow
            .state_mut()
            .store_validated_alternate(import, validated)
            .expect("persist side before simulated crash");
        drop(shadow);

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
        let shadow = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        assert!(shadow.subscribe_mining_events().is_err());
        assert!(
            !shadow
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
        assert!(validate_node_config(&NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::HsdVerified,
            ..NodeConfig::default()
        })
        .is_err());
        let mut unacknowledged_active_sync = active_state_shadow_config();
        unacknowledged_active_sync.acknowledge_incomplete_consensus = false;
        assert!(validate_node_config(&unacknowledged_active_sync).is_err());

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
        assert!(!authority.consensus_complete);
        assert!(authority.experimental_bypass_active);
        assert!(authority.can_authorize_mining_templates);
        assert!(authority.can_accept_mining_candidates);
    }

    #[test]
    fn mining_templates_require_the_cached_hsd_deployment_version() {
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
            .mining_engine_build_template(request)
            .expect("HSD deployment version template");
        assert_eq!(template.header().version, 0);
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
        assert_eq!(json["authority"]["mode"], "shadow");
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
        assert!(json["active_state_resulting_root"].is_null());
        assert!(json["active_state_resulting_root_height"].is_null());

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
}
