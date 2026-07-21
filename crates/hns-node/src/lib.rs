#![forbid(unsafe_code)]

mod mining_engine;
mod shadow_sync;

pub use mining_engine::{
    MiningEngineConfig, MiningEngineDiagnostics, MiningPublicationAttempt, MiningPublicationResult,
    MiningTemplateRequest,
};
pub use shadow_sync::{ShadowSyncConfig, ShadowSyncDiagnostics};

use std::{
    collections::HashSet,
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
    delete_canonical_height_from_batch, delete_tx_index_for_block_from_batch,
    write_block_index_to_batch, write_canonical_height_to_batch, write_raw_block_to_batch,
    write_record_to_batch, write_tx_index_for_block_to_batch, BlockIndexRecord, BlockStatus,
    ChainTip, HeaderIndex, HeaderRecord, RawBlockRecord, RawBlockSource, ReorgPlan,
    StoredBlockIndex, StoredHeaderIndex,
};
use hns_consensus::{
    expected_next_bits, validate_block_finality, ConsensusParams, DifficultyPoint, HeaderConsensus,
    HeaderParent, HeaderValidationContext, NameFlags, Network, MAX_FUTURE_BLOCK_TIME,
    MEDIAN_TIMESPAN,
};
use hns_mempool::{MemoryMempool, Mempool};
use hns_mining::{
    HeaderSummary, MiningEventHub, MiningGeneration, MiningSnapshot, MiningSubscriptions,
    SolvedMiningCandidate, TemplateCoordinator,
};
use hns_primitives::{Block, BlockHash, Coin, CompactTarget, Height, NameHash, NameState, Uint256};
use hns_rpc::{
    BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcAuthorityInfo, RpcBlockEntry,
    RpcConsensusReadiness, RpcErrorObject, RpcHeaderEntry, RpcMiningEngineInfo, RpcNodeStatus,
    RpcParityInfo, RpcService, RpcSnapshot, RpcTransactionEntry,
};
use hns_state::{
    connect_block_to_batch_with_services, decode_coin, decode_name_state,
    disconnect_block_to_batch, verify_stored_name_tree_root, BlockUndo, ConnectBlock,
    DisconnectBlock, StoredStateEngine,
};
use hns_store::{
    decode_u64, encode_u64, mark_clean_shutdown, mark_unclean_start, open_store,
    was_clean_shutdown, ColumnFamily, DurabilityPolicy, MetaKey, ReadSnapshot, StagingOverlay,
    Store, StoreBackend, StoreConfig, StoreHandle, WriteBatch, SCHEMA_VERSION, STORAGE_PROFILE,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

pub const HSRD_DIAGNOSTIC_API_VERSION: u32 = 3;
pub const HSD_ORACLE_REVISION: &str = "698e252ebc7b5c1dd0a9587e342fdd153d020ae4";

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
        checkpoints_and_deployments: false,
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
        // branch before exposing any mining generation. Shadow mode is
        // observation-only and therefore never mutates the active chain at
        // startup.
        if authority_can_mine(&config) {
            state.recover_best_stored_chain()?;
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
            HeaderConsensus::new(ConsensusParams::for_network(self.config.network))
                .validate_block_body(&connect.block)
                .map_err(|error| anyhow::anyhow!("reorg block body validation failed: {error}"))?;
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
        let alternate_block_count = metadata
            .scan_prefix(ColumnFamily::BlockIndex, b"")
            .context("failed to scan alternate block count")?
            .into_iter()
            .map(|(_, bytes)| {
                BlockIndexRecord::decode(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode block index: {error}"))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|record| !record.status.active_chain)
            .count();
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
            chain_epoch,
            mining_generation: durable.generation,
            alternate_block_count,
            pending_best_chain_activation,
            staged_chain_tip: durable.snapshot.is_some(),
            authoritative_mining_tip: self.mining_events.snapshot().is_some(),
            tip_validation,
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
struct NodeReorgMutation {
    summary: NodeReorgSummary,
    mining: DurableMiningState,
}

#[derive(Clone, Debug)]
pub struct NodeState {
    network: Network,
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
        let durable_name_tree_root = verify_stored_name_tree_root(&snapshot)
            .map_err(|error| anyhow::anyhow!("durable name-tree invariant failed: {error}"))?;
        let active_tip = best_block_tip_from_snapshot(&snapshot)?;
        let best_header = best_header_tip_from_snapshot(&snapshot)?;
        let mut heights = snapshot
            .scan_prefix(ColumnFamily::HeightIndex, b"")
            .context("failed to scan active height index")?;
        heights.sort_by(|left, right| left.0.cmp(&right.0));

        match active_tip.as_ref() {
            None if !heights.is_empty() => {
                anyhow::bail!("active height index exists without a best-block binding")
            }
            None => {
                if durable_name_tree_root.as_bytes() != &[0; 32] {
                    anyhow::bail!(
                        "empty active chain has non-empty durable name-tree root {:?}",
                        durable_name_tree_root
                    );
                }
            }
            Some(tip) => {
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
                let mut expected_previous_tree_root = [0u8; 32];
                let mut active_resulting_tree_root = [0u8; 32];
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
                    if record.height != height || !record.status.active_chain {
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
                    let raw = load_raw_block_record(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!("active block body {} is missing", hash.to_hex())
                    })?;
                    let block = raw.decode_block().map_err(|error| {
                        anyhow::anyhow!("active block body {} is corrupt: {error}", hash.to_hex())
                    })?;
                    if block.hash() != hash || block.header.prev_block != record.prev_hash {
                        anyhow::bail!(
                            "active block body {} disagrees with its index",
                            hash.to_hex()
                        );
                    }
                    if !record.status.undo_present {
                        anyhow::bail!("active block {} is missing undo status", hash.to_hex());
                    }
                    let undo = load_block_undo(&snapshot, &hash)?.ok_or_else(|| {
                        anyhow::anyhow!("active block undo {} is missing", hash.to_hex())
                    })?;
                    if undo.block_hash != hash || undo.height != height {
                        anyhow::bail!(
                            "active block undo {} disagrees with its index",
                            hash.to_hex()
                        );
                    }
                    if *undo.previous_tree_root.as_bytes() != expected_previous_tree_root {
                        anyhow::bail!(
                            "active block {} breaks name-tree root continuity",
                            hash.to_hex()
                        );
                    }
                    if block.header.tree_root != *undo.previous_tree_root.as_bytes() {
                        anyhow::bail!(
                            "active block {} header root disagrees with undo pre-state",
                            hash.to_hex()
                        );
                    }
                    active_resulting_tree_root = *undo.resulting_tree_root.as_bytes();
                    expected_previous_tree_root = active_resulting_tree_root;
                    previous_hash = hash;
                    previous_work = record.chainwork;
                }

                if previous_hash != tip.hash || previous_work != tip.chainwork {
                    anyhow::bail!("best-block binding does not match the active height index tip");
                }
                if durable_name_tree_root.as_bytes() != &active_resulting_tree_root {
                    anyhow::bail!(
                        "durable name-tree root does not match the active tip's resulting root"
                    );
                }
            }
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
        self.refresh_indexes()?;

        Ok(StoredBlockMutation {
            record,
            already_known: false,
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

        HeaderConsensus::new(ConsensusParams::for_network(self.network))
            .validate_block_body(&request.block)
            .map_err(|error| anyhow::anyhow!("block body validation failed: {error}"))?;

        validate_block_finality(
            &request.block,
            request.height,
            median_time_past.unwrap_or(request.block.header.time),
        )
        .map_err(|error| anyhow::anyhow!("transaction finality validation failed: {error}"))?;

        validate_branch_extension(snapshot, request, chainwork, self.network)?;

        Ok(ValidatedImport {
            chainwork,
            status: BlockStatus {
                header_context_valid,
                checkpoint_valid: matches!(request.validation, ImportValidationPolicy::Strict),
                body_present: true,
                body_syntax_valid: true,
                absolute_finality_valid: true,
                ..BlockStatus::default()
            },
        })
    }

    fn expected_bits_for_import<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        request: &NodeBlockImport,
        parent: Option<&HeaderRecord>,
    ) -> Result<u32> {
        let pow = self.network.params().pow;
        let Some(parent) = parent else {
            return Ok(pow.bits);
        };
        let previous = difficulty_point(parent);
        let reset = pow.target_reset
            && request.block.header.time
                > parent
                    .header
                    .time
                    .saturating_add(u64::from(pow.target_spacing).saturating_mul(2));
        if pow.no_retargeting || reset || parent.height < pow.target_window.saturating_add(2) {
            return expected_next_bits(pow, request.block.header.time, previous, None, None)
                .map_err(|error| anyhow::anyhow!("difficulty validation failed: {error}"));
        }

        let last = self.suitable_block(snapshot, parent)?;
        let ancestor_height = parent
            .height
            .checked_sub(pow.target_window)
            .ok_or_else(|| anyhow::anyhow!("difficulty ancestor height underflow"))?;
        let ancestor = self.ancestor(snapshot, parent.clone(), ancestor_height)?;
        let first = self.suitable_block(snapshot, &ancestor)?;
        expected_next_bits(
            pow,
            request.block.header.time,
            previous,
            Some(difficulty_point(&first)),
            Some(difficulty_point(&last)),
        )
        .map_err(|error| anyhow::anyhow!("difficulty validation failed: {error}"))
    }

    fn suitable_block<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        tip: &HeaderRecord,
    ) -> Result<HeaderRecord> {
        let mut z = tip.clone();
        let mut y = self.header_parent(snapshot, &z)?;
        let mut x = self.header_parent(snapshot, &y)?;
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

    fn median_time_past<T: ReadSnapshot>(&self, snapshot: &T, tip: &HeaderRecord) -> Result<u64> {
        let mut times = Vec::with_capacity(MEDIAN_TIMESPAN);
        let mut record = tip.clone();
        loop {
            times.push(record.header.time);
            if times.len() == MEDIAN_TIMESPAN || record.height == 0 {
                break;
            }
            record = self.header_parent(snapshot, &record)?;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    fn ancestor<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        mut record: HeaderRecord,
        height: Height,
    ) -> Result<HeaderRecord> {
        if height > record.height {
            anyhow::bail!("difficulty ancestor is above the starting header");
        }
        while record.height > height {
            record = self.header_parent(snapshot, &record)?;
        }
        if record.height != height {
            anyhow::bail!("difficulty ancestor chain is not contiguous");
        }
        Ok(record)
    }

    fn header_parent<T: ReadSnapshot>(
        &self,
        snapshot: &T,
        record: &HeaderRecord,
    ) -> Result<HeaderRecord> {
        if record.height == 0 {
            anyhow::bail!("genesis header has no parent");
        }
        let parent = load_header_record(snapshot, &record.header.prev_block)?
            .ok_or_else(|| anyhow::anyhow!("difficulty parent header is missing"))?;
        if parent.height.checked_add(1) != Some(record.height)
            || parent.hash != record.header.prev_block
        {
            anyhow::bail!("difficulty parent linkage is invalid");
        }
        Ok(parent)
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
        self.refresh_indexes()?;

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
        let mut status = validated.status;
        let raw_record = RawBlockRecord::from_block(&request.block, request.source);

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
            self.state_engine.services(),
        )
        .map_err(|error| anyhow::anyhow!("failed to stage state update: {error}"))?;

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

        Ok(record)
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
        self.refresh_indexes()?;

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

        if block.header.tree_root != *undo.previous_tree_root.as_bytes() {
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
        if request.disconnect.is_empty() && request.connect.is_empty() {
            return Ok(NodeReorgMutation {
                summary: NodeReorgSummary::default(),
                mining: self.durable_mining_state()?,
            });
        }
        if request.connect.is_empty() {
            anyhow::bail!("a best-chain reorganization must connect a replacement tip");
        }

        let base = self.store.snapshot()?;
        let original_tip = best_block_tip_from_snapshot(&base)?;
        validate_reorg_request_shape(&base, &request, original_tip.as_ref())?;

        let generation = next_mining_generation(&base)?;
        let chain_epoch = next_chain_epoch(&base)?;
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let mut batch = overlay.batch(self.store.batch());
        let mut summary = NodeReorgSummary::default();

        for disconnect in request.disconnect {
            let record = self.stage_disconnect(&staged, &mut batch, disconnect)?;
            summary.disconnected.push(record);
        }

        for connect in request.connect {
            let validated = self.validate_import_against(&staged, &connect)?;
            let record = self.stage_connect(&staged, &mut batch, &connect, validated)?;
            summary.connected.push(record);
        }

        let final_tip = best_block_tip_from_snapshot(&staged)?
            .ok_or_else(|| anyhow::anyhow!("reorganization produced an empty active chain"))?;
        if let Some(original_tip) = &original_tip {
            if final_tip.chainwork <= original_tip.chainwork {
                anyhow::bail!(
                    "replacement tip chainwork {} does not exceed active tip chainwork {}",
                    final_tip.chainwork.to_fixed_hex(),
                    original_tip.chainwork.to_fixed_hex()
                );
            }
        }
        let connected_tip = summary
            .connected
            .last()
            .ok_or_else(|| anyhow::anyhow!("reorganization connected no replacement block"))?;
        if connected_tip.hash != final_tip.hash {
            anyhow::bail!("reorganization final tip does not match its last connected block");
        }

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
        let batch = batch.into_inner();
        drop(staged);
        drop(base);
        self.store.commit(batch)?;
        self.refresh_indexes()?;

        Ok(NodeReorgMutation {
            summary,
            mining: self.durable_mining_state()?,
        })
    }

    fn refresh_indexes(&mut self) -> Result<()> {
        self.chain = StoredHeaderIndex::new(self.store.clone())
            .map_err(|error| anyhow::anyhow!("failed to refresh header index: {error}"))?;
        self.blocks = StoredBlockIndex::new(self.store.clone())
            .map_err(|error| anyhow::anyhow!("failed to refresh block index: {error}"))?;
        Ok(())
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::memory()
    }
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
        .get(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())
        .context("failed to read durable mining name-tree root")?
        .ok_or_else(|| anyhow::anyhow!("durable mining name-tree root is missing"))?;
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
    use hns_chain::{read_canonical_hash, HeaderImport};
    use hns_consensus::{block_merkle_root, block_witness_root};
    use hns_primitives::{
        Address, Covenant, CovenantKind, Header, Input, Outpoint, Output, Transaction, Txid,
        Witness,
    };
    use hns_rpc::{JsonRpcRequest, RpcService};
    use hns_state::StateView;
    use hns_store::ReadSnapshot;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    fn experimental_authority_config() -> NodeConfig {
        NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::NativeExperimental,
            acknowledge_incomplete_consensus: true,
            ..NodeConfig::default()
        }
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

        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(12, 50)]);
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
