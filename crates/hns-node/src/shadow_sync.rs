use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    routing::{get, post},
    Json, Router,
};
use hns_chain::{BlockIndexRecord, ChainTip, HeaderImport, HeaderIndex, HeaderRecord};
use hns_consensus::{
    block_merkle_root, block_witness_root, ConsensusParams, HeaderConsensus, HeaderParent,
    HeaderValidationContext, MAX_FUTURE_BLOCK_TIME,
};
use hns_mempool::Admission;
use hns_p2p::{
    Inventory, InventoryKind, LivePeerConfig, LivePeerManager, LocatorPacket, OutboundPriority,
    Packet, PeerDirection, PeerEvent, PeerId, PeerSnapshot,
};
use hns_primitives::{Block, BlockHash, Header, Height, Txid};
use hns_rpc::{BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcService};
use hns_store::{mark_clean_shutdown, Store};
use hns_sync::{
    spawn_validation_pipeline, BoundedOrphanPool, OrderedValidationResult, OrphanLimits,
    OrphanSnapshot, StatelessBlockValidator, StoredSyncCheckpoint, SyncAction, SyncCheckpoint,
    SyncLimits, SyncScheduler, SyncSnapshot, ValidationFailureKind, ValidationRejection,
    ValidationRequest, ValidationSubmitter,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch, Mutex, RwLock},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};

use super::{
    current_unix_time, json_rpc_error, load_header_record, AuthorityMode, ChainActivationFailure,
    FailedBlockMutation, FailedBlockStage, HeaderSummary, NodeBlockImport, NodeReorg, NodeService,
    ShutdownSignal,
};

const MAX_LOCATOR_ENTRIES: usize = 32;
const MAX_SERVED_HEADERS: usize = hns_p2p::MAX_HEADERS;
const MAX_GETDATA_ITEMS: usize = 1_024;
const LOCAL_ORPHAN_PEER: PeerId = PeerId(0);
const MAX_RECONNECT_DELAY_SECONDS: u64 = 60;
const MAX_SHADOW_SYNC_PEERS: usize = 256;
const MAX_SHADOW_SYNC_VALIDATION_WORKERS: usize = 128;
const MAX_SHADOW_SYNC_VALIDATION_QUEUE: usize = 8_192;
const MAX_SHADOW_SYNC_ORPHAN_BLOCKS: usize = 8_192;
const MAX_SHADOW_SYNC_ORPHAN_BYTES: usize = 1024 * 1024 * 1024;
const MAX_ACTIVE_STATE_CONNECT_BATCH: usize = 1_024;
pub(super) const MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE: usize = 8;
const MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE: usize = 64;
const MIN_SHADOW_SYNC_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowSyncConfig {
    pub enabled: bool,
    pub connect_active_state: bool,
    pub active_state_connect_batch: usize,
    pub listen: Option<SocketAddr>,
    pub connect: Vec<SocketAddr>,
    pub maximum_inbound: usize,
    pub maximum_outbound: usize,
    pub validation_workers: usize,
    pub validation_queue: usize,
    pub orphan_blocks: usize,
    pub orphan_bytes: usize,
    pub poll_interval: Duration,
}

impl Default for ShadowSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            connect_active_state: false,
            active_state_connect_batch: 288,
            listen: None,
            connect: Vec::new(),
            maximum_inbound: 32,
            maximum_outbound: 8,
            validation_workers: 4,
            validation_queue: 128,
            orphan_blocks: 1_024,
            orphan_bytes: 64 * 1024 * 1024,
            poll_interval: Duration::from_millis(250),
        }
    }
}

impl ShadowSyncConfig {
    pub fn validate(&self, authority_mode: AuthorityMode) -> Result<()> {
        if self.connect_active_state && !self.enabled {
            anyhow::bail!("active-state synchronization requires shadow sync to be enabled");
        }
        if !self.enabled {
            return Ok(());
        }
        if !matches!(
            authority_mode,
            AuthorityMode::Disabled | AuthorityMode::Shadow
        ) {
            anyhow::bail!(
                "Shadow sync live P2P is non-authoritative and requires disabled or shadow authority mode"
            );
        }
        if self.active_state_connect_batch == 0
            || self.active_state_connect_batch > MAX_ACTIVE_STATE_CONNECT_BATCH
        {
            anyhow::bail!(
                "active-state connector batch {} must be within 1..={MAX_ACTIVE_STATE_CONNECT_BATCH}",
                self.active_state_connect_batch
            );
        }
        if self.listen.is_none() && self.connect.is_empty() {
            anyhow::bail!(
                "Shadow sync requires an inbound listener, at least one explicit outbound peer, or both"
            );
        }
        if self.listen.is_some() && self.maximum_inbound == 0 {
            anyhow::bail!("Shadow sync listener requires a non-zero maximum-inbound value");
        }
        if !self.connect.is_empty() && self.maximum_outbound == 0 {
            anyhow::bail!("Shadow sync outbound peers require a non-zero maximum-outbound value");
        }
        if self.connect.len() > self.maximum_outbound {
            anyhow::bail!(
                "{} configured outbound peers exceed the maximum-outbound value {}",
                self.connect.len(),
                self.maximum_outbound
            );
        }
        if self.validation_workers == 0 || self.validation_queue == 0 {
            anyhow::bail!("Shadow sync validation workers and queue must be non-zero");
        }
        if self.validation_workers > MAX_SHADOW_SYNC_VALIDATION_WORKERS {
            anyhow::bail!(
                "Shadow sync validation workers {} exceed the hard limit {}",
                self.validation_workers,
                MAX_SHADOW_SYNC_VALIDATION_WORKERS
            );
        }
        if self.validation_queue > MAX_SHADOW_SYNC_VALIDATION_QUEUE {
            anyhow::bail!(
                "Shadow sync validation queue {} exceeds the hard limit {}",
                self.validation_queue,
                MAX_SHADOW_SYNC_VALIDATION_QUEUE
            );
        }
        if self.orphan_blocks == 0 || self.orphan_bytes == 0 {
            anyhow::bail!("Shadow sync orphan bounds must be non-zero");
        }
        if self.orphan_blocks > MAX_SHADOW_SYNC_ORPHAN_BLOCKS {
            anyhow::bail!(
                "Shadow sync orphan block limit {} exceeds the hard limit {}",
                self.orphan_blocks,
                MAX_SHADOW_SYNC_ORPHAN_BLOCKS
            );
        }
        if self.orphan_bytes > MAX_SHADOW_SYNC_ORPHAN_BYTES {
            anyhow::bail!(
                "Shadow sync orphan byte limit {} exceeds the hard limit {}",
                self.orphan_bytes,
                MAX_SHADOW_SYNC_ORPHAN_BYTES
            );
        }
        if self.poll_interval < MIN_SHADOW_SYNC_POLL_INTERVAL {
            anyhow::bail!(
                "Shadow sync poll interval must be at least {} ms",
                MIN_SHADOW_SYNC_POLL_INTERVAL.as_millis()
            );
        }
        let maximum_peers = self
            .maximum_inbound
            .checked_add(self.maximum_outbound)
            .ok_or_else(|| anyhow::anyhow!("Shadow sync peer limits overflow usize"))?;
        if maximum_peers > MAX_SHADOW_SYNC_PEERS {
            anyhow::bail!(
                "Shadow sync total peer limit {maximum_peers} exceeds the hard limit {MAX_SHADOW_SYNC_PEERS}"
            );
        }

        let mut unique = HashSet::with_capacity(self.connect.len());
        for address in &self.connect {
            if !unique.insert(*address) {
                anyhow::bail!("duplicate shadow-sync outbound peer {address}");
            }
            if self.listen == Some(*address) {
                anyhow::bail!("Shadow-sync outbound peer {address} is the configured listener");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowSyncDiagnostics {
    pub enabled: bool,
    pub observation_only: bool,
    pub active_state: bool,
    /// Opaque process-local identifier used only to correlate qualification
    /// observations across runtime restarts.
    pub runtime_instance: String,
    pub listen: Option<SocketAddr>,
    pub configured_outbound: Vec<SocketAddr>,
    pub outbound_connected: usize,
    pub outbound_connecting: usize,
    pub outbound_reconnect_attempts: u64,
    pub started_at: u64,
    pub peers: Vec<PeerSnapshot>,
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
    pub reorganizations: u64,
    pub contextual_failed_bodies: u64,
    pub received_transactions: u64,
    pub served_transactions: u64,
    pub rejected_transactions: u64,
    pub served_mempool_inventories: u64,
    pub rejected_messages: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
struct HnsBodyValidator {
    consensus: HeaderConsensus,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ActiveStateConnectOutcome {
    pub(super) connected: usize,
    pub(super) disconnected: usize,
    pub(super) contextual_failure: Option<FailedBlockMutation>,
}

impl HnsBodyValidator {
    fn new(network: hns_consensus::Network) -> Self {
        Self {
            consensus: HeaderConsensus::new(ConsensusParams::for_network(network)),
        }
    }
}

impl StatelessBlockValidator for HnsBodyValidator {
    fn validate(
        &self,
        block: &Block,
        _height: Height,
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
        self.consensus
            .validate_block_body(block)
            .map(|_| ())
            .map_err(|error| ValidationRejection::invalid_block(error.to_string()))
    }
}

#[derive(Clone, Debug)]
struct ReconnectState {
    connected: bool,
    connecting: bool,
    failures: u32,
    next_attempt: Instant,
}

impl ReconnectState {
    fn new(now: Instant) -> Self {
        Self {
            connected: false,
            connecting: false,
            failures: 0,
            next_attempt: now,
        }
    }

    fn connected(&mut self, now: Instant) {
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

impl NodeService {
    pub async fn run_shadow_sync_until_shutdown(self, shutdown: ShutdownSignal) -> Result<()> {
        self.config
            .shadow_sync
            .validate(self.config.authority_mode)?;
        if !self.config.shadow_sync.enabled {
            return self.run_rpc_until_shutdown(shutdown).await;
        }

        let shadow_sync_config = self.config.shadow_sync.clone();
        let rpc_bind = self.config.rpc_bind;
        let network = self.config.network;
        let store = self.state.store.clone();
        let node = Arc::new(Mutex::new(self));

        {
            let mut node = node.lock().await;
            node.shadow_sync_ensure_genesis_header()?;
        }

        let checkpoint_store = StoredSyncCheckpoint::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize sync checkpoint: {error}"))?;
        let durable_checkpoint = checkpoint_store
            .load()
            .map_err(|error| anyhow::anyhow!("failed to load sync checkpoint: {error}"))?;
        let scheduler_now = StdInstant::now();
        let reconnect_now = Instant::now();
        let maximum_peers = shadow_sync_config
            .maximum_inbound
            .checked_add(shadow_sync_config.maximum_outbound)
            .ok_or_else(|| anyhow::anyhow!("Shadow sync peer limits overflow usize"))?;
        let sync_limits = SyncLimits {
            maximum_peers,
            ..SyncLimits::default()
        };
        let mut scheduler = match durable_checkpoint.as_ref() {
            Some(checkpoint) => SyncScheduler::restore(sync_limits, scheduler_now, checkpoint),
            None => SyncScheduler::new(sync_limits, scheduler_now),
        }
        .map_err(|error| anyhow::anyhow!("failed to initialize sync scheduler: {error}"))?;

        let (best_header, active_tip, stored_tip) = {
            let node = node.lock().await;
            let best_header = node.shadow_sync_best_header_tip()?;
            let active_tip = node.shadow_sync_active_tip()?;
            let stored_tip = node.shadow_sync_contiguous_body_tip(
                durable_checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.stored_tip.as_ref()),
            )?;
            (best_header, active_tip, stored_tip)
        };
        scheduler.set_best_header(best_header);
        scheduler.set_active_tip(active_tip.clone());
        scheduler.set_stored_tip(stored_tip);

        let mut peer_config = LivePeerConfig::for_network(network);
        peer_config.maximum_inbound = shadow_sync_config.maximum_inbound;
        peer_config.maximum_outbound = shadow_sync_config.maximum_outbound;
        let (peers, mut peer_events) = LivePeerManager::new(peer_config)
            .map_err(|error| anyhow::anyhow!("failed to initialize live peers: {error}"))?;
        peers.set_local_height(active_tip.as_ref().map_or(0, |tip| tip.height));

        {
            let node = node.lock().await;
            node.shadow_sync_queue_missing_canonical_bodies(&mut scheduler)?;
        }

        let mut orphan_pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: shadow_sync_config.orphan_blocks,
            maximum_bytes: shadow_sync_config.orphan_bytes,
        })
        .map_err(|error| anyhow::anyhow!("failed to initialize orphan pool: {error}"))?;
        let (validation, mut validated) = spawn_validation_pipeline(
            Arc::new(HnsBodyValidator::new(network)),
            shadow_sync_config.validation_workers,
            shadow_sync_config.validation_queue,
        )
        .map_err(|error| anyhow::anyhow!("failed to initialize validation pipeline: {error}"))?;

        let initial_sequence = durable_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.sequence);
        let diagnostics = Arc::new(RwLock::new(ShadowSyncDiagnostics {
            enabled: true,
            observation_only: !shadow_sync_config.connect_active_state,
            active_state: shadow_sync_config.connect_active_state,
            runtime_instance: runtime_instance_id(),
            listen: shadow_sync_config.listen,
            configured_outbound: shadow_sync_config.connect.clone(),
            started_at: unix_time(),
            sync: scheduler.snapshot(),
            orphans: orphan_pool.snapshot(),
            checkpoint_sequence: initial_sequence,
            ..ShadowSyncDiagnostics::default()
        }));

        if shadow_sync_config.connect_active_state {
            connect_stored_active_state(
                &node,
                &peers,
                &mut scheduler,
                &mut orphan_pool,
                &diagnostics,
                shadow_sync_config.active_state_connect_batch,
            )
            .await
            .context("failed to resume active-state synchronization")?;
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let rpc_listener = TcpListener::bind(rpc_bind)
            .await
            .with_context(|| format!("failed to bind RPC listener on {rpc_bind}"))?;
        let rpc_task = tokio::spawn(serve_shadow_sync_rpc(
            rpc_listener,
            Arc::clone(&node),
            Arc::clone(&diagnostics),
            shutdown_rx.clone(),
        ));

        let listener_task = if let Some(address) = shadow_sync_config.listen {
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

        let mut reconnects = shadow_sync_config
            .connect
            .iter()
            .copied()
            .map(|address| (address, ReconnectState::new(reconnect_now)))
            .collect::<HashMap<_, _>>();
        let (connect_results_tx, mut connect_results_rx) =
            mpsc::channel::<ConnectAttemptResult>(shadow_sync_config.connect.len().max(1));

        tracing::info!(
            rpc = %rpc_bind,
            p2p = ?shadow_sync_config.listen,
            outbound = shadow_sync_config.connect.len(),
            "hsrd shadow-sync runtime started"
        );

        let mut checkpoint_sequence = initial_sequence;
        let mut poll = tokio::time::interval(shadow_sync_config.poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        poll.tick().await;
        let mut shutdown_wait = Box::pin(shutdown.wait());
        let mut terminal_error: Option<anyhow::Error> = None;

        loop {
            tokio::select! {
                _ = &mut shutdown_wait => break,
                _ = poll.tick() => {
                    if rpc_task.is_finished() {
                        let message = "Shadow sync RPC task terminated unexpectedly".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    }
                    if listener_task.as_ref().is_some_and(|task| task.is_finished()) {
                        let message = "Shadow sync P2P listener terminated unexpectedly".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    }

                    if shadow_sync_config.connect_active_state {
                        if let Err(error) = connect_stored_active_state(
                            &node,
                            &peers,
                            &mut scheduler,
                            &mut orphan_pool,
                            &diagnostics,
                            shadow_sync_config.active_state_connect_batch,
                        )
                        .await
                        {
                            let error = error.context("active-state synchronization failed");
                            record_error(&diagnostics, error.to_string()).await;
                            terminal_error = Some(error);
                            break;
                        }
                    }

                    let queue_result = {
                        let node = node.lock().await;
                        node.shadow_sync_queue_missing_canonical_bodies(&mut scheduler)
                    };
                    if let Err(error) = queue_result {
                        let error = error.context(
                            "failed to refresh canonical block-body work queue",
                        );
                        record_error(&diagnostics, error.to_string()).await;
                        terminal_error = Some(error);
                        break;
                    }
                    let attempts = spawn_due_connections(
                        &mut reconnects,
                        &peers,
                        &connect_results_tx,
                        Instant::now(),
                    );
                    if attempts > 0 {
                        update_diagnostics(&diagnostics, |state| {
                            state.outbound_reconnect_attempts = state
                                .outbound_reconnect_attempts
                                .saturating_add(attempts as u64);
                        })
                        .await;
                    }

                    let locator_result = {
                        let node = node.lock().await;
                        node.shadow_sync_block_locator(MAX_LOCATOR_ENTRIES)
                    };
                    let locator = match locator_result {
                        Ok(locator) => locator,
                        Err(error) => {
                            let error = error.context("failed to build synchronization locator");
                            record_error(&diagnostics, error.to_string()).await;
                            terminal_error = Some(error);
                            break;
                        }
                    };
                    let actions = scheduler.poll(StdInstant::now(), &locator);
                    for action in actions {
                        if let Err(error) = apply_sync_action(
                            action,
                            &peers,
                            &checkpoint_store,
                            &scheduler,
                            &mut checkpoint_sequence,
                        )
                        .await
                        {
                            record_error(&diagnostics, error.to_string()).await;
                        }
                    }
                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        checkpoint_sequence,
                    )
                    .await;
                }
                result = connect_results_rx.recv() => {
                    let Some(result) = result else {
                        let message = "outbound connection result channel closed".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    };
                    handle_connect_attempt_result(result, &mut reconnects, &diagnostics).await;
                }
                event = peer_events.recv() => {
                    let Some(event) = event else {
                        let message = "peer event channel closed".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    };
                    // Header batches yield after each durable import slice.
                    // Race that cooperative work against shutdown so an HSD
                    // peer cannot keep SIGINT behind a full 2,000-header batch.
                    let handled = tokio::select! {
                        _ = &mut shutdown_wait => None,
                        result = handle_peer_event(
                            event,
                            &node,
                            &peers,
                            &validation,
                            &mut scheduler,
                            &mut reconnects,
                            &diagnostics,
                        ) => Some(result),
                    };
                    let Some(handled) = handled else {
                        break;
                    };
                    if let Err(error) = handled {
                        record_error(&diagnostics, error.to_string()).await;
                    }
                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        checkpoint_sequence,
                    )
                    .await;
                }
                result = validated.recv() => {
                    let Some(result) = result else {
                        let message = "validation result channel closed".to_owned();
                        record_error(&diagnostics, message.clone()).await;
                        terminal_error = Some(anyhow::anyhow!(message));
                        break;
                    };
                    if let Err(error) = handle_validation_result(
                        result,
                        &node,
                        &peers,
                        &validation,
                        &mut scheduler,
                        &mut orphan_pool,
                        &diagnostics,
                    )
                    .await
                    {
                        record_error(&diagnostics, error.to_string()).await;
                    }
                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        checkpoint_sequence,
                    )
                    .await;
                }
            }
        }

        checkpoint_sequence = checkpoint_sequence.saturating_add(1);
        if let Err(error) = persist_checkpoint(&checkpoint_store, &scheduler, checkpoint_sequence) {
            record_error(&diagnostics, error.to_string()).await;
            if terminal_error.is_none() {
                terminal_error = Some(error);
            }
        }
        peers.disconnect_all().await;
        let _ = shutdown_tx.send(true);

        let rpc_result = await_task("RPC", rpc_task).await;
        let listener_result = match listener_task {
            Some(task) => await_p2p_task("P2P listener", task).await,
            None => Ok(()),
        };

        if terminal_error.is_none() && rpc_result.is_ok() && listener_result.is_ok() {
            mark_clean_shutdown(&store)
                .map_err(|error| anyhow::anyhow!("failed to mark node store clean: {error}"))?;
        }
        if let Some(error) = terminal_error {
            return Err(error);
        }
        rpc_result?;
        listener_result?;
        tracing::info!("hsrd shadow-sync runtime stopped");
        Ok(())
    }

    fn shadow_sync_ensure_genesis_header(&mut self) -> Result<HeaderRecord> {
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
        self.state
            .chain
            .import_header(HeaderImport {
                header,
                height: 0,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .map_err(|error| anyhow::anyhow!("failed to persist genesis header: {error}"))
    }

    fn shadow_sync_import_headers(&mut self, headers: Vec<Header>) -> Result<Vec<HeaderRecord>> {
        if headers.len() > hns_p2p::MAX_HEADERS {
            anyhow::bail!("peer sent too many headers: {}", headers.len());
        }

        let mut imported = Vec::with_capacity(headers.len());
        for header in headers {
            let hash = header.hash();
            if let Some(record) = self
                .state
                .chain
                .load_record(&hash)
                .map_err(|error| anyhow::anyhow!("failed to load known header: {error}"))?
            {
                imported.push(record);
                continue;
            }

            let snapshot = self.state.store.snapshot()?;
            let parent = if header == self.config.network.params().genesis_header() {
                None
            } else {
                Some(
                    load_header_record(&snapshot, &header.prev_block)?.ok_or_else(|| {
                        anyhow::anyhow!("missing header parent {}", header.prev_block.to_hex())
                    })?,
                )
            };
            let height = parent
                .as_ref()
                .map_or(0, |record| record.height.saturating_add(1));
            let median_time_past = parent
                .as_ref()
                .map(|record| self.state.median_time_past(&snapshot, record))
                .transpose()?;
            let dummy = NodeBlockImport::from_peer(
                Block {
                    header: header.clone(),
                    transactions: Vec::new(),
                },
                height,
            );
            let expected_bits =
                self.state
                    .expected_bits_for_import(&snapshot, &dummy, parent.as_ref())?;
            let maximum_time = current_unix_time()?.saturating_add(MAX_FUTURE_BLOCK_TIME);
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
                .map_err(|error| anyhow::anyhow!("header validation failed: {error}"))?;
            drop(snapshot);

            let record = self
                .state
                .chain
                .import_header(HeaderImport {
                    header,
                    height,
                    verify_pow: !is_canonical_genesis,
                    checkpoint_valid: true,
                })
                .map_err(|error| anyhow::anyhow!("failed to persist header: {error}"))?;
            imported.push(record);
        }
        Ok(imported)
    }

    fn shadow_sync_best_header_tip(&self) -> Result<Option<ChainTip>> {
        self.state
            .chain
            .best_tip()
            .map_err(|error| anyhow::anyhow!("failed to read best header: {error}"))
    }

    fn shadow_sync_active_tip(&self) -> Result<Option<ChainTip>> {
        self.state.best_block_tip()
    }

    fn shadow_sync_has_block(&self, hash: &BlockHash) -> Result<bool> {
        self.state
            .blocks
            .load_raw_block(hash)
            .map(|block| block.is_some())
            .map_err(|error| anyhow::anyhow!("failed to read block availability: {error}"))
    }

    fn shadow_sync_header_record(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>> {
        self.state
            .chain
            .load_record(hash)
            .map_err(|error| anyhow::anyhow!("failed to load header: {error}"))
    }

    fn shadow_sync_block(&self, hash: &BlockHash) -> Result<Option<Block>> {
        self.state
            .blocks
            .load_block(hash)
            .map_err(|error| anyhow::anyhow!("failed to load block: {error}"))
    }

    fn shadow_sync_store_shadow_block(
        &mut self,
        block: Block,
        height: Height,
    ) -> Result<BlockIndexRecord> {
        let request = NodeBlockImport::from_peer(block, height);
        let validated = self.state.validate_import(&request)?;
        let stored = self.state.store_validated_alternate(request, validated)?;
        Ok(stored.record)
    }

    fn shadow_sync_store_failed_block(
        &mut self,
        block: Block,
        height: Height,
    ) -> Result<super::FailedBlockMutation> {
        self.state.store_failed_block(
            NodeBlockImport::from_peer(block, height),
            FailedBlockStage::BodySyntax,
        )
    }

    pub(super) fn shadow_sync_connect_stored_state(
        &mut self,
        maximum_connect: usize,
    ) -> Result<ActiveStateConnectOutcome> {
        if maximum_connect == 0 || maximum_connect > MAX_ACTIVE_STATE_CONNECT_BATCH {
            anyhow::bail!(
                "active-state connector batch {maximum_connect} is outside 1..={MAX_ACTIVE_STATE_CONNECT_BATCH}"
            );
        }

        let Some(stored_tip) = self.shadow_sync_contiguous_body_tip(None)? else {
            return Ok(ActiveStateConnectOutcome::default());
        };
        let active_tip = self.shadow_sync_active_tip()?;
        if active_tip.as_ref() == Some(&stored_tip) {
            return Ok(ActiveStateConnectOutcome::default());
        }
        // Direct IBD progress does not require a reorganization-sized atomic
        // transaction. Keep each supervisor slice small enough to return to
        // the shutdown/network select loop promptly. A divergent best-work
        // branch still uses the operator's full configured bound below so its
        // disconnect/connect transition remains one atomic commit.
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
                        return Ok(ActiveStateConnectOutcome::default());
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

        let Some(mut activation) = self.state.best_chain_activation_plan(candidate_hash)? else {
            return Ok(ActiveStateConnectOutcome::default());
        };
        if activation.connect.len() > maximum_connect {
            activation.connect.truncate(maximum_connect);
            let candidate = activation
                .connect
                .last()
                .ok_or_else(|| anyhow::anyhow!("bounded connector plan has no candidate"))?;
            let candidate_record = self
                .state
                .load_block_record(&candidate.block.hash())?
                .ok_or_else(|| anyhow::anyhow!("bounded connector candidate index is missing"))?;
            if active_tip
                .as_ref()
                .is_some_and(|active| candidate_record.chainwork <= active.chainwork)
            {
                anyhow::bail!(
                    "active-state reorganization needs more than {maximum_connect} replacement blocks before exceeding the active tip"
                );
            }
        }

        for connect in &activation.connect {
            let summary = HeaderSummary::from_block(&connect.block, connect.height);
            self.mining_events.candidate_tip_seen(summary.clone());
            self.mining_events.block_syntax_validated(summary);
        }

        let is_reorg = !activation.disconnect.is_empty();
        if is_reorg {
            self.mining_events
                .reorg_started(activation.disconnect.len(), activation.connect.len());
        }
        match self.state.apply_reorg_classified(NodeReorg {
            disconnect: activation.disconnect,
            connect: activation.connect,
        }) {
            Ok(reorg) => {
                let mempool_generation = self.mining_engine_clear_mempool_for_chain_transition();
                self.publish_durable_mining_state(&reorg.mining)?;
                self.mining_engine_publish_mempool_reconciled(
                    reorg.mining.generation,
                    mempool_generation,
                )?;
                Ok(ActiveStateConnectOutcome {
                    connected: reorg.summary.connected.len(),
                    disconnected: reorg.summary.disconnected.len(),
                    contextual_failure: None,
                })
            }
            Err(ChainActivationFailure::ContextualInvalid(failure)) => {
                if is_reorg {
                    self.mining_events.reorg_aborted();
                }
                tracing::warn!(
                    block = %failure.request.block.hash().to_hex(),
                    height = failure.request.height,
                    reason = %failure.error,
                    "durably rejecting contextual-invalid shadow branch"
                );
                let failed = self
                    .state
                    .store_failed_block(failure.request, FailedBlockStage::ContextualState)?;
                Ok(ActiveStateConnectOutcome {
                    contextual_failure: Some(failed),
                    ..ActiveStateConnectOutcome::default()
                })
            }
            Err(ChainActivationFailure::Internal(error)) => {
                if is_reorg {
                    self.mining_events.reorg_aborted();
                }
                Err(error.context("active-state connector failed without block-invalid evidence"))
            }
        }
    }

    fn shadow_sync_contiguous_body_tip(&self, hint: Option<&ChainTip>) -> Result<Option<ChainTip>> {
        let Some(best) = self.shadow_sync_best_header_tip()? else {
            return Ok(None);
        };

        let mut current = None;
        let mut start_height = 0;
        if let Some(hint) = hint {
            if hint.height <= best.height
                && self
                    .state
                    .chain
                    .canonical_hash(hint.height)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to validate stored-tip hint: {error}")
                    })?
                    == Some(hint.hash)
                && self.shadow_sync_has_block(&hint.hash)?
            {
                current = Some(hint.clone());
                start_height = hint.height.saturating_add(1);
            }
        }

        for height in start_height..=best.height {
            let Some(hash) = self.state.chain.canonical_hash(height).map_err(|error| {
                anyhow::anyhow!("failed to inspect canonical body chain: {error}")
            })?
            else {
                break;
            };
            if !self.shadow_sync_has_block(&hash)? {
                break;
            }
            let record = self
                .shadow_sync_header_record(&hash)?
                .ok_or_else(|| anyhow::anyhow!("canonical header {} is missing", hash.to_hex()))?;
            current = Some(ChainTip {
                hash,
                height: record.height,
                chainwork: record.chainwork,
            });
        }
        Ok(current)
    }

    fn shadow_sync_queue_missing_canonical_bodies(
        &self,
        scheduler: &mut SyncScheduler,
    ) -> Result<usize> {
        let contiguous = self.shadow_sync_contiguous_body_tip(scheduler.stored_tip())?;
        if scheduler.stored_tip() != contiguous.as_ref() {
            scheduler.set_stored_tip(contiguous.clone());
        }

        let Some(best) = self.shadow_sync_best_header_tip()? else {
            return Ok(0);
        };
        let start_height = contiguous
            .as_ref()
            .map_or(0, |tip| tip.height.saturating_add(1));
        let mut queued = 0usize;
        let mut available = scheduler.available_pending_slots();
        if available == 0 {
            return Ok(0);
        }

        for height in start_height..=best.height {
            if available == 0 {
                break;
            }
            let Some(hash) = self.state.chain.canonical_hash(height).map_err(|error| {
                anyhow::anyhow!("failed to read canonical body target: {error}")
            })?
            else {
                break;
            };
            if self.shadow_sync_has_block(&hash)? || scheduler.is_queued_or_inflight(&hash) {
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

    fn shadow_sync_block_locator(&self, maximum: usize) -> Result<Vec<BlockHash>> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        let Some(tip) = self.shadow_sync_best_header_tip()? else {
            return Ok(vec![self.config.network.params().genesis_hash]);
        };

        let mut locator = Vec::with_capacity(maximum.min(MAX_LOCATOR_ENTRIES));
        let mut height = tip.height;
        let mut step = 1u32;
        while locator.len() < maximum {
            if let Some(hash) = self
                .state
                .chain
                .canonical_hash(height)
                .map_err(|error| anyhow::anyhow!("failed to read locator header: {error}"))?
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
        if !locator.contains(&self.config.network.params().genesis_hash) {
            locator.push(self.config.network.params().genesis_hash);
        }
        locator.truncate(maximum);
        Ok(locator)
    }

    fn shadow_sync_headers_after_locator(
        &self,
        locator: &[BlockHash],
        stop: BlockHash,
        maximum: usize,
    ) -> Result<Vec<Header>> {
        let maximum = maximum.min(MAX_SERVED_HEADERS);
        let Some(best) = self.shadow_sync_best_header_tip()? else {
            return Ok(Vec::new());
        };

        let mut start_height = 0;
        'locator: for hash in locator {
            if let Some(record) = self.shadow_sync_header_record(hash)? {
                if self
                    .state
                    .chain
                    .canonical_hash(record.height)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to inspect canonical header: {error}")
                    })?
                    == Some(*hash)
                {
                    start_height = record.height.saturating_add(1);
                    break 'locator;
                }
            }
        }

        let mut headers = Vec::with_capacity(maximum);
        for height in start_height..=best.height {
            if headers.len() >= maximum {
                break;
            }
            let Some(hash) = self
                .state
                .chain
                .canonical_hash(height)
                .map_err(|error| anyhow::anyhow!("failed to read canonical header: {error}"))?
            else {
                break;
            };
            let record = self
                .shadow_sync_header_record(&hash)?
                .ok_or_else(|| anyhow::anyhow!("canonical header {} is missing", hash.to_hex()))?;
            headers.push(record.header);
            if stop != BlockHash::ZERO && hash == stop {
                break;
            }
        }
        Ok(headers)
    }
}

#[derive(Clone)]
struct ShadowSyncHttpState {
    node: Arc<Mutex<NodeService>>,
    diagnostics: Arc<RwLock<ShadowSyncDiagnostics>>,
}

async fn serve_shadow_sync_rpc(
    listener: TcpListener,
    node: Arc<Mutex<NodeService>>,
    diagnostics: Arc<RwLock<ShadowSyncDiagnostics>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let state = ShadowSyncHttpState { node, diagnostics };
    let app = Router::new()
        .route("/", post(handle_shadow_sync_rpc))
        .route("/rpc", post(handle_shadow_sync_rpc))
        .route("/api/v1/status", get(handle_shadow_sync_status))
        .route("/api/v1/authority", get(handle_shadow_sync_authority))
        .route("/api/v1/parity", get(handle_shadow_sync_parity))
        .route("/api/v1/peers", get(handle_shadow_sync_peers))
        .route("/api/v1/sync", get(handle_shadow_sync_sync))
        .route("/api/v1/shadow-sync", get(handle_shadow_sync_diagnostics))
        .route(
            "/api/v1/mining-engine",
            get(handle_mining_engine_diagnostics),
        )
        .with_state(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
        .context("Shadow sync RPC server failed")
}

async fn shadow_sync_rpc_service(state: &ShadowSyncHttpState) -> Result<BasicRpcService> {
    let diagnostics = state.diagnostics.read().await.clone();
    let node = state.node.lock().await;
    let mut snapshot = node.rpc_snapshot()?;
    snapshot.network_active = diagnostics.enabled;
    snapshot.peer_count = diagnostics.peers.len();
    snapshot.node_status.release_stage = if node.config.mining_engine.enabled {
        "mining-engine-shadow".to_owned()
    } else {
        "shadow-sync-live-p2p".to_owned()
    };
    snapshot.node_status.parity.configured = false;
    snapshot.node_status.parity.live_shadow_active = false;
    snapshot.node_status.parity.state = "shadow-sync-network-no-hsd-oracle".to_owned();
    Ok(BasicRpcService::new(snapshot))
}

async fn handle_shadow_sync_rpc(
    State(state): State<ShadowSyncHttpState>,
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
    match shadow_sync_rpc_service(&state).await {
        Ok(service) => Json(
            service
                .handle(request)
                .unwrap_or_else(|error| json_rpc_error(id, -32603, error.to_string())),
        ),
        Err(error) => Json(json_rpc_error(id, -32603, error.to_string())),
    }
}

async fn diagnostic_method(state: &ShadowSyncHttpState, method: &str) -> serde_json::Value {
    match shadow_sync_rpc_service(state).await {
        Ok(service) => {
            let response = service.handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: method.to_owned(),
                params: serde_json::Value::Null,
                id: None,
            });
            match response {
                Ok(response) => response.result.unwrap_or_else(|| {
                    serde_json::json!({
                        "error": response
                            .error
                            .map(|error| error.message)
                            .unwrap_or_else(|| "missing result".to_owned())
                    })
                }),
                Err(error) => serde_json::json!({ "error": error.to_string() }),
            }
        }
        Err(error) => serde_json::json!({ "error": error.to_string() }),
    }
}

async fn handle_shadow_sync_status(
    State(state): State<ShadowSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "gethsrdstatus").await)
}

async fn handle_shadow_sync_authority(
    State(state): State<ShadowSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "getauthorityinfo").await)
}

async fn handle_shadow_sync_parity(
    State(state): State<ShadowSyncHttpState>,
) -> Json<serde_json::Value> {
    Json(diagnostic_method(&state, "getparityinfo").await)
}

async fn handle_shadow_sync_peers(
    State(state): State<ShadowSyncHttpState>,
) -> Json<Vec<PeerSnapshot>> {
    Json(state.diagnostics.read().await.peers.clone())
}

async fn handle_shadow_sync_sync(State(state): State<ShadowSyncHttpState>) -> Json<SyncSnapshot> {
    Json(state.diagnostics.read().await.sync.clone())
}

async fn handle_shadow_sync_diagnostics(
    State(state): State<ShadowSyncHttpState>,
) -> Json<ShadowSyncDiagnostics> {
    Json(state.diagnostics.read().await.clone())
}

async fn handle_mining_engine_diagnostics(
    State(state): State<ShadowSyncHttpState>,
) -> Json<serde_json::Value> {
    let node = state.node.lock().await;
    Json(match node.mining_engine_diagnostics() {
        Ok(diagnostics) => serde_json::to_value(diagnostics)
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() })),
        Err(error) => serde_json::json!({ "error": error.to_string() }),
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_peer_event(
    event: PeerEvent,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
    match event {
        PeerEvent::Connected {
            address, direction, ..
        } => {
            if direction == PeerDirection::Outbound {
                if let Some(state) = reconnects.get_mut(&address) {
                    state.connected(Instant::now());
                }
            }
        }
        PeerEvent::Ready { peer, version } => {
            scheduler
                .register_peer(peer, version.services, version.height)
                .map_err(|error| anyhow::anyhow!("failed to register sync peer: {error}"))?;
        }
        PeerEvent::Disconnected {
            peer,
            address,
            direction,
            reason,
        } => {
            scheduler.remove_peer(peer);
            if direction == PeerDirection::Outbound {
                if let Some(state) = reconnects.get_mut(&address) {
                    state.failed(Instant::now());
                }
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
        PeerEvent::Packet { peer, packet } => match packet {
            Packet::Headers(headers) => {
                let header_count = headers.len();
                // A response consumes the outstanding request even if the
                // supplied batch is invalid. Otherwise a malicious peer can
                // pin the header-request slot until the timeout fires.
                scheduler.note_headers_response(peer, header_count);
                let imported = import_headers_cooperatively(node, headers).await;
                let imported = match imported {
                    Ok(imported) => imported,
                    Err(error) => {
                        // Header import is intentionally incremental: a valid
                        // prefix may already be durable when a later header in
                        // the same batch fails. Refresh the scheduler from the
                        // durable index before disconnecting the sender so the
                        // accepted prefix is neither forgotten nor requested
                        // again after the peer event returns.
                        {
                            let node = node.lock().await;
                            scheduler.set_best_header(node.shadow_sync_best_header_tip()?);
                            node.shadow_sync_queue_missing_canonical_bodies(scheduler)?;
                        }
                        penalize_peer(peers, peer, 100, "peer header batch rejected").await?;
                        update_diagnostics(diagnostics, |state| {
                            state.rejected_messages = state.rejected_messages.saturating_add(1);
                        })
                        .await;
                        return Err(error.context("peer header batch rejected"));
                    }
                };
                {
                    let node = node.lock().await;
                    scheduler.set_best_header(node.shadow_sync_best_header_tip()?);
                    node.shadow_sync_queue_missing_canonical_bodies(scheduler)?;
                }
                update_diagnostics(diagnostics, |state| {
                    state.received_headers =
                        state.received_headers.saturating_add(imported.len() as u64);
                })
                .await;
            }
            Packet::Inv(items) => {
                let mut unknown_header_seen = false;
                for item in items {
                    if !matches!(
                        item.kind,
                        InventoryKind::Block
                            | InventoryKind::FilteredBlock
                            | InventoryKind::CompactBlock
                    ) {
                        continue;
                    }
                    let hash = BlockHash::new(item.hash);
                    let record = {
                        let node = node.lock().await;
                        node.shadow_sync_header_record(&hash)?
                    };
                    match record {
                        Some(record) => {
                            let has_body = {
                                let node = node.lock().await;
                                node.shadow_sync_has_block(&hash)?
                            };
                            if !has_body {
                                scheduler
                                    .announce_block(peer, hash, record.height)
                                    .map_err(|error| {
                                        anyhow::anyhow!("failed to queue announced block: {error}")
                                    })?;
                            }
                        }
                        None => unknown_header_seen = true,
                    }
                }
                if unknown_header_seen {
                    request_headers_from_peer(peer, node, peers, scheduler).await?;
                }
            }
            Packet::Block(block) => {
                update_diagnostics(diagnostics, |state| {
                    state.received_blocks = state.received_blocks.saturating_add(1);
                })
                .await;
                accept_peer_block(peer, block, node, peers, validation, scheduler).await?;
            }
            Packet::GetHeaders(locator) => {
                let headers = {
                    let node = node.lock().await;
                    node.shadow_sync_headers_after_locator(
                        &locator.locator,
                        locator.stop,
                        MAX_SERVED_HEADERS,
                    )?
                };
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
                let headers = {
                    let node = node.lock().await;
                    node.shadow_sync_headers_after_locator(
                        &locator.locator,
                        locator.stop,
                        MAX_GETDATA_ITEMS,
                    )?
                };
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
                            let transaction = {
                                let node = node.lock().await;
                                if node.config.mining_engine.enabled
                                    && node.config.mining_engine.transaction_relay
                                {
                                    node.mining_engine_mempool_transaction(&Txid::new(item.hash))
                                } else {
                                    None
                                }
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
                        InventoryKind::Block
                        | InventoryKind::FilteredBlock
                        | InventoryKind::CompactBlock => {
                            let hash = BlockHash::new(item.hash);
                            let block = {
                                let node = node.lock().await;
                                node.shadow_sync_block(&hash)?
                            };
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
                peers
                    .try_send(
                        peer,
                        Arc::new(Packet::Addr(Vec::new())),
                        OutboundPriority::Control,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("failed to answer getaddr: {error}"))?;
            }
            Packet::Mempool => {
                let inventory = {
                    let node = node.lock().await;
                    if node.config.mining_engine.enabled
                        && node.config.mining_engine.transaction_relay
                    {
                        node.mining_engine_mempool_inventory(MAX_GETDATA_ITEMS)
                    } else {
                        Vec::new()
                    }
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
                let admission = {
                    let mut node = node.lock().await;
                    node.mining_engine_accept_peer_transaction(transaction)?
                };
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
                        scheduler.reject_block(Some(peer), hash, true, StdInstant::now());
                    }
                }
            }
            Packet::Addr(_)
            | Packet::SendHeaders
            | Packet::FeeFilter(_)
            | Packet::SendCmpct { .. }
            | Packet::Unknown { .. }
            | Packet::Version(_)
            | Packet::Verack
            | Packet::Ping(_)
            | Packet::Pong(_) => {}
        },
    }
    Ok(())
}

async fn import_headers_cooperatively(
    node: &Arc<Mutex<NodeService>>,
    headers: Vec<Header>,
) -> Result<Vec<HeaderRecord>> {
    if headers.len() > hns_p2p::MAX_HEADERS {
        anyhow::bail!("peer sent too many headers: {}", headers.len());
    }

    let mut pending = headers.into_iter();
    let mut imported = Vec::with_capacity(pending.len());
    while pending.len() != 0 {
        let slice = pending
            .by_ref()
            .take(MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE)
            .collect::<Vec<_>>();
        let records = {
            let mut node = node.lock().await;
            node.shadow_sync_import_headers(slice)?
        };
        imported.extend(records);
        if pending.len() != 0 {
            tokio::task::yield_now().await;
        }
    }
    Ok(imported)
}

#[allow(clippy::too_many_arguments)]
async fn accept_peer_block(
    peer: PeerId,
    block: Block,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
) -> Result<()> {
    let hash = block.hash();
    let mut record = {
        let node = node.lock().await;
        let record = node.shadow_sync_header_record(&hash)?;
        if record.as_ref().is_some_and(|record| record.status.failed) {
            drop(node);
            scheduler.reject_block(Some(peer), hash, false, StdInstant::now());
            penalize_peer(peers, peer, 100, "known invalid block branch").await?;
            anyhow::bail!("peer {:?} sent known invalid block {}", peer, hash.to_hex());
        }
        if node.shadow_sync_has_block(&hash)? {
            scheduler.complete_block(hash);
            return Ok(());
        }
        record
    };
    if record.is_none() {
        let parent_known = {
            let node = node.lock().await;
            if block.header == node.config.network.params().genesis_header() {
                true
            } else {
                node.shadow_sync_header_record(&block.header.prev_block)?
                    .is_some()
            }
        };
        if !parent_known {
            // Shadow sync is headers-first. A body without known header context is
            // neither requested nor eligible for retention. Ask for headers,
            // apply a small protocol penalty, and drop the body. The bounded
            // orphan pool is reserved for statelessly valid bodies whose own
            // header is known but whose parent body has not arrived yet.
            request_headers_from_peer(peer, node, peers, scheduler).await?;
            penalize_peer(peers, peer, 10, "block arrived before header context").await?;
            anyhow::bail!(
                "peer {:?} sent block {} before its header context was known",
                peer,
                hash.to_hex()
            );
        }

        let imported = {
            let mut node = node.lock().await;
            node.shadow_sync_import_headers(vec![block.header.clone()])
        };
        record = match imported {
            Ok(imported) => imported.into_iter().next(),
            Err(error) => {
                penalize_peer(peers, peer, 50, "peer block header rejected").await?;
                return Err(error.context("peer block header rejected"));
            }
        };
        {
            let node = node.lock().await;
            scheduler.set_best_header(node.shadow_sync_best_header_tip()?);
            node.shadow_sync_queue_missing_canonical_bodies(scheduler)?;
        }
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
    if !scheduler.is_queued_or_inflight(&hash) {
        scheduler
            .announce_block(peer, hash, record.height)
            .map_err(|error| anyhow::anyhow!("failed to queue delivered block: {error}"))?;
    }
    let request = scheduler
        .receive_block(peer, hash, StdInstant::now())
        .map_err(|error| anyhow::anyhow!("peer block was not eligible: {error}"))?;
    if let Err(error) = validation
        .submit(ValidationRequest {
            peer,
            height: record.height,
            attempt: request.attempt,
            block,
        })
        .await
    {
        let _ = scheduler.queue_block(hash, record.height);
        return Err(anyhow::anyhow!("validation queue rejected block: {error}"));
    }
    Ok(())
}

async fn request_headers_from_peer(
    peer: PeerId,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
) -> Result<()> {
    let locator = {
        let node = node.lock().await;
        node.shadow_sync_block_locator(MAX_LOCATOR_ENTRIES)?
    };
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

async fn submit_released_orphans(
    parent: BlockHash,
    node: &Arc<Mutex<NodeService>>,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
) -> Result<()> {
    for block in orphans.take_children(parent) {
        let hash = block.hash();
        let record = {
            let mut node = node.lock().await;
            match node.shadow_sync_header_record(&hash)? {
                Some(record) => record,
                None => node
                    .shadow_sync_import_headers(vec![block.header.clone()])?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        anyhow::anyhow!("released orphan header import returned no record")
                    })?,
            }
        };
        scheduler.begin_local_validation(hash);
        let retry = block.clone();
        if let Err(error) = validation
            .submit(ValidationRequest {
                peer: LOCAL_ORPHAN_PEER,
                height: record.height,
                attempt: 0,
                block,
            })
            .await
        {
            let _ = orphans.insert_with_evictions(retry);
            let _ = scheduler.queue_block(hash, record.height);
            return Err(anyhow::anyhow!("failed to submit released orphan: {error}"));
        }
    }
    Ok(())
}

async fn handle_validation_result(
    result: OrderedValidationResult,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
    match result {
        Ok(validated) => {
            let hash = validated.block.hash();
            let parent_available = {
                let node = node.lock().await;
                validated.block.header == node.config.network.params().genesis_header()
                    || node.shadow_sync_has_block(&validated.block.header.prev_block)?
            };
            if !parent_available {
                let outcome = orphans
                    .insert_with_evictions(validated.block)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to retain validated orphan: {error}")
                    })?;
                for evicted in outcome.evicted {
                    let evicted_hash = evicted.hash();
                    let node = node.lock().await;
                    if let Some(record) = node.shadow_sync_header_record(&evicted_hash)? {
                        if !node.shadow_sync_has_block(&evicted_hash)? {
                            let _ = scheduler.queue_block(evicted_hash, record.height);
                        }
                    }
                }
                scheduler.complete_orphan_validation();
                return Ok(());
            }

            let stored = {
                let mut node = node.lock().await;
                node.shadow_sync_store_shadow_block(validated.block, validated.height)?
            };
            scheduler.complete_block(hash);
            {
                let node = node.lock().await;
                let stored_tip = node.shadow_sync_contiguous_body_tip(scheduler.stored_tip())?;
                if scheduler.stored_tip() != stored_tip.as_ref() {
                    scheduler.set_stored_tip(stored_tip);
                }
                node.shadow_sync_queue_missing_canonical_bodies(scheduler)?;
            }
            update_diagnostics(diagnostics, |state| {
                state.stored_bodies = state.stored_bodies.saturating_add(1);
            })
            .await;
            submit_released_orphans(stored.hash, node, validation, scheduler, orphans).await?;
        }
        Err(failure) => {
            let hash = failure.block.hash();
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
                            peers,
                            failure.peer,
                            100,
                            "block body did not match its header",
                        )
                        .await?;
                    }
                    update_diagnostics(diagnostics, |state| {
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

            let stored = {
                let mut node = node.lock().await;
                node.shadow_sync_store_failed_block(failure.block, failure.height)
            };
            let stored = match stored {
                Ok(stored) => stored,
                Err(error) => {
                    scheduler.retry_validation_failure(
                        hash,
                        failure.height,
                        failure.attempt,
                        (failure.peer != LOCAL_ORPHAN_PEER).then_some(failure.peer),
                        StdInstant::now(),
                    );
                    return Err(error.context("failed to persist invalid block branch"));
                }
            };
            for affected in &stored.affected {
                scheduler.reject_block(
                    (*affected == hash).then_some(failure.peer),
                    *affected,
                    false,
                    StdInstant::now(),
                );
            }
            discard_orphan_descendants(hash, orphans);
            if failure.peer != LOCAL_ORPHAN_PEER {
                penalize_peer(
                    peers,
                    failure.peer,
                    100,
                    "stateless block validation failed",
                )
                .await?;
            }
            update_diagnostics(diagnostics, |state| {
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
    }
    Ok(())
}

pub(super) async fn connect_stored_active_state(
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    maximum_connect: usize,
) -> Result<()> {
    let outcome = {
        let mut node = node.lock().await;
        node.shadow_sync_connect_stored_state(maximum_connect)?
    };

    if let Some(failed) = &outcome.contextual_failure {
        for hash in &failed.affected {
            scheduler.reject_block(None, *hash, false, StdInstant::now());
        }
        discard_orphan_descendants(failed.record.hash, orphans);
    }

    let (best_header, active_tip, stored_tip) = {
        let node = node.lock().await;
        let best_header = node.shadow_sync_best_header_tip()?;
        let active_tip = node.shadow_sync_active_tip()?;
        let stored_tip = node.shadow_sync_contiguous_body_tip(scheduler.stored_tip())?;
        (best_header, active_tip, stored_tip)
    };
    scheduler.set_best_header(best_header);
    scheduler.set_active_tip(active_tip.clone());
    scheduler.set_stored_tip(stored_tip);
    {
        let node = node.lock().await;
        node.shadow_sync_queue_missing_canonical_bodies(scheduler)?;
    }
    peers.set_local_height(active_tip.as_ref().map_or(0, |tip| tip.height));

    if outcome.connected != 0 || outcome.disconnected != 0 || outcome.contextual_failure.is_some() {
        let sync_snapshot = scheduler.snapshot();
        let orphan_snapshot = orphans.snapshot();
        update_diagnostics(diagnostics, |state| {
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

fn discard_orphan_descendants(root: BlockHash, orphans: &mut BoundedOrphanPool) {
    let mut pending = vec![root];
    while let Some(parent) = pending.pop() {
        for child in orphans.take_children(parent) {
            pending.push(child.hash());
        }
    }
}

async fn penalize_peer(
    peers: &LivePeerManager,
    peer: PeerId,
    score: u32,
    reason: &str,
) -> Result<i32> {
    let total = peers
        .penalize(peer, score)
        .await
        .map_err(|error| anyhow::anyhow!("failed to penalize peer: {error}"))?;
    tracing::debug!(?peer, score, total, %reason, "penalized HNS peer");
    if total >= 100 {
        peers
            .disconnect(peer)
            .await
            .map_err(|error| anyhow::anyhow!("failed to disconnect peer: {error}"))?;
    }
    Ok(total)
}

async fn apply_sync_action(
    action: SyncAction,
    peers: &LivePeerManager,
    checkpoints: &StoredSyncCheckpoint<hns_store::StoreHandle>,
    scheduler: &SyncScheduler,
    checkpoint_sequence: &mut u64,
) -> Result<()> {
    match action {
        SyncAction::RequestHeaders {
            peer,
            locator,
            stop,
        } => peers
            .try_send(
                peer,
                Arc::new(Packet::GetHeaders(LocatorPacket { locator, stop })),
                OutboundPriority::Control,
            )
            .await
            .map_err(|error| anyhow::anyhow!("failed to request headers: {error}")),
        SyncAction::RequestBlock(request) => {
            let peer = request
                .peer
                .ok_or_else(|| anyhow::anyhow!("block request has no selected peer"))?;
            peers
                .try_send(
                    peer,
                    Arc::new(Packet::GetData(vec![Inventory::block(request.hash)])),
                    OutboundPriority::Control,
                )
                .await
                .map_err(|error| anyhow::anyhow!("failed to request block: {error}"))
        }
        SyncAction::Penalize {
            peer,
            score,
            reason,
        } => {
            penalize_peer(peers, peer, score, &reason).await?;
            Ok(())
        }
        SyncAction::Disconnect { peer, reason } => {
            tracing::debug!(?peer, %reason, "disconnecting HNS peer");
            peers
                .disconnect(peer)
                .await
                .map_err(|error| anyhow::anyhow!("failed to disconnect peer: {error}"))
        }
        SyncAction::PersistCheckpoint => {
            *checkpoint_sequence = checkpoint_sequence.saturating_add(1);
            persist_checkpoint(checkpoints, scheduler, *checkpoint_sequence)
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
    peers: &LivePeerManager,
    results: &mpsc::Sender<ConnectAttemptResult>,
    now: Instant,
) -> usize {
    let due = reconnects
        .iter_mut()
        .filter_map(|(address, state)| {
            if state.connected || state.connecting || state.next_attempt > now {
                return None;
            }
            state.connecting = true;
            Some(*address)
        })
        .collect::<Vec<_>>();

    for address in &due {
        let address = *address;
        let peers = peers.clone();
        let results = results.clone();
        tokio::spawn(async move {
            let result = peers
                .connect(address)
                .await
                .map_err(|error| error.to_string());
            let _ = results.send(ConnectAttemptResult { address, result }).await;
        });
    }
    due.len()
}

async fn handle_connect_attempt_result(
    result: ConnectAttemptResult,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) {
    let Some(state) = reconnects.get_mut(&result.address) else {
        return;
    };
    match result.result {
        Ok(peer) => {
            state.connected(Instant::now());
            tracing::debug!(?peer, address = %result.address, "outbound HNS peer connected");
        }
        Err(error) => {
            state.failed(Instant::now());
            record_error(
                diagnostics,
                format!("outbound peer {} failed: {error}", result.address),
            )
            .await;
        }
    }
}

async fn refresh_diagnostics(
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    peers: &LivePeerManager,
    scheduler: &SyncScheduler,
    orphans: &BoundedOrphanPool,
    reconnects: &HashMap<SocketAddr, ReconnectState>,
    checkpoint_sequence: u64,
) {
    let snapshots = peers.snapshots().await;
    let mut state = diagnostics.write().await;
    state.peers = snapshots;
    state.sync = scheduler.snapshot();
    state.orphans = orphans.snapshot();
    state.checkpoint_sequence = checkpoint_sequence;
    state.outbound_connected = reconnects.values().filter(|item| item.connected).count();
    state.outbound_connecting = reconnects.values().filter(|item| item.connecting).count();
}

async fn update_diagnostics<F>(diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>, update: F)
where
    F: FnOnce(&mut ShadowSyncDiagnostics),
{
    let mut state = diagnostics.write().await;
    update(&mut state);
}

async fn record_error(diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>, error: String) {
    tracing::warn!(%error, "Shadow sync runtime error");
    update_diagnostics(diagnostics, |state| state.last_error = Some(error)).await;
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
    use crate::NodeConfig;
    use hns_consensus::Network;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn shadow_sync_rejects_authority_modes_and_duplicate_peers() {
        let peer: SocketAddr = "127.0.0.1:14038".parse().expect("peer");
        let config = ShadowSyncConfig {
            enabled: true,
            connect: vec![peer],
            ..ShadowSyncConfig::default()
        };
        assert!(config.validate(AuthorityMode::NativeExperimental).is_err());

        let duplicate = ShadowSyncConfig {
            connect: vec![peer, peer],
            ..config
        };
        assert!(duplicate.validate(AuthorityMode::Shadow).is_err());
    }

    #[test]
    fn shadow_sync_requires_a_real_network_endpoint() {
        let config = ShadowSyncConfig {
            enabled: true,
            ..ShadowSyncConfig::default()
        };
        assert!(config.validate(AuthorityMode::Shadow).is_err());

        let active_without_network = ShadowSyncConfig {
            connect_active_state: true,
            ..ShadowSyncConfig::default()
        };
        assert!(active_without_network
            .validate(AuthorityMode::Shadow)
            .is_err());
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(1));
        assert_eq!(reconnect_delay(2), Duration::from_secs(2));
        assert_eq!(reconnect_delay(20), Duration::from_secs(60));
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

    #[tokio::test]
    async fn cooperative_header_import_cancels_at_a_durable_slice_boundary() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .shadow_sync_ensure_genesis_header()
            .expect("genesis");
        let params = Network::Regtest.params();
        let mut previous = genesis.header;
        let mut headers = Vec::new();
        for _ in 0..MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE * 2 {
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
        let node = Arc::new(Mutex::new(service));

        {
            let import = import_headers_cooperatively(&node, headers);
            tokio::pin!(import);
            let shutdown = async { tokio::task::yield_now().await };
            tokio::pin!(shutdown);
            tokio::select! {
                biased;
                _ = &mut shutdown => {}
                result = &mut import => {
                    panic!("header import completed before cancellation: {result:?}")
                }
            }
        }

        let node = node.lock().await;
        assert_eq!(
            node.shadow_sync_best_header_tip()
                .expect("best header")
                .expect("durable imported tip")
                .height as usize,
            MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE
        );
    }

    #[test]
    fn shadow_sync_resource_limits_fail_closed() {
        let peer: SocketAddr = "127.0.0.1:14038".parse().expect("peer");
        let too_many_peers = ShadowSyncConfig {
            enabled: true,
            connect: vec![peer],
            maximum_inbound: MAX_SHADOW_SYNC_PEERS,
            maximum_outbound: 1,
            ..ShadowSyncConfig::default()
        };
        assert!(too_many_peers.validate(AuthorityMode::Shadow).is_err());

        let too_fast = ShadowSyncConfig {
            poll_interval: Duration::from_millis(1),
            ..too_many_peers
        };
        assert!(too_fast.validate(AuthorityMode::Shadow).is_err());

        let zero_connector_batch = ShadowSyncConfig {
            active_state_connect_batch: 0,
            ..too_fast
        };
        assert!(zero_connector_batch
            .validate(AuthorityMode::Shadow)
            .is_err());

        let oversized_connector_batch = ShadowSyncConfig {
            active_state_connect_batch: MAX_ACTIVE_STATE_CONNECT_BATCH + 1,
            ..zero_connector_batch
        };
        assert!(oversized_connector_batch
            .validate(AuthorityMode::Shadow)
            .is_err());
    }

    #[tokio::test]
    async fn shadow_sync_serves_capability_named_diagnostic_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let node = Arc::new(Mutex::new(NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        })));
        let diagnostics = Arc::new(RwLock::new(ShadowSyncDiagnostics {
            enabled: true,
            observation_only: true,
            runtime_instance: "test-runtime".to_owned(),
            ..ShadowSyncDiagnostics::default()
        }));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve_shadow_sync_rpc(
            listener,
            node,
            diagnostics,
            shutdown_rx,
        ));

        for path in ["/api/v1/shadow-sync", "/api/v1/mining-engine"] {
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
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
            if path == "/api/v1/shadow-sync" {
                assert_eq!(json["observation_only"], true);
                assert_eq!(json["active_state"], false);
                assert_eq!(json["runtime_instance"], "test-runtime");
                assert_eq!(json["connected_blocks"], 0);
                assert_eq!(json["contextual_failed_bodies"], 0);
            }
        }

        shutdown_tx.send(true).expect("shutdown");
        server.await.expect("server join").expect("server result");
    }

    #[test]
    fn block_locator_uses_exponential_backoff_and_genesis() {
        let config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let mut node = NodeService::new(config);
        node.shadow_sync_ensure_genesis_header().expect("genesis");
        assert_eq!(
            node.shadow_sync_block_locator(MAX_LOCATOR_ENTRIES)
                .expect("locator"),
            vec![Network::Regtest.params().genesis_hash]
        );
    }
}
