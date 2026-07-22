use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
use hns_chain::{
    prepare_header_record, BlockIndexRecord, ChainTip, HeaderImport, HeaderIndex, HeaderRecord,
};
use hns_consensus::{
    advance_threshold_state, block_merkle_root, block_witness_root,
    compute_block_version_from_state, is_hsd_historical_block, validate_coinbase_height,
    validate_transaction_start, ConsensusParams, DeploymentState, HeaderConsensus, HeaderParent,
    HeaderValidationContext, Network, ThresholdState, MAX_FUTURE_BLOCK_TIME,
};
use hns_mempool::Admission;
use hns_p2p::{
    Inventory, InventoryKind, LivePeerConfig, LivePeerManager, LocatorPacket, OutboundPriority,
    P2pError, Packet, PeerDirection, PeerEvent, PeerId, PeerSnapshot, SERVICE_NETWORK,
};
use hns_primitives::{Block, BlockHash, Header, Height, Txid};
use hns_rpc::{BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcService};
use hns_store::mark_clean_shutdown;
use hns_sync::{
    spawn_validation_pipeline, BlockDownloadRequest, BoundedOrphanPool, OrderedValidationResult,
    OrphanLimits, OrphanSnapshot, StatelessBlockValidator, StoredSyncCheckpoint, SyncAction,
    SyncCheckpoint, SyncLimits, SyncScheduler, SyncSnapshot, ValidationFailureKind,
    ValidationRejection, ValidationRequest, ValidationSubmitter,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch, Mutex, RwLock},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};

use super::{
    completed_deployment_period_with_lookup, current_unix_time, expected_bits_with_lookup,
    json_rpc_error, median_time_past_with_lookup, AuthorityMode, ChainActivationFailure,
    FailedBlockMutation, FailedBlockStage, HeaderSummary, NodeBlockImport, NodeReorg, NodeService,
    ShutdownSignal,
};

const MAX_LOCATOR_ENTRIES: usize = 32;
const MAX_SERVED_HEADERS: usize = hns_p2p::MAX_HEADERS;
const MAX_GETDATA_ITEMS: usize = 1_024;
const LOCAL_ORPHAN_PEER: PeerId = PeerId(0);
const MAX_RECONNECT_DELAY_SECONDS: u64 = 60;
const MAX_DISCOVERY_CONNECT_FAILURES: u32 = 3;
const MAX_KNOWN_PEER_ADDRESSES: usize = 16_384;
const DEFAULT_KNOWN_PEER_ADDRESSES: usize = 4_096;
const DNS_SEED_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ADDR_FUTURE_SECONDS: u64 = 10 * 60;
const FALLBACK_ADDR_AGE_SECONDS: u64 = 5 * 24 * 60 * 60;
const MIN_ADDR_TIMESTAMP: u64 = 100_000_000;
const MAX_SHADOW_SYNC_PEERS: usize = 256;
const MAX_SHADOW_SYNC_VALIDATION_WORKERS: usize = 128;
const MAX_SHADOW_SYNC_VALIDATION_QUEUE: usize = 8_192;
const MAX_SHADOW_SYNC_ORPHAN_BLOCKS: usize = 8_192;
const MAX_SHADOW_SYNC_ORPHAN_BYTES: usize = 1024 * 1024 * 1024;
const MAX_ACTIVE_STATE_CONNECT_BATCH: usize = 1_024;
pub(super) const MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE: usize = 8;
const MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE: usize = hns_p2p::MAX_HEADERS;
const MIN_SHADOW_SYNC_POLL_INTERVAL: Duration = Duration::from_millis(10);

const fn hsd_dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &["hs-mainnet.bcoin.ninja", "seed.htools.work"],
        Network::Testnet => &["hs-testnet.bcoin.ninja"],
        Network::Regtest | Network::Simnet => &[],
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowSyncConfig {
    pub enabled: bool,
    /// Acquire and validate canonical headers without scheduling block bodies.
    pub headers_only: bool,
    pub connect_active_state: bool,
    pub active_state_connect_batch: usize,
    pub listen: Option<SocketAddr>,
    pub connect: Vec<SocketAddr>,
    /// Resolve HSD's network DNS seeds and learn bounded plaintext peers from
    /// GETADDR/ADDR. Explicit `connect` peers remain pinned reconnect targets.
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

impl Default for ShadowSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            headers_only: false,
            connect_active_state: false,
            active_state_connect_batch: 288,
            listen: None,
            connect: Vec::new(),
            discovery: false,
            maximum_known_addresses: DEFAULT_KNOWN_PEER_ADDRESSES,
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
    pub fn validate(&self, authority_mode: AuthorityMode, network: Network) -> Result<()> {
        if self.connect_active_state && !self.enabled {
            anyhow::bail!("active-state synchronization requires shadow sync to be enabled");
        }
        if self.headers_only && !self.enabled {
            anyhow::bail!("headers-only synchronization requires shadow sync to be enabled");
        }
        if self.headers_only && self.connect_active_state {
            anyhow::bail!("headers-only shadow sync cannot connect active state");
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
        let has_discovery_endpoint = self.discovery && !hsd_dns_seeds(network).is_empty();
        if self.listen.is_none() && self.connect.is_empty() && !has_discovery_endpoint {
            anyhow::bail!(
                "Shadow sync requires an inbound listener, an explicit outbound peer, or DNS discovery on a seeded network"
            );
        }
        if self.listen.is_some() && self.maximum_inbound == 0 {
            anyhow::bail!("Shadow sync listener requires a non-zero maximum-inbound value");
        }
        if (!self.connect.is_empty() || self.discovery) && self.maximum_outbound == 0 {
            anyhow::bail!("Shadow sync outbound peers require a non-zero maximum-outbound value");
        }
        if self.connect.len() > self.maximum_outbound {
            anyhow::bail!(
                "{} configured outbound peers exceed the maximum-outbound value {}",
                self.connect.len(),
                self.maximum_outbound
            );
        }
        if self.maximum_known_addresses == 0
            || self.maximum_known_addresses > MAX_KNOWN_PEER_ADDRESSES
        {
            anyhow::bail!(
                "Shadow sync known-address limit {} must be within 1..={MAX_KNOWN_PEER_ADDRESSES}",
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
    pub headers_only: bool,
    pub observation_only: bool,
    pub active_state: bool,
    /// Opaque process-local identifier used only to correlate qualification
    /// observations across runtime restarts.
    pub runtime_instance: String,
    pub listen: Option<SocketAddr>,
    pub configured_outbound: Vec<SocketAddr>,
    pub discovery_enabled: bool,
    pub known_addresses: usize,
    pub dns_seed_addresses: u64,
    pub dns_seed_failures: u64,
    pub discovery_connection_failures: u64,
    pub received_addresses: u64,
    pub accepted_addresses: u64,
    pub rejected_addresses: u64,
    pub served_addresses: u64,
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

#[derive(Clone, Debug)]
struct KnownPeerAddress {
    wire: hns_p2p::NetAddress,
    configured: bool,
    failures: u32,
    eligible_at: Instant,
    sequence: u64,
}

#[derive(Debug)]
struct BoundedAddressBook {
    network: Network,
    listen: Option<SocketAddr>,
    maximum: usize,
    sequence: u64,
    entries: BTreeMap<SocketAddr, KnownPeerAddress>,
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
            entries: BTreeMap::new(),
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
        self.entries.insert(
            address,
            KnownPeerAddress {
                wire: hns_p2p::NetAddress::from_socket_addr(address, timestamp, SERVICE_NETWORK),
                configured: true,
                failures: 0,
                eligible_at: now,
                sequence: self.sequence,
            },
        );
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
        if wire.key != [0; 33]
            || wire.services & SERVICE_NETWORK == 0
            || !is_discoverable_address(self.network, self.listen, address)
        {
            return AddressAdmission::Rejected;
        }
        wire.time = normalize_peer_timestamp(wire.time, timestamp);

        if let Some(existing) = self.entries.get_mut(&address) {
            existing.wire.services |= wire.services;
            if wire.time > existing.wire.time {
                existing.wire.time = wire.time;
            }
            return AddressAdmission::Updated;
        }

        if self.entries.len() >= self.maximum {
            let eviction = self
                .entries
                .iter()
                .filter(|(_, entry)| !entry.configured)
                .min_by_key(|(address, entry)| (entry.wire.time, entry.sequence, **address))
                .map(|(address, _)| *address);
            let Some(eviction) = eviction else {
                return AddressAdmission::Rejected;
            };
            self.entries.remove(&eviction);
        }

        self.sequence = self.sequence.saturating_add(1);
        self.entries.insert(
            address,
            KnownPeerAddress {
                wire,
                configured: false,
                failures: 0,
                eligible_at: now,
                sequence: self.sequence,
            },
        );
        AddressAdmission::Added
    }

    fn connection_candidates(
        &self,
        tracked: &HashMap<SocketAddr, ReconnectState>,
        now: Instant,
        maximum: usize,
    ) -> Vec<SocketAddr> {
        let mut candidates = self
            .entries
            .iter()
            .filter(|(address, entry)| {
                !entry.configured && entry.eligible_at <= now && !tracked.contains_key(address)
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
        candidates
            .into_iter()
            .take(maximum)
            .map(|(_, _, _, address)| address)
            .collect()
    }

    fn note_failure(&mut self, address: SocketAddr, now: Instant) {
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        entry.failures = entry.failures.saturating_add(1);
        entry.eligible_at = now + reconnect_delay(entry.failures);
    }

    fn note_success(&mut self, address: SocketAddr, now: Instant, timestamp: u64) {
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        entry.failures = 0;
        entry.eligible_at = now;
        entry.wire.time = timestamp;
    }

    fn advertised(&self, maximum: usize) -> Vec<hns_p2p::NetAddress> {
        let mut entries = self
            .entries
            .values()
            .filter(|entry| {
                is_discoverable_address(
                    self.network,
                    self.listen,
                    entry
                        .wire
                        .socket_addr()
                        .expect("address-book key is an IP socket"),
                )
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

#[derive(Debug, Default)]
struct DnsSeedResolution {
    addresses: Vec<SocketAddr>,
    errors: Vec<String>,
}

async fn resolve_hsd_dns_seeds(network: Network) -> DnsSeedResolution {
    let mut resolved = BTreeSet::new();
    let mut errors = Vec::new();
    for seed in hsd_dns_seeds(network) {
        let lookup = tokio::time::timeout(
            DNS_SEED_TIMEOUT,
            tokio::net::lookup_host((*seed, network.params().port)),
        )
        .await;
        match lookup {
            Ok(Ok(addresses)) => resolved.extend(addresses),
            Ok(Err(error)) => errors.push(format!("DNS seed {seed} failed: {error}")),
            Err(_) => errors.push(format!(
                "DNS seed {seed} exceeded the {} second timeout",
                DNS_SEED_TIMEOUT.as_secs()
            )),
        }
    }
    DnsSeedResolution {
        addresses: resolved.into_iter().collect(),
        errors,
    }
}

impl NodeService {
    pub async fn run_shadow_sync_until_shutdown(self, shutdown: ShutdownSignal) -> Result<()> {
        self.config
            .shadow_sync
            .validate(self.config.authority_mode, self.config.network)?;
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
        scheduler.set_headers_only(shadow_sync_config.headers_only);

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

        let address_now = Instant::now();
        let address_timestamp = unix_time();
        let mut address_book = BoundedAddressBook::new(
            network,
            shadow_sync_config.listen,
            shadow_sync_config.maximum_known_addresses,
        )?;
        for address in &shadow_sync_config.connect {
            address_book.insert_configured(*address, address_now, address_timestamp)?;
        }
        let mut dns_seed_addresses = 0u64;
        let mut dns_seed_failures = 0u64;
        if shadow_sync_config.discovery {
            let resolution = resolve_hsd_dns_seeds(network).await;
            dns_seed_failures = resolution.errors.len() as u64;
            for error in resolution.errors {
                tracing::warn!(%error, "HNS DNS seed resolution failed");
            }
            for address in resolution.addresses {
                let wire = hns_p2p::NetAddress::from_socket_addr(
                    address,
                    address_timestamp,
                    SERVICE_NETWORK,
                );
                if address_book
                    .insert_discovered(wire, address_now, address_timestamp)
                    .accepted()
                {
                    dns_seed_addresses = dns_seed_addresses.saturating_add(1);
                }
            }
            if shadow_sync_config.connect.is_empty()
                && shadow_sync_config.listen.is_none()
                && address_book.len() == 0
            {
                anyhow::bail!("HNS DNS discovery resolved no admissible peer addresses");
            }
        }

        let mut reconnects = shadow_sync_config
            .connect
            .iter()
            .copied()
            .map(|address| (address, ReconnectState::new(address_now, true)))
            .collect::<HashMap<_, _>>();
        fill_discovery_slots(
            &address_book,
            &mut reconnects,
            shadow_sync_config.maximum_outbound,
            address_now,
        );

        let initial_sequence = durable_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.sequence);
        let diagnostics = Arc::new(RwLock::new(ShadowSyncDiagnostics {
            enabled: true,
            headers_only: shadow_sync_config.headers_only,
            observation_only: !shadow_sync_config.connect_active_state,
            active_state: shadow_sync_config.connect_active_state,
            runtime_instance: runtime_instance_id(),
            listen: shadow_sync_config.listen,
            configured_outbound: shadow_sync_config.connect.clone(),
            discovery_enabled: shadow_sync_config.discovery,
            known_addresses: address_book.len(),
            dns_seed_addresses,
            dns_seed_failures,
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

        let (connect_results_tx, mut connect_results_rx) =
            mpsc::channel::<ConnectAttemptResult>(shadow_sync_config.maximum_outbound.max(1));

        tracing::info!(
            rpc = %rpc_bind,
            p2p = ?shadow_sync_config.listen,
            outbound = reconnects.len(),
            discovery = shadow_sync_config.discovery,
            known_addresses = address_book.len(),
            "hsrd shadow-sync runtime started"
        );

        let mut checkpoint_sequence = initial_sequence;
        let mut poll = tokio::time::interval(shadow_sync_config.poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        poll.tick().await;
        let mut served_getaddr = HashSet::new();
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

                    // Start due sockets before potentially expensive local
                    // active-state and canonical-body scans. Historical replay
                    // must not starve peer bootstrap or reconnect scheduling.
                    let connection_now = Instant::now();
                    if shadow_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            shadow_sync_config.maximum_outbound,
                            connection_now,
                        );
                    }
                    let attempts = spawn_due_connections(
                        &mut reconnects,
                        &peers,
                        &connect_results_tx,
                        connection_now,
                        shadow_sync_config.maximum_outbound,
                    );
                    if attempts > 0 {
                        update_diagnostics(&diagnostics, |state| {
                            state.outbound_reconnect_attempts = state
                                .outbound_reconnect_attempts
                                .saturating_add(attempts as u64);
                        })
                        .await;
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
                    let dispatches = match batch_sync_actions(
                        scheduler.poll(StdInstant::now(), &locator),
                    ) {
                        Ok(dispatches) => dispatches,
                        Err(error) => {
                            let error = error.context("failed to batch synchronization actions");
                            record_error(&diagnostics, error.to_string()).await;
                            terminal_error = Some(error);
                            break;
                        }
                    };
                    for dispatch in dispatches {
                        if let Err(error) = apply_sync_dispatch(
                            dispatch,
                            &peers,
                            &checkpoint_store,
                            &mut scheduler,
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
                        &address_book,
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
                    handle_connect_attempt_result(
                        result,
                        &mut reconnects,
                        &mut address_book,
                        &diagnostics,
                    )
                    .await;
                    if shadow_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            shadow_sync_config.maximum_outbound,
                            Instant::now(),
                        );
                    }
                }
                event = peer_events.recv() => {
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
                            &peers,
                            &validation,
                            &mut scheduler,
                            &mut reconnects,
                            &mut address_book,
                            &mut served_getaddr,
                            shadow_sync_config.discovery,
                            shadow_sync_config.headers_only,
                            &diagnostics,
                        ) => Some(result),
                    };
                    let Some(handled) = handled else {
                        break;
                    };
                    if let Err(error) = handled {
                        record_error(&diagnostics, error.to_string()).await;
                    }
                    if shadow_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            shadow_sync_config.maximum_outbound,
                            Instant::now(),
                        );
                    }
                    refresh_diagnostics(
                        &diagnostics,
                        &peers,
                        &scheduler,
                        &orphan_pool,
                        &reconnects,
                        &address_book,
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
                        &address_book,
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

    pub(super) fn shadow_sync_ensure_genesis_header(&mut self) -> Result<HeaderRecord> {
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
        if headers.len() > MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE {
            anyhow::bail!("peer sent too many headers: {}", headers.len());
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
                Some(lookup(&header.prev_block)?.ok_or_else(|| {
                    anyhow::anyhow!("missing header parent {}", header.prev_block.to_hex())
                })?)
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
                .map_err(|error| anyhow::anyhow!("header validation failed: {error}"))?;

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

        let committed = self
            .state
            .chain
            .import_headers(requests)
            .map_err(|error| anyhow::anyhow!("failed to persist header batch: {error}"))?;
        if committed != pending_records {
            anyhow::bail!("committed header batch differs from its staged validation view");
        }
        Ok(imported)
    }

    fn shadow_sync_best_header_tip(&self) -> Result<Option<ChainTip>> {
        self.state
            .chain
            .best_tip()
            .map_err(|error| anyhow::anyhow!("failed to read best header: {error}"))
    }

    fn shadow_sync_header_deployments(&self) -> Result<HeaderDeploymentDiagnostics> {
        let best_header = self
            .shadow_sync_best_header_tip()?
            .ok_or_else(|| anyhow::anyhow!("best header is unavailable"))?;
        let next_height = best_header
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("best-header height exhausted"))?;
        let params = self.config.network.params();
        let mut state = DeploymentState::from_states([ThresholdState::Defined; 4]);

        for deployment in self.config.network.deployments() {
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
                let parent_hash = self
                    .state
                    .chain
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
                let parent = self
                    .state
                    .chain
                    .header(&parent_hash)
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
                    self.state.chain.header(hash).map_err(|error| {
                        anyhow::anyhow!("failed to read deployment ancestry: {error}")
                    })
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

        let deployments = self
            .config
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
        let final_checkpoint = self
            .config
            .network
            .checkpoints()
            .last()
            .map(|checkpoint| {
                let anchored = if best_header.height < checkpoint.height {
                    false
                } else {
                    let canonical =
                        self.state
                            .chain
                            .canonical_hash(checkpoint.height)
                            .map_err(|error| {
                                anyhow::anyhow!("failed to read final checkpoint ancestry: {error}")
                            })?;
                    let record = self.state.chain.header(&checkpoint.hash).map_err(|error| {
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
                self.config.network.deployments(),
                state,
            )
            .context("failed to derive next-block deployment version")?,
            final_checkpoint,
            historical_script_assumption_through,
        })
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

    fn shadow_sync_is_canonical_header(&self, hash: BlockHash, height: Height) -> Result<bool> {
        self.state
            .chain
            .canonical_hash(height)
            .map(|canonical| canonical == Some(hash))
            .map_err(|error| anyhow::anyhow!("failed to read canonical header: {error}"))
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
        canonical: bool,
    ) -> Result<BlockIndexRecord> {
        let request = NodeBlockImport::from_peer(block, height);
        let validated = if canonical {
            self.state.validate_canonical_shadow_import(&request)?
        } else {
            self.state.validate_import(&request)?
        };
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
        if self.config.shadow_sync.headers_only {
            return Ok(0);
        }
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
        let body_window = Height::try_from(self.config.shadow_sync.orphan_blocks)
            .context("orphan block horizon exceeds the canonical height range")?;
        if body_window == 0 {
            anyhow::bail!("orphan block horizon is zero");
        }
        // Canonical validated bodies are durable even when a lower parent body
        // has not arrived, but the downloader must not create an unbounded
        // future-body range on disk. Advancing the contiguous stored tip slides
        // this focused window forward.
        let last_height = start_height
            .saturating_add(body_window.saturating_sub(1))
            .min(best.height);
        let mut queued = 0usize;
        let mut available = scheduler.available_pending_slots();
        if available == 0 {
            return Ok(0);
        }

        for height in start_height..=last_height {
            if available == 0 {
                break;
            }
            let Some(hash) = self.state.chain.canonical_hash(height).map_err(|error| {
                anyhow::anyhow!("failed to read canonical body target: {error}")
            })?
            else {
                break;
            };
            if self.shadow_sync_has_block(&hash)? || scheduler.is_tracked_block(&hash) {
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
        .route("/api/v1/header-deployments", get(handle_header_deployments))
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

async fn handle_header_deployments(
    State(state): State<ShadowSyncHttpState>,
) -> Json<serde_json::Value> {
    let node = state.node.lock().await;
    Json(match node.shadow_sync_header_deployments() {
        Ok(diagnostics) => serde_json::to_value(diagnostics)
            .unwrap_or_else(|error| serde_json::json!({ "error": error.to_string() })),
        Err(error) => serde_json::json!({ "error": error.to_string() }),
    })
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
    addresses: &mut BoundedAddressBook,
    served_getaddr: &mut HashSet<PeerId>,
    discovery: bool,
    headers_only: bool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
    match event {
        PeerEvent::Connected {
            address, direction, ..
        } => {
            if direction == PeerDirection::Outbound {
                if let Some(state) = reconnects.get_mut(&address) {
                    state.transport_connected(Instant::now());
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
                    addresses.note_success(snapshot.address, now, unix_time());
                }
            }
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
            if direction == PeerDirection::Outbound {
                note_reconnect_failure(address, reconnects, addresses, Instant::now());
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
                let imported = import_header_packet(node, headers).await;
                let imported = match imported {
                    Ok(imported) => imported,
                    Err(error) => {
                        // Header packets commit atomically. Refresh from the
                        // unchanged durable index before disconnecting the
                        // sender so the scheduler retries from the last
                        // complete protocol batch.
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
                        Some(record) if !headers_only => {
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
                        Some(_) => {}
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
                    if headers_only {
                        state.rejected_messages = state.rejected_messages.saturating_add(1);
                    }
                })
                .await;
                if !headers_only {
                    accept_peer_block(peer, block, node, peers, validation, scheduler).await?;
                }
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
                let inbound = peers.snapshots().await.iter().any(|snapshot| {
                    snapshot.id == peer && snapshot.direction == PeerDirection::Inbound
                });
                if !admit_getaddr(peer, inbound, served_getaddr) {
                    return Ok(());
                }
                let advertised = addresses.advertised(hns_p2p::MAX_ADDR_ITEMS);
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
                        if addresses.insert_discovered(item, now, timestamp).accepted() {
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

async fn import_header_packet(
    node: &Arc<Mutex<NodeService>>,
    headers: Vec<Header>,
) -> Result<Vec<HeaderRecord>> {
    if headers.len() > MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE {
        anyhow::bail!("peer sent too many headers: {}", headers.len());
    }

    let mut node = node.lock().await;
    node.shadow_sync_import_headers(headers)
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
    if !scheduler.is_tracked_block(&hash) {
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
        scheduler
            .requeue_tracked_block(hash, record.height)
            .context("failed to preserve body work after validation queue rejection")?;
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
            let outcome = match orphans.insert_with_evictions(retry) {
                Ok(outcome) => outcome,
                Err(insert_error) => {
                    scheduler
                        .requeue_tracked_block(hash, record.height)
                        .context("failed to requeue released orphan after retention failure")?;
                    anyhow::bail!(
                        "validation queue rejected block ({error}) and orphan retention failed: {insert_error}"
                    );
                }
            };
            for evicted in outcome.evicted {
                let evicted_hash = evicted.hash();
                let node = node.lock().await;
                if let Some(evicted_record) = node.shadow_sync_header_record(&evicted_hash)? {
                    if !node.shadow_sync_has_block(&evicted_hash)? {
                        scheduler
                            .requeue_tracked_block(evicted_hash, evicted_record.height)
                            .context("failed to requeue orphan evicted during queue recovery")?;
                    }
                }
            }
            scheduler.complete_orphan_validation();
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
            let (parent_available, canonical) = {
                let node = node.lock().await;
                (
                    validated.block.header == node.config.network.params().genesis_header()
                        || node.shadow_sync_has_block(&validated.block.header.prev_block)?,
                    node.shadow_sync_is_canonical_header(hash, validated.height)?,
                )
            };
            if !parent_available && !canonical {
                let outcome = match orphans.insert_with_evictions(validated.block) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        scheduler
                            .requeue_tracked_block(hash, validated.height)
                            .context("failed to requeue unretained validated orphan")?;
                        return Err(anyhow::anyhow!(
                            "failed to retain validated orphan: {error}"
                        ));
                    }
                };
                for evicted in outcome.evicted {
                    let evicted_hash = evicted.hash();
                    let node = node.lock().await;
                    if let Some(record) = node.shadow_sync_header_record(&evicted_hash)? {
                        if !node.shadow_sync_has_block(&evicted_hash)? {
                            scheduler
                                .requeue_tracked_block(evicted_hash, record.height)
                                .context("failed to requeue evicted orphan body")?;
                        }
                    }
                }
                scheduler.complete_orphan_validation();
                return Ok(());
            }

            // Canonical header ancestry is already independently validated and
            // `store_shadow_block` deliberately writes a non-active record. It
            // therefore does not need the parent body: retaining it immediately
            // makes an out-of-order download window restart-durable, while the
            // contiguous stored tip and active-state connector remain pinned at
            // the first missing body. Non-canonical descendants still use the
            // bounded in-memory orphan pool above.
            let stored = {
                let mut node = node.lock().await;
                node.shadow_sync_store_shadow_block(validated.block, validated.height, canonical)?
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
    let total = peers.penalize(peer, score).await?;
    tracing::debug!(?peer, score, total, %reason, "penalized HNS peer");
    if total >= 100 {
        peers.disconnect(peer).await?;
    }
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
                .map(|request| Inventory::block(request.hash))
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
    peers: &LivePeerManager,
    results: &mpsc::Sender<ConnectAttemptResult>,
    now: Instant,
    maximum_outbound: usize,
) -> usize {
    let occupied = reconnects
        .values()
        .filter(|state| state.connected || state.connecting)
        .count();
    let available = maximum_outbound.saturating_sub(occupied);
    let due = reconnects
        .iter_mut()
        .filter_map(|(address, state)| {
            if state.connected || state.connecting || state.next_attempt > now {
                return None;
            }
            state.connecting = true;
            Some(*address)
        })
        .take(available)
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

fn fill_discovery_slots(
    addresses: &BoundedAddressBook,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    maximum_outbound: usize,
    now: Instant,
) -> usize {
    let available = maximum_outbound.saturating_sub(reconnects.len());
    let candidates = addresses.connection_candidates(reconnects, now, available);
    let added = candidates.len();
    for address in candidates {
        reconnects.insert(address, ReconnectState::new(now, false));
    }
    added
}

fn note_reconnect_failure(
    address: SocketAddr,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    addresses: &mut BoundedAddressBook,
    now: Instant,
) {
    let retire = reconnects.get_mut(&address).is_some_and(|state| {
        state.failed(now);
        !state.persistent && state.failures >= MAX_DISCOVERY_CONNECT_FAILURES
    });
    if retire {
        reconnects.remove(&address);
        addresses.note_failure(address, now);
    }
}

async fn handle_connect_attempt_result(
    result: ConnectAttemptResult,
    reconnects: &mut HashMap<SocketAddr, ReconnectState>,
    addresses: &mut BoundedAddressBook,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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
            note_reconnect_failure(result.address, reconnects, addresses, Instant::now());
            if persistent {
                record_error(
                    diagnostics,
                    format!("outbound peer {} failed: {error}", result.address),
                )
                .await;
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

async fn refresh_diagnostics(
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    peers: &LivePeerManager,
    scheduler: &SyncScheduler,
    orphans: &BoundedOrphanPool,
    reconnects: &HashMap<SocketAddr, ReconnectState>,
    addresses: &BoundedAddressBook,
    checkpoint_sequence: u64,
) {
    let snapshots = peers.snapshots().await;
    let mut state = diagnostics.write().await;
    state.peers = snapshots;
    state.sync = scheduler.snapshot();
    state.orphans = orphans.snapshot();
    state.checkpoint_sequence = checkpoint_sequence;
    state.known_addresses = addresses.len();
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
    use hns_primitives::{
        Address, Covenant, CovenantKind, Input, Outpoint, Output, Transaction, Txid, Witness,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn shadow_sync_rejects_authority_modes_and_duplicate_peers() {
        let peer: SocketAddr = "127.0.0.1:14038".parse().expect("peer");
        let config = ShadowSyncConfig {
            enabled: true,
            connect: vec![peer],
            ..ShadowSyncConfig::default()
        };
        assert!(config
            .validate(AuthorityMode::NativeExperimental, Network::Regtest)
            .is_err());

        let duplicate = ShadowSyncConfig {
            connect: vec![peer, peer],
            ..config
        };
        assert!(duplicate
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());
    }

    #[test]
    fn shadow_sync_requires_a_real_network_endpoint() {
        let config = ShadowSyncConfig {
            enabled: true,
            ..ShadowSyncConfig::default()
        };
        assert!(config
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let active_without_network = ShadowSyncConfig {
            connect_active_state: true,
            ..ShadowSyncConfig::default()
        };
        assert!(active_without_network
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let headers_without_network = ShadowSyncConfig {
            headers_only: true,
            ..ShadowSyncConfig::default()
        };
        assert!(headers_without_network
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let headers_only_active_state = ShadowSyncConfig {
            enabled: true,
            headers_only: true,
            connect_active_state: true,
            connect: vec!["127.0.0.1:14038".parse().expect("peer")],
            ..ShadowSyncConfig::default()
        };
        assert!(headers_only_active_state
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(1));
        assert_eq!(reconnect_delay(2), Duration::from_secs(2));
        assert_eq!(reconnect_delay(20), Duration::from_secs(60));
    }

    #[test]
    fn dns_discovery_uses_pinned_hsd_network_seeds() {
        assert_eq!(
            hsd_dns_seeds(Network::Mainnet),
            &["hs-mainnet.bcoin.ninja", "seed.htools.work"]
        );
        assert_eq!(hsd_dns_seeds(Network::Testnet), &["hs-testnet.bcoin.ninja"]);
        assert!(hsd_dns_seeds(Network::Regtest).is_empty());

        let discovery = ShadowSyncConfig {
            enabled: true,
            discovery: true,
            ..ShadowSyncConfig::default()
        };
        discovery
            .validate(AuthorityMode::Shadow, Network::Mainnet)
            .expect("mainnet has HSD DNS seeds");
        assert!(discovery
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());
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
    fn bounded_address_book_applies_hsd_admission_and_eviction_rules() {
        let now = Instant::now();
        let timestamp = 1_800_000_000;
        let mut addresses = BoundedAddressBook::new(Network::Mainnet, None, 2).expect("book");
        let first: SocketAddr = "8.8.8.8:12038".parse().expect("first");
        let second: SocketAddr = "1.1.1.1:12038".parse().expect("second");
        let third: SocketAddr = "9.9.9.9:12038".parse().expect("third");

        let mut first_wire = hns_p2p::NetAddress::from_socket_addr(
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
        let private = hns_p2p::NetAddress::from_socket_addr(
            "192.168.1.1:12038".parse().expect("private"),
            timestamp,
            SERVICE_NETWORK,
        );
        assert_eq!(
            addresses.insert_discovered(private, now, timestamp),
            AddressAdmission::Rejected
        );
        let mut keyed = hns_p2p::NetAddress::from_socket_addr(second, timestamp, SERVICE_NETWORK);
        keyed.key[0] = 1;
        assert_eq!(
            addresses.insert_discovered(keyed, now, timestamp),
            AddressAdmission::Rejected
        );

        assert!(addresses
            .insert_discovered(
                hns_p2p::NetAddress::from_socket_addr(second, timestamp - 2, SERVICE_NETWORK,),
                now,
                timestamp,
            )
            .accepted());
        assert!(addresses
            .insert_discovered(
                hns_p2p::NetAddress::from_socket_addr(third, timestamp - 1, SERVICE_NETWORK,),
                now,
                timestamp,
            )
            .accepted());
        assert_eq!(addresses.len(), 2);
        assert!(!addresses.entries.contains_key(&first));
        assert!(addresses.entries.contains_key(&second));
        assert!(addresses.entries.contains_key(&third));
        assert_eq!(addresses.advertised(1).len(), 1);
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
                    hns_p2p::NetAddress::from_socket_addr(address, timestamp, SERVICE_NETWORK,),
                    now,
                    timestamp,
                )
                .accepted());
        }
        let mut reconnects = HashMap::from([(configured, ReconnectState::new(now, true))]);
        assert_eq!(fill_discovery_slots(&addresses, &mut reconnects, 2, now), 1);
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
            note_reconnect_failure(discovered, &mut reconnects, &mut addresses, now);
        }
        assert!(!reconnects.contains_key(&discovered));
        assert!(reconnects.contains_key(&configured));
        assert_eq!(fill_discovery_slots(&addresses, &mut reconnects, 2, now), 1);
        assert_eq!(reconnects.len(), 2);
        assert!(!reconnects.contains_key(&discovered));
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
            shadow_sync: ShadowSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..ShadowSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .shadow_sync_ensure_genesis_header()
            .expect("genesis");
        let first = linked_validator_block(1, &genesis.header);
        let second = linked_validator_block(2, &first.header);
        service
            .shadow_sync_import_headers(vec![first.header.clone(), second.header.clone()])
            .expect("canonical headers");
        let second_hash = second.hash();
        let first_hash = first.hash();
        let ordinary_error = service
            .accept_block(NodeBlockImport::from_peer(second.clone(), 2))
            .expect_err("ordinary import still requires the parent body");
        assert!(ordinary_error.to_string().contains("parent index"));
        let node = Arc::new(Mutex::new(service));

        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest))
                .expect("peer manager");
        let (validation, _validation_results) =
            spawn_validation_pipeline(Arc::new(HnsBodyValidator::new(Network::Regtest)), 1, 8)
                .expect("validation pipeline");
        let mut scheduler =
            SyncScheduler::new(SyncLimits::default(), StdInstant::now()).expect("scheduler");
        scheduler
            .queue_block(second_hash, 2)
            .expect("second body reservation");
        scheduler.begin_local_validation(second_hash);
        let mut orphans = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 8,
            maximum_bytes: 1_024 * 1_024,
        })
        .expect("orphan pool");
        let diagnostics = Arc::new(RwLock::new(ShadowSyncDiagnostics::default()));

        handle_validation_result(
            Ok(hns_sync::ValidatedBlock {
                sequence: 0,
                peer: PeerId(1),
                height: 2,
                block: second,
            }),
            &node,
            &peers,
            &validation,
            &mut scheduler,
            &mut orphans,
            &diagnostics,
        )
        .await
        .expect("store out-of-order canonical body");

        let node = node.lock().await;
        assert!(node
            .shadow_sync_has_block(&second_hash)
            .expect("second body lookup"));
        assert!(!node
            .shadow_sync_has_block(&first_hash)
            .expect("first body lookup"));
        assert_eq!(
            node.shadow_sync_contiguous_body_tip(None)
                .expect("contiguous body tip"),
            None
        );
        drop(node);
        assert!(!scheduler.is_tracked_block(&second_hash));
        assert_eq!(orphans.snapshot().blocks, 0);
        assert_eq!(diagnostics.read().await.stored_bodies, 1);
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn out_of_order_canonical_body_survives_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-shadow-out-of-order-{}-{}",
            std::process::id(),
            current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = NodeConfig {
            network: Network::Regtest,
            data_dir: Some(path.clone()),
            shadow_sync: ShadowSyncConfig {
                enabled: true,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..ShadowSyncConfig::default()
            },
            ..NodeConfig::default()
        };
        let second_hash;
        let first_hash;

        {
            let mut service = NodeService::try_new(config.clone()).expect("open first node");
            let genesis = service
                .shadow_sync_ensure_genesis_header()
                .expect("genesis");
            let first = linked_validator_block(1, &genesis.header);
            let second = linked_validator_block(2, &first.header);
            second_hash = second.hash();
            first_hash = first.hash();
            service
                .shadow_sync_import_headers(vec![first.header.clone(), second.header.clone()])
                .expect("canonical headers");
            service
                .shadow_sync_store_shadow_block(second, 2, true)
                .expect("store out-of-order canonical body");
            mark_clean_shutdown(&service.state.store).expect("clean first shutdown");
        }

        {
            let service = NodeService::try_new(config).expect("reopen node");
            assert!(service
                .shadow_sync_has_block(&second_hash)
                .expect("reopened second body"));
            assert!(!service
                .shadow_sync_has_block(&first_hash)
                .expect("reopened first body"));
            mark_clean_shutdown(&service.state.store).expect("clean second shutdown");
        }

        std::fs::remove_dir_all(&path).expect("remove test store");
    }

    #[test]
    fn shadow_header_slice_validation_is_atomic() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .shadow_sync_ensure_genesis_header()
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
            .shadow_sync_import_headers(vec![first, invalid_second])
            .expect_err("late invalid header rejects the slice");

        assert_eq!(
            service
                .shadow_sync_best_header_tip()
                .expect("best header")
                .expect("tip")
                .hash,
            genesis.hash
        );
        assert_eq!(
            service
                .shadow_sync_header_record(&first_hash)
                .expect("first header lookup"),
            None
        );
    }

    #[tokio::test]
    async fn maximum_header_packet_imports_as_one_durable_batch() {
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
        for _ in 0..MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE {
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

        let imported = import_header_packet(&node, headers)
            .await
            .expect("maximum header packet");
        assert_eq!(imported.len(), MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE);

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
    fn canonical_body_queue_is_bounded_to_orphan_horizon() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            shadow_sync: ShadowSyncConfig {
                enabled: true,
                orphan_blocks: 2,
                connect: vec!["127.0.0.1:14038".parse().expect("peer")],
                ..ShadowSyncConfig::default()
            },
            ..NodeConfig::default()
        });
        let genesis = service
            .shadow_sync_ensure_genesis_header()
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
            .shadow_sync_import_headers(headers)
            .expect("canonical headers");

        let now = StdInstant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), hns_p2p::SERVICE_NETWORK, 4)
            .expect("peer");
        scheduler.set_best_header(service.shadow_sync_best_header_tip().expect("best header"));
        assert_eq!(
            service
                .shadow_sync_queue_missing_canonical_bodies(&mut scheduler)
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
                SyncAction::RequestBlock(request) => Some(request.height),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(requested, vec![0, 1]);
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

    #[test]
    fn canonical_headers_derive_hsd_deployment_and_script_policy() {
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
            .shadow_sync_import_headers(headers)
            .expect("deployment header ancestry");

        let diagnostics = service
            .shadow_sync_header_deployments()
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
        assert!(too_many_peers
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let too_fast = ShadowSyncConfig {
            poll_interval: Duration::from_millis(1),
            ..too_many_peers
        };
        assert!(too_fast
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let zero_connector_batch = ShadowSyncConfig {
            active_state_connect_batch: 0,
            ..too_fast
        };
        assert!(zero_connector_batch
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let oversized_connector_batch = ShadowSyncConfig {
            active_state_connect_batch: MAX_ACTIVE_STATE_CONNECT_BATCH + 1,
            ..zero_connector_batch
        };
        assert!(oversized_connector_batch
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());
    }

    #[tokio::test]
    async fn shadow_sync_serves_capability_named_diagnostic_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        service
            .shadow_sync_ensure_genesis_header()
            .expect("genesis header");
        let node = Arc::new(Mutex::new(service));
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

        for path in [
            "/api/v1/shadow-sync",
            "/api/v1/header-deployments",
            "/api/v1/mining-engine",
        ] {
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
            } else if path == "/api/v1/header-deployments" {
                assert_eq!(json["best_header"]["height"], 0);
                assert_eq!(json["next_height"], 1);
                assert_eq!(json["script_flags"], 50);
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
