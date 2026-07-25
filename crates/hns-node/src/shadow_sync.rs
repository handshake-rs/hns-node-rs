use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    middleware,
    routing::{get, post},
    Json, Router,
};
use hns_chain::{
    prepare_header_record, read_canonical_hash, BlockIndex, BlockIndexRecord, ChainTip,
    HeaderImport, HeaderIndex, HeaderRecord,
};
use hns_consensus::{
    advance_threshold_state, block_merkle_root, block_witness_root,
    compute_block_version_from_state, is_hsd_historical_block, validate_coinbase_height,
    validate_transaction_start, ConsensusParams, DeploymentState, HeaderConsensus, HeaderParent,
    HeaderValidationContext, Network, ThresholdState, MAX_FUTURE_BLOCK_TIME,
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
use hns_rpc::{BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcService};
#[cfg(all(test, feature = "rocksdb-backend"))]
use hns_store::mark_clean_shutdown;
use hns_store::{ColumnFamily, ReadSnapshot, Store, StoreHandle, WriteBatch};
use hns_sync::{
    spawn_validation_pipeline, BlockDownloadRequest, BoundedOrphanPool, OrderedValidationResult,
    OrphanLimits, OrphanSnapshot, StatelessBlockValidator, StoredSyncCheckpoint, SyncAction,
    SyncCheckpoint, SyncLimits, SyncScheduler, SyncSnapshot, ValidatedBlock, ValidationFailure,
    ValidationFailureKind, ValidationRejection, ValidationRequest, ValidationSubmitter,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch, Mutex, RwLock},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};

use super::{
    authority_info, best_block_tip_from_snapshot, best_header_tip_from_snapshot,
    completed_deployment_period_with_lookup, current_unix_time, expected_bits_with_lookup,
    json_rpc_error, load_block_index_record, load_header_record, mark_node_store_clean,
    median_time_past_with_lookup, mining_generation_from_snapshot, mining_snapshot_for_hash,
    require_rpc_authorization, AuthorityMode, ChainActivationFailure, DurableMiningState,
    FailedBlockMutation, FailedBlockStage, HeaderSummary, NativeRuntimeExtension, NodeBlockImport,
    NodeReorg, NodeService, RpcAuthorizationHeader, ShutdownSignal, HSRD_DIAGNOSTIC_API_VERSION,
};
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
const ADDRESS_BOOK_FLUSH_INTERVAL: Duration = Duration::from_secs(120);
const HSD_ADDRESS_HORIZON_SECONDS: u64 = 30 * 24 * 60 * 60;
const HSD_ADDRESS_MIN_FAIL_SECONDS: u64 = 7 * 24 * 60 * 60;
const HSD_ADDRESS_MAX_FAILURES: u32 = 10;
const HSD_ADDRESS_RECENT_ATTEMPT_SECONDS: u64 = 60;
const HSD_ADDRESS_TIMESTAMP_REFRESH_SECONDS: u64 = 20 * 60;
const MAX_ADDR_FUTURE_SECONDS: u64 = 10 * 60;
const FALLBACK_ADDR_AGE_SECONDS: u64 = 5 * 24 * 60 * 60;
const MIN_ADDR_TIMESTAMP: u64 = 100_000_000;
const MAX_SHADOW_SYNC_PEERS: usize = 256;
const MAX_SHADOW_SYNC_VALIDATION_WORKERS: usize = 128;
const MAX_SHADOW_SYNC_VALIDATION_QUEUE: usize = 8_192;
const MAX_VALIDATED_BODY_COMMIT_BATCH: usize = 32;
const MAX_SHADOW_SYNC_ORPHAN_BLOCKS: usize = 8_192;
const MAX_SHADOW_SYNC_ORPHAN_BYTES: usize = 1024 * 1024 * 1024;
const MAX_ACTIVE_STATE_CONNECT_BATCH: usize = 1_024;
pub(super) const MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE: usize = 288;
const MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE: usize = hns_p2p::MAX_HEADERS;
const MIN_SHADOW_SYNC_POLL_INTERVAL: Duration = Duration::from_millis(10);
// Native IBD deliberately fails over stalled body reservations sooner than
// HSD's conservative two-minute connection timeout. The request remains
// single-flight, bounded, and independently validated after reassignment.
const NATIVE_BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const NATIVE_MAX_INFLIGHT_PER_PEER: usize = 32;
const BRONTIDE_IDENTITY_FILE: &str = "p2p-identity-v1.key";

// Key-bearing fixed seeds from the pinned HSD `lib/net/seeds` tables. HSD's
// DNS seed answers expose legacy plaintext endpoints without static keys, so a
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
pub struct ShadowSyncConfig {
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

/// Native name for the synchronization configuration. The older alias remains
/// available so persisted API integrations can migrate without a flag day.
pub type NativeSyncConfig = ShadowSyncConfig;

impl Default for ShadowSyncConfig {
    fn default() -> Self {
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
            AuthorityMode::Disabled | AuthorityMode::Shadow | AuthorityMode::Native
        ) {
            anyhow::bail!(
                "native sync live P2P requires disabled, shadow, or native authority mode"
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
        if self.validation_workers > MAX_SHADOW_SYNC_VALIDATION_WORKERS {
            anyhow::bail!(
                "Native sync validation workers {} exceed the hard limit {}",
                self.validation_workers,
                MAX_SHADOW_SYNC_VALIDATION_WORKERS
            );
        }
        if self.validation_queue > MAX_SHADOW_SYNC_VALIDATION_QUEUE {
            anyhow::bail!(
                "Native sync validation queue {} exceeds the hard limit {}",
                self.validation_queue,
                MAX_SHADOW_SYNC_VALIDATION_QUEUE
            );
        }
        if self.orphan_blocks == 0 || self.orphan_bytes == 0 {
            anyhow::bail!("Native sync orphan bounds must be non-zero");
        }
        if self.orphan_blocks > MAX_SHADOW_SYNC_ORPHAN_BLOCKS {
            anyhow::bail!(
                "Native sync orphan block limit {} exceeds the hard limit {}",
                self.orphan_blocks,
                MAX_SHADOW_SYNC_ORPHAN_BLOCKS
            );
        }
        if self.orphan_bytes > MAX_SHADOW_SYNC_ORPHAN_BYTES {
            anyhow::bail!(
                "Native sync orphan byte limit {} exceeds the hard limit {}",
                self.orphan_bytes,
                MAX_SHADOW_SYNC_ORPHAN_BYTES
            );
        }
        if self.poll_interval < MIN_SHADOW_SYNC_POLL_INTERVAL {
            anyhow::bail!(
                "Native sync poll interval must be at least {} ms",
                MIN_SHADOW_SYNC_POLL_INTERVAL.as_millis()
            );
        }
        let maximum_peers = self
            .maximum_inbound
            .checked_add(self.maximum_outbound)
            .ok_or_else(|| anyhow::anyhow!("Native sync peer limits overflow usize"))?;
        if maximum_peers > MAX_SHADOW_SYNC_PEERS {
            anyhow::bail!(
                "Native sync total peer limit {maximum_peers} exceeds the hard limit {MAX_SHADOW_SYNC_PEERS}"
            );
        }

        let mut unique = HashSet::with_capacity(self.connect.len());
        for address in &self.connect {
            if !unique.insert(*address) {
                anyhow::bail!("duplicate native-sync outbound peer {address}");
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

pub type NativeSyncDiagnostics = ShadowSyncDiagnostics;

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
pub(super) struct ActiveStateWorkload {
    transactions: usize,
    non_coinbase_inputs: usize,
    outputs: usize,
    name_actions: usize,
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
            self.dirty = true;
        }

        self.sequence = self.sequence.saturating_add(1);
        self.entries.insert(
            address,
            KnownPeerAddress {
                wire,
                configured: false,
                failures: 0,
                last_success: 0,
                last_attempt: 0,
                eligible_at: now,
                sequence: self.sequence,
            },
        );
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
        let before = self.entries.len();
        self.entries.retain(|candidate, entry| {
            entry.configured || normalize_peer_ip(candidate.ip()) != address
        });
        let removed = before.saturating_sub(self.entries.len());
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
            entry.wire.time = timestamp;
            if !entry.configured {
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
            self.entries.insert(
                entry.address,
                KnownPeerAddress {
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
                },
            );
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
    pub async fn run_shadow_sync_until_shutdown(self, shutdown: ShutdownSignal) -> Result<()> {
        self.run_shadow_sync_until_shutdown_with_extension(shutdown, None)
            .await
    }

    pub(crate) async fn run_shadow_sync_until_shutdown_with_extension(
        self,
        shutdown: ShutdownSignal,
        extension: Option<Box<dyn NativeRuntimeExtension>>,
    ) -> Result<()> {
        self.config
            .shadow_sync
            .validate(self.config.authority_mode, self.config.network)?;
        if !self.config.shadow_sync.enabled {
            return self.run_rpc_until_shutdown(shutdown).await;
        }

        let shadow_sync_config = self.config.shadow_sync.clone();
        let rpc_bind = self.config.rpc_bind;
        let rpc_authorization = self.config.rpc_authorization.clone();
        let network = self.config.network;
        let data_dir = self.config.data_dir.clone();
        let ban_list_persistent = self.config.data_dir.is_some();
        let address_book_persistent = shadow_sync_config.discovery && ban_list_persistent;
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
        if matches!(network, Network::Mainnet | Network::Testnet) {
            peer_config.transport =
                PeerTransport::Brontide(load_or_create_brontide_identity(data_dir.as_deref())?);
        }
        peer_config.maximum_inbound = shadow_sync_config.maximum_inbound;
        peer_config.maximum_outbound = shadow_sync_config.maximum_outbound;
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
            if let Some(key) = shadow_sync_config.connect_keys.get(address) {
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
        if shadow_sync_config.discovery {
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
            &ban_list,
            shadow_sync_config.maximum_outbound,
            address_now,
            address_timestamp,
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
            sync: scheduler.snapshot(),
            orphans: orphan_pool.snapshot(),
            checkpoint_sequence: initial_sequence,
            ..ShadowSyncDiagnostics::default()
        }));
        let diagnostic_rpc = initialize_cached_diagnostic_rpc(&node, &diagnostics).await?;

        // Bind diagnostics before startup replay/compaction. The cached,
        // explicitly timestamped snapshot remains readable while the
        // state-coordination lock is held; authoritative parent reads still
        // wait for the live node.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let rpc_listener = TcpListener::bind(rpc_bind)
            .await
            .with_context(|| format!("failed to bind RPC listener on {rpc_bind}"))?;
        let rpc_task = tokio::spawn(serve_shadow_sync_rpc(
            rpc_listener,
            Arc::clone(&node),
            Arc::clone(&diagnostics),
            Arc::clone(&diagnostic_rpc),
            rpc_authorization,
            shutdown_rx.clone(),
        ));

        if shadow_sync_config.connect_active_state {
            if let Err(error) = connect_stored_active_state_with_diagnostic_rpc(
                &node,
                &peers,
                &mut scheduler,
                &mut orphan_pool,
                &diagnostics,
                &diagnostic_rpc,
                shadow_sync_config.active_state_connect_batch,
            )
            .await
            {
                let _ = shutdown_tx.send(true);
                let _ = rpc_task.await;
                return Err(error.context("failed to resume active-state synchronization"));
            }
        }

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
        let mut extension_task = extension.map(|extension| {
            extension.spawn(Arc::clone(&node), peers.clone(), shutdown_rx.clone())
        });

        let (connect_results_tx, mut connect_results_rx) =
            mpsc::channel::<ConnectAttemptResult>(shadow_sync_config.maximum_outbound.max(1));

        tracing::info!(
            rpc = %rpc_bind,
            p2p = ?shadow_sync_config.listen,
            outbound = reconnects.len(),
            discovery = shadow_sync_config.discovery,
            known_addresses = address_book.len(),
            "hsrd native-sync runtime started"
        );

        let mut checkpoint_sequence = initial_sequence;
        let mut poll = tokio::time::interval(shadow_sync_config.poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        poll.tick().await;
        let mut active_state_poll = tokio::time::interval(MIN_SHADOW_SYNC_POLL_INTERVAL);
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

        loop {
            tokio::select! {
                _ = &mut shutdown_wait => break,
                _ = peer_state_flush.tick(), if ban_list_persistent => {
                    if address_book_persistent {
                        flush_address_book(&store, &mut address_book, &diagnostics).await;
                    }
                    flush_peer_bans(&store, &mut ban_list, &diagnostics).await;
                }
                _ = active_state_poll.tick(),
                    if shadow_sync_config.connect_active_state
                        && active_state_work_ready(&scheduler) =>
                {
                    // One atomic slice per scheduler turn. The independent
                    // short cadence removes the general poll-rate ceiling,
                    // while Delay semantics force an inter-slice opportunity
                    // for peer events, validation results, and shutdown.
                    if let Err(error) = connect_stored_active_state_with_diagnostic_rpc(
                        &node,
                        &peers,
                        &mut scheduler,
                        &mut orphan_pool,
                        &diagnostics,
                        &diagnostic_rpc,
                        shadow_sync_config.active_state_connect_batch,
                    )
                    .await
                    {
                        let error = error.context("active-state synchronization failed");
                        record_error(&diagnostics, format!("{error:#}")).await;
                        terminal_error = Some(error);
                        break;
                    }
                    active_state_poll.reset_after(MIN_SHADOW_SYNC_POLL_INTERVAL);
                    update_diagnostics(&diagnostics, |state| {
                        state.peer_event_backlog = peer_events.len();
                        state.validation_result_backlog = validated.len();
                    })
                    .await;
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
                _ = poll.tick() => {
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
                    if extension_task.as_ref().is_some_and(|task| task.is_finished()) {
                        let task = extension_task.take().expect("finished extension task");
                        let message = match task.await {
                            Ok(Ok(())) => {
                                "native runtime extension terminated unexpectedly".to_owned()
                            }
                            Ok(Err(error)) => {
                                format!("native runtime extension failed: {error:#}")
                            }
                            Err(error) => {
                                format!("native runtime extension task failed: {error}")
                            }
                        };
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
                    if shadow_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            &ban_list,
                            shadow_sync_config.maximum_outbound,
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

                    let queue_result = {
                        let node = node.lock().await;
                        node.shadow_sync_queue_missing_canonical_bodies(&mut scheduler)
                    };
                    if let Err(error) = queue_result {
                        let error = error.context(
                            "failed to refresh canonical block-body work queue",
                        );
                        record_error(&diagnostics, format!("{error:#}")).await;
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
                            record_error(&diagnostics, format!("{error:#}")).await;
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
                        &diagnostics,
                    )
                    .await;
                    if shadow_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            &ban_list,
                            shadow_sync_config.maximum_outbound,
                            Instant::now(),
                            unix_time(),
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
                            &ban_list,
                            &mut served_getaddr,
                            &mut compact_peers,
                            &mut pending_compact_blocks,
                            shadow_sync_config.discovery,
                            shadow_sync_config.headers_only,
                            &diagnostics,
                        ) => Some(result),
                    };
                    let Some(handled) = handled else {
                        break;
                    };
                    if let Err(error) = handled {
                        record_warning(format!("{error:#}"));
                    }
                    if shadow_sync_config.discovery {
                        fill_discovery_slots(
                            &address_book,
                            &mut reconnects,
                            &ban_list,
                            shadow_sync_config.maximum_outbound,
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
                result = validated.recv() => {
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
                    let validation_result = handle_validation_results(
                        results,
                        &node,
                        &peers,
                        &validation,
                        &mut scheduler,
                        &mut orphan_pool,
                        &diagnostics,
                    )
                    .await;
                    if let Err(error) = &validation_result {
                        record_warning(format!("{error:#}"));
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
        if let Err(error) = persist_checkpoint(&checkpoint_store, &scheduler, checkpoint_sequence) {
            record_error(&diagnostics, format!("{error:#}")).await;
            if terminal_error.is_none() {
                terminal_error = Some(error);
            }
        }
        let _ = shutdown_tx.send(true);
        let extension_result = match extension_task {
            Some(task) => await_task("native runtime extension", task).await,
            None => Ok(()),
        };
        peers.disconnect_all().await;

        let rpc_result = await_task("RPC", rpc_task).await;
        let listener_result = match listener_task {
            Some(task) => await_p2p_task("P2P listener", task).await,
            None => Ok(()),
        };

        if terminal_error.is_none()
            && rpc_result.is_ok()
            && listener_result.is_ok()
            && extension_result.is_ok()
        {
            mark_node_store_clean(&store, network)?;
        }
        if let Some(error) = terminal_error {
            return Err(error);
        }
        rpc_result?;
        listener_result?;
        extension_result?;
        tracing::info!("hsrd native-sync runtime stopped");
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
            .block(hash)
            .map(|record| record.is_some_and(|record| record.status.body_present))
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

    fn shadow_sync_store_validated_blocks(
        &mut self,
        blocks: Vec<(ValidatedBlock, bool)>,
    ) -> Result<Vec<BlockIndexRecord>> {
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
                .validate_prevalidated_shadow_import(&request, canonical, stateless)?;
            candidates.push((request, import));
        }
        self.state
            .store_validated_alternates(candidates)
            .map(|mutations| {
                mutations
                    .into_iter()
                    .map(|mutation| mutation.record)
                    .collect()
            })
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

    #[cfg(test)]
    pub(super) fn shadow_sync_connect_stored_state(
        &mut self,
        maximum_connect: usize,
    ) -> Result<ActiveStateConnectOutcome> {
        self.shadow_sync_connect_stored_state_with_hint(maximum_connect, None)
    }

    fn shadow_sync_connect_stored_state_with_hint(
        &mut self,
        maximum_connect: usize,
        stored_tip_hint: Option<&ChainTip>,
    ) -> Result<ActiveStateConnectOutcome> {
        let planning_started = StdInstant::now();
        if maximum_connect == 0 || maximum_connect > MAX_ACTIVE_STATE_CONNECT_BATCH {
            anyhow::bail!(
                "active-state connector batch {maximum_connect} is outside 1..={MAX_ACTIVE_STATE_CONNECT_BATCH}"
            );
        }

        let Some(stored_tip) = self.shadow_sync_contiguous_body_tip(stored_tip_hint)? else {
            return Ok(ActiveStateConnectOutcome::default());
        };
        let active_tip = self.shadow_sync_active_tip()?;
        if active_tip.as_ref() == Some(&stored_tip) {
            return Ok(ActiveStateConnectOutcome::default());
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
        let workload =
            activation
                .connect
                .iter()
                .fold(ActiveStateWorkload::default(), |mut total, connect| {
                    total.transactions = total
                        .transactions
                        .saturating_add(connect.block.transactions.len());
                    for (transaction_index, transaction) in
                        connect.block.transactions.iter().enumerate()
                    {
                        if transaction_index != 0 {
                            total.non_coinbase_inputs = total
                                .non_coinbase_inputs
                                .saturating_add(transaction.inputs.len());
                        }
                        total.outputs = total.outputs.saturating_add(transaction.outputs.len());
                        total.name_actions = total.name_actions.saturating_add(
                            transaction
                                .outputs
                                .iter()
                                .filter(|output| output.covenant.kind != CovenantKind::None)
                                .count(),
                        );
                    }
                    total
                });
        let planning_micros =
            u64::try_from(planning_started.elapsed().as_micros()).unwrap_or(u64::MAX);

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
        let mutation = self.state.apply_reorg_classified(NodeReorg {
            disconnect: activation.disconnect,
            connect: activation.connect,
        });
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
                Ok(ActiveStateConnectOutcome {
                    connected: reorg.summary.connected.len(),
                    disconnected: reorg.summary.disconnected.len(),
                    contextual_failure: None,
                    planning_micros,
                    state_commit_micros,
                    post_commit_micros,
                    workload,
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
                let post_commit_micros =
                    u64::try_from(post_commit_started.elapsed().as_micros()).unwrap_or(u64::MAX);
                Ok(ActiveStateConnectOutcome {
                    contextual_failure: Some(failed),
                    planning_micros,
                    state_commit_micros,
                    post_commit_micros,
                    workload,
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

    /// Build Core's parent-authority response with O(1) keyed reads while the
    /// native-sync coordinator lock excludes a concurrent chain transition.
    /// The general diagnostic snapshot intentionally remains richer and may
    /// scan state; parent requalification must not put that work in the mining
    /// critical path.
    fn parent_authority_value(&self, hash: BlockHash) -> Result<serde_json::Value> {
        let snapshot = self.state.store.snapshot()?;
        let active_tip = best_block_tip_from_snapshot(&snapshot)?;
        let best_header = best_header_tip_from_snapshot(&snapshot)?;
        let header = load_header_record(&snapshot, &hash)?
            .ok_or_else(|| anyhow::anyhow!("block header not found"))?;
        if read_canonical_hash(&snapshot, header.height)? != Some(hash) {
            anyhow::bail!("block header is not canonical");
        }

        let generation = mining_generation_from_snapshot(&snapshot)?;
        let (mining_snapshot, authoritative) = match active_tip.as_ref() {
            Some(tip) => {
                let (mining_snapshot, authoritative) = mining_snapshot_for_hash(
                    &snapshot,
                    self.config.network.canonical_id(),
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
        let authority = authority_info(&self.config, &durable);
        let tip_validation = match active_tip.as_ref() {
            Some(tip) => load_block_index_record(&snapshot, &tip.hash)?.map(|record| record.status),
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
            "network": self.config.network.to_string(),
            "rpc_authentication_required": self.config.rpc_authorization.is_some(),
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
            "authoritative_mining_tip": self.mining_events.snapshot().is_some(),
            "pending_best_chain_activation": pending_best_chain_activation,
            "tip_validation": tip_validation,
        }))
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
struct ShadowSyncHttpState {
    node: Arc<Mutex<NodeService>>,
    diagnostics: Arc<RwLock<ShadowSyncDiagnostics>>,
    diagnostic_rpc: Arc<RwLock<CachedDiagnosticRpc>>,
}

#[derive(Clone)]
struct CachedDiagnosticRpc {
    service: BasicRpcService,
    captured_at: u64,
}

async fn serve_shadow_sync_rpc(
    listener: TcpListener,
    node: Arc<Mutex<NodeService>>,
    diagnostics: Arc<RwLock<ShadowSyncDiagnostics>>,
    diagnostic_rpc: Arc<RwLock<CachedDiagnosticRpc>>,
    authorization: Option<RpcAuthorizationHeader>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let state = ShadowSyncHttpState {
        node,
        diagnostics,
        diagnostic_rpc,
    };
    let app = Router::new()
        .route("/", post(handle_shadow_sync_rpc))
        .route("/rpc", post(handle_shadow_sync_rpc))
        .route("/api/v1/status", get(handle_shadow_sync_status))
        .route("/api/v1/authority", get(handle_shadow_sync_authority))
        .route("/api/v1/parity", get(handle_shadow_sync_parity))
        .route("/api/v1/peers", get(handle_shadow_sync_peers))
        .route("/api/v1/sync", get(handle_shadow_sync_sync))
        .route("/api/v1/native-sync", get(handle_shadow_sync_diagnostics))
        .route("/api/v1/shadow-sync", get(handle_shadow_sync_diagnostics))
        .route("/api/v1/header-deployments", get(handle_header_deployments))
        .route(
            "/api/v1/mining-engine",
            get(handle_mining_engine_diagnostics),
        )
        .with_state(state);
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

async fn shadow_sync_rpc_service(
    state: &ShadowSyncHttpState,
    include_entries: bool,
) -> Result<BasicRpcService> {
    let diagnostics = state.diagnostics.read().await.clone();
    let node = state.node.lock().await;
    compose_shadow_sync_rpc_service(&node, &diagnostics, include_entries)
}

fn compose_shadow_sync_rpc_service(
    node: &NodeService,
    diagnostics: &ShadowSyncDiagnostics,
    include_entries: bool,
) -> Result<BasicRpcService> {
    let mut snapshot = if include_entries {
        node.rpc_snapshot()?
    } else {
        node.rpc_diagnostic_snapshot()?
    };
    snapshot.network_active = diagnostics.enabled;
    snapshot.peer_count = diagnostics.peers.len();
    snapshot.node_status.release_stage = if node.config.mainnet_canary {
        "mainnet-canary-gated".to_owned()
    } else if node.config.mining_engine.enabled {
        "mining-engine-observe".to_owned()
    } else {
        "native-sync-live-p2p".to_owned()
    };
    snapshot.node_status.parity.configured = false;
    snapshot.node_status.parity.live_shadow_active = false;
    snapshot.node_status.parity.state =
        "historical-replay-qualified-native-no-live-oracle".to_owned();
    Ok(BasicRpcService::new(snapshot))
}

async fn initialize_cached_diagnostic_rpc(
    node: &Arc<Mutex<NodeService>>,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<Arc<RwLock<CachedDiagnosticRpc>>> {
    let diagnostics = diagnostics.read().await.clone();
    let node = node.lock().await;
    Ok(Arc::new(RwLock::new(CachedDiagnosticRpc {
        service: compose_shadow_sync_rpc_service(&node, &diagnostics, false)?,
        captured_at: unix_time(),
    })))
}

async fn refresh_cached_diagnostic_rpc(
    node: &Arc<Mutex<NodeService>>,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    diagnostic_rpc: &Arc<RwLock<CachedDiagnosticRpc>>,
) -> Result<()> {
    let diagnostics = diagnostics.read().await.clone();
    let node = node.lock().await;
    let service = compose_shadow_sync_rpc_service(&node, &diagnostics, false)?;
    drop(node);
    *diagnostic_rpc.write().await = CachedDiagnosticRpc {
        service,
        captured_at: unix_time(),
    };
    Ok(())
}

async fn available_diagnostic_rpc(
    state: &ShadowSyncHttpState,
) -> Result<(BasicRpcService, bool, u64)> {
    let diagnostics = state.diagnostics.read().await.clone();
    if let Ok(node) = state.node.try_lock() {
        let service = compose_shadow_sync_rpc_service(&node, &diagnostics, false)?;
        let captured_at = unix_time();
        drop(node);
        *state.diagnostic_rpc.write().await = CachedDiagnosticRpc {
            service: service.clone(),
            captured_at,
        };
        return Ok((service, false, captured_at));
    }
    let cached = state.diagnostic_rpc.read().await.clone();
    Ok((cached.service, true, cached.captured_at))
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
    if matches!(
        request.method.as_str(),
        "gethsrdstatus" | "getauthorityinfo" | "getparityinfo" | "getminingengineinfo"
    ) {
        return cached_json_rpc_diagnostic(&state, request).await;
    }
    if request.method == "getblockhash" {
        let Some(height) = request
            .params
            .as_array()
            .and_then(|params| params.first())
            .and_then(serde_json::Value::as_u64)
            .and_then(|height| Height::try_from(height).ok())
        else {
            return Json(json_rpc_error(
                id,
                -32602,
                "missing or invalid block height".to_owned(),
            ));
        };
        let result = state.node.lock().await.state.chain.canonical_hash(height);
        return match result {
            Ok(Some(hash)) => Json(JsonRpcResponse {
                jsonrpc: "2.0".to_owned(),
                result: Some(serde_json::json!(hash.to_hex())),
                error: None,
                id,
            }),
            Ok(None) => Json(json_rpc_error(
                id,
                -8,
                "block height out of range".to_owned(),
            )),
            Err(error) => Json(json_rpc_error(id, -32603, error.to_string())),
        };
    }
    if request.method == "getparentauthority" {
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
        let result = state.node.lock().await.parent_authority_value(hash);
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
    match shadow_sync_rpc_service(&state, true).await {
        Ok(service) => Json(
            service
                .handle(request)
                .unwrap_or_else(|error| json_rpc_error(id, -32603, error.to_string())),
        ),
        Err(error) => Json(json_rpc_error(id, -32603, error.to_string())),
    }
}

async fn diagnostic_method(state: &ShadowSyncHttpState, method: &str) -> serde_json::Value {
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
    state: &ShadowSyncHttpState,
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
    Json(diagnostic_method(&state, "getminingengineinfo").await)
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
    bans: &PeerBanBook,
    served_getaddr: &mut HashSet<PeerId>,
    compact_peers: &mut HashSet<PeerId>,
    pending_compact_blocks: &mut HashMap<BlockHash, PendingCompactBlock>,
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
        PeerEvent::Packet { peer, packet } => match packet {
            Packet::Headers(headers) => {
                let header_count = headers.len();
                let imported = import_header_packet(node, headers).await;
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
                    Err(error) => {
                        // A connecting response consumes the outstanding
                        // request even if its consensus validation fails.
                        // Otherwise a malicious peer can pin the request slot
                        // until the timeout fires.
                        scheduler.note_headers_response(peer, header_count);
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
                scheduler.note_headers_response(peer, header_count);
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
                        let missing = {
                            let node = node.lock().await;
                            if !node.config.mining_engine.enabled
                                || !node.config.mining_engine.transaction_relay
                            {
                                false
                            } else {
                                match item.kind {
                                    InventoryKind::Transaction => node
                                        .mining_engine_mempool_transaction(&Txid::new(item.hash))
                                        .is_none(),
                                    InventoryKind::Claim => {
                                        node.mining_engine_mempool_claim(&item.hash).is_none()
                                    }
                                    InventoryKind::Airdrop => {
                                        node.mining_engine_mempool_airdrop(&item.hash).is_none()
                                    }
                                    _ => false,
                                }
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
                        InventoryKind::Claim => {
                            let claim = {
                                let node = node.lock().await;
                                if node.config.mining_engine.enabled
                                    && node.config.mining_engine.transaction_relay
                                {
                                    node.mining_engine_mempool_claim(&item.hash)
                                } else {
                                    None
                                }
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
                            let proof = {
                                let node = node.lock().await;
                                if node.config.mining_engine.enabled
                                    && node.config.mining_engine.transaction_relay
                                {
                                    node.mining_engine_mempool_airdrop(&item.hash)
                                } else {
                                    None
                                }
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
                        InventoryKind::CompactBlock => {
                            let hash = BlockHash::new(item.hash);
                            let block = {
                                let node = node.lock().await;
                                node.shadow_sync_block(&hash)?
                            };
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
            Packet::Claim(claim) => {
                update_diagnostics(diagnostics, |state| {
                    state.received_claims = state.received_claims.saturating_add(1);
                })
                .await;
                let admission = {
                    let mut node = node.lock().await;
                    node.mining_engine_accept_peer_claim(claim)?
                };
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
                let admission = {
                    let mut node = node.lock().await;
                    node.mining_engine_accept_peer_airdrop(proof)?
                };
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
async fn handle_compact_block(
    peer: PeerId,
    compact: CompactBlock,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    compact_peers: &HashSet<PeerId>,
    pending: &mut HashMap<BlockHash, PendingCompactBlock>,
    headers_only: bool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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

    let mempool = {
        let node = node.lock().await;
        node.mining_engine_mempool_transactions(hns_p2p::MAX_COMPACT_BLOCK_TRANSACTIONS)
    };
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
        return accept_peer_block(peer, block, node, peers, validation, scheduler).await;
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
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    pending: &mut HashMap<BlockHash, PendingCompactBlock>,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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
    accept_peer_block(peer, block, node, peers, validation, scheduler).await
}

async fn request_full_block_fallback(
    peer: PeerId,
    hash: BlockHash,
    peers: &LivePeerManager,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
    let block_hash = request.block_hash;
    let block = {
        let node = node.lock().await;
        let Some(record) = node.shadow_sync_header_record(&block_hash)? else {
            drop(node);
            penalize_peer(peers, peer, 100, "getblocktxn requested an unknown block").await?;
            anyhow::bail!("peer {peer:?} requested transactions for unknown block");
        };
        let active_height = node.shadow_sync_active_tip()?.map_or(0, |tip| tip.height);
        if record.height.saturating_add(15) < active_height {
            return Ok(());
        }
        node.shadow_sync_block(&block_hash)?
    };
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

async fn handle_validation_results(
    results: Vec<OrderedValidationResult>,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
    let mut validated = Vec::new();
    let mut first_failure = None;

    for result in results {
        match result {
            Ok(block) => validated.push(block),
            Err(failure) => {
                if !validated.is_empty() {
                    handle_validated_blocks(
                        std::mem::take(&mut validated),
                        node,
                        validation,
                        scheduler,
                        orphans,
                        diagnostics,
                    )
                    .await?;
                }
                if let Err(error) =
                    handle_validation_failure(failure, node, peers, scheduler, orphans, diagnostics)
                        .await
                {
                    first_failure.get_or_insert(error);
                }
            }
        }
    }

    if !validated.is_empty() {
        handle_validated_blocks(validated, node, validation, scheduler, orphans, diagnostics)
            .await?;
    }

    match first_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn handle_validated_blocks(
    validated: Vec<ValidatedBlock>,
    node: &Arc<Mutex<NodeService>>,
    validation: &ValidationSubmitter,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
    let mut eligible = Vec::with_capacity(validated.len());
    for validated in validated {
        let hash = validated.block.hash();
        let (parent_available, canonical) = {
            let node = node.lock().await;
            (
                validated.block.header == node.config.network.params().genesis_header()
                    || node.shadow_sync_has_block(&validated.block.header.prev_block)?,
                node.shadow_sync_is_canonical_header(hash, validated.height)?,
            )
        };
        if parent_available || canonical {
            eligible.push((validated, canonical));
            continue;
        }

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
    let stored = {
        let mut node = node.lock().await;
        node.shadow_sync_store_validated_blocks(eligible)?
    };
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
    {
        let node = node.lock().await;
        let stored_tip = node.shadow_sync_contiguous_body_tip(scheduler.stored_tip())?;
        if scheduler.stored_tip() != stored_tip.as_ref() {
            scheduler.set_stored_tip(stored_tip);
        }
        node.shadow_sync_queue_missing_canonical_bodies(scheduler)?;
    }
    let stored_count = u64::try_from(stored.len()).unwrap_or(u64::MAX);
    update_diagnostics(diagnostics, |state| {
        state.stored_bodies = state.stored_bodies.saturating_add(stored_count);
    })
    .await;
    for record in stored {
        submit_released_orphans(record.hash, node, validation, scheduler, orphans).await?;
    }
    Ok(())
}

async fn handle_validation_failure(
    failure: ValidationFailure,
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
) -> Result<()> {
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

#[cfg(test)]
pub(super) async fn connect_stored_active_state(
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    maximum_connect: usize,
) -> Result<()> {
    let diagnostic_rpc = initialize_cached_diagnostic_rpc(node, diagnostics).await?;
    connect_stored_active_state_with_diagnostic_rpc(
        node,
        peers,
        scheduler,
        orphans,
        diagnostics,
        &diagnostic_rpc,
        maximum_connect,
    )
    .await
}

async fn connect_stored_active_state_with_diagnostic_rpc(
    node: &Arc<Mutex<NodeService>>,
    peers: &LivePeerManager,
    scheduler: &mut SyncScheduler,
    orphans: &mut BoundedOrphanPool,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    diagnostic_rpc: &Arc<RwLock<CachedDiagnosticRpc>>,
    maximum_connect: usize,
) -> Result<()> {
    // The scheduler's stored tip is already a validated contiguous frontier.
    // Revalidate that one anchor and scan only newly available descendants;
    // restarting at genesis here makes replay quadratic because this helper is
    // called on every supervisor tick and after each full validation slice.
    let stored_tip_hint = scheduler.stored_tip().cloned();
    let slice_started = StdInstant::now();
    let outcome = {
        let mut node = node.lock().await;
        node.shadow_sync_connect_stored_state_with_hint(maximum_connect, stored_tip_hint.as_ref())?
    };
    let slice_blocks = outcome.connected.saturating_add(outcome.disconnected);
    if slice_blocks != 0 || outcome.contextual_failure.is_some() {
        let slice_millis = u64::try_from(slice_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        update_diagnostics(diagnostics, |state| {
            state.active_state_slices = state.active_state_slices.saturating_add(1);
            state.active_state_last_slice_blocks = slice_blocks;
            state.active_state_last_slice_millis = slice_millis;
            state.active_state_max_slice_millis =
                state.active_state_max_slice_millis.max(slice_millis);
            state.active_state_last_planning_micros = outcome.planning_micros;
            state.active_state_last_commit_micros = outcome.state_commit_micros;
            state.active_state_last_post_commit_micros = outcome.post_commit_micros;
            state.active_state_last_transactions = outcome.workload.transactions;
            state.active_state_last_non_coinbase_inputs = outcome.workload.non_coinbase_inputs;
            state.active_state_last_outputs = outcome.workload.outputs;
            state.active_state_last_name_actions = outcome.workload.name_actions;
        })
        .await;
    }
    // Capture the newly committed tip before a due compaction takes the
    // state-coordination lock for its long, stable-snapshot deletion pass.
    // Diagnostic RPC can serve this explicitly marked snapshot while all
    // authoritative state access remains serialized behind the lock.
    refresh_cached_diagnostic_rpc(node, diagnostics, diagnostic_rpc).await?;
    let compaction = {
        let mut node = node.lock().await;
        node.compact_pruned_name_tree_nodes_if_due()?
    };
    if let Some(checkpoint) = compaction {
        tracing::info!(
            height = checkpoint.height,
            tip = %checkpoint.tip.to_hex(),
            nodes_before = checkpoint.summary.nodes_before,
            nodes_retained = checkpoint.summary.nodes_retained,
            nodes_deleted = checkpoint.summary.nodes_deleted,
            "compacted pruned durable name tree during native sync"
        );
        refresh_cached_diagnostic_rpc(node, diagnostics, diagnostic_rpc).await?;
    }

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

fn active_state_work_ready(scheduler: &SyncScheduler) -> bool {
    match (scheduler.stored_tip(), scheduler.active_tip()) {
        (Some(stored), Some(active)) => stored != active,
        (Some(_), None) => true,
        (None, _) => false,
    }
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
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
    peers: &LivePeerManager,
    scheduler: &SyncScheduler,
    orphans: &BoundedOrphanPool,
    reconnects: &HashMap<SocketAddr, ReconnectState>,
    addresses: &BoundedAddressBook,
    bans: &PeerBanBook,
    compact_peers: &HashSet<PeerId>,
    pending_compact_blocks: &HashMap<BlockHash, PendingCompactBlock>,
    checkpoint_sequence: u64,
) {
    let traffic = peers.traffic_totals().await;
    let snapshots = peers.snapshots().await;
    let mut state = diagnostics.write().await;
    state.bytes_sent = traffic.bytes_sent;
    state.bytes_received = traffic.bytes_received;
    state.peers = snapshots;
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

async fn flush_address_book(
    store: &StoreHandle,
    addresses: &mut BoundedAddressBook,
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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
    diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>,
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

async fn update_diagnostics<F>(diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>, update: F)
where
    F: FnOnce(&mut ShadowSyncDiagnostics),
{
    let mut state = diagnostics.write().await;
    update(&mut state);
}

async fn record_error(diagnostics: &Arc<RwLock<ShadowSyncDiagnostics>>, error: String) {
    tracing::warn!(%error, "Native sync runtime error");
    update_diagnostics(diagnostics, |state| state.last_error = Some(error)).await;
}

fn record_warning(warning: String) {
    tracing::warn!(%warning, "Native sync peer/runtime warning");
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
        Address, Covenant, CovenantKind, Input, Outpoint, Output, Transaction, Txid, Uint256,
        Witness,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn parent_authority_fast_path_is_coherent_and_fail_closed() {
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

        let value = node.parent_authority_value(hash).expect("parent authority");
        assert_eq!(value["network"], "regtest");
        assert_eq!(value["rpc_authentication_required"], true);
        assert_eq!(value["chain"]["bestblockhash"], hash.to_hex());
        assert_eq!(value["header"]["hash"], hash.to_hex());
        assert_eq!(value["header"]["confirmations"], 1);
        assert_eq!(value["authority"]["mode"], "native");
        assert_eq!(value["authority"]["consensus_complete"], true);
        assert_eq!(value["authoritative_mining_tip"], true);
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

        let discovery = ShadowSyncConfig {
            enabled: true,
            discovery: true,
            ..ShadowSyncConfig::default()
        };
        discovery
            .validate(AuthorityMode::Shadow, Network::Mainnet)
            .expect("mainnet has HSD Brontide seeds");
        assert!(discovery
            .validate(AuthorityMode::Shadow, Network::Regtest)
            .is_err());

        let address = "129.153.177.220:44806".parse().expect("seed socket");
        let mut explicit = ShadowSyncConfig {
            enabled: true,
            connect: vec![address],
            ..ShadowSyncConfig::default()
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
            .shadow_sync_ensure_genesis_header()
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
            .shadow_sync_import_headers(vec![block.header.clone()])
            .expect("block header");
        let node = Arc::new(Mutex::new(service));

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
        let diagnostics = Arc::new(RwLock::new(ShadowSyncDiagnostics::default()));

        handle_compact_block(
            peer,
            compact,
            &node,
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
        let diagnostics = Arc::new(RwLock::new(ShadowSyncDiagnostics::default()));

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

        handle_validation_results(
            vec![Ok(hns_sync::ValidatedBlock {
                sequence: 0,
                peer: PeerId(1),
                height: 2,
                block: second,
            })],
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

    #[test]
    fn validated_body_batch_is_all_or_nothing_before_durable_commit() {
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
        let first_hash = first.hash();
        let second_hash = second.hash();
        service
            .shadow_sync_import_headers(vec![first.header.clone(), second.header.clone()])
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
            .shadow_sync_store_validated_blocks(invalid_batch)
            .expect_err("one mismatched member rejects the complete batch");
        assert!(!service
            .shadow_sync_has_block(&first_hash)
            .expect("first body after rejected batch"));
        assert!(!service
            .shadow_sync_has_block(&second_hash)
            .expect("second body after rejected batch"));

        let stored = service
            .shadow_sync_store_validated_blocks(vec![
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
            .shadow_sync_has_block(&first_hash)
            .expect("first stored body"));
        assert!(service
            .shadow_sync_has_block(&second_hash)
            .expect("second stored body"));
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
            authority_mode: AuthorityMode::Shadow,
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
                .shadow_sync_store_validated_blocks(vec![(
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

    #[test]
    fn detached_live_header_is_classified_without_mutating_the_header_tip() {
        let mut service = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let genesis = service
            .shadow_sync_ensure_genesis_header()
            .expect("genesis");
        let parent = BlockHash::new([0x91; 32]);
        let error = service
            .shadow_sync_import_headers(vec![Header {
                prev_block: parent,
                ..Header::default()
            }])
            .expect_err("detached live header");
        assert_eq!(
            error.downcast_ref::<MissingHeaderParent>(),
            Some(&MissingHeaderParent { parent })
        );
        let tip = service
            .shadow_sync_best_header_tip()
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
        let diagnostic_rpc = {
            let diagnostics_snapshot = diagnostics.read().await.clone();
            let node_snapshot = node.lock().await;
            Arc::new(RwLock::new(CachedDiagnosticRpc {
                service: compose_shadow_sync_rpc_service(
                    &node_snapshot,
                    &diagnostics_snapshot,
                    false,
                )
                .expect("initial diagnostic snapshot"),
                captured_at: unix_time(),
            }))
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let authorization =
            RpcAuthorizationHeader::new("Bearer native-sync-test").expect("authorization");
        let server = tokio::spawn(serve_shadow_sync_rpc(
            listener,
            Arc::clone(&node),
            diagnostics,
            diagnostic_rpc,
            Some(authorization),
            shutdown_rx,
        ));

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
                assert_eq!(json["observation_only"], true);
                assert_eq!(json["active_state"], false);
                assert_eq!(json["runtime_instance"], "test-runtime");
                assert_eq!(json["connected_blocks"], 0);
                assert_eq!(json["contextual_failed_bodies"], 0);
            } else if path == "/api/v1/header-deployments" {
                assert_eq!(json["best_header"]["height"], 0);
                assert_eq!(json["next_height"], 1);
                assert_eq!(json["script_flags"], 50);
            } else if path == "/api/v1/status" {
                assert_eq!(json["diagnostic_snapshot_cached"], false);
                assert!(json["diagnostic_snapshot_captured_at"].is_u64());
            }
        }

        let node_guard = node.lock().await;
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
        .expect("cached diagnostic status must not wait for the node lock");
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
        .expect("cached JSON-RPC diagnostics must not wait for the node lock");
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
        drop(node_guard);

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
        assert_eq!(json["result"], genesis_hash);

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
