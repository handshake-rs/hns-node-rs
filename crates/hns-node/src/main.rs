#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use clap::{ArgAction, Parser, ValueEnum};
use hns_consensus::Network;
use hns_mempool::{MempoolLimits, HSD_MEMPOOL_EXPIRY_TIME};
use hns_node::{
    init_logging, recommended_template_build_limits, validate_node_config, AuthorityMode,
    DenuoRelayRoles, MiningEngineConfig, NameTreeCompactionConfig, NativeSyncConfig, NodeConfig,
    NodeService, RpcAuthorizationHeader, RpcLimits, ShutdownSignal, StorageMode,
    UndoRetentionConfig, DEFAULT_NAME_TREE_COMPACTION_INTERVAL, DEFAULT_RPC_MAX_COLLECTION_ENTRIES,
    DEFAULT_RPC_MAX_CONCURRENT_REQUESTS, DEFAULT_RPC_MAX_REQUEST_BYTES,
    MAX_RPC_AUTHORIZATION_BYTES,
};
use hns_store::DurabilityPolicy;

const MAX_RPC_AUTHORIZATION_FILE_BYTES: usize = MAX_RPC_AUTHORIZATION_BYTES + 2;

#[derive(Debug, Parser)]
#[command(
    name = "hsrd",
    version,
    about = "Lean Handshake consensus and mining full node"
)]
struct Cli {
    #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
    network: NetworkArg,

    #[arg(long)]
    data_dir: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:12037")]
    rpc_bind: SocketAddr,

    /// Read the exact required HTTP Authorization value from a mode-0600 file.
    #[arg(long)]
    rpc_authorization_header_file: Option<PathBuf>,

    /// Maximum accepted HTTP request body size for every RPC route.
    #[arg(long, default_value_t = DEFAULT_RPC_MAX_REQUEST_BYTES)]
    rpc_max_request_bytes: usize,

    /// Maximum number of RPC requests executing at once; excess work gets HTTP 429.
    #[arg(long, default_value_t = DEFAULT_RPC_MAX_CONCURRENT_REQUESTS)]
    rpc_max_concurrent_requests: usize,

    /// Maximum wall-clock execution time for one RPC request.
    #[arg(long, default_value_t = 5_000)]
    rpc_execution_timeout_ms: u64,

    /// Maximum entries returned by a single collection RPC.
    #[arg(long, default_value_t = DEFAULT_RPC_MAX_COLLECTION_ENTRIES)]
    rpc_max_collection_entries: usize,

    #[arg(long, env = "HSRD_LOG", default_value = "info")]
    log_filter: String,

    #[arg(long, value_enum, default_value_t = AuthorityMode::Native)]
    authority_mode: AuthorityMode,

    /// Explicitly request the fail-closed native mainnet mining canary. This
    /// never bypasses consensus readiness, full synchronization, or durable
    /// tip authority.
    #[arg(long)]
    mainnet_canary: bool,

    #[arg(long)]
    acknowledge_incomplete_consensus: bool,

    #[arg(long, default_value_t = DurabilityPolicy::Sync)]
    storage_durability: DurabilityPolicy,

    /// Maintain active-chain transaction-to-block history for diagnostics.
    #[arg(long = "transaction-index", alias = "index-tx")]
    transaction_index: bool,

    /// Maintain active-chain history keyed by canonical output script.
    #[arg(long = "script-history-index")]
    script_history_index: bool,

    /// Maintain active-chain output-to-spending-transaction mappings.
    #[arg(long = "spender-index")]
    spender_index: bool,

    /// Maintain the complete restoration profile; this also enables the
    /// transaction, script-history, spender, and script-UTXO indexes.
    #[arg(long = "wallet-index")]
    wallet_index: bool,

    /// Enable the local name-market relay core for an installed native adapter.
    #[arg(long = "denuo-name-market-relay")]
    denuo_name_market_relay: bool,

    /// Enable the local cross-chain relay core for an installed native adapter.
    #[arg(long = "denuo-cross-chain-relay")]
    denuo_cross_chain_relay: bool,

    /// Enable the local price relay core for an installed native adapter.
    #[arg(long = "denuo-price-relay")]
    denuo_price_relay: bool,

    /// Enable the local rendezvous relay core for an installed native adapter.
    #[arg(long = "denuo-rendezvous-relay")]
    denuo_rendezvous_relay: bool,

    /// Enable the local swap-status relay core for an installed native adapter.
    #[arg(long = "denuo-swap-status-relay")]
    denuo_swap_status_relay: bool,

    /// Compact retained durable name-tree nodes when the startup height is due.
    #[arg(long)]
    compact_name_tree_on_startup: bool,

    /// Minimum active-chain height advance between startup compactions.
    #[arg(long, default_value_t = DEFAULT_NAME_TREE_COMPACTION_INTERVAL)]
    name_tree_compaction_interval: u32,

    /// Raw block/undo retention policy. Pruned is the default mining profile;
    /// archive retains complete history for historical peer serving.
    #[arg(long, value_enum, default_value_t = StorageMode::Pruned)]
    storage_mode: StorageMode,

    /// Legacy spelling for `--storage-mode pruned`.
    #[arg(long, hide = true)]
    prune_undo_history: bool,

    /// Reaffirm the default native P2P, headers, block-body, and active-state synchronization.
    #[arg(long = "native-sync", action = ArgAction::SetTrue)]
    native_sync: bool,

    /// Disable native P2P and synchronization for an RPC-only process.
    #[arg(long = "no-native-sync", conflicts_with = "native_sync")]
    no_native_sync: bool,

    /// Validate and persist only headers; do not download or connect bodies.
    #[arg(long = "native-sync-headers-only", conflicts_with = "no_native_sync")]
    native_sync_headers_only: bool,

    /// Download bodies without connecting them to active state.
    #[arg(
        long,
        conflicts_with_all = ["native_sync_headers_only", "no_native_sync"]
    )]
    native_sync_observe_only: bool,

    /// Maximum stored blocks connected in one atomic active-state batch.
    #[arg(long, default_value_t = 288)]
    active_state_connect_batch: usize,

    /// Bind an inbound Handshake P2P listener (Brontide on public networks).
    #[arg(long)]
    p2p_listen: Option<SocketAddr>,

    /// Connect to a peer. Public networks require KEYHEX@IP:PORT; may be repeated.
    #[arg(long = "connect")]
    p2p_connect: Vec<P2pConnectArg>,

    /// Reaffirm default fixed-seed bootstrap and GETADDR/ADDR peer discovery.
    #[arg(long, action = ArgAction::SetTrue)]
    p2p_discovery: bool,

    /// Disable fixed-seed bootstrap and learned-peer discovery.
    #[arg(long = "no-p2p-discovery", conflicts_with = "p2p_discovery")]
    no_p2p_discovery: bool,

    /// Explicitly restore HIP-76 requester policy to the default `Auto` mode.
    #[arg(long = "hip76-requester", action = ArgAction::SetTrue)]
    hip76_requester: bool,

    /// Persistently disable the HIP-76 requester without enabling a DNS output.
    #[arg(long = "no-hip76-requester", conflicts_with = "hip76_requester")]
    no_hip76_requester: bool,

    /// Explicitly restore the HIP-77 ODoH requester to its default-on policy.
    #[arg(long = "odoh-requester", action = ArgAction::SetTrue)]
    odoh_requester: bool,

    /// Disable the outbound-only HIP-77 ODoH requester. Local provider roles
    /// remain unavailable regardless of this setting.
    #[arg(long = "no-odoh-requester", conflicts_with = "odoh_requester")]
    no_odoh_requester: bool,

    /// Explicitly restore the HIP-78 HNSR requester to its default-on policy.
    #[arg(long = "hnsr-requester", action = ArgAction::SetTrue)]
    hnsr_requester: bool,

    /// Disable the HIP-78 HNSR requester. Requester policy is enabled by
    /// default and uses only authenticated, exactly negotiated relay peers.
    #[arg(long = "no-hnsr-requester", conflicts_with = "hnsr_requester")]
    no_hnsr_requester: bool,

    /// Explicitly restore the HIP-78 opaque-relay policy to its default-on state.
    #[arg(long = "hnsr-relay", action = ArgAction::SetTrue)]
    hnsr_relay: bool,

    /// Disable the HIP-78 opaque relay policy. Endpoint and rendezvous roles
    /// remain unavailable regardless of this setting.
    #[arg(long = "no-hnsr-relay", conflicts_with = "hnsr_relay")]
    no_hnsr_relay: bool,

    /// Public address placed in locally issued HNSR relay tickets. The relay
    /// service is unavailable until this explicit address is configured.
    #[arg(long = "hnsr-relay-address")]
    hnsr_relay_address: Option<SocketAddr>,

    /// Maximum explicit and discovered peers retained by the address book.
    #[arg(long, default_value_t = 4_096)]
    maximum_known_addresses: usize,

    #[arg(long, default_value_t = 32)]
    maximum_inbound: usize,

    #[arg(long, default_value_t = 8)]
    maximum_outbound: usize,

    /// Concurrent stateless block-validation workers. When omitted, use all
    /// visible CPUs within the native runtime's hard maximum of 128.
    #[arg(long)]
    validation_workers: Option<usize>,

    /// Admitted validation jobs. When omitted, derive 32 slots per default
    /// worker, with a 128-slot floor and a hard maximum of 8192.
    #[arg(long)]
    validation_queue: Option<usize>,

    #[arg(long, default_value_t = 1_024)]
    orphan_blocks: usize,

    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    orphan_bytes: usize,

    #[arg(long, default_value_t = 250)]
    native_sync_poll_ms: u64,

    /// Enable the bounded mining engine for mempool, template, and publication work.
    #[arg(long)]
    mining_engine: bool,

    /// Serve already admitted transactions and mempool inventory to peers.
    /// Admission remains fail closed until complete contextual consensus parity.
    #[arg(long)]
    transaction_relay: bool,

    #[arg(long, default_value_t = 50_000)]
    mempool_max_transactions: usize,

    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    mempool_max_bytes: usize,

    #[arg(long, default_value_t = 1_024)]
    mempool_max_orphans: usize,

    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    mempool_max_orphan_bytes: usize,

    #[arg(long, default_value_t = 25)]
    mempool_max_ancestors: usize,

    #[arg(long, default_value_t = 25)]
    mempool_max_descendants: usize,

    #[arg(long, default_value_t = HSD_MEMPOOL_EXPIRY_TIME)]
    mempool_expiry_time: u64,

    #[arg(long, default_value_t = 16)]
    template_variants: usize,

    /// Concurrent template assemblies. Defaults from online CPU and memory
    /// capacity; hard-capped at 16 and never above --template-variants.
    #[arg(long)]
    template_build_workers: Option<usize>,

    /// Active plus waiting template assemblies. Must cover all workers, is
    /// hard-capped at 64, and must fit the 2 GiB snapshot-memory envelope.
    #[arg(long)]
    template_build_queue_capacity: Option<usize>,

    #[arg(long, default_value_t = 64)]
    pending_publications: usize,

    #[arg(long, default_value_t = 250)]
    publication_retry_ms: u64,

    #[arg(long)]
    check_config: bool,
}

impl Cli {
    fn into_config(self) -> anyhow::Result<NodeConfig> {
        if self.prune_undo_history && self.storage_mode == StorageMode::Archive {
            anyhow::bail!("--prune-undo-history conflicts with explicit --storage-mode archive");
        }
        let native_sync = self.native_sync || !self.no_native_sync;
        let p2p_discovery = self.p2p_discovery || !self.no_p2p_discovery;
        let connect = self
            .p2p_connect
            .iter()
            .map(|peer| peer.address)
            .collect::<Vec<_>>();
        let connect_keys = self
            .p2p_connect
            .iter()
            .filter_map(|peer| peer.key.map(|key| (peer.address, key)))
            .collect::<BTreeMap<_, _>>();
        let rpc_authorization = self
            .rpc_authorization_header_file
            .as_deref()
            .map(read_rpc_authorization)
            .transpose()?;
        let native_sync_defaults = NativeSyncConfig::default();
        let mempool_limits = MempoolLimits {
            maximum_transactions: self.mempool_max_transactions,
            maximum_bytes: self.mempool_max_bytes,
            maximum_orphans: self.mempool_max_orphans,
            maximum_orphan_bytes: self.mempool_max_orphan_bytes,
            maximum_ancestors: self.mempool_max_ancestors,
            maximum_descendants: self.mempool_max_descendants,
            expiry_time: self.mempool_expiry_time,
        };
        let (recommended_template_workers, recommended_template_queue) =
            recommended_template_build_limits(&mempool_limits, self.template_variants);
        Ok(NodeConfig {
            network: self.network.into(),
            data_dir: self.data_dir,
            rpc_bind: self.rpc_bind,
            rpc_authorization,
            rpc_limits: RpcLimits {
                maximum_request_bytes: self.rpc_max_request_bytes,
                maximum_concurrent_requests: self.rpc_max_concurrent_requests,
                execution_timeout: Duration::from_millis(self.rpc_execution_timeout_ms),
                maximum_collection_entries: self.rpc_max_collection_entries,
            },
            log_filter: self.log_filter,
            authority_mode: self.authority_mode,
            mainnet_canary: self.mainnet_canary,
            acknowledge_incomplete_consensus: self.acknowledge_incomplete_consensus,
            storage_durability: self.storage_durability,
            transaction_index: self.transaction_index,
            script_history_index: self.script_history_index,
            spender_index: self.spender_index,
            wallet_index: self.wallet_index,
            denuo_relay_roles: DenuoRelayRoles::new(
                self.denuo_name_market_relay,
                self.denuo_cross_chain_relay,
                self.denuo_price_relay,
                self.denuo_rendezvous_relay,
                self.denuo_swap_status_relay,
            ),
            name_tree_compaction: NameTreeCompactionConfig {
                compact_on_startup: self.compact_name_tree_on_startup,
                startup_interval: self.name_tree_compaction_interval,
            },
            undo_retention: UndoRetentionConfig {
                prune_history: self.prune_undo_history
                    || self.storage_mode.prunes_payload_history(),
            },
            native_sync: NativeSyncConfig {
                enabled: native_sync,
                headers_only: self.native_sync_headers_only,
                connect_active_state: native_sync
                    && !self.native_sync_headers_only
                    && !self.native_sync_observe_only,
                active_state_connect_batch: self.active_state_connect_batch,
                listen: self.p2p_listen,
                connect,
                connect_keys,
                discovery: p2p_discovery,
                hip76_requester_override: if self.hip76_requester {
                    Some(true)
                } else if self.no_hip76_requester {
                    Some(false)
                } else {
                    None
                },
                // These are capability ceilings for the node runtime. The
                // CLI selection belongs exclusively in the tri-state
                // overrides so a saved opt-out can be explicitly reversed.
                odoh_requester: true,
                odoh_requester_override: if self.odoh_requester {
                    Some(true)
                } else if self.no_odoh_requester {
                    Some(false)
                } else {
                    None
                },
                hnsr_requester: true,
                hnsr_opaque_relay: true,
                hnsr_requester_override: if self.hnsr_requester {
                    Some(true)
                } else if self.no_hnsr_requester {
                    Some(false)
                } else {
                    None
                },
                hnsr_opaque_relay_override: if self.hnsr_relay {
                    Some(true)
                } else if self.no_hnsr_relay {
                    Some(false)
                } else {
                    None
                },
                hnsr_relay_address: self.hnsr_relay_address,
                maximum_known_addresses: self.maximum_known_addresses,
                maximum_inbound: self.maximum_inbound,
                maximum_outbound: self.maximum_outbound,
                validation_workers: self
                    .validation_workers
                    .unwrap_or(native_sync_defaults.validation_workers),
                validation_queue: self
                    .validation_queue
                    .unwrap_or(native_sync_defaults.validation_queue),
                orphan_blocks: self.orphan_blocks,
                orphan_bytes: self.orphan_bytes,
                poll_interval: Duration::from_millis(self.native_sync_poll_ms),
            },
            mining_engine: MiningEngineConfig {
                enabled: self.mining_engine,
                transaction_relay: self.transaction_relay,
                mempool_limits,
                maximum_template_variants: self.template_variants,
                template_build_workers: self
                    .template_build_workers
                    .unwrap_or(recommended_template_workers),
                template_build_queue_capacity: self
                    .template_build_queue_capacity
                    .unwrap_or(recommended_template_queue),
                maximum_pending_publications: self.pending_publications,
                publication_retry_interval: Duration::from_millis(self.publication_retry_ms),
            },
        })
    }
}

fn read_rpc_authorization(path: &Path) -> anyhow::Result<RpcAuthorizationHeader> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("RPC authorization header path must be absolute without parent traversal");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_RPC_AUTHORIZATION_FILE_BYTES as u64 {
        anyhow::bail!("RPC authorization header must be a bounded mode-0600 regular file");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("RPC authorization header must not be accessible by group or other users");
    }
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_symlink() {
        anyhow::bail!("RPC authorization header must not be a symbolic link");
    }
    let mut bytes = Vec::new();
    file.take((MAX_RPC_AUTHORIZATION_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RPC_AUTHORIZATION_FILE_BYTES {
        anyhow::bail!("RPC authorization header exceeds the hard byte limit");
    }
    let value = String::from_utf8(bytes)?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(&value);
    RpcAuthorizationHeader::new(value.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct P2pConnectArg {
    address: SocketAddr,
    key: Option<[u8; 33]>,
}

impl FromStr for P2pConnectArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (key, address) = match value.split_once('@') {
            Some((encoded_key, encoded_address)) => {
                if encoded_key.len() != 66 {
                    return Err(format!(
                        "Brontide public key has {} hex characters; expected 66",
                        encoded_key.len()
                    ));
                }
                let mut key = [0u8; 33];
                for (index, output) in key.iter_mut().enumerate() {
                    let offset = index * 2;
                    *output = u8::from_str_radix(&encoded_key[offset..offset + 2], 16)
                        .map_err(|error| format!("invalid Brontide public key hex: {error}"))?;
                }
                if !matches!(key[0], 0x02 | 0x03) {
                    return Err("Brontide public key must be compressed".to_owned());
                }
                (Some(key), encoded_address)
            }
            None => (None, value),
        };
        let address = address
            .parse()
            .map_err(|error| format!("invalid peer socket address: {error}"))?;
        Ok(Self { address, key })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => Self::Mainnet,
            NetworkArg::Testnet => Self::Testnet,
            NetworkArg::Regtest => Self::Regtest,
            NetworkArg::Simnet => Self::Simnet,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let check_config = cli.check_config;
    let config = cli.into_config()?;

    init_logging(&config.log_filter)?;
    validate_node_config(&config)?;

    if check_config {
        tracing::info!(
            network = %config.network,
            authority_mode = config.authority_mode.as_str(),
            mainnet_canary = config.mainnet_canary,
            storage_durability = %config.storage_durability,
            transaction_index = config.transaction_index,
            script_history_index = config.script_history_index,
            spender_index = config.spender_index,
            wallet_index = config.wallet_index,
            denuo_relay_roles = config.denuo_relay_roles.bits(),
            rpc_max_request_bytes = config.rpc_limits.maximum_request_bytes,
            rpc_max_concurrent_requests = config.rpc_limits.maximum_concurrent_requests,
            rpc_execution_timeout_ms = config.rpc_limits.execution_timeout.as_millis(),
            rpc_max_collection_entries = config.rpc_limits.maximum_collection_entries,
            compact_name_tree_on_startup = config.name_tree_compaction.compact_on_startup,
            name_tree_compaction_interval = config.name_tree_compaction.startup_interval,
            prune_undo_history = config.undo_retention.prune_history,
            native_sync = config.native_sync.enabled,
            native_sync_headers_only = config.native_sync.headers_only,
            native_sync_active_state = config.native_sync.connect_active_state,
            hip76_requester_override = ?config.native_sync.hip76_requester_override,
            odoh_requester_capable = config.native_sync.odoh_requester,
            odoh_requester_override = ?config.native_sync.odoh_requester_override,
            hnsr_requester_capable = config.native_sync.hnsr_requester,
            hnsr_requester_override = ?config.native_sync.hnsr_requester_override,
            hnsr_opaque_relay_capable = config.native_sync.hnsr_opaque_relay,
            hnsr_opaque_relay_override = ?config.native_sync.hnsr_opaque_relay_override,
            hnsr_relay_address = ?config.native_sync.hnsr_relay_address,
            validation_workers = config.native_sync.validation_workers,
            validation_queue = config.native_sync.validation_queue,
            mining_engine = config.mining_engine.enabled,
            transaction_relay = config.mining_engine.transaction_relay,
            mempool_max_bytes = config.mining_engine.mempool_limits.maximum_bytes,
            template_variants = config.mining_engine.maximum_template_variants,
            template_build_workers = config.mining_engine.template_build_workers,
            template_build_queue_capacity = config.mining_engine.template_build_queue_capacity,
            "configuration parsed successfully"
        );
        return Ok(());
    }

    let node = NodeService::try_new(config)?;
    node.run_until_shutdown(ShutdownSignal::ctrl_c()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_advertises_the_cargo_package_version() {
        assert_eq!(
            Cli::command().get_version(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn storage_mode_defaults_to_pruned_and_archive_is_explicit() {
        let default = Cli::try_parse_from(["hsrd"])
            .expect("default CLI")
            .into_config()
            .expect("default config");
        assert!(default.undo_retention.prune_history);

        let archive = Cli::try_parse_from(["hsrd", "--storage-mode", "archive"])
            .expect("archive CLI")
            .into_config()
            .expect("archive config");
        assert!(!archive.undo_retention.prune_history);

        let conflict =
            Cli::try_parse_from(["hsrd", "--storage-mode", "archive", "--prune-undo-history"])
                .expect("legacy conflict parses")
                .into_config()
                .expect_err("archive and legacy prune flag conflict");
        assert!(conflict.to_string().contains("conflicts"));
    }

    #[test]
    fn outbound_p2p_and_discovery_default_on_with_explicit_opt_outs() {
        let default = Cli::try_parse_from(["hsrd"])
            .expect("default CLI")
            .into_config()
            .expect("default config");
        assert!(default.native_sync.enabled);
        assert!(default.native_sync.connect_active_state);
        assert!(default.native_sync.discovery);
        assert_eq!(default.native_sync.hip76_requester_override, None);
        assert!(default.native_sync.odoh_requester);
        assert_eq!(default.native_sync.odoh_requester_override, None);
        assert!(default.native_sync.hnsr_requester);
        assert!(default.native_sync.hnsr_opaque_relay);
        assert_eq!(default.native_sync.hnsr_requester_override, None);
        assert_eq!(default.native_sync.hnsr_opaque_relay_override, None);
        assert!(default.native_sync.hnsr_relay_address.is_none());
        assert!(default.native_sync.listen.is_none());

        let disabled = Cli::try_parse_from([
            "hsrd",
            "--no-native-sync",
            "--no-p2p-discovery",
            "--no-hip76-requester",
            "--no-odoh-requester",
            "--no-hnsr-requester",
            "--no-hnsr-relay",
        ])
        .expect("explicit opt-out CLI")
        .into_config()
        .expect("explicit opt-out config");
        assert!(!disabled.native_sync.enabled);
        assert!(!disabled.native_sync.connect_active_state);
        assert!(!disabled.native_sync.discovery);
        assert_eq!(disabled.native_sync.hip76_requester_override, Some(false));
        assert!(disabled.native_sync.odoh_requester);
        assert_eq!(disabled.native_sync.odoh_requester_override, Some(false));
        assert!(disabled.native_sync.hnsr_requester);
        assert!(disabled.native_sync.hnsr_opaque_relay);
        assert_eq!(disabled.native_sync.hnsr_requester_override, Some(false));
        assert_eq!(disabled.native_sync.hnsr_opaque_relay_override, Some(false));

        let reenabled = Cli::try_parse_from([
            "hsrd",
            "--hip76-requester",
            "--odoh-requester",
            "--hnsr-requester",
            "--hnsr-relay",
        ])
        .expect("explicit requester enable CLI")
        .into_config()
        .expect("explicit requester enable config");
        assert_eq!(reenabled.native_sync.hip76_requester_override, Some(true));
        assert_eq!(reenabled.native_sync.odoh_requester_override, Some(true));
        assert_eq!(reenabled.native_sync.hnsr_requester_override, Some(true));
        assert_eq!(reenabled.native_sync.hnsr_opaque_relay_override, Some(true));
    }

    #[test]
    fn explicit_peer_parser_preserves_brontide_key_and_socket() {
        let peer = "02a58318ea330487308b1a4bd90bd196a466e99be64a3cf2f1fe7b5352154a25c2@129.153.177.220:44806"
            .parse::<P2pConnectArg>()
            .expect("keyed peer");
        assert_eq!(
            peer.address,
            "129.153.177.220:44806".parse().expect("socket")
        );
        assert_eq!(peer.key.expect("key")[0], 0x02);

        let local = "127.0.0.1:14038"
            .parse::<P2pConnectArg>()
            .expect("local peer");
        assert!(local.key.is_none());
        assert!("01aa@127.0.0.1:44806".parse::<P2pConnectArg>().is_err());
    }

    #[test]
    fn rpc_resource_limits_parse_and_validate_fail_closed() {
        let config = Cli::try_parse_from([
            "hsrd",
            "--rpc-max-request-bytes",
            "8192",
            "--rpc-max-concurrent-requests",
            "7",
            "--rpc-execution-timeout-ms",
            "2500",
            "--rpc-max-collection-entries",
            "1234",
        ])
        .expect("bounded RPC CLI")
        .into_config()
        .expect("bounded RPC config");
        assert_eq!(config.rpc_limits.maximum_request_bytes, 8192);
        assert_eq!(config.rpc_limits.maximum_concurrent_requests, 7);
        assert_eq!(
            config.rpc_limits.execution_timeout,
            Duration::from_millis(2500)
        );
        assert_eq!(config.rpc_limits.maximum_collection_entries, 1234);
        validate_node_config(&config).expect("bounded RPC config validates");

        let unbounded = Cli::try_parse_from(["hsrd", "--rpc-max-request-bytes", "0"])
            .expect("zero parses for fail-closed validation")
            .into_config()
            .expect("zero config");
        assert!(validate_node_config(&unbounded).is_err());
    }

    #[test]
    fn native_sync_flags_map_directly_to_native_configuration() {
        let native = Cli::try_parse_from([
            "hsrd",
            "--native-sync",
            "--native-sync-headers-only",
            "--p2p-discovery",
        ])
        .expect("direct native sync CLI")
        .into_config()
        .expect("direct native sync config");
        assert!(native.native_sync.enabled);
        assert!(native.native_sync.headers_only);
        assert!(!native.native_sync.connect_active_state);
    }

    #[test]
    fn native_validation_limits_default_from_visible_parallelism() {
        let expected = NativeSyncConfig::default();
        let config = Cli::try_parse_from(["hsrd"])
            .expect("default CLI")
            .into_config()
            .expect("default config");
        assert_eq!(
            config.native_sync.validation_workers,
            expected.validation_workers
        );
        assert_eq!(
            config.native_sync.validation_queue,
            expected.validation_queue
        );

        let explicit = Cli::try_parse_from([
            "hsrd",
            "--native-sync",
            "--p2p-discovery",
            "--validation-workers",
            "3",
            "--validation-queue",
            "257",
        ])
        .expect("explicit validation CLI")
        .into_config()
        .expect("explicit validation config");
        assert_eq!(explicit.native_sync.validation_workers, 3);
        assert_eq!(explicit.native_sync.validation_queue, 257);
        validate_node_config(&explicit).expect("explicit validation config validates");
    }

    #[test]
    fn template_build_limits_default_from_engine_configuration() {
        let expected = MiningEngineConfig::default();
        let config = Cli::try_parse_from(["hsrd"])
            .expect("default CLI")
            .into_config()
            .expect("default config");

        assert_eq!(
            config.mining_engine.template_build_workers,
            expected.template_build_workers
        );
        assert_eq!(
            config.mining_engine.template_build_queue_capacity,
            expected.template_build_queue_capacity
        );

        let one_variant = Cli::try_parse_from(["hsrd", "--template-variants", "1"])
            .expect("single-variant CLI")
            .into_config()
            .expect("single-variant config");
        let one_variant_expected = recommended_template_build_limits(
            &one_variant.mining_engine.mempool_limits,
            one_variant.mining_engine.maximum_template_variants,
        );
        assert_eq!(
            (
                one_variant.mining_engine.template_build_workers,
                one_variant.mining_engine.template_build_queue_capacity,
            ),
            one_variant_expected
        );
        validate_node_config(&one_variant).expect("single-variant defaults validate");

        let maximum_mempool_bytes = hns_mempool::MAX_MEMPOOL_BYTES.to_string();
        let maximum_mempool = Cli::try_parse_from([
            "hsrd".to_owned(),
            "--mempool-max-bytes".to_owned(),
            maximum_mempool_bytes,
        ])
        .expect("maximum-mempool CLI")
        .into_config()
        .expect("maximum-mempool config");
        let maximum_mempool_expected = recommended_template_build_limits(
            &maximum_mempool.mining_engine.mempool_limits,
            maximum_mempool.mining_engine.maximum_template_variants,
        );
        assert_eq!(
            (
                maximum_mempool.mining_engine.template_build_workers,
                maximum_mempool.mining_engine.template_build_queue_capacity,
            ),
            maximum_mempool_expected
        );
        validate_node_config(&maximum_mempool).expect("maximum-mempool defaults validate");
    }

    #[test]
    fn template_build_limits_parse_and_validate_fail_closed() {
        let config = Cli::try_parse_from([
            "hsrd",
            "--template-variants",
            "4",
            "--template-build-workers",
            "2",
            "--template-build-queue-capacity",
            "3",
        ])
        .expect("bounded template CLI")
        .into_config()
        .expect("bounded template config");
        assert_eq!(config.mining_engine.maximum_template_variants, 4);
        assert_eq!(config.mining_engine.template_build_workers, 2);
        assert_eq!(config.mining_engine.template_build_queue_capacity, 3);
        validate_node_config(&config).expect("bounded template config validates");

        let fewer_slots_than_workers = Cli::try_parse_from([
            "hsrd",
            "--template-build-workers",
            "2",
            "--template-build-queue-capacity",
            "1",
        ])
        .expect("invalid bounds parse for fail-closed validation")
        .into_config()
        .expect("invalid bounds reach typed config validation");
        assert!(validate_node_config(&fewer_slots_than_workers).is_err());

        let above_hard_queue_limit =
            Cli::try_parse_from(["hsrd", "--template-build-queue-capacity", "65"])
                .expect("hard-limit violation parses for fail-closed validation")
                .into_config()
                .expect("hard-limit violation reaches typed config validation");
        assert!(validate_node_config(&above_hard_queue_limit).is_err());
    }
}
