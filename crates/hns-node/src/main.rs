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

use clap::{Parser, ValueEnum};
use hns_consensus::Network;
use hns_mempool::{MempoolLimits, HSD_MEMPOOL_EXPIRY_TIME};
use hns_node::{
    init_logging, validate_node_config, AuthorityMode, MiningEngineConfig,
    NameTreeCompactionConfig, NativeSyncConfig, NodeConfig, NodeService, RpcAuthorizationHeader,
    ShutdownSignal, StorageMode, UndoRetentionConfig, DEFAULT_NAME_TREE_COMPACTION_INTERVAL,
    MAX_RPC_AUTHORIZATION_BYTES,
};
use hns_store::DurabilityPolicy;

#[derive(Debug, Parser)]
#[command(name = "hsrd", about = "Lean Handshake consensus and mining full node")]
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

    /// Enable native P2P, headers, block-body, and active-state synchronization.
    #[arg(long = "native-sync", alias = "shadow-sync")]
    native_sync: bool,

    /// Validate and persist only headers; do not download or connect bodies.
    #[arg(
        long = "native-sync-headers-only",
        alias = "shadow-sync-headers-only",
        requires = "native_sync"
    )]
    native_sync_headers_only: bool,

    /// Download bodies without connecting them to active state.
    #[arg(
        long,
        requires = "native_sync",
        conflicts_with = "native_sync_headers_only"
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

    /// Bootstrap from HSD's key-bearing fixed seeds and learn peers through GETADDR/ADDR.
    #[arg(long)]
    p2p_discovery: bool,

    /// Maximum explicit and discovered peers retained by the address book.
    #[arg(long, default_value_t = 4_096)]
    maximum_known_addresses: usize,

    #[arg(long, default_value_t = 32)]
    maximum_inbound: usize,

    #[arg(long, default_value_t = 8)]
    maximum_outbound: usize,

    #[arg(long, default_value_t = 4)]
    validation_workers: usize,

    #[arg(long, default_value_t = 128)]
    validation_queue: usize,

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
        Ok(NodeConfig {
            network: self.network.into(),
            data_dir: self.data_dir,
            rpc_bind: self.rpc_bind,
            rpc_authorization,
            log_filter: self.log_filter,
            authority_mode: self.authority_mode,
            mainnet_canary: self.mainnet_canary,
            acknowledge_incomplete_consensus: self.acknowledge_incomplete_consensus,
            storage_durability: self.storage_durability,
            transaction_index: self.transaction_index,
            name_tree_compaction: NameTreeCompactionConfig {
                compact_on_startup: self.compact_name_tree_on_startup,
                startup_interval: self.name_tree_compaction_interval,
            },
            undo_retention: UndoRetentionConfig {
                prune_history: self.prune_undo_history
                    || self.storage_mode.prunes_payload_history(),
            },
            shadow_sync: NativeSyncConfig {
                enabled: self.native_sync,
                headers_only: self.native_sync_headers_only,
                connect_active_state: self.native_sync
                    && !self.native_sync_headers_only
                    && !self.native_sync_observe_only,
                active_state_connect_batch: self.active_state_connect_batch,
                listen: self.p2p_listen,
                connect,
                connect_keys,
                discovery: self.p2p_discovery,
                maximum_known_addresses: self.maximum_known_addresses,
                maximum_inbound: self.maximum_inbound,
                maximum_outbound: self.maximum_outbound,
                validation_workers: self.validation_workers,
                validation_queue: self.validation_queue,
                orphan_blocks: self.orphan_blocks,
                orphan_bytes: self.orphan_bytes,
                poll_interval: Duration::from_millis(self.native_sync_poll_ms),
            },
            mining_engine: MiningEngineConfig {
                enabled: self.mining_engine,
                transaction_relay: self.transaction_relay,
                mempool_limits: MempoolLimits {
                    maximum_transactions: self.mempool_max_transactions,
                    maximum_bytes: self.mempool_max_bytes,
                    maximum_orphans: self.mempool_max_orphans,
                    maximum_orphan_bytes: self.mempool_max_orphan_bytes,
                    maximum_ancestors: self.mempool_max_ancestors,
                    maximum_descendants: self.mempool_max_descendants,
                    expiry_time: self.mempool_expiry_time,
                },
                maximum_template_variants: self.template_variants,
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
    if !metadata.is_file() || metadata.len() > MAX_RPC_AUTHORIZATION_BYTES as u64 {
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
    file.take((MAX_RPC_AUTHORIZATION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RPC_AUTHORIZATION_BYTES {
        anyhow::bail!("RPC authorization header exceeds the hard byte limit");
    }
    let value = String::from_utf8(bytes)?.trim().to_owned();
    RpcAuthorizationHeader::new(value)
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
            compact_name_tree_on_startup = config.name_tree_compaction.compact_on_startup,
            name_tree_compaction_interval = config.name_tree_compaction.startup_interval,
            prune_undo_history = config.undo_retention.prune_history,
            native_sync = config.shadow_sync.enabled,
            native_sync_headers_only = config.shadow_sync.headers_only,
            native_sync_active_state = config.shadow_sync.connect_active_state,
            mining_engine = config.mining_engine.enabled,
            transaction_relay = config.mining_engine.transaction_relay,
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
}
