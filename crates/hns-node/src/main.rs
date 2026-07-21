#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};
use hns_consensus::Network;
use hns_mempool::MempoolLimits;
use hns_node::{
    init_logging, validate_node_config, AuthorityMode, MiningEngineConfig,
    NameTreeCompactionConfig, NodeConfig, NodeService, ShadowSyncConfig, ShutdownSignal,
    UndoRetentionConfig, DEFAULT_NAME_TREE_COMPACTION_INTERVAL,
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

    #[arg(long, env = "HSRD_LOG", default_value = "info")]
    log_filter: String,

    #[arg(long, value_enum, default_value_t = AuthorityMode::Shadow)]
    authority_mode: AuthorityMode,

    #[arg(long)]
    acknowledge_incomplete_consensus: bool,

    #[arg(long, default_value_t = DurabilityPolicy::Sync)]
    storage_durability: DurabilityPolicy,

    /// Compact retained durable name-tree nodes when the startup height is due.
    #[arg(long)]
    compact_name_tree_on_startup: bool,

    /// Minimum active-chain height advance between startup compactions.
    #[arg(long, default_value_t = DEFAULT_NAME_TREE_COMPACTION_INTERVAL)]
    name_tree_compaction_interval: u32,

    /// Retire active-chain undo records beyond the HSD network reorg horizon.
    #[arg(long)]
    prune_undo_history: bool,

    /// Enable live, observation-only P2P and shadow synchronization.
    #[arg(long)]
    shadow_sync: bool,

    /// Bind an inbound plaintext Handshake P2P listener.
    #[arg(long)]
    p2p_listen: Option<SocketAddr>,

    /// Connect to an explicit Handshake peer. May be repeated.
    #[arg(long = "connect")]
    p2p_connect: Vec<SocketAddr>,

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
    shadow_sync_poll_ms: u64,

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
    fn into_config(self) -> NodeConfig {
        NodeConfig {
            network: self.network.into(),
            data_dir: self.data_dir,
            rpc_bind: self.rpc_bind,
            log_filter: self.log_filter,
            authority_mode: self.authority_mode,
            acknowledge_incomplete_consensus: self.acknowledge_incomplete_consensus,
            storage_durability: self.storage_durability,
            name_tree_compaction: NameTreeCompactionConfig {
                compact_on_startup: self.compact_name_tree_on_startup,
                startup_interval: self.name_tree_compaction_interval,
            },
            undo_retention: UndoRetentionConfig {
                prune_history: self.prune_undo_history,
            },
            shadow_sync: ShadowSyncConfig {
                enabled: self.shadow_sync,
                listen: self.p2p_listen,
                connect: self.p2p_connect,
                maximum_inbound: self.maximum_inbound,
                maximum_outbound: self.maximum_outbound,
                validation_workers: self.validation_workers,
                validation_queue: self.validation_queue,
                orphan_blocks: self.orphan_blocks,
                orphan_bytes: self.orphan_bytes,
                poll_interval: Duration::from_millis(self.shadow_sync_poll_ms),
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
                },
                maximum_template_variants: self.template_variants,
                maximum_pending_publications: self.pending_publications,
                publication_retry_interval: Duration::from_millis(self.publication_retry_ms),
            },
        }
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
    let config = cli.into_config();

    init_logging(&config.log_filter)?;
    validate_node_config(&config)?;

    if check_config {
        tracing::info!(
            network = %config.network,
            authority_mode = config.authority_mode.as_str(),
            storage_durability = %config.storage_durability,
            compact_name_tree_on_startup = config.name_tree_compaction.compact_on_startup,
            name_tree_compaction_interval = config.name_tree_compaction.startup_interval,
            prune_undo_history = config.undo_retention.prune_history,
            shadow_sync = config.shadow_sync.enabled,
            mining_engine = config.mining_engine.enabled,
            transaction_relay = config.mining_engine.transaction_relay,
            "configuration parsed successfully"
        );
        return Ok(());
    }

    let node = NodeService::try_new(config)?;
    node.run_until_shutdown(ShutdownSignal::ctrl_c()).await
}
