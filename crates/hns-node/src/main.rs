#![forbid(unsafe_code)]

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};
use hns_consensus::Network;
use hns_node::{init_logging, NodeConfig, NodeService, ShutdownSignal};

#[derive(Debug, Parser)]
#[command(name = "hsrd", about = "Lean Handshake consensus and mining full node")]
struct Cli {
    #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
    network: NetworkArg,

    #[arg(long)]
    data_dir: Option<PathBuf>,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:12037")]
    rpc_bind: SocketAddr,

    #[arg(long)]
    metrics_bind: Option<SocketAddr>,

    #[arg(long, env = "HSRD_LOG", default_value = "info")]
    log_filter: String,

    #[arg(long)]
    check_config: bool,
}

impl Cli {
    fn into_config(self) -> NodeConfig {
        NodeConfig {
            network: self.network.into(),
            data_dir: self.data_dir,
            config_file: self.config,
            rpc_bind: self.rpc_bind,
            metrics_bind: self.metrics_bind,
            log_filter: self.log_filter,
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

    if check_config {
        tracing::info!(network = %config.network, "configuration parsed successfully");
        return Ok(());
    }

    let node = NodeService::try_new(config)?;
    node.run_until_shutdown(ShutdownSignal::ctrl_c()).await
}
