#![forbid(unsafe_code)]

use std::{
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use clap::Parser;
use hns_resolver::{HsrdRpcClient, ResolverConfig, ResolverRuntime};
use reqwest::header::HeaderValue;
use tracing_subscriber::{fmt, EnvFilter};

const MAX_AUTHORIZATION_BYTES: usize = 4_096;

#[derive(Debug, Parser)]
#[command(
    name = "hns-resolverd",
    version,
    about = "Native Handshake recursive DNS resolver backed by hsrd"
)]
struct Cli {
    /// Public UDP/TCP DNS listener.
    #[arg(long, default_value = "127.0.0.1:5350")]
    listen: SocketAddr,

    /// Explicitly permit binding DNS outside loopback (for an isolated sidecar network).
    #[arg(long)]
    allow_non_loopback_listen: bool,

    /// hsrd JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:12037/")]
    hsrd_rpc_url: String,

    /// Read the exact hsrd HTTP Authorization value from a private file.
    #[arg(long)]
    hsrd_authorization_header_file: Option<PathBuf>,

    #[arg(long, default_value_t = 2_000)]
    hsrd_timeout_ms: u64,

    #[arg(long, default_value_t = 32)]
    hsrd_max_concurrent_requests: usize,

    /// Poll interval used to gate synchronization and invalidate caches on chain changes.
    #[arg(long, default_value_t = 1_000)]
    hsrd_chain_state_poll_ms: u64,

    #[arg(long, default_value_t = 256)]
    maximum_concurrent_queries: usize,

    #[arg(long, default_value_t = 1_024)]
    name_server_cache_size: usize,

    #[arg(long, default_value_t = 32_768)]
    record_cache_size: usize,

    /// Maximum time a positive DNS result remains in the local cache.
    #[arg(long, default_value_t = 1_800)]
    maximum_positive_ttl_seconds: u64,

    /// Maximum time an NXDOMAIN result remains in the local cache.
    #[arg(long, default_value_t = 300)]
    maximum_negative_ttl_seconds: u64,

    /// Answer from validated active state even while headers are ahead.
    #[arg(long)]
    allow_unsynchronized: bool,

    /// Permit recursive queries to loopback, private, link-local, and reserved addresses.
    #[arg(long)]
    allow_private_name_servers: bool,

    /// Disable DNSSEC-validated fallback for unclaimed ICANN root names.
    #[arg(long)]
    disable_icann_fallback: bool,

    /// Override an ICANN root-hints address (repeat for multiple servers).
    #[arg(long = "icann-root-server")]
    icann_root_servers: Vec<IpAddr>,

    #[arg(long, default_value_t = 3_000)]
    icann_timeout_ms: u64,

    #[arg(long, default_value_t = 16)]
    icann_max_concurrent_queries: usize,

    #[arg(long, default_value_t = 4_096)]
    icann_cache_size: usize,

    #[arg(long, env = "HNS_RESOLVERD_LOG", default_value = "info")]
    log_filter: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_filter)?;
    anyhow::ensure!(
        cli.listen.ip().is_loopback() || cli.allow_non_loopback_listen,
        "a non-loopback DNS listener requires --allow-non-loopback-listen and an external network ACL"
    );
    anyhow::ensure!(
        cli.hsrd_max_concurrent_requests > 0,
        "hsrd maximum concurrent requests must be non-zero"
    );
    let authorization = cli
        .hsrd_authorization_header_file
        .as_deref()
        .map(read_authorization_header)
        .transpose()?;
    let source = HsrdRpcClient::new(
        cli.hsrd_rpc_url,
        authorization,
        Duration::from_millis(cli.hsrd_timeout_ms),
        cli.hsrd_max_concurrent_requests,
    )?;
    let defaults = ResolverConfig::default();
    let config = ResolverConfig {
        listen: cli.listen,
        require_synchronized: !cli.allow_unsynchronized,
        maximum_concurrent_queries: cli.maximum_concurrent_queries,
        name_server_cache_size: cli.name_server_cache_size,
        record_cache_size: cli.record_cache_size,
        maximum_positive_ttl: Duration::from_secs(cli.maximum_positive_ttl_seconds),
        maximum_negative_ttl: Duration::from_secs(cli.maximum_negative_ttl_seconds),
        deny_private_name_servers: !cli.allow_private_name_servers,
        chain_state_poll_interval: Duration::from_millis(cli.hsrd_chain_state_poll_ms),
        icann_fallback: !cli.disable_icann_fallback,
        icann_root_servers: if cli.icann_root_servers.is_empty() {
            defaults.icann_root_servers.clone()
        } else {
            cli.icann_root_servers
        },
        icann_timeout: Duration::from_millis(cli.icann_timeout_ms),
        icann_maximum_concurrent_queries: cli.icann_max_concurrent_queries,
        icann_cache_size: cli.icann_cache_size,
        ..defaults
    };
    let runtime = ResolverRuntime::bind(Arc::new(source), config).await?;
    runtime.serve_until(shutdown_signal()).await
}

async fn shutdown_signal() {
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

fn init_logging(filter: &str) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_new(filter)?;
    fmt()
        .with_env_filter(env_filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing: {error}"))
}

fn read_authorization_header(path: &Path) -> anyhow::Result<HeaderValue> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("authorization header path must be absolute without parent traversal");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_AUTHORIZATION_BYTES as u64 {
        anyhow::bail!("authorization header must be a bounded mode-0600 regular file");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("authorization header must not be accessible by group or other users");
    }
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        anyhow::bail!("authorization header must not be a symbolic link");
    }
    let mut bytes = Vec::new();
    file.take((MAX_AUTHORIZATION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_AUTHORIZATION_BYTES {
        anyhow::bail!("authorization header exceeds the hard byte limit");
    }
    let value = String::from_utf8(bytes)?.trim().to_owned();
    anyhow::ensure!(!value.is_empty(), "authorization header must not be empty");
    Ok(HeaderValue::from_str(&value)?)
}
