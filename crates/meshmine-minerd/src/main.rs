#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{Context, Result};
use clap::Parser;
use hns_consensus::Network;
use hns_mempool::MempoolLimits;
use hns_mining::TemplatePolicy;
use hns_node::{
    init_logging, validate_node_config, AuthorityMode, LivePeerManager, MiningEngineConfig,
    NameTreeCompactionConfig, NativeMiningJob, NativeMiningJobRequest, NativeRuntimeExtension,
    NativeSyncConfig, NodeConfig, NodeService, RpcAuthorizationHeader, SharedNodeService,
    ShutdownSignal, UndoRetentionConfig,
};
use hns_primitives::Address;
use hns_store::DurabilityPolicy;
use meshmine_gateway::{
    handy_target_from_difficulty, serve_rpc_connection_shared, DeviceProfile, Gateway, GatewayJob,
    PreviousJobTransition, RpcSession, SharedRpcControl,
};
use meshmine_hns::{blake2b_256, derive_capture_parameters, Hash256};
use meshmine_storage::{DurableStore, RedbStore};
use meshmine_types::U256;
use meshmine_work::{
    BackendKind, CpuBackend, DeviceCapabilities, DeviceEvent, MiningBackend, PreparedDeviceJob,
    VulkanBackend, WORK_PROTOCOL_VERSION,
};
use tokio::{sync::watch, task::JoinHandle};

const CAPTURE_NAMESPACE: &str = "native-solved-capture-v1";
const BLIND_BAND_BITS: u16 = 8;
const GATEWAY_DIFFICULTY: u32 = 1;
const GATEWAY_ASSIGNMENT_MS: u64 = 24 * 60 * 60 * 1_000;
const GATEWAY_GRACE_MS: u64 = 2 * 60 * 1_000;

#[derive(Debug, Parser)]
#[command(
    name = "meshmine-minerd",
    about = "Authoritative hsrd plus MeshMine CPU, Vulkan GPU, and HandyStratum ASIC mining"
)]
struct Cli {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:12047")]
    rpc_bind: SocketAddr,
    #[arg(long)]
    rpc_authorization_header_file: PathBuf,
    #[arg(long)]
    work_state: PathBuf,
    #[arg(long)]
    gateway_state: PathBuf,
    #[arg(long)]
    gateway_password_file: PathBuf,
    #[arg(long, default_value = "meshmine")]
    gateway_username: String,
    #[arg(long, default_value = "0.0.0.0:3008")]
    gateway_listen: SocketAddr,
    #[arg(long)]
    payout_version: u8,
    #[arg(long)]
    payout_hash: String,
    #[arg(long, default_value_t = 3)]
    cpu_threads: usize,
    #[arg(long)]
    disable_cpu: bool,
    #[arg(long)]
    disable_vulkan: bool,
    #[arg(long, default_value_t = 0)]
    vulkan_device: usize,
    #[arg(long, env = "HSRD_LOG", default_value = "info")]
    log_filter: String,
}

struct MinerExtension {
    payout_address: Address,
    work_store: Arc<dyn DurableStore>,
    gateway: Arc<Mutex<Gateway>>,
    gateway_control: Arc<SharedRpcControl>,
    workers: Vec<DeviceWorker>,
    next_extra_nonce: u32,
}

struct DeviceWorker {
    name: &'static str,
    id: Hash256,
    backend: Box<dyn MiningBackend>,
    hashes_per_second: Option<u64>,
}

struct ActiveJob {
    native: NativeMiningJob,
    network_target: Hash256,
    capture_target: Hash256,
}

impl NativeRuntimeExtension for MinerExtension {
    fn spawn(
        self: Box<Self>,
        node: SharedNodeService,
        peers: LivePeerManager,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move { self.run(node, peers, shutdown).await })
    }
}

impl MinerExtension {
    async fn run(
        mut self,
        node: SharedNodeService,
        peers: LivePeerManager,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut snapshots = {
            let guard = node.lock().await;
            guard.subscribe_observed_mining_events().latest_snapshot
        };
        let mut active: Option<ActiveJob> = None;
        let mut gateway_jobs = HashMap::<String, NativeMiningJob>::new();
        let mut poll = tokio::time::interval(Duration::from_millis(25));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = snapshots.changed() => {
                    self.replace_job_if_authoritative(
                        &node,
                        &mut active,
                        &mut gateway_jobs,
                    ).await?;
                }
                _ = poll.tick() => {
                    if active.is_none() && snapshots.borrow().is_some() {
                        self.replace_job_if_authoritative(
                            &node,
                            &mut active,
                            &mut gateway_jobs,
                        ).await?;
                    }
                    if let Some(job) = active.as_ref() {
                        self.poll_workers(job, &node, &peers).await?;
                        self.poll_gateway(&gateway_jobs, &node, &peers).await?;
                    }
                }
            }
        }

        if let Some(job) = &active {
            for worker in &mut self.workers {
                let _ = worker.backend.cancel_job(job.native.snapshot.generation);
            }
        }
        self.gateway_control.request_shutdown();
        Ok(())
    }

    async fn replace_job_if_authoritative(
        &mut self,
        node: &SharedNodeService,
        active: &mut Option<ActiveJob>,
        gateway_jobs: &mut HashMap<String, NativeMiningJob>,
    ) -> Result<()> {
        let request = NativeMiningJobRequest {
            variant: 0,
            payout_address: self.payout_address.clone(),
            coinbase_flags: b"MeshMine/hsrd".to_vec(),
            reserved_root: [0; 32],
            mask: [0; 32],
            policy: TemplatePolicy::default(),
        };
        let native = {
            let guard = node.lock().await;
            match guard.mining_engine_build_native_job(request) {
                Ok(job) => job,
                Err(error) => {
                    if active.is_none() {
                        tracing::debug!(%error, "waiting for authoritative mining permit");
                    }
                    return Ok(());
                }
            }
        };
        if active
            .as_ref()
            .is_some_and(|current| current.native.prepared.job_id() == native.prepared.job_id())
        {
            return Ok(());
        }

        if let Some(previous) = active.as_ref() {
            for worker in &mut self.workers {
                worker
                    .backend
                    .cancel_job(previous.native.snapshot.generation)
                    .with_context(|| format!("failed to cancel {} job", worker.name))?;
            }
        }

        let capture = derive_capture_parameters(native.prepared.header().bits, BLIND_BAND_BITS)
            .context("failed to derive MeshMine capture target")?;
        let gateway_job = gateway_job(&native, &capture, unix_time_ms())?;
        let gateway_job_id = gateway_job.id.clone();
        {
            let mut gateway = self
                .gateway
                .lock()
                .map_err(|_| anyhow::anyhow!("gateway lock poisoned"))?;
            gateway.close_expired(gateway_job.issued_ms)?;
            let transition = gateway.current_job().map(|previous| PreviousJobTransition {
                job_id: previous.id.clone(),
                credit_cutoff_ms: gateway_job.issued_ms,
                submission_end_ms: gateway_job
                    .issued_ms
                    .saturating_add(GATEWAY_GRACE_MS)
                    .min(previous.submission_end_ms),
            });
            gateway
                .issue_job_with_transition(gateway_job, transition)
                .context("failed to issue HandyStratum job")?;
        }
        let current = ActiveJob {
            native: native.clone(),
            network_target: capture.network_target,
            capture_target: capture.capture_target,
        };
        for index in 0..self.workers.len() {
            self.start_worker(index, &current)?;
        }
        gateway_jobs.insert(gateway_job_id.clone(), native);
        if gateway_jobs.len() > 8 {
            gateway_jobs.retain(|id, _| {
                id == &gateway_job_id
                    || self
                        .gateway
                        .lock()
                        .ok()
                        .is_some_and(|gateway| gateway.forwarded().iter().any(|c| &c.job_id == id))
            });
        }
        tracing::info!(
            generation = current.native.snapshot.generation,
            parent_height = current.native.snapshot.tip.height,
            parent = %current.native.snapshot.tip.hash.to_hex(),
            job_id = %gateway_job_id,
            cpu_gpu_workers = self.workers.len(),
            "authoritative MeshMine job activated for CPU, GPU, and ASIC gateway"
        );
        *active = Some(current);
        Ok(())
    }

    fn start_worker(&mut self, index: usize, active: &ActiveJob) -> Result<()> {
        let worker = self
            .workers
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("worker index is outside configured set"))?;
        let extra_nonce = device_extra_nonce(worker.id, self.next_extra_nonce);
        self.next_extra_nonce = self.next_extra_nonce.wrapping_add(1);
        let header = active.native.prepared.header();
        let mut identity = Vec::with_capacity(72);
        identity.extend_from_slice(&active.native.prepared.job_id());
        identity.extend_from_slice(&worker.id);
        identity.extend_from_slice(&extra_nonce);
        let lease_id = blake2b_256(&[&identity]);
        let job = PreparedDeviceJob {
            protocol_version: WORK_PROTOCOL_VERSION,
            job_id: active.native.prepared.job_id(),
            assignment_id: blake2b_256(&[&identity[..64]]),
            lease_id,
            generation: active.native.snapshot.generation,
            previous_block: *header.parent_hash.as_bytes(),
            merkle_root: header.merkle_root,
            witness_root: header.witness_root,
            tree_root: header.tree_root,
            reserved_root: header.reserved_root,
            version: header.version,
            bits: header.bits,
            ntime: header.minimum_time,
            mask_hash: header.mask_hash,
            extra_nonce_start: extra_nonce,
            extra_nonce_end: extra_nonce,
            nonce_start: 0,
            nonce_end: u32::MAX,
            nonce_stride: 1,
            edge_target: U256(active.capture_target),
            capture_target: U256(active.capture_target),
        };
        worker
            .backend
            .prepare_job(&job)
            .with_context(|| format!("{} rejected native job", worker.name))?;
        worker
            .backend
            .activate_job(job.generation)
            .with_context(|| format!("{} failed to activate native job", worker.name))
    }

    async fn poll_workers(
        &mut self,
        active: &ActiveJob,
        node: &SharedNodeService,
        peers: &LivePeerManager,
    ) -> Result<()> {
        for index in 0..self.workers.len() {
            let mut events = Vec::new();
            self.workers[index]
                .backend
                .poll_events(&mut |event| events.push(event))
                .with_context(|| format!("failed to poll {}", self.workers[index].name))?;
            for event in events {
                match event {
                    DeviceEvent::Capture {
                        generation,
                        nonce,
                        ntime,
                        extra_nonce,
                        raw_share_hash,
                        ..
                    } if generation == active.native.snapshot.generation => {
                        let worker_name = self.workers[index].name;
                        self.process_capture(
                            worker_name,
                            &active.native,
                            active.network_target,
                            nonce,
                            ntime,
                            extra_nonce,
                            raw_share_hash,
                            node,
                            peers,
                        )
                        .await?;
                    }
                    DeviceEvent::RangeCompleted { generation, .. }
                        if generation == active.native.snapshot.generation =>
                    {
                        self.workers[index].backend.cancel_job(generation)?;
                        self.start_worker(index, active)?;
                    }
                    DeviceEvent::Telemetry {
                        hashes_reported: Some(rate),
                        ..
                    } => {
                        if self.workers[index].hashes_per_second != Some(rate) {
                            self.workers[index].hashes_per_second = Some(rate);
                            tracing::info!(
                                worker = self.workers[index].name,
                                hashes_per_second = rate,
                                "MeshMine worker rate"
                            );
                        }
                    }
                    DeviceEvent::Disconnected => {
                        anyhow::bail!("{} mining backend disconnected", self.workers[index].name);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn poll_gateway(
        &mut self,
        jobs: &HashMap<String, NativeMiningJob>,
        node: &SharedNodeService,
        peers: &LivePeerManager,
    ) -> Result<()> {
        let captures = self
            .gateway
            .lock()
            .map_err(|_| anyhow::anyhow!("gateway lock poisoned"))?
            .forwarded()
            .to_vec();
        for capture in captures {
            let key = capture.work_key();
            if let Some(job) = jobs.get(&capture.job_id) {
                let network_target =
                    derive_capture_parameters(job.prepared.header().bits, BLIND_BAND_BITS)?
                        .network_target;
                self.process_capture(
                    "handystratum",
                    job,
                    network_target,
                    capture.miner_header.nonce,
                    capture.miner_header.time,
                    capture.miner_header.extra_nonce,
                    capture.raw_share_hash,
                    node,
                    peers,
                )
                .await?;
            }
            self.gateway
                .lock()
                .map_err(|_| anyhow::anyhow!("gateway lock poisoned"))?
                .acknowledge_capture(&key)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_capture(
        &mut self,
        source: &'static str,
        job: &NativeMiningJob,
        network_target: Hash256,
        nonce: u32,
        ntime: u64,
        extra_nonce: [u8; 24],
        raw_share_hash: Hash256,
        node: &SharedNodeService,
        peers: &LivePeerManager,
    ) -> Result<()> {
        let capture_id = capture_id(job, nonce, ntime, &extra_nonce, &raw_share_hash);
        let key = hex::encode(capture_id);
        self.work_store
            .put(
                CAPTURE_NAMESPACE,
                &key,
                &capture_record(nonce, ntime, extra_nonce, raw_share_hash),
            )
            .context("failed to durably spool mining capture")?;
        if raw_share_hash > network_target {
            self.work_store.delete(CAPTURE_NAMESPACE, &key)?;
            return Ok(());
        }
        let candidate = job
            .prepared
            .admit_solution(&job.snapshot, nonce, ntime, extra_nonce, [0; 32])
            .context("network-target capture failed hsrd solution admission")?;
        let result = node
            .lock()
            .await
            .mining_engine_publish_solved_candidate(candidate, peers, unix_time_seconds())
            .await
            .context("solved candidate failed local connection or publication")?;
        self.work_store.delete(CAPTURE_NAMESPACE, &key)?;
        tracing::info!(
            source,
            block = %result.connected.hash.to_hex(),
            height = result.connected.height,
            peers = result.attempt.written_peers,
            publication_pending = result.publication_pending,
            "MeshMine solved block connected locally and published"
        );
        Ok(())
    }
}

fn worker_capabilities(id: Hash256, backend_kind: BackendKind) -> DeviceCapabilities {
    DeviceCapabilities {
        device_id: id,
        backend_kind,
        supports_nonce_range: true,
        supports_nonce_stride: backend_kind != BackendKind::Vulkan,
        supports_extra_nonce_range: true,
        supports_ntime_rolling: false,
        supports_job_prepare: true,
        reports_range_completion: true,
        minimum_device_target: U256([0; 32]),
        maximum_job_rate_hz: 10,
        preferred_batch_size: 65_536,
        measured_hashrate: None,
        telemetry_level: 1,
    }
}

fn gateway_job(
    native: &NativeMiningJob,
    capture: &meshmine_hns::CaptureParameters,
    now_ms: u64,
) -> Result<GatewayJob> {
    let header = native.prepared.header();
    Ok(GatewayJob {
        id: hex::encode(native.prepared.job_id()),
        assignment_sequence: 0,
        previous_block: *header.parent_hash.as_bytes(),
        merkle_root: header.merkle_root,
        witness_root: header.witness_root,
        tree_root: header.tree_root,
        reserved_root: header.reserved_root,
        version: header.version,
        bits: header.bits,
        ntime: u32::try_from(header.minimum_time).context("template ntime exceeds u32")?,
        mask_hash: header.mask_hash,
        leading_zero_prefix_q: capture.leading_zero_prefix_q,
        blind_band_bits_d: capture.blind_band_bits_d,
        capture_target: capture.capture_target,
        advertised_device_target: handy_target_from_difficulty(GATEWAY_DIFFICULTY)?,
        advertised_difficulty: GATEWAY_DIFFICULTY,
        issued_ms: now_ms,
        assignment_end_ms: now_ms.saturating_add(GATEWAY_ASSIGNMENT_MS),
        submission_end_ms: now_ms
            .saturating_add(GATEWAY_ASSIGNMENT_MS)
            .saturating_add(GATEWAY_GRACE_MS),
        transaction_hashes: native
            .prepared
            .transactions()
            .iter()
            .map(|transaction| *transaction.txid().as_bytes())
            .collect(),
    })
}

fn start_gateway_listener(
    listen: SocketAddr,
    username: String,
    password: String,
    gateway: Arc<Mutex<Gateway>>,
    control: Arc<SharedRpcControl>,
) -> Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(listen)
        .with_context(|| format!("failed to bind HandyStratum listener on {listen}"))?;
    listener.set_nonblocking(true)?;
    let mut seed = Vec::with_capacity(16);
    seed.extend_from_slice(&unix_time_ms().to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    let prefix_seed = blake2b_256(&[&seed]);
    let prefixes = Arc::new(AtomicU32::new(u32::from_be_bytes(
        prefix_seed[..4].try_into().expect("four-byte prefix seed"),
    )));
    tracing::info!(%listen, %username, "HandyStratum ASIC listener started");
    thread::Builder::new()
        .name("meshmine-handystratum-listener".to_owned())
        .spawn(move || {
            while !control.shutdown_requested() {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        let gateway = Arc::clone(&gateway);
                        let control = Arc::clone(&control);
                        let username = username.clone();
                        let password = password.clone();
                        let prefix = prefixes.fetch_add(1, Ordering::Relaxed).to_be_bytes();
                        let _ = thread::Builder::new()
                            .name(format!("meshmine-asic-{peer}"))
                            .spawn(move || {
                                let session = RpcSession::new(
                                    username,
                                    password,
                                    prefix,
                                    DeviceProfile::handyminer_reference(),
                                );
                                if let Err(error) = serve_rpc_connection_shared(
                                    stream,
                                    session,
                                    gateway,
                                    control,
                                    100_000,
                                    Duration::from_millis(250),
                                ) {
                                    tracing::warn!(%peer, %error, "HandyStratum session ended");
                                }
                            });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => {
                        tracing::error!(%error, "HandyStratum accept failed");
                        break;
                    }
                }
            }
        })
        .context("failed to start HandyStratum listener")
}

fn open_store(path: &Path) -> Result<Arc<dyn DurableStore>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let store = if path.exists() {
        RedbStore::open_existing(path)?
    } else {
        RedbStore::create(path)?
    };
    Ok(Arc::new(store))
}

fn read_private_text(path: &Path, maximum: usize) -> Result<String> {
    if !path.is_absolute() {
        anyhow::bail!("secret file path must be absolute");
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        anyhow::bail!("secret must be a bounded regular file");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("secret file must have mode 0600");
    }
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        anyhow::bail!("secret file must not be a symbolic link");
    }
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        anyhow::bail!("secret exceeds configured bound");
    }
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn device_extra_nonce(id: Hash256, sequence: u32) -> [u8; 24] {
    let mut extra_nonce = [0; 24];
    extra_nonce[..4].copy_from_slice(&id[..4]);
    extra_nonce[4..8].copy_from_slice(&sequence.to_be_bytes());
    extra_nonce
}

fn capture_id(
    job: &NativeMiningJob,
    nonce: u32,
    ntime: u64,
    extra_nonce: &[u8; 24],
    hash: &Hash256,
) -> Hash256 {
    let mut bytes = Vec::with_capacity(100);
    bytes.extend_from_slice(&job.prepared.job_id());
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&ntime.to_le_bytes());
    bytes.extend_from_slice(extra_nonce);
    bytes.extend_from_slice(hash);
    blake2b_256(&[&bytes])
}

fn capture_record(nonce: u32, ntime: u64, extra_nonce: [u8; 24], hash: Hash256) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(68);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&ntime.to_le_bytes());
    bytes.extend_from_slice(&extra_nonce);
    bytes.extend_from_slice(&hash);
    bytes
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let payout_hash = hex::decode(&cli.payout_hash).context("payout hash is not hexadecimal")?;
    let payout_address = Address::new(cli.payout_version, payout_hash)
        .context("payout address version/hash is invalid")?;
    let rpc_authorization = RpcAuthorizationHeader::new(read_private_text(
        &cli.rpc_authorization_header_file,
        hns_node::MAX_RPC_AUTHORIZATION_BYTES,
    )?)?;
    let gateway_password = read_private_text(&cli.gateway_password_file, 255)?;
    if gateway_password.is_empty() {
        anyhow::bail!("gateway password must not be empty");
    }

    let config = NodeConfig {
        network: Network::Mainnet,
        data_dir: Some(cli.data_dir),
        rpc_bind: cli.rpc_bind,
        rpc_authorization: Some(rpc_authorization),
        log_filter: cli.log_filter,
        authority_mode: AuthorityMode::Native,
        mainnet_canary: true,
        acknowledge_incomplete_consensus: false,
        storage_durability: DurabilityPolicy::Sync,
        transaction_index: false,
        name_tree_compaction: NameTreeCompactionConfig {
            compact_on_startup: true,
            startup_interval: 10_000,
        },
        undo_retention: UndoRetentionConfig {
            prune_history: true,
        },
        shadow_sync: NativeSyncConfig {
            enabled: true,
            headers_only: false,
            connect_active_state: true,
            active_state_connect_batch: 288,
            discovery: true,
            maximum_outbound: 8,
            ..NativeSyncConfig::default()
        },
        mining_engine: MiningEngineConfig {
            enabled: true,
            transaction_relay: true,
            mempool_limits: MempoolLimits::default(),
            ..MiningEngineConfig::default()
        },
    };
    init_logging(&config.log_filter)?;
    validate_node_config(&config)?;

    let work_store = open_store(&cli.work_state)?;
    let gateway_store = open_store(&cli.gateway_state)?;
    let gateway = Arc::new(Mutex::new(Gateway::open(gateway_store)?));
    let gateway_control = Arc::new(SharedRpcControl::new(100)?);
    let _gateway_listener = start_gateway_listener(
        cli.gateway_listen,
        cli.gateway_username,
        gateway_password,
        gateway.clone(),
        gateway_control.clone(),
    )?;

    let mut workers = Vec::<DeviceWorker>::new();
    if !cli.disable_cpu {
        let id = blake2b_256(&[b"MeshMine/native/arm64-cpu/0"]);
        workers.push(DeviceWorker {
            name: "cpu",
            id,
            backend: Box::new(CpuBackend::new(
                worker_capabilities(id, BackendKind::Arm64Cpu),
                cli.cpu_threads,
                4_096,
            )?),
            hashes_per_second: None,
        });
    }
    if !cli.disable_vulkan {
        let id = blake2b_256(&[b"MeshMine/native/vulkan/0"]);
        workers.push(DeviceWorker {
            name: "vulkan",
            id,
            backend: Box::new(VulkanBackend::new(
                worker_capabilities(id, BackendKind::Vulkan),
                cli.vulkan_device,
                65_536,
                1_024,
                4_096,
            )?),
            hashes_per_second: None,
        });
    }

    let extension = MinerExtension {
        payout_address,
        work_store,
        gateway,
        gateway_control,
        workers,
        next_extra_nonce: 1,
    };
    let node = NodeService::try_new(config)?;
    node.run_until_shutdown_with_extension(ShutdownSignal::ctrl_c(), Box::new(extension))
        .await
}
