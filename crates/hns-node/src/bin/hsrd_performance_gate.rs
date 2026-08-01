use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use hns_chain::HeaderIndex;
use hns_consensus::{compute_block_version, DeploymentHistoryEntry, Network};
use hns_mining::{TemplateCacheKey, TemplatePolicy};
use hns_node::{
    MiningEngineConfig, MiningTemplateRequest, NodeBlockImport, NodeConfig, NodeService, NodeState,
};
use hns_primitives::{blake2b_256_many, Address, Block, NONCE_SIZE};
use hns_store::{DurabilityPolicy, StoreHandle};
use serde_json::Value;

const WARMUP_BLOCKS: usize = 10;
const MEASURED_BLOCKS: usize = 100;
const PERSISTENT_SETUP_BLOCKS: usize = 4_096;
const PERSISTENT_CACHE_OCCUPANCY: usize = 4_096;
const TIP_TO_JOB_P99_TARGET_MICROS: u128 = 25_000;
const CANDIDATE_VALIDATION_P99_TARGET_MICROS: u128 = 5_000;
const LOCAL_CONNECT_P99_TARGET_MICROS: u128 = 50_000;
const AUTO_DATA_ROOT_MARKER: &str = ".hsrd-performance-gate-owned-v1";
const AUTO_DATA_ROOT_ATTEMPTS: u32 = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum Scenario {
    #[default]
    Smoke,
    PersistentRocksdbSync,
}

impl Scenario {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::PersistentRocksdbSync => "persistent-rocksdb-sync",
        }
    }
}

#[derive(Debug, Parser)]
#[command(about = "Run a deterministic native mining-path latency gate", version)]
struct Arguments {
    /// Select the fast in-memory smoke gate or the persistent RocksDB/sync gate.
    #[arg(long, value_enum, default_value = "smoke")]
    scenario: Scenario,

    /// Fresh, nonexistent persistent-scenario data root to create and retain.
    /// Without this option, a uniquely created temporary root is safely removed.
    #[arg(long)]
    data_root: Option<PathBuf>,

    /// Also write a schema-versioned JSON evidence record to this new file.
    #[arg(long)]
    json_output: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("hsrd-performance-gate: {error:#}");
        std::process::exit(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScenarioPlan {
    scenario: Scenario,
    expected_backend: &'static str,
    expected_durability: &'static str,
    warmup_blocks: usize,
    setup_blocks: usize,
    measured_blocks: usize,
    requested_cache_occupancy: Option<usize>,
}

impl ScenarioPlan {
    const fn for_scenario(scenario: Scenario) -> Self {
        match scenario {
            Scenario::Smoke => Self {
                scenario,
                expected_backend: "memory",
                expected_durability: "not-applicable",
                warmup_blocks: WARMUP_BLOCKS,
                setup_blocks: 0,
                measured_blocks: MEASURED_BLOCKS,
                requested_cache_occupancy: None,
            },
            Scenario::PersistentRocksdbSync => Self {
                scenario,
                expected_backend: "rocksdb",
                expected_durability: "sync",
                warmup_blocks: 0,
                setup_blocks: PERSISTENT_SETUP_BLOCKS,
                measured_blocks: MEASURED_BLOCKS,
                requested_cache_occupancy: Some(PERSISTENT_CACHE_OCCUPANCY),
            },
        }
    }

    fn history_entry_limit(self) -> Result<usize, Box<dyn Error>> {
        1usize
            .checked_add(self.warmup_blocks)
            .and_then(|count| count.checked_add(self.setup_blocks))
            .and_then(|count| count.checked_add(self.measured_blocks))
            .ok_or_else(|| "performance deployment-history limit overflowed".into())
    }
}

/// Bounded independent oracle for the synthetic chain's next header version.
/// Production template construction still derives and checks its cached HSD
/// deployment state independently; an oracle disagreement therefore fails the
/// gate rather than selecting a retry or fallback version.
#[derive(Debug)]
struct HsdVersionOracle {
    network: Network,
    maximum_entries: usize,
    history: Vec<DeploymentHistoryEntry>,
    next_version: u32,
}

impl HsdVersionOracle {
    fn from_genesis(
        network: Network,
        maximum_entries: usize,
        genesis_height: u32,
        genesis: DeploymentHistoryEntry,
    ) -> Result<Self, Box<dyn Error>> {
        if maximum_entries == 0 {
            return Err("performance deployment-history limit is zero".into());
        }
        if genesis_height != 0 {
            return Err(format!(
                "performance deployment history starts at height {genesis_height}, not genesis"
            )
            .into());
        }
        let mut history = Vec::with_capacity(maximum_entries);
        history.push(genesis);
        let next_version = Self::compute_version(network, &history)?;
        Ok(Self {
            network,
            maximum_entries,
            history,
            next_version,
        })
    }

    fn version_for_tip(
        &self,
        tip_height: u32,
        tip_median_time_past: u64,
    ) -> Result<u32, Box<dyn Error>> {
        if self.history.len() >= self.maximum_entries {
            return Err(format!(
                "performance deployment history exhausted its {}-entry scenario limit",
                self.maximum_entries
            )
            .into());
        }
        let expected_height = u32::try_from(self.history.len().saturating_sub(1))?;
        if tip_height != expected_height {
            return Err(format!(
                "performance deployment-history tip height {tip_height} is not contiguous with {expected_height}"
            )
            .into());
        }
        let recorded_median_time = self
            .history
            .last()
            .ok_or("performance deployment history is empty")?
            .median_time_past;
        if tip_median_time_past != recorded_median_time {
            return Err(format!(
                "performance deployment-history MTP {recorded_median_time} disagrees with durable tip MTP {tip_median_time_past} at height {tip_height}"
            )
            .into());
        }
        Ok(self.next_version)
    }

    fn record_connected(
        &mut self,
        height: u32,
        entry: DeploymentHistoryEntry,
        requested_version: u32,
    ) -> Result<(), Box<dyn Error>> {
        if self.history.len() >= self.maximum_entries {
            return Err(format!(
                "performance deployment history exceeded its {}-entry scenario limit",
                self.maximum_entries
            )
            .into());
        }
        let expected_height = u32::try_from(self.history.len())?;
        if height != expected_height {
            return Err(format!(
                "connected performance height {height} is not contiguous with deployment-history height {expected_height}"
            )
            .into());
        }
        if entry.version != requested_version {
            return Err(format!(
                "accepted performance header version {} disagrees with requested HSD oracle version {requested_version} at height {height}",
                entry.version
            )
            .into());
        }
        self.history.push(entry);

        let next_height = height
            .checked_add(1)
            .ok_or("performance deployment-history height exhausted")?;
        if self.history.len() < self.maximum_entries
            && Self::is_deployment_boundary(self.network, next_height)?
        {
            self.next_version = Self::compute_version(self.network, &self.history)?;
        }
        Ok(())
    }

    fn is_deployment_boundary(network: Network, next_height: u32) -> Result<bool, Box<dyn Error>> {
        let default_window = network.params().miner_window;
        for deployment in network.deployments() {
            let window = deployment.effective_window(default_window);
            if window == 0 {
                return Err(format!("deployment {} has a zero window", deployment.name()).into());
            }
            if next_height.is_multiple_of(window) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn compute_version(
        network: Network,
        history: &[DeploymentHistoryEntry],
    ) -> Result<u32, Box<dyn Error>> {
        let params = network.params();
        Ok(compute_block_version(
            params.activation_threshold,
            params.miner_window,
            network.deployments(),
            history,
        )?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockTiming {
    template_micros: u128,
    prepare_micros: u128,
    tip_to_job_micros: u128,
    candidate_micros: u128,
    connect_micros: u128,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct LatencySamples {
    template_micros: Vec<u128>,
    prepare_micros: Vec<u128>,
    tip_to_job_micros: Vec<u128>,
    candidate_micros: Vec<u128>,
    connect_micros: Vec<u128>,
}

impl LatencySamples {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            template_micros: Vec::with_capacity(capacity),
            prepare_micros: Vec::with_capacity(capacity),
            tip_to_job_micros: Vec::with_capacity(capacity),
            candidate_micros: Vec::with_capacity(capacity),
            connect_micros: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, timing: BlockTiming) {
        self.template_micros.push(timing.template_micros);
        self.prepare_micros.push(timing.prepare_micros);
        self.tip_to_job_micros.push(timing.tip_to_job_micros);
        self.candidate_micros.push(timing.candidate_micros);
        self.connect_micros.push(timing.connect_micros);
    }

    fn all_counts_match(&self, expected: usize) -> bool {
        [
            self.template_micros.len(),
            self.prepare_micros.len(),
            self.tip_to_job_micros.len(),
            self.candidate_micros.len(),
            self.connect_micros.len(),
        ]
        .into_iter()
        .all(|count| count == expected)
    }
}

#[derive(Debug)]
struct GateOutcome {
    plan: ScenarioPlan,
    observed_backend: Option<&'static str>,
    observed_durability: Option<&'static str>,
    data_root: Option<String>,
    data_root_policy: &'static str,
    observed_cache_capacity: Option<usize>,
    observed_cache_occupancy: Option<usize>,
    observed_final_cache_occupancy: Option<usize>,
    observed_warmup_blocks: Option<usize>,
    observed_setup_blocks: Option<usize>,
    observed_measured_blocks: Option<usize>,
    latencies: LatencySamples,
    unavailable_evidence: usize,
    failure_detail: Option<String>,
}

impl GateOutcome {
    fn unavailable(plan: ScenarioPlan, failure_detail: String) -> Self {
        Self {
            plan,
            observed_backend: None,
            observed_durability: None,
            data_root: None,
            data_root_policy: "unavailable",
            observed_cache_capacity: None,
            observed_cache_occupancy: None,
            observed_final_cache_occupancy: None,
            observed_warmup_blocks: None,
            observed_setup_blocks: None,
            observed_measured_blocks: None,
            latencies: LatencySamples::default(),
            unavailable_evidence: 1,
            failure_detail: Some(failure_detail),
        }
    }

    fn backend_matches(&self) -> bool {
        self.observed_backend == Some(self.plan.expected_backend)
    }

    fn durability_matches(&self) -> bool {
        self.observed_durability == Some(self.plan.expected_durability)
    }

    fn preparation_matches(&self) -> bool {
        self.observed_warmup_blocks == Some(self.plan.warmup_blocks)
            && self.observed_setup_blocks == Some(self.plan.setup_blocks)
    }

    fn measured_blocks_match(&self) -> bool {
        self.observed_measured_blocks == Some(self.plan.measured_blocks)
            && self.latencies.all_counts_match(self.plan.measured_blocks)
    }

    fn cache_evidence_matches(&self) -> bool {
        let Some(requested) = self.plan.requested_cache_occupancy else {
            return true;
        };
        self.observed_cache_capacity == Some(requested)
            && self.observed_cache_occupancy == Some(requested)
            && self.observed_final_cache_occupancy == Some(requested)
    }

    fn latency_targets_pass(&self) -> bool {
        self.latencies.all_counts_match(self.plan.measured_blocks)
            && percentile(&self.latencies.tip_to_job_micros, 99) < TIP_TO_JOB_P99_TARGET_MICROS
            && percentile(&self.latencies.candidate_micros, 99)
                < CANDIDATE_VALIDATION_P99_TARGET_MICROS
            && percentile(&self.latencies.connect_micros, 99) < LOCAL_CONNECT_P99_TARGET_MICROS
    }

    fn passed(&self) -> bool {
        self.unavailable_evidence == 0
            && self.failure_detail.is_none()
            && self.backend_matches()
            && self.durability_matches()
            && self.preparation_matches()
            && self.measured_blocks_match()
            && self.cache_evidence_matches()
            && self.latency_targets_pass()
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();
    let plan = ScenarioPlan::for_scenario(arguments.scenario);
    let outcome = match execute_workload(&arguments, plan) {
        Ok(outcome) => outcome,
        Err(error) => {
            let outcome = GateOutcome::unavailable(plan, error.to_string());
            print_outcome(&outcome);
            if let Some(path) = arguments.json_output.as_deref() {
                if let Err(output_error) = write_json_output(path, &outcome) {
                    return Err(format!(
                        "{error}; additionally failed to write unavailable-evidence report: {output_error}"
                    )
                    .into());
                }
            }
            return Err(error);
        }
    };
    let passed = outcome.passed();
    print_outcome(&outcome);
    if let Some(path) = arguments.json_output.as_deref() {
        write_json_output(path, &outcome)?;
    }
    if !passed {
        return Err(
            "one or more mining-path latency or persistent-evidence targets were missed".into(),
        );
    }
    Ok(())
}

fn execute_workload(
    arguments: &Arguments,
    plan: ScenarioPlan,
) -> Result<GateOutcome, Box<dyn Error>> {
    if plan.scenario == Scenario::Smoke && arguments.data_root.is_some() {
        return Err("--data-root is only valid with --scenario persistent-rocksdb-sync".into());
    }
    #[cfg(not(feature = "rocksdb-backend"))]
    if plan.scenario == Scenario::PersistentRocksdbSync {
        return Err("persistent-rocksdb-sync requires the rocksdb-backend feature".into());
    }

    let mut persistent_root = if plan.scenario == Scenario::PersistentRocksdbSync {
        Some(match &arguments.data_root {
            Some(path) => PerformanceDataRoot::create_caller_selected(path)?,
            None => PerformanceDataRoot::create_automatic()?,
        })
    } else {
        None
    };
    let data_root = persistent_root
        .as_ref()
        .map(|root| root.path().display().to_string());
    let data_root_policy = persistent_root
        .as_ref()
        .map_or("none", PerformanceDataRoot::policy);

    let config = NodeConfig {
        network: Network::Regtest,
        data_dir: persistent_root
            .as_ref()
            .map(|root| root.path().to_path_buf()),
        storage_durability: DurabilityPolicy::Sync,
        mining_engine: MiningEngineConfig {
            enabled: true,
            ..MiningEngineConfig::default()
        },
        ..NodeConfig::default()
    };
    let state = NodeState::from_config(&config)?;
    let observed_backend = store_backend(&state.store);
    let observed_durability = if observed_backend == "rocksdb" {
        state.store.durability_policy().as_str()
    } else {
        "not-applicable"
    };
    let mut node = NodeService::try_with_state(config, state)?;
    node.connect_block(NodeBlockImport::from_peer(canonical_regtest_genesis()?, 0))?;
    let genesis_snapshot = node
        .observed_mining_snapshot()?
        .ok_or("durable genesis mining snapshot is unavailable")?;
    let genesis_height = usize::try_from(genesis_snapshot.tip.height)?;
    if genesis_height != 0 {
        return Err(
            format!("regtest genesis connected at unexpected height {genesis_height}").into(),
        );
    }
    let mut version_oracle = HsdVersionOracle::from_genesis(
        Network::Regtest,
        plan.history_entry_limit()?,
        genesis_snapshot.tip.height,
        deployment_history_entry_for_tip(&node, &genesis_snapshot)?,
    )?;

    for _ in 0..plan.warmup_blocks {
        mine_and_connect(&mut node, &mut version_oracle)?;
    }
    let after_warmup_height = observed_tip_height(&node)?;
    let observed_warmup_blocks = after_warmup_height.checked_sub(genesis_height);

    for completed in 1..=plan.setup_blocks {
        mine_and_connect(&mut node, &mut version_oracle)?;
        if completed.is_multiple_of(256) || completed == plan.setup_blocks {
            eprintln!("persistent_setup_blocks_completed={completed}");
        }
    }
    let after_setup_height = observed_tip_height(&node)?;
    let observed_setup_blocks = after_setup_height.checked_sub(after_warmup_height);
    let observed_cache_capacity = node.block_cache_capacity();
    let observed_cache_occupancy = node.block_cache_occupancy();

    let mut latencies = LatencySamples::with_capacity(plan.measured_blocks);
    for _ in 0..plan.measured_blocks {
        latencies.push(mine_and_connect(&mut node, &mut version_oracle)?);
    }
    let after_measurement_height = observed_tip_height(&node)?;
    let observed_measured_blocks = after_measurement_height.checked_sub(after_setup_height);
    let observed_final_cache_occupancy = node.block_cache_occupancy();

    drop(node);
    if let Some(root) = persistent_root.as_mut() {
        root.cleanup_if_automatic()?;
    }

    Ok(GateOutcome {
        plan,
        observed_backend: Some(observed_backend),
        observed_durability: Some(observed_durability),
        data_root,
        data_root_policy,
        observed_cache_capacity: Some(observed_cache_capacity),
        observed_cache_occupancy: Some(observed_cache_occupancy),
        observed_final_cache_occupancy: Some(observed_final_cache_occupancy),
        observed_warmup_blocks,
        observed_setup_blocks,
        observed_measured_blocks,
        latencies,
        unavailable_evidence: 0,
        failure_detail: None,
    })
}

fn mine_and_connect(
    node: &mut NodeService,
    version_oracle: &mut HsdVersionOracle,
) -> Result<BlockTiming, Box<dyn Error>> {
    let snapshot = node
        .observed_mining_snapshot()?
        .ok_or("durable mining snapshot is unavailable")?;
    let version =
        version_oracle.version_for_tip(snapshot.tip.height, snapshot.parent_median_time)?;
    let mask = [0x42; 32];
    let mask_hash = blake2b_256_many([snapshot.tip.hash.as_bytes().as_slice(), mask.as_slice()]);
    let request = MiningTemplateRequest {
        variant: 0,
        payout_address: Address::new(0, vec![0x51; 20])?,
        coinbase_flags: b"hsrd-performance-gate".to_vec(),
        version,
        bits: Network::Regtest.params().pow.bits,
        minimum_time: snapshot.parent_median_time.saturating_add(1),
        reserved_root: [0; 32],
        mask_hash,
        policy: TemplatePolicy::default(),
    };

    let tip_started = Instant::now();
    let template_started = Instant::now();
    let template = node.mining_engine_build_template(request)?;
    let template_micros = template_started.elapsed().as_micros();
    let key = TemplateCacheKey {
        snapshot_generation: template.snapshot_generation(),
        mempool_generation: template.mempool_generation(),
        variant: 0,
    };
    let prepare_started = Instant::now();
    let job = node.mining_engine_prepare_cached_job(&key)?;
    let prepare_micros = prepare_started.elapsed().as_micros();
    let tip_to_job_micros = tip_started.elapsed().as_micros();

    let mut nonce = 0u32;
    let extra_nonce = [0; NONCE_SIZE];
    loop {
        let candidate = job.reconstruct(nonce, job.header().minimum_time, extra_nonce, mask)?;
        if candidate.header.verify_pow() {
            break;
        }
        nonce = nonce
            .checked_add(1)
            .ok_or("regtest nonce space exhausted")?;
    }

    let candidate_started = Instant::now();
    let candidate = job.admit_solution(
        &snapshot,
        nonce,
        job.header().minimum_time,
        extra_nonce,
        mask,
    )?;
    let candidate_micros = candidate_started.elapsed().as_micros();

    let connect_started = Instant::now();
    node.connect_block(NodeBlockImport::from_mining_candidate(candidate)?)?;
    let connect_micros = connect_started.elapsed().as_micros();
    let connected_snapshot = node
        .observed_mining_snapshot()?
        .ok_or("connected durable mining snapshot is unavailable")?;
    let connected_entry = deployment_history_entry_for_tip(node, &connected_snapshot)?;
    version_oracle.record_connected(connected_snapshot.tip.height, connected_entry, version)?;

    Ok(BlockTiming {
        template_micros,
        prepare_micros,
        tip_to_job_micros,
        candidate_micros,
        connect_micros,
    })
}

fn deployment_history_entry_for_tip(
    node: &NodeService,
    snapshot: &hns_mining::MiningSnapshot,
) -> Result<DeploymentHistoryEntry, Box<dyn Error>> {
    let canonical = node
        .state()
        .chain
        .canonical_hash(snapshot.tip.height)?
        .ok_or_else(|| {
            format!(
                "durable mining tip height {} has no canonical header",
                snapshot.tip.height
            )
        })?;
    if canonical != snapshot.tip.hash {
        return Err(format!(
            "durable mining tip {} disagrees with canonical header {} at height {}",
            snapshot.tip.hash.to_hex(),
            canonical.to_hex(),
            snapshot.tip.height
        )
        .into());
    }
    let record = node
        .state()
        .chain
        .header(&snapshot.tip.hash)?
        .ok_or_else(|| {
            format!(
                "durable mining tip {} has no accepted header record",
                snapshot.tip.hash.to_hex()
            )
        })?;
    if record.hash != snapshot.tip.hash
        || record.height != snapshot.tip.height
        || record.header.prev_block != snapshot.tip.parent_hash
        || record.header.tree_root != snapshot.tip.tree_root
        || record.header.time != snapshot.tip.time
        || record.header.bits != snapshot.tip.bits
    {
        return Err(format!(
            "accepted header record disagrees with durable mining snapshot at height {}",
            snapshot.tip.height
        )
        .into());
    }
    Ok(DeploymentHistoryEntry {
        version: record.header.version,
        median_time_past: snapshot.parent_median_time,
    })
}

fn observed_tip_height(node: &NodeService) -> Result<usize, Box<dyn Error>> {
    let snapshot = node
        .observed_mining_snapshot()?
        .ok_or("durable mining snapshot is unavailable")?;
    Ok(usize::try_from(snapshot.tip.height)?)
}

fn store_backend(store: &StoreHandle) -> &'static str {
    match store {
        StoreHandle::Memory(_) => "memory",
        #[cfg(feature = "rocksdb-backend")]
        StoreHandle::Rocks(_) => "rocksdb",
        StoreHandle::Archived { inner, .. } => store_backend(inner),
    }
}

fn print_outcome(outcome: &GateOutcome) {
    print_distribution("template_build", &outcome.latencies.template_micros);
    print_distribution("job_prepare", &outcome.latencies.prepare_micros);
    print_distribution("tip_to_job", &outcome.latencies.tip_to_job_micros);
    print_distribution("candidate_validation", &outcome.latencies.candidate_micros);
    print_distribution("local_connect", &outcome.latencies.connect_micros);
    println!("scenario={}", outcome.plan.scenario.as_str());
    println!(
        "backend={}",
        outcome.observed_backend.unwrap_or("unavailable")
    );
    println!(
        "durability={}",
        outcome.observed_durability.unwrap_or("unavailable")
    );
    println!("package_version={}", env!("CARGO_PKG_VERSION"));
    println!("setup_blocks={}", outcome.plan.setup_blocks);
    println!("measured_blocks={}", outcome.plan.measured_blocks);
    println!(
        "requested_cache_occupancy={}",
        outcome.plan.requested_cache_occupancy.unwrap_or(0)
    );
    println!(
        "observed_cache_occupancy={}",
        outcome.observed_cache_occupancy.unwrap_or(0)
    );
    println!("failure_count={}", if outcome.passed() { 0 } else { 1 });
    println!("unavailable_evidence={}", outcome.unavailable_evidence);
    println!("tip_to_job_p99_target_micros={TIP_TO_JOB_P99_TARGET_MICROS}");
    println!("candidate_validation_p99_target_micros={CANDIDATE_VALIDATION_P99_TARGET_MICROS}");
    println!("local_connect_p99_target_micros={LOCAL_CONNECT_P99_TARGET_MICROS}");
}

fn distribution(samples: &[u128]) -> Value {
    serde_json::json!({
        "count": samples.len(),
        "p50_micros": percentile(samples, 50),
        "p95_micros": percentile(samples, 95),
        "p99_micros": percentile(samples, 99),
        "max_micros": samples.iter().copied().max().unwrap_or(0),
    })
}

fn json_report(outcome: &GateOutcome) -> Value {
    let passed = outcome.passed();
    serde_json::json!({
        "schema_version": 2,
        "gate": "deterministic_performance",
        "scenario": outcome.plan.scenario.as_str(),
        "package_name": env!("CARGO_PKG_NAME"),
        "package_version": env!("CARGO_PKG_VERSION"),
        "status": if passed { "pass" } else { "fail" },
        "passed": passed,
        "backend": outcome.observed_backend,
        "requested_backend": outcome.plan.expected_backend,
        "durability": outcome.observed_durability,
        "requested_durability": outcome.plan.expected_durability,
        "data_root": outcome.data_root.as_deref(),
        "data_root_policy": outcome.data_root_policy,
        "workload": {
            "network": "regtest",
            "warmup_blocks": outcome.plan.warmup_blocks,
            "observed_warmup_blocks": outcome.observed_warmup_blocks,
            "setup_blocks": outcome.plan.setup_blocks,
            "requested_setup_blocks": outcome.plan.setup_blocks,
            "observed_setup_blocks": outcome.observed_setup_blocks,
            "measured_blocks": outcome.plan.measured_blocks,
            "requested_measured_blocks": outcome.plan.measured_blocks,
            "observed_measured_blocks": outcome.observed_measured_blocks,
            "requested_cache_occupancy": outcome.plan.requested_cache_occupancy,
            "observed_cache_occupancy": outcome.observed_cache_occupancy,
            "observed_final_cache_occupancy": outcome.observed_final_cache_occupancy,
            "observed_cache_capacity": outcome.observed_cache_capacity,
        },
        "thresholds": {
            "tip_to_job_p99_target_micros_exclusive": TIP_TO_JOB_P99_TARGET_MICROS,
            "candidate_validation_p99_target_micros_exclusive":
                CANDIDATE_VALIDATION_P99_TARGET_MICROS,
            "local_connect_p99_target_micros_exclusive": LOCAL_CONNECT_P99_TARGET_MICROS,
        },
        "metrics": {
            "template_build": distribution(&outcome.latencies.template_micros),
            "job_prepare": distribution(&outcome.latencies.prepare_micros),
            "tip_to_job": distribution(&outcome.latencies.tip_to_job_micros),
            "candidate_validation": distribution(&outcome.latencies.candidate_micros),
            "local_connect": distribution(&outcome.latencies.connect_micros),
            "failure_count": if passed { 0 } else { 1 },
            "unavailable_evidence": outcome.unavailable_evidence,
        },
        "evidence": {
            "backend_matches": outcome.backend_matches(),
            "durability_matches": outcome.durability_matches(),
            "preparation_matches": outcome.preparation_matches(),
            "measured_blocks_match": outcome.measured_blocks_match(),
            "cache_evidence_matches": outcome.cache_evidence_matches(),
            "latency_targets_pass": outcome.latency_targets_pass(),
        },
        "failure_detail": outcome.failure_detail.as_deref(),
    })
}

fn write_json_output(path: &Path, outcome: &GateOutcome) -> Result<(), Box<dyn Error>> {
    let report = json_report(outcome);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    serde_json::to_writer_pretty(&mut output, &report)?;
    writeln!(output)?;
    output.sync_all()?;
    Ok(())
}

#[derive(Debug)]
struct PerformanceDataRoot {
    path: PathBuf,
    automatic_marker: Option<String>,
    cleaned: bool,
}

impl PerformanceDataRoot {
    fn create_caller_selected(path: &Path) -> io::Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing to reuse caller-selected data root {}",
                        path.display()
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to create fresh caller-selected data root {}: {error}",
                    path.display()
                ),
            )
        })?;
        let canonical = match fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(error) => {
                let _ = fs::remove_dir(path);
                return Err(error);
            }
        };
        Ok(Self {
            path: canonical,
            automatic_marker: None,
            cleaned: false,
        })
    }

    fn create_automatic() -> io::Result<Self> {
        let base = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                io::Error::other(format!("system clock precedes Unix epoch: {error}"))
            })?
            .as_nanos();
        for attempt in 0..AUTO_DATA_ROOT_ATTEMPTS {
            let path = base.join(format!(
                "hsrd-performance-gate-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    let marker = format!(
                        "hsrd-performance-gate-owned-v1\npid={}\nnonce={nonce}-{attempt}\n",
                        std::process::id()
                    );
                    let marker_path = path.join(AUTO_DATA_ROOT_MARKER);
                    let marker_result = (|| -> io::Result<()> {
                        let mut file = OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&marker_path)?;
                        file.write_all(marker.as_bytes())?;
                        file.sync_all()
                    })();
                    if let Err(error) = marker_result {
                        let _ = fs::remove_file(&marker_path);
                        let _ = fs::remove_dir(&path);
                        return Err(error);
                    }
                    let canonical = match fs::canonicalize(&path) {
                        Ok(canonical) => canonical,
                        Err(error) => {
                            let _ = fs::remove_file(&marker_path);
                            let _ = fs::remove_dir(&path);
                            return Err(error);
                        }
                    };
                    return Ok(Self {
                        path: canonical,
                        automatic_marker: Some(marker),
                        cleaned: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "could not create a unique automatic data root after {AUTO_DATA_ROOT_ATTEMPTS} attempts"
            ),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn policy(&self) -> &'static str {
        if self.automatic_marker.is_some() {
            "automatic-create-new-scoped-cleanup"
        } else {
            "caller-create-new-retained"
        }
    }

    fn cleanup_if_automatic(&mut self) -> io::Result<()> {
        let Some(expected_marker) = self.automatic_marker.as_deref() else {
            return Ok(());
        };
        if self.cleaned {
            return Ok(());
        }
        let root_metadata = fs::symlink_metadata(&self.path)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(io::Error::other(format!(
                "refusing to clean replaced automatic data root {}",
                self.path.display()
            )));
        }
        let marker_path = self.path.join(AUTO_DATA_ROOT_MARKER);
        let marker_metadata = fs::symlink_metadata(&marker_path)?;
        if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() {
            return Err(io::Error::other(format!(
                "refusing to clean automatic data root with invalid ownership marker {}",
                marker_path.display()
            )));
        }
        let observed_marker = fs::read_to_string(&marker_path)?;
        if observed_marker != expected_marker {
            return Err(io::Error::other(format!(
                "refusing to clean automatic data root with mismatched ownership marker {}",
                marker_path.display()
            )));
        }
        fs::remove_dir_all(&self.path)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PerformanceDataRoot {
    fn drop(&mut self) {
        let _ = self.cleanup_if_automatic();
    }
}

fn canonical_regtest_genesis() -> Result<Block, Box<dyn Error>> {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/hsd/blocks/genesis-v1.json"
    )))?;
    let case = fixture["networks"]
        .as_array()
        .ok_or("genesis fixture has no network cases")?
        .iter()
        .find(|case| case["network"] == "regtest")
        .ok_or("genesis fixture has no regtest case")?;
    let raw = decode_hex(
        case["raw"]
            .as_str()
            .ok_or("regtest genesis fixture has no raw block")?,
    )?;
    Ok(Block::decode(&raw)?)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&value[offset..offset + 2], 16)?))
        .collect()
}

fn print_distribution(name: &str, samples: &[u128]) {
    println!("{name}_count={}", samples.len());
    println!("{name}_p50_micros={}", percentile(samples, 50));
    println!("{name}_p95_micros={}", percentile(samples, 95));
    println!("{name}_p99_micros={}", percentile(samples, 99));
    println!(
        "{name}_max_micros={}",
        samples.iter().copied().max().unwrap_or(0)
    );
}

fn percentile(samples: &[u128], percentile: usize) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = percentile.saturating_mul(sorted.len()).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing_outcome(scenario: Scenario) -> GateOutcome {
        let plan = ScenarioPlan::for_scenario(scenario);
        let passing_sample = 1u128;
        let latencies = LatencySamples {
            template_micros: vec![passing_sample; plan.measured_blocks],
            prepare_micros: vec![passing_sample; plan.measured_blocks],
            tip_to_job_micros: vec![passing_sample; plan.measured_blocks],
            candidate_micros: vec![passing_sample; plan.measured_blocks],
            connect_micros: vec![passing_sample; plan.measured_blocks],
        };
        let persistent = scenario == Scenario::PersistentRocksdbSync;
        GateOutcome {
            plan,
            observed_backend: Some(if persistent { "rocksdb" } else { "memory" }),
            observed_durability: Some(if persistent { "sync" } else { "not-applicable" }),
            data_root: persistent.then(|| "/fresh/performance/root".to_owned()),
            data_root_policy: if persistent {
                "caller-create-new-retained"
            } else {
                "none"
            },
            observed_cache_capacity: Some(PERSISTENT_CACHE_OCCUPANCY),
            observed_cache_occupancy: Some(if persistent {
                PERSISTENT_CACHE_OCCUPANCY
            } else {
                WARMUP_BLOCKS + 1
            }),
            observed_final_cache_occupancy: Some(if persistent {
                PERSISTENT_CACHE_OCCUPANCY
            } else {
                WARMUP_BLOCKS + MEASURED_BLOCKS + 1
            }),
            observed_warmup_blocks: Some(plan.warmup_blocks),
            observed_setup_blocks: Some(plan.setup_blocks),
            observed_measured_blocks: Some(plan.measured_blocks),
            latencies,
            unavailable_evidence: 0,
            failure_detail: None,
        }
    }

    #[test]
    fn arguments_preserve_smoke_default_and_parse_persistent_scenario() {
        let default =
            Arguments::try_parse_from(["hsrd-performance-gate"]).expect("default arguments");
        assert_eq!(default.scenario, Scenario::Smoke);
        assert_eq!(default.data_root, None);

        let persistent = Arguments::try_parse_from([
            "hsrd-performance-gate",
            "--scenario",
            "persistent-rocksdb-sync",
            "--data-root",
            "/new/performance/root",
            "--json-output",
            "/new/performance/report.json",
        ])
        .expect("persistent arguments");
        assert_eq!(persistent.scenario, Scenario::PersistentRocksdbSync);
        assert_eq!(
            persistent.data_root,
            Some(PathBuf::from("/new/performance/root"))
        );
        assert_eq!(
            persistent.json_output,
            Some(PathBuf::from("/new/performance/report.json"))
        );
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let values = (1..=100).collect::<Vec<u128>>();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 99), 99);
        assert_eq!(percentile(&[], 99), 0);
    }

    #[test]
    fn persistent_report_contains_exact_backend_scale_version_and_distributions() {
        let outcome = passing_outcome(Scenario::PersistentRocksdbSync);
        assert!(outcome.passed());
        let report = json_report(&outcome);
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["scenario"], "persistent-rocksdb-sync");
        assert_eq!(report["backend"], "rocksdb");
        assert_eq!(report["durability"], "sync");
        assert_eq!(report["package_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            report["workload"]["requested_cache_occupancy"],
            PERSISTENT_CACHE_OCCUPANCY
        );
        assert_eq!(
            report["workload"]["observed_cache_occupancy"],
            PERSISTENT_CACHE_OCCUPANCY
        );
        assert_eq!(
            report["workload"]["requested_setup_blocks"],
            PERSISTENT_SETUP_BLOCKS
        );
        assert_eq!(
            report["workload"]["observed_setup_blocks"],
            PERSISTENT_SETUP_BLOCKS
        );
        assert_eq!(
            report["workload"]["requested_measured_blocks"],
            MEASURED_BLOCKS
        );
        assert_eq!(
            report["workload"]["observed_measured_blocks"],
            MEASURED_BLOCKS
        );
        assert_eq!(report["metrics"]["local_connect"]["count"], MEASURED_BLOCKS);
        assert_eq!(report["status"], "pass");
        assert_eq!(report["passed"], true);
    }

    #[test]
    fn persistent_report_fails_closed_on_cache_or_unavailable_evidence() {
        let mut mismatched = passing_outcome(Scenario::PersistentRocksdbSync);
        mismatched.observed_cache_occupancy = Some(PERSISTENT_CACHE_OCCUPANCY - 1);
        assert!(!mismatched.passed());
        let mismatch_report = json_report(&mismatched);
        assert_eq!(mismatch_report["status"], "fail");
        assert_eq!(mismatch_report["evidence"]["cache_evidence_matches"], false);

        let unavailable = GateOutcome::unavailable(
            ScenarioPlan::for_scenario(Scenario::PersistentRocksdbSync),
            "backend unavailable".to_owned(),
        );
        assert!(!unavailable.passed());
        let unavailable_report = json_report(&unavailable);
        assert_eq!(unavailable_report["status"], "fail");
        assert_eq!(unavailable_report["backend"], Value::Null);
        assert_eq!(unavailable_report["metrics"]["unavailable_evidence"], 1);
        assert_eq!(unavailable_report["metrics"]["local_connect"]["count"], 0);
    }

    #[test]
    fn latency_thresholds_are_exclusive() {
        let mut outcome = passing_outcome(Scenario::Smoke);
        outcome
            .latencies
            .connect_micros
            .fill(LOCAL_CONNECT_P99_TARGET_MICROS - 1);
        assert!(outcome.passed());
        outcome
            .latencies
            .connect_micros
            .fill(LOCAL_CONNECT_P99_TARGET_MICROS);
        assert!(!outcome.passed());
    }

    #[test]
    fn automatic_root_cleanup_is_marker_scoped_and_caller_root_is_retained() {
        let mut automatic = PerformanceDataRoot::create_automatic().expect("automatic root");
        let automatic_path = automatic.path().to_path_buf();
        assert!(automatic_path.join(AUTO_DATA_ROOT_MARKER).is_file());
        automatic
            .cleanup_if_automatic()
            .expect("clean automatic root");
        assert!(!automatic_path.exists());

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let caller_path = std::env::temp_dir().join(format!(
            "hsrd-performance-gate-caller-test-{}-{nonce}",
            std::process::id()
        ));
        let caller =
            PerformanceDataRoot::create_caller_selected(&caller_path).expect("fresh caller root");
        drop(caller);
        assert!(
            caller_path.is_dir(),
            "caller-selected root must be retained"
        );
        let reuse = PerformanceDataRoot::create_caller_selected(&caller_path)
            .expect_err("existing caller root must be rejected");
        assert_eq!(reuse.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir(&caller_path).expect("remove exact test-owned caller root");
    }

    #[test]
    fn bounded_hsd_version_oracle_covers_persistent_setup_and_measurement() {
        let plan = ScenarioPlan::for_scenario(Scenario::PersistentRocksdbSync);
        let maximum_entries = plan.history_entry_limit().expect("history limit");
        assert_eq!(
            maximum_entries,
            1 + PERSISTENT_SETUP_BLOCKS + MEASURED_BLOCKS
        );

        let genesis = canonical_regtest_genesis().expect("regtest genesis");
        let median_time_past = genesis.header.time;
        let mut oracle = HsdVersionOracle::from_genesis(
            Network::Regtest,
            maximum_entries,
            0,
            DeploymentHistoryEntry {
                version: genesis.header.version,
                median_time_past,
            },
        )
        .expect("genesis deployment history");

        for height in 1..u32::try_from(maximum_entries).expect("bounded height") {
            let version = oracle
                .version_for_tip(height - 1, median_time_past)
                .expect("next HSD version");
            let expected = if (144..432).contains(&height) {
                1 << 28
            } else {
                0
            };
            assert_eq!(version, expected, "candidate height {height}");
            oracle
                .record_connected(
                    height,
                    DeploymentHistoryEntry {
                        version,
                        median_time_past,
                    },
                    version,
                )
                .expect("record connected synthetic header");
        }
        assert_eq!(oracle.history.len(), maximum_entries);
        assert!(oracle
            .version_for_tip(
                u32::try_from(maximum_entries - 1).expect("final height"),
                median_time_past,
            )
            .expect_err("scenario history cap must be final")
            .to_string()
            .contains("exhausted"));
    }

    #[test]
    fn production_template_and_native_job_cross_regtest_version_boundaries() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            mining_engine: MiningEngineConfig {
                enabled: true,
                ..MiningEngineConfig::default()
            },
            ..NodeConfig::default()
        });
        node.connect_block(NodeBlockImport::from_peer(
            canonical_regtest_genesis().expect("regtest genesis"),
            0,
        ))
        .expect("connect canonical genesis");
        let genesis_snapshot = node
            .observed_mining_snapshot()
            .expect("read genesis snapshot")
            .expect("genesis snapshot");
        let mut oracle = HsdVersionOracle::from_genesis(
            Network::Regtest,
            433,
            genesis_snapshot.tip.height,
            deployment_history_entry_for_tip(&node, &genesis_snapshot)
                .expect("accepted genesis deployment entry"),
        )
        .expect("initialize deployment oracle");

        for expected_height in 1..=143 {
            mine_and_connect(&mut node, &mut oracle).unwrap_or_else(|error| {
                panic!("candidate height {expected_height} failed: {error}")
            });
        }
        assert_eq!(oracle.history[143].version, 0);
        assert_eq!(
            oracle
                .version_for_tip(143, oracle.history[143].median_time_past)
                .expect("height-144 version"),
            1 << 28
        );

        let native = node
            .mining_engine_build_native_job(hns_node::NativeMiningJobRequest {
                variant: 0,
                payout_address: Address::new(0, vec![0x52; 20]).expect("native payout address"),
                coinbase_flags: b"hsrd-performance-boundary".to_vec(),
                reserved_root: [0; 32],
                mask: [0x43; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("native height-144 job");
        assert_eq!(native.snapshot.tip.height, 143);
        assert_eq!(native.prepared.header().version, 1 << 28);

        for expected_height in 144..=432 {
            mine_and_connect(&mut node, &mut oracle).unwrap_or_else(|error| {
                panic!("candidate height {expected_height} failed: {error}")
            });
        }
        for (height, expected_version) in [
            (143, 0),
            (144, 1 << 28),
            (287, 1 << 28),
            (288, 1 << 28),
            (431, 1 << 28),
            (432, 0),
        ] {
            assert_eq!(
                oracle.history[height].version, expected_version,
                "accepted header height {height}"
            );
        }
        assert_eq!(observed_tip_height(&node).expect("final height"), 432);
    }

    #[test]
    fn canonical_fixture_decodes_to_regtest_genesis() {
        let block = canonical_regtest_genesis().expect("regtest genesis");
        assert_eq!(block.header, Network::Regtest.params().genesis_header());
        assert_eq!(block.hash(), Network::Regtest.params().genesis_hash);
    }
}
