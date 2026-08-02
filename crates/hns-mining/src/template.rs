use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashSet},
    sync::Arc,
};

use hns_consensus::{
    block_merkle_root, block_subsidy, block_witness_root, validate_block_body, Network,
    MAX_BLOCK_OPENS, MAX_BLOCK_RENEWALS, MAX_BLOCK_SIGOPS, MAX_BLOCK_UPDATES,
};
use hns_mempool::{
    minimum_policy_fee, AirdropMempoolEntry, ClaimMempoolEntry, MempoolPackage, MempoolSnapshot,
};
use hns_primitives::{
    blake2b_256_many, Address, Block, Covenant, CovenantKind, Header, Input, Outpoint, Output,
    Transaction, Witness, MAX_BLOCK_WEIGHT,
};

use crate::{
    MiningError, MiningHeaderTemplate, MiningSnapshot, PreparedMiningJob, MAX_PREPARED_JOBS,
};

pub const DEFAULT_RESERVED_TEMPLATE_WEIGHT: usize = 4_000;
pub const DEFAULT_RESERVED_TEMPLATE_SIGOPS: u32 = 400;
pub const MAX_TEMPLATE_VARIANTS: usize = MAX_PREPARED_JOBS;
pub type TemplateId = [u8; 32];

/// Hard live workspace ceiling for one dependency-frontier template build.
/// The selector checks this before reverse-index allocation and every heap
/// insertion, retaining a separate transient-package reserve throughout.
pub const MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES: u64 = 512 * 1024 * 1024;
/// Hard aggregate configuration ceiling for concurrently executing template
/// builds. Queued immutable-generation captures have a separate node envelope.
pub const MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const TEMPLATE_SELECTION_CANDIDATE_CHARGE_BYTES: u64 = 768;
const TEMPLATE_SELECTION_CANDIDATE_BASE_BYTES: u64 = 512;
const TEMPLATE_SELECTION_HEAP_ENTRY_BYTES: u64 =
    TEMPLATE_SELECTION_CANDIDATE_CHARGE_BYTES - TEMPLATE_SELECTION_CANDIDATE_BASE_BYTES;
const TEMPLATE_SELECTION_EDGE_OR_MEMBER_CHARGE_BYTES: u64 = 128;
const TEMPLATE_SELECTION_VECTOR_ELEMENT_BYTES: u64 = 32;
const TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Conservatively estimates dependency-frontier workspace from configured
/// mempool cardinality, maximum ancestor count, and active build count.
///
/// The estimate charges one self member in addition to the ancestor ceiling,
/// one reverse edge and one retained package member at four times the 32-byte
/// txid payload size (covering minimum `Vec` growth and allocator slack), fixed
/// adversarial-map/heap overhead per candidate, and one transient package
/// reserve per build. Runtime accounting additionally charges exact retained
/// exclusive-name vector and binary-heap capacities.
pub fn estimate_template_selection_workspace_bytes(
    maximum_candidates: usize,
    maximum_ancestors: usize,
    active_builds: usize,
) -> Option<u64> {
    let candidates = u64::try_from(maximum_candidates).ok()?;
    let package_members = u64::try_from(maximum_ancestors).ok()?.checked_add(1)?;
    let builds = u64::try_from(active_builds).ok()?;
    let candidate_bytes = candidates.checked_mul(TEMPLATE_SELECTION_CANDIDATE_CHARGE_BYTES)?;
    let dependency_members = candidates.checked_mul(package_members)?;
    let dependency_and_package_bytes = dependency_members
        .checked_mul(TEMPLATE_SELECTION_EDGE_OR_MEMBER_CHARGE_BYTES)?
        .checked_mul(2)?;
    candidate_bytes
        .checked_add(dependency_and_package_bytes)?
        .checked_add(TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES)?
        .checked_mul(builds)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplatePolicy {
    pub maximum_weight: usize,
    pub maximum_sigops: u32,
    pub maximum_opens: u32,
    pub maximum_updates: u32,
    pub maximum_renewals: u32,
    pub maximum_transactions: usize,
    pub reserved_weight: usize,
    pub reserved_sigops: u32,
    /// Minimum package fee in atomic units per 1,000 HSD policy virtual bytes.
    pub minimum_package_fee_rate: u64,
}

impl Default for TemplatePolicy {
    fn default() -> Self {
        Self {
            maximum_weight: MAX_BLOCK_WEIGHT,
            maximum_sigops: MAX_BLOCK_SIGOPS,
            maximum_opens: MAX_BLOCK_OPENS,
            maximum_updates: MAX_BLOCK_UPDATES,
            maximum_renewals: MAX_BLOCK_RENEWALS,
            maximum_transactions: 50_000,
            reserved_weight: DEFAULT_RESERVED_TEMPLATE_WEIGHT,
            reserved_sigops: DEFAULT_RESERVED_TEMPLATE_SIGOPS,
            minimum_package_fee_rate: 0,
        }
    }
}

impl TemplatePolicy {
    pub fn validate(&self) -> Result<(), MiningError> {
        if self.maximum_weight == 0
            || self.maximum_sigops == 0
            || self.maximum_transactions == 0
            || self.reserved_weight > self.maximum_weight
            || self.reserved_sigops > self.maximum_sigops
            || self.maximum_weight > MAX_BLOCK_WEIGHT
            || self.maximum_sigops > MAX_BLOCK_SIGOPS
            || self.maximum_opens > MAX_BLOCK_OPENS
            || self.maximum_updates > MAX_BLOCK_UPDATES
            || self.maximum_renewals > MAX_BLOCK_RENEWALS
        {
            return Err(MiningError::InvalidTemplatePolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TemplateBuildRequest<'a> {
    pub snapshot: &'a MiningSnapshot,
    pub mempool: &'a MempoolSnapshot,
    pub payout_address: Address,
    pub coinbase_flags: Vec<u8>,
    pub version: u32,
    pub bits: u32,
    pub minimum_time: u64,
    pub reserved_root: [u8; 32],
    pub mask_hash: [u8; 32],
    pub policy: TemplatePolicy,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TemplateMetrics {
    pub transaction_count: usize,
    pub claim_count: usize,
    pub airdrop_count: usize,
    pub selected_packages: usize,
    pub fees: u64,
    pub weight: usize,
    pub sigops: u32,
    pub opens: u32,
    pub updates: u32,
    pub renewals: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningTemplate {
    template_id: TemplateId,
    snapshot_generation: u64,
    mempool_generation: u64,
    header: MiningHeaderTemplate,
    transactions: Arc<[Transaction]>,
    metrics: TemplateMetrics,
}

impl MiningTemplate {
    pub const fn template_id(&self) -> TemplateId {
        self.template_id
    }

    pub const fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    pub const fn mempool_generation(&self) -> u64 {
        self.mempool_generation
    }

    pub const fn header(&self) -> &MiningHeaderTemplate {
        &self.header
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub const fn metrics(&self) -> &TemplateMetrics {
        &self.metrics
    }

    pub fn prepare_job(&self, snapshot: &MiningSnapshot) -> Result<PreparedMiningJob, MiningError> {
        if snapshot.generation != self.snapshot_generation
            || snapshot.tip.hash != self.header.parent_hash
            || snapshot.next_tree_root != self.header.tree_root
        {
            return Err(MiningError::StaleTemplate);
        }
        PreparedMiningJob::new(
            snapshot,
            self.header.clone(),
            Arc::clone(&self.transactions),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct TemplateAssembler;

impl TemplateAssembler {
    pub fn assemble(
        &self,
        request: TemplateBuildRequest<'_>,
    ) -> Result<MiningTemplate, MiningError> {
        self.assemble_with_selection(
            request,
            SelectionAlgorithm::DependencyFrontier,
            &mut TemplateSelectionWork::default(),
        )
    }

    fn assemble_with_selection(
        &self,
        request: TemplateBuildRequest<'_>,
        selection: SelectionAlgorithm,
        work: &mut TemplateSelectionWork,
    ) -> Result<MiningTemplate, MiningError> {
        request.policy.validate()?;
        let next_height = request
            .snapshot
            .tip
            .height
            .checked_add(1)
            .ok_or(MiningError::InvalidTemplateContext)?;
        let network = Network::from_canonical_id(request.snapshot.network_id)
            .ok_or(MiningError::InvalidTemplateContext)?;
        if request.minimum_time <= request.snapshot.parent_median_time
            || request.mask_hash == [0; 32]
            || request.payout_address.validate().is_err()
        {
            return Err(MiningError::InvalidTemplateContext);
        }

        let mut selected_names = HashSet::new();
        let mut selected_claims: Vec<&ClaimMempoolEntry> = Vec::new();
        let mut selected_airdrops: Vec<&AirdropMempoolEntry> = Vec::new();
        let mut metrics = TemplateMetrics {
            weight: request.policy.reserved_weight,
            sigops: request.policy.reserved_sigops,
            ..TemplateMetrics::default()
        };

        // Sorting borrowed entries keeps large proof payloads structurally
        // shared with the immutable mempool snapshot. Only the at-most-ten
        // selected payloads are materialized while constructing the coinbase.
        let mut claims = request.mempool.claims().collect::<Vec<_>>();
        claims.sort_by(|left, right| {
            compare_fee_rates(right.fee, right.policy_size, left.fee, left.policy_size)
                .then_with(|| left.hash.cmp(&right.hash))
        });
        for entry in claims {
            if selected_claims.len() >= 10 {
                break;
            }
            if metrics
                .weight
                .checked_add(entry.coinbase_weight)
                .is_none_or(|weight| weight > request.policy.maximum_weight)
                || metrics.updates.saturating_add(1) > request.policy.maximum_updates
            {
                continue;
            }
            if entry.commit_height == 1 {
                metrics.fees = metrics
                    .fees
                    .checked_add(entry.fee)
                    .ok_or(MiningError::TemplateArithmetic)?;
            }
            metrics.weight = metrics
                .weight
                .checked_add(entry.coinbase_weight)
                .ok_or(MiningError::TemplateArithmetic)?;
            metrics.updates = metrics.updates.saturating_add(1);
            selected_claims.push(entry);
            work.special_payload_materializations =
                work.special_payload_materializations.saturating_add(1);
        }

        let mut airdrops = request.mempool.airdrops().collect::<Vec<_>>();
        airdrops.sort_by(|left, right| {
            compare_fee_rates(right.fee, right.policy_size, left.fee, left.policy_size)
                .then_with(|| left.hash.cmp(&right.hash))
        });
        for entry in airdrops {
            if selected_airdrops.len() >= 10 {
                break;
            }
            if metrics
                .weight
                .checked_add(entry.coinbase_weight)
                .is_none_or(|weight| weight > request.policy.maximum_weight)
                || metrics.updates.saturating_add(1) > request.policy.maximum_updates
            {
                continue;
            }
            metrics.fees = metrics
                .fees
                .checked_add(entry.fee)
                .ok_or(MiningError::TemplateArithmetic)?;
            metrics.weight = metrics
                .weight
                .checked_add(entry.coinbase_weight)
                .ok_or(MiningError::TemplateArithmetic)?;
            metrics.updates = metrics.updates.saturating_add(1);
            selected_airdrops.push(entry);
            work.special_payload_materializations =
                work.special_payload_materializations.saturating_add(1);
        }

        let candidates = request.mempool.txids().collect::<Vec<_>>();
        let reverse_dependencies = reverse_dependencies(request.mempool, &candidates)?;
        let selected_txids = match selection {
            SelectionAlgorithm::DependencyFrontier => select_packages_with_frontier(
                &candidates,
                &reverse_dependencies,
                |txid, selected| {
                    request
                        .mempool
                        .package_for(txid, selected)
                        .map_err(|error| MiningError::Mempool(error.to_string()))
                },
                &request.policy,
                &mut metrics,
                &mut selected_names,
                work,
            )?,
            #[cfg(test)]
            SelectionAlgorithm::ReferenceFullScan => select_packages_reference(
                &candidates,
                |txid, selected| {
                    request
                        .mempool
                        .package_for(txid, selected)
                        .map_err(|error| MiningError::Mempool(error.to_string()))
                },
                &request.policy,
                &mut metrics,
                &mut selected_names,
                work,
            )?,
        };
        let selected_transactions = selected_txids
            .iter()
            .map(|txid| {
                request
                    .mempool
                    .transaction(txid)
                    .ok_or(MiningError::MempoolTransactionMissing(*txid))
                    .cloned()
            })
            .collect::<Result<Vec<_>, _>>()?;

        let reward = block_subsidy(next_height, network.params().halving_interval)
            .checked_add(metrics.fees)
            .ok_or(MiningError::TemplateArithmetic)?;
        let coinbase = create_coinbase(
            next_height,
            request.snapshot.generation,
            reward,
            request.payout_address,
            request.coinbase_flags,
            &selected_claims,
            &selected_airdrops,
        )?;
        let mut transactions = Vec::with_capacity(selected_transactions.len().saturating_add(1));
        transactions.push(coinbase);
        transactions.extend(selected_transactions);
        let mut block = Block {
            header: Header {
                time: request.minimum_time,
                prev_block: request.snapshot.tip.hash,
                tree_root: request.snapshot.next_tree_root,
                reserved_root: request.reserved_root,
                version: request.version,
                bits: request.bits,
                ..Header::default()
            },
            transactions,
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        let body = validate_block_body(&block).map_err(|_| MiningError::InvalidTemplateBody)?;
        if body.weight > request.policy.maximum_weight {
            return Err(MiningError::InvalidTemplateBody);
        }
        metrics.transaction_count = block.transactions.len();
        metrics.claim_count = selected_claims.len();
        metrics.airdrop_count = selected_airdrops.len();
        metrics.weight = body.weight;
        let header = MiningHeaderTemplate {
            parent_hash: block.header.prev_block,
            tree_root: block.header.tree_root,
            reserved_root: block.header.reserved_root,
            witness_root: block.header.witness_root,
            merkle_root: block.header.merkle_root,
            version: block.header.version,
            bits: block.header.bits,
            minimum_time: block.header.time,
            mask_hash: request.mask_hash,
        };
        let transactions = Arc::<[Transaction]>::from(block.transactions);
        let template_id = template_id(
            request.snapshot.network_id,
            request.snapshot.generation,
            request.mempool.generation(),
            &header,
            &transactions,
        );
        Ok(MiningTemplate {
            template_id,
            snapshot_generation: request.snapshot.generation,
            mempool_generation: request.mempool.generation(),
            header,
            transactions,
            metrics,
        })
    }

    #[cfg(test)]
    fn assemble_reference(
        &self,
        request: TemplateBuildRequest<'_>,
        work: &mut TemplateSelectionWork,
    ) -> Result<MiningTemplate, MiningError> {
        self.assemble_with_selection(request, SelectionAlgorithm::ReferenceFullScan, work)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionAlgorithm {
    DependencyFrontier,
    #[cfg(test)]
    ReferenceFullScan,
}

/// Exact operation counts for deterministic complexity regressions. This is
/// deliberately local to one build and has no synchronization or global hook.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct TemplateSelectionWork {
    initial_package_builds: usize,
    affected_package_rebuilds: usize,
    dependency_edges: usize,
    affected_candidates: usize,
    affected_dependency_edges: usize,
    heap_pushes: usize,
    heap_pops: usize,
    stale_heap_pops: usize,
    heap_compactions: usize,
    #[cfg(test)]
    full_scan_candidates: usize,
    special_payload_materializations: usize,
}

#[derive(Clone, Debug)]
struct PackageFrontierEntry {
    candidate: hns_primitives::Txid,
    version: u64,
    package: MempoolPackage,
}

#[derive(Clone, Debug)]
struct TemplateSelectionWorkspace {
    base_bytes: u64,
    retained_package_bytes: u64,
    charged_heap_capacity: usize,
}

impl TemplateSelectionWorkspace {
    fn new(
        candidate_count: usize,
        reverse_dependencies: &BTreeMap<hns_primitives::Txid, Vec<hns_primitives::Txid>>,
        heap_capacity: usize,
    ) -> Result<Self, MiningError> {
        let candidates =
            u64::try_from(candidate_count).map_err(|_| MiningError::TemplateCapacity)?;
        let candidate_bytes = candidates
            .checked_mul(TEMPLATE_SELECTION_CANDIDATE_BASE_BYTES)
            .ok_or(MiningError::TemplateCapacity)?;
        let heap_bytes = u64::try_from(heap_capacity)
            .map_err(|_| MiningError::TemplateCapacity)?
            .checked_mul(TEMPLATE_SELECTION_HEAP_ENTRY_BYTES)
            .ok_or(MiningError::TemplateCapacity)?;
        let mut dependency_capacity = 0u64;
        for children in reverse_dependencies.values() {
            dependency_capacity = dependency_capacity
                .checked_add(
                    u64::try_from(children.capacity())
                        .map_err(|_| MiningError::TemplateCapacity)?,
                )
                .ok_or(MiningError::TemplateCapacity)?;
        }
        let dependency_bytes = dependency_capacity
            .checked_mul(TEMPLATE_SELECTION_VECTOR_ELEMENT_BYTES)
            .ok_or(MiningError::TemplateCapacity)?;
        let base_bytes = candidate_bytes
            .checked_add(heap_bytes)
            .ok_or(MiningError::TemplateCapacity)?
            .checked_add(dependency_bytes)
            .ok_or(MiningError::TemplateCapacity)?;
        let workspace = Self {
            base_bytes,
            retained_package_bytes: 0,
            charged_heap_capacity: heap_capacity,
        };
        workspace.ensure_transient_capacity()?;
        Ok(workspace)
    }

    fn package_bytes(package: &MempoolPackage) -> Result<u64, MiningError> {
        let vector_capacity = package
            .txids
            .capacity()
            .checked_add(package.exclusive_names.capacity())
            .ok_or(MiningError::TemplateCapacity)?;
        u64::try_from(vector_capacity)
            .map_err(|_| MiningError::TemplateCapacity)?
            .checked_mul(TEMPLATE_SELECTION_VECTOR_ELEMENT_BYTES)
            .ok_or(MiningError::TemplateCapacity)
    }

    fn ensure_transient_capacity(&self) -> Result<(), MiningError> {
        let projected = self
            .base_bytes
            .checked_add(self.retained_package_bytes)
            .and_then(|bytes| bytes.checked_add(TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES))
            .ok_or(MiningError::TemplateCapacity)?;
        if projected > MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES {
            return Err(MiningError::TemplateCapacity);
        }
        Ok(())
    }

    fn can_retain(&self, package: &MempoolPackage) -> Result<bool, MiningError> {
        let package_bytes = Self::package_bytes(package)?;
        if package_bytes > TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES {
            return Ok(false);
        }
        let projected = self
            .base_bytes
            .checked_add(self.retained_package_bytes)
            .and_then(|bytes| bytes.checked_add(package_bytes))
            .and_then(|bytes| bytes.checked_add(TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES))
            .ok_or(MiningError::TemplateCapacity)?;
        Ok(projected <= MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES)
    }

    fn retain(&mut self, package: &MempoolPackage) -> Result<(), MiningError> {
        if !self.can_retain(package)? {
            return Err(MiningError::TemplateCapacity);
        }
        self.retained_package_bytes = self
            .retained_package_bytes
            .checked_add(Self::package_bytes(package)?)
            .ok_or(MiningError::TemplateCapacity)?;
        Ok(())
    }

    fn release(&mut self, package: &MempoolPackage) -> Result<(), MiningError> {
        self.retained_package_bytes = self
            .retained_package_bytes
            .checked_sub(Self::package_bytes(package)?)
            .ok_or(MiningError::TemplateArithmetic)?;
        Ok(())
    }

    fn reset_retained(
        &mut self,
        frontier: &BinaryHeap<PackageFrontierEntry>,
    ) -> Result<(), MiningError> {
        self.validate_heap_capacity(frontier)?;
        self.retained_package_bytes = frontier.iter().try_fold(0u64, |total, entry| {
            total
                .checked_add(Self::package_bytes(&entry.package)?)
                .ok_or(MiningError::TemplateCapacity)
        })?;
        self.ensure_transient_capacity()
    }

    fn validate_heap_capacity(
        &self,
        frontier: &BinaryHeap<PackageFrontierEntry>,
    ) -> Result<(), MiningError> {
        if frontier.capacity() != self.charged_heap_capacity {
            return Err(MiningError::TemplateCapacity);
        }
        Ok(())
    }

    #[cfg(test)]
    fn with_base_bytes(base_bytes: u64, charged_heap_capacity: usize) -> Self {
        Self {
            base_bytes,
            retained_package_bytes: 0,
            charged_heap_capacity,
        }
    }

    #[cfg(test)]
    fn total_with_transient(&self) -> Result<u64, MiningError> {
        self.base_bytes
            .checked_add(self.retained_package_bytes)
            .and_then(|bytes| bytes.checked_add(TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES))
            .ok_or(MiningError::TemplateCapacity)
    }
}

impl PartialEq for PackageFrontierEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PackageFrontierEntry {}

impl PartialOrd for PackageFrontierEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageFrontierEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_packages(&self.package, &other.package)
            // The reference scan retains the first candidate on an exact
            // package tie. Candidate iteration is ascending txid order, so a
            // smaller candidate must be the greater heap entry.
            .then_with(|| other.candidate.cmp(&self.candidate))
            .then_with(|| self.version.cmp(&other.version))
    }
}

fn reverse_dependencies(
    mempool: &MempoolSnapshot,
    candidates: &[hns_primitives::Txid],
) -> Result<BTreeMap<hns_primitives::Txid, Vec<hns_primitives::Txid>>, MiningError> {
    let dependency_edges = candidates.iter().try_fold(0u64, |total, candidate| {
        let mut parents = 0u64;
        for parent in mempool.parents(candidate) {
            if candidates.binary_search(&parent).is_err() {
                return Err(MiningError::MempoolTransactionMissing(parent));
            }
            parents = parents
                .checked_add(1)
                .ok_or(MiningError::TemplateCapacity)?;
        }
        total
            .checked_add(parents)
            .ok_or(MiningError::TemplateCapacity)
    })?;
    let candidate_bytes = u64::try_from(candidates.len())
        .map_err(|_| MiningError::TemplateCapacity)?
        .checked_mul(TEMPLATE_SELECTION_CANDIDATE_CHARGE_BYTES)
        .ok_or(MiningError::TemplateCapacity)?;
    let dependency_bytes = dependency_edges
        .checked_mul(TEMPLATE_SELECTION_EDGE_OR_MEMBER_CHARGE_BYTES)
        .ok_or(MiningError::TemplateCapacity)?;
    let preflight = candidate_bytes
        .checked_add(dependency_bytes)
        .and_then(|bytes| bytes.checked_add(TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES))
        .ok_or(MiningError::TemplateCapacity)?;
    if preflight > MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES {
        return Err(MiningError::TemplateCapacity);
    }

    let mut reverse = candidates
        .iter()
        .copied()
        .map(|txid| (txid, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for candidate in candidates {
        for parent in mempool.parents(candidate) {
            reverse.entry(parent).or_default().push(*candidate);
        }
    }
    Ok(reverse)
}

fn package_is_eligible(
    package: &MempoolPackage,
    metrics: &TemplateMetrics,
    selected_count: usize,
    selected_names: &HashSet<[u8; 32]>,
    policy: &TemplatePolicy,
) -> bool {
    !package.is_empty()
        && package_meets_fee_rate(package, policy.minimum_package_fee_rate)
        && package_fits(package, metrics, selected_count, selected_names, policy)
}

fn commit_package(
    package: &MempoolPackage,
    selected: &mut HashSet<hns_primitives::Txid>,
    selected_txids: &mut Vec<hns_primitives::Txid>,
    selected_names: &mut HashSet<[u8; 32]>,
    metrics: &mut TemplateMetrics,
) -> Result<Vec<hns_primitives::Txid>, MiningError> {
    let mut newly_selected = Vec::with_capacity(package.txids.len());
    for txid in &package.txids {
        if selected.insert(*txid) {
            selected_txids.push(*txid);
            newly_selected.push(*txid);
        }
    }
    selected_names.extend(package.exclusive_names.iter().copied());
    metrics.selected_packages = metrics.selected_packages.saturating_add(1);
    metrics.fees = metrics
        .fees
        .checked_add(package.fee)
        .ok_or(MiningError::TemplateArithmetic)?;
    metrics.weight = metrics
        .weight
        .checked_add(package.weight)
        .ok_or(MiningError::TemplateArithmetic)?;
    metrics.sigops = metrics.sigops.saturating_add(package.sigops);
    metrics.opens = metrics.opens.saturating_add(package.opens);
    metrics.updates = metrics.updates.saturating_add(package.updates);
    metrics.renewals = metrics.renewals.saturating_add(package.renewals);
    Ok(newly_selected)
}

fn collect_affected_candidates(
    newly_selected: &[hns_primitives::Txid],
    reverse_dependencies: &BTreeMap<hns_primitives::Txid, Vec<hns_primitives::Txid>>,
) -> Result<(BTreeSet<hns_primitives::Txid>, usize), MiningError> {
    let mut affected = BTreeSet::new();
    let mut pending = Vec::with_capacity(newly_selected.len());
    for txid in newly_selected {
        if affected.insert(*txid) {
            pending.push(*txid);
        }
    }
    let mut dependency_edge_visits = 0usize;
    while let Some(parent) = pending.pop() {
        if let Some(children) = reverse_dependencies.get(&parent) {
            for child in children {
                dependency_edge_visits = dependency_edge_visits
                    .checked_add(1)
                    .ok_or(MiningError::TemplateArithmetic)?;
                if affected.insert(*child) {
                    pending.push(*child);
                }
            }
        }
    }
    Ok((affected, dependency_edge_visits))
}

fn compact_frontier(
    frontier: &mut BinaryHeap<PackageFrontierEntry>,
    versions: &BTreeMap<hns_primitives::Txid, u64>,
    selected: &HashSet<hns_primitives::Txid>,
    workspace: &mut TemplateSelectionWorkspace,
) -> Result<(), MiningError> {
    frontier.retain(|entry| {
        !selected.contains(&entry.candidate)
            && versions.get(&entry.candidate) == Some(&entry.version)
    });
    workspace.reset_retained(frontier)
}

fn push_frontier_bounded(
    frontier: &mut BinaryHeap<PackageFrontierEntry>,
    versions: &BTreeMap<hns_primitives::Txid, u64>,
    selected: &HashSet<hns_primitives::Txid>,
    workspace: &mut TemplateSelectionWorkspace,
    entry: PackageFrontierEntry,
    work: &mut TemplateSelectionWork,
) -> Result<(), MiningError> {
    workspace.validate_heap_capacity(frontier)?;
    if frontier.len() >= versions.len() || !workspace.can_retain(&entry.package)? {
        compact_frontier(frontier, versions, selected, workspace)?;
        work.heap_compactions = work.heap_compactions.saturating_add(1);
    }
    if frontier.len() >= versions.len() {
        return Err(MiningError::TemplateCapacity);
    }
    workspace.retain(&entry.package)?;
    frontier.push(entry);
    workspace.validate_heap_capacity(frontier)?;
    work.heap_pushes = work.heap_pushes.saturating_add(1);
    Ok(())
}

/// Dependency-aware exact selector. `MempoolSnapshot::package_for` uses
/// separate recursion-stack and emitted sets, so each construction is linear
/// in its bounded ancestor closure and dependency edges. Initial construction
/// covers N candidates; direct reverse storage is O(N + E); and a candidate is
/// recomputed only when one of its bounded ancestors was selected. Versioned
/// lazy heap entries avoid full rescans, while checked workspace accounting and
/// periodic stale compaction hard-bound retained package vectors.
#[allow(clippy::too_many_arguments)]
fn select_packages_with_frontier<F>(
    candidates: &[hns_primitives::Txid],
    reverse_dependencies: &BTreeMap<hns_primitives::Txid, Vec<hns_primitives::Txid>>,
    mut package_for: F,
    policy: &TemplatePolicy,
    metrics: &mut TemplateMetrics,
    selected_names: &mut HashSet<[u8; 32]>,
    work: &mut TemplateSelectionWork,
) -> Result<Vec<hns_primitives::Txid>, MiningError>
where
    F: FnMut(
        hns_primitives::Txid,
        &HashSet<hns_primitives::Txid>,
    ) -> Result<MempoolPackage, MiningError>,
{
    let mut selected = HashSet::with_capacity(candidates.len());
    let mut selected_txids = Vec::with_capacity(candidates.len());
    let mut versions = candidates
        .iter()
        .copied()
        .map(|txid| (txid, 0u64))
        .collect::<BTreeMap<_, _>>();
    let mut frontier = BinaryHeap::with_capacity(candidates.len());
    let mut workspace = TemplateSelectionWorkspace::new(
        candidates.len(),
        reverse_dependencies,
        frontier.capacity(),
    )?;
    work.dependency_edges = reverse_dependencies
        .values()
        .try_fold(0usize, |total, children| total.checked_add(children.len()))
        .ok_or(MiningError::TemplateArithmetic)?;

    for candidate in candidates {
        workspace.ensure_transient_capacity()?;
        let package = package_for(*candidate, &selected)?;
        work.initial_package_builds = work.initial_package_builds.saturating_add(1);
        if package_is_eligible(
            &package,
            metrics,
            selected_txids.len(),
            selected_names,
            policy,
        ) {
            push_frontier_bounded(
                &mut frontier,
                &versions,
                &selected,
                &mut workspace,
                PackageFrontierEntry {
                    candidate: *candidate,
                    version: 0,
                    package,
                },
                work,
            )?;
        }
    }

    while let Some(entry) = frontier.pop() {
        workspace.release(&entry.package)?;
        work.heap_pops = work.heap_pops.saturating_add(1);
        if selected.contains(&entry.candidate)
            || versions.get(&entry.candidate) != Some(&entry.version)
        {
            work.stale_heap_pops = work.stale_heap_pops.saturating_add(1);
            continue;
        }
        if !package_is_eligible(
            &entry.package,
            metrics,
            selected_txids.len(),
            selected_names,
            policy,
        ) {
            // An ancestor-bearing package can become eligible after that
            // ancestor is selected elsewhere and the package shrinks. It is
            // deliberately deferred, not permanently rejected; the reverse
            // dependency walk below will recompute and reinsert it.
            continue;
        }

        let selected_package = entry.package;
        let newly_selected = commit_package(
            &selected_package,
            &mut selected,
            &mut selected_txids,
            selected_names,
            metrics,
        )?;
        drop(selected_package);
        let (affected, affected_dependency_edges) =
            collect_affected_candidates(&newly_selected, reverse_dependencies)?;
        if affected.len() > candidates.len() || affected_dependency_edges > work.dependency_edges {
            return Err(MiningError::TemplateArithmetic);
        }
        work.affected_candidates = work.affected_candidates.saturating_add(affected.len());
        work.affected_dependency_edges = work
            .affected_dependency_edges
            .saturating_add(affected_dependency_edges);
        for candidate in &affected {
            let version = versions
                .get_mut(candidate)
                .ok_or(MiningError::MempoolTransactionMissing(*candidate))?;
            *version = version
                .checked_add(1)
                .ok_or(MiningError::TemplateArithmetic)?;
        }

        // Stale packages retain ancestor vectors. Compact in place before the
        // pending replacements could exhaust the one-entry-per-candidate heap
        // allocation; the backing `Vec` capacity never grows after preflight.
        if frontier.len().saturating_add(affected.len()) > candidates.len() {
            compact_frontier(&mut frontier, &versions, &selected, &mut workspace)?;
            work.heap_compactions = work.heap_compactions.saturating_add(1);
        }

        for candidate in affected {
            if selected.contains(&candidate) {
                continue;
            }
            workspace.ensure_transient_capacity()?;
            let package = package_for(candidate, &selected)?;
            work.affected_package_rebuilds = work.affected_package_rebuilds.saturating_add(1);
            if package_is_eligible(
                &package,
                metrics,
                selected_txids.len(),
                selected_names,
                policy,
            ) {
                let version = *versions
                    .get(&candidate)
                    .ok_or(MiningError::MempoolTransactionMissing(candidate))?;
                push_frontier_bounded(
                    &mut frontier,
                    &versions,
                    &selected,
                    &mut workspace,
                    PackageFrontierEntry {
                        candidate,
                        version,
                        package,
                    },
                    work,
                )?;
            }
        }
    }

    Ok(selected_txids)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn select_packages_reference<F>(
    candidates: &[hns_primitives::Txid],
    mut package_for: F,
    policy: &TemplatePolicy,
    metrics: &mut TemplateMetrics,
    selected_names: &mut HashSet<[u8; 32]>,
    work: &mut TemplateSelectionWork,
) -> Result<Vec<hns_primitives::Txid>, MiningError>
where
    F: FnMut(
        hns_primitives::Txid,
        &HashSet<hns_primitives::Txid>,
    ) -> Result<MempoolPackage, MiningError>,
{
    let mut selected = HashSet::with_capacity(candidates.len());
    let mut selected_txids = Vec::with_capacity(candidates.len());
    loop {
        let mut best: Option<MempoolPackage> = None;
        for candidate in candidates {
            if selected.contains(candidate) {
                continue;
            }
            work.full_scan_candidates = work.full_scan_candidates.saturating_add(1);
            let package = package_for(*candidate, &selected)?;
            if !package_is_eligible(
                &package,
                metrics,
                selected_txids.len(),
                selected_names,
                policy,
            ) {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| compare_packages(&package, current) == Ordering::Greater)
            {
                best = Some(package);
            }
        }
        let Some(package) = best else {
            break;
        };
        commit_package(
            &package,
            &mut selected,
            &mut selected_txids,
            selected_names,
            metrics,
        )?;
    }
    Ok(selected_txids)
}

fn create_coinbase(
    height: u32,
    generation: u64,
    reward: u64,
    payout_address: Address,
    coinbase_flags: Vec<u8>,
    claims: &[&ClaimMempoolEntry],
    airdrops: &[&AirdropMempoolEntry],
) -> Result<Transaction, MiningError> {
    if coinbase_flags.len() > hns_consensus::MAX_COINBASE_WITNESS_SIZE {
        return Err(MiningError::InvalidTemplateContext);
    }
    let sequence = u32::try_from(generation & u64::from(u32::MAX))
        .map_err(|_| MiningError::TemplateArithmetic)?;
    let mut coinbase = Transaction {
        version: 0,
        inputs: vec![Input {
            previous_output: Outpoint::null(),
            sequence,
            witness: Witness {
                items: vec![coinbase_flags, vec![0; 8], vec![0; 8]],
            },
        }],
        outputs: vec![Output {
            value: reward,
            address: payout_address,
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }],
        locktime: height,
    };
    for entry in claims {
        coinbase.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![entry.claim.blob.clone()],
            },
        });
        coinbase.outputs.push(Output {
            value: entry
                .value
                .checked_sub(entry.fee)
                .ok_or(MiningError::TemplateArithmetic)?,
            address: entry.address.clone(),
            covenant: Covenant {
                kind: CovenantKind::Claim,
                items: vec![
                    entry.name_hash.to_vec(),
                    height.to_le_bytes().to_vec(),
                    entry.name.clone(),
                    vec![u8::from(entry.weak)],
                    entry.commit_hash.to_vec(),
                    entry.commit_height.to_le_bytes().to_vec(),
                ],
            },
        });
    }
    for entry in airdrops {
        let raw = entry
            .proof
            .encode()
            .map_err(|_| MiningError::InvalidTemplateBody)?;
        let address = Address::new(entry.proof.version, entry.proof.address.clone())
            .map_err(|_| MiningError::InvalidTemplateBody)?;
        coinbase.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness { items: vec![raw] },
        });
        coinbase.outputs.push(Output {
            value: entry
                .value
                .checked_sub(entry.fee)
                .ok_or(MiningError::TemplateArithmetic)?,
            address,
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        });
    }
    Ok(coinbase)
}

fn compare_fee_rates(
    left_fee: u64,
    left_size: usize,
    right_fee: u64,
    right_size: usize,
) -> Ordering {
    let left = u128::from(left_fee).saturating_mul(right_size.max(1) as u128);
    let right = u128::from(right_fee).saturating_mul(left_size.max(1) as u128);
    left.cmp(&right)
}

fn package_meets_fee_rate(package: &MempoolPackage, minimum_rate: u64) -> bool {
    package.fee >= minimum_policy_fee(package.policy_size, minimum_rate)
}

fn package_fits(
    package: &MempoolPackage,
    current: &TemplateMetrics,
    selected_count: usize,
    selected_names: &HashSet<[u8; 32]>,
    policy: &TemplatePolicy,
) -> bool {
    selected_count
        .checked_add(package.txids.len())
        .is_some_and(|count| count.saturating_add(1) <= policy.maximum_transactions)
        && current
            .weight
            .checked_add(package.weight)
            .is_some_and(|weight| weight <= policy.maximum_weight)
        && current.sigops.saturating_add(package.sigops) <= policy.maximum_sigops
        && current.opens.saturating_add(package.opens) <= policy.maximum_opens
        && current.updates.saturating_add(package.updates) <= policy.maximum_updates
        && current.renewals.saturating_add(package.renewals) <= policy.maximum_renewals
        && package
            .exclusive_names
            .iter()
            .all(|name| !selected_names.contains(name))
}

fn compare_packages(left: &MempoolPackage, right: &MempoolPackage) -> Ordering {
    let left_rate = u128::from(left.fee).saturating_mul(right.policy_size.max(1) as u128);
    let right_rate = u128::from(right.fee).saturating_mul(left.policy_size.max(1) as u128);
    left_rate
        .cmp(&right_rate)
        .then_with(|| right.oldest_sequence.cmp(&left.oldest_sequence))
        .then_with(|| right.txids.cmp(&left.txids))
}

fn template_id(
    network_id: u8,
    generation: u64,
    mempool_generation: u64,
    header: &MiningHeaderTemplate,
    transactions: &[Transaction],
) -> TemplateId {
    let mut body = Vec::new();
    let transaction_count = u64::try_from(transactions.len())
        .expect("transaction count fits in the canonical u64 encoding")
        .to_le_bytes();
    body.extend_from_slice(&transaction_count);
    for transaction in transactions {
        let encoded = transaction.encode();
        let encoded_len = u64::try_from(encoded.len())
            .expect("transaction length fits in the canonical u64 encoding")
            .to_le_bytes();
        body.extend_from_slice(&encoded_len);
        body.extend_from_slice(&encoded);
    }
    let network = [network_id];
    let generation = generation.to_le_bytes();
    let mempool_generation = mempool_generation.to_le_bytes();
    let version = header.version.to_le_bytes();
    let bits = header.bits.to_le_bytes();
    let minimum_time = header.minimum_time.to_le_bytes();
    blake2b_256_many([
        b"hsrd/mining-template/v1".as_slice(),
        network.as_slice(),
        generation.as_slice(),
        mempool_generation.as_slice(),
        header.parent_hash.as_bytes().as_slice(),
        header.tree_root.as_slice(),
        header.reserved_root.as_slice(),
        version.as_slice(),
        bits.as_slice(),
        minimum_time.as_slice(),
        header.mask_hash.as_slice(),
        body.as_slice(),
    ])
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TemplateCacheKey {
    pub snapshot_generation: u64,
    pub mempool_generation: u64,
    pub variant: u32,
}

#[derive(Clone, Debug, Default)]
pub struct FutureTemplateCache {
    templates: std::collections::BTreeMap<TemplateCacheKey, Arc<MiningTemplate>>,
}

impl FutureTemplateCache {
    pub fn insert(
        &mut self,
        key: TemplateCacheKey,
        template: MiningTemplate,
    ) -> Result<Arc<MiningTemplate>, MiningError> {
        if key.snapshot_generation != template.snapshot_generation()
            || key.mempool_generation != template.mempool_generation()
        {
            return Err(MiningError::InvalidTemplateContext);
        }
        if let Some(existing) = self.templates.get(&key) {
            if existing.as_ref() == &template {
                return Ok(Arc::clone(existing));
            }
            return Err(MiningError::TemplateConflict);
        }
        if self.templates.len() >= MAX_TEMPLATE_VARIANTS {
            return Err(MiningError::TemplateCapacity);
        }
        let template = Arc::new(template);
        self.templates.insert(key, Arc::clone(&template));
        Ok(template)
    }

    pub fn activate(
        &mut self,
        key: &TemplateCacheKey,
        snapshot: &MiningSnapshot,
    ) -> Result<Arc<MiningTemplate>, MiningError> {
        let template = self
            .templates
            .get(key)
            .cloned()
            .ok_or(MiningError::UnknownTemplate)?;
        if template.snapshot_generation() != snapshot.generation
            || template.header().parent_hash != snapshot.tip.hash
            || template.header().tree_root != snapshot.next_tree_root
        {
            return Err(MiningError::StaleTemplate);
        }
        self.templates
            .retain(|candidate, _| candidate.snapshot_generation == snapshot.generation);
        Ok(template)
    }

    pub fn get(&self, key: &TemplateCacheKey) -> Option<Arc<MiningTemplate>> {
        self.templates.get(key).cloned()
    }

    pub fn retain_generation(&mut self, snapshot_generation: u64) {
        self.templates
            .retain(|key, _| key.snapshot_generation == snapshot_generation);
    }

    pub fn clear(&mut self) {
        self.templates.clear();
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateVariant {
    pub variant: u32,
    pub payout_address: Address,
    pub coinbase_flags: Vec<u8>,
    pub version: u32,
    pub bits: u32,
    pub minimum_time: u64,
    pub reserved_root: [u8; 32],
    pub mask_hash: [u8; 32],
    pub policy: TemplatePolicy,
}

/// Atomically prepares a bounded set of future template variants for one chain
/// and mempool generation. A failed rebuild leaves the previous cache intact.
#[derive(Clone, Debug)]
pub struct TemplateCoordinator {
    assembler: TemplateAssembler,
    cache: FutureTemplateCache,
    maximum_variants: usize,
}

impl TemplateCoordinator {
    pub fn new(maximum_variants: usize) -> Result<Self, MiningError> {
        if maximum_variants == 0 || maximum_variants > MAX_TEMPLATE_VARIANTS {
            return Err(MiningError::TemplateCapacity);
        }
        Ok(Self {
            assembler: TemplateAssembler,
            cache: FutureTemplateCache::default(),
            maximum_variants,
        })
    }

    pub fn rebuild(
        &mut self,
        snapshot: &MiningSnapshot,
        mempool: &MempoolSnapshot,
        variants: impl IntoIterator<Item = TemplateVariant>,
    ) -> Result<Vec<Arc<MiningTemplate>>, MiningError> {
        let variants = variants.into_iter().collect::<Vec<_>>();
        if variants.is_empty() || variants.len() > self.maximum_variants {
            return Err(MiningError::TemplateCapacity);
        }
        let mut seen = HashSet::new();
        let mut replacement = FutureTemplateCache::default();
        let mut built = Vec::with_capacity(variants.len());
        for variant in variants {
            if !seen.insert(variant.variant) {
                return Err(MiningError::TemplateConflict);
            }
            let template = self.assembler.assemble(TemplateBuildRequest {
                snapshot,
                mempool,
                payout_address: variant.payout_address,
                coinbase_flags: variant.coinbase_flags,
                version: variant.version,
                bits: variant.bits,
                minimum_time: variant.minimum_time,
                reserved_root: variant.reserved_root,
                mask_hash: variant.mask_hash,
                policy: variant.policy,
            })?;
            let key = TemplateCacheKey {
                snapshot_generation: snapshot.generation,
                mempool_generation: mempool.generation(),
                variant: variant.variant,
            };
            built.push(replacement.insert(key, template)?);
        }
        self.cache = replacement;
        Ok(built)
    }

    /// Atomically installs templates assembled outside the canonical writer.
    ///
    /// Variant identity is supplied explicitly and the complete replacement
    /// is authenticated off to the side. Any duplicate, stale generation,
    /// context mismatch, malformed body, or identity mismatch leaves the
    /// currently active cache byte-for-byte intact.
    pub fn install_prebuilt<I>(
        &mut self,
        snapshot: &MiningSnapshot,
        expected_mempool_generation: u64,
        templates: I,
    ) -> Result<Vec<Arc<MiningTemplate>>, MiningError>
    where
        I: IntoIterator<Item = (u32, MiningTemplate)>,
    {
        let mut templates = templates.into_iter().collect::<Vec<_>>();
        if templates.is_empty() || templates.len() > self.maximum_variants {
            return Err(MiningError::TemplateCapacity);
        }
        templates.sort_by_key(|(variant, _)| *variant);
        if templates.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(MiningError::TemplateConflict);
        }

        let mut replacement = FutureTemplateCache::default();
        let mut installed = Vec::with_capacity(templates.len());
        for (variant, template) in templates {
            validate_prebuilt_template(snapshot, expected_mempool_generation, &template)?;
            let key = TemplateCacheKey {
                snapshot_generation: snapshot.generation,
                mempool_generation: expected_mempool_generation,
                variant,
            };
            installed.push(replacement.insert(key, template)?);
        }
        self.cache = replacement;
        Ok(installed)
    }

    pub fn activate(
        &mut self,
        key: &TemplateCacheKey,
        snapshot: &MiningSnapshot,
    ) -> Result<Arc<MiningTemplate>, MiningError> {
        self.cache.activate(key, snapshot)
    }

    pub fn get(&self, key: &TemplateCacheKey) -> Option<Arc<MiningTemplate>> {
        self.cache.get(key)
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

fn validate_prebuilt_template(
    snapshot: &MiningSnapshot,
    expected_mempool_generation: u64,
    template: &MiningTemplate,
) -> Result<(), MiningError> {
    if template.snapshot_generation != snapshot.generation
        || template.mempool_generation != expected_mempool_generation
        || template.header.parent_hash != snapshot.tip.hash
        || template.header.tree_root != snapshot.next_tree_root
    {
        return Err(MiningError::StaleTemplate);
    }

    let block = Block {
        header: Header {
            time: template.header.minimum_time,
            prev_block: template.header.parent_hash,
            tree_root: template.header.tree_root,
            reserved_root: template.header.reserved_root,
            witness_root: template.header.witness_root,
            merkle_root: template.header.merkle_root,
            version: template.header.version,
            bits: template.header.bits,
            ..Header::default()
        },
        transactions: template.transactions.to_vec(),
    };
    if block_merkle_root(&block) != template.header.merkle_root
        || block_witness_root(&block) != template.header.witness_root
    {
        return Err(MiningError::InvalidTemplateBody);
    }
    let body = validate_block_body(&block).map_err(|_| MiningError::InvalidTemplateBody)?;
    if template.metrics.transaction_count != template.transactions.len()
        || template.metrics.weight != body.weight
    {
        return Err(MiningError::InvalidTemplateBody);
    }
    if template.template_id
        != template_id(
            snapshot.network_id,
            snapshot.generation,
            expected_mempool_generation,
            &template.header,
            &template.transactions,
        )
    {
        return Err(MiningError::InvalidTemplateContext);
    }

    let prepared = template
        .prepare_job(snapshot)
        .map_err(|_| MiningError::InvalidTemplateBody)?;
    prepared
        .validate_for_snapshot(snapshot)
        .map_err(|_| MiningError::InvalidTemplateBody)
}

impl Default for TemplateCoordinator {
    fn default() -> Self {
        Self::new(MAX_TEMPLATE_VARIANTS).expect("default template capacity is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_consensus::{
        transaction_weight, ConsensusError, Network, OpenSslDnssecVerifier, SequenceLockView,
        TransactionInputVerifier, VerifiedClaim,
    };
    use hns_mempool::{
        sigop_adjusted_virtual_size, standard_output_dust_threshold, Admission, AirdropAdmission,
        AirdropMempoolContext, AirdropMempoolView, ClaimAdmission, ClaimContextValidation,
        ClaimMempoolContext, ClaimMempoolView, ContextualTransactionVerifier, MemoryMempool,
        Mempool, MempoolContext, MempoolView, BYTES_PER_SIGOP, HSD_ABSURD_FEE_FACTOR,
        HSD_FREE_DECAY_SECONDS, HSD_FREE_RELAY_MULTIPLIER, HSD_FREE_THRESHOLD,
        HSD_LIMIT_FREE_RELAY, HSD_MAX_P2WSH_PUSH, HSD_MAX_P2WSH_SIZE, HSD_MAX_P2WSH_STACK,
        HSD_MAX_STANDARD_TX_VERSION, HSD_MAX_STANDARD_TX_WEIGHT, HSD_MEMPOOL_EXPIRY_TIME,
        HSD_MEMPOOL_MAX_SIZE, HSD_MEMPOOL_TRIM_DENOMINATOR, HSD_MEMPOOL_TRIM_NUMERATOR,
        HSD_MINIMUM_RELAY_FEE_RATE, MAX_TX_SIGOPS,
    };
    use hns_primitives::{
        AirdropProof, Claim, Coin, Height, Txid, UnavailableAirdropSignatureVerifier,
    };
    use std::collections::HashMap;

    fn test_mempool() -> MemoryMempool {
        MemoryMempool::new().expect("test mempool initialization")
    }

    #[derive(Default)]
    struct View {
        coins: HashMap<Outpoint, Coin>,
    }

    impl SequenceLockView for View {
        fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
            Ok(self.coins.get(outpoint).map(|coin| coin.height))
        }

        fn median_time_past(&self, _height: Height) -> Result<u64, ConsensusError> {
            Ok(1)
        }
    }

    impl MempoolView for View {
        fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, ConsensusError> {
            Ok(self.coins.get(outpoint).cloned())
        }
    }

    impl AirdropMempoolView for View {
        fn airdrop_position_spent(&self, _position: u32) -> Result<bool, ConsensusError> {
            Ok(false)
        }
    }

    impl ClaimMempoolView for View {
        fn verify_claim_context(
            &self,
            _output: &Output,
            _claim: &VerifiedClaim,
            _context: &ClaimMempoolContext,
        ) -> Result<ClaimContextValidation, ConsensusError> {
            Ok(ClaimContextValidation::Valid)
        }
    }

    struct Allow;

    impl TransactionInputVerifier for Allow {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    impl ContextualTransactionVerifier for Allow {
        fn verify(
            &self,
            _transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            _accepted_name_transactions: &hns_mempool::AcceptedNameTransactions<'_>,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    fn address(byte: u8) -> Address {
        Address::new(0, vec![byte; 20]).expect("address")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            }
        }
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn transaction(previous: Outpoint, input_value: u64, output_value: u64) -> (Transaction, Coin) {
        let coin = Coin {
            outpoint: previous.clone(),
            value: input_value,
            height: 1,
            coinbase: false,
            address: address(2),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let transaction = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: previous,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: output_value,
                address: address(3),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        (transaction, coin)
    }

    fn indexed_txid(index: u64) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        bytes[31] = 1;
        Txid::new(bytes)
    }

    fn output(value: u64, marker: u8) -> Output {
        Output {
            value,
            address: address(marker),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }
    }

    fn admit_graph_transaction(
        pool: &mut MemoryMempool,
        view: &View,
        inputs: Vec<Outpoint>,
        outputs: Vec<u64>,
        marker: u32,
    ) -> Transaction {
        let transaction = Transaction {
            version: 1,
            inputs: inputs
                .into_iter()
                .map(|previous_output| Input {
                    previous_output,
                    sequence: u32::MAX,
                    witness: Witness::default(),
                })
                .collect(),
            outputs: outputs.into_iter().map(|value| output(value, 3)).collect(),
            locktime: marker % 10,
        };
        assert!(matches!(
            pool.submit_with_context(
                transaction.clone(),
                &MempoolContext::testing(11, 100),
                view,
                &Allow,
                &Allow,
            )
            .expect("admit graph transaction"),
            Admission::Accepted(_)
        ));
        transaction
    }

    fn admit_graph_root(
        pool: &mut MemoryMempool,
        view: &mut View,
        external_index: u64,
        outputs: Vec<u64>,
        fee: u64,
        marker: u32,
    ) -> Transaction {
        let previous = Outpoint {
            txid: indexed_txid(external_index),
            index: 0,
        };
        let value = outputs
            .iter()
            .try_fold(fee, |total, value| total.checked_add(*value))
            .expect("test root value");
        view.coins.insert(
            previous.clone(),
            Coin {
                outpoint: previous.clone(),
                value,
                height: 1,
                coinbase: false,
                address: address(2),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            },
        );
        admit_graph_transaction(pool, view, vec![previous], outputs, marker)
    }

    fn template_request<'a>(
        mining_snapshot: &'a MiningSnapshot,
        mempool: &'a MempoolSnapshot,
        policy: TemplatePolicy,
        marker: u8,
    ) -> TemplateBuildRequest<'a> {
        TemplateBuildRequest {
            snapshot: mining_snapshot,
            mempool,
            payout_address: address(9),
            coinbase_flags: vec![marker],
            version: 1,
            bits: 0x207f_ffff,
            minimum_time: 101,
            reserved_root: [marker; 32],
            mask_hash: [marker.max(1); 32],
            policy,
        }
    }

    fn assert_frontier_matches_reference(pool: &MemoryMempool, policy: TemplatePolicy, marker: u8) {
        let mining_snapshot = snapshot();
        let mempool = pool.snapshot();
        let request = template_request(&mining_snapshot, &mempool, policy, marker);
        let mut frontier_work = TemplateSelectionWork::default();
        let frontier = TemplateAssembler
            .assemble_with_selection(
                request.clone(),
                SelectionAlgorithm::DependencyFrontier,
                &mut frontier_work,
            )
            .expect("frontier template");
        let mut reference_work = TemplateSelectionWork::default();
        let reference = TemplateAssembler
            .assemble_reference(request, &mut reference_work)
            .expect("reference template");
        assert_eq!(frontier, reference);
        assert_eq!(frontier.template_id(), reference.template_id());
        assert_eq!(
            frontier
                .transactions()
                .iter()
                .map(Transaction::txid)
                .collect::<Vec<_>>(),
            reference
                .transactions()
                .iter()
                .map(Transaction::txid)
                .collect::<Vec<_>>()
        );
        assert_eq!(frontier_work.initial_package_builds, mempool.len());
        assert_eq!(frontier_work.full_scan_candidates, 0);
        assert!(reference_work.full_scan_candidates >= mempool.len());
    }

    fn empty_template(
        mining_snapshot: &MiningSnapshot,
        mempool: &MempoolSnapshot,
        marker: u8,
    ) -> MiningTemplate {
        TemplateAssembler
            .assemble(template_request(
                mining_snapshot,
                mempool,
                TemplatePolicy::default(),
                marker,
            ))
            .expect("empty-pool template")
    }

    fn assert_cache_preserved(
        coordinator: &TemplateCoordinator,
        key: &TemplateCacheKey,
        expected: &Arc<MiningTemplate>,
    ) {
        assert_eq!(coordinator.len(), 1);
        let actual = coordinator.get(key).expect("preserved cache entry");
        assert!(Arc::ptr_eq(&actual, expected));
    }

    fn snapshot() -> MiningSnapshot {
        MiningSnapshot {
            network_id: Network::Regtest.canonical_id(),
            generation: 7,
            tip: crate::HeaderSummary {
                hash: hns_primitives::BlockHash::new([1; 32]),
                parent_hash: hns_primitives::BlockHash::new([0; 32]),
                height: 10,
                tree_root: [2; 32],
                time: 100,
                bits: 0x207f_ffff,
            },
            parent_median_time: 100,
            next_tree_root: [3; 32],
            chainwork: 10u64.into(),
        }
    }

    #[test]
    fn template_time_uses_parent_median_time_instead_of_raw_tip_time() {
        let mut mining_snapshot = snapshot();
        mining_snapshot.tip.time = 200;
        mining_snapshot.parent_median_time = 100;
        let pool = test_mempool();
        let pool_snapshot = pool.snapshot();
        let request = TemplateBuildRequest {
            snapshot: &mining_snapshot,
            mempool: &pool_snapshot,
            payout_address: address(9),
            coinbase_flags: Vec::new(),
            version: 0,
            bits: Network::Regtest.params().pow.bits,
            minimum_time: 101,
            reserved_root: [0; 32],
            mask_hash: [8; 32],
            policy: TemplatePolicy::default(),
        };
        let template = TemplateAssembler
            .assemble(request.clone())
            .expect("time above parent median");
        assert_eq!(template.header().minimum_time, 101);
        assert!(template.header().minimum_time <= mining_snapshot.tip.time);

        let error = TemplateAssembler
            .assemble(TemplateBuildRequest {
                minimum_time: mining_snapshot.parent_median_time,
                ..request
            })
            .expect_err("time at parent median");
        assert!(matches!(error, MiningError::InvalidTemplateContext));
    }

    #[test]
    fn hsd_oracle_coinbase_and_subsidy_vectors_match() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/mining/template-v1.json"
        ))
        .expect("hsrd mining fixture");
        assert_eq!(fixture["schema"], 7);
        let deterministic = &fixture["deterministicCoinbase"];
        let coinbase = create_coinbase(
            u32::try_from(deterministic["height"].as_u64().expect("height"))
                .expect("height fits u32"),
            deterministic["generationAsSequence"]
                .as_u64()
                .expect("generation"),
            deterministic["reward"].as_u64().expect("reward"),
            address(9),
            b"hsrd".to_vec(),
            &[],
            &[],
        )
        .expect("coinbase");
        assert_eq!(
            hns_primitives::hex_encode(&coinbase.encode()),
            deterministic["raw"].as_str().expect("raw coinbase")
        );

        for case in fixture["subsidyCases"].as_array().expect("subsidy cases") {
            let height =
                u32::try_from(case["height"].as_u64().expect("height")).expect("height fits u32");
            let interval = u32::try_from(case["interval"].as_u64().expect("interval"))
                .expect("interval fits u32");
            assert_eq!(
                block_subsidy(height, interval),
                case["reward"].as_u64().expect("reward")
            );
        }

        let policy = &fixture["mempoolSigopPolicy"];
        assert_eq!(
            policy["maxTxSigops"].as_u64().expect("maximum sigops"),
            u64::from(MAX_TX_SIGOPS)
        );
        assert_eq!(
            policy["bytesPerSigop"].as_u64().expect("bytes per sigop"),
            BYTES_PER_SIGOP as u64
        );
        let policy_transaction = Transaction::decode(&decode_hex(
            policy["transactionRaw"]
                .as_str()
                .expect("policy transaction"),
        ))
        .expect("policy transaction decode");
        assert_eq!(
            transaction_weight(&policy_transaction) as u64,
            policy["transactionWeight"]
                .as_u64()
                .expect("policy transaction weight")
        );
        for case in policy["cases"].as_array().expect("sigop policy cases") {
            let sigops = u32::try_from(case["sigops"].as_u64().expect("case sigops"))
                .expect("case sigops fit u32");
            assert_eq!(
                sigop_adjusted_virtual_size(&policy_transaction, sigops) as u64,
                case["policySize"].as_u64().expect("policy size")
            );
            assert_eq!(
                sigops <= MAX_TX_SIGOPS,
                case["accepted"].as_bool().expect("policy acceptance")
            );
        }
        for case in policy["minimumFeeCases"]
            .as_array()
            .expect("minimum fee cases")
        {
            let policy_size =
                usize::try_from(case["policySize"].as_u64().expect("fee policy size"))
                    .expect("fee policy size fits usize");
            let rate = case["rate"].as_u64().expect("fee rate");
            assert_eq!(
                minimum_policy_fee(policy_size, rate),
                case["minimumFee"].as_u64().expect("minimum fee")
            );
        }
        let standard = &fixture["mempoolStandardPolicy"];
        assert_eq!(standard["maximumVersion"], HSD_MAX_STANDARD_TX_VERSION);
        assert_eq!(standard["maximumWeight"], HSD_MAX_STANDARD_TX_WEIGHT);
        assert_eq!(standard["maximumWitnessStack"], HSD_MAX_P2WSH_STACK);
        assert_eq!(standard["maximumWitnessPush"], HSD_MAX_P2WSH_PUSH);
        assert_eq!(standard["maximumWitnessScript"], HSD_MAX_P2WSH_SIZE);
        assert_eq!(standard["absurdFeeFactor"], HSD_ABSURD_FEE_FACTOR);
        let dust_output = Output {
            value: 1,
            address: address(2),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        assert_eq!(
            standard_output_dust_threshold(&dust_output, HSD_MINIMUM_RELAY_FEE_RATE),
            standard["dustThreshold"].as_u64().expect("dust threshold")
        );
        for network in standard["requireStandard"]
            .as_array()
            .expect("network standardness")
        {
            let expected = match network["network"].as_str().expect("network") {
                "main" => true,
                "testnet" | "regtest" | "simnet" => false,
                other => panic!("unexpected HSD network {other}"),
            };
            assert_eq!(
                network["required"].as_bool().expect("standardness flag"),
                expected
            );
        }
        let expected_cases = [
            ("baseline", true),
            ("version-one", false),
            ("unknown-address", false),
            ("dust", false),
            ("multiple-nulldata", false),
        ];
        for (case, (name, accepted)) in standard["cases"]
            .as_array()
            .expect("standardness cases")
            .iter()
            .zip(expected_cases)
        {
            assert_eq!(case["name"], name);
            assert_eq!(case["accepted"], accepted);
        }
        let dynamic = &fixture["mempoolDynamicPolicy"];
        assert_eq!(dynamic["maximumSize"], HSD_MEMPOOL_MAX_SIZE);
        assert_eq!(dynamic["expiryTime"], HSD_MEMPOOL_EXPIRY_TIME);
        assert_eq!(
            dynamic["trimTarget"]["numerator"],
            HSD_MEMPOOL_TRIM_NUMERATOR
        );
        assert_eq!(
            dynamic["trimTarget"]["denominator"],
            HSD_MEMPOOL_TRIM_DENOMINATOR
        );
        assert_eq!(dynamic["dependencyRootsOnly"], true);
        assert_eq!(dynamic["descendantPackageRate"], true);
        assert_eq!(dynamic["equalRateOldestFirst"], true);
        assert_eq!(dynamic["freeThreshold"], HSD_FREE_THRESHOLD);
        assert_eq!(dynamic["relayPriority"], true);
        assert_eq!(dynamic["limitFree"], true);
        assert_eq!(dynamic["limitFreeRelay"], HSD_LIMIT_FREE_RELAY);
        assert_eq!(dynamic["freeDecay"]["numerator"], 599);
        assert_eq!(dynamic["freeDecay"]["denominator"], 600);
        assert_eq!(dynamic["freeDecaySeconds"], HSD_FREE_DECAY_SECONDS);
        assert_eq!(dynamic["freeRelayMultiplier"], HSD_FREE_RELAY_MULTIPLIER);
        assert_eq!(dynamic["strictFreeThreshold"], true);
        assert_eq!(dynamic["strictRateLimitThreshold"], true);

        let special_claim = &fixture["specialClaimPolicy"];
        let claim_vector = &special_claim["claim"];
        let claim = Claim::decode(&decode_hex(
            claim_vector["raw"].as_str().expect("claim raw"),
        ))
        .expect("claim");
        assert_eq!(
            hns_primitives::hex_encode(&claim.blob),
            claim_vector["blob"].as_str().expect("claim blob")
        );
        let claim_height = u32::try_from(special_claim["height"].as_u64().expect("claim height"))
            .expect("claim height fits u32");
        let parent_time = special_claim["parentTime"]
            .as_u64()
            .expect("claim parent time");
        let mut claim_pool = test_mempool();
        assert!(matches!(
            claim_pool
                .submit_claim_with_context(
                    claim,
                    &ClaimMempoolContext {
                        next_height: claim_height,
                        transaction_start: 0,
                        current_time: parent_time,
                        parent_time,
                        network: Network::Mainnet,
                        hardening: false,
                    },
                    &View::default(),
                    &OpenSslDnssecVerifier,
                )
                .expect("claim admission"),
            ClaimAdmission::Accepted(_)
        ));
        let claim_entry = claim_pool
            .claim_entries()
            .into_iter()
            .next()
            .expect("claim entry");
        assert_eq!(
            hns_primitives::hex_encode(&claim_entry.hash),
            claim_vector["hash"].as_str().expect("claim hash")
        );
        assert_eq!(
            std::str::from_utf8(&claim_entry.name).expect("claim name"),
            claim_vector["name"].as_str().expect("fixture claim name")
        );
        assert_eq!(
            hns_primitives::hex_encode(&claim_entry.name_hash),
            claim_vector["nameHash"].as_str().expect("claim name hash")
        );
        assert_eq!(claim_entry.value, claim_vector["value"]);
        assert_eq!(claim_entry.fee, claim_vector["fee"]);
        assert_eq!(claim_entry.weak, claim_vector["weak"]);
        assert_eq!(
            hns_primitives::hex_encode(&claim_entry.commit_hash),
            claim_vector["commitHash"].as_str().expect("commit hash")
        );
        assert_eq!(
            claim_entry.commit_height as u64,
            claim_vector["commitHeight"]
        );
        assert_eq!(claim_entry.inception, claim_vector["inception"]);
        assert_eq!(claim_entry.expiration, claim_vector["expiration"]);
        assert_eq!(claim_entry.address.version as u64, claim_vector["version"]);
        assert_eq!(
            hns_primitives::hex_encode(&claim_entry.address.hash),
            claim_vector["address"].as_str().expect("claim address")
        );
        assert_eq!(claim_entry.policy_size as u64, claim_vector["policySize"]);
        assert_eq!(claim_entry.memory_usage as u64, claim_vector["memoryUsage"]);
        assert_eq!(
            claim_entry.coinbase_weight as u64,
            claim_vector["coinbaseWeight"]
        );
        let mut claim_mining_snapshot = snapshot();
        claim_mining_snapshot.network_id = Network::Mainnet.canonical_id();
        claim_mining_snapshot.tip.height = claim_height - 1;
        claim_mining_snapshot.tip.time = parent_time;
        let claim_mempool_snapshot = claim_pool.snapshot();
        let mut claim_work = TemplateSelectionWork::default();
        let claim_template = TemplateAssembler
            .assemble_with_selection(
                TemplateBuildRequest {
                    snapshot: &claim_mining_snapshot,
                    mempool: &claim_mempool_snapshot,
                    payout_address: address(9),
                    coinbase_flags: b"hsrd".to_vec(),
                    version: 1,
                    bits: 0x207f_ffff,
                    minimum_time: parent_time + 1,
                    reserved_root: [0; 32],
                    mask_hash: [8; 32],
                    policy: TemplatePolicy::default(),
                },
                SelectionAlgorithm::DependencyFrontier,
                &mut claim_work,
            )
            .expect("claim template");
        assert_eq!(claim_work.special_payload_materializations, 1);
        let expected_claim_coinbase = &special_claim["deterministicCoinbase"];
        let claim_coinbase = &claim_template.transactions()[0];
        assert_eq!(
            hns_primitives::hex_encode(&claim_coinbase.encode()),
            expected_claim_coinbase["raw"]
                .as_str()
                .expect("claim coinbase raw")
        );
        assert_eq!(claim_template.metrics().claim_count, 1);
        assert_eq!(claim_template.metrics().airdrop_count, 0);
        assert_eq!(
            claim_coinbase.outputs[0].value,
            expected_claim_coinbase["payoutValue"]
        );
        assert_eq!(
            claim_coinbase.outputs[1].value,
            expected_claim_coinbase["claimValue"]
        );

        let special = &fixture["specialAirdropPolicy"];
        let proof_vector = &special["proof"];
        let proof = AirdropProof::decode(&decode_hex(
            proof_vector["raw"].as_str().expect("airdrop proof raw"),
        ))
        .expect("airdrop proof");
        let mut pool = test_mempool();
        assert!(matches!(
            pool.submit_airdrop_with_context(
                proof,
                &AirdropMempoolContext {
                    next_height: 11,
                    transaction_start: 0,
                    current_time: 5,
                    airstop: false,
                    hardening: false,
                    goosig_disabled: false,
                },
                &View::default(),
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("airdrop admission"),
            AirdropAdmission::Accepted(_)
        ));
        let entry = pool
            .airdrop_entries()
            .into_iter()
            .next()
            .expect("airdrop entry");
        assert_eq!(
            hns_primitives::hex_encode(&entry.hash),
            proof_vector["hash"].as_str().expect("airdrop hash")
        );
        assert_eq!(entry.position as u64, proof_vector["position"]);
        assert_eq!(entry.value, proof_vector["value"]);
        assert_eq!(entry.fee, proof_vector["fee"]);
        assert_eq!(entry.policy_size as u64, proof_vector["policySize"]);
        assert_eq!(entry.memory_usage as u64, proof_vector["memoryUsage"]);
        assert_eq!(entry.coinbase_weight as u64, proof_vector["coinbaseWeight"]);
        let mining_snapshot = snapshot();
        let mempool_snapshot = pool.snapshot();
        let mut airdrop_work = TemplateSelectionWork::default();
        let template = TemplateAssembler
            .assemble_with_selection(
                TemplateBuildRequest {
                    snapshot: &mining_snapshot,
                    mempool: &mempool_snapshot,
                    payout_address: address(9),
                    coinbase_flags: b"hsrd".to_vec(),
                    version: 1,
                    bits: 0x207f_ffff,
                    minimum_time: 101,
                    reserved_root: [0; 32],
                    mask_hash: [8; 32],
                    policy: TemplatePolicy::default(),
                },
                SelectionAlgorithm::DependencyFrontier,
                &mut airdrop_work,
            )
            .expect("airdrop template");
        assert_eq!(airdrop_work.special_payload_materializations, 1);
        let expected = &special["deterministicCoinbase"];
        let coinbase = &template.transactions()[0];
        assert_eq!(
            hns_primitives::hex_encode(&coinbase.encode()),
            expected["raw"].as_str().expect("airdrop coinbase raw")
        );
        assert_eq!(template.metrics().airdrop_count, 1);
        assert_eq!(coinbase.outputs[0].value, expected["payoutValue"]);
        assert_eq!(coinbase.outputs[1].value, expected["airdropValue"]);
    }

    #[test]
    fn package_selection_prefers_fee_rate_and_builds_valid_body() {
        let first_prev = Outpoint {
            txid: Txid::new([4; 32]),
            index: 0,
        };
        let second_prev = Outpoint {
            txid: Txid::new([5; 32]),
            index: 0,
        };
        let (first, first_coin) = transaction(first_prev.clone(), 100, 90);
        let (second, second_coin) = transaction(second_prev.clone(), 100, 50);
        let mut view = View::default();
        view.coins.insert(first_prev, first_coin);
        view.coins.insert(second_prev, second_coin);
        let mut pool = test_mempool();
        for transaction in [first, second] {
            assert!(matches!(
                pool.submit_with_context(
                    transaction,
                    &MempoolContext::testing(11, 100),
                    &view,
                    &Allow,
                    &Allow,
                )
                .expect("admit"),
                Admission::Accepted(_)
            ));
        }
        let snapshot = snapshot();
        let pool_snapshot = pool.snapshot();
        let template = TemplateAssembler
            .assemble(TemplateBuildRequest {
                snapshot: &snapshot,
                mempool: &pool_snapshot,
                payout_address: address(9),
                coinbase_flags: b"hsrd".to_vec(),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                reserved_root: [0; 32],
                mask_hash: [8; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("template");
        assert_eq!(template.transactions().len(), 3);
        assert_eq!(template.header().tree_root, snapshot.next_tree_root);
        assert_eq!(template.metrics().fees, 60);
        assert_eq!(template.transactions()[0].outputs[0].value, 2_000_000_060);
        assert!(template.prepare_job(&snapshot).is_ok());
    }

    #[test]
    fn package_ranking_uses_hsd_sigop_size_but_block_fit_uses_weight() {
        let heavy_prev = Outpoint {
            txid: Txid::new([6; 32]),
            index: 0,
        };
        let normal_prev = Outpoint {
            txid: Txid::new([7; 32]),
            index: 0,
        };
        let (mut heavy, mut heavy_coin) = transaction(heavy_prev.clone(), 1_000, 900);
        heavy_coin.address = Address::new(0, vec![0x44; 32]).expect("script-hash address");
        heavy.inputs[0].witness = Witness {
            items: vec![vec![0xae; 200]],
        };
        let heavy_txid = heavy.txid();
        let (normal, normal_coin) = transaction(normal_prev.clone(), 100, 90);
        let normal_txid = normal.txid();
        let mut view = View::default();
        view.coins.insert(heavy_prev, heavy_coin);
        view.coins.insert(normal_prev, normal_coin);
        let mut pool = test_mempool();
        for transaction in [heavy.clone(), normal.clone()] {
            assert!(matches!(
                pool.submit_with_context(
                    transaction,
                    &MempoolContext::testing(11, 100),
                    &view,
                    &Allow,
                    &Allow,
                )
                .expect("admit"),
                Admission::Accepted(_)
            ));
        }
        let pool_snapshot = pool.snapshot();
        let heavy_entry = pool_snapshot.entry(&heavy_txid).expect("heavy entry");
        let normal_entry = pool_snapshot.entry(&normal_txid).expect("normal entry");
        assert!(
            100u128 * (transaction_weight(&normal) as u128)
                > 10u128 * (transaction_weight(&heavy) as u128),
            "raw weight would rank the sigop-heavy transaction first"
        );
        assert!(
            100u128 * (normal_entry.policy_size as u128)
                < 10u128 * (heavy_entry.policy_size as u128),
            "HSD policy size must reverse the raw-weight ranking"
        );

        let snapshot = snapshot();
        let template = TemplateAssembler
            .assemble(TemplateBuildRequest {
                snapshot: &snapshot,
                mempool: &pool_snapshot,
                payout_address: address(9),
                coinbase_flags: b"hsrd".to_vec(),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                reserved_root: [0; 32],
                mask_hash: [8; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("template");
        assert_eq!(template.transactions()[1].txid(), normal_txid);
        assert_eq!(template.transactions()[2].txid(), heavy_txid);
        assert_eq!(
            template.metrics().weight,
            hns_consensus::block_weight(&Block {
                header: Header::default(),
                transactions: template.transactions().to_vec(),
            })
        );
    }

    #[test]
    fn dependency_frontier_matches_reference_for_chain_star_and_random_dags() {
        let mut chain_pool = test_mempool();
        let mut chain_view = View::default();
        let root = admit_graph_root(
            &mut chain_pool,
            &mut chain_view,
            10_000,
            vec![1_000_000],
            17,
            1,
        );
        let mut previous = Outpoint {
            txid: root.txid(),
            index: 0,
        };
        let mut previous_value = 1_000_000u64;
        for index in 0..18u32 {
            let fee = 5 + u64::from((index * 37) % 113);
            let next_value = previous_value.checked_sub(fee).expect("chain value");
            let child = admit_graph_transaction(
                &mut chain_pool,
                &chain_view,
                vec![previous],
                vec![next_value],
                index + 2,
            );
            previous = Outpoint {
                txid: child.txid(),
                index: 0,
            };
            previous_value = next_value;
        }
        assert_frontier_matches_reference(&chain_pool, TemplatePolicy::default(), 11);

        let mut star_pool = test_mempool();
        let mut star_view = View::default();
        let root_outputs = (0..20).map(|_| 20_000u64).collect::<Vec<_>>();
        let root = admit_graph_root(
            &mut star_pool,
            &mut star_view,
            20_000,
            root_outputs.clone(),
            3,
            1,
        );
        for (index, value) in root_outputs.into_iter().enumerate() {
            let fee = 1 + u64::try_from((index * 53) % 97).expect("star fee");
            admit_graph_transaction(
                &mut star_pool,
                &star_view,
                vec![Outpoint {
                    txid: root.txid(),
                    index: u32::try_from(index).expect("star output index"),
                }],
                vec![value.checked_sub(fee).expect("star value")],
                u32::try_from(index + 2).expect("star marker"),
            );
        }
        let constrained = TemplatePolicy {
            maximum_transactions: 14,
            minimum_package_fee_rate: 25,
            ..TemplatePolicy::default()
        };
        assert_frontier_matches_reference(&star_pool, constrained, 12);

        for case in 0..8u64 {
            let mut pool = test_mempool();
            let mut view = View::default();
            let mut available = Vec::new();
            for root_index in 0..4u64 {
                let outputs = vec![2_000_000u64; 8];
                let root = admit_graph_root(
                    &mut pool,
                    &mut view,
                    30_000 + case * 10 + root_index,
                    outputs.clone(),
                    11 + root_index,
                    u32::try_from(root_index + 1).expect("root marker"),
                );
                available.extend(outputs.into_iter().enumerate().map(|(index, value)| {
                    (
                        Outpoint {
                            txid: root.txid(),
                            index: u32::try_from(index).expect("root output index"),
                        },
                        value,
                    )
                }));
            }

            let mut random = 0x9e37_79b9_7f4a_7c15u64 ^ case;
            for step in 0..24u32 {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let input_count = if available.len() > 1 && random & 1 == 0 {
                    2
                } else {
                    1
                };
                let mut inputs = Vec::with_capacity(input_count);
                let mut input_value = 0u64;
                for _ in 0..input_count {
                    let available_len =
                        u64::try_from(available.len()).expect("available length fits u64");
                    let index = usize::try_from(random % available_len)
                        .expect("bounded available index fits usize");
                    let (outpoint, value) = available.swap_remove(index);
                    inputs.push(outpoint);
                    input_value = input_value.checked_add(value).expect("DAG input value");
                    random = random.rotate_left(17).wrapping_add(u64::from(step) + 1);
                }
                let fee = 1 + random % 500;
                let output_count = 1 + usize::try_from((random >> 8) % 3).expect("output count");
                let spendable = input_value.checked_sub(fee).expect("DAG spendable value");
                let base = spendable / u64::try_from(output_count).expect("output divisor");
                let mut outputs = vec![base; output_count];
                outputs[0] = outputs[0]
                    .checked_add(
                        spendable % u64::try_from(output_count).expect("output remainder divisor"),
                    )
                    .expect("DAG output remainder");
                let child =
                    admit_graph_transaction(&mut pool, &view, inputs, outputs.clone(), step + 5);
                available.extend(outputs.into_iter().enumerate().map(|(index, value)| {
                    (
                        Outpoint {
                            txid: child.txid(),
                            index: u32::try_from(index).expect("DAG output index"),
                        },
                        value,
                    )
                }));
            }
            let policy = TemplatePolicy {
                maximum_transactions: 12 + usize::try_from(case % 9).expect("policy count"),
                minimum_package_fee_rate: 25 + case * 5,
                ..TemplatePolicy::default()
            };
            assert_frontier_matches_reference(
                &pool,
                policy,
                u8::try_from(case + 20).expect("case marker"),
            );
        }
    }

    #[test]
    fn dependency_frontier_work_is_nonquadratic_at_policy_scale() {
        const TRANSACTIONS: usize = 49_999;
        let candidates = (0..TRANSACTIONS)
            .map(|index| indexed_txid(u64::try_from(index + 1).expect("policy index")))
            .collect::<Vec<_>>();
        let reverse = candidates
            .iter()
            .copied()
            .map(|txid| (txid, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        let mut metrics = TemplateMetrics {
            weight: DEFAULT_RESERVED_TEMPLATE_WEIGHT,
            sigops: DEFAULT_RESERVED_TEMPLATE_SIGOPS,
            ..TemplateMetrics::default()
        };
        let mut names = HashSet::new();
        let mut work = TemplateSelectionWork::default();
        let selected = select_packages_with_frontier(
            &candidates,
            &reverse,
            |candidate, _| {
                Ok(MempoolPackage {
                    txids: vec![candidate],
                    fee: 1,
                    weight: 1,
                    policy_size: 1,
                    sigops: 0,
                    opens: 0,
                    updates: 0,
                    renewals: 0,
                    exclusive_names: Vec::new(),
                    oldest_sequence: 0,
                })
            },
            &TemplatePolicy::default(),
            &mut metrics,
            &mut names,
            &mut work,
        )
        .expect("policy-scale frontier");
        assert_eq!(selected.len(), TRANSACTIONS);
        assert_eq!(work.initial_package_builds, TRANSACTIONS);
        assert_eq!(work.affected_package_rebuilds, 0);
        assert_eq!(work.dependency_edges, 0);
        assert_eq!(work.affected_dependency_edges, 0);
        assert_eq!(work.heap_pushes, TRANSACTIONS);
        assert_eq!(work.heap_pops, TRANSACTIONS);
        assert_eq!(work.stale_heap_pops, 0);
        assert_eq!(work.full_scan_candidates, 0);
        assert!(
            work.initial_package_builds + work.affected_package_rebuilds
                <= TRANSACTIONS.saturating_mul(2)
        );

        const STAR: usize = 1_000;
        let star_candidates = (0..STAR)
            .map(|index| indexed_txid(100_000 + u64::try_from(index).expect("star index")))
            .collect::<Vec<_>>();
        let root = star_candidates[0];
        let mut star_reverse = star_candidates
            .iter()
            .copied()
            .map(|txid| (txid, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        star_reverse
            .get_mut(&root)
            .expect("star root")
            .extend(star_candidates.iter().copied().skip(1));
        let (deduplicated_affected, duplicate_edge_visits) =
            collect_affected_candidates(&[root, root], &star_reverse)
                .expect("deduplicated affected traversal");
        assert_eq!(deduplicated_affected.len(), STAR);
        assert_eq!(duplicate_edge_visits, STAR - 1);
        let mut star_metrics = TemplateMetrics::default();
        let mut star_names = HashSet::new();
        let mut star_work = TemplateSelectionWork::default();
        let star_selected = select_packages_with_frontier(
            &star_candidates,
            &star_reverse,
            |candidate, selected| {
                let root_pending = candidate != root && !selected.contains(&root);
                Ok(MempoolPackage {
                    txids: if root_pending {
                        vec![root, candidate]
                    } else {
                        vec![candidate]
                    },
                    fee: if candidate == root {
                        1_000_000
                    } else if root_pending {
                        1_000_001
                    } else {
                        1
                    },
                    weight: usize::from(root_pending) + 1,
                    policy_size: usize::from(root_pending) + 1,
                    sigops: 0,
                    opens: 0,
                    updates: 0,
                    renewals: 0,
                    exclusive_names: Vec::new(),
                    oldest_sequence: 0,
                })
            },
            &TemplatePolicy::default(),
            &mut star_metrics,
            &mut star_names,
            &mut star_work,
        )
        .expect("star frontier");
        assert_eq!(star_selected.len(), STAR);
        assert_eq!(star_work.dependency_edges, STAR - 1);
        assert_eq!(star_work.affected_dependency_edges, STAR - 1);
        assert_eq!(star_work.initial_package_builds, STAR);
        assert_eq!(star_work.affected_package_rebuilds, STAR - 1);
        assert!(
            star_work.initial_package_builds + star_work.affected_package_rebuilds
                <= STAR.saturating_mul(2)
        );
    }

    #[test]
    fn dependency_frontier_workspace_is_bounded_at_exact_limit() {
        fn package_with_capacity(candidate: Txid, capacity: usize) -> MempoolPackage {
            let mut txids = Vec::with_capacity(capacity);
            txids.push(candidate);
            MempoolPackage {
                txids,
                fee: 1,
                weight: 1,
                policy_size: 1,
                sigops: 0,
                opens: 0,
                updates: 0,
                renewals: 0,
                exclusive_names: Vec::new(),
                oldest_sequence: 0,
            }
        }

        let candidate = indexed_txid(900_000);
        let exact_package_bytes = TEMPLATE_SELECTION_VECTOR_ELEMENT_BYTES;
        let exact_base = MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES
            .checked_sub(TEMPLATE_SELECTION_TRANSIENT_PACKAGE_BYTES)
            .and_then(|bytes| bytes.checked_sub(exact_package_bytes))
            .expect("exact workspace base");
        let mut exact_frontier = BinaryHeap::with_capacity(1);
        let mut exact_workspace =
            TemplateSelectionWorkspace::with_base_bytes(exact_base, exact_frontier.capacity());
        let versions = BTreeMap::from([(candidate, 0u64)]);
        let selected = HashSet::new();
        let mut exact_work = TemplateSelectionWork::default();
        push_frontier_bounded(
            &mut exact_frontier,
            &versions,
            &selected,
            &mut exact_workspace,
            PackageFrontierEntry {
                candidate,
                version: 0,
                package: package_with_capacity(candidate, 1),
            },
            &mut exact_work,
        )
        .expect("exact workspace insertion");
        assert_eq!(exact_frontier.len(), 1);
        assert_eq!(
            exact_workspace
                .total_with_transient()
                .expect("exact workspace total"),
            MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES
        );

        let stale_package = package_with_capacity(candidate, 1);
        let mut compacting_frontier = BinaryHeap::with_capacity(1);
        let mut compacting_workspace =
            TemplateSelectionWorkspace::with_base_bytes(exact_base, compacting_frontier.capacity());
        compacting_workspace
            .retain(&stale_package)
            .expect("retain stale package");
        compacting_frontier.push(PackageFrontierEntry {
            candidate,
            version: 0,
            package: stale_package,
        });
        let current_versions = BTreeMap::from([(candidate, 1u64)]);
        let mut compacting_work = TemplateSelectionWork::default();
        push_frontier_bounded(
            &mut compacting_frontier,
            &current_versions,
            &selected,
            &mut compacting_workspace,
            PackageFrontierEntry {
                candidate,
                version: 1,
                package: package_with_capacity(candidate, 1),
            },
            &mut compacting_work,
        )
        .expect("stale compaction makes exact room");
        assert_eq!(compacting_frontier.len(), 1);
        assert_eq!(
            compacting_frontier.peek().expect("current entry").version,
            1
        );
        assert_eq!(compacting_work.heap_compactions, 1);
        assert_eq!(
            compacting_workspace
                .total_with_transient()
                .expect("compacted workspace total"),
            MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES
        );

        let mut one_over_frontier = BinaryHeap::with_capacity(1);
        let mut one_over_workspace =
            TemplateSelectionWorkspace::with_base_bytes(exact_base, one_over_frontier.capacity());
        let mut one_over_work = TemplateSelectionWork::default();
        assert!(matches!(
            push_frontier_bounded(
                &mut one_over_frontier,
                &versions,
                &selected,
                &mut one_over_workspace,
                PackageFrontierEntry {
                    candidate,
                    version: 0,
                    package: package_with_capacity(candidate, 2),
                },
                &mut one_over_work,
            ),
            Err(MiningError::TemplateCapacity)
        ));
        assert!(one_over_frontier.is_empty());
        assert_eq!(one_over_workspace.retained_package_bytes, 0);
        assert_eq!(one_over_work.heap_pushes, 0);
    }

    #[test]
    fn workspace_estimator_accepts_defaults_and_rejects_adversarial_dags() {
        assert!(
            u64::try_from(std::mem::size_of::<PackageFrontierEntry>())
                .expect("heap entry size fits u64")
                <= TEMPLATE_SELECTION_HEAP_ENTRY_BYTES
        );
        let default_one = estimate_template_selection_workspace_bytes(50_000, 25, 1)
            .expect("default single-build estimate");
        assert_eq!(default_one, 438_308_864);
        assert!(default_one <= MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES);
        let four_active = estimate_template_selection_workspace_bytes(50_000, 25, 4)
            .expect("four-worker aggregate estimate");
        assert_eq!(four_active, 1_753_235_456);
        assert!(four_active <= MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES);
        let maximum_variants_active =
            estimate_template_selection_workspace_bytes(50_000, 25, MAX_TEMPLATE_VARIANTS)
                .expect("maximum-variant aggregate estimate");
        assert_eq!(maximum_variants_active, 7_012_941_824);
        assert!(maximum_variants_active > MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES);

        let maximum_chain = estimate_template_selection_workspace_bytes(1_000, 999, 1)
            .expect("maximum-chain estimate");
        assert!(maximum_chain <= MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES);
        let adversarial_dag = estimate_template_selection_workspace_bytes(250_000, 1_000, 1)
            .expect("adversarial-DAG estimate");
        assert!(adversarial_dag > MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES);
        assert!(
            estimate_template_selection_workspace_bytes(usize::MAX, usize::MAX, usize::MAX)
                .is_none()
        );
    }

    #[test]
    fn template_cache_rejects_stale_generation() {
        let snapshot = snapshot();
        let pool = test_mempool();
        let pool_snapshot = pool.snapshot();
        let template = TemplateAssembler
            .assemble(TemplateBuildRequest {
                snapshot: &snapshot,
                mempool: &pool_snapshot,
                payout_address: address(9),
                coinbase_flags: Vec::new(),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                reserved_root: [0; 32],
                mask_hash: [8; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("template");
        let key = TemplateCacheKey {
            snapshot_generation: snapshot.generation,
            mempool_generation: pool.info().generation,
            variant: 0,
        };
        let mut cache = FutureTemplateCache::default();
        cache.insert(key.clone(), template).expect("insert");
        assert!(cache.activate(&key, &snapshot).is_ok());
        let mut stale = snapshot.clone();
        stale.generation += 1;
        assert!(matches!(
            cache.activate(&key, &stale),
            Err(MiningError::StaleTemplate)
        ));
    }

    #[test]
    fn coordinator_rebuild_is_atomic_and_generation_bound() {
        let snapshot = snapshot();
        let pool = test_mempool();
        let pool_snapshot = pool.snapshot();
        let mut coordinator = TemplateCoordinator::new(2).expect("coordinator");
        let variants = [0u32, 1u32].map(|variant| TemplateVariant {
            variant,
            payout_address: address(9),
            coinbase_flags: vec![u8::try_from(variant).expect("test variant fits in u8")],
            version: 1,
            bits: 0x207f_ffff,
            minimum_time: 101,
            reserved_root: [0; 32],
            mask_hash: [u8::try_from(variant.saturating_add(1)).expect("test variant fits in u8");
                32],
            policy: TemplatePolicy::default(),
        });
        let templates = coordinator
            .rebuild(&snapshot, &pool_snapshot, variants)
            .expect("rebuild");
        assert_eq!(templates.len(), 2);
        assert_eq!(coordinator.len(), 2);

        let key = TemplateCacheKey {
            snapshot_generation: snapshot.generation,
            mempool_generation: pool_snapshot.generation(),
            variant: 1,
        };
        assert!(coordinator.activate(&key, &snapshot).is_ok());

        let duplicate = [0u32, 0u32].map(|variant| TemplateVariant {
            variant,
            payout_address: address(9),
            coinbase_flags: Vec::new(),
            version: 1,
            bits: 0x207f_ffff,
            minimum_time: 101,
            reserved_root: [0; 32],
            mask_hash: [9; 32],
            policy: TemplatePolicy::default(),
        });
        assert!(matches!(
            coordinator.rebuild(&snapshot, &pool_snapshot, duplicate),
            Err(MiningError::TemplateConflict)
        ));
        assert_eq!(coordinator.len(), 2);
    }

    #[test]
    fn prebuilt_install_authenticates_every_field_and_is_atomic() {
        let mining_snapshot = snapshot();
        let pool = test_mempool();
        let mempool = pool.snapshot();
        let generation = mempool.generation();
        let mut coordinator = TemplateCoordinator::new(2).expect("coordinator");
        let baseline = empty_template(&mining_snapshot, &mempool, 1);
        let baseline_key = TemplateCacheKey {
            snapshot_generation: mining_snapshot.generation,
            mempool_generation: generation,
            variant: 1,
        };
        let baseline = coordinator
            .install_prebuilt(&mining_snapshot, generation, [(1, baseline)])
            .expect("baseline install")
            .pop()
            .expect("baseline template");
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        assert!(matches!(
            coordinator.install_prebuilt(
                &mining_snapshot,
                generation,
                std::iter::empty::<(u32, MiningTemplate)>()
            ),
            Err(MiningError::TemplateCapacity)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let valid = empty_template(&mining_snapshot, &mempool, 2);
        assert!(matches!(
            coordinator.install_prebuilt(
                &mining_snapshot,
                generation,
                [(1, valid.clone()), (2, valid.clone()), (3, valid.clone())]
            ),
            Err(MiningError::TemplateCapacity)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        assert!(matches!(
            coordinator.install_prebuilt(
                &mining_snapshot,
                generation,
                [(7, valid.clone()), (7, valid.clone())]
            ),
            Err(MiningError::TemplateConflict)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation + 1, [(2, valid.clone())]),
            Err(MiningError::StaleTemplate)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut stale_snapshot = mining_snapshot.clone();
        stale_snapshot.generation += 1;
        assert!(matches!(
            coordinator.install_prebuilt(&stale_snapshot, generation, [(2, valid.clone())]),
            Err(MiningError::StaleTemplate)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut stale_template = valid.clone();
        stale_template.snapshot_generation += 1;
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, stale_template)]),
            Err(MiningError::StaleTemplate)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut stale_mempool = valid.clone();
        stale_mempool.mempool_generation += 1;
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, stale_mempool)]),
            Err(MiningError::StaleTemplate)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut stale_parent = valid.clone();
        stale_parent.header.parent_hash = hns_primitives::BlockHash::new([91; 32]);
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, stale_parent)]),
            Err(MiningError::StaleTemplate)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut stale_tree = valid.clone();
        stale_tree.header.tree_root = [92; 32];
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, stale_tree)]),
            Err(MiningError::StaleTemplate)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut tampered_identity = valid.clone();
        tampered_identity.template_id[0] ^= 1;
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, tampered_identity)]),
            Err(MiningError::InvalidTemplateContext)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut tampered_body = valid.clone();
        let mut transactions = tampered_body.transactions.to_vec();
        transactions[0].outputs[0].value = transactions[0].outputs[0].value.saturating_add(1);
        tampered_body.transactions = Arc::from(transactions);
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, tampered_body)]),
            Err(MiningError::InvalidTemplateBody)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut invalid_body_with_matching_identity = valid.clone();
        invalid_body_with_matching_identity.transactions = Arc::from(Vec::<Transaction>::new());
        let mut empty_block = Block {
            header: Header {
                time: invalid_body_with_matching_identity.header.minimum_time,
                prev_block: invalid_body_with_matching_identity.header.parent_hash,
                tree_root: invalid_body_with_matching_identity.header.tree_root,
                reserved_root: invalid_body_with_matching_identity.header.reserved_root,
                version: invalid_body_with_matching_identity.header.version,
                bits: invalid_body_with_matching_identity.header.bits,
                ..Header::default()
            },
            transactions: Vec::new(),
        };
        empty_block.header.merkle_root = block_merkle_root(&empty_block);
        empty_block.header.witness_root = block_witness_root(&empty_block);
        invalid_body_with_matching_identity.header.merkle_root = empty_block.header.merkle_root;
        invalid_body_with_matching_identity.header.witness_root = empty_block.header.witness_root;
        invalid_body_with_matching_identity
            .metrics
            .transaction_count = 0;
        invalid_body_with_matching_identity.template_id = template_id(
            mining_snapshot.network_id,
            mining_snapshot.generation,
            generation,
            &invalid_body_with_matching_identity.header,
            &invalid_body_with_matching_identity.transactions,
        );
        assert!(matches!(
            coordinator.install_prebuilt(
                &mining_snapshot,
                generation,
                [(2, invalid_body_with_matching_identity)]
            ),
            Err(MiningError::InvalidTemplateBody)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut tampered_body_root = valid.clone();
        tampered_body_root.header.merkle_root[0] ^= 1;
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, tampered_body_root)]),
            Err(MiningError::InvalidTemplateBody)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut tampered_witness_root = valid.clone();
        tampered_witness_root.header.witness_root[0] ^= 1;
        assert!(matches!(
            coordinator.install_prebuilt(
                &mining_snapshot,
                generation,
                [(2, tampered_witness_root)]
            ),
            Err(MiningError::InvalidTemplateBody)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut tampered_header = valid.clone();
        tampered_header.header.bits ^= 1;
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, tampered_header)]),
            Err(MiningError::InvalidTemplateContext)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);

        let mut tampered_metrics = valid.clone();
        tampered_metrics.metrics.transaction_count =
            tampered_metrics.metrics.transaction_count.saturating_add(1);
        assert!(matches!(
            coordinator.install_prebuilt(&mining_snapshot, generation, [(2, tampered_metrics)]),
            Err(MiningError::InvalidTemplateBody)
        ));
        assert_cache_preserved(&coordinator, &baseline_key, &baseline);
    }

    #[test]
    fn prebuilt_install_returns_variant_order_and_activates_exact_templates() {
        let mining_snapshot = snapshot();
        let pool = test_mempool();
        let mempool = pool.snapshot();
        let generation = mempool.generation();
        let low_variant = empty_template(&mining_snapshot, &mempool, 3);
        let high_variant = empty_template(&mining_snapshot, &mempool, 9);
        let low_id = low_variant.template_id();
        let high_id = high_variant.template_id();
        let mut coordinator = TemplateCoordinator::new(2).expect("coordinator");
        let installed = coordinator
            .install_prebuilt(
                &mining_snapshot,
                generation,
                [(9, high_variant), (3, low_variant)],
            )
            .expect("prebuilt install");
        assert_eq!(
            installed
                .iter()
                .map(|template| template.template_id())
                .collect::<Vec<_>>(),
            vec![low_id, high_id]
        );
        assert_eq!(coordinator.len(), 2);

        for (variant, expected) in [(3, low_id), (9, high_id)] {
            let key = TemplateCacheKey {
                snapshot_generation: mining_snapshot.generation,
                mempool_generation: generation,
                variant,
            };
            assert_eq!(
                coordinator
                    .get(&key)
                    .expect("installed template")
                    .template_id(),
                expected
            );
            assert_eq!(
                coordinator
                    .activate(&key, &mining_snapshot)
                    .expect("activate prebuilt template")
                    .template_id(),
                expected
            );
        }
    }

    #[test]
    fn policy_never_exceeds_consensus_limits() {
        assert!(TemplatePolicy {
            maximum_weight: MAX_BLOCK_WEIGHT + 1,
            ..TemplatePolicy::default()
        }
        .validate()
        .is_err());
        assert!(TemplatePolicy {
            reserved_sigops: MAX_BLOCK_SIGOPS + 1,
            ..TemplatePolicy::default()
        }
        .validate()
        .is_err());
    }
}
