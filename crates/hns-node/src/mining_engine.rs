use std::{
    collections::HashSet,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use hns_chain::{read_canonical_hash, BlockIndexRecord, HeaderRecord, RawBlockSource};
use hns_consensus::{
    advance_threshold_state, compute_block_version_from_state, ConsensusError, DeploymentState,
    NameFlags, NativeSignatureVerifier, Network, ScriptFlags, SequenceLockView, ThresholdState,
    VerifiedClaim, WitnessProgramVerifier, MEDIAN_TIMESPAN,
};
use hns_mempool::{
    AcceptedNameTransactions, AirdropAdmission, AirdropMempoolContext, AirdropMempoolView,
    ClaimAdmission, ClaimContextValidation, ClaimMempoolContext, ClaimMempoolView,
    ContextualTransactionVerifier, Mempool, MempoolContext, MempoolInfo, MempoolLimits,
    MempoolSnapshot, MempoolView, HSD_MINIMUM_RELAY_FEE_RATE,
};
use hns_mining::{
    estimate_template_selection_workspace_bytes, MiningSnapshot, MiningTemplate, PreparedMiningJob,
    SolvedBlockPublicationIntent, SolvedMiningCandidate, TemplateAssembler, TemplateBuildRequest,
    TemplateCacheKey, TemplateCoordinator, TemplatePolicy, TemplateVariant,
    MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES, MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES,
    MAX_TEMPLATE_VARIANTS, PUBLICATION_KEY_PREFIX,
};
use hns_p2p::{BroadcastReport, LivePeerManager, Packet};
use hns_primitives::{
    blake2b_256, Address, AirdropProof, Block, BlockHash, Claim, Coin, Height, Outpoint, Output,
    Reader, Transaction, Writer, MAX_BLOCK_WEIGHT,
};
use hns_state::{
    airdrop_position_spent, decode_coin, encode_outpoint_key, prepare_mempool_name_delta,
    rebuild_mempool_name_overlay, verify_mempool_claim_context, MempoolNameDelta,
    MempoolNameOverlay,
};
use hns_store::{
    ColumnFamily, PrefixScanBudget, ReadSnapshot, Store, StoreHandle, WriteBatch,
    PREFIX_SCAN_MAX_BYTES, PREFIX_SCAN_MAX_ENTRIES,
};
use serde::{Deserialize, Serialize};

use super::{
    issue_authority_permit, AuthorityMode, CanonicalChainEpoch, CanonicalEpoch,
    CanonicalStateWriter, CanonicalWriterError, NativeSyncConfig, NodeBlockImport, NodeReadHandle,
    NodeService, ProductionSafetyFence, ProductionSafetyFenceKind,
};

pub const DEFAULT_MAX_PENDING_PUBLICATIONS: usize = 64;
pub const MAX_PENDING_PUBLICATIONS: usize = 1_024;
pub const MIN_PUBLICATION_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const PUBLICATION_QUEUE_INDEX_KEY: &[u8] = b"publication-queue-index/v1";
const PUBLICATION_QUEUE_INDEX_MAGIC: [u8; 4] = *b"HSPQ";
const PUBLICATION_QUEUE_INDEX_VERSION: u16 = 1;
const PUBLICATION_QUEUE_SCAN_PAGE_ENTRIES: usize = 8;
const PUBLICATION_QUEUE_SCAN_MAX_ELAPSED: Duration = Duration::from_secs(120);
const PUBLICATION_INTENT_MAX_ENCODED_BYTES: usize = MAX_BLOCK_WEIGHT + 256;
const PUBLICATION_INTENT_KEY_BYTES: usize = PUBLICATION_KEY_PREFIX.len() + 32;
const PUBLICATION_QUEUE_MAX_BYTES: u64 = (MAX_PENDING_PUBLICATIONS as u64)
    * ((PUBLICATION_INTENT_KEY_BYTES + PUBLICATION_INTENT_MAX_ENCODED_BYTES) as u64);
const PUBLICATION_RETRY_PAGE_ENTRIES: usize = 8;
const PUBLICATION_RETRY_PAGE_MAX_BYTES: usize = PUBLICATION_RETRY_PAGE_ENTRIES
    * (PUBLICATION_INTENT_KEY_BYTES + PUBLICATION_INTENT_MAX_ENCODED_BYTES);
const PUBLICATION_RETRY_PAGE_MAX_ELAPSED: Duration = Duration::from_secs(30);
const PUBLICATION_RETRY_PAGE_ASYNC_MAX_ELAPSED: Duration = Duration::from_secs(30);
const PUBLICATION_QUEUE_SCAN_ASYNC_MAX_ELAPSED: Duration = Duration::from_secs(120);
const PUBLICATION_RETRY_CURSOR_MAGIC: [u8; 4] = *b"HSPC";
const PUBLICATION_RETRY_CURSOR_VERSION: u16 = 2;
/// A fixed-slot archive for solved intents that were still current but failed
/// full local consensus admission. Slots make both cardinality and disk usage
/// independent of node uptime; a later collision replaces the older diagnostic
/// entry but never affects a live publication intent.
const PUBLICATION_QUARANTINE_KEY_PREFIX: &[u8] = b"publication-quarantine/v1/";
const PUBLICATION_QUARANTINE_SLOTS: usize = DEFAULT_MAX_PENDING_PUBLICATIONS;
const PUBLICATION_QUARANTINE_MAX_ENTRY_BYTES: usize = PUBLICATION_INTENT_MAX_ENCODED_BYTES;
const PUBLICATION_QUARANTINE_MAX_BYTES: u64 =
    (PUBLICATION_QUARANTINE_SLOTS as u64) * (PUBLICATION_QUARANTINE_MAX_ENTRY_BYTES as u64);
// These are type/layout invariants, not runtime configuration. Keep them as
// compile-time failures so changing a queue constant cannot silently create an
// invalid modulo, truncate a slot identifier, or exceed the disk envelope.
const _: () = {
    assert!(PUBLICATION_QUARANTINE_SLOTS > 0);
    assert!((PUBLICATION_QUARANTINE_SLOTS as u64) <= (u16::MAX as u64) + 1);
    assert!(PUBLICATION_QUARANTINE_MAX_BYTES <= 512_u64 * 1024 * 1024);
};
/// Hard CPU-parallelism envelope for template assembly. The default is further
/// constrained by online CPUs, configured variants, and snapshot memory.
pub const MAX_TEMPLATE_BUILD_WORKERS: usize = MAX_TEMPLATE_VARIANTS;
/// Total active plus queued template builds admitted by one node runtime.
pub const MAX_TEMPLATE_BUILD_QUEUE_CAPACITY: usize = 64;
/// Conservative charge for retaining one old persistent mempool generation
/// while a queued build waits. Snapshot cloning itself is O(1), but later
/// mutations may path-copy nodes and keep the captured payload generation live.
pub const TEMPLATE_BUILD_SNAPSHOT_MEMORY_MULTIPLIER: u64 = 2;
/// Bound the aggregate old-generation payload retained by admitted builds.
pub const MAX_TEMPLATE_BUILD_SNAPSHOT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Derive host- and memory-aware template concurrency from the operator's
/// final mempool and variant envelopes. Callers should override each returned
/// field independently when its corresponding value was explicit, then run
/// [`MiningEngineConfig::validate`] on the completed configuration.
pub fn recommended_template_build_limits(
    mempool_limits: &MempoolLimits,
    maximum_template_variants: usize,
) -> (usize, usize) {
    let charged_snapshot_bytes = u64::try_from(mempool_limits.maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(TEMPLATE_BUILD_SNAPSHOT_MEMORY_MULTIPLIER);
    let memory_bound =
        usize::try_from(MAX_TEMPLATE_BUILD_SNAPSHOT_BYTES / charged_snapshot_bytes.max(1))
            .unwrap_or(1)
            .max(1);
    let mut workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(maximum_template_variants)
        .min(MAX_TEMPLATE_BUILD_WORKERS)
        .min(memory_bound)
        .max(1);
    while workers > 1
        && estimate_template_selection_workspace_bytes(
            mempool_limits.maximum_transactions,
            mempool_limits.maximum_ancestors,
            workers,
        )
        .is_none_or(|bytes| bytes > MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES)
    {
        workers -= 1;
    }
    let queue_capacity = workers
        .saturating_mul(2)
        .min(MAX_TEMPLATE_BUILD_QUEUE_CAPACITY)
        .min(memory_bound)
        .max(workers);
    (workers, queue_capacity)
}

struct ActiveMempoolView<'a, T> {
    snapshot: &'a T,
}

impl<T: ReadSnapshot> ActiveMempoolView<'_, T> {
    const fn new(snapshot: &T) -> ActiveMempoolView<'_, T> {
        ActiveMempoolView { snapshot }
    }
}

impl<T: ReadSnapshot> SequenceLockView for ActiveMempoolView<'_, T> {
    fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
        Ok(self.coin(outpoint)?.map(|coin| coin.height))
    }

    fn median_time_past(&self, height: Height) -> Result<u64, ConsensusError> {
        let mut times = Vec::with_capacity(MEDIAN_TIMESPAN);
        let mut cursor = height;
        for _ in 0..MEDIAN_TIMESPAN {
            let hash = read_canonical_hash(self.snapshot, cursor)
                .map_err(|error| ConsensusError::View(error.to_string()))?
                .ok_or_else(|| {
                    ConsensusError::View(format!(
                        "active chain has no canonical header at height {cursor}"
                    ))
                })?;
            let record = super::load_header_record(self.snapshot, &hash)
                .map_err(|error| ConsensusError::View(error.to_string()))?
                .ok_or_else(|| {
                    ConsensusError::View(format!(
                        "canonical header {} is missing at height {cursor}",
                        hash.to_hex()
                    ))
                })?;
            if record.hash != hash || record.height != cursor {
                return Err(ConsensusError::View(format!(
                    "canonical header payload disagrees with height {cursor}"
                )));
            }
            times.push(record.header.time);
            if cursor == 0 {
                break;
            }
            cursor -= 1;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }
}

impl<T: ReadSnapshot> MempoolView for ActiveMempoolView<'_, T> {
    fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, ConsensusError> {
        let Some(bytes) = self
            .snapshot
            .get(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))
            .map_err(|error| ConsensusError::View(error.to_string()))?
        else {
            return Ok(None);
        };
        let coin = decode_coin(&bytes).map_err(|error| ConsensusError::View(error.to_string()))?;
        if coin.outpoint != *outpoint {
            return Err(ConsensusError::View(format!(
                "UTXO payload disagrees with requested outpoint {outpoint:?}"
            )));
        }
        Ok(Some(coin))
    }
}

impl<T: ReadSnapshot> AirdropMempoolView for ActiveMempoolView<'_, T> {
    fn airdrop_position_spent(&self, position: u32) -> Result<bool, ConsensusError> {
        airdrop_position_spent(self.snapshot, position)
            .map_err(|error| ConsensusError::View(error.to_string()))
    }
}

impl<T: ReadSnapshot> ClaimMempoolView for ActiveMempoolView<'_, T> {
    fn verify_claim_context(
        &self,
        output: &Output,
        claim: &VerifiedClaim,
        context: &ClaimMempoolContext,
    ) -> Result<ClaimContextValidation, ConsensusError> {
        match verify_mempool_claim_context(
            self.snapshot,
            output,
            claim,
            context.next_height,
            context.network,
            if context.hardening {
                NameFlags::HARDENED
            } else {
                NameFlags::from_bits(0)
            },
        ) {
            Ok(()) => Ok(ClaimContextValidation::Valid),
            Err(error) if error.is_consensus_invalid() => Ok(ClaimContextValidation::Rejected {
                reason: "invalid-covenant".to_owned(),
            }),
            Err(error) => Err(ConsensusError::View(error.to_string())),
        }
    }
}

struct ActiveContextualTransactionVerifier<'a, T> {
    snapshot: &'a T,
    network: Network,
    name_flags: NameFlags,
    chain_tip: BlockHash,
    name_context: &'a Mutex<ActiveMempoolNameCache>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveMempoolNameIdentity {
    chain_tip: BlockHash,
    height: Height,
    network: Network,
    name_flags: NameFlags,
}

#[derive(Debug)]
struct StagedMempoolNameDelta {
    txid: hns_primitives::Txid,
    base_revision: u64,
    delta: MempoolNameDelta,
}

#[derive(Debug, Default)]
pub(crate) struct ActiveMempoolNameCache {
    identity: Option<ActiveMempoolNameIdentity>,
    revision: u64,
    overlay: MempoolNameOverlay,
    staged: Option<StagedMempoolNameDelta>,
    #[cfg(test)]
    rebuilds: usize,
}

impl<T: ReadSnapshot + Sync> ContextualTransactionVerifier
    for ActiveContextualTransactionVerifier<'_, T>
{
    fn verify(
        &self,
        transaction: &Transaction,
        _input_coins: &[Coin],
        context: &MempoolContext,
        accepted_name_transactions: &AcceptedNameTransactions<'_>,
    ) -> Result<(), ConsensusError> {
        if !transaction
            .outputs
            .iter()
            .any(|output| output.covenant.kind.is_name())
        {
            return Ok(());
        }
        let identity = ActiveMempoolNameIdentity {
            chain_tip: self.chain_tip,
            height: context.next_height,
            network: self.network,
            name_flags: self.name_flags,
        };
        let mut cache = self
            .name_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.staged = None;
        if cache.identity != Some(identity)
            || cache.revision != accepted_name_transactions.revision()
        {
            cache.overlay = rebuild_mempool_name_overlay(
                self.snapshot,
                accepted_name_transactions.iter(),
                context.next_height,
                self.network,
                self.name_flags,
            )
            .map_err(|error| ConsensusError::ContextualCovenant(error.to_string()))?;
            cache.identity = Some(identity);
            cache.revision = accepted_name_transactions.revision();
            #[cfg(test)]
            {
                cache.rebuilds = cache.rebuilds.saturating_add(1);
            }
        }
        let delta = prepare_mempool_name_delta(
            self.snapshot,
            &cache.overlay,
            transaction,
            context.next_height,
            self.network,
            self.name_flags,
        )
        .map_err(|error| ConsensusError::ContextualCovenant(error.to_string()))?;
        cache.staged = Some(StagedMempoolNameDelta {
            txid: transaction.txid(),
            base_revision: accepted_name_transactions.revision(),
            delta,
        });
        Ok(())
    }

    fn transaction_accepted(
        &self,
        transaction: &Transaction,
        accepted_name_transactions: &AcceptedNameTransactions<'_>,
    ) {
        if !transaction
            .outputs
            .iter()
            .any(|output| output.covenant.kind.is_name())
        {
            return;
        }
        let mut cache = self
            .name_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(staged) = cache.staged.take() else {
            cache.identity = None;
            return;
        };
        if staged.txid == transaction.txid()
            && cache.revision == staged.base_revision
            && accepted_name_transactions.revision() == staged.base_revision.saturating_add(1)
        {
            cache.overlay.commit(staged.delta);
            cache.revision = accepted_name_transactions.revision();
        } else {
            cache.identity = None;
        }
    }

    fn is_consensus_complete(&self) -> bool {
        true
    }
}

fn active_mempool_parameters<T: ReadSnapshot>(
    state: &super::NodeState,
    network: Network,
    snapshot: &T,
) -> Result<Option<(MempoolContext, NameFlags, BlockHash)>> {
    let Some(tip) = super::best_block_tip_from_snapshot(snapshot)? else {
        return Ok(None);
    };
    let next_height = tip
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("active-chain height exhausted"))?;
    let tip_record = super::load_header_record(snapshot, &tip.hash)?
        .ok_or_else(|| anyhow::anyhow!("active tip {} has no header record", tip.hash.to_hex()))?;
    if tip_record.hash != tip.hash || tip_record.height != tip.height {
        anyhow::bail!(
            "active tip header payload disagrees with {} at height {}",
            tip.hash.to_hex(),
            tip.height
        );
    }
    let parent_median_time = state.median_time_past(snapshot, &tip_record)?;
    let deployments = state.deployment_state_for_block(snapshot, next_height, tip.hash)?;
    Ok(Some((
        MempoolContext {
            next_height,
            parent_median_time,
            current_time: super::current_unix_time()?,
            coinbase_maturity: network.params().coinbase_maturity,
            minimum_relay_fee_rate: HSD_MINIMUM_RELAY_FEE_RATE,
            require_standard: matches!(network, Network::Mainnet),
            reject_absurd_fees: true,
            relay_priority: true,
            limit_free: true,
            limit_free_relay: hns_mempool::HSD_LIMIT_FREE_RELAY,
            require_complete_verifiers: true,
        },
        deployments.name_flags,
        tip.hash,
    )))
}

fn active_airdrop_parameters<T: ReadSnapshot>(
    state: &super::NodeState,
    network: Network,
    snapshot: &T,
) -> Result<Option<AirdropMempoolContext>> {
    let Some(tip) = super::best_block_tip_from_snapshot(snapshot)? else {
        return Ok(None);
    };
    let next_height = tip
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("active-chain height exhausted"))?;
    let deployments = state.deployment_state_for_block(snapshot, next_height, tip.hash)?;
    Ok(Some(AirdropMempoolContext {
        next_height,
        transaction_start: network.params().tx_start,
        current_time: super::current_unix_time()?,
        airstop: deployments.has_airstop,
        hardening: deployments.name_flags.contains(NameFlags::HARDENED),
        goosig_disabled: next_height >= network.params().goosig_stop,
    }))
}

fn active_claim_parameters<T: ReadSnapshot>(
    state: &super::NodeState,
    network: Network,
    snapshot: &T,
) -> Result<Option<ClaimMempoolContext>> {
    let Some(tip) = super::best_block_tip_from_snapshot(snapshot)? else {
        return Ok(None);
    };
    let next_height = tip
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("active-chain height exhausted"))?;
    let tip_record = super::load_header_record(snapshot, &tip.hash)?
        .ok_or_else(|| anyhow::anyhow!("active tip {} has no header record", tip.hash.to_hex()))?;
    if tip_record.hash != tip.hash || tip_record.height != tip.height {
        anyhow::bail!(
            "active tip header payload disagrees with {} at height {}",
            tip.hash.to_hex(),
            tip.height
        );
    }
    let deployments = state.deployment_state_for_block(snapshot, next_height, tip.hash)?;
    Ok(Some(ClaimMempoolContext {
        next_height,
        transaction_start: network.params().tx_start,
        current_time: super::current_unix_time()?,
        parent_time: tip_record.header.time,
        network,
        hardening: deployments.name_flags.contains(NameFlags::HARDENED),
    }))
}

fn active_mempool_input_verifier() -> Result<WitnessProgramVerifier<NativeSignatureVerifier>> {
    let signatures = NativeSignatureVerifier::new()
        .map_err(|error| anyhow::anyhow!("native mempool signature backend failed: {error}"))?;
    Ok(WitnessProgramVerifier::new(
        signatures,
        ScriptFlags::STANDARD,
    ))
}

/// Node-side mining adapter configuration. Template construction is useful for
/// diagnostics, but transaction relay and solved-block publication remain
/// separately gated. No setting in this structure can manufacture an authority
/// permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningEngineConfig {
    pub enabled: bool,
    pub transaction_relay: bool,
    pub mempool_limits: MempoolLimits,
    pub maximum_template_variants: usize,
    /// Maximum template assemblies allowed to execute concurrently. This is a
    /// resource envelope, not a consensus or machine-specific single-core lock.
    pub template_build_workers: usize,
    /// Total active plus waiting template builds admitted by the runtime.
    pub template_build_queue_capacity: usize,
    pub maximum_pending_publications: usize,
    pub publication_retry_interval: Duration,
}

impl Default for MiningEngineConfig {
    fn default() -> Self {
        let mempool_limits = MempoolLimits::default();
        let (template_build_workers, template_build_queue_capacity) =
            recommended_template_build_limits(&mempool_limits, MAX_TEMPLATE_VARIANTS);
        Self {
            enabled: false,
            transaction_relay: false,
            mempool_limits,
            maximum_template_variants: MAX_TEMPLATE_VARIANTS,
            template_build_workers,
            template_build_queue_capacity,
            maximum_pending_publications: DEFAULT_MAX_PENDING_PUBLICATIONS,
            publication_retry_interval: Duration::from_millis(250),
        }
    }
}

impl MiningEngineConfig {
    pub const fn template_build_workers(&self) -> usize {
        self.template_build_workers
    }

    pub const fn template_build_queue_capacity(&self) -> usize {
        self.template_build_queue_capacity
    }

    pub fn validate(
        &self,
        native_sync: &NativeSyncConfig,
        _authority_mode: AuthorityMode,
    ) -> Result<()> {
        self.mempool_limits.validate().map_err(|error| {
            anyhow::anyhow!("Mining engine mempool configuration failed: {error}")
        })?;
        if self.maximum_template_variants == 0
            || self.maximum_template_variants > MAX_TEMPLATE_VARIANTS
        {
            anyhow::bail!(
                "Mining engine template variants must be between 1 and {MAX_TEMPLATE_VARIANTS}"
            );
        }
        if self.template_build_workers == 0
            || self.template_build_workers > MAX_TEMPLATE_BUILD_WORKERS
            || self.template_build_workers > self.maximum_template_variants
        {
            anyhow::bail!(
                "Mining engine template workers must be between 1 and the configured variant/hard limit of {}",
                self.maximum_template_variants.min(MAX_TEMPLATE_BUILD_WORKERS)
            );
        }
        if self.template_build_queue_capacity < self.template_build_workers
            || self.template_build_queue_capacity > MAX_TEMPLATE_BUILD_QUEUE_CAPACITY
        {
            anyhow::bail!(
                "Mining engine template queue must be between {} and {MAX_TEMPLATE_BUILD_QUEUE_CAPACITY}",
                self.template_build_workers
            );
        }
        let per_worker_workspace = estimate_template_selection_workspace_bytes(
            self.mempool_limits.maximum_transactions,
            self.mempool_limits.maximum_ancestors,
            1,
        )
        .ok_or_else(|| anyhow::anyhow!("mining template workspace estimate overflow"))?;
        if per_worker_workspace > MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES {
            anyhow::bail!(
                "one mining template selector may require {per_worker_workspace} workspace bytes; maximum is {MAX_TEMPLATE_SELECTION_WORKSPACE_BYTES}"
            );
        }
        let aggregate_workspace = estimate_template_selection_workspace_bytes(
            self.mempool_limits.maximum_transactions,
            self.mempool_limits.maximum_ancestors,
            self.template_build_workers,
        )
        .ok_or_else(|| anyhow::anyhow!("aggregate mining template workspace estimate overflow"))?;
        if aggregate_workspace > MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES {
            anyhow::bail!(
                "active mining template selectors may require {aggregate_workspace} workspace bytes; aggregate maximum is {MAX_TEMPLATE_SELECTION_AGGREGATE_WORKSPACE_BYTES}"
            );
        }
        let admitted_snapshot_bytes = u64::try_from(self.template_build_queue_capacity)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(self.mempool_limits.maximum_bytes).unwrap_or(u64::MAX))
            .saturating_mul(TEMPLATE_BUILD_SNAPSHOT_MEMORY_MULTIPLIER);
        if admitted_snapshot_bytes > MAX_TEMPLATE_BUILD_SNAPSHOT_BYTES {
            anyhow::bail!(
                "Mining engine template queue may retain {admitted_snapshot_bytes} mempool-snapshot bytes; maximum is {MAX_TEMPLATE_BUILD_SNAPSHOT_BYTES}"
            );
        }
        if self.maximum_pending_publications == 0
            || self.maximum_pending_publications > MAX_PENDING_PUBLICATIONS
        {
            anyhow::bail!(
                "Mining engine pending publications must be between 1 and {MAX_PENDING_PUBLICATIONS}"
            );
        }
        if self.publication_retry_interval < MIN_PUBLICATION_RETRY_INTERVAL {
            anyhow::bail!(
                "Mining engine publication retry interval must be at least {} ms",
                MIN_PUBLICATION_RETRY_INTERVAL.as_millis()
            );
        }
        if !self.enabled {
            if self.transaction_relay {
                anyhow::bail!("Mining engine transaction relay requires the engine to be enabled");
            }
            return Ok(());
        }
        if self.transaction_relay && !native_sync.enabled {
            anyhow::bail!("Mining engine transaction relay requires the native-sync P2P runtime");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MiningTemplateRequest {
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

#[derive(Clone, Debug)]
pub struct NativeMiningJobRequest {
    pub variant: u32,
    pub payout_address: Address,
    pub coinbase_flags: Vec<u8>,
    pub reserved_root: [u8; 32],
    pub mask: [u8; 32],
    pub policy: TemplatePolicy,
}

#[derive(Clone, Debug)]
pub struct NativeMiningJob {
    pub snapshot: Arc<MiningSnapshot>,
    pub prepared: Arc<PreparedMiningJob>,
}

/// Exact immutable inputs captured from one atomically published generation,
/// then consumed by a bounded CPU worker. `MempoolSnapshot` is a structurally
/// shared O(1) clone; active selector workspaces are bounded independently.
struct CapturedTemplateBuild {
    snapshot: Arc<MiningSnapshot>,
    mempool: MempoolSnapshot,
}

fn assemble_captured_template(
    captured: &CapturedTemplateBuild,
    request: MiningTemplateRequest,
) -> Result<MiningTemplate> {
    TemplateAssembler
        .assemble(TemplateBuildRequest {
            snapshot: &captured.snapshot,
            mempool: &captured.mempool,
            payout_address: request.payout_address,
            coinbase_flags: request.coinbase_flags,
            version: request.version,
            bits: request.bits,
            minimum_time: request.minimum_time,
            reserved_root: request.reserved_root,
            mask_hash: request.mask_hash,
            policy: request.policy,
        })
        .map_err(|error| anyhow::anyhow!("failed to assemble mining template: {error}"))
}

fn validate_template_request_set(
    config: &MiningEngineConfig,
    requests: &[MiningTemplateRequest],
) -> Result<()> {
    if !config.enabled {
        anyhow::bail!("Mining engine is disabled");
    }
    if requests.is_empty() || requests.len() > config.maximum_template_variants {
        anyhow::bail!(
            "mining template request count must be between 1 and {}",
            config.maximum_template_variants
        );
    }
    let mut variants = HashSet::with_capacity(requests.len());
    for request in requests {
        if !variants.insert(request.variant) {
            anyhow::bail!("mining template variants must be unique");
        }
        request
            .policy
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid mining template policy: {error}"))?;
        if request.coinbase_flags.len() > hns_consensus::MAX_COINBASE_WITNESS_SIZE {
            anyhow::bail!(
                "mining template coinbase flags contain {} bytes; maximum is {}",
                request.coinbase_flags.len(),
                hns_consensus::MAX_COINBASE_WITNESS_SIZE
            );
        }
    }
    Ok(())
}

fn validate_template_mempool_capture(
    config: &MiningEngineConfig,
    info: &MempoolInfo,
    snapshot: &MempoolSnapshot,
) -> Result<()> {
    if info.transaction_count > config.mempool_limits.maximum_transactions
        || info.bytes > config.mempool_limits.maximum_bytes
        || info.orphan_count > config.mempool_limits.maximum_orphans
        || info.orphan_bytes > config.mempool_limits.maximum_orphan_bytes
    {
        anyhow::bail!("mempool exceeds its configured template-capture envelope");
    }
    if snapshot.generation() != info.generation || snapshot.len() != info.transaction_count {
        anyhow::bail!("published mempool snapshot disagrees with its bounded summary");
    }
    Ok(())
}

struct TemplateConsensusContext {
    next_height: Height,
    parent_median_time: u64,
    expected_version: u32,
    tip: HeaderRecord,
}

fn template_deployment_state<T: ReadSnapshot>(
    metadata: &T,
    network: Network,
    height: Height,
    previous_hash: BlockHash,
) -> Result<DeploymentState> {
    if height == 0 {
        if previous_hash != BlockHash::ZERO {
            anyhow::bail!("genesis deployment state has a non-zero parent");
        }
        return Ok(DeploymentState::from_states([ThresholdState::Defined; 4]));
    }
    let parent = super::load_header_record(metadata, &previous_hash)?.ok_or_else(|| {
        anyhow::anyhow!(
            "deployment-state parent {} is missing",
            previous_hash.to_hex()
        )
    })?;
    if parent.height.checked_add(1) != Some(height) || parent.hash != previous_hash {
        anyhow::bail!(
            "deployment-state parent {} is not contiguous with height {height}",
            previous_hash.to_hex()
        );
    }
    let previous = super::load_deployment_state(metadata, parent.hash)?.ok_or_else(|| {
        anyhow::anyhow!(
            "deployment-state cache is missing for parent {} at height {}",
            parent.hash.to_hex(),
            parent.height
        )
    })?;
    if previous.height != parent.height {
        anyhow::bail!(
            "deployment-state cache height {} disagrees with parent height {}",
            previous.height,
            parent.height
        );
    }
    let params = network.params();
    let mut state = previous.state;
    for deployment in network.deployments() {
        let window = deployment.effective_window(params.miner_window);
        if window == 0 {
            anyhow::bail!("deployment {} has a zero window", deployment.name());
        }
        let period = if height.is_multiple_of(window) {
            let mut lookup = |hash: &BlockHash| super::load_header_record(metadata, hash);
            Some(super::completed_deployment_period_with_lookup(
                &parent,
                *deployment,
                window,
                &mut lookup,
            )?)
        } else {
            None
        };
        let next = advance_threshold_state(
            params.activation_threshold,
            params.miner_window,
            *deployment,
            height,
            previous.state.state(deployment.id),
            period,
        )
        .with_context(|| {
            format!(
                "failed to advance deployment {} for block height {height}",
                deployment.name()
            )
        })?;
        state = state.with_state(deployment.id, next);
    }
    Ok(state)
}

fn template_consensus_context<T: ReadSnapshot>(
    metadata: &T,
    network: Network,
    snapshot: &MiningSnapshot,
) -> Result<TemplateConsensusContext> {
    if snapshot.network_id != network.canonical_id() {
        anyhow::bail!("published mining snapshot belongs to a different network");
    }
    let next_height = snapshot
        .tip
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("mining template height exhausted"))?;
    let canonical_tip = read_canonical_hash(metadata, snapshot.tip.height)?
        .ok_or_else(|| anyhow::anyhow!("durable mining tip is missing from the active chain"))?;
    if canonical_tip != snapshot.tip.hash {
        anyhow::bail!(
            "durable mining tip {} disagrees with active-chain height {}",
            snapshot.tip.hash.to_hex(),
            snapshot.tip.height
        );
    }
    let tip = super::load_header_record(metadata, &snapshot.tip.hash)?.ok_or_else(|| {
        anyhow::anyhow!(
            "durable mining tip {} has no header record",
            snapshot.tip.hash.to_hex()
        )
    })?;
    if tip.hash != snapshot.tip.hash
        || tip.height != snapshot.tip.height
        || tip.header.prev_block != snapshot.tip.parent_hash
        || tip.header.tree_root != snapshot.tip.tree_root
        || tip.header.time != snapshot.tip.time
        || tip.header.bits != snapshot.tip.bits
    {
        anyhow::bail!(
            "durable mining header context disagrees with {} at height {}",
            snapshot.tip.hash.to_hex(),
            snapshot.tip.height
        );
    }
    let mut lookup = |hash: &BlockHash| super::load_header_record(metadata, hash);
    let parent_median_time = super::median_time_past_with_lookup(&tip, &mut lookup)?;
    if parent_median_time != snapshot.parent_median_time {
        anyhow::bail!(
            "durable mining median time {} disagrees with active-chain median time {parent_median_time} at height {}",
            snapshot.parent_median_time,
            snapshot.tip.height
        );
    }
    let deployments = template_deployment_state(metadata, network, next_height, snapshot.tip.hash)?;
    let expected_version = compute_block_version_from_state(network.deployments(), deployments)?;
    Ok(TemplateConsensusContext {
        next_height,
        parent_median_time,
        expected_version,
        tip,
    })
}

fn validate_template_consensus_requests<T: ReadSnapshot>(
    metadata: &T,
    network: Network,
    context: &TemplateConsensusContext,
    requests: &[MiningTemplateRequest],
) -> Result<()> {
    let maximum_time = super::current_unix_time()?.saturating_add(super::MAX_FUTURE_BLOCK_TIME);
    for request in requests {
        if request.version != context.expected_version {
            anyhow::bail!(
                "mining template version {} disagrees with HSD deployment version {} at height {}",
                request.version,
                context.expected_version,
                context.next_height
            );
        }
        if request.minimum_time <= context.parent_median_time {
            anyhow::bail!(
                "mining template minimum time {} does not exceed HSD parent median time {} at height {}",
                request.minimum_time,
                context.parent_median_time,
                context.next_height
            );
        }
        if request.minimum_time > maximum_time {
            anyhow::bail!(
                "mining template minimum time {} exceeds maximum consensus time {maximum_time} at height {}",
                request.minimum_time,
                context.next_height
            );
        }
        let mut lookup = |hash: &BlockHash| super::load_header_record(metadata, hash);
        let expected_bits = super::expected_bits_with_lookup(
            network,
            request.minimum_time,
            Some(&context.tip),
            &mut lookup,
        )?;
        if request.bits != expected_bits {
            anyhow::bail!(
                "mining template bits {:#010x} disagree with HSD target {expected_bits:#010x} at height {} for time {}",
                request.bits,
                context.next_height,
                request.minimum_time
            );
        }
    }
    Ok(())
}

fn mining_engine_locally_accepted_record_from_snapshot<T: ReadSnapshot>(
    snapshot: &T,
    block_hash: BlockHash,
) -> Result<Option<BlockIndexRecord>> {
    let Some(record) = super::load_block_index_record(snapshot, &block_hash)? else {
        return Ok(None);
    };
    if !record.status.active_chain || !record.status.body_present || record.status.failed {
        return Ok(None);
    }
    if read_canonical_hash(snapshot, record.height)? != Some(block_hash) {
        anyhow::bail!(
            "active mining block {} is not bound at canonical height {}",
            block_hash.to_hex(),
            record.height
        );
    }
    let header = super::load_header_record(snapshot, &block_hash)?.ok_or_else(|| {
        anyhow::anyhow!(
            "active mining block {} is missing its canonical header",
            block_hash.to_hex()
        )
    })?;
    if header.hash != record.hash
        || header.height != record.height
        || header.chainwork != record.chainwork
        || header.status != record.status
    {
        anyhow::bail!(
            "active mining block {} disagrees with canonical header state",
            block_hash.to_hex()
        );
    }
    Ok(Some(record))
}

/// The template cache is derived state. Recover a poisoned mutex by clearing
/// the cache before reuse so no caller can observe a partially updated value.
fn lock_template_coordinator(
    coordinator: &Mutex<TemplateCoordinator>,
) -> MutexGuard<'_, TemplateCoordinator> {
    match coordinator.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.clear();
            guard
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MiningPublicationAttempt {
    pub block_hash: BlockHash,
    pub attempted_peers: usize,
    pub written_peers: usize,
    pub failures: Vec<String>,
}

impl MiningPublicationAttempt {
    fn from_report(block_hash: BlockHash, report: BroadcastReport) -> Self {
        Self {
            block_hash,
            attempted_peers: report.attempted,
            written_peers: report.queued,
            failures: report
                .failed
                .into_iter()
                .map(|(peer, reason)| format!("peer {}: {reason}", peer.0))
                .collect(),
        }
    }
}

/// Opaque hash-order continuation for bounded durable publication recovery.
///
/// The checksum catches damaged persistence and accidental field forgery, but
/// the cursor is only a traversal hint: it never serves as proof of queue
/// cardinality or bytes. Exact proofs are rebuilt from one immutable store
/// snapshot at a completed traversal boundary. Losing the cursor is safe
/// because [`Default`] deterministically restarts at the first key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiningPublicationRetryCursor {
    version: u16,
    after: Option<BlockHash>,
    revision: Option<u64>,
    /// Authenticated traversal budget only. It bounds time to wrap under churn
    /// and is never interpreted as a queue count or byte proof.
    remaining_pages: Option<u16>,
    checksum: [u8; 32],
}

impl MiningPublicationRetryCursor {
    fn new(after: Option<BlockHash>, revision: Option<u64>, remaining_pages: Option<u16>) -> Self {
        debug_assert_eq!(after.is_some(), revision.is_some());
        debug_assert_eq!(after.is_some(), remaining_pages.is_some());
        let version = PUBLICATION_RETRY_CURSOR_VERSION;
        let checksum = publication_retry_cursor_checksum(version, after, revision, remaining_pages);
        Self {
            version,
            after,
            revision,
            remaining_pages,
            checksum,
        }
    }

    fn validate(self, maximum_pages: u16) -> Result<()> {
        if self.version != PUBLICATION_RETRY_CURSOR_VERSION {
            anyhow::bail!(
                "mining publication retry cursor version {} is unsupported",
                self.version
            );
        }
        if self.after.is_some() != self.revision.is_some()
            || self.after.is_some() != self.remaining_pages.is_some()
        {
            anyhow::bail!("mining publication retry cursor has incomplete continuation state");
        }
        if self
            .remaining_pages
            .is_some_and(|remaining| remaining == 0 || remaining > maximum_pages)
        {
            anyhow::bail!(
                "mining publication retry cursor page budget exceeds the configured traversal envelope"
            );
        }
        let expected = publication_retry_cursor_checksum(
            self.version,
            self.after,
            self.revision,
            self.remaining_pages,
        );
        if self.checksum != expected {
            anyhow::bail!("mining publication retry cursor checksum mismatch");
        }
        Ok(())
    }
}

impl Default for MiningPublicationRetryCursor {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

fn publication_retry_cursor_checksum(
    version: u16,
    after: Option<BlockHash>,
    revision: Option<u64>,
    remaining_pages: Option<u16>,
) -> [u8; 32] {
    let mut writer = Writer::new();
    writer.write_bytes(&PUBLICATION_RETRY_CURSOR_MAGIC);
    writer.write_u16(version);
    match after {
        Some(hash) => {
            writer.write_u8(1);
            writer.write_bytes(hash.as_bytes());
        }
        None => writer.write_u8(0),
    }
    match revision {
        Some(revision) => {
            writer.write_u8(1);
            writer.write_u64(revision);
        }
        None => writer.write_u8(0),
    }
    match remaining_pages {
        Some(remaining_pages) => {
            writer.write_u8(1);
            writer.write_u16(remaining_pages);
        }
        None => writer.write_u8(0),
    }
    blake2b_256(&writer.finish())
}

fn publication_retry_page_budget(maximum: usize) -> Result<u16> {
    if maximum == 0 || maximum > MAX_PENDING_PUBLICATIONS {
        anyhow::bail!("publication queue maximum must be between 1 and {MAX_PENDING_PUBLICATIONS}");
    }
    let pages = maximum
        .checked_add(PUBLICATION_RETRY_PAGE_ENTRIES - 1)
        .ok_or_else(|| anyhow::anyhow!("publication retry page budget overflow"))?
        / PUBLICATION_RETRY_PAGE_ENTRIES;
    u16::try_from(pages).context("publication retry page budget exceeds its cursor encoding")
}

/// Apply an async wall-clock bound to a blocking storage worker. Dropping the
/// join handle cannot stop a RocksDB syscall, so the concurrency permit lives
/// inside the worker and remains charged until the underlying call exits.
async fn await_publication_blocking_worker<T>(
    operation: &'static str,
    maximum_elapsed: Duration,
    worker: tokio::task::JoinHandle<Result<T>>,
) -> Result<T>
where
    T: Send + 'static,
{
    match tokio::time::timeout(maximum_elapsed, worker).await {
        Ok(joined) => joined.with_context(|| format!("{operation} worker failed"))?,
        Err(_) => anyhow::bail!(
            "{operation} exceeded its {} ms async deadline; the detached blocking worker retains its concurrency permit until the underlying storage call returns",
            maximum_elapsed.as_millis()
        ),
    }
}

#[derive(Clone, Debug, Default)]
pub struct MiningPublicationRetryBatch {
    pub attempts: Vec<MiningPublicationAttempt>,
    pub next_cursor: MiningPublicationRetryCursor,
    /// True only after this invocation reached the end of hash-key order and a
    /// separate immutable-snapshot audit authenticated the current queue index.
    /// The next cursor starts at the first live key, including insertions behind
    /// the old cursor, so deferred records cannot starve later records.
    pub completed_cycle: bool,
    /// The cursor was rebased onto a newer durable queue revision or its
    /// authenticated traversal budget forced a wrap. At an audit boundary,
    /// any disagreement also restarts from the first key.
    pub audit_restarted: bool,
    pub queue_revision: u64,
    pub decoded_records: usize,
    pub decoded_bytes: u64,
}

#[derive(Clone, Debug)]
enum PublicationRecovery {
    Accepted { warning: Option<String> },
    Deferred { reason: String },
    RetiredStale { reason: String },
    Quarantined { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationRetirement {
    Stale,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationQueueIndex {
    revision: u64,
    count: u64,
    total_bytes: u64,
}

impl PublicationQueueIndex {
    fn migrated(count: u64, total_bytes: u64) -> Result<Self> {
        let index = Self {
            revision: 1,
            count,
            total_bytes,
        };
        index.validate(MAX_PENDING_PUBLICATIONS)?;
        Ok(index)
    }

    fn validate(self, maximum: usize) -> Result<()> {
        let configured = u64::try_from(maximum)
            .map_err(|_| anyhow::anyhow!("publication maximum does not fit u64"))?;
        if self.revision == 0 {
            return Err(publication_queue_invariant(
                "publication queue revision is zero",
                1,
                0,
            ));
        }
        if self.count > u64::try_from(MAX_PENDING_PUBLICATIONS).unwrap_or(u64::MAX) {
            return Err(publication_queue_invariant(
                "publication queue count exceeds its hard limit",
                u64::try_from(MAX_PENDING_PUBLICATIONS).unwrap_or(u64::MAX),
                self.count,
            ));
        }
        if self.total_bytes > PUBLICATION_QUEUE_MAX_BYTES {
            return Err(publication_queue_invariant(
                "publication queue bytes exceed their hard limit",
                PUBLICATION_QUEUE_MAX_BYTES,
                self.total_bytes,
            ));
        }
        if (self.count == 0) != (self.total_bytes == 0) {
            return Err(publication_queue_invariant(
                "publication queue count and byte total disagree on emptiness",
                self.count,
                self.total_bytes,
            ));
        }
        if self.count > configured {
            anyhow::bail!(
                "publication queue contains {} intents, above configured maximum {maximum}",
                self.count
            );
        }
        Ok(())
    }

    fn inserted(self, record_bytes: u64, maximum: usize) -> Result<Self> {
        let next = Self {
            revision: self.revision.checked_add(1).ok_or_else(|| {
                publication_queue_invariant(
                    "publication queue revision overflow",
                    u64::MAX - 1,
                    u64::MAX,
                )
            })?,
            count: self.count.checked_add(1).ok_or_else(|| {
                publication_queue_invariant(
                    "publication queue count overflow",
                    u64::MAX - 1,
                    u64::MAX,
                )
            })?,
            total_bytes: self.total_bytes.checked_add(record_bytes).ok_or_else(|| {
                publication_queue_invariant(
                    "publication queue byte total overflow",
                    PUBLICATION_QUEUE_MAX_BYTES,
                    u64::MAX,
                )
            })?,
        };
        next.validate(maximum)?;
        Ok(next)
    }

    fn deleted(self, record_bytes: u64, maximum: usize) -> Result<Self> {
        let next = Self {
            revision: self.revision.checked_add(1).ok_or_else(|| {
                publication_queue_invariant(
                    "publication queue revision overflow",
                    u64::MAX - 1,
                    u64::MAX,
                )
            })?,
            count: self.count.checked_sub(1).ok_or_else(|| {
                publication_queue_invariant("publication queue count underflow", 1, 0)
            })?,
            total_bytes: self.total_bytes.checked_sub(record_bytes).ok_or_else(|| {
                publication_queue_invariant(
                    "publication queue byte total underflow",
                    record_bytes,
                    self.total_bytes,
                )
            })?,
        };
        next.validate(maximum)?;
        Ok(next)
    }

    fn encode(self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_bytes(&PUBLICATION_QUEUE_INDEX_MAGIC);
        writer.write_u16(PUBLICATION_QUEUE_INDEX_VERSION);
        writer.write_u64(self.revision);
        writer.write_u64(self.count);
        writer.write_u64(self.total_bytes);
        let mut encoded = writer.finish();
        encoded.extend_from_slice(&blake2b_256(&encoded));
        encoded
    }

    fn decode(encoded: &[u8], maximum: usize) -> Result<Self> {
        const BODY_BYTES: usize = 4 + 2 + 8 + 8 + 8;
        const ENCODED_BYTES: usize = BODY_BYTES + 32;
        if encoded.len() != ENCODED_BYTES {
            return Err(publication_queue_invariant(
                "publication queue index has an invalid encoded length",
                ENCODED_BYTES as u64,
                u64::try_from(encoded.len()).unwrap_or(u64::MAX),
            ));
        }
        let (body, checksum) = encoded.split_at(BODY_BYTES);
        if checksum != blake2b_256(body) {
            return Err(publication_queue_invariant(
                "publication queue index checksum mismatch",
                1,
                0,
            ));
        }
        let mut reader = Reader::new(body, BODY_BYTES).map_err(|error| {
            publication_queue_invariant(
                format!("publication queue index reader failed: {error}"),
                BODY_BYTES as u64,
                u64::try_from(body.len()).unwrap_or(u64::MAX),
            )
        })?;
        if reader.read_vec(4).map_err(publication_codec_invariant)? != PUBLICATION_QUEUE_INDEX_MAGIC
        {
            return Err(publication_queue_invariant(
                "publication queue index magic mismatch",
                1,
                0,
            ));
        }
        let version = reader.read_u16().map_err(publication_codec_invariant)?;
        if version != PUBLICATION_QUEUE_INDEX_VERSION {
            return Err(publication_queue_invariant(
                "publication queue index version is unsupported",
                u64::from(PUBLICATION_QUEUE_INDEX_VERSION),
                u64::from(version),
            ));
        }
        let index = Self {
            revision: reader.read_u64().map_err(publication_codec_invariant)?,
            count: reader.read_u64().map_err(publication_codec_invariant)?,
            total_bytes: reader.read_u64().map_err(publication_codec_invariant)?,
        };
        reader
            .ensure_finished()
            .map_err(publication_codec_invariant)?;
        index.validate(maximum)?;
        Ok(index)
    }
}

#[derive(Clone, Debug)]
struct PublicationQueueInvariantError {
    detail: String,
    limit: u64,
    actual: u64,
}

impl std::fmt::Display for PublicationQueueInvariantError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: limit {}, actual {}",
            self.detail, self.limit, self.actual
        )
    }
}

impl std::error::Error for PublicationQueueInvariantError {}

fn publication_queue_invariant(
    detail: impl Into<String>,
    limit: u64,
    actual: u64,
) -> anyhow::Error {
    anyhow::Error::new(PublicationQueueInvariantError {
        detail: detail.into(),
        limit,
        actual,
    })
}

fn publication_codec_invariant(error: hns_primitives::PrimitiveError) -> anyhow::Error {
    publication_queue_invariant(
        format!("publication queue index codec failed: {error}"),
        1,
        0,
    )
}

#[derive(Debug)]
struct PublicationQueueInventory {
    index: PublicationQueueIndex,
    persisted_index: bool,
    #[cfg(test)]
    pages: usize,
}

#[derive(Debug)]
struct PublicationQueuePage {
    intents: Vec<SolvedBlockPublicationIntent>,
    record_bytes: Vec<u64>,
    next_cursor: MiningPublicationRetryCursor,
    completed_cycle: bool,
    forced_wrap: bool,
    audit_restarted: bool,
    revision: u64,
    indexed_count: u64,
    indexed_bytes: u64,
    decoded_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct MiningPublicationResult {
    pub attempt: MiningPublicationAttempt,
    pub connected: BlockIndexRecord,
    /// A post-commit operational error returned by local candidate admission.
    /// The active block record was re-read before publication, so this warning
    /// does not mean that the consensus-state commit failed.
    pub local_admission_warning: Option<String>,
    /// True when local consensus accepted the block but no ready peer completed
    /// the critical publication socket write. The durable intent remains
    /// available for retry and must not be mistaken for a failed local
    /// connection.
    pub publication_pending: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MiningEngineDiagnostics {
    pub enabled: bool,
    pub observation_only: bool,
    pub transaction_relay_enabled: bool,
    pub mempool: MempoolInfo,
    pub maximum_template_variants: usize,
    pub template_build_workers: usize,
    pub template_build_queue_capacity: usize,
    pub cached_template_variants: usize,
    pub pending_publications: usize,
    pub maximum_pending_publications: usize,
    pub publication_retry_interval_ms: u64,
    pub can_build_templates: bool,
    pub can_publish_solved_blocks: bool,
    pub blockers: Vec<String>,
}

impl NodeBlockImport {
    /// Reconstruct the exact strict mining-source import that
    /// `SolvedMiningCandidate` normally produces. Publication intents are the
    /// crash-recovery representation of an already admitted solution, so this
    /// constructor is deliberately private to the node-side mining adapter and
    /// is used only after generation, tip, tree-root, hash, and proof-of-work
    /// bindings have all been rechecked under the canonical writer.
    fn from_mining_publication(block: Block, height: Height) -> Self {
        Self {
            block,
            height,
            validation: super::ImportValidationPolicy::Strict,
            source: RawBlockSource::Mining,
        }
    }
}

impl NodeService {
    /// The future-template cache is derived state. If a prior panic poisoned
    /// the mutex, discard the cache before reuse rather than allowing a stale
    /// derivative object to permanently stop node operation.
    fn mining_engine_template_cache(&self) -> MutexGuard<'_, hns_mining::TemplateCoordinator> {
        lock_template_coordinator(&self.mining_engine_templates)
    }

    pub fn mining_engine_diagnostics(&self) -> Result<MiningEngineDiagnostics> {
        let enabled = self.config.mining_engine.enabled;
        let durable = self.state.durable_mining_state()?;
        let can_publish = enabled && issue_authority_permit(&self.config, &durable).is_some();
        let publication_index = if enabled {
            self.mining_engine_finish_publication_queue_read(load_publication_queue_index(
                &self.state.store,
                self.config.mining_engine.maximum_pending_publications,
            ))?
        } else {
            None
        };
        let pending = publication_index
            .map(|index| usize::try_from(index.count).unwrap_or(usize::MAX))
            .unwrap_or(0);
        let mut blockers = Vec::new();
        if !enabled {
            blockers.push("Mining engine is disabled".to_owned());
        }
        if durable.snapshot.is_none() {
            blockers.push("no durable active-chain mining snapshot is available".to_owned());
        }
        if !can_publish {
            blockers.push("no mining-authority permit is available".to_owned());
        }
        if enabled && publication_index.is_none() {
            blockers.push("durable publication queue index is not initialized".to_owned());
        }
        blockers.sort();
        blockers.dedup();
        let cached_template_variants = self.mining_engine_template_cache().len();
        Ok(MiningEngineDiagnostics {
            enabled,
            observation_only: !can_publish,
            transaction_relay_enabled: self.config.mining_engine.transaction_relay,
            mempool: self.state.mempool.info(),
            maximum_template_variants: self.config.mining_engine.maximum_template_variants,
            template_build_workers: self.config.mining_engine.template_build_workers,
            template_build_queue_capacity: self.config.mining_engine.template_build_queue_capacity,
            cached_template_variants,
            pending_publications: pending,
            maximum_pending_publications: self.config.mining_engine.maximum_pending_publications,
            publication_retry_interval_ms: u64::try_from(
                self.config
                    .mining_engine
                    .publication_retry_interval
                    .as_millis(),
            )
            .unwrap_or(u64::MAX),
            can_build_templates: enabled && durable.snapshot.is_some(),
            can_publish_solved_blocks: can_publish,
            blockers,
        })
    }

    /// Build an immutable diagnostic or future template from one durable chain
    /// snapshot and one immutable mempool snapshot. Publishing the resulting
    /// job still requires an authority permit through the existing mining
    /// subscription boundary.
    pub fn mining_engine_build_template(
        &self,
        request: MiningTemplateRequest,
    ) -> Result<MiningTemplate> {
        let templates = self.mining_engine_rebuild_templates(vec![request])?;
        templates
            .first()
            .map(|template| template.as_ref().clone())
            .ok_or_else(|| anyhow::anyhow!("Mining engine template rebuild returned no template"))
    }

    /// Build and activate one current authoritative job without asking a
    /// worker to duplicate deployment, MTP, or difficulty derivation.
    pub fn mining_engine_build_native_job(
        &self,
        request: NativeMiningJobRequest,
    ) -> Result<NativeMiningJob> {
        let (captured, template_request) = self.mining_engine_capture_native_job_build(request)?;
        let variants = std::iter::once(TemplateVariant {
            variant: template_request.variant,
            payout_address: template_request.payout_address,
            coinbase_flags: template_request.coinbase_flags,
            version: template_request.version,
            bits: template_request.bits,
            minimum_time: template_request.minimum_time,
            reserved_root: template_request.reserved_root,
            mask_hash: template_request.mask_hash,
            policy: template_request.policy,
        });
        let mut replacement = TemplateCoordinator::new(
            self.config.mining_engine.maximum_template_variants,
        )
        .map_err(|error| anyhow::anyhow!("failed to initialize native mining cache: {error}"))?;
        let templates = replacement
            .rebuild(&captured.snapshot, &captured.mempool, variants)
            .map_err(|error| anyhow::anyhow!("failed to assemble native mining job: {error}"))?;
        let template = templates
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("native mining template rebuild returned no job"))?;
        let prepared =
            Arc::new(template.prepare_job(&captured.snapshot).map_err(|error| {
                anyhow::anyhow!("failed to prepare native mining job: {error}")
            })?);
        prepared
            .validate_for_snapshot(&captured.snapshot)
            .map_err(|error| anyhow::anyhow!("native mining job is stale: {error}"))?;
        *self.mining_engine_template_cache() = replacement;
        debug_assert_eq!(template.snapshot_generation(), captured.snapshot.generation);
        Ok(NativeMiningJob {
            snapshot: captured.snapshot,
            prepared,
        })
    }

    /// Capture all chain and mempool inputs required by a CPU template worker
    /// while the canonical writer is at one ordered generation. No template
    /// assembly occurs in this method.
    fn mining_engine_capture_template_build(
        &self,
        requests: &[MiningTemplateRequest],
        require_authority: bool,
    ) -> Result<CapturedTemplateBuild> {
        if !self.config.mining_engine.enabled {
            anyhow::bail!("Mining engine is disabled");
        }
        if requests.is_empty()
            || requests.len() > self.config.mining_engine.maximum_template_variants
        {
            anyhow::bail!(
                "mining template request count must be between 1 and {}",
                self.config.mining_engine.maximum_template_variants
            );
        }
        let mut variants = HashSet::with_capacity(requests.len());
        for request in requests {
            if !variants.insert(request.variant) {
                anyhow::bail!("mining template variants must be unique");
            }
            request
                .policy
                .validate()
                .map_err(|error| anyhow::anyhow!("invalid mining template policy: {error}"))?;
            if request.coinbase_flags.len() > hns_consensus::MAX_COINBASE_WITNESS_SIZE {
                anyhow::bail!(
                    "mining template coinbase flags contain {} bytes; maximum is {}",
                    request.coinbase_flags.len(),
                    hns_consensus::MAX_COINBASE_WITNESS_SIZE
                );
            }
        }

        let durable = self.state.durable_mining_state()?;
        if require_authority {
            issue_authority_permit(&self.config, &durable)
                .ok_or_else(|| anyhow::anyhow!("native mining authority is unavailable"))?;
        }
        let snapshot = durable
            .snapshot
            .ok_or_else(|| anyhow::anyhow!("no durable mining snapshot is available"))?;
        let next_height = snapshot
            .tip
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("mining template height exhausted"))?;
        let metadata = self.state.store.snapshot()?;
        let canonical_tip =
            read_canonical_hash(&metadata, snapshot.tip.height)?.ok_or_else(|| {
                anyhow::anyhow!("durable mining tip is missing from the active chain")
            })?;
        if canonical_tip != snapshot.tip.hash {
            anyhow::bail!(
                "durable mining tip {} disagrees with active-chain height {}",
                snapshot.tip.hash.to_hex(),
                snapshot.tip.height
            );
        }
        let tip_record =
            super::load_header_record(&metadata, &snapshot.tip.hash)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "durable mining tip {} has no header record",
                    snapshot.tip.hash.to_hex()
                )
            })?;
        if tip_record.hash != snapshot.tip.hash
            || tip_record.height != snapshot.tip.height
            || tip_record.header.prev_block != snapshot.tip.parent_hash
            || tip_record.header.tree_root != snapshot.tip.tree_root
            || tip_record.header.time != snapshot.tip.time
            || tip_record.header.bits != snapshot.tip.bits
        {
            anyhow::bail!(
                "durable mining header context disagrees with {} at height {}",
                snapshot.tip.hash.to_hex(),
                snapshot.tip.height
            );
        }
        let parent_median_time = self.state.median_time_past(&metadata, &tip_record)?;
        if parent_median_time != snapshot.parent_median_time {
            anyhow::bail!(
                "durable mining median time {} disagrees with active-chain median time {parent_median_time} at height {}",
                snapshot.parent_median_time,
                snapshot.tip.height
            );
        }
        let deployments =
            self.state
                .deployment_state_for_block(&metadata, next_height, snapshot.tip.hash)?;
        let expected_version =
            compute_block_version_from_state(self.config.network.deployments(), deployments)?;
        let maximum_time = super::current_unix_time()?.saturating_add(super::MAX_FUTURE_BLOCK_TIME);
        for request in requests {
            if request.version != expected_version {
                anyhow::bail!(
                    "mining template version {} disagrees with HSD deployment version {expected_version} at height {next_height}",
                    request.version
                );
            }
            if request.minimum_time <= parent_median_time {
                anyhow::bail!(
                    "mining template minimum time {} does not exceed HSD parent median time {parent_median_time} at height {next_height}",
                    request.minimum_time
                );
            }
            if request.minimum_time > maximum_time {
                anyhow::bail!(
                    "mining template minimum time {} exceeds maximum consensus time {maximum_time} at height {next_height}",
                    request.minimum_time
                );
            }
            let mut lookup = |hash: &BlockHash| super::load_header_record(&metadata, hash);
            let expected_bits = super::expected_bits_with_lookup(
                self.config.network,
                request.minimum_time,
                Some(&tip_record),
                &mut lookup,
            )?;
            if request.bits != expected_bits {
                anyhow::bail!(
                    "mining template bits {:#010x} disagree with HSD target {expected_bits:#010x} at height {next_height} for time {}",
                    request.bits,
                    request.minimum_time
                );
            }
        }
        drop(metadata);

        let mempool_info = self.state.mempool.info();
        if mempool_info.transaction_count
            > self
                .config
                .mining_engine
                .mempool_limits
                .maximum_transactions
            || mempool_info.bytes > self.config.mining_engine.mempool_limits.maximum_bytes
            || mempool_info.orphan_count > self.config.mining_engine.mempool_limits.maximum_orphans
            || mempool_info.orphan_bytes
                > self
                    .config
                    .mining_engine
                    .mempool_limits
                    .maximum_orphan_bytes
        {
            anyhow::bail!("mempool exceeds its configured template-capture envelope");
        }
        let mempool = self.state.mempool.snapshot();
        if mempool.generation() != mempool_info.generation
            || mempool.len() != mempool_info.transaction_count
        {
            anyhow::bail!("captured mempool generation disagrees with its bounded summary");
        }
        Ok(CapturedTemplateBuild { snapshot, mempool })
    }

    fn mining_engine_capture_native_job_build(
        &self,
        request: NativeMiningJobRequest,
    ) -> Result<(CapturedTemplateBuild, MiningTemplateRequest)> {
        let durable = self.state.durable_mining_state()?;
        let permit = issue_authority_permit(&self.config, &durable)
            .ok_or_else(|| anyhow::anyhow!("native mining authority is unavailable"))?;
        let snapshot = durable
            .snapshot
            .ok_or_else(|| anyhow::anyhow!("native mining snapshot is unavailable"))?;
        if permit.generation != snapshot.generation || permit.tip != snapshot.tip.hash {
            anyhow::bail!("native mining permit disagrees with its durable snapshot");
        }
        let next_height = snapshot
            .tip
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("mining template height exhausted"))?;
        let metadata = self.state.store.snapshot()?;
        let tip_record =
            super::load_header_record(&metadata, &snapshot.tip.hash)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "durable mining tip {} has no header record",
                    snapshot.tip.hash.to_hex()
                )
            })?;
        let parent_median_time = self.state.median_time_past(&metadata, &tip_record)?;
        let deployments =
            self.state
                .deployment_state_for_block(&metadata, next_height, snapshot.tip.hash)?;
        let version =
            compute_block_version_from_state(self.config.network.deployments(), deployments)?;
        let minimum_time = super::current_unix_time()?.max(parent_median_time.saturating_add(1));
        let mut lookup = |hash: &BlockHash| super::load_header_record(&metadata, hash);
        let bits = super::expected_bits_with_lookup(
            self.config.network,
            minimum_time,
            Some(&tip_record),
            &mut lookup,
        )?;
        drop(metadata);
        let template_request = MiningTemplateRequest {
            variant: request.variant,
            payout_address: request.payout_address,
            coinbase_flags: request.coinbase_flags,
            version,
            bits,
            minimum_time,
            reserved_root: request.reserved_root,
            mask_hash: hns_primitives::blake2b_256_many([
                snapshot.tip.hash.as_bytes().as_slice(),
                request.mask.as_slice(),
            ]),
            policy: request.policy,
        };
        let captured = self
            .mining_engine_capture_template_build(std::slice::from_ref(&template_request), true)?;
        if captured.snapshot.generation != snapshot.generation
            || captured.snapshot.tip.hash != snapshot.tip.hash
        {
            anyhow::bail!("native mining capture changed generation during ordered preparation");
        }
        Ok((captured, template_request))
    }

    /// Atomically replace the complete future-template set for one immutable
    /// chain and mempool generation. A failed variant leaves the prior cache
    /// untouched.
    pub fn mining_engine_rebuild_templates(
        &self,
        requests: Vec<MiningTemplateRequest>,
    ) -> Result<Vec<Arc<MiningTemplate>>> {
        let captured = self.mining_engine_capture_template_build(&requests, false)?;
        let variants = requests.into_iter().map(|request| TemplateVariant {
            variant: request.variant,
            payout_address: request.payout_address,
            coinbase_flags: request.coinbase_flags,
            version: request.version,
            bits: request.bits,
            minimum_time: request.minimum_time,
            reserved_root: request.reserved_root,
            mask_hash: request.mask_hash,
            policy: request.policy,
        });
        let mut replacement = TemplateCoordinator::new(
            self.config.mining_engine.maximum_template_variants,
        )
        .map_err(|error| anyhow::anyhow!("failed to initialize mining template cache: {error}"))?;
        let templates = replacement
            .rebuild(&captured.snapshot, &captured.mempool, variants)
            .map_err(|error| anyhow::anyhow!("failed to assemble mining templates: {error}"))?;
        *self.mining_engine_template_cache() = replacement;
        Ok(templates)
    }

    /// Retrieve and validate a cached future template against the exact durable
    /// generation before producing a prepared job. This does not publish an
    /// authoritative job and does not bypass the authority permit boundary.
    pub fn mining_engine_prepare_cached_job(
        &self,
        key: &TemplateCacheKey,
    ) -> Result<Arc<PreparedMiningJob>> {
        if !self.config.mining_engine.enabled {
            anyhow::bail!("Mining engine is disabled");
        }
        let snapshot = self
            .state
            .durable_mining_state()?
            .snapshot
            .ok_or_else(|| anyhow::anyhow!("no durable mining snapshot is available"))?;
        let template = self
            .mining_engine_template_cache()
            .activate(key, &snapshot)
            .map_err(|error| anyhow::anyhow!("cached mining template is unavailable: {error}"))?;
        template
            .prepare_job(&snapshot)
            .map(Arc::new)
            .map_err(|error| anyhow::anyhow!("failed to prepare cached mining job: {error}"))
    }

    pub(crate) fn mining_engine_reconcile_connected_transactions(
        &mut self,
        transactions: &[hns_primitives::Transaction],
    ) -> Option<u64> {
        self.mining_engine_reconcile_chain_transition(&[], transactions)
    }

    pub(crate) fn mining_engine_reconcile_chain_transition(
        &mut self,
        disconnected_transactions: &[hns_primitives::Transaction],
        connected_transactions: &[hns_primitives::Transaction],
    ) -> Option<u64> {
        if !self.config.mining_engine.enabled {
            return None;
        }
        let pool = self.state.mempool.info();
        if disconnected_transactions.is_empty()
            && pool.transaction_count == 0
            && pool.orphan_count == 0
            && pool.claim_count == 0
            && pool.airdrop_count == 0
        {
            // A direct IBD slice cannot remove or revalidate anything from an
            // empty pool. Avoid reopening chain/name snapshots after every
            // historical state commit solely to rediscover that fact.
            return None;
        }
        let revalidation = (|| -> Result<hns_mempool::MempoolRevalidation> {
            let snapshot = self
                .state
                .store
                .snapshot()
                .context("failed to open post-connect mempool context")?;
            let (context, name_flags, chain_tip) =
                active_mempool_parameters(&self.state, self.config.network, &snapshot)?
                    .ok_or_else(|| {
                        anyhow::anyhow!("connected chain has no active mempool context")
                    })?;
            let view = ActiveMempoolView::new(&snapshot);
            let contextual_verifier = ActiveContextualTransactionVerifier {
                snapshot: &snapshot,
                network: self.config.network,
                name_flags,
                chain_tip,
                name_context: &self.mempool_name_context,
            };
            let input_verifier = active_mempool_input_verifier()?;
            let claim_context =
                active_claim_parameters(&self.state, self.config.network, &snapshot)?.ok_or_else(
                    || anyhow::anyhow!("connected chain has no claim mempool context"),
                )?;
            // Expire retained claims before rebuilding ordinary transactions so
            // an invalid claim cannot keep blocking an otherwise valid name
            // transaction during this transition.
            let before_claim_revalidation = self.state.mempool.info();
            let claims_revalidated = self
                .state
                .mempool
                .revalidate_claims_with_context(&claim_context, &view, &self.claim_dnssec)
                .map_err(|error| anyhow::anyhow!("claim revalidation failed: {error}"))?;
            let after_claim_revalidation = self.state.mempool.info();
            let claim_revalidation_removed = before_claim_revalidation
                .transaction_count
                .saturating_add(before_claim_revalidation.orphan_count)
                .saturating_add(before_claim_revalidation.claim_count)
                .saturating_add(before_claim_revalidation.airdrop_count)
                .saturating_sub(
                    after_claim_revalidation
                        .transaction_count
                        .saturating_add(after_claim_revalidation.orphan_count)
                        .saturating_add(after_claim_revalidation.claim_count)
                        .saturating_add(after_claim_revalidation.airdrop_count),
                );
            let mut revalidation = self
                .state
                .mempool
                .reconcile_chain_transition_with_context(
                    connected_transactions,
                    disconnected_transactions,
                    &context,
                    &view,
                    &input_verifier,
                    &contextual_verifier,
                )
                .map_err(|error| anyhow::anyhow!("post-connect revalidation failed: {error}"))?;
            if claims_revalidated {
                revalidation.changed = true;
                revalidation.removed = revalidation
                    .removed
                    .saturating_add(claim_revalidation_removed);
                revalidation.retained_claims = self.state.mempool.info().claim_count;
                revalidation.generation = self.state.mempool.info().generation;
            }
            if self
                .state
                .mempool
                .reconcile_claims_with_context(
                    disconnected_transactions,
                    &claim_context,
                    &view,
                    &self.claim_dnssec,
                )
                .map_err(|error| anyhow::anyhow!("claim revalidation failed: {error}"))?
            {
                revalidation.changed = true;
                revalidation.retained_claims = self.state.mempool.info().claim_count;
                revalidation.generation = self.state.mempool.info().generation;
            }
            let airdrop_context =
                active_airdrop_parameters(&self.state, self.config.network, &snapshot)?
                    .ok_or_else(|| {
                        anyhow::anyhow!("connected chain has no airdrop mempool context")
                    })?;
            if self
                .state
                .mempool
                .reconcile_airdrops_with_context(
                    disconnected_transactions,
                    &airdrop_context,
                    &view,
                    &self.airdrop_signatures,
                )
                .map_err(|error| anyhow::anyhow!("airdrop revalidation failed: {error}"))?
            {
                revalidation.changed = true;
                revalidation.retained_airdrops = self.state.mempool.info().airdrop_count;
                revalidation.generation = self.state.mempool.info().generation;
            }
            Ok(revalidation)
        })();
        let revalidation = match revalidation {
            Ok(revalidation) => revalidation,
            Err(error) => {
                let removed = self.state.mempool.clear();
                self.mining_engine_template_cache().clear();
                tracing::warn!(
                    %error,
                    "post-connect mempool revalidation failed; cleared the retained pool"
                );
                return (removed > 0).then(|| self.state.mempool.info().generation);
            }
        };
        if revalidation.changed {
            self.mining_engine_template_cache().clear();
        }
        revalidation.changed.then_some(revalidation.generation)
    }

    pub(crate) fn mining_engine_publish_mempool_reconciled(
        &self,
        tip_generation: u64,
        mempool_generation: Option<u64>,
    ) -> Result<()> {
        let Some(mempool_generation) = mempool_generation else {
            return Ok(());
        };
        self.mining_events
            .mempool_reconciled(tip_generation, mempool_generation)
            .map_err(|error| anyhow::anyhow!("failed to publish mempool reconciliation: {error}"))
    }

    pub fn mining_engine_mempool_inventory(&self, maximum: usize) -> Vec<hns_p2p::Inventory> {
        if maximum == 0 {
            return Vec::new();
        }
        let txids = self.state.mempool.ordered_txids_snapshot();
        let mut inventory = txids
            .txids()
            .take(maximum)
            .map(hns_p2p::Inventory::transaction)
            .collect::<Vec<_>>();
        if inventory.len() == maximum {
            return inventory;
        }
        // Claims and airdrops are small special-purpose pools, but their crate
        // API currently returns owned ordered entries. Only materialize one of
        // those bounded pools when the ordinary transaction prefix leaves room.
        // Ordinary inventory—the production hot path—uses the structurally
        // shared txid index above and never clones the full mempool.
        let remaining = maximum - inventory.len();
        inventory.extend(
            self.state
                .mempool
                .claim_entries()
                .into_iter()
                .take(remaining)
                .map(|entry| hns_p2p::Inventory::claim(entry.hash)),
        );
        if inventory.len() == maximum {
            return inventory;
        }
        let remaining = maximum - inventory.len();
        inventory.extend(
            self.state
                .mempool
                .airdrop_entries()
                .into_iter()
                .take(remaining)
                .map(|entry| hns_p2p::Inventory::airdrop(entry.hash)),
        );
        inventory
    }

    pub fn mining_engine_mempool_transaction(
        &self,
        txid: &hns_primitives::Txid,
    ) -> Option<hns_primitives::Transaction> {
        self.state.mempool.transaction(txid).cloned()
    }

    pub fn mining_engine_mempool_claim(&self, hash: &[u8; 32]) -> Option<Claim> {
        self.state.mempool.claim(hash).cloned()
    }

    pub fn mining_engine_mempool_airdrop(&self, hash: &[u8; 32]) -> Option<AirdropProof> {
        self.state.mempool.airdrop(hash).cloned()
    }

    /// Admit an ordinary peer transaction against one immutable active-chain
    /// snapshot and the pool's deterministic in-memory name-state overlay.
    /// The P2P runtime remains policy-free and only relays accepted inventory.
    pub fn mining_engine_accept_peer_transaction(
        &mut self,
        transaction: hns_primitives::Transaction,
    ) -> Result<hns_mempool::Admission> {
        self.state.ensure_storage_operational()?;
        if !self.config.mining_engine.enabled || !self.config.mining_engine.transaction_relay {
            return Ok(hns_mempool::Admission::Rejected {
                reason: "mining_engine-transaction-relay-disabled".to_owned(),
            });
        }

        let snapshot = self
            .state
            .store
            .snapshot()
            .context("failed to open active mempool context")?;
        let Some((context, name_flags, chain_tip)) =
            active_mempool_parameters(&self.state, self.config.network, &snapshot)?
        else {
            return Ok(hns_mempool::Admission::Rejected {
                reason: "active-chain-context-unavailable".to_owned(),
            });
        };
        let view = ActiveMempoolView::new(&snapshot);
        let contextual_verifier = ActiveContextualTransactionVerifier {
            snapshot: &snapshot,
            network: self.config.network,
            name_flags,
            chain_tip,
            name_context: &self.mempool_name_context,
        };
        let input_verifier = active_mempool_input_verifier()?;
        let admission = self
            .state
            .mempool
            .submit_with_context(
                transaction,
                &context,
                &view,
                &input_verifier,
                &contextual_verifier,
            )
            .map_err(|error| anyhow::anyhow!("peer transaction admission failed: {error}"))?;
        drop(snapshot);
        if matches!(admission, hns_mempool::Admission::Accepted(_)) {
            self.mining_engine_template_cache().clear();
            let durable = self.state.durable_mining_state()?;
            let mempool_generation = self.state.mempool.info().generation;
            if durable.generation > 0 && mempool_generation > 0 {
                self.mining_events
                    .mempool_reconciled(durable.generation, mempool_generation)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to publish mempool admission: {error}")
                    })?;
            }
        }
        Ok(admission)
    }

    /// Admit a peer DNSSEC ownership claim against the same immutable active
    /// snapshot used by block connection, including canonical commit ancestry
    /// and post-deflation replacement rules.
    pub fn mining_engine_accept_peer_claim(&mut self, claim: Claim) -> Result<ClaimAdmission> {
        self.state.ensure_storage_operational()?;
        if !self.config.mining_engine.enabled || !self.config.mining_engine.transaction_relay {
            return Ok(ClaimAdmission::Rejected {
                reason: "mining_engine-transaction-relay-disabled".to_owned(),
            });
        }
        let snapshot = self
            .state
            .store
            .snapshot()
            .context("failed to open active claim mempool context")?;
        let Some(context) = active_claim_parameters(&self.state, self.config.network, &snapshot)?
        else {
            return Ok(ClaimAdmission::Rejected {
                reason: "active-chain-context-unavailable".to_owned(),
            });
        };
        let view = ActiveMempoolView::new(&snapshot);
        let admission = self
            .state
            .mempool
            .submit_claim_with_context(claim, &context, &view, &self.claim_dnssec)
            .map_err(|error| anyhow::anyhow!("peer claim admission failed: {error}"))?;
        drop(snapshot);
        if matches!(admission, ClaimAdmission::Accepted(_)) {
            self.mining_engine_template_cache().clear();
            let durable = self.state.durable_mining_state()?;
            let mempool_generation = self.state.mempool.info().generation;
            if durable.generation > 0 && mempool_generation > 0 {
                self.mining_events
                    .mempool_reconciled(durable.generation, mempool_generation)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to publish claim mempool admission: {error}")
                    })?;
            }
        }
        Ok(admission)
    }

    /// Admit a peer airdrop/faucet proof against the same immutable active
    /// snapshot used by templates and the durable allocation bitfield.
    pub fn mining_engine_accept_peer_airdrop(
        &mut self,
        proof: AirdropProof,
    ) -> Result<AirdropAdmission> {
        self.state.ensure_storage_operational()?;
        if !self.config.mining_engine.enabled || !self.config.mining_engine.transaction_relay {
            return Ok(AirdropAdmission::Rejected {
                reason: "mining_engine-transaction-relay-disabled".to_owned(),
            });
        }
        let snapshot = self
            .state
            .store
            .snapshot()
            .context("failed to open active airdrop mempool context")?;
        let Some(context) = active_airdrop_parameters(&self.state, self.config.network, &snapshot)?
        else {
            return Ok(AirdropAdmission::Rejected {
                reason: "active-chain-context-unavailable".to_owned(),
            });
        };
        let view = ActiveMempoolView::new(&snapshot);
        let admission = self
            .state
            .mempool
            .submit_airdrop_with_context(proof, &context, &view, &self.airdrop_signatures)
            .map_err(|error| anyhow::anyhow!("peer airdrop admission failed: {error}"))?;
        drop(snapshot);
        if matches!(admission, AirdropAdmission::Accepted(_)) {
            self.mining_engine_template_cache().clear();
            let durable = self.state.durable_mining_state()?;
            let mempool_generation = self.state.mempool.info().generation;
            if durable.generation > 0 && mempool_generation > 0 {
                self.mining_events
                    .mempool_reconciled(durable.generation, mempool_generation)
                    .map_err(|error| {
                        anyhow::anyhow!("failed to publish airdrop mempool admission: {error}")
                    })?;
            }
        }
        Ok(admission)
    }

    /// Verify or migrate the complete durable publication queue before a
    /// [`super::NodeRuntime`] starts accepting commands. This deliberately
    /// executes before the canonical actor exists: startup owns the service,
    /// enumeration is paginated and resource-bounded, and only the final
    /// versioned index installation is an atomic point mutation.
    pub(crate) fn mining_engine_initialize_publication_queue(&mut self) -> Result<()> {
        if !self.config.mining_engine.enabled {
            return Ok(());
        }
        self.state.ensure_storage_operational()?;
        let maximum = self.config.mining_engine.maximum_pending_publications;
        let result = (|| {
            let inventory = enumerate_publication_queue(&self.state.store, maximum)?;
            if inventory.persisted_index {
                return Ok(());
            }
            install_publication_queue_index(&self.state.store, inventory.index, maximum)?;
            let installed =
                load_publication_queue_index(&self.state.store, maximum)?.ok_or_else(|| {
                    publication_queue_invariant(
                        "publication queue index is missing after acknowledged migration",
                        1,
                        0,
                    )
                })?;
            if installed != inventory.index {
                return Err(publication_queue_invariant(
                    "publication queue index changed after acknowledged migration",
                    inventory.index.revision,
                    installed.revision,
                ));
            }
            Ok(())
        })();
        self.mining_engine_finish_publication_queue_mutation(result)
    }

    /// Persist the solved block before network publication. The durable queue
    /// makes a crash between candidate reconstruction and fan-out observable
    /// and retryable. This method requires the same authority capability as
    /// candidate connection.
    pub fn mining_engine_stage_publication(
        &mut self,
        candidate: &SolvedMiningCandidate,
        created_at: u64,
    ) -> Result<SolvedBlockPublicationIntent> {
        let result = (|| {
            if !self.config.mining_engine.enabled {
                anyhow::bail!("Mining engine is disabled");
            }
            self.validate_mining_engine_candidate(candidate)?;
            let intent = SolvedBlockPublicationIntent::from_candidate(candidate, created_at)
                .map_err(|error| anyhow::anyhow!("failed to create publication intent: {error}"))?;
            stage_publication_intent(
                &self.state.store,
                &intent,
                self.config.mining_engine.maximum_pending_publications,
            )?;
            Ok(intent)
        })();
        self.mining_engine_finish_publication_queue_mutation(result)
    }

    pub fn mining_engine_complete_publication(&mut self, block_hash: BlockHash) -> Result<()> {
        self.state.ensure_storage_operational()?;
        let result = delete_publication_intent(
            &self.state.store,
            block_hash,
            self.config.mining_engine.maximum_pending_publications,
        );
        self.mining_engine_finish_publication_queue_mutation(result)
    }

    fn mining_engine_locally_accepted_record(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<BlockIndexRecord>> {
        let snapshot = self
            .state
            .store
            .snapshot()
            .context("failed to authenticate locally accepted mining block")?;
        mining_engine_locally_accepted_record_from_snapshot(&snapshot, block_hash)
    }

    fn mining_engine_retire_publication(
        &mut self,
        intent: &SolvedBlockPublicationIntent,
        retirement: PublicationRetirement,
    ) -> Result<()> {
        self.state.ensure_storage_operational()?;
        let result = retire_publication_intent(
            &self.state.store,
            intent,
            retirement,
            self.config.mining_engine.maximum_pending_publications,
        );
        self.mining_engine_finish_publication_queue_mutation(result)
    }

    fn mining_engine_finish_publication_queue_mutation<T>(
        &mut self,
        result: Result<T>,
    ) -> Result<T> {
        #[cfg(test)]
        if result.as_ref().is_err_and(|error| {
            error
                .downcast_ref::<InjectedPublicationQueueCommitAmbiguity>()
                .is_some()
        }) {
            // Exercise the same node-level reopen fence used when a physical
            // name-page or RocksDB publication crosses its commit boundary.
            // The memory StoreHandle itself has no ambiguous-commit state.
            if let Some(pages) = self.state.name_pages.as_mut() {
                pages.fence_after_commit_attempt();
            }
        }
        if let Some(invariant) = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<PublicationQueueInvariantError>())
            .cloned()
        {
            if let Err(fence_error) = self.mining_engine_fence_publication_queue(&invariant) {
                if self.state.storage_reopen_required() {
                    self.fail_closed_after_ambiguous_commit();
                } else {
                    self.revoke_runtime_authority();
                }
                return Err(anyhow::anyhow!(
                    "publication queue invariant failed: {invariant}; durable safety fencing also failed: {fence_error}"
                ));
            }
        }
        if result.is_err() && self.state.storage_reopen_required() {
            // Backends distinguish a definite pre-commit rejection from an
            // ambiguous post-write acknowledgement. Only the latter carries a
            // reopen fence and revokes authority.
            self.fail_closed_after_ambiguous_commit();
        }
        result
    }

    fn mining_engine_finish_publication_queue_read<T>(&self, result: Result<T>) -> Result<T> {
        if let Some(invariant) = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<PublicationQueueInvariantError>())
            .cloned()
        {
            if let Err(fence_error) = self.mining_engine_fence_publication_queue(&invariant) {
                self.revoke_runtime_authority();
                return Err(anyhow::anyhow!(
                    "publication queue invariant failed: {invariant}; durable safety fencing also failed: {fence_error}"
                ));
            }
        }
        result
    }

    fn mining_engine_fence_publication_queue(
        &self,
        invariant: &PublicationQueueInvariantError,
    ) -> Result<()> {
        let mut detail =
            format!("durable mining publication queue requires offline recovery: {invariant}");
        if detail.len() > super::MAX_PRODUCTION_SAFETY_DETAIL_BYTES {
            let mut end = super::MAX_PRODUCTION_SAFETY_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        self.state
            .chain
            .record_external_safety_fence(ProductionSafetyFence {
                version: super::PRODUCTION_SAFETY_FENCE_VERSION,
                kind: ProductionSafetyFenceKind::Storage,
                context: "mining publication queue".to_owned(),
                limit: invariant.limit,
                actual: invariant.actual,
                root: None,
                candidate: None,
                detail,
            })?;
        self.revoke_runtime_authority();
        Ok(())
    }

    fn mining_engine_install_publication_queue_index(
        &mut self,
        prepared: PublicationQueueIndex,
    ) -> Result<()> {
        let maximum = self.config.mining_engine.maximum_pending_publications;
        let result = install_publication_queue_index(&self.state.store, prepared, maximum);
        self.mining_engine_finish_publication_queue_mutation(result)
    }

    /// Recover the cancellation/crash window between durable intent staging and
    /// local candidate admission. Classification, exact authority validation,
    /// strict consensus admission, and terminal retirement all run in one
    /// canonical-writer command. The caller may relay only `Accepted`.
    fn mining_engine_recover_publication(
        &mut self,
        intent: SolvedBlockPublicationIntent,
    ) -> Result<PublicationRecovery> {
        self.state.ensure_storage_operational()?;
        if !self.config.mining_engine.enabled {
            return Ok(PublicationRecovery::Deferred {
                reason: "Mining engine is disabled".to_owned(),
            });
        }

        // A block admitted before cancellation is publishable only after its
        // active-chain binding has been authenticated, never merely because a
        // body or index record exists.
        if self
            .mining_engine_locally_accepted_record(intent.block_hash)?
            .is_some()
        {
            let durable = self.state.durable_mining_state()?;
            if issue_authority_permit(&self.config, &durable).is_none() {
                return Ok(PublicationRecovery::Deferred {
                    reason: "locally accepted block is waiting for mining authority".to_owned(),
                });
            }
            return Ok(PublicationRecovery::Accepted { warning: None });
        }

        let block = intent
            .block()
            .map_err(|error| anyhow::anyhow!("pending publication intent is corrupt: {error}"))?;
        let durable = self.state.durable_mining_state()?;
        let Some(snapshot) = durable.snapshot.as_ref() else {
            return Ok(PublicationRecovery::Deferred {
                reason: "no durable active-chain mining snapshot is available".to_owned(),
            });
        };
        let stale_reason = if intent.snapshot_generation != durable.generation {
            Some(format!(
                "intent generation {} is stale for durable generation {}",
                intent.snapshot_generation, durable.generation
            ))
        } else if block.header.prev_block != snapshot.tip.hash {
            Some("intent parent is no longer the active mining tip".to_owned())
        } else if block.header.tree_root != snapshot.next_tree_root {
            Some("intent name-tree root is stale for the active mining tip".to_owned())
        } else {
            None
        };
        if let Some(reason) = stale_reason {
            self.mining_engine_retire_publication(&intent, PublicationRetirement::Stale)?;
            return Ok(PublicationRecovery::RetiredStale { reason });
        }

        let Some(permit) = issue_authority_permit(&self.config, &durable) else {
            return Ok(PublicationRecovery::Deferred {
                reason: "current publication intent is waiting for mining authority".to_owned(),
            });
        };
        if permit.generation != intent.snapshot_generation || permit.tip != snapshot.tip.hash {
            // `issue_authority_permit` is derived from the same durable snapshot;
            // disagreement is local state corruption, not peer or candidate
            // invalidity, and therefore must fail closed rather than retire data.
            anyhow::bail!("mining authority permit disagrees with durable publication state");
        }
        let height = snapshot
            .tip
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("mining publication height overflow"))?;
        let import = NodeBlockImport::from_mining_publication(block, height);
        match self.connect_block(import) {
            Ok(record) => {
                let authenticated = self
                    .mining_engine_locally_accepted_record(intent.block_hash)?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "strict mining admission returned without an authenticated active block"
                        )
                    })?;
                if authenticated != record {
                    anyhow::bail!(
                        "strict mining admission record disagrees with canonical active state"
                    );
                }
                Ok(PublicationRecovery::Accepted { warning: None })
            }
            Err(admission_error) => {
                match self.mining_engine_locally_accepted_record(intent.block_hash) {
                    Ok(Some(_record)) => Ok(PublicationRecovery::Accepted {
                        warning: Some(format!(
                            "candidate was committed locally but post-commit processing reported: {admission_error}"
                        )),
                    }),
                    Ok(None) => {
                        // Reaching this branch with the exact durable generation,
                        // parent, tree root, and authority means strict local
                        // admission deterministically rejected the reconstructed
                        // solution. Preserve the checksummed raw intent in the
                        // bounded quarantine and remove it from automatic retry.
                        self.state.ensure_storage_operational().with_context(|| {
                            format!(
                                "strict mining admission failed and storage became unavailable: {admission_error}"
                            )
                        })?;
                        self.mining_engine_retire_publication(
                            &intent,
                            PublicationRetirement::Invalid,
                        )?;
                        Ok(PublicationRecovery::Quarantined {
                            reason: format!(
                                "strict local consensus admission rejected publication intent: {admission_error}"
                            ),
                        })
                    }
                    Err(authentication_error) => Err(anyhow::anyhow!(
                        "strict mining admission reported {admission_error}; local active-state authentication also failed: {authentication_error}"
                    )),
                }
            }
        }
    }

    fn validate_mining_engine_candidate(&self, candidate: &SolvedMiningCandidate) -> Result<()> {
        let durable = self.state.durable_mining_state()?;
        let permit = issue_authority_permit(&self.config, &durable).ok_or_else(|| {
            anyhow::anyhow!("solved-block publication requires a mining-authority permit")
        })?;
        let snapshot = durable.snapshot.as_ref().ok_or_else(|| {
            anyhow::anyhow!("authority permit exists without a durable mining snapshot")
        })?;
        if candidate.snapshot_generation() != permit.generation
            || candidate.parent_height() != snapshot.tip.height
            || candidate.block().header.prev_block != permit.tip
            || candidate.block().header.tree_root != snapshot.next_tree_root
        {
            anyhow::bail!("solved candidate is stale or not bound to the current durable snapshot");
        }
        Ok(())
    }
}

/// Runtime-facing mining reads bind immutable published generations directly;
/// consensus metadata reads and template assembly run on the configured bounded
/// worker pool without using the canonical actor as a read executor.
impl NodeReadHandle {
    /// Bind an immutable published chain/mempool pair to a stable durable
    /// generation. Consensus metadata is authenticated on the calling blocking
    /// worker; the canonical writer is never used as a read executor.
    fn mining_engine_capture_published_template_build(
        &self,
        requests: &[MiningTemplateRequest],
        require_authority: bool,
    ) -> Result<(CanonicalEpoch, CapturedTemplateBuild)> {
        let config = self.config();
        validate_template_request_set(&config.mining_engine, requests)?;
        let (
            published_epoch,
            observed_snapshot,
            authoritative_snapshot,
            mining_authoritative,
            mempool_info,
            mempool,
        ) = self.published_mining_inputs()?;
        let snapshot = if require_authority {
            if !mining_authoritative {
                anyhow::bail!("native mining authority is unavailable");
            }
            authoritative_snapshot
                .ok_or_else(|| anyhow::anyhow!("native mining snapshot is unavailable"))?
        } else {
            observed_snapshot
                .ok_or_else(|| anyhow::anyhow!("no durable mining snapshot is available"))?
        };
        validate_template_mempool_capture(&config.mining_engine, &mempool_info, &mempool)?;

        let network = config.network;
        let (durable_epoch, ()) = self.with_stable_epoch_read(|store, _headers| {
            let metadata = store
                .snapshot()
                .context("failed to snapshot mining-template consensus metadata")?;
            let consensus = template_consensus_context(&metadata, network, &snapshot)?;
            validate_template_consensus_requests(&metadata, network, &consensus, requests)
        })?;
        if durable_epoch != published_epoch
            || !self.canonical_generation_is_stable(&published_epoch)
        {
            return Err(anyhow::Error::new(CanonicalWriterError::Busy)).context(
                "mining template inputs changed while binding their published generation",
            );
        }
        Ok((published_epoch, CapturedTemplateBuild { snapshot, mempool }))
    }

    /// Derive the authoritative native job parameters from the same durable
    /// generation as the published mining and mempool snapshots.
    fn mining_engine_capture_published_native_job(
        &self,
        request: NativeMiningJobRequest,
    ) -> Result<(CanonicalEpoch, CapturedTemplateBuild, MiningTemplateRequest)> {
        let config = self.config();
        if !config.mining_engine.enabled {
            anyhow::bail!("Mining engine is disabled");
        }
        let (
            published_epoch,
            _observed_snapshot,
            authoritative_snapshot,
            mining_authoritative,
            mempool_info,
            mempool,
        ) = self.published_mining_inputs()?;
        if !mining_authoritative {
            anyhow::bail!("native mining authority is unavailable");
        }
        let snapshot = authoritative_snapshot
            .ok_or_else(|| anyhow::anyhow!("native mining snapshot is unavailable"))?;
        validate_template_mempool_capture(&config.mining_engine, &mempool_info, &mempool)?;

        let network = config.network;
        let (durable_epoch, template_request) =
            self.with_stable_epoch_read(|store, _headers| {
                let metadata = store
                    .snapshot()
                    .context("failed to snapshot native-job consensus metadata")?;
                let consensus = template_consensus_context(&metadata, network, &snapshot)?;
                let minimum_time =
                    super::current_unix_time()?.max(consensus.parent_median_time.saturating_add(1));
                let mut lookup = |hash: &BlockHash| super::load_header_record(&metadata, hash);
                let bits = super::expected_bits_with_lookup(
                    network,
                    minimum_time,
                    Some(&consensus.tip),
                    &mut lookup,
                )?;
                let template_request = MiningTemplateRequest {
                    variant: request.variant,
                    payout_address: request.payout_address,
                    coinbase_flags: request.coinbase_flags,
                    version: consensus.expected_version,
                    bits,
                    minimum_time,
                    reserved_root: request.reserved_root,
                    mask_hash: hns_primitives::blake2b_256_many([
                        snapshot.tip.hash.as_bytes().as_slice(),
                        request.mask.as_slice(),
                    ]),
                    policy: request.policy,
                };
                validate_template_request_set(
                    &config.mining_engine,
                    std::slice::from_ref(&template_request),
                )?;
                validate_template_consensus_requests(
                    &metadata,
                    network,
                    &consensus,
                    std::slice::from_ref(&template_request),
                )?;
                Ok(template_request)
            })?;
        if durable_epoch != published_epoch
            || !self.canonical_generation_is_stable(&published_epoch)
        {
            return Err(anyhow::Error::new(CanonicalWriterError::Busy))
                .context("native mining inputs changed during consensus derivation");
        }
        Ok((
            published_epoch,
            CapturedTemplateBuild { snapshot, mempool },
            template_request,
        ))
    }

    /// Validate a complete replacement off-lock, then swap it under the shared
    /// cache mutex only if the exact published generation remains current.
    fn mining_engine_install_prebuilt_templates(
        &self,
        expected: &CanonicalEpoch,
        captured: &CapturedTemplateBuild,
        templates: Vec<(u32, MiningTemplate)>,
    ) -> Result<Vec<Arc<MiningTemplate>>> {
        let maximum = self.config().mining_engine.maximum_template_variants;
        let mut replacement = TemplateCoordinator::new(maximum).map_err(|error| {
            anyhow::anyhow!("failed to initialize mining template cache: {error}")
        })?;
        let installed = replacement
            .install_prebuilt(&captured.snapshot, captured.mempool.generation(), templates)
            .map_err(|error| anyhow::anyhow!("failed to install mining templates: {error}"))?;

        let coordinator = self.template_coordinator_handle();
        let mut active = lock_template_coordinator(&coordinator);
        if !self.canonical_generation_is_stable(expected) {
            return Err(anyhow::Error::new(CanonicalWriterError::Busy))
                .context("mining template generation changed before cache installation");
        }
        *active = replacement;
        Ok(installed)
    }

    pub async fn mining_engine_diagnostics(&self) -> Result<MiningEngineDiagnostics> {
        self.ensure_storage_operational()?;
        let config = self.config();
        let published = self.published();
        let coordinator = self.template_coordinator_handle();
        let cached_template_variants = lock_template_coordinator(&coordinator).len();
        let publication_index = if config.mining_engine.enabled {
            self.mining_engine_publication_queue_index().await?
        } else {
            None
        };
        let pending_publications = publication_index
            .map(|index| usize::try_from(index.count).unwrap_or(usize::MAX))
            .unwrap_or(0);
        let can_publish = config.mining_engine.enabled && published.mining_authoritative();
        let mut blockers = Vec::new();
        if !config.mining_engine.enabled {
            blockers.push("Mining engine is disabled".to_owned());
        }
        if published.observed_mining_snapshot().is_none() {
            blockers.push("no durable active-chain mining snapshot is available".to_owned());
        }
        if !can_publish {
            blockers.push("no mining-authority permit is available".to_owned());
        }
        if config.mining_engine.enabled && publication_index.is_none() {
            blockers.push("durable publication queue index is not initialized".to_owned());
        }
        blockers.sort();
        blockers.dedup();
        Ok(MiningEngineDiagnostics {
            enabled: config.mining_engine.enabled,
            observation_only: !can_publish,
            transaction_relay_enabled: config.mining_engine.transaction_relay,
            mempool: published.mempool_info().clone(),
            maximum_template_variants: config.mining_engine.maximum_template_variants,
            template_build_workers: config.mining_engine.template_build_workers,
            template_build_queue_capacity: config.mining_engine.template_build_queue_capacity,
            cached_template_variants,
            pending_publications,
            maximum_pending_publications: config.mining_engine.maximum_pending_publications,
            publication_retry_interval_ms: u64::try_from(
                config.mining_engine.publication_retry_interval.as_millis(),
            )
            .unwrap_or(u64::MAX),
            can_build_templates: config.mining_engine.enabled
                && published.observed_mining_snapshot().is_some(),
            can_publish_solved_blocks: can_publish,
            blockers,
        })
    }

    pub async fn mining_engine_build_template(
        &self,
        request: MiningTemplateRequest,
    ) -> Result<MiningTemplate> {
        let admission = self.try_acquire_template_build_admission()?;
        let worker = self.acquire_template_build_worker().await?;
        let read = self.clone();
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let _worker = worker;
            let variant = request.variant;
            let (epoch, captured) = read.mining_engine_capture_published_template_build(
                std::slice::from_ref(&request),
                false,
            )?;
            let template = assemble_captured_template(&captured, request)?;
            let installed = read.mining_engine_install_prebuilt_templates(
                &epoch,
                &captured,
                vec![(variant, template)],
            )?;
            installed
                .into_iter()
                .next()
                .map(|template| template.as_ref().clone())
                .ok_or_else(|| anyhow::anyhow!("mining template installation returned no template"))
        })
        .await
        .context("mining template worker failed")?
    }

    pub async fn mining_engine_build_native_job(
        &self,
        request: NativeMiningJobRequest,
    ) -> Result<NativeMiningJob> {
        let admission = self.try_acquire_template_build_admission()?;
        let worker = self.acquire_template_build_worker().await?;
        let read = self.clone();
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let _worker = worker;
            let (epoch, captured, template_request) =
                read.mining_engine_capture_published_native_job(request)?;
            let variant = template_request.variant;
            let template = assemble_captured_template(&captured, template_request)?;
            let prepared = Arc::new(template.prepare_job(&captured.snapshot).map_err(|error| {
                anyhow::anyhow!("failed to prepare native mining job: {error}")
            })?);
            prepared
                .validate_for_snapshot(&captured.snapshot)
                .map_err(|error| anyhow::anyhow!("native mining job is stale: {error}"))?;
            read.mining_engine_install_prebuilt_templates(
                &epoch,
                &captured,
                vec![(variant, template)],
            )?;
            Ok(NativeMiningJob {
                snapshot: captured.snapshot,
                prepared,
            })
        })
        .await
        .context("native mining job worker failed")?
    }

    pub async fn mining_engine_prepare_cached_job(
        &self,
        key: TemplateCacheKey,
    ) -> Result<Arc<PreparedMiningJob>> {
        let admission = self.try_acquire_template_build_admission()?;
        let config = self.config();
        if !config.mining_engine.enabled {
            anyhow::bail!("Mining engine is disabled");
        }
        let (epoch, observed, _authoritative, _can_publish, mempool_info, mempool) =
            self.published_mining_inputs()?;
        let snapshot =
            observed.ok_or_else(|| anyhow::anyhow!("no durable mining snapshot is available"))?;
        validate_template_mempool_capture(&config.mining_engine, &mempool_info, &mempool)?;
        if key.snapshot_generation != snapshot.generation
            || key.mempool_generation != mempool.generation()
        {
            anyhow::bail!("cached mining template is unavailable for the published generation");
        }
        let coordinator = self.template_coordinator_handle();
        let template = {
            let cache = lock_template_coordinator(&coordinator);
            let template = cache.get(&key).ok_or_else(|| {
                anyhow::anyhow!("cached mining template is unavailable for the requested variant")
            })?;
            if !self.canonical_generation_is_stable(&epoch) {
                return Err(anyhow::Error::new(CanonicalWriterError::Busy))
                    .context("cached mining template generation changed during activation");
            }
            template
        };
        let worker = self.acquire_template_build_worker().await?;
        let read = self.clone();
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            let _worker = worker;
            let prepared = Arc::new(template.prepare_job(&snapshot).map_err(|error| {
                anyhow::anyhow!("failed to prepare cached mining job: {error}")
            })?);
            prepared
                .validate_for_snapshot(&snapshot)
                .map_err(|error| anyhow::anyhow!("cached mining job is stale: {error}"))?;
            if !read.canonical_generation_is_stable(&epoch) {
                return Err(anyhow::Error::new(CanonicalWriterError::Busy))
                    .context("cached mining template generation changed during preparation");
            }
            Ok(prepared)
        })
        .await
        .context("cached mining-job worker failed")?
    }

    async fn mining_engine_pending_publication_page(
        &self,
        cursor: MiningPublicationRetryCursor,
    ) -> Result<PublicationQueuePage> {
        self.mining_engine_ensure_publication_queue_index().await?;
        self.ensure_storage_operational()?;
        let maximum = self.config().mining_engine.maximum_pending_publications;
        let store = self.store.clone();
        let permit = Arc::clone(&self.collection_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("mining publication-read concurrency is saturated"))?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            read_publication_queue_page(&store, maximum, cursor)
        });
        let result = await_publication_blocking_worker(
            "mining publication-page read",
            PUBLICATION_RETRY_PAGE_ASYNC_MAX_ELAPSED,
            worker,
        )
        .await;
        self.ensure_storage_operational()?;
        match result {
            Ok(page) => Ok(page),
            Err(error) => {
                if let Some(invariant) = error
                    .downcast_ref::<PublicationQueueInvariantError>()
                    .cloned()
                {
                    if let Err(fence_error) = self
                        .mining_engine_fence_publication_queue_invariant(invariant.clone())
                        .await
                    {
                        return Err(anyhow::anyhow!(
                            "publication queue invariant failed: {invariant}; durable safety fencing also failed: {fence_error}"
                        ));
                    }
                }
                Err(error)
            }
        }
    }

    /// Diagnostics need only the authenticated O(1) count. They never turn a
    /// status request into publication-body decoding or a range scan.
    async fn mining_engine_publication_queue_index(&self) -> Result<Option<PublicationQueueIndex>> {
        self.ensure_storage_operational()?;
        let maximum = self.config().mining_engine.maximum_pending_publications;
        let store = self.store.clone();
        let permit = Arc::clone(&self.point_read_concurrency)
            .try_acquire_owned()
            .map_err(|_| {
                anyhow::anyhow!("mining publication point-read concurrency is saturated")
            })?;
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            load_publication_queue_index(&store, maximum)
        })
        .await
        .context("mining publication-index worker failed")?;
        self.ensure_storage_operational()?;
        match result {
            Ok(index) => Ok(index),
            Err(error) => {
                if let Some(invariant) = error
                    .downcast_ref::<PublicationQueueInvariantError>()
                    .cloned()
                {
                    if let Err(fence_error) = self
                        .mining_engine_fence_publication_queue_invariant(invariant.clone())
                        .await
                    {
                        return Err(anyhow::anyhow!(
                            "publication queue invariant failed: {invariant}; durable safety fencing also failed: {fence_error}"
                        ));
                    }
                }
                Err(error)
            }
        }
    }

    /// Enumerate and authenticate the complete bounded publication queue on a
    /// blocking collection worker. The immutable store snapshot is additionally
    /// bound to one published writer generation, so migration cannot install an
    /// index prepared across a concurrent canonical mutation.
    async fn mining_engine_enumerate_publication_queue_for_migration(
        &self,
    ) -> Result<(super::CanonicalEpoch, PublicationQueueInventory)> {
        self.ensure_storage_operational()?;
        let maximum = self.config().mining_engine.maximum_pending_publications;
        let read = self.clone();
        let permit = Arc::clone(&self.collection_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("mining publication-read concurrency is saturated"))?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            read.with_stable_epoch_read(|store, _headers| {
                enumerate_publication_queue(store, maximum)
            })
        });
        let result = await_publication_blocking_worker(
            "mining publication migration scan",
            PUBLICATION_QUEUE_SCAN_ASYNC_MAX_ELAPSED,
            worker,
        )
        .await;
        self.ensure_storage_operational()?;
        match result {
            Ok(inventory) => Ok(inventory),
            Err(error) => {
                if let Some(invariant) = error
                    .downcast_ref::<PublicationQueueInvariantError>()
                    .cloned()
                {
                    if let Err(fence_error) = self
                        .mining_engine_fence_publication_queue_invariant(invariant.clone())
                        .await
                    {
                        return Err(anyhow::anyhow!(
                            "publication queue invariant failed: {invariant}; durable safety fencing also failed: {fence_error}"
                        ));
                    }
                }
                Err(error)
            }
        }
    }

    /// Authenticate the complete bounded publication queue from its own
    /// immutable storage snapshot. This deliberately does not bind unrelated
    /// canonical publication sequence traffic to the audit result.
    async fn mining_engine_audit_publication_queue(&self) -> Result<PublicationQueueInventory> {
        self.ensure_storage_operational()?;
        let maximum = self.config().mining_engine.maximum_pending_publications;
        let store = self.store.clone();
        let permit = Arc::clone(&self.collection_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("mining publication-read concurrency is saturated"))?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            enumerate_publication_queue(&store, maximum)
        });
        let result = await_publication_blocking_worker(
            "mining publication queue audit",
            PUBLICATION_QUEUE_SCAN_ASYNC_MAX_ELAPSED,
            worker,
        )
        .await;
        self.ensure_storage_operational()?;
        match result {
            Ok(inventory) => Ok(inventory),
            Err(error) => {
                if let Some(invariant) = error
                    .downcast_ref::<PublicationQueueInvariantError>()
                    .cloned()
                {
                    if let Err(fence_error) = self
                        .mining_engine_fence_publication_queue_invariant(invariant.clone())
                        .await
                    {
                        return Err(anyhow::anyhow!(
                            "publication queue invariant failed: {invariant}; durable safety fencing also failed: {fence_error}"
                        ));
                    }
                }
                Err(error)
            }
        }
    }

    /// Install the versioned count/revision index only from a fully enumerated
    /// immutable snapshot. A competing canonical command invalidates the exact
    /// epoch and causes a bounded re-enumeration rather than committing stale
    /// counts.
    async fn mining_engine_ensure_publication_queue_index(&self) -> Result<()> {
        const MAX_MIGRATION_ATTEMPTS: usize = 3;
        if self
            .mining_engine_publication_queue_index()
            .await?
            .is_some()
        {
            return Ok(());
        }
        for _attempt in 0..MAX_MIGRATION_ATTEMPTS {
            let (epoch, inventory) = self
                .mining_engine_enumerate_publication_queue_for_migration()
                .await?;
            if inventory.persisted_index {
                return Ok(());
            }
            let runtime = self
                .runtime
                .upgrade()
                .ok_or_else(|| anyhow::Error::new(CanonicalWriterError::Stopped))?;
            let writer = CanonicalStateWriter { inner: runtime };
            let prepared = inventory.index;
            match writer
                .execute_at(
                    epoch,
                    "initialize mining publication queue index",
                    move |node| node.mining_engine_install_publication_queue_index(prepared),
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(error)
                    if matches!(
                        error.downcast_ref::<CanonicalWriterError>(),
                        Some(CanonicalWriterError::StaleEpoch { .. } | CanonicalWriterError::Busy)
                    ) =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(anyhow::Error::new(CanonicalWriterError::Busy))
            .context("publication queue migration could not capture a stable writer generation")
    }

    async fn mining_engine_fence_publication_queue_invariant(
        &self,
        invariant: PublicationQueueInvariantError,
    ) -> Result<()> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| anyhow::Error::new(CanonicalWriterError::Stopped))?;
        CanonicalStateWriter { inner: runtime }
            .execute(
                None,
                "fence corrupt mining publication queue",
                move |node| node.mining_engine_fence_publication_queue(&invariant),
            )
            .await
    }

    pub async fn mining_engine_locally_accepted_record(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<BlockIndexRecord>> {
        self.ensure_storage_operational()?;
        let permit = Arc::clone(&self.point_read_concurrency)
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(CanonicalWriterError::Busy))?;
        let read = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            read.with_stable_read(|store, _headers| {
                let snapshot = store
                    .snapshot()
                    .context("failed to snapshot mining candidate active state")?;
                mining_engine_locally_accepted_record_from_snapshot(&snapshot, block_hash)
            })
        })
        .await
        .context("mining candidate active-record worker failed")?
    }
}

/// Named mutation surface for MeshMine and the native P2P runtime. Every
/// operation is admitted to the bounded canonical writer; callers never obtain
/// mutable node state.
impl CanonicalStateWriter {
    pub async fn mining_engine_accept_peer_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<hns_mempool::Admission> {
        self.execute(None, "admit peer mempool transaction", move |node| {
            node.mining_engine_accept_peer_transaction(transaction)
        })
        .await
    }

    pub async fn mining_engine_accept_peer_claim(&self, claim: Claim) -> Result<ClaimAdmission> {
        self.execute(None, "admit peer mempool claim", move |node| {
            node.mining_engine_accept_peer_claim(claim)
        })
        .await
    }

    pub async fn mining_engine_accept_peer_airdrop(
        &self,
        proof: AirdropProof,
    ) -> Result<AirdropAdmission> {
        self.execute(None, "admit peer mempool airdrop", move |node| {
            node.mining_engine_accept_peer_airdrop(proof)
        })
        .await
    }

    pub async fn mining_engine_stage_publication(
        &self,
        read: &NodeReadHandle,
        expected: CanonicalChainEpoch,
        candidate: SolvedMiningCandidate,
        created_at: u64,
    ) -> Result<SolvedBlockPublicationIntent> {
        read.mining_engine_ensure_publication_queue_index().await?;
        self.execute_at_chain(expected, "stage solved mining publication", move |node| {
            node.mining_engine_stage_publication(&candidate, created_at)
        })
        .await
    }

    pub async fn mining_engine_submit_solved_candidate(
        &self,
        expected: CanonicalChainEpoch,
        candidate: SolvedMiningCandidate,
    ) -> Result<BlockIndexRecord> {
        self.execute_at_chain(expected, "connect solved mining candidate", move |node| {
            node.submit_mining_candidate(candidate)
        })
        .await
    }

    pub async fn mining_engine_complete_publication(&self, block_hash: BlockHash) -> Result<()> {
        self.execute(None, "complete solved mining publication", move |node| {
            node.mining_engine_complete_publication(block_hash)
        })
        .await
    }

    /// Recover and retry durable intents without ever treating network fan-out
    /// as consensus admission. A cancellation before local admission resumes
    /// the same strict mining-source path under one exact writer epoch. Stale
    /// intents are retired and deterministic admission failures are quarantined,
    /// so neither class can loop forever. An accepted intent is deleted only
    /// after at least one ready peer completes its critical socket write.
    pub async fn mining_engine_retry_pending_publications(
        &self,
        read: &NodeReadHandle,
        peers: &LivePeerManager,
        cursor: MiningPublicationRetryCursor,
    ) -> Result<MiningPublicationRetryBatch> {
        let mut page = read.mining_engine_pending_publication_page(cursor).await?;
        let intents = std::mem::take(&mut page.intents);
        let record_bytes = std::mem::take(&mut page.record_bytes);
        let decoded_records = intents.len();
        let decoded_bytes = page.decoded_bytes;
        let mut attempts = Vec::with_capacity(decoded_records);
        let mut deleted_record_bytes = Vec::new();
        for (intent, record_bytes) in intents.into_iter().zip(record_bytes) {
            let expected = read.stable_canonical_epoch()?.chain();
            let recovery_intent = intent.clone();
            let recovery = self
                .execute_at_chain(expected, "recover solved mining publication", move |node| {
                    node.mining_engine_recover_publication(recovery_intent)
                })
                .await?;
            let local_warning = match recovery {
                PublicationRecovery::Accepted { warning } => warning,
                PublicationRecovery::Deferred { reason } => {
                    attempts.push(MiningPublicationAttempt {
                        block_hash: intent.block_hash,
                        failures: vec![format!("local publication deferred: {reason}")],
                        ..MiningPublicationAttempt::default()
                    });
                    continue;
                }
                PublicationRecovery::RetiredStale { reason } => {
                    deleted_record_bytes.push(record_bytes);
                    attempts.push(MiningPublicationAttempt {
                        block_hash: intent.block_hash,
                        failures: vec![format!("stale publication intent retired: {reason}")],
                        ..MiningPublicationAttempt::default()
                    });
                    continue;
                }
                PublicationRecovery::Quarantined { reason } => {
                    deleted_record_bytes.push(record_bytes);
                    attempts.push(MiningPublicationAttempt {
                        block_hash: intent.block_hash,
                        failures: vec![format!("publication intent quarantined: {reason}")],
                        ..MiningPublicationAttempt::default()
                    });
                    continue;
                }
            };
            let block = intent.block().map_err(|error| {
                anyhow::anyhow!("pending publication intent is corrupt: {error}")
            })?;
            let report = peers
                .broadcast_critical_parallel(Arc::new(Packet::Block(block)))
                .await;
            let mut attempt = MiningPublicationAttempt::from_report(intent.block_hash, report);
            if let Some(warning) = local_warning {
                attempt
                    .failures
                    .push(format!("local admission warning: {warning}"));
            }
            if attempt.written_peers > 0 {
                self.mining_engine_complete_publication(intent.block_hash)
                    .await?;
                deleted_record_bytes.push(record_bytes);
            }
            attempts.push(attempt);
        }
        let Some(final_index) = read.mining_engine_publication_queue_index().await? else {
            let invariant = PublicationQueueInvariantError {
                detail: "publication queue index disappeared after retry mutations".to_owned(),
                limit: 1,
                actual: 0,
            };
            read.mining_engine_fence_publication_queue_invariant(invariant.clone())
                .await?;
            return Err(anyhow::Error::new(invariant));
        };
        let (next_cursor, interleaved_rebase) =
            match reconcile_publication_retry_cursor(&page, &deleted_record_bytes, final_index) {
                Ok(reconciled) => reconciled,
                Err(error) => {
                    if let Some(invariant) = error
                        .downcast_ref::<PublicationQueueInvariantError>()
                        .cloned()
                    {
                        read.mining_engine_fence_publication_queue_invariant(invariant)
                            .await?;
                    }
                    return Err(error);
                }
            };
        let audit_boundary = page.completed_cycle || page.forced_wrap;
        let mut queue_revision = final_index.revision;
        let mut completed_cycle = false;
        let mut audit_restarted = page.audit_restarted || interleaved_rebase;
        if audit_boundary {
            // A cursor crosses fresh snapshots and is therefore never trusted as
            // an aggregate proof. Authenticate count and bytes by enumerating
            // the current queue once from a single immutable snapshot at the
            // traversal boundary, then re-read its index to establish a
            // linearization point after that audit.
            let audit = read.mining_engine_audit_publication_queue().await?;
            if !audit.persisted_index {
                let invariant = PublicationQueueInvariantError {
                    detail: "publication queue index disappeared before completed-cycle audit"
                        .to_owned(),
                    limit: 1,
                    actual: 0,
                };
                read.mining_engine_fence_publication_queue_invariant(invariant.clone())
                    .await?;
                return Err(anyhow::Error::new(invariant));
            }
            let Some(post_audit_index) = read.mining_engine_publication_queue_index().await? else {
                let invariant = PublicationQueueInvariantError {
                    detail: "publication queue index disappeared after completed-cycle audit"
                        .to_owned(),
                    limit: 1,
                    actual: 0,
                };
                read.mining_engine_fence_publication_queue_invariant(invariant.clone())
                    .await?;
                return Err(anyhow::Error::new(invariant));
            };
            queue_revision = post_audit_index.revision;
            completed_cycle = publication_retry_cycle_is_complete(
                &page,
                interleaved_rebase,
                final_index,
                &audit,
                post_audit_index,
            );
            audit_restarted |= !completed_cycle;
        }
        Ok(MiningPublicationRetryBatch {
            attempts,
            next_cursor,
            completed_cycle,
            audit_restarted,
            queue_revision,
            decoded_records,
            decoded_bytes,
        })
    }

    /// Local-first solved-candidate transaction for the runtime architecture.
    /// The durable intent and consensus admission are serialized by this
    /// writer; only the already accepted block is then fanned out in parallel.
    pub async fn mining_engine_publish_solved_candidate(
        &self,
        read: &NodeReadHandle,
        candidate: SolvedMiningCandidate,
        peers: &LivePeerManager,
        created_at: u64,
    ) -> Result<MiningPublicationResult> {
        let expected = read.stable_canonical_epoch()?.chain();
        let intent = self
            .mining_engine_stage_publication(read, expected.clone(), candidate.clone(), created_at)
            .await?;
        let mut local_admission_warning = None;
        let connected = match read
            .mining_engine_locally_accepted_record(intent.block_hash)
            .await?
        {
            Some(record) => record,
            None => match self
                .mining_engine_submit_solved_candidate(expected, candidate)
                .await
            {
                Ok(record) => record,
                Err(error) => {
                    if let Some(record) = read
                        .mining_engine_locally_accepted_record(intent.block_hash)
                        .await?
                    {
                        local_admission_warning = Some(format!(
                            "candidate was committed locally but post-commit processing reported: {error}"
                        ));
                        record
                    } else {
                        let cleanup = self
                            .mining_engine_complete_publication(intent.block_hash)
                            .await;
                        return match cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup_error) => Err(anyhow::anyhow!(
                                "solved candidate failed local admission: {error}; publication-intent cleanup also failed: {cleanup_error}"
                            )),
                        };
                    }
                }
            },
        };
        let block = intent
            .block()
            .map_err(|error| anyhow::anyhow!("publication intent block failed: {error}"))?;
        let report = peers
            .broadcast_critical_parallel(Arc::new(Packet::Block(block)))
            .await;
        let attempt = MiningPublicationAttempt::from_report(intent.block_hash, report);
        let publication_pending = attempt.written_peers == 0;
        if !publication_pending {
            self.mining_engine_complete_publication(intent.block_hash)
                .await?;
        }
        Ok(MiningPublicationResult {
            attempt,
            connected,
            local_admission_warning,
            publication_pending,
        })
    }
}

fn publication_intent_key(block_hash: BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(PUBLICATION_KEY_PREFIX.len() + 32);
    key.extend_from_slice(PUBLICATION_KEY_PREFIX);
    key.extend_from_slice(block_hash.as_bytes());
    key
}

fn publication_record_bytes(key: &[u8], encoded: &[u8]) -> Result<u64> {
    if key.len() != PUBLICATION_INTENT_KEY_BYTES
        || !key.starts_with(PUBLICATION_KEY_PREFIX)
        || encoded.len() > PUBLICATION_INTENT_MAX_ENCODED_BYTES
    {
        return Err(publication_queue_invariant(
            "publication intent exceeds its key/value envelope",
            u64::try_from(PUBLICATION_INTENT_KEY_BYTES + PUBLICATION_INTENT_MAX_ENCODED_BYTES)
                .unwrap_or(u64::MAX),
            u64::try_from(key.len().saturating_add(encoded.len())).unwrap_or(u64::MAX),
        ));
    }
    u64::try_from(key.len().saturating_add(encoded.len())).map_err(|_| {
        publication_queue_invariant(
            "publication intent storage byte count overflows u64",
            PUBLICATION_QUEUE_MAX_BYTES,
            u64::MAX,
        )
    })
}

fn decode_publication_record(
    key: &[u8],
    value: &[u8],
) -> Result<(SolvedBlockPublicationIntent, u64)> {
    if key.len() != PUBLICATION_INTENT_KEY_BYTES || !key.starts_with(PUBLICATION_KEY_PREFIX) {
        return Err(publication_queue_invariant(
            "publication queue contains a malformed key",
            PUBLICATION_INTENT_KEY_BYTES as u64,
            u64::try_from(key.len()).unwrap_or(u64::MAX),
        ));
    }
    let intent = SolvedBlockPublicationIntent::decode(value).map_err(|error| {
        publication_queue_invariant(format!("invalid publication intent: {error}"), 1, 0)
    })?;
    if key != intent.storage_key() {
        return Err(publication_queue_invariant(
            "publication intent key does not match its block hash",
            1,
            0,
        ));
    }
    if intent.encode() != value {
        return Err(publication_queue_invariant(
            "publication intent is not canonically encoded",
            1,
            0,
        ));
    }
    let record_bytes = publication_record_bytes(key, value)?;
    Ok((intent, record_bytes))
}

fn load_publication_queue_index_from<T: ReadSnapshot>(
    snapshot: &T,
    maximum: usize,
) -> Result<Option<PublicationQueueIndex>> {
    snapshot
        .get(ColumnFamily::Snapshots, PUBLICATION_QUEUE_INDEX_KEY)
        .context("failed to read publication queue index")?
        .map(|encoded| PublicationQueueIndex::decode(&encoded, maximum))
        .transpose()
}

fn load_publication_queue_index(
    store: &StoreHandle,
    maximum: usize,
) -> Result<Option<PublicationQueueIndex>> {
    let snapshot = store
        .snapshot()
        .context("failed to open publication queue index snapshot")?;
    load_publication_queue_index_from(&snapshot, maximum)
}

fn require_publication_queue_index<T: ReadSnapshot>(
    snapshot: &T,
    maximum: usize,
) -> Result<PublicationQueueIndex> {
    load_publication_queue_index_from(snapshot, maximum)?.ok_or_else(|| {
        publication_queue_invariant(
            "durable publication queue index disappeared after runtime initialization",
            1,
            0,
        )
    })
}

fn install_publication_queue_index(
    store: &StoreHandle,
    prepared: PublicationQueueIndex,
    maximum: usize,
) -> Result<()> {
    prepared.validate(maximum)?;
    let snapshot = store
        .snapshot()
        .context("failed to open publication index installation snapshot")?;
    if let Some(existing) = load_publication_queue_index_from(&snapshot, maximum)? {
        if existing != prepared {
            return Err(publication_queue_invariant(
                "publication queue index changed during migration",
                prepared.revision,
                existing.revision,
            ));
        }
        return Ok(());
    }
    drop(snapshot);
    let mut batch = store.batch();
    batch
        .put(
            ColumnFamily::Snapshots,
            PUBLICATION_QUEUE_INDEX_KEY,
            &prepared.encode(),
        )
        .context("failed to stage publication queue index migration")?;
    commit_publication_queue_batch(store, batch, "publication queue index migration")
}

fn stage_publication_intent(
    store: &StoreHandle,
    intent: &SolvedBlockPublicationIntent,
    maximum: usize,
) -> Result<()> {
    let key = publication_intent_key(intent.block_hash);
    let encoded = intent.encode();
    let record_bytes = publication_record_bytes(&key, &encoded)?;
    let snapshot = store
        .snapshot()
        .context("failed to open publication staging snapshot")?;
    let index = require_publication_queue_index(&snapshot, maximum)?;
    if let Some(current) = snapshot
        .get(ColumnFamily::Snapshots, &key)
        .context("failed to read existing publication intent")?
    {
        let decoded = SolvedBlockPublicationIntent::decode(&current).map_err(|error| {
            publication_queue_invariant(
                format!("existing publication intent is corrupt: {error}"),
                1,
                0,
            )
        })?;
        if decoded == *intent && current == encoded {
            return Ok(());
        }
        return Err(publication_queue_invariant(
            "publication intent conflicts with an existing block-hash key",
            1,
            2,
        ));
    }
    if index.count >= u64::try_from(maximum).unwrap_or(u64::MAX) {
        anyhow::bail!("pending solved-block publication capacity is exhausted");
    }
    let next = index.inserted(record_bytes, maximum)?;
    drop(snapshot);

    let mut batch = store.batch();
    batch
        .put(ColumnFamily::Snapshots, &key, &encoded)
        .context("failed to stage solved-block publication intent")?;
    batch
        .put(
            ColumnFamily::Snapshots,
            PUBLICATION_QUEUE_INDEX_KEY,
            &next.encode(),
        )
        .context("failed to stage publication queue index update")?;
    commit_publication_queue_batch(store, batch, "solved-block publication staging")
}

fn delete_publication_intent(
    store: &StoreHandle,
    block_hash: BlockHash,
    maximum: usize,
) -> Result<()> {
    let key = publication_intent_key(block_hash);
    let snapshot = store
        .snapshot()
        .context("failed to open publication deletion snapshot")?;
    let index = require_publication_queue_index(&snapshot, maximum)?;
    let Some(encoded) = snapshot
        .get(ColumnFamily::Snapshots, &key)
        .context("failed to read publication intent for deletion")?
    else {
        return Ok(());
    };
    let intent = SolvedBlockPublicationIntent::decode(&encoded).map_err(|error| {
        publication_queue_invariant(
            format!("publication intent selected for deletion is corrupt: {error}"),
            1,
            0,
        )
    })?;
    if intent.block_hash != block_hash || intent.storage_key() != key {
        return Err(publication_queue_invariant(
            "publication deletion key does not match its intent",
            1,
            0,
        ));
    }
    let next = index.deleted(publication_record_bytes(&key, &encoded)?, maximum)?;
    drop(snapshot);

    let mut batch = store.batch();
    batch
        .delete(ColumnFamily::Snapshots, &key)
        .context("failed to stage publication-intent deletion")?;
    batch
        .put(
            ColumnFamily::Snapshots,
            PUBLICATION_QUEUE_INDEX_KEY,
            &next.encode(),
        )
        .context("failed to stage publication queue deletion index")?;
    commit_publication_queue_batch(store, batch, "publication-intent deletion")
}

fn publication_quarantine_key(block_hash: BlockHash) -> Vec<u8> {
    let bytes = block_hash.as_bytes();
    let slot = usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) % PUBLICATION_QUARANTINE_SLOTS;
    let slot = u16::try_from(slot).expect("publication quarantine slot is bounded by u16");
    let mut key = Vec::with_capacity(PUBLICATION_QUARANTINE_KEY_PREFIX.len() + 2);
    key.extend_from_slice(PUBLICATION_QUARANTINE_KEY_PREFIX);
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

fn retire_publication_intent(
    store: &StoreHandle,
    intent: &SolvedBlockPublicationIntent,
    retirement: PublicationRetirement,
    maximum: usize,
) -> Result<()> {
    let live_key = publication_intent_key(intent.block_hash);
    let encoded = intent.encode();
    if encoded.len() > PUBLICATION_QUARANTINE_MAX_ENTRY_BYTES {
        anyhow::bail!(
            "publication intent contains {} bytes, exceeding quarantine entry bound {} ({} slots, {} aggregate bytes)",
            encoded.len(),
            PUBLICATION_QUARANTINE_MAX_ENTRY_BYTES,
            PUBLICATION_QUARANTINE_SLOTS,
            PUBLICATION_QUARANTINE_MAX_BYTES
        );
    }
    let snapshot = store
        .snapshot()
        .context("failed to open publication retirement snapshot")?;
    let index = require_publication_queue_index(&snapshot, maximum)?;
    let Some(current) = snapshot
        .get(ColumnFamily::Snapshots, &live_key)
        .context("failed to authenticate live publication intent")?
    else {
        // A retry after a definitely acknowledged retirement is idempotent.
        return Ok(());
    };
    let current_intent = SolvedBlockPublicationIntent::decode(&current).map_err(|error| {
        publication_queue_invariant(format!("live publication intent is corrupt: {error}"), 1, 0)
    })?;
    if current_intent != *intent || current != encoded {
        return Err(publication_queue_invariant(
            "live publication intent changed before terminal retirement",
            1,
            2,
        ));
    }
    let next = index.deleted(publication_record_bytes(&live_key, &current)?, maximum)?;
    drop(snapshot);

    let mut batch = store.batch();
    if retirement == PublicationRetirement::Invalid {
        // The value retains hns-mining's checksum and commits to the exact raw
        // block. The fixed slot derived from that committed block hash bounds
        // quarantine cardinality without an in-writer range scan.
        batch
            .put(
                ColumnFamily::Snapshots,
                &publication_quarantine_key(intent.block_hash),
                &encoded,
            )
            .context("failed to stage publication quarantine")?;
    }
    batch
        .delete(ColumnFamily::Snapshots, &live_key)
        .context("failed to stage terminal publication retirement")?;
    batch
        .put(
            ColumnFamily::Snapshots,
            PUBLICATION_QUEUE_INDEX_KEY,
            &next.encode(),
        )
        .context("failed to stage terminal publication index update")?;
    commit_publication_queue_batch(store, batch, "terminal publication retirement")
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationQueueCommitFault {
    None = 0,
    BeforeCommit = 1,
    AfterCommit = 2,
}

#[cfg(test)]
#[derive(Debug)]
struct InjectedPublicationQueueCommitAmbiguity;

#[cfg(test)]
impl std::fmt::Display for InjectedPublicationQueueCommitAmbiguity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("injected publication queue ambiguity after atomic commit")
    }
}

#[cfg(test)]
impl std::error::Error for InjectedPublicationQueueCommitAmbiguity {}

#[cfg(test)]
std::thread_local! {
    static PUBLICATION_QUEUE_COMMIT_FAULT: std::cell::Cell<u8> = const {
        std::cell::Cell::new(PublicationQueueCommitFault::None as u8)
    };
}

#[cfg(test)]
fn inject_publication_queue_commit_fault(fault: PublicationQueueCommitFault) {
    PUBLICATION_QUEUE_COMMIT_FAULT.with(|configured| configured.set(fault as u8));
}

#[cfg(test)]
fn take_publication_queue_commit_fault() -> PublicationQueueCommitFault {
    PUBLICATION_QUEUE_COMMIT_FAULT.with(|configured| match configured.replace(0) {
        1 => PublicationQueueCommitFault::BeforeCommit,
        2 => PublicationQueueCommitFault::AfterCommit,
        _ => PublicationQueueCommitFault::None,
    })
}

fn commit_publication_queue_batch(
    store: &StoreHandle,
    batch: hns_store::StoreHandleBatch,
    context: &'static str,
) -> Result<()> {
    #[cfg(test)]
    let fault = take_publication_queue_commit_fault();
    #[cfg(test)]
    if fault == PublicationQueueCommitFault::BeforeCommit {
        anyhow::bail!("injected publication queue failure before atomic commit");
    }
    store
        .commit(batch)
        .with_context(|| format!("failed to commit {context}"))?;
    #[cfg(test)]
    if fault == PublicationQueueCommitFault::AfterCommit {
        return Err(anyhow::Error::new(InjectedPublicationQueueCommitAmbiguity));
    }
    Ok(())
}

#[cfg(test)]
fn load_quarantined_publication(
    store: &StoreHandle,
    block_hash: BlockHash,
) -> Result<Option<SolvedBlockPublicationIntent>> {
    let snapshot = store.snapshot()?;
    let Some(encoded) = snapshot.get(
        ColumnFamily::Snapshots,
        &publication_quarantine_key(block_hash),
    )?
    else {
        return Ok(None);
    };
    let intent = SolvedBlockPublicationIntent::decode(&encoded)
        .map_err(|error| anyhow::anyhow!("invalid checksummed quarantine entry: {error}"))?;
    if intent.block_hash != block_hash {
        return Ok(None);
    }
    Ok(Some(intent))
}

fn read_publication_queue_page(
    store: &StoreHandle,
    maximum: usize,
    cursor: MiningPublicationRetryCursor,
) -> Result<PublicationQueuePage> {
    let maximum_pages = publication_retry_page_budget(maximum)?;
    cursor.validate(maximum_pages)?;
    if PUBLICATION_RETRY_PAGE_ENTRIES > PREFIX_SCAN_MAX_ENTRIES
        || PUBLICATION_RETRY_PAGE_MAX_BYTES > PREFIX_SCAN_MAX_BYTES
    {
        anyhow::bail!("publication retry page exceeds the storage cursor envelope");
    }
    let started = Instant::now();
    let deadline = started
        .checked_add(PUBLICATION_RETRY_PAGE_MAX_ELAPSED)
        .unwrap_or(started);
    let snapshot = store
        .snapshot()
        .context("failed to open publication retry snapshot")?;
    let encoded_index = snapshot
        .get(ColumnFamily::Snapshots, PUBLICATION_QUEUE_INDEX_KEY)
        .context("failed to capture publication retry revision")?
        .ok_or_else(|| {
            publication_queue_invariant(
                "publication queue index disappeared before retry pagination",
                1,
                0,
            )
        })?;
    let index = PublicationQueueIndex::decode(&encoded_index, maximum)?;

    // A revision change cannot invalidate hash-order progress. Continuing from
    // the last returned key prevents sustained, legitimate queue mutations from
    // repeatedly forcing page zero and starving higher keys. Insertions behind
    // the cursor are picked up after the deterministic tail wrap.
    let revision_changed = cursor
        .revision
        .is_some_and(|revision| revision != index.revision);
    let page_budget = cursor.remaining_pages.unwrap_or(maximum_pages);
    let start_after = cursor.after.map(publication_intent_key);
    let page = snapshot
        .scan_prefix_page(
            ColumnFamily::Snapshots,
            PUBLICATION_KEY_PREFIX,
            start_after.as_deref(),
            PrefixScanBudget {
                max_entries: PUBLICATION_RETRY_PAGE_ENTRIES,
                max_bytes: PUBLICATION_RETRY_PAGE_MAX_BYTES,
            },
        )
        .context("failed to read bounded publication retry page")?;
    if page.entries.is_empty() && page.continuation.is_some() {
        return Err(publication_queue_invariant(
            "publication retry pagination made no progress",
            1,
            0,
        ));
    }

    if Instant::now() >= deadline {
        anyhow::bail!(
            "publication retry page exceeded its {} ms deadline",
            PUBLICATION_RETRY_PAGE_MAX_ELAPSED.as_millis()
        );
    }

    let mut intents = Vec::with_capacity(page.entries.len());
    let mut intent_record_bytes = Vec::with_capacity(page.entries.len());
    let mut decoded_bytes = 0u64;
    let mut previous_key = start_after;
    for (key, value) in page.entries {
        if previous_key
            .as_ref()
            .is_some_and(|previous| key <= *previous)
        {
            return Err(publication_queue_invariant(
                "publication retry keys are not strictly ordered",
                1,
                0,
            ));
        }
        let (intent, record_bytes) = decode_publication_record(&key, &value)?;
        decoded_bytes = decoded_bytes.checked_add(record_bytes).ok_or_else(|| {
            publication_queue_invariant(
                "publication retry byte count overflow",
                u64::try_from(PUBLICATION_RETRY_PAGE_MAX_BYTES).unwrap_or(u64::MAX),
                u64::MAX,
            )
        })?;
        if decoded_bytes > u64::try_from(PUBLICATION_RETRY_PAGE_MAX_BYTES).unwrap_or(u64::MAX) {
            return Err(publication_queue_invariant(
                "publication retry page exceeds its decoded-byte bound",
                u64::try_from(PUBLICATION_RETRY_PAGE_MAX_BYTES).unwrap_or(u64::MAX),
                decoded_bytes,
            ));
        }
        intents.push(intent);
        intent_record_bytes.push(record_bytes);
        previous_key = Some(key);
        if Instant::now() >= deadline {
            anyhow::bail!(
                "publication retry page exceeded its {} ms deadline",
                PUBLICATION_RETRY_PAGE_MAX_ELAPSED.as_millis()
            );
        }
    }
    if intents.len() > PUBLICATION_RETRY_PAGE_ENTRIES {
        return Err(publication_queue_invariant(
            "publication retry page exceeds its record bound",
            PUBLICATION_RETRY_PAGE_ENTRIES as u64,
            u64::try_from(intents.len()).unwrap_or(u64::MAX),
        ));
    }
    let decoded_records = u64::try_from(intents.len()).unwrap_or(u64::MAX);
    if decoded_records > index.count {
        return Err(publication_queue_invariant(
            "publication retry page exceeds the durable indexed count",
            index.count,
            decoded_records,
        ));
    }
    if decoded_bytes > index.total_bytes {
        return Err(publication_queue_invariant(
            "publication retry page exceeds the durable indexed bytes",
            index.total_bytes,
            decoded_bytes,
        ));
    }
    let continuation = page.continuation;
    if let Some(next) = continuation.as_ref() {
        if previous_key.as_ref() != Some(next) || !next.starts_with(PUBLICATION_KEY_PREFIX) {
            return Err(publication_queue_invariant(
                "publication retry continuation is not the last verified key",
                1,
                0,
            ));
        }
    }
    let encoded_index_after = snapshot
        .get(ColumnFamily::Snapshots, PUBLICATION_QUEUE_INDEX_KEY)
        .context("failed to recapture publication retry revision")?;
    if encoded_index_after.as_deref() != Some(encoded_index.as_slice()) {
        return Err(publication_queue_invariant(
            "publication retry revision changed within an immutable snapshot",
            index.revision,
            0,
        ));
    }

    let completed_cycle = continuation.is_none();
    let forced_wrap = continuation.is_some() && page_budget == 1;
    let next_cursor = match continuation {
        Some(_) if !forced_wrap => {
            let after = intents
                .last()
                .map(|intent| intent.block_hash)
                .ok_or_else(|| {
                    publication_queue_invariant(
                        "publication retry continuation has no verified record",
                        1,
                        0,
                    )
                })?;
            MiningPublicationRetryCursor::new(
                Some(after),
                Some(index.revision),
                Some(page_budget - 1),
            )
        }
        Some(_) | None => MiningPublicationRetryCursor::default(),
    };
    Ok(PublicationQueuePage {
        intents,
        record_bytes: intent_record_bytes,
        next_cursor,
        completed_cycle,
        forced_wrap,
        audit_restarted: revision_changed || forced_wrap,
        revision: index.revision,
        indexed_count: index.count,
        indexed_bytes: index.total_bytes,
        decoded_bytes,
    })
}

fn reconcile_publication_retry_cursor(
    page: &PublicationQueuePage,
    deleted_record_bytes: &[u64],
    final_index: PublicationQueueIndex,
) -> Result<(MiningPublicationRetryCursor, bool)> {
    if deleted_record_bytes.len() > page.record_bytes.len() {
        return Err(publication_queue_invariant(
            "publication retry accounted more deletions than decoded records",
            u64::try_from(page.record_bytes.len()).unwrap_or(u64::MAX),
            u64::try_from(deleted_record_bytes.len()).unwrap_or(u64::MAX),
        ));
    }
    let deleted_records = u64::try_from(deleted_record_bytes.len()).unwrap_or(u64::MAX);
    let deleted_bytes = deleted_record_bytes.iter().try_fold(0u64, |total, bytes| {
        total.checked_add(*bytes).ok_or_else(|| {
            publication_queue_invariant(
                "publication retry deleted-byte count overflow",
                page.indexed_bytes,
                u64::MAX,
            )
        })
    })?;
    let expected_revision = page.revision.checked_add(deleted_records).ok_or_else(|| {
        publication_queue_invariant(
            "publication retry expected revision overflow",
            u64::MAX - deleted_records,
            page.revision,
        )
    })?;
    let expected_count = page
        .indexed_count
        .checked_sub(deleted_records)
        .ok_or_else(|| {
            publication_queue_invariant(
                "publication retry expected count underflow",
                page.indexed_count,
                deleted_records,
            )
        })?;
    let expected_bytes = page
        .indexed_bytes
        .checked_sub(deleted_bytes)
        .ok_or_else(|| {
            publication_queue_invariant(
                "publication retry expected bytes underflow",
                page.indexed_bytes,
                deleted_bytes,
            )
        })?;
    let interleaved = expected_revision != final_index.revision
        || expected_count != final_index.count
        || expected_bytes != final_index.total_bytes;
    if page.completed_cycle || page.forced_wrap {
        return Ok((MiningPublicationRetryCursor::default(), interleaved));
    }
    let after = page.next_cursor.after.ok_or_else(|| {
        publication_queue_invariant(
            "non-terminal publication retry page lost its continuation",
            1,
            0,
        )
    })?;
    let remaining_pages = page.next_cursor.remaining_pages.ok_or_else(|| {
        publication_queue_invariant(
            "non-terminal publication retry page lost its traversal budget",
            1,
            0,
        )
    })?;
    // Rebase onto the latest authenticated revision without moving backward.
    // This is traversal state only; the independent tail audit provides the
    // exact queue proof.
    Ok((
        MiningPublicationRetryCursor::new(
            Some(after),
            Some(final_index.revision),
            Some(remaining_pages),
        ),
        interleaved,
    ))
}

fn publication_retry_cycle_is_complete(
    page: &PublicationQueuePage,
    interleaved_rebase: bool,
    final_index: PublicationQueueIndex,
    audit: &PublicationQueueInventory,
    post_audit_index: PublicationQueueIndex,
) -> bool {
    page.completed_cycle
        && !page.forced_wrap
        && !page.audit_restarted
        && !interleaved_rebase
        && audit.persisted_index
        && audit.index == final_index
        && post_audit_index == audit.index
}

fn enumerate_publication_queue(
    store: &StoreHandle,
    maximum: usize,
) -> Result<PublicationQueueInventory> {
    if maximum == 0 || maximum > MAX_PENDING_PUBLICATIONS {
        anyhow::bail!("publication queue maximum must be between 1 and {MAX_PENDING_PUBLICATIONS}");
    }
    let maximum_bytes = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_mul(
        u64::try_from(PUBLICATION_INTENT_KEY_BYTES + PUBLICATION_INTENT_MAX_ENCODED_BYTES)
            .unwrap_or(u64::MAX),
    );
    let started = Instant::now();
    let deadline = started
        .checked_add(PUBLICATION_QUEUE_SCAN_MAX_ELAPSED)
        .unwrap_or(started);
    let snapshot = store
        .snapshot()
        .context("failed to open publication queue snapshot")?;
    let encoded_index_before = snapshot
        .get(ColumnFamily::Snapshots, PUBLICATION_QUEUE_INDEX_KEY)
        .context("failed to capture publication queue revision")?;
    let expected_index = encoded_index_before
        .as_deref()
        .map(|encoded| PublicationQueueIndex::decode(encoded, maximum))
        .transpose()?;

    let mut record_count = 0u64;
    let mut total_bytes = 0u64;
    let mut continuation: Option<Vec<u8>> = None;
    let mut previous_key: Option<Vec<u8>> = None;
    #[cfg(test)]
    let mut pages = 0usize;
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "publication queue enumeration exceeded its {} ms deadline",
                PUBLICATION_QUEUE_SCAN_MAX_ELAPSED.as_millis()
            );
        }
        let page = snapshot
            .scan_prefix_page(
                ColumnFamily::Snapshots,
                PUBLICATION_KEY_PREFIX,
                continuation.as_deref(),
                PrefixScanBudget {
                    max_entries: PUBLICATION_QUEUE_SCAN_PAGE_ENTRIES.min(PREFIX_SCAN_MAX_ENTRIES),
                    max_bytes: PREFIX_SCAN_MAX_BYTES,
                },
            )
            .context("failed to read bounded publication queue")?;
        #[cfg(test)]
        {
            pages = pages.saturating_add(1);
        }
        if page.entries.is_empty() && page.continuation.is_some() {
            return Err(publication_queue_invariant(
                "publication queue pagination made no progress",
                1,
                0,
            ));
        }
        for (key, value) in page.entries {
            if previous_key
                .as_ref()
                .is_some_and(|previous| key <= *previous)
            {
                return Err(publication_queue_invariant(
                    "publication queue keys are not strictly ordered",
                    1,
                    0,
                ));
            }
            let (_intent, record_bytes) = decode_publication_record(&key, &value)?;
            total_bytes = total_bytes.checked_add(record_bytes).ok_or_else(|| {
                publication_queue_invariant(
                    "publication enumeration byte count overflow",
                    maximum_bytes,
                    u64::MAX,
                )
            })?;
            if total_bytes > maximum_bytes {
                anyhow::bail!(
                    "publication queue contains {total_bytes} bytes, above configured envelope {maximum_bytes}"
                );
            }
            record_count = record_count.checked_add(1).ok_or_else(|| {
                publication_queue_invariant(
                    "publication queue record count overflows u64",
                    u64::try_from(maximum).unwrap_or(u64::MAX),
                    u64::MAX,
                )
            })?;
            if record_count > u64::try_from(maximum).unwrap_or(u64::MAX) {
                anyhow::bail!(
                    "publication queue contains at least {record_count} intents, above configured maximum {maximum}"
                );
            }
            previous_key = Some(key);
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "publication queue enumeration exceeded its {} ms deadline",
                    PUBLICATION_QUEUE_SCAN_MAX_ELAPSED.as_millis()
                );
            }
        }
        match page.continuation {
            Some(cursor) => {
                if previous_key.as_ref() != Some(&cursor)
                    || !cursor.starts_with(PUBLICATION_KEY_PREFIX)
                {
                    return Err(publication_queue_invariant(
                        "publication queue continuation is not the last verified key",
                        1,
                        0,
                    ));
                }
                continuation = Some(cursor);
            }
            None => break,
        }
    }
    let computed = PublicationQueueIndex::migrated(record_count, total_bytes)?;
    computed.validate(maximum)?;
    if let Some(expected) = expected_index {
        if expected.count != computed.count {
            return Err(publication_queue_invariant(
                "publication queue index count does not match enumerated contents",
                expected.count,
                computed.count,
            ));
        }
        if expected.total_bytes != computed.total_bytes {
            return Err(publication_queue_invariant(
                "publication queue index bytes do not match enumerated contents",
                expected.total_bytes,
                computed.total_bytes,
            ));
        }
    }
    let encoded_index_after = snapshot
        .get(ColumnFamily::Snapshots, PUBLICATION_QUEUE_INDEX_KEY)
        .context("failed to recapture publication queue revision")?;
    if encoded_index_after != encoded_index_before {
        return Err(publication_queue_invariant(
            "publication queue revision changed within an immutable snapshot",
            1,
            0,
        ));
    }
    Ok(PublicationQueueInventory {
        index: expected_index.unwrap_or(computed),
        persisted_index: encoded_index_before.is_some(),
        #[cfg(test)]
        pages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_mining::MiningError;
    use hns_primitives::{Covenant, CovenantKind, Header, Input, Witness, NONCE_SIZE};
    use hns_store::{initialize_schema, StoreHandle};

    fn mining_test_config() -> crate::NodeConfig {
        crate::NodeConfig {
            network: Network::Regtest,
            authority_mode: AuthorityMode::NativeExperimental,
            acknowledge_incomplete_consensus: true,
            mining_engine: MiningEngineConfig {
                enabled: true,
                ..MiningEngineConfig::default()
            },
            ..crate::NodeConfig::default()
        }
    }

    fn canonical_regtest_genesis() -> Block {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/blocks/genesis-v1.json"))
                .expect("HSD genesis fixture");
        let raw = fixture["networks"]
            .as_array()
            .expect("genesis networks")
            .iter()
            .find(|case| case["network"].as_str() == Some("regtest"))
            .and_then(|case| case["raw"].as_str())
            .expect("regtest genesis raw block");
        Block::decode(&hex::decode(raw).expect("regtest genesis hex"))
            .expect("canonical regtest genesis block")
    }

    fn authoritative_mining_node() -> NodeService {
        let mut node = NodeService::new(mining_test_config());
        node.connect_block(NodeBlockImport::from_peer(canonical_regtest_genesis(), 0))
            .expect("connect canonical regtest genesis");
        node.mining_engine_initialize_publication_queue()
            .expect("initialize durable publication queue");
        assert!(node.mining_snapshot().is_some());
        node
    }

    fn solve_native_candidate(
        node: &NodeService,
        variant: u32,
        mask_byte: u8,
    ) -> SolvedMiningCandidate {
        let mask = [mask_byte; 32];
        let job = node
            .mining_engine_build_native_job(NativeMiningJobRequest {
                variant,
                payout_address: Address::new(0, vec![mask_byte; 20]).expect("payout address"),
                coinbase_flags: vec![mask_byte],
                reserved_root: [variant as u8; 32],
                mask,
                policy: TemplatePolicy::default(),
            })
            .expect("native mining job");
        let time = job.prepared.header().minimum_time;
        for nonce in 0..=u32::MAX {
            match job.prepared.admit_solution(
                &job.snapshot,
                nonce,
                time,
                [variant as u8; NONCE_SIZE],
                mask,
            ) {
                Ok(candidate) => return candidate,
                Err(MiningError::InsufficientProofOfWork) => {}
                Err(error) => panic!("native solution failed: {error}"),
            }
        }
        panic!("regtest proof of work search exhausted")
    }

    fn synthetic_publication_intent(
        tag: u8,
        created_at: u64,
        transaction_count: usize,
        witness_item_bytes: usize,
    ) -> SolvedBlockPublicationIntent {
        let transactions = (0..transaction_count)
            .map(|index| {
                let index_tag = u8::try_from(index).expect("synthetic transaction index fits u8");
                Transaction {
                    version: 1,
                    inputs: vec![Input {
                        previous_output: Outpoint::null(),
                        sequence: u32::MAX.saturating_sub(u32::try_from(index).unwrap_or(u32::MAX)),
                        witness: Witness {
                            items: vec![vec![tag.wrapping_add(index_tag); witness_item_bytes]],
                        },
                    }],
                    outputs: vec![Output {
                        value: 1,
                        address: Address::new(0, vec![tag; 20]).expect("synthetic address"),
                        covenant: Covenant {
                            kind: CovenantKind::None,
                            items: Vec::new(),
                        },
                    }],
                    locktime: u32::try_from(index).unwrap_or(u32::MAX),
                }
            })
            .collect::<Vec<_>>();
        let mut block = Block {
            header: Header {
                nonce: 0,
                time: created_at,
                prev_block: BlockHash::new([tag.wrapping_add(1); 32]),
                tree_root: [tag.wrapping_add(2); 32],
                extra_nonce: [tag; NONCE_SIZE],
                reserved_root: [tag.wrapping_add(3); 32],
                witness_root: [tag.wrapping_add(4); 32],
                merkle_root: [tag.wrapping_add(5); 32],
                version: 0,
                bits: Network::Regtest.params().pow.bits,
                mask: [tag.wrapping_add(6); 32],
            },
            transactions,
        };
        loop {
            if block.header.verify_pow() {
                break;
            }
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .expect("regtest synthetic proof of work exhausted");
        }
        let raw_block = block.encode();
        assert!(raw_block.len() <= MAX_BLOCK_WEIGHT);
        let intent = SolvedBlockPublicationIntent {
            snapshot_generation: 1,
            job_id: [tag; 32],
            block_hash: block.hash(),
            created_at,
            raw_block,
        };
        assert_eq!(
            SolvedBlockPublicationIntent::decode(&intent.encode()).expect("synthetic intent"),
            intent
        );
        intent
    }

    fn put_legacy_publication(store: &StoreHandle, intent: &SolvedBlockPublicationIntent) {
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                &intent.storage_key(),
                &intent.encode(),
            )
            .expect("stage legacy publication intent");
        store
            .commit(batch)
            .expect("commit legacy publication intent");
    }

    fn initialize_test_publication_index(store: &StoreHandle, maximum: usize) {
        let inventory = enumerate_publication_queue(store, maximum).expect("verify legacy queue");
        install_publication_queue_index(store, inventory.index, maximum)
            .expect("install publication queue index");
    }

    fn restart_mining_node(node: NodeService) -> (NodeService, StoreHandle) {
        let config = node.config().clone();
        let store = node.state().store.clone();
        drop(node);
        let state = crate::NodeState::from_store_for_network(store.clone(), Network::Regtest)
            .expect("reopen node state");
        let restarted =
            NodeService::try_with_state(config, state).expect("restart mining node service");
        (restarted, store)
    }

    fn attach_test_ambiguity_fence(node: &mut NodeService, tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-publication-{tag}-fence-{}-{nonce}",
            std::process::id()
        ));
        node.state.name_pages = Some(
            crate::NamePageStorage::open_or_bootstrap(
                directory.clone(),
                &node.state.store,
                Network::Regtest,
            )
            .expect("test name-page storage"),
        );
        directory
    }

    #[test]
    fn mining_engine_configuration_is_bounded_and_relay_requires_native_sync() {
        let native_sync = NativeSyncConfig::default();
        let mut config = MiningEngineConfig {
            enabled: true,
            transaction_relay: true,
            ..MiningEngineConfig::default()
        };
        assert!(config
            .validate(&native_sync, AuthorityMode::Native)
            .is_err());
        config.transaction_relay = false;
        assert!(config.validate(&native_sync, AuthorityMode::Native).is_ok());
        config.maximum_pending_publications = MAX_PENDING_PUBLICATIONS + 1;
        assert!(config
            .validate(&native_sync, AuthorityMode::Native)
            .is_err());
    }

    #[test]
    fn empty_publication_queue_round_trips_through_schema_store() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        let inventory = enumerate_publication_queue(&store, 1).expect("publication queue");
        assert_eq!(
            inventory.index,
            PublicationQueueIndex::migrated(0, 0).unwrap()
        );
        assert!(!inventory.persisted_index);
        install_publication_queue_index(&store, inventory.index, 1).expect("install queue index");
        let page = read_publication_queue_page(&store, 1, MiningPublicationRetryCursor::default())
            .expect("empty publication page");
        assert!(page.intents.is_empty());
        assert!(page.completed_cycle);
        assert_eq!(page.next_cursor, MiningPublicationRetryCursor::default());
    }

    #[test]
    fn publication_queue_rejects_invalid_limits_and_corrupt_records() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        let mut batch = store.batch();
        let mut key = PUBLICATION_KEY_PREFIX.to_vec();
        key.extend_from_slice(&[0x11; 32]);
        batch
            .put(ColumnFamily::Snapshots, &key, &[0x11])
            .expect("stage deliberately invalid intent");
        store.commit(batch).expect("publish corrupt queue");

        let error = enumerate_publication_queue(&store, 1).expect_err("corrupt queue");
        assert!(
            error.to_string().contains("invalid publication intent"),
            "{error:#}"
        );
        let error = enumerate_publication_queue(&store, 0).expect_err("zero queue maximum");
        assert!(error.to_string().contains("must be between 1"), "{error:#}");
        let error = enumerate_publication_queue(&store, MAX_PENDING_PUBLICATIONS + 1)
            .expect_err("excessive queue maximum");
        assert!(error.to_string().contains("must be between 1"), "{error:#}");
    }

    #[test]
    fn publication_queue_index_codec_binds_version_revision_count_and_checksum() {
        let index = PublicationQueueIndex {
            revision: 7,
            count: 2,
            total_bytes: 123,
        };
        let encoded = index.encode();
        assert_eq!(
            PublicationQueueIndex::decode(&encoded, 2).expect("decode queue index"),
            index
        );

        let mut corrupt = encoded;
        *corrupt.last_mut().expect("index checksum") ^= 1;
        assert!(PublicationQueueIndex::decode(&corrupt, 2)
            .expect_err("corrupt checksum")
            .to_string()
            .contains("checksum mismatch"));

        let zero_revision = PublicationQueueIndex {
            revision: 0,
            ..index
        }
        .encode();
        assert!(PublicationQueueIndex::decode(&zero_revision, 2)
            .expect_err("zero revision")
            .to_string()
            .contains("revision is zero"));
    }

    #[test]
    fn startup_migrates_legacy_publications_once_and_restart_revalidates_index() {
        let mut node = NodeService::new(mining_test_config());
        node.connect_block(NodeBlockImport::from_peer(canonical_regtest_genesis(), 0))
            .expect("connect canonical regtest genesis");
        let intent = synthetic_publication_intent(0x21, 21, 1, 8);
        put_legacy_publication(&node.state().store, &intent);
        assert!(load_publication_queue_index(
            &node.state().store,
            DEFAULT_MAX_PENDING_PUBLICATIONS
        )
        .expect("missing legacy index")
        .is_none());

        node.mining_engine_initialize_publication_queue()
            .expect("migrate legacy publication queue");
        let migrated =
            load_publication_queue_index(&node.state().store, DEFAULT_MAX_PENDING_PUBLICATIONS)
                .expect("migrated index")
                .expect("installed index");
        assert_eq!(migrated.revision, 1);
        assert_eq!(migrated.count, 1);

        let (mut restarted, store) = restart_mining_node(node);
        restarted
            .mining_engine_initialize_publication_queue()
            .expect("revalidate publication queue on restart");
        assert_eq!(
            load_publication_queue_index(&store, DEFAULT_MAX_PENDING_PUBLICATIONS)
                .expect("restart index"),
            Some(migrated)
        );
        assert_eq!(
            read_publication_queue_page(
                &store,
                DEFAULT_MAX_PENDING_PUBLICATIONS,
                MiningPublicationRetryCursor::default(),
            )
            .expect("restart publication page")
            .intents,
            vec![intent]
        );
    }

    #[test]
    fn publication_capacity_and_revision_have_exact_maximum_semantics() {
        let mut node = authoritative_mining_node();
        node.config.mining_engine.maximum_pending_publications = 1;
        let first = solve_native_candidate(&node, 1, 0x61);
        let second = solve_native_candidate(&node, 2, 0x62);
        let initial = load_publication_queue_index(&node.state().store, 1)
            .expect("initial index")
            .expect("initialized index");
        let first_intent = node
            .mining_engine_stage_publication(&first, 61)
            .expect("fill exact publication capacity");
        let full = load_publication_queue_index(&node.state().store, 1)
            .expect("full index")
            .expect("full queue index");
        assert_eq!(full.count, 1);
        assert_eq!(full.revision, initial.revision + 1);

        let error = node
            .mining_engine_stage_publication(&second, 62)
            .expect_err("reject one over publication capacity");
        assert!(
            error.to_string().contains("capacity is exhausted"),
            "{error:#}"
        );
        assert_eq!(
            load_publication_queue_index(&node.state().store, 1).expect("unchanged full index"),
            Some(full)
        );
        assert_eq!(
            read_publication_queue_page(
                &node.state().store,
                1,
                MiningPublicationRetryCursor::default(),
            )
            .expect("exact-capacity page")
            .intents,
            vec![first_intent]
        );
    }

    #[test]
    fn startup_fences_stale_or_corrupt_publication_index() {
        let mut stale = authoritative_mining_node();
        let candidate = solve_native_candidate(&stale, 1, 0x71);
        stale
            .mining_engine_stage_publication(&candidate, 71)
            .expect("stage stale-index fixture");
        let current =
            load_publication_queue_index(&stale.state().store, DEFAULT_MAX_PENDING_PUBLICATIONS)
                .expect("current queue index")
                .expect("current queue index exists");
        let mismatched = PublicationQueueIndex {
            revision: current.revision + 1,
            count: current.count + 1,
            total_bytes: current.total_bytes + 1,
        };
        let mut batch = stale.state().store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                PUBLICATION_QUEUE_INDEX_KEY,
                &mismatched.encode(),
            )
            .expect("stage mismatched index");
        stale
            .state()
            .store
            .commit(batch)
            .expect("commit mismatched index");
        stale
            .mining_engine_initialize_publication_queue()
            .expect_err("fence stale publication index");
        assert!(stale.mining_snapshot().is_none());
        assert!(crate::inspect_production_safety_fence(&stale.state().store)
            .expect("inspect stale-index fence")
            .is_some());

        let mut corrupt = authoritative_mining_node();
        let mut damaged =
            load_publication_queue_index(&corrupt.state().store, DEFAULT_MAX_PENDING_PUBLICATIONS)
                .expect("queue index")
                .expect("queue index exists")
                .encode();
        *damaged.last_mut().expect("queue checksum") ^= 1;
        let mut batch = corrupt.state().store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                PUBLICATION_QUEUE_INDEX_KEY,
                &damaged,
            )
            .expect("stage corrupt index");
        corrupt
            .state()
            .store
            .commit(batch)
            .expect("commit corrupt index");
        corrupt
            .mining_engine_initialize_publication_queue()
            .expect_err("fence corrupt publication index");
        assert!(corrupt.mining_snapshot().is_none());
        assert!(
            crate::inspect_production_safety_fence(&corrupt.state().store)
                .expect("inspect corrupt-index fence")
                .is_some()
        );
    }

    #[test]
    fn deferred_retry_pages_advance_wrap_and_bound_each_invocation() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        for tag in 1u8..=17 {
            put_legacy_publication(
                &store,
                &synthetic_publication_intent(tag, u64::from(tag), 1, 8),
            );
        }
        initialize_test_publication_index(&store, 17);

        let mut cursor = MiningPublicationRetryCursor::default();
        let mut seen = Vec::new();
        for page_number in 0..3 {
            let page = read_publication_queue_page(&store, 17, cursor)
                .expect("bounded deferred retry page");
            assert!(page.intents.len() <= PUBLICATION_RETRY_PAGE_ENTRIES);
            assert!(page.decoded_bytes <= PUBLICATION_RETRY_PAGE_MAX_BYTES as u64);
            assert_eq!(page.completed_cycle, page_number == 2);
            seen.extend(page.intents.iter().map(|intent| intent.block_hash));
            cursor = page.next_cursor;
        }
        seen.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        seen.dedup();
        assert_eq!(seen.len(), 17, "deferred first page starved later keys");
        assert_eq!(cursor, MiningPublicationRetryCursor::default());

        let wrapped =
            read_publication_queue_page(&store, 17, cursor).expect("deterministic retry wrap");
        assert_eq!(wrapped.intents.len(), PUBLICATION_RETRY_PAGE_ENTRIES);
        assert!(!wrapped.completed_cycle);
    }

    #[test]
    fn near_maximum_publications_remain_multipage_and_memory_bounded() {
        const RECORDS: usize = PUBLICATION_RETRY_PAGE_ENTRIES + 1;
        const WITNESS_ITEM_BYTES: usize = 950_000;
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        for tag in 1u8..=u8::try_from(RECORDS).expect("record count fits u8") {
            let intent = synthetic_publication_intent(tag, u64::from(tag), 4, WITNESS_ITEM_BYTES);
            assert!(
                intent.raw_block.len() >= MAX_BLOCK_WEIGHT - 250_000,
                "large publication fixture is not near the legal block ceiling"
            );
            put_legacy_publication(&store, &intent);
        }
        let inventory = enumerate_publication_queue(&store, RECORDS)
            .expect("stream near-maximum publication queue");
        assert_eq!(inventory.index.count, RECORDS as u64);
        assert!(inventory.pages >= 2);
        install_publication_queue_index(&store, inventory.index, RECORDS)
            .expect("install large queue index");

        let first =
            read_publication_queue_page(&store, RECORDS, MiningPublicationRetryCursor::default())
                .expect("first large retry page");
        assert_eq!(first.intents.len(), PUBLICATION_RETRY_PAGE_ENTRIES);
        assert!(first.decoded_bytes <= PUBLICATION_RETRY_PAGE_MAX_BYTES as u64);
        assert!(!first.completed_cycle);
        let second = read_publication_queue_page(&store, RECORDS, first.next_cursor)
            .expect("second large retry page");
        assert_eq!(second.intents.len(), 1);
        assert!(second.decoded_bytes <= PUBLICATION_RETRY_PAGE_MAX_BYTES as u64);
        assert!(second.completed_cycle);
    }

    #[test]
    fn retry_cursor_rejects_damage_forgery_and_legacy_accumulators() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        for tag in 0x20u8..0x29 {
            put_legacy_publication(
                &store,
                &synthetic_publication_intent(tag, u64::from(tag), 1, 8),
            );
        }
        initialize_test_publication_index(&store, 9);
        let first = read_publication_queue_page(&store, 9, MiningPublicationRetryCursor::default())
            .expect("first cursor page");
        let encoded = serde_json::to_vec(&first.next_cursor).expect("serialize cursor");
        assert_eq!(
            serde_json::from_slice::<MiningPublicationRetryCursor>(&encoded)
                .expect("deserialize authenticated cursor"),
            first.next_cursor
        );

        let mut damaged = first.next_cursor;
        damaged.checksum[0] ^= 1;
        let error = read_publication_queue_page(&store, 9, damaged)
            .expect_err("damaged cursor checksum must fail closed");
        assert!(error.to_string().contains("checksum mismatch"), "{error:#}");

        let mut forged = serde_json::to_value(first.next_cursor).expect("cursor JSON");
        forged
            .as_object_mut()
            .expect("cursor JSON object")
            .insert("revision".to_owned(), serde_json::json!(u64::MAX));
        let forged: MiningPublicationRetryCursor =
            serde_json::from_value(forged).expect("deserialize forged cursor fields");
        let error = read_publication_queue_page(&store, 9, forged)
            .expect_err("forged cursor fields must fail checksum validation");
        assert!(error.to_string().contains("checksum mismatch"), "{error:#}");

        let mut legacy = serde_json::to_value(first.next_cursor).expect("cursor JSON");
        legacy
            .as_object_mut()
            .expect("cursor JSON object")
            .insert("audited_records".to_owned(), serde_json::json!(8));
        assert!(
            serde_json::from_value::<MiningPublicationRetryCursor>(legacy).is_err(),
            "caller-supplied cross-snapshot accumulators must be rejected"
        );
    }

    #[test]
    fn immutable_tail_audit_detects_unindexed_deletion_behind_cursor() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        let mut intents = Vec::new();
        for tag in 0x30u8..0x3b {
            let intent = synthetic_publication_intent(tag, u64::from(tag), 1, 8);
            put_legacy_publication(&store, &intent);
            intents.push(intent);
        }
        initialize_test_publication_index(&store, intents.len());
        let mut ordered = intents
            .iter()
            .map(|intent| intent.block_hash)
            .collect::<Vec<_>>();
        ordered.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let first = read_publication_queue_page(
            &store,
            intents.len(),
            MiningPublicationRetryCursor::default(),
        )
        .expect("first retry page");
        assert!(!first.completed_cycle);
        let missing = ordered[0];
        assert!(first
            .intents
            .iter()
            .any(|intent| intent.block_hash == missing));
        let mut corrupt = store.batch();
        corrupt
            .delete(ColumnFamily::Snapshots, &publication_intent_key(missing))
            .expect("stage unindexed deletion");
        store.commit(corrupt).expect("commit unindexed deletion");

        let tail = read_publication_queue_page(&store, intents.len(), first.next_cursor)
            .expect("per-page traversal does not trust cross-snapshot totals");
        assert!(tail.completed_cycle);
        let error = enumerate_publication_queue(&store, intents.len())
            .expect_err("single-snapshot tail audit must detect missing key");
        assert!(
            error
                .to_string()
                .contains("index count does not match enumerated contents"),
            "{error:#}"
        );
    }

    #[test]
    fn tail_audit_restarts_when_insertion_lands_behind_cursor_before_audit() {
        const MAXIMUM: usize = 32;
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        let mut live = HashSet::new();
        for tag in 0x70u8..0x79 {
            let intent = synthetic_publication_intent(tag, u64::from(tag), 1, 8);
            live.insert(intent.block_hash);
            put_legacy_publication(&store, &intent);
        }
        initialize_test_publication_index(&store, MAXIMUM);
        let first =
            read_publication_queue_page(&store, MAXIMUM, MiningPublicationRetryCursor::default())
                .expect("first retry page");
        let boundary = first.next_cursor.after.expect("first-page cursor");
        let tail = read_publication_queue_page(&store, MAXIMUM, first.next_cursor)
            .expect("tail retry page");
        assert!(tail.completed_cycle);
        let final_index = load_publication_queue_index(&store, MAXIMUM)
            .expect("pre-audit index")
            .expect("pre-audit index exists");

        let inserted = (1u64..=10_000)
            .map(|nonce| {
                let tag = u8::try_from(nonce % 251).expect("bounded fixture tag");
                synthetic_publication_intent(tag, 10_000 + nonce, 1, 8)
            })
            .find(|intent| {
                !live.contains(&intent.block_hash)
                    && intent.block_hash.as_bytes() < boundary.as_bytes()
            })
            .expect("find insertion behind retry cursor");
        stage_publication_intent(&store, &inserted, MAXIMUM)
            .expect("insert behind cursor before audit");

        let audit = enumerate_publication_queue(&store, MAXIMUM).expect("exact tail audit");
        let post_audit_index = load_publication_queue_index(&store, MAXIMUM)
            .expect("post-audit index")
            .expect("post-audit index exists");
        assert_ne!(final_index, audit.index);
        assert_eq!(audit.index, post_audit_index);
        assert!(
            !publication_retry_cycle_is_complete(
                &tail,
                false,
                final_index,
                &audit,
                post_audit_index,
            ),
            "an insertion in the final-index/audit gap must restart the cycle"
        );
    }

    #[test]
    fn authenticated_page_budget_forces_wrap_under_ahead_churn() {
        const MAXIMUM: usize = 17;
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        let mut live = HashSet::new();
        for tag in 0x90u8..0xa1 {
            let intent = synthetic_publication_intent(tag, u64::from(tag), 1, 8);
            live.insert(intent.block_hash);
            put_legacy_publication(&store, &intent);
        }
        initialize_test_publication_index(&store, MAXIMUM);
        let maximum_pages = publication_retry_page_budget(MAXIMUM).expect("page budget");
        let mut cursor = MiningPublicationRetryCursor::default();
        let mut seed = 20_000u64;
        let mut wrapped = false;

        for page_number in 0..maximum_pages {
            let page = read_publication_queue_page(&store, MAXIMUM, cursor)
                .expect("ahead-churn retry page");
            assert!(
                !page.completed_cycle,
                "ahead churn unexpectedly reached tail"
            );
            if page.forced_wrap {
                assert_eq!(page_number + 1, maximum_pages);
                assert_eq!(page.next_cursor, MiningPublicationRetryCursor::default());
                assert!(page.audit_restarted);
                let final_index = load_publication_queue_index(&store, MAXIMUM)
                    .expect("forced-wrap index")
                    .expect("forced-wrap index exists");
                let audit =
                    enumerate_publication_queue(&store, MAXIMUM).expect("forced-wrap exact audit");
                assert!(!publication_retry_cycle_is_complete(
                    &page,
                    false,
                    final_index,
                    &audit,
                    final_index,
                ));
                wrapped = true;
                break;
            }

            let boundary = page.next_cursor.after.expect("ahead-churn cursor");
            for old in &page.intents {
                delete_publication_intent(&store, old.block_hash, MAXIMUM)
                    .expect("delete traversed publication");
                live.remove(&old.block_hash);
                let replacement = loop {
                    seed = seed.checked_add(1).expect("fixture seed");
                    let tag = u8::try_from(seed % 251).expect("bounded fixture tag");
                    let candidate = synthetic_publication_intent(tag, seed, 1, 8);
                    if candidate.block_hash.as_bytes() > boundary.as_bytes()
                        && !live.contains(&candidate.block_hash)
                    {
                        break candidate;
                    }
                };
                stage_publication_intent(&store, &replacement, MAXIMUM)
                    .expect("insert publication ahead of cursor");
                live.insert(replacement.block_hash);
            }
            let final_index = load_publication_queue_index(&store, MAXIMUM)
                .expect("ahead-churn index")
                .expect("ahead-churn index exists");
            let (next, interleaved) = reconcile_publication_retry_cursor(&page, &[], final_index)
                .expect("reconcile ahead churn");
            assert!(interleaved);
            cursor = next;
        }
        assert!(
            wrapped,
            "ahead churn exceeded its authenticated page budget"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_blocking_publication_worker_keeps_its_permit() {
        let concurrency = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::clone(&concurrency)
            .try_acquire_owned()
            .expect("worker permit");
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || -> Result<()> {
            let _permit = permit;
            entered_tx.send(()).expect("signal worker entry");
            release_rx.recv().expect("release blocking worker");
            Ok(())
        });
        entered_rx.await.expect("worker entered");

        let error =
            await_publication_blocking_worker("test publication worker", Duration::ZERO, worker)
                .await
                .expect_err("blocked worker must exceed zero deadline");
        assert!(
            error.to_string().contains("retains its concurrency permit"),
            "{error:#}"
        );
        assert_eq!(concurrency.available_permits(), 0);

        release_tx.send(()).expect("release worker");
        let recovered = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&concurrency).acquire_owned(),
        )
        .await
        .expect("worker returned permit before test deadline")
        .expect("semaphore remains open");
        drop(recovered);
    }

    #[test]
    fn sustained_interleaved_mutations_preserve_forward_retry_fairness() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        let mut target = HashSet::new();
        for tag in 0x50u8..0x61 {
            let intent = synthetic_publication_intent(tag, u64::from(tag), 1, 8);
            target.insert(intent.block_hash);
            put_legacy_publication(&store, &intent);
        }
        initialize_test_publication_index(&store, target.len());

        let mut cursor = MiningPublicationRetryCursor::default();
        let mut seen = HashSet::new();
        for _ in 0..4 {
            let page = read_publication_queue_page(&store, target.len(), cursor)
                .expect("interleaved retry page");
            seen.extend(page.intents.iter().map(|intent| intent.block_hash));

            // Churn a record at or behind this page's cursor without telling the
            // reconciler. The revision changes on every page, but forward
            // progress must not reset to the lowest keys.
            let churn = page.intents.first().expect("non-empty retry page").clone();
            delete_publication_intent(&store, churn.block_hash, target.len())
                .expect("interleaved deletion");
            stage_publication_intent(&store, &churn, target.len())
                .expect("interleaved reinsertion");
            let final_index = load_publication_queue_index(&store, target.len())
                .expect("interleaved index")
                .expect("interleaved index exists");
            let (next, rebased) = reconcile_publication_retry_cursor(&page, &[], final_index)
                .expect("rebase interleaved traversal");
            assert!(rebased, "interleaved revision was not observed");
            if !page.completed_cycle {
                assert_eq!(
                    next.after, page.next_cursor.after,
                    "interleaving moved the cursor backward"
                );
                assert_ne!(next, MiningPublicationRetryCursor::default());
            }
            cursor = next;
            if target.is_subset(&seen) {
                break;
            }
        }
        assert!(
            target.is_subset(&seen),
            "sustained interleaving starved higher publication keys"
        );
    }

    #[test]
    fn known_continuous_deletions_advance_authenticated_cursor_without_restart() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        for tag in 0x40u8..0x51 {
            put_legacy_publication(
                &store,
                &synthetic_publication_intent(tag, u64::from(tag), 1, 8),
            );
        }
        initialize_test_publication_index(&store, 17);
        let mut cursor = MiningPublicationRetryCursor::default();
        let mut deleted = 0usize;
        loop {
            let page = read_publication_queue_page(&store, 17, cursor)
                .expect("continuous-deletion audit page");
            assert!(!page.audit_restarted);
            let deleted_bytes = page.record_bytes.clone();
            for intent in &page.intents {
                delete_publication_intent(&store, intent.block_hash, 17)
                    .expect("delete authenticated retry record");
                deleted += 1;
            }
            let final_index = load_publication_queue_index(&store, 17)
                .expect("post-deletion index")
                .expect("post-deletion index exists");
            let (next, restarted) =
                reconcile_publication_retry_cursor(&page, &deleted_bytes, final_index)
                    .expect("reconcile known deletions");
            assert!(!restarted);
            cursor = next;
            if page.completed_cycle {
                break;
            }
        }
        assert_eq!(deleted, 17);
        assert_eq!(cursor, MiningPublicationRetryCursor::default());
        assert_eq!(
            load_publication_queue_index(&store, 17)
                .expect("empty index")
                .expect("empty index exists")
                .count,
            0
        );
    }

    #[test]
    fn retry_cursor_survives_delete_insert_wrap_and_restart() {
        let node = authoritative_mining_node();
        let store = node.state().store.clone();
        let mut live = Vec::new();
        for tag in 0x80u8..0x8c {
            let intent = synthetic_publication_intent(tag, u64::from(tag), 1, 8);
            stage_publication_intent(&store, &intent, DEFAULT_MAX_PENDING_PUBLICATIONS)
                .expect("stage cursor fixture");
            live.push(intent);
        }
        let first = read_publication_queue_page(
            &store,
            DEFAULT_MAX_PENDING_PUBLICATIONS,
            MiningPublicationRetryCursor::default(),
        )
        .expect("first cursor page");
        assert_eq!(first.intents.len(), PUBLICATION_RETRY_PAGE_ENTRIES);
        let encoded_cursor = serde_json::to_vec(&first.next_cursor).expect("serialize cursor");
        let deleted_hash = first
            .next_cursor
            .after
            .expect("first page has a continuation hash");
        delete_publication_intent(&store, deleted_hash, DEFAULT_MAX_PENDING_PUBLICATIONS)
            .expect("delete cursor key");
        live.retain(|intent| intent.block_hash != deleted_hash);
        let inserted = synthetic_publication_intent(0xf1, 0xf1, 1, 8);
        stage_publication_intent(&store, &inserted, DEFAULT_MAX_PENDING_PUBLICATIONS)
            .expect("insert across cursor");
        live.push(inserted);

        let (mut restarted, restarted_store) = restart_mining_node(node);
        restarted
            .mining_engine_initialize_publication_queue()
            .expect("revalidate changed queue after restart");
        let mut cursor: MiningPublicationRetryCursor =
            serde_json::from_slice(&encoded_cursor).expect("restore cursor");
        let mut observed = first
            .intents
            .iter()
            .filter(|intent| intent.block_hash != deleted_hash)
            .map(|intent| intent.block_hash)
            .collect::<HashSet<_>>();
        let target = live
            .iter()
            .map(|intent| intent.block_hash)
            .collect::<HashSet<_>>();
        let mut crossed_end = false;
        let mut audit_restarted = false;
        for _ in 0..4 {
            let page = read_publication_queue_page(
                &restarted_store,
                DEFAULT_MAX_PENDING_PUBLICATIONS,
                cursor,
            )
            .expect("resume cursor page after restart");
            observed.extend(page.intents.iter().map(|intent| intent.block_hash));
            crossed_end |= page.completed_cycle;
            audit_restarted |= page.audit_restarted;
            cursor = page.next_cursor;
            if crossed_end && target.is_subset(&observed) {
                break;
            }
        }
        assert!(crossed_end, "retry cursor never reached deterministic wrap");
        assert!(
            audit_restarted,
            "changed queue revision did not rebase traversal progress"
        );
        assert!(
            target.is_subset(&observed),
            "insert/delete around the cursor starved a live publication"
        );
        assert!(!observed.contains(&deleted_hash));
    }

    #[tokio::test]
    async fn restart_recovers_staged_then_accepted_intent_only_after_active_authentication() {
        let mut node = authoritative_mining_node();
        let candidate = solve_native_candidate(&node, 1, 0x31);
        let intent = node
            .mining_engine_stage_publication(&candidate, 1)
            .expect("stage publication before local admission");
        let accepted = node
            .submit_mining_candidate(candidate)
            .expect("locally admit staged solution");
        assert_eq!(accepted.hash, intent.block_hash);

        let (restarted, _) = restart_mining_node(node);
        let runtime = crate::NodeRuntime::spawn(restarted, 4).expect("canonical writer runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let expected = read.stable_canonical_epoch().expect("stable epoch").chain();
        let recovered = writer
            .execute_at_chain(
                expected,
                "test accepted publication recovery",
                move |node| node.mining_engine_recover_publication(intent),
            )
            .await
            .expect("recover accepted intent");
        match recovered {
            PublicationRecovery::Accepted { warning } => assert!(warning.is_none()),
            other => panic!("accepted intent was not recovered: {other:?}"),
        }
        assert_eq!(
            read.mining_engine_locally_accepted_record(accepted.hash)
                .await
                .expect("authenticated active record")
                .expect("active record")
                .hash,
            accepted.hash
        );
        runtime.shutdown().await.expect("runtime shutdown");
    }

    #[tokio::test]
    async fn restart_retires_cancelled_intent_after_competing_tip_wins() {
        let mut node = authoritative_mining_node();
        let cancelled = solve_native_candidate(&node, 1, 0x41);
        let competing = solve_native_candidate(&node, 2, 0x42);
        let intent = node
            .mining_engine_stage_publication(&cancelled, 2)
            .expect("stage publication before cancellation");
        node.submit_mining_candidate(competing)
            .expect("advance canonical tip with competing solution");

        let (restarted, store) = restart_mining_node(node);
        let runtime = crate::NodeRuntime::spawn(restarted, 4).expect("canonical writer runtime");
        let read = runtime.read();
        let writer = runtime.writer();
        let expected = read.stable_canonical_epoch().expect("stable epoch").chain();
        let stale_hash = intent.block_hash;
        let recovered = writer
            .execute_at_chain(expected, "test stale publication recovery", move |node| {
                node.mining_engine_recover_publication(intent)
            })
            .await
            .expect("recover stale intent");
        assert!(matches!(
            recovered,
            PublicationRecovery::RetiredStale { .. }
        ));
        assert!(read_publication_queue_page(
            &store,
            DEFAULT_MAX_PENDING_PUBLICATIONS,
            MiningPublicationRetryCursor::default()
        )
        .expect("live publication queue")
        .intents
        .is_empty());
        assert!(store
            .snapshot()
            .expect("retirement snapshot")
            .get(ColumnFamily::Snapshots, &publication_intent_key(stale_hash))
            .expect("retired intent point read")
            .is_none());
        runtime.shutdown().await.expect("runtime shutdown");
    }

    #[test]
    fn stage_and_migration_faults_preserve_atomic_index_semantics() {
        let mut before_stage = authoritative_mining_node();
        let candidate = solve_native_candidate(&before_stage, 1, 0xa1);
        let block_hash = candidate.block().hash();
        let initial = load_publication_queue_index(
            &before_stage.state().store,
            DEFAULT_MAX_PENDING_PUBLICATIONS,
        )
        .expect("initial staging index")
        .expect("initialized staging index");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::BeforeCommit);
        before_stage
            .mining_engine_stage_publication(&candidate, 0xa1)
            .expect_err("definite pre-commit stage failure");
        assert_eq!(
            load_publication_queue_index(
                &before_stage.state().store,
                DEFAULT_MAX_PENDING_PUBLICATIONS
            )
            .expect("unchanged staging index"),
            Some(initial)
        );
        assert!(before_stage
            .state()
            .store
            .snapshot()
            .expect("precommit snapshot")
            .get(ColumnFamily::Snapshots, &publication_intent_key(block_hash))
            .expect("precommit intent point read")
            .is_none());
        assert!(before_stage.mining_snapshot().is_some());

        let mut after_stage = authoritative_mining_node();
        let stage_pages = attach_test_ambiguity_fence(&mut after_stage, "stage");
        let candidate = solve_native_candidate(&after_stage, 1, 0xa2);
        let expected_intent =
            SolvedBlockPublicationIntent::from_candidate(&candidate, 0xa2).expect("stage intent");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::AfterCommit);
        after_stage
            .mining_engine_stage_publication(&candidate, 0xa2)
            .expect_err("ambiguous post-commit stage acknowledgement");
        assert!(after_stage.state.storage_reopen_required());
        assert!(after_stage.mining_snapshot().is_none());
        assert_eq!(
            read_publication_queue_page(
                &after_stage.state().store,
                DEFAULT_MAX_PENDING_PUBLICATIONS,
                MiningPublicationRetryCursor::default()
            )
            .expect("committed ambiguous stage")
            .intents,
            vec![expected_intent]
        );
        drop(after_stage);
        std::fs::remove_dir_all(stage_pages).expect("remove stage fence fixture");

        let mut before_migration = NodeService::new(mining_test_config());
        before_migration
            .connect_block(NodeBlockImport::from_peer(canonical_regtest_genesis(), 0))
            .expect("connect migration genesis");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::BeforeCommit);
        before_migration
            .mining_engine_initialize_publication_queue()
            .expect_err("definite pre-commit migration failure");
        assert!(load_publication_queue_index(
            &before_migration.state().store,
            DEFAULT_MAX_PENDING_PUBLICATIONS
        )
        .expect("precommit migration index")
        .is_none());
        assert!(before_migration.mining_snapshot().is_some());

        let mut after_migration = NodeService::new(mining_test_config());
        after_migration
            .connect_block(NodeBlockImport::from_peer(canonical_regtest_genesis(), 0))
            .expect("connect ambiguous migration genesis");
        let migration_pages = attach_test_ambiguity_fence(&mut after_migration, "migration");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::AfterCommit);
        after_migration
            .mining_engine_initialize_publication_queue()
            .expect_err("ambiguous post-commit migration acknowledgement");
        assert!(load_publication_queue_index(
            &after_migration.state().store,
            DEFAULT_MAX_PENDING_PUBLICATIONS
        )
        .expect("committed migration index")
        .is_some());
        assert!(after_migration.state.storage_reopen_required());
        assert!(after_migration.mining_snapshot().is_none());
        drop(after_migration);
        std::fs::remove_dir_all(migration_pages).expect("remove migration fence fixture");
    }

    #[test]
    fn retirement_fault_semantics_distinguish_definite_and_ambiguous_commit() {
        let mut before = authoritative_mining_node();
        let before_candidate = solve_native_candidate(&before, 1, 0x51);
        let before_intent = before
            .mining_engine_stage_publication(&before_candidate, 3)
            .expect("stage before-commit fixture");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::BeforeCommit);
        before
            .mining_engine_retire_publication(&before_intent, PublicationRetirement::Stale)
            .expect_err("definite pre-commit failure");
        assert!(before.mining_snapshot().is_some());
        assert_eq!(
            read_publication_queue_page(
                &before.state().store,
                DEFAULT_MAX_PENDING_PUBLICATIONS,
                MiningPublicationRetryCursor::default()
            )
            .expect("unchanged live queue")
            .intents,
            vec![before_intent]
        );

        let mut after_delete = authoritative_mining_node();
        let delete_pages = attach_test_ambiguity_fence(&mut after_delete, "delete");
        let delete_candidate = solve_native_candidate(&after_delete, 1, 0x52);
        let delete_intent = after_delete
            .mining_engine_stage_publication(&delete_candidate, 4)
            .expect("stage post-commit deletion fixture");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::AfterCommit);
        after_delete
            .mining_engine_retire_publication(&delete_intent, PublicationRetirement::Stale)
            .expect_err("ambiguous post-commit deletion acknowledgement");
        assert!(after_delete.state.storage_reopen_required());
        assert!(after_delete.mining_snapshot().is_none());
        assert!(read_publication_queue_page(
            &after_delete.state().store,
            DEFAULT_MAX_PENDING_PUBLICATIONS,
            MiningPublicationRetryCursor::default()
        )
        .expect("post-commit live queue")
        .intents
        .is_empty());

        drop(after_delete);
        std::fs::remove_dir_all(delete_pages).expect("remove deletion fence fixture");

        let mut after_quarantine = authoritative_mining_node();
        let quarantine_pages = attach_test_ambiguity_fence(&mut after_quarantine, "quarantine");
        let quarantine_candidate = solve_native_candidate(&after_quarantine, 1, 0x53);
        let quarantine_intent = after_quarantine
            .mining_engine_stage_publication(&quarantine_candidate, 5)
            .expect("stage post-commit quarantine fixture");
        inject_publication_queue_commit_fault(PublicationQueueCommitFault::AfterCommit);
        after_quarantine
            .mining_engine_retire_publication(&quarantine_intent, PublicationRetirement::Invalid)
            .expect_err("ambiguous post-commit quarantine acknowledgement");
        assert!(after_quarantine.state.storage_reopen_required());
        assert!(after_quarantine.mining_snapshot().is_none());
        assert_eq!(
            load_quarantined_publication(
                &after_quarantine.state().store,
                quarantine_intent.block_hash
            )
            .expect("checksummed quarantine entry"),
            Some(quarantine_intent)
        );
        drop(after_quarantine);
        std::fs::remove_dir_all(quarantine_pages).expect("remove quarantine fence fixture");
    }
}
