use std::{
    sync::{Arc, MutexGuard},
    time::Duration,
};

use anyhow::{Context, Result};
use hns_chain::{read_canonical_hash, BlockIndexRecord};
use hns_consensus::{
    compute_block_version_from_state, ConsensusError, NameFlags, NativeSignatureVerifier, Network,
    ScriptFlags, SequenceLockView, VerifiedClaim, WitnessProgramVerifier, MEDIAN_TIMESPAN,
};
use hns_mempool::{
    AirdropAdmission, AirdropMempoolContext, AirdropMempoolView, ClaimAdmission,
    ClaimContextValidation, ClaimMempoolContext, ClaimMempoolView, ContextualTransactionVerifier,
    Mempool, MempoolContext, MempoolInfo, MempoolLimits, MempoolView, HSD_MINIMUM_RELAY_FEE_RATE,
};
use hns_mining::{
    MiningTemplate, PreparedMiningJob, SolvedBlockPublicationIntent, SolvedMiningCandidate,
    TemplateCacheKey, TemplatePolicy, TemplateVariant, MAX_TEMPLATE_VARIANTS,
    PUBLICATION_KEY_PREFIX,
};
use hns_p2p::{BroadcastReport, LivePeerManager, Packet};
use hns_primitives::{
    Address, AirdropProof, BlockHash, Claim, Coin, Height, Outpoint, Output, Transaction,
};
use hns_state::{
    airdrop_position_spent, decode_coin, encode_outpoint_key, verify_mempool_claim_context,
    verify_mempool_name_context,
};
use hns_store::{ColumnFamily, ReadSnapshot, Store, StoreHandle, WriteBatch};
use serde::{Deserialize, Serialize};

use super::{issue_authority_permit, AuthorityMode, NodeService, ShadowSyncConfig};

pub const DEFAULT_MAX_PENDING_PUBLICATIONS: usize = 64;
pub const MAX_PENDING_PUBLICATIONS: usize = 1_024;
pub const MIN_PUBLICATION_RETRY_INTERVAL: Duration = Duration::from_millis(10);

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
}

impl<T: ReadSnapshot + Sync> ContextualTransactionVerifier
    for ActiveContextualTransactionVerifier<'_, T>
{
    fn verify(
        &self,
        transaction: &Transaction,
        _input_coins: &[Coin],
        context: &MempoolContext,
        accepted_name_transactions: &[&Transaction],
    ) -> Result<(), ConsensusError> {
        verify_mempool_name_context(
            self.snapshot,
            accepted_name_transactions,
            transaction,
            context.next_height,
            self.network,
            self.name_flags,
        )
        .map_err(|error| ConsensusError::ContextualCovenant(error.to_string()))
    }

    fn is_consensus_complete(&self) -> bool {
        true
    }
}

fn active_mempool_parameters<T: ReadSnapshot>(
    state: &super::NodeState,
    network: Network,
    snapshot: &T,
) -> Result<Option<(MempoolContext, NameFlags)>> {
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

/// The mining engine may build diagnostic templates in shadow mode, but
/// transaction relay and solved-block publication remain
/// separately gated. No setting in this structure can manufacture an authority
/// permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningEngineConfig {
    pub enabled: bool,
    pub transaction_relay: bool,
    pub mempool_limits: MempoolLimits,
    pub maximum_template_variants: usize,
    pub maximum_pending_publications: usize,
    pub publication_retry_interval: Duration,
}

impl Default for MiningEngineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transaction_relay: false,
            mempool_limits: MempoolLimits::default(),
            maximum_template_variants: MAX_TEMPLATE_VARIANTS,
            maximum_pending_publications: DEFAULT_MAX_PENDING_PUBLICATIONS,
            publication_retry_interval: Duration::from_millis(250),
        }
    }
}

impl MiningEngineConfig {
    pub fn validate(
        &self,
        shadow_sync: &ShadowSyncConfig,
        _authority_mode: AuthorityMode,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
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
        if self.transaction_relay && !shadow_sync.enabled {
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
    pub cached_template_variants: usize,
    pub pending_publications: usize,
    pub maximum_pending_publications: usize,
    pub publication_retry_interval_ms: u64,
    pub can_build_shadow_templates: bool,
    pub can_publish_solved_blocks: bool,
    pub blockers: Vec<String>,
}

impl NodeService {
    /// The future-template cache is derived state. If a prior panic poisoned
    /// the mutex, discard the cache before reuse rather than allowing a stale
    /// derivative object to permanently stop node operation.
    fn mining_engine_template_cache(&self) -> MutexGuard<'_, hns_mining::TemplateCoordinator> {
        match self.mining_engine_templates.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        }
    }

    pub fn mining_engine_diagnostics(&self) -> Result<MiningEngineDiagnostics> {
        let enabled = self.config.mining_engine.enabled;
        let durable = self.state.durable_mining_state()?;
        let can_publish = enabled && issue_authority_permit(&self.config, &durable).is_some();
        let pending = if enabled {
            load_publication_intents(
                &self.state.store,
                self.config.mining_engine.maximum_pending_publications,
            )?
            .len()
        } else {
            0
        };
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
        blockers.sort();
        blockers.dedup();
        let cached_template_variants = self.mining_engine_template_cache().len();
        Ok(MiningEngineDiagnostics {
            enabled,
            observation_only: !can_publish,
            transaction_relay_enabled: self.config.mining_engine.transaction_relay,
            mempool: self.state.mempool.info(),
            maximum_template_variants: self.config.mining_engine.maximum_template_variants,
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
            can_build_shadow_templates: enabled && durable.snapshot.is_some(),
            can_publish_solved_blocks: can_publish,
            blockers,
        })
    }

    /// Build an immutable diagnostic or future template from one durable chain
    /// snapshot and one immutable mempool snapshot. Shadow mode may call this
    /// method, but publishing the resulting job still requires an authority
    /// permit through the existing mining subscription boundary.
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

    /// Atomically replace the complete future-template set for one immutable
    /// chain and mempool generation. A failed variant leaves the prior cache
    /// untouched.
    pub fn mining_engine_rebuild_templates(
        &self,
        requests: Vec<MiningTemplateRequest>,
    ) -> Result<Vec<Arc<MiningTemplate>>> {
        if !self.config.mining_engine.enabled {
            anyhow::bail!("Mining engine is disabled");
        }
        let snapshot = self
            .state
            .durable_mining_state()?
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
        for request in &requests {
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
        let mempool = self.state.mempool.snapshot();
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
        self.mining_engine_template_cache()
            .rebuild(&snapshot, &mempool, variants)
            .map_err(|error| anyhow::anyhow!("failed to assemble mining templates: {error}"))
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
        let revalidation = (|| -> Result<hns_mempool::MempoolRevalidation> {
            let snapshot = self
                .state
                .store
                .snapshot()
                .context("failed to open post-connect mempool context")?;
            let (context, name_flags) =
                active_mempool_parameters(&self.state, self.config.network, &snapshot)?
                    .ok_or_else(|| {
                        anyhow::anyhow!("connected chain has no active mempool context")
                    })?;
            let view = ActiveMempoolView::new(&snapshot);
            let contextual_verifier = ActiveContextualTransactionVerifier {
                snapshot: &snapshot,
                network: self.config.network,
                name_flags,
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
        let snapshot = self.state.mempool.snapshot();
        snapshot
            .txids()
            .map(hns_p2p::Inventory::transaction)
            .chain(
                snapshot
                    .claims()
                    .map(|entry| hns_p2p::Inventory::claim(entry.hash)),
            )
            .chain(
                snapshot
                    .airdrops()
                    .map(|entry| hns_p2p::Inventory::airdrop(entry.hash)),
            )
            .take(maximum)
            .collect()
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

    pub(crate) fn mining_engine_mempool_transactions(
        &self,
        maximum: usize,
    ) -> Vec<hns_primitives::Transaction> {
        let snapshot = self.state.mempool.snapshot();
        snapshot
            .txids()
            .take(maximum)
            .filter_map(|txid| snapshot.transaction(&txid).cloned())
            .collect()
    }

    /// Admit an ordinary peer transaction against one immutable active-chain
    /// snapshot and the pool's deterministic in-memory name-state overlay.
    /// The P2P runtime remains policy-free and only relays accepted inventory.
    pub fn mining_engine_accept_peer_transaction(
        &mut self,
        transaction: hns_primitives::Transaction,
    ) -> Result<hns_mempool::Admission> {
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
        let Some((context, name_flags)) =
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

    /// Persist the solved block before network publication. The durable queue
    /// makes a crash between candidate reconstruction and fan-out observable
    /// and retryable. This method requires the same authority capability as
    /// candidate connection.
    pub fn mining_engine_stage_publication(
        &self,
        candidate: &SolvedMiningCandidate,
        created_at: u64,
    ) -> Result<SolvedBlockPublicationIntent> {
        if !self.config.mining_engine.enabled {
            anyhow::bail!("Mining engine is disabled");
        }
        self.validate_mining_engine_candidate(candidate)?;
        let intent = SolvedBlockPublicationIntent::from_candidate(candidate, created_at)
            .map_err(|error| anyhow::anyhow!("failed to create publication intent: {error}"))?;
        let existing = load_publication_intents(
            &self.state.store,
            self.config.mining_engine.maximum_pending_publications,
        )?;
        if let Some(previous) = existing
            .iter()
            .find(|previous| previous.block_hash == intent.block_hash)
        {
            if previous.snapshot_generation == intent.snapshot_generation
                && previous.job_id == intent.job_id
                && previous.raw_block == intent.raw_block
            {
                return Ok(previous.clone());
            }
            anyhow::bail!("publication intent conflicts with existing block hash");
        }
        if existing.len() >= self.config.mining_engine.maximum_pending_publications {
            anyhow::bail!("pending solved-block publication capacity is exhausted");
        }
        write_publication_intent(&self.state.store, &intent)?;
        Ok(intent)
    }

    pub fn mining_engine_pending_publications(&self) -> Result<Vec<SolvedBlockPublicationIntent>> {
        load_publication_intents(
            &self.state.store,
            self.config.mining_engine.maximum_pending_publications,
        )
    }

    pub fn mining_engine_complete_publication(&self, block_hash: BlockHash) -> Result<()> {
        delete_publication_intent(&self.state.store, block_hash)
    }

    pub async fn mining_engine_retry_pending_publications(
        &self,
        peers: &LivePeerManager,
    ) -> Result<Vec<MiningPublicationAttempt>> {
        let durable = self.state.durable_mining_state()?;
        issue_authority_permit(&self.config, &durable).ok_or_else(|| {
            anyhow::anyhow!("pending solved blocks cannot be published without an authority permit")
        })?;
        let mut attempts = Vec::new();
        for intent in self.mining_engine_pending_publications()? {
            if self
                .mining_engine_locally_accepted_record(intent.block_hash)?
                .is_none()
            {
                attempts.push(MiningPublicationAttempt {
                    block_hash: intent.block_hash,
                    failures: vec![
                        "publication intent is not bound to a locally accepted active block"
                            .to_owned(),
                    ],
                    ..MiningPublicationAttempt::default()
                });
                continue;
            }
            let block = intent.block().map_err(|error| {
                anyhow::anyhow!("pending publication intent is corrupt: {error}")
            })?;
            let report = peers
                .broadcast_critical_parallel(Arc::new(Packet::Block(block)))
                .await;
            let attempt = MiningPublicationAttempt::from_report(intent.block_hash, report);
            if attempt.written_peers > 0 {
                self.mining_engine_complete_publication(intent.block_hash)?;
            }
            attempts.push(attempt);
        }
        Ok(attempts)
    }

    /// Persist and locally connect a solved candidate before publishing it.
    /// Network fan-out never precedes the full local candidate-admission path.
    /// The durable intent is removed only after at least one ready peer writer
    /// completes the critical socket write. A zero-peer publication is reported as pending
    /// rather than as a failed local connection because the active-chain state
    /// transition has already succeeded.
    pub async fn mining_engine_publish_solved_candidate(
        &mut self,
        candidate: SolvedMiningCandidate,
        peers: &LivePeerManager,
        created_at: u64,
    ) -> Result<MiningPublicationResult> {
        let intent = self.mining_engine_stage_publication(&candidate, created_at)?;
        let mut local_admission_warning = None;
        let connected = match self.mining_engine_locally_accepted_record(intent.block_hash)? {
            Some(record) => record,
            None => match self.submit_mining_candidate(candidate) {
                Ok(record) => record,
                Err(error) => {
                    // Candidate admission can report an operational error after
                    // the durable consensus-state commit (for example, a closed
                    // notification channel). Re-read the canonical record before
                    // deciding whether the intent represents a failed candidate.
                    if let Some(record) =
                        self.mining_engine_locally_accepted_record(intent.block_hash)?
                    {
                        local_admission_warning = Some(format!(
                            "candidate was committed locally but post-commit processing reported: {error}"
                        ));
                        record
                    } else {
                        let cleanup = self.mining_engine_complete_publication(intent.block_hash);
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
            self.mining_engine_complete_publication(intent.block_hash)?;
        }
        Ok(MiningPublicationResult {
            attempt,
            connected,
            local_admission_warning,
            publication_pending,
        })
    }

    fn mining_engine_locally_accepted_record(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<BlockIndexRecord>> {
        Ok(self.state.load_block_record(&block_hash)?.filter(|record| {
            record.status.active_chain && record.status.body_present && !record.status.failed
        }))
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

fn write_publication_intent(
    store: &StoreHandle,
    intent: &SolvedBlockPublicationIntent,
) -> Result<()> {
    let mut batch = store.batch();
    batch
        .put(
            ColumnFamily::Snapshots,
            &intent.storage_key(),
            &intent.encode(),
        )
        .context("failed to stage solved-block publication intent")?;
    store
        .commit(batch)
        .context("failed to commit solved-block publication intent")
}

fn delete_publication_intent(store: &StoreHandle, block_hash: BlockHash) -> Result<()> {
    let mut key = Vec::with_capacity(PUBLICATION_KEY_PREFIX.len() + 32);
    key.extend_from_slice(PUBLICATION_KEY_PREFIX);
    key.extend_from_slice(block_hash.as_bytes());
    let mut batch = store.batch();
    batch
        .delete(ColumnFamily::Snapshots, &key)
        .context("failed to stage publication-intent deletion")?;
    store
        .commit(batch)
        .context("failed to commit publication-intent deletion")
}

fn load_publication_intents(
    store: &StoreHandle,
    maximum: usize,
) -> Result<Vec<SolvedBlockPublicationIntent>> {
    let snapshot = store
        .snapshot()
        .context("failed to open publication queue snapshot")?;
    let entries = snapshot
        .scan_prefix(ColumnFamily::Snapshots, PUBLICATION_KEY_PREFIX)
        .context("failed to scan publication queue")?;
    if entries.len() > maximum {
        anyhow::bail!(
            "publication queue contains {} entries above configured maximum {maximum}",
            entries.len()
        );
    }
    let mut intents = entries
        .into_iter()
        .map(|(key, value)| {
            let intent = SolvedBlockPublicationIntent::decode(&value)
                .map_err(|error| anyhow::anyhow!("invalid publication intent: {error}"))?;
            if key != intent.storage_key() {
                anyhow::bail!("publication intent key does not match its block hash");
            }
            Ok(intent)
        })
        .collect::<Result<Vec<_>>>()?;
    intents.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.block_hash.as_bytes().cmp(right.block_hash.as_bytes()))
    });
    Ok(intents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_store::{initialize_schema, StoreHandle};

    #[test]
    fn mining_engine_configuration_is_bounded_and_relay_requires_shadow_sync() {
        let shadow_sync = ShadowSyncConfig::default();
        let mut config = MiningEngineConfig {
            enabled: true,
            transaction_relay: true,
            ..MiningEngineConfig::default()
        };
        assert!(config
            .validate(&shadow_sync, AuthorityMode::Shadow)
            .is_err());
        config.transaction_relay = false;
        assert!(config.validate(&shadow_sync, AuthorityMode::Shadow).is_ok());
        config.maximum_pending_publications = MAX_PENDING_PUBLICATIONS + 1;
        assert!(config
            .validate(&shadow_sync, AuthorityMode::Shadow)
            .is_err());
    }

    #[test]
    fn empty_publication_queue_round_trips_through_schema_store() {
        let store = StoreHandle::memory();
        initialize_schema(&store).expect("schema");
        assert!(load_publication_intents(&store, 1)
            .expect("publication queue")
            .is_empty());
    }
}
