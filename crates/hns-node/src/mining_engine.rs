use std::{
    sync::{Arc, MutexGuard},
    time::Duration,
};

use anyhow::{Context, Result};
use hns_chain::BlockIndexRecord;
use hns_consensus::compute_block_version_from_state;
use hns_mempool::{Mempool, MempoolInfo, MempoolLimits};
use hns_mining::{
    MiningTemplate, PreparedMiningJob, SolvedBlockPublicationIntent, SolvedMiningCandidate,
    TemplateCacheKey, TemplatePolicy, TemplateVariant, MAX_TEMPLATE_VARIANTS,
    PUBLICATION_KEY_PREFIX,
};
use hns_p2p::{BroadcastReport, LivePeerManager, Packet};
use hns_primitives::{Address, BlockHash};
use hns_store::{ColumnFamily, ReadSnapshot, Store, StoreHandle, WriteBatch};
use serde::{Deserialize, Serialize};

use super::{issue_authority_permit, AuthorityMode, NodeService, ShadowSyncConfig};

pub const DEFAULT_MAX_PENDING_PUBLICATIONS: usize = 64;
pub const MAX_PENDING_PUBLICATIONS: usize = 1_024;
pub const MIN_PUBLICATION_RETRY_INTERVAL: Duration = Duration::from_millis(10);

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
            anyhow::bail!("Mining engine transaction relay requires the shadow-sync P2P runtime");
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
        if self.config.mining_engine.transaction_relay {
            blockers.push(
                "transaction relay remains fail-closed until contextual consensus admission is complete"
                    .to_owned(),
            );
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
        let deployments =
            self.state
                .deployment_state_for_block(&metadata, next_height, snapshot.tip.hash)?;
        let expected_version =
            compute_block_version_from_state(self.config.network.deployments(), deployments)?;
        drop(metadata);
        for request in &requests {
            if request.version != expected_version {
                anyhow::bail!(
                    "mining template version {} disagrees with HSD deployment version {expected_version} at height {next_height}",
                    request.version
                );
            }
        }
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
        if !self.config.mining_engine.enabled {
            return None;
        }
        let removed = self.state.mempool.remove_confirmed(transactions);
        (removed > 0).then(|| self.state.mempool.info().generation)
    }

    pub(crate) fn mining_engine_clear_mempool_for_chain_transition(&mut self) -> Option<u64> {
        if !self.config.mining_engine.enabled {
            return None;
        }
        let removed = self.state.mempool.clear();
        (removed > 0).then(|| self.state.mempool.info().generation)
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
        self.state
            .mempool
            .snapshot()
            .txids()
            .take(maximum)
            .map(hns_p2p::Inventory::transaction)
            .collect()
    }

    pub fn mining_engine_mempool_transaction(
        &self,
        txid: &hns_primitives::Txid,
    ) -> Option<hns_primitives::Transaction> {
        self.state.mempool.transaction(txid).cloned()
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

    /// Peer transaction admission remains deliberately fail closed until the
    /// complete contextual consensus verifier is composed. Keeping the method
    /// at the mutable service boundary makes the eventual verifier swap local
    /// and prevents the P2P runtime from owning consensus policy.
    pub fn mining_engine_accept_peer_transaction(
        &mut self,
        transaction: hns_primitives::Transaction,
    ) -> Result<hns_mempool::Admission> {
        if !self.config.mining_engine.enabled || !self.config.mining_engine.transaction_relay {
            return Ok(hns_mempool::Admission::Rejected {
                reason: "mining_engine-transaction-relay-disabled".to_owned(),
            });
        }
        let admission = self
            .state
            .mempool
            .submit(transaction)
            .map_err(|error| anyhow::anyhow!("peer transaction admission failed: {error}"))?;
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
