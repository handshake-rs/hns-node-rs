use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use hns_chain::ChainTip;
use hns_p2p::{PeerId, SERVICE_NETWORK};
use hns_primitives::{BlockHash, Height};
use serde::{Deserialize, Serialize};

use crate::{checkpoint::SyncCheckpoint, BlockDownloadRequest, SyncError, SyncMetrics, SyncStage};

#[derive(Clone, Debug)]
pub struct SyncLimits {
    pub maximum_peers: usize,
    pub maximum_pending_blocks: usize,
    pub maximum_inflight_blocks: usize,
    pub maximum_inflight_per_peer: usize,
    pub maximum_retries: u8,
    pub block_request_timeout: Duration,
    pub headers_request_timeout: Duration,
    pub checkpoint_interval: Duration,
}

impl Default for SyncLimits {
    fn default() -> Self {
        Self {
            maximum_peers: 64,
            maximum_pending_blocks: 8_192,
            maximum_inflight_blocks: 128,
            maximum_inflight_per_peer: 16,
            maximum_retries: 3,
            // Match HSD's `Peer.BLOCK_TIMEOUT` and the doubled 30-second
            // response deadline attached to `GETHEADERS`.
            block_request_timeout: Duration::from_secs(120),
            headers_request_timeout: Duration::from_secs(60),
            checkpoint_interval: Duration::from_secs(30),
        }
    }
}

impl SyncLimits {
    pub fn validate(&self) -> Result<(), SyncError> {
        if self.maximum_peers == 0
            || self.maximum_pending_blocks == 0
            || self.maximum_inflight_blocks == 0
            || self.maximum_inflight_per_peer == 0
        {
            return Err(SyncError::Configuration(
                "sync capacities must be non-zero".to_owned(),
            ));
        }
        if self.maximum_inflight_per_peer > self.maximum_inflight_blocks {
            return Err(SyncError::Configuration(
                "per-peer inflight limit exceeds global inflight limit".to_owned(),
            ));
        }
        if self.block_request_timeout.is_zero()
            || self.headers_request_timeout.is_zero()
            || self.checkpoint_interval.is_zero()
        {
            return Err(SyncError::Configuration(
                "sync timeouts and checkpoint interval must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerSyncSnapshot {
    pub peer: PeerId,
    pub services: u64,
    pub advertised_height: Height,
    pub ready: bool,
    pub inflight_blocks: usize,
    /// The peer delivered at least one eligible body on this connection and
    /// may use the configured per-peer body window instead of one probe.
    pub body_available: bool,
    pub failures: u32,
    /// Honest block `notfound` responses observed from this peer. These are
    /// availability evidence, not validation or protocol failures.
    pub unavailable_blocks: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncSnapshot {
    pub stage: SyncStage,
    pub best_header: Option<ChainTip>,
    pub active_tip: Option<ChainTip>,
    pub stored_tip: Option<ChainTip>,
    pub target_height: Option<Height>,
    pub pending_blocks: usize,
    pub inflight_blocks: usize,
    /// All reserved body work, including pending, inflight, validating, and
    /// statelessly validated orphan bodies.
    pub tracked_blocks: usize,
    pub validated_blocks: u64,
    pub failed_blocks: u64,
    pub unavailable_blocks: u64,
    pub sequence: u64,
    pub peers: Vec<PeerSyncSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncAction {
    RequestHeaders {
        peer: PeerId,
        locator: Vec<BlockHash>,
        stop: BlockHash,
    },
    RequestBlock(BlockDownloadRequest),
    Penalize {
        peer: PeerId,
        score: u32,
        reason: String,
    },
    Disconnect {
        peer: PeerId,
        reason: String,
    },
    PersistCheckpoint,
}

#[derive(Clone, Debug)]
struct PeerSyncState {
    services: u64,
    advertised_height: Height,
    ready: bool,
    inflight: BTreeSet<BlockHash>,
    headers_requested_at: Option<Instant>,
    last_block_received_at: Option<Instant>,
    body_available: bool,
    failures: u32,
    unavailable_blocks: u64,
}

#[derive(Clone, Debug)]
struct PendingBlock {
    hash: BlockHash,
    height: Height,
    announced_by: BTreeSet<PeerId>,
    retry_backoff: Option<PeerRetryBackoff>,
    attempts: u8,
}

#[derive(Clone, Debug)]
struct PeerRetryBackoff {
    peer: PeerId,
    eligible_at: Instant,
}

impl PendingBlock {
    fn peer_can_deliver(&self, peer: PeerId) -> bool {
        self.announced_by.is_empty() || self.announced_by.contains(&peer)
    }

    fn peer_is_eligible(&self, peer: PeerId, now: Instant) -> bool {
        let retry_ready = self
            .retry_backoff
            .as_ref()
            .is_none_or(|backoff| backoff.peer != peer || now >= backoff.eligible_at);
        self.peer_can_deliver(peer) && retry_ready
    }
}

#[derive(Clone, Debug)]
struct InflightBlock {
    request: BlockDownloadRequest,
    requested_at: Instant,
    attempts: u8,
}

#[derive(Clone, Debug)]
pub struct SyncScheduler {
    limits: SyncLimits,
    stage: SyncStage,
    headers_only: bool,
    peers: BTreeMap<PeerId, PeerSyncState>,
    pending_order: VecDeque<BlockHash>,
    pending: HashMap<BlockHash, PendingBlock>,
    inflight: HashMap<BlockHash, InflightBlock>,
    /// One bounded reservation per body across every scheduler/validator/
    /// orphan state. Moving a request between those states cannot lose its
    /// capacity slot or admit a duplicate download.
    tracked: HashSet<BlockHash>,
    /// Connection-local negative block availability learned from `notfound`.
    /// Entries are bounded by pending/inflight work and prevent repeatedly
    /// assigning a pruned hash to the same peer.
    unavailable_by: HashMap<BlockHash, BTreeSet<PeerId>>,
    best_header: Option<ChainTip>,
    active_tip: Option<ChainTip>,
    stored_tip: Option<ChainTip>,
    target_height: Option<Height>,
    validated_blocks: u64,
    failed_blocks: u64,
    unavailable_blocks: u64,
    sequence: u64,
    last_checkpoint: Instant,
}

impl SyncScheduler {
    pub fn new(limits: SyncLimits, now: Instant) -> Result<Self, SyncError> {
        limits.validate()?;
        Ok(Self {
            limits,
            stage: SyncStage::Idle,
            headers_only: false,
            peers: BTreeMap::new(),
            pending_order: VecDeque::new(),
            pending: HashMap::new(),
            inflight: HashMap::new(),
            tracked: HashSet::new(),
            unavailable_by: HashMap::new(),
            best_header: None,
            active_tip: None,
            stored_tip: None,
            target_height: None,
            validated_blocks: 0,
            failed_blocks: 0,
            unavailable_blocks: 0,
            sequence: 0,
            last_checkpoint: now,
        })
    }

    pub fn restore(
        limits: SyncLimits,
        now: Instant,
        checkpoint: &SyncCheckpoint,
    ) -> Result<Self, SyncError> {
        let mut scheduler = Self::new(limits, now)?;
        scheduler.stage = match checkpoint.stage {
            SyncStage::Validating => SyncStage::Blocks,
            other => other,
        };
        scheduler.best_header = checkpoint.best_header.clone();
        scheduler.active_tip = checkpoint.active_tip.clone();
        scheduler.stored_tip = checkpoint.stored_tip.clone();
        scheduler.target_height = checkpoint.target_height;
        scheduler.sequence = checkpoint.sequence;
        Ok(scheduler)
    }

    pub fn stage(&self) -> SyncStage {
        self.stage
    }

    pub fn set_headers_only(&mut self, headers_only: bool) {
        self.headers_only = headers_only;
        self.update_stage();
        self.bump_sequence();
    }

    pub fn set_stage(&mut self, stage: SyncStage) {
        self.stage = stage;
        self.bump_sequence();
    }

    pub fn register_peer(
        &mut self,
        peer: PeerId,
        services: u64,
        advertised_height: Height,
    ) -> Result<(), SyncError> {
        if !self.peers.contains_key(&peer) && self.peers.len() >= self.limits.maximum_peers {
            return Err(SyncError::LimitExceeded {
                context: "sync peers",
                limit: self.limits.maximum_peers,
                actual: self.peers.len().saturating_add(1),
            });
        }
        self.peers.insert(
            peer,
            PeerSyncState {
                services,
                advertised_height,
                ready: true,
                inflight: BTreeSet::new(),
                headers_requested_at: None,
                last_block_received_at: None,
                body_available: false,
                failures: 0,
                unavailable_blocks: 0,
            },
        );
        self.recalculate_target();
        if self.stage == SyncStage::Idle {
            self.stage = SyncStage::Headers;
        }
        self.bump_sequence();
        Ok(())
    }

    pub fn update_peer_tip(&mut self, peer: PeerId, height: Height, services: u64) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.advertised_height = height;
            state.services = services;
            state.ready = true;
            self.recalculate_target();
            self.bump_sequence();
        }
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        let Some(state) = self.peers.remove(&peer) else {
            return;
        };
        let now_pending = state.inflight.into_iter().collect::<Vec<_>>();
        for hash in now_pending {
            if let Some(inflight) = self.inflight.remove(&hash) {
                self.requeue(
                    inflight.request.hash,
                    inflight.request.height,
                    inflight.attempts,
                    None,
                );
            }
        }
        for pending in self.pending.values_mut() {
            pending.announced_by.remove(&peer);
            if pending
                .retry_backoff
                .as_ref()
                .is_some_and(|backoff| backoff.peer == peer)
            {
                pending.retry_backoff = None;
            }
        }
        self.unavailable_by.retain(|_, unavailable| {
            unavailable.remove(&peer);
            !unavailable.is_empty()
        });
        self.recalculate_target();
        self.bump_sequence();
    }

    pub fn contains_peer(&self, peer: PeerId) -> bool {
        self.peers.contains_key(&peer)
    }

    /// Release a header request which never entered the peer's outbound
    /// queue so the next poll can retry it without waiting for a timeout.
    pub fn rollback_header_dispatch(&mut self, peer: PeerId) -> bool {
        let Some(state) = self.peers.get_mut(&peer) else {
            return false;
        };
        if state.headers_requested_at.take().is_none() {
            return false;
        }
        self.bump_sequence();
        true
    }

    pub fn set_best_header(&mut self, tip: Option<ChainTip>) {
        self.best_header = tip;
        self.update_stage();
        self.bump_sequence();
    }

    pub fn set_active_tip(&mut self, tip: Option<ChainTip>) {
        self.active_tip = tip;
        self.update_stage();
        self.bump_sequence();
    }

    pub fn active_tip(&self) -> Option<&ChainTip> {
        self.active_tip.as_ref()
    }

    pub fn set_stored_tip(&mut self, tip: Option<ChainTip>) {
        self.stored_tip = tip;
        self.update_stage();
        self.bump_sequence();
    }

    pub fn stored_tip(&self) -> Option<&ChainTip> {
        self.stored_tip.as_ref()
    }

    pub fn available_pending_slots(&self) -> usize {
        self.limits
            .maximum_pending_blocks
            .saturating_sub(self.tracked.len())
    }

    pub fn is_tracked_block(&self, hash: &BlockHash) -> bool {
        self.tracked.contains(hash)
    }

    /// Check whether a body may currently arrive from `peer` without
    /// consuming its scheduler reservation. Compact-block reconstruction uses
    /// this before retaining a partial response; the completed block still
    /// passes through [`Self::receive_block`] exactly once.
    pub fn peer_can_deliver_block(&self, peer: PeerId, hash: &BlockHash) -> bool {
        if let Some(inflight) = self.inflight.get(hash) {
            return inflight.request.peer == Some(peer);
        }
        self.pending
            .get(hash)
            .is_some_and(|pending| pending.peer_can_deliver(peer))
    }

    pub fn request_headers_from(
        &mut self,
        peer: PeerId,
        now: Instant,
        locator: &[BlockHash],
        stop: BlockHash,
    ) -> Result<Option<SyncAction>, SyncError> {
        let Some(state) = self.peers.get_mut(&peer) else {
            return Err(SyncError::UnexpectedBlock(format!(
                "cannot request headers from unknown peer {:?}",
                peer
            )));
        };
        if !state.ready || state.services & SERVICE_NETWORK == 0 {
            return Ok(None);
        }
        if state.headers_requested_at.is_some() {
            return Ok(None);
        }
        state.headers_requested_at = Some(now);
        self.stage = SyncStage::Headers;
        self.bump_sequence();
        Ok(Some(SyncAction::RequestHeaders {
            peer,
            locator: locator.to_vec(),
            stop,
        }))
    }

    pub fn note_headers_response(&mut self, peer: PeerId, header_count: usize) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.headers_requested_at = None;
            if header_count == 0 {
                state.advertised_height = state
                    .advertised_height
                    .min(self.best_header.as_ref().map_or(0, |tip| tip.height));
            }
        }
        self.recalculate_target();
        self.update_stage();
        self.bump_sequence();
    }

    pub fn announce_block(
        &mut self,
        peer: PeerId,
        hash: BlockHash,
        height: Height,
    ) -> Result<bool, SyncError> {
        if self.tracked.contains(&hash) {
            if let Some(pending) = self.pending.get_mut(&hash) {
                // An empty set represents wildcard eligibility for canonical
                // queued/retried work. A later inventory announcement must not
                // narrow that eligibility back to one peer.
                if !pending.announced_by.is_empty() {
                    pending.announced_by.insert(peer);
                }
            }
            return Ok(false);
        }
        if self.tracked.len() >= self.limits.maximum_pending_blocks {
            return Err(SyncError::LimitExceeded {
                context: "tracked blocks",
                limit: self.limits.maximum_pending_blocks,
                actual: self.tracked.len().saturating_add(1),
            });
        }
        let mut announced_by = BTreeSet::new();
        announced_by.insert(peer);
        self.pending.insert(
            hash,
            PendingBlock {
                hash,
                height,
                announced_by,
                retry_backoff: None,
                attempts: 0,
            },
        );
        self.tracked.insert(hash);
        self.pending_order.push_back(hash);
        self.update_stage();
        self.bump_sequence();
        Ok(true)
    }

    pub fn queue_block(&mut self, hash: BlockHash, height: Height) -> Result<bool, SyncError> {
        if self.tracked.contains(&hash) {
            return Ok(false);
        }
        if self.tracked.len() >= self.limits.maximum_pending_blocks {
            return Err(SyncError::LimitExceeded {
                context: "tracked blocks",
                limit: self.limits.maximum_pending_blocks,
                actual: self.tracked.len().saturating_add(1),
            });
        }
        self.pending.insert(
            hash,
            PendingBlock {
                hash,
                height,
                announced_by: BTreeSet::new(),
                retry_backoff: None,
                attempts: 0,
            },
        );
        self.tracked.insert(hash);
        self.pending_order.push_back(hash);
        self.update_stage();
        self.bump_sequence();
        Ok(true)
    }

    pub fn begin_local_validation(&mut self, hash: BlockHash) {
        self.pending.remove(&hash);
        if let Some(inflight) = self.inflight.remove(&hash) {
            if let Some(peer) = inflight.request.peer {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.inflight.remove(&hash);
                }
            }
        }
        self.stage = SyncStage::Validating;
        self.bump_sequence();
    }

    /// Finish stateless validation for a body whose parent/header context is
    /// not available yet. The validated body remains in the bounded orphan
    /// pool and is not counted as a durably stored canonical body.
    pub fn complete_orphan_validation(&mut self) {
        self.update_stage();
        self.bump_sequence();
    }

    pub fn receive_block(
        &mut self,
        peer: PeerId,
        hash: BlockHash,
        now: Instant,
    ) -> Result<BlockDownloadRequest, SyncError> {
        if let Some(inflight) = self.inflight.remove(&hash) {
            if inflight.request.peer != Some(peer) {
                let expected = inflight.request.peer;
                self.inflight.insert(hash, inflight);
                return Err(SyncError::UnexpectedBlock(format!(
                    "block {} arrived from peer {:?}, expected {:?}",
                    hash.to_hex(),
                    peer,
                    expected
                )));
            }
            if let Some(state) = self.peers.get_mut(&peer) {
                state.inflight.remove(&hash);
                state.last_block_received_at = Some(now);
                state.body_available = true;
            }
            self.stage = SyncStage::Validating;
            self.bump_sequence();
            return Ok(inflight.request);
        }

        // HSD peers may deliver an announced block before our scheduled
        // GETDATA reaches them, or answer just after a request timeout moved
        // the hash back to pending. Accept either only for bounded tracked
        // work and an eligible announcer; retry backoff controls new request
        // assignment, not an already-in-transit response.
        if let Some(pending) = self.pending.remove(&hash) {
            if !pending.peer_can_deliver(peer) {
                self.pending.insert(hash, pending);
                return Err(SyncError::UnexpectedBlock(format!(
                    "peer {:?} sent pending block {} without announcement eligibility",
                    peer,
                    hash.to_hex()
                )));
            }
            if let Some(state) = self.peers.get_mut(&peer) {
                state.last_block_received_at = Some(now);
                state.body_available = true;
            }
            self.stage = SyncStage::Validating;
            self.bump_sequence();
            return Ok(BlockDownloadRequest {
                hash,
                height: pending.height,
                peer: Some(peer),
                attempt: pending.attempts,
            });
        }

        Err(SyncError::UnexpectedBlock(format!(
            "peer {:?} sent unrequested block {}",
            peer,
            hash.to_hex()
        )))
    }

    pub fn complete_block(&mut self, hash: BlockHash) {
        self.pending.remove(&hash);
        if let Some(inflight) = self.inflight.remove(&hash) {
            if let Some(peer) = inflight.request.peer {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.inflight.remove(&hash);
                }
            }
        }
        self.tracked.remove(&hash);
        self.unavailable_by.remove(&hash);
        self.validated_blocks = self.validated_blocks.saturating_add(1);
        self.update_stage();
        self.bump_sequence();
    }

    /// Return already-reserved body work to the pending queue without
    /// treating local queue/worker availability as a peer or block failure.
    pub fn requeue_tracked_block(
        &mut self,
        hash: BlockHash,
        height: Height,
    ) -> Result<(), SyncError> {
        if !self.tracked.contains(&hash) {
            return Err(SyncError::UnexpectedBlock(format!(
                "cannot requeue untracked block {}",
                hash.to_hex()
            )));
        }
        self.requeue(hash, height, 0, None);
        self.update_stage();
        self.bump_sequence();
        Ok(())
    }

    /// Record an honest `notfound` response for the peer that owns the
    /// corresponding inflight request. The hash is immediately eligible for
    /// another peer, the unavailable peer is excluded for the remainder of
    /// that connection, and neither validation-failure nor retry counters
    /// advance.
    pub fn note_block_unavailable(
        &mut self,
        peer: PeerId,
        hash: BlockHash,
    ) -> Result<(), SyncError> {
        let Some(inflight) = self.inflight.get(&hash) else {
            return Err(SyncError::UnexpectedBlock(format!(
                "peer {peer:?} reported unrequested block {} unavailable",
                hash.to_hex()
            )));
        };
        if inflight.request.peer != Some(peer) {
            return Err(SyncError::UnexpectedBlock(format!(
                "peer {peer:?} reported block {} unavailable while it was assigned to {:?}",
                hash.to_hex(),
                inflight.request.peer
            )));
        }

        let inflight = self
            .inflight
            .remove(&hash)
            .expect("inflight request was checked above");
        if let Some(state) = self.peers.get_mut(&peer) {
            state.inflight.remove(&hash);
            state.unavailable_blocks = state.unavailable_blocks.saturating_add(1);
        }
        self.unavailable_by.entry(hash).or_default().insert(peer);
        self.unavailable_blocks = self.unavailable_blocks.saturating_add(1);
        // Selecting a peer that legitimately lacks a pruned block does not
        // consume the transport/validation retry budget.
        self.requeue(
            hash,
            inflight.request.height,
            inflight.attempts.saturating_sub(1),
            None,
        );
        self.update_stage();
        self.bump_sequence();
        Ok(())
    }

    /// Roll back a block-request batch which never entered the peer's
    /// outbound queue. Polling reserves every request as inflight before the
    /// transport is touched; a queue-admission race must therefore restore
    /// the exact pending work without consuming a network retry attempt.
    pub fn rollback_block_dispatch(
        &mut self,
        peer: PeerId,
        requests: &[BlockDownloadRequest],
    ) -> Result<(), SyncError> {
        let mut seen = BTreeSet::new();
        for request in requests {
            if request.peer != Some(peer) {
                return Err(SyncError::UnexpectedBlock(format!(
                    "block {} dispatch peer {:?} disagrees with batch peer {peer:?}",
                    request.hash.to_hex(),
                    request.peer
                )));
            }
            if !seen.insert(request.hash) {
                return Err(SyncError::UnexpectedBlock(format!(
                    "block dispatch batch repeats {}",
                    request.hash.to_hex()
                )));
            }
            let Some(inflight) = self.inflight.get(&request.hash) else {
                return Err(SyncError::UnexpectedBlock(format!(
                    "cannot roll back non-inflight block {}",
                    request.hash.to_hex()
                )));
            };
            if inflight.request != *request {
                return Err(SyncError::UnexpectedBlock(format!(
                    "block {} dispatch no longer matches its inflight request",
                    request.hash.to_hex()
                )));
            }
        }

        let mut pending = Vec::with_capacity(requests.len());
        for request in requests {
            let inflight = self
                .inflight
                .remove(&request.hash)
                .expect("dispatch rollback was validated above");
            if let Some(state) = self.peers.get_mut(&peer) {
                state.inflight.remove(&request.hash);
            }
            pending.push((
                inflight.request.hash,
                inflight.request.height,
                inflight.attempts.saturating_sub(1),
            ));
        }
        for (hash, height, attempts) in pending {
            self.requeue(hash, height, attempts, None);
        }
        self.update_stage();
        self.bump_sequence();
        Ok(())
    }

    pub fn reject_block(
        &mut self,
        peer: Option<PeerId>,
        hash: BlockHash,
        retryable: bool,
        now: Instant,
    ) {
        let inflight = self.inflight.remove(&hash);
        let pending = self.pending.remove(&hash);
        if let Some(inflight) = &inflight {
            if let Some(peer) = inflight.request.peer {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.inflight.remove(&hash);
                }
            }
        }
        if let Some(peer) = peer {
            if let Some(state) = self.peers.get_mut(&peer) {
                state.failures = state.failures.saturating_add(1);
            }
        }
        self.failed_blocks = self.failed_blocks.saturating_add(1);
        if retryable {
            let retry = inflight.map(|inflight| {
                (
                    inflight.request.hash,
                    inflight.request.height,
                    inflight.attempts,
                )
            });
            let retry = retry.or_else(|| {
                pending.map(|pending| (pending.hash, pending.height, pending.attempts))
            });
            if let Some((hash, height, attempts)) = retry {
                let retry_backoff = peer.map(|peer| self.retry_backoff(peer, attempts, now));
                self.requeue(hash, height, attempts, retry_backoff);
            }
        } else {
            self.tracked.remove(&hash);
            self.unavailable_by.remove(&hash);
        }
        self.update_stage();
        self.bump_sequence();
    }

    /// Requeue a body after validation has consumed its inflight request.
    ///
    /// `failed_peer` is present only when the peer supplied bad data. Local
    /// worker failures retry immediately without affecting peer selection or
    /// the failed-block counter.
    pub fn retry_validation_failure(
        &mut self,
        hash: BlockHash,
        height: Height,
        attempts: u8,
        failed_peer: Option<PeerId>,
        now: Instant,
    ) {
        if let Some(peer) = failed_peer {
            if let Some(state) = self.peers.get_mut(&peer) {
                state.failures = state.failures.saturating_add(1);
            }
            self.failed_blocks = self.failed_blocks.saturating_add(1);
        }
        let retry_backoff = failed_peer.map(|peer| self.retry_backoff(peer, attempts, now));
        self.requeue(hash, height, attempts, retry_backoff);
        self.update_stage();
        self.bump_sequence();
    }

    pub fn poll(&mut self, now: Instant, locator: &[BlockHash]) -> Vec<SyncAction> {
        let mut actions = Vec::new();
        self.expire_header_requests(now, &mut actions);
        self.expire_block_requests(now, &mut actions);

        if self.needs_headers() {
            if let Some(peer) = self.select_header_peer() {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.headers_requested_at = Some(now);
                }
                actions.push(SyncAction::RequestHeaders {
                    peer,
                    locator: locator.to_vec(),
                    stop: BlockHash::ZERO,
                });
            }
        }

        // Inspect each currently pending block at most once. A temporarily
        // ineligible head is rotated behind other work instead of stalling the
        // entire queue or spinning indefinitely.
        let mut pending_to_scan = self.pending.len();
        while self.inflight.len() < self.limits.maximum_inflight_blocks && pending_to_scan > 0 {
            pending_to_scan -= 1;
            let Some(hash) = self.pop_pending_hash() else {
                break;
            };
            let Some(pending) = self.pending.remove(&hash) else {
                continue;
            };
            let Some(peer) = self.select_block_peer(&pending, now) else {
                self.pending.insert(hash, pending);
                self.pending_order.push_back(hash);
                continue;
            };
            let attempts = pending.attempts.saturating_add(1);
            let request = BlockDownloadRequest {
                hash: pending.hash,
                height: pending.height,
                peer: Some(peer),
                attempt: attempts,
            };
            if let Some(state) = self.peers.get_mut(&peer) {
                state.inflight.insert(hash);
            }
            self.inflight.insert(
                hash,
                InflightBlock {
                    request: request.clone(),
                    requested_at: now,
                    attempts,
                },
            );
            actions.push(SyncAction::RequestBlock(request));
        }

        if now.duration_since(self.last_checkpoint) >= self.limits.checkpoint_interval {
            self.last_checkpoint = now;
            actions.push(SyncAction::PersistCheckpoint);
        }
        self.update_stage();
        actions
    }

    pub fn snapshot(&self) -> SyncSnapshot {
        SyncSnapshot {
            stage: self.stage,
            best_header: self.best_header.clone(),
            active_tip: self.active_tip.clone(),
            stored_tip: self.stored_tip.clone(),
            target_height: self.target_height,
            pending_blocks: self.pending.len(),
            inflight_blocks: self.inflight.len(),
            tracked_blocks: self.tracked.len(),
            validated_blocks: self.validated_blocks,
            failed_blocks: self.failed_blocks,
            unavailable_blocks: self.unavailable_blocks,
            sequence: self.sequence,
            peers: self
                .peers
                .iter()
                .map(|(peer, state)| PeerSyncSnapshot {
                    peer: *peer,
                    services: state.services,
                    advertised_height: state.advertised_height,
                    ready: state.ready,
                    inflight_blocks: state.inflight.len(),
                    body_available: state.body_available,
                    failures: state.failures,
                    unavailable_blocks: state.unavailable_blocks,
                })
                .collect(),
        }
    }

    pub fn metrics(&self) -> SyncMetrics {
        SyncMetrics {
            validation_queue_depth: self.pending.len().saturating_add(self.inflight.len()),
            state_connector_height: self.active_tip.as_ref().map(|tip| tip.height),
            stored_body_height: self.stored_tip.as_ref().map(|tip| tip.height),
            peer_count: self.peers.len(),
            target_height: self.target_height,
            pending_blocks: self.pending.len(),
            inflight_blocks: self.inflight.len(),
            tracked_blocks: self.tracked.len(),
            validated_blocks: self.validated_blocks,
            failed_blocks: self.failed_blocks,
            unavailable_blocks: self.unavailable_blocks,
            ..SyncMetrics::default()
        }
    }

    pub fn checkpoint_sequence(&self) -> u64 {
        self.sequence
    }

    fn expire_header_requests(&mut self, now: Instant, actions: &mut Vec<SyncAction>) {
        for (peer, state) in &mut self.peers {
            if state.headers_requested_at.is_some_and(|requested| {
                now.duration_since(requested) >= self.limits.headers_request_timeout
            }) {
                state.headers_requested_at = None;
                state.failures = state.failures.saturating_add(1);
                actions.push(SyncAction::Disconnect {
                    peer: *peer,
                    reason: "headers request timed out".to_owned(),
                });
            }
        }
    }

    fn expire_block_requests(&mut self, now: Instant, actions: &mut Vec<SyncAction>) {
        let expired = self
            .inflight
            .iter()
            .filter_map(|(hash, item)| {
                let request_expired =
                    now.duration_since(item.requested_at) >= self.limits.block_request_timeout;
                let peer_is_delivering = item
                    .request
                    .peer
                    .and_then(|peer| self.peers.get(&peer))
                    .and_then(|state| state.last_block_received_at)
                    .is_some_and(|last_received| {
                        last_received > item.requested_at
                            && now.duration_since(last_received) < self.limits.block_request_timeout
                    });
                (request_expired && !peer_is_delivering).then_some(*hash)
            })
            .collect::<Vec<_>>();
        let mut disconnects = BTreeMap::new();
        for hash in expired {
            let Some(item) = self.inflight.remove(&hash) else {
                continue;
            };
            if let Some(peer) = item.request.peer {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.inflight.remove(&hash);
                    state.failures = state.failures.saturating_add(1);
                }
                disconnects
                    .entry(peer)
                    .or_insert_with(|| format!("block {} request timed out", hash.to_hex()));
            }
            if item.attempts < self.limits.maximum_retries {
                let retry_backoff = item
                    .request
                    .peer
                    .map(|peer| self.retry_backoff(peer, item.attempts, now));
                self.requeue(
                    item.request.hash,
                    item.request.height,
                    item.attempts,
                    retry_backoff,
                );
            } else if let Some(peer) = item.request.peer {
                // The terminal request has left every scheduler/validator/
                // orphan stage. Release its reservation so canonical queueing
                // can reconsider it after the peer is disconnected.
                self.tracked.remove(&hash);
                self.unavailable_by.remove(&hash);
                disconnects.insert(
                    peer,
                    format!("block {} exhausted retry budget", hash.to_hex()),
                );
            }
        }
        for (peer, reason) in disconnects {
            if !actions.iter().any(
                |action| matches!(action, SyncAction::Disconnect { peer: queued, .. } if *queued == peer),
            ) {
                actions.push(SyncAction::Disconnect { peer, reason });
            }
        }
    }

    fn retry_backoff(&self, peer: PeerId, attempts: u8, now: Instant) -> PeerRetryBackoff {
        const MAXIMUM_BACKOFF: Duration = Duration::from_secs(60);

        let exponent = u32::from(attempts.saturating_sub(1).min(6));
        let multiplier = 1_u32 << exponent;
        let delay = self
            .limits
            .block_request_timeout
            .saturating_mul(multiplier)
            .min(MAXIMUM_BACKOFF);
        PeerRetryBackoff {
            peer,
            eligible_at: now.checked_add(delay).unwrap_or(now),
        }
    }

    fn requeue(
        &mut self,
        hash: BlockHash,
        height: Height,
        attempts: u8,
        retry_backoff: Option<PeerRetryBackoff>,
    ) {
        if !self.tracked.contains(&hash) && self.tracked.len() >= self.limits.maximum_pending_blocks
        {
            self.failed_blocks = self.failed_blocks.saturating_add(1);
            self.unavailable_by.remove(&hash);
            return;
        }
        self.tracked.insert(hash);
        self.pending.insert(
            hash,
            PendingBlock {
                hash,
                height,
                // Retried canonical work is available to every network-capable
                // peer. Only the failed peer is time-gated below, so unusable
                // or newly registered peers cannot strand the request.
                announced_by: BTreeSet::new(),
                retry_backoff,
                attempts,
            },
        );
        self.pending_order.push_back(hash);
    }

    fn pop_pending_hash(&mut self) -> Option<BlockHash> {
        while let Some(hash) = self.pending_order.pop_front() {
            if self.pending.contains_key(&hash) {
                return Some(hash);
            }
        }
        None
    }

    fn select_header_peer(&self) -> Option<PeerId> {
        self.peers
            .iter()
            .filter(|(_, state)| {
                state.ready
                    && state.services & SERVICE_NETWORK != 0
                    && state.headers_requested_at.is_none()
            })
            .max_by_key(|(_, state)| (state.advertised_height, std::cmp::Reverse(state.failures)))
            .map(|(peer, _)| *peer)
    }

    fn select_block_peer(&self, pending: &PendingBlock, now: Instant) -> Option<PeerId> {
        let unavailable = self.unavailable_by.get(&pending.hash);
        self.peers
            .iter()
            .filter(|(peer, state)| {
                let body_window = if state.body_available {
                    self.limits.maximum_inflight_per_peer
                } else {
                    1
                };
                state.ready
                    && state.services & SERVICE_NETWORK != 0
                    && state.inflight.len() < body_window
                    && pending.peer_is_eligible(**peer, now)
                    && unavailable.is_none_or(|unavailable| !unavailable.contains(peer))
            })
            .min_by_key(|(_, state)| (state.inflight.len(), state.failures))
            .map(|(peer, _)| *peer)
    }

    fn recalculate_target(&mut self) {
        self.target_height = self
            .peers
            .values()
            .filter(|state| state.ready && state.services & SERVICE_NETWORK != 0)
            .map(|state| state.advertised_height)
            .max();
    }

    fn needs_headers(&self) -> bool {
        let current = self.best_header.as_ref().map_or(0, |tip| tip.height);
        self.target_height.is_some_and(|target| current < target)
            || matches!(self.stage, SyncStage::Idle | SyncStage::Headers)
    }

    fn update_stage(&mut self) {
        if self.peers.is_empty() {
            self.stage = SyncStage::Idle;
            return;
        }
        let best_height = self.best_header.as_ref().map_or(0, |tip| tip.height);
        let stored_height = self.stored_tip.as_ref().map_or(0, |tip| tip.height);
        let active_height = self.active_tip.as_ref().map_or(0, |tip| tip.height);
        let target = self.target_height.unwrap_or(best_height);
        self.stage = if best_height < target {
            SyncStage::Headers
        } else if self.headers_only {
            SyncStage::Synced
        } else if !self.inflight.is_empty()
            || !self.pending.is_empty()
            || stored_height < best_height
        {
            SyncStage::Blocks
        } else if active_height < best_height {
            SyncStage::BackgroundVerify
        } else {
            SyncStage::Synced
        };
    }

    fn bump_sequence(&mut self) {
        self.sequence = self.sequence.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(byte: u8, height: u32) -> ChainTip {
        ChainTip {
            hash: BlockHash::new([byte; 32]),
            height,
            chainwork: u64::from(height).into(),
        }
    }

    #[test]
    fn scheduler_bounds_and_requeues_block_requests() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            maximum_retries: 2,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 10)
            .expect("peer");
        scheduler.set_best_header(Some(tip(1, 10)));
        scheduler.set_active_tip(Some(tip(2, 8)));
        let hash = BlockHash::new([3; 32]);
        scheduler.announce_block(PeerId(1), hash, 9).expect("queue");
        let actions = scheduler.poll(now, &[tip(2, 8).hash]);
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request) if request.hash == hash && request.attempt == 1
        )));
        let actions = scheduler.poll(now + Duration::from_millis(11), &[tip(2, 8).hash]);
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Disconnect {
                peer: PeerId(1),
                ..
            }
        )));
        assert_eq!(scheduler.snapshot().pending_blocks, 1);
        assert_eq!(scheduler.snapshot().inflight_blocks, 0);
        assert!(!actions.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request) if request.hash == hash
        )));

        let actions = scheduler.poll(now + Duration::from_millis(20), &[tip(2, 8).hash]);
        assert!(!actions.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request) if request.hash == hash
        )));

        let actions = scheduler.poll(now + Duration::from_millis(21), &[tip(2, 8).hash]);
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash && request.peer == Some(PeerId(1)) && request.attempt == 2
        )));

        let actions = scheduler.poll(now + Duration::from_millis(32), &[tip(2, 8).hash]);
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Disconnect {
                peer: PeerId(1),
                ..
            }
        )));
        assert_eq!(scheduler.snapshot().pending_blocks, 0);
        assert_eq!(scheduler.snapshot().inflight_blocks, 0);
        assert_eq!(scheduler.snapshot().tracked_blocks, 0);
        assert_eq!(scheduler.available_pending_slots(), 8_192);
    }

    #[test]
    fn failed_outbound_batch_rolls_back_without_consuming_attempts() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 2,
            maximum_inflight_per_peer: 2,
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        let peer = PeerId(1);
        scheduler
            .register_peer(peer, SERVICE_NETWORK, 10)
            .expect("peer");
        scheduler
            .peers
            .get_mut(&peer)
            .expect("registered peer")
            .body_available = true;
        let first = BlockHash::new([3; 32]);
        let second = BlockHash::new([4; 32]);
        scheduler.queue_block(first, 1).expect("first body");
        scheduler.queue_block(second, 2).expect("second body");

        let requests = scheduler
            .poll(now, &[])
            .into_iter()
            .filter_map(|action| match action {
                SyncAction::RequestBlock(request) => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.attempt == 1));
        assert_eq!(scheduler.snapshot().inflight_blocks, 2);

        scheduler
            .rollback_block_dispatch(peer, &requests)
            .expect("dispatch rollback");
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 2);
        assert_eq!(snapshot.inflight_blocks, 0);
        assert_eq!(snapshot.tracked_blocks, 2);
        assert_eq!(snapshot.peers[0].inflight_blocks, 0);
        assert_eq!(snapshot.failed_blocks, 0);

        let retried = scheduler
            .poll(now, &[])
            .into_iter()
            .filter_map(|action| match action {
                SyncAction::RequestBlock(request) => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(retried.len(), 2);
        assert!(retried.iter().all(|request| request.attempt == 1));
    }

    #[test]
    fn new_peers_prove_body_availability_before_using_the_full_window() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 6,
            maximum_inflight_per_peer: 3,
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        let first_peer = PeerId(1);
        let second_peer = PeerId(2);
        scheduler
            .register_peer(first_peer, SERVICE_NETWORK, 10)
            .expect("first peer");
        scheduler
            .register_peer(second_peer, SERVICE_NETWORK, 10)
            .expect("second peer");
        for index in 0..6u8 {
            scheduler
                .queue_block(BlockHash::new([30 + index; 32]), Height::from(index))
                .expect("body");
        }

        let probes = scheduler
            .poll(now, &[])
            .into_iter()
            .filter_map(|action| match action {
                SyncAction::RequestBlock(request) => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(probes.len(), 2);
        assert_eq!(scheduler.snapshot().pending_blocks, 4);
        assert!(scheduler
            .snapshot()
            .peers
            .iter()
            .all(|peer| peer.inflight_blocks == 1 && !peer.body_available));

        let first_probe = probes
            .iter()
            .find(|request| request.peer == Some(first_peer))
            .expect("first peer probe");
        scheduler
            .receive_block(first_peer, first_probe.hash, now + Duration::from_millis(1))
            .expect("body proof");
        scheduler.complete_block(first_probe.hash);

        let expanded = scheduler
            .poll(now + Duration::from_millis(1), &[])
            .into_iter()
            .filter_map(|action| match action {
                SyncAction::RequestBlock(request) => Some(request),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(expanded.len(), 3);
        assert!(expanded
            .iter()
            .all(|request| request.peer == Some(first_peer)));
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 1);
        assert_eq!(snapshot.inflight_blocks, 4);
        assert!(snapshot.peers[0].body_available);
        assert!(!snapshot.peers[1].body_available);
    }

    #[test]
    fn expired_block_batch_disconnects_peer_once() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 2,
            maximum_inflight_per_peer: 2,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        let peer = PeerId(1);
        scheduler
            .register_peer(peer, SERVICE_NETWORK, 10)
            .expect("peer");
        scheduler
            .peers
            .get_mut(&peer)
            .expect("registered peer")
            .body_available = true;
        scheduler
            .queue_block(BlockHash::new([5; 32]), 1)
            .expect("first body");
        scheduler
            .queue_block(BlockHash::new([6; 32]), 2)
            .expect("second body");
        assert_eq!(
            scheduler
                .poll(now, &[])
                .into_iter()
                .filter(|action| matches!(action, SyncAction::RequestBlock(_)))
                .count(),
            2
        );

        let actions = scheduler.poll(now + Duration::from_millis(11), &[]);
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, SyncAction::Disconnect { peer: target, .. } if *target == peer))
                .count(),
            1
        );
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 2);
        assert_eq!(snapshot.inflight_blocks, 0);
        assert_eq!(snapshot.failed_blocks, 0);
    }

    #[test]
    fn progressive_block_batch_uses_an_inactivity_deadline() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 2,
            maximum_inflight_per_peer: 2,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        let peer = PeerId(1);
        scheduler
            .register_peer(peer, SERVICE_NETWORK, 10)
            .expect("peer");
        scheduler
            .peers
            .get_mut(&peer)
            .expect("registered peer")
            .body_available = true;
        let first = BlockHash::new([17; 32]);
        let second = BlockHash::new([18; 32]);
        scheduler.queue_block(first, 1).expect("first body");
        scheduler.queue_block(second, 2).expect("second body");
        assert_eq!(
            scheduler
                .poll(now, &[])
                .into_iter()
                .filter(|action| matches!(action, SyncAction::RequestBlock(_)))
                .count(),
            2
        );

        scheduler
            .receive_block(peer, first, now + Duration::from_millis(9))
            .expect("progressing response");
        scheduler.complete_block(first);
        let progressing = scheduler.poll(now + Duration::from_millis(11), &[]);
        assert!(!progressing
            .iter()
            .any(|action| matches!(action, SyncAction::Disconnect { .. })));
        assert_eq!(scheduler.snapshot().inflight_blocks, 1);

        let stalled = scheduler.poll(now + Duration::from_millis(20), &[]);
        assert!(stalled.iter().any(
            |action| matches!(action, SyncAction::Disconnect { peer: target, .. } if *target == peer)
        ));
        assert_eq!(scheduler.snapshot().pending_blocks, 1);
    }

    #[test]
    fn late_block_response_is_accepted_during_request_backoff() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        let hash = BlockHash::new([16; 32]);
        scheduler.queue_block(hash, 5).expect("queue");
        let request = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == hash => Some(request),
                _ => None,
            })
            .expect("request");
        assert_eq!(request.attempt, 1);

        let timeout = scheduler.poll(now + Duration::from_millis(11), &[]);
        assert!(timeout.iter().any(|action| matches!(
            action,
            SyncAction::Disconnect {
                peer: PeerId(1),
                ..
            }
        )));
        assert_eq!(scheduler.snapshot().pending_blocks, 1);

        let late = scheduler
            .receive_block(PeerId(1), hash, now + Duration::from_millis(12))
            .expect("late response");
        assert_eq!(late.hash, hash);
        assert_eq!(late.attempt, 1);
        assert_eq!(scheduler.snapshot().pending_blocks, 0);
        assert!(scheduler.is_tracked_block(&hash));
        scheduler.complete_block(hash);
        assert!(!scheduler.is_tracked_block(&hash));
    }

    #[test]
    fn timed_out_block_fails_over_to_an_alternate_peer_immediately() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 10)
            .expect("peer 1");
        scheduler
            .register_peer(PeerId(2), SERVICE_NETWORK, 10)
            .expect("peer 2");
        let hash = BlockHash::new([4; 32]);
        scheduler.announce_block(PeerId(1), hash, 9).expect("queue");
        let first = scheduler.poll(now, &[]);
        assert!(first.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash && request.peer == Some(PeerId(1))
        )));

        let retried = scheduler.poll(now + Duration::from_millis(11), &[]);
        assert!(retried.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash
                    && request.peer == Some(PeerId(2))
                    && request.attempt == 2
        )));
    }

    #[test]
    fn unusable_alternate_does_not_strand_backed_off_peer_after_deadline() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 10)
            .expect("network peer");
        scheduler
            .register_peer(PeerId(2), 0, 10)
            .expect("non-network peer");
        let hash = BlockHash::new([7; 32]);
        scheduler.announce_block(PeerId(1), hash, 9).expect("queue");
        let _ = scheduler.poll(now, &[]);

        let timed_out = scheduler.poll(now + Duration::from_millis(11), &[]);
        assert!(!timed_out.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request) if request.hash == hash
        )));

        let retried = scheduler.poll(now + Duration::from_millis(21), &[]);
        assert!(retried.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash
                    && request.peer == Some(PeerId(1))
                    && request.attempt == 2
        )));
    }

    #[test]
    fn reannouncement_does_not_narrow_wildcard_retry_eligibility() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 10)
            .expect("network peer");
        scheduler
            .register_peer(PeerId(2), 0, 10)
            .expect("initially ineligible peer");
        let hash = BlockHash::new([10; 32]);
        scheduler.announce_block(PeerId(1), hash, 9).expect("queue");
        let _ = scheduler.poll(now, &[]);
        let _ = scheduler.poll(now + Duration::from_millis(11), &[]);

        assert!(!scheduler
            .announce_block(PeerId(1), hash, 9)
            .expect("reannounce"));
        scheduler.update_peer_tip(PeerId(2), 10, SERVICE_NETWORK);
        let actions = scheduler.poll(now + Duration::from_millis(12), &[]);
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash
                    && request.peer == Some(PeerId(2))
                    && request.attempt == 2
        )));
    }

    #[test]
    fn backed_off_head_does_not_block_later_eligible_work() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            block_request_timeout: Duration::from_millis(10),
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 10)
            .expect("peer");
        let backed_off = BlockHash::new([5; 32]);
        let eligible = BlockHash::new([6; 32]);
        scheduler
            .announce_block(PeerId(1), backed_off, 9)
            .expect("queue backed-off block");
        let _ = scheduler.poll(now, &[]);
        let timeout = scheduler.poll(now + Duration::from_millis(11), &[]);
        assert!(!timeout.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request) if request.hash == backed_off
        )));
        scheduler
            .queue_block(eligible, 10)
            .expect("queue eligible block");

        let actions = scheduler.poll(now + Duration::from_millis(12), &[]);
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == eligible && request.peer == Some(PeerId(1))
        )));
        assert_eq!(scheduler.snapshot().pending_blocks, 1);
    }

    #[test]
    fn equal_peer_height_reaches_synced_only_after_active_tip_catches_up() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        scheduler.set_best_header(Some(tip(1, 5)));
        scheduler.set_active_tip(Some(tip(2, 4)));
        scheduler.set_stored_tip(Some(tip(2, 4)));
        assert_eq!(scheduler.stage(), SyncStage::Blocks);
        scheduler.set_stored_tip(Some(tip(1, 5)));
        assert_eq!(scheduler.stage(), SyncStage::BackgroundVerify);
        scheduler.set_active_tip(Some(tip(1, 5)));
        assert_eq!(scheduler.stage(), SyncStage::Synced);
    }

    #[test]
    fn headers_only_reaches_synced_without_body_or_active_tips() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler.set_headers_only(true);
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        scheduler.set_best_header(Some(tip(1, 4)));
        assert_eq!(scheduler.stage(), SyncStage::Headers);
        scheduler.set_best_header(Some(tip(2, 5)));
        assert_eq!(scheduler.stage(), SyncStage::Synced);
        assert_eq!(scheduler.snapshot().stored_tip, None);
        assert_eq!(scheduler.snapshot().active_tip, None);
    }

    #[test]
    fn early_pending_block_is_accepted_only_from_an_announcer() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer 1");
        scheduler
            .register_peer(PeerId(2), SERVICE_NETWORK, 5)
            .expect("peer 2");
        let hash = BlockHash::new([8; 32]);
        scheduler
            .announce_block(PeerId(1), hash, 5)
            .expect("announce");
        assert!(scheduler.peer_can_deliver_block(PeerId(1), &hash));
        assert!(!scheduler.peer_can_deliver_block(PeerId(2), &hash));
        assert!(scheduler.receive_block(PeerId(2), hash, now).is_err());
        assert!(scheduler.receive_block(PeerId(1), hash, now).is_ok());
    }

    #[test]
    fn explicit_headers_request_is_single_flight_per_peer() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        let locator = [BlockHash::new([1; 32])];
        assert!(scheduler
            .request_headers_from(PeerId(1), now, &locator, BlockHash::ZERO)
            .expect("request")
            .is_some());
        assert!(scheduler
            .request_headers_from(PeerId(1), now, &locator, BlockHash::ZERO)
            .expect("second")
            .is_none());
        assert!(scheduler.rollback_header_dispatch(PeerId(1)));
        assert!(scheduler
            .request_headers_from(PeerId(1), now, &locator, BlockHash::ZERO)
            .expect("after rollback")
            .is_some());
        scheduler.note_headers_response(PeerId(1), 0);
        assert!(!scheduler.rollback_header_dispatch(PeerId(1)));
        assert!(scheduler
            .request_headers_from(PeerId(1), now, &locator, BlockHash::ZERO)
            .expect("after response")
            .is_some());
    }

    #[test]
    fn restore_preserves_stored_tip() {
        let now = Instant::now();
        let stored = tip(3, 4);
        let checkpoint = SyncCheckpoint {
            sequence: 9,
            stage: SyncStage::Blocks,
            best_header: Some(tip(1, 5)),
            active_tip: Some(tip(2, 3)),
            stored_tip: Some(stored.clone()),
            target_height: Some(5),
            updated_at: 0,
        };
        let scheduler =
            SyncScheduler::restore(SyncLimits::default(), now, &checkpoint).expect("restore");
        assert_eq!(scheduler.stored_tip(), Some(&stored));
        assert_eq!(scheduler.snapshot().sequence, 9);
    }

    #[test]
    fn removing_peer_requeues_its_inflight_work() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        scheduler
            .register_peer(PeerId(2), SERVICE_NETWORK, 5)
            .expect("peer");
        let hash = BlockHash::new([9; 32]);
        scheduler.announce_block(PeerId(1), hash, 5).expect("queue");
        let _ = scheduler.poll(now, &[]);
        scheduler.remove_peer(PeerId(1));
        assert_eq!(scheduler.snapshot().pending_blocks, 1);
        assert_eq!(scheduler.snapshot().inflight_blocks, 0);
    }

    #[test]
    fn unavailable_block_fails_over_without_blaming_or_reselecting_peer() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer 1");
        scheduler
            .register_peer(PeerId(2), SERVICE_NETWORK, 5)
            .expect("peer 2");
        let hash = BlockHash::new([10; 32]);
        scheduler.queue_block(hash, 5).expect("queue");

        let first = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == hash => Some(request),
                _ => None,
            })
            .expect("first request");
        assert_eq!(first.peer, Some(PeerId(1)));
        assert_eq!(first.attempt, 1);

        scheduler
            .note_block_unavailable(PeerId(1), hash)
            .expect("honest notfound");
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 1);
        assert_eq!(snapshot.inflight_blocks, 0);
        assert_eq!(snapshot.failed_blocks, 0);
        assert_eq!(snapshot.unavailable_blocks, 1);
        assert_eq!(snapshot.peers[0].failures, 0);
        assert_eq!(snapshot.peers[0].unavailable_blocks, 1);

        let second = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == hash => Some(request),
                _ => None,
            })
            .expect("alternate request");
        assert_eq!(second.peer, Some(PeerId(2)));
        assert_eq!(second.attempt, 1);

        scheduler
            .note_block_unavailable(PeerId(2), hash)
            .expect("second honest notfound");
        assert!(!scheduler.poll(now, &[]).iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request) if request.hash == hash
        )));
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 1);
        assert_eq!(snapshot.failed_blocks, 0);
        assert_eq!(snapshot.unavailable_blocks, 2);
    }

    #[test]
    fn unsolicited_notfound_cannot_cancel_another_peers_request() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer 1");
        scheduler
            .register_peer(PeerId(2), SERVICE_NETWORK, 5)
            .expect("peer 2");
        let hash = BlockHash::new([12; 32]);
        scheduler.queue_block(hash, 5).expect("queue");
        let request = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == hash => Some(request),
                _ => None,
            })
            .expect("request");
        assert_eq!(request.peer, Some(PeerId(1)));

        assert!(scheduler.note_block_unavailable(PeerId(2), hash).is_err());
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 0);
        assert_eq!(snapshot.inflight_blocks, 1);
        assert_eq!(snapshot.failed_blocks, 0);
        assert_eq!(snapshot.unavailable_blocks, 0);
        assert!(snapshot
            .peers
            .iter()
            .all(|peer| peer.failures == 0 && peer.unavailable_blocks == 0));
    }

    #[test]
    fn body_reservation_survives_validation_and_retry_without_capacity_overflow() {
        let now = Instant::now();
        let limits = SyncLimits {
            maximum_pending_blocks: 2,
            maximum_inflight_blocks: 1,
            maximum_inflight_per_peer: 1,
            ..SyncLimits::default()
        };
        let mut scheduler = SyncScheduler::new(limits, now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        let first = BlockHash::new([13; 32]);
        let second = BlockHash::new([14; 32]);
        let extra = BlockHash::new([15; 32]);
        scheduler.queue_block(first, 1).expect("first");
        scheduler.queue_block(second, 2).expect("second");

        let request = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == first => Some(request),
                _ => None,
            })
            .expect("request");
        scheduler
            .receive_block(PeerId(1), first, now)
            .expect("validation reservation");
        assert_eq!(scheduler.available_pending_slots(), 0);
        assert!(scheduler.queue_block(extra, 3).is_err());

        scheduler.retry_validation_failure(first, request.height, request.attempt, None, now);
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 2);
        assert_eq!(snapshot.tracked_blocks, 2);
        assert_eq!(snapshot.inflight_blocks, 0);
        assert_eq!(snapshot.failed_blocks, 0);
        assert!(!scheduler.queue_block(first, 1).expect("duplicate"));
    }

    #[test]
    fn local_validation_failure_retries_without_blaming_peer() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        scheduler
            .register_peer(PeerId(1), SERVICE_NETWORK, 5)
            .expect("peer");
        let hash = BlockHash::new([11; 32]);
        scheduler.announce_block(PeerId(1), hash, 5).expect("queue");
        let request = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == hash => Some(request),
                _ => None,
            })
            .expect("request");
        scheduler
            .receive_block(PeerId(1), hash, now)
            .expect("receive");

        scheduler.retry_validation_failure(hash, request.height, request.attempt, None, now);

        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.pending_blocks, 1);
        assert_eq!(snapshot.failed_blocks, 0);
        assert_eq!(snapshot.peers[0].failures, 0);
        assert!(scheduler.poll(now, &[]).iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash
                    && request.peer == Some(PeerId(1))
                    && request.attempt == 2
        )));
    }

    #[test]
    fn permanent_rejection_removes_pending_descendant() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        let hash = BlockHash::new([12; 32]);
        scheduler.queue_block(hash, 5).expect("queue");

        scheduler.reject_block(None, hash, false, now);

        assert!(!scheduler.is_tracked_block(&hash));
        assert_eq!(scheduler.snapshot().pending_blocks, 0);
        assert_eq!(scheduler.snapshot().failed_blocks, 1);
    }

    #[test]
    fn bad_validation_response_fails_over_and_blames_only_its_peer() {
        let now = Instant::now();
        let mut scheduler = SyncScheduler::new(SyncLimits::default(), now).expect("scheduler");
        for peer in [PeerId(1), PeerId(2)] {
            scheduler
                .register_peer(peer, SERVICE_NETWORK, 5)
                .expect("peer");
        }
        let hash = BlockHash::new([13; 32]);
        scheduler.announce_block(PeerId(1), hash, 5).expect("queue");
        let request = scheduler
            .poll(now, &[])
            .into_iter()
            .find_map(|action| match action {
                SyncAction::RequestBlock(request) if request.hash == hash => Some(request),
                _ => None,
            })
            .expect("request");
        assert_eq!(request.peer, Some(PeerId(1)));
        scheduler
            .receive_block(PeerId(1), hash, now)
            .expect("receive");

        scheduler.retry_validation_failure(
            hash,
            request.height,
            request.attempt,
            Some(PeerId(1)),
            now,
        );

        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.failed_blocks, 1);
        assert_eq!(snapshot.peers[0].failures, 1);
        assert_eq!(snapshot.peers[1].failures, 0);
        assert!(scheduler.poll(now, &[]).iter().any(|action| matches!(
            action,
            SyncAction::RequestBlock(request)
                if request.hash == hash
                    && request.peer == Some(PeerId(2))
                    && request.attempt == 2
        )));
    }
}
