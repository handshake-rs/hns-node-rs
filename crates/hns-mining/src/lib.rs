#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use hns_consensus::{block_weight, ConsensusParams, HeaderConsensus, Network};
use hns_primitives::{
    blake2b_256_many, Block, BlockHash, Header, Height, Transaction, Uint256, MAX_BLOCK_WEIGHT,
    NONCE_SIZE,
};
use tokio::sync::{broadcast, watch};

pub const MINING_EVENT_CAPACITY: usize = 256;
pub const MAX_PREPARED_JOBS: usize = 16;
pub type MiningGeneration = u64;
pub type MiningJobId = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderSummary {
    pub hash: BlockHash,
    pub parent_hash: BlockHash,
    pub height: Height,
    pub tree_root: [u8; 32],
    pub time: u64,
    pub bits: u32,
}

impl HeaderSummary {
    pub fn from_block(block: &Block, height: Height) -> Self {
        Self {
            hash: block.hash(),
            parent_hash: block.header.prev_block,
            height,
            tree_root: block.header.tree_root,
            time: block.header.time,
            bits: block.header.bits,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningSnapshot {
    pub network_id: u8,
    pub generation: MiningGeneration,
    pub tip: HeaderSummary,
    pub chainwork: Uint256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainEvent {
    CandidateTipSeen {
        committed_generation: MiningGeneration,
        candidate: HeaderSummary,
    },
    BlockValidated {
        committed_generation: MiningGeneration,
        block: HeaderSummary,
    },
    TipCommitted {
        previous_generation: MiningGeneration,
        snapshot: Arc<MiningSnapshot>,
    },
    TipCleared {
        previous_generation: MiningGeneration,
        generation: MiningGeneration,
    },
    ReorgStarted {
        committed_generation: MiningGeneration,
        disconnect_count: usize,
        connect_count: usize,
    },
    ReorgAborted {
        committed_generation: MiningGeneration,
    },
    MempoolReconciled {
        tip_generation: MiningGeneration,
        mempool_generation: u64,
    },
}

#[derive(Debug)]
pub struct MiningSubscriptions {
    pub events: broadcast::Receiver<ChainEvent>,
    pub latest_snapshot: watch::Receiver<Option<Arc<MiningSnapshot>>>,
}

/// Nonblocking staged-event boundary. The watch channel is authoritative for
/// resynchronization after a bounded broadcast receiver reports lag.
#[derive(Clone, Debug)]
pub struct MiningEventHub {
    events: broadcast::Sender<ChainEvent>,
    latest_snapshot: watch::Sender<Option<Arc<MiningSnapshot>>>,
    state: Arc<Mutex<HubState>>,
}

#[derive(Clone, Debug)]
struct HubState {
    generation: MiningGeneration,
    snapshot: Option<Arc<MiningSnapshot>>,
}

impl MiningEventHub {
    pub fn new(initial: Option<Arc<MiningSnapshot>>) -> Result<Self, MiningError> {
        let generation = initial.as_ref().map_or(0, |snapshot| snapshot.generation);
        Self::from_durable(generation, initial)
    }

    pub fn from_durable(
        generation: MiningGeneration,
        initial: Option<Arc<MiningSnapshot>>,
    ) -> Result<Self, MiningError> {
        if initial
            .as_ref()
            .is_some_and(|snapshot| snapshot.generation != generation || generation == 0)
        {
            return Err(MiningError::InvalidGeneration);
        }
        let (events, _) = broadcast::channel(MINING_EVENT_CAPACITY);
        let (latest_snapshot, _) = watch::channel(initial.clone());
        Ok(Self {
            events,
            latest_snapshot,
            state: Arc::new(Mutex::new(HubState {
                generation,
                snapshot: initial,
            })),
        })
    }

    pub fn subscribe(&self) -> MiningSubscriptions {
        MiningSubscriptions {
            events: self.events.subscribe(),
            latest_snapshot: self.latest_snapshot.subscribe(),
        }
    }

    pub fn snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot
            .clone()
    }

    pub fn committed_generation(&self) -> MiningGeneration {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation
    }

    pub fn candidate_tip_seen(&self, candidate: HeaderSummary) {
        let _ = self.events.send(ChainEvent::CandidateTipSeen {
            committed_generation: self.committed_generation(),
            candidate,
        });
    }

    pub fn block_validated(&self, block: HeaderSummary) {
        let _ = self.events.send(ChainEvent::BlockValidated {
            committed_generation: self.committed_generation(),
            block,
        });
    }

    pub fn tip_committed(&self, snapshot: Arc<MiningSnapshot>) -> Result<(), MiningError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_generation = state.generation;
        if snapshot.generation <= previous_generation || snapshot.generation == 0 {
            return Err(MiningError::InvalidGeneration);
        }
        state.generation = snapshot.generation;
        state.snapshot = Some(Arc::clone(&snapshot));
        self.latest_snapshot
            .send_replace(Some(Arc::clone(&snapshot)));
        let _ = self.events.send(ChainEvent::TipCommitted {
            previous_generation,
            snapshot,
        });
        Ok(())
    }

    pub fn tip_cleared(&self, generation: MiningGeneration) -> Result<(), MiningError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_generation = state.generation;
        if generation <= previous_generation || generation == 0 {
            return Err(MiningError::InvalidGeneration);
        }
        state.generation = generation;
        state.snapshot = None;
        self.latest_snapshot.send_replace(None);
        let _ = self.events.send(ChainEvent::TipCleared {
            previous_generation,
            generation,
        });
        Ok(())
    }

    pub fn reorg_started(&self, disconnect_count: usize, connect_count: usize) {
        let _ = self.events.send(ChainEvent::ReorgStarted {
            committed_generation: self.committed_generation(),
            disconnect_count,
            connect_count,
        });
    }

    pub fn reorg_aborted(&self) {
        let _ = self.events.send(ChainEvent::ReorgAborted {
            committed_generation: self.committed_generation(),
        });
    }

    pub fn mempool_reconciled(
        &self,
        tip_generation: MiningGeneration,
        mempool_generation: u64,
    ) -> Result<(), MiningError> {
        if tip_generation == 0
            || tip_generation != self.committed_generation()
            || mempool_generation == 0
        {
            return Err(MiningError::InvalidGeneration);
        }
        let _ = self.events.send(ChainEvent::MempoolReconciled {
            tip_generation,
            mempool_generation,
        });
        Ok(())
    }
}

/// Header fields shared by every worker assignment for one immutable body.
/// `mask_hash` is public; the clear mask is supplied only for reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningHeaderTemplate {
    pub parent_hash: BlockHash,
    pub tree_root: [u8; 32],
    pub reserved_root: [u8; 32],
    pub witness_root: [u8; 32],
    pub merkle_root: [u8; 32],
    pub version: u32,
    pub bits: u32,
    pub minimum_time: u64,
    pub mask_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMiningJob {
    job_id: MiningJobId,
    snapshot_generation: MiningGeneration,
    header: MiningHeaderTemplate,
    transactions: Arc<[Transaction]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolvedMiningCandidate {
    job_id: MiningJobId,
    snapshot_generation: MiningGeneration,
    parent_height: Height,
    block: Block,
}

impl SolvedMiningCandidate {
    pub const fn job_id(&self) -> MiningJobId {
        self.job_id
    }

    pub const fn snapshot_generation(&self) -> MiningGeneration {
        self.snapshot_generation
    }

    pub const fn parent_height(&self) -> Height {
        self.parent_height
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub fn into_block(self) -> Block {
        self.block
    }
}

impl PreparedMiningJob {
    pub fn new(
        snapshot: &MiningSnapshot,
        header: MiningHeaderTemplate,
        transactions: Arc<[Transaction]>,
    ) -> Result<Self, MiningError> {
        if header.parent_hash != snapshot.tip.hash || transactions.is_empty() {
            return Err(MiningError::InvalidJob);
        }
        let provisional = Block {
            header: Header {
                time: header.minimum_time,
                prev_block: header.parent_hash,
                tree_root: header.tree_root,
                reserved_root: header.reserved_root,
                witness_root: header.witness_root,
                merkle_root: header.merkle_root,
                version: header.version,
                bits: header.bits,
                ..Header::default()
            },
            transactions: transactions.to_vec(),
        };
        let network =
            Network::from_canonical_id(snapshot.network_id).ok_or(MiningError::InvalidJob)?;
        if provisional.encode().len() > MAX_BLOCK_WEIGHT
            || block_weight(&provisional) > MAX_BLOCK_WEIGHT
            || HeaderConsensus::new(ConsensusParams::for_network(network))
                .validate_block_body(&provisional)
                .is_err()
        {
            return Err(MiningError::InvalidJob);
        }
        let job_id = job_id(
            snapshot.network_id,
            snapshot.generation,
            &header,
            &transactions,
        );
        Ok(Self {
            job_id,
            snapshot_generation: snapshot.generation,
            header,
            transactions,
        })
    }

    pub const fn job_id(&self) -> MiningJobId {
        self.job_id
    }

    pub const fn snapshot_generation(&self) -> MiningGeneration {
        self.snapshot_generation
    }

    pub const fn header(&self) -> &MiningHeaderTemplate {
        &self.header
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn validate_for_snapshot(&self, snapshot: &MiningSnapshot) -> Result<(), MiningError> {
        if self.snapshot_generation != snapshot.generation
            || self.header.parent_hash != snapshot.tip.hash
            || self.job_id
                != job_id(
                    snapshot.network_id,
                    snapshot.generation,
                    &self.header,
                    &self.transactions,
                )
        {
            return Err(MiningError::StaleJob);
        }
        Ok(())
    }

    pub fn reconstruct(
        &self,
        nonce: u32,
        time: u64,
        extra_nonce: [u8; NONCE_SIZE],
        mask: [u8; 32],
    ) -> Result<Block, MiningError> {
        if time < self.header.minimum_time
            || blake2b_256_many([
                self.header.parent_hash.as_bytes().as_slice(),
                mask.as_slice(),
            ]) != self.header.mask_hash
        {
            return Err(MiningError::InvalidReconstruction);
        }
        let block = Block {
            header: Header {
                nonce,
                time,
                prev_block: self.header.parent_hash,
                tree_root: self.header.tree_root,
                extra_nonce,
                reserved_root: self.header.reserved_root,
                witness_root: self.header.witness_root,
                merkle_root: self.header.merkle_root,
                version: self.header.version,
                bits: self.header.bits,
                mask,
            },
            transactions: self.transactions.to_vec(),
        };
        if block.encode().len() > MAX_BLOCK_WEIGHT
            || block_weight(&block) > MAX_BLOCK_WEIGHT
            || block.header.mask_hash() != self.header.mask_hash
        {
            return Err(MiningError::InvalidReconstruction);
        }
        Ok(block)
    }

    pub fn admit_solution(
        &self,
        snapshot: &MiningSnapshot,
        nonce: u32,
        time: u64,
        extra_nonce: [u8; NONCE_SIZE],
        mask: [u8; 32],
    ) -> Result<SolvedMiningCandidate, MiningError> {
        self.validate_for_snapshot(snapshot)?;
        let block = self.reconstruct(nonce, time, extra_nonce, mask)?;
        if !block.header.verify_pow() {
            return Err(MiningError::InsufficientProofOfWork);
        }
        let network =
            Network::from_canonical_id(snapshot.network_id).ok_or(MiningError::InvalidJob)?;
        HeaderConsensus::new(ConsensusParams::for_network(network))
            .validate_block_body(&block)
            .map_err(|_| MiningError::InvalidReconstruction)?;
        Ok(SolvedMiningCandidate {
            job_id: self.job_id,
            snapshot_generation: self.snapshot_generation,
            parent_height: snapshot.tip.height,
            block,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct PreparedJobSet {
    jobs: BTreeMap<MiningJobId, Arc<PreparedMiningJob>>,
}

impl PreparedJobSet {
    pub fn insert(
        &mut self,
        job: PreparedMiningJob,
    ) -> Result<Arc<PreparedMiningJob>, MiningError> {
        if let Some(existing) = self.jobs.get(&job.job_id) {
            if existing.as_ref() == &job {
                return Ok(Arc::clone(existing));
            }
            return Err(MiningError::JobConflict);
        }
        if self.jobs.len() >= MAX_PREPARED_JOBS {
            return Err(MiningError::JobCapacity);
        }
        let job = Arc::new(job);
        self.jobs.insert(job.job_id, Arc::clone(&job));
        Ok(job)
    }

    /// Activate only a job bound to the exact committed generation and parent,
    /// then retire every job prepared for an obsolete generation.
    pub fn activate(
        &mut self,
        job_id: MiningJobId,
        snapshot: &MiningSnapshot,
    ) -> Result<Arc<PreparedMiningJob>, MiningError> {
        let job = self.jobs.get(&job_id).ok_or(MiningError::UnknownJob)?;
        if job.snapshot_generation != snapshot.generation
            || job.header.parent_hash != snapshot.tip.hash
        {
            return Err(MiningError::StaleJob);
        }
        let job = Arc::clone(job);
        self.jobs
            .retain(|_, candidate| candidate.snapshot_generation == snapshot.generation);
        Ok(job)
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

fn job_id(
    network_id: u8,
    generation: MiningGeneration,
    header: &MiningHeaderTemplate,
    transactions: &[Transaction],
) -> MiningJobId {
    let generation = generation.to_le_bytes();
    let version = header.version.to_le_bytes();
    let bits = header.bits.to_le_bytes();
    let minimum_time = header.minimum_time.to_le_bytes();
    let transaction_count = u64::try_from(transactions.len())
        .expect("transaction count fits in the canonical u64 encoding")
        .to_le_bytes();
    let mut transaction_bytes = Vec::new();
    transaction_bytes.extend_from_slice(&transaction_count);
    for transaction in transactions {
        let encoded = transaction.encode();
        let encoded_len = u64::try_from(encoded.len())
            .expect("transaction length fits in the canonical u64 encoding")
            .to_le_bytes();
        transaction_bytes.extend_from_slice(&encoded_len);
        transaction_bytes.extend_from_slice(&encoded);
    }
    blake2b_256_many([
        b"hsrd/mining-job/v1".as_slice(),
        [network_id].as_slice(),
        generation.as_slice(),
        header.parent_hash.as_bytes().as_slice(),
        header.tree_root.as_slice(),
        header.reserved_root.as_slice(),
        header.witness_root.as_slice(),
        header.merkle_root.as_slice(),
        version.as_slice(),
        bits.as_slice(),
        minimum_time.as_slice(),
        header.mask_hash.as_slice(),
        transaction_bytes.as_slice(),
    ])
}

#[derive(Debug, thiserror::Error)]
pub enum MiningError {
    #[error("mining generation is zero, stale, or inconsistent")]
    InvalidGeneration,
    #[error("prepared mining job is malformed or not bound to the current snapshot")]
    InvalidJob,
    #[error("prepared mining job ID conflicts with different bytes")]
    JobConflict,
    #[error("prepared mining job capacity is exhausted")]
    JobCapacity,
    #[error("prepared mining job is unknown")]
    UnknownJob,
    #[error("prepared mining job is stale")]
    StaleJob,
    #[error("opened-mask block reconstruction is invalid")]
    InvalidReconstruction,
    #[error("opened-mask mining result does not meet the HNS network target")]
    InsufficientProofOfWork,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_consensus::Network;
    use hns_primitives::{Address, Covenant, CovenantKind, Input, Outpoint, Output, Txid, Witness};

    fn transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 1,
                address: Address::new(0, vec![1; 20]).unwrap(),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn snapshot(generation: u64, marker: u8) -> MiningSnapshot {
        MiningSnapshot {
            network_id: Network::Regtest.canonical_id(),
            generation,
            tip: HeaderSummary {
                hash: BlockHash::new([marker; 32]),
                parent_hash: BlockHash::new([marker.saturating_sub(1); 32]),
                height: u32::from(marker),
                tree_root: [marker; 32],
                time: 100,
                bits: 0x207f_ffff,
            },
            chainwork: Uint256::from(u64::from(marker)),
        }
    }

    fn prepared(snapshot: &MiningSnapshot, mask: [u8; 32]) -> PreparedMiningJob {
        let transactions = Arc::<[Transaction]>::from(vec![transaction()]);
        let body = Block {
            header: Header::default(),
            transactions: transactions.to_vec(),
        };
        PreparedMiningJob::new(
            snapshot,
            MiningHeaderTemplate {
                parent_hash: snapshot.tip.hash,
                tree_root: [2; 32],
                reserved_root: [3; 32],
                witness_root: hns_consensus::block_witness_root(&body),
                merkle_root: hns_consensus::block_merkle_root(&body),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                mask_hash: blake2b_256_many([
                    snapshot.tip.hash.as_bytes().as_slice(),
                    mask.as_slice(),
                ]),
            },
            transactions,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn staged_events_are_ordered_and_snapshot_supports_lag_recovery() {
        let hub = MiningEventHub::new(None).unwrap();
        let mut subscription = hub.subscribe();
        let block = Block {
            header: Header {
                prev_block: BlockHash::new([1; 32]),
                ..Header::default()
            },
            transactions: vec![transaction()],
        };
        let summary = HeaderSummary::from_block(&block, 2);
        hub.candidate_tip_seen(summary.clone());
        hub.block_validated(summary.clone());
        let committed = Arc::new(snapshot(1, 2));
        hub.tip_committed(Arc::clone(&committed)).unwrap();

        assert!(matches!(
            subscription.events.recv().await.unwrap(),
            ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            subscription.events.recv().await.unwrap(),
            ChainEvent::BlockValidated { .. }
        ));
        assert!(matches!(
            subscription.events.recv().await.unwrap(),
            ChainEvent::TipCommitted { .. }
        ));
        assert_eq!(
            subscription.latest_snapshot.borrow().as_ref(),
            Some(&committed)
        );
    }

    #[tokio::test]
    async fn lagged_event_consumer_recovers_the_latest_authoritative_snapshot() {
        let hub = MiningEventHub::new(None).unwrap();
        let mut subscription = hub.subscribe();
        let last_generation = u64::try_from(MINING_EVENT_CAPACITY + 5).unwrap();

        for generation in 1..=last_generation {
            let marker = u8::try_from((generation % 250) + 1).unwrap();
            hub.tip_committed(Arc::new(snapshot(generation, marker)))
                .unwrap();
        }

        assert!(matches!(
            subscription.events.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        assert_eq!(
            subscription
                .latest_snapshot
                .borrow()
                .as_ref()
                .map(|snapshot| snapshot.generation),
            Some(last_generation)
        );
    }

    #[test]
    fn generation_rollback_fails_and_exact_job_activation_is_local() {
        let first = Arc::new(snapshot(1, 1));
        let hub = MiningEventHub::new(Some(Arc::clone(&first))).unwrap();
        assert!(matches!(
            hub.tip_committed(first),
            Err(MiningError::InvalidGeneration)
        ));

        let mask = [9; 32];
        let job = prepared(&snapshot(1, 1), mask);
        let job_id = job.job_id();
        let mut jobs = PreparedJobSet::default();
        jobs.insert(job).unwrap();
        let active = jobs.activate(job_id, &snapshot(1, 1)).unwrap();
        let block = active.reconstruct(7, 101, [8; NONCE_SIZE], mask).unwrap();
        assert_eq!(block.header.mask_hash(), active.header().mask_hash);
        assert!(matches!(
            jobs.activate(job_id, &snapshot(2, 2)),
            Err(MiningError::StaleJob)
        ));
    }

    #[test]
    fn wrong_mask_or_time_cannot_reconstruct_a_candidate() {
        let snapshot = snapshot(1, 1);
        let job = prepared(&snapshot, [9; 32]);
        assert!(job.reconstruct(1, 100, [0; NONCE_SIZE], [9; 32]).is_err());
        assert!(job.reconstruct(1, 101, [0; NONCE_SIZE], [8; 32]).is_err());
    }

    #[test]
    fn solved_candidate_admission_requires_exact_job_generation_and_network_pow() {
        let current_snapshot = snapshot(1, 1);
        let mask = [9; 32];
        let job = prepared(&current_snapshot, mask);
        let extra_nonce = [7; NONCE_SIZE];
        let mut nonce = 0u32;
        let solved = loop {
            match job.admit_solution(&current_snapshot, nonce, 101, extra_nonce, mask) {
                Ok(candidate) => break candidate,
                Err(MiningError::InsufficientProofOfWork) => {
                    nonce = nonce.checked_add(1).expect("nonce space")
                }
                Err(error) => panic!("unexpected candidate error: {error}"),
            }
        };
        assert_eq!(solved.job_id(), job.job_id());
        assert_eq!(solved.snapshot_generation(), current_snapshot.generation);
        assert!(solved.block().header.verify_pow());

        assert!(matches!(
            job.admit_solution(&snapshot(2, 1), nonce, 101, extra_nonce, mask),
            Err(MiningError::StaleJob)
        ));
    }

    #[test]
    fn canonical_job_identity_commits_to_transaction_count_and_bytes() {
        let snapshot = snapshot(1, 1);
        let one = prepared(&snapshot, [9; 32]);
        let mut ordinary = transaction();
        ordinary.inputs[0].previous_output = Outpoint {
            txid: Txid::new([7; 32]),
            index: 0,
        };
        let transactions = Arc::<[Transaction]>::from(vec![transaction(), ordinary]);
        let body = Block {
            header: Header::default(),
            transactions: transactions.to_vec(),
        };
        let mut header = one.header().clone();
        header.merkle_root = hns_consensus::block_merkle_root(&body);
        header.witness_root = hns_consensus::block_witness_root(&body);
        let two = PreparedMiningJob::new(&snapshot, header, transactions).unwrap();

        assert_ne!(one.job_id(), two.job_id());
    }
}
