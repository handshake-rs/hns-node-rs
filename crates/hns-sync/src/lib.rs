#![forbid(unsafe_code)]

//! Bounded, restartable Handshake synchronization primitives.
//!
//! This crate deliberately separates scheduling, orphan retention, stateless
//! validation, and durable checkpoints. It does not mutate active consensus
//! state; the node-level coordinator remains the sole owner of ordered state
//! transitions.

pub mod checkpoint;
pub mod orphan;
pub mod scheduler;
pub mod validation;

use hns_chain::ChainTip;
use hns_p2p::PeerId;
use hns_primitives::{BlockHash, Height};
use serde::{Deserialize, Serialize};

pub use checkpoint::{StoredSyncCheckpoint, SyncCheckpoint};
pub use orphan::{BoundedOrphanPool, OrphanInsertOutcome, OrphanLimits, OrphanSnapshot};
pub use scheduler::{PeerSyncSnapshot, SyncAction, SyncLimits, SyncScheduler, SyncSnapshot};
pub use validation::{
    spawn_validation_pipeline, OrderedValidationResult, StatelessBlockValidator, ValidatedBlock,
    ValidationFailure, ValidationRequest, ValidationSubmitter,
};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum SyncStage {
    #[default]
    Idle,
    Headers,
    Blocks,
    Validating,
    SnapshotImport,
    BackgroundVerify,
    Synced,
}

impl SyncStage {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Headers => 1,
            Self::Blocks => 2,
            Self::Validating => 3,
            Self::SnapshotImport => 4,
            Self::BackgroundVerify => 5,
            Self::Synced => 6,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, SyncError> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Headers),
            2 => Ok(Self::Blocks),
            3 => Ok(Self::Validating),
            4 => Ok(Self::SnapshotImport),
            5 => Ok(Self::BackgroundVerify),
            6 => Ok(Self::Synced),
            _ => Err(SyncError::Checkpoint(format!(
                "unknown synchronization stage {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncMetrics {
    pub headers_per_second: u64,
    pub blocks_per_second: u64,
    pub validation_queue_depth: usize,
    pub script_queue_depth: usize,
    pub state_connector_height: Option<Height>,
    pub stored_body_height: Option<Height>,
    pub peer_count: usize,
    pub target_height: Option<Height>,
    pub pending_blocks: usize,
    pub inflight_blocks: usize,
    pub validated_blocks: u64,
    pub failed_blocks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockDownloadRequest {
    pub hash: BlockHash,
    pub height: Height,
    pub peer: Option<PeerId>,
    pub attempt: u8,
}

pub trait SyncController {
    fn stage(&self) -> SyncStage;

    fn best_header(&self) -> Result<Option<ChainTip>, SyncError>;

    fn metrics(&self) -> SyncMetrics;
}

#[derive(Clone, Debug, Default)]
pub struct ManualSyncController {
    stage: SyncStage,
    best_header: Option<ChainTip>,
    metrics: SyncMetrics,
}

impl ManualSyncController {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_stage(&mut self, stage: SyncStage) {
        self.stage = stage;
    }

    pub fn set_best_header(&mut self, best_header: Option<ChainTip>) {
        self.best_header = best_header;
    }

    pub fn set_metrics(&mut self, metrics: SyncMetrics) {
        self.metrics = metrics;
    }
}

impl SyncController for ManualSyncController {
    fn stage(&self) -> SyncStage {
        self.stage
    }

    fn best_header(&self) -> Result<Option<ChainTip>, SyncError> {
        Ok(self.best_header.clone())
    }

    fn metrics(&self) -> SyncMetrics {
        self.metrics.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("invalid synchronization configuration: {0}")]
    Configuration(String),
    #[error("synchronization checkpoint is invalid: {0}")]
    Checkpoint(String),
    #[error("sync dependency failed: {0}")]
    Dependency(String),
    #[error("{context} limit exceeded: limit {limit}, observed {actual}")]
    LimitExceeded {
        context: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("unexpected block: {0}")]
    UnexpectedBlock(String),
    #[error("validation pipeline is closed")]
    ValidationPipelineClosed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::BlockHash;

    #[test]
    fn manual_sync_controller_reports_state() {
        let mut sync = ManualSyncController::new();
        sync.set_stage(SyncStage::Headers);
        sync.set_best_header(Some(ChainTip {
            hash: BlockHash::new([1; 32]),
            height: 5,
            chainwork: 6u64.into(),
        }));

        assert_eq!(sync.stage(), SyncStage::Headers);
        assert_eq!(sync.best_header().expect("best").expect("tip").height, 5);
    }

    #[test]
    fn stage_codec_is_stable() {
        for value in 0..=6 {
            let stage = SyncStage::from_u8(value).expect("known stage");
            assert_eq!(stage.as_u8(), value);
        }
        assert!(SyncStage::from_u8(7).is_err());
    }
}
