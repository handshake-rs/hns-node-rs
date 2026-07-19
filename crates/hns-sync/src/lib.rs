#![forbid(unsafe_code)]

use hns_chain::ChainTip;
use hns_p2p::PeerId;
use hns_primitives::{BlockHash, Height};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum SyncStage {
    #[default]
    Idle,
    Headers,
    Blocks,
    Validating,
    SnapshotImport,
    BackgroundVerify,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncMetrics {
    pub headers_per_second: u64,
    pub blocks_per_second: u64,
    pub validation_queue_depth: usize,
    pub script_queue_depth: usize,
    pub state_connector_height: Option<Height>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockDownloadRequest {
    pub hash: BlockHash,
    pub height: Height,
    pub peer: Option<PeerId>,
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
    #[error("sync controller is not implemented in the scaffold")]
    Unimplemented,
    #[error("sync dependency failed: {0}")]
    Dependency(String),
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
}
