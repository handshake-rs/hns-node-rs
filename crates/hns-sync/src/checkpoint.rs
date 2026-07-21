use hns_chain::ChainTip;
use hns_primitives::{blake2b_256, BlockHash, Reader, Uint256, Writer};
use hns_store::{ColumnFamily, MetaKey, ReadSnapshot, Store, WriteBatch};
use serde::{Deserialize, Serialize};

use crate::{SyncError, SyncStage};

const CHECKPOINT_MAGIC: &[u8; 4] = b"HSS4";
const CHECKPOINT_VERSION: u8 = 2;
const CHECKSUM_SIZE: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub sequence: u64,
    pub stage: SyncStage,
    pub best_header: Option<ChainTip>,
    pub active_tip: Option<ChainTip>,
    pub stored_tip: Option<ChainTip>,
    pub target_height: Option<u32>,
    pub updated_at: u64,
}

impl Default for SyncCheckpoint {
    fn default() -> Self {
        Self {
            sequence: 0,
            stage: SyncStage::Idle,
            best_header: None,
            active_tip: None,
            stored_tip: None,
            target_height: None,
            updated_at: 0,
        }
    }
}

impl SyncCheckpoint {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_bytes(CHECKPOINT_MAGIC);
        writer.write_u8(CHECKPOINT_VERSION);
        writer.write_u64(self.sequence);
        writer.write_u8(self.stage.as_u8());
        write_tip(&mut writer, self.best_header.as_ref());
        write_tip(&mut writer, self.active_tip.as_ref());
        write_tip(&mut writer, self.stored_tip.as_ref());
        match self.target_height {
            Some(height) => {
                writer.write_u8(1);
                writer.write_u32(height);
            }
            None => writer.write_u8(0),
        }
        writer.write_u64(self.updated_at);
        let mut bytes = writer.finish();
        let checksum = blake2b_256(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() < CHECKPOINT_MAGIC.len() + 1 + CHECKSUM_SIZE {
            return Err(SyncError::Checkpoint("checkpoint is truncated".to_owned()));
        }
        let payload_len = bytes.len() - CHECKSUM_SIZE;
        let (payload, checksum) = bytes.split_at(payload_len);
        let expected_checksum = blake2b_256(payload);
        if expected_checksum.as_slice() != checksum {
            return Err(SyncError::Checkpoint(
                "checkpoint checksum mismatch".to_owned(),
            ));
        }
        let mut reader =
            Reader::new(payload, 512).map_err(|error| SyncError::Checkpoint(error.to_string()))?;
        let magic = read_array::<4>(&mut reader)?;
        if &magic != CHECKPOINT_MAGIC {
            return Err(SyncError::Checkpoint(
                "checkpoint magic mismatch".to_owned(),
            ));
        }
        let version = primitive(reader.read_u8())?;
        if version != CHECKPOINT_VERSION {
            return Err(SyncError::Checkpoint(format!(
                "unsupported checkpoint version {version}"
            )));
        }
        let sequence = primitive(reader.read_u64())?;
        let stage = SyncStage::from_u8(primitive(reader.read_u8())?)?;
        let best_header = read_tip(&mut reader)?;
        let active_tip = read_tip(&mut reader)?;
        let stored_tip = read_tip(&mut reader)?;
        let target_height = match primitive(reader.read_u8())? {
            0 => None,
            1 => Some(primitive(reader.read_u32())?),
            _ => {
                return Err(SyncError::Checkpoint(
                    "target-height presence flag is invalid".to_owned(),
                ))
            }
        };
        let updated_at = primitive(reader.read_u64())?;
        reader
            .ensure_finished()
            .map_err(|error| SyncError::Checkpoint(error.to_string()))?;
        Ok(Self {
            sequence,
            stage,
            best_header,
            active_tip,
            stored_tip,
            target_height,
            updated_at,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StoredSyncCheckpoint<S: Store> {
    store: S,
}

impl<S: Store> StoredSyncCheckpoint<S> {
    pub fn new(store: S) -> Result<Self, SyncError> {
        hns_store::initialize_schema(&store)
            .map_err(|error| SyncError::Dependency(error.to_string()))?;
        Ok(Self { store })
    }

    pub fn load(&self) -> Result<Option<SyncCheckpoint>, SyncError> {
        let snapshot = self
            .store
            .snapshot()
            .map_err(|error| SyncError::Dependency(error.to_string()))?;
        snapshot
            .get(ColumnFamily::Meta, MetaKey::SyncCheckpoint.as_bytes())
            .map_err(|error| SyncError::Dependency(error.to_string()))?
            .map(|bytes| SyncCheckpoint::decode(&bytes))
            .transpose()
    }

    pub fn save(&self, checkpoint: &SyncCheckpoint) -> Result<(), SyncError> {
        let current = self.load()?;
        if let Some(current) = current.as_ref() {
            if checkpoint.sequence <= current.sequence {
                return Err(SyncError::Checkpoint(format!(
                    "checkpoint sequence {} does not advance durable sequence {}",
                    checkpoint.sequence, current.sequence
                )));
            }
        }
        let mut batch = self.store.batch();
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SyncCheckpoint.as_bytes(),
                &checkpoint.encode(),
            )
            .map_err(|error| SyncError::Dependency(error.to_string()))?;
        self.store
            .commit(batch)
            .map_err(|error| SyncError::Dependency(error.to_string()))
    }

    pub fn clear(&self) -> Result<(), SyncError> {
        let mut batch = self.store.batch();
        batch
            .delete(ColumnFamily::Meta, MetaKey::SyncCheckpoint.as_bytes())
            .map_err(|error| SyncError::Dependency(error.to_string()))?;
        self.store
            .commit(batch)
            .map_err(|error| SyncError::Dependency(error.to_string()))
    }
}

fn write_tip(writer: &mut Writer, tip: Option<&ChainTip>) {
    match tip {
        Some(tip) => {
            writer.write_u8(1);
            writer.write_bytes(tip.hash.as_bytes());
            writer.write_u32(tip.height);
            writer.write_bytes(tip.chainwork.as_be_bytes());
        }
        None => writer.write_u8(0),
    }
}

fn read_tip(reader: &mut Reader<'_>) -> Result<Option<ChainTip>, SyncError> {
    match primitive(reader.read_u8())? {
        0 => Ok(None),
        1 => Ok(Some(ChainTip {
            hash: BlockHash::new(primitive(reader.read_hash())?),
            height: primitive(reader.read_u32())?,
            chainwork: Uint256::from_be_bytes(read_array::<32>(reader)?),
        })),
        _ => Err(SyncError::Checkpoint(
            "chain-tip presence flag is invalid".to_owned(),
        )),
    }
}

fn primitive<T>(result: Result<T, hns_primitives::PrimitiveError>) -> Result<T, SyncError> {
    result.map_err(|error| SyncError::Checkpoint(error.to_string()))
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], SyncError> {
    primitive(reader.read_vec(N))?
        .try_into()
        .map_err(|_| SyncError::Checkpoint(format!("expected {N} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_store::MemoryStore;

    #[test]
    fn checkpoint_codec_round_trips_and_detects_corruption() {
        let checkpoint = SyncCheckpoint {
            sequence: 3,
            stage: SyncStage::Blocks,
            best_header: Some(ChainTip {
                hash: BlockHash::new([1; 32]),
                height: 10,
                chainwork: 11u64.into(),
            }),
            active_tip: Some(ChainTip {
                hash: BlockHash::new([2; 32]),
                height: 8,
                chainwork: 9u64.into(),
            }),
            stored_tip: Some(ChainTip {
                hash: BlockHash::new([3; 32]),
                height: 9,
                chainwork: 10u64.into(),
            }),
            target_height: Some(12),
            updated_at: 99,
        };
        let encoded = checkpoint.encode();
        assert_eq!(
            SyncCheckpoint::decode(&encoded).expect("decode"),
            checkpoint
        );
        let mut corrupt = encoded;
        corrupt[10] ^= 1;
        assert!(matches!(
            SyncCheckpoint::decode(&corrupt).expect_err("corrupt"),
            SyncError::Checkpoint(_)
        ));
    }

    #[test]
    fn stored_checkpoint_requires_monotonic_sequence() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let stored = StoredSyncCheckpoint::new(store).expect("stored");
        let mut checkpoint = SyncCheckpoint {
            sequence: 1,
            ..SyncCheckpoint::default()
        };
        stored.save(&checkpoint).expect("save");
        assert_eq!(stored.load().expect("load"), Some(checkpoint.clone()));
        assert!(stored.save(&checkpoint).is_err());
        checkpoint.sequence = 2;
        stored.save(&checkpoint).expect("advance");
    }
}
