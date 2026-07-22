use hns_primitives::{blake2b_256, Block, BlockHash, Reader, Writer, MAX_BLOCK_WEIGHT};

use crate::{MiningError, MiningGeneration, MiningJobId, SolvedMiningCandidate};

const PUBLICATION_MAGIC: [u8; 4] = *b"HSPB";
pub const PUBLICATION_INTENT_VERSION: u16 = 1;
pub const PUBLICATION_KEY_PREFIX: &[u8] = b"publication/v1/";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolvedBlockPublicationIntent {
    pub snapshot_generation: MiningGeneration,
    pub job_id: MiningJobId,
    pub block_hash: BlockHash,
    pub created_at: u64,
    pub raw_block: Vec<u8>,
}

impl SolvedBlockPublicationIntent {
    pub fn from_candidate(
        candidate: &SolvedMiningCandidate,
        created_at: u64,
    ) -> Result<Self, MiningError> {
        if candidate.snapshot_generation() == 0
            || created_at == 0
            || !candidate.block().header.verify_pow()
        {
            return Err(MiningError::InvalidPublicationIntent);
        }
        let raw_block = candidate.block().encode();
        if raw_block.len() > MAX_BLOCK_WEIGHT {
            return Err(MiningError::InvalidPublicationIntent);
        }
        Ok(Self {
            snapshot_generation: candidate.snapshot_generation(),
            job_id: candidate.job_id(),
            block_hash: candidate.block().hash(),
            created_at,
            raw_block,
        })
    }

    pub fn block(&self) -> Result<Block, MiningError> {
        let block =
            Block::decode(&self.raw_block).map_err(|_| MiningError::InvalidPublicationIntent)?;
        if block.hash() != self.block_hash || !block.header.verify_pow() {
            return Err(MiningError::InvalidPublicationIntent);
        }
        Ok(block)
    }

    pub fn storage_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(PUBLICATION_KEY_PREFIX.len() + 32);
        key.extend_from_slice(PUBLICATION_KEY_PREFIX);
        key.extend_from_slice(self.block_hash.as_bytes());
        key
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Writer::new();
        payload.write_bytes(&PUBLICATION_MAGIC);
        payload.write_u16(PUBLICATION_INTENT_VERSION);
        payload.write_u64(self.snapshot_generation);
        payload.write_bytes(&self.job_id);
        payload.write_bytes(self.block_hash.as_bytes());
        payload.write_u64(self.created_at);
        payload.write_varbytes(&self.raw_block);
        let payload = payload.finish();
        let checksum = blake2b_256(&payload);
        let mut encoded = payload;
        encoded.extend_from_slice(&checksum);
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, MiningError> {
        if bytes.len() < 32 {
            return Err(MiningError::InvalidPublicationIntent);
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if blake2b_256(payload).as_slice() != checksum {
            return Err(MiningError::InvalidPublicationIntent);
        }
        let mut reader = Reader::new(payload, MAX_BLOCK_WEIGHT + 256)
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        if reader
            .read_vec(PUBLICATION_MAGIC.len())
            .map_err(|_| MiningError::InvalidPublicationIntent)?
            != PUBLICATION_MAGIC
        {
            return Err(MiningError::InvalidPublicationIntent);
        }
        let version = reader
            .read_u16()
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        if version != PUBLICATION_INTENT_VERSION {
            return Err(MiningError::InvalidPublicationIntent);
        }
        let snapshot_generation = reader
            .read_u64()
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        let job_id = reader
            .read_hash()
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        let block_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|_| MiningError::InvalidPublicationIntent)?,
        );
        let created_at = reader
            .read_u64()
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        let raw_block = reader
            .read_varbytes(MAX_BLOCK_WEIGHT, "publication block")
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        reader
            .ensure_finished()
            .map_err(|_| MiningError::InvalidPublicationIntent)?;
        let intent = Self {
            snapshot_generation,
            job_id,
            block_hash,
            created_at,
            raw_block,
        };
        intent.block()?;
        Ok(intent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderSummary, MiningSnapshot, PreparedMiningJob};
    use hns_consensus::{block_merkle_root, block_witness_root, Network};
    use hns_primitives::{
        blake2b_256_many, Address, Covenant, CovenantKind, Header, Input, Outpoint, Output,
        Transaction, Witness, NONCE_SIZE,
    };
    use std::sync::Arc;

    fn candidate() -> SolvedMiningCandidate {
        let snapshot = MiningSnapshot {
            network_id: Network::Regtest.canonical_id(),
            generation: 1,
            tip: HeaderSummary {
                hash: BlockHash::new([1; 32]),
                parent_hash: BlockHash::ZERO,
                height: 1,
                tree_root: [2; 32],
                time: 100,
                bits: 0x207f_ffff,
            },
            parent_median_time: 100,
            next_tree_root: [3; 32],
            chainwork: 1u64.into(),
        };
        let transaction = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 1,
                address: Address::new(0, vec![4; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 2,
        };
        let transactions = Arc::<[Transaction]>::from(vec![transaction]);
        let subject = Block {
            header: Header::default(),
            transactions: transactions.to_vec(),
        };
        let mask = [9; 32];
        let prepared = PreparedMiningJob::new(
            &snapshot,
            crate::MiningHeaderTemplate {
                parent_hash: snapshot.tip.hash,
                tree_root: snapshot.next_tree_root,
                reserved_root: [0; 32],
                witness_root: block_witness_root(&subject),
                merkle_root: block_merkle_root(&subject),
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
        .expect("prepared");
        let mut nonce = 0u32;
        loop {
            match prepared.admit_solution(&snapshot, nonce, 101, [0; NONCE_SIZE], mask) {
                Ok(candidate) => return candidate,
                Err(MiningError::InsufficientProofOfWork) => nonce += 1,
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
    }

    #[test]
    fn publication_intent_round_trips_and_commits_to_block() {
        let candidate = candidate();
        let intent = SolvedBlockPublicationIntent::from_candidate(&candidate, 10).expect("intent");
        let decoded = SolvedBlockPublicationIntent::decode(&intent.encode()).expect("decode");
        assert_eq!(decoded, intent);
        assert_eq!(
            decoded.block().expect("block").hash(),
            candidate.block().hash()
        );
        assert!(decoded.storage_key().starts_with(PUBLICATION_KEY_PREFIX));
    }

    #[test]
    fn publication_checksum_fails_closed() {
        let candidate = candidate();
        let intent = SolvedBlockPublicationIntent::from_candidate(&candidate, 10).expect("intent");
        let mut encoded = intent.encode();
        encoded[8] ^= 1;
        assert!(SolvedBlockPublicationIntent::decode(&encoded).is_err());
    }
}
