#![forbid(unsafe_code)]

use std::collections::HashMap;

use hns_primitives::{
    blake2b_256, Block, BlockHash, CompactTarget, Header, Height, Reader, Transaction, Txid,
    Uint256, Writer, HEADER_SIZE, MAX_BLOCK_WEIGHT,
};
use hns_store::{ColumnFamily, MetaKey, ReadSnapshot, Store, StoreError, WriteBatch};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainTip {
    pub hash: BlockHash,
    pub height: Height,
    pub chainwork: Uint256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockStatus {
    pub header_context_valid: bool,
    pub checkpoint_valid: bool,
    pub deployment_state_valid: bool,
    pub body_present: bool,
    pub body_syntax_valid: bool,
    pub absolute_finality_valid: bool,
    pub relative_locks_valid: bool,
    pub scripts_valid: bool,
    /// Input/output covenant linkage and local commitment checks have passed.
    /// This is narrower than full name-state contextual validation.
    pub covenant_links_valid: bool,
    pub covenants_context_valid: bool,
    pub claims_and_airdrops_valid: bool,
    pub utxo_connected: bool,
    pub name_state_connected: bool,
    pub tree_root_valid: bool,
    pub undo_present: bool,
    pub active_chain: bool,
    pub failed: bool,
}

impl BlockStatus {
    const HEADER_CONTEXT_VALID: u32 = 1 << 0;
    const CHECKPOINT_VALID: u32 = 1 << 1;
    const DEPLOYMENT_STATE_VALID: u32 = 1 << 2;
    const BODY_PRESENT: u32 = 1 << 3;
    const BODY_SYNTAX_VALID: u32 = 1 << 4;
    const ABSOLUTE_FINALITY_VALID: u32 = 1 << 5;
    const RELATIVE_LOCKS_VALID: u32 = 1 << 6;
    const SCRIPTS_VALID: u32 = 1 << 7;
    const COVENANT_LINKS_VALID: u32 = 1 << 8;
    const COVENANTS_CONTEXT_VALID: u32 = 1 << 9;
    const CLAIMS_AND_AIRDROPS_VALID: u32 = 1 << 10;
    const UTXO_CONNECTED: u32 = 1 << 11;
    const NAME_STATE_CONNECTED: u32 = 1 << 12;
    const TREE_ROOT_VALID: u32 = 1 << 13;
    const UNDO_PRESENT: u32 = 1 << 14;
    const ACTIVE_CHAIN: u32 = 1 << 15;
    const FAILED: u32 = 1 << 16;

    /// Every consensus validation stage represented by the durable status
    /// schema has completed. Persistence and active-chain membership are kept
    /// separate so side-chain validation remains representable.
    pub fn is_consensus_valid(&self) -> bool {
        self.header_context_valid
            && self.checkpoint_valid
            && self.deployment_state_valid
            && self.body_present
            && self.body_syntax_valid
            && self.absolute_finality_valid
            && self.relative_locks_valid
            && self.scripts_valid
            && self.covenant_links_valid
            && self.covenants_context_valid
            && self.claims_and_airdrops_valid
            && self.tree_root_valid
            && !self.failed
    }

    /// A committed block can authorize mining only when complete consensus
    /// validation, state connection, undo durability, and active-chain status
    /// all agree.
    pub fn is_mining_authoritative(&self) -> bool {
        self.is_consensus_valid()
            && self.utxo_connected
            && self.name_state_connected
            && self.undo_present
            && self.active_chain
    }

    /// The current pre-authority engine has committed the subset of state that
    /// it presently knows how to derive. This state is useful for diagnostics
    /// and differential development, never for production mining authority.
    pub fn is_staged_state(&self) -> bool {
        self.header_context_valid
            && self.body_present
            && self.body_syntax_valid
            && self.absolute_finality_valid
            && self.covenant_links_valid
            && self.utxo_connected
            && self.undo_present
            && self.active_chain
            && !self.failed
    }

    pub fn to_bits(&self) -> u32 {
        let mut bits = 0;

        if self.header_context_valid {
            bits |= Self::HEADER_CONTEXT_VALID;
        }
        if self.checkpoint_valid {
            bits |= Self::CHECKPOINT_VALID;
        }
        if self.deployment_state_valid {
            bits |= Self::DEPLOYMENT_STATE_VALID;
        }
        if self.body_present {
            bits |= Self::BODY_PRESENT;
        }
        if self.body_syntax_valid {
            bits |= Self::BODY_SYNTAX_VALID;
        }
        if self.absolute_finality_valid {
            bits |= Self::ABSOLUTE_FINALITY_VALID;
        }
        if self.relative_locks_valid {
            bits |= Self::RELATIVE_LOCKS_VALID;
        }
        if self.scripts_valid {
            bits |= Self::SCRIPTS_VALID;
        }
        if self.covenant_links_valid {
            bits |= Self::COVENANT_LINKS_VALID;
        }
        if self.covenants_context_valid {
            bits |= Self::COVENANTS_CONTEXT_VALID;
        }
        if self.claims_and_airdrops_valid {
            bits |= Self::CLAIMS_AND_AIRDROPS_VALID;
        }
        if self.utxo_connected {
            bits |= Self::UTXO_CONNECTED;
        }
        if self.name_state_connected {
            bits |= Self::NAME_STATE_CONNECTED;
        }
        if self.tree_root_valid {
            bits |= Self::TREE_ROOT_VALID;
        }
        if self.undo_present {
            bits |= Self::UNDO_PRESENT;
        }
        if self.active_chain {
            bits |= Self::ACTIVE_CHAIN;
        }
        if self.failed {
            bits |= Self::FAILED;
        }

        bits
    }

    pub fn from_bits(bits: u32) -> Self {
        Self {
            header_context_valid: bits & Self::HEADER_CONTEXT_VALID != 0,
            checkpoint_valid: bits & Self::CHECKPOINT_VALID != 0,
            deployment_state_valid: bits & Self::DEPLOYMENT_STATE_VALID != 0,
            body_present: bits & Self::BODY_PRESENT != 0,
            body_syntax_valid: bits & Self::BODY_SYNTAX_VALID != 0,
            absolute_finality_valid: bits & Self::ABSOLUTE_FINALITY_VALID != 0,
            relative_locks_valid: bits & Self::RELATIVE_LOCKS_VALID != 0,
            scripts_valid: bits & Self::SCRIPTS_VALID != 0,
            covenant_links_valid: bits & Self::COVENANT_LINKS_VALID != 0,
            covenants_context_valid: bits & Self::COVENANTS_CONTEXT_VALID != 0,
            claims_and_airdrops_valid: bits & Self::CLAIMS_AND_AIRDROPS_VALID != 0,
            utxo_connected: bits & Self::UTXO_CONNECTED != 0,
            name_state_connected: bits & Self::NAME_STATE_CONNECTED != 0,
            tree_root_valid: bits & Self::TREE_ROOT_VALID != 0,
            undo_present: bits & Self::UNDO_PRESENT != 0,
            active_chain: bits & Self::ACTIVE_CHAIN != 0,
            failed: bits & Self::FAILED != 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderRecord {
    pub hash: BlockHash,
    pub height: Height,
    pub chainwork: Uint256,
    pub header: Header,
    pub status: BlockStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockIndexRecord {
    pub hash: BlockHash,
    pub height: Height,
    pub prev_hash: BlockHash,
    pub chainwork: Uint256,
    pub status: BlockStatus,
    pub tx_count: u32,
    pub validated_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxIndexEntry {
    pub txid: Txid,
    pub block_hash: BlockHash,
    pub height: Height,
    pub tx_offset: u32,
    pub tx_len: u32,
    pub output_count: u32,
}

impl TxIndexEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(32 + 32 + 4 + 4 + 4 + 4);
        writer.write_bytes(self.txid.as_bytes());
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_u32(self.tx_offset);
        writer.write_u32(self.tx_len);
        writer.write_u32(self.output_count);
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChainError> {
        let mut reader = Reader::new(bytes, 32 + 32 + 4 + 4 + 4 + 4)
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let txid = Txid::new(
            reader
                .read_hash()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        );
        let block_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        );
        let height = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let tx_offset = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let tx_len = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let output_count = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        reader
            .ensure_finished()
            .map_err(|error| ChainError::Codec(error.to_string()))?;

        Ok(Self {
            txid,
            block_hash,
            height,
            tx_offset,
            tx_len,
            output_count,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum RawBlockCompression {
    None,
}

impl RawBlockCompression {
    const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
        }
    }

    fn from_u8(value: u8) -> Result<Self, ChainError> {
        match value {
            0 => Ok(Self::None),
            _ => Err(ChainError::Codec(
                "unknown raw block compression".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum RawBlockSource {
    Unknown,
    Peer,
    Fixture,
    Rpc,
    Snapshot,
    Mining,
}

impl RawBlockSource {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Peer => 1,
            Self::Fixture => 2,
            Self::Rpc => 3,
            Self::Snapshot => 4,
            Self::Mining => 5,
        }
    }

    fn from_u8(value: u8) -> Result<Self, ChainError> {
        match value {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Peer),
            2 => Ok(Self::Fixture),
            3 => Ok(Self::Rpc),
            4 => Ok(Self::Snapshot),
            5 => Ok(Self::Mining),
            _ => Err(ChainError::Codec("unknown raw block source".to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawBlockRecord {
    pub hash: BlockHash,
    pub bytes: Vec<u8>,
    pub compression: RawBlockCompression,
    pub source: RawBlockSource,
    pub checksum: [u8; 32],
}

impl RawBlockRecord {
    pub fn from_block(block: &Block, source: RawBlockSource) -> Self {
        Self::from_raw(block.hash(), block.encode(), source)
    }

    pub fn from_raw(hash: BlockHash, bytes: Vec<u8>, source: RawBlockSource) -> Self {
        let checksum = blake2b_256(&bytes);

        Self {
            hash,
            bytes,
            compression: RawBlockCompression::None,
            source,
            checksum,
        }
    }

    pub fn decode_block(&self) -> Result<Block, ChainError> {
        let block =
            Block::decode(&self.bytes).map_err(|error| ChainError::Codec(error.to_string()))?;

        if block.hash() != self.hash {
            return Err(ChainError::Codec("raw block hash mismatch".to_owned()));
        }

        Ok(block)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(32 + 1 + 1 + 32 + self.bytes.len() + 9);
        writer.write_bytes(self.hash.as_bytes());
        writer.write_u8(self.compression.as_u8());
        writer.write_u8(self.source.as_u8());
        writer.write_bytes(&self.checksum);
        writer.write_varbytes(&self.bytes);
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChainError> {
        let mut reader = Reader::new(bytes, 32 + 1 + 1 + 32 + MAX_BLOCK_WEIGHT + 9)
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        );
        let compression = RawBlockCompression::from_u8(
            reader
                .read_u8()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        )?;
        let source = RawBlockSource::from_u8(
            reader
                .read_u8()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        )?;
        let checksum = reader
            .read_hash()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let raw = reader
            .read_varbytes(MAX_BLOCK_WEIGHT, "raw block")
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        reader
            .ensure_finished()
            .map_err(|error| ChainError::Codec(error.to_string()))?;

        if blake2b_256(&raw) != checksum {
            return Err(ChainError::Codec("raw block checksum mismatch".to_owned()));
        }

        Ok(Self {
            hash,
            bytes: raw,
            compression,
            source,
            checksum,
        })
    }
}

impl BlockIndexRecord {
    pub fn from_block(
        block: &Block,
        height: Height,
        chainwork: Uint256,
    ) -> Result<Self, ChainError> {
        let tx_count = u32::try_from(block.transactions.len()).map_err(|_| {
            ChainError::Codec(format!(
                "block transaction count {} exceeds u32",
                block.transactions.len()
            ))
        })?;

        Ok(Self {
            hash: block.hash(),
            height,
            prev_hash: block.header.prev_block,
            chainwork,
            status: BlockStatus {
                body_present: true,
                ..BlockStatus::default()
            },
            tx_count,
            validated_at: None,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(32 + 4 + 32 + 32 + 4 + 4 + 8);
        writer.write_bytes(self.hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_bytes(self.prev_hash.as_bytes());
        writer.write_bytes(self.chainwork.as_be_bytes());
        writer.write_bytes(&self.status.to_bits().to_le_bytes());
        writer.write_u32(self.tx_count);
        writer.write_u64(self.validated_at.unwrap_or(0));
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChainError> {
        let mut reader = Reader::new(bytes, 32 + 4 + 32 + 32 + 4 + 4 + 8)
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        );
        let height = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let prev_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        );
        let chainwork = Uint256::from_be_bytes(read_array::<32>(&mut reader)?);
        let status = BlockStatus::from_bits(u32::from_le_bytes(read_array::<4>(&mut reader)?));
        let tx_count = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let validated_at = match reader
            .read_u64()
            .map_err(|error| ChainError::Codec(error.to_string()))?
        {
            0 => None,
            value => Some(value),
        };
        reader
            .ensure_finished()
            .map_err(|error| ChainError::Codec(error.to_string()))?;

        Ok(Self {
            hash,
            height,
            prev_hash,
            chainwork,
            status,
            tx_count,
            validated_at,
        })
    }
}

impl HeaderRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(32 + 4 + 32 + 4 + HEADER_SIZE);
        writer.write_bytes(self.hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_bytes(self.chainwork.as_be_bytes());
        writer.write_bytes(&self.status.to_bits().to_le_bytes());
        self.header.write_to(&mut writer);
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChainError> {
        let mut reader = Reader::new(bytes, 32 + 4 + 32 + 4 + HEADER_SIZE)
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|error| ChainError::Codec(error.to_string()))?,
        );
        let height = reader
            .read_u32()
            .map_err(|error| ChainError::Codec(error.to_string()))?;
        let chainwork = Uint256::from_be_bytes(read_array::<32>(&mut reader)?);
        let status = BlockStatus::from_bits(u32::from_le_bytes(read_array::<4>(&mut reader)?));
        let header =
            Header::read_from(&mut reader).map_err(|error| ChainError::Codec(error.to_string()))?;
        reader
            .ensure_finished()
            .map_err(|error| ChainError::Codec(error.to_string()))?;

        Ok(Self {
            hash,
            height,
            chainwork,
            header,
            status,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReorgPlan {
    pub disconnect: Vec<BlockHash>,
    pub connect: Vec<BlockHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderImport {
    pub header: Header,
    pub height: Height,
    pub verify_pow: bool,
}

pub trait HeaderIndex {
    fn best_tip(&self) -> Result<Option<ChainTip>, ChainError>;

    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>, ChainError>;

    fn canonical_hash(&self, height: Height) -> Result<Option<BlockHash>, ChainError>;

    fn plan_reorg(&self, candidate: &BlockHash) -> Result<ReorgPlan, ChainError>;

    fn plan_reorg_between(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
    ) -> Result<ReorgPlan, ChainError>;
}

pub trait BlockIndex {
    fn block(&self, hash: &BlockHash) -> Result<Option<BlockIndexRecord>, ChainError>;

    fn insert_block_record(&mut self, record: BlockIndexRecord) -> Result<(), ChainError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryHeaderIndex {
    records: HashMap<BlockHash, HeaderRecord>,
    canonical: HashMap<Height, BlockHash>,
    best: Option<ChainTip>,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryBlockIndex {
    records: HashMap<BlockHash, BlockIndexRecord>,
}

impl MemoryBlockIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_records(records: impl IntoIterator<Item = BlockIndexRecord>) -> Self {
        Self {
            records: records
                .into_iter()
                .map(|record| (record.hash, record))
                .collect(),
        }
    }
}

impl BlockIndex for MemoryBlockIndex {
    fn block(&self, hash: &BlockHash) -> Result<Option<BlockIndexRecord>, ChainError> {
        Ok(self.records.get(hash).cloned())
    }

    fn insert_block_record(&mut self, record: BlockIndexRecord) -> Result<(), ChainError> {
        self.records.insert(record.hash, record);
        Ok(())
    }
}

impl MemoryHeaderIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_header(
        &mut self,
        header: Header,
        height: Height,
    ) -> Result<HeaderRecord, ChainError> {
        let hash = header.hash();
        let parent_work = if height == 0 {
            Uint256::ZERO
        } else {
            self.records
                .get(&header.prev_block)
                .map(|record| record.chainwork)
                .ok_or(ChainError::MissingParent(header.prev_block))?
        };

        let record = HeaderRecord {
            hash,
            height,
            chainwork: parent_work
                .checked_add(
                    CompactTarget::from_bits(header.bits)
                        .proof()
                        .ok_or(ChainError::InvalidHeader("invalid proof-of-work target"))?,
                )
                .ok_or_else(|| ChainError::Codec("chainwork overflow".to_owned()))?,
            header,
            status: BlockStatus {
                header_context_valid: true,
                ..BlockStatus::default()
            },
        };

        self.records.insert(hash, record.clone());
        self.promote_if_best(&record)?;
        Ok(record)
    }

    pub fn insert_record(&mut self, record: HeaderRecord) -> Result<(), ChainError> {
        self.records.insert(record.hash, record.clone());
        self.promote_if_best(&record)
    }

    pub fn from_records(
        records: impl IntoIterator<Item = HeaderRecord>,
    ) -> Result<Self, ChainError> {
        Self::from_records_with_best(records, None)
    }

    pub fn from_records_with_best(
        records: impl IntoIterator<Item = HeaderRecord>,
        persisted_best: Option<BlockHash>,
    ) -> Result<Self, ChainError> {
        let mut index = Self::new();
        let mut records = records.into_iter().collect::<Vec<_>>();
        records.sort_by_key(|record| (record.height, record.chainwork, record.hash));

        for record in records {
            index.records.insert(record.hash, record);
        }

        if let Some(best_hash) = persisted_best {
            let best_record = index
                .records
                .get(&best_hash)
                .cloned()
                .ok_or(ChainError::MissingHeader(best_hash))?;
            if index
                .records
                .values()
                .any(|record| record.chainwork > best_record.chainwork)
            {
                return Err(ChainError::InconsistentBestHeader(best_hash));
            }
            index.promote(&best_record)?;
            return Ok(index);
        }

        let mut candidates = index.records.values().cloned().collect::<Vec<_>>();
        candidates.sort_by_key(|record| (record.chainwork, record.height, record.hash));

        for record in candidates {
            index.promote_if_best(&record)?;
        }

        Ok(index)
    }

    pub fn canonical_entries(&self) -> Vec<(Height, BlockHash)> {
        let mut entries = self
            .canonical
            .iter()
            .map(|(height, hash)| (*height, *hash))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(height, _)| *height);
        entries
    }

    fn promote_if_best(&mut self, record: &HeaderRecord) -> Result<(), ChainError> {
        let should_promote = self
            .best
            .as_ref()
            .map(|best| record.chainwork > best.chainwork)
            .unwrap_or(true);

        if should_promote {
            self.promote(record)?;
        }

        Ok(())
    }

    fn promote(&mut self, record: &HeaderRecord) -> Result<(), ChainError> {
        let path = self.path_to_genesis(record.hash)?;
        self.canonical.clear();

        for hash in path.into_iter().rev() {
            let path_record = self
                .records
                .get(&hash)
                .ok_or(ChainError::MissingHeader(hash))?;
            self.canonical.insert(path_record.height, hash);
        }

        self.best = Some(ChainTip {
            hash: record.hash,
            height: record.height,
            chainwork: record.chainwork,
        });

        Ok(())
    }

    fn path_to_genesis(&self, tip: BlockHash) -> Result<Vec<BlockHash>, ChainError> {
        let mut path = Vec::new();
        let mut current = tip;

        loop {
            let record = self
                .records
                .get(&current)
                .ok_or(ChainError::MissingHeader(current))?;
            path.push(current);

            if record.height == 0 {
                return Ok(path);
            }

            current = record.header.prev_block;
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoredHeaderIndex<S: Store> {
    store: S,
    memory: MemoryHeaderIndex,
}

impl<S: Store> StoredHeaderIndex<S> {
    pub fn new(store: S) -> Result<Self, ChainError> {
        hns_store::initialize_schema(&store)?;
        let memory = load_header_index(&store)?;
        Ok(Self { store, memory })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn import_header(&mut self, request: HeaderImport) -> Result<HeaderRecord, ChainError> {
        if request.verify_pow && !request.header.verify_pow() {
            return Err(ChainError::InvalidHeader("proof of work failed"));
        }

        let record = self.memory.insert_header(request.header, request.height)?;
        self.persist_record(&record)?;
        Ok(record)
    }

    pub fn persist_record(&mut self, record: &HeaderRecord) -> Result<(), ChainError> {
        let mut batch = self.store.batch();
        write_record_to_batch(&mut batch, record)?;

        if self
            .memory
            .best_tip()?
            .as_ref()
            .map(|tip| tip.hash == record.hash)
            .unwrap_or(false)
        {
            batch.put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                record.hash.as_bytes(),
            )?;
        }

        // HeightIndex is the connected active-block chain. Header-only imports
        // must never rewrite it merely because they carry more work.
        self.store.commit(batch)?;
        Ok(())
    }

    pub fn load_record(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>, ChainError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::Headers, hash.as_bytes())? else {
            return Ok(None);
        };
        HeaderRecord::decode(&bytes).map(Some)
    }

    pub fn cache_record(&mut self, record: HeaderRecord) -> Result<(), ChainError> {
        self.memory.insert_record(record)
    }
}

fn load_header_index<S: Store>(store: &S) -> Result<MemoryHeaderIndex, ChainError> {
    let snapshot = store.snapshot()?;
    let records = snapshot
        .scan_prefix(ColumnFamily::Headers, b"")?
        .into_iter()
        .map(|(_, bytes)| HeaderRecord::decode(&bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let persisted_best = snapshot
        .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())?
        .map(|bytes| decode_block_hash(&bytes))
        .transpose()?;

    if !records.is_empty() && persisted_best.is_none() {
        return Err(ChainError::MissingBestHeaderBinding);
    }

    MemoryHeaderIndex::from_records_with_best(records, persisted_best)
}

impl<S: Store> HeaderIndex for StoredHeaderIndex<S> {
    fn best_tip(&self) -> Result<Option<ChainTip>, ChainError> {
        self.memory.best_tip()
    }

    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>, ChainError> {
        self.memory.header(hash)
    }

    fn canonical_hash(&self, height: Height) -> Result<Option<BlockHash>, ChainError> {
        self.memory.canonical_hash(height)
    }

    fn plan_reorg(&self, candidate: &BlockHash) -> Result<ReorgPlan, ChainError> {
        self.memory.plan_reorg(candidate)
    }

    fn plan_reorg_between(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
    ) -> Result<ReorgPlan, ChainError> {
        self.memory.plan_reorg_between(current, candidate)
    }
}

#[derive(Clone, Debug)]
pub struct StoredBlockIndex<S: Store> {
    store: S,
    memory: MemoryBlockIndex,
}

impl<S: Store> StoredBlockIndex<S> {
    pub fn new(store: S) -> Result<Self, ChainError> {
        hns_store::initialize_schema(&store)?;
        let memory = load_block_index(&store)?;
        Ok(Self { store, memory })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_block(
        &mut self,
        block: &Block,
        height: Height,
        chainwork: Uint256,
        source: RawBlockSource,
    ) -> Result<BlockIndexRecord, ChainError> {
        let record = BlockIndexRecord::from_block(block, height, chainwork)?;
        let raw_record = RawBlockRecord::from_block(block, source);
        let mut batch = self.store.batch();

        write_block_index_to_batch(&mut batch, &record)?;
        write_raw_block_to_batch(&mut batch, &raw_record)?;
        write_tx_index_for_block_to_batch(&mut batch, block, height)?;
        self.store.commit(batch)?;
        self.memory.insert_block_record(record.clone())?;

        Ok(record)
    }

    pub fn load_block_record(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockIndexRecord>, ChainError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::BlockIndex, hash.as_bytes())? else {
            return Ok(None);
        };
        BlockIndexRecord::decode(&bytes).map(Some)
    }

    pub fn load_raw_block(&self, hash: &BlockHash) -> Result<Option<RawBlockRecord>, ChainError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::Blocks, hash.as_bytes())? else {
            return Ok(None);
        };
        RawBlockRecord::decode(&bytes).map(Some)
    }

    pub fn load_block(&self, hash: &BlockHash) -> Result<Option<Block>, ChainError> {
        let Some(raw_record) = self.load_raw_block(hash)? else {
            return Ok(None);
        };
        raw_record.decode_block().map(Some)
    }

    pub fn load_tx_index(&self, txid: &Txid) -> Result<Option<TxIndexEntry>, ChainError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::TxIndex, txid.as_bytes())? else {
            return Ok(None);
        };
        TxIndexEntry::decode(&bytes).map(Some)
    }

    pub fn cache_record(&mut self, record: BlockIndexRecord) -> Result<(), ChainError> {
        self.memory.insert_block_record(record)
    }
}

impl<S: Store> BlockIndex for StoredBlockIndex<S> {
    fn block(&self, hash: &BlockHash) -> Result<Option<BlockIndexRecord>, ChainError> {
        if let Some(record) = self.memory.block(hash)? {
            return Ok(Some(record));
        }

        self.load_block_record(hash)
    }

    fn insert_block_record(&mut self, record: BlockIndexRecord) -> Result<(), ChainError> {
        let mut batch = self.store.batch();
        write_block_index_to_batch(&mut batch, &record)?;
        self.store.commit(batch)?;
        self.memory.insert_block_record(record)
    }
}

fn load_block_index<S: Store>(store: &S) -> Result<MemoryBlockIndex, ChainError> {
    let snapshot = store.snapshot()?;
    let records = snapshot
        .scan_prefix(ColumnFamily::BlockIndex, b"")?
        .into_iter()
        .map(|(_, bytes)| BlockIndexRecord::decode(&bytes))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MemoryBlockIndex::from_records(records))
}

pub fn write_record_to_batch<B: WriteBatch>(
    batch: &mut B,
    record: &HeaderRecord,
) -> Result<(), ChainError> {
    batch.put(
        ColumnFamily::Headers,
        record.hash.as_bytes(),
        &record.encode(),
    )?;
    Ok(())
}

pub fn write_block_index_to_batch<B: WriteBatch>(
    batch: &mut B,
    record: &BlockIndexRecord,
) -> Result<(), ChainError> {
    batch.put(
        ColumnFamily::BlockIndex,
        record.hash.as_bytes(),
        &record.encode(),
    )?;
    Ok(())
}

pub fn write_raw_block_to_batch<B: WriteBatch>(
    batch: &mut B,
    record: &RawBlockRecord,
) -> Result<(), ChainError> {
    batch.put(
        ColumnFamily::Blocks,
        record.hash.as_bytes(),
        &record.encode(),
    )?;
    Ok(())
}

pub fn write_tx_index_to_batch<B: WriteBatch>(
    batch: &mut B,
    entry: &TxIndexEntry,
) -> Result<(), ChainError> {
    batch.put(
        ColumnFamily::TxIndex,
        entry.txid.as_bytes(),
        &entry.encode(),
    )?;
    Ok(())
}

pub fn write_tx_index_for_block_to_batch<B: WriteBatch>(
    batch: &mut B,
    block: &Block,
    height: Height,
) -> Result<Vec<TxIndexEntry>, ChainError> {
    let entries = tx_index_entries_for_block(block, height)?;

    for entry in &entries {
        write_tx_index_to_batch(batch, entry)?;
    }

    Ok(entries)
}

pub fn delete_tx_index_for_block_from_batch<B: WriteBatch>(
    batch: &mut B,
    block: &Block,
) -> Result<Vec<Txid>, ChainError> {
    let mut txids = Vec::with_capacity(block.transactions.len());

    for transaction in &block.transactions {
        let txid = transaction.txid();
        batch.delete(ColumnFamily::TxIndex, txid.as_bytes())?;
        txids.push(txid);
    }

    Ok(txids)
}

pub fn tx_index_entries_for_block(
    block: &Block,
    height: Height,
) -> Result<Vec<TxIndexEntry>, ChainError> {
    let block_hash = block.hash();
    let tx_count = u64::try_from(block.transactions.len()).map_err(|_| {
        ChainError::Codec(format!(
            "block transaction count {} exceeds u64",
            block.transactions.len()
        ))
    })?;
    let mut offset = checked_usize_to_u32(
        HEADER_SIZE
            .checked_add(varint_size(tx_count))
            .ok_or(ChainError::Codec("transaction offset overflow".to_owned()))?,
        "transaction offset",
    )?;
    let mut entries = Vec::with_capacity(block.transactions.len());

    for transaction in &block.transactions {
        let tx_len = checked_usize_to_u32(transaction.encode().len(), "transaction length")?;
        entries.push(tx_index_entry(
            transaction,
            block_hash,
            height,
            offset,
            tx_len,
        )?);
        offset = offset
            .checked_add(tx_len)
            .ok_or(ChainError::Codec("transaction offset overflow".to_owned()))?;
    }

    Ok(entries)
}

fn tx_index_entry(
    transaction: &Transaction,
    block_hash: BlockHash,
    height: Height,
    tx_offset: u32,
    tx_len: u32,
) -> Result<TxIndexEntry, ChainError> {
    let output_count = u32::try_from(transaction.outputs.len()).map_err(|_| {
        ChainError::Codec(format!(
            "transaction output count {} exceeds u32",
            transaction.outputs.len()
        ))
    })?;

    Ok(TxIndexEntry {
        txid: transaction.txid(),
        block_hash,
        height,
        tx_offset,
        tx_len,
        output_count,
    })
}

pub fn write_canonical_height_to_batch<B: WriteBatch>(
    batch: &mut B,
    height: Height,
    hash: BlockHash,
) -> Result<(), ChainError> {
    batch.put(
        ColumnFamily::HeightIndex,
        &hns_store::encode_height(height),
        hash.as_bytes(),
    )?;
    Ok(())
}

pub fn delete_canonical_height_from_batch<B: WriteBatch>(
    batch: &mut B,
    height: Height,
) -> Result<(), ChainError> {
    batch.delete(ColumnFamily::HeightIndex, &hns_store::encode_height(height))?;
    Ok(())
}

pub fn read_canonical_hash<S: ReadSnapshot>(
    snapshot: &S,
    height: Height,
) -> Result<Option<BlockHash>, ChainError> {
    let Some(bytes) = snapshot.get(ColumnFamily::HeightIndex, &hns_store::encode_height(height))?
    else {
        return Ok(None);
    };

    let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        ChainError::Codec(format!(
            "expected 32-byte height index, got {}",
            bytes.len()
        ))
    })?;
    Ok(Some(BlockHash::new(hash)))
}

impl HeaderIndex for MemoryHeaderIndex {
    fn best_tip(&self) -> Result<Option<ChainTip>, ChainError> {
        Ok(self.best.clone())
    }

    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>, ChainError> {
        Ok(self.records.get(hash).cloned())
    }

    fn canonical_hash(&self, height: Height) -> Result<Option<BlockHash>, ChainError> {
        Ok(self.canonical.get(&height).copied())
    }

    fn plan_reorg(&self, candidate: &BlockHash) -> Result<ReorgPlan, ChainError> {
        let Some(best) = &self.best else {
            let mut connect = self.path_to_genesis(*candidate)?;
            connect.reverse();
            return Ok(ReorgPlan {
                disconnect: Vec::new(),
                connect,
            });
        };

        self.plan_reorg_between(&best.hash, candidate)
    }

    fn plan_reorg_between(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
    ) -> Result<ReorgPlan, ChainError> {
        if current == candidate {
            return Ok(ReorgPlan::default());
        }

        let mut old = self
            .records
            .get(current)
            .cloned()
            .ok_or(ChainError::MissingHeader(*current))?;
        let mut new = self
            .records
            .get(candidate)
            .cloned()
            .ok_or(ChainError::MissingHeader(*candidate))?;
        let mut disconnect = Vec::new();
        let mut connect_reverse = Vec::new();

        while old.height > new.height {
            disconnect.push(old.hash);
            old = self
                .records
                .get(&old.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(old.header.prev_block))?;
        }

        while new.height > old.height {
            connect_reverse.push(new.hash);
            new = self
                .records
                .get(&new.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(new.header.prev_block))?;
        }

        while old.hash != new.hash {
            if old.height == 0 || new.height == 0 {
                return Err(ChainError::NoCommonAncestor {
                    current: *current,
                    candidate: *candidate,
                });
            }
            disconnect.push(old.hash);
            connect_reverse.push(new.hash);
            old = self
                .records
                .get(&old.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(old.header.prev_block))?;
            new = self
                .records
                .get(&new.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(new.header.prev_block))?;
        }

        connect_reverse.reverse();
        Ok(ReorgPlan {
            disconnect,
            connect: connect_reverse,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("chain index is not implemented in the scaffold")]
    Unimplemented,
    #[error("chain store failed: {0}")]
    Store(String),
    #[error("chain codec failed: {0}")]
    Codec(String),
    #[error("missing parent header {0:?}")]
    MissingParent(BlockHash),
    #[error("missing header {0:?}")]
    MissingHeader(BlockHash),
    #[error("stored headers exist without a persisted best-header binding")]
    MissingBestHeaderBinding,
    #[error("persisted best header {0:?} is inconsistent with stored chainwork")]
    InconsistentBestHeader(BlockHash),
    #[error("chains {current:?} and {candidate:?} do not share a stored ancestor")]
    NoCommonAncestor {
        current: BlockHash,
        candidate: BlockHash,
    },
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
}

impl From<StoreError> for ChainError {
    fn from(value: StoreError) -> Self {
        Self::Store(value.to_string())
    }
}


fn decode_block_hash(bytes: &[u8]) -> Result<BlockHash, ChainError> {
    let hash: [u8; 32] = bytes.try_into().map_err(|_| {
        ChainError::Codec(format!("expected 32-byte block hash, got {}", bytes.len()))
    })?;
    Ok(BlockHash::new(hash))
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], ChainError> {
    let bytes = reader
        .read_vec(N)
        .map_err(|error| ChainError::Codec(error.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| ChainError::Codec(format!("expected {N} bytes")))
}

fn checked_usize_to_u32(value: usize, context: &'static str) -> Result<u32, ChainError> {
    u32::try_from(value).map_err(|_| ChainError::Codec(format!("{context} exceeds u32")))
}

fn varint_size(value: u64) -> usize {
    match value {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{Address, Covenant, CovenantKind, Input, Outpoint, Output, Witness};
    use hns_store::{MemoryStore, Store};

    fn header(prev_block: BlockHash, nonce: u32) -> Header {
        Header {
            prev_block,
            nonce,
            bits: 0x207f_ffff,
            ..Header::default()
        }
    }

    fn covenant() -> Covenant {
        Covenant {
            kind: CovenantKind::None,
            items: Vec::new(),
        }
    }

    fn output(value: u64) -> Output {
        Output {
            value,
            address: Address::new(0, vec![5; 20]).expect("address"),
            covenant: covenant(),
        }
    }

    fn transaction(seed: u8, outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([seed; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs,
            locktime: 0,
        }
    }

    #[test]
    fn block_status_codec_preserves_every_validation_stage() {
        let status = BlockStatus {
            header_context_valid: true,
            checkpoint_valid: true,
            deployment_state_valid: true,
            body_present: true,
            body_syntax_valid: true,
            absolute_finality_valid: true,
            relative_locks_valid: true,
            scripts_valid: true,
            covenant_links_valid: true,
            covenants_context_valid: true,
            claims_and_airdrops_valid: true,
            utxo_connected: true,
            name_state_connected: true,
            tree_root_valid: true,
            undo_present: true,
            active_chain: true,
            failed: true,
        };

        assert_eq!(BlockStatus::from_bits(status.to_bits()), status);
        assert_eq!(status.to_bits(), (1u32 << 17) - 1);
    }

    #[test]
    fn mining_authority_requires_complete_consensus_and_durable_state() {
        let mut status = BlockStatus {
            header_context_valid: true,
            checkpoint_valid: true,
            deployment_state_valid: true,
            body_present: true,
            body_syntax_valid: true,
            absolute_finality_valid: true,
            relative_locks_valid: true,
            scripts_valid: true,
            covenant_links_valid: true,
            covenants_context_valid: true,
            claims_and_airdrops_valid: true,
            tree_root_valid: true,
            ..BlockStatus::default()
        };

        assert!(status.is_consensus_valid());
        assert!(!status.is_mining_authoritative());

        status.utxo_connected = true;
        status.name_state_connected = true;
        status.undo_present = true;
        status.active_chain = true;
        assert!(status.is_mining_authoritative());

        status.scripts_valid = false;
        assert!(!status.is_consensus_valid());
        assert!(!status.is_mining_authoritative());
    }

    #[test]
    fn memory_index_promotes_best_chain() {
        let mut index = MemoryHeaderIndex::new();
        let genesis = index
            .insert_header(header(BlockHash::ZERO, 1), 0)
            .expect("genesis");
        let first = index
            .insert_header(header(genesis.hash, 2), 1)
            .expect("first");

        assert_eq!(
            index.best_tip().expect("tip").expect("some").hash,
            first.hash
        );
        assert_eq!(
            index.canonical_hash(0).expect("canonical"),
            Some(genesis.hash)
        );
        assert_eq!(
            index.canonical_hash(1).expect("canonical"),
            Some(first.hash)
        );
    }

    #[test]
    fn equal_work_header_preserves_first_seen_best_tip() {
        let mut index = MemoryHeaderIndex::new();
        let genesis = index
            .insert_header(header(BlockHash::ZERO, 1), 0)
            .expect("genesis");
        let first = index
            .insert_header(header(genesis.hash, 2), 1)
            .expect("first");
        let alternate_header = header(genesis.hash, 3);
        let alternate = HeaderRecord {
            hash: alternate_header.hash(),
            height: 1,
            chainwork: first.chainwork,
            header: alternate_header,
            status: BlockStatus {
                header_context_valid: true,
                ..BlockStatus::default()
            },
        };

        index.insert_record(alternate).expect("alternate");
        assert_eq!(index.best_tip().expect("tip").expect("best").hash, first.hash);
        assert_eq!(index.canonical_hash(1).expect("canonical"), Some(first.hash));
    }

    #[test]
    fn memory_index_plans_reorg() {
        let mut index = MemoryHeaderIndex::new();
        let genesis = index
            .insert_header(header(BlockHash::ZERO, 1), 0)
            .expect("genesis");
        let old_tip = index
            .insert_header(header(genesis.hash, 2), 1)
            .expect("old");
        let side = HeaderRecord {
            hash: header(genesis.hash, 3).hash(),
            height: 1,
            chainwork: old_tip.chainwork,
            header: header(genesis.hash, 3),
            status: BlockStatus {
                header_context_valid: true,
                ..BlockStatus::default()
            },
        };
        let side_hash = side.hash;
        index.insert_record(side).expect("side");

        let plan = index.plan_reorg(&side_hash).expect("plan");
        assert_eq!(plan.disconnect, vec![old_tip.hash]);
        assert_eq!(plan.connect, vec![side_hash]);
    }

    #[test]
    fn header_record_codec_round_trips() {
        let record = HeaderRecord {
            hash: header(BlockHash::ZERO, 10).hash(),
            height: 42,
            chainwork: 99u64.into(),
            header: header(BlockHash::ZERO, 10),
            status: BlockStatus {
                header_context_valid: true,
                body_present: true,
                failed: false,
                ..BlockStatus::default()
            },
        };

        assert_eq!(
            HeaderRecord::decode(&record.encode()).expect("decode"),
            record
        );
    }

    #[test]
    fn block_index_record_codec_round_trips() {
        let block = Block {
            header: header(BlockHash::new([9; 32]), 13),
            transactions: Vec::new(),
        };
        let mut record = BlockIndexRecord::from_block(&block, 8, 21u64.into()).expect("record");
        record.status.body_syntax_valid = true;
        record.validated_at = Some(123);

        assert_eq!(
            BlockIndexRecord::decode(&record.encode()).expect("decode"),
            record
        );
    }

    #[test]
    fn tx_index_entry_codec_round_trips() {
        let entry = TxIndexEntry {
            txid: Txid::new([1; 32]),
            block_hash: BlockHash::new([2; 32]),
            height: 3,
            tx_offset: 4,
            tx_len: 5,
            output_count: 6,
        };

        assert_eq!(
            TxIndexEntry::decode(&entry.encode()).expect("decode"),
            entry
        );
    }

    #[test]
    fn memory_block_index_tracks_records() {
        let block = Block {
            header: header(BlockHash::ZERO, 14),
            transactions: Vec::new(),
        };
        let record = BlockIndexRecord::from_block(&block, 0, Uint256::ONE).expect("record");
        let mut index = MemoryBlockIndex::new();
        index.insert_block_record(record.clone()).expect("insert");

        assert_eq!(index.block(&record.hash).expect("block"), Some(record));
    }

    #[test]
    fn raw_block_record_codec_checks_checksum_and_hash() {
        let block = Block {
            header: header(BlockHash::ZERO, 15),
            transactions: Vec::new(),
        };
        let record = RawBlockRecord::from_block(&block, RawBlockSource::Fixture);

        assert_eq!(
            RawBlockRecord::decode(&record.encode())
                .expect("decode")
                .decode_block()
                .expect("block"),
            block
        );
    }

    #[test]
    fn stored_header_index_persists_imported_records() {
        let store = MemoryStore::new();
        let mut index = StoredHeaderIndex::new(store.clone()).expect("index");
        let record = index
            .import_header(HeaderImport {
                header: header(BlockHash::ZERO, 11),
                height: 0,
                verify_pow: false,
            })
            .expect("import");

        assert_eq!(
            index.load_record(&record.hash).expect("load"),
            Some(record.clone())
        );

        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            read_canonical_hash(&snapshot, 0).expect("active height"),
            None,
            "header-only imports must not mutate the active block height index"
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())
                .expect("best"),
            Some(record.hash.as_bytes().to_vec())
        );

        let reloaded = StoredHeaderIndex::new(store).expect("reloaded");
        assert_eq!(
            reloaded.best_tip().expect("tip").expect("best").hash,
            record.hash
        );
        assert_eq!(
            reloaded.canonical_hash(0).expect("canonical"),
            Some(record.hash)
        );
    }

    #[test]
    fn stored_header_index_rejects_bad_pow_when_requested() {
        let store = MemoryStore::new();
        let mut index = StoredHeaderIndex::new(store).expect("index");
        let error = index
            .import_header(HeaderImport {
                header: header(BlockHash::ZERO, 12),
                height: 0,
                verify_pow: true,
            })
            .expect_err("bad pow");

        assert!(matches!(
            error,
            ChainError::InvalidHeader("proof of work failed")
        ));
    }

    #[test]
    fn stored_block_index_persists_raw_blocks() {
        let store = MemoryStore::new();
        let block = Block {
            header: header(BlockHash::ZERO, 16),
            transactions: vec![
                transaction(1, vec![output(10)]),
                transaction(2, vec![output(20)]),
            ],
        };
        let mut index = StoredBlockIndex::new(store.clone()).expect("index");
        let record = index
            .store_block(&block, 0, Uint256::ONE, RawBlockSource::Fixture)
            .expect("store block");

        let reloaded = StoredBlockIndex::new(store).expect("reloaded");
        assert_eq!(
            reloaded.load_block_record(&record.hash).expect("record"),
            Some(record.clone())
        );
        assert_eq!(
            reloaded.load_block(&record.hash).expect("block"),
            Some(block)
        );
        assert_eq!(reloaded.block(&record.hash).expect("memory"), Some(record));
    }

    #[test]
    fn stored_block_index_persists_tx_index_entries() {
        let store = MemoryStore::new();
        let block = Block {
            header: header(BlockHash::ZERO, 17),
            transactions: vec![
                transaction(3, vec![output(10)]),
                transaction(4, vec![output(20)]),
            ],
        };
        let first_txid = block.transactions[0].txid();
        let second_txid = block.transactions[1].txid();
        let mut index = StoredBlockIndex::new(store.clone()).expect("index");
        let record = index
            .store_block(&block, 42, 99u64.into(), RawBlockSource::Fixture)
            .expect("store block");

        let reloaded = StoredBlockIndex::new(store).expect("reloaded");
        let first = reloaded
            .load_tx_index(&first_txid)
            .expect("tx index")
            .expect("first tx");
        let second = reloaded
            .load_tx_index(&second_txid)
            .expect("tx index")
            .expect("second tx");

        assert_eq!(first.block_hash, record.hash);
        assert_eq!(first.height, 42);
        assert_eq!(first.tx_offset, (HEADER_SIZE + 1) as u32);
        assert_eq!(first.tx_len, block.transactions[0].encode().len() as u32);
        assert_eq!(first.output_count, 1);
        assert_eq!(second.tx_offset, first.tx_offset + first.tx_len);
    }
}
