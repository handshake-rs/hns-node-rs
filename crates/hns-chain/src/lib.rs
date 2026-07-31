#![forbid(unsafe_code)]

use std::{
    cmp::Reverse,
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use hns_primitives::{
    blake2b_256, Block, BlockHash, CompactTarget, Header, Height, Reader, Transaction, Txid,
    Uint256, Writer, HEADER_SIZE, MAX_BLOCK_WEIGHT,
};
use hns_store::{
    ColumnFamily, MetaKey, PrefixScanBudget, ReadSnapshot, Store, StoreError, WriteBatch,
};
use serde::{Deserialize, Serialize};

const INDEX_LOAD_PAGE_ENTRIES: usize = 4_096;
const INDEX_LOAD_PAGE_BYTES: usize = 4 * 1024 * 1024;
const STORED_BLOCK_CACHE_RECORDS: usize = 4_096;
const MAX_LIVE_HEADER_IMPORT_RECORDS: usize = 2_000;
const MAX_LIVE_HEADER_CANONICAL_SWITCH: usize = 16_384;
const MAX_LIVE_CACHE_UPDATE_RECORDS: usize = 1_024;
const MAX_LIVE_FAILED_BRANCH_RECORDS: usize = 16_384;
const MAX_LIVE_FAILED_BRANCH_ELAPSED: Duration = Duration::from_secs(30);
/// Canonical headers scale with chain height. Competing and stale branches do
/// not: one million resident records leaves substantial mainnet fork headroom
/// while bounding the extra graph/map footprint well below the 8 GiB
/// qualification envelope.
pub const MAX_RESIDENT_ALTERNATE_HEADERS: usize = 1_000_000;

fn bounded_alternate_header_count(
    total_records: usize,
    canonical_records: usize,
    maximum_alternates: usize,
) -> Result<usize, ChainError> {
    let alternates = total_records
        .checked_sub(canonical_records)
        .ok_or_else(|| {
            ChainError::Codec("canonical header count exceeds total records".to_owned())
        })?;
    if alternates > maximum_alternates {
        return Err(ChainError::LiveWorkLimit {
            context: "resident alternate headers",
            limit: maximum_alternates,
            actual: alternates,
        });
    }
    Ok(alternates)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainTip {
    pub hash: BlockHash,
    pub height: Height,
    pub chainwork: Uint256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
/// Durable validation-stage satisfaction. For a block on the hardcoded
/// checkpoint ancestry, a stage bit may be satisfied by HSD's exact historical
/// assumption rather than local execution; `checkpoint_valid`, the block
/// height/hash, and canonical header ancestry provide that provenance.
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
    /// schema is satisfied either by execution or by an authenticated HSD
    /// historical assumption. Persistence and active-chain membership are
    /// kept separate so side-chain validation remains representable.
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

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockIndexRecord {
    pub hash: BlockHash,
    pub height: Height,
    pub prev_hash: BlockHash,
    pub chainwork: Uint256,
    pub status: BlockStatus,
    pub tx_count: u32,
    pub validated_at: Option<u64>,
}

impl Clone for BlockIndexRecord {
    fn clone(&self) -> Self {
        #[cfg(test)]
        BLOCK_INDEX_RECORD_CLONES.with(|clones| clones.set(clones.get().saturating_add(1)));
        Self {
            hash: self.hash,
            height: self.height,
            prev_hash: self.prev_hash,
            chainwork: self.chainwork,
            status: self.status.clone(),
            tx_count: self.tx_count,
            validated_at: self.validated_at,
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static BLOCK_INDEX_RECORD_CLONES: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn reset_block_index_record_clone_count() {
    BLOCK_INDEX_RECORD_CLONES.with(|clones| clones.set(0));
}

#[cfg(test)]
fn block_index_record_clone_count() -> usize {
    BLOCK_INDEX_RECORD_CLONES.with(std::cell::Cell::get)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReorgPlanLimits {
    pub maximum_disconnect: usize,
    pub maximum_connect: usize,
}

impl ReorgPlanLimits {
    pub const UNBOUNDED: Self = Self {
        maximum_disconnect: usize::MAX,
        maximum_connect: usize::MAX,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderImport {
    pub header: Header,
    pub height: Height,
    pub verify_pow: bool,
    /// The caller enforced its selected checkpoint policy while validating
    /// this header. The index itself has no network parameter dependency.
    pub checkpoint_valid: bool,
}

/// Construct the durable record for a contextually validated header import.
/// This helper is also used by staged callers that need later headers in the
/// same atomic batch to observe their predecessors before anything commits.
pub fn prepare_header_record(
    request: &HeaderImport,
    parent: Option<&HeaderRecord>,
) -> Result<HeaderRecord, ChainError> {
    if request.verify_pow && !request.header.verify_pow() {
        return Err(ChainError::InvalidHeader("proof of work failed"));
    }

    let (parent_work, failed) = match (request.height, parent) {
        (0, None) if request.header.prev_block == BlockHash::ZERO => (Uint256::ZERO, false),
        (0, None) => {
            return Err(ChainError::InvalidHeader(
                "genesis header has a non-zero parent",
            ));
        }
        (0, Some(_)) => {
            return Err(ChainError::InvalidHeader(
                "genesis import unexpectedly has a parent",
            ));
        }
        (_, None) => return Err(ChainError::MissingParent(request.header.prev_block)),
        (_, Some(parent)) => {
            if parent.hash != request.header.prev_block
                || parent.height.checked_add(1) != Some(request.height)
            {
                return Err(ChainError::InvalidHeader(
                    "height is not contiguous with parent",
                ));
            }
            (parent.chainwork, parent.status.failed)
        }
    };
    let proof = CompactTarget::from_bits(request.header.bits)
        .proof()
        .ok_or(ChainError::InvalidHeader("invalid proof-of-work target"))?;
    let chainwork = parent_work
        .checked_add(proof)
        .ok_or_else(|| ChainError::Codec("chainwork overflow".to_owned()))?;

    Ok(HeaderRecord {
        hash: request.header.hash(),
        height: request.height,
        chainwork,
        header: request.header.clone(),
        status: BlockStatus {
            header_context_valid: true,
            checkpoint_valid: request.checkpoint_valid,
            failed,
            ..BlockStatus::default()
        },
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedHeaderPlan {
    pub affected: Vec<HeaderRecord>,
    pub best: ChainTip,
    previous_best: ChainTip,
    canonical: ReorgPlan,
}

#[derive(Clone, Debug)]
pub struct HeaderIndexCacheUpdate {
    records: Vec<HeaderRecord>,
    previous_records: Vec<Option<HeaderRecord>>,
    previous_best: Option<ChainTip>,
    best: Option<ChainTip>,
    canonical: ReorgPlan,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum HeaderRecordValidation {
    #[default]
    Strict,
    #[cfg(any(test, feature = "test-fixtures"))]
    TestFixtures,
}

impl HeaderRecordValidation {
    const fn permits_synthetic_roots(self) -> bool {
        #[cfg(any(test, feature = "test-fixtures"))]
        if matches!(self, Self::TestFixtures) {
            return true;
        }
        false
    }
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

    fn plan_reorg_bounded(
        &self,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
    ) -> Result<ReorgPlan, ChainError>;

    fn plan_reorg_between_bounded(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
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
    children: HashMap<BlockHash, Vec<BlockHash>>,
    viable: BTreeSet<(Uint256, Reverse<Height>, Reverse<BlockHash>)>,
    root_count: usize,
    validation: HeaderRecordValidation,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryBlockIndex {
    records: HashMap<BlockHash, BlockIndexRecord>,
    record_order: VecDeque<BlockHash>,
    maximum_records: Option<usize>,
    alternate_count: usize,
    failed_count: usize,
    generation: u64,
}

#[derive(Clone, Debug)]
pub struct BlockIndexCacheUpdate {
    expected_generation: u64,
    next_generation: u64,
    alternate_count: usize,
    failed_count: usize,
    records: Vec<BlockIndexRecord>,
}

impl MemoryBlockIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_records(records: impl IntoIterator<Item = BlockIndexRecord>) -> Self {
        let mut index = Self::new();
        for record in records {
            index
                .insert_block_record(record)
                .expect("unbounded memory block index counters cannot overflow");
        }
        index
    }

    fn bounded(maximum_records: usize) -> Self {
        debug_assert!(maximum_records > 0);
        Self {
            maximum_records: Some(maximum_records),
            ..Self::default()
        }
    }

    pub const fn status_counts(&self) -> (usize, usize) {
        (self.alternate_count, self.failed_count)
    }

    const fn status_contribution(record: &BlockIndexRecord) -> (usize, usize) {
        if record.status.failed {
            (0, 1)
        } else if !record.status.active_chain {
            (1, 0)
        } else {
            (0, 0)
        }
    }

    fn observe_loaded_record(&mut self, record: BlockIndexRecord) -> Result<(), ChainError> {
        let (alternate, failed) = Self::status_contribution(&record);
        self.alternate_count = self
            .alternate_count
            .checked_add(alternate)
            .ok_or_else(|| ChainError::Codec("alternate block counter overflow".to_owned()))?;
        self.failed_count = self
            .failed_count
            .checked_add(failed)
            .ok_or_else(|| ChainError::Codec("failed block counter overflow".to_owned()))?;
        self.cache_record(record);
        Ok(())
    }

    fn replace_loaded_record(
        &mut self,
        previous: Option<&BlockIndexRecord>,
        record: BlockIndexRecord,
    ) -> Result<(), ChainError> {
        let (old_alternate, old_failed) = previous.map(Self::status_contribution).unwrap_or((0, 0));
        let (new_alternate, new_failed) = Self::status_contribution(&record);
        let alternate_count = self
            .alternate_count
            .checked_sub(old_alternate)
            .and_then(|count| count.checked_add(new_alternate))
            .ok_or_else(|| ChainError::Codec("alternate block counter overflow".to_owned()))?;
        let failed_count = self
            .failed_count
            .checked_sub(old_failed)
            .and_then(|count| count.checked_add(new_failed))
            .ok_or_else(|| ChainError::Codec("failed block counter overflow".to_owned()))?;
        self.cache_record(record);
        self.alternate_count = alternate_count;
        self.failed_count = failed_count;
        Ok(())
    }

    fn cache_record(&mut self, record: BlockIndexRecord) {
        if !self.records.contains_key(&record.hash) {
            if self
                .maximum_records
                .is_some_and(|maximum| self.records.len() == maximum)
            {
                let evicted = self
                    .record_order
                    .pop_front()
                    .expect("bounded block cache order is non-empty at capacity");
                self.records.remove(&evicted);
            }
            self.record_order.push_back(record.hash);
        }
        self.records.insert(record.hash, record);
    }
}

impl BlockIndex for MemoryBlockIndex {
    fn block(&self, hash: &BlockHash) -> Result<Option<BlockIndexRecord>, ChainError> {
        Ok(self.records.get(hash).cloned())
    }

    fn insert_block_record(&mut self, record: BlockIndexRecord) -> Result<(), ChainError> {
        let previous = self.records.get(&record.hash).cloned();
        self.replace_loaded_record(previous.as_ref(), record)
    }
}

impl MemoryHeaderIndex {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn new_for_test_fixtures() -> Self {
        Self {
            validation: HeaderRecordValidation::TestFixtures,
            ..Self::default()
        }
    }

    pub fn insert_header(
        &mut self,
        header: Header,
        height: Height,
    ) -> Result<HeaderRecord, ChainError> {
        self.insert_import(HeaderImport {
            header,
            height,
            verify_pow: false,
            checkpoint_valid: false,
        })
    }

    fn insert_import(&mut self, request: HeaderImport) -> Result<HeaderRecord, ChainError> {
        let hash = request.header.hash();
        if self.records.contains_key(&hash) {
            return Err(ChainError::DuplicateHeader(hash));
        }
        if request.height == 0 && !self.validation.permits_synthetic_roots() && self.root_count != 0
        {
            return Err(ChainError::InvalidHeader(
                "header index already has a genesis root",
            ));
        }
        let parent = if request.height == 0 {
            None
        } else {
            Some(
                self.records
                    .get(&request.header.prev_block)
                    .ok_or(ChainError::MissingParent(request.header.prev_block))?,
            )
        };
        let record = prepare_header_record(&request, parent)?;
        let projected_total = self
            .records
            .len()
            .checked_add(1)
            .ok_or_else(|| ChainError::Codec("resident header count overflow".to_owned()))?;
        bounded_alternate_header_count(
            projected_total,
            self.projected_canonical_count(&record)?,
            MAX_RESIDENT_ALTERNATE_HEADERS,
        )?;

        self.records.insert(record.hash, record.clone());
        self.index_new_record(&record);
        self.promote_if_best(&record)?;
        Ok(record)
    }

    pub fn insert_record(&mut self, record: HeaderRecord) -> Result<(), ChainError> {
        validate_header_record_identity(&record)?;
        let previous = self.records.get(&record.hash);
        if record.height == 0
            && previous.is_none()
            && !self.validation.permits_synthetic_roots()
            && self.root_count != 0
        {
            return Err(ChainError::InvalidHeader(
                "header index already has a genesis root",
            ));
        }
        let parent = if record.height == 0 {
            None
        } else {
            Some(
                self.records
                    .get(&record.header.prev_block)
                    .ok_or(ChainError::MissingParent(record.header.prev_block))?,
            )
        };
        validate_header_record_structure(&record, parent, self.validation)?;
        if parent.is_some_and(|parent| parent.status.failed && !record.status.failed) {
            return Err(ChainError::InconsistentFailureAncestry(record.hash));
        }
        if previous.is_none() {
            let projected_total =
                self.records.len().checked_add(1).ok_or_else(|| {
                    ChainError::Codec("resident header count overflow".to_owned())
                })?;
            bounded_alternate_header_count(
                projected_total,
                self.projected_canonical_count(&record)?,
                MAX_RESIDENT_ALTERNATE_HEADERS,
            )?;
        }
        if let Some(previous) = previous {
            if previous.height != record.height
                || previous.chainwork != record.chainwork
                || previous.header != record.header
            {
                return Err(ChainError::Codec(format!(
                    "replacement header {} changes immutable index fields",
                    record.hash.to_hex()
                )));
            }
            if self
                .best
                .as_ref()
                .is_some_and(|best| best.hash == record.hash)
                && record.status.failed
            {
                return Err(ChainError::FailedBestHeader(record.hash));
            }
        }

        if let Some(previous) = previous {
            if !previous.status.failed {
                self.viable.remove(&Self::viable_key(previous));
            }
        } else if record.height != 0 {
            self.children
                .entry(record.header.prev_block)
                .or_default()
                .push(record.hash);
        } else {
            self.root_count = self
                .root_count
                .checked_add(1)
                .expect("validated header root count cannot overflow");
        }
        if !record.status.failed {
            self.viable.insert(Self::viable_key(&record));
        }
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
        let mut record_map = HashMap::new();
        for record in records {
            let hash = record.hash;
            if record_map.insert(hash, record).is_some() {
                return Err(ChainError::DuplicateHeader(hash));
            }
        }
        Self::from_record_map_with_best_and_validation(
            record_map,
            persisted_best,
            HeaderRecordValidation::Strict,
        )
    }

    fn from_record_map_with_best_and_validation(
        records: HashMap<BlockHash, HeaderRecord>,
        persisted_best: Option<BlockHash>,
        validation: HeaderRecordValidation,
    ) -> Result<Self, ChainError> {
        Self::from_record_map_with_best_validation_and_alternate_limit(
            records,
            persisted_best,
            validation,
            MAX_RESIDENT_ALTERNATE_HEADERS,
        )
    }

    fn from_record_map_with_best_validation_and_alternate_limit(
        records: HashMap<BlockHash, HeaderRecord>,
        persisted_best: Option<BlockHash>,
        validation: HeaderRecordValidation,
        maximum_alternates: usize,
    ) -> Result<Self, ChainError> {
        let mut children = HashMap::<BlockHash, Vec<BlockHash>>::new();
        let mut viable = BTreeSet::new();
        let mut roots = 0usize;
        for record in records.values() {
            validate_header_record_identity(record)?;
            let parent = if record.height == 0 {
                roots = roots
                    .checked_add(1)
                    .ok_or_else(|| ChainError::Codec("header root count overflow".to_owned()))?;
                None
            } else {
                Some(
                    records
                        .get(&record.header.prev_block)
                        .ok_or(ChainError::MissingParent(record.header.prev_block))?,
                )
            };
            validate_header_record_structure(record, parent, validation)?;
            if parent.is_some_and(|parent| parent.status.failed && !record.status.failed) {
                return Err(ChainError::InconsistentFailureAncestry(record.hash));
            }
            if record.height != 0 {
                children
                    .entry(record.header.prev_block)
                    .or_default()
                    .push(record.hash);
            }
            if !record.status.failed {
                viable.insert(Self::viable_key(record));
            }
        }
        if !records.is_empty() && roots == 0 {
            return Err(ChainError::InvalidHeader(
                "header index has no genesis root",
            ));
        }
        if roots > 1 && !validation.permits_synthetic_roots() {
            return Err(ChainError::InvalidHeader(
                "header index has multiple genesis roots",
            ));
        }
        let mut index = Self {
            records,
            canonical: HashMap::new(),
            best: None,
            children,
            viable,
            root_count: roots,
            validation,
        };

        if let Some(best_hash) = persisted_best {
            let best_record = index
                .records
                .get(&best_hash)
                .cloned()
                .ok_or(ChainError::MissingHeader(best_hash))?;
            if best_record.status.failed {
                return Err(ChainError::FailedBestHeader(best_hash));
            }
            if index
                .records
                .values()
                .any(|record| !record.status.failed && record.chainwork > best_record.chainwork)
            {
                return Err(ChainError::InconsistentBestHeader(best_hash));
            }
            index.promote_recovery(&best_record)?;
            index.ensure_alternate_header_budget_with_limit(maximum_alternates)?;
            return Ok(index);
        }

        if let Some(best_record) = index.best_viable_excluding(&HashSet::new()).cloned() {
            index.promote_recovery(&best_record)?;
        }

        index.ensure_alternate_header_budget_with_limit(maximum_alternates)?;
        Ok(index)
    }

    fn viable_key(record: &HeaderRecord) -> (Uint256, Reverse<Height>, Reverse<BlockHash>) {
        (
            record.chainwork,
            Reverse(record.height),
            Reverse(record.hash),
        )
    }

    fn index_new_record(&mut self, record: &HeaderRecord) {
        if record.height != 0 {
            self.children
                .entry(record.header.prev_block)
                .or_default()
                .push(record.hash);
        } else {
            self.root_count = self
                .root_count
                .checked_add(1)
                .expect("validated header root count cannot overflow");
        }
        if !record.status.failed {
            self.viable.insert(Self::viable_key(record));
        }
    }

    fn best_viable_excluding(&self, excluded: &HashSet<BlockHash>) -> Option<&HeaderRecord> {
        self.viable.iter().rev().find_map(|(_, _, Reverse(hash))| {
            if excluded.contains(hash) {
                None
            } else {
                self.records.get(hash)
            }
        })
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

    fn records(&self) -> impl Iterator<Item = &HeaderRecord> {
        self.records.values()
    }

    pub fn alternate_header_count(&self) -> usize {
        self.records.len().saturating_sub(self.canonical.len())
    }

    fn ensure_alternate_header_budget(&self) -> Result<(), ChainError> {
        self.ensure_alternate_header_budget_with_limit(MAX_RESIDENT_ALTERNATE_HEADERS)
    }

    fn ensure_alternate_header_budget_with_limit(
        &self,
        maximum_alternates: usize,
    ) -> Result<(), ChainError> {
        bounded_alternate_header_count(self.records.len(), self.canonical.len(), maximum_alternates)
            .map(|_| ())
    }

    fn projected_canonical_count(&self, candidate: &HeaderRecord) -> Result<usize, ChainError> {
        let should_promote = !candidate.status.failed
            && self
                .best
                .as_ref()
                .is_none_or(|best| candidate.chainwork > best.chainwork);
        if !should_promote {
            return Ok(self.canonical.len());
        }
        usize::try_from(candidate.height)
            .ok()
            .and_then(|height| height.checked_add(1))
            .ok_or_else(|| ChainError::Codec("canonical header count overflow".to_owned()))
    }

    fn promote_if_best(&mut self, record: &HeaderRecord) -> Result<(), ChainError> {
        if record.status.failed {
            return Ok(());
        }
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
        if record.status.failed {
            return Err(ChainError::FailedBestHeader(record.hash));
        }

        if self.best.as_ref().is_some_and(|best| {
            record.header.prev_block == best.hash
                && best.height.checked_add(1) == Some(record.height)
        }) {
            self.canonical.insert(record.height, record.hash);
            self.best = Some(ChainTip {
                hash: record.hash,
                height: record.height,
                chainwork: record.chainwork,
            });
            return Ok(());
        }

        let path = self.path_to_genesis_bounded(record.hash, MAX_LIVE_HEADER_CANONICAL_SWITCH)?;
        self.canonical.clear();

        for hash in path.into_iter().rev() {
            let path_record = self
                .records
                .get(&hash)
                .ok_or(ChainError::MissingHeader(hash))?;
            if path_record.status.failed {
                return Err(ChainError::InconsistentFailureAncestry(record.hash));
            }
            self.canonical.insert(path_record.height, hash);
        }

        self.best = Some(ChainTip {
            hash: record.hash,
            height: record.height,
            chainwork: record.chainwork,
        });

        Ok(())
    }

    /// Reconstruct the complete canonical map once while opening a validated
    /// durable index. Unlike live peer-triggered branch switching, recovery
    /// must accept the full u32 height domain and therefore walks decreasing
    /// heights without materializing an ancestry vector.
    fn promote_recovery(&mut self, record: &HeaderRecord) -> Result<(), ChainError> {
        if record.status.failed {
            return Err(ChainError::FailedBestHeader(record.hash));
        }
        self.canonical.clear();
        let mut current = record;
        loop {
            if current.status.failed {
                return Err(ChainError::InconsistentFailureAncestry(record.hash));
            }
            self.canonical.insert(current.height, current.hash);
            if current.height == 0 {
                break;
            }
            current = self
                .records
                .get(&current.header.prev_block)
                .ok_or(ChainError::MissingHeader(current.header.prev_block))?;
        }
        self.best = Some(ChainTip {
            hash: record.hash,
            height: record.height,
            chainwork: record.chainwork,
        });
        Ok(())
    }

    fn failed_branch_plan(&self, root: BlockHash) -> Result<FailedHeaderPlan, ChainError> {
        let now = Instant::now();
        self.failed_branch_plan_bounded(
            root,
            MAX_LIVE_FAILED_BRANCH_RECORDS,
            now.checked_add(MAX_LIVE_FAILED_BRANCH_ELAPSED)
                .unwrap_or(now),
        )
    }

    fn failed_branch_plan_bounded(
        &self,
        root: BlockHash,
        maximum_records: usize,
        deadline: Instant,
    ) -> Result<FailedHeaderPlan, ChainError> {
        if Instant::now() >= deadline {
            return Err(ChainError::LiveWorkDeadline {
                context: "failed header descendants",
            });
        }
        let root_record = self
            .records
            .get(&root)
            .ok_or(ChainError::MissingHeader(root))?;
        if root_record.height == 0 {
            return Err(ChainError::FailedGenesis(root));
        }

        if maximum_records == 0 {
            return Err(ChainError::LiveWorkLimit {
                context: "failed header descendants",
                limit: 0,
                actual: 1,
            });
        }
        let mut affected_hashes = HashSet::with_capacity(maximum_records);
        let mut affected_order = Vec::with_capacity(maximum_records);
        let mut queue = VecDeque::from([root]);
        let mut enqueued = 1usize;
        while let Some(hash) = queue.pop_front() {
            if Instant::now() >= deadline {
                return Err(ChainError::LiveWorkDeadline {
                    context: "failed header descendants",
                });
            }
            if !affected_hashes.insert(hash) {
                continue;
            }
            affected_order.push(hash);
            if let Some(descendants) = self.children.get(&hash) {
                for descendant in descendants {
                    if Instant::now() >= deadline {
                        return Err(ChainError::LiveWorkDeadline {
                            context: "failed header descendants",
                        });
                    }
                    if enqueued == maximum_records {
                        return Err(ChainError::LiveWorkLimit {
                            context: "failed header descendants",
                            limit: maximum_records,
                            actual: maximum_records.saturating_add(1),
                        });
                    }
                    queue.push_back(*descendant);
                    enqueued += 1;
                }
            }
        }

        if affected_hashes.iter().any(|hash| {
            self.records
                .get(hash)
                .is_some_and(|record| record.status.active_chain)
        }) {
            return Err(ChainError::FailedActiveHeader(root));
        }

        let affected = affected_order
            .into_iter()
            .map(|hash| {
                let mut record = self
                    .records
                    .get(&hash)
                    .cloned()
                    .ok_or(ChainError::MissingHeader(hash))?;
                record.status.failed = true;
                Ok(record)
            })
            .collect::<Result<Vec<_>, ChainError>>()?;

        let previous_best = self
            .best
            .clone()
            .ok_or(ChainError::MissingBestHeaderBinding)?;
        let next_best_record = self
            .best_viable_excluding(&affected_hashes)
            .cloned()
            .ok_or(ChainError::MissingBestHeaderBinding)?;
        let best = ChainTip {
            hash: next_best_record.hash,
            height: next_best_record.height,
            chainwork: next_best_record.chainwork,
        };
        let canonical = if previous_best.hash == best.hash {
            ReorgPlan::default()
        } else {
            self.plan_reorg_delta_bounded(
                &previous_best.hash,
                &best.hash,
                ReorgPlanLimits {
                    maximum_disconnect: MAX_LIVE_HEADER_CANONICAL_SWITCH,
                    maximum_connect: MAX_LIVE_HEADER_CANONICAL_SWITCH,
                },
            )?
        };
        let projected_canonical = self
            .canonical
            .len()
            .checked_sub(canonical.disconnect.len())
            .and_then(|count| count.checked_add(canonical.connect.len()))
            .ok_or_else(|| ChainError::Codec("canonical header count overflow".to_owned()))?;
        bounded_alternate_header_count(
            self.records.len(),
            projected_canonical,
            MAX_RESIDENT_ALTERNATE_HEADERS,
        )?;

        Ok(FailedHeaderPlan {
            affected,
            best,
            previous_best,
            canonical,
        })
    }

    fn validate_failed_plan(&self, plan: &FailedHeaderPlan) -> Result<(), ChainError> {
        if self.best.as_ref() != Some(&plan.previous_best) {
            return Err(ChainError::Codec(
                "failed-header plan was built against a stale best-header generation".to_owned(),
            ));
        }
        plan.affected
            .len()
            .checked_add(plan.canonical.disconnect.len())
            .and_then(|work| work.checked_add(plan.canonical.connect.len()))
            .ok_or_else(|| {
                ChainError::Codec("failed-header plan work count overflow".to_owned())
            })?;

        for planned in &plan.affected {
            let current = self
                .records
                .get(&planned.hash)
                .ok_or(ChainError::MissingHeader(planned.hash))?;
            if current.height != planned.height
                || current.chainwork != planned.chainwork
                || current.header != planned.header
            {
                return Err(ChainError::Codec(format!(
                    "failed-header plan record {} changed before publication",
                    planned.hash.to_hex()
                )));
            }
        }
        for hash in &plan.canonical.disconnect {
            let record = self
                .records
                .get(hash)
                .ok_or(ChainError::MissingHeader(*hash))?;
            if self.canonical.get(&record.height) != Some(hash) {
                return Err(ChainError::Codec(format!(
                    "failed-header plan disconnect {} is no longer canonical",
                    hash.to_hex()
                )));
            }
        }
        for hash in &plan.canonical.connect {
            let record = self
                .records
                .get(hash)
                .ok_or(ChainError::MissingHeader(*hash))?;
            if record.status.failed {
                return Err(ChainError::InconsistentFailureAncestry(plan.best.hash));
            }
        }
        let best_record = self
            .records
            .get(&plan.best.hash)
            .ok_or(ChainError::MissingHeader(plan.best.hash))?;
        if best_record.status.failed
            || best_record.height != plan.best.height
            || best_record.chainwork != plan.best.chainwork
        {
            return Err(ChainError::FailedBestHeader(plan.best.hash));
        }
        Ok(())
    }

    fn apply_validated_failed_plan(&mut self, plan: &FailedHeaderPlan) {
        debug_assert!(self.validate_failed_plan(plan).is_ok());
        for planned in &plan.affected {
            let record = self
                .records
                .get_mut(&planned.hash)
                .expect("failed-header plan was fully validated");
            if !record.status.failed {
                self.viable.remove(&Self::viable_key(record));
            }
            record.status = planned.status.clone();
        }

        for hash in &plan.canonical.disconnect {
            let height = self
                .records
                .get(hash)
                .expect("failed-header plan was fully validated")
                .height;
            self.canonical.remove(&height);
        }
        for hash in &plan.canonical.connect {
            let record = self
                .records
                .get(hash)
                .expect("failed-header plan was fully validated");
            self.canonical.insert(record.height, record.hash);
        }
        self.best = Some(plan.best.clone());
    }

    fn prepare_cache_update(
        &self,
        records: &[HeaderRecord],
    ) -> Result<HeaderIndexCacheUpdate, ChainError> {
        if records.len() > MAX_LIVE_CACHE_UPDATE_RECORDS {
            return Err(ChainError::LiveWorkLimit {
                context: "header cache update records",
                limit: MAX_LIVE_CACHE_UPDATE_RECORDS,
                actual: records.len(),
            });
        }
        let mut seen = HashSet::with_capacity(records.len());
        let mut staged = HashMap::with_capacity(records.len());
        let mut previous_records = Vec::with_capacity(records.len());
        for planned in records {
            validate_header_record_identity(planned)?;
            if !seen.insert(planned.hash) {
                return Err(ChainError::DuplicateHeader(planned.hash));
            }
            if let Some(current) = self.records.get(&planned.hash) {
                if current.height != planned.height
                    || current.chainwork != planned.chainwork
                    || current.header != planned.header
                {
                    return Err(ChainError::Codec(format!(
                        "header cache update {} changes immutable index fields",
                        planned.hash.to_hex()
                    )));
                }
                if current.status.failed != planned.status.failed {
                    return Err(ChainError::Codec(format!(
                        "header cache update {} changes failure state outside a failure plan",
                        planned.hash.to_hex()
                    )));
                }
            }
            previous_records.push(self.records.get(&planned.hash).cloned());
            staged.insert(planned.hash, planned.clone());
        }

        let mut roots = self.root_count;
        for planned in records {
            if planned.height == 0 && !self.records.contains_key(&planned.hash) {
                roots = roots
                    .checked_add(1)
                    .ok_or_else(|| ChainError::Codec("header root count overflow".to_owned()))?;
                if roots > 1 && !self.validation.permits_synthetic_roots() {
                    return Err(ChainError::InvalidHeader(
                        "header cache update adds a second genesis root",
                    ));
                }
            }
            let parent = if planned.height == 0 {
                None
            } else {
                Some(
                    staged
                        .get(&planned.header.prev_block)
                        .or_else(|| self.records.get(&planned.header.prev_block))
                        .ok_or(ChainError::MissingParent(planned.header.prev_block))?,
                )
            };
            validate_header_record_structure(planned, parent, self.validation)?;
            if parent.is_some_and(|parent| parent.status.failed && !planned.status.failed) {
                return Err(ChainError::InconsistentFailureAncestry(planned.hash));
            }
        }

        let previous_best = self.best.clone();
        let mut best = previous_best.clone();
        for planned in records {
            if planned.status.failed {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| planned.chainwork > current.chainwork)
            {
                best = Some(ChainTip {
                    hash: planned.hash,
                    height: planned.height,
                    chainwork: planned.chainwork,
                });
            }
        }
        let canonical = match (&previous_best, &best) {
            (Some(previous), Some(next)) if previous.hash != next.hash => self
                .plan_reorg_delta_with_staged_bounded(
                    &previous.hash,
                    &next.hash,
                    &staged,
                    ReorgPlanLimits {
                        maximum_disconnect: MAX_LIVE_CACHE_UPDATE_RECORDS,
                        maximum_connect: MAX_LIVE_CACHE_UPDATE_RECORDS,
                    },
                )?,
            (None, Some(next)) => {
                let mut connect = Vec::new();
                let mut current = next.hash;
                loop {
                    if connect.len() == MAX_LIVE_CACHE_UPDATE_RECORDS {
                        return Err(ChainError::LiveWorkLimit {
                            context: "initial header cache canonical path",
                            limit: MAX_LIVE_CACHE_UPDATE_RECORDS,
                            actual: MAX_LIVE_CACHE_UPDATE_RECORDS.saturating_add(1),
                        });
                    }
                    let record = self.staged_record(&staged, &current)?;
                    if record.status.failed {
                        return Err(ChainError::InconsistentFailureAncestry(next.hash));
                    }
                    connect.push(current);
                    if record.height == 0 {
                        break;
                    }
                    current = record.header.prev_block;
                }
                connect.reverse();
                ReorgPlan {
                    disconnect: Vec::new(),
                    connect,
                }
            }
            _ => ReorgPlan::default(),
        };
        let added_records = previous_records
            .iter()
            .filter(|previous| previous.is_none())
            .count();
        let projected_total = self
            .records
            .len()
            .checked_add(added_records)
            .ok_or_else(|| ChainError::Codec("resident header count overflow".to_owned()))?;
        let projected_canonical = self
            .canonical
            .len()
            .checked_sub(canonical.disconnect.len())
            .and_then(|count| count.checked_add(canonical.connect.len()))
            .ok_or_else(|| ChainError::Codec("canonical header count overflow".to_owned()))?;
        bounded_alternate_header_count(
            projected_total,
            projected_canonical,
            MAX_RESIDENT_ALTERNATE_HEADERS,
        )?;
        Ok(HeaderIndexCacheUpdate {
            records: records.to_vec(),
            previous_records,
            previous_best,
            best,
            canonical,
        })
    }

    fn validate_cache_update(&self, update: &HeaderIndexCacheUpdate) -> Result<(), ChainError> {
        if self.best != update.previous_best {
            return Err(ChainError::Codec(
                "header cache update was built against a stale best generation".to_owned(),
            ));
        }
        if update.records.len() != update.previous_records.len() {
            return Err(ChainError::Codec(
                "header cache update previous-record cardinality mismatch".to_owned(),
            ));
        }
        for (planned, previous) in update.records.iter().zip(&update.previous_records) {
            if self.records.get(&planned.hash) != previous.as_ref() {
                return Err(ChainError::Codec(format!(
                    "header cache update {} was built against stale record state",
                    planned.hash.to_hex()
                )));
            }
        }
        for hash in &update.canonical.disconnect {
            let record = self
                .records
                .get(hash)
                .ok_or(ChainError::MissingHeader(*hash))?;
            if self.canonical.get(&record.height) != Some(hash) {
                return Err(ChainError::Codec(format!(
                    "header cache disconnect {} is no longer canonical",
                    hash.to_hex()
                )));
            }
        }
        Ok(())
    }

    fn apply_validated_cache_update(&mut self, update: HeaderIndexCacheUpdate) {
        debug_assert!(self.validate_cache_update(&update).is_ok());
        for planned in &update.records {
            if let Some(current) = self.records.get_mut(&planned.hash) {
                current.status = planned.status.clone();
            } else {
                self.records.insert(planned.hash, planned.clone());
                self.index_new_record(planned);
            }
        }
        for hash in &update.canonical.disconnect {
            let height = self
                .records
                .get(hash)
                .expect("prepared cache disconnect record exists")
                .height;
            self.canonical.remove(&height);
        }
        for hash in &update.canonical.connect {
            let record = self
                .records
                .get(hash)
                .expect("prepared cache connect record exists");
            self.canonical.insert(record.height, record.hash);
        }
        self.best = update.best;
    }

    fn staged_record<'a>(
        &'a self,
        staged: &'a HashMap<BlockHash, HeaderRecord>,
        hash: &BlockHash,
    ) -> Result<&'a HeaderRecord, ChainError> {
        staged
            .get(hash)
            .or_else(|| self.records.get(hash))
            .ok_or(ChainError::MissingHeader(*hash))
    }

    fn plan_reorg_delta_with_staged_bounded(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
        staged: &HashMap<BlockHash, HeaderRecord>,
        limits: ReorgPlanLimits,
    ) -> Result<ReorgPlan, ChainError> {
        if current == candidate {
            return Ok(ReorgPlan::default());
        }
        let mut old = self.staged_record(staged, current)?.clone();
        let mut new = self.staged_record(staged, candidate)?.clone();
        let mut disconnect = Vec::new();
        let mut connect_reverse = Vec::new();
        while old.height > new.height {
            push_reorg_hash(
                &mut disconnect,
                old.hash,
                limits.maximum_disconnect,
                "disconnect",
            )?;
            old = self.staged_record(staged, &old.header.prev_block)?.clone();
        }
        while new.height > old.height {
            push_reorg_hash(
                &mut connect_reverse,
                new.hash,
                limits.maximum_connect,
                "connect",
            )?;
            new = self.staged_record(staged, &new.header.prev_block)?.clone();
        }
        while old.hash != new.hash {
            if old.height == 0 || new.height == 0 {
                if self.validation.permits_synthetic_roots() && old.height == 0 && new.height == 0 {
                    push_reorg_hash(
                        &mut disconnect,
                        old.hash,
                        limits.maximum_disconnect,
                        "disconnect",
                    )?;
                    push_reorg_hash(
                        &mut connect_reverse,
                        new.hash,
                        limits.maximum_connect,
                        "connect",
                    )?;
                    break;
                }
                return Err(ChainError::NoCommonAncestor {
                    current: *current,
                    candidate: *candidate,
                });
            }
            push_reorg_hash(
                &mut disconnect,
                old.hash,
                limits.maximum_disconnect,
                "disconnect",
            )?;
            push_reorg_hash(
                &mut connect_reverse,
                new.hash,
                limits.maximum_connect,
                "connect",
            )?;
            old = self.staged_record(staged, &old.header.prev_block)?.clone();
            new = self.staged_record(staged, &new.header.prev_block)?.clone();
        }
        connect_reverse.reverse();
        Ok(ReorgPlan {
            disconnect,
            connect: connect_reverse,
        })
    }

    #[cfg(test)]
    fn fail_branch(&mut self, root: BlockHash) -> Result<Vec<HeaderRecord>, ChainError> {
        let plan = self.failed_branch_plan(root)?;
        self.validate_failed_plan(&plan)?;
        self.apply_validated_failed_plan(&plan);
        Ok(plan.affected)
    }

    fn plan_reorg_delta_bounded(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
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
            push_reorg_hash(
                &mut disconnect,
                old.hash,
                limits.maximum_disconnect,
                "disconnect",
            )?;
            old = self
                .records
                .get(&old.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(old.header.prev_block))?;
        }
        while new.height > old.height {
            push_reorg_hash(
                &mut connect_reverse,
                new.hash,
                limits.maximum_connect,
                "connect",
            )?;
            new = self
                .records
                .get(&new.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(new.header.prev_block))?;
        }
        while old.hash != new.hash {
            if old.height == 0 || new.height == 0 {
                if self.validation.permits_synthetic_roots() && old.height == 0 && new.height == 0 {
                    push_reorg_hash(
                        &mut disconnect,
                        old.hash,
                        limits.maximum_disconnect,
                        "disconnect",
                    )?;
                    push_reorg_hash(
                        &mut connect_reverse,
                        new.hash,
                        limits.maximum_connect,
                        "connect",
                    )?;
                    break;
                }
                return Err(ChainError::NoCommonAncestor {
                    current: *current,
                    candidate: *candidate,
                });
            }
            push_reorg_hash(
                &mut disconnect,
                old.hash,
                limits.maximum_disconnect,
                "disconnect",
            )?;
            old = self
                .records
                .get(&old.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(old.header.prev_block))?;
            push_reorg_hash(
                &mut connect_reverse,
                new.hash,
                limits.maximum_connect,
                "connect",
            )?;
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

    fn path_to_genesis_bounded(
        &self,
        tip: BlockHash,
        maximum_records: usize,
    ) -> Result<Vec<BlockHash>, ChainError> {
        let mut path = Vec::new();
        let mut current = tip;

        loop {
            if path.len() == maximum_records {
                return Err(ChainError::LiveWorkLimit {
                    context: "canonical header path",
                    limit: maximum_records,
                    actual: maximum_records.saturating_add(1),
                });
            }
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

    /// Explicit synthetic-chain recovery for development fixtures. Production
    /// constructors remain strict even when this non-default feature is built.
    #[cfg(feature = "test-fixtures")]
    pub fn new_for_test_fixtures(store: S) -> Result<Self, ChainError> {
        hns_store::initialize_schema(&store)?;
        let memory =
            load_header_index_with_validation(&store, HeaderRecordValidation::TestFixtures)?;
        Ok(Self { store, memory })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Iterate the complete resident header graph without cloning it. Recovery
    /// callers can validate bounded ancestry without database point reads.
    pub fn records(&self) -> impl Iterator<Item = &HeaderRecord> {
        self.memory.records()
    }

    pub fn alternate_header_count(&self) -> usize {
        self.memory.alternate_header_count()
    }

    pub const fn alternate_header_capacity(&self) -> usize {
        MAX_RESIDENT_ALTERNATE_HEADERS
    }

    pub fn import_header(&mut self, request: HeaderImport) -> Result<HeaderRecord, ChainError> {
        self.import_headers(vec![request])?
            .pop()
            .ok_or_else(|| ChainError::Codec("single-header import returned no record".to_owned()))
    }

    /// Import a validated header sequence with one durable commit. The next
    /// in-memory view is built first and is published only after every record
    /// and the final best-header binding commit atomically.
    pub fn import_headers(
        &mut self,
        requests: Vec<HeaderImport>,
    ) -> Result<Vec<HeaderRecord>, ChainError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        if requests.len() > MAX_LIVE_HEADER_IMPORT_RECORDS {
            return Err(ChainError::LiveWorkLimit {
                context: "header import records",
                limit: MAX_LIVE_HEADER_IMPORT_RECORDS,
                actual: requests.len(),
            });
        }

        // Build a compact staged view. Cloning the complete historical index
        // for every bounded network slice would make initial header sync
        // quadratic in chain height.
        let original_best = self.memory.best.clone();
        let mut next_best = original_best.clone();
        let mut direct_extension = true;
        let mut canonical_appends = Vec::with_capacity(requests.len());
        let mut staged = HashMap::<BlockHash, HeaderRecord>::with_capacity(requests.len());
        let mut records = Vec::with_capacity(requests.len());
        let mut roots = self.memory.root_count;
        for request in requests {
            let hash = request.header.hash();
            if self.memory.records.contains_key(&hash) || staged.contains_key(&hash) {
                return Err(ChainError::DuplicateHeader(hash));
            }
            if request.height == 0 {
                roots = roots
                    .checked_add(1)
                    .ok_or_else(|| ChainError::Codec("header root count overflow".to_owned()))?;
                if roots > 1 && !self.memory.validation.permits_synthetic_roots() {
                    return Err(ChainError::InvalidHeader(
                        "header import adds a second genesis root",
                    ));
                }
            }
            let parent = if request.height == 0 {
                None
            } else {
                Some(
                    staged
                        .get(&request.header.prev_block)
                        .or_else(|| self.memory.records.get(&request.header.prev_block))
                        .ok_or(ChainError::MissingParent(request.header.prev_block))?,
                )
            };
            let record = prepare_header_record(&request, parent)?;

            if !record.status.failed
                && next_best
                    .as_ref()
                    .map(|best| record.chainwork > best.chainwork)
                    .unwrap_or(true)
            {
                let extends_best = next_best.as_ref().map_or(record.height == 0, |best| {
                    record.header.prev_block == best.hash
                        && best.height.checked_add(1) == Some(record.height)
                });
                if direct_extension && extends_best {
                    canonical_appends.push((record.height, record.hash));
                } else {
                    direct_extension = false;
                    canonical_appends.clear();
                }
                next_best = Some(ChainTip {
                    hash: record.hash,
                    height: record.height,
                    chainwork: record.chainwork,
                });
            }

            staged.insert(record.hash, record.clone());
            records.push(record);
        }

        let best = next_best.ok_or(ChainError::MissingBestHeaderBinding)?;
        let best_changed = original_best.as_ref() != Some(&best);
        let canonical_delta = if best_changed && !direct_extension {
            let previous = original_best
                .as_ref()
                .ok_or(ChainError::MissingBestHeaderBinding)?;
            Some(self.memory.plan_reorg_delta_with_staged_bounded(
                &previous.hash,
                &best.hash,
                &staged,
                ReorgPlanLimits {
                    maximum_disconnect: MAX_LIVE_HEADER_CANONICAL_SWITCH,
                    maximum_connect: MAX_LIVE_HEADER_CANONICAL_SWITCH,
                },
            )?)
        } else {
            None
        };
        let projected_total = self
            .memory
            .records
            .len()
            .checked_add(records.len())
            .ok_or_else(|| ChainError::Codec("resident header count overflow".to_owned()))?;
        let projected_canonical = if let Some(delta) = canonical_delta.as_ref() {
            self.memory
                .canonical
                .len()
                .checked_sub(delta.disconnect.len())
                .and_then(|count| count.checked_add(delta.connect.len()))
                .ok_or_else(|| ChainError::Codec("canonical header count overflow".to_owned()))?
        } else if best_changed {
            self.memory
                .canonical
                .len()
                .checked_add(canonical_appends.len())
                .ok_or_else(|| ChainError::Codec("canonical header count overflow".to_owned()))?
        } else {
            self.memory.canonical.len()
        };
        bounded_alternate_header_count(
            projected_total,
            projected_canonical,
            MAX_RESIDENT_ALTERNATE_HEADERS,
        )?;

        let mut batch = self.store.batch();
        for record in &records {
            write_record_to_batch(&mut batch, record)?;
        }
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestHeaderHash.as_bytes(),
            best.hash.as_bytes(),
        )?;
        self.store.commit(batch)?;

        for record in &records {
            self.memory.records.insert(record.hash, record.clone());
            self.memory.index_new_record(record);
        }
        if best_changed {
            if let Some(canonical) = canonical_delta {
                for hash in canonical.disconnect {
                    let record = self
                        .memory
                        .records
                        .get(&hash)
                        .expect("bounded canonical disconnect was validated");
                    self.memory.canonical.remove(&record.height);
                }
                for hash in canonical.connect {
                    let record = self
                        .memory
                        .records
                        .get(&hash)
                        .expect("bounded canonical connect was validated");
                    self.memory.canonical.insert(record.height, hash);
                }
            } else {
                for (height, hash) in canonical_appends {
                    self.memory.canonical.insert(height, hash);
                }
            }
            self.memory.best = Some(best);
        }
        Ok(records)
    }

    pub fn persist_record(&self, record: &HeaderRecord) -> Result<(), ChainError> {
        self.persist_record_against(record, &self.memory)
    }

    fn persist_record_against(
        &self,
        record: &HeaderRecord,
        memory: &MemoryHeaderIndex,
    ) -> Result<(), ChainError> {
        if !memory.records.contains_key(&record.hash) {
            return Err(ChainError::MissingHeader(record.hash));
        }
        memory.ensure_alternate_header_budget()?;
        let mut batch = self.store.batch();
        write_record_to_batch(&mut batch, record)?;

        if memory
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
        let record = HeaderRecord::decode(&bytes)?;
        validate_header_record_key(hash.as_bytes(), &record)?;
        Ok(Some(record))
    }

    pub fn cache_record(&mut self, record: HeaderRecord) -> Result<(), ChainError> {
        self.memory.insert_record(record)
    }

    pub fn plan_failed_branch(&self, root: BlockHash) -> Result<FailedHeaderPlan, ChainError> {
        self.memory.failed_branch_plan(root)
    }

    pub fn validate_failed_plan(&self, plan: &FailedHeaderPlan) -> Result<(), ChainError> {
        self.memory.validate_failed_plan(plan)
    }

    /// Publish a prevalidated failure plan after its complete durable batch
    /// commits while the caller retains exclusive index access.
    pub fn apply_validated_failed_plan(&mut self, plan: &FailedHeaderPlan) {
        self.memory.apply_validated_failed_plan(plan);
    }

    pub fn prepare_cache_update(
        &self,
        records: &[HeaderRecord],
    ) -> Result<HeaderIndexCacheUpdate, ChainError> {
        self.memory.prepare_cache_update(records)
    }

    pub fn validate_cache_update(&self, update: &HeaderIndexCacheUpdate) -> Result<(), ChainError> {
        self.memory.validate_cache_update(update)
    }

    pub fn apply_validated_cache_update(&mut self, update: HeaderIndexCacheUpdate) {
        self.memory.apply_validated_cache_update(update);
    }
}

fn load_header_index<S: Store>(store: &S) -> Result<MemoryHeaderIndex, ChainError> {
    load_header_index_with_validation(store, HeaderRecordValidation::Strict)
}

fn load_header_index_with_validation<S: Store>(
    store: &S,
    validation: HeaderRecordValidation,
) -> Result<MemoryHeaderIndex, ChainError> {
    let snapshot = store.snapshot()?;
    let persisted_best = snapshot
        .get(ColumnFamily::Meta, MetaKey::BestHeaderHash.as_bytes())?
        .map(|bytes| decode_block_hash(&bytes))
        .transpose()?;
    let mut records = HashMap::new();
    let mut cursor = None;
    loop {
        let page = snapshot.scan_prefix_page(
            ColumnFamily::Headers,
            b"",
            cursor.as_deref(),
            PrefixScanBudget {
                max_entries: INDEX_LOAD_PAGE_ENTRIES,
                max_bytes: INDEX_LOAD_PAGE_BYTES,
            },
        )?;
        for (key, bytes) in page.entries {
            let record = HeaderRecord::decode(&bytes)?;
            validate_header_record_key(&key, &record)?;
            let hash = record.hash;
            if records.insert(hash, record).is_some() {
                return Err(ChainError::DuplicateHeader(hash));
            }
        }
        match page.continuation {
            Some(next) => {
                if cursor.as_ref().is_some_and(|previous| previous >= &next) {
                    return Err(ChainError::Store(
                        "header index page cursor did not advance".to_owned(),
                    ));
                }
                cursor = Some(next);
            }
            None => break,
        }
    }

    if !records.is_empty() && persisted_best.is_none() {
        return Err(ChainError::MissingBestHeaderBinding);
    }

    MemoryHeaderIndex::from_record_map_with_best_and_validation(records, persisted_best, validation)
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

    fn plan_reorg_bounded(
        &self,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
    ) -> Result<ReorgPlan, ChainError> {
        self.memory.plan_reorg_bounded(candidate, limits)
    }

    fn plan_reorg_between_bounded(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
    ) -> Result<ReorgPlan, ChainError> {
        self.memory
            .plan_reorg_between_bounded(current, candidate, limits)
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

    /// Read diagnostic status counts from the post-commit in-memory index.
    /// This avoids decoding the complete durable block-index column for every
    /// live status request.
    pub fn status_counts(&self) -> (usize, usize) {
        self.memory.status_counts()
    }

    /// Current number of decoded block-index records retained by the bounded
    /// live point-read cache.
    pub fn cache_occupancy(&self) -> usize {
        self.memory.records.len()
    }

    /// Hard live block-index cache capacity. Publication evicts one oldest
    /// entry before inserting a new hash at exact saturation.
    pub const fn cache_capacity(&self) -> usize {
        STORED_BLOCK_CACHE_RECORDS
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
        let previous = self.load_block_record(&record.hash)?;
        let cache_update = self.prepare_cache_update(&[(previous, record.clone())])?;
        let mut batch = self.store.batch();

        write_block_index_to_batch(&mut batch, &record)?;
        write_raw_block_to_batch(&mut batch, &raw_record)?;
        write_tx_index_for_block_to_batch(&mut batch, block, height)?;
        self.store.commit(batch)?;
        self.publish_cache_update(cache_update);

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
        let record = BlockIndexRecord::decode(&bytes)?;
        validate_block_index_key(hash.as_bytes(), &record)?;
        Ok(Some(record))
    }

    pub fn load_raw_block(&self, hash: &BlockHash) -> Result<Option<RawBlockRecord>, ChainError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::Blocks, hash.as_bytes())? else {
            return Ok(None);
        };
        let record = RawBlockRecord::decode(&bytes)?;
        if record.hash != *hash {
            return Err(ChainError::Codec(format!(
                "raw block key {} has embedded hash {}",
                hash.to_hex(),
                record.hash.to_hex()
            )));
        }
        Ok(Some(record))
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

    pub fn cache_record(
        &mut self,
        previous: Option<&BlockIndexRecord>,
        record: BlockIndexRecord,
    ) -> Result<(), ChainError> {
        let update = self.prepare_cache_update(&[(previous.cloned(), record)])?;
        self.publish_cache_update(update);
        Ok(())
    }

    pub fn prepare_cache_update(
        &self,
        replacements: &[(Option<BlockIndexRecord>, BlockIndexRecord)],
    ) -> Result<BlockIndexCacheUpdate, ChainError> {
        if replacements.len() > MAX_LIVE_CACHE_UPDATE_RECORDS {
            return Err(ChainError::LiveWorkLimit {
                context: "block cache update records",
                limit: MAX_LIVE_CACHE_UPDATE_RECORDS,
                actual: replacements.len(),
            });
        }
        let mut seen = HashSet::with_capacity(replacements.len());
        let mut alternate_count = self.memory.alternate_count;
        let mut failed_count = self.memory.failed_count;
        let mut records = Vec::with_capacity(replacements.len());
        for (previous, record) in replacements {
            if !seen.insert(record.hash) {
                return Err(ChainError::Codec(format!(
                    "duplicate block cache replacement {}",
                    record.hash.to_hex()
                )));
            }
            let durable = self.load_block_record(&record.hash)?;
            if durable.as_ref() != previous.as_ref() {
                return Err(ChainError::Codec(format!(
                    "block cache replacement {} was built against stale durable state",
                    record.hash.to_hex()
                )));
            }
            let (old_alternate, old_failed) = previous
                .as_ref()
                .map(MemoryBlockIndex::status_contribution)
                .unwrap_or((0, 0));
            let (new_alternate, new_failed) = MemoryBlockIndex::status_contribution(record);
            alternate_count = alternate_count
                .checked_sub(old_alternate)
                .and_then(|count| count.checked_add(new_alternate))
                .ok_or_else(|| ChainError::Codec("alternate block counter overflow".to_owned()))?;
            failed_count = failed_count
                .checked_sub(old_failed)
                .and_then(|count| count.checked_add(new_failed))
                .ok_or_else(|| ChainError::Codec("failed block counter overflow".to_owned()))?;
            records.push(record.clone());
        }
        let next_generation = self
            .memory
            .generation
            .checked_add(1)
            .ok_or_else(|| ChainError::Codec("block cache generation exhausted".to_owned()))?;
        Ok(BlockIndexCacheUpdate {
            expected_generation: self.memory.generation,
            next_generation,
            alternate_count,
            failed_count,
            records,
        })
    }

    pub fn validate_cache_update(&self, update: &BlockIndexCacheUpdate) -> Result<(), ChainError> {
        if self.memory.generation != update.expected_generation
            || update.next_generation
                != update.expected_generation.checked_add(1).ok_or_else(|| {
                    ChainError::Codec("block cache generation exhausted".to_owned())
                })?
        {
            return Err(ChainError::Codec(
                "block cache update was built against a stale generation".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn publish_cache_update(&mut self, update: BlockIndexCacheUpdate) {
        debug_assert!(self.validate_cache_update(&update).is_ok());
        for record in update.records {
            self.memory.cache_record(record);
        }
        self.memory.alternate_count = update.alternate_count;
        self.memory.failed_count = update.failed_count;
        self.memory.generation = update.next_generation;
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
        let previous = self.load_block_record(&record.hash)?;
        let cache_update = self.prepare_cache_update(&[(previous, record.clone())])?;
        let mut batch = self.store.batch();
        write_block_index_to_batch(&mut batch, &record)?;
        self.store.commit(batch)?;
        self.publish_cache_update(cache_update);
        Ok(())
    }
}

fn load_block_index<S: Store>(store: &S) -> Result<MemoryBlockIndex, ChainError> {
    let snapshot = store.snapshot()?;
    let mut index = MemoryBlockIndex::bounded(STORED_BLOCK_CACHE_RECORDS);
    let mut cursor = None;
    loop {
        let page = snapshot.scan_prefix_page(
            ColumnFamily::BlockIndex,
            b"",
            cursor.as_deref(),
            PrefixScanBudget {
                max_entries: INDEX_LOAD_PAGE_ENTRIES,
                max_bytes: INDEX_LOAD_PAGE_BYTES,
            },
        )?;
        for (key, bytes) in page.entries {
            let record = BlockIndexRecord::decode(&bytes)?;
            validate_block_index_key(&key, &record)?;
            index.observe_loaded_record(record)?;
        }
        match page.continuation {
            Some(next) => {
                if cursor.as_ref().is_some_and(|previous| previous >= &next) {
                    return Err(ChainError::Store(
                        "block index page cursor did not advance".to_owned(),
                    ));
                }
                cursor = Some(next);
            }
            None => break,
        }
    }
    Ok(index)
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
        self.plan_reorg_bounded(candidate, ReorgPlanLimits::UNBOUNDED)
    }

    fn plan_reorg_bounded(
        &self,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
    ) -> Result<ReorgPlan, ChainError> {
        let Some(best) = &self.best else {
            let mut connect = Vec::new();
            let mut current = *candidate;
            loop {
                push_reorg_hash(&mut connect, current, limits.maximum_connect, "connect")?;
                let record = self
                    .records
                    .get(&current)
                    .ok_or(ChainError::MissingHeader(current))?;
                if record.height == 0 {
                    break;
                }
                current = record.header.prev_block;
            }
            connect.reverse();
            return Ok(ReorgPlan {
                disconnect: Vec::new(),
                connect,
            });
        };

        self.plan_reorg_between_bounded(&best.hash, candidate, limits)
    }

    fn plan_reorg_between(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
    ) -> Result<ReorgPlan, ChainError> {
        self.plan_reorg_between_bounded(current, candidate, ReorgPlanLimits::UNBOUNDED)
    }

    fn plan_reorg_between_bounded(
        &self,
        current: &BlockHash,
        candidate: &BlockHash,
        limits: ReorgPlanLimits,
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
            push_reorg_hash(
                &mut disconnect,
                old.hash,
                limits.maximum_disconnect,
                "disconnect",
            )?;
            old = self
                .records
                .get(&old.header.prev_block)
                .cloned()
                .ok_or(ChainError::MissingHeader(old.header.prev_block))?;
        }

        while new.height > old.height {
            push_reorg_hash(
                &mut connect_reverse,
                new.hash,
                limits.maximum_connect,
                "connect",
            )?;
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
            push_reorg_hash(
                &mut disconnect,
                old.hash,
                limits.maximum_disconnect,
                "disconnect",
            )?;
            push_reorg_hash(
                &mut connect_reverse,
                new.hash,
                limits.maximum_connect,
                "connect",
            )?;
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

fn push_reorg_hash(
    path: &mut Vec<BlockHash>,
    hash: BlockHash,
    limit: usize,
    phase: &'static str,
) -> Result<(), ChainError> {
    let actual = path
        .len()
        .checked_add(1)
        .ok_or(ChainError::ReorgPlanLimit {
            phase,
            limit,
            actual: usize::MAX,
        })?;
    if actual > limit {
        return Err(ChainError::ReorgPlanLimit {
            phase,
            limit,
            actual,
        });
    }
    path.push(hash);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("chain store failed: {0}")]
    Store(String),
    #[error("chain codec failed: {0}")]
    Codec(String),
    #[error("missing parent header {0:?}")]
    MissingParent(BlockHash),
    #[error("header {0:?} is already indexed or duplicated in its import batch")]
    DuplicateHeader(BlockHash),
    #[error("missing header {0:?}")]
    MissingHeader(BlockHash),
    #[error("stored headers exist without a persisted best-header binding")]
    MissingBestHeaderBinding,
    #[error("persisted best header {0:?} is inconsistent with stored chainwork")]
    InconsistentBestHeader(BlockHash),
    #[error("genesis header {0:?} cannot be marked failed")]
    FailedGenesis(BlockHash),
    #[error("persisted best header {0:?} is marked failed")]
    FailedBestHeader(BlockHash),
    #[error("header {0:?} is not marked failed despite a failed ancestor")]
    InconsistentFailureAncestry(BlockHash),
    #[error("cannot mark active header branch {0:?} failed")]
    FailedActiveHeader(BlockHash),
    #[error("chains {current:?} and {candidate:?} do not share a stored ancestor")]
    NoCommonAncestor {
        current: BlockHash,
        candidate: BlockHash,
    },
    #[error(
        "reorganization {phase} path contains at least {actual} headers, exceeding limit {limit}"
    )]
    ReorgPlanLimit {
        phase: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("{context} requires at least {actual} records, exceeding live limit {limit}")]
    LiveWorkLimit {
        context: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("{context} exceeded its live execution deadline")]
    LiveWorkDeadline { context: &'static str },
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
}

impl ChainError {
    pub const fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::ReorgPlanLimit { .. }
                | Self::LiveWorkLimit { .. }
                | Self::LiveWorkDeadline { .. }
        )
    }
}

impl From<StoreError> for ChainError {
    fn from(value: StoreError) -> Self {
        Self::Store(value.to_string())
    }
}

fn validate_header_record_identity(record: &HeaderRecord) -> Result<(), ChainError> {
    let computed = record.header.hash();
    if computed != record.hash {
        return Err(ChainError::Codec(format!(
            "header record hash {} disagrees with its header hash {}",
            record.hash.to_hex(),
            computed.to_hex()
        )));
    }
    Ok(())
}

fn validate_header_record_structure(
    record: &HeaderRecord,
    parent: Option<&HeaderRecord>,
    validation: HeaderRecordValidation,
) -> Result<(), ChainError> {
    if record.height == 0 {
        if parent.is_some() {
            return Err(ChainError::InvalidHeader(
                "genesis header unexpectedly has a parent",
            ));
        }
        if record.header.prev_block != BlockHash::ZERO {
            return Err(ChainError::InvalidHeader(
                "genesis header has a non-zero parent",
            ));
        }
        if record.status.failed {
            return Err(ChainError::FailedGenesis(record.hash));
        }
    } else {
        let parent = parent.ok_or(ChainError::MissingParent(record.header.prev_block))?;
        if parent.hash != record.header.prev_block
            || parent.height.checked_add(1) != Some(record.height)
        {
            return Err(ChainError::InvalidHeader(
                "header height is not contiguous with parent",
            ));
        }
    }

    if !validation.permits_synthetic_roots() {
        let proof = CompactTarget::from_bits(record.header.bits)
            .proof()
            .ok_or(ChainError::InvalidHeader("invalid proof-of-work target"))?;
        let expected = parent
            .map(|parent| parent.chainwork)
            .unwrap_or(Uint256::ZERO)
            .checked_add(proof)
            .ok_or_else(|| ChainError::Codec("header chainwork overflow".to_owned()))?;
        if record.chainwork != expected {
            return Err(ChainError::InvalidHeader(
                "header chainwork is not proof-derived",
            ));
        }
    }

    Ok(())
}

fn validate_header_record_key(key: &[u8], record: &HeaderRecord) -> Result<(), ChainError> {
    if key != record.hash.as_bytes() {
        return Err(ChainError::Codec(format!(
            "header index key disagrees with decoded hash {}",
            record.hash.to_hex()
        )));
    }
    validate_header_record_identity(record)
}

fn validate_block_index_key(key: &[u8], record: &BlockIndexRecord) -> Result<(), ChainError> {
    if key != record.hash.as_bytes() {
        return Err(ChainError::Codec(format!(
            "block index key disagrees with decoded hash {}",
            record.hash.to_hex()
        )));
    }
    Ok(())
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
    use hns_store::{
        MemoryBatch, MemorySnapshot, MemoryStore, PrefixScanPage, ReadSnapshot, Store,
    };

    #[derive(Debug, Default)]
    struct PagingMetrics {
        full_scans: std::sync::atomic::AtomicUsize,
        pages: std::sync::atomic::AtomicUsize,
        maximum_entries: std::sync::atomic::AtomicUsize,
        maximum_bytes: std::sync::atomic::AtomicUsize,
    }

    #[derive(Clone, Debug)]
    struct PagedStore {
        inner: MemoryStore,
        metrics: std::sync::Arc<PagingMetrics>,
    }

    #[derive(Debug)]
    struct PagedSnapshot {
        inner: MemorySnapshot,
        metrics: std::sync::Arc<PagingMetrics>,
    }

    impl PagedStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                metrics: std::sync::Arc::new(PagingMetrics::default()),
            }
        }

        fn reset_metrics(&self) {
            self.metrics
                .full_scans
                .store(0, std::sync::atomic::Ordering::SeqCst);
            self.metrics
                .pages
                .store(0, std::sync::atomic::Ordering::SeqCst);
            self.metrics
                .maximum_entries
                .store(0, std::sync::atomic::Ordering::SeqCst);
            self.metrics
                .maximum_bytes
                .store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl ReadSnapshot for PagedSnapshot {
        fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
            self.inner.get(family, key)
        }

        fn scan_prefix(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
        ) -> Result<Vec<hns_store::ScanEntry>, StoreError> {
            self.metrics
                .full_scans
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.scan_prefix(family, prefix)
        }

        fn scan_prefix_page(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
            start_after: Option<&[u8]>,
            budget: PrefixScanBudget,
        ) -> Result<PrefixScanPage, StoreError> {
            let page = self
                .inner
                .scan_prefix_page(family, prefix, start_after, budget)?;
            self.metrics
                .pages
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.metrics
                .maximum_entries
                .fetch_max(page.entries.len(), std::sync::atomic::Ordering::SeqCst);
            self.metrics
                .maximum_bytes
                .fetch_max(page.returned_bytes, std::sync::atomic::Ordering::SeqCst);
            Ok(page)
        }
    }

    impl Store for PagedStore {
        type Snapshot<'a> = PagedSnapshot;
        type Batch = MemoryBatch;

        fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
            Ok(PagedSnapshot {
                inner: self.inner.snapshot()?,
                metrics: std::sync::Arc::clone(&self.metrics),
            })
        }

        fn batch(&self) -> Self::Batch {
            self.inner.batch()
        }

        fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
            self.inner.commit(batch)
        }
    }

    #[derive(Clone)]
    struct InstrumentedStore {
        inner: MemoryStore,
        commits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fail_next_commit: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl InstrumentedStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                commits: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                fail_next_commit: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        fn commit_count(&self) -> usize {
            self.commits.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn fail_next_commit(&self) {
            self.fail_next_commit
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Store for InstrumentedStore {
        type Snapshot<'a> = MemorySnapshot;
        type Batch = MemoryBatch;

        fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
            self.inner.snapshot()
        }

        fn batch(&self) -> Self::Batch {
            self.inner.batch()
        }

        fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
            if self
                .fail_next_commit
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(StoreError::Io("injected commit failure".to_owned()));
            }
            self.inner.commit(batch)?;
            self.commits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    fn header(prev_block: BlockHash, nonce: u32) -> Header {
        Header {
            prev_block,
            nonce,
            bits: 0x207f_ffff,
            ..Header::default()
        }
    }

    fn header_record(
        prev_block: BlockHash,
        nonce: u32,
        height: Height,
        chainwork: u64,
    ) -> HeaderRecord {
        let header = header(prev_block, nonce);
        HeaderRecord {
            hash: header.hash(),
            height,
            chainwork: chainwork.into(),
            header,
            status: BlockStatus {
                header_context_valid: true,
                ..BlockStatus::default()
            },
        }
    }

    fn indexed_hash(seed: u32) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        bytes[4..8].copy_from_slice(&seed.rotate_left(13).to_be_bytes());
        BlockHash::new(bytes)
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
    fn alternate_header_budget_accepts_exact_and_rejects_one_over() {
        assert_eq!(
            bounded_alternate_header_count(
                MAX_RESIDENT_ALTERNATE_HEADERS + 17,
                17,
                MAX_RESIDENT_ALTERNATE_HEADERS,
            )
            .expect("exact alternate-header budget"),
            MAX_RESIDENT_ALTERNATE_HEADERS
        );
        assert!(matches!(
            bounded_alternate_header_count(
                MAX_RESIDENT_ALTERNATE_HEADERS + 18,
                17,
                MAX_RESIDENT_ALTERNATE_HEADERS,
            ),
            Err(ChainError::LiveWorkLimit {
                context: "resident alternate headers",
                limit: MAX_RESIDENT_ALTERNATE_HEADERS,
                actual,
            }) if actual == MAX_RESIDENT_ALTERNATE_HEADERS + 1
        ));
        assert!(matches!(
            bounded_alternate_header_count(16, 17, MAX_RESIDENT_ALTERNATE_HEADERS),
            Err(ChainError::Codec(_))
        ));
    }

    #[test]
    fn startup_reconstruction_enforces_alternate_header_budget() {
        let genesis = header_record(BlockHash::ZERO, 70_000, 0, 1);
        let best = header_record(genesis.hash, 70_001, 1, 4);
        let alternate_a = header_record(genesis.hash, 70_002, 1, 2);
        let alternate_b = header_record(genesis.hash, 70_003, 1, 3);
        let records = [genesis, best.clone(), alternate_a, alternate_b]
            .into_iter()
            .map(|record| (record.hash, record))
            .collect::<HashMap<_, _>>();

        let exact = MemoryHeaderIndex::from_record_map_with_best_validation_and_alternate_limit(
            records.clone(),
            Some(best.hash),
            HeaderRecordValidation::TestFixtures,
            2,
        )
        .expect("two alternate headers fit an exact startup budget");
        assert_eq!(exact.alternate_header_count(), 2);

        assert!(matches!(
            MemoryHeaderIndex::from_record_map_with_best_validation_and_alternate_limit(
                records,
                Some(best.hash),
                HeaderRecordValidation::TestFixtures,
                1,
            ),
            Err(ChainError::LiveWorkLimit {
                context: "resident alternate headers",
                limit: 1,
                actual: 2,
            })
        ));
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
        assert_eq!(
            index.best_tip().expect("tip").expect("best").hash,
            first.hash
        );
        assert_eq!(
            index.canonical_hash(1).expect("canonical"),
            Some(first.hash)
        );
    }

    #[test]
    fn failed_header_branch_falls_back_and_taints_descendants() {
        let mut index = MemoryHeaderIndex::new();
        let genesis = index
            .insert_header(header(BlockHash::ZERO, 1), 0)
            .expect("genesis");
        let failed_root = index
            .insert_header(header(genesis.hash, 2), 1)
            .expect("failed root");
        let failed_tip = index
            .insert_header(header(failed_root.hash, 3), 2)
            .expect("failed tip");
        let fallback = index
            .insert_header(header(genesis.hash, 4), 1)
            .expect("fallback");
        assert_eq!(
            index.best_tip().expect("best").expect("tip").hash,
            failed_tip.hash
        );

        let affected = index.fail_branch(failed_root.hash).expect("fail branch");
        assert_eq!(
            affected
                .iter()
                .map(|record| record.hash)
                .collect::<HashSet<_>>(),
            HashSet::from([failed_root.hash, failed_tip.hash])
        );
        assert!(affected.iter().all(|record| record.status.failed));
        assert_eq!(
            index.best_tip().expect("best").expect("fallback tip").hash,
            fallback.hash
        );
        assert_eq!(
            index.canonical_hash(1).expect("canonical"),
            Some(fallback.hash)
        );
        assert_eq!(index.canonical_hash(2).expect("canonical"), None);

        let failed_child = index
            .insert_header(header(failed_tip.hash, 5), 3)
            .expect("failed descendant");
        assert!(failed_child.status.failed);
        assert_eq!(
            index.best_tip().expect("best").expect("fallback tip").hash,
            fallback.hash
        );
    }

    #[test]
    fn failed_header_plan_scales_with_descendants_and_preserves_unrelated_branches() {
        const AFFECTED: u32 = 1_024;
        const UNRELATED: u32 = 5_000;
        const FALLBACK: u32 = 64;

        let mut index = MemoryHeaderIndex::new_for_test_fixtures();
        let genesis = header_record(BlockHash::ZERO, 100_000, 0, 1);
        index.insert_record(genesis.clone()).expect("genesis");

        let mut fallback_parent = genesis.hash;
        let mut fallback_hashes = Vec::with_capacity(FALLBACK as usize);
        for height in 1..=FALLBACK {
            let record = header_record(
                fallback_parent,
                110_000 + height,
                height,
                u64::from(height) + 1,
            );
            fallback_parent = record.hash;
            fallback_hashes.push(record.hash);
            index.insert_record(record).expect("fallback branch");
        }

        let mut affected_parent = genesis.hash;
        let mut affected_hashes = Vec::with_capacity(AFFECTED as usize);
        for height in 1..=AFFECTED {
            let record = header_record(
                affected_parent,
                120_000 + height,
                height,
                100 + u64::from(height),
            );
            affected_parent = record.hash;
            affected_hashes.push(record.hash);
            index.insert_record(record).expect("affected branch");
        }

        let mut unrelated_hashes = Vec::with_capacity(UNRELATED as usize);
        for offset in 0..UNRELATED {
            let record = header_record(genesis.hash, 200_000 + offset, 1, 2);
            unrelated_hashes.push(record.hash);
            index.insert_record(record).expect("unrelated sibling");
        }

        let plan = index
            .failed_branch_plan(affected_hashes[0])
            .expect("failure plan");
        assert_eq!(plan.affected.len(), AFFECTED as usize);
        assert_eq!(
            plan.affected
                .iter()
                .map(|record| record.hash)
                .collect::<Vec<_>>(),
            affected_hashes,
            "breadth-first descendant order is already publication-ready"
        );
        assert_eq!(
            plan.canonical.disconnect,
            affected_hashes.iter().rev().copied().collect::<Vec<_>>()
        );
        assert_eq!(plan.canonical.connect, fallback_hashes);
        assert_eq!(plan.best.hash, fallback_parent);

        index
            .validate_failed_plan(&plan)
            .expect("validated failure plan");
        index.apply_validated_failed_plan(&plan);

        assert_eq!(
            index.best_tip().expect("best").expect("fallback").hash,
            fallback_parent
        );
        assert!(plan.affected.iter().all(|planned| {
            index
                .header(&planned.hash)
                .expect("affected header")
                .is_some_and(|record| record.status.failed)
        }));
        assert!(unrelated_hashes.iter().all(|hash| {
            index
                .header(hash)
                .expect("unrelated header")
                .is_some_and(|record| !record.status.failed)
        }));
    }

    #[test]
    fn failed_header_plan_accepts_exact_count_and_rejects_one_over_or_expired() {
        let mut index = MemoryHeaderIndex::new_for_test_fixtures();
        let genesis = header_record(BlockHash::ZERO, 410_000, 0, 1);
        index.insert_record(genesis.clone()).expect("genesis");
        index
            .insert_record(header_record(genesis.hash, 410_001, 1, 100))
            .expect("dominant fallback");

        let root = header_record(genesis.hash, 420_001, 1, 2);
        let child = header_record(root.hash, 420_002, 2, 3);
        let tip = header_record(child.hash, 420_003, 3, 4);
        for record in [root.clone(), child, tip] {
            index.insert_record(record).expect("affected branch");
        }

        let now = Instant::now();
        let exact = index
            .failed_branch_plan_bounded(
                root.hash,
                3,
                now.checked_add(Duration::from_secs(30)).unwrap_or(now),
            )
            .expect("exact failed-branch budget");
        assert_eq!(exact.affected.len(), 3);

        assert!(matches!(
            index.failed_branch_plan_bounded(
                root.hash,
                2,
                now.checked_add(Duration::from_secs(30)).unwrap_or(now),
            ),
            Err(ChainError::LiveWorkLimit {
                context: "failed header descendants",
                limit: 2,
                actual: 3,
            })
        ));
        assert!(matches!(
            index.failed_branch_plan_bounded(root.hash, 3, Instant::now()),
            Err(ChainError::LiveWorkDeadline {
                context: "failed header descendants",
            })
        ));
    }

    #[test]
    fn header_index_rejects_nontransitive_failure_state() {
        let genesis_header = header(BlockHash::ZERO, 1);
        let proof = CompactTarget::from_bits(genesis_header.bits)
            .proof()
            .expect("fixture target proof");
        let genesis = HeaderRecord {
            hash: genesis_header.hash(),
            height: 0,
            chainwork: proof,
            header: genesis_header,
            status: BlockStatus::default(),
        };
        let parent_header = header(genesis.hash, 2);
        let parent = HeaderRecord {
            hash: parent_header.hash(),
            height: 1,
            chainwork: proof.checked_add(proof).expect("parent work"),
            header: parent_header,
            status: BlockStatus {
                failed: true,
                ..BlockStatus::default()
            },
        };
        let child_header = header(parent.hash, 3);
        let child = HeaderRecord {
            hash: child_header.hash(),
            height: 2,
            chainwork: proof
                .checked_add(proof)
                .and_then(|work| work.checked_add(proof))
                .expect("child work"),
            header: child_header,
            status: BlockStatus::default(),
        };

        assert!(matches!(
            MemoryHeaderIndex::from_records([genesis, parent, child]),
            Err(ChainError::InconsistentFailureAncestry(_))
        ));
    }

    #[test]
    fn strict_header_records_require_unique_root_contiguous_height_and_exact_work() {
        let genesis_header = header(BlockHash::ZERO, 41);
        let genesis = prepare_header_record(
            &HeaderImport {
                header: genesis_header,
                height: 0,
                verify_pow: false,
                checkpoint_valid: true,
            },
            None,
        )
        .expect("genesis record");
        let child_header = header(genesis.hash, 42);
        let child = prepare_header_record(
            &HeaderImport {
                header: child_header,
                height: 1,
                verify_pow: false,
                checkpoint_valid: true,
            },
            Some(&genesis),
        )
        .expect("child record");

        let mut bad_height = child.clone();
        bad_height.height = 2;
        assert!(matches!(
            MemoryHeaderIndex::from_records([genesis.clone(), bad_height]),
            Err(ChainError::InvalidHeader(_))
        ));

        let mut bad_work = child.clone();
        bad_work.chainwork = bad_work
            .chainwork
            .checked_add(Uint256::ONE)
            .expect("forged work");
        assert!(matches!(
            MemoryHeaderIndex::from_records([genesis.clone(), bad_work]),
            Err(ChainError::InvalidHeader(_))
        ));

        let second_header = header(BlockHash::ZERO, 43);
        let second = prepare_header_record(
            &HeaderImport {
                header: second_header,
                height: 0,
                verify_pow: false,
                checkpoint_valid: true,
            },
            None,
        )
        .expect("second root record");
        assert!(matches!(
            MemoryHeaderIndex::from_records([genesis, second]),
            Err(ChainError::InvalidHeader(
                "header index has multiple genesis roots"
            ))
        ));
    }

    #[test]
    fn failed_best_replacement_leaves_viable_index_unchanged() {
        let mut index = MemoryHeaderIndex::new();
        let genesis = index
            .insert_header(header(BlockHash::ZERO, 44), 0)
            .expect("genesis");
        let best = index
            .insert_header(header(genesis.hash, 45), 1)
            .expect("best");
        let viable = MemoryHeaderIndex::viable_key(&best);
        let mut failed = best.clone();
        failed.status.failed = true;

        assert!(matches!(
            index.insert_record(failed),
            Err(ChainError::FailedBestHeader(hash)) if hash == best.hash
        ));
        assert!(index.viable.contains(&viable));
        assert_eq!(
            index.best_tip().expect("best").expect("tip").hash,
            best.hash
        );
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
    fn bounded_reorg_planner_accepts_exact_paths_and_rejects_one_over() {
        let mut index = MemoryHeaderIndex::new();
        let genesis = index
            .insert_header(header(BlockHash::ZERO, 70), 0)
            .expect("genesis");
        let old_one = index
            .insert_header(header(genesis.hash, 71), 1)
            .expect("old one");
        let old_two = index
            .insert_header(header(old_one.hash, 72), 2)
            .expect("old two");
        let side_one = index
            .insert_header(header(genesis.hash, 73), 1)
            .expect("side one");
        let side_two = index
            .insert_header(header(side_one.hash, 74), 2)
            .expect("side two");

        let exact = index
            .plan_reorg_between_bounded(
                &old_two.hash,
                &side_two.hash,
                ReorgPlanLimits {
                    maximum_disconnect: 2,
                    maximum_connect: 2,
                },
            )
            .expect("exact bounded plan");
        assert_eq!(exact.disconnect, vec![old_two.hash, old_one.hash]);
        assert_eq!(exact.connect, vec![side_one.hash, side_two.hash]);

        assert!(matches!(
            index.plan_reorg_between_bounded(
                &old_two.hash,
                &side_two.hash,
                ReorgPlanLimits {
                    maximum_disconnect: 1,
                    maximum_connect: 2,
                },
            ),
            Err(ChainError::ReorgPlanLimit {
                phase: "disconnect",
                limit: 1,
                actual: 2,
            })
        ));
        assert!(matches!(
            index.plan_reorg_between_bounded(
                &old_two.hash,
                &side_two.hash,
                ReorgPlanLimits {
                    maximum_disconnect: 2,
                    maximum_connect: 1,
                },
            ),
            Err(ChainError::ReorgPlanLimit {
                phase: "connect",
                limit: 1,
                actual: 2,
            })
        ));
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
    fn memory_block_index_status_counts_exclude_active_and_failed_overlap() {
        let mut active = BlockIndexRecord::from_block(
            &Block {
                header: header(BlockHash::ZERO, 21),
                transactions: Vec::new(),
            },
            0,
            Uint256::ONE,
        )
        .expect("active");
        active.status.active_chain = true;

        let alternate = BlockIndexRecord::from_block(
            &Block {
                header: header(active.hash, 22),
                transactions: Vec::new(),
            },
            1,
            Uint256::from(2u64),
        )
        .expect("alternate");

        let mut failed = BlockIndexRecord::from_block(
            &Block {
                header: header(active.hash, 23),
                transactions: Vec::new(),
            },
            1,
            Uint256::from(3u64),
        )
        .expect("failed");
        failed.status.failed = true;

        let index = MemoryBlockIndex::from_records([active, alternate, failed]);
        assert_eq!(index.status_counts(), (1, 1));
    }

    #[test]
    fn memory_block_index_status_counts_track_replacement_transitions() {
        let block = Block {
            header: header(BlockHash::ZERO, 24),
            transactions: Vec::new(),
        };
        let alternate =
            BlockIndexRecord::from_block(&block, 0, Uint256::ONE).expect("alternate record");
        let mut index = MemoryBlockIndex::new();

        index
            .insert_block_record(alternate.clone())
            .expect("insert alternate");
        assert_eq!(index.status_counts(), (1, 0));

        let mut active = alternate.clone();
        active.status.active_chain = true;
        index
            .insert_block_record(active.clone())
            .expect("replace with active");
        assert_eq!(index.status_counts(), (0, 0));

        let mut failed = active;
        failed.status.failed = true;
        index
            .insert_block_record(failed.clone())
            .expect("replace with failed");
        assert_eq!(
            index.status_counts(),
            (0, 1),
            "failed status takes precedence over active-chain overlap"
        );

        index
            .insert_block_record(failed)
            .expect("idempotent failed replacement");
        assert_eq!(index.status_counts(), (0, 1));

        index
            .insert_block_record(alternate)
            .expect("replace failed with alternate");
        assert_eq!(index.status_counts(), (1, 0));
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
                checkpoint_valid: false,
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
    fn stored_header_index_loads_directly_from_bounded_pages() {
        const RECORDS: u32 = 5_000;

        let store = PagedStore::new();
        hns_store::initialize_schema(&store).expect("initialize schema");
        let mut batch = store.batch();
        let mut parent = BlockHash::ZERO;
        let mut best = BlockHash::ZERO;
        let mut chainwork = Uint256::ZERO;
        for height in 0..RECORDS {
            let mut record = header_record(parent, 300_000 + height, height, 0);
            let proof = CompactTarget::from_bits(record.header.bits)
                .proof()
                .expect("fixture target proof");
            chainwork = chainwork.checked_add(proof).expect("header chainwork");
            record.chainwork = chainwork;
            write_record_to_batch(&mut batch, &record).expect("stage header");
            parent = record.hash;
            best = record.hash;
        }
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                best.as_bytes(),
            )
            .expect("stage best header");
        store.commit(batch).expect("populate header index");
        store.reset_metrics();

        let index = StoredHeaderIndex::new(store.clone()).expect("paged header index");
        assert_eq!(index.memory.records.len(), RECORDS as usize);
        assert_eq!(index.best_tip().expect("best").expect("tip").hash, best);
        assert_eq!(
            store
                .metrics
                .full_scans
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "startup must not call the unbounded scan interface"
        );
        assert!(
            store
                .metrics
                .pages
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 2
        );
        assert!(
            store
                .metrics
                .maximum_entries
                .load(std::sync::atomic::Ordering::SeqCst)
                <= INDEX_LOAD_PAGE_ENTRIES
        );
        assert!(
            store
                .metrics
                .maximum_bytes
                .load(std::sync::atomic::Ordering::SeqCst)
                <= INDEX_LOAD_PAGE_BYTES
        );
    }

    #[test]
    fn stored_header_index_rejects_key_and_embedded_header_hash_mismatches() {
        let point_store = MemoryStore::new();
        let index = StoredHeaderIndex::new(point_store.clone()).expect("empty header index");
        let record = header_record(BlockHash::ZERO, 400_001, 0, 1);
        let wrong_key = indexed_hash(400_002);
        let mut batch = point_store.batch();
        batch
            .put(
                ColumnFamily::Headers,
                wrong_key.as_bytes(),
                &record.encode(),
            )
            .expect("stage mismatched key");
        point_store.commit(batch).expect("commit mismatched key");
        assert!(matches!(
            index.load_record(&wrong_key),
            Err(ChainError::Codec(_))
        ));

        let startup_store = MemoryStore::new();
        hns_store::initialize_schema(&startup_store).expect("initialize startup schema");
        let mut corrupt = header_record(BlockHash::ZERO, 400_003, 0, 1);
        corrupt.hash = indexed_hash(400_004);
        let mut batch = startup_store.batch();
        batch
            .put(
                ColumnFamily::Headers,
                corrupt.hash.as_bytes(),
                &corrupt.encode(),
            )
            .expect("stage corrupt record");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                corrupt.hash.as_bytes(),
            )
            .expect("stage corrupt best");
        startup_store
            .commit(batch)
            .expect("commit corrupt header record");
        assert!(matches!(
            StoredHeaderIndex::new(startup_store),
            Err(ChainError::Codec(_))
        ));
    }

    #[cfg(feature = "test-fixtures")]
    #[test]
    fn explicit_fixture_loader_does_not_weaken_strict_constructor() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("initialize schema");
        let fixture = header_record(BlockHash::ZERO, 410_001, 0, 1);
        let mut batch = store.batch();
        write_record_to_batch(&mut batch, &fixture).expect("stage synthetic root");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestHeaderHash.as_bytes(),
                fixture.hash.as_bytes(),
            )
            .expect("stage fixture best");
        store.commit(batch).expect("commit fixture chain");

        assert!(matches!(
            StoredHeaderIndex::new(store.clone()),
            Err(ChainError::InvalidHeader(
                "header chainwork is not proof-derived"
            ))
        ));
        assert_eq!(
            StoredHeaderIndex::new_for_test_fixtures(store)
                .expect("explicit fixture loader")
                .best_tip()
                .expect("best")
                .expect("tip")
                .hash,
            fixture.hash
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
                checkpoint_valid: false,
            })
            .expect_err("bad pow");

        assert!(matches!(
            error,
            ChainError::InvalidHeader("proof of work failed")
        ));
    }

    #[test]
    fn stored_header_index_commits_a_header_batch_once() {
        let store = InstrumentedStore::new();
        let mut index = StoredHeaderIndex::new(store.clone()).expect("index");
        let commits_before = store.commit_count();
        let genesis_header = header(BlockHash::ZERO, 21);
        let first_header = header(genesis_header.hash(), 22);
        let second_header = header(first_header.hash(), 23);

        let records = index
            .import_headers(vec![
                HeaderImport {
                    header: genesis_header,
                    height: 0,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
                HeaderImport {
                    header: first_header,
                    height: 1,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
                HeaderImport {
                    header: second_header,
                    height: 2,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
            ])
            .expect("batch import");

        assert_eq!(store.commit_count(), commits_before + 1);
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|record| record.status.checkpoint_valid));
        assert_eq!(
            index.best_tip().expect("tip").expect("best").hash,
            records[2].hash
        );
        assert_eq!(
            StoredHeaderIndex::new(store)
                .expect("reload")
                .canonical_hash(2)
                .expect("canonical"),
            Some(records[2].hash)
        );
    }

    #[test]
    fn invalid_header_batch_leaves_no_partial_import() {
        let store = InstrumentedStore::new();
        let mut index = StoredHeaderIndex::new(store.clone()).expect("index");
        let commits_before = store.commit_count();
        let genesis_header = header(BlockHash::ZERO, 24);
        let first_header = header(genesis_header.hash(), 25);
        let first_hash = first_header.hash();
        let invalid_second = header(first_hash, 26);

        let error = index
            .import_headers(vec![
                HeaderImport {
                    header: genesis_header,
                    height: 0,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
                HeaderImport {
                    header: first_header,
                    height: 1,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
                HeaderImport {
                    header: invalid_second,
                    height: 3,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
            ])
            .expect_err("non-contiguous header");

        assert!(matches!(error, ChainError::InvalidHeader(_)));
        assert_eq!(store.commit_count(), commits_before);
        assert_eq!(index.best_tip().expect("tip"), None);
        assert_eq!(index.load_record(&first_hash).expect("record"), None);
    }

    #[test]
    fn failed_header_batch_commit_preserves_durable_and_live_tip() {
        let store = InstrumentedStore::new();
        let mut index = StoredHeaderIndex::new(store.clone()).expect("index");
        let genesis = index
            .import_header(HeaderImport {
                header: header(BlockHash::ZERO, 27),
                height: 0,
                verify_pow: false,
                checkpoint_valid: true,
            })
            .expect("genesis");
        let first_header = header(genesis.hash, 28);
        let first_hash = first_header.hash();
        let second_header = header(first_hash, 29);
        let second_hash = second_header.hash();

        store.fail_next_commit();
        index
            .import_headers(vec![
                HeaderImport {
                    header: first_header,
                    height: 1,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
                HeaderImport {
                    header: second_header,
                    height: 2,
                    verify_pow: false,
                    checkpoint_valid: true,
                },
            ])
            .expect_err("injected commit failure");

        assert_eq!(
            index.best_tip().expect("live tip").expect("best").hash,
            genesis.hash
        );
        assert_eq!(index.load_record(&first_hash).expect("first"), None);
        assert_eq!(index.load_record(&second_hash).expect("second"), None);
        assert_eq!(
            StoredHeaderIndex::new(store)
                .expect("reload")
                .best_tip()
                .expect("durable tip")
                .expect("best")
                .hash,
            genesis.hash
        );
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
    fn stored_block_index_uses_bounded_cache_exact_counts_and_durable_misses() {
        const RECORDS: u32 = 5_000;

        let store = PagedStore::new();
        hns_store::initialize_schema(&store).expect("initialize schema");
        let mut batch = store.batch();
        let mut records = Vec::with_capacity(RECORDS as usize);
        let mut expected_alternates = 0usize;
        let mut expected_failed = 0usize;
        for seed in 0..RECORDS {
            let mut record = BlockIndexRecord {
                hash: indexed_hash(500_000 + seed),
                height: seed,
                prev_hash: indexed_hash(499_999 + seed),
                chainwork: Uint256::from(u64::from(seed) + 1),
                status: BlockStatus::default(),
                tx_count: 0,
                validated_at: None,
            };
            match seed % 3 {
                0 => record.status.active_chain = true,
                1 => {
                    record.status.failed = true;
                    expected_failed += 1;
                }
                _ => expected_alternates += 1,
            }
            write_block_index_to_batch(&mut batch, &record).expect("stage block index");
            records.push(record);
        }
        store.commit(batch).expect("populate block index");
        store.reset_metrics();

        let mut index = StoredBlockIndex::new(store.clone()).expect("paged block index");
        assert_eq!(
            index.cache_occupancy(),
            STORED_BLOCK_CACHE_RECORDS,
            "the live block index is a fixed-size point-read cache"
        );
        assert_eq!(index.cache_capacity(), STORED_BLOCK_CACHE_RECORDS);
        assert_eq!(
            index.status_counts(),
            (expected_alternates, expected_failed),
            "diagnostic counts cover the complete durable index, not only cached records"
        );
        assert_eq!(
            store
                .metrics
                .full_scans
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "startup must not call the unbounded scan interface"
        );
        assert!(
            store
                .metrics
                .maximum_entries
                .load(std::sync::atomic::Ordering::SeqCst)
                <= INDEX_LOAD_PAGE_ENTRIES
        );
        assert!(
            store
                .metrics
                .maximum_bytes
                .load(std::sync::atomic::Ordering::SeqCst)
                <= INDEX_LOAD_PAGE_BYTES
        );

        let previous = records
            .iter()
            .find(|record| {
                !record.status.failed
                    && !record.status.active_chain
                    && !index.memory.records.contains_key(&record.hash)
            })
            .cloned()
            .expect("an alternate record was evicted");
        assert_eq!(
            index.block(&previous.hash).expect("durable cache miss"),
            Some(previous.clone())
        );

        let mut active = previous.clone();
        active.status.active_chain = true;
        let update = index
            .prepare_cache_update(&[(Some(previous), active.clone())])
            .expect("prepare exact counter transition");
        reset_block_index_record_clone_count();
        index.publish_cache_update(update);
        assert_eq!(
            block_index_record_clone_count(),
            0,
            "O(changes) publication must move its prepared delta without cloning cache history"
        );
        assert_eq!(
            index.cache_occupancy(),
            STORED_BLOCK_CACHE_RECORDS,
            "a new hash at exact saturation evicts instead of growing to 4,097"
        );
        assert_eq!(
            index.status_counts(),
            (expected_alternates - 1, expected_failed)
        );
        assert_eq!(
            index.block(&active.hash).expect("published cache record"),
            Some(active)
        );

        let exact_records = (0..MAX_LIVE_CACHE_UPDATE_RECORDS)
            .map(|offset| BlockIndexRecord {
                hash: indexed_hash(900_000 + offset as u32),
                height: 900_000 + offset as u32,
                prev_hash: indexed_hash(899_999 + offset as u32),
                chainwork: Uint256::from(900_001 + offset as u64),
                status: BlockStatus {
                    active_chain: true,
                    ..BlockStatus::default()
                },
                tx_count: 0,
                validated_at: None,
            })
            .collect::<Vec<_>>();
        let exact_update = BlockIndexCacheUpdate {
            expected_generation: index.memory.generation,
            next_generation: index.memory.generation + 1,
            alternate_count: index.memory.alternate_count,
            failed_count: index.memory.failed_count,
            records: exact_records,
        };
        assert_eq!(exact_update.records.len(), MAX_LIVE_CACHE_UPDATE_RECORDS);
        reset_block_index_record_clone_count();
        index.publish_cache_update(exact_update);
        assert_eq!(block_index_record_clone_count(), 0);
        assert_eq!(index.cache_occupancy(), STORED_BLOCK_CACHE_RECORDS);

        let one_over = (0..=MAX_LIVE_CACHE_UPDATE_RECORDS)
            .map(|offset| {
                (
                    None,
                    BlockIndexRecord {
                        hash: indexed_hash(1_000_000 + offset as u32),
                        height: 1_000_000 + offset as u32,
                        prev_hash: indexed_hash(999_999 + offset as u32),
                        chainwork: Uint256::from(1_000_001 + offset as u64),
                        status: BlockStatus::default(),
                        tx_count: 0,
                        validated_at: None,
                    },
                )
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            index.prepare_cache_update(&one_over),
            Err(ChainError::LiveWorkLimit {
                context: "block cache update records",
                limit: MAX_LIVE_CACHE_UPDATE_RECORDS,
                actual,
            }) if actual == MAX_LIVE_CACHE_UPDATE_RECORDS + 1
        ));
    }

    #[test]
    fn stored_block_index_rejects_point_key_hash_mismatch() {
        let store = MemoryStore::new();
        let index = StoredBlockIndex::new(store.clone()).expect("empty block index");
        let record = BlockIndexRecord {
            hash: indexed_hash(600_001),
            height: 0,
            prev_hash: BlockHash::ZERO,
            chainwork: Uint256::ONE,
            status: BlockStatus::default(),
            tx_count: 0,
            validated_at: None,
        };
        let wrong_key = indexed_hash(600_002);
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::BlockIndex,
                wrong_key.as_bytes(),
                &record.encode(),
            )
            .expect("stage mismatched block key");
        store.commit(batch).expect("commit mismatched block key");

        assert!(matches!(
            index.load_block_record(&wrong_key),
            Err(ChainError::Codec(_))
        ));
    }

    #[test]
    fn stored_block_index_prepares_cache_before_durable_commit() {
        let store = InstrumentedStore::new();
        let block = Block {
            header: header(BlockHash::ZERO, 700_001),
            transactions: Vec::new(),
        };
        let hash = block.hash();
        let mut index = StoredBlockIndex::new(store.clone()).expect("empty block index");

        store.fail_next_commit();
        index
            .store_block(&block, 0, Uint256::ONE, RawBlockSource::Fixture)
            .expect_err("injected block commit failure");
        assert_eq!(index.block(&hash).expect("live block index"), None);
        assert_eq!(
            index.load_block_record(&hash).expect("durable block index"),
            None
        );
        assert_eq!(index.status_counts(), (0, 0));

        let alternate =
            BlockIndexRecord::from_block(&block, 0, Uint256::ONE).expect("alternate record");
        index
            .insert_block_record(alternate.clone())
            .expect("initial insert");
        assert_eq!(index.status_counts(), (1, 0));

        let mut active = alternate.clone();
        active.status.active_chain = true;
        assert!(matches!(
            index.prepare_cache_update(&[(None, active.clone())]),
            Err(ChainError::Codec(_))
        ));
        store.fail_next_commit();
        index
            .insert_block_record(active)
            .expect_err("injected replacement failure");
        assert_eq!(
            index.block(&hash).expect("unchanged live record"),
            Some(alternate.clone())
        );
        assert_eq!(
            index
                .load_block_record(&hash)
                .expect("unchanged durable record"),
            Some(alternate)
        );
        assert_eq!(index.status_counts(), (1, 0));
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
