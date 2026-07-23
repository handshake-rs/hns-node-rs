#![forbid(unsafe_code)]

mod page_tree;

pub use hns_urkel::TreeRoot;
pub use page_tree::{
    name_page_root_key, pack_name_page_records, NamePageRootLocator, NamePageRootRecord,
    NamePageSnapshot, NamePageState, NamePageTreeReader, PackedNamePages, PageTreeError,
    NAME_PAGE_ROOT_PREFIX, NAME_PAGE_SEGMENT_BLOCKS, NAME_PAGE_STATE_KEY,
};

use std::{
    cell::RefCell,
    collections::{btree_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use hns_chain::{read_canonical_hash, HeaderRecord};
use hns_consensus::{
    is_reserved, maybe_expire_name, name_lifecycle, transaction_sigops, verify_airdrop_output,
    verify_and_apply_name_covenant, verify_claim_output, verify_sequence_locks,
    verify_transaction_covenant_links, AirdropFlags, ClaimFlags, ConsensusError, CovenantLinkError,
    DeploymentState, HistoricalValidationPlan, NameContext, NameFlags,
    NativeAirdropSignatureVerifier, NativeSignatureVerifier, Network, OpenSslDnssecVerifier,
    RejectUnverifiedInputs, SequenceLockView, TransactionInputVerifier, VerifiedClaim,
    WitnessProgramVerifier, MAX_BLOCK_SIGOPS, MAX_MONEY, MEDIAN_TIMESPAN,
};
use hns_primitives::{
    blake2b_256, Address, AirdropKey, AirdropProof, AirdropSignatureVerifier, Amount, Block,
    BlockHash, Coin, Covenant, CovenantKind, DnssecVerifier, Height, NameHash, NameLifecycleState,
    NameState, Outpoint, OwnershipProof, PrimitiveError, Reader, Transaction,
    UnavailableAirdropSignatureVerifier, Writer, AIRDROP_TREE_LEAVES, MAX_ADDRESS_HASH_SIZE,
    MAX_BLOCK_WEIGHT, MAX_NAME_SIZE, MAX_RESOURCE_SIZE, MAX_TX_SIZE,
};
use hns_store::{
    decode_u32, encode_u32, ColumnFamily, MetaKey, ReadSnapshot, Store, StoreError, WriteBatch,
    AIRDROP_FIELD_BYTES, LEGACY_SCHEMA_VERSION, LEGACY_STORAGE_PROFILE, SCHEMA_VERSION,
    STORAGE_PROFILE,
};
use hns_urkel::{
    materialize_record_tree, prove_hsd_from_records, reachable_record_roots,
    reachable_record_roots_batched, update_record_tree, update_record_tree_batched,
    validate_record_root, validate_record_tree, validate_record_trees_batched, MemoryUrkel,
    NameTreeSnapshot, UrkelError, UrkelProof,
};
use serde::{Deserialize, Serialize};

const BLOCK_UNDO_VERSION: u32 = 7;
const LEGACY_BLOCK_UNDO_VERSION: u32 = 6;
const NAME_TREE_ACCUMULATOR_VERSION: u32 = 1;
pub const NAME_TREE_ACCUMULATOR_KEY: &[u8] = b"name-tree-accumulator/v1";
pub const NAME_TREE_INTERVAL_MIGRATION_PREFIX: &[u8] = b"migration/v17/";
const NAME_TREE_INTERVAL_MIGRATION_SCHEMA_KEY: &[u8] = b"migration/v17/original-schema";
const NAME_TREE_INTERVAL_MIGRATION_PROFILE_KEY: &[u8] = b"migration/v17/original-profile";
const NAME_TREE_INTERVAL_MIGRATION_ROOT_KEY: &[u8] = b"migration/v17/original-working-root";
const NAME_TREE_INTERVAL_MIGRATION_COMMIT_ROOT_KEY: &[u8] =
    b"migration/v17/original-committed-root";
const NAME_TREE_INTERVAL_MIGRATION_UNDO_PREFIX: &[u8] = b"migration/v17/undo-v6/";
const NAME_TREE_INTERVAL_MIGRATION_BATCH: usize = 256;
const NAME_TREE_SNAPSHOT_PIN_VERSION: u32 = 1;
pub const NAME_TREE_SNAPSHOT_PIN_PREFIX: &[u8] = b"name-tree-snapshot/v1/";
const NAME_TREE_SNAPSHOT_PIN_BODY_SIZE: usize = 4 + 4 + 32 + 32;
const NAME_TREE_SNAPSHOT_PIN_CODEC_SIZE: usize = NAME_TREE_SNAPSHOT_PIN_BODY_SIZE + 32;
const OUTPOINT_KEY_SIZE: usize = 36;
const ADDRESS_CODEC_MAX: usize = 2 + MAX_ADDRESS_HASH_SIZE;
const COIN_CODEC_MAX: usize = OUTPOINT_KEY_SIZE + 8 + 4 + 1 + ADDRESS_CODEC_MAX + MAX_TX_SIZE + 9;
const NAME_STATE_FIELD_MASK: u16 = (1 << 10) - 1;
const NAME_STATE_CODEC_MAX: usize =
    1 + MAX_NAME_SIZE + 2 + MAX_RESOURCE_SIZE + 4 + 4 + 2 + 32 + 9 + 9 + 9 + 4 + 4 + 4 + 9;
const NAME_UNDO_CODEC_MAX: usize = 32 + 1 + NAME_STATE_CODEC_MAX + 9;
const BLOCK_UNDO_CODEC_MAX: usize = MAX_BLOCK_WEIGHT * 8;
const NAME_TREE_ACCUMULATOR_CODEC_MAX: usize = MAX_BLOCK_WEIGHT * 2;

#[derive(Default)]
struct NameStateChanges {
    current: BTreeMap<NameHash, NameState>,
    previous: BTreeMap<NameHash, Option<NameState>>,
    changed: HashSet<NameHash>,
}

#[derive(Clone, Debug)]
pub struct ConnectBlock<'a> {
    pub block_hash: BlockHash,
    pub height: Height,
    pub coinbase_maturity: u32,
    pub block_reward: Amount,
    pub block: &'a Block,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisconnectBlock {
    pub block_hash: BlockHash,
    pub height: Height,
}

/// Explicit state-validation evidence returned to the chain coordinator. A
/// true flag means the stage was either performed or was satisfied by the
/// exact checkpoint-backed route recorded in [`StateSummary::historical_validation`].
/// These flags remain narrower than full block-consensus validity.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateValidationSummary {
    pub relative_locks_valid: bool,
    pub scripts_valid: bool,
    pub covenant_links_valid: bool,
    pub covenants_context_valid: bool,
    pub claims_and_airdrops_valid: bool,
    pub name_state_connected: bool,
    pub tree_root_valid: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateSummary {
    pub coins_created: usize,
    pub coins_spent: usize,
    pub names_changed: usize,
    /// Latest interval-committed authenticated root before this block.
    /// Pending names live in the compact accumulator, not an intermediate tree.
    pub inherited_tree_root: TreeRoot,
    /// Latest interval-committed root after this block. This changes only at a
    /// `tree_interval` boundary.
    pub resulting_tree_root: TreeRoot,
    /// Interval-committed root checked against this block header.
    pub inherited_committed_tree_root: TreeRoot,
    /// Interval-committed root inherited by the next block.
    pub resulting_committed_tree_root: TreeRoot,
    /// Exact full or checkpoint-backed validation route selected by the chain
    /// coordinator. Historical assumptions are honored only when this equals
    /// HSD's complete canonical checkpoint plan.
    pub historical_validation: HistoricalValidationPlan,
    pub validation: StateValidationSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameUndo {
    pub name_hash: NameHash,
    pub previous: Option<NameState>,
}

/// Compact durable description of the names changed since the last
/// header-visible Urkel commitment. Counts, rather than a plain set, let a
/// non-boundary disconnect remove one block without scanning older undo.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameTreeAccumulator {
    pub base_root: TreeRoot,
    pub first_height: Height,
    pub last_height: Height,
    pub names: BTreeMap<NameHash, u16>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameTreeIntervalMigrationSummary {
    pub active_heights: usize,
    pub undos_rewritten: usize,
    pub legacy_undos_backed_up: usize,
    pub pending_names: usize,
    pub tip_height: Option<Height>,
}

impl NameTreeAccumulator {
    fn new(base_root: TreeRoot, height: Height) -> Self {
        Self {
            base_root,
            first_height: height,
            last_height: height,
            names: BTreeMap::new(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, StateError> {
        if self.first_height > self.last_height {
            return Err(StateError::Codec(
                "name-tree accumulator height range is inverted".to_owned(),
            ));
        }
        let mut writer = Writer::new();
        writer.write_u32(NAME_TREE_ACCUMULATOR_VERSION);
        writer.write_bytes(self.base_root.as_bytes());
        writer.write_u32(self.first_height);
        writer.write_u32(self.last_height);
        writer.write_varint(self.names.len() as u64);
        for (name_hash, count) in &self.names {
            if *count == 0 {
                return Err(StateError::Codec(
                    "name-tree accumulator contains a zero reference count".to_owned(),
                ));
            }
            writer.write_bytes(name_hash.as_bytes());
            writer.write_u16(*count);
        }
        let mut raw = writer.finish();
        if raw.len() + 32 > NAME_TREE_ACCUMULATOR_CODEC_MAX {
            return Err(StateError::Codec(
                "name-tree accumulator exceeds its codec limit".to_owned(),
            ));
        }
        raw.extend_from_slice(&blake2b_256(&raw));
        Ok(raw)
    }

    fn decode(raw: &[u8]) -> Result<Self, StateError> {
        if raw.len() < 32 {
            return Err(StateError::Codec(
                "name-tree accumulator is truncated".to_owned(),
            ));
        }
        let (body, checksum) = raw.split_at(raw.len() - 32);
        if checksum != blake2b_256(body) {
            return Err(StateError::Codec(
                "name-tree accumulator checksum mismatch".to_owned(),
            ));
        }
        let mut reader = Reader::new(body, NAME_TREE_ACCUMULATOR_CODEC_MAX)?;
        let version = reader.read_u32()?;
        if version != NAME_TREE_ACCUMULATOR_VERSION {
            return Err(StateError::Codec(format!(
                "unsupported name-tree accumulator version {version}"
            )));
        }
        let base_root = TreeRoot::new(reader.read_hash()?);
        let first_height = reader.read_u32()?;
        let last_height = reader.read_u32()?;
        if first_height > last_height {
            return Err(StateError::Codec(
                "name-tree accumulator height range is inverted".to_owned(),
            ));
        }
        let count = reader.read_varint_usize("name-tree accumulator names")?;
        let mut names = BTreeMap::new();
        for _ in 0..count {
            let name_hash = NameHash::new(reader.read_hash()?);
            let references = reader.read_u16()?;
            if references == 0 {
                return Err(StateError::Codec(
                    "name-tree accumulator contains a zero reference count".to_owned(),
                ));
            }
            if names.insert(name_hash, references).is_some() {
                return Err(StateError::Codec(
                    "name-tree accumulator contains a duplicate name".to_owned(),
                ));
            }
        }
        reader.ensure_finished()?;
        Ok(Self {
            base_root,
            first_height,
            last_height,
            names,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockUndo {
    pub block_hash: BlockHash,
    pub height: Height,
    pub previous_tree_root: TreeRoot,
    pub resulting_tree_root: TreeRoot,
    pub previous_committed_tree_root: TreeRoot,
    pub resulting_committed_tree_root: TreeRoot,
    pub spent_coins: Vec<Coin>,
    pub created_coins: Vec<Outpoint>,
    pub airdrop_positions: Vec<u32>,
    pub previous_name_states: Vec<NameUndo>,
    pub name_tree_interval_boundary: bool,
    /// The accumulator's prior end height, when one existed. Production block
    /// activation is contiguous; retaining this value also keeps the low-level
    /// state harness reversible when pinned historical fixtures skip heights.
    pub previous_name_tree_accumulator_last_height: Option<Height>,
    /// Populated when an interval-boundary block cleared an existing
    /// accumulator. The separate boundary flag also represents genesis or an
    /// interval-one network, where no prior accumulator exists.
    pub previous_name_tree_accumulator: Option<NameTreeAccumulator>,
}

impl BlockUndo {
    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
        let mut writer = Writer::new();
        writer.write_u32(BLOCK_UNDO_VERSION);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_bytes(self.previous_tree_root.as_bytes());
        writer.write_bytes(self.resulting_tree_root.as_bytes());
        writer.write_bytes(self.previous_committed_tree_root.as_bytes());
        writer.write_bytes(self.resulting_committed_tree_root.as_bytes());
        writer.write_varint(self.spent_coins.len() as u64);

        for coin in &self.spent_coins {
            writer.write_varbytes(&encode_coin(coin));
        }

        writer.write_varint(self.created_coins.len() as u64);
        for outpoint in &self.created_coins {
            outpoint.write_to(&mut writer);
        }

        writer.write_varint(self.airdrop_positions.len() as u64);
        for position in &self.airdrop_positions {
            writer.write_u32(*position);
        }

        writer.write_varint(self.previous_name_states.len() as u64);
        for undo in &self.previous_name_states {
            writer.write_varbytes(&encode_name_undo(undo)?);
        }
        writer.write_u8(u8::from(self.name_tree_interval_boundary));
        match self.previous_name_tree_accumulator_last_height {
            Some(height) => {
                writer.write_u8(1);
                writer.write_u32(height);
            }
            None => writer.write_u8(0),
        }
        match &self.previous_name_tree_accumulator {
            Some(accumulator) => {
                writer.write_u8(1);
                writer.write_varbytes(&accumulator.encode()?);
            }
            None => writer.write_u8(0),
        }

        Ok(writer.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        let mut reader = Reader::new(bytes, BLOCK_UNDO_CODEC_MAX)?;
        let version = reader.read_u32()?;
        if version != BLOCK_UNDO_VERSION && version != LEGACY_BLOCK_UNDO_VERSION {
            return Err(StateError::Codec(format!(
                "unsupported block undo version {version}"
            )));
        }

        let block_hash = BlockHash::new(reader.read_hash()?);
        let height = reader.read_u32()?;
        let previous_tree_root = TreeRoot::new(reader.read_hash()?);
        let resulting_tree_root = TreeRoot::new(reader.read_hash()?);
        let previous_committed_tree_root = TreeRoot::new(reader.read_hash()?);
        let resulting_committed_tree_root = TreeRoot::new(reader.read_hash()?);
        let spent_count = reader.read_varint_usize("spent coins")?;
        let mut spent_coins = Vec::with_capacity(spent_count);
        for _ in 0..spent_count {
            let bytes = reader.read_varbytes(COIN_CODEC_MAX, "spent coin")?;
            spent_coins.push(decode_coin(&bytes)?);
        }

        let created_count = reader.read_varint_usize("created coins")?;
        let mut created_coins = Vec::with_capacity(created_count);
        for _ in 0..created_count {
            created_coins.push(Outpoint::read_from(&mut reader)?);
        }

        let airdrop_count = reader.read_varint_usize("airdrop undo positions")?;
        let mut airdrop_positions = Vec::with_capacity(airdrop_count);
        for _ in 0..airdrop_count {
            airdrop_positions.push(reader.read_u32()?);
        }

        let name_count = reader.read_varint_usize("name undo records")?;
        let mut previous_name_states = Vec::with_capacity(name_count);
        for _ in 0..name_count {
            let bytes = reader.read_varbytes(NAME_UNDO_CODEC_MAX, "name undo")?;
            previous_name_states.push(decode_name_undo(&bytes)?);
        }
        let (
            name_tree_interval_boundary,
            previous_name_tree_accumulator_last_height,
            previous_name_tree_accumulator,
        ) = if version == BLOCK_UNDO_VERSION {
            let name_tree_interval_boundary = match reader.read_u8()? {
                0 => false,
                1 => true,
                value => {
                    return Err(StateError::Codec(format!(
                        "invalid name-tree interval-boundary flag {value}"
                    )))
                }
            };
            let previous_name_tree_accumulator_last_height = match reader.read_u8()? {
                0 => None,
                1 => Some(reader.read_u32()?),
                value => {
                    return Err(StateError::Codec(format!(
                        "invalid previous name-tree accumulator height flag {value}"
                    )))
                }
            };
            let previous_name_tree_accumulator = match reader.read_u8()? {
                0 => None,
                1 => {
                    let bytes = reader.read_varbytes(
                        NAME_TREE_ACCUMULATOR_CODEC_MAX,
                        "previous name-tree accumulator",
                    )?;
                    Some(NameTreeAccumulator::decode(&bytes)?)
                }
                value => {
                    return Err(StateError::Codec(format!(
                        "invalid previous name-tree accumulator flag {value}"
                    )))
                }
            };
            (
                name_tree_interval_boundary,
                previous_name_tree_accumulator_last_height,
                previous_name_tree_accumulator,
            )
        } else {
            (false, None, None)
        };

        reader.ensure_finished()?;
        Ok(Self {
            block_hash,
            height,
            previous_tree_root,
            resulting_tree_root,
            previous_committed_tree_root,
            resulting_committed_tree_root,
            spent_coins,
            created_coins,
            airdrop_positions,
            previous_name_states,
            name_tree_interval_boundary,
            previous_name_tree_accumulator_last_height,
            previous_name_tree_accumulator,
        })
    }
}

/// Durable interval commitment for one active-chain post-state root. Pins are
/// checksummed and height-keyed so a replacement branch atomically removes the
/// old interval binding before installing its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameTreeSnapshotPin {
    pub height: Height,
    pub block_hash: BlockHash,
    pub root: TreeRoot,
}

impl NameTreeSnapshotPin {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(NAME_TREE_SNAPSHOT_PIN_CODEC_SIZE);
        writer.write_u32(NAME_TREE_SNAPSHOT_PIN_VERSION);
        writer.write_u32(self.height);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_bytes(self.root.as_bytes());
        let mut raw = writer.finish();
        debug_assert_eq!(raw.len(), NAME_TREE_SNAPSHOT_PIN_BODY_SIZE);
        raw.extend_from_slice(&blake2b_256(&raw));
        raw
    }

    pub fn decode(raw: &[u8]) -> Result<Self, StateError> {
        if raw.len() != NAME_TREE_SNAPSHOT_PIN_CODEC_SIZE {
            return Err(StateError::Codec(format!(
                "name-tree snapshot pin contains {} bytes; expected {NAME_TREE_SNAPSHOT_PIN_CODEC_SIZE}",
                raw.len()
            )));
        }
        let (body, checksum) = raw.split_at(NAME_TREE_SNAPSHOT_PIN_BODY_SIZE);
        if checksum != blake2b_256(body) {
            return Err(StateError::Codec(
                "name-tree snapshot pin checksum mismatch".to_owned(),
            ));
        }
        let mut reader = Reader::new(body, NAME_TREE_SNAPSHOT_PIN_BODY_SIZE)?;
        let version = reader.read_u32()?;
        if version != NAME_TREE_SNAPSHOT_PIN_VERSION {
            return Err(StateError::Codec(format!(
                "unsupported name-tree snapshot pin version {version}"
            )));
        }
        let height = reader.read_u32()?;
        let block_hash = BlockHash::new(reader.read_hash()?);
        let root = TreeRoot::new(reader.read_hash()?);
        reader.ensure_finished()?;
        Ok(Self {
            height,
            block_hash,
            root,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameTreeCompactionSummary {
    pub retained_roots: usize,
    pub nodes_before: usize,
    pub nodes_retained: usize,
    pub nodes_deleted: usize,
}

pub trait StateView {
    fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, StateError>;
    fn name_state(&self, name_hash: &NameHash) -> Result<Option<NameState>, StateError>;
}

pub trait StateEngine {
    fn connect_block(&mut self, request: ConnectBlock<'_>) -> Result<StateSummary, StateError>;
    fn disconnect_block(&mut self, request: DisconnectBlock) -> Result<StateSummary, StateError>;
}

/// Result from the dedicated coinbase claim/airdrop boundary. On the full
/// route, a production implementation accounts for every conjured unit and
/// authenticates every special input against the historical HNS datasets. On
/// the canonical historical route, the exact plan records which cryptographic
/// and value checks are checkpoint-backed assumptions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoinbaseIssuanceSummary {
    pub conjured: Amount,
    pub claims_and_airdrops_valid: bool,
    /// HSD allocation-field positions derived by this verifier. The state
    /// engine atomically rejects already-spent positions and records newly
    /// spent positions in block undo.
    pub airdrop_positions: Vec<u32>,
    /// Claims keyed to their same-index coinbase outputs. Full-route entries
    /// are cryptographically authenticated; historical entries are decoded
    /// and time-checked while their bindings are checkpoint-backed. The state
    /// engine applies them only after every special input has passed atomically.
    pub claims: Vec<CoinbaseClaim>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinbaseClaim {
    pub output_index: usize,
    pub claim: VerifiedClaim,
}

pub trait CoinbaseIssuanceVerifier: Send + Sync {
    fn verify_coinbase(
        &self,
        transaction: &Transaction,
        height: Height,
        parent_time: u64,
        network: Network,
    ) -> Result<CoinbaseIssuanceSummary, StateError>;

    /// HSD's checkpoint route retains special-proof format, time, deployment,
    /// and allocation-bit checks while assuming Merkle/signature cryptography
    /// and output-value binding. Verifiers which do not implement that exact
    /// route remain conservatively full-verification by default.
    fn verify_historical_coinbase(
        &self,
        transaction: &Transaction,
        height: Height,
        parent_time: u64,
        network: Network,
    ) -> Result<CoinbaseIssuanceSummary, StateError> {
        self.verify_coinbase(transaction, height, parent_time, network)
    }
}

/// Fail-closed verifier which accepts only an ordinary coinbase with no claim
/// covenant and no additional claim/airdrop inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectSpecialCoinbaseIssuance;

impl CoinbaseIssuanceVerifier for RejectSpecialCoinbaseIssuance {
    fn verify_coinbase(
        &self,
        transaction: &Transaction,
        _height: Height,
        _parent_time: u64,
        _network: Network,
    ) -> Result<CoinbaseIssuanceSummary, StateError> {
        let special_input = transaction.inputs.len() > 1;
        let claim_output = transaction
            .outputs
            .iter()
            .any(|output| output.covenant.kind == CovenantKind::Claim);
        if special_input || claim_output {
            return Err(StateError::UnsupportedCoinbaseIssuance);
        }
        Ok(CoinbaseIssuanceSummary {
            conjured: 0,
            claims_and_airdrops_valid: true,
            airdrop_positions: Vec::new(),
            claims: Vec::new(),
        })
    }
}

/// A proof-capable coinbase boundary for HSD airdrops and DNSSEC CLAIM outputs.
/// The historical type name is retained while this boundary grows toward full
/// issuance parity. [`Self::native`] enables the full HSD key set, including
/// the historical GooSig allocations. [`Self::faucet_only`] remains available
/// for explicitly fail-closed tests and tools. CLAIM signatures are verified
/// by the OpenSSL DNSSEC backend.
#[derive(Clone)]
pub struct AirdropCoinbaseIssuanceVerifier {
    flags: AirdropFlags,
    signatures: Arc<dyn AirdropSignatureVerifier>,
    dnssec: Arc<dyn DnssecVerifier>,
}

impl fmt::Debug for AirdropCoinbaseIssuanceVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AirdropCoinbaseIssuanceVerifier")
            .field("flags", &self.flags)
            .field("signatures", &"<airdrop-signature-verifier>")
            .field("dnssec", &"<dnssec-verifier>")
            .finish()
    }
}

impl AirdropCoinbaseIssuanceVerifier {
    /// Construct from deployment state already derived for the candidate's
    /// active-chain parent. GooSig cutoff is additionally derived from the
    /// candidate height and selected network on every verification call.
    pub fn new(
        deployments: DeploymentState,
        signatures: Arc<dyn AirdropSignatureVerifier>,
    ) -> Self {
        Self {
            flags: AirdropFlags {
                airstop: deployments.has_airstop,
                hardening: deployments.name_flags.contains(NameFlags::HARDENED),
                goosig_disabled: false,
            },
            signatures,
            dnssec: Arc::new(OpenSslDnssecVerifier),
        }
    }

    pub fn native(deployments: DeploymentState) -> Result<Self, StateError> {
        let signatures = NativeAirdropSignatureVerifier::new()
            .map_err(|error| StateError::AirdropSignatureBackend(error.to_string()))?;
        Ok(Self::new(deployments, Arc::new(signatures)))
    }

    pub fn faucet_only(deployments: DeploymentState) -> Self {
        Self::new(deployments, Arc::new(UnavailableAirdropSignatureVerifier))
    }
}

impl CoinbaseIssuanceVerifier for AirdropCoinbaseIssuanceVerifier {
    fn verify_coinbase(
        &self,
        transaction: &Transaction,
        height: Height,
        parent_time: u64,
        network: Network,
    ) -> Result<CoinbaseIssuanceSummary, StateError> {
        let mut conjured = 0u64;
        let mut airdrop_positions = Vec::with_capacity(transaction.inputs.len().saturating_sub(1));
        let mut claims = Vec::new();
        for input_index in 1..transaction.inputs.len() {
            let input = &transaction.inputs[input_index];
            if input.witness.items.len() != 1 {
                return Err(StateError::AirdropVerification(format!(
                    "coinbase input {input_index} must contain exactly one proof item"
                )));
            }
            let output = transaction.outputs.get(input_index).ok_or_else(|| {
                StateError::AirdropVerification(format!(
                    "coinbase input {input_index} has no same-index output"
                ))
            })?;
            if output.covenant.kind == CovenantKind::Claim {
                let verified = verify_claim_output(
                    &input.witness.items[0],
                    output,
                    height,
                    parent_time,
                    network,
                    ClaimFlags {
                        hardened: self.flags.hardening,
                    },
                    self.dnssec.as_ref(),
                )
                .map_err(|error| StateError::ClaimVerification(error.to_string()))?;
                conjured = conjured
                    .checked_add(verified.conjured)
                    .filter(|value| *value <= MAX_MONEY)
                    .ok_or(StateError::CoinbaseRewardOverflow)?;
                claims.push(CoinbaseClaim {
                    output_index: input_index,
                    claim: verified,
                });
                continue;
            }

            let mut flags = self.flags;
            flags.goosig_disabled = height >= network.params().goosig_stop;
            let verified = verify_airdrop_output(
                &input.witness.items[0],
                output,
                flags,
                self.signatures.as_ref(),
            )
            .map_err(|error| StateError::AirdropVerification(error.to_string()))?;
            conjured = conjured
                .checked_add(verified.value)
                .filter(|value| *value <= MAX_MONEY)
                .ok_or(StateError::CoinbaseRewardOverflow)?;
            airdrop_positions.push(verified.position);
        }

        Ok(CoinbaseIssuanceSummary {
            conjured,
            claims_and_airdrops_valid: true,
            airdrop_positions,
            claims,
        })
    }

    fn verify_historical_coinbase(
        &self,
        transaction: &Transaction,
        height: Height,
        parent_time: u64,
        network: Network,
    ) -> Result<CoinbaseIssuanceSummary, StateError> {
        let mut airdrop_positions = Vec::with_capacity(transaction.inputs.len().saturating_sub(1));
        let mut claims = Vec::new();
        for input_index in 1..transaction.inputs.len() {
            let input = &transaction.inputs[input_index];
            if input.witness.items.len() != 1 {
                return Err(StateError::AirdropVerification(format!(
                    "coinbase input {input_index} must contain exactly one proof item"
                )));
            }
            let output = transaction.outputs.get(input_index).ok_or_else(|| {
                StateError::AirdropVerification(format!(
                    "coinbase input {input_index} has no same-index output"
                ))
            })?;
            if output.covenant.kind == CovenantKind::Claim {
                let proof = OwnershipProof::decode(&input.witness.items[0])
                    .map_err(|error| StateError::ClaimVerification(error.to_string()))?;
                if !proof.verify_time(parent_time) {
                    return Err(StateError::ClaimVerification(
                        "ownership proof signatures do not cover the parent block time".to_owned(),
                    ));
                }
                claims.push(CoinbaseClaim {
                    output_index: input_index,
                    claim: checkpoint_assumed_claim(output)?,
                });
                continue;
            }

            if self.flags.airstop {
                return Err(StateError::AirdropVerification(
                    "airdrop issuance is disabled by the active airstop deployment".to_owned(),
                ));
            }
            let proof = AirdropProof::decode(&input.witness.items[0])
                .map_err(|error| StateError::AirdropVerification(error.to_string()))?;
            if !proof.is_sane() {
                return Err(StateError::AirdropVerification(
                    "airdrop proof is structurally non-sane".to_owned(),
                ));
            }
            if height >= network.params().goosig_stop {
                let key = proof
                    .key()
                    .map_err(|error| StateError::AirdropVerification(error.to_string()))?;
                if matches!(key, AirdropKey::Goo { .. }) {
                    return Err(StateError::AirdropVerification(
                        "GooSig airdrop keys are disabled at this height".to_owned(),
                    ));
                }
            }
            // HSD's `proof.isWeak()` returns false when a key cannot be
            // decoded. Key decoding is independently mandatory only after the
            // GooSig cutoff above.
            if self.flags.hardening && proof.key().is_ok_and(|key| key.is_weak()) {
                return Err(StateError::AirdropVerification(
                    "weak RSA airdrop key is disabled by hardening".to_owned(),
                ));
            }
            airdrop_positions.push(
                proof
                    .position()
                    .map_err(|error| StateError::AirdropVerification(error.to_string()))?,
            );
        }

        Ok(CoinbaseIssuanceSummary {
            // HSD's historical route does not use issuance values for reward
            // accounting. The hardcoded checkpoint authenticates them.
            conjured: 0,
            claims_and_airdrops_valid: true,
            airdrop_positions,
            claims,
        })
    }
}

fn checkpoint_assumed_claim(output: &hns_primitives::Output) -> Result<VerifiedClaim, StateError> {
    if output.covenant.kind != CovenantKind::Claim {
        return Err(StateError::ClaimVerification(
            "historical claim covenant is malformed".to_owned(),
        ));
    }
    let name_hash = output
        .covenant
        .item_hash(0)
        .map(NameHash::new)
        .ok_or_else(|| {
            StateError::ClaimVerification("historical claim name hash is missing".to_owned())
        })?;
    let name = output
        .covenant
        .item(2)
        .ok_or_else(|| {
            StateError::ClaimVerification("historical claim name is missing".to_owned())
        })?
        .to_vec();
    let weak = output
        .covenant
        .item_u8(3)
        .map(|flags| flags & 1 != 0)
        .ok_or_else(|| {
            StateError::ClaimVerification("historical claim flags are missing".to_owned())
        })?;
    let commit_hash = output.covenant.item_hash(4).ok_or_else(|| {
        StateError::ClaimVerification("historical claim commit hash is missing".to_owned())
    })?;
    let commit_height = output.covenant.item_u32(5).ok_or_else(|| {
        StateError::ClaimVerification("historical claim commit height is missing".to_owned())
    })?;

    Ok(VerifiedClaim {
        name_hash,
        name,
        weak,
        commit_hash,
        commit_height,
        value: output.value,
        fee: 0,
        conjured: 0,
    })
}

#[derive(Clone, Copy)]
pub struct StateServices<'a> {
    pub network: Network,
    pub name_flags: NameFlags,
    pub name_flags_valid: bool,
    /// Branch-specific historical route selected only after the caller has
    /// established checkpoint ancestry. Standalone state engines use the full
    /// fail-closed route.
    pub historical_validation: HistoricalValidationPlan,
    pub input_verifier: &'a dyn TransactionInputVerifier,
    pub issuance_verifier: &'a dyn CoinbaseIssuanceVerifier,
}

impl fmt::Debug for StateServices<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateServices")
            .field("network", &self.network)
            .field("name_flags", &self.name_flags)
            .field("name_flags_valid", &self.name_flags_valid)
            .field("historical_validation", &self.historical_validation)
            .field("input_verifier", &"<transaction-input-verifier>")
            .field("issuance_verifier", &"<coinbase-issuance-verifier>")
            .finish()
    }
}

#[derive(Clone)]
pub struct StoredStateEngine<S: Store> {
    store: S,
    network: Network,
    name_flags: NameFlags,
    name_flags_valid: bool,
    input_verifier: Arc<dyn TransactionInputVerifier>,
    issuance_verifier: Arc<dyn CoinbaseIssuanceVerifier>,
}

impl<S: Store> fmt::Debug for StoredStateEngine<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredStateEngine")
            .field("store", &"<store>")
            .field("network", &self.network)
            .field("name_flags", &self.name_flags)
            .field("name_flags_valid", &self.name_flags_valid)
            .field("input_verifier", &"<transaction-input-verifier>")
            .field("issuance_verifier", &"<coinbase-issuance-verifier>")
            .finish()
    }
}

impl<S: Store> StoredStateEngine<S> {
    /// Construct a deliberately fail-closed engine. This is useful for tests
    /// and for deployments which want to supply their own explicitly selected verifier.
    pub fn new(store: S) -> Result<Self, StateError> {
        Self::with_services(
            store,
            Network::Mainnet,
            NameFlags::NONE,
            false,
            Arc::new(RejectUnverifiedInputs),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
    }

    pub fn for_network(store: S, network: Network) -> Result<Self, StateError> {
        Self::with_services(
            store,
            network,
            NameFlags::NONE,
            false,
            Arc::new(RejectUnverifiedInputs),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
    }

    /// Construct the native shadow-validation engine. Authority remains gated
    /// elsewhere until claim/airdrop coverage, persistent Urkel storage, and
    /// historical replay have independently completed. Active node callers
    /// supply verified parent-derived deployment flags per block.
    pub fn with_native_authorization(
        store: S,
        network: Network,
        name_flags: NameFlags,
    ) -> Result<Self, StateError> {
        Self::with_native_authorization_inner(store, network, name_flags, false)
    }

    /// Construct the native verifier with deployment-derived name flags that
    /// the caller has already validated against the active chain. This
    /// constructor is deliberately explicit so a static placeholder such as
    /// `NameFlags::NONE` cannot silently acquire contextual authority.
    pub fn with_native_authorization_and_verified_name_flags(
        store: S,
        network: Network,
        name_flags: NameFlags,
    ) -> Result<Self, StateError> {
        Self::with_native_authorization_inner(store, network, name_flags, true)
    }

    fn with_native_authorization_inner(
        store: S,
        network: Network,
        name_flags: NameFlags,
        name_flags_valid: bool,
    ) -> Result<Self, StateError> {
        let signatures = NativeSignatureVerifier::new()
            .map_err(|error| StateError::InputAuthorizationBackend(error.to_string()))?;
        Self::with_services(
            store,
            network,
            name_flags,
            name_flags_valid,
            Arc::new(WitnessProgramVerifier::mandatory(signatures)),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
    }

    pub fn with_input_verifier(
        store: S,
        input_verifier: Arc<dyn TransactionInputVerifier>,
    ) -> Result<Self, StateError> {
        Self::with_services(
            store,
            Network::Mainnet,
            NameFlags::NONE,
            false,
            input_verifier,
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
    }

    pub fn with_services(
        store: S,
        network: Network,
        name_flags: NameFlags,
        name_flags_valid: bool,
        input_verifier: Arc<dyn TransactionInputVerifier>,
        issuance_verifier: Arc<dyn CoinbaseIssuanceVerifier>,
    ) -> Result<Self, StateError> {
        hns_store::initialize_schema(&store)?;
        Ok(Self {
            store,
            network,
            name_flags,
            name_flags_valid,
            input_verifier,
            issuance_verifier,
        })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn name_flags(&self) -> NameFlags {
        self.name_flags
    }

    pub fn name_flags_valid(&self) -> bool {
        self.name_flags_valid
    }

    pub fn input_verifier(&self) -> &dyn TransactionInputVerifier {
        self.input_verifier.as_ref()
    }

    pub fn issuance_verifier(&self) -> &dyn CoinbaseIssuanceVerifier {
        self.issuance_verifier.as_ref()
    }

    pub fn services(&self) -> StateServices<'_> {
        StateServices {
            network: self.network,
            name_flags: self.name_flags,
            name_flags_valid: self.name_flags_valid,
            historical_validation: HistoricalValidationPlan::full(),
            input_verifier: self.input_verifier(),
            issuance_verifier: self.issuance_verifier(),
        }
    }

    pub fn load_undo(&self, block_hash: &BlockHash) -> Result<Option<BlockUndo>, StateError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::Undo, block_hash.as_bytes())? else {
            return Ok(None);
        };
        BlockUndo::decode(&bytes).map(Some)
    }

    /// Materialize one immutable, root-checked view of the durable name-state
    /// column family. The view owns its exact HSD proof-generation tree, so a
    /// later store commit cannot mix roots and values within one proof.
    pub fn name_tree_snapshot(&self) -> Result<MaterializedNameTreeSnapshot, StateError> {
        let snapshot = self.store.snapshot()?;
        materialize_name_tree_snapshot(&snapshot)
    }

    /// Generate a path-local proof from the content-addressed durable node
    /// records bound to the current root. Only records on the requested path
    /// are loaded and each is rehashed before use.
    pub fn name_proof(&self, name_hash: NameHash) -> Result<(TreeRoot, UrkelProof), StateError> {
        let snapshot = self.store.snapshot()?;
        let root = load_stored_name_tree_root(&snapshot)?;
        let proof = prove_persisted_name_tree(&snapshot, root, name_hash)?;
        Ok((root, proof))
    }

    /// Atomically remove content-addressed records that are unreachable from
    /// the current root, active undo history, or durable interval pins. Node
    /// coordination must serialize this maintenance operation with state
    /// transitions, just like connect/disconnect.
    pub fn compact_name_tree_nodes(&mut self) -> Result<NameTreeCompactionSummary, StateError> {
        let snapshot = self.store.snapshot()?;
        let mut batch = self.store.batch();
        let summary = stage_name_tree_node_compaction(&snapshot, &mut batch)?;
        drop(snapshot);
        self.store.commit(batch)?;
        Ok(summary)
    }
}

impl<S: Store> StateView for StoredStateEngine<S> {
    fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, StateError> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot.get(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))? else {
            return Ok(None);
        };
        decode_coin(&bytes).map(Some)
    }

    fn name_state(&self, name_hash: &NameHash) -> Result<Option<NameState>, StateError> {
        let snapshot = self.store.snapshot()?;
        load_name_state(&snapshot, name_hash)
    }
}

impl<S: Store> StateEngine for StoredStateEngine<S> {
    fn connect_block(&mut self, request: ConnectBlock<'_>) -> Result<StateSummary, StateError> {
        let snapshot = self.store.snapshot()?;
        let mut batch = self.store.batch();
        let summary =
            connect_block_to_batch_with_services(&snapshot, &mut batch, request, self.services())?;
        self.store.commit(batch)?;
        Ok(summary)
    }

    fn disconnect_block(&mut self, request: DisconnectBlock) -> Result<StateSummary, StateError> {
        let snapshot = self.store.snapshot()?;
        let undo = snapshot
            .get(ColumnFamily::Undo, request.block_hash.as_bytes())?
            .map(|bytes| BlockUndo::decode(&bytes))
            .transpose()?
            .ok_or(StateError::MissingUndo(request.block_hash))?;
        let mut batch = self.store.batch();
        let summary = disconnect_block_to_batch(&snapshot, &mut batch, request, &undo)?;
        drop(snapshot);
        self.store.commit(batch)?;
        Ok(summary)
    }
}

pub fn connect_block_to_batch<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    request: ConnectBlock<'_>,
) -> Result<StateSummary, StateError> {
    connect_block_to_batch_with_services(
        snapshot,
        batch,
        request,
        StateServices {
            network: Network::Mainnet,
            name_flags: NameFlags::NONE,
            name_flags_valid: false,
            historical_validation: HistoricalValidationPlan::full(),
            input_verifier: &RejectUnverifiedInputs,
            issuance_verifier: &RejectSpecialCoinbaseIssuance,
        },
    )
}

pub fn connect_block_to_batch_with_verifier<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    request: ConnectBlock<'_>,
    input_verifier: &dyn TransactionInputVerifier,
) -> Result<StateSummary, StateError> {
    connect_block_to_batch_with_services(
        snapshot,
        batch,
        request,
        StateServices {
            network: Network::Mainnet,
            name_flags: NameFlags::NONE,
            name_flags_valid: false,
            historical_validation: HistoricalValidationPlan::full(),
            input_verifier,
            issuance_verifier: &RejectSpecialCoinbaseIssuance,
        },
    )
}

pub fn connect_block_to_batch_with_services<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    request: ConnectBlock<'_>,
    services: StateServices<'_>,
) -> Result<StateSummary, StateError> {
    let route = services.historical_validation;
    let checkpointed = route == HistoricalValidationPlan::hsd_checkpointed();
    if route != HistoricalValidationPlan::full() && !checkpointed {
        return Err(StateError::InvalidHistoricalValidationPlan);
    }

    if request.block_hash != request.block.hash() {
        return Err(StateError::BlockHashMismatch {
            expected: request.block_hash,
            actual: request.block.hash(),
        });
    }

    let tree_interval = services.network.params().names.tree_interval;
    if tree_interval == 0 {
        return Err(StateError::Codec(
            "network name-tree snapshot interval is zero".to_owned(),
        ));
    }

    // HSD applies name transitions to an in-memory transaction every block but
    // commits that transaction to the header-visible tree only at name-tree
    // interval boundaries. HSRD durably accumulates the unique changed names
    // and mutates authenticated paths only at that same boundary.
    let inherited_tree_root = load_stored_name_tree_root(snapshot)?;
    validate_persisted_name_tree_root(snapshot, inherited_tree_root)?;
    let inherited_committed_tree_root = load_stored_name_tree_commit_root(snapshot)?;
    validate_persisted_name_tree_root(snapshot, inherited_committed_tree_root)?;
    if inherited_tree_root != inherited_committed_tree_root {
        return Err(StateError::Codec(
            "durable name-tree roots diverge under the interval-accumulator profile".to_owned(),
        ));
    }
    let committed_tree_root = TreeRoot::new(request.block.header.tree_root);
    if committed_tree_root != inherited_committed_tree_root {
        return Err(StateError::HeaderTreeRootMismatch {
            committed: committed_tree_root,
            inherited: inherited_committed_tree_root,
        });
    }

    let coinbase = request
        .block
        .transactions
        .first()
        .ok_or(StateError::MissingCoinbase)?;
    let prefetched_utxos = prefetch_block_utxos(snapshot, request.block)?;
    let chain_context =
        SnapshotChainContext::new(snapshot, request.height, services.historical_validation);
    let has_claim = coinbase
        .outputs
        .iter()
        .any(|output| output.covenant.kind == CovenantKind::Claim);
    // HSD validates claim RRSIG windows against the exact candidate parent's
    // header time. This is deliberately distinct from the median-time-past
    // clock used for transaction finality and sequence locks.
    let parent_time = if has_claim && request.height != 0 {
        chain_context.block_time(request.height - 1)?
    } else {
        0
    };
    let assumes = |checked: bool| checkpointed && !checked;
    let issuance = if assumes(route.claim_airdrop_cryptography) {
        services.issuance_verifier.verify_historical_coinbase(
            coinbase,
            request.height,
            parent_time,
            services.network,
        )?
    } else {
        services.issuance_verifier.verify_coinbase(
            coinbase,
            request.height,
            parent_time,
            services.network,
        )?
    };
    stage_airdrop_positions(snapshot, batch, &issuance.airdrop_positions)?;
    let coinbase_value = (!assumes(route.coinbase_reward))
        .then(|| transaction_output_value(coinbase))
        .transpose()?;

    let mut spent_coins = Vec::new();
    let mut spent_outpoints = HashSet::new();
    let mut created_coins = Vec::new();
    let mut created_set = HashSet::new();
    let mut pending_created = HashMap::new();
    let mut name_state_changes = NameStateChanges::default();
    let mut total_fees = 0u64;
    let mut block_sigops = 0u32;

    apply_verified_claims(
        snapshot,
        coinbase,
        request.height,
        services,
        &chain_context,
        &mut name_state_changes,
        &issuance.claims,
    )?;

    for (transaction_index, transaction) in request.block.transactions.iter().enumerate() {
        if transaction_index != 0 {
            let resolved = resolve_transaction_inputs(
                &prefetched_utxos,
                &pending_created,
                &mut spent_outpoints,
                transaction,
                request.height,
                request.coinbase_maturity,
                !assumes(route.input_values),
            )?;
            let input_coins = resolved.coins();

            if !assumes(route.sequence_locks) {
                verify_transaction_sequence_locks(
                    transaction,
                    request.height,
                    input_coins,
                    &chain_context,
                )?;
            }
            if !assumes(route.block_sigops) {
                block_sigops = block_sigops
                    .checked_add(transaction_sigops(transaction, input_coins)?)
                    .ok_or(StateError::BlockSigopsExceeded {
                        actual: u32::MAX,
                        maximum: MAX_BLOCK_SIGOPS,
                    })?;
                if block_sigops > MAX_BLOCK_SIGOPS {
                    return Err(StateError::BlockSigopsExceeded {
                        actual: block_sigops,
                        maximum: MAX_BLOCK_SIGOPS,
                    });
                }
            }
            if !assumes(route.scripts) {
                verify_transaction_inputs(services.input_verifier, transaction, input_coins)?;
            }
            if !assumes(route.covenant_links) {
                verify_transaction_covenant_links(transaction, input_coins)?;
            }

            let fee = if assumes(route.input_values) {
                None
            } else {
                let input_value = input_coins.iter().try_fold(0u64, |total, coin| {
                    total
                        .checked_add(coin.value)
                        .ok_or(StateError::InputValueOverflow)
                })?;
                let output_value = transaction_output_value(transaction)?;
                if input_value < output_value {
                    return Err(StateError::InputValueBelowOutput {
                        input: input_value,
                        output: output_value,
                    });
                }
                Some(input_value - output_value)
            };

            apply_transaction_name_covenants(
                snapshot,
                transaction,
                request.height,
                services,
                &chain_context,
                &mut name_state_changes,
                false,
            )?;

            stage_transaction_spends(
                batch,
                &mut pending_created,
                &mut created_coins,
                &mut spent_coins,
                resolved,
            )?;
            if let Some(fee) = fee {
                total_fees = total_fees
                    .checked_add(fee)
                    .ok_or(StateError::FeeValueOverflow)?;
            }
        } else {
            apply_transaction_name_covenants(
                snapshot,
                transaction,
                request.height,
                services,
                &chain_context,
                &mut name_state_changes,
                true,
            )?;
        }

        let txid = transaction.txid();
        for (output_index, output) in transaction.outputs.iter().enumerate() {
            // HSD's Coins.fromTX omits null-data and REVOKE outputs entirely.
            // Their value and covenant effects were still validated above,
            // but admitting them here would corrupt UTXO and undo parity.
            if output.is_unspendable() {
                continue;
            }
            let index = u32::try_from(output_index).map_err(|_| {
                StateError::Codec(format!("output index {output_index} exceeds u32"))
            })?;
            let outpoint = Outpoint { txid, index };
            if !created_set.insert(outpoint.clone()) {
                return Err(StateError::DuplicateCoin(outpoint));
            }
            let existing = prefetched_utxos.get(&outpoint).ok_or_else(|| {
                StateError::Codec("prefetched UTXO set is missing a block output".to_owned())
            })?;
            if !spent_outpoints.contains(&outpoint) && existing.is_some() {
                return Err(StateError::DuplicateCoin(outpoint));
            }

            let coin = Coin {
                outpoint: outpoint.clone(),
                value: output.value,
                height: request.height,
                coinbase: transaction_index == 0,
                address: output.address.clone(),
                covenant: output.covenant.clone(),
            };
            batch.put(
                ColumnFamily::Utxo,
                &encode_outpoint_key(&outpoint),
                &encode_coin(&coin),
            )?;
            pending_created.insert(outpoint.clone(), coin);
            created_coins.push(outpoint);
        }
    }

    if let Some(coinbase_value) = coinbase_value {
        let maximum_coinbase = request
            .block_reward
            .checked_add(total_fees)
            .and_then(|value| value.checked_add(issuance.conjured))
            .ok_or(StateError::CoinbaseRewardOverflow)?;
        if coinbase_value > maximum_coinbase {
            return Err(StateError::CoinbaseValueExceedsReward {
                coinbase: coinbase_value,
                maximum: maximum_coinbase,
            });
        }
    }

    let mut name_overrides = BTreeMap::<NameHash, Option<NameState>>::new();
    for name_hash in &name_state_changes.changed {
        let state = name_state_changes.current.get(name_hash).ok_or_else(|| {
            StateError::Codec("changed name is missing from transaction cache".to_owned())
        })?;
        write_name_state_to_batch(batch, state)?;
        name_overrides.insert(*name_hash, (!state.is_null()).then_some(state.clone()));
    }

    let interval_boundary = request.height.is_multiple_of(tree_interval);
    let previous_name_tree_accumulator = load_name_tree_accumulator(snapshot)?;
    let mut accumulator = match &previous_name_tree_accumulator {
        Some(accumulator) => {
            if accumulator.base_root != inherited_committed_tree_root {
                return Err(StateError::Codec(
                    "name-tree accumulator base root does not match the committed root".to_owned(),
                ));
            }
            let mut accumulator = accumulator.clone();
            accumulator.last_height = request.height;
            accumulator
        }
        None => NameTreeAccumulator::new(inherited_committed_tree_root, request.height),
    };
    for name_hash in name_overrides.keys() {
        let count = accumulator.names.entry(*name_hash).or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            StateError::Codec("name-tree accumulator reference count overflowed".to_owned())
        })?;
    }

    let resulting_tree_root = if interval_boundary {
        let mut interval_overrides = BTreeMap::<NameHash, Option<NameState>>::new();
        for name_hash in accumulator.names.keys() {
            let state = match name_state_changes.current.get(name_hash) {
                Some(state) => (!state.is_null()).then_some(state.clone()),
                None => load_name_state(snapshot, name_hash)?.filter(|state| !state.is_null()),
            };
            interval_overrides.insert(*name_hash, state);
        }
        let root = stage_name_tree_with_overrides(
            snapshot,
            batch,
            inherited_committed_tree_root,
            &interval_overrides,
        )?;
        batch.delete(ColumnFamily::Snapshots, NAME_TREE_ACCUMULATOR_KEY)?;
        root
    } else {
        batch.put(
            ColumnFamily::Snapshots,
            NAME_TREE_ACCUMULATOR_KEY,
            &accumulator.encode()?,
        )?;
        inherited_committed_tree_root
    };
    let resulting_committed_tree_root = resulting_tree_root;
    batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeRoot.as_bytes(),
        resulting_tree_root.as_bytes(),
    )?;
    batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeCommitRoot.as_bytes(),
        resulting_committed_tree_root.as_bytes(),
    )?;

    let previous_name_states = name_state_changes
        .previous
        .into_iter()
        .map(|(name_hash, previous)| NameUndo {
            name_hash,
            previous,
        })
        .collect::<Vec<_>>();
    let undo = BlockUndo {
        block_hash: request.block_hash,
        height: request.height,
        previous_tree_root: inherited_tree_root,
        resulting_tree_root,
        previous_committed_tree_root: inherited_committed_tree_root,
        resulting_committed_tree_root,
        spent_coins,
        created_coins,
        airdrop_positions: issuance.airdrop_positions.clone(),
        previous_name_states,
        name_tree_interval_boundary: interval_boundary,
        previous_name_tree_accumulator_last_height: previous_name_tree_accumulator
            .as_ref()
            .map(|accumulator| accumulator.last_height),
        previous_name_tree_accumulator: interval_boundary
            .then_some(previous_name_tree_accumulator)
            .flatten(),
    };
    batch.put(
        ColumnFamily::Undo,
        request.block_hash.as_bytes(),
        &undo.encode()?,
    )?;
    if request.height.is_multiple_of(tree_interval) {
        stage_name_tree_snapshot_pin(
            snapshot,
            batch,
            &NameTreeSnapshotPin {
                height: request.height,
                block_hash: request.block_hash,
                root: resulting_committed_tree_root,
            },
        )?;
    }

    Ok(StateSummary {
        coins_created: undo.created_coins.len(),
        coins_spent: undo.spent_coins.len(),
        names_changed: undo.previous_name_states.len(),
        inherited_tree_root,
        resulting_tree_root,
        inherited_committed_tree_root,
        resulting_committed_tree_root,
        historical_validation: services.historical_validation,
        validation: StateValidationSummary {
            relative_locks_valid: true,
            // Every non-coinbase input in this block reached the configured
            // verifier and returned success. Global interpreter completeness is
            // reported separately by node readiness and remains fail-closed.
            scripts_valid: true,
            covenant_links_valid: true,
            covenants_context_valid: true,
            claims_and_airdrops_valid: issuance.claims_and_airdrops_valid,
            name_state_connected: true,
            tree_root_valid: true,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedCoinSource {
    Pending,
    Existing,
}

#[derive(Clone, Debug, Default)]
struct ResolvedInputs {
    coins: Vec<Coin>,
    sources: Vec<ResolvedCoinSource>,
}

impl ResolvedInputs {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            coins: Vec::with_capacity(capacity),
            sources: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, coin: Coin, source: ResolvedCoinSource) {
        self.coins.push(coin);
        self.sources.push(source);
    }

    fn coins(&self) -> &[Coin] {
        &self.coins
    }
}

fn resolve_transaction_inputs(
    prefetched_utxos: &HashMap<Outpoint, Option<Coin>>,
    pending_created: &HashMap<Outpoint, Coin>,
    spent_outpoints: &mut HashSet<Outpoint>,
    transaction: &Transaction,
    spend_height: Height,
    coinbase_maturity: u32,
    check_maturity: bool,
) -> Result<ResolvedInputs, StateError> {
    let mut resolved = ResolvedInputs::with_capacity(transaction.inputs.len());
    for input in &transaction.inputs {
        if !spent_outpoints.insert(input.previous_output.clone()) {
            return Err(StateError::DuplicateSpend(input.previous_output.clone()));
        }
        let (coin, source) = match pending_created.get(&input.previous_output) {
            Some(coin) => (coin.clone(), ResolvedCoinSource::Pending),
            None => (
                prefetched_existing_coin(prefetched_utxos, &input.previous_output)?,
                ResolvedCoinSource::Existing,
            ),
        };
        if check_maturity {
            check_coinbase_maturity(&coin, spend_height, coinbase_maturity)?;
        }
        resolved.push(coin, source);
    }
    Ok(resolved)
}

fn prefetch_block_utxos<T: ReadSnapshot>(
    snapshot: &T,
    block: &Block,
) -> Result<HashMap<Outpoint, Option<Coin>>, StateError> {
    let mut unique = HashSet::new();
    let mut outpoints = Vec::new();
    for (transaction_index, transaction) in block.transactions.iter().enumerate() {
        if transaction_index != 0 {
            for input in &transaction.inputs {
                if unique.insert(input.previous_output.clone()) {
                    outpoints.push(input.previous_output.clone());
                }
            }
        }
        let txid = transaction.txid();
        for (output_index, output) in transaction.outputs.iter().enumerate() {
            if output.is_unspendable() {
                continue;
            }
            let index = u32::try_from(output_index).map_err(|_| {
                StateError::Codec(format!("output index {output_index} exceeds u32"))
            })?;
            let outpoint = Outpoint { txid, index };
            if unique.insert(outpoint.clone()) {
                outpoints.push(outpoint);
            }
        }
    }
    if outpoints.is_empty() {
        return Ok(HashMap::new());
    }

    let keys = outpoints
        .iter()
        .map(encode_outpoint_key)
        .collect::<Vec<_>>();
    let key_refs = keys.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let values = snapshot.get_many(ColumnFamily::Utxo, &key_refs)?;
    if values.len() != outpoints.len() {
        return Err(StateError::Codec(format!(
            "UTXO multi-get returned {} values for {} block outpoints",
            values.len(),
            outpoints.len()
        )));
    }

    outpoints
        .into_iter()
        .zip(values)
        .map(|(outpoint, raw)| {
            let coin = raw.map(|raw| decode_coin(&raw)).transpose()?;
            if coin.as_ref().is_some_and(|coin| coin.outpoint != outpoint) {
                return Err(StateError::Codec(
                    "coin payload does not match its prefetched UTXO key".to_owned(),
                ));
            }
            Ok((outpoint, coin))
        })
        .collect()
}

fn prefetched_existing_coin(
    prefetched_utxos: &HashMap<Outpoint, Option<Coin>>,
    outpoint: &Outpoint,
) -> Result<Coin, StateError> {
    prefetched_utxos
        .get(outpoint)
        .ok_or_else(|| {
            StateError::Codec("prefetched UTXO set is missing a transaction input".to_owned())
        })?
        .clone()
        .ok_or_else(|| StateError::MissingCoin(outpoint.clone()))
}

fn verify_transaction_sequence_locks<T: ReadSnapshot>(
    transaction: &Transaction,
    next_height: Height,
    coins: &[Coin],
    chain: &SnapshotChainContext<'_, T>,
) -> Result<(), StateError> {
    if transaction
        .inputs
        .iter()
        .all(|input| input.sequence & hns_consensus::SEQUENCE_DISABLE_FLAG != 0)
    {
        return Ok(());
    }
    let parent_median_time = if next_height == 0 {
        0
    } else {
        chain.median_time_past(next_height - 1)?
    };
    let view = TransactionSequenceView::new(coins, chain);
    if !verify_sequence_locks(transaction, next_height, parent_median_time, &view)? {
        return Err(StateError::RelativeLocks);
    }
    Ok(())
}

fn verify_transaction_inputs(
    verifier: &dyn TransactionInputVerifier,
    transaction: &Transaction,
    coins: &[Coin],
) -> Result<(), StateError> {
    if transaction.inputs.len() != coins.len() {
        return Err(StateError::Codec(
            "resolved input count does not match transaction inputs".to_owned(),
        ));
    }
    for (input_index, coin) in coins.iter().enumerate() {
        verifier
            .verify_input(transaction, input_index, coin)
            .map_err(|error| StateError::InputAuthorization {
                input_index,
                reason: error.to_string(),
            })?;
    }
    Ok(())
}

fn apply_verified_claims<T: ReadSnapshot>(
    snapshot: &T,
    coinbase: &Transaction,
    height: Height,
    services: StateServices<'_>,
    context: &SnapshotChainContext<'_, T>,
    changes: &mut NameStateChanges,
    claims: &[CoinbaseClaim],
) -> Result<(), StateError> {
    let claim_outputs = coinbase
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            (output.covenant.kind == CovenantKind::Claim).then_some(index)
        })
        .collect::<Vec<_>>();
    if claim_outputs.len() != claims.len()
        || !claim_outputs
            .iter()
            .zip(claims)
            .all(|(index, claim)| *index == claim.output_index)
    {
        return Err(StateError::ClaimVerification(
            "verified claim set does not match coinbase claim outputs".to_owned(),
        ));
    }
    if claims.is_empty() {
        return Ok(());
    }
    if !services.name_flags_valid {
        return Err(StateError::DeploymentStateUnavailable);
    }

    let params = services.network.params().names;
    let transaction_id = coinbase.txid();
    for authenticated in claims {
        let claim = &authenticated.claim;
        let output = coinbase
            .outputs
            .get(authenticated.output_index)
            .ok_or_else(|| {
                StateError::ClaimVerification("claim output index is out of range".to_owned())
            })?;

        if let Entry::Vacant(entry) = changes.current.entry(claim.name_hash) {
            let loaded = load_name_state(snapshot, &claim.name_hash)?;
            changes
                .previous
                .entry(claim.name_hash)
                .or_insert_with(|| loaded.clone());
            let mut state = loaded.unwrap_or_else(|| NameState::null(claim.name_hash));
            if state.is_null() {
                state.initialize(claim.name.clone(), height);
            }
            entry.insert(state);
        }
        let state = changes.current.get_mut(&claim.name_hash).ok_or_else(|| {
            StateError::ClaimVerification("claim name cache insertion failed".to_owned())
        })?;
        if state.name != claim.name {
            return Err(StateError::ClaimVerification(
                "claim name does not match stored name state".to_owned(),
            ));
        }

        maybe_expire_name(state, height, params);
        let lifecycle = name_lifecycle(state, height, params);
        let valid_state = matches!(
            lifecycle,
            NameLifecycleState::Opening | NameLifecycleState::Locked
        ) || (lifecycle == NameLifecycleState::Closed && !state.registered);
        if !valid_state {
            return Err(StateError::ClaimVerification(format!(
                "claim cannot replace name in {lifecycle:?} state"
            )));
        }
        if state.expired || !is_reserved(&claim.name_hash, height, params) {
            return Err(StateError::ClaimVerification(
                "claim targets an expired or non-reserved name".to_owned(),
            ));
        }
        if services.name_flags.contains(NameFlags::HARDENED) && claim.weak {
            return Err(StateError::ClaimVerification(
                "hardened covenant rules reject weak claim keys".to_owned(),
            ));
        }

        let committed = context.main_chain_height(&BlockHash::new(claim.commit_hash))?;
        if committed != Some(claim.commit_height) || claim.commit_height <= state.claimed {
            return Err(StateError::ClaimVerification(
                "claim commit is not a newer active-chain ancestor".to_owned(),
            ));
        }

        if height >= services.network.params().deflation_height {
            if state.owner.is_null() && claim.commit_height != 1 {
                return Err(StateError::ClaimVerification(
                    "initial post-deflation claim must commit to height 1".to_owned(),
                ));
            }
            if !state.owner.is_null()
                && height < state.height.saturating_add(params.claim_frequency)
            {
                return Err(StateError::ClaimVerification(
                    "replacement claim violates claim-frequency limit".to_owned(),
                ));
            }
            if !state.owner.is_null() {
                let previous = load_existing_coin(snapshot, &state.owner)?;
                if output.value != previous.value {
                    return Err(StateError::ClaimVerification(
                        "replacement claim changes its post-deflation output value".to_owned(),
                    ));
                }
            }
        }

        state.height = height;
        state.renewal = height;
        state.claimed = claim.commit_height;
        state.value = 0;
        state.owner = Outpoint {
            txid: transaction_id,
            index: u32::try_from(authenticated.output_index).map_err(|_| {
                StateError::ClaimVerification("claim output index exceeds u32".to_owned())
            })?,
        };
        state.highest = 0;
        state.weak = claim.weak;
        changes.changed.insert(claim.name_hash);
    }
    Ok(())
}

/// Validate an ordinary mempool candidate against the durable active name
/// state plus all previously accepted name-covenant transactions. The overlay
/// is replayed in caller-supplied admission order and never mutates storage.
/// Claims remain restricted to the dedicated coinbase issuance path.
pub fn verify_mempool_name_context<T: ReadSnapshot>(
    snapshot: &T,
    accepted_name_transactions: &[&Transaction],
    candidate: &Transaction,
    height: Height,
    network: Network,
    name_flags: NameFlags,
) -> Result<(), StateError> {
    let input_verifier = RejectUnverifiedInputs;
    let issuance_verifier = RejectSpecialCoinbaseIssuance;
    let services = StateServices {
        network,
        name_flags,
        name_flags_valid: true,
        historical_validation: HistoricalValidationPlan::full(),
        input_verifier: &input_verifier,
        issuance_verifier: &issuance_verifier,
    };
    let context = SnapshotChainContext::new(snapshot, height, HistoricalValidationPlan::full());
    let mut changes = NameStateChanges::default();
    for transaction in accepted_name_transactions {
        apply_transaction_name_covenants(
            snapshot,
            transaction,
            height,
            services,
            &context,
            &mut changes,
            false,
        )?;
    }
    apply_transaction_name_covenants(
        snapshot,
        candidate,
        height,
        services,
        &context,
        &mut changes,
        false,
    )
}

/// Validate one authenticated DNSSEC claim against the immutable active-chain
/// name state and canonical commit ancestry. This deliberately reuses the
/// exact claim transition applied during block connection; the synthetic
/// transaction is discarded after validation and never reaches storage.
pub fn verify_mempool_claim_context<T: ReadSnapshot>(
    snapshot: &T,
    output: &hns_primitives::Output,
    claim: &VerifiedClaim,
    height: Height,
    network: Network,
    name_flags: NameFlags,
) -> Result<(), StateError> {
    let input_verifier = RejectUnverifiedInputs;
    let issuance_verifier = RejectSpecialCoinbaseIssuance;
    let services = StateServices {
        network,
        name_flags,
        name_flags_valid: true,
        historical_validation: HistoricalValidationPlan::full(),
        input_verifier: &input_verifier,
        issuance_verifier: &issuance_verifier,
    };
    let context = SnapshotChainContext::new(snapshot, height, HistoricalValidationPlan::full());
    let transaction = Transaction {
        version: 0,
        inputs: Vec::new(),
        outputs: vec![output.clone()],
        locktime: height,
    };
    let claims = [CoinbaseClaim {
        output_index: 0,
        claim: claim.clone(),
    }];
    let mut changes = NameStateChanges::default();
    apply_verified_claims(
        snapshot,
        &transaction,
        height,
        services,
        &context,
        &mut changes,
        &claims,
    )
}

fn apply_transaction_name_covenants<T: ReadSnapshot>(
    snapshot: &T,
    transaction: &Transaction,
    height: Height,
    services: StateServices<'_>,
    context: &SnapshotChainContext<'_, T>,
    changes: &mut NameStateChanges,
    allow_verified_claims: bool,
) -> Result<(), StateError> {
    for (output_index, output) in transaction.outputs.iter().enumerate() {
        if !output.covenant.kind.is_name() {
            continue;
        }
        if output.covenant.kind == CovenantKind::Claim {
            if allow_verified_claims {
                continue;
            }
            return Err(StateError::UnsupportedCoinbaseIssuance);
        }
        if !services.name_flags_valid {
            return Err(StateError::DeploymentStateUnavailable);
        }
        if context.is_historical_height(height)
            && matches!(
                output.covenant.kind,
                CovenantKind::Bid | CovenantKind::Redeem
            )
        {
            continue;
        }
        let bytes = output
            .covenant
            .item(0)
            .and_then(|item| <[u8; 32]>::try_from(item).ok())
            .ok_or_else(|| StateError::ContextualCovenant("invalid name hash".to_owned()))?;
        let name_hash = NameHash::new(bytes);

        if let Entry::Vacant(entry) = changes.current.entry(name_hash) {
            let loaded = load_name_state(snapshot, &name_hash)?;
            changes
                .previous
                .entry(name_hash)
                .or_insert_with(|| loaded.clone());
            entry.insert(loaded.unwrap_or_else(|| NameState::null(name_hash)));
        }
        let state = changes
            .current
            .get_mut(&name_hash)
            .ok_or_else(|| StateError::Codec("name cache insertion failed".to_owned()))?;
        let mutation = verify_and_apply_name_covenant(
            transaction,
            output_index,
            height,
            services.network.params().names,
            services.name_flags,
            state,
            context,
        )?;
        if mutation.changed() {
            changes.changed.insert(name_hash);
        }
    }
    Ok(())
}

fn stage_transaction_spends<B: WriteBatch>(
    batch: &mut B,
    pending_created: &mut HashMap<Outpoint, Coin>,
    created_coins: &mut Vec<Outpoint>,
    spent_coins: &mut Vec<Coin>,
    resolved: ResolvedInputs,
) -> Result<(), StateError> {
    if resolved.coins.len() != resolved.sources.len() {
        return Err(StateError::Codec(
            "resolved input coin/source count mismatch".to_owned(),
        ));
    }
    for (coin, source) in resolved.coins.into_iter().zip(resolved.sources) {
        match source {
            ResolvedCoinSource::Pending => {
                pending_created.remove(&coin.outpoint);
                batch.delete(ColumnFamily::Utxo, &encode_outpoint_key(&coin.outpoint))?;
                created_coins.retain(|outpoint| outpoint != &coin.outpoint);
            }
            ResolvedCoinSource::Existing => {
                batch.delete(ColumnFamily::Utxo, &encode_outpoint_key(&coin.outpoint))?;
                spent_coins.push(coin);
            }
        }
    }
    Ok(())
}

fn transaction_output_value(transaction: &Transaction) -> Result<Amount, StateError> {
    transaction.outputs.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value)
            .ok_or(StateError::OutputValueOverflow)
    })
}

fn load_airdrop_field<T: ReadSnapshot>(snapshot: &T) -> Result<Vec<u8>, StateError> {
    let field = snapshot
        .get(ColumnFamily::Meta, MetaKey::AirdropField.as_bytes())?
        .ok_or(StateError::MissingAirdropField)?;
    if field.len() != AIRDROP_FIELD_BYTES {
        return Err(StateError::InvalidAirdropFieldLength(field.len()));
    }
    Ok(field)
}

fn airdrop_mask(position: u32) -> Result<(usize, u8), StateError> {
    if position >= AIRDROP_TREE_LEAVES {
        return Err(StateError::AirdropPositionOutOfRange(position));
    }
    let position =
        usize::try_from(position).map_err(|_| StateError::AirdropPositionOutOfRange(position))?;
    Ok((position >> 3, 1 << (7 - (position & 7))))
}

/// Read one allocation bit from the immutable active-chain snapshot. This is
/// the storage-backed half of special airdrop mempool admission; the pool owns
/// a second in-memory position index for unconfirmed proofs.
pub fn airdrop_position_spent<T: ReadSnapshot>(
    snapshot: &T,
    position: u32,
) -> Result<bool, StateError> {
    let field = load_airdrop_field(snapshot)?;
    let (byte, mask) = airdrop_mask(position)?;
    Ok(field[byte] & mask != 0)
}

fn stage_airdrop_positions<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    positions: &[u32],
) -> Result<(), StateError> {
    if positions.is_empty() {
        return Ok(());
    }
    let mut field = load_airdrop_field(snapshot)?;
    for position in positions {
        let (byte, mask) = airdrop_mask(*position)?;
        if field[byte] & mask != 0 {
            return Err(StateError::AirdropAlreadySpent(*position));
        }
        field[byte] |= mask;
    }
    batch.put(ColumnFamily::Meta, MetaKey::AirdropField.as_bytes(), &field)?;
    Ok(())
}

fn undo_airdrop_positions<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    positions: &[u32],
) -> Result<(), StateError> {
    if positions.is_empty() {
        return Ok(());
    }
    let mut field = load_airdrop_field(snapshot)?;
    for position in positions {
        let (byte, mask) = airdrop_mask(*position)?;
        if field[byte] & mask == 0 {
            return Err(StateError::UndoAirdropPositionNotSpent(*position));
        }
        field[byte] &= !mask;
    }
    batch.put(ColumnFamily::Meta, MetaKey::AirdropField.as_bytes(), &field)?;
    Ok(())
}

fn load_existing_coin<T: ReadSnapshot>(
    snapshot: &T,
    outpoint: &Outpoint,
) -> Result<Coin, StateError> {
    let Some(bytes) = snapshot.get(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))? else {
        return Err(StateError::MissingCoin(outpoint.clone()));
    };
    let coin = decode_coin(&bytes)?;
    if coin.outpoint != *outpoint {
        return Err(StateError::Codec(
            "coin payload does not match its UTXO key".to_owned(),
        ));
    }
    Ok(coin)
}

fn check_coinbase_maturity(
    coin: &Coin,
    spend_height: Height,
    coinbase_maturity: u32,
) -> Result<(), StateError> {
    if coin.coinbase
        && spend_height
            .checked_sub(coin.height)
            .is_none_or(|depth| depth < coinbase_maturity)
    {
        return Err(StateError::PrematureCoinbaseSpend {
            coin_height: coin.height,
            spend_height,
            required_depth: coinbase_maturity,
        });
    }
    Ok(())
}

struct SnapshotChainContext<'a, T: ReadSnapshot> {
    snapshot: &'a T,
    candidate_height: Height,
    historical_validation: HistoricalValidationPlan,
    headers_by_height: RefCell<HashMap<Height, Option<HeaderRecord>>>,
    median_times: RefCell<HashMap<Height, u64>>,
}

impl<'a, T: ReadSnapshot> SnapshotChainContext<'a, T> {
    fn new(
        snapshot: &'a T,
        candidate_height: Height,
        historical_validation: HistoricalValidationPlan,
    ) -> Self {
        Self {
            snapshot,
            candidate_height,
            historical_validation,
            headers_by_height: RefCell::new(HashMap::new()),
            median_times: RefCell::new(HashMap::new()),
        }
    }

    fn header_at(&self, height: Height) -> Result<Option<HeaderRecord>, StateError> {
        if let Some(cached) = self.headers_by_height.borrow().get(&height) {
            return Ok(cached.clone());
        }
        let Some(hash) = read_canonical_hash(self.snapshot, height)? else {
            self.headers_by_height.borrow_mut().insert(height, None);
            return Ok(None);
        };
        let Some(bytes) = self.snapshot.get(ColumnFamily::Headers, hash.as_bytes())? else {
            return Err(StateError::ChainView(format!(
                "canonical height {height} points to a missing header"
            )));
        };
        let record = HeaderRecord::decode(&bytes)?;
        if record.hash != hash || record.height != height {
            return Err(StateError::ChainView(format!(
                "canonical header payload disagrees with height {height}"
            )));
        }
        self.headers_by_height
            .borrow_mut()
            .insert(height, Some(record.clone()));
        Ok(Some(record))
    }

    fn median_time_past(&self, height: Height) -> Result<u64, StateError> {
        if let Some(cached) = self.median_times.borrow().get(&height) {
            return Ok(*cached);
        }
        let mut times = Vec::with_capacity(MEDIAN_TIMESPAN);
        let mut cursor = height;
        for _ in 0..MEDIAN_TIMESPAN {
            let Some(record) = self.header_at(cursor)? else {
                break;
            };
            times.push(record.header.time);
            if cursor == 0 {
                break;
            }
            cursor -= 1;
        }
        if times.is_empty() {
            return Err(StateError::ChainView(format!(
                "cannot calculate median time past at height {height}"
            )));
        }
        times.sort_unstable();
        let median = times[times.len() / 2];
        self.median_times.borrow_mut().insert(height, median);
        Ok(median)
    }

    fn block_time(&self, height: Height) -> Result<u64, StateError> {
        self.header_at(height)?
            .map(|record| record.header.time)
            .ok_or_else(|| {
                StateError::ChainView(format!(
                    "cannot load canonical block time at height {height}"
                ))
            })
    }
}

impl<T: ReadSnapshot> NameContext for SnapshotChainContext<'_, T> {
    fn main_chain_height(&self, hash: &BlockHash) -> Result<Option<Height>, ConsensusError> {
        let Some(bytes) = self
            .snapshot
            .get(ColumnFamily::Headers, hash.as_bytes())
            .map_err(|error| ConsensusError::View(error.to_string()))?
        else {
            return Ok(None);
        };
        let record = HeaderRecord::decode(&bytes)
            .map_err(|error| ConsensusError::View(error.to_string()))?;
        let canonical = read_canonical_hash(self.snapshot, record.height)
            .map_err(|error| ConsensusError::View(error.to_string()))?;
        Ok((canonical == Some(*hash)).then_some(record.height))
    }

    fn is_historical_height(&self, height: Height) -> bool {
        height == self.candidate_height
            && self.historical_validation.historical
            && !self.historical_validation.bid_redeem_context
    }
}

struct TransactionSequenceView<'a, T: ReadSnapshot> {
    heights: HashMap<Outpoint, Height>,
    chain: &'a SnapshotChainContext<'a, T>,
}

impl<'a, T: ReadSnapshot> TransactionSequenceView<'a, T> {
    fn new(coins: &[Coin], chain: &'a SnapshotChainContext<'a, T>) -> Self {
        let heights = coins
            .iter()
            .map(|coin| (coin.outpoint.clone(), coin.height))
            .collect();
        Self { heights, chain }
    }
}

impl<T: ReadSnapshot> SequenceLockView for TransactionSequenceView<'_, T> {
    fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
        Ok(self.heights.get(outpoint).copied())
    }

    fn median_time_past(&self, height: Height) -> Result<u64, ConsensusError> {
        self.chain
            .median_time_past(height)
            .map_err(|error| ConsensusError::View(error.to_string()))
    }
}

pub fn disconnect_block_to_batch<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    request: DisconnectBlock,
    undo: &BlockUndo,
) -> Result<StateSummary, StateError> {
    if undo.block_hash != request.block_hash {
        return Err(StateError::UndoBlockMismatch {
            expected: request.block_hash,
            actual: undo.block_hash,
        });
    }
    if undo.height != request.height {
        return Err(StateError::UndoHeightMismatch {
            expected: request.height,
            actual: undo.height,
        });
    }

    let current_tree_root = load_stored_name_tree_root(snapshot)?;
    validate_persisted_name_tree_root(snapshot, current_tree_root)?;
    if current_tree_root != undo.resulting_tree_root {
        return Err(StateError::UndoResultingTreeRootMismatch {
            expected: undo.resulting_tree_root,
            actual: current_tree_root,
        });
    }
    let current_committed_tree_root = load_stored_name_tree_commit_root(snapshot)?;
    validate_persisted_name_tree_root(snapshot, current_committed_tree_root)?;
    if current_committed_tree_root != undo.resulting_committed_tree_root {
        return Err(StateError::UndoResultingCommittedTreeRootMismatch {
            expected: undo.resulting_committed_tree_root,
            actual: current_committed_tree_root,
        });
    }

    for outpoint in &undo.created_coins {
        batch.delete(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))?;
    }
    for coin in &undo.spent_coins {
        batch.put(
            ColumnFamily::Utxo,
            &encode_outpoint_key(&coin.outpoint),
            &encode_coin(coin),
        )?;
    }
    undo_airdrop_positions(snapshot, batch, &undo.airdrop_positions)?;
    for name_undo in &undo.previous_name_states {
        match &name_undo.previous {
            Some(state) => write_name_state_to_batch(batch, state)?,
            None => batch.delete(ColumnFamily::NameState, name_undo.name_hash.as_bytes())?,
        }
    }
    let current_accumulator = load_name_tree_accumulator(snapshot)?;
    if undo.name_tree_interval_boundary {
        if current_accumulator.is_some() {
            return Err(StateError::Codec(
                "interval-boundary disconnect found a post-boundary accumulator".to_owned(),
            ));
        }
        match &undo.previous_name_tree_accumulator {
            Some(accumulator) => {
                if accumulator.base_root != undo.previous_committed_tree_root
                    || accumulator.last_height >= undo.height
                {
                    return Err(StateError::Codec(
                        "boundary undo contains an invalid previous name-tree accumulator"
                            .to_owned(),
                    ));
                }
                batch.put(
                    ColumnFamily::Snapshots,
                    NAME_TREE_ACCUMULATOR_KEY,
                    &accumulator.encode()?,
                )?;
            }
            None => batch.delete(ColumnFamily::Snapshots, NAME_TREE_ACCUMULATOR_KEY)?,
        }
    } else {
        if undo.previous_name_tree_accumulator.is_some() {
            return Err(StateError::Codec(
                "non-boundary undo unexpectedly contains a previous name-tree accumulator"
                    .to_owned(),
            ));
        }
        if undo.previous_tree_root != undo.resulting_tree_root
            || undo.previous_committed_tree_root != undo.resulting_committed_tree_root
            || undo.previous_tree_root != undo.previous_committed_tree_root
        {
            return Err(StateError::Codec(
                "non-boundary undo changes an authenticated name-tree root".to_owned(),
            ));
        }
        let mut accumulator = current_accumulator.ok_or_else(|| {
            StateError::Codec(
                "non-boundary disconnect is missing its name-tree accumulator".to_owned(),
            )
        })?;
        if accumulator.base_root != undo.previous_committed_tree_root
            || accumulator.last_height != undo.height
        {
            return Err(StateError::Codec(
                "non-boundary disconnect found a mismatched name-tree accumulator".to_owned(),
            ));
        }
        for name_undo in &undo.previous_name_states {
            match accumulator.names.entry(name_undo.name_hash) {
                Entry::Occupied(mut entry) if *entry.get() > 1 => {
                    *entry.get_mut() -= 1;
                }
                Entry::Occupied(entry) => {
                    entry.remove();
                }
                Entry::Vacant(_) => {
                    return Err(StateError::Codec(
                        "name-tree accumulator is missing a disconnected block name".to_owned(),
                    ));
                }
            }
        }
        if let Some(previous_last_height) = undo.previous_name_tree_accumulator_last_height {
            if previous_last_height >= undo.height
                || previous_last_height < accumulator.first_height
            {
                return Err(StateError::Codec(
                    "non-boundary undo contains an invalid prior accumulator height".to_owned(),
                ));
            }
            accumulator.last_height = previous_last_height;
            batch.put(
                ColumnFamily::Snapshots,
                NAME_TREE_ACCUMULATOR_KEY,
                &accumulator.encode()?,
            )?;
        } else {
            batch.delete(ColumnFamily::Snapshots, NAME_TREE_ACCUMULATOR_KEY)?;
        }
    }
    let restored_tree_root = undo.previous_tree_root;
    validate_persisted_name_tree_root(snapshot, restored_tree_root)?;
    batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeRoot.as_bytes(),
        restored_tree_root.as_bytes(),
    )?;
    validate_persisted_name_tree_root(snapshot, undo.previous_committed_tree_root)?;
    batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeCommitRoot.as_bytes(),
        undo.previous_committed_tree_root.as_bytes(),
    )?;
    stage_remove_name_tree_snapshot_pin(snapshot, batch, undo)?;
    batch.delete(ColumnFamily::Undo, request.block_hash.as_bytes())?;

    Ok(StateSummary {
        coins_created: undo.spent_coins.len(),
        coins_spent: undo.created_coins.len(),
        names_changed: undo.previous_name_states.len(),
        inherited_tree_root: current_tree_root,
        resulting_tree_root: restored_tree_root,
        inherited_committed_tree_root: current_committed_tree_root,
        resulting_committed_tree_root: undo.previous_committed_tree_root,
        historical_validation: HistoricalValidationPlan::full(),
        validation: StateValidationSummary {
            name_state_connected: true,
            tree_root_valid: true,
            ..StateValidationSummary::default()
        },
    })
}

pub fn encode_outpoint_key(outpoint: &Outpoint) -> Vec<u8> {
    let mut writer = Writer::with_capacity(OUTPOINT_KEY_SIZE);
    outpoint.write_to(&mut writer);
    writer.finish()
}

pub fn write_coin_to_batch<B: WriteBatch>(batch: &mut B, coin: &Coin) -> Result<(), StateError> {
    batch.put(
        ColumnFamily::Utxo,
        &encode_outpoint_key(&coin.outpoint),
        &encode_coin(coin),
    )?;
    Ok(())
}

pub fn write_name_state_to_batch<B: WriteBatch>(
    batch: &mut B,
    state: &NameState,
) -> Result<(), StateError> {
    if state.is_null() {
        batch.delete(ColumnFamily::NameState, state.name_hash.as_bytes())?;
        return Ok(());
    }
    batch.put(
        ColumnFamily::NameState,
        state.name_hash.as_bytes(),
        &encode_name_state(state)?,
    )?;
    Ok(())
}

/// Rebuild the exact authenticated name-tree root from the durable NameState
/// column family using the pinned HSD/Urkel hashing rules. This intentionally
/// O(number of names) path is the independent startup and differential-test
/// oracle; steady-state transitions use path-local content-addressed mutation.
pub fn rebuild_name_tree_root<T: ReadSnapshot>(snapshot: &T) -> Result<TreeRoot, StateError> {
    rebuild_name_tree_root_with_overrides(snapshot, &BTreeMap::new())
}

/// Materialize the exact authenticated tree represented by one immutable
/// durable snapshot. This correctness-first path remains O(number of names)
/// and independent from steady-state incremental mutation.
pub fn materialize_name_tree<T: ReadSnapshot>(snapshot: &T) -> Result<MemoryUrkel, StateError> {
    materialize_name_tree_with_overrides(snapshot, &BTreeMap::new())
}

/// Rebuild the authenticated name-tree root from one immutable base snapshot
/// plus an explicit set of staged name-state replacements. This keeps root
/// calculation independent of whether a particular WriteBatch implementation
/// offers read-your-writes semantics.
pub fn rebuild_name_tree_root_with_overrides<T: ReadSnapshot>(
    snapshot: &T,
    overrides: &BTreeMap<NameHash, Option<NameState>>,
) -> Result<TreeRoot, StateError> {
    Ok(materialize_name_tree_with_overrides(snapshot, overrides)?.root())
}

fn materialize_name_tree_with_overrides<T: ReadSnapshot>(
    snapshot: &T,
    overrides: &BTreeMap<NameHash, Option<NameState>>,
) -> Result<MemoryUrkel, StateError> {
    let mut entries = BTreeMap::<NameHash, Vec<u8>>::new();
    for (key, value) in snapshot.scan_prefix(ColumnFamily::NameState, b"")? {
        let key: [u8; 32] = key.try_into().map_err(|key: Vec<u8>| {
            StateError::Codec(format!(
                "name-state key must contain 32 bytes, got {}",
                key.len()
            ))
        })?;
        let name_hash = NameHash::new(key);
        let state = decode_name_state(&name_hash, &value)?;
        if state.is_null() {
            return Err(StateError::Codec(
                "null NameState must not be persisted in the authenticated tree".to_owned(),
            ));
        }
        entries.insert(name_hash, value);
    }

    for (name_hash, state) in overrides {
        match state {
            Some(state) if !state.is_null() => {
                if state.name_hash != *name_hash {
                    return Err(StateError::Codec(
                        "name-tree override key does not match its state".to_owned(),
                    ));
                }
                entries.insert(*name_hash, encode_name_state(state)?);
            }
            Some(_) | None => {
                entries.remove(name_hash);
            }
        }
    }

    MemoryUrkel::from_entries(entries).map_err(StateError::NameTree)
}

/// Mutate only affected paths from `root` and stage newly constructed
/// content-addressed records in the same state batch. Existing records must be
/// byte-identical; conflicting bytes under an authenticated key are durable
/// corruption.
fn stage_name_tree_with_overrides<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    root: TreeRoot,
    overrides: &BTreeMap<NameHash, Option<NameState>>,
) -> Result<TreeRoot, StateError> {
    const MUTATION_MULTI_GET_THRESHOLD: usize = 2;
    const MUTATION_READ_BATCH: usize = 1_024;

    if overrides.is_empty() {
        return Ok(root);
    }

    let mut mutations = Vec::with_capacity(overrides.len());
    for (name_hash, state) in overrides {
        let value = match state {
            Some(state) if !state.is_null() => {
                if state.name_hash != *name_hash {
                    return Err(StateError::Codec(
                        "name-tree override key does not match its state".to_owned(),
                    ));
                }
                Some(encode_name_state(state)?)
            }
            Some(_) | None => None,
        };
        mutations.push((*name_hash, value));
    }

    let update = if mutations.len() >= MUTATION_MULTI_GET_THRESHOLD {
        update_record_tree_batched(root, mutations, MUTATION_READ_BATCH, |node_roots| {
            let keys = node_roots
                .iter()
                .map(|node_root| node_root.as_bytes().as_slice())
                .collect::<Vec<_>>();
            snapshot
                .get_many(ColumnFamily::NameTreeNodes, &keys)
                .map_err(|error| UrkelError::Storage(error.to_string()))
        })?
    } else {
        update_record_tree(root, mutations, |node_root| {
            load_persisted_node(snapshot, node_root)
        })?
    };
    let record_keys = update
        .records()
        .keys()
        .map(|node_root| node_root.as_bytes().as_slice())
        .collect::<Vec<_>>();
    let existing_records = snapshot.get_many(ColumnFamily::NameTreeNodes, &record_keys)?;
    if existing_records.len() != update.records().len() {
        return Err(StateError::Codec(format!(
            "name-tree multi-get returned {} records for {} keys",
            existing_records.len(),
            update.records().len()
        )));
    }
    for ((node_root, raw), existing) in update.records().iter().zip(existing_records) {
        match existing {
            Some(existing) if existing != *raw => {
                return Err(StateError::PersistedNodeConflict(*node_root));
            }
            Some(_) => {}
            None => batch.put(ColumnFamily::NameTreeNodes, node_root.as_bytes(), raw)?,
        }
    }
    Ok(update.root())
}

fn load_persisted_node<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
) -> Result<Option<Vec<u8>>, UrkelError> {
    snapshot
        .get(ColumnFamily::NameTreeNodes, root.as_bytes())
        .map_err(|error| UrkelError::Storage(error.to_string()))
}

/// Verify every unique content-addressed record reachable from the durable
/// root. The materialized `NameState` root must be checked separately (startup
/// does both) so neither representation can silently authorize the other.
pub fn validate_persisted_name_tree<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
) -> Result<usize, StateError> {
    validate_record_tree(root, |node_root| load_persisted_node(snapshot, node_root))
        .map_err(StateError::NameTree)
}

pub fn load_persisted_name_tree_records<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
) -> Result<BTreeMap<TreeRoot, Vec<u8>>, StateError> {
    let roots =
        reachable_record_roots([root], |node_root| load_persisted_node(snapshot, node_root))?;
    let mut records = BTreeMap::new();
    for node_root in roots {
        let raw = snapshot
            .get(ColumnFamily::NameTreeNodes, node_root.as_bytes())?
            .ok_or(UrkelError::MissingNode(node_root))?;
        records.insert(node_root, raw);
    }
    Ok(records)
}

/// Verify the reachable union of multiple durable content-addressed roots.
/// Shared historical subtrees are loaded once at each depth while preserving
/// the same canonical-record and path-depth checks as individual validation.
pub fn validate_persisted_name_trees<T, I>(snapshot: &T, roots: I) -> Result<usize, StateError>
where
    T: ReadSnapshot,
    I: IntoIterator<Item = TreeRoot>,
{
    const STARTUP_VALIDATION_BATCH: usize = 1_024;

    validate_record_trees_batched(roots, STARTUP_VALIDATION_BATCH, |node_roots| {
        let keys = node_roots
            .iter()
            .map(|root| root.as_bytes().as_slice())
            .collect::<Vec<_>>();
        snapshot
            .get_many(ColumnFamily::NameTreeNodes, &keys)
            .map_err(|error| UrkelError::Storage(error.to_string()))
    })
    .map_err(StateError::NameTree)
}

/// Validate only the content-addressed record directly bound by the current
/// root. This keeps steady-state transitions path-local; node startup performs
/// the full materialized-state and reachable-record validation.
pub fn validate_persisted_name_tree_root<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
) -> Result<(), StateError> {
    validate_record_root(root, |node_root| load_persisted_node(snapshot, node_root))
        .map_err(StateError::NameTree)
}

/// Generate one canonical HSD inclusion/non-inclusion proof by traversing only
/// the durable records on `name_hash`'s path from the supplied bound root.
pub fn prove_persisted_name_tree<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
    name_hash: NameHash,
) -> Result<UrkelProof, StateError> {
    prove_hsd_from_records(root, name_hash, |node_root| {
        load_persisted_node(snapshot, node_root)
    })
    .map_err(StateError::NameTree)
}

pub fn load_name_tree_accumulator<T: ReadSnapshot>(
    snapshot: &T,
) -> Result<Option<NameTreeAccumulator>, StateError> {
    snapshot
        .get(ColumnFamily::Snapshots, NAME_TREE_ACCUMULATOR_KEY)?
        .map(|raw| NameTreeAccumulator::decode(&raw))
        .transpose()
}

/// Upgrade the schema-16 per-block working-tree layout to the schema-17
/// interval accumulator. Legacy undo bytes are retained under a migration
/// prefix before their active records are rewritten, and the schema/profile
/// marker changes only after every undo chunk is durable. Re-entering after a
/// crash is idempotent.
pub fn migrate_name_tree_interval_accumulator<S: Store>(
    store: &S,
    tree_interval: Height,
) -> Result<Option<NameTreeIntervalMigrationSummary>, StateError> {
    if tree_interval == 0 {
        return Err(StateError::Codec(
            "network name-tree snapshot interval is zero".to_owned(),
        ));
    }

    let snapshot = store.snapshot()?;
    let Some(raw_schema) = snapshot.get(ColumnFamily::Meta, MetaKey::SchemaVersion.as_bytes())?
    else {
        return Ok(None);
    };
    let schema = decode_u32(&raw_schema)?;
    let profile = snapshot
        .get(ColumnFamily::Meta, MetaKey::StorageProfile.as_bytes())?
        .ok_or_else(|| {
            StateError::Codec("schema marker exists without a storage profile".to_owned())
        })?;
    if schema == SCHEMA_VERSION && profile.as_slice() == STORAGE_PROFILE {
        return Ok(None);
    }
    if schema != LEGACY_SCHEMA_VERSION || profile.as_slice() != LEGACY_STORAGE_PROFILE {
        return Err(StateError::Codec(format!(
            "cannot migrate schema/profile {schema}/{} to {SCHEMA_VERSION}/{}",
            String::from_utf8_lossy(&profile),
            String::from_utf8_lossy(STORAGE_PROFILE)
        )));
    }

    let original_working_root = load_stored_name_tree_root(&snapshot)?;
    let original_committed_root = load_stored_name_tree_commit_root(&snapshot)?;
    validate_persisted_name_tree_root(&snapshot, original_working_root)?;
    validate_persisted_name_tree_root(&snapshot, original_committed_root)?;
    let mut heights = snapshot.scan_prefix(ColumnFamily::HeightIndex, b"")?;
    heights.sort_by(|left, right| left.0.cmp(&right.0));
    drop(snapshot);

    // These small bindings are written first and never overwritten. They are
    // enough to identify and reverse the metadata cutover; each rewritten
    // legacy undo is backed up alongside them below.
    {
        let snapshot = store.snapshot()?;
        let backups = [
            (
                NAME_TREE_INTERVAL_MIGRATION_SCHEMA_KEY,
                raw_schema.as_slice(),
            ),
            (NAME_TREE_INTERVAL_MIGRATION_PROFILE_KEY, profile.as_slice()),
            (
                NAME_TREE_INTERVAL_MIGRATION_ROOT_KEY,
                original_working_root.as_bytes().as_slice(),
            ),
            (
                NAME_TREE_INTERVAL_MIGRATION_COMMIT_ROOT_KEY,
                original_committed_root.as_bytes().as_slice(),
            ),
        ];
        let mut batch = store.batch();
        for (key, expected) in backups {
            match snapshot.get(ColumnFamily::Snapshots, key)? {
                Some(existing) if existing.as_slice() != expected => {
                    return Err(StateError::Codec(
                        "name-tree interval migration backup conflicts with an existing value"
                            .to_owned(),
                    ));
                }
                Some(_) => {}
                None => batch.put(ColumnFamily::Snapshots, key, expected)?,
            }
        }
        batch.put(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes(), &[0])?;
        drop(snapshot);
        store.commit(batch)?;
    }

    let mut summary = NameTreeIntervalMigrationSummary {
        active_heights: heights.len(),
        ..NameTreeIntervalMigrationSummary::default()
    };
    let mut accumulator: Option<NameTreeAccumulator> = None;
    let mut previous_undo_height = None;
    let mut pending_batch = store.batch();
    let mut pending_writes = 0usize;

    for (height_key, hash_bytes) in &heights {
        let raw_height: [u8; 4] = height_key.as_slice().try_into().map_err(|_| {
            StateError::Codec(format!(
                "active height key contains {} bytes; expected 4",
                height_key.len()
            ))
        })?;
        let height = u32::from_be_bytes(raw_height);
        summary.tip_height = Some(height);
        let raw_hash: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            StateError::Codec(format!(
                "active height {height} contains a {}-byte block hash",
                hash_bytes.len()
            ))
        })?;
        let block_hash = BlockHash::new(raw_hash);
        let snapshot = store.snapshot()?;
        let Some(raw_undo) = snapshot.get(ColumnFamily::Undo, block_hash.as_bytes())? else {
            accumulator = None;
            previous_undo_height = None;
            continue;
        };
        let undo_version = raw_undo
            .get(..4)
            .and_then(|raw| raw.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| StateError::Codec("block undo version is truncated".to_owned()))?;
        let mut undo = BlockUndo::decode(&raw_undo)?;
        if undo.block_hash != block_hash || undo.height != height {
            return Err(StateError::Codec(format!(
                "active block undo disagrees with height {height}"
            )));
        }

        if previous_undo_height.and_then(|value: Height| value.checked_add(1)) != Some(height) {
            accumulator = None;
        }
        if accumulator
            .as_ref()
            .is_some_and(|pending| pending.base_root != undo.previous_committed_tree_root)
        {
            return Err(StateError::Codec(format!(
                "legacy name-tree interval root continuity breaks at height {height}"
            )));
        }

        let previous_accumulator = accumulator.clone();
        undo.previous_tree_root = undo.previous_committed_tree_root;
        undo.resulting_tree_root = undo.resulting_committed_tree_root;
        undo.name_tree_interval_boundary = height.is_multiple_of(tree_interval);
        undo.previous_name_tree_accumulator_last_height = previous_accumulator
            .as_ref()
            .map(|pending| pending.last_height);
        undo.previous_name_tree_accumulator = undo
            .name_tree_interval_boundary
            .then_some(previous_accumulator.clone())
            .flatten();

        if undo.name_tree_interval_boundary {
            accumulator = None;
        } else {
            let mut pending = previous_accumulator.unwrap_or_else(|| {
                NameTreeAccumulator::new(undo.previous_committed_tree_root, height)
            });
            pending.last_height = height;
            for name_undo in &undo.previous_name_states {
                let count = pending.names.entry(name_undo.name_hash).or_default();
                *count = count.checked_add(1).ok_or_else(|| {
                    StateError::Codec(
                        "migrated name-tree accumulator reference count overflowed".to_owned(),
                    )
                })?;
            }
            accumulator = Some(pending);
        }

        if undo_version == LEGACY_BLOCK_UNDO_VERSION {
            let mut backup_key = Vec::with_capacity(
                NAME_TREE_INTERVAL_MIGRATION_UNDO_PREFIX.len() + block_hash.as_bytes().len(),
            );
            backup_key.extend_from_slice(NAME_TREE_INTERVAL_MIGRATION_UNDO_PREFIX);
            backup_key.extend_from_slice(block_hash.as_bytes());
            match snapshot.get(ColumnFamily::Snapshots, &backup_key)? {
                Some(existing) if existing != raw_undo => {
                    return Err(StateError::Codec(format!(
                        "legacy undo migration backup conflicts at height {height}"
                    )));
                }
                Some(_) => {}
                None => {
                    pending_batch.put(ColumnFamily::Snapshots, &backup_key, &raw_undo)?;
                    pending_writes += 1;
                    summary.legacy_undos_backed_up += 1;
                }
            }
        }
        pending_batch.put(ColumnFamily::Undo, block_hash.as_bytes(), &undo.encode()?)?;
        pending_writes += 1;
        summary.undos_rewritten += 1;
        previous_undo_height = Some(height);
        drop(snapshot);

        if pending_writes >= NAME_TREE_INTERVAL_MIGRATION_BATCH {
            store.commit(pending_batch)?;
            pending_batch = store.batch();
            pending_writes = 0;
        }
    }
    if pending_writes != 0 {
        store.commit(pending_batch)?;
    }

    if let Some(tip_height) = summary.tip_height {
        if previous_undo_height != Some(tip_height) {
            return Err(StateError::Codec(
                "active tip is missing undo required for interval migration".to_owned(),
            ));
        }
        if tip_height.is_multiple_of(tree_interval) != accumulator.is_none() {
            return Err(StateError::Codec(
                "migrated name-tree accumulator disagrees with tip interval timing".to_owned(),
            ));
        }
    } else if original_working_root != TreeRoot::ZERO || original_committed_root != TreeRoot::ZERO {
        return Err(StateError::Codec(
            "empty legacy chain has a non-empty name-tree root".to_owned(),
        ));
    }
    if accumulator
        .as_ref()
        .is_some_and(|pending| pending.base_root != original_committed_root)
    {
        return Err(StateError::Codec(
            "migrated accumulator base does not match the durable committed root".to_owned(),
        ));
    }
    summary.pending_names = accumulator
        .as_ref()
        .map(|pending| pending.names.len())
        .unwrap_or(0);

    let mut final_batch = store.batch();
    final_batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeRoot.as_bytes(),
        original_committed_root.as_bytes(),
    )?;
    match accumulator {
        Some(accumulator) => final_batch.put(
            ColumnFamily::Snapshots,
            NAME_TREE_ACCUMULATOR_KEY,
            &accumulator.encode()?,
        )?,
        None => final_batch.delete(ColumnFamily::Snapshots, NAME_TREE_ACCUMULATOR_KEY)?,
    }
    final_batch.put(
        ColumnFamily::Meta,
        MetaKey::SchemaVersion.as_bytes(),
        &encode_u32(SCHEMA_VERSION),
    )?;
    final_batch.put(
        ColumnFamily::Meta,
        MetaKey::StorageProfile.as_bytes(),
        STORAGE_PROFILE,
    )?;
    final_batch.put(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes(), &[0])?;
    store.commit(final_batch)?;
    Ok(Some(summary))
}

pub fn name_tree_snapshot_pin_key(height: Height) -> Vec<u8> {
    let mut key = Vec::with_capacity(NAME_TREE_SNAPSHOT_PIN_PREFIX.len() + 4);
    key.extend_from_slice(NAME_TREE_SNAPSHOT_PIN_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

pub fn load_name_tree_snapshot_pins<T: ReadSnapshot>(
    snapshot: &T,
) -> Result<Vec<NameTreeSnapshotPin>, StateError> {
    let entries = snapshot.scan_prefix(ColumnFamily::Snapshots, NAME_TREE_SNAPSHOT_PIN_PREFIX)?;
    let mut pins = Vec::with_capacity(entries.len());
    for (key, raw) in entries {
        let pin = NameTreeSnapshotPin::decode(&raw)?;
        if key != name_tree_snapshot_pin_key(pin.height) {
            return Err(StateError::NameTreeSnapshotPinInvariant {
                height: pin.height,
                reason: "snapshot key does not match its encoded height".to_owned(),
            });
        }
        pins.push(pin);
    }
    Ok(pins)
}

fn stage_name_tree_snapshot_pin<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    pin: &NameTreeSnapshotPin,
) -> Result<(), StateError> {
    let key = name_tree_snapshot_pin_key(pin.height);
    let raw = pin.encode();
    match snapshot.get(ColumnFamily::Snapshots, &key)? {
        Some(existing) if existing != raw => {
            return Err(StateError::NameTreeSnapshotPinConflict { height: pin.height });
        }
        Some(_) => {}
        None => batch.put(ColumnFamily::Snapshots, &key, &raw)?,
    }
    Ok(())
}

/// Remove an interval snapshot pin when the matching undo record is retired.
///
/// The undo record is the rollback authority for that historical root, so
/// callers must delete both in the same durable batch.
pub fn stage_remove_name_tree_snapshot_pin<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    undo: &BlockUndo,
) -> Result<(), StateError> {
    let key = name_tree_snapshot_pin_key(undo.height);
    let Some(raw) = snapshot.get(ColumnFamily::Snapshots, &key)? else {
        return Ok(());
    };
    let pin = NameTreeSnapshotPin::decode(&raw)?;
    if pin.height != undo.height
        || pin.block_hash != undo.block_hash
        || pin.root != undo.resulting_committed_tree_root
    {
        return Err(StateError::NameTreeSnapshotPinInvariant {
            height: undo.height,
            reason: "disconnect target does not match the durable interval pin".to_owned(),
        });
    }
    batch.delete(ColumnFamily::Snapshots, &key)?;
    Ok(())
}

fn retained_name_tree_roots<T: ReadSnapshot>(
    snapshot: &T,
) -> Result<BTreeSet<TreeRoot>, StateError> {
    let current_root = load_stored_name_tree_root(snapshot)?;
    let committed_root = load_stored_name_tree_commit_root(snapshot)?;
    let mut roots = BTreeSet::from([current_root, committed_root]);
    let mut undos = BTreeMap::new();
    for (key, raw) in snapshot.scan_prefix(ColumnFamily::Undo, b"")? {
        let undo = BlockUndo::decode(&raw)?;
        if key.as_slice() != undo.block_hash.as_bytes() {
            return Err(StateError::Codec(
                "block undo key does not match its encoded block hash".to_owned(),
            ));
        }
        roots.insert(undo.previous_tree_root);
        roots.insert(undo.resulting_tree_root);
        roots.insert(undo.previous_committed_tree_root);
        roots.insert(undo.resulting_committed_tree_root);
        undos.insert(undo.block_hash, undo);
    }

    for pin in load_name_tree_snapshot_pins(snapshot)? {
        if let Some(undo) = undos.get(&pin.block_hash) {
            if undo.height != pin.height || undo.resulting_committed_tree_root != pin.root {
                return Err(StateError::NameTreeSnapshotPinInvariant {
                    height: pin.height,
                    reason: "pin disagrees with its block undo".to_owned(),
                });
            }
        } else {
            let active_hash = read_canonical_hash(snapshot, pin.height)?.ok_or_else(|| {
                StateError::NameTreeSnapshotPinInvariant {
                    height: pin.height,
                    reason: "pin has neither block undo nor an active height binding".to_owned(),
                }
            })?;
            if active_hash != pin.block_hash {
                return Err(StateError::NameTreeSnapshotPinInvariant {
                    height: pin.height,
                    reason: "pin block hash disagrees with the active height binding".to_owned(),
                });
            }
            let expected_root = match pin.height.checked_add(1) {
                Some(next_height) => match load_canonical_header(snapshot, next_height)? {
                    Some(next) => TreeRoot::new(next.header.tree_root),
                    None => committed_root,
                },
                None => committed_root,
            };
            if pin.root != expected_root {
                return Err(StateError::NameTreeSnapshotPinInvariant {
                    height: pin.height,
                    reason: "pin root disagrees with active-chain root timing".to_owned(),
                });
            }
        }
        roots.insert(pin.root);
    }
    Ok(roots)
}

fn load_canonical_header<T: ReadSnapshot>(
    snapshot: &T,
    height: Height,
) -> Result<Option<HeaderRecord>, StateError> {
    let Some(hash) = read_canonical_hash(snapshot, height)? else {
        return Ok(None);
    };
    let raw = snapshot
        .get(ColumnFamily::Headers, hash.as_bytes())?
        .ok_or(StateError::Chain(hns_chain::ChainError::MissingHeader(
            hash,
        )))?;
    let record = HeaderRecord::decode(&raw)?;
    if record.hash != hash || record.height != height {
        return Err(StateError::Codec(format!(
            "canonical header at height {height} disagrees with its index"
        )));
    }
    Ok(Some(record))
}

/// Validate every retained root before staging any deletion, then remove all
/// content-addressed records outside their reachable union. Callers commit the
/// supplied batch atomically with no concurrent state transition.
pub fn stage_name_tree_node_compaction<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
) -> Result<NameTreeCompactionSummary, StateError> {
    let retained_roots = retained_name_tree_roots(snapshot)?;
    let reachable = reachable_record_roots(retained_roots.iter().copied(), |node_root| {
        load_persisted_node(snapshot, node_root)
    })?;
    let entries = snapshot.scan_prefix(ColumnFamily::NameTreeNodes, b"")?;
    let mut stored = Vec::with_capacity(entries.len());
    for (key, _) in &entries {
        let root: [u8; 32] = key.as_slice().try_into().map_err(|_| {
            StateError::Codec(format!(
                "name-tree node key contains {} bytes; expected 32",
                key.len()
            ))
        })?;
        stored.push((key, TreeRoot::new(root)));
    }

    let mut nodes_deleted = 0usize;
    for (key, root) in stored {
        if !reachable.contains(&root) {
            batch.delete(ColumnFamily::NameTreeNodes, key)?;
            nodes_deleted += 1;
        }
    }
    let nodes_retained = entries.len().saturating_sub(nodes_deleted);
    if nodes_retained != reachable.len() {
        return Err(StateError::Codec(format!(
            "retained name-tree node count {nodes_retained} does not match reachable count {}",
            reachable.len()
        )));
    }
    Ok(NameTreeCompactionSummary {
        retained_roots: retained_roots.len(),
        nodes_before: entries.len(),
        nodes_retained,
        nodes_deleted,
    })
}

/// Validate retained roots first, then stream unreachable-node deletions in
/// bounded commits. Deleting unreachable content-addressed records is
/// monotonic garbage collection: a crash can leave extra nodes but cannot
/// remove a retained node. Callers write their completed-compaction checkpoint
/// only after this function returns.
pub fn compact_name_tree_nodes_streaming<S: Store>(
    store: &S,
    delete_batch_size: usize,
) -> Result<NameTreeCompactionSummary, StateError> {
    const REACHABILITY_READ_BATCH: usize = 1_024;

    if delete_batch_size == 0 {
        return Err(StateError::Codec(
            "name-tree compaction delete batch size must be non-zero".to_owned(),
        ));
    }

    let snapshot = store.snapshot()?;
    let retained_roots = retained_name_tree_roots(&snapshot)?;
    let reachable = reachable_record_roots_batched(
        retained_roots.iter().copied(),
        REACHABILITY_READ_BATCH,
        |node_roots| {
            let keys = node_roots
                .iter()
                .map(|root| root.as_bytes().as_slice())
                .collect::<Vec<_>>();
            snapshot
                .get_many(ColumnFamily::NameTreeNodes, &keys)
                .map_err(|error| UrkelError::Storage(error.to_string()))
        },
    )?;

    // Validate every durable key before the first mutation. Values are not
    // materialized, and the stable snapshot is reused for the deletion pass.
    let mut nodes_before = 0usize;
    let mut malformed_key_length = None;
    snapshot.visit_prefix(ColumnFamily::NameTreeNodes, b"", &mut |key, _value| {
        nodes_before = nodes_before.checked_add(1).ok_or_else(|| {
            StoreError::Backend("name-tree compaction node count overflowed".to_owned())
        })?;
        if key.len() != 32 && malformed_key_length.is_none() {
            malformed_key_length = Some(key.len());
        }
        Ok(())
    })?;
    if let Some(length) = malformed_key_length {
        return Err(StateError::Codec(format!(
            "name-tree node key contains {length} bytes; expected 32"
        )));
    }

    let mut delete_keys = Vec::with_capacity(delete_batch_size);
    let mut nodes_deleted = 0usize;
    snapshot.visit_prefix(ColumnFamily::NameTreeNodes, b"", &mut |key, _value| {
        let root = TreeRoot::new(
            key.try_into()
                .expect("name-tree keys were validated before deletion"),
        );
        if reachable.contains(&root) {
            return Ok(());
        }
        delete_keys.push(key.to_vec());
        nodes_deleted = nodes_deleted
            .checked_add(1)
            .ok_or_else(|| StoreError::Backend("name-tree deletion count overflowed".to_owned()))?;
        if delete_keys.len() == delete_batch_size {
            commit_name_tree_node_deletes(store, &mut delete_keys)?;
        }
        Ok(())
    })?;
    commit_name_tree_node_deletes(store, &mut delete_keys)?;

    let nodes_retained = nodes_before.saturating_sub(nodes_deleted);
    if nodes_retained != reachable.len() {
        return Err(StateError::Codec(format!(
            "retained name-tree node count {nodes_retained} does not match reachable count {}",
            reachable.len()
        )));
    }
    Ok(NameTreeCompactionSummary {
        retained_roots: retained_roots.len(),
        nodes_before,
        nodes_retained,
        nodes_deleted,
    })
}

fn commit_name_tree_node_deletes<S: Store>(
    store: &S,
    delete_keys: &mut Vec<Vec<u8>>,
) -> Result<(), StoreError> {
    if delete_keys.is_empty() {
        return Ok(());
    }
    let mut batch = store.batch();
    for key in delete_keys.drain(..) {
        batch.delete(ColumnFamily::NameTreeNodes, &key)?;
    }
    store.commit(batch)
}

/// Immutable exact-proof view rebuilt from one durable store snapshot after
/// checking its materialized root against the durable root binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedNameTreeSnapshot {
    root: TreeRoot,
    tree: MemoryUrkel,
}

impl MaterializedNameTreeSnapshot {
    pub const fn root(&self) -> TreeRoot {
        self.root
    }

    pub fn get(&self, name_hash: &NameHash) -> Option<&[u8]> {
        self.tree.get(name_hash)
    }

    pub fn prove(&self, name_hash: NameHash) -> Result<UrkelProof, UrkelError> {
        self.tree.prove_hsd(name_hash)
    }
}

impl NameTreeSnapshot for MaterializedNameTreeSnapshot {
    fn root(&self) -> TreeRoot {
        self.root
    }

    fn get(&self, name_hash: &NameHash) -> Result<Option<Vec<u8>>, UrkelError> {
        Ok(self.tree.get(name_hash).map(ToOwned::to_owned))
    }

    fn prove(&self, name_hash: &NameHash) -> Result<UrkelProof, UrkelError> {
        self.tree.prove_hsd(*name_hash)
    }
}

/// Build an immutable exact-proof view of the latest interval-committed tree.
/// Pending NameState changes deliberately remain outside this snapshot until
/// the next consensus tree boundary.
pub fn materialize_name_tree_snapshot<T: ReadSnapshot>(
    snapshot: &T,
) -> Result<MaterializedNameTreeSnapshot, StateError> {
    let stored = verify_stored_name_tree_root(snapshot)?;
    let tree =
        materialize_record_tree(stored, |node_root| load_persisted_node(snapshot, node_root))?;
    Ok(MaterializedNameTreeSnapshot { root: stored, tree })
}

/// Load the durable binding for the latest interval-committed name-state tree.
pub fn load_stored_name_tree_root<T: ReadSnapshot>(snapshot: &T) -> Result<TreeRoot, StateError> {
    let bytes = snapshot
        .get(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())?
        .ok_or(StateError::MissingStoredTreeRoot)?;
    let root: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StateError::InvalidStoredTreeRootLength(bytes.len()))?;
    Ok(TreeRoot::new(root))
}

/// Load the durable HSD interval-committed root used by block headers.
pub fn load_stored_name_tree_commit_root<T: ReadSnapshot>(
    snapshot: &T,
) -> Result<TreeRoot, StateError> {
    let bytes = snapshot
        .get(ColumnFamily::Meta, MetaKey::NameTreeCommitRoot.as_bytes())?
        .ok_or(StateError::MissingStoredTreeCommitRoot)?;
    let root: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StateError::InvalidStoredTreeCommitRootLength(bytes.len()))?;
    Ok(TreeRoot::new(root))
}

/// Verify the durable interval root binding and its content-addressed records.
/// When no interval accumulator exists, the NameState column must also match
/// the committed tree exactly. With pending changes, the node startup audit
/// validates accumulator/undo continuity separately.
pub fn verify_stored_name_tree_root<T: ReadSnapshot>(snapshot: &T) -> Result<TreeRoot, StateError> {
    let stored = load_stored_name_tree_root(snapshot)?;
    let committed = load_stored_name_tree_commit_root(snapshot)?;
    if stored != committed {
        return Err(StateError::StoredTreeRootMismatch {
            stored,
            actual: committed,
        });
    }
    validate_persisted_name_tree(snapshot, stored)?;
    match load_name_tree_accumulator(snapshot)? {
        Some(accumulator) if accumulator.base_root != stored => {
            return Err(StateError::Codec(
                "name-tree accumulator base root does not match the durable root".to_owned(),
            ));
        }
        Some(_) => {}
        None => {
            let actual = rebuild_name_tree_root(snapshot)?;
            if stored != actual {
                return Err(StateError::StoredTreeRootMismatch { stored, actual });
            }
        }
    }
    Ok(stored)
}

/// Exhaustively bind the current materialized NameState view, the pending
/// interval accumulator, canonical undo, and the latest committed root.
/// Startup calls this once; steady-state block admission remains path-local.
pub fn verify_name_tree_interval_state<T: ReadSnapshot>(
    snapshot: &T,
    tree_interval: Height,
    tip_height: Height,
) -> Result<TreeRoot, StateError> {
    if tree_interval == 0 {
        return Err(StateError::Codec(
            "network name-tree snapshot interval is zero".to_owned(),
        ));
    }
    let stored = load_stored_name_tree_root(snapshot)?;
    let committed = load_stored_name_tree_commit_root(snapshot)?;
    if stored != committed {
        return Err(StateError::StoredTreeRootMismatch {
            stored,
            actual: committed,
        });
    }

    let Some(accumulator) = load_name_tree_accumulator(snapshot)? else {
        if !tip_height.is_multiple_of(tree_interval) {
            return Err(StateError::Codec(format!(
                "active tip height {tip_height} is between tree intervals but has no accumulator"
            )));
        }
        let actual = rebuild_name_tree_root(snapshot)?;
        if stored != actual {
            return Err(StateError::StoredTreeRootMismatch { stored, actual });
        }
        return Ok(stored);
    };

    if tip_height.is_multiple_of(tree_interval) {
        return Err(StateError::Codec(format!(
            "tree-interval tip height {tip_height} unexpectedly has an accumulator"
        )));
    }
    let expected_first = tip_height
        .checked_sub(tip_height % tree_interval)
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| StateError::Codec("name-tree interval start overflowed".to_owned()))?;
    if accumulator.base_root != stored
        || accumulator.first_height != expected_first
        || accumulator.last_height != tip_height
    {
        return Err(StateError::Codec(
            "name-tree accumulator does not match the active tip interval".to_owned(),
        ));
    }

    let mut expected_counts = BTreeMap::<NameHash, u16>::new();
    let mut boundary_overrides = BTreeMap::<NameHash, Option<NameState>>::new();
    for height in expected_first..=tip_height {
        let hash = read_canonical_hash(snapshot, height)?.ok_or_else(|| {
            StateError::Codec(format!(
                "name-tree accumulator audit is missing canonical height {height}"
            ))
        })?;
        let raw = snapshot
            .get(ColumnFamily::Undo, hash.as_bytes())?
            .ok_or(StateError::MissingUndo(hash))?;
        let undo = BlockUndo::decode(&raw)?;
        if undo.block_hash != hash
            || undo.height != height
            || undo.name_tree_interval_boundary
            || undo.previous_name_tree_accumulator.is_some()
            || (height == expected_first
                && undo.previous_name_tree_accumulator_last_height.is_some())
            || (height > expected_first
                && undo.previous_name_tree_accumulator_last_height != height.checked_sub(1))
            || undo.previous_tree_root != stored
            || undo.resulting_tree_root != stored
            || undo.previous_committed_tree_root != stored
            || undo.resulting_committed_tree_root != stored
        {
            return Err(StateError::Codec(format!(
                "block undo at height {height} violates pending interval continuity"
            )));
        }
        for name_undo in &undo.previous_name_states {
            let count = expected_counts.entry(name_undo.name_hash).or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                StateError::Codec(
                    "name-tree accumulator audit reference count overflowed".to_owned(),
                )
            })?;
            boundary_overrides
                .entry(name_undo.name_hash)
                .or_insert_with(|| name_undo.previous.clone());
        }
    }
    if accumulator.names != expected_counts {
        return Err(StateError::Codec(
            "name-tree accumulator names disagree with canonical undo".to_owned(),
        ));
    }

    let actual = rebuild_name_tree_root_with_overrides(snapshot, &boundary_overrides)?;
    if stored != actual {
        return Err(StateError::StoredTreeRootMismatch { stored, actual });
    }
    Ok(stored)
}

pub fn encode_coin(coin: &Coin) -> Vec<u8> {
    let mut writer = Writer::with_capacity(COIN_CODEC_MAX);
    coin.outpoint.write_to(&mut writer);
    writer.write_u64(coin.value);
    writer.write_u32(coin.height);
    writer.write_u8(u8::from(coin.coinbase));
    coin.address.write_to(&mut writer);
    writer.write_varbytes(&coin.covenant.encode());
    writer.finish()
}

pub fn decode_coin(bytes: &[u8]) -> Result<Coin, StateError> {
    let mut reader = Reader::new(bytes, COIN_CODEC_MAX)?;
    let outpoint = Outpoint::read_from(&mut reader)?;
    let value = reader.read_u64()?;
    let height = reader.read_u32()?;
    let coinbase = match reader.read_u8()? {
        0 => false,
        1 => true,
        value => return Err(StateError::Codec(format!("invalid coinbase flag {value}"))),
    };
    let address = Address::read_from(&mut reader)?;
    let covenant = Covenant::decode(&reader.read_varbytes(MAX_TX_SIZE, "coin covenant")?)?;
    reader.ensure_finished()?;
    Ok(Coin {
        outpoint,
        value,
        height,
        coinbase,
        address,
        covenant,
    })
}

/// Encode exactly the value payload written by HSD's `NameState.write`. The
/// name hash is the authenticated-tree key and is deliberately not duplicated
/// in the value.
pub fn encode_name_state(state: &NameState) -> Result<Vec<u8>, StateError> {
    if state.name.len() > MAX_NAME_SIZE || state.name.len() > u8::MAX as usize {
        return Err(StateError::Codec(
            "name exceeds HNS name-state limit".to_owned(),
        ));
    }
    if state.data.len() > MAX_RESOURCE_SIZE || state.data.len() > u16::MAX as usize {
        return Err(StateError::Codec(
            "name resource exceeds HNS name-state limit".to_owned(),
        ));
    }

    let mut field = 0u16;
    if !state.owner.is_null() {
        field |= 1 << 0;
    }
    if state.value != 0 {
        field |= 1 << 1;
    }
    if state.highest != 0 {
        field |= 1 << 2;
    }
    if state.transfer != 0 {
        field |= 1 << 3;
    }
    if state.revoked != 0 {
        field |= 1 << 4;
    }
    if state.claimed != 0 {
        field |= 1 << 5;
    }
    if state.renewals != 0 {
        field |= 1 << 6;
    }
    if state.registered {
        field |= 1 << 7;
    }
    if state.expired {
        field |= 1 << 8;
    }
    if state.weak {
        field |= 1 << 9;
    }

    let mut writer = Writer::with_capacity(NAME_STATE_CODEC_MAX);
    writer.write_u8(state.name.len() as u8);
    writer.write_bytes(&state.name);
    writer.write_u16(state.data.len() as u16);
    writer.write_bytes(&state.data);
    writer.write_u32(state.height);
    writer.write_u32(state.renewal);
    writer.write_u16(field);
    if !state.owner.is_null() {
        writer.write_bytes(state.owner.txid.as_bytes());
        writer.write_varint(u64::from(state.owner.index));
    }
    if state.value != 0 {
        writer.write_varint(state.value);
    }
    if state.highest != 0 {
        writer.write_varint(state.highest);
    }
    if state.transfer != 0 {
        writer.write_u32(state.transfer);
    }
    if state.revoked != 0 {
        writer.write_u32(state.revoked);
    }
    if state.claimed != 0 {
        writer.write_u32(state.claimed);
    }
    if state.renewals != 0 {
        writer.write_varint(u64::from(state.renewals));
    }
    Ok(writer.finish())
}

pub fn decode_name_state(name_hash: &NameHash, bytes: &[u8]) -> Result<NameState, StateError> {
    let mut reader = Reader::new(bytes, NAME_STATE_CODEC_MAX)?;
    let name_length = usize::from(reader.read_u8()?);
    if name_length > MAX_NAME_SIZE {
        return Err(StateError::Codec(
            "encoded name exceeds HNS limit".to_owned(),
        ));
    }
    let name = reader.read_vec(name_length)?;
    let data_length = usize::from(reader.read_u16()?);
    if data_length > MAX_RESOURCE_SIZE {
        return Err(StateError::Codec(
            "encoded name resource exceeds HNS limit".to_owned(),
        ));
    }
    let data = reader.read_vec(data_length)?;
    let height = reader.read_u32()?;
    let renewal = reader.read_u32()?;
    let field = reader.read_u16()?;
    if field & !NAME_STATE_FIELD_MASK != 0 {
        return Err(StateError::Codec(format!(
            "name-state field contains unknown bits 0x{:04x}",
            field & !NAME_STATE_FIELD_MASK
        )));
    }

    let owner = if field & (1 << 0) != 0 {
        let txid = hns_primitives::Txid::new(reader.read_hash()?);
        let index = u32::try_from(reader.read_varint()?)
            .map_err(|_| StateError::Codec("name owner index exceeds u32".to_owned()))?;
        Outpoint { txid, index }
    } else {
        Outpoint::null()
    };
    let value = if field & (1 << 1) != 0 {
        reader.read_varint()?
    } else {
        0
    };
    let highest = if field & (1 << 2) != 0 {
        reader.read_varint()?
    } else {
        0
    };
    let transfer = if field & (1 << 3) != 0 {
        reader.read_u32()?
    } else {
        0
    };
    let revoked = if field & (1 << 4) != 0 {
        reader.read_u32()?
    } else {
        0
    };
    let claimed = if field & (1 << 5) != 0 {
        reader.read_u32()?
    } else {
        0
    };
    let renewals = if field & (1 << 6) != 0 {
        u32::try_from(reader.read_varint()?)
            .map_err(|_| StateError::Codec("name renewal count exceeds u32".to_owned()))?
    } else {
        0
    };
    reader.ensure_finished()?;

    Ok(NameState {
        name_hash: *name_hash,
        name,
        height,
        renewal,
        owner,
        value,
        highest,
        data,
        transfer,
        revoked,
        claimed,
        renewals,
        registered: field & (1 << 7) != 0,
        expired: field & (1 << 8) != 0,
        weak: field & (1 << 9) != 0,
    })
}

fn load_name_state<T: ReadSnapshot>(
    snapshot: &T,
    name_hash: &NameHash,
) -> Result<Option<NameState>, StateError> {
    let Some(bytes) = snapshot.get(ColumnFamily::NameState, name_hash.as_bytes())? else {
        return Ok(None);
    };
    decode_name_state(name_hash, &bytes).map(Some)
}

fn encode_name_undo(undo: &NameUndo) -> Result<Vec<u8>, StateError> {
    let mut writer = Writer::with_capacity(NAME_UNDO_CODEC_MAX);
    writer.write_bytes(undo.name_hash.as_bytes());
    match &undo.previous {
        Some(state) => {
            if state.name_hash != undo.name_hash {
                return Err(StateError::Codec(
                    "name undo key does not match previous state".to_owned(),
                ));
            }
            writer.write_u8(1);
            writer.write_varbytes(&encode_name_state(state)?);
        }
        None => writer.write_u8(0),
    }
    Ok(writer.finish())
}

fn decode_name_undo(bytes: &[u8]) -> Result<NameUndo, StateError> {
    let mut reader = Reader::new(bytes, NAME_UNDO_CODEC_MAX)?;
    let name_hash = NameHash::new(reader.read_hash()?);
    let previous = match reader.read_u8()? {
        0 => None,
        1 => {
            let bytes = reader.read_varbytes(NAME_STATE_CODEC_MAX, "previous name state")?;
            Some(decode_name_state(&name_hash, &bytes)?)
        }
        value => {
            return Err(StateError::Codec(format!(
                "invalid previous-name flag {value}"
            )))
        }
    };
    reader.ensure_finished()?;
    Ok(NameUndo {
        name_hash,
        previous,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state codec failed: {0}")]
    Codec(String),
    #[error("state store failed: {0}")]
    Store(#[from] StoreError),
    #[error("authenticated name-tree calculation failed: {0}")]
    NameTree(#[from] UrkelError),
    #[error("durable name-tree-root metadata is missing")]
    MissingStoredTreeRoot,
    #[error("durable name-tree-root metadata must contain 32 bytes, got {0}")]
    InvalidStoredTreeRootLength(usize),
    #[error("durable name-tree-commit-root metadata is missing")]
    MissingStoredTreeCommitRoot,
    #[error("durable name-tree-commit-root metadata must contain 32 bytes, got {0}")]
    InvalidStoredTreeCommitRootLength(usize),
    #[error("durable name-tree root {stored:?} does not match materialized name state {actual:?}")]
    StoredTreeRootMismatch { stored: TreeRoot, actual: TreeRoot },
    #[error("durable urkel node key {0:?} maps to conflicting record bytes")]
    PersistedNodeConflict(TreeRoot),
    #[error("name-tree snapshot pin at height {height} conflicts with the durable active pin")]
    NameTreeSnapshotPinConflict { height: Height },
    #[error("name-tree snapshot pin at height {height} violates its invariant: {reason}")]
    NameTreeSnapshotPinInvariant { height: Height, reason: String },
    #[error(
        "block header commits to name-tree root {committed:?}, but inherited state root is {inherited:?}"
    )]
    HeaderTreeRootMismatch {
        committed: TreeRoot,
        inherited: TreeRoot,
    },
    #[error(
        "undo expects current name-tree root {expected:?}, but the bound state root is {actual:?}"
    )]
    UndoResultingTreeRootMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
    #[error(
        "undo expects current committed name-tree root {expected:?}, but the durable commit root is {actual:?}"
    )]
    UndoResultingCommittedTreeRootMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
    #[error("undo restores name-tree root {actual:?}, but recorded previous root is {expected:?}")]
    UndoPreviousTreeRootMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
    #[error("chain index failed: {0}")]
    Chain(#[from] hns_chain::ChainError),
    #[error("consensus validation failed: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("chain view failed: {0}")]
    ChainView(String),
    #[error("input-authorization backend failed to initialize: {0}")]
    InputAuthorizationBackend(String),
    #[error("airdrop-signature backend failed to initialize: {0}")]
    AirdropSignatureBackend(String),
    #[error("missing coin for outpoint {0:?}")]
    MissingCoin(Outpoint),
    #[error("duplicate spend for outpoint {0:?}")]
    DuplicateSpend(Outpoint),
    #[error("transaction input {input_index} authorization failed: {reason}")]
    InputAuthorization { input_index: usize, reason: String },
    #[error("transaction relative sequence locks are not satisfied")]
    RelativeLocks,
    #[error("transaction covenant linkage failed: {0}")]
    CovenantLink(#[from] CovenantLinkError),
    #[error("contextual covenant validation failed: {0}")]
    ContextualCovenant(String),
    #[error("duplicate created coin for outpoint {0:?}")]
    DuplicateCoin(Outpoint),
    #[error("block has no coinbase transaction")]
    MissingCoinbase,
    #[error("deployment-derived name flags are unavailable for contextual covenant validation")]
    DeploymentStateUnavailable,
    #[error("state validation requires the exact full or canonical HSD checkpoint plan")]
    InvalidHistoricalValidationPlan,
    #[error("coinbase claim/airdrop issuance is disabled by the configured state service")]
    UnsupportedCoinbaseIssuance,
    #[error("airdrop issuance verification failed: {0}")]
    AirdropVerification(String),
    #[error("DNSSEC claim issuance verification failed: {0}")]
    ClaimVerification(String),
    #[error("durable airdrop allocation field is missing")]
    MissingAirdropField,
    #[error("durable airdrop allocation field must contain {AIRDROP_FIELD_BYTES} bytes, got {0}")]
    InvalidAirdropFieldLength(usize),
    #[error("airdrop allocation position {0} is outside the HSD field")]
    AirdropPositionOutOfRange(u32),
    #[error("airdrop allocation position {0} was already spent")]
    AirdropAlreadySpent(u32),
    #[error("airdrop undo position {0} is not currently spent")]
    UndoAirdropPositionNotSpent(u32),
    #[error("transaction input value overflow")]
    InputValueOverflow,
    #[error("transaction output value overflow")]
    OutputValueOverflow,
    #[error("block transaction fee total overflow")]
    FeeValueOverflow,
    #[error("block sigop count {actual} exceeds consensus maximum {maximum}")]
    BlockSigopsExceeded { actual: u32, maximum: u32 },
    #[error("block subsidy, fees, and verified issuance overflow")]
    CoinbaseRewardOverflow,
    #[error("coinbase value {coinbase} exceeds verified maximum {maximum}")]
    CoinbaseValueExceedsReward { coinbase: Amount, maximum: Amount },
    #[error("transaction input value {input} is below output value {output}")]
    InputValueBelowOutput { input: u64, output: u64 },
    #[error(
        "coinbase from height {coin_height} spent at {spend_height} before required depth {required_depth}"
    )]
    PrematureCoinbaseSpend {
        coin_height: Height,
        spend_height: Height,
        required_depth: u32,
    },
    #[error("missing undo data for block {0:?}")]
    MissingUndo(BlockHash),
    #[error("block hash mismatch: expected {expected:?}, got {actual:?}")]
    BlockHashMismatch {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("undo height mismatch: expected {expected}, got {actual}")]
    UndoHeightMismatch { expected: Height, actual: Height },
    #[error("undo block mismatch: expected {expected:?}, got {actual:?}")]
    UndoBlockMismatch {
        expected: BlockHash,
        actual: BlockHash,
    },
}

impl StateError {
    /// Whether this error proves the candidate block invalid against an
    /// otherwise valid parent-state snapshot. Storage, authenticated-tree,
    /// backend, chain-view, and undo failures are deliberately excluded so a
    /// local fault can never poison a peer branch.
    pub fn is_consensus_invalid(&self) -> bool {
        matches!(
            self,
            Self::HeaderTreeRootMismatch { .. }
                | Self::Consensus(_)
                | Self::MissingCoin(_)
                | Self::DuplicateSpend(_)
                | Self::InputAuthorization { .. }
                | Self::RelativeLocks
                | Self::CovenantLink(_)
                | Self::ContextualCovenant(_)
                | Self::DuplicateCoin(_)
                | Self::MissingCoinbase
                | Self::AirdropVerification(_)
                | Self::ClaimVerification(_)
                | Self::AirdropPositionOutOfRange(_)
                | Self::AirdropAlreadySpent(_)
                | Self::InputValueOverflow
                | Self::OutputValueOverflow
                | Self::FeeValueOverflow
                | Self::BlockSigopsExceeded { .. }
                | Self::CoinbaseRewardOverflow
                | Self::CoinbaseValueExceedsReward { .. }
                | Self::InputValueBelowOutput { .. }
                | Self::PrematureCoinbaseSpend { .. }
                | Self::BlockHashMismatch { .. }
        )
    }
}

impl From<PrimitiveError> for StateError {
    fn from(value: PrimitiveError) -> Self {
        Self::Codec(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
    };

    use hns_chain::{write_canonical_height_to_batch, BlockStatus, HeaderRecord};
    use hns_consensus::{reserved_name, ConsensusError, ThresholdState};
    use hns_primitives::{
        hash_name, Address, CovenantKind, Header, Input, Output, Txid, Uint256, Witness,
    };
    #[cfg(feature = "rocksdb-backend")]
    use hns_store::{open_store, DurabilityPolicy, StoreBackend, StoreConfig};
    use hns_store::{MemoryBatch, MemorySnapshot, MemoryStore, StagingOverlay, Store};

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct AllowAllInputVerifier;

    #[test]
    fn consensus_invalid_classifier_excludes_local_state_faults() {
        assert!(StateError::MissingCoin(Outpoint::null()).is_consensus_invalid());
        assert!(StateError::HeaderTreeRootMismatch {
            committed: TreeRoot::new([1; 32]),
            inherited: TreeRoot::new([2; 32]),
        }
        .is_consensus_invalid());
        assert!(!StateError::MissingStoredTreeRoot.is_consensus_invalid());
        assert!(!StateError::MissingStoredTreeCommitRoot.is_consensus_invalid());
        assert!(
            !StateError::ChainView("missing historical context".to_owned()).is_consensus_invalid()
        );
        assert!(
            !StateError::InputAuthorizationBackend("backend unavailable".to_owned())
                .is_consensus_invalid()
        );
    }

    struct NoNameStateScanSnapshot<S> {
        inner: S,
        name_node_reads: Cell<usize>,
        name_node_batches: Cell<usize>,
        maximum_name_node_batch: Cell<usize>,
        utxo_reads: Cell<usize>,
        utxo_batches: Cell<usize>,
        maximum_utxo_batch: Cell<usize>,
    }

    #[derive(Clone)]
    struct FailingCommitStore {
        inner: MemoryStore,
        fail_next_commit: Arc<AtomicBool>,
    }

    impl FailingCommitStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                fail_next_commit: Arc::new(AtomicBool::new(false)),
            }
        }

        fn fail_next_commit(&self) {
            self.fail_next_commit.store(true, Ordering::SeqCst);
        }
    }

    impl Store for FailingCommitStore {
        type Snapshot<'a> = MemorySnapshot;
        type Batch = MemoryBatch;

        fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
            self.inner.snapshot()
        }

        fn batch(&self) -> Self::Batch {
            self.inner.batch()
        }

        fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
            if self.fail_next_commit.swap(false, Ordering::SeqCst) {
                return Err(StoreError::Io("injected compaction failure".to_owned()));
            }
            self.inner.commit(batch)
        }
    }

    #[derive(Clone)]
    struct RecordingStore {
        inner: MemoryStore,
        committed_batch_sizes: Arc<Mutex<Vec<usize>>>,
    }

    impl RecordingStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::new(),
                committed_batch_sizes: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn take_committed_batch_sizes(&self) -> Vec<usize> {
            std::mem::take(
                &mut *self
                    .committed_batch_sizes
                    .lock()
                    .expect("recorded batches lock"),
            )
        }
    }

    impl Store for RecordingStore {
        type Snapshot<'a> = MemorySnapshot;
        type Batch = MemoryBatch;

        fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
            self.inner.snapshot()
        }

        fn batch(&self) -> Self::Batch {
            self.inner.batch()
        }

        fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
            self.committed_batch_sizes
                .lock()
                .expect("recorded batches lock")
                .push(batch.len());
            self.inner.commit(batch)
        }
    }

    #[cfg(feature = "rocksdb-backend")]
    struct ExitAfterCommitStore<S: Store> {
        inner: S,
        exit_after: usize,
        commits: Cell<usize>,
    }

    #[cfg(feature = "rocksdb-backend")]
    impl<S: Store> ExitAfterCommitStore<S> {
        fn new(inner: S, exit_after: usize) -> Self {
            Self {
                inner,
                exit_after,
                commits: Cell::new(0),
            }
        }
    }

    #[cfg(feature = "rocksdb-backend")]
    impl<S: Store> Store for ExitAfterCommitStore<S> {
        type Snapshot<'a>
            = S::Snapshot<'a>
        where
            Self: 'a;
        type Batch = S::Batch;

        fn snapshot(&self) -> Result<Self::Snapshot<'_>, StoreError> {
            self.inner.snapshot()
        }

        fn batch(&self) -> Self::Batch {
            self.inner.batch()
        }

        fn commit(&self, batch: Self::Batch) -> Result<(), StoreError> {
            self.inner.commit(batch)?;
            let commits = self.commits.get().saturating_add(1);
            self.commits.set(commits);
            if commits == self.exit_after {
                std::process::exit(86);
            }
            Ok(())
        }
    }

    impl<S: ReadSnapshot> ReadSnapshot for NoNameStateScanSnapshot<S> {
        fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
            if family == ColumnFamily::NameTreeNodes {
                self.name_node_reads
                    .set(self.name_node_reads.get().saturating_add(1));
            } else if family == ColumnFamily::Utxo {
                self.utxo_reads.set(self.utxo_reads.get().saturating_add(1));
            }
            self.inner.get(family, key)
        }

        fn get_many(
            &self,
            family: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
            if family == ColumnFamily::NameTreeNodes {
                self.name_node_batches
                    .set(self.name_node_batches.get().saturating_add(1));
                self.maximum_name_node_batch
                    .set(self.maximum_name_node_batch.get().max(keys.len()));
            } else if family == ColumnFamily::Utxo {
                self.utxo_batches
                    .set(self.utxo_batches.get().saturating_add(1));
                self.maximum_utxo_batch
                    .set(self.maximum_utxo_batch.get().max(keys.len()));
            }
            self.inner.get_many(family, keys)
        }

        fn scan_prefix(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
        ) -> Result<Vec<hns_store::ScanEntry>, StoreError> {
            if family == ColumnFamily::NameState {
                return Err(StoreError::Io(
                    "incremental name-tree mutation scanned NameState".to_owned(),
                ));
            }
            self.inner.scan_prefix(family, prefix)
        }
    }

    impl TransactionInputVerifier for AllowAllInputVerifier {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct AuthenticatedClaimIssuer {
        claim: VerifiedClaim,
    }

    impl CoinbaseIssuanceVerifier for AuthenticatedClaimIssuer {
        fn verify_coinbase(
            &self,
            _transaction: &Transaction,
            _height: Height,
            _parent_time: u64,
            _network: Network,
        ) -> Result<CoinbaseIssuanceSummary, StateError> {
            Ok(CoinbaseIssuanceSummary {
                conjured: self.claim.conjured,
                claims_and_airdrops_valid: true,
                airdrop_positions: Vec::new(),
                claims: vec![CoinbaseClaim {
                    output_index: 1,
                    claim: self.claim.clone(),
                }],
            })
        }
    }

    fn engine(store: MemoryStore) -> StoredStateEngine<MemoryStore> {
        engine_for_network(store, Network::Regtest)
    }

    fn engine_for_network(store: MemoryStore, network: Network) -> StoredStateEngine<MemoryStore> {
        StoredStateEngine::with_services(
            store,
            network,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("test engine")
    }

    fn encode_legacy_block_undo(undo: &BlockUndo) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_u32(LEGACY_BLOCK_UNDO_VERSION);
        writer.write_bytes(undo.block_hash.as_bytes());
        writer.write_u32(undo.height);
        writer.write_bytes(undo.previous_tree_root.as_bytes());
        writer.write_bytes(undo.resulting_tree_root.as_bytes());
        writer.write_bytes(undo.previous_committed_tree_root.as_bytes());
        writer.write_bytes(undo.resulting_committed_tree_root.as_bytes());
        writer.write_varint(undo.spent_coins.len() as u64);
        for coin in &undo.spent_coins {
            writer.write_varbytes(&encode_coin(coin));
        }
        writer.write_varint(undo.created_coins.len() as u64);
        for outpoint in &undo.created_coins {
            outpoint.write_to(&mut writer);
        }
        writer.write_varint(undo.airdrop_positions.len() as u64);
        for position in &undo.airdrop_positions {
            writer.write_u32(*position);
        }
        writer.write_varint(undo.previous_name_states.len() as u64);
        for name_undo in &undo.previous_name_states {
            writer.write_varbytes(&encode_name_undo(name_undo).expect("legacy name undo"));
        }
        writer.finish()
    }

    #[test]
    fn schema_16_working_tree_migrates_to_reversible_interval_accumulator() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());

        let mut first = block(100, vec![coinbase(vec![open_output(b"migratealpha")])]);
        first.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let first_hash = first.hash();
        let first_summary = state
            .connect_block(ConnectBlock {
                block_hash: first_hash,
                height: 100,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &first,
            })
            .expect("connect migration boundary");

        let mut second = block(101, vec![coinbase(vec![open_output(b"migratebeta")])]);
        second.header.tree_root = *first_summary.resulting_committed_tree_root.as_bytes();
        let second_hash = second.hash();
        state
            .connect_block(ConnectBlock {
                block_hash: second_hash,
                height: 101,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &second,
            })
            .expect("connect migration pending block");

        let snapshot = store.snapshot().expect("new-profile snapshot");
        let mut first_undo = BlockUndo::decode(
            &snapshot
                .get(ColumnFamily::Undo, first_hash.as_bytes())
                .expect("first undo read")
                .expect("first undo"),
        )
        .expect("decode first undo");
        let mut second_undo = BlockUndo::decode(
            &snapshot
                .get(ColumnFamily::Undo, second_hash.as_bytes())
                .expect("second undo read")
                .expect("second undo"),
        )
        .expect("decode second undo");
        let committed_root = load_stored_name_tree_commit_root(&snapshot).expect("committed root");
        let working_root = rebuild_name_tree_root(&snapshot).expect("legacy working root");
        let beta_hash = hash_name("migratebeta").expect("beta hash");
        let beta_state = load_name_state(&snapshot, &beta_hash)
            .expect("beta state read")
            .expect("beta state");
        let mut legacy_batch = store.batch();
        let staged_working_root = stage_name_tree_with_overrides(
            &snapshot,
            &mut legacy_batch,
            committed_root,
            &BTreeMap::from([(beta_hash, Some(beta_state))]),
        )
        .expect("stage legacy working tree");
        assert_eq!(staged_working_root, working_root);
        first_undo.name_tree_interval_boundary = false;
        first_undo.previous_name_tree_accumulator_last_height = None;
        first_undo.previous_name_tree_accumulator = None;
        second_undo.previous_tree_root = committed_root;
        second_undo.resulting_tree_root = working_root;
        second_undo.name_tree_interval_boundary = false;
        second_undo.previous_name_tree_accumulator_last_height = None;
        second_undo.previous_name_tree_accumulator = None;
        legacy_batch
            .put(
                ColumnFamily::Undo,
                first_hash.as_bytes(),
                &encode_legacy_block_undo(&first_undo),
            )
            .expect("legacy first undo");
        legacy_batch
            .put(
                ColumnFamily::Undo,
                second_hash.as_bytes(),
                &encode_legacy_block_undo(&second_undo),
            )
            .expect("legacy second undo");
        write_canonical_height_to_batch(&mut legacy_batch, 100, first_hash)
            .expect("first active height");
        write_canonical_height_to_batch(&mut legacy_batch, 101, second_hash)
            .expect("second active height");
        legacy_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                working_root.as_bytes(),
            )
            .expect("legacy working root");
        legacy_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::SchemaVersion.as_bytes(),
                &encode_u32(LEGACY_SCHEMA_VERSION),
            )
            .expect("legacy schema");
        legacy_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::StorageProfile.as_bytes(),
                LEGACY_STORAGE_PROFILE,
            )
            .expect("legacy profile");
        legacy_batch
            .delete(ColumnFamily::Snapshots, NAME_TREE_ACCUMULATOR_KEY)
            .expect("remove new accumulator");
        drop(snapshot);
        store.commit(legacy_batch).expect("commit legacy fixture");

        let migration = migrate_name_tree_interval_accumulator(
            &store,
            Network::Regtest.params().names.tree_interval,
        )
        .expect("migrate legacy state")
        .expect("migration performed");
        assert_eq!(migration.active_heights, 2);
        assert_eq!(migration.undos_rewritten, 2);
        assert_eq!(migration.legacy_undos_backed_up, 2);
        assert_eq!(migration.pending_names, 1);
        assert_eq!(migration.tip_height, Some(101));

        let snapshot = store.snapshot().expect("migrated snapshot");
        assert_eq!(
            decode_u32(
                &snapshot
                    .get(ColumnFamily::Meta, MetaKey::SchemaVersion.as_bytes())
                    .expect("schema read")
                    .expect("schema")
            )
            .expect("decode schema"),
            SCHEMA_VERSION
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::StorageProfile.as_bytes())
                .expect("profile read")
                .expect("profile"),
            STORAGE_PROFILE
        );
        assert_eq!(
            load_stored_name_tree_root(&snapshot).expect("migrated root"),
            committed_root
        );
        let accumulator = load_name_tree_accumulator(&snapshot)
            .expect("accumulator read")
            .expect("accumulator");
        assert_eq!(accumulator.first_height, 101);
        assert_eq!(accumulator.last_height, 101);
        assert_eq!(accumulator.names, BTreeMap::from([(beta_hash, 1)]));
        verify_name_tree_interval_state(
            &snapshot,
            Network::Regtest.params().names.tree_interval,
            101,
        )
        .expect("migrated interval audit");
        drop(snapshot);

        state
            .disconnect_block(DisconnectBlock {
                block_hash: second_hash,
                height: 101,
            })
            .expect("disconnect migrated pending block");
        let snapshot = store.snapshot().expect("post-disconnect snapshot");
        assert!(load_name_tree_accumulator(&snapshot)
            .expect("post-disconnect accumulator")
            .is_none());
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("post-disconnect root"),
            committed_root
        );
    }

    #[test]
    fn mainnet_2024_open_state_waits_for_tree_interval_commitment() {
        let store = MemoryStore::new();
        let mut state = engine_for_network(store.clone(), Network::Mainnet);
        let mut opening = block(2_024, vec![coinbase(vec![open_output(b"sad")])]);
        opening.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let opening_summary = state
            .connect_block(ConnectBlock {
                block_hash: opening.hash(),
                height: 2_024,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &opening,
            })
            .expect("connect canonical-height OPEN shape");
        assert_eq!(opening_summary.resulting_tree_root, TreeRoot::ZERO);
        assert_eq!(
            opening_summary.resulting_committed_tree_root,
            TreeRoot::ZERO
        );
        let pending_root = {
            let snapshot = store.snapshot().expect("pending OPEN snapshot");
            rebuild_name_tree_root(&snapshot).expect("pending OPEN root")
        };
        assert_ne!(pending_root, TreeRoot::ZERO);

        let mut incorrectly_committed = block(2_025, vec![coinbase(Vec::new())]);
        incorrectly_committed.header.tree_root = *pending_root.as_bytes();
        assert!(matches!(
            state.connect_block(ConnectBlock {
                block_hash: incorrectly_committed.hash(),
                height: 2_025,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &incorrectly_committed,
            }),
            Err(StateError::HeaderTreeRootMismatch { .. })
        ));

        let mut next = block(2_026, vec![coinbase(Vec::new())]);
        next.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let next_summary = state
            .connect_block(ConnectBlock {
                block_hash: next.hash(),
                height: 2_025,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &next,
            })
            .expect("connect post-OPEN block with retained commitment");
        assert_eq!(
            next_summary.resulting_tree_root,
            opening_summary.resulting_tree_root
        );
        assert_eq!(next_summary.resulting_committed_tree_root, TreeRoot::ZERO);

        let mut interval = block(2_052, vec![coinbase(Vec::new())]);
        interval.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let interval_summary = state
            .connect_block(ConnectBlock {
                block_hash: interval.hash(),
                height: 2_052,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &interval,
            })
            .expect("commit working tree at the mainnet interval");
        assert_eq!(interval_summary.resulting_committed_tree_root, pending_root);

        let mut after_interval = block(2_053, vec![coinbase(Vec::new())]);
        after_interval.header.tree_root = *pending_root.as_bytes();
        state
            .connect_block(ConnectBlock {
                block_hash: after_interval.hash(),
                height: 2_053,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &after_interval,
            })
            .expect("inherit newly committed interval root");

        let snapshot = store.snapshot().expect("post-interval snapshot");
        assert_eq!(
            load_stored_name_tree_commit_root(&snapshot).expect("commit root"),
            pending_root
        );
    }

    fn address() -> Address {
        Address::new(0, vec![0; 20]).expect("address")
    }

    fn covenant() -> Covenant {
        Covenant {
            kind: CovenantKind::None,
            items: Vec::new(),
        }
    }

    fn output(value: Amount) -> Output {
        Output {
            value,
            address: address(),
            covenant: covenant(),
        }
    }

    #[test]
    fn connect_omits_hsd_unspendable_outputs_from_utxo_and_undo() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());
        let transaction = coinbase(vec![
            output(1),
            Output {
                value: 7,
                address: Address::new(31, vec![0; 2]).expect("null-data address"),
                covenant: covenant(),
            },
        ]);
        let txid = transaction.txid();
        let candidate = block(77, vec![transaction]);
        let block_hash = candidate.hash();

        let summary = state
            .connect_block(ConnectBlock {
                block_hash,
                height: 77,
                coinbase_maturity: 0,
                block_reward: 8,
                block: &candidate,
            })
            .expect("connect block with null-data output");
        assert_eq!(summary.coins_created, 1);

        let spendable = Outpoint { txid, index: 0 };
        let nulldata = Outpoint { txid, index: 1 };
        assert!(state
            .coin(&spendable)
            .expect("spendable coin read")
            .is_some());
        assert!(state
            .coin(&nulldata)
            .expect("null-data coin read")
            .is_none());

        let undo = state
            .load_undo(&block_hash)
            .expect("undo read")
            .expect("block undo");
        assert_eq!(undo.created_coins, vec![spendable.clone()]);

        state
            .disconnect_block(DisconnectBlock {
                block_hash,
                height: 77,
            })
            .expect("disconnect block with null-data output");
        assert!(state
            .coin(&spendable)
            .expect("restored coin read")
            .is_none());
        assert!(state
            .coin(&nulldata)
            .expect("restored null-data read")
            .is_none());
    }

    fn open_output(name: &[u8]) -> Output {
        let name_hash = NameHash::new(hns_primitives::sha3_256(name));
        Output {
            value: 0,
            address: address(),
            covenant: Covenant {
                kind: CovenantKind::Open,
                items: vec![
                    name_hash.as_bytes().to_vec(),
                    0u32.to_le_bytes().to_vec(),
                    name.to_vec(),
                ],
            },
        }
    }

    fn coinbase(outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs,
            locktime: 0,
        }
    }

    fn block(nonce: u32, transactions: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                nonce,
                ..Header::default()
            },
            transactions,
        }
    }

    #[test]
    fn block_utxos_are_prefetched_in_one_storage_batch() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let first_outpoint = Outpoint {
            txid: Txid::new([1; 32]),
            index: 0,
        };
        let second_outpoint = Outpoint {
            txid: Txid::new([2; 32]),
            index: 1,
        };
        let mut initial = store.batch();
        for (outpoint, value) in [(first_outpoint.clone(), 11), (second_outpoint.clone(), 13)] {
            write_coin_to_batch(
                &mut initial,
                &Coin {
                    outpoint,
                    value,
                    height: 1,
                    coinbase: false,
                    address: address(),
                    covenant: covenant(),
                },
            )
            .expect("write input coin");
        }
        store.commit(initial).expect("commit input coins");

        let spend = Transaction {
            version: 1,
            inputs: vec![
                Input {
                    previous_output: first_outpoint.clone(),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                },
                Input {
                    previous_output: second_outpoint.clone(),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![output(20)],
            locktime: 0,
        };
        let created = Outpoint {
            txid: spend.txid(),
            index: 0,
        };
        let candidate = block(88, vec![coinbase(Vec::new()), spend]);
        let guarded = NoNameStateScanSnapshot {
            inner: store.snapshot().expect("snapshot"),
            name_node_reads: Cell::new(0),
            name_node_batches: Cell::new(0),
            maximum_name_node_batch: Cell::new(0),
            utxo_reads: Cell::new(0),
            utxo_batches: Cell::new(0),
            maximum_utxo_batch: Cell::new(0),
        };
        let prefetched = prefetch_block_utxos(&guarded, &candidate).expect("prefetch");

        assert_eq!(guarded.utxo_reads.get(), 0);
        assert_eq!(guarded.utxo_batches.get(), 1);
        assert_eq!(guarded.maximum_utxo_batch.get(), 3);
        assert_eq!(
            prefetched[&first_outpoint].as_ref().map(|coin| coin.value),
            Some(11)
        );
        assert_eq!(
            prefetched[&second_outpoint].as_ref().map(|coin| coin.value),
            Some(13)
        );
        assert_eq!(prefetched[&created], None);
    }

    #[test]
    fn checkpoint_route_composes_only_historical_bid_redeem_name_context() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let snapshot = store.snapshot().expect("snapshot");
        let input_verifier = AllowAllInputVerifier;
        let issuance_verifier = RejectSpecialCoinbaseIssuance;
        let height = 100;
        let name = b"historicalbid";
        let name_hash = NameHash::new(hns_primitives::sha3_256(name));
        let transactions = [
            coinbase(vec![Output {
                value: 0,
                address: address(),
                covenant: Covenant {
                    kind: CovenantKind::Bid,
                    items: vec![
                        name_hash.as_bytes().to_vec(),
                        1u32.to_le_bytes().to_vec(),
                        name.to_vec(),
                        vec![0x55; 32],
                    ],
                },
            }]),
            coinbase(vec![Output {
                value: 0,
                address: address(),
                covenant: Covenant {
                    kind: CovenantKind::Redeem,
                    items: vec![name_hash.as_bytes().to_vec(), 1u32.to_le_bytes().to_vec()],
                },
            }]),
        ];
        let full_services = StateServices {
            network: Network::Mainnet,
            name_flags: NameFlags::NONE,
            name_flags_valid: true,
            historical_validation: HistoricalValidationPlan::full(),
            input_verifier: &input_verifier,
            issuance_verifier: &issuance_verifier,
        };
        let full_context =
            SnapshotChainContext::new(&snapshot, height, HistoricalValidationPlan::full());
        let historical_plan = HistoricalValidationPlan::hsd_checkpointed();
        let historical_context = SnapshotChainContext::new(&snapshot, height, historical_plan);

        for transaction in &transactions {
            let mut full_changes = NameStateChanges::default();
            let error = apply_transaction_name_covenants(
                &snapshot,
                transaction,
                height,
                full_services,
                &full_context,
                &mut full_changes,
                false,
            )
            .expect_err("a BID/REDEEM without NameState must fail on the full route");
            assert!(
                matches!(
                    error,
                    StateError::Consensus(ConsensusError::ContextualCovenant(_))
                ),
                "unexpected full-route error: {error:?}"
            );

            let mut historical_changes = NameStateChanges::default();
            apply_transaction_name_covenants(
                &snapshot,
                transaction,
                height,
                StateServices {
                    historical_validation: historical_plan,
                    ..full_services
                },
                &historical_context,
                &mut historical_changes,
                false,
            )
            .expect("checkpoint-backed BID/REDEEM context bypass");
            assert!(historical_changes.current.is_empty());
        }
        assert!(historical_context.is_historical_height(height));
        assert!(!historical_context.is_historical_height(height + 1));
    }

    #[test]
    fn checkpoint_route_coordinates_all_hsd_input_assumptions() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let previous = Outpoint {
            txid: Txid::new([0x61; 32]),
            index: 0,
        };
        let coin = Coin {
            outpoint: previous.clone(),
            value: 1,
            height: 100,
            coinbase: true,
            address: Address::new(0, vec![0x55; 32]).expect("script-hash address"),
            covenant: Covenant {
                kind: CovenantKind::Bid,
                items: vec![
                    vec![0x63; 32],
                    1u32.to_le_bytes().to_vec(),
                    b"historical-assumption".to_vec(),
                    vec![0x64; 32],
                ],
            },
        };
        let mut initial = store.batch();
        write_coin_to_batch(&mut initial, &coin).expect("seed coin");
        store.commit(initial).expect("commit seed coin");

        let spend = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: previous.clone(),
                sequence: 1,
                witness: Witness {
                    // HSD conservatively counts 20 sigops for each bare
                    // CHECKMULTISIG without a preceding small integer.
                    items: vec![vec![
                        0xae;
                        usize::try_from(MAX_BLOCK_SIGOPS / 20 + 1)
                            .expect("sigop fixture length")
                    ]],
                },
            }],
            outputs: vec![output(2)],
            locktime: 0,
        };
        let mut candidate = block(0x62, vec![coinbase(vec![output(10)]), spend]);
        candidate.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let candidate_hash = candidate.hash();
        let issuance = RejectSpecialCoinbaseIssuance;
        let full_services = StateServices {
            network: Network::Mainnet,
            name_flags: NameFlags::NONE,
            name_flags_valid: true,
            historical_validation: HistoricalValidationPlan::full(),
            input_verifier: &RejectUnverifiedInputs,
            issuance_verifier: &issuance,
        };
        let request = ConnectBlock {
            block_hash: candidate_hash,
            height: 100,
            coinbase_maturity: 100,
            block_reward: 0,
            block: &candidate,
        };

        let snapshot = store.snapshot().expect("full snapshot");
        let mut rejected = store.batch();
        assert!(matches!(
            connect_block_to_batch_with_services(
                &snapshot,
                &mut rejected,
                request.clone(),
                full_services,
            ),
            Err(StateError::PrematureCoinbaseSpend { .. })
        ));

        let historical_plan = HistoricalValidationPlan::hsd_checkpointed();
        let mut incomplete_plan = historical_plan;
        incomplete_plan.scripts = true;
        let mut invalid_route = store.batch();
        assert!(matches!(
            connect_block_to_batch_with_services(
                &snapshot,
                &mut invalid_route,
                request.clone(),
                StateServices {
                    historical_validation: incomplete_plan,
                    ..full_services
                },
            ),
            Err(StateError::InvalidHistoricalValidationPlan)
        ));

        let mut historical = store.batch();
        let summary = connect_block_to_batch_with_services(
            &snapshot,
            &mut historical,
            request,
            StateServices {
                historical_validation: historical_plan,
                ..full_services
            },
        )
        .expect("coordinated checkpoint route");
        assert_eq!(summary.historical_validation, historical_plan);
        assert!(summary.validation.relative_locks_valid);
        assert!(summary.validation.scripts_valid);
        assert!(summary.validation.covenant_links_valid);
        drop(snapshot);
        store.commit(historical).expect("commit historical route");
        assert_eq!(
            engine(store).coin(&previous).expect("read spent coin"),
            None
        );
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTreeFixture {
        states: Vec<NameTreeStateFixture>,
        incremental_roots: Vec<NameTreeRootFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTreeStateFixture {
        name_hash: String,
        encoded: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTreeRootFixture {
        header_root: String,
        resulting_root: String,
        root: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTransitionFixture {
        network: String,
        parameters: NameTransitionParametersFixture,
        cases: Vec<NameTransitionCaseFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTransitionParametersFixture {
        auction_start: u32,
        rollout_interval: u32,
        lockup_period: u32,
        renewal_window: u32,
        renewal_period: u32,
        renewal_maturity: u32,
        claim_period: u32,
        alexa_lockup_period: u32,
        claim_frequency: u32,
        bidding_period: u32,
        reveal_period: u32,
        tree_interval: u32,
        transfer_lockup: u32,
        auction_maturity: u32,
        no_rollout: bool,
        no_reserved: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTransitionCaseFixture {
        id: String,
        height: u32,
        name_flags: u32,
        historical: bool,
        name_hash: String,
        pre_state_raw: String,
        transaction_raw: String,
        input_coins: Vec<NameTransitionCoinFixture>,
        active_chain: Vec<NameTransitionChainEntryFixture>,
        linkage_result: i32,
        accepted: bool,
        reason: Option<String>,
        post_state_raw: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameTransitionCoinFixture {
        outpoint_txid: String,
        outpoint_index: u32,
        value: u64,
        height: u32,
        coinbase: bool,
        address_version: u8,
        address_hash: String,
        covenant_type: u8,
        covenant_items: Vec<String>,
    }

    #[derive(Deserialize)]
    struct NameTransitionChainEntryFixture {
        hash: String,
        height: u32,
        main: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContextualInvalidFixture {
        schema: u32,
        network: String,
        oracle: ContextualInvalidOracleFixture,
        generation: ContextualInvalidGenerationFixture,
        context_headers: Vec<ContextualInvalidHeaderFixture>,
        cases: Vec<ContextualInvalidCaseFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContextualInvalidOracleFixture {
        repository: String,
        revision: String,
        hsd_version: String,
        route: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContextualInvalidGenerationFixture {
        method: String,
        seed_domain: String,
        upstream_invalid_vectors_copied: bool,
        candidate_height: u32,
        parent_height: u32,
        coinbase_maturity: u32,
        invalid_cases: usize,
        valid_controls: usize,
    }

    #[derive(Deserialize)]
    struct ContextualInvalidHeaderFixture {
        height: u32,
        time: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContextualInvalidCaseFixture {
        id: String,
        target: String,
        mutation_class: String,
        raw: String,
        input_coins: Vec<NameTransitionCoinFixture>,
        oracle: ContextualInvalidOutcomeFixture,
    }

    #[derive(Deserialize)]
    struct ContextualInvalidOutcomeFixture {
        accepted: bool,
        reason: String,
        score: u32,
    }

    struct FixtureNameContext {
        historical: bool,
        heights: HashMap<BlockHash, Height>,
    }

    impl NameContext for FixtureNameContext {
        fn main_chain_height(&self, hash: &BlockHash) -> Result<Option<Height>, ConsensusError> {
            Ok(self.heights.get(hash).copied())
        }

        fn is_historical_height(&self, _height: Height) -> bool {
            self.historical
        }
    }

    #[derive(Deserialize)]
    struct AirdropFixture {
        proofs: Vec<AirdropFixtureProof>,
        faucet: AirdropFixtureProof,
    }

    #[derive(Deserialize)]
    struct AirdropFixtureProof {
        raw: String,
        value: u64,
        version: u8,
        address: String,
        fee: u64,
        position: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimHistoryFixture {
        canonical_context: MainnetClaimContextFixture,
        block: MainnetClaimBlockFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimReplacementHistoryFixture {
        schema: u32,
        canonical_context: MainnetClaimReplacementContextFixture,
        history: Vec<MainnetClaimReplacementFixture>,
        lifecycle: MainnetClaimLifecycleFixture,
        blocks: Vec<MainnetClaimReplacementBlockFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimLifecycleFixture {
        claim_period_height: u32,
        lineage: MainnetClaimLineageFixture,
        terminal: MainnetTerminalClaimFixture,
        boundary: MainnetClaimBoundaryFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimLineageFixture {
        name: String,
        name_hash: String,
        points: Vec<MainnetClaimPointFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetTerminalClaimFixture {
        name: String,
        name_hash: String,
        blocks_before_claim_period: u32,
        point: MainnetClaimPointFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimBoundaryFixture {
        block_height: u32,
        parent_time: u64,
        claim_count: usize,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimPointFixture {
        block_height: u32,
        coinbase_txid: String,
        output_index: u32,
        output_value: u64,
        reserved_value: u64,
        fee: u64,
        commit_height: u32,
        weak: bool,
        conjured: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimContextFixture {
        parent_time: u64,
        context_headers: Vec<MainnetClaimHeaderFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimReplacementContextFixture {
        commit_headers: Vec<MainnetClaimHeaderFixture>,
        blocks: Vec<MainnetClaimReplacementBlockContextFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimReplacementBlockContextFixture {
        block_height: u32,
        parent_time: u64,
        context_headers: Vec<MainnetClaimHeaderFixture>,
    }

    #[derive(Deserialize)]
    struct MainnetClaimHeaderFixture {
        height: u32,
        hash: String,
        raw: String,
    }

    #[derive(Deserialize)]
    struct MainnetClaimBlockFixture {
        height: u32,
        raw: String,
        claims: Vec<MainnetClaimStateFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimStateFixture {
        output_index: usize,
        name: String,
        weak: bool,
        commit_height: u32,
        reserved_value: u64,
        fee: u64,
        output_value: u64,
        conjured: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimReplacementBlockFixture {
        role: String,
        height: u32,
        raw: String,
        claims: Vec<MainnetClaimStateFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimReplacementFixture {
        name: String,
        name_hash: String,
        initial: MainnetClaimReplacementPointFixture,
        replacement: MainnetClaimReplacementPointFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimReplacementPointFixture {
        block_height: u32,
        coinbase_txid: String,
        output_index: u32,
        output_value: u64,
        commit_height: u32,
    }

    fn decode_fixture_bytes(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
            .collect()
    }

    fn decode_hash(value: &str) -> [u8; 32] {
        decode_fixture_bytes(value)
            .try_into()
            .expect("32-byte hash")
    }

    fn seed_mainnet_claim_headers(store: &MemoryStore, context: &MainnetClaimContextFixture) {
        let mut batch = store.batch();
        for expected in &context.context_headers {
            let header = Header::decode(&decode_fixture_bytes(&expected.raw))
                .expect("mainnet context header");
            let hash = header.hash();
            assert_eq!(hash.to_hex(), expected.hash);
            batch
                .put(
                    ColumnFamily::Headers,
                    hash.as_bytes(),
                    &HeaderRecord {
                        hash,
                        height: expected.height,
                        chainwork: Uint256::ONE,
                        header,
                        status: BlockStatus::default(),
                    }
                    .encode(),
                )
                .expect("mainnet context header");
            write_canonical_height_to_batch(&mut batch, expected.height, hash)
                .expect("mainnet canonical header");
        }
        store.commit(batch).expect("mainnet context headers");
    }

    fn seed_mainnet_claim_replacement_headers(
        store: &MemoryStore,
        context: &MainnetClaimReplacementContextFixture,
    ) {
        let mut batch = store.batch();
        for expected in context.commit_headers.iter().chain(
            context
                .blocks
                .iter()
                .flat_map(|block| &block.context_headers),
        ) {
            let header = Header::decode(&decode_fixture_bytes(&expected.raw))
                .expect("mainnet replacement context header");
            let hash = header.hash();
            assert_eq!(hash.to_hex(), expected.hash);
            batch
                .put(
                    ColumnFamily::Headers,
                    hash.as_bytes(),
                    &HeaderRecord {
                        hash,
                        height: expected.height,
                        chainwork: Uint256::ONE,
                        header,
                        status: BlockStatus::default(),
                    }
                    .encode(),
                )
                .expect("mainnet replacement context header");
            write_canonical_height_to_batch(&mut batch, expected.height, hash)
                .expect("mainnet replacement canonical header");
        }
        store
            .commit(batch)
            .expect("mainnet replacement context headers");
    }

    fn connect_mainnet_claim_fixture_block(
        engine: &mut StoredStateEngine<MemoryStore>,
        expected: &MainnetClaimReplacementBlockFixture,
        context: &MainnetClaimReplacementBlockContextFixture,
    ) -> (Block, StateSummary) {
        assert_eq!(context.block_height, expected.height);
        let historical = Block::decode(&decode_fixture_bytes(&expected.raw))
            .expect("canonical mainnet claim-history block");
        let coinbase = historical.transactions[0].clone();
        assert_eq!(coinbase.locktime, expected.height);
        let issuance = engine
            .issuance_verifier()
            .verify_coinbase(
                &coinbase,
                expected.height,
                context.parent_time,
                Network::Mainnet,
            )
            .expect("canonical mainnet claim issuance");
        assert_eq!(issuance.claims.len(), expected.claims.len());

        let output_value = coinbase
            .outputs
            .iter()
            .try_fold(0u64, |total, output| total.checked_add(output.value))
            .expect("coinbase output value");
        let ordinary_reward_and_fees = output_value
            .checked_sub(issuance.conjured)
            .expect("ordinary coinbase component");
        let inherited_committed_tree_root = {
            let snapshot = engine.store().snapshot().expect("pre-claim snapshot");
            verify_stored_name_tree_root(&snapshot).expect("pre-claim tree root");
            load_stored_name_tree_commit_root(&snapshot).expect("pre-claim commit root")
        };
        let mut candidate = block(expected.height, vec![coinbase]);
        candidate.header.tree_root = *inherited_committed_tree_root.as_bytes();
        let summary = engine
            .connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: expected.height,
                coinbase_maturity: 100,
                block_reward: ordinary_reward_and_fees,
                block: &candidate,
            })
            .expect("canonical mainnet claim-history coinbase");
        assert_eq!(summary.names_changed, expected.claims.len());
        assert!(summary.validation.claims_and_airdrops_valid);
        (candidate, summary)
    }

    #[test]
    fn name_tree_snapshot_pin_codec_is_versioned_and_checksummed() {
        let pin = NameTreeSnapshotPin {
            height: 144,
            block_hash: BlockHash::new([3; 32]),
            root: TreeRoot::new([7; 32]),
        };
        let encoded = pin.encode();
        assert_eq!(encoded.len(), NAME_TREE_SNAPSHOT_PIN_CODEC_SIZE);
        assert_eq!(NameTreeSnapshotPin::decode(&encoded).expect("decode"), pin);

        let mut corrupt = encoded.clone();
        *corrupt.last_mut().expect("checksum byte") ^= 1;
        assert!(matches!(
            NameTreeSnapshotPin::decode(&corrupt),
            Err(StateError::Codec(message)) if message.contains("checksum")
        ));

        let mut unknown = encoded;
        unknown[..4].copy_from_slice(&2u32.to_le_bytes());
        let body_checksum = blake2b_256(&unknown[..NAME_TREE_SNAPSHOT_PIN_BODY_SIZE]);
        unknown[NAME_TREE_SNAPSHOT_PIN_BODY_SIZE..].copy_from_slice(&body_checksum);
        assert!(matches!(
            NameTreeSnapshotPin::decode(&unknown),
            Err(StateError::Codec(message)) if message.contains("version 2")
        ));
        assert_eq!(
            name_tree_snapshot_pin_key(pin.height),
            [
                NAME_TREE_SNAPSHOT_PIN_PREFIX,
                pin.height.to_be_bytes().as_slice()
            ]
            .concat()
        );
    }

    #[test]
    fn rebuilt_name_tree_root_matches_incremental_hsd_roots() {
        let fixture: NameTreeFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/state-urkel-v1.json"
        ))
        .expect("fixture");
        assert_eq!(fixture.states.len(), fixture.incremental_roots.len());

        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let mut historical_roots = Vec::new();
        for (index, (state, expected)) in fixture
            .states
            .iter()
            .zip(&fixture.incremental_roots)
            .enumerate()
        {
            let snapshot = store.snapshot().expect("pre-state snapshot");
            let inherited_root = verify_stored_name_tree_root(&snapshot).expect("pre-state root");
            assert_eq!(
                inherited_root,
                TreeRoot::new(decode_hash(&expected.header_root))
            );

            let name_hash = NameHash::new(decode_hash(&state.name_hash));
            let encoded = decode_fixture_bytes(&state.encoded);
            let decoded = decode_name_state(&name_hash, &encoded).expect("decode state");
            let mut batch = store.batch();
            write_name_state_to_batch(&mut batch, &decoded).expect("write state");
            let overrides = BTreeMap::from([(name_hash, Some(decoded))]);
            let staged_root =
                stage_name_tree_with_overrides(&snapshot, &mut batch, inherited_root, &overrides)
                    .expect("stage");
            assert_eq!(
                staged_root,
                TreeRoot::new(decode_hash(&expected.resulting_root))
            );
            batch
                .put(
                    ColumnFamily::Meta,
                    MetaKey::NameTreeRoot.as_bytes(),
                    staged_root.as_bytes(),
                )
                .expect("bind resulting root");
            batch
                .put(
                    ColumnFamily::Meta,
                    MetaKey::NameTreeCommitRoot.as_bytes(),
                    staged_root.as_bytes(),
                )
                .expect("bind resulting committed root");
            drop(snapshot);
            store.commit(batch).expect("commit");
            let snapshot = store.snapshot().expect("snapshot");
            assert_eq!(expected.root, expected.resulting_root);
            assert_eq!(
                rebuild_name_tree_root(&snapshot).expect("root"),
                TreeRoot::new(decode_hash(&expected.resulting_root))
            );
            assert_eq!(
                verify_stored_name_tree_root(&snapshot).expect("bound root"),
                TreeRoot::new(decode_hash(&expected.resulting_root))
            );
            assert_eq!(
                validate_persisted_name_tree(&snapshot, staged_root).expect("persisted node tree"),
                index * 2 + 1
            );
            historical_roots.push(staged_root);
            let stored_nodes = snapshot
                .scan_prefix(ColumnFamily::NameTreeNodes, b"")
                .expect("stored persistent nodes")
                .len();
            assert_eq!(
                validate_persisted_name_trees(&snapshot, historical_roots.iter().copied())
                    .expect("persisted historical node trees"),
                stored_nodes
            );
            assert_eq!(
                prove_persisted_name_tree(&snapshot, staged_root, name_hash)
                    .expect("persisted proof")
                    .verify_value(staged_root)
                    .expect("verify proof"),
                Some(encoded)
            );
        }
    }

    #[test]
    fn staged_name_tree_mutation_is_path_local_and_matches_rebuild_oracle() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let mut states = Vec::new();
        let mut tree_entries = Vec::new();
        for index in 0..64u32 {
            let name = format!("incrementalstate{index}").into_bytes();
            let name_hash = NameHash::new(hns_primitives::sha3_256(&name));
            let mut state = NameState::null(name_hash);
            state.initialize(name, 100 + index);
            tree_entries.push((name_hash, encode_name_state(&state).expect("encode state")));
            states.push(state);
        }
        let tree = MemoryUrkel::from_entries(tree_entries).expect("materialized tree");
        let root = tree.root();
        let records = tree.node_records().expect("node records");

        let mut initial = store.batch();
        for state in &states {
            write_name_state_to_batch(&mut initial, state).expect("write state");
        }
        for (node_root, raw) in &records {
            initial
                .put(ColumnFamily::NameTreeNodes, node_root.as_bytes(), raw)
                .expect("write node");
        }
        initial
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                root.as_bytes(),
            )
            .expect("bind root");
        store.commit(initial).expect("commit initial tree");

        let overrides = states[16..18]
            .iter()
            .cloned()
            .map(|mut replacement| {
                replacement.height += 1;
                (replacement.name_hash, Some(replacement))
            })
            .collect::<BTreeMap<_, _>>();
        let base = store.snapshot().expect("base snapshot");
        let expected =
            rebuild_name_tree_root_with_overrides(&base, &overrides).expect("rebuild oracle");
        let guarded = NoNameStateScanSnapshot {
            inner: base,
            name_node_reads: Cell::new(0),
            name_node_batches: Cell::new(0),
            maximum_name_node_batch: Cell::new(0),
            utxo_reads: Cell::new(0),
            utxo_batches: Cell::new(0),
            maximum_utxo_batch: Cell::new(0),
        };
        let mut batch = store.batch();
        let actual = stage_name_tree_with_overrides(&guarded, &mut batch, root, &overrides)
            .expect("path-local mutation");

        assert_eq!(actual, expected);
        assert_eq!(
            guarded.name_node_reads.get(),
            0,
            "two-name mutation must batch independent path reads"
        );
        assert!(guarded.name_node_batches.get() > 1);
        assert!(guarded.maximum_name_node_batch.get() > 1);

        let empty_base = store.snapshot().expect("empty override snapshot");
        let empty_guarded = NoNameStateScanSnapshot {
            inner: empty_base,
            name_node_reads: Cell::new(0),
            name_node_batches: Cell::new(0),
            maximum_name_node_batch: Cell::new(0),
            utxo_reads: Cell::new(0),
            utxo_batches: Cell::new(0),
            maximum_utxo_batch: Cell::new(0),
        };
        let mut empty_batch = store.batch();
        assert_eq!(
            stage_name_tree_with_overrides(
                &empty_guarded,
                &mut empty_batch,
                root,
                &BTreeMap::new()
            )
            .expect("empty mutation"),
            root
        );
        assert_eq!(empty_guarded.name_node_reads.get(), 0);
        assert_eq!(empty_guarded.name_node_batches.get(), 0);
    }

    #[test]
    fn multi_step_overlay_reads_incremental_nodes_and_retains_historical_roots() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let input_verifier = AllowAllInputVerifier;
        let issuance_verifier = RejectSpecialCoinbaseIssuance;
        let services = StateServices {
            network: Network::Regtest,
            name_flags: NameFlags::NONE,
            name_flags_valid: true,
            historical_validation: HistoricalValidationPlan::full(),
            input_verifier: &input_verifier,
            issuance_verifier: &issuance_verifier,
        };

        let mut first = block(119, vec![coinbase(vec![open_output(b"overlayalpha")])]);
        first.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let first_hash = first.hash();
        let base = store.snapshot().expect("base snapshot");
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let mut batch = overlay.batch(store.batch());
        let first_summary = connect_block_to_batch_with_services(
            &staged,
            &mut batch,
            ConnectBlock {
                block_hash: first_hash,
                height: 119,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &first,
            },
            services,
        )
        .expect("stage first block");

        let mut second = block(120, vec![coinbase(vec![open_output(b"overlaybeta")])]);
        second.header.tree_root = *first_summary.resulting_tree_root.as_bytes();
        let second_hash = second.hash();
        let second_summary = connect_block_to_batch_with_services(
            &staged,
            &mut batch,
            ConnectBlock {
                block_hash: second_hash,
                height: 120,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &second,
            },
            services,
        )
        .expect("stage second block from overlay nodes");
        assert_ne!(
            second_summary.resulting_tree_root,
            first_summary.resulting_tree_root
        );
        drop(staged);
        drop(base);
        store.commit(batch.into_inner()).expect("commit two blocks");

        let historical_root = second_summary.resulting_tree_root;
        let alpha_hash = hash_name("overlayalpha").expect("alpha hash");
        let beta_hash = hash_name("overlaybeta").expect("beta hash");
        let snapshot = store.snapshot().expect("connected snapshot");
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("connected root"),
            historical_root
        );
        let alpha_value = prove_persisted_name_tree(&snapshot, historical_root, alpha_hash)
            .expect("alpha proof")
            .verify_value(historical_root)
            .expect("verify alpha")
            .expect("alpha value");
        let beta_value = prove_persisted_name_tree(&snapshot, historical_root, beta_hash)
            .expect("beta proof")
            .verify_value(historical_root)
            .expect("verify beta")
            .expect("beta value");
        let first_undo = BlockUndo::decode(
            &snapshot
                .get(ColumnFamily::Undo, first_hash.as_bytes())
                .expect("first undo read")
                .expect("first undo"),
        )
        .expect("decode first undo");
        let second_undo = BlockUndo::decode(
            &snapshot
                .get(ColumnFamily::Undo, second_hash.as_bytes())
                .expect("second undo read")
                .expect("second undo"),
        )
        .expect("decode second undo");
        drop(snapshot);

        let base = store.snapshot().expect("disconnect base");
        let overlay = StagingOverlay::new();
        let staged = overlay.snapshot(&base);
        let mut batch = overlay.batch(store.batch());
        let second_disconnect = disconnect_block_to_batch(
            &staged,
            &mut batch,
            DisconnectBlock {
                block_hash: second_hash,
                height: 120,
            },
            &second_undo,
        )
        .expect("disconnect second through overlay");
        assert_eq!(
            second_disconnect.resulting_tree_root,
            first_summary.resulting_tree_root
        );
        let first_disconnect = disconnect_block_to_batch(
            &staged,
            &mut batch,
            DisconnectBlock {
                block_hash: first_hash,
                height: 119,
            },
            &first_undo,
        )
        .expect("disconnect first through overlay");
        assert_eq!(first_disconnect.resulting_tree_root, TreeRoot::ZERO);
        drop(staged);
        drop(base);
        store
            .commit(batch.into_inner())
            .expect("commit two disconnects");

        let snapshot = store.snapshot().expect("disconnected snapshot");
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("empty current root"),
            TreeRoot::ZERO
        );
        assert!(snapshot
            .scan_prefix(ColumnFamily::NameState, b"")
            .expect("current names")
            .is_empty());
        assert_eq!(
            prove_persisted_name_tree(&snapshot, historical_root, alpha_hash)
                .expect("historical alpha proof")
                .verify_value(historical_root)
                .expect("verify historical alpha"),
            Some(alpha_value)
        );
        assert_eq!(
            prove_persisted_name_tree(&snapshot, historical_root, beta_hash)
                .expect("historical beta proof")
                .verify_value(historical_root)
                .expect("verify historical beta"),
            Some(beta_value)
        );
    }

    #[test]
    fn interval_pins_and_compaction_preserve_only_retained_proof_roots() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());

        let mut first = block(130, vec![coinbase(vec![open_output(b"compactalpha")])]);
        first.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let first_hash = first.hash();
        let first_summary = state
            .connect_block(ConnectBlock {
                block_hash: first_hash,
                height: 100,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &first,
            })
            .expect("connect first interval block");

        let mut second = block(131, vec![coinbase(vec![open_output(b"compactbeta")])]);
        second.header.tree_root = *first_summary.resulting_tree_root.as_bytes();
        let second_hash = second.hash();
        let second_summary = state
            .connect_block(ConnectBlock {
                block_hash: second_hash,
                height: 101,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &second,
            })
            .expect("connect second block");

        let mut third = block(132, vec![coinbase(vec![open_output(b"compactgamma")])]);
        third.header.tree_root = *second_summary.resulting_committed_tree_root.as_bytes();
        let third_hash = third.hash();
        let third_summary = state
            .connect_block(ConnectBlock {
                block_hash: third_hash,
                height: 105,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &third,
            })
            .expect("connect third interval block");

        let alpha_hash = hash_name("compactalpha").expect("alpha hash");
        let beta_hash = hash_name("compactbeta").expect("beta hash");
        let alpha_proof;
        let beta_proof;
        {
            let snapshot = store.snapshot().expect("connected snapshot");
            assert_eq!(
                load_name_tree_snapshot_pins(&snapshot)
                    .expect("interval pins")
                    .iter()
                    .map(|pin| pin.height)
                    .collect::<Vec<_>>(),
                vec![100, 105]
            );
            alpha_proof =
                prove_persisted_name_tree(&snapshot, first_summary.resulting_tree_root, alpha_hash)
                    .expect("first-root proof")
                    .raw;
            beta_proof =
                prove_persisted_name_tree(&snapshot, second_summary.resulting_tree_root, beta_hash)
                    .expect("second-root proof")
                    .raw;
        }

        state
            .disconnect_block(DisconnectBlock {
                block_hash: third_hash,
                height: 105,
            })
            .expect("disconnect third block");
        let before = store
            .snapshot()
            .expect("pre-compaction snapshot")
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("pre-compaction nodes")
            .len();
        let summary = state.compact_name_tree_nodes().expect("compact nodes");
        assert_eq!(summary.nodes_before, before);
        assert!(summary.nodes_deleted > 0);
        assert_eq!(
            summary.nodes_before,
            summary.nodes_retained + summary.nodes_deleted
        );

        let snapshot = store.snapshot().expect("compacted snapshot");
        assert_eq!(
            load_name_tree_snapshot_pins(&snapshot)
                .expect("remaining pins")
                .iter()
                .map(|pin| pin.height)
                .collect::<Vec<_>>(),
            vec![100]
        );
        assert_eq!(
            prove_persisted_name_tree(&snapshot, first_summary.resulting_tree_root, alpha_hash,)
                .expect("retained first proof")
                .raw,
            alpha_proof
        );
        assert_eq!(
            prove_persisted_name_tree(&snapshot, second_summary.resulting_tree_root, beta_hash,)
                .expect("retained second proof")
                .raw,
            beta_proof
        );
        assert!(matches!(
            prove_persisted_name_tree(
                &snapshot,
                third_summary.resulting_tree_root,
                hash_name("compactgamma").expect("gamma hash"),
            ),
            Err(StateError::NameTree(UrkelError::MissingNode(root)))
                if root == third_summary.resulting_tree_root
        ));
        drop(snapshot);
        drop(state);

        let mut reopened = engine(store);
        assert_eq!(
            reopened
                .name_proof(beta_hash)
                .expect("reopened current proof")
                .1
                .raw,
            beta_proof
        );
        assert_eq!(
            reopened
                .compact_name_tree_nodes()
                .expect("idempotent compaction")
                .nodes_deleted,
            0
        );
    }

    #[test]
    fn malformed_snapshot_pin_aborts_compaction_without_deleting_nodes() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());
        let mut opening = block(133, vec![coinbase(vec![open_output(b"compactfault")])]);
        opening.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let opening_hash = opening.hash();
        let summary = state
            .connect_block(ConnectBlock {
                block_hash: opening_hash,
                height: 101,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &opening,
            })
            .expect("connect opening");

        let mut corrupt = NameTreeSnapshotPin {
            height: 100,
            block_hash: opening_hash,
            root: summary.resulting_tree_root,
        }
        .encode();
        *corrupt.last_mut().expect("checksum byte") ^= 1;
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Snapshots,
                &name_tree_snapshot_pin_key(100),
                &corrupt,
            )
            .expect("write corrupt pin");
        store.commit(batch).expect("commit corrupt pin");
        let before = store
            .snapshot()
            .expect("before snapshot")
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("before nodes");

        assert!(matches!(
            state.compact_name_tree_nodes(),
            Err(StateError::Codec(message)) if message.contains("checksum")
        ));
        assert_eq!(
            store
                .snapshot()
                .expect("after snapshot")
                .scan_prefix(ColumnFamily::NameTreeNodes, b"")
                .expect("after nodes"),
            before
        );
    }

    #[test]
    fn failed_compaction_commit_preserves_all_nodes() {
        let store = FailingCommitStore::new();
        let mut state = StoredStateEngine::with_services(
            store.clone(),
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("test engine");
        let tree = MemoryUrkel::from_entries([(
            hash_name("orphanedcompactnode").expect("orphan hash"),
            b"orphaned compact value".to_vec(),
        )])
        .expect("orphan tree");
        let records = tree.node_records().expect("orphan records");
        let mut batch = store.batch();
        for (root, raw) in &records {
            batch
                .put(ColumnFamily::NameTreeNodes, root.as_bytes(), raw)
                .expect("stage orphan node");
        }
        store.commit(batch).expect("commit orphan nodes");
        let before = store
            .snapshot()
            .expect("before snapshot")
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("before nodes");
        assert_eq!(before.len(), records.len());

        store.fail_next_commit();
        assert!(matches!(
            state.compact_name_tree_nodes(),
            Err(StateError::Store(StoreError::Io(message)))
                if message == "injected compaction failure"
        ));
        assert_eq!(
            store
                .snapshot()
                .expect("failed snapshot")
                .scan_prefix(ColumnFamily::NameTreeNodes, b"")
                .expect("nodes after failed commit"),
            before
        );

        let summary = state
            .compact_name_tree_nodes()
            .expect("successful compaction retry");
        assert_eq!(summary.nodes_deleted, records.len());
        assert!(store
            .snapshot()
            .expect("compacted snapshot")
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("compacted nodes")
            .is_empty());
    }

    #[test]
    fn streaming_compaction_bounds_delete_batches_and_is_idempotent() {
        let store = RecordingStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let tree = MemoryUrkel::from_entries(
            (0..16).map(|index| (NameHash::new([index; 32]), vec![index; 32])),
        )
        .expect("orphan tree");
        let records = tree.node_records().expect("orphan records");
        let mut batch = store.batch();
        for (root, raw) in &records {
            batch
                .put(ColumnFamily::NameTreeNodes, root.as_bytes(), raw)
                .expect("stage orphan record");
        }
        store.commit(batch).expect("commit orphan records");
        store.take_committed_batch_sizes();

        let summary = compact_name_tree_nodes_streaming(&store, 3).expect("stream compaction");
        assert_eq!(summary.nodes_before, records.len());
        assert_eq!(summary.nodes_retained, 0);
        assert_eq!(summary.nodes_deleted, records.len());
        let batches = store.take_committed_batch_sizes();
        assert!(batches.len() > 1);
        assert!(batches.iter().all(|size| *size <= 3));
        assert_eq!(batches.iter().sum::<usize>(), records.len());
        assert!(store
            .snapshot()
            .expect("compacted snapshot")
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("compacted nodes")
            .is_empty());

        assert_eq!(
            compact_name_tree_nodes_streaming(&store, 3)
                .expect("idempotent streaming compaction")
                .nodes_deleted,
            0
        );
        assert!(store.take_committed_batch_sizes().is_empty());
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn streaming_compaction_process_exit_is_restart_safe() {
        const CHILD_ENV: &str = "HSRD_COMPACTION_EXIT_CHILD";
        const PATH_ENV: &str = "HSRD_COMPACTION_EXIT_PATH";
        const DELETE_BATCH: usize = 64;

        if std::env::var_os(CHILD_ENV).is_some() {
            let path = std::path::PathBuf::from(
                std::env::var_os(PATH_ENV).expect("child compaction path"),
            );
            let store = open_store(&StoreConfig {
                path,
                backend: StoreBackend::RocksDb,
                durability: DurabilityPolicy::Sync,
            })
            .expect("open child store");
            let store = ExitAfterCommitStore::new(store, 1);
            compact_name_tree_nodes_streaming(&store, DELETE_BATCH)
                .expect("child exits after first durable delete chunk");
            panic!("fault-injected compaction child did not exit");
        }

        fn fixture_key(domain: u8, index: u32) -> NameHash {
            let mut raw = Vec::with_capacity(5);
            raw.push(domain);
            raw.extend_from_slice(&index.to_le_bytes());
            NameHash::new(blake2b_256(&raw))
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-stream-compaction-exit-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = StoreConfig {
            path: path.clone(),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        };
        let retained = MemoryUrkel::from_entries((0..64).map(|index| {
            (
                fixture_key(0x51, index),
                format!("retained-{index}").into_bytes(),
            )
        }))
        .expect("retained tree");
        let retained_records = retained.node_records().expect("retained records");
        let orphaned = MemoryUrkel::from_entries((0..512).map(|index| {
            (
                fixture_key(0xa7, index),
                format!("orphaned-{index}").into_bytes(),
            )
        }))
        .expect("orphaned tree");
        let orphaned_records = orphaned.node_records().expect("orphaned records");
        let nodes_before = retained_records.len() + orphaned_records.len();

        {
            let store = open_store(&config).expect("open fixture store");
            hns_store::initialize_schema(&store).expect("schema");
            let mut batch = store.batch();
            for (root, raw) in retained_records.iter().chain(&orphaned_records) {
                batch
                    .put(ColumnFamily::NameTreeNodes, root.as_bytes(), raw)
                    .expect("put fixture node");
            }
            batch
                .put(
                    ColumnFamily::Meta,
                    MetaKey::NameTreeRoot.as_bytes(),
                    retained.root().as_bytes(),
                )
                .expect("bind retained root");
            batch
                .put(
                    ColumnFamily::Meta,
                    MetaKey::NameTreeCommitRoot.as_bytes(),
                    retained.root().as_bytes(),
                )
                .expect("bind retained commit root");
            store.commit(batch).expect("commit compaction fixture");
        }

        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "tests::streaming_compaction_process_exit_is_restart_safe",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env(PATH_ENV, path.as_os_str())
            .status()
            .expect("spawn compaction fault child");
        assert_eq!(status.code(), Some(86));

        {
            let store = open_store(&config).expect("reopen interrupted store");
            let snapshot = store.snapshot().expect("interrupted snapshot");
            let nodes_after_exit = snapshot
                .scan_prefix(ColumnFamily::NameTreeNodes, b"")
                .expect("nodes after exit")
                .len();
            assert!(nodes_after_exit < nodes_before);
            assert!(nodes_after_exit > retained_records.len());
            assert_eq!(
                validate_persisted_name_tree(&snapshot, retained.root())
                    .expect("retained tree after exit"),
                retained_records.len()
            );
            drop(snapshot);

            let summary = compact_name_tree_nodes_streaming(&store, DELETE_BATCH)
                .expect("resume interrupted compaction");
            assert_eq!(summary.nodes_before, nodes_after_exit);
            assert_eq!(summary.nodes_retained, retained_records.len());
            assert_eq!(
                summary.nodes_deleted,
                nodes_after_exit - retained_records.len()
            );
            let snapshot = store.snapshot().expect("resumed snapshot");
            assert_eq!(
                snapshot
                    .scan_prefix(ColumnFamily::NameTreeNodes, b"")
                    .expect("nodes after resumed compaction")
                    .len(),
                retained_records.len()
            );
            assert_eq!(
                validate_persisted_name_tree(&snapshot, retained.root())
                    .expect("retained tree after resume"),
                retained_records.len()
            );
        }

        std::fs::remove_dir_all(path).expect("remove compaction fault store");
    }

    #[test]
    fn materialized_name_tree_proofs_are_snapshot_and_restart_stable() {
        let fixture: NameTreeFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/state-urkel-v1.json"
        ))
        .expect("fixture");
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");

        let first_state = &fixture.states[0];
        let first_root = TreeRoot::new(decode_hash(&fixture.incremental_roots[0].resulting_root));
        let first_tree = MemoryUrkel::from_entries([(
            NameHash::new(decode_hash(&first_state.name_hash)),
            decode_fixture_bytes(&first_state.encoded),
        )])
        .expect("first tree");
        assert_eq!(first_tree.root(), first_root);
        let mut first_batch = store.batch();
        first_batch
            .put(
                ColumnFamily::NameState,
                &decode_hash(&first_state.name_hash),
                &decode_fixture_bytes(&first_state.encoded),
            )
            .expect("first state");
        first_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                first_root.as_bytes(),
            )
            .expect("first root");
        first_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                first_root.as_bytes(),
            )
            .expect("first committed root");
        for (root, raw) in first_tree.node_records().expect("first records") {
            first_batch
                .put(ColumnFamily::NameTreeNodes, root.as_bytes(), &raw)
                .expect("first record");
        }
        store.commit(first_batch).expect("first commit");

        let first_engine = engine(store.clone());
        let frozen = first_engine.name_tree_snapshot().expect("first snapshot");
        assert_eq!(frozen.root(), first_root);
        let first_hash = NameHash::new(decode_hash(&first_state.name_hash));
        let first_proof = frozen.prove(first_hash).expect("first proof");
        assert_eq!(
            first_proof.verify_value(first_root).expect("verify first"),
            Some(decode_fixture_bytes(&first_state.encoded))
        );

        let second_state = &fixture.states[1];
        let second_hash = NameHash::new(decode_hash(&second_state.name_hash));
        let absent_before = frozen.prove(second_hash).expect("absence proof");
        assert_eq!(
            absent_before
                .verify_value(first_root)
                .expect("verify absence"),
            None
        );

        let second_root = TreeRoot::new(decode_hash(&fixture.incremental_roots[1].resulting_root));
        let second_tree = MemoryUrkel::from_entries([
            (first_hash, decode_fixture_bytes(&first_state.encoded)),
            (second_hash, decode_fixture_bytes(&second_state.encoded)),
        ])
        .expect("second tree");
        assert_eq!(second_tree.root(), second_root);
        let mut second_batch = store.batch();
        second_batch
            .put(
                ColumnFamily::NameState,
                second_hash.as_bytes(),
                &decode_fixture_bytes(&second_state.encoded),
            )
            .expect("second state");
        second_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                second_root.as_bytes(),
            )
            .expect("second root");
        second_batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeCommitRoot.as_bytes(),
                second_root.as_bytes(),
            )
            .expect("second committed root");
        for (root, raw) in second_tree.node_records().expect("second records") {
            second_batch
                .put(ColumnFamily::NameTreeNodes, root.as_bytes(), &raw)
                .expect("second record");
        }
        store.commit(second_batch).expect("second commit");

        assert_eq!(
            frozen
                .prove(second_hash)
                .expect("frozen absence proof")
                .verify_value(first_root)
                .expect("verify frozen absence"),
            None
        );
        drop(first_engine);

        let reopened = engine(store.clone());
        let current = reopened.name_tree_snapshot().expect("reopened snapshot");
        assert_eq!(current.root(), second_root);
        let second_proof = current.prove(second_hash).expect("second proof");
        assert_eq!(
            second_proof
                .verify_value(second_root)
                .expect("verify second"),
            Some(decode_fixture_bytes(&second_state.encoded))
        );
        assert_eq!(
            reopened
                .name_tree_snapshot()
                .expect("repeat snapshot")
                .prove(second_hash)
                .expect("repeat proof")
                .raw,
            second_proof.raw
        );
    }

    #[test]
    fn persisted_name_tree_proofs_survive_restart_and_reject_node_faults() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());
        let name = "hsrdpersistedproof";
        let name_hash = hash_name(name).expect("name hash");
        let mut opening = block(90, vec![coinbase(vec![open_output(name.as_bytes())])]);
        opening.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let summary = state
            .connect_block(ConnectBlock {
                block_hash: opening.hash(),
                height: 100,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &opening,
            })
            .expect("connect opening");
        assert_ne!(summary.resulting_tree_root, TreeRoot::ZERO);

        let (root, proof) = state.name_proof(name_hash).expect("persisted proof");
        let absent_hash = hash_name("hsrdabsentproof").expect("absent name hash");
        let (_, absent_proof) = state.name_proof(absent_hash).expect("non-inclusion proof");
        assert_eq!(root, summary.resulting_tree_root);
        let snapshot = store.snapshot().expect("snapshot");
        let encoded = snapshot
            .get(ColumnFamily::NameState, name_hash.as_bytes())
            .expect("name state read")
            .expect("name state");
        let nodes = snapshot
            .scan_prefix(ColumnFamily::NameTreeNodes, b"")
            .expect("node records");
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            validate_persisted_name_tree(&snapshot, root).expect("validate records"),
            nodes.len()
        );
        assert_eq!(
            proof.verify_value(root).expect("verify proof"),
            Some(encoded)
        );
        assert_eq!(
            absent_proof
                .verify_value(root)
                .expect("verify non-inclusion proof"),
            None
        );
        let root_record = snapshot
            .get(ColumnFamily::NameTreeNodes, root.as_bytes())
            .expect("root read")
            .expect("root record");
        drop(snapshot);
        drop(state);

        let mut reopened = engine(store.clone());
        let (_, repeated) = reopened.name_proof(name_hash).expect("reopened proof");
        assert_eq!(repeated.raw, proof.raw);
        let (_, repeated_absent) = reopened
            .name_proof(absent_hash)
            .expect("reopened non-inclusion proof");
        assert_eq!(repeated_absent.raw, absent_proof.raw);

        let mut missing = store.batch();
        missing
            .delete(ColumnFamily::NameTreeNodes, root.as_bytes())
            .expect("delete root record");
        store.commit(missing).expect("commit missing record");
        assert!(matches!(
            reopened.name_proof(name_hash),
            Err(StateError::NameTree(UrkelError::MissingNode(missing_root)))
                if missing_root == root
        ));

        let mut corrupted = root_record;
        *corrupted.last_mut().expect("record byte") ^= 1;
        let mut corrupt = store.batch();
        corrupt
            .put(ColumnFamily::NameTreeNodes, root.as_bytes(), &corrupted)
            .expect("corrupt root record");
        store.commit(corrupt).expect("commit corrupt record");
        assert!(matches!(
            reopened.name_proof(name_hash),
            Err(StateError::NameTree(UrkelError::NodeHashMismatch {
                expected,
                ..
            })) if expected == root
        ));

        let mut next = block(91, vec![coinbase(Vec::new())]);
        next.header.tree_root = *root.as_bytes();
        let next_hash = next.hash();
        assert!(matches!(
            reopened.connect_block(ConnectBlock {
                block_hash: next_hash,
                height: 201,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &next,
            }),
            Err(StateError::NameTree(UrkelError::NodeHashMismatch {
                expected,
                ..
            })) if expected == root
        ));
        let snapshot = store.snapshot().expect("post-rejection snapshot");
        assert!(snapshot
            .get(ColumnFamily::Undo, next_hash.as_bytes())
            .expect("undo read")
            .is_none());
        assert_eq!(
            load_stored_name_tree_root(&snapshot).expect("stored root"),
            root
        );
    }

    #[test]
    fn block_header_commits_pre_state_root_and_disconnect_restores_it() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());
        let mut opening = block(91, vec![coinbase(vec![open_output(b"hsrdstateroot")])]);
        opening.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let opening_hash = opening.hash();

        let summary = state
            .connect_block(ConnectBlock {
                block_hash: opening_hash,
                height: 100,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &opening,
            })
            .expect("connect OPEN block");
        assert_eq!(summary.inherited_tree_root, TreeRoot::ZERO);
        assert_ne!(summary.resulting_tree_root, TreeRoot::ZERO);
        assert!(summary.validation.tree_root_valid);
        let snapshot = store.snapshot().expect("post-state snapshot");
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("post-state root"),
            summary.resulting_tree_root
        );
        drop(snapshot);

        let fresh_store = MemoryStore::new();
        let mut fresh_state = engine(fresh_store);
        let mut incorrectly_committed = opening.clone();
        incorrectly_committed.header.tree_root = *summary.resulting_tree_root.as_bytes();
        assert!(matches!(
            fresh_state.connect_block(ConnectBlock {
                block_hash: incorrectly_committed.hash(),
                height: 100,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &incorrectly_committed,
            }),
            Err(StateError::HeaderTreeRootMismatch { .. })
        ));

        let disconnected = state
            .disconnect_block(DisconnectBlock {
                block_hash: opening_hash,
                height: 100,
            })
            .expect("disconnect OPEN block");
        assert_eq!(
            disconnected.inherited_tree_root,
            summary.resulting_tree_root
        );
        assert_eq!(disconnected.resulting_tree_root, TreeRoot::ZERO);
        let snapshot = store.snapshot().expect("restored snapshot");
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("restored root"),
            TreeRoot::ZERO
        );
        assert!(snapshot
            .scan_prefix(ColumnFamily::NameState, b"")
            .expect("name states")
            .is_empty());
    }

    #[test]
    fn disconnect_rejects_corrupt_root_binding_without_mutation() {
        let store = MemoryStore::new();
        let mut state = engine(store.clone());
        let mut opening = block(92, vec![coinbase(vec![open_output(b"hsrdstateroot")])]);
        opening.header.tree_root = *TreeRoot::ZERO.as_bytes();
        let opening_hash = opening.hash();

        let summary = state
            .connect_block(ConnectBlock {
                block_hash: opening_hash,
                height: 100,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &opening,
            })
            .expect("connect OPEN block");
        assert_ne!(summary.resulting_tree_root, TreeRoot::ZERO);

        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                TreeRoot::ZERO.as_bytes(),
            )
            .expect("corrupt root binding");
        store.commit(corrupt).expect("commit corrupt root binding");

        assert!(matches!(
            state.disconnect_block(DisconnectBlock {
                block_hash: opening_hash,
                height: 100,
            }),
            Err(StateError::UndoResultingTreeRootMismatch { expected, actual })
                if expected == summary.resulting_tree_root && actual == TreeRoot::ZERO
        ));

        let snapshot = store
            .snapshot()
            .expect("snapshot after rejected disconnect");
        assert!(snapshot
            .get(ColumnFamily::Undo, opening_hash.as_bytes())
            .expect("undo lookup")
            .is_some());
        assert_eq!(
            snapshot
                .scan_prefix(ColumnFamily::NameState, b"")
                .expect("name states")
                .len(),
            1
        );
    }

    #[test]
    fn durable_name_tree_binding_detects_materialized_state_corruption() {
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let hash = hash_name("alpha").expect("name hash");
        let mut state = NameState::null(hash);
        state.initialize(b"alpha".to_vec(), 100);
        let mut batch = store.batch();
        write_name_state_to_batch(&mut batch, &state).expect("write state");
        store
            .commit(batch)
            .expect("commit corrupt state without root binding");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            verify_stored_name_tree_root(&snapshot),
            Err(StateError::StoredTreeRootMismatch { .. })
        ));
        assert!(matches!(
            materialize_name_tree_snapshot(&snapshot),
            Err(StateError::StoredTreeRootMismatch { .. })
        ));
    }

    #[test]
    fn exact_hsd_name_state_codec_round_trips() {
        let hash = hash_name("alpha").expect("name hash");
        let state = NameState {
            name_hash: hash,
            name: b"alpha".to_vec(),
            height: 10,
            renewal: 20,
            owner: Outpoint {
                txid: Txid::new([3; 32]),
                index: 7,
            },
            value: 50,
            highest: 80,
            data: vec![1, 2, 3],
            transfer: 30,
            revoked: 40,
            claimed: 5,
            renewals: 9,
            registered: true,
            expired: true,
            weak: true,
        };
        let encoded = encode_name_state(&state).expect("encode");
        assert_eq!(decode_name_state(&hash, &encoded).expect("decode"), state);
        assert_eq!(encoded[0], 5);
        assert_eq!(&encoded[1..6], b"alpha");
    }

    #[derive(Deserialize)]
    struct NameCodecFixture {
        vectors: Vec<NameCodecVector>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameCodecVector {
        name_hash: String,
        raw: String,
        json: NameCodecJson,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NameCodecJson {
        name: String,
        height: u32,
        renewal: u32,
        owner_hash: String,
        owner_index: u32,
        value: u64,
        highest: u64,
        data: String,
        transfer: u32,
        revoked: u32,
        claimed: u32,
        renewals: u32,
        registered: bool,
        expired: bool,
        weak: bool,
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut bytes = [0u8; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .expect("valid fixture hex");
        }
        bytes
    }

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16).expect("valid fixture hex")
            })
            .collect()
    }

    #[test]
    fn name_state_codec_matches_pinned_hsd_vectors() {
        let fixture: NameCodecFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/codec-v1.json"
        ))
        .expect("fixture");

        for vector in fixture.vectors {
            let name_hash = NameHash::new(decode_hex::<32>(&vector.name_hash));
            let raw = decode_hex_vec(&vector.raw);
            let expected = NameState {
                name_hash,
                name: vector.json.name.into_bytes(),
                height: vector.json.height,
                renewal: vector.json.renewal,
                owner: Outpoint {
                    txid: Txid::new(decode_hex::<32>(&vector.json.owner_hash)),
                    index: vector.json.owner_index,
                },
                value: vector.json.value,
                highest: vector.json.highest,
                data: decode_hex_vec(&vector.json.data),
                transfer: vector.json.transfer,
                revoked: vector.json.revoked,
                claimed: vector.json.claimed,
                renewals: vector.json.renewals,
                registered: vector.json.registered,
                expired: vector.json.expired,
                weak: vector.json.weak,
            };
            assert_eq!(
                decode_name_state(&name_hash, &raw).expect("decode"),
                expected
            );
            assert_eq!(encode_name_state(&expected).expect("encode"), raw);
        }
    }

    #[test]
    fn contextual_name_transitions_match_the_pinned_hsd_oracle() {
        let fixture: NameTransitionFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/transitions-v1.json"
        ))
        .expect("name transition fixture");
        assert_eq!(fixture.network, "regtest");

        let expected = Network::Regtest.params().names;
        let actual = fixture.parameters;
        assert_eq!(actual.auction_start, expected.auction_start);
        assert_eq!(actual.rollout_interval, expected.rollout_interval);
        assert_eq!(actual.lockup_period, expected.lockup_period);
        assert_eq!(actual.renewal_window, expected.renewal_window);
        assert_eq!(actual.renewal_period, expected.renewal_period);
        assert_eq!(actual.renewal_maturity, expected.renewal_maturity);
        assert_eq!(actual.claim_period, expected.claim_period);
        assert_eq!(actual.alexa_lockup_period, expected.alexa_lockup_period);
        assert_eq!(actual.claim_frequency, expected.claim_frequency);
        assert_eq!(actual.bidding_period, expected.bidding_period);
        assert_eq!(actual.reveal_period, expected.reveal_period);
        assert_eq!(actual.tree_interval, expected.tree_interval);
        assert_eq!(actual.transfer_lockup, expected.transfer_lockup);
        assert_eq!(actual.auction_maturity, expected.auction_maturity);
        assert_eq!(actual.no_rollout, expected.no_rollout);
        assert_eq!(actual.no_reserved, expected.no_reserved);
        assert_eq!(fixture.cases.len(), 28);

        for case in fixture.cases {
            let transaction = Transaction::decode(&decode_hex_vec(&case.transaction_raw))
                .unwrap_or_else(|error| panic!("{} transaction: {error}", case.id));
            let input_coins = case
                .input_coins
                .into_iter()
                .map(|coin| Coin {
                    outpoint: Outpoint {
                        txid: Txid::new(decode_hex::<32>(&coin.outpoint_txid)),
                        index: coin.outpoint_index,
                    },
                    value: coin.value,
                    height: coin.height,
                    coinbase: coin.coinbase,
                    address: Address::new(coin.address_version, decode_hex_vec(&coin.address_hash))
                        .expect("transition coin address"),
                    covenant: Covenant {
                        kind: CovenantKind::from_u8(coin.covenant_type),
                        items: coin
                            .covenant_items
                            .iter()
                            .map(|item| decode_hex_vec(item))
                            .collect(),
                    },
                })
                .collect::<Vec<_>>();
            assert!(case.linkage_result >= 0, "oracle linkage {}", case.id);
            verify_transaction_covenant_links(&transaction, &input_coins)
                .unwrap_or_else(|error| panic!("{} native linkage: {error}", case.id));

            let name_hash = NameHash::new(decode_hex::<32>(&case.name_hash));
            let mut state = decode_name_state(&name_hash, &decode_hex_vec(&case.pre_state_raw))
                .unwrap_or_else(|error| panic!("{} pre-state: {error}", case.id));
            let context = FixtureNameContext {
                historical: case.historical,
                heights: case
                    .active_chain
                    .into_iter()
                    .filter(|entry| entry.main)
                    .map(|entry| (BlockHash::new(decode_hex::<32>(&entry.hash)), entry.height))
                    .collect(),
            };
            let name_outputs = transaction
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, output)| output.covenant.kind.is_name())
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            assert_eq!(name_outputs.len(), 1, "oracle case {}", case.id);
            let result = verify_and_apply_name_covenant(
                &transaction,
                name_outputs[0],
                case.height,
                expected,
                NameFlags::from_bits(case.name_flags),
                &mut state,
                &context,
            );
            assert_eq!(result.is_ok(), case.accepted, "oracle case {}", case.id);

            if case.accepted {
                assert!(case.reason.is_none(), "accepted oracle case {}", case.id);
                let post_raw = decode_hex_vec(
                    case.post_state_raw
                        .as_deref()
                        .expect("accepted transition post-state"),
                );
                assert_eq!(
                    encode_name_state(&state).expect("native transition post-state"),
                    post_raw,
                    "oracle case {}",
                    case.id
                );
                assert_eq!(
                    state,
                    decode_name_state(&name_hash, &post_raw).expect("oracle transition post-state"),
                    "oracle case {}",
                    case.id
                );
            } else {
                assert!(case.reason.is_some(), "rejected oracle case {}", case.id);
                assert!(
                    case.post_state_raw.is_none(),
                    "rejected oracle case {}",
                    case.id
                );
            }
        }
    }

    #[test]
    fn independently_generated_contextual_invalid_corpus_matches_pinned_hsd() {
        let fixture: ContextualInvalidFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/chains/invalid-contextual-v1.json"
        ))
        .expect("contextual invalid corpus fixture");
        assert_eq!(fixture.schema, 1);
        assert_eq!(fixture.network, "regtest");
        assert_eq!(fixture.oracle.repository, "handshake-org/hsd");
        assert_eq!(
            fixture.oracle.revision,
            "698e252ebc7b5c1dd0a9587e342fdd153d020ae4"
        );
        assert!(!fixture.oracle.hsd_version.is_empty());
        assert_eq!(fixture.oracle.route, "Chain.verifyInputs");
        assert_eq!(
            fixture.generation.method,
            "independent-fixed-state-boundary-mutations"
        );
        assert_eq!(
            fixture.generation.seed_domain,
            "meshmine/hsrd-invalid-contextual/v1"
        );
        assert!(!fixture.generation.upstream_invalid_vectors_copied);
        assert_eq!(
            fixture.generation.candidate_height,
            fixture.generation.parent_height + 1
        );
        assert_eq!(
            fixture.generation.coinbase_maturity,
            Network::Regtest.params().coinbase_maturity
        );
        assert_eq!(
            fixture
                .cases
                .iter()
                .filter(|case| !case.oracle.accepted)
                .count(),
            fixture.generation.invalid_cases
        );
        assert_eq!(
            fixture
                .cases
                .iter()
                .filter(|case| case.oracle.accepted)
                .count(),
            fixture.generation.valid_controls
        );
        assert_eq!(fixture.cases.len(), 12);
        assert_eq!(fixture.context_headers.len(), 22);

        for case in fixture.cases {
            assert_eq!(case.target, "block-context", "oracle case {}", case.id);
            let expected_reason = match case.mutation_class.as_str() {
                "valid-future-program"
                | "valid-height-sequence"
                | "valid-time-sequence"
                | "valid-mandatory-script" => "valid",
                "missing-input" | "in-block-double-spend" => "bad-txns-inputs-missingorspent",
                "premature-coinbase-spend" => "bad-txns-premature-spend-of-coinbase",
                "input-value-below-output" => "bad-txns-in-belowout",
                "height-sequence-lock" | "time-sequence-lock" => "bad-txns-nonfinal",
                "mandatory-script-mismatch" => "mandatory-script-verify-flag-failed",
                "coinbase-overclaim" => "bad-cb-amount",
                other => panic!("{}: unknown mutation class {other}", case.id),
            };
            assert_eq!(
                case.oracle.reason, expected_reason,
                "{}: pinned HSD reason",
                case.id
            );
            assert_eq!(
                case.oracle.score == 0,
                matches!(
                    case.mutation_class.as_str(),
                    "valid-future-program"
                        | "valid-height-sequence"
                        | "valid-time-sequence"
                        | "valid-mandatory-script"
                        | "premature-coinbase-spend"
                        | "coinbase-overclaim"
                ),
                "{}: pinned HSD score",
                case.id
            );

            let block = Block::decode(&decode_hex_vec(&case.raw))
                .unwrap_or_else(|error| panic!("{} candidate block: {error}", case.id));
            hns_consensus::validate_block_body(&block)
                .unwrap_or_else(|error| panic!("{} contextual body control: {error}", case.id));

            let store = MemoryStore::new();
            let mut engine = StoredStateEngine::with_native_authorization_and_verified_name_flags(
                store.clone(),
                Network::Regtest,
                NameFlags::NONE,
            )
            .expect("native contextual corpus engine");
            let mut seed = store.batch();
            let mut previous = BlockHash::ZERO;
            for expected in &fixture.context_headers {
                let header = Header {
                    nonce: expected.height,
                    time: expected.time,
                    prev_block: previous,
                    bits: Network::Regtest.params().pow.bits,
                    ..Header::default()
                };
                let hash = header.hash();
                seed.put(
                    ColumnFamily::Headers,
                    hash.as_bytes(),
                    &HeaderRecord {
                        hash,
                        height: expected.height,
                        chainwork: Uint256::ONE,
                        header,
                        status: BlockStatus::default(),
                    }
                    .encode(),
                )
                .expect("context header");
                write_canonical_height_to_batch(&mut seed, expected.height, hash)
                    .expect("canonical context header");
                previous = hash;
            }
            let input_outpoints = case
                .input_coins
                .iter()
                .map(|expected| {
                    let coin = Coin {
                        outpoint: Outpoint {
                            txid: Txid::new(decode_hex::<32>(&expected.outpoint_txid)),
                            index: expected.outpoint_index,
                        },
                        value: expected.value,
                        height: expected.height,
                        coinbase: expected.coinbase,
                        address: Address::new(
                            expected.address_version,
                            decode_hex_vec(&expected.address_hash),
                        )
                        .expect("contextual corpus coin address"),
                        covenant: Covenant {
                            kind: CovenantKind::from_u8(expected.covenant_type),
                            items: expected
                                .covenant_items
                                .iter()
                                .map(|item| decode_hex_vec(item))
                                .collect(),
                        },
                    };
                    seed.put(
                        ColumnFamily::Utxo,
                        &encode_outpoint_key(&coin.outpoint),
                        &encode_coin(&coin),
                    )
                    .expect("contextual corpus coin");
                    coin.outpoint
                })
                .collect::<Vec<_>>();
            store.commit(seed).expect("contextual corpus seed");

            let fingerprint = |store: &MemoryStore| {
                let snapshot = store.snapshot().expect("contextual corpus snapshot");
                ColumnFamily::ALL
                    .into_iter()
                    .map(|family| {
                        (
                            family,
                            snapshot
                                .scan_prefix(family, b"")
                                .expect("contextual corpus state scan"),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            let before = fingerprint(&store);
            let result = engine.connect_block(ConnectBlock {
                block_hash: block.hash(),
                height: fixture.generation.candidate_height,
                coinbase_maturity: fixture.generation.coinbase_maturity,
                block_reward: Network::Regtest
                    .params()
                    .block_reward(fixture.generation.candidate_height),
                block: &block,
            });
            assert_eq!(
                result.is_ok(),
                case.oracle.accepted,
                "{}: HSD/hsrd contextual admission",
                case.id
            );

            if case.oracle.accepted {
                result.unwrap_or_else(|error| panic!("{} native control: {error}", case.id));
                assert!(
                    engine
                        .load_undo(&block.hash())
                        .expect("accepted corpus undo")
                        .is_some(),
                    "{}: accepted candidate undo",
                    case.id
                );
                engine
                    .disconnect_block(DisconnectBlock {
                        block_hash: block.hash(),
                        height: fixture.generation.candidate_height,
                    })
                    .unwrap_or_else(|error| panic!("{} control disconnect: {error}", case.id));
                assert_eq!(
                    fingerprint(&store),
                    before,
                    "{}: accepted control exact disconnect",
                    case.id
                );
            } else {
                let error = result.expect_err("rejected contextual corpus case");
                assert!(error.is_consensus_invalid(), "{}: {error}", case.id);
                let class_matches = match case.mutation_class.as_str() {
                    "missing-input" => matches!(error, StateError::MissingCoin(_)),
                    "in-block-double-spend" => {
                        matches!(error, StateError::DuplicateSpend(_))
                    }
                    "premature-coinbase-spend" => {
                        matches!(error, StateError::PrematureCoinbaseSpend { .. })
                    }
                    "input-value-below-output" => {
                        matches!(error, StateError::InputValueBelowOutput { .. })
                    }
                    "height-sequence-lock" | "time-sequence-lock" => {
                        matches!(error, StateError::RelativeLocks)
                    }
                    "mandatory-script-mismatch" => {
                        matches!(error, StateError::InputAuthorization { .. })
                    }
                    "coinbase-overclaim" => {
                        matches!(error, StateError::CoinbaseValueExceedsReward { .. })
                    }
                    other => panic!("{}: rejected unknown mutation {other}", case.id),
                };
                assert!(class_matches, "{}: native rejection {error}", case.id);
                assert_eq!(
                    fingerprint(&store),
                    before,
                    "{}: rejected candidate changed durable state",
                    case.id
                );
                assert!(
                    engine
                        .load_undo(&block.hash())
                        .expect("rejected corpus undo lookup")
                        .is_none(),
                    "{}: rejected candidate wrote undo",
                    case.id
                );
                for outpoint in &input_outpoints {
                    assert!(
                        engine.coin(outpoint).expect("seeded coin read").is_some(),
                        "{}: rejected candidate spent input",
                        case.id
                    );
                }
            }
        }
    }

    #[test]
    fn name_codec_rejects_unknown_field_bits() {
        let hash = hash_name("alpha").expect("name hash");
        let mut encoded = encode_name_state(&NameState::null(hash)).expect("encode");
        let field_offset = 1 + 2 + 4 + 4;
        encoded[field_offset..field_offset + 2].copy_from_slice(&(1u16 << 15).to_le_bytes());
        assert!(decode_name_state(&hash, &encoded).is_err());
    }

    #[test]
    fn default_engine_rejects_noncoinbase_authorization_without_mutation() {
        let store = MemoryStore::new();
        let mut engine = StoredStateEngine::for_network(store, Network::Regtest).expect("engine");
        let funding = coinbase(vec![output(100)]);
        let funding_outpoint = Outpoint {
            txid: funding.txid(),
            index: 0,
        };
        let funding_block = block(1, vec![funding]);
        engine
            .connect_block(ConnectBlock {
                block_hash: funding_block.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &funding_block,
            })
            .expect("funding block");

        let spend = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: funding_outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(90)],
            locktime: 0,
        };
        let candidate = block(2, vec![coinbase(Vec::new()), spend]);
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &candidate,
            }),
            Err(StateError::InputAuthorization { .. })
        ));
        assert!(engine.coin(&funding_outpoint).expect("coin").is_some());
        assert!(engine.load_undo(&candidate.hash()).expect("undo").is_none());
    }

    #[test]
    fn failed_connect_does_not_commit_partial_utxo_changes() {
        let store = MemoryStore::new();
        let mut engine = engine(store);
        let funding = coinbase(vec![output(100)]);
        let funding_outpoint = Outpoint {
            txid: funding.txid(),
            index: 0,
        };
        let funding_block = block(10, vec![funding]);
        engine
            .connect_block(ConnectBlock {
                block_hash: funding_block.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &funding_block,
            })
            .expect("funding");

        let inflation = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: funding_outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(101)],
            locktime: 0,
        };
        let candidate = block(11, vec![coinbase(Vec::new()), inflation]);
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &candidate,
            }),
            Err(StateError::InputValueBelowOutput { .. })
        ));
        assert!(engine.coin(&funding_outpoint).expect("coin").is_some());
    }

    #[test]
    fn block_sigop_limit_is_contextual_and_atomic() {
        let store = MemoryStore::new();
        let mut engine = engine(store);
        let funding = coinbase(vec![Output {
            value: 100,
            address: Address::new(0, vec![0x55; 32]).expect("script-hash address"),
            covenant: covenant(),
        }]);
        let funding_outpoint = Outpoint {
            txid: funding.txid(),
            index: 0,
        };
        let funding_block = block(12, vec![funding]);
        engine
            .connect_block(ConnectBlock {
                block_hash: funding_block.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &funding_block,
            })
            .expect("funding");

        // With no preceding OP_1..OP_16, HSD assigns the conservative maximum
        // of 20 sigops to each CHECKMULTISIG opcode.
        let checkmultisig_count =
            usize::try_from(MAX_BLOCK_SIGOPS / 20 + 1).expect("sigop fixture length");
        let spend = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: funding_outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![vec![0xae; checkmultisig_count]],
                },
            }],
            outputs: vec![output(90)],
            locktime: 0,
        };
        let candidate = block(13, vec![coinbase(Vec::new()), spend]);
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &candidate,
            }),
            Err(StateError::BlockSigopsExceeded {
                actual: 80_020,
                maximum: MAX_BLOCK_SIGOPS,
            })
        ));
        assert!(engine.coin(&funding_outpoint).expect("coin").is_some());
        assert!(engine.load_undo(&candidate.hash()).expect("undo").is_none());
    }

    #[test]
    fn special_coinbase_inputs_fail_closed() {
        let store = MemoryStore::new();
        let mut engine = engine(store);
        let mut special = coinbase(vec![output(100)]);
        special.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![vec![1]],
            },
        });
        let candidate = block(20, vec![special]);
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &candidate,
            }),
            Err(StateError::UnsupportedCoinbaseIssuance)
        ));
    }

    #[test]
    fn historical_airdrop_route_retains_sanity_but_assumes_proof_cryptography() {
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let proof = &fixture.proofs[0];
        let verifier = AirdropCoinbaseIssuanceVerifier::faucet_only(DeploymentState::from_states(
            [ThresholdState::Defined; 4],
        ));
        let mut transaction = coinbase(vec![output(0)]);
        transaction.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![decode_fixture_bytes(&proof.raw)],
            },
        });
        transaction.outputs.push(Output {
            value: proof.value - proof.fee,
            address: Address::new(proof.version, decode_fixture_bytes(&proof.address))
                .expect("airdrop address"),
            covenant: covenant(),
        });

        assert!(matches!(
            verifier.verify_coinbase(&transaction, 0, 0, Network::Regtest),
            Err(StateError::AirdropVerification(_))
        ));
        let historical = verifier
            .verify_historical_coinbase(&transaction, 0, 0, Network::Regtest)
            .expect("checkpoint-backed airdrop sanity route");
        assert_eq!(historical.conjured, 0);
        assert_eq!(historical.airdrop_positions, vec![proof.position]);
        assert!(historical.claims.is_empty());
        assert!(historical.claims_and_airdrops_valid);
    }

    #[test]
    fn historical_airdrop_hardening_matches_hsd_malformed_key_behavior() {
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let mut proof =
            AirdropProof::decode(&decode_fixture_bytes(&fixture.proofs[0].raw)).expect("proof");
        proof.key = vec![0xff];
        assert!(proof.is_sane());
        assert!(proof.key().is_err());

        let verifier =
            AirdropCoinbaseIssuanceVerifier::faucet_only(DeploymentState::from_states([
                ThresholdState::Active,
                ThresholdState::Defined,
                ThresholdState::Defined,
                ThresholdState::Defined,
            ]));
        let mut transaction = coinbase(vec![output(0)]);
        transaction.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![proof.encode().expect("malformed-key proof encoding")],
            },
        });
        transaction.outputs.push(output(0));

        let historical = verifier
            .verify_historical_coinbase(&transaction, 0, 0, Network::Regtest)
            .expect("HSD treats an undecodable key as non-weak before GooSig stop");
        assert_eq!(historical.airdrop_positions, vec![proof.index]);
    }

    #[test]
    fn faucet_issuance_spends_rejects_duplicates_and_undoes_hsd_position() {
        let fixture: AirdropFixture =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let proof = fixture.faucet;
        let store = MemoryStore::new();
        let mut engine = StoredStateEngine::with_services(
            store,
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(AirdropCoinbaseIssuanceVerifier::faucet_only(
                DeploymentState::from_states([ThresholdState::Defined; 4]),
            )),
        )
        .expect("airdrop state engine");

        let mut transaction = coinbase(vec![output(0)]);
        transaction.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![decode_fixture_bytes(&proof.raw)],
            },
        });
        transaction.outputs.push(Output {
            value: proof.value - proof.fee,
            address: Address::new(proof.version, decode_fixture_bytes(&proof.address))
                .expect("faucet address"),
            covenant: covenant(),
        });
        let candidate = block(30, vec![transaction]);
        let summary = engine
            .connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &candidate,
            })
            .expect("valid faucet issuance");
        assert!(summary.validation.claims_and_airdrops_valid);
        let undo = engine
            .load_undo(&candidate.hash())
            .expect("undo read")
            .expect("undo record");
        assert_eq!(undo.airdrop_positions, vec![proof.position]);

        let snapshot = engine.store().snapshot().expect("snapshot");
        let field = load_airdrop_field(&snapshot).expect("airdrop field");
        let (byte, mask) = airdrop_mask(proof.position).expect("field position");
        assert_eq!(field[byte] & mask, mask);
        drop(snapshot);

        let duplicate = block(31, candidate.transactions.clone());
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: duplicate.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &duplicate,
            }),
            Err(StateError::AirdropAlreadySpent(position)) if position == proof.position
        ));

        engine
            .disconnect_block(DisconnectBlock {
                block_hash: candidate.hash(),
                height: 0,
            })
            .expect("faucet disconnect");
        let snapshot = engine.store().snapshot().expect("snapshot");
        let field = load_airdrop_field(&snapshot).expect("airdrop field");
        assert_eq!(field[byte] & mask, 0);
    }

    #[test]
    fn authenticated_claim_connects_name_state_and_disconnect_restores_it() {
        let reserved = reserved_name(b"nl").expect("reserved nl name");
        let name_hash = hash_name("nl").expect("nl name hash");
        let commit_header = Header {
            time: 1_600_000_000,
            ..Header::default()
        };
        let commit_hash = commit_header.hash();
        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        let mut header_batch = store.batch();
        header_batch
            .put(
                ColumnFamily::Headers,
                commit_hash.as_bytes(),
                &HeaderRecord {
                    hash: commit_hash,
                    height: 1,
                    chainwork: Uint256::ONE,
                    header: commit_header,
                    status: BlockStatus::default(),
                }
                .encode(),
            )
            .expect("commit header");
        write_canonical_height_to_batch(&mut header_batch, 1, commit_hash)
            .expect("canonical commit height");
        store.commit(header_batch).expect("commit header index");

        let fee = 1_000u64;
        let claim = VerifiedClaim {
            name_hash,
            name: reserved.name.clone(),
            weak: false,
            commit_hash: *commit_hash.as_bytes(),
            commit_height: 1,
            value: reserved.value,
            fee,
            conjured: reserved.value,
        };
        let mut engine = StoredStateEngine::with_services(
            store.clone(),
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(AuthenticatedClaimIssuer {
                claim: claim.clone(),
            }),
        )
        .expect("claim state engine");

        let mut transaction = coinbase(vec![output(0)]);
        transaction.inputs.push(Input {
            previous_output: Outpoint::null(),
            sequence: u32::MAX,
            witness: Witness {
                items: vec![vec![0]],
            },
        });
        transaction.outputs.push(Output {
            value: reserved.value - fee,
            address: address(),
            covenant: Covenant {
                kind: CovenantKind::Claim,
                items: vec![
                    name_hash.as_bytes().to_vec(),
                    2u32.to_le_bytes().to_vec(),
                    b"nl".to_vec(),
                    vec![0],
                    commit_hash.as_bytes().to_vec(),
                    1u32.to_le_bytes().to_vec(),
                ],
            },
        });
        let candidate = block(32, vec![transaction]);
        let summary = engine
            .connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: 2,
                coinbase_maturity: 0,
                block_reward: 0,
                block: &candidate,
            })
            .expect("authenticated claim connect");
        assert_eq!(summary.names_changed, 1);
        assert!(summary.validation.claims_and_airdrops_valid);

        let state = engine
            .name_state(&name_hash)
            .expect("name state read")
            .expect("claimed name state");
        assert_eq!(state.name, b"nl");
        assert_eq!(state.height, 2);
        assert_eq!(state.renewal, 2);
        assert_eq!(state.claimed, 1);
        assert_eq!(state.owner.txid, candidate.transactions[0].txid());
        assert_eq!(state.owner.index, 1);
        assert!(!state.weak);

        engine
            .disconnect_block(DisconnectBlock {
                block_hash: candidate.hash(),
                height: 2,
            })
            .expect("claim disconnect");
        assert!(engine
            .name_state(&name_hash)
            .expect("name state read")
            .is_none());
    }

    #[test]
    fn historical_claim_route_retains_time_but_assumes_dnssec_cryptography() {
        let fixture: MainnetClaimHistoryFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-history-v1.json"
        ))
        .expect("mainnet claim history fixture");
        let historical = Block::decode(&decode_fixture_bytes(&fixture.block.raw))
            .expect("canonical mainnet claim block");
        let mut coinbase = historical.transactions[0].clone();
        let claim_input = coinbase
            .outputs
            .iter()
            .position(|output| output.covenant.kind == CovenantKind::Claim)
            .expect("claim output");
        let proof_raw = &mut coinbase.inputs[claim_input].witness.items[0];
        *proof_raw.last_mut().expect("ownership proof byte") ^= 1;
        let altered = OwnershipProof::decode(proof_raw).expect("altered ownership proof codec");
        assert!(altered.verify_time(fixture.canonical_context.parent_time));

        let verifier = AirdropCoinbaseIssuanceVerifier::native(DeploymentState::from_states(
            [ThresholdState::Defined; 4],
        ))
        .expect("native issuance verifier");
        assert!(matches!(
            verifier.verify_coinbase(
                &coinbase,
                fixture.block.height,
                fixture.canonical_context.parent_time,
                Network::Mainnet,
            ),
            Err(StateError::ClaimVerification(_))
        ));
        let assumed = verifier
            .verify_historical_coinbase(
                &coinbase,
                fixture.block.height,
                fixture.canonical_context.parent_time,
                Network::Mainnet,
            )
            .expect("checkpoint-backed claim format/time route");
        assert_eq!(assumed.conjured, 0);
        assert_eq!(assumed.claims.len(), fixture.block.claims.len());
        assert!(assumed.airdrop_positions.is_empty());
        assert!(assumed.claims_and_airdrops_valid);

        let mut checkpoint_shape = coinbase;
        checkpoint_shape.outputs[claim_input].covenant.items[1] = fixture
            .block
            .height
            .saturating_add(1)
            .to_le_bytes()
            .to_vec();
        checkpoint_shape.outputs[claim_input]
            .covenant
            .items
            .push(vec![0xaa]);
        let assumed = verifier
            .verify_historical_coinbase(
                &checkpoint_shape,
                fixture.block.height,
                fixture.canonical_context.parent_time,
                Network::Mainnet,
            )
            .expect("HSD historical route leaves full claim covenant shape assumed");
        assert_eq!(assumed.claims.len(), fixture.block.claims.len());
    }

    #[test]
    fn canonical_mainnet_claim_coinbase_connects_with_exact_parent_time() {
        let fixture: MainnetClaimHistoryFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-history-v1.json"
        ))
        .expect("mainnet claim history fixture");
        let historical = Block::decode(&decode_fixture_bytes(&fixture.block.raw))
            .expect("canonical mainnet claim block");
        let coinbase = historical.transactions[0].clone();
        assert_eq!(fixture.block.claims.len(), 2);

        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        seed_mainnet_claim_headers(&store, &fixture.canonical_context);
        let mut engine = StoredStateEngine::with_services(
            store,
            Network::Mainnet,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(
                AirdropCoinbaseIssuanceVerifier::native(DeploymentState::from_states(
                    [ThresholdState::Defined; 4],
                ))
                .expect("native issuance verifier"),
            ),
        )
        .expect("mainnet claim state engine");

        let candidate = block(fixture.block.height, vec![coinbase.clone()]);
        let output_value = coinbase
            .outputs
            .iter()
            .try_fold(0u64, |total, output| total.checked_add(output.value))
            .expect("coinbase output value");
        let conjured = fixture
            .block
            .claims
            .iter()
            .try_fold(0u64, |total, claim| total.checked_add(claim.conjured))
            .expect("claim conjured value");
        let ordinary_reward_and_fees = output_value
            .checked_sub(conjured)
            .expect("ordinary coinbase component");
        let summary = engine
            .connect_block(ConnectBlock {
                block_hash: candidate.hash(),
                height: fixture.block.height,
                coinbase_maturity: 100,
                block_reward: ordinary_reward_and_fees,
                block: &candidate,
            })
            .expect("canonical mainnet claim coinbase");
        assert_eq!(summary.coins_created, coinbase.outputs.len());
        assert_eq!(summary.names_changed, fixture.block.claims.len());
        assert!(summary.validation.claims_and_airdrops_valid);

        for expected in &fixture.block.claims {
            let name_hash = hash_name(&expected.name).expect("claimed name hash");
            let state = engine
                .name_state(&name_hash)
                .expect("claimed name state read")
                .expect("claimed name state");
            assert_eq!(state.name, expected.name.as_bytes());
            assert_eq!(state.height, fixture.block.height);
            assert_eq!(state.renewal, fixture.block.height);
            assert_eq!(state.claimed, expected.commit_height);
            assert_eq!(state.owner.txid, coinbase.txid());
            assert_eq!(state.weak, expected.weak);
        }

        engine
            .disconnect_block(DisconnectBlock {
                block_hash: candidate.hash(),
                height: fixture.block.height,
            })
            .expect("mainnet claim disconnect");
        for expected in &fixture.block.claims {
            let name_hash = hash_name(&expected.name).expect("claimed name hash");
            assert!(engine
                .name_state(&name_hash)
                .expect("restored name state read")
                .is_none());
        }
    }

    #[test]
    fn mempool_claim_context_reuses_exact_mainnet_state_transition() {
        let fixture: MainnetClaimHistoryFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-history-v1.json"
        ))
        .expect("mainnet claim history fixture");
        let historical = Block::decode(&decode_fixture_bytes(&fixture.block.raw))
            .expect("canonical mainnet claim block");
        let coinbase = &historical.transactions[0];
        let verifier = AirdropCoinbaseIssuanceVerifier::native(DeploymentState::from_states(
            [ThresholdState::Defined; 4],
        ))
        .expect("native issuance verifier");
        let issuance = verifier
            .verify_coinbase(
                coinbase,
                fixture.block.height,
                fixture.canonical_context.parent_time,
                Network::Mainnet,
            )
            .expect("canonical mainnet claim authentication");

        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        seed_mainnet_claim_headers(&store, &fixture.canonical_context);
        let snapshot = store.snapshot().expect("claim context snapshot");
        for claim in &issuance.claims {
            let output = &coinbase.outputs[claim.output_index];
            verify_mempool_claim_context(
                &snapshot,
                output,
                &claim.claim,
                fixture.block.height,
                Network::Mainnet,
                NameFlags::NONE,
            )
            .expect("canonical claim mempool context");
            if claim.claim.weak {
                assert!(verify_mempool_claim_context(
                    &snapshot,
                    output,
                    &claim.claim,
                    fixture.block.height,
                    Network::Mainnet,
                    NameFlags::HARDENED,
                )
                .is_err());
            }
        }
    }

    #[test]
    fn canonical_mainnet_replacement_claims_replay_exact_predecessors() {
        let fixture: MainnetClaimReplacementHistoryFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-replacements-v1.json"
        ))
        .expect("mainnet claim replacement fixture");
        assert_eq!(fixture.history.len(), 10);

        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        seed_mainnet_claim_replacement_headers(&store, &fixture.canonical_context);
        let mut engine = StoredStateEngine::with_services(
            store,
            Network::Mainnet,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(
                AirdropCoinbaseIssuanceVerifier::native(DeploymentState::from_states(
                    [ThresholdState::Defined; 4],
                ))
                .expect("native issuance verifier"),
            ),
        )
        .expect("mainnet replacement state engine");

        let mut connected_initial = Vec::new();
        for expected in fixture
            .blocks
            .iter()
            .filter(|block| block.role == "initial")
        {
            let context = fixture
                .canonical_context
                .blocks
                .iter()
                .find(|context| context.block_height == expected.height)
                .expect("initial claim context");
            let (candidate, summary) =
                connect_mainnet_claim_fixture_block(&mut engine, expected, context);
            assert_eq!(
                summary.coins_created,
                candidate.transactions[0].outputs.len()
            );
            for claim in &expected.claims {
                assert_eq!(
                    candidate.transactions[0].outputs[claim.output_index].value,
                    claim.output_value
                );
                assert_eq!(claim.commit_height, 1);
                assert!(claim.conjured >= claim.output_value);
            }
            connected_initial.push((candidate, expected.height));
        }

        for expected in &fixture.history {
            let name_hash = hash_name(&expected.name).expect("replacement name hash");
            assert_eq!(name_hash.to_hex(), expected.name_hash);
            let state = engine
                .name_state(&name_hash)
                .expect("initial claimed name read")
                .expect("initial claimed name");
            assert_eq!(state.height, expected.initial.block_height);
            assert_eq!(state.renewal, expected.initial.block_height);
            assert_eq!(state.claimed, expected.initial.commit_height);
            assert_eq!(state.owner.txid.to_hex(), expected.initial.coinbase_txid);
            assert_eq!(state.owner.index, expected.initial.output_index);
            let coin = engine
                .coin(&state.owner)
                .expect("initial claim coin read")
                .expect("initial claim coin");
            assert_eq!(coin.value, expected.initial.output_value);
        }

        let replacement = fixture
            .blocks
            .iter()
            .find(|block| block.role == "replacement")
            .expect("replacement block");
        let replacement_context = fixture
            .canonical_context
            .blocks
            .iter()
            .find(|context| context.block_height == replacement.height)
            .expect("replacement block context");
        let (replacement_candidate, replacement_summary) =
            connect_mainnet_claim_fixture_block(&mut engine, replacement, replacement_context);
        assert_eq!(replacement_summary.names_changed, fixture.history.len());
        assert_eq!(replacement.claims.len(), fixture.history.len());
        for claim in &replacement.claims {
            assert_eq!(claim.commit_height, 2);
            assert_eq!(claim.conjured, claim.output_value);
        }

        for expected in &fixture.history {
            let name_hash = hash_name(&expected.name).expect("replacement name hash");
            let state = engine
                .name_state(&name_hash)
                .expect("replacement name read")
                .expect("replacement name");
            assert_eq!(state.height, expected.replacement.block_height);
            assert_eq!(state.renewal, expected.replacement.block_height);
            assert_eq!(state.claimed, expected.replacement.commit_height);
            assert_eq!(
                state.owner.txid.to_hex(),
                expected.replacement.coinbase_txid
            );
            assert_eq!(state.owner.index, expected.replacement.output_index);
            let coin = engine
                .coin(&state.owner)
                .expect("replacement coin read")
                .expect("replacement coin");
            assert_eq!(coin.value, expected.replacement.output_value);
        }

        engine
            .disconnect_block(DisconnectBlock {
                block_hash: replacement_candidate.hash(),
                height: replacement.height,
            })
            .expect("replacement claim disconnect");
        for expected in &fixture.history {
            let name_hash = hash_name(&expected.name).expect("restored initial name hash");
            let state = engine
                .name_state(&name_hash)
                .expect("restored initial name read")
                .expect("restored initial name");
            assert_eq!(state.height, expected.initial.block_height);
            assert_eq!(state.claimed, expected.initial.commit_height);
            assert_eq!(state.owner.txid.to_hex(), expected.initial.coinbase_txid);
            assert_eq!(state.owner.index, expected.initial.output_index);
        }

        for (candidate, height) in connected_initial.iter().rev() {
            engine
                .disconnect_block(DisconnectBlock {
                    block_hash: candidate.hash(),
                    height: *height,
                })
                .expect("initial claim disconnect");
        }
        for expected in fixture
            .blocks
            .iter()
            .filter(|block| block.role == "initial")
            .flat_map(|block| &block.claims)
        {
            let name_hash = hash_name(&expected.name).expect("disconnected initial name hash");
            assert!(engine
                .name_state(&name_hash)
                .expect("disconnected initial name read")
                .is_none());
        }
        let snapshot = engine.store().snapshot().expect("final claim snapshot");
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("final claim tree root"),
            TreeRoot::ZERO
        );
    }

    #[test]
    fn canonical_mainnet_terminal_and_third_generation_claims_replay() {
        let fixture: MainnetClaimReplacementHistoryFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-replacements-v1.json"
        ))
        .expect("mainnet claim lifecycle fixture");
        assert_eq!(fixture.schema, 2);
        assert_eq!(
            fixture.lifecycle.claim_period_height,
            Network::Mainnet.params().names.claim_period
        );
        assert_eq!(fixture.lifecycle.lineage.name, "mylinksfree");
        assert_eq!(fixture.lifecycle.lineage.points.len(), 3);

        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        seed_mainnet_claim_replacement_headers(&store, &fixture.canonical_context);
        let mut engine = StoredStateEngine::with_services(
            store,
            Network::Mainnet,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(
                AirdropCoinbaseIssuanceVerifier::native(DeploymentState::from_states(
                    [ThresholdState::Defined; 4],
                ))
                .expect("native issuance verifier"),
            ),
        )
        .expect("mainnet claim lifecycle state engine");

        let lineage_hash =
            hash_name(&fixture.lifecycle.lineage.name).expect("claim lineage name hash");
        assert_eq!(lineage_hash.to_hex(), fixture.lifecycle.lineage.name_hash);
        let mut connected = Vec::new();
        for (index, point) in fixture.lifecycle.lineage.points.iter().enumerate() {
            let expected = fixture
                .blocks
                .iter()
                .find(|block| block.height == point.block_height)
                .expect("claim lifecycle block");
            let context = fixture
                .canonical_context
                .blocks
                .iter()
                .find(|context| context.block_height == point.block_height)
                .expect("claim lifecycle context");
            let expected_claim = expected
                .claims
                .iter()
                .find(|claim| {
                    claim.name == fixture.lifecycle.lineage.name
                        && claim.output_index == point.output_index as usize
                })
                .expect("claim lifecycle output");
            assert_eq!(expected_claim.output_value, point.output_value);
            assert_eq!(expected_claim.reserved_value, point.reserved_value);
            assert_eq!(expected_claim.fee, point.fee);
            assert_eq!(expected_claim.commit_height, point.commit_height);
            assert_eq!(expected_claim.weak, point.weak);
            assert_eq!(expected_claim.conjured, point.conjured);

            let (candidate, summary) =
                connect_mainnet_claim_fixture_block(&mut engine, expected, context);
            assert!(summary.validation.claims_and_airdrops_valid);
            assert_eq!(
                candidate.transactions[0].txid().to_hex(),
                point.coinbase_txid
            );
            assert_eq!(
                candidate.transactions[0].outputs[point.output_index as usize].value,
                point.output_value
            );

            let state = engine
                .name_state(&lineage_hash)
                .expect("claim lineage state read")
                .expect("claim lineage state");
            assert_eq!(state.height, point.block_height);
            assert_eq!(state.renewal, point.block_height);
            assert_eq!(state.claimed, point.commit_height);
            assert_eq!(state.owner.txid.to_hex(), point.coinbase_txid);
            assert_eq!(state.owner.index, point.output_index);
            assert_eq!(state.weak, point.weak);
            let coin = engine
                .coin(&state.owner)
                .expect("claim lineage coin read")
                .expect("claim lineage coin");
            assert_eq!(coin.value, point.output_value);
            if index == 0 {
                assert_eq!(point.conjured, point.reserved_value);
                assert_eq!(point.reserved_value - point.fee, point.output_value);
            } else {
                assert_eq!(point.conjured, point.output_value);
                assert_eq!(
                    point.output_value,
                    fixture.lifecycle.lineage.points[0].output_value
                );
            }
            connected.push(candidate);
        }
        assert!(
            fixture.lifecycle.lineage.points[2].block_height
                - fixture.lifecycle.lineage.points[1].block_height
                >= Network::Mainnet.params().names.claim_frequency
        );

        for index in (0..connected.len()).rev() {
            let point = &fixture.lifecycle.lineage.points[index];
            engine
                .disconnect_block(DisconnectBlock {
                    block_hash: connected[index].hash(),
                    height: point.block_height,
                })
                .expect("claim lifecycle disconnect");
            let restored = engine
                .name_state(&lineage_hash)
                .expect("restored claim lineage state");
            if index == 0 {
                assert!(restored.is_none());
            } else {
                let previous = &fixture.lifecycle.lineage.points[index - 1];
                let restored = restored.expect("prior claim generation");
                assert_eq!(restored.height, previous.block_height);
                assert_eq!(restored.claimed, previous.commit_height);
                assert_eq!(restored.owner.txid.to_hex(), previous.coinbase_txid);
                assert_eq!(restored.owner.index, previous.output_index);
            }
        }

        let terminal = &fixture.lifecycle.terminal;
        assert_eq!(terminal.name, "vcel");
        assert_eq!(terminal.blocks_before_claim_period, 3);
        assert_eq!(
            terminal.point.block_height + terminal.blocks_before_claim_period,
            fixture.lifecycle.claim_period_height
        );
        let terminal_hash = hash_name(&terminal.name).expect("terminal claim name hash");
        assert_eq!(terminal_hash.to_hex(), terminal.name_hash);
        let terminal_block = fixture
            .blocks
            .iter()
            .find(|block| block.height == terminal.point.block_height)
            .expect("terminal claim block");
        let terminal_context = fixture
            .canonical_context
            .blocks
            .iter()
            .find(|context| context.block_height == terminal.point.block_height)
            .expect("terminal claim context");
        let (terminal_candidate, terminal_summary) =
            connect_mainnet_claim_fixture_block(&mut engine, terminal_block, terminal_context);
        assert!(terminal_summary.validation.claims_and_airdrops_valid);
        let terminal_state = engine
            .name_state(&terminal_hash)
            .expect("terminal claim state read")
            .expect("terminal claim state");
        assert_eq!(terminal_state.height, terminal.point.block_height);
        assert_eq!(terminal_state.claimed, terminal.point.commit_height);
        assert_eq!(
            terminal_state.owner.txid.to_hex(),
            terminal.point.coinbase_txid
        );
        assert_eq!(terminal_state.owner.index, terminal.point.output_index);

        let historical = Block::decode(&decode_fixture_bytes(&terminal_block.raw))
            .expect("terminal canonical block");
        let mut ended_coinbase = historical.transactions[0].clone();
        ended_coinbase.locktime = fixture.lifecycle.claim_period_height;
        ended_coinbase.outputs[terminal.point.output_index as usize]
            .covenant
            .items[1] = fixture.lifecycle.claim_period_height.to_le_bytes().to_vec();
        let ended = engine.issuance_verifier().verify_coinbase(
            &ended_coinbase,
            fixture.lifecycle.claim_period_height,
            fixture.lifecycle.boundary.parent_time,
            Network::Mainnet,
        );
        assert!(ended
            .expect_err("claim-period boundary must reject claims")
            .to_string()
            .contains("not claimable"));
        assert_eq!(
            fixture.lifecycle.boundary.block_height,
            fixture.lifecycle.claim_period_height
        );
        assert_eq!(fixture.lifecycle.boundary.claim_count, 0);

        engine
            .disconnect_block(DisconnectBlock {
                block_hash: terminal_candidate.hash(),
                height: terminal.point.block_height,
            })
            .expect("terminal claim disconnect");
        assert!(engine
            .name_state(&terminal_hash)
            .expect("disconnected terminal state")
            .is_none());
        let snapshot = engine.store().snapshot().expect("final lifecycle snapshot");
        assert_eq!(
            verify_stored_name_tree_root(&snapshot).expect("final lifecycle tree root"),
            TreeRoot::ZERO
        );
    }
}
