#![forbid(unsafe_code)]

use std::{
    collections::{btree_map::Entry, BTreeMap, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use hns_chain::{read_canonical_hash, HeaderRecord};
use hns_consensus::{
    is_reserved, maybe_expire_name, name_lifecycle, verify_airdrop_output,
    verify_and_apply_name_covenant, verify_claim_output, verify_sequence_locks,
    verify_transaction_covenant_links, AirdropFlags, ClaimFlags, ConsensusError, CovenantLinkError,
    DeploymentState, NameContext, NameFlags, NativeAirdropSignatureVerifier,
    NativeSignatureVerifier, Network, OpenSslDnssecVerifier, RejectUnverifiedInputs,
    SequenceLockView, TransactionInputVerifier, VerifiedClaim, WitnessProgramVerifier, MAX_MONEY,
    MEDIAN_TIMESPAN,
};
use hns_primitives::{
    Address, AirdropSignatureVerifier, Amount, Block, BlockHash, Coin, Covenant, CovenantKind,
    DnssecVerifier, Height, NameHash, NameLifecycleState, NameState, Outpoint, PrimitiveError,
    Reader, Transaction, UnavailableAirdropSignatureVerifier, Writer, AIRDROP_TREE_LEAVES,
    MAX_ADDRESS_HASH_SIZE, MAX_BLOCK_WEIGHT, MAX_NAME_SIZE, MAX_RESOURCE_SIZE, MAX_TX_SIZE,
};
use hns_store::{
    ColumnFamily, MetaKey, ReadSnapshot, Store, StoreError, WriteBatch, AIRDROP_FIELD_BYTES,
};
use hns_urkel::{root_from_entries, TreeRoot, UrkelError};
use serde::{Deserialize, Serialize};

const BLOCK_UNDO_VERSION: u32 = 5;
const OUTPOINT_KEY_SIZE: usize = 36;
const ADDRESS_CODEC_MAX: usize = 2 + MAX_ADDRESS_HASH_SIZE;
const COIN_CODEC_MAX: usize = OUTPOINT_KEY_SIZE + 8 + 4 + 1 + ADDRESS_CODEC_MAX + MAX_TX_SIZE + 9;
const NAME_STATE_FIELD_MASK: u16 = (1 << 10) - 1;
const NAME_STATE_CODEC_MAX: usize =
    1 + MAX_NAME_SIZE + 2 + MAX_RESOURCE_SIZE + 4 + 4 + 2 + 32 + 9 + 9 + 9 + 4 + 4 + 4 + 9;
const NAME_UNDO_CODEC_MAX: usize = 32 + 1 + NAME_STATE_CODEC_MAX + 9;
const BLOCK_UNDO_CODEC_MAX: usize = MAX_BLOCK_WEIGHT * 8;

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

/// Explicit state-validation evidence returned to the chain coordinator. These
/// flags describe only work actually performed by this state transition; they
/// are intentionally narrower than full block-consensus validity.
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
    /// Authenticated name-tree root committed by this block header. Handshake
    /// commits to the parent/pre-state root, not the resulting post-state root.
    pub inherited_tree_root: TreeRoot,
    /// Authenticated name-tree root after this block's name transitions. This is
    /// the root the next block must commit to.
    pub resulting_tree_root: TreeRoot,
    pub validation: StateValidationSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameUndo {
    pub name_hash: NameHash,
    pub previous: Option<NameState>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockUndo {
    pub block_hash: BlockHash,
    pub height: Height,
    pub previous_tree_root: TreeRoot,
    pub resulting_tree_root: TreeRoot,
    pub spent_coins: Vec<Coin>,
    pub created_coins: Vec<Outpoint>,
    pub airdrop_positions: Vec<u32>,
    pub previous_name_states: Vec<NameUndo>,
}

impl BlockUndo {
    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
        let mut writer = Writer::new();
        writer.write_u32(BLOCK_UNDO_VERSION);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_bytes(self.previous_tree_root.as_bytes());
        writer.write_bytes(self.resulting_tree_root.as_bytes());
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

        Ok(writer.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        let mut reader = Reader::new(bytes, BLOCK_UNDO_CODEC_MAX)?;
        let version = reader.read_u32()?;
        if version != BLOCK_UNDO_VERSION {
            return Err(StateError::Codec(format!(
                "unsupported block undo version {version}"
            )));
        }

        let block_hash = BlockHash::new(reader.read_hash()?);
        let height = reader.read_u32()?;
        let previous_tree_root = TreeRoot::new(reader.read_hash()?);
        let resulting_tree_root = TreeRoot::new(reader.read_hash()?);
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

        reader.ensure_finished()?;
        Ok(Self {
            block_hash,
            height,
            previous_tree_root,
            resulting_tree_root,
            spent_coins,
            created_coins,
            airdrop_positions,
            previous_name_states,
        })
    }
}

pub trait StateView {
    fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, StateError>;
    fn name_state(&self, name_hash: &NameHash) -> Result<Option<NameState>, StateError>;
}

pub trait StateEngine {
    fn connect_block(&mut self, request: ConnectBlock<'_>) -> Result<StateSummary, StateError>;
    fn disconnect_block(&mut self, request: DisconnectBlock) -> Result<StateSummary, StateError>;
}

/// Result from the dedicated coinbase claim/airdrop boundary. A production
/// implementation must account for every conjured unit and authenticate every
/// special input against the historical HNS datasets.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoinbaseIssuanceSummary {
    pub conjured: Amount,
    pub claims_and_airdrops_valid: bool,
    /// HSD allocation-field positions authenticated by this verifier. The
    /// state engine atomically rejects already-spent positions and records the
    /// newly spent positions in block undo.
    pub airdrop_positions: Vec<u32>,
    /// Fully authenticated claims keyed to their same-index coinbase outputs.
    /// The state engine applies these transitions to the name tree only after
    /// every special issuance input has passed atomically.
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
}

#[derive(Clone, Copy)]
pub struct StateServices<'a> {
    pub network: Network,
    pub name_flags: NameFlags,
    pub name_flags_valid: bool,
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
    /// elsewhere until claim/airdrop coverage, persistent Urkel/proof parity,
    /// and historical replay have independently completed. Active node callers
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
    if request.block_hash != request.block.hash() {
        return Err(StateError::BlockHashMismatch {
            expected: request.block_hash,
            actual: request.block.hash(),
        });
    }

    // Handshake commits each block header to the authenticated name-tree root
    // inherited from its parent. The current block's covenant transitions are
    // applied only after this comparison and produce the root committed by the
    // following block.
    let inherited_tree_root = verify_stored_name_tree_root(snapshot)?;
    let committed_tree_root = TreeRoot::new(request.block.header.tree_root);
    if committed_tree_root != inherited_tree_root {
        return Err(StateError::HeaderTreeRootMismatch {
            committed: committed_tree_root,
            inherited: inherited_tree_root,
        });
    }

    let coinbase = request
        .block
        .transactions
        .first()
        .ok_or(StateError::MissingCoinbase)?;
    let chain_context = SnapshotChainContext::new(snapshot);
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
    let issuance = services.issuance_verifier.verify_coinbase(
        coinbase,
        request.height,
        parent_time,
        services.network,
    )?;
    stage_airdrop_positions(snapshot, batch, &issuance.airdrop_positions)?;
    let coinbase_value = transaction_output_value(coinbase)?;

    let mut spent_coins = Vec::new();
    let mut spent_outpoints = HashSet::new();
    let mut created_coins = Vec::new();
    let mut created_set = HashSet::new();
    let mut pending_created = HashMap::new();
    let mut name_state_changes = NameStateChanges::default();
    let mut total_fees = 0u64;

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
                snapshot,
                &pending_created,
                &mut spent_outpoints,
                transaction,
                request.height,
                request.coinbase_maturity,
            )?;
            let input_coins = resolved
                .iter()
                .map(|resolved| resolved.coin.clone())
                .collect::<Vec<_>>();

            verify_transaction_sequence_locks(
                transaction,
                request.height,
                &input_coins,
                &chain_context,
            )?;
            verify_transaction_inputs(services.input_verifier, transaction, &input_coins)?;
            verify_transaction_covenant_links(transaction, &input_coins)?;

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
            total_fees = total_fees
                .checked_add(input_value - output_value)
                .ok_or(StateError::FeeValueOverflow)?;
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
            let index = u32::try_from(output_index).map_err(|_| {
                StateError::Codec(format!("output index {output_index} exceeds u32"))
            })?;
            let outpoint = Outpoint { txid, index };
            if !created_set.insert(outpoint.clone()) {
                return Err(StateError::DuplicateCoin(outpoint));
            }
            if !spent_outpoints.contains(&outpoint)
                && snapshot
                    .get(ColumnFamily::Utxo, &encode_outpoint_key(&outpoint))?
                    .is_some()
            {
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

    let mut name_overrides = BTreeMap::<NameHash, Option<NameState>>::new();
    for name_hash in &name_state_changes.changed {
        let state = name_state_changes.current.get(name_hash).ok_or_else(|| {
            StateError::Codec("changed name is missing from transaction cache".to_owned())
        })?;
        write_name_state_to_batch(batch, state)?;
        name_overrides.insert(*name_hash, (!state.is_null()).then_some(state.clone()));
    }

    let resulting_tree_root = rebuild_name_tree_root_with_overrides(snapshot, &name_overrides)?;
    batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeRoot.as_bytes(),
        resulting_tree_root.as_bytes(),
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
        spent_coins,
        created_coins,
        airdrop_positions: issuance.airdrop_positions.clone(),
        previous_name_states,
    };
    batch.put(
        ColumnFamily::Undo,
        request.block_hash.as_bytes(),
        &undo.encode()?,
    )?;

    Ok(StateSummary {
        coins_created: undo.created_coins.len(),
        coins_spent: undo.spent_coins.len(),
        names_changed: undo.previous_name_states.len(),
        inherited_tree_root,
        resulting_tree_root,
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

#[derive(Clone, Debug)]
struct ResolvedInput {
    coin: Coin,
    source: ResolvedCoinSource,
}

fn resolve_transaction_inputs<T: ReadSnapshot>(
    snapshot: &T,
    pending_created: &HashMap<Outpoint, Coin>,
    spent_outpoints: &mut HashSet<Outpoint>,
    transaction: &Transaction,
    spend_height: Height,
    coinbase_maturity: u32,
) -> Result<Vec<ResolvedInput>, StateError> {
    let mut resolved = Vec::with_capacity(transaction.inputs.len());
    for input in &transaction.inputs {
        if !spent_outpoints.insert(input.previous_output.clone()) {
            return Err(StateError::DuplicateSpend(input.previous_output.clone()));
        }
        let (coin, source) = match pending_created.get(&input.previous_output) {
            Some(coin) => (coin.clone(), ResolvedCoinSource::Pending),
            None => (
                load_existing_coin(snapshot, &input.previous_output)?,
                ResolvedCoinSource::Existing,
            ),
        };
        check_coinbase_maturity(&coin, spend_height, coinbase_maturity)?;
        resolved.push(ResolvedInput { coin, source });
    }
    Ok(resolved)
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
            "authenticated claim set does not match coinbase claim outputs".to_owned(),
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
    resolved: Vec<ResolvedInput>,
) -> Result<(), StateError> {
    for input in resolved {
        match input.source {
            ResolvedCoinSource::Pending => {
                pending_created.remove(&input.coin.outpoint);
                batch.delete(
                    ColumnFamily::Utxo,
                    &encode_outpoint_key(&input.coin.outpoint),
                )?;
                created_coins.retain(|outpoint| outpoint != &input.coin.outpoint);
            }
            ResolvedCoinSource::Existing => {
                batch.delete(
                    ColumnFamily::Utxo,
                    &encode_outpoint_key(&input.coin.outpoint),
                )?;
                spent_coins.push(input.coin);
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
}

impl<'a, T: ReadSnapshot> SnapshotChainContext<'a, T> {
    const fn new(snapshot: &'a T) -> Self {
        Self { snapshot }
    }

    fn header_at(&self, height: Height) -> Result<Option<HeaderRecord>, StateError> {
        let Some(hash) = read_canonical_hash(self.snapshot, height)? else {
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
        Ok(Some(record))
    }

    fn median_time_past(&self, height: Height) -> Result<u64, StateError> {
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
        Ok(times[times.len() / 2])
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

    let current_tree_root = verify_stored_name_tree_root(snapshot)?;
    if current_tree_root != undo.resulting_tree_root {
        return Err(StateError::UndoResultingTreeRootMismatch {
            expected: undo.resulting_tree_root,
            actual: current_tree_root,
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
    let mut name_overrides = BTreeMap::<NameHash, Option<NameState>>::new();
    for name_undo in &undo.previous_name_states {
        match &name_undo.previous {
            Some(state) => write_name_state_to_batch(batch, state)?,
            None => batch.delete(ColumnFamily::NameState, name_undo.name_hash.as_bytes())?,
        }
        name_overrides.insert(
            name_undo.name_hash,
            name_undo
                .previous
                .as_ref()
                .filter(|state| !state.is_null())
                .cloned(),
        );
    }
    let restored_tree_root = rebuild_name_tree_root_with_overrides(snapshot, &name_overrides)?;
    if restored_tree_root != undo.previous_tree_root {
        return Err(StateError::UndoPreviousTreeRootMismatch {
            expected: undo.previous_tree_root,
            actual: restored_tree_root,
        });
    }
    batch.put(
        ColumnFamily::Meta,
        MetaKey::NameTreeRoot.as_bytes(),
        restored_tree_root.as_bytes(),
    )?;
    batch.delete(ColumnFamily::Undo, request.block_hash.as_bytes())?;

    Ok(StateSummary {
        coins_created: undo.spent_coins.len(),
        coins_spent: undo.created_coins.len(),
        names_changed: undo.previous_name_states.len(),
        inherited_tree_root: current_tree_root,
        resulting_tree_root: restored_tree_root,
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
/// column family using the pinned HSD/Urkel hashing rules. This is a
/// correctness-first oracle path: it is intentionally O(number of names) and
/// does not replace the future persistent incremental tree, interval snapshots,
/// or reorganization injection semantics.
pub fn rebuild_name_tree_root<T: ReadSnapshot>(snapshot: &T) -> Result<TreeRoot, StateError> {
    rebuild_name_tree_root_with_overrides(snapshot, &BTreeMap::new())
}

/// Rebuild the authenticated name-tree root from one immutable base snapshot
/// plus an explicit set of staged name-state replacements. This keeps root
/// calculation independent of whether a particular WriteBatch implementation
/// offers read-your-writes semantics.
pub fn rebuild_name_tree_root_with_overrides<T: ReadSnapshot>(
    snapshot: &T,
    overrides: &BTreeMap<NameHash, Option<NameState>>,
) -> Result<TreeRoot, StateError> {
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

    root_from_entries(entries).map_err(StateError::NameTree)
}

/// Load the durable binding for the currently materialized name-state tree.
pub fn load_stored_name_tree_root<T: ReadSnapshot>(snapshot: &T) -> Result<TreeRoot, StateError> {
    let bytes = snapshot
        .get(ColumnFamily::Meta, MetaKey::NameTreeRoot.as_bytes())?
        .ok_or(StateError::MissingStoredTreeRoot)?;
    let root: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| StateError::InvalidStoredTreeRootLength(bytes.len()))?;
    Ok(TreeRoot::new(root))
}

/// Verify that durable metadata and the materialized NameState column family
/// describe exactly the same authenticated root.
pub fn verify_stored_name_tree_root<T: ReadSnapshot>(snapshot: &T) -> Result<TreeRoot, StateError> {
    let stored = load_stored_name_tree_root(snapshot)?;
    let actual = rebuild_name_tree_root(snapshot)?;
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
    #[error("durable name-tree root {stored:?} does not match materialized name state {actual:?}")]
    StoredTreeRootMismatch { stored: TreeRoot, actual: TreeRoot },
    #[error(
        "block header commits to name-tree root {committed:?}, but inherited state root is {inherited:?}"
    )]
    HeaderTreeRootMismatch {
        committed: TreeRoot,
        inherited: TreeRoot,
    },
    #[error(
        "undo expects current name-tree root {expected:?}, but materialized state is {actual:?}"
    )]
    UndoResultingTreeRootMismatch {
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

impl From<PrimitiveError> for StateError {
    fn from(value: PrimitiveError) -> Self {
        Self::Codec(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hns_chain::{write_canonical_height_to_batch, BlockStatus, HeaderRecord};
    use hns_consensus::{reserved_name, ConsensusError, ThresholdState};
    use hns_primitives::{
        hash_name, Address, CovenantKind, Header, Input, Output, Txid, Uint256, Witness,
    };
    use hns_store::{MemoryStore, Store};

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct AllowAllInputVerifier;

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
        StoredStateEngine::with_services(
            store,
            Network::Regtest,
            NameFlags::NONE,
            true,
            Arc::new(AllowAllInputVerifier),
            Arc::new(RejectSpecialCoinbaseIssuance),
        )
        .expect("test engine")
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
    struct AirdropFixture {
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
    struct MainnetClaimContextFixture {
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
        name: String,
        weak: bool,
        commit_height: u32,
        conjured: u64,
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

    #[test]
    fn rebuilt_name_tree_root_matches_incremental_hsd_roots() {
        let fixture: NameTreeFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/state-urkel-v1.json"
        ))
        .expect("fixture");
        assert_eq!(fixture.states.len(), fixture.incremental_roots.len());

        let store = MemoryStore::new();
        hns_store::initialize_schema(&store).expect("schema");
        for (state, expected) in fixture.states.iter().zip(&fixture.incremental_roots) {
            let snapshot = store.snapshot().expect("pre-state snapshot");
            assert_eq!(
                verify_stored_name_tree_root(&snapshot).expect("pre-state root"),
                TreeRoot::new(decode_hash(&expected.header_root))
            );
            drop(snapshot);

            let mut batch = store.batch();
            batch
                .put(
                    ColumnFamily::NameState,
                    &decode_hash(&state.name_hash),
                    &decode_fixture_bytes(&state.encoded),
                )
                .expect("put");
            batch
                .put(
                    ColumnFamily::Meta,
                    MetaKey::NameTreeRoot.as_bytes(),
                    &decode_hash(&expected.resulting_root),
                )
                .expect("bind resulting root");
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
        }
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
            Err(StateError::StoredTreeRootMismatch { .. })
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
}
