#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use hns_consensus::{
    verify_transaction_covenant_links, CovenantLinkError, RejectUnverifiedInputs,
    TransactionInputVerifier,
};
use hns_primitives::{
    Address, Amount, Block, BlockHash, Coin, Covenant, Height, NameHash, NameLifecycleState,
    NameState, Outpoint, PrimitiveError, Reader, Writer, MAX_ADDRESS_HASH_SIZE, MAX_BLOCK_WEIGHT,
    MAX_NAME_SIZE, MAX_TX_SIZE,
};
use hns_store::{ColumnFamily, ReadSnapshot, Store, StoreError, WriteBatch};
use serde::{Deserialize, Serialize};

const BLOCK_UNDO_VERSION: u32 = 2;
const OUTPOINT_KEY_SIZE: usize = 36;
const ADDRESS_CODEC_MAX: usize = 2 + MAX_ADDRESS_HASH_SIZE;
const COIN_CODEC_MAX: usize = OUTPOINT_KEY_SIZE + 8 + 4 + 1 + ADDRESS_CODEC_MAX + MAX_TX_SIZE + 9;
const NAME_STATE_CODEC_MAX: usize = 32 + 1 + MAX_NAME_SIZE + 9 + 4 + 1;
const NAME_UNDO_CODEC_MAX: usize = 32 + 1 + NAME_STATE_CODEC_MAX + 9;
const BLOCK_UNDO_CODEC_MAX: usize = MAX_BLOCK_WEIGHT * 8;

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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateSummary {
    pub coins_created: usize,
    pub coins_spent: usize,
    pub names_changed: usize,
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
    pub spent_coins: Vec<Coin>,
    pub created_coins: Vec<Outpoint>,
    pub previous_name_states: Vec<NameUndo>,
}

impl BlockUndo {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_u32(BLOCK_UNDO_VERSION);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_varint(self.spent_coins.len() as u64);

        for coin in &self.spent_coins {
            writer.write_varbytes(&encode_coin(coin));
        }

        writer.write_varint(self.created_coins.len() as u64);

        for outpoint in &self.created_coins {
            outpoint.write_to(&mut writer);
        }

        writer.write_varint(self.previous_name_states.len() as u64);

        for undo in &self.previous_name_states {
            writer.write_varbytes(&encode_name_undo(undo));
        }

        writer.finish()
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
            spent_coins,
            created_coins,
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

#[derive(Clone)]
pub struct StoredStateEngine<S: Store> {
    store: S,
    input_verifier: Arc<dyn TransactionInputVerifier>,
}

impl<S: Store> fmt::Debug for StoredStateEngine<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredStateEngine")
            .field("store", &"<store>")
            .field("input_verifier", &"<transaction-input-verifier>")
            .finish()
    }
}

impl<S: Store> StoredStateEngine<S> {
    /// Construct a state engine that fails closed on every non-coinbase input
    /// until a consensus-complete authorization verifier is explicitly wired.
    pub fn new(store: S) -> Result<Self, StateError> {
        Self::with_input_verifier(store, Arc::new(RejectUnverifiedInputs))
    }

    pub fn with_input_verifier(
        store: S,
        input_verifier: Arc<dyn TransactionInputVerifier>,
    ) -> Result<Self, StateError> {
        hns_store::initialize_schema(&store)?;
        Ok(Self {
            store,
            input_verifier,
        })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn input_verifier(&self) -> &dyn TransactionInputVerifier {
        self.input_verifier.as_ref()
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
        let Some(bytes) = snapshot.get(ColumnFamily::NameState, name_hash.as_bytes())? else {
            return Ok(None);
        };
        decode_name_state(&bytes).map(Some)
    }
}

impl<S: Store> StateEngine for StoredStateEngine<S> {
    fn connect_block(&mut self, request: ConnectBlock<'_>) -> Result<StateSummary, StateError> {
        let snapshot = self.store.snapshot()?;
        let mut batch = self.store.batch();
        let summary = connect_block_to_batch_with_verifier(
            &snapshot,
            &mut batch,
            request,
            self.input_verifier(),
        )?;
        self.store.commit(batch)?;
        Ok(summary)
    }

    fn disconnect_block(&mut self, request: DisconnectBlock) -> Result<StateSummary, StateError> {
        let undo = self
            .load_undo(&request.block_hash)?
            .ok_or(StateError::MissingUndo(request.block_hash))?;

        let mut batch = self.store.batch();
        let summary = disconnect_block_to_batch(&mut batch, request, &undo)?;
        self.store.commit(batch)?;
        Ok(summary)
    }
}

pub fn connect_block_to_batch<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    request: ConnectBlock<'_>,
) -> Result<StateSummary, StateError> {
    connect_block_to_batch_with_verifier(
        snapshot,
        batch,
        request,
        &RejectUnverifiedInputs,
    )
}

pub fn connect_block_to_batch_with_verifier<T: ReadSnapshot, B: WriteBatch>(
    snapshot: &T,
    batch: &mut B,
    request: ConnectBlock<'_>,
    input_verifier: &dyn TransactionInputVerifier,
) -> Result<StateSummary, StateError> {
    if request.block_hash != request.block.hash() {
        return Err(StateError::BlockHashMismatch {
            expected: request.block_hash,
            actual: request.block.hash(),
        });
    }

    let mut spent_coins = Vec::new();
    let mut spent_outpoints = HashSet::new();
    let mut created_coins = Vec::new();
    let mut created_set = HashSet::new();
    let mut pending_created = HashMap::new();
    let coinbase = request
        .block
        .transactions
        .first()
        .ok_or(StateError::MissingCoinbase)?;
    if coinbase.inputs.len() > 1 {
        return Err(StateError::UnsupportedCoinbaseIssuance);
    }
    let coinbase_value = transaction_output_value(coinbase)?;
    let mut total_fees = 0u64;

    for (transaction_index, transaction) in request.block.transactions.iter().enumerate() {
        if transaction_index != 0 {
            let resolved = resolve_transaction_inputs(
                snapshot,
                &pending_created,
                &mut spent_outpoints,
                transaction,
                request.height,
                request.coinbase_maturity,
                input_verifier,
            )?;
            let input_coins = resolved
                .iter()
                .map(|resolved| resolved.coin.clone())
                .collect::<Vec<_>>();
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
        .ok_or(StateError::CoinbaseRewardOverflow)?;
    if coinbase_value > maximum_coinbase {
        return Err(StateError::CoinbaseValueExceedsReward {
            coinbase: coinbase_value,
            maximum: maximum_coinbase,
        });
    }

    let undo = BlockUndo {
        block_hash: request.block_hash,
        height: request.height,
        spent_coins,
        created_coins,
        previous_name_states: Vec::new(),
    };
    batch.put(
        ColumnFamily::Undo,
        request.block_hash.as_bytes(),
        &undo.encode(),
    )?;

    Ok(StateSummary {
        coins_created: undo.created_coins.len(),
        coins_spent: undo.spent_coins.len(),
        names_changed: undo.previous_name_states.len(),
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
    transaction: &hns_primitives::Transaction,
    spend_height: Height,
    coinbase_maturity: u32,
    input_verifier: &dyn TransactionInputVerifier,
) -> Result<Vec<ResolvedInput>, StateError> {
    let mut resolved = Vec::with_capacity(transaction.inputs.len());

    for (input_index, input) in transaction.inputs.iter().enumerate() {
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
        verify_input_authorization(input_verifier, transaction, input_index, &coin)?;
        resolved.push(ResolvedInput { coin, source });
    }

    Ok(resolved)
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
                stage_existing_coin_spend(batch, &input.coin, spent_coins)?;
            }
        }
    }
    Ok(())
}

fn transaction_output_value(
    transaction: &hns_primitives::Transaction,
) -> Result<Amount, StateError> {
    transaction.outputs.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value)
            .ok_or(StateError::OutputValueOverflow)
    })
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

fn verify_input_authorization(
    verifier: &dyn TransactionInputVerifier,
    transaction: &hns_primitives::Transaction,
    input_index: usize,
    coin: &Coin,
) -> Result<(), StateError> {
    verifier
        .verify_input(transaction, input_index, coin)
        .map_err(|error| StateError::InputAuthorization {
            input_index,
            reason: error.to_string(),
        })
}

fn stage_existing_coin_spend<B: WriteBatch>(
    batch: &mut B,
    coin: &Coin,
    spent_coins: &mut Vec<Coin>,
) -> Result<(), StateError> {
    batch.delete(
        ColumnFamily::Utxo,
        &encode_outpoint_key(&coin.outpoint),
    )?;
    spent_coins.push(coin.clone());
    Ok(())
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

pub fn disconnect_block_to_batch<B: WriteBatch>(
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

    for name_undo in &undo.previous_name_states {
        match &name_undo.previous {
            Some(state) => write_name_state_to_batch(batch, state)?,
            None => batch.delete(ColumnFamily::NameState, name_undo.name_hash.as_bytes())?,
        }
    }

    batch.delete(ColumnFamily::Undo, request.block_hash.as_bytes())?;

    Ok(StateSummary {
        coins_created: undo.spent_coins.len(),
        coins_spent: undo.created_coins.len(),
        names_changed: undo.previous_name_states.len(),
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
    batch.put(
        ColumnFamily::NameState,
        state.name_hash.as_bytes(),
        &encode_name_state(state),
    )?;
    Ok(())
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

pub fn encode_name_state(state: &NameState) -> Vec<u8> {
    let mut writer = Writer::with_capacity(NAME_STATE_CODEC_MAX);
    writer.write_bytes(state.name_hash.as_bytes());

    match &state.name {
        Some(name) => {
            writer.write_u8(1);
            writer.write_varbytes(name.as_bytes());
        }
        None => writer.write_u8(0),
    }

    writer.write_u32(state.height);
    writer.write_u8(name_lifecycle_to_u8(state.state));
    writer.finish()
}

pub fn decode_name_state(bytes: &[u8]) -> Result<NameState, StateError> {
    let mut reader = Reader::new(bytes, NAME_STATE_CODEC_MAX)?;
    let name_hash = NameHash::new(reader.read_hash()?);
    let name = match reader.read_u8()? {
        0 => None,
        1 => {
            let bytes = reader.read_varbytes(MAX_NAME_SIZE, "name")?;
            Some(String::from_utf8(bytes).map_err(|error| StateError::Codec(error.to_string()))?)
        }
        value => {
            return Err(StateError::Codec(format!(
                "invalid name-present flag {value}"
            )))
        }
    };
    let height = reader.read_u32()?;
    let state = name_lifecycle_from_u8(reader.read_u8()?)?;
    reader.ensure_finished()?;

    Ok(NameState {
        name_hash,
        name,
        height,
        state,
    })
}

fn encode_name_undo(undo: &NameUndo) -> Vec<u8> {
    let mut writer = Writer::with_capacity(NAME_UNDO_CODEC_MAX);
    writer.write_bytes(undo.name_hash.as_bytes());

    match &undo.previous {
        Some(state) => {
            writer.write_u8(1);
            writer.write_varbytes(&encode_name_state(state));
        }
        None => writer.write_u8(0),
    }

    writer.finish()
}

fn decode_name_undo(bytes: &[u8]) -> Result<NameUndo, StateError> {
    let mut reader = Reader::new(bytes, NAME_UNDO_CODEC_MAX)?;
    let name_hash = NameHash::new(reader.read_hash()?);
    let previous = match reader.read_u8()? {
        0 => None,
        1 => {
            let bytes = reader.read_varbytes(NAME_STATE_CODEC_MAX, "previous name state")?;
            Some(decode_name_state(&bytes)?)
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

const fn name_lifecycle_to_u8(state: NameLifecycleState) -> u8 {
    match state {
        NameLifecycleState::Available => 0,
        NameLifecycleState::Opening => 1,
        NameLifecycleState::Bidding => 2,
        NameLifecycleState::Reveal => 3,
        NameLifecycleState::Redeem => 4,
        NameLifecycleState::Registered => 5,
        NameLifecycleState::Updating => 6,
        NameLifecycleState::Renewing => 7,
        NameLifecycleState::Transferring => 8,
        NameLifecycleState::Finalizing => 9,
        NameLifecycleState::Revoked => 10,
        NameLifecycleState::Expired => 11,
        NameLifecycleState::Reserved => 12,
    }
}

const fn name_lifecycle_from_u8(value: u8) -> Result<NameLifecycleState, StateError> {
    match value {
        0 => Ok(NameLifecycleState::Available),
        1 => Ok(NameLifecycleState::Opening),
        2 => Ok(NameLifecycleState::Bidding),
        3 => Ok(NameLifecycleState::Reveal),
        4 => Ok(NameLifecycleState::Redeem),
        5 => Ok(NameLifecycleState::Registered),
        6 => Ok(NameLifecycleState::Updating),
        7 => Ok(NameLifecycleState::Renewing),
        8 => Ok(NameLifecycleState::Transferring),
        9 => Ok(NameLifecycleState::Finalizing),
        10 => Ok(NameLifecycleState::Revoked),
        11 => Ok(NameLifecycleState::Expired),
        12 => Ok(NameLifecycleState::Reserved),
        _ => Err(StateError::InvalidNameLifecycle(value)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state engine is not implemented in the scaffold")]
    Unimplemented,
    #[error("state codec failed: {0}")]
    Codec(String),
    #[error("state store failed: {0}")]
    Store(#[from] StoreError),
    #[error("missing coin for outpoint {0:?}")]
    MissingCoin(Outpoint),
    #[error("duplicate spend for outpoint {0:?}")]
    DuplicateSpend(Outpoint),
    #[error("transaction input {input_index} authorization failed: {reason}")]
    InputAuthorization { input_index: usize, reason: String },
    #[error("transaction covenant linkage failed: {0}")]
    CovenantLink(#[from] CovenantLinkError),
    #[error("duplicate created coin for outpoint {0:?}")]
    DuplicateCoin(Outpoint),
    #[error("block has no coinbase transaction")]
    MissingCoinbase,
    #[error(
        "coinbase claim/airdrop issuance is disabled until its proof and historical dataset are verified"
    )]
    UnsupportedCoinbaseIssuance,
    #[error("transaction input value overflow")]
    InputValueOverflow,
    #[error("transaction output value overflow")]
    OutputValueOverflow,
    #[error("block transaction fee total overflow")]
    FeeValueOverflow,
    #[error("block subsidy plus fees overflow")]
    CoinbaseRewardOverflow,
    #[error("coinbase value {coinbase} exceeds subsidy-plus-fee maximum {maximum}")]
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
    #[error("invalid name lifecycle value {0}")]
    InvalidNameLifecycle(u8),
}

impl From<PrimitiveError> for StateError {
    fn from(value: PrimitiveError) -> Self {
        Self::Codec(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hns_consensus::ConsensusError;

    use super::*;
    use hns_primitives::{
        Address, CovenantKind, Header, Input, Output, Transaction, Txid, Witness,
    };
    use hns_store::{MemoryStore, Store};

    #[derive(Clone, Copy, Debug)]
    struct AllowAllInputVerifier;

    impl TransactionInputVerifier for AllowAllInputVerifier {
        fn verify_input(
            &self,
            _transaction: &hns_primitives::Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    fn authorized_engine(store: MemoryStore) -> StoredStateEngine<MemoryStore> {
        StoredStateEngine::with_input_verifier(store, Arc::new(AllowAllInputVerifier))
            .expect("authorized test engine")
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
            address: Address::new(0, vec![0; 20]).expect("address"),
            covenant: covenant(),
        }
    }

    fn name_covenant(kind: CovenantKind, name_hash: [u8; 32], start: u32) -> Covenant {
        Covenant {
            kind,
            items: vec![name_hash.to_vec(), start.to_le_bytes().to_vec()],
        }
    }

    fn coinbase(outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 1,
            inputs: Vec::new(),
            outputs,
            locktime: 0,
        }
    }

    fn spend(previous_output: Outpoint, outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output,
                sequence: 0xffff_ffff,
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
    fn coin_codec_round_trips() {
        let coin = Coin {
            outpoint: Outpoint {
                txid: Txid::new([1; 32]),
                index: 7,
            },
            value: 42,
            height: 3,
            coinbase: true,
            address: address(),
            covenant: covenant(),
        };

        assert_eq!(decode_coin(&encode_coin(&coin)).expect("decode"), coin);
    }

    #[test]
    fn name_state_codec_round_trips() {
        let state = NameState {
            name_hash: NameHash::new([2; 32]),
            name: Some("example-name".to_owned()),
            height: 9,
            state: NameLifecycleState::Registered,
        };

        assert_eq!(
            decode_name_state(&encode_name_state(&state)).expect("decode"),
            state
        );
    }

    #[test]
    fn connect_and_disconnect_block_updates_utxo_with_undo() {
        let store = MemoryStore::new();
        let mut engine = authorized_engine(store.clone());
        let first_tx = coinbase(vec![output(100)]);
        let first_outpoint = Outpoint {
            txid: first_tx.txid(),
            index: 0,
        };
        let first_block = block(1, vec![first_tx]);

        let summary = engine
            .connect_block(ConnectBlock {
                block_hash: first_block.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &first_block,
            })
            .expect("connect first");

        assert_eq!(
            summary,
            StateSummary {
                coins_created: 1,
                coins_spent: 0,
                names_changed: 0,
            }
        );
        assert!(engine.coin(&first_outpoint).expect("coin").is_some());

        let spend_tx = spend(first_outpoint.clone(), vec![output(25)]);
        let spend_outpoint = Outpoint {
            txid: spend_tx.txid(),
            index: 0,
        };
        let second_block = block(2, vec![coinbase(Vec::new()), spend_tx]);
        let summary = engine
            .connect_block(ConnectBlock {
                block_hash: second_block.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &second_block,
            })
            .expect("connect second");

        assert_eq!(summary.coins_created, 1);
        assert_eq!(summary.coins_spent, 1);
        assert!(engine.coin(&first_outpoint).expect("old coin").is_none());
        assert!(engine.coin(&spend_outpoint).expect("new coin").is_some());
        assert!(engine
            .load_undo(&second_block.hash())
            .expect("undo")
            .is_some());

        let summary = engine
            .disconnect_block(DisconnectBlock {
                block_hash: second_block.hash(),
                height: 1,
            })
            .expect("disconnect second");

        assert_eq!(summary.coins_created, 1);
        assert_eq!(summary.coins_spent, 1);
        assert!(engine
            .coin(&first_outpoint)
            .expect("old restored")
            .is_some());
        assert!(engine.coin(&spend_outpoint).expect("new deleted").is_none());
        assert!(engine
            .load_undo(&second_block.hash())
            .expect("undo removed")
            .is_none());

        let snapshot = store.snapshot().expect("snapshot");
        assert!(snapshot
            .get(ColumnFamily::Undo, second_block.hash().as_bytes())
            .expect("undo cf")
            .is_none());
    }

    #[test]
    fn connect_rejects_immature_and_value_creating_spends_without_mutation() {
        let store = MemoryStore::new();
        let mut engine = authorized_engine(store);
        let first_tx = coinbase(vec![output(100)]);
        let first_outpoint = Outpoint {
            txid: first_tx.txid(),
            index: 0,
        };
        let first_block = block(10, vec![first_tx]);
        engine
            .connect_block(ConnectBlock {
                block_hash: first_block.hash(),
                height: 0,
                coinbase_maturity: 2,
                block_reward: 100,
                block: &first_block,
            })
            .expect("connect funding block");

        let immature = block(
            11,
            vec![
                coinbase(Vec::new()),
                spend(first_outpoint.clone(), vec![output(100)]),
            ],
        );
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: immature.hash(),
                height: 1,
                coinbase_maturity: 2,
                block_reward: 100,
                block: &immature,
            }),
            Err(StateError::PrematureCoinbaseSpend { .. })
        ));
        assert!(engine.coin(&first_outpoint).unwrap().is_some());

        let inflationary = block(
            12,
            vec![
                coinbase(Vec::new()),
                spend(first_outpoint.clone(), vec![output(101)]),
            ],
        );
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: inflationary.hash(),
                height: 2,
                coinbase_maturity: 2,
                block_reward: 100,
                block: &inflationary,
            }),
            Err(StateError::InputValueBelowOutput {
                input: 100,
                output: 101
            })
        ));
        assert!(engine.coin(&first_outpoint).unwrap().is_some());
    }

    #[test]
    fn connect_enforces_subsidy_plus_fees_and_is_atomic_on_overpayment() {
        let store = MemoryStore::new();
        let mut engine = authorized_engine(store);
        let funding = coinbase(vec![output(100)]);
        let funding_outpoint = Outpoint {
            txid: funding.txid(),
            index: 0,
        };
        let funding_block = block(20, vec![funding]);
        engine
            .connect_block(ConnectBlock {
                block_hash: funding_block.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &funding_block,
            })
            .expect("connect funding block");

        let spend_tx = spend(funding_outpoint.clone(), vec![output(60)]);
        let overpaid_coinbase = coinbase(vec![output(141)]);
        let overpaid_outpoint = Outpoint {
            txid: overpaid_coinbase.txid(),
            index: 0,
        };
        let overpaid = block(21, vec![overpaid_coinbase, spend_tx.clone()]);
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: overpaid.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &overpaid,
            }),
            Err(StateError::CoinbaseValueExceedsReward {
                coinbase: 141,
                maximum: 140
            })
        ));
        assert!(engine.coin(&funding_outpoint).unwrap().is_some());
        assert!(engine.coin(&overpaid_outpoint).unwrap().is_none());
        assert!(engine.load_undo(&overpaid.hash()).unwrap().is_none());

        let paid_coinbase = coinbase(vec![output(140)]);
        let paid_outpoint = Outpoint {
            txid: paid_coinbase.txid(),
            index: 0,
        };
        let paid = block(22, vec![paid_coinbase, spend_tx]);
        engine
            .connect_block(ConnectBlock {
                block_hash: paid.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &paid,
            })
            .expect("fees may be paid to the miner");
        assert!(engine.coin(&funding_outpoint).unwrap().is_none());
        assert!(engine.coin(&paid_outpoint).unwrap().is_some());
    }

    #[test]
    fn default_engine_rejects_unauthorized_spends_without_mutation() {
        let store = MemoryStore::new();
        let mut engine = StoredStateEngine::new(store).expect("engine");
        let funding = coinbase(vec![output(100)]);
        let funding_outpoint = Outpoint {
            txid: funding.txid(),
            index: 0,
        };
        let funding_block = block(30, vec![funding]);
        engine
            .connect_block(ConnectBlock {
                block_hash: funding_block.hash(),
                height: 0,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &funding_block,
            })
            .expect("connect funding block");

        let unauthorized = block(
            31,
            vec![
                coinbase(Vec::new()),
                spend(funding_outpoint.clone(), vec![output(90)]),
            ],
        );
        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: unauthorized.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &unauthorized,
            }),
            Err(StateError::InputAuthorization { input_index: 0, .. })
        ));
        assert!(engine.coin(&funding_outpoint).unwrap().is_some());
        assert!(engine.load_undo(&unauthorized.hash()).unwrap().is_none());
    }

    #[test]
    fn covenant_linkage_rejects_invalid_transition_before_utxo_mutation() {
        let store = MemoryStore::new();
        let funding_outpoint = Outpoint {
            txid: Txid::new([44; 32]),
            index: 0,
        };
        let owner = Address::new(0, vec![45; 20]).expect("owner address");
        let name_hash = [46; 32];
        let funding_coin = Coin {
            outpoint: funding_outpoint.clone(),
            value: 50,
            height: 1,
            coinbase: false,
            address: owner.clone(),
            covenant: name_covenant(CovenantKind::Register, name_hash, 7),
        };
        let mut funding_batch = store.batch();
        write_coin_to_batch(&mut funding_batch, &funding_coin).expect("stage funding coin");
        store.commit(funding_batch).expect("commit funding coin");

        let mut engine = authorized_engine(store);
        let invalid_spend = spend(
            funding_outpoint.clone(),
            vec![Output {
                value: 50,
                address: owner.clone(),
                covenant: covenant(),
            }],
        );
        let invalid_outpoint = Outpoint {
            txid: invalid_spend.txid(),
            index: 0,
        };
        let invalid_block = block(40, vec![coinbase(Vec::new()), invalid_spend]);

        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: invalid_block.hash(),
                height: 2,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &invalid_block,
            }),
            Err(StateError::CovenantLink(
                CovenantLinkError::InvalidTransition {
                    input_index: 0,
                    from: CovenantKind::Register,
                    to: CovenantKind::None,
                }
            ))
        ));
        assert!(engine.coin(&funding_outpoint).unwrap().is_some());
        assert!(engine.coin(&invalid_outpoint).unwrap().is_none());
        assert!(engine.load_undo(&invalid_block.hash()).unwrap().is_none());

        let valid_spend = spend(
            funding_outpoint.clone(),
            vec![Output {
                value: 50,
                address: owner,
                covenant: name_covenant(CovenantKind::Update, name_hash, 7),
            }],
        );
        let valid_outpoint = Outpoint {
            txid: valid_spend.txid(),
            index: 0,
        };
        let valid_block = block(41, vec![coinbase(Vec::new()), valid_spend]);
        engine
            .connect_block(ConnectBlock {
                block_hash: valid_block.hash(),
                height: 2,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &valid_block,
            })
            .expect("REGISTER to UPDATE linkage");
        assert!(engine.coin(&funding_outpoint).unwrap().is_none());
        assert!(engine.coin(&valid_outpoint).unwrap().is_some());
    }

    #[test]
    fn connect_fails_closed_on_unverified_coinbase_issuance() {
        let store = MemoryStore::new();
        let mut engine = StoredStateEngine::new(store).expect("engine");
        let mut issuance = coinbase(vec![output(100)]);
        issuance.inputs = vec![
            Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            },
            Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![vec![1]],
                },
            },
        ];
        let issuance_outpoint = Outpoint {
            txid: issuance.txid(),
            index: 0,
        };
        let issuance_block = block(23, vec![issuance]);

        assert!(matches!(
            engine.connect_block(ConnectBlock {
                block_hash: issuance_block.hash(),
                height: 1,
                coinbase_maturity: 0,
                block_reward: 100,
                block: &issuance_block,
            }),
            Err(StateError::UnsupportedCoinbaseIssuance)
        ));
        assert!(engine.coin(&issuance_outpoint).unwrap().is_none());
        assert!(engine.load_undo(&issuance_block.hash()).unwrap().is_none());
    }
}
