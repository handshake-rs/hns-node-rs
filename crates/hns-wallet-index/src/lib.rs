//! Optional, active-chain wallet indexes for `hns-node`.
//!
//! The indexes live in the existing transaction-index column family under
//! versioned, non-32-byte prefixes. They are staged in the same atomic batch
//! as UTXO/name-state connection or disconnection and are never consensus
//! inputs.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "the public index boundary uses explicit domain names"
)]

use std::collections::{BTreeMap, HashMap};

use hns_primitives::{
    blake2b_256, Address, Block, BlockHash, Coin, Height, Outpoint, Transaction, Txid, Writer,
};
use hns_state::{decode_coin, encode_coin, encode_outpoint_key, BlockUndo};
use hns_store::{
    ColumnFamily, PrefixScanBudget, ReadSnapshot, StoreError, WriteBatch, PREFIX_SCAN_MAX_ENTRIES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod incoming_transfer;
mod swap;

pub use incoming_transfer::{
    stage_prune_undo as stage_prune_incoming_transfer_undo, IncomingTransferEntry,
};

pub use swap::{
    completed_tracked_contract_retirement, register_tracked_contract,
    retire_completed_tracked_contract, retire_never_confirmed_tracked_contract, tracked_contract,
    tracked_contract_events, tracked_contract_funding, tracked_contract_fundings,
    tracked_contract_lifecycle_revision, validate_completed_tracked_contract_retirements,
    validate_tracked_contract_registry, CompletedContractRetirement,
    CompletedContractRetirementOutcome, ContractId, ContractRegistration,
    ContractRegistrationOutcome, ContractRetirementOutcome, ContractRollbackBoundary,
    HnsHtlcDescriptor, RetiredRevealedPreimage, RevealedPreimage, ShakedexV2Descriptor,
    TrackedContractCursor, TrackedContractEvent, TrackedContractEventPage, TrackedContractFunding,
    TrackedContractFundingPage, TrackedContractKind, TrackedContractSpendKind,
    MAX_RETIRED_TRACKED_CONTRACTS, MAX_TRACKED_CONTRACTS, MAX_TRACKED_CONTRACTS_PER_ADDRESS,
    MAX_TRACKED_CONTRACT_RETIREMENT_EVENTS,
};

/// Persistent profile key. Changing a non-empty chain's profile requires an
/// explicit offline reindex.
pub const INDEX_PROFILE_MODE_KEY: &[u8] = b"wallet-index-profile/v1";
/// Maximum entries returned by one wallet-index page.
pub const MAX_QUERY_ENTRIES: usize = PREFIX_SCAN_MAX_ENTRIES;
/// Maximum aggregate key/value bytes in one wallet-index page.
pub const MAX_QUERY_BYTES: usize = 16 * 1024 * 1024;

const ORIGINAL_PROFILE_VERSION: u8 = 1;
const LIFECYCLE_PROFILE_VERSION: u8 = 2;
const COMPLETED_RETIREMENT_PROFILE_VERSION: u8 = 3;
/// Current wallet-index profile version. Version four adds confirmed
/// TRANSFER-recipient indexing and compact source-inclusion evidence.
pub const PROFILE_VERSION: u8 = 4;
const PROFILE_SCRIPT_HISTORY: u8 = 1 << 0;
const PROFILE_SPENDER: u8 = 1 << 1;
const PROFILE_WALLET: u8 = 1 << 2;
const PROFILE_KNOWN_FLAGS: u8 = PROFILE_SCRIPT_HISTORY | PROFILE_SPENDER | PROFILE_WALLET;
const PROFILE_BYTES: usize = 2 + 32;

const HISTORY_PREFIX: &[u8] = b"wallet-index/v1/history/";
const UTXO_PREFIX: &[u8] = b"wallet-index/v1/utxo/";
const SPENDER_PREFIX: &[u8] = b"wallet-index/v1/spender/";
const HISTORY_VALUE_VERSION: u8 = 1;
const HISTORY_VALUE_BODY_BYTES: usize = 1 + 32 + 32 + 4 + 4 + 1;
const HISTORY_VALUE_BYTES: usize = HISTORY_VALUE_BODY_BYTES + 32;
const SPENDER_VALUE_VERSION: u8 = 1;
const SPENDER_VALUE_BODY_BYTES: usize = 1 + 32 + 4 + 32 + 4;
const SPENDER_VALUE_BYTES: usize = SPENDER_VALUE_BODY_BYTES + 32;
const UTXO_VALUE_VERSION: u8 = 1;
const UTXO_VALUE_CHECKSUM_BYTES: usize = 32;
const UTXO_VALUE_MIN_BYTES: usize = 1 + UTXO_VALUE_CHECKSUM_BYTES;

/// Configuration-controlled active-chain wallet index profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletIndexProfile {
    /// Retain transaction history keyed by canonical output address script.
    pub script_history: bool,
    /// Retain active-chain output-to-spending-transaction mappings.
    pub spender: bool,
    /// Retain script UTXOs and incoming TRANSFER-recipient/source evidence, and
    /// imply history/spender support.
    pub wallet: bool,
}

impl WalletIndexProfile {
    /// Whether any wallet index writes are enabled.
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.script_history || self.spender || self.wallet
    }

    /// Whether script transaction history is available.
    #[must_use]
    pub const fn histories(self) -> bool {
        self.script_history || self.wallet
    }

    /// Whether output spender lookup is available.
    #[must_use]
    pub const fn spenders(self) -> bool {
        self.spender || self.wallet
    }

    /// Whether script UTXO lookup is available.
    #[must_use]
    pub const fn utxos(self) -> bool {
        self.wallet
    }

    /// Checks whether `available` satisfies all parts of this requested profile.
    #[must_use]
    pub const fn is_satisfied_by(self, available: Self) -> bool {
        (!self.histories() || available.histories())
            && (!self.spenders() || available.spenders())
            && (!self.utxos() || available.utxos())
    }
}

/// Encode a checksummed persistent profile record.
#[must_use]
pub fn encode_index_profile(profile: WalletIndexProfile) -> [u8; PROFILE_BYTES] {
    let flags = (if profile.script_history {
        PROFILE_SCRIPT_HISTORY
    } else {
        0
    }) | (if profile.spender { PROFILE_SPENDER } else { 0 })
        | (if profile.wallet { PROFILE_WALLET } else { 0 });
    let mut output = [0_u8; PROFILE_BYTES];
    output[0] = PROFILE_VERSION;
    output[1] = flags;
    let checksum = blake2b_256(&output[..2]);
    output[2..].copy_from_slice(&checksum);
    output
}

/// Decode and validate a persistent profile record.
pub fn decode_index_profile(raw: &[u8]) -> Result<WalletIndexProfile, IndexError> {
    if raw.len() != PROFILE_BYTES
        || !matches!(
            raw.first().copied(),
            Some(ORIGINAL_PROFILE_VERSION)
                | Some(LIFECYCLE_PROFILE_VERSION)
                | Some(COMPLETED_RETIREMENT_PROFILE_VERSION)
                | Some(PROFILE_VERSION)
        )
        || raw
            .get(1)
            .is_none_or(|flags| flags & !PROFILE_KNOWN_FLAGS != 0)
        || raw.get(2..) != Some(blake2b_256(&raw[..2]).as_slice())
    {
        return Err(IndexError::Corrupt("invalid wallet-index profile record"));
    }
    let flags = raw[1];
    Ok(WalletIndexProfile {
        script_history: flags & PROFILE_SCRIPT_HISTORY != 0,
        spender: flags & PROFILE_SPENDER != 0,
        wallet: flags & PROFILE_WALLET != 0,
    })
}

/// Decode and return the downgrade-fencing profile version.
pub fn index_profile_version(raw: &[u8]) -> Result<u8, IndexError> {
    let _ = decode_index_profile(raw)?;
    raw.first()
        .copied()
        .ok_or(IndexError::Corrupt("invalid wallet-index profile record"))
}

/// Whether a valid persistent profile carries the current downgrade-fencing
/// version. Versions one through three remain readable for diagnosis and safe
/// initialization of profiles that did not enable the wallet component. A
/// non-empty wallet-enabled legacy profile must not be upgraded by normal
/// startup because it lacks v4 TRANSFER-recipient/source evidence.
pub fn index_profile_is_current(raw: &[u8]) -> Result<bool, IndexError> {
    Ok(index_profile_version(raw)? == PROFILE_VERSION)
}

/// Stable content identity for the canonical Handshake output address script.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ScriptId([u8; 32]);

impl ScriptId {
    /// Construct an identity from its stable raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive an ID from the canonical address encoding used in transaction outputs.
    #[must_use]
    pub fn from_address(address: &Address) -> Self {
        let mut writer = Writer::with_capacity(2 + address.hash.len());
        address.write_to(&mut writer);
        Self(blake2b_256(&writer.finish()))
    }

    /// Derive an ID for a caller-supplied canonical script descriptor.
    #[must_use]
    pub fn from_descriptor(descriptor: &[u8]) -> Self {
        Self(blake2b_256(descriptor))
    }

    /// Raw stable identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Direction flags for one transaction in a script's history.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptHistoryDirection {
    /// At least one transaction output pays this script.
    pub received: bool,
    /// At least one transaction input spends an output paying this script.
    pub spent: bool,
}

/// One confirmed active-chain script history row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptHistoryEntry {
    /// Canonical transaction ID.
    pub txid: Txid,
    /// Active-chain block containing the transaction.
    pub block_hash: BlockHash,
    /// Active-chain height.
    pub height: Height,
    /// Zero-based transaction position in the block.
    pub transaction_position: u32,
    /// Consolidated received/spent direction for this script and transaction.
    pub direction: ScriptHistoryDirection,
}

impl ScriptHistoryEntry {
    fn encode(&self, script: ScriptId) -> Vec<u8> {
        let mut writer = Writer::with_capacity(HISTORY_VALUE_BYTES);
        writer.write_u8(HISTORY_VALUE_VERSION);
        writer.write_bytes(self.txid.as_bytes());
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_u32(self.transaction_position);
        writer.write_u8(u8::from(self.direction.received) | (u8::from(self.direction.spent) << 1));
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-history-v1",
            &history_key(script, self),
            &raw,
        ));
        raw
    }

    fn decode(script: ScriptId, key: &[u8], raw: &[u8]) -> Result<Self, IndexError> {
        if raw.len() != HISTORY_VALUE_BYTES
            || raw.first().copied() != Some(HISTORY_VALUE_VERSION)
            || raw.get(HISTORY_VALUE_BODY_BYTES..)
                != Some(
                    bound_checksum(
                        b"hns-wallet-index-history-v1",
                        key,
                        &raw[..HISTORY_VALUE_BODY_BYTES],
                    )
                    .as_slice(),
                )
        {
            return Err(IndexError::Corrupt("invalid script-history value"));
        }
        let txid = Txid::new(array_at::<32>(raw, 1, "script-history txid")?);
        let block_hash = BlockHash::new(array_at::<32>(raw, 33, "script-history block hash")?);
        let height = u32::from_le_bytes(array_at::<4>(raw, 65, "script-history height")?);
        let transaction_position = u32::from_le_bytes(array_at::<4>(
            raw,
            69,
            "script-history transaction position",
        )?);
        let flags = *raw
            .get(73)
            .ok_or(IndexError::Corrupt("missing script-history flags"))?;
        if flags & !0b11 != 0 || flags == 0 {
            return Err(IndexError::Corrupt("invalid script-history flags"));
        }
        let entry = Self {
            txid,
            block_hash,
            height,
            transaction_position,
            direction: ScriptHistoryDirection {
                received: flags & 1 != 0,
                spent: flags & 2 != 0,
            },
        };
        if key != history_key(script, &entry) {
            return Err(IndexError::Corrupt(
                "script-history key/value binding mismatch",
            ));
        }
        Ok(entry)
    }
}

/// Exclusive script-history continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptHistoryCursor {
    /// Last returned height.
    pub height: Height,
    /// Last returned transaction position.
    pub transaction_position: u32,
    /// Last returned transaction ID.
    pub txid: Txid,
}

/// One bounded script-history result page.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptHistoryPage {
    /// Active-chain history rows in height/position order.
    pub entries: Vec<ScriptHistoryEntry>,
    /// Exclusive continuation when another page may exist.
    pub continuation: Option<ScriptHistoryCursor>,
}

/// Indexed spending transaction for one active-chain output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpendingTransaction {
    /// Spending transaction ID.
    pub txid: Txid,
    /// Input position that spends the queried output.
    pub input_position: u32,
    /// Active-chain inclusion block.
    pub block_hash: BlockHash,
    /// Active-chain inclusion height.
    pub height: Height,
}

impl SpendingTransaction {
    fn encode(&self, spent_outpoint: &Outpoint) -> Vec<u8> {
        let mut writer = Writer::with_capacity(SPENDER_VALUE_BYTES);
        writer.write_u8(SPENDER_VALUE_VERSION);
        writer.write_bytes(self.txid.as_bytes());
        writer.write_u32(self.input_position);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-spender-v1",
            &spender_key(spent_outpoint),
            &raw,
        ));
        raw
    }

    fn decode(spent_outpoint: &Outpoint, raw: &[u8]) -> Result<Self, IndexError> {
        if raw.len() != SPENDER_VALUE_BYTES
            || raw.first().copied() != Some(SPENDER_VALUE_VERSION)
            || raw.get(SPENDER_VALUE_BODY_BYTES..)
                != Some(
                    bound_checksum(
                        b"hns-wallet-index-spender-v1",
                        &spender_key(spent_outpoint),
                        &raw[..SPENDER_VALUE_BODY_BYTES],
                    )
                    .as_slice(),
                )
        {
            return Err(IndexError::Corrupt("invalid spender-index value"));
        }
        Ok(Self {
            txid: Txid::new(array_at::<32>(raw, 1, "spender txid")?),
            input_position: u32::from_le_bytes(array_at::<4>(raw, 33, "spender input")?),
            block_hash: BlockHash::new(array_at::<32>(raw, 37, "spender block hash")?),
            height: u32::from_le_bytes(array_at::<4>(raw, 69, "spender height")?),
        })
    }
}

/// One indexed unspent coin for a script.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptUtxo {
    /// Complete canonical coin from the active UTXO set.
    pub coin: Coin,
}

/// Exclusive script-UTXO continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptUtxoCursor {
    /// Last returned outpoint.
    pub outpoint: Outpoint,
}

/// One bounded script-UTXO result page.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptUtxoPage {
    /// Active unspent coins.
    pub entries: Vec<ScriptUtxo>,
    /// Exclusive continuation when another page may exist.
    pub continuation: Option<ScriptUtxoCursor>,
}

/// Wallet index staging/query failure.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Durable store failure.
    #[error("wallet index store failure: {0}")]
    Store(#[from] StoreError),
    /// Active-state coin codec failure.
    #[error("wallet index state failure: {0}")]
    State(#[from] hns_state::StateError),
    /// Required profile component is disabled.
    #[error("wallet index component is disabled: {0}")]
    Disabled(&'static str),
    /// Query bound is invalid.
    #[error("wallet index query limit must be between 1 and {MAX_QUERY_ENTRIES}")]
    InvalidLimit,
    /// A connected transaction input could not be resolved to a coin.
    #[error("wallet index could not resolve input coin {0:?}")]
    MissingInputCoin(Outpoint),
    /// A position exceeds the persisted fixed-width schema.
    #[error("wallet index position exceeds u32")]
    PositionOverflow,
    /// A TRANSFER-kind covenant is not the exact pinned canonical shape.
    #[error("wallet incoming TRANSFER covenant is malformed")]
    InvalidTransferCovenant,
    /// Incoming-TRANSFER derivative data exceeds a hard persistence bound.
    #[error("wallet incoming TRANSFER capacity exceeded: {0}")]
    TransferCapacity(&'static str),
    /// A public Shakedex/HTLC descriptor is malformed or unsupported.
    #[error("wallet tracked-contract descriptor is invalid")]
    InvalidContract,
    /// One script address has reached its bounded descriptor candidate limit.
    #[error("wallet tracked-contract address candidate set is full")]
    ContractAddressCapacity,
    /// The configured active contract registry has reached its hard bound.
    #[error("wallet tracked-contract registry is full")]
    ContractCapacity,
    /// The immutable completed-contract retirement registry is full.
    #[error("wallet tracked-contract retirement registry is full")]
    ContractRetirementCapacity,
    /// This exact descriptor identity was irreversibly retired.
    #[error("wallet tracked-contract descriptor was permanently retired")]
    ContractRetired,
    /// A matching funding has already been confirmed for this registration.
    #[error("wallet tracked-contract registration has confirmed funding history")]
    ContractConfirmed,
    /// This legacy registration predates authoritative monotonic confirmation state.
    #[error("wallet tracked-contract confirmation history is unknown")]
    ContractConfirmationUnknown,
    /// The caller prepared retirement for another registration lifecycle.
    #[error("wallet tracked-contract lifecycle changed from {expected} to {actual}")]
    StaleContractLifecycle { expected: u64, actual: u64 },
    /// Completed retirement still needs retained rollback data or has no exact
    /// terminal spend proof.
    #[error("wallet tracked-contract history is not safely retireable")]
    ContractRollbackRequired,
    /// Completed retirement history exceeds the bounded atomic proof walk.
    #[error("wallet tracked-contract retirement history exceeds its hard bound")]
    ContractRetirementHistoryCapacity,
    /// No immutable contract registration exists for the requested identity.
    #[error("wallet tracked-contract registration is unknown")]
    UnknownContract,
    /// Persisted data is malformed or inconsistent.
    #[error("wallet index corruption: {0}")]
    Corrupt(&'static str),
}

/// Stage all enabled indexes for an active-chain block connection.
///
/// `snapshot` must be the same immutable pre-connect state used by consensus
/// connection and `batch` must be the same uncommitted atomic batch.
pub fn stage_connect<B: WriteBatch, S: ReadSnapshot>(
    snapshot: &S,
    batch: &mut B,
    block: &Block,
    height: Height,
    profile: WalletIndexProfile,
) -> Result<(), IndexError> {
    if !profile.enabled() {
        return Ok(());
    }
    let block_hash = block.hash();
    let created = block_created_coins(block, height)?;
    let mut history = BTreeMap::<(ScriptId, Txid), ScriptHistoryEntry>::new();

    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        let txid = transaction.txid();
        if profile.histories() || profile.utxos() {
            stage_created_outputs(
                batch,
                transaction,
                txid,
                block_hash,
                height,
                transaction_position,
                profile,
                &mut history,
            )?;
        }
        for (input_position, input) in transaction.inputs.iter().enumerate() {
            if input.previous_output.is_null() {
                continue;
            }
            let input_position =
                u32::try_from(input_position).map_err(|_| IndexError::PositionOverflow)?;
            let coin = match created.get(&input.previous_output) {
                Some(coin) => coin.clone(),
                None => load_coin(snapshot, &input.previous_output)?
                    .ok_or_else(|| IndexError::MissingInputCoin(input.previous_output.clone()))?,
            };
            if profile.histories() {
                record_history(
                    &mut history,
                    ScriptId::from_address(&coin.address),
                    txid,
                    block_hash,
                    height,
                    transaction_position,
                    ScriptHistoryDirection {
                        received: false,
                        spent: true,
                    },
                );
            }
            if profile.spenders() {
                batch.put(
                    ColumnFamily::TxIndex,
                    &spender_key(&input.previous_output),
                    &SpendingTransaction {
                        txid,
                        input_position,
                        block_hash,
                        height,
                    }
                    .encode(&input.previous_output),
                )?;
            }
            if profile.utxos() {
                batch.delete(
                    ColumnFamily::TxIndex,
                    &utxo_key(
                        ScriptId::from_address(&coin.address),
                        &input.previous_output,
                    ),
                )?;
            }
        }
    }
    if profile.histories() {
        for ((script, _), entry) in history {
            batch.put(
                ColumnFamily::TxIndex,
                &history_key(script, &entry),
                &entry.encode(script),
            )?;
        }
    }
    if profile.wallet {
        incoming_transfer::stage_connect(snapshot, batch, block, height)?;
    }
    swap::stage_connect(snapshot, batch, block, height, profile)?;
    Ok(())
}

/// Stage exact reversal of enabled indexes for an active-tip disconnect.
///
/// `undo` must be the same checked block undo consumed by active-state
/// disconnection and `batch` must be the same uncommitted atomic batch.
pub fn stage_disconnect<B: WriteBatch, S: ReadSnapshot>(
    snapshot: &S,
    batch: &mut B,
    block: &Block,
    undo: &BlockUndo,
    profile: WalletIndexProfile,
) -> Result<(), IndexError> {
    if !profile.enabled() {
        return Ok(());
    }
    if undo.block_hash != block.hash() {
        return Err(IndexError::Corrupt("wallet-index undo block mismatch"));
    }
    let created = block_created_coins(block, undo.height)?;
    let restored = undo
        .spent_coins
        .iter()
        .map(|coin| (coin.outpoint.clone(), coin.clone()))
        .collect::<HashMap<_, _>>();
    let mut history = BTreeMap::<(ScriptId, Txid), ScriptHistoryEntry>::new();

    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        let txid = transaction.txid();
        for (output_position, output) in transaction.outputs.iter().enumerate() {
            if output.is_unspendable() {
                continue;
            }
            let output_position =
                u32::try_from(output_position).map_err(|_| IndexError::PositionOverflow)?;
            let outpoint = Outpoint {
                txid,
                index: output_position,
            };
            let script = ScriptId::from_address(&output.address);
            if profile.histories() {
                record_history(
                    &mut history,
                    script,
                    txid,
                    undo.block_hash,
                    undo.height,
                    transaction_position,
                    ScriptHistoryDirection {
                        received: true,
                        spent: false,
                    },
                );
            }
            if profile.utxos() {
                batch.delete(ColumnFamily::TxIndex, &utxo_key(script, &outpoint))?;
            }
        }
        for input in &transaction.inputs {
            if input.previous_output.is_null() {
                continue;
            }
            let coin = created
                .get(&input.previous_output)
                .or_else(|| restored.get(&input.previous_output))
                .ok_or_else(|| IndexError::MissingInputCoin(input.previous_output.clone()))?;
            if profile.histories() {
                record_history(
                    &mut history,
                    ScriptId::from_address(&coin.address),
                    txid,
                    undo.block_hash,
                    undo.height,
                    transaction_position,
                    ScriptHistoryDirection {
                        received: false,
                        spent: true,
                    },
                );
            }
            if profile.spenders() {
                batch.delete(ColumnFamily::TxIndex, &spender_key(&input.previous_output))?;
            }
        }
    }

    if profile.histories() {
        for ((script, _), entry) in history {
            batch.delete(ColumnFamily::TxIndex, &history_key(script, &entry))?;
        }
    }
    if profile.utxos() {
        for coin in &undo.spent_coins {
            let script = ScriptId::from_address(&coin.address);
            batch.put(
                ColumnFamily::TxIndex,
                &utxo_key(script, &coin.outpoint),
                &encode_utxo_value(script, coin),
            )?;
        }
    }
    if profile.wallet {
        incoming_transfer::stage_disconnect(snapshot, batch, block, undo)?;
    }
    swap::stage_disconnect(snapshot, batch, block, undo, profile)?;
    Ok(())
}

/// Read one bounded page of confirmed script history.
pub fn script_history<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    script: ScriptId,
    cursor: Option<&ScriptHistoryCursor>,
    limit: usize,
) -> Result<ScriptHistoryPage, IndexError> {
    if !profile.histories() {
        return Err(IndexError::Disabled("script-history"));
    }
    validate_limit(limit)?;
    let prefix = history_prefix(script);
    let start_after = cursor.map(|cursor| history_cursor_key(script, cursor));
    let page = snapshot.scan_prefix_page(
        ColumnFamily::TxIndex,
        &prefix,
        start_after.as_deref(),
        PrefixScanBudget {
            max_entries: limit,
            max_bytes: MAX_QUERY_BYTES,
        },
    )?;
    let entries = page
        .entries
        .iter()
        .map(|(key, raw)| ScriptHistoryEntry::decode(script, key, raw))
        .collect::<Result<Vec<_>, _>>()?;
    let continuation = page
        .continuation
        .as_deref()
        .map(decode_history_cursor)
        .transpose()?;
    Ok(ScriptHistoryPage {
        entries,
        continuation,
    })
}

/// Read one bounded page of active script UTXOs.
pub fn script_utxos<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    script: ScriptId,
    cursor: Option<&ScriptUtxoCursor>,
    limit: usize,
) -> Result<ScriptUtxoPage, IndexError> {
    if !profile.utxos() {
        return Err(IndexError::Disabled("wallet/script-utxo"));
    }
    validate_limit(limit)?;
    let prefix = utxo_prefix(script);
    let start_after = cursor.map(|cursor| utxo_key(script, &cursor.outpoint));
    let page = snapshot.scan_prefix_page(
        ColumnFamily::TxIndex,
        &prefix,
        start_after.as_deref(),
        PrefixScanBudget {
            max_entries: limit,
            max_bytes: MAX_QUERY_BYTES,
        },
    )?;
    let entries = page
        .entries
        .iter()
        .map(|(key, raw)| {
            let coin = decode_utxo_value(script, key, raw)?;
            Ok::<ScriptUtxo, IndexError>(ScriptUtxo { coin })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let continuation = page
        .continuation
        .as_deref()
        .map(decode_utxo_cursor)
        .transpose()?;
    Ok(ScriptUtxoPage {
        entries,
        continuation,
    })
}

/// Look up the active-chain transaction spending one output.
pub fn spending_transaction<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    outpoint: &Outpoint,
) -> Result<Option<SpendingTransaction>, IndexError> {
    if !profile.spenders() {
        return Err(IndexError::Disabled("spender"));
    }
    snapshot
        .get(ColumnFamily::TxIndex, &spender_key(outpoint))?
        .as_deref()
        .map(|raw| SpendingTransaction::decode(outpoint, raw))
        .transpose()
}

fn bound_checksum(domain: &[u8], key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut writer = Writer::with_capacity(domain.len() + key.len() + value.len() + 24);
    writer.write_varbytes(domain);
    writer.write_varbytes(key);
    writer.write_varbytes(value);
    blake2b_256(&writer.finish())
}

fn encode_utxo_value(script: ScriptId, coin: &Coin) -> Vec<u8> {
    let key = utxo_key(script, &coin.outpoint);
    let encoded_coin = encode_coin(coin);
    let mut raw = Vec::with_capacity(1 + encoded_coin.len() + UTXO_VALUE_CHECKSUM_BYTES);
    raw.push(UTXO_VALUE_VERSION);
    raw.extend_from_slice(&encoded_coin);
    raw.extend_from_slice(&bound_checksum(b"hns-wallet-index-utxo-v1", &key, &raw));
    raw
}

fn decode_utxo_value(script: ScriptId, key: &[u8], raw: &[u8]) -> Result<Coin, IndexError> {
    if raw.len() <= UTXO_VALUE_MIN_BYTES || raw.first().copied() != Some(UTXO_VALUE_VERSION) {
        return Err(IndexError::Corrupt("invalid script-UTXO value"));
    }
    let body_len = raw
        .len()
        .checked_sub(UTXO_VALUE_CHECKSUM_BYTES)
        .ok_or(IndexError::Corrupt("invalid script-UTXO value"))?;
    let (body, checksum) = raw.split_at(body_len);
    let expected_checksum = bound_checksum(b"hns-wallet-index-utxo-v1", key, body);
    if checksum != expected_checksum.as_slice() {
        return Err(IndexError::Corrupt("invalid script-UTXO checksum"));
    }
    let coin = decode_coin(
        body.get(1..)
            .ok_or(IndexError::Corrupt("invalid script-UTXO value"))?,
    )
    .map_err(|_| IndexError::Corrupt("invalid script-UTXO coin"))?;
    let expected_key = utxo_key(script, &coin.outpoint);
    if key != expected_key.as_slice() || ScriptId::from_address(&coin.address) != script {
        return Err(IndexError::Corrupt(
            "script-UTXO key/value binding mismatch",
        ));
    }
    Ok(coin)
}

#[allow(
    clippy::too_many_arguments,
    reason = "atomic staging keeps the exact block/transaction coordinates explicit"
)]
fn stage_created_outputs<B: WriteBatch>(
    batch: &mut B,
    transaction: &Transaction,
    txid: Txid,
    block_hash: BlockHash,
    height: Height,
    transaction_position: u32,
    profile: WalletIndexProfile,
    history: &mut BTreeMap<(ScriptId, Txid), ScriptHistoryEntry>,
) -> Result<(), IndexError> {
    for (output_position, output) in transaction.outputs.iter().enumerate() {
        if output.is_unspendable() {
            continue;
        }
        let output_position =
            u32::try_from(output_position).map_err(|_| IndexError::PositionOverflow)?;
        let outpoint = Outpoint {
            txid,
            index: output_position,
        };
        let script = ScriptId::from_address(&output.address);
        if profile.histories() {
            record_history(
                history,
                script,
                txid,
                block_hash,
                height,
                transaction_position,
                ScriptHistoryDirection {
                    received: true,
                    spent: false,
                },
            );
        }
        if profile.utxos() {
            let coin = Coin {
                outpoint: outpoint.clone(),
                value: output.value,
                height,
                coinbase: transaction_position == 0,
                address: output.address.clone(),
                covenant: output.covenant.clone(),
            };
            batch.put(
                ColumnFamily::TxIndex,
                &utxo_key(script, &outpoint),
                &encode_utxo_value(script, &coin),
            )?;
        }
    }
    Ok(())
}

fn record_history(
    history: &mut BTreeMap<(ScriptId, Txid), ScriptHistoryEntry>,
    script: ScriptId,
    txid: Txid,
    block_hash: BlockHash,
    height: Height,
    transaction_position: u32,
    direction: ScriptHistoryDirection,
) {
    let entry = history.entry((script, txid)).or_insert(ScriptHistoryEntry {
        txid,
        block_hash,
        height,
        transaction_position,
        direction: ScriptHistoryDirection::default(),
    });
    entry.direction.received |= direction.received;
    entry.direction.spent |= direction.spent;
}

fn block_created_coins(
    block: &Block,
    height: Height,
) -> Result<HashMap<Outpoint, Coin>, IndexError> {
    let mut coins = HashMap::new();
    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let txid = transaction.txid();
        for (output_position, output) in transaction.outputs.iter().enumerate() {
            if output.is_unspendable() {
                continue;
            }
            let output_position =
                u32::try_from(output_position).map_err(|_| IndexError::PositionOverflow)?;
            let outpoint = Outpoint {
                txid,
                index: output_position,
            };
            coins.insert(
                outpoint.clone(),
                Coin {
                    outpoint,
                    value: output.value,
                    height,
                    coinbase: transaction_position == 0,
                    address: output.address.clone(),
                    covenant: output.covenant.clone(),
                },
            );
        }
    }
    Ok(coins)
}

fn load_coin<S: ReadSnapshot>(
    snapshot: &S,
    outpoint: &Outpoint,
) -> Result<Option<Coin>, IndexError> {
    snapshot
        .get(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))?
        .as_deref()
        .map(decode_coin)
        .transpose()
        .map_err(IndexError::from)
}

fn history_prefix(script: ScriptId) -> Vec<u8> {
    let mut key = Vec::with_capacity(HISTORY_PREFIX.len() + 32);
    key.extend_from_slice(HISTORY_PREFIX);
    key.extend_from_slice(script.as_bytes());
    key
}

fn history_key(script: ScriptId, entry: &ScriptHistoryEntry) -> Vec<u8> {
    let mut key = history_prefix(script);
    key.extend_from_slice(&entry.height.to_be_bytes());
    key.extend_from_slice(&entry.transaction_position.to_be_bytes());
    key.extend_from_slice(entry.txid.as_bytes());
    key
}

fn history_cursor_key(script: ScriptId, cursor: &ScriptHistoryCursor) -> Vec<u8> {
    let mut key = history_prefix(script);
    key.extend_from_slice(&cursor.height.to_be_bytes());
    key.extend_from_slice(&cursor.transaction_position.to_be_bytes());
    key.extend_from_slice(cursor.txid.as_bytes());
    key
}

fn decode_history_cursor(key: &[u8]) -> Result<ScriptHistoryCursor, IndexError> {
    let suffix = key
        .get(HISTORY_PREFIX.len() + 32..)
        .ok_or(IndexError::Corrupt("truncated script-history key"))?;
    if suffix.len() != 4 + 4 + 32 {
        return Err(IndexError::Corrupt("invalid script-history key length"));
    }
    Ok(ScriptHistoryCursor {
        height: u32::from_be_bytes(array_at::<4>(suffix, 0, "history cursor height")?),
        transaction_position: u32::from_be_bytes(array_at::<4>(
            suffix,
            4,
            "history cursor position",
        )?),
        txid: Txid::new(array_at::<32>(suffix, 8, "history cursor txid")?),
    })
}

fn utxo_prefix(script: ScriptId) -> Vec<u8> {
    let mut key = Vec::with_capacity(UTXO_PREFIX.len() + 32);
    key.extend_from_slice(UTXO_PREFIX);
    key.extend_from_slice(script.as_bytes());
    key
}

fn utxo_key(script: ScriptId, outpoint: &Outpoint) -> Vec<u8> {
    let mut key = utxo_prefix(script);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.index.to_be_bytes());
    key
}

fn decode_utxo_cursor(key: &[u8]) -> Result<ScriptUtxoCursor, IndexError> {
    let suffix = key
        .get(UTXO_PREFIX.len() + 32..)
        .ok_or(IndexError::Corrupt("truncated script-utxo key"))?;
    if suffix.len() != 32 + 4 {
        return Err(IndexError::Corrupt("invalid script-utxo key length"));
    }
    Ok(ScriptUtxoCursor {
        outpoint: Outpoint {
            txid: Txid::new(array_at::<32>(suffix, 0, "script-utxo txid")?),
            index: u32::from_be_bytes(array_at::<4>(suffix, 32, "script-utxo index")?),
        },
    })
}

fn spender_key(outpoint: &Outpoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(SPENDER_PREFIX.len() + 36);
    key.extend_from_slice(SPENDER_PREFIX);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.index.to_be_bytes());
    key
}

fn validate_limit(limit: usize) -> Result<(), IndexError> {
    if (1..=MAX_QUERY_ENTRIES).contains(&limit) {
        Ok(())
    } else {
        Err(IndexError::InvalidLimit)
    }
}

fn array_at<const N: usize>(
    raw: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<[u8; N], IndexError> {
    raw.get(offset..offset.saturating_add(N))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(IndexError::Corrupt(context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{Covenant, CovenantKind, Input, Output, Witness};
    use hns_state::{write_coin_to_batch, TreeRoot};
    use hns_store::{MemoryStore, Store};

    fn address(byte: u8) -> Address {
        Address::new(0, vec![byte; 20]).unwrap()
    }

    fn output(byte: u8, value: u64) -> Output {
        Output {
            value,
            address: address(byte),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }
    }

    fn transfer_output(owner: u8, recipient: u8, value: u64) -> Output {
        Output {
            value,
            address: address(owner),
            covenant: Covenant {
                kind: CovenantKind::Transfer,
                items: vec![
                    vec![3; 32],
                    2_u32.to_le_bytes().to_vec(),
                    vec![0],
                    vec![recipient; 20],
                ],
            },
        }
    }

    fn block(transactions: Vec<Transaction>) -> Block {
        Block {
            header: hns_primitives::Header::default(),
            transactions,
        }
    }

    fn undo(block: &Block, spent_coins: Vec<Coin>) -> BlockUndo {
        BlockUndo {
            block_hash: block.hash(),
            height: 9,
            previous_tree_root: TreeRoot::ZERO,
            resulting_tree_root: TreeRoot::ZERO,
            previous_committed_tree_root: TreeRoot::ZERO,
            resulting_committed_tree_root: TreeRoot::ZERO,
            spent_coins,
            created_coins: Vec::new(),
            airdrop_positions: Vec::new(),
            previous_name_states: Vec::new(),
            name_tree_interval_boundary: false,
            previous_name_tree_accumulator_last_height: None,
            previous_name_tree_accumulator: None,
        }
    }

    #[test]
    fn profile_round_trip_is_checksummed() {
        let profile = WalletIndexProfile {
            script_history: true,
            spender: false,
            wallet: true,
        };
        let mut encoded = encode_index_profile(profile);
        assert_eq!(decode_index_profile(&encoded).unwrap(), profile);
        encoded[2] ^= 1;
        assert!(matches!(
            decode_index_profile(&encoded),
            Err(IndexError::Corrupt(_))
        ));
    }

    #[test]
    fn incoming_transfer_profile_version_fences_all_prior_writers() {
        let profile = WalletIndexProfile {
            script_history: true,
            spender: true,
            wallet: true,
        };
        let current = encode_index_profile(profile);
        assert_eq!(current[0], PROFILE_VERSION);
        assert!(index_profile_is_current(&current).expect("current profile"));

        for prior_version in [
            ORIGINAL_PROFILE_VERSION,
            LIFECYCLE_PROFILE_VERSION,
            COMPLETED_RETIREMENT_PROFILE_VERSION,
        ] {
            let mut legacy = current;
            legacy[0] = prior_version;
            let legacy_checksum = blake2b_256(&legacy[..2]);
            legacy[2..].copy_from_slice(&legacy_checksum);
            assert_eq!(
                decode_index_profile(&legacy).expect("legacy profile"),
                profile
            );
            assert!(!index_profile_is_current(&legacy).expect("legacy version"));
            assert_eq!(
                index_profile_version(&legacy).expect("legacy version number"),
                prior_version
            );
        }

        let mut future = current;
        future[0] = PROFILE_VERSION + 1;
        let future_checksum = blake2b_256(&future[..2]);
        future[2..].copy_from_slice(&future_checksum);
        assert!(matches!(
            decode_index_profile(&future),
            Err(IndexError::Corrupt(_))
        ));
    }

    #[test]
    fn connect_disconnect_and_reconnect_are_exactly_reversible() {
        let store = MemoryStore::new();
        let previous = Outpoint {
            txid: Txid::new([4; 32]),
            index: 3,
        };
        let previous_coin = Coin {
            outpoint: previous.clone(),
            value: 50,
            height: 2,
            coinbase: false,
            address: address(7),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let mut seed = store.batch();
        write_coin_to_batch(&mut seed, &previous_coin).unwrap();
        store.commit(seed).unwrap();

        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: previous.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(8, 40)],
            locktime: 0,
        };
        let block = block(vec![transaction.clone()]);
        let profile = WalletIndexProfile {
            wallet: true,
            ..WalletIndexProfile::default()
        };
        let snapshot = store.snapshot().unwrap();
        let mut connect = store.batch();
        stage_connect(&snapshot, &mut connect, &block, 9, profile).unwrap();
        drop(snapshot);
        store.commit(connect).unwrap();

        let snapshot = store.snapshot().unwrap();
        let received = script_utxos(
            &snapshot,
            profile,
            ScriptId::from_address(&address(8)),
            None,
            10,
        )
        .unwrap();
        assert_eq!(received.entries.len(), 1);
        assert_eq!(received.entries[0].coin.value, 40);
        assert_eq!(
            spending_transaction(&snapshot, profile, &previous)
                .unwrap()
                .unwrap()
                .txid,
            transaction.txid()
        );
        let spent_history = script_history(
            &snapshot,
            profile,
            ScriptId::from_address(&address(7)),
            None,
            10,
        )
        .unwrap();
        assert_eq!(spent_history.entries.len(), 1);
        assert!(spent_history.entries[0].direction.spent);
        drop(snapshot);

        let snapshot = store.snapshot().unwrap();
        let mut disconnect = store.batch();
        stage_disconnect(
            &snapshot,
            &mut disconnect,
            &block,
            &undo(&block, vec![previous_coin.clone()]),
            profile,
        )
        .unwrap();
        drop(snapshot);
        store.commit(disconnect).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(script_utxos(
            &snapshot,
            profile,
            ScriptId::from_address(&address(8)),
            None,
            10,
        )
        .unwrap()
        .entries
        .is_empty());
        assert!(spending_transaction(&snapshot, profile, &previous)
            .unwrap()
            .is_none());
        assert!(script_history(
            &snapshot,
            profile,
            ScriptId::from_address(&address(7)),
            None,
            10,
        )
        .unwrap()
        .entries
        .is_empty());
        drop(snapshot);

        let snapshot = store.snapshot().unwrap();
        let mut reconnect = store.batch();
        stage_connect(&snapshot, &mut reconnect, &block, 9, profile).unwrap();
        drop(snapshot);
        store.commit(reconnect).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            spending_transaction(&snapshot, profile, &previous)
                .unwrap()
                .unwrap()
                .txid,
            transaction.txid()
        );
    }

    #[test]
    fn within_block_spends_consolidate_history_and_leave_no_utxo() {
        let first = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(11, 25)],
            locktime: 0,
        };
        let second = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: first.txid(),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(12, 20)],
            locktime: 0,
        };
        let block = block(vec![first, second]);
        let store = MemoryStore::new();
        let snapshot = store.snapshot().unwrap();
        let mut batch = store.batch();
        let profile = WalletIndexProfile {
            wallet: true,
            ..WalletIndexProfile::default()
        };
        stage_connect(&snapshot, &mut batch, &block, 3, profile).unwrap();
        drop(snapshot);
        store.commit(batch).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(script_utxos(
            &snapshot,
            profile,
            ScriptId::from_address(&address(11)),
            None,
            10,
        )
        .unwrap()
        .entries
        .is_empty());
        let history = script_history(
            &snapshot,
            profile,
            ScriptId::from_address(&address(11)),
            None,
            10,
        )
        .unwrap();
        assert_eq!(history.entries.len(), 2);
        assert!(history.entries[0].direction.received);
        assert!(history.entries[1].direction.spent);
    }

    #[test]
    fn transfer_recipient_never_changes_ordinary_script_ownership() {
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![transfer_output(7, 9, 50)],
            locktime: 0,
        };
        let block = block(vec![transaction]);
        let store = MemoryStore::new();
        let profile = WalletIndexProfile {
            wallet: true,
            ..WalletIndexProfile::default()
        };
        let snapshot = store.snapshot().unwrap();
        let mut batch = store.batch();
        stage_connect(&snapshot, &mut batch, &block, 8, profile).unwrap();
        drop(snapshot);
        store.commit(batch).unwrap();

        let snapshot = store.snapshot().unwrap();
        let owner = ScriptId::from_address(&address(7));
        let recipient = ScriptId::from_address(&address(9));
        assert_eq!(
            script_history(&snapshot, profile, owner, None, 10)
                .unwrap()
                .entries
                .len(),
            1
        );
        assert_eq!(
            script_utxos(&snapshot, profile, owner, None, 10)
                .unwrap()
                .entries
                .len(),
            1
        );
        assert!(script_history(&snapshot, profile, recipient, None, 10)
            .unwrap()
            .entries
            .is_empty());
        assert!(script_utxos(&snapshot, profile, recipient, None, 10)
            .unwrap()
            .entries
            .is_empty());
    }

    #[test]
    fn relocated_and_bit_corrupted_index_values_fail_closed() {
        let store = MemoryStore::new();
        let previous = Outpoint {
            txid: Txid::new([41; 32]),
            index: 2,
        };
        let previous_coin = Coin {
            outpoint: previous.clone(),
            value: 50,
            height: 2,
            coinbase: false,
            address: address(7),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let mut seed = store.batch();
        write_coin_to_batch(&mut seed, &previous_coin).unwrap();
        store.commit(seed).unwrap();

        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: previous.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(8, 40)],
            locktime: 0,
        };
        let block = block(vec![transaction.clone()]);
        let profile = WalletIndexProfile {
            wallet: true,
            ..WalletIndexProfile::default()
        };
        let snapshot = store.snapshot().unwrap();
        let mut connect = store.batch();
        stage_connect(&snapshot, &mut connect, &block, 9, profile).unwrap();
        drop(snapshot);
        store.commit(connect).unwrap();

        let txid = transaction.txid();
        let history_entry = ScriptHistoryEntry {
            txid,
            block_hash: block.hash(),
            height: 9,
            transaction_position: 0,
            direction: ScriptHistoryDirection {
                received: false,
                spent: true,
            },
        };
        let received_outpoint = Outpoint { txid, index: 0 };
        let other_outpoint = Outpoint {
            txid: Txid::new([42; 32]),
            index: 7,
        };
        let source_history_key = history_key(ScriptId::from_address(&address(7)), &history_entry);
        let source_utxo_key = utxo_key(ScriptId::from_address(&address(8)), &received_outpoint);
        let source_spender_key = spender_key(&previous);
        let snapshot = store.snapshot().unwrap();
        let history_value = snapshot
            .get(ColumnFamily::TxIndex, &source_history_key)
            .unwrap()
            .unwrap();
        let utxo_value = snapshot
            .get(ColumnFamily::TxIndex, &source_utxo_key)
            .unwrap()
            .unwrap();
        let spender_value = snapshot
            .get(ColumnFamily::TxIndex, &source_spender_key)
            .unwrap()
            .unwrap();
        drop(snapshot);

        let relocated_script = ScriptId::from_address(&address(99));
        let mut corrupted_utxo_value = utxo_value.clone();
        *corrupted_utxo_value
            .get_mut(5)
            .expect("encoded UTXO has a checksummed body") ^= 1;
        let mut relocate = store.batch();
        relocate
            .put(
                ColumnFamily::TxIndex,
                &history_key(relocated_script, &history_entry),
                &history_value,
            )
            .unwrap();
        relocate
            .put(
                ColumnFamily::TxIndex,
                &utxo_key(relocated_script, &received_outpoint),
                &utxo_value,
            )
            .unwrap();
        relocate
            .put(
                ColumnFamily::TxIndex,
                &spender_key(&other_outpoint),
                &spender_value,
            )
            .unwrap();
        relocate
            .put(
                ColumnFamily::TxIndex,
                &source_utxo_key,
                &corrupted_utxo_value,
            )
            .unwrap();
        store.commit(relocate).unwrap();

        let snapshot = store.snapshot().unwrap();
        assert!(matches!(
            script_history(&snapshot, profile, relocated_script, None, 10),
            Err(IndexError::Corrupt(_))
        ));
        assert!(matches!(
            script_utxos(&snapshot, profile, relocated_script, None, 10),
            Err(IndexError::Corrupt(_))
        ));
        assert!(matches!(
            spending_transaction(&snapshot, profile, &other_outpoint),
            Err(IndexError::Corrupt(_))
        ));
        assert!(matches!(
            script_utxos(
                &snapshot,
                profile,
                ScriptId::from_address(&address(8)),
                None,
                10,
            ),
            Err(IndexError::Corrupt(_))
        ));
    }
}
