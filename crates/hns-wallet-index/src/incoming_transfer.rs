//! Confirmed, active TRANSFER-recipient ownership hints.
//!
//! A Handshake TRANSFER output remains locked to the old owner's address. The
//! future recipient exists only in the covenant, so it must not be mixed into
//! ordinary script history, script UTXOs, spenders, or balances. This module
//! maintains a separate active-recipient namespace and retains compact source
//! inclusion metadata while raw block bodies may be pruned.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use hns_consensus::{MAX_BLOCK_RENEWALS, MAX_BLOCK_UPDATES};
use hns_covenants::{Covenant as CanonicalCovenant, TransferCovenant};
use hns_primitives::{
    blake2b_256, Block, BlockHash, Coin, Covenant, CovenantKind, Height, Outpoint, Reader, Txid,
    Writer, MAX_TX_SIZE, MIN_ADDRESS_HASH_SIZE,
};
use hns_state::{decode_coin, encode_coin, encode_outpoint_key, BlockUndo};
use hns_store::{ColumnFamily, PrefixScanBudget, ReadSnapshot, WriteBatch};
use serde::{Deserialize, Serialize};

use super::{
    bound_checksum, validate_limit, IndexError, ScriptId, WalletIndexProfile, MAX_QUERY_BYTES,
};

const ACTIVE_PREFIX: &[u8] = b"wallet-index/v1/name-transfer/active/";
const EVIDENCE_PREFIX: &[u8] = b"wallet-index/v1/name-transfer/evidence/";
const EVIDENCE_STATE_PREFIX: &[u8] = b"wallet-index/v1/name-transfer/evidence-state/";
const UNDO_PREFIX: &[u8] = b"wallet-index/v1/name-transfer/undo/";

const ACTIVE_VALUE_VERSION: u8 = 1;
const EVIDENCE_VALUE_VERSION: u8 = 1;
const EVIDENCE_STATE_VERSION: u8 = 1;
const UNDO_VALUE_VERSION: u8 = 1;
const CHECKSUM_BYTES: usize = 32;

const ACTIVE_KEY_BYTES: usize = ACTIVE_PREFIX.len() + 32 + 4 + 4 + 32 + 4;
const MAX_ACTIVE_VALUE_BYTES: usize = 4 * 1024;
const EVIDENCE_VALUE_BYTES: usize = 1 + 32 + 4 + 4 + 4 + CHECKSUM_BYTES;
const MIN_COMPACT_OUTPUT_BYTES: usize = 8 + 1 + 1 + MIN_ADDRESS_HASH_SIZE + 1 + 1;
const MAX_EVIDENCE_SOURCE_OUTPUTS: usize = MAX_TX_SIZE / MIN_COMPACT_OUTPUT_BYTES;
const MAX_EVIDENCE_OUTPUTS: usize = MAX_BLOCK_UPDATES as usize;
const MAX_EVIDENCE_STATE_BYTES: usize = 1 + 1 + 32 + 4 + MAX_EVIDENCE_OUTPUTS * 4 + 32;
const MAX_TRANSFER_EFFECTS_PER_BLOCK_U32: u32 =
    match MAX_BLOCK_UPDATES.checked_add(MAX_BLOCK_RENEWALS) {
        Some(bound) => bound,
        None => panic!("Handshake TRANSFER effect bounds overflow u32"),
    };
const MAX_TRANSFER_EFFECTS_PER_BLOCK: usize = MAX_TRANSFER_EFFECTS_PER_BLOCK_U32 as usize;
const UNDO_VALUE_BYTES: usize = 1 + 32 + 4 + 4 + 32 + 4 + 32 + CHECKSUM_BYTES;

/// One active confirmed TRANSFER addressed to a covenant recipient.
///
/// This is ownership evidence only. It is deliberately not a script-history
/// row or wallet coin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IncomingTransferEntry {
    /// Covenant recipient witness version.
    pub recipient_version: u8,
    /// Covenant recipient witness program.
    pub recipient_hash: Vec<u8>,
    /// Name hash committed by the TRANSFER.
    pub name_hash: [u8; 32],
    /// Original name auction start height.
    pub start_height: Height,
    /// Exact active TRANSFER coin, still addressed to the old owner.
    pub coin: Coin,
    /// Active-chain inclusion block for the source transaction.
    pub block_hash: BlockHash,
    /// Active-chain inclusion height.
    pub height: Height,
    /// Zero-based transaction position in the inclusion block.
    pub transaction_position: u32,
}

impl IncomingTransferEntry {
    fn recipient_id(&self) -> Result<ScriptId, IndexError> {
        recipient_id(self.recipient_version, &self.recipient_hash)
    }

    fn key(&self) -> Result<Vec<u8>, IndexError> {
        Ok(active_key(self.recipient_id()?, self))
    }

    fn encode(&self) -> Result<Vec<u8>, IndexError> {
        self.validate_transfer_fields()?;
        let key = self.key()?;
        let coin = encode_coin(&self.coin);
        let mut writer = Writer::with_capacity(256 + coin.len());
        writer.write_u8(ACTIVE_VALUE_VERSION);
        writer.write_u8(self.recipient_version);
        writer.write_varbytes(&self.recipient_hash);
        writer.write_bytes(&self.name_hash);
        writer.write_u32(self.start_height);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_u32(self.transaction_position);
        writer.write_varbytes(&coin);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-active-v1",
            &key,
            &raw,
        ));
        if raw.len() > MAX_ACTIVE_VALUE_BYTES {
            return Err(IndexError::TransferCapacity(
                "incoming TRANSFER active value exceeds its hard bound",
            ));
        }
        Ok(raw)
    }

    fn decode(key: &[u8], raw: &[u8]) -> Result<Self, IndexError> {
        let body = checked_body(
            b"hns-wallet-index-incoming-transfer-active-v1",
            key,
            raw,
            MAX_ACTIVE_VALUE_BYTES,
            "invalid incoming TRANSFER active value",
        )?;
        let mut reader = Reader::new(body, MAX_ACTIVE_VALUE_BYTES)
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER active value"))?;
        if reader
            .read_u8()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER active value"))?
            != ACTIVE_VALUE_VERSION
        {
            return Err(IndexError::Corrupt(
                "unsupported incoming TRANSFER active value version",
            ));
        }
        let recipient_version = reader
            .read_u8()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER recipient version"))?;
        let recipient_hash = reader
            .read_varbytes(40, "incoming TRANSFER recipient hash")
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER recipient hash"))?;
        let name_hash = reader
            .read_hash()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER name hash"))?;
        let start_height = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER start height"))?;
        let block_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER block hash"))?,
        );
        let height = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER height"))?;
        let transaction_position = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER transaction position"))?;
        let coin = decode_coin(
            &reader
                .read_varbytes(MAX_TX_SIZE + 256, "incoming TRANSFER coin")
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER coin"))?,
        )
        .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER coin"))?;
        reader
            .ensure_finished()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER active value"))?;
        let entry = Self {
            recipient_version,
            recipient_hash,
            name_hash,
            start_height,
            coin,
            block_hash,
            height,
            transaction_position,
        };
        entry
            .validate_transfer_fields()
            .map_err(|error| match error {
                IndexError::InvalidTransferCovenant => {
                    IndexError::Corrupt("invalid incoming TRANSFER active covenant")
                }
                other => other,
            })?;
        if key.len() != ACTIVE_KEY_BYTES || key != entry.key()? {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER active key/value binding mismatch",
            ));
        }
        Ok(entry)
    }

    fn validate_transfer_fields(&self) -> Result<(), IndexError> {
        if self.coin.height != self.height {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER coin height mismatch",
            ));
        }
        let transfer = decode_transfer(&self.coin.covenant)?.ok_or(IndexError::Corrupt(
            "incoming TRANSFER entry does not contain a TRANSFER coin",
        ))?;
        if transfer.recipient_version != self.recipient_version
            || transfer.recipient_hash != self.recipient_hash
            || transfer.name_hash != self.name_hash
            || transfer.start_height != self.start_height
        {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER covenant/value binding mismatch",
            ));
        }
        Ok(())
    }

    fn validate_evidence(&self, evidence: &TransferEvidence) -> Result<(), IndexError> {
        self.validate_transfer_fields()?;
        if evidence.txid != self.coin.outpoint.txid
            || evidence.block_hash != self.block_hash
            || evidence.height != self.height
            || evidence.transaction_position != self.transaction_position
        {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER active/evidence inclusion mismatch",
            ));
        }
        if self.coin.outpoint.index >= evidence.output_count {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER output is outside source transaction bounds",
            ));
        }
        if self.coin.coinbase != (self.transaction_position == 0) {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER coinbase/inclusion mismatch",
            ));
        }
        Ok(())
    }
}

/// Exclusive cursor for active incoming TRANSFER ordering.
///
/// The four fields encode the complete suffix of the 113-byte active-row key;
/// callers do not need to have received the referenced row for the cursor to
/// be a valid exclusive seek hint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingTransferCursor {
    /// Last returned (or caller-selected) active-chain height.
    pub height: Height,
    /// Last returned (or caller-selected) transaction position.
    pub transaction_position: u32,
    /// Last returned (or caller-selected) source transaction ID.
    pub txid: Txid,
    /// Last returned (or caller-selected) source output position.
    pub output_index: u32,
}

/// One verified active incoming TRANSFER projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IncomingTransferRecord {
    /// Exact active-row data, including the canonical active UTXO coin.
    pub entry: IncomingTransferEntry,
    /// Total outputs in the source transaction, retained with its evidence.
    pub source_output_count: u32,
}

/// One bounded page of verified active incoming TRANSFER projections.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IncomingTransferPage {
    /// Active incoming TRANSFERs in height/transaction/output key order.
    pub entries: Vec<IncomingTransferRecord>,
    /// Exclusive continuation when another page may exist.
    pub continuation: Option<IncomingTransferCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferFields {
    name_hash: [u8; 32],
    start_height: Height,
    recipient_version: u8,
    recipient_hash: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferEvidence {
    txid: Txid,
    block_hash: BlockHash,
    height: Height,
    transaction_position: u32,
    output_count: u32,
}

impl TransferEvidence {
    fn encode(&self) -> Result<Vec<u8>, IndexError> {
        if !evidence_source_output_count_is_valid(self.output_count) {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER evidence source output count is outside its hard bound",
            ));
        }
        let key = evidence_key(self.txid);
        let mut writer = Writer::with_capacity(EVIDENCE_VALUE_BYTES);
        writer.write_u8(EVIDENCE_VALUE_VERSION);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_u32(self.transaction_position);
        writer.write_u32(self.output_count);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-evidence-v1",
            &key,
            &raw,
        ));
        if raw.len() != EVIDENCE_VALUE_BYTES {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER evidence has an invalid encoded size",
            ));
        }
        Ok(raw)
    }

    fn decode(txid: Txid, raw: &[u8]) -> Result<Self, IndexError> {
        let key = evidence_key(txid);
        let body = checked_body(
            b"hns-wallet-index-incoming-transfer-evidence-v1",
            &key,
            raw,
            EVIDENCE_VALUE_BYTES,
            "invalid incoming TRANSFER evidence",
        )?;
        if raw.len() != EVIDENCE_VALUE_BYTES {
            return Err(IndexError::Corrupt("invalid incoming TRANSFER evidence"));
        }
        let mut reader = Reader::new(body, EVIDENCE_VALUE_BYTES)
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence"))?;
        if reader
            .read_u8()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence"))?
            != EVIDENCE_VALUE_VERSION
        {
            return Err(IndexError::Corrupt(
                "unsupported incoming TRANSFER evidence version",
            ));
        }
        let block_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence block"))?,
        );
        let height = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence height"))?;
        let transaction_position = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence position"))?;
        let output_count = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER output count"))?;
        reader
            .ensure_finished()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence"))?;
        if !evidence_source_output_count_is_valid(output_count) {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER evidence source output count is outside its hard bound",
            ));
        }
        Ok(Self {
            txid,
            block_hash,
            height,
            transaction_position,
            output_count,
        })
    }
}

fn evidence_source_output_count_is_valid(output_count: u32) -> bool {
    output_count != 0
        && usize::try_from(output_count).is_ok_and(|count| count <= MAX_EVIDENCE_SOURCE_OUTPUTS)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EvidenceState {
    active_outputs: BTreeSet<u32>,
    retired_by: Option<BlockHash>,
}

impl EvidenceState {
    fn active(active_outputs: BTreeSet<u32>) -> Result<Self, IndexError> {
        if active_outputs.is_empty() || active_outputs.len() > MAX_EVIDENCE_OUTPUTS {
            return Err(IndexError::TransferCapacity(
                "incoming TRANSFER evidence output set is outside its hard bound",
            ));
        }
        Ok(Self {
            active_outputs,
            retired_by: None,
        })
    }

    fn encode(&self, txid: Txid) -> Result<Vec<u8>, IndexError> {
        self.validate_shape()?;
        let key = evidence_state_key(txid);
        let mut writer = Writer::with_capacity(72 + self.active_outputs.len() * 4);
        writer.write_u8(EVIDENCE_STATE_VERSION);
        writer.write_u8(u8::from(self.retired_by.is_some()));
        writer.write_bytes(self.retired_by.unwrap_or(BlockHash::ZERO).as_bytes());
        writer.write_u32(
            u32::try_from(self.active_outputs.len())
                .map_err(|_| IndexError::TransferCapacity("too many incoming TRANSFER outputs"))?,
        );
        for output in &self.active_outputs {
            writer.write_u32(*output);
        }
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-evidence-state-v1",
            &key,
            &raw,
        ));
        if raw.len() > MAX_EVIDENCE_STATE_BYTES {
            return Err(IndexError::TransferCapacity(
                "incoming TRANSFER evidence state exceeds its hard bound",
            ));
        }
        Ok(raw)
    }

    fn decode(txid: Txid, raw: &[u8]) -> Result<Self, IndexError> {
        let key = evidence_state_key(txid);
        let body = checked_body(
            b"hns-wallet-index-incoming-transfer-evidence-state-v1",
            &key,
            raw,
            MAX_EVIDENCE_STATE_BYTES,
            "invalid incoming TRANSFER evidence state",
        )?;
        let mut reader = Reader::new(body, MAX_EVIDENCE_STATE_BYTES)
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence state"))?;
        if reader
            .read_u8()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence state"))?
            != EVIDENCE_STATE_VERSION
        {
            return Err(IndexError::Corrupt(
                "unsupported incoming TRANSFER evidence-state version",
            ));
        }
        let retired = reader
            .read_u8()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER retirement flag"))?;
        if retired > 1 {
            return Err(IndexError::Corrupt(
                "invalid incoming TRANSFER retirement flag",
            ));
        }
        let retirement_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER retirement hash"))?,
        );
        if (retired == 0 && retirement_hash != BlockHash::ZERO)
            || (retired == 1 && retirement_hash == BlockHash::ZERO)
        {
            return Err(IndexError::Corrupt(
                "non-canonical incoming TRANSFER retirement hash",
            ));
        }
        let count = usize::try_from(
            reader
                .read_u32()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER output count"))?,
        )
        .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER output count"))?;
        if count > MAX_EVIDENCE_OUTPUTS || count > reader.remaining() / 4 {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER output count exceeds its hard bound",
            ));
        }
        let mut active_outputs = BTreeSet::new();
        let mut previous = None;
        for _ in 0..count {
            let output = reader
                .read_u32()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER output index"))?;
            if previous.is_some_and(|prior| prior >= output) || !active_outputs.insert(output) {
                return Err(IndexError::Corrupt(
                    "incoming TRANSFER output indices are not strictly sorted",
                ));
            }
            previous = Some(output);
        }
        reader
            .ensure_finished()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER evidence state"))?;
        let state = Self {
            active_outputs,
            retired_by: (retired == 1).then_some(retirement_hash),
        };
        state.validate_shape()?;
        Ok(state)
    }

    fn validate_shape(&self) -> Result<(), IndexError> {
        if self.active_outputs.len() > MAX_EVIDENCE_OUTPUTS
            || (self.active_outputs.is_empty() != self.retired_by.is_some())
            || self.retired_by.is_some_and(|hash| hash == BlockHash::ZERO)
        {
            return Err(IndexError::Corrupt(
                "invalid incoming TRANSFER evidence-state lifecycle",
            ));
        }
        Ok(())
    }

    fn validate_evidence(&self, evidence: &TransferEvidence) -> Result<(), IndexError> {
        self.validate_shape()?;
        for output_index in &self.active_outputs {
            if *output_index >= evidence.output_count {
                return Err(IndexError::Corrupt(
                    "incoming TRANSFER state references an output outside source bounds",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EffectCommitment {
    count: u32,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransferUndoMarker {
    block_hash: BlockHash,
    height: Height,
    created: EffectCommitment,
    spent: EffectCommitment,
}

impl TransferUndoMarker {
    fn encode(&self) -> Result<Vec<u8>, IndexError> {
        if !marker_effect_counts_are_valid(self.created.count, self.spent.count) {
            return Err(IndexError::TransferCapacity(
                "incoming TRANSFER marker effect count exceeds its consensus bound",
            ));
        }
        let key = undo_key(self.block_hash);
        let mut writer = Writer::with_capacity(UNDO_VALUE_BYTES);
        writer.write_u8(UNDO_VALUE_VERSION);
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_u32(self.height);
        writer.write_u32(self.created.count);
        writer.write_bytes(&self.created.digest);
        writer.write_u32(self.spent.count);
        writer.write_bytes(&self.spent.digest);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-undo-v1",
            &key,
            &raw,
        ));
        if raw.len() != UNDO_VALUE_BYTES {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER undo marker has an invalid encoded size",
            ));
        }
        Ok(raw)
    }

    fn decode(block_hash: BlockHash, raw: &[u8]) -> Result<Self, IndexError> {
        let key = undo_key(block_hash);
        let body = checked_body(
            b"hns-wallet-index-incoming-transfer-undo-v1",
            &key,
            raw,
            UNDO_VALUE_BYTES,
            "invalid incoming TRANSFER undo",
        )?;
        if raw.len() != UNDO_VALUE_BYTES {
            return Err(IndexError::Corrupt("invalid incoming TRANSFER undo"));
        }
        let mut reader = Reader::new(body, UNDO_VALUE_BYTES)
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER undo"))?;
        if reader
            .read_u8()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER undo"))?
            != UNDO_VALUE_VERSION
        {
            return Err(IndexError::Corrupt(
                "unsupported incoming TRANSFER undo version",
            ));
        }
        let encoded_hash = BlockHash::new(
            reader
                .read_hash()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER undo hash"))?,
        );
        if encoded_hash != block_hash {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER undo key/value binding mismatch",
            ));
        }
        let height = reader
            .read_u32()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER undo height"))?;
        let created = EffectCommitment {
            count: reader
                .read_u32()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER created count"))?,
            digest: reader
                .read_hash()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER created digest"))?,
        };
        let spent = EffectCommitment {
            count: reader
                .read_u32()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER spent count"))?,
            digest: reader
                .read_hash()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER spent digest"))?,
        };
        reader
            .ensure_finished()
            .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER undo"))?;
        if !marker_effect_counts_are_valid(created.count, spent.count) {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER marker effect count exceeds its consensus bound",
            ));
        }
        let mut empty = Vec::new();
        if created.count == 0
            && created
                != effect_commitment(
                    b"hns-wallet-index-incoming-transfer-created-v1",
                    block_hash,
                    height,
                    &mut empty,
                )?
        {
            return Err(IndexError::Corrupt(
                "non-canonical empty incoming TRANSFER created commitment",
            ));
        }
        if spent.count == 0
            && spent
                != effect_commitment(
                    b"hns-wallet-index-incoming-transfer-spent-v1",
                    block_hash,
                    height,
                    &mut empty,
                )?
        {
            return Err(IndexError::Corrupt(
                "non-canonical empty incoming TRANSFER spent commitment",
            ));
        }
        Ok(Self {
            block_hash,
            height,
            created,
            spent,
        })
    }
}

fn marker_effect_counts_are_valid(created: u32, spent: u32) -> bool {
    created <= MAX_BLOCK_UPDATES
        && spent <= MAX_TRANSFER_EFFECTS_PER_BLOCK_U32
        && created
            .checked_add(spent)
            .is_some_and(|count| count <= MAX_TRANSFER_EFFECTS_PER_BLOCK_U32)
}

#[derive(Clone)]
struct CreatedTransactionPlan {
    evidence: TransferEvidence,
    entries: Vec<(IncomingTransferEntry, Vec<u8>, Vec<u8>)>,
}

struct ExistingTransactionDelta {
    evidence: TransferEvidence,
    state: EvidenceState,
}

/// Read one bounded page of active, confirmed TRANSFERs for a covenant
/// recipient.
///
/// Every returned row is re-bound to its retained source evidence, evidence
/// state, and the byte-exact active UTXO record. The derivative index therefore
/// fails closed instead of returning a partially corrupted projection.
pub fn incoming_transfers<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    recipient: ScriptId,
    cursor: Option<&IncomingTransferCursor>,
    limit: usize,
) -> Result<IncomingTransferPage, IndexError> {
    if !profile.wallet {
        return Err(IndexError::Disabled("wallet/incoming-transfer"));
    }
    validate_limit(limit)?;

    let prefix = active_prefix(recipient);
    let start_after = cursor.map(|cursor| active_cursor_key(recipient, cursor));
    let page = snapshot.scan_prefix_page(
        ColumnFamily::TxIndex,
        &prefix,
        start_after.as_deref(),
        PrefixScanBudget {
            max_entries: limit,
            max_bytes: MAX_QUERY_BYTES,
        },
    )?;

    let mut entries = Vec::with_capacity(page.entries.len());
    let mut cached_evidence = None::<(Txid, TransferEvidence, EvidenceState)>;
    for (key, raw) in &page.entries {
        let entry = IncomingTransferEntry::decode(key, raw)?;
        let txid = entry.coin.outpoint.txid;
        if cached_evidence
            .as_ref()
            .is_none_or(|(cached_txid, _, _)| *cached_txid != txid)
        {
            let evidence = load_evidence(snapshot, txid)?.ok_or(IndexError::Corrupt(
                "active incoming TRANSFER is missing source evidence",
            ))?;
            let state = load_evidence_state(snapshot, txid)?.ok_or(IndexError::Corrupt(
                "active incoming TRANSFER is missing evidence state",
            ))?;
            state.validate_evidence(&evidence)?;
            if state.retired_by.is_some() {
                return Err(IndexError::Corrupt(
                    "active incoming TRANSFER uses retired evidence",
                ));
            }
            cached_evidence = Some((txid, evidence, state));
        }

        let (_, evidence, state) = cached_evidence
            .as_ref()
            .expect("incoming TRANSFER evidence cache was populated");
        entry.validate_evidence(evidence)?;
        if !state.active_outputs.contains(&entry.coin.outpoint.index) {
            return Err(IndexError::Corrupt(
                "active incoming TRANSFER is absent from evidence state",
            ));
        }

        let utxo_key = encode_outpoint_key(&entry.coin.outpoint);
        let stored_coin =
            snapshot
                .get(ColumnFamily::Utxo, &utxo_key)?
                .ok_or(IndexError::Corrupt(
                    "active incoming TRANSFER coin is missing from active UTXO set",
                ))?;
        if stored_coin != encode_coin(&entry.coin) {
            return Err(IndexError::Corrupt(
                "active incoming TRANSFER coin disagrees with active UTXO set",
            ));
        }

        entries.push(IncomingTransferRecord {
            entry,
            source_output_count: evidence.output_count,
        });
    }

    let continuation = page
        .continuation
        .as_deref()
        .map(|key| decode_active_cursor(recipient, key))
        .transpose()?;
    Ok(IncomingTransferPage {
        entries,
        continuation,
    })
}

/// Stage the incoming-TRANSFER derivative index for one block connection.
pub(super) fn stage_connect<B: WriteBatch, S: ReadSnapshot>(
    snapshot: &S,
    batch: &mut B,
    block: &Block,
    height: Height,
) -> Result<(), IndexError> {
    let block_hash = block.hash();
    if snapshot
        .get(ColumnFamily::TxIndex, &undo_key(block_hash))?
        .is_some()
    {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER undo already exists for connecting block",
        ));
    }

    let (created_outpoints, created_plans) = created_live_plans(block, height)?;
    let mut existing = BTreeMap::<Txid, ExistingTransactionDelta>::new();
    let mut spent_outpoints = HashSet::<Outpoint>::new();
    let mut spent_effects = Vec::new();

    for transaction in &block.transactions {
        for input in &transaction.inputs {
            if input.previous_output.is_null() || created_outpoints.contains(&input.previous_output)
            {
                continue;
            }
            let coin = load_coin(snapshot, &input.previous_output)?
                .ok_or_else(|| IndexError::MissingInputCoin(input.previous_output.clone()))?;
            let Some(transfer) = decode_transfer(&coin.covenant)? else {
                continue;
            };
            if !spent_outpoints.insert(input.previous_output.clone()) {
                return Err(IndexError::Corrupt(
                    "incoming TRANSFER output is spent more than once in one block",
                ));
            }
            let txid = coin.outpoint.txid;
            let delta = match existing.entry(txid) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let evidence = load_evidence(snapshot, txid)?.ok_or(IndexError::Corrupt(
                        "active incoming TRANSFER is missing source evidence",
                    ))?;
                    let state = load_evidence_state(snapshot, txid)?.ok_or(IndexError::Corrupt(
                        "active incoming TRANSFER is missing evidence state",
                    ))?;
                    state.validate_evidence(&evidence)?;
                    if state.retired_by.is_some() {
                        return Err(IndexError::Corrupt(
                            "active incoming TRANSFER uses retired evidence",
                        ));
                    }
                    entry.insert(ExistingTransactionDelta { evidence, state })
                }
            };
            let entry = entry_from_coin(&coin, &transfer, &delta.evidence);
            entry.validate_evidence(&delta.evidence)?;
            let key = entry.key()?;
            let value = snapshot
                .get(ColumnFamily::TxIndex, &key)?
                .ok_or(IndexError::Corrupt(
                    "active incoming TRANSFER row is missing",
                ))?;
            if IncomingTransferEntry::decode(&key, &value)? != entry {
                return Err(IndexError::Corrupt(
                    "active incoming TRANSFER row disagrees with spent coin",
                ));
            }
            if !delta.state.active_outputs.remove(&coin.outpoint.index) {
                return Err(IndexError::Corrupt(
                    "spent incoming TRANSFER is absent from evidence state",
                ));
            }
            spent_effects.push((key.clone(), value));
            batch.delete(ColumnFamily::TxIndex, &key)?;
        }
    }

    let mut created_effects = Vec::new();
    for (txid, plan) in &created_plans {
        if load_evidence(snapshot, *txid)?.is_some()
            || load_evidence_state(snapshot, *txid)?.is_some()
        {
            return Err(IndexError::Corrupt(
                "new incoming TRANSFER txid collides with retained evidence",
            ));
        }
        let mut outputs = BTreeSet::new();
        for (entry, key, value) in &plan.entries {
            entry.validate_evidence(&plan.evidence)?;
            if snapshot.get(ColumnFamily::TxIndex, key)?.is_some() {
                return Err(IndexError::Corrupt(
                    "new incoming TRANSFER active row already exists",
                ));
            }
            if !outputs.insert(entry.coin.outpoint.index) {
                return Err(IndexError::Corrupt(
                    "duplicate new incoming TRANSFER output",
                ));
            }
            created_effects.push((key.clone(), value.clone()));
        }
        batch.put(
            ColumnFamily::TxIndex,
            &evidence_key(*txid),
            &plan.evidence.encode()?,
        )?;
        batch.put(
            ColumnFamily::TxIndex,
            &evidence_state_key(*txid),
            &EvidenceState::active(outputs)?.encode(*txid)?,
        )?;
        for (_, key, value) in &plan.entries {
            batch.put(ColumnFamily::TxIndex, key, value)?;
        }
    }

    for (txid, mut delta) in existing {
        delta.state.retired_by = delta.state.active_outputs.is_empty().then_some(block_hash);
        delta.state.validate_evidence(&delta.evidence)?;
        batch.put(
            ColumnFamily::TxIndex,
            &evidence_state_key(txid),
            &delta.state.encode(txid)?,
        )?;
    }

    // Every wallet-indexed block carries one fixed-size marker, including
    // blocks with no TRANSFER activity. Reversal is reconstructed from the
    // authenticated block, consensus undo, and compact source metadata.
    let undo = TransferUndoMarker {
        block_hash,
        height,
        created: effect_commitment(
            b"hns-wallet-index-incoming-transfer-created-v1",
            block_hash,
            height,
            &mut created_effects,
        )?,
        spent: effect_commitment(
            b"hns-wallet-index-incoming-transfer-spent-v1",
            block_hash,
            height,
            &mut spent_effects,
        )?,
    };
    batch.put(
        ColumnFamily::TxIndex,
        &undo_key(block_hash),
        &undo.encode()?,
    )?;
    Ok(())
}

/// Stage exact incoming-TRANSFER reversal for an active-tip disconnect.
pub(super) fn stage_disconnect<B: WriteBatch, S: ReadSnapshot>(
    snapshot: &S,
    batch: &mut B,
    block: &Block,
    undo: &BlockUndo,
) -> Result<(), IndexError> {
    let block_hash = block.hash();
    if undo.block_hash != block_hash {
        return Err(IndexError::Corrupt("incoming TRANSFER undo block mismatch"));
    }
    let (created_outpoints, created_plans) = created_live_plans(block, undo.height)?;
    let expected_spent = undo
        .spent_coins
        .iter()
        .filter(|coin| !created_outpoints.contains(&coin.outpoint))
        .filter_map(|coin| match decode_transfer(&coin.covenant) {
            Ok(Some(_)) => Some(Ok(coin.clone())),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let raw_undo = snapshot.get(ColumnFamily::TxIndex, &undo_key(block_hash))?;
    let transfer_undo = TransferUndoMarker::decode(
        block_hash,
        raw_undo
            .as_deref()
            .ok_or(IndexError::Corrupt("incoming TRANSFER undo is missing"))?,
    )?;
    if transfer_undo.height != undo.height {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER undo height mismatch",
        ));
    }
    let expected_created_count = created_plans
        .values()
        .map(|plan| plan.entries.len())
        .try_fold(0_usize, usize::checked_add)
        .ok_or(IndexError::TransferCapacity(
            "incoming TRANSFER created effect count overflow",
        ))?;
    if usize::try_from(transfer_undo.created.count).ok() != Some(expected_created_count)
        || usize::try_from(transfer_undo.spent.count).ok() != Some(expected_spent.len())
    {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER marker counts disagree with block and consensus undo",
        ));
    }
    let mut created_effects = created_plans
        .values()
        .flat_map(|plan| {
            plan.entries
                .iter()
                .map(|(_, key, value)| (key.clone(), value.clone()))
        })
        .collect::<Vec<_>>();
    if effect_commitment(
        b"hns-wallet-index-incoming-transfer-created-v1",
        block_hash,
        undo.height,
        &mut created_effects,
    )? != transfer_undo.created
    {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER created-effect commitment disagrees with block",
        ));
    }

    let created_txids = created_plans.keys().copied().collect::<BTreeSet<_>>();
    for (txid, plan) in created_plans {
        let evidence = load_evidence(snapshot, txid)?.ok_or(IndexError::Corrupt(
            "created incoming TRANSFER is missing evidence",
        ))?;
        if evidence != plan.evidence {
            return Err(IndexError::Corrupt(
                "created incoming TRANSFER evidence disagrees with block",
            ));
        }
        let state = load_evidence_state(snapshot, txid)?.ok_or(IndexError::Corrupt(
            "created incoming TRANSFER is missing evidence state",
        ))?;
        let expected_outputs = plan
            .entries
            .iter()
            .map(|(entry, _, _)| entry.coin.outpoint.index)
            .collect::<BTreeSet<_>>();
        if state.active_outputs != expected_outputs || state.retired_by.is_some() {
            return Err(IndexError::Corrupt(
                "created incoming TRANSFER evidence state disagrees with block",
            ));
        }
        for (_, key, value) in &plan.entries {
            if snapshot.get(ColumnFamily::TxIndex, key)?.as_deref() != Some(value) {
                return Err(IndexError::Corrupt(
                    "created incoming TRANSFER active row disagrees with undo",
                ));
            }
            batch.delete(ColumnFamily::TxIndex, key)?;
        }
        batch.delete(ColumnFamily::TxIndex, &evidence_state_key(txid))?;
        batch.delete(ColumnFamily::TxIndex, &evidence_key(txid))?;
    }

    let mut restore = BTreeMap::<
        Txid,
        (
            TransferEvidence,
            EvidenceState,
            Vec<(IncomingTransferEntry, Vec<u8>, Vec<u8>)>,
        ),
    >::new();
    for coin in expected_spent {
        let transfer = decode_transfer(&coin.covenant)?.ok_or(IndexError::Corrupt(
            "consensus undo TRANSFER classification changed during disconnect",
        ))?;
        let txid = coin.outpoint.txid;
        if created_txids.contains(&txid) {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER undo mixes created and pre-block txids",
            ));
        }
        let group = match restore.entry(txid) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let evidence = load_evidence(snapshot, txid)?.ok_or(IndexError::Corrupt(
                    "spent incoming TRANSFER is missing retained source evidence",
                ))?;
                let state = load_evidence_state(snapshot, txid)?.ok_or(IndexError::Corrupt(
                    "spent incoming TRANSFER is missing retained state",
                ))?;
                state.validate_evidence(&evidence)?;
                entry.insert((evidence, state, Vec::new()))
            }
        };
        let entry = entry_from_coin(&coin, &transfer, &group.0);
        entry.validate_evidence(&group.0)?;
        let key = entry.key()?;
        let value = entry.encode()?;
        group.2.push((entry, key, value));
    }
    let mut spent_effects = Vec::new();
    for (txid, (evidence, mut state, items)) in restore {
        if state.active_outputs.is_empty() {
            if state.retired_by != Some(block_hash) {
                return Err(IndexError::Corrupt(
                    "incoming TRANSFER retirement is bound to another block",
                ));
            }
        } else if state.retired_by.is_some() {
            return Err(IndexError::Corrupt(
                "live incoming TRANSFER evidence is marked retired",
            ));
        }
        for (entry, key, value) in items {
            if snapshot.get(ColumnFamily::TxIndex, &key)?.is_some()
                || !state.active_outputs.insert(entry.coin.outpoint.index)
            {
                return Err(IndexError::Corrupt(
                    "incoming TRANSFER disconnect would overwrite an active row",
                ));
            }
            spent_effects.push((key.clone(), value.clone()));
            batch.put(ColumnFamily::TxIndex, &key, &value)?;
        }
        state.retired_by = None;
        state.validate_evidence(&evidence)?;
        batch.put(
            ColumnFamily::TxIndex,
            &evidence_state_key(txid),
            &state.encode(txid)?,
        )?;
    }
    if effect_commitment(
        b"hns-wallet-index-incoming-transfer-spent-v1",
        block_hash,
        undo.height,
        &mut spent_effects,
    )? != transfer_undo.spent
    {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER spent-effect commitment disagrees with consensus undo",
        ));
    }
    batch.delete(ColumnFamily::TxIndex, &undo_key(block_hash))?;
    Ok(())
}

/// Retire transfer rollback data atomically with the corresponding consensus
/// undo. Source evidence is deleted only when this exact block retired the final
/// active output for its source transaction.
pub fn stage_prune_undo<B: WriteBatch, S: ReadSnapshot>(
    snapshot: &S,
    batch: &mut B,
    consensus_undo: &BlockUndo,
    require_marker: bool,
) -> Result<(), IndexError> {
    let block_hash = consensus_undo.block_hash;
    let key = undo_key(block_hash);
    let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? else {
        if require_marker {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER undo marker is missing for a wallet-indexed block",
            ));
        }
        return Ok(());
    };
    let marker = TransferUndoMarker::decode(block_hash, &raw)?;
    if marker.height != consensus_undo.height {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER prune undo height mismatch",
        ));
    }
    let expected_spent = consensus_undo
        .spent_coins
        .iter()
        .filter_map(|coin| match decode_transfer(&coin.covenant) {
            Ok(Some(_)) => Some(Ok(coin)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if usize::try_from(marker.spent.count).ok() != Some(expected_spent.len()) {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER prune count disagrees with consensus undo",
        ));
    }
    let mut evidence_by_txid = BTreeMap::<Txid, TransferEvidence>::new();
    let mut spent_outputs_by_txid = BTreeMap::<Txid, BTreeSet<u32>>::new();
    let mut spent_effects = Vec::new();
    for coin in expected_spent {
        let transfer = decode_transfer(&coin.covenant)?.ok_or(IndexError::Corrupt(
            "consensus undo TRANSFER classification changed during pruning",
        ))?;
        let txid = coin.outpoint.txid;
        if let std::collections::btree_map::Entry::Vacant(slot) = evidence_by_txid.entry(txid) {
            let evidence = load_evidence(snapshot, txid)?.ok_or(IndexError::Corrupt(
                "incoming TRANSFER prune marker is missing retained source evidence",
            ))?;
            slot.insert(evidence);
        }
        let evidence = evidence_by_txid.get(&txid).ok_or(IndexError::Corrupt(
            "incoming TRANSFER evidence disappeared during pruning",
        ))?;
        let entry = entry_from_coin(coin, &transfer, evidence);
        entry.validate_evidence(evidence)?;
        let key = entry.key()?;
        let value = entry.encode()?;
        if snapshot.get(ColumnFamily::TxIndex, &key)?.is_some() {
            return Err(IndexError::Corrupt(
                "spent incoming TRANSFER remains active at undo pruning",
            ));
        }
        spent_effects.push((key, value));
        if !spent_outputs_by_txid
            .entry(txid)
            .or_default()
            .insert(coin.outpoint.index)
        {
            return Err(IndexError::Corrupt(
                "incoming TRANSFER prune undo repeats a spent output",
            ));
        }
    }
    if effect_commitment(
        b"hns-wallet-index-incoming-transfer-spent-v1",
        block_hash,
        consensus_undo.height,
        &mut spent_effects,
    )? != marker.spent
    {
        return Err(IndexError::Corrupt(
            "incoming TRANSFER prune commitment disagrees with consensus undo",
        ));
    }
    for (txid, spent_outputs) in spent_outputs_by_txid {
        let evidence = evidence_by_txid
            .get(&txid)
            .ok_or(IndexError::Corrupt("incoming TRANSFER evidence is missing"))?;
        let state = load_evidence_state(snapshot, txid)?.ok_or(IndexError::Corrupt(
            "incoming TRANSFER undo is missing retained evidence state",
        ))?;
        state.validate_evidence(evidence)?;
        if !state.active_outputs.is_disjoint(&spent_outputs) {
            return Err(IndexError::Corrupt(
                "spent incoming TRANSFER remains in evidence state at undo pruning",
            ));
        }
        if state.active_outputs.is_empty() {
            if state.retired_by == Some(block_hash) {
                batch.delete(ColumnFamily::TxIndex, &evidence_state_key(txid))?;
                batch.delete(ColumnFamily::TxIndex, &evidence_key(txid))?;
            } else if state.retired_by.is_none() {
                return Err(IndexError::Corrupt(
                    "empty incoming TRANSFER evidence lacks a retirement block",
                ));
            }
        } else if state.retired_by.is_some() {
            return Err(IndexError::Corrupt(
                "live incoming TRANSFER evidence is marked retired",
            ));
        }
    }
    batch.delete(ColumnFamily::TxIndex, &key)?;
    Ok(())
}

fn created_live_plans(
    block: &Block,
    height: Height,
) -> Result<(HashSet<Outpoint>, BTreeMap<Txid, CreatedTransactionPlan>), IndexError> {
    let spent = block
        .transactions
        .iter()
        .flat_map(|transaction| &transaction.inputs)
        .filter(|input| !input.previous_output.is_null())
        .map(|input| input.previous_output.clone())
        .collect::<HashSet<_>>();
    let mut all_created = HashSet::new();
    let mut plans = BTreeMap::new();
    let block_hash = block.hash();
    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        let txid = transaction.txid();
        let output_count =
            u32::try_from(transaction.outputs.len()).map_err(|_| IndexError::PositionOverflow)?;
        let evidence = TransferEvidence {
            txid,
            block_hash,
            height,
            transaction_position,
            output_count,
        };
        let mut entries = Vec::new();
        for (output_position, output) in transaction.outputs.iter().enumerate() {
            let output_position =
                u32::try_from(output_position).map_err(|_| IndexError::PositionOverflow)?;
            let outpoint = Outpoint {
                txid,
                index: output_position,
            };
            if !all_created.insert(outpoint.clone()) {
                return Err(IndexError::Corrupt(
                    "block contains duplicate created outpoints",
                ));
            }
            let Some(transfer) = decode_transfer(&output.covenant)? else {
                continue;
            };
            if spent.contains(&outpoint) {
                continue;
            }
            let coin = Coin {
                outpoint,
                value: output.value,
                height,
                coinbase: transaction_position == 0,
                address: output.address.clone(),
                covenant: output.covenant.clone(),
            };
            let entry = entry_from_coin(&coin, &transfer, &evidence);
            let key = entry.key()?;
            let value = entry.encode()?;
            entries.push((entry, key, value));
        }
        if !entries.is_empty()
            && plans
                .insert(txid, CreatedTransactionPlan { evidence, entries })
                .is_some()
        {
            return Err(IndexError::Corrupt(
                "block contains duplicate transaction IDs",
            ));
        }
    }
    Ok((all_created, plans))
}

fn entry_from_coin(
    coin: &Coin,
    transfer: &TransferFields,
    evidence: &TransferEvidence,
) -> IncomingTransferEntry {
    IncomingTransferEntry {
        recipient_version: transfer.recipient_version,
        recipient_hash: transfer.recipient_hash.clone(),
        name_hash: transfer.name_hash,
        start_height: transfer.start_height,
        coin: coin.clone(),
        block_hash: evidence.block_hash,
        height: evidence.height,
        transaction_position: evidence.transaction_position,
    }
}

fn decode_transfer(covenant: &Covenant) -> Result<Option<TransferFields>, IndexError> {
    if covenant.kind != CovenantKind::Transfer {
        return Ok(None);
    }
    let canonical = CanonicalCovenant::decode(&covenant.encode())
        .map_err(|_| IndexError::InvalidTransferCovenant)?;
    let transfer =
        TransferCovenant::try_from(&canonical).map_err(|_| IndexError::InvalidTransferCovenant)?;
    Ok(Some(TransferFields {
        name_hash: transfer.name_hash.into_bytes(),
        start_height: transfer.start_height.get(),
        recipient_version: transfer.recipient_version,
        recipient_hash: transfer.recipient_hash,
    }))
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

fn load_evidence<S: ReadSnapshot>(
    snapshot: &S,
    txid: Txid,
) -> Result<Option<TransferEvidence>, IndexError> {
    snapshot
        .get(ColumnFamily::TxIndex, &evidence_key(txid))?
        .as_deref()
        .map(|raw| TransferEvidence::decode(txid, raw))
        .transpose()
}

fn load_evidence_state<S: ReadSnapshot>(
    snapshot: &S,
    txid: Txid,
) -> Result<Option<EvidenceState>, IndexError> {
    snapshot
        .get(ColumnFamily::TxIndex, &evidence_state_key(txid))?
        .as_deref()
        .map(|raw| EvidenceState::decode(txid, raw))
        .transpose()
}

fn recipient_id(version: u8, hash: &[u8]) -> Result<ScriptId, IndexError> {
    let hash_len = u8::try_from(hash.len()).map_err(|_| {
        IndexError::TransferCapacity("incoming TRANSFER recipient hash exceeds its hard bound")
    })?;
    let mut writer = Writer::with_capacity(2 + hash.len());
    writer.write_u8(version);
    writer.write_u8(hash_len);
    writer.write_bytes(hash);
    Ok(ScriptId::from_descriptor(&writer.finish()))
}

fn active_prefix(recipient: ScriptId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ACTIVE_PREFIX.len() + 32);
    key.extend_from_slice(ACTIVE_PREFIX);
    key.extend_from_slice(recipient.as_bytes());
    key
}

fn active_key(recipient: ScriptId, entry: &IncomingTransferEntry) -> Vec<u8> {
    let mut key = active_prefix(recipient);
    key.extend_from_slice(&entry.height.to_be_bytes());
    key.extend_from_slice(&entry.transaction_position.to_be_bytes());
    key.extend_from_slice(entry.coin.outpoint.txid.as_bytes());
    key.extend_from_slice(&entry.coin.outpoint.index.to_be_bytes());
    key
}

fn active_cursor_key(recipient: ScriptId, cursor: &IncomingTransferCursor) -> Vec<u8> {
    let mut key = active_prefix(recipient);
    key.extend_from_slice(&cursor.height.to_be_bytes());
    key.extend_from_slice(&cursor.transaction_position.to_be_bytes());
    key.extend_from_slice(cursor.txid.as_bytes());
    key.extend_from_slice(&cursor.output_index.to_be_bytes());
    key
}

fn decode_active_cursor(
    recipient: ScriptId,
    key: &[u8],
) -> Result<IncomingTransferCursor, IndexError> {
    let prefix = active_prefix(recipient);
    if key.len() != ACTIVE_KEY_BYTES || key.get(..prefix.len()) != Some(prefix.as_slice()) {
        return Err(IndexError::Corrupt(
            "invalid incoming TRANSFER continuation key",
        ));
    }
    let suffix = &key[prefix.len()..];
    let bytes = |offset: usize, length: usize| {
        suffix
            .get(offset..offset.saturating_add(length))
            .ok_or(IndexError::Corrupt(
                "invalid incoming TRANSFER continuation key",
            ))
    };
    Ok(IncomingTransferCursor {
        height: u32::from_be_bytes(
            bytes(0, 4)?
                .try_into()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER continuation key"))?,
        ),
        transaction_position: u32::from_be_bytes(
            bytes(4, 4)?
                .try_into()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER continuation key"))?,
        ),
        txid: Txid::new(
            bytes(8, 32)?
                .try_into()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER continuation key"))?,
        ),
        output_index: u32::from_be_bytes(
            bytes(40, 4)?
                .try_into()
                .map_err(|_| IndexError::Corrupt("invalid incoming TRANSFER continuation key"))?,
        ),
    })
}

fn evidence_key(txid: Txid) -> Vec<u8> {
    let mut key = Vec::with_capacity(EVIDENCE_PREFIX.len() + 32);
    key.extend_from_slice(EVIDENCE_PREFIX);
    key.extend_from_slice(txid.as_bytes());
    key
}

fn evidence_state_key(txid: Txid) -> Vec<u8> {
    let mut key = Vec::with_capacity(EVIDENCE_STATE_PREFIX.len() + 32);
    key.extend_from_slice(EVIDENCE_STATE_PREFIX);
    key.extend_from_slice(txid.as_bytes());
    key
}

fn undo_key(block_hash: BlockHash) -> Vec<u8> {
    let mut key = Vec::with_capacity(UNDO_PREFIX.len() + 32);
    key.extend_from_slice(UNDO_PREFIX);
    key.extend_from_slice(block_hash.as_bytes());
    key
}

fn checked_body<'a>(
    domain: &[u8],
    key: &[u8],
    raw: &'a [u8],
    maximum: usize,
    context: &'static str,
) -> Result<&'a [u8], IndexError> {
    if raw.len() <= CHECKSUM_BYTES || raw.len() > maximum {
        return Err(IndexError::Corrupt(context));
    }
    let body_len = raw.len() - CHECKSUM_BYTES;
    let (body, checksum) = raw.split_at(body_len);
    if checksum != bound_checksum(domain, key, body).as_slice() {
        return Err(IndexError::Corrupt(context));
    }
    Ok(body)
}

fn effect_commitment(
    domain: &[u8],
    block_hash: BlockHash,
    height: Height,
    effects: &mut [(Vec<u8>, Vec<u8>)],
) -> Result<EffectCommitment, IndexError> {
    if effects.len() > MAX_TRANSFER_EFFECTS_PER_BLOCK {
        return Err(IndexError::TransferCapacity(
            "incoming TRANSFER effect count exceeds its consensus bound",
        ));
    }
    effects.sort_by(|left, right| left.0.cmp(&right.0));
    if effects.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(IndexError::Corrupt(
            "duplicate incoming TRANSFER effect commitment key",
        ));
    }
    let count = u32::try_from(effects.len()).map_err(|_| {
        IndexError::TransferCapacity("too many incoming TRANSFER effect commitments")
    })?;
    let mut writer = Writer::new();
    writer.write_varbytes(domain);
    writer.write_bytes(block_hash.as_bytes());
    writer.write_u32(height);
    writer.write_u32(count);
    for (key, value) in effects {
        writer.write_varbytes(key);
        writer.write_varbytes(value);
    }
    Ok(EffectCommitment {
        count,
        digest: blake2b_256(&writer.finish()),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;
    use hns_primitives::{Address, Input, Output, Transaction, Witness, MAX_BLOCK_WEIGHT};
    use hns_state::{write_coin_to_batch, TreeRoot};
    use hns_store::{
        MemorySnapshot, MemoryStore, PrefixScanBudget, PrefixScanPage, ScanEntry, Store,
        StoreError, PREFIX_SCAN_MAX_ENTRIES,
    };

    fn address(byte: u8) -> Address {
        Address::new(0, vec![byte; 20]).expect("valid fixture address")
    }

    fn transfer_output(owner: u8, recipient: u8, name: u8, value: u64) -> Output {
        Output {
            value,
            address: address(owner),
            covenant: Covenant {
                kind: CovenantKind::Transfer,
                items: vec![
                    vec![name; 32],
                    2_u32.to_le_bytes().to_vec(),
                    vec![0],
                    vec![recipient; 20],
                ],
            },
        }
    }

    fn plain_output(owner: u8, value: u64) -> Output {
        Output {
            value,
            address: address(owner),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }
    }

    fn transaction(outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs,
            locktime: 0,
        }
    }

    fn block(transactions: Vec<Transaction>) -> Block {
        static NEXT_NONCE: AtomicU32 = AtomicU32::new(1);
        let header = hns_primitives::Header {
            nonce: NEXT_NONCE.fetch_add(1, Ordering::Relaxed),
            ..hns_primitives::Header::default()
        };
        Block {
            header,
            transactions,
        }
    }

    fn undo(block: &Block, height: Height, spent_coins: Vec<Coin>) -> BlockUndo {
        BlockUndo {
            block_hash: block.hash(),
            height,
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

    fn family_image(store: &MemoryStore) -> Vec<(Vec<u8>, Vec<u8>)> {
        let snapshot = store.snapshot().expect("snapshot");
        snapshot
            .scan_prefix_page(
                ColumnFamily::TxIndex,
                b"wallet-index/v1/name-transfer/",
                None,
                PrefixScanBudget {
                    max_entries: PREFIX_SCAN_MAX_ENTRIES,
                    max_bytes: MAX_BLOCK_WEIGHT * 8,
                },
            )
            .expect("scan incoming TRANSFER image")
            .entries
    }

    fn active_values(store: &MemoryStore, recipient: u8) -> Vec<Vec<u8>> {
        let id = recipient_id(0, &[recipient; 20]).expect("valid fixture recipient");
        let mut prefix = ACTIVE_PREFIX.to_vec();
        prefix.extend_from_slice(id.as_bytes());
        let snapshot = store.snapshot().expect("snapshot");
        snapshot
            .scan_prefix_page(
                ColumnFamily::TxIndex,
                &prefix,
                None,
                PrefixScanBudget {
                    max_entries: 32,
                    max_bytes: 64 * 1024,
                },
            )
            .expect("scan recipient")
            .entries
            .into_iter()
            .map(|(_, value)| value)
            .collect()
    }

    fn connect(store: &MemoryStore, block: &Block, height: Height) {
        let snapshot = store.snapshot().expect("snapshot");
        let mut batch = store.batch();
        stage_connect(&snapshot, &mut batch, block, height).expect("stage TRANSFER connect");
        drop(snapshot);
        store.commit(batch).expect("commit TRANSFER connect");
    }

    fn seed_block_coins(store: &MemoryStore, block: &Block, height: Height) -> Vec<Coin> {
        let mut coins = Vec::new();
        let mut batch = store.batch();
        for (transaction_position, transaction) in block.transactions.iter().enumerate() {
            for (output_index, output) in transaction.outputs.iter().enumerate() {
                let coin = Coin {
                    outpoint: Outpoint {
                        txid: transaction.txid(),
                        index: u32::try_from(output_index).expect("fixture output index"),
                    },
                    value: output.value,
                    height,
                    coinbase: transaction_position == 0,
                    address: output.address.clone(),
                    covenant: output.covenant.clone(),
                };
                write_coin_to_batch(&mut batch, &coin).expect("seed active coin");
                coins.push(coin);
            }
        }
        store.commit(batch).expect("commit active coins");
        coins
    }

    fn connect_with_coins(store: &MemoryStore, block: &Block, height: Height) -> Vec<Coin> {
        connect(store, block, height);
        seed_block_coins(store, block, height)
    }

    fn wallet_profile() -> WalletIndexProfile {
        WalletIndexProfile {
            script_history: false,
            spender: false,
            wallet: true,
        }
    }

    fn recipient_script(recipient: u8) -> ScriptId {
        recipient_id(0, &[recipient; 20]).expect("valid fixture recipient")
    }

    fn single_query_fixture() -> (MemoryStore, ScriptId, Txid, Outpoint, BlockHash) {
        let store = MemoryStore::new();
        let transaction = transaction(vec![transfer_output(7, 9, 3, 50), plain_output(8, 10)]);
        let txid = transaction.txid();
        let outpoint = Outpoint { txid, index: 0 };
        let source = block(vec![transaction]);
        let block_hash = source.hash();
        connect_with_coins(&store, &source, 8);
        (store, recipient_script(9), txid, outpoint, block_hash)
    }

    fn active_raw_unchecked(entry: &IncomingTransferEntry) -> Vec<u8> {
        let key = entry.key().expect("fixture active key");
        let coin = encode_coin(&entry.coin);
        let mut writer = Writer::with_capacity(256 + coin.len());
        writer.write_u8(ACTIVE_VALUE_VERSION);
        writer.write_u8(entry.recipient_version);
        writer.write_varbytes(&entry.recipient_hash);
        writer.write_bytes(&entry.name_hash);
        writer.write_u32(entry.start_height);
        writer.write_bytes(entry.block_hash.as_bytes());
        writer.write_u32(entry.height);
        writer.write_u32(entry.transaction_position);
        writer.write_varbytes(&coin);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-active-v1",
            &key,
            &raw,
        ));
        raw
    }

    struct CountingSnapshot {
        inner: MemorySnapshot,
        evidence_gets: Cell<usize>,
        evidence_state_gets: Cell<usize>,
        utxo_gets: Cell<usize>,
    }

    impl CountingSnapshot {
        fn new(inner: MemorySnapshot) -> Self {
            Self {
                inner,
                evidence_gets: Cell::new(0),
                evidence_state_gets: Cell::new(0),
                utxo_gets: Cell::new(0),
            }
        }
    }

    impl ReadSnapshot for CountingSnapshot {
        fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
            if family == ColumnFamily::TxIndex && key.starts_with(EVIDENCE_PREFIX) {
                self.evidence_gets.set(self.evidence_gets.get() + 1);
            } else if family == ColumnFamily::TxIndex && key.starts_with(EVIDENCE_STATE_PREFIX) {
                self.evidence_state_gets
                    .set(self.evidence_state_gets.get() + 1);
            } else if family == ColumnFamily::Utxo {
                self.utxo_gets.set(self.utxo_gets.get() + 1);
            }
            self.inner.get(family, key)
        }

        fn scan_prefix(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
        ) -> Result<Vec<ScanEntry>, StoreError> {
            self.inner.scan_prefix(family, prefix)
        }

        fn scan_prefix_page(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
            start_after: Option<&[u8]>,
            budget: PrefixScanBudget,
        ) -> Result<PrefixScanPage, StoreError> {
            self.inner
                .scan_prefix_page(family, prefix, start_after, budget)
        }
    }

    fn marker_raw_with_counts(
        marker: &TransferUndoMarker,
        created_count: u32,
        spent_count: u32,
    ) -> Vec<u8> {
        let key = undo_key(marker.block_hash);
        let mut writer = Writer::with_capacity(UNDO_VALUE_BYTES);
        writer.write_u8(UNDO_VALUE_VERSION);
        writer.write_bytes(marker.block_hash.as_bytes());
        writer.write_u32(marker.height);
        writer.write_u32(created_count);
        writer.write_bytes(&marker.created.digest);
        writer.write_u32(spent_count);
        writer.write_bytes(&marker.spent.digest);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-undo-v1",
            &key,
            &raw,
        ));
        raw
    }

    fn evidence_raw_with_output_count(evidence: &TransferEvidence, output_count: u32) -> Vec<u8> {
        let key = evidence_key(evidence.txid);
        let mut writer = Writer::with_capacity(EVIDENCE_VALUE_BYTES);
        writer.write_u8(EVIDENCE_VALUE_VERSION);
        writer.write_bytes(evidence.block_hash.as_bytes());
        writer.write_u32(evidence.height);
        writer.write_u32(evidence.transaction_position);
        writer.write_u32(output_count);
        let mut raw = writer.finish();
        raw.extend_from_slice(&bound_checksum(
            b"hns-wallet-index-incoming-transfer-evidence-v1",
            &key,
            &raw,
        ));
        raw
    }

    #[test]
    fn query_orders_pages_and_accepts_a_nonexistent_exclusive_hint() {
        let store = MemoryStore::new();
        let first = block(vec![transaction(vec![
            transfer_output(7, 9, 3, 50),
            transfer_output(7, 9, 4, 40),
        ])]);
        connect_with_coins(&store, &first, 8);
        let second = block(vec![transaction(vec![
            transfer_output(8, 9, 5, 30),
            plain_output(8, 20),
        ])]);
        connect_with_coins(&store, &second, 10);

        let recipient = recipient_script(9);
        let snapshot = store.snapshot().expect("snapshot");
        let first_page = incoming_transfers(&snapshot, wallet_profile(), recipient, None, 2)
            .expect("first query page");
        assert_eq!(first_page.entries.len(), 2);
        assert_eq!(
            first_page
                .entries
                .iter()
                .map(|record| (
                    record.entry.height,
                    record.entry.transaction_position,
                    record.entry.coin.outpoint.index,
                    record.source_output_count,
                ))
                .collect::<Vec<_>>(),
            vec![(8, 0, 0, 2), (8, 0, 1, 2)]
        );
        let continuation = first_page.continuation.expect("continuation");
        assert_eq!(continuation.height, 8);
        assert_eq!(continuation.transaction_position, 0);
        assert_eq!(continuation.output_index, 1);

        let second_page = incoming_transfers(
            &snapshot,
            wallet_profile(),
            recipient,
            Some(&continuation),
            2,
        )
        .expect("second query page");
        assert_eq!(second_page.entries.len(), 1);
        assert_eq!(second_page.entries[0].entry.height, 10);
        assert_eq!(second_page.entries[0].source_output_count, 2);
        assert!(second_page.continuation.is_none());

        let nonexistent_hint = IncomingTransferCursor {
            height: 9,
            transaction_position: 0,
            txid: Txid::ZERO,
            output_index: 0,
        };
        let hinted = incoming_transfers(
            &snapshot,
            wallet_profile(),
            recipient,
            Some(&nonexistent_hint),
            2,
        )
        .expect("query from arbitrary exclusive hint");
        assert_eq!(hinted.entries.len(), 1);
        assert_eq!(hinted.entries[0].entry.height, 10);
    }

    #[test]
    fn query_enforces_wallet_profile_and_public_page_bounds() {
        let store = MemoryStore::new();
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(
                &snapshot,
                WalletIndexProfile::default(),
                recipient_script(9),
                None,
                1,
            ),
            Err(IndexError::Disabled("wallet/incoming-transfer"))
        ));
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient_script(9), None, 0),
            Err(IndexError::InvalidLimit)
        ));
        assert!(matches!(
            incoming_transfers(
                &snapshot,
                wallet_profile(),
                recipient_script(9),
                None,
                super::super::MAX_QUERY_ENTRIES + 1,
            ),
            Err(IndexError::InvalidLimit)
        ));
    }

    #[test]
    fn active_cursor_is_the_exact_strict_recipient_bound_key() {
        let recipient = recipient_script(9);
        let cursor = IncomingTransferCursor {
            height: 17,
            transaction_position: 3,
            txid: Txid::new([7; 32]),
            output_index: 5,
        };
        let key = active_cursor_key(recipient, &cursor);
        assert_eq!(key.len(), ACTIVE_KEY_BYTES);
        assert_eq!(ACTIVE_KEY_BYTES, 113);
        assert_eq!(
            decode_active_cursor(recipient, &key).expect("cursor round trip"),
            cursor
        );
        assert!(matches!(
            decode_active_cursor(recipient_script(10), &key),
            Err(IndexError::Corrupt(
                "invalid incoming TRANSFER continuation key"
            ))
        ));
        assert!(matches!(
            decode_active_cursor(recipient, &key[..key.len() - 1]),
            Err(IndexError::Corrupt(
                "invalid incoming TRANSFER continuation key"
            ))
        ));
    }

    #[test]
    fn query_rejects_active_checksum_and_normalizes_durable_covenant_corruption() {
        let (store, recipient, _, _, _) = single_query_fixture();
        let snapshot = store.snapshot().expect("snapshot");
        let (key, mut raw) = snapshot
            .scan_prefix_page(
                ColumnFamily::TxIndex,
                &active_prefix(recipient),
                None,
                PrefixScanBudget {
                    max_entries: 1,
                    max_bytes: MAX_QUERY_BYTES,
                },
            )
            .expect("active row")
            .entries
            .into_iter()
            .next()
            .expect("active row present");
        drop(snapshot);
        raw[1] ^= 1;
        let mut corrupt = store.batch();
        corrupt
            .put(ColumnFamily::TxIndex, &key, &raw)
            .expect("replace active row");
        store.commit(corrupt).expect("commit checksum corruption");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "invalid incoming TRANSFER active value"
            ))
        ));

        let (store, recipient, _, _, _) = single_query_fixture();
        let snapshot = store.snapshot().expect("snapshot");
        let (key, raw) = snapshot
            .scan_prefix_page(
                ColumnFamily::TxIndex,
                &active_prefix(recipient),
                None,
                PrefixScanBudget {
                    max_entries: 1,
                    max_bytes: MAX_QUERY_BYTES,
                },
            )
            .expect("active row")
            .entries
            .into_iter()
            .next()
            .expect("active row present");
        let mut entry = IncomingTransferEntry::decode(&key, &raw).expect("valid active row");
        drop(snapshot);
        entry.coin.covenant.items.pop();
        let malformed = active_raw_unchecked(&entry);
        let mut corrupt = store.batch();
        corrupt
            .put(ColumnFamily::TxIndex, &key, &malformed)
            .expect("replace active row");
        store.commit(corrupt).expect("commit covenant corruption");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "invalid incoming TRANSFER active covenant"
            ))
        ));
    }

    #[test]
    fn query_rejects_missing_or_mismatched_evidence_and_state() {
        let (store, recipient, txid, _, _) = single_query_fixture();
        let mut corrupt = store.batch();
        corrupt
            .delete(ColumnFamily::TxIndex, &evidence_key(txid))
            .expect("delete evidence");
        store.commit(corrupt).expect("commit missing evidence");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "active incoming TRANSFER is missing source evidence"
            ))
        ));

        let (store, recipient, txid, _, _) = single_query_fixture();
        let mut corrupt = store.batch();
        corrupt
            .delete(ColumnFamily::TxIndex, &evidence_state_key(txid))
            .expect("delete evidence state");
        store
            .commit(corrupt)
            .expect("commit missing evidence state");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "active incoming TRANSFER is missing evidence state"
            ))
        ));

        let (store, recipient, txid, _, block_hash) = single_query_fixture();
        let mismatched = TransferEvidence {
            txid,
            block_hash,
            height: 9,
            transaction_position: 0,
            output_count: 2,
        };
        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::TxIndex,
                &evidence_key(txid),
                &mismatched.encode().expect("encode mismatched evidence"),
            )
            .expect("replace evidence");
        store.commit(corrupt).expect("commit mismatched evidence");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "incoming TRANSFER active/evidence inclusion mismatch"
            ))
        ));
    }

    #[test]
    fn query_rejects_absent_membership_and_retired_evidence_state() {
        let (store, recipient, txid, _, _) = single_query_fixture();
        let wrong_membership = EvidenceState::active(BTreeSet::from([1]))
            .expect("valid but mismatched evidence state");
        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::TxIndex,
                &evidence_state_key(txid),
                &wrong_membership
                    .encode(txid)
                    .expect("encode mismatched evidence state"),
            )
            .expect("replace evidence state");
        store
            .commit(corrupt)
            .expect("commit mismatched evidence state");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "active incoming TRANSFER is absent from evidence state"
            ))
        ));

        let (store, recipient, txid, _, block_hash) = single_query_fixture();
        let retired = EvidenceState {
            active_outputs: BTreeSet::new(),
            retired_by: Some(block_hash),
        };
        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::TxIndex,
                &evidence_state_key(txid),
                &retired.encode(txid).expect("encode retired evidence state"),
            )
            .expect("replace evidence state");
        store
            .commit(corrupt)
            .expect("commit retired evidence state");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "active incoming TRANSFER uses retired evidence"
            ))
        ));
    }

    #[test]
    fn query_requires_the_byte_exact_active_utxo_coin() {
        let (store, recipient, _, outpoint, _) = single_query_fixture();
        let mut corrupt = store.batch();
        corrupt
            .delete(ColumnFamily::Utxo, &encode_outpoint_key(&outpoint))
            .expect("delete active coin");
        store.commit(corrupt).expect("commit missing active coin");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "active incoming TRANSFER coin is missing from active UTXO set"
            ))
        ));

        let (store, recipient, _, outpoint, _) = single_query_fixture();
        let snapshot = store.snapshot().expect("snapshot");
        let mut coin = load_coin(&snapshot, &outpoint)
            .expect("load active coin")
            .expect("active coin present");
        drop(snapshot);
        coin.value += 1;
        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::Utxo,
                &encode_outpoint_key(&outpoint),
                &encode_coin(&coin),
            )
            .expect("replace active coin");
        store
            .commit(corrupt)
            .expect("commit mismatched active coin");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(matches!(
            incoming_transfers(&snapshot, wallet_profile(), recipient, None, 1),
            Err(IndexError::Corrupt(
                "active incoming TRANSFER coin disagrees with active UTXO set"
            ))
        ));
    }

    #[test]
    fn query_caches_evidence_and_state_for_adjacent_outputs_of_one_txid() {
        let store = MemoryStore::new();
        let source = block(vec![transaction(vec![
            transfer_output(7, 9, 3, 50),
            transfer_output(7, 9, 4, 40),
        ])]);
        connect_with_coins(&store, &source, 8);
        let snapshot = CountingSnapshot::new(store.snapshot().expect("snapshot"));
        let page = incoming_transfers(&snapshot, wallet_profile(), recipient_script(9), None, 2)
            .expect("query active transfers");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(snapshot.evidence_gets.get(), 1);
        assert_eq!(snapshot.evidence_state_gets.get(), 1);
        assert_eq!(snapshot.utxo_gets.get(), 2);
    }

    #[test]
    fn recipient_is_indexed_separately_from_old_owner() {
        let store = MemoryStore::new();
        let source = block(vec![
            transaction(vec![plain_output(1, 2_000)]),
            transaction(vec![transfer_output(7, 9, 3, 50)]),
        ]);
        connect(&store, &source, 8);

        assert!(active_values(&store, 7).is_empty());
        let rows = active_values(&store, 9);
        assert_eq!(rows.len(), 1);
        let (_, plans) = created_live_plans(&source, 8).expect("source plan");
        let (_, key, _) = &plans.values().next().expect("transfer plan").entries[0];
        let entry = IncomingTransferEntry::decode(key, &rows[0]).expect("active row");
        assert_eq!(entry.coin.address, address(7));
        assert!(!entry.coin.coinbase);
        assert_eq!(entry.transaction_position, 1);
        assert_eq!(entry.recipient_hash, vec![9; 20]);
    }

    #[test]
    fn malformed_transfer_covenant_is_rejected_by_pinned_codec() {
        let store = MemoryStore::new();
        let mut malformed = transfer_output(7, 9, 3, 50);
        malformed.covenant.items.pop();
        let block = block(vec![transaction(vec![malformed])]);
        let snapshot = store.snapshot().expect("snapshot");
        let mut batch = store.batch();
        assert!(matches!(
            stage_connect(&snapshot, &mut batch, &block, 8),
            Err(IndexError::InvalidTransferCovenant)
        ));
    }

    #[test]
    fn multi_output_source_transaction_has_one_evidence_record() {
        let store = MemoryStore::new();
        let transaction = transaction(vec![
            transfer_output(7, 9, 3, 50),
            transfer_output(7, 10, 4, 40),
        ]);
        let txid = transaction.txid();
        let source = block(vec![transaction]);
        connect(&store, &source, 8);

        let snapshot = store.snapshot().expect("snapshot");
        assert!(snapshot
            .get(ColumnFamily::TxIndex, &evidence_key(txid))
            .expect("evidence")
            .is_some());
        assert_eq!(
            load_evidence_state(&snapshot, txid)
                .expect("state")
                .expect("present")
                .active_outputs,
            BTreeSet::from([0, 1])
        );
        assert_eq!(active_values(&store, 9).len(), 1);
        assert_eq!(active_values(&store, 10).len(), 1);
    }

    #[test]
    fn evidence_is_fixed_size_and_never_retains_source_witness() {
        let transaction = transaction(vec![transfer_output(7, 9, 3, 50)]);
        let mut witness_heavy = transaction.clone();
        witness_heavy.inputs[0].witness.items = vec![vec![0x41; 600_000], vec![0x42; 600_000]];
        assert!(witness_heavy.encode().len() > MAX_TX_SIZE);
        assert!(witness_heavy.encode().len() < MAX_BLOCK_WEIGHT);
        assert_eq!(witness_heavy.txid(), transaction.txid());

        let evidence = TransferEvidence {
            txid: transaction.txid(),
            block_hash: BlockHash::new([0x55; 32]),
            height: 8,
            transaction_position: 1,
            output_count: 1,
        };
        let witness_heavy_evidence = TransferEvidence {
            txid: witness_heavy.txid(),
            block_hash: evidence.block_hash,
            height: evidence.height,
            transaction_position: evidence.transaction_position,
            output_count: u32::try_from(witness_heavy.outputs.len()).expect("bounded outputs"),
        };

        let raw = evidence.encode().expect("encode compact evidence");
        assert_eq!(raw.len(), EVIDENCE_VALUE_BYTES);
        assert_eq!(raw.len(), 77);
        assert_eq!(
            witness_heavy_evidence
                .encode()
                .expect("encode witness-independent evidence"),
            raw
        );
        assert_eq!(
            TransferEvidence::decode(transaction.txid(), &raw).expect("decode compact evidence"),
            evidence
        );
    }

    #[test]
    fn evidence_rejects_key_relocation_and_noncanonical_lengths() {
        let txid = transaction(vec![transfer_output(7, 9, 3, 50)]).txid();
        let evidence = TransferEvidence {
            txid,
            block_hash: BlockHash::new([0x56; 32]),
            height: 8,
            transaction_position: 1,
            output_count: 1,
        };
        let raw = evidence.encode().expect("encode compact evidence");
        let relocated_txid = transaction(vec![transfer_output(7, 9, 3, 51)]).txid();
        assert_ne!(relocated_txid, txid);
        assert!(matches!(
            TransferEvidence::decode(relocated_txid, &raw),
            Err(IndexError::Corrupt("invalid incoming TRANSFER evidence"))
        ));

        let mut short = raw.clone();
        short.remove(EVIDENCE_VALUE_BYTES - CHECKSUM_BYTES - 1);
        assert!(matches!(
            TransferEvidence::decode(txid, &short),
            Err(IndexError::Corrupt("invalid incoming TRANSFER evidence"))
        ));
        let mut long = raw;
        long.insert(EVIDENCE_VALUE_BYTES - CHECKSUM_BYTES, 0);
        assert!(matches!(
            TransferEvidence::decode(txid, &long),
            Err(IndexError::Corrupt("invalid incoming TRANSFER evidence"))
        ));
    }

    #[test]
    fn evidence_source_output_count_has_base_size_derived_bound() {
        assert_eq!(MIN_COMPACT_OUTPUT_BYTES, 14);
        assert_eq!(MAX_EVIDENCE_SOURCE_OUTPUTS, 71_428);
        let maximum = u32::try_from(MAX_EVIDENCE_SOURCE_OUTPUTS).expect("maximum fits u32");
        let evidence = TransferEvidence {
            txid: transaction(vec![transfer_output(7, 9, 3, 50)]).txid(),
            block_hash: BlockHash::new([0x58; 32]),
            height: 8,
            transaction_position: 1,
            output_count: maximum,
        };
        let maximum_raw = evidence.encode().expect("encode maximum output count");
        assert_eq!(
            TransferEvidence::decode(evidence.txid, &maximum_raw)
                .expect("decode maximum output count"),
            evidence
        );

        let over_bound = maximum.checked_add(1).expect("maximum plus one fits u32");
        let mut over_bound_evidence = evidence.clone();
        over_bound_evidence.output_count = over_bound;
        assert!(matches!(
            over_bound_evidence.encode(),
            Err(IndexError::Corrupt(
                "incoming TRANSFER evidence source output count is outside its hard bound"
            ))
        ));
        assert!(matches!(
            TransferEvidence::decode(
                evidence.txid,
                &evidence_raw_with_output_count(&evidence, over_bound),
            ),
            Err(IndexError::Corrupt(
                "incoming TRANSFER evidence source output count is outside its hard bound"
            ))
        ));

        let mut empty_evidence = evidence.clone();
        empty_evidence.output_count = 0;
        assert!(matches!(
            empty_evidence.encode(),
            Err(IndexError::Corrupt(
                "incoming TRANSFER evidence source output count is outside its hard bound"
            ))
        ));
        assert!(matches!(
            TransferEvidence::decode(evidence.txid, &evidence_raw_with_output_count(&evidence, 0),),
            Err(IndexError::Corrupt(
                "incoming TRANSFER evidence source output count is outside its hard bound"
            ))
        ));
    }

    #[test]
    fn compact_evidence_binds_output_count_and_coinbase_position() {
        let source = block(vec![
            transaction(vec![plain_output(1, 2_000)]),
            transaction(vec![plain_output(7, 1), transfer_output(7, 9, 3, 50)]),
        ]);
        let (_, plans) = created_live_plans(&source, 8).expect("source plan");
        let plan = plans.values().next().expect("transfer plan");
        let entry = &plan.entries[0].0;
        assert_eq!(entry.coin.outpoint.index, 1);

        let raw = evidence_raw_with_output_count(&plan.evidence, 1);
        let truncated = TransferEvidence::decode(plan.evidence.txid, &raw)
            .expect("decode checksummed but inconsistent output count");
        assert!(matches!(
            entry.validate_evidence(&truncated),
            Err(IndexError::Corrupt(
                "incoming TRANSFER output is outside source transaction bounds"
            ))
        ));

        let mut wrong_coinbase = entry.clone();
        wrong_coinbase.coin.coinbase = true;
        assert!(matches!(
            wrong_coinbase.validate_evidence(&plan.evidence),
            Err(IndexError::Corrupt(
                "incoming TRANSFER coinbase/inclusion mismatch"
            ))
        ));
    }

    #[test]
    fn evidence_references_and_block_effects_use_independent_consensus_bounds() {
        let bounded_outputs = (0..MAX_BLOCK_UPDATES).collect::<BTreeSet<_>>();
        let state = EvidenceState::active(bounded_outputs).expect("600 active outputs");
        let evidence = TransferEvidence {
            txid: transaction(vec![transfer_output(7, 9, 3, 50)]).txid(),
            block_hash: BlockHash::new([0x57; 32]),
            height: 8,
            transaction_position: 1,
            output_count: MAX_BLOCK_UPDATES + 1,
        };
        state
            .validate_evidence(&evidence)
            .expect("total source outputs may exceed the active-reference bound");
        assert_eq!(
            state
                .encode(evidence.txid)
                .expect("encode maximum reference state")
                .len(),
            MAX_EVIDENCE_STATE_BYTES
        );

        let over_bound = (0..=MAX_BLOCK_UPDATES).collect::<BTreeSet<_>>();
        assert!(matches!(
            EvidenceState::active(over_bound),
            Err(IndexError::TransferCapacity(
                "incoming TRANSFER evidence output set is outside its hard bound"
            ))
        ));

        let consensus_effect_bound = MAX_BLOCK_UPDATES
            .checked_add(MAX_BLOCK_RENEWALS)
            .expect("consensus effect bounds fit u32");
        assert_eq!(
            MAX_TRANSFER_EFFECTS_PER_BLOCK,
            usize::try_from(consensus_effect_bound).expect("consensus effect bound fits usize")
        );
        let mut maximum_effects = (0..consensus_effect_bound)
            .map(|index| (index.to_be_bytes().to_vec(), vec![0]))
            .collect::<Vec<_>>();
        effect_commitment(
            b"maximum-effects",
            evidence.block_hash,
            evidence.height,
            &mut maximum_effects,
        )
        .expect("1,200 update-bucket plus renewal-bucket effects");
        maximum_effects.push((consensus_effect_bound.to_be_bytes().to_vec(), vec![0]));
        assert!(matches!(
            effect_commitment(
                b"over-bound-effects",
                evidence.block_hash,
                evidence.height,
                &mut maximum_effects,
            ),
            Err(IndexError::TransferCapacity(
                "incoming TRANSFER effect count exceeds its consensus bound"
            ))
        ));
    }

    #[test]
    fn evidence_state_rejects_hidden_retirement_hash() {
        let txid = transaction(vec![transfer_output(7, 9, 3, 50)]).txid();
        let mut raw = EvidenceState::active(BTreeSet::from([0]))
            .expect("valid active evidence state")
            .encode(txid)
            .expect("encode active evidence state");
        let body_len = raw.len() - CHECKSUM_BYTES;
        raw[2] = 1;
        let checksum = bound_checksum(
            b"hns-wallet-index-incoming-transfer-evidence-state-v1",
            &evidence_state_key(txid),
            &raw[..body_len],
        );
        raw[body_len..].copy_from_slice(&checksum);

        assert!(matches!(
            EvidenceState::decode(txid, &raw),
            Err(IndexError::Corrupt(
                "non-canonical incoming TRANSFER retirement hash"
            ))
        ));
    }

    #[test]
    fn effect_commitments_are_canonical_domain_bound_and_fixed_size() {
        let block_hash = BlockHash::new([0x31; 32]);
        let mut first = vec![
            (b"key-b".to_vec(), b"value-b".to_vec()),
            (b"key-a".to_vec(), b"value-a".to_vec()),
        ];
        let mut permuted = vec![
            (b"key-a".to_vec(), b"value-a".to_vec()),
            (b"key-b".to_vec(), b"value-b".to_vec()),
        ];
        let created = effect_commitment(
            b"hns-wallet-index-incoming-transfer-created-v1",
            block_hash,
            8,
            &mut first,
        )
        .expect("created commitment");
        assert_eq!(
            effect_commitment(
                b"hns-wallet-index-incoming-transfer-created-v1",
                block_hash,
                8,
                &mut permuted,
            )
            .expect("permuted commitment"),
            created
        );

        let mut domain_effects = first.clone();
        let spent = effect_commitment(
            b"hns-wallet-index-incoming-transfer-spent-v1",
            block_hash,
            8,
            &mut domain_effects,
        )
        .expect("spent commitment");
        assert_ne!(spent, created);
        let mut height_effects = first.clone();
        assert_ne!(
            effect_commitment(
                b"hns-wallet-index-incoming-transfer-created-v1",
                block_hash,
                9,
                &mut height_effects,
            )
            .expect("height-bound commitment"),
            created
        );
        let mut hash_effects = first.clone();
        assert_ne!(
            effect_commitment(
                b"hns-wallet-index-incoming-transfer-created-v1",
                BlockHash::new([0x32; 32]),
                8,
                &mut hash_effects,
            )
            .expect("hash-bound commitment"),
            created
        );
        let mut duplicate = vec![
            (b"same".to_vec(), b"one".to_vec()),
            (b"same".to_vec(), b"two".to_vec()),
        ];
        assert!(matches!(
            effect_commitment(
                b"hns-wallet-index-incoming-transfer-created-v1",
                block_hash,
                8,
                &mut duplicate,
            ),
            Err(IndexError::Corrupt(
                "duplicate incoming TRANSFER effect commitment key"
            ))
        ));
        let mut no_effects = Vec::new();
        let empty = effect_commitment(
            b"hns-wallet-index-incoming-transfer-created-v1",
            block_hash,
            8,
            &mut no_effects,
        )
        .expect("canonical empty commitment");
        assert_eq!(empty.count, 0);
        assert_ne!(empty.digest, [0; 32]);

        let marker = TransferUndoMarker {
            block_hash,
            height: 8,
            created,
            spent,
        };
        let raw = marker.encode().expect("encode fixed-size marker");
        assert_eq!(raw.len(), UNDO_VALUE_BYTES);
        assert_eq!(
            TransferUndoMarker::decode(block_hash, &raw).expect("decode fixed-size marker"),
            marker
        );
    }

    #[test]
    fn marker_counts_enforce_created_spent_and_combined_consensus_bounds() {
        let block_hash = BlockHash::new([0x33; 32]);
        let height = 8;
        let mut empty = Vec::new();
        let empty_created = effect_commitment(
            b"hns-wallet-index-incoming-transfer-created-v1",
            block_hash,
            height,
            &mut empty,
        )
        .expect("empty created commitment");
        let empty_spent = effect_commitment(
            b"hns-wallet-index-incoming-transfer-spent-v1",
            block_hash,
            height,
            &mut empty,
        )
        .expect("empty spent commitment");

        let created_over_bound = TransferUndoMarker {
            block_hash,
            height,
            created: EffectCommitment {
                count: MAX_BLOCK_UPDATES + 1,
                digest: [0x41; 32],
            },
            spent: empty_spent.clone(),
        };
        assert!(matches!(
            created_over_bound.encode(),
            Err(IndexError::TransferCapacity(
                "incoming TRANSFER marker effect count exceeds its consensus bound"
            ))
        ));

        let spent_at_bound = TransferUndoMarker {
            block_hash,
            height,
            created: empty_created,
            spent: EffectCommitment {
                count: MAX_TRANSFER_EFFECTS_PER_BLOCK_U32,
                digest: [0x42; 32],
            },
        };
        let accepted = spent_at_bound.encode().expect("1,200 spent effects");
        assert_eq!(
            TransferUndoMarker::decode(block_hash, &accepted).expect("decode 1,200 spent effects"),
            spent_at_bound
        );

        let created_over_raw = marker_raw_with_counts(&spent_at_bound, MAX_BLOCK_UPDATES + 1, 0);
        assert!(matches!(
            TransferUndoMarker::decode(block_hash, &created_over_raw),
            Err(IndexError::Corrupt(
                "incoming TRANSFER marker effect count exceeds its consensus bound"
            ))
        ));

        let combined_over_bound = TransferUndoMarker {
            block_hash,
            height,
            created: EffectCommitment {
                count: 1,
                digest: [0x43; 32],
            },
            spent: spent_at_bound.spent.clone(),
        };
        assert!(matches!(
            combined_over_bound.encode(),
            Err(IndexError::TransferCapacity(
                "incoming TRANSFER marker effect count exceeds its consensus bound"
            ))
        ));
        let combined_over_raw =
            marker_raw_with_counts(&spent_at_bound, 1, MAX_TRANSFER_EFFECTS_PER_BLOCK_U32);
        assert!(matches!(
            TransferUndoMarker::decode(block_hash, &combined_over_raw),
            Err(IndexError::Corrupt(
                "incoming TRANSFER marker effect count exceeds its consensus bound"
            ))
        ));
    }

    #[test]
    fn prune_requires_marker_for_wallet_indexed_block() {
        let store = MemoryStore::new();
        let block = block(vec![transaction(vec![plain_output(7, 50)])]);
        let consensus_undo = undo(&block, 8, Vec::new());
        let snapshot = store.snapshot().expect("snapshot");
        let mut required = store.batch();
        assert!(matches!(
            stage_prune_undo(&snapshot, &mut required, &consensus_undo, true),
            Err(IndexError::Corrupt(
                "incoming TRANSFER undo marker is missing for a wallet-indexed block"
            ))
        ));

        let mut disabled = store.batch();
        stage_prune_undo(&snapshot, &mut disabled, &consensus_undo, false)
            .expect("disabled wallet profile does not require a marker");
    }

    #[test]
    fn same_block_create_and_spend_leaves_no_transfer_residue() {
        let store = MemoryStore::new();
        let source = transaction(vec![transfer_output(7, 9, 3, 50)]);
        let same_block_coin = Coin {
            outpoint: Outpoint {
                txid: source.txid(),
                index: 0,
            },
            value: 50,
            height: 8,
            coinbase: true,
            address: address(7),
            covenant: source.outputs[0].covenant.clone(),
        };
        let spend = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: source.txid(),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 49)],
            locktime: 0,
        };
        let block = block(vec![source, spend]);
        connect(&store, &block, 8);
        let image = family_image(&store);
        assert_eq!(image.len(), 1);
        assert_eq!(image[0].0, undo_key(block.hash()));
        let marker =
            TransferUndoMarker::decode(block.hash(), &image[0].1).expect("empty undo marker");
        assert_eq!(marker.created.count, 0);
        assert_eq!(marker.spent.count, 0);

        let snapshot = store.snapshot().expect("snapshot");
        let mut disconnect = store.batch();
        stage_disconnect(
            &snapshot,
            &mut disconnect,
            &block,
            &undo(&block, 8, vec![same_block_coin]),
        )
        .expect("same-block disconnect ignores non-pre-block coin");
        drop(snapshot);
        store.commit(disconnect).expect("commit disconnect");
        assert!(family_image(&store).is_empty());
    }

    #[test]
    fn partial_same_block_spend_retains_only_the_live_transfer() {
        let store = MemoryStore::new();
        let source = transaction(vec![
            transfer_output(7, 9, 3, 50),
            transfer_output(7, 10, 4, 40),
        ]);
        let source_txid = source.txid();
        let same_block_coin = Coin {
            outpoint: Outpoint {
                txid: source_txid,
                index: 0,
            },
            value: 50,
            height: 8,
            coinbase: false,
            address: address(7),
            covenant: source.outputs[0].covenant.clone(),
        };
        let spend = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: same_block_coin.outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 49)],
            locktime: 0,
        };
        let source_block = block(vec![
            transaction(vec![plain_output(1, 2_000)]),
            source,
            spend,
        ]);
        connect(&store, &source_block, 8);
        let connected = family_image(&store);

        assert!(active_values(&store, 9).is_empty());
        assert_eq!(active_values(&store, 10).len(), 1);
        let snapshot = store.snapshot().expect("snapshot");
        let evidence = load_evidence(&snapshot, source_txid)
            .expect("source evidence")
            .expect("source evidence present");
        assert_eq!(evidence.output_count, 2);
        assert_eq!(evidence.transaction_position, 1);
        assert_eq!(
            load_evidence_state(&snapshot, source_txid)
                .expect("source state")
                .expect("source state present")
                .active_outputs,
            BTreeSet::from([1])
        );

        let mut disconnect = store.batch();
        stage_disconnect(
            &snapshot,
            &mut disconnect,
            &source_block,
            &undo(&source_block, 8, vec![same_block_coin]),
        )
        .expect("partial same-block disconnect");
        drop(snapshot);
        store.commit(disconnect).expect("commit disconnect");
        assert!(family_image(&store).is_empty());

        connect(&store, &source_block, 8);
        assert_eq!(family_image(&store), connected);
    }

    #[test]
    fn connect_disconnect_and_reconnect_are_byte_exact() {
        let store = MemoryStore::new();
        let source = block(vec![transaction(vec![transfer_output(7, 9, 3, 50)])]);
        connect(&store, &source, 8);
        let connected = family_image(&store);

        let snapshot = store.snapshot().expect("snapshot");
        let mut batch = store.batch();
        stage_disconnect(
            &snapshot,
            &mut batch,
            &source,
            &undo(&source, 8, Vec::new()),
        )
        .expect("stage disconnect");
        drop(snapshot);
        store.commit(batch).expect("commit disconnect");
        assert!(family_image(&store).is_empty());

        connect(&store, &source, 8);
        assert_eq!(family_image(&store), connected);
    }

    #[test]
    fn spent_evidence_survives_until_spender_undo_is_pruned() {
        let store = MemoryStore::new();
        let source_transaction = transaction(vec![transfer_output(7, 9, 3, 50)]);
        let source_outpoint = Outpoint {
            txid: source_transaction.txid(),
            index: 0,
        };
        let source_coin = Coin {
            outpoint: source_outpoint.clone(),
            value: 50,
            height: 8,
            coinbase: true,
            address: address(7),
            covenant: source_transaction.outputs[0].covenant.clone(),
        };
        let source = block(vec![source_transaction]);
        connect(&store, &source, 8);
        let mut seed = store.batch();
        write_coin_to_batch(&mut seed, &source_coin).expect("seed source coin");
        store.commit(seed).expect("commit source coin");

        let spend = block(vec![Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: source_outpoint,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 49)],
            locktime: 0,
        }]);
        connect(&store, &spend, 9);
        assert!(active_values(&store, 9).is_empty());
        let txid = source_coin.outpoint.txid;
        let snapshot = store.snapshot().expect("snapshot");
        assert!(load_evidence(&snapshot, txid).expect("evidence").is_some());
        assert_eq!(
            load_evidence_state(&snapshot, txid)
                .expect("state")
                .expect("present")
                .retired_by,
            Some(spend.hash())
        );
        let exact_retired_state = snapshot
            .get(ColumnFamily::TxIndex, &evidence_state_key(txid))
            .expect("read retired state")
            .expect("retired state present");
        drop(snapshot);

        let stale_state = EvidenceState::active(BTreeSet::from([0]))
            .expect("construct stale state")
            .encode(txid)
            .expect("encode stale state");
        let mut corrupt_state = store.batch();
        corrupt_state
            .put(
                ColumnFamily::TxIndex,
                &evidence_state_key(txid),
                &stale_state,
            )
            .expect("stage stale evidence state");
        store
            .commit(corrupt_state)
            .expect("commit stale evidence state");
        let snapshot = store.snapshot().expect("stale-state snapshot");
        let mut rejected_prune = store.batch();
        assert!(matches!(
            stage_prune_undo(
                &snapshot,
                &mut rejected_prune,
                &undo(&spend, 9, vec![source_coin.clone()]),
                true,
            ),
            Err(IndexError::Corrupt(
                "spent incoming TRANSFER remains in evidence state at undo pruning"
            ))
        ));
        drop(snapshot);
        let mut restore_state = store.batch();
        restore_state
            .put(
                ColumnFamily::TxIndex,
                &evidence_state_key(txid),
                &exact_retired_state,
            )
            .expect("restore exact retired state");
        store
            .commit(restore_state)
            .expect("commit restored retired state");

        let snapshot = store.snapshot().expect("snapshot");
        let real_spender_marker = snapshot
            .get(ColumnFamily::TxIndex, &undo_key(spend.hash()))
            .expect("read spender marker")
            .expect("spender marker present");
        drop(snapshot);
        let mut empty_effects = Vec::new();
        let mut mismatched_spent = effect_commitment(
            b"hns-wallet-index-incoming-transfer-spent-v1",
            spend.hash(),
            9,
            &mut empty_effects,
        )
        .expect("empty spent commitment");
        mismatched_spent.count = 1;
        let empty_spender_marker = TransferUndoMarker {
            block_hash: spend.hash(),
            height: 9,
            created: effect_commitment(
                b"hns-wallet-index-incoming-transfer-created-v1",
                spend.hash(),
                9,
                &mut empty_effects,
            )
            .expect("empty created commitment"),
            spent: mismatched_spent,
        }
        .encode()
        .expect("encode semantically incomplete marker");
        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::TxIndex,
                &undo_key(spend.hash()),
                &empty_spender_marker,
            )
            .expect("stage incomplete spender marker");
        store.commit(corrupt).expect("commit incomplete marker");
        let snapshot = store.snapshot().expect("snapshot");
        let mut rejected_prune = store.batch();
        assert!(matches!(
            stage_prune_undo(
                &snapshot,
                &mut rejected_prune,
                &undo(&spend, 9, vec![source_coin.clone()]),
                true,
            ),
            Err(IndexError::Corrupt(
                "incoming TRANSFER prune commitment disagrees with consensus undo"
            ))
        ));
        drop(snapshot);
        let mut restore_marker = store.batch();
        restore_marker
            .put(
                ColumnFamily::TxIndex,
                &undo_key(spend.hash()),
                &real_spender_marker,
            )
            .expect("restore spender marker");
        store
            .commit(restore_marker)
            .expect("commit restored spender marker");

        let snapshot = store.snapshot().expect("snapshot");
        let mut prune_source = store.batch();
        stage_prune_undo(
            &snapshot,
            &mut prune_source,
            &undo(&source, 8, Vec::new()),
            true,
        )
        .expect("prune source undo");
        drop(snapshot);
        store.commit(prune_source).expect("commit source prune");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(load_evidence(&snapshot, txid)
            .expect("evidence retained")
            .is_some());
        drop(snapshot);

        let snapshot = store.snapshot().expect("snapshot");
        let mut prune_spend = store.batch();
        stage_prune_undo(
            &snapshot,
            &mut prune_spend,
            &undo(&spend, 9, vec![source_coin.clone()]),
            true,
        )
        .expect("prune spender undo");
        drop(snapshot);
        store.commit(prune_spend).expect("commit spender prune");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(load_evidence(&snapshot, txid)
            .expect("evidence deleted")
            .is_none());
        assert!(load_evidence_state(&snapshot, txid)
            .expect("state deleted")
            .is_none());
    }

    #[test]
    fn disconnecting_spender_restores_exact_pre_block_transfer_image() {
        let store = MemoryStore::new();
        let source_transaction = transaction(vec![
            transfer_output(7, 9, 3, 50),
            transfer_output(7, 10, 4, 40),
        ]);
        let txid = source_transaction.txid();
        let source = block(vec![source_transaction.clone()]);
        connect(&store, &source, 8);
        let pre_spend_image = family_image(&store);
        let spent_coin = Coin {
            outpoint: Outpoint { txid, index: 0 },
            value: 50,
            height: 8,
            coinbase: true,
            address: address(7),
            covenant: source_transaction.outputs[0].covenant.clone(),
        };
        let mut seed = store.batch();
        write_coin_to_batch(&mut seed, &spent_coin).expect("seed spent coin");
        store.commit(seed).expect("commit spent coin");

        let spend = block(vec![Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: spent_coin.outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 49)],
            locktime: 0,
        }]);
        connect(&store, &spend, 9);
        let spent_image = family_image(&store);
        assert!(active_values(&store, 9).is_empty());
        assert_eq!(active_values(&store, 10).len(), 1);

        let snapshot = store.snapshot().expect("snapshot");
        let mut disconnect = store.batch();
        stage_disconnect(
            &snapshot,
            &mut disconnect,
            &spend,
            &undo(&spend, 9, vec![spent_coin.clone()]),
        )
        .expect("stage spender disconnect");
        drop(snapshot);
        store.commit(disconnect).expect("commit spender disconnect");
        assert_eq!(family_image(&store), pre_spend_image);

        connect(&store, &spend, 9);
        assert_eq!(family_image(&store), spent_image);
    }

    #[test]
    fn staggered_multi_output_spends_retire_deduplicated_evidence_at_last_undo() {
        let store = MemoryStore::new();
        let source_transaction = transaction(vec![
            transfer_output(7, 9, 3, 50),
            transfer_output(7, 10, 4, 40),
        ]);
        let txid = source_transaction.txid();
        let source = block(vec![source_transaction.clone()]);
        connect(&store, &source, 8);
        let coins = source_transaction
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| Coin {
                outpoint: Outpoint {
                    txid,
                    index: u32::try_from(index).expect("fixture index"),
                },
                value: output.value,
                height: 8,
                coinbase: true,
                address: output.address.clone(),
                covenant: output.covenant.clone(),
            })
            .collect::<Vec<_>>();
        let mut seed = store.batch();
        for coin in &coins {
            write_coin_to_batch(&mut seed, coin).expect("seed transfer coin");
        }
        store.commit(seed).expect("commit transfer coins");

        let first_spend = block(vec![Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: coins[0].outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 49)],
            locktime: 0,
        }]);
        connect(&store, &first_spend, 9);
        let second_spend = block(vec![Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: coins[1].outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 39)],
            locktime: 0,
        }]);
        connect(&store, &second_spend, 10);

        let snapshot = store.snapshot().expect("snapshot");
        let state = load_evidence_state(&snapshot, txid)
            .expect("state")
            .expect("present");
        assert!(state.active_outputs.is_empty());
        assert_eq!(state.retired_by, Some(second_spend.hash()));
        drop(snapshot);

        for consensus_undo in [
            undo(&source, 8, Vec::new()),
            undo(&first_spend, 9, vec![coins[0].clone()]),
        ] {
            let snapshot = store.snapshot().expect("snapshot");
            let mut batch = store.batch();
            stage_prune_undo(&snapshot, &mut batch, &consensus_undo, true)
                .expect("prune earlier undo");
            drop(snapshot);
            store.commit(batch).expect("commit earlier prune");
            let snapshot = store.snapshot().expect("snapshot");
            assert!(load_evidence(&snapshot, txid)
                .expect("evidence retained")
                .is_some());
        }

        let snapshot = store.snapshot().expect("snapshot");
        let mut batch = store.batch();
        stage_prune_undo(
            &snapshot,
            &mut batch,
            &undo(&second_spend, 10, vec![coins[1].clone()]),
            true,
        )
        .expect("prune last undo");
        drop(snapshot);
        store.commit(batch).expect("commit last prune");
        let snapshot = store.snapshot().expect("snapshot");
        assert!(load_evidence(&snapshot, txid)
            .expect("evidence retired")
            .is_none());
    }

    #[test]
    fn corrupted_active_row_fails_closed_on_spend() {
        let store = MemoryStore::new();
        let source_transaction = transaction(vec![transfer_output(7, 9, 3, 50)]);
        let source_outpoint = Outpoint {
            txid: source_transaction.txid(),
            index: 0,
        };
        let source_coin = Coin {
            outpoint: source_outpoint.clone(),
            value: 50,
            height: 8,
            coinbase: true,
            address: address(7),
            covenant: source_transaction.outputs[0].covenant.clone(),
        };
        let source = block(vec![source_transaction]);
        connect(&store, &source, 8);
        let (_, plans) = created_live_plans(&source, 8).expect("source plans");
        let (_, key, value) = &plans.values().next().expect("plan").entries[0];
        let mut corrupt = value.clone();
        corrupt[7] ^= 1;
        let mut seed = store.batch();
        write_coin_to_batch(&mut seed, &source_coin).expect("seed source coin");
        seed.put(ColumnFamily::TxIndex, key, &corrupt)
            .expect("corrupt active row");
        store.commit(seed).expect("commit corruption");

        let spend = block(vec![Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: source_outpoint,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![plain_output(7, 49)],
            locktime: 0,
        }]);
        let snapshot = store.snapshot().expect("snapshot");
        let mut batch = store.batch();
        assert!(matches!(
            stage_connect(&snapshot, &mut batch, &spend, 9),
            Err(IndexError::Corrupt(_))
        ));
    }
}
