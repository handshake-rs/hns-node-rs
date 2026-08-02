//! Durable, active-chain tracking for registered Shakedex and HNS HTLC locks.
//!
//! Registrations contain public transaction terms only. They are immutable,
//! bounded, and must be committed before broadcasting a funding transaction.
//! Confirmed funding/spend events are written in the canonical block batch and
//! are therefore recovered on restart and reversed exactly with a reorg.

use std::collections::HashMap;

use hns_primitives::{
    blake2b_256, sha3_256, Address, Block, BlockHash, Coin, CovenantKind, Height, Outpoint,
    Output, Transaction, Txid, Writer,
};
use hns_state::{decode_coin, encode_outpoint_key, BlockUndo};
use hns_secp256k1::Secp256k1Verifier;
use hns_store::{ColumnFamily, PrefixScanBudget, ReadSnapshot, WriteBatch};
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{IndexError, WalletIndexProfile, MAX_QUERY_BYTES, MAX_QUERY_ENTRIES};

/// Maximum immutable public contract registrations in one node store.
/// Registrations are append-only in this schema and capacity is not reclaimed.
pub const MAX_TRACKED_CONTRACTS: u32 = 16_384;
/// Maximum distinct public descriptors sharing one script address.
/// Address bindings are append-only in this schema and capacity is not reclaimed.
pub const MAX_TRACKED_CONTRACTS_PER_ADDRESS: usize = 256;

const REGISTRATION_PREFIX: &[u8] = b"wallet-index/v1/contract/registration/";
const ADDRESS_PREFIX: &[u8] = b"wallet-index/v1/contract/address/";
const FUNDING_PREFIX: &[u8] = b"wallet-index/v1/contract/funding/";
const EVENT_PREFIX: &[u8] = b"wallet-index/v1/contract/event/";
const REGISTRATION_COUNT_KEY: &[u8] = b"wallet-index/v1/contract/count";
const RECORD_VERSION: u8 = 1;
const CHECKSUM_BYTES: usize = 32;
const ADDRESS_BINDING_HEADER_BYTES: usize = 3;
const HNS_HTLC_PREIMAGE_BYTES: usize = 32;
const HNS_HTLC_MAX_SCRIPT_BYTES: usize = 192;
const LOCKTIME_MASK: u32 = 0x7fff_ffff;
const HNS_HTLC_SIGHASH_ALL: u8 = 0x01;
const HIP1_SELLER_FULFILLMENT_SIGHASH: u8 = 0x84;
const HIP1_SELLER_RECOVERY_SIGHASH: u8 = 0x83;
const CONTRACT_ID_DOMAIN: &[u8] = b"hns-wallet-index/contract-id";
const CONTRACT_ID_ENCODING_VERSION: u8 = 1;
const SHAKEDEX_V2_CONTRACT_TAG: u8 = 1;
const HNS_HTLC_V1_CONTRACT_TAG: u8 = 2;

// The exact script opcodes used by hns-rs Shakedex-v2 and HNS-HTLC-v1.
const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_SHA256: u8 = 0xa8;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_TYPE: u8 = 0xd0;
const OP_9: u8 = OP_1 + 8;
const OP_10: u8 = OP_1 + 9;

/// Network-independent identity derived from a versioned canonical binary
/// encoding of the complete public tracking descriptor.
///
/// Network identity is deliberately absent: the same script and public terms
/// have the same identifier on every Handshake network. Durable events remain
/// local to, and protected by, the node store's independently validated
/// network/genesis binding.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ContractId([u8; 32]);

impl ContractId {
    /// Raw stable identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact public Shakedex-v2 lock terms needed for authoritative chain tracking.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakedexV2Descriptor {
    /// Canonical Handshake name hash committed by the FINALIZE locking coin.
    pub name_hash: [u8; 32],
    /// Seller public key committed by the canonical HIP-0001 lock script.
    pub seller_public_key: [u8; 33],
    /// Exact name coin value expected at the locking script.
    pub value: u64,
}

/// Exact public HNS-HTLC-v1 terms needed for funding and spend verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsHtlcDescriptor {
    /// Exact funding value in HNS atomic units.
    pub value: u64,
    /// SHA-256 commitment to the 32-byte settlement preimage.
    pub hashlock: [u8; 32],
    /// Receiver key for the preimage branch.
    pub receiver_public_key: [u8; 33],
    /// Refund key for the absolute-timelock branch.
    pub refund_public_key: [u8; 33],
    /// Exact HSD absolute locktime encoding.
    pub refund_locktime: u32,
}

/// Supported authoritative Handshake contract trackers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub enum TrackedContractKind {
    /// HIP-0001 fixed-price name-sale lock.
    ShakedexV2(ShakedexV2Descriptor),
    /// Native Handshake SHA-256/CLTV HTLC.
    HnsHtlcV1(HnsHtlcDescriptor),
}

/// Immutable public contract registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractRegistration {
    /// Content-derived registration identity.
    pub id: ContractId,
    /// Exact supported public descriptor.
    pub kind: TrackedContractKind,
}

impl ContractRegistration {
    /// Construct and validate a Shakedex-v2 registration.
    pub fn shakedex_v2(descriptor: ShakedexV2Descriptor) -> Result<Self, IndexError> {
        Self::new(TrackedContractKind::ShakedexV2(descriptor))
    }

    /// Construct and validate an HNS-HTLC-v1 registration.
    pub fn hns_htlc_v1(descriptor: HnsHtlcDescriptor) -> Result<Self, IndexError> {
        Self::new(TrackedContractKind::HnsHtlcV1(descriptor))
    }

    fn new(kind: TrackedContractKind) -> Result<Self, IndexError> {
        validate_kind(&kind)?;
        Ok(Self {
            id: ContractId(blake2b_256(&canonical_contract_identity(&kind))),
            kind,
        })
    }

    /// Exact version-zero script-hash address for this lock.
    pub fn funding_address(&self) -> Result<Address, IndexError> {
        self.validate()?;
        Address::new(0, sha3_256(&self.lock_script()?).to_vec())
            .map_err(|_| IndexError::Corrupt("tracked contract produced an invalid address"))
    }

    /// Whether an output exactly satisfies the registered funding terms.
    pub fn matches_funding_output(&self, output: &Output) -> Result<bool, IndexError> {
        if output.address != self.funding_address()? {
            return Ok(false);
        }
        Ok(match &self.kind {
            TrackedContractKind::ShakedexV2(descriptor) => {
                output.value == descriptor.value
                    && output.covenant.kind == CovenantKind::Finalize
                    && output.covenant.item(0) == Some(descriptor.name_hash.as_slice())
            }
            TrackedContractKind::HnsHtlcV1(descriptor) => {
                output.value == descriptor.value
                    && output.covenant.kind == CovenantKind::None
                    && output.covenant.items.is_empty()
            }
        })
    }

    /// Classify a consensus-confirmed spend against this exact descriptor.
    pub fn classify_spend(
        &self,
        transaction: &Transaction,
        input_position: usize,
        funding_coin: &Coin,
    ) -> Result<TrackedContractSpendKind, IndexError> {
        let input = transaction.inputs.get(input_position).ok_or(IndexError::Corrupt(
            "tracked contract spend input is absent",
        ))?;
        if input.previous_output != funding_coin.outpoint
            || !self.matches_funding_output(&Output {
                value: funding_coin.value,
                address: funding_coin.address.clone(),
                covenant: funding_coin.covenant.clone(),
            })?
        {
            return Err(IndexError::Corrupt(
                "tracked contract funding coin disagrees with registration",
            ));
        }
        let script = self.lock_script()?;
        match &self.kind {
            TrackedContractKind::ShakedexV2(_) => {
                let Some(output) = transaction.outputs.get(input_position) else {
                    return Ok(TrackedContractSpendKind::Unrecognized);
                };
                match (output.covenant.kind, input.witness.items.as_slice()) {
                    (CovenantKind::Transfer, [signature, witness_script])
                        if canonical_signature(signature, HIP1_SELLER_FULFILLMENT_SIGHASH)
                            && witness_script == &script =>
                    {
                        Ok(TrackedContractSpendKind::ShakedexFulfillment)
                    }
                    (CovenantKind::Transfer, [signature, witness_script])
                        if canonical_signature(signature, HIP1_SELLER_RECOVERY_SIGHASH)
                            && witness_script == &script =>
                    {
                        Ok(TrackedContractSpendKind::ShakedexRecovery)
                    }
                    _ => Ok(TrackedContractSpendKind::Unrecognized),
                }
            }
            TrackedContractKind::HnsHtlcV1(descriptor) => {
                match input.witness.items.as_slice() {
                    [signature, preimage, selector, witness_script]
                        if canonical_signature(signature, HNS_HTLC_SIGHASH_ALL)
                            && preimage.len() == HNS_HTLC_PREIMAGE_BYTES
                            && selector.as_slice() == [1]
                            && witness_script == &script =>
                    {
                        let Ok(preimage): Result<[u8; HNS_HTLC_PREIMAGE_BYTES], _> =
                            preimage.as_slice().try_into()
                        else {
                            return Ok(TrackedContractSpendKind::Unrecognized);
                        };
                        let observed_hash: [u8; 32] = Sha256::digest(preimage).into();
                        if observed_hash != descriptor.hashlock {
                            return Ok(TrackedContractSpendKind::Unrecognized);
                        }
                        Ok(TrackedContractSpendKind::HtlcRedemption {
                            preimage: RevealedPreimage(preimage),
                        })
                    }
                    [signature, selector, witness_script]
                        if canonical_signature(signature, HNS_HTLC_SIGHASH_ALL)
                            && selector.is_empty()
                            && witness_script == &script =>
                    {
                        Ok(TrackedContractSpendKind::HtlcRefund)
                    }
                    _ => Ok(TrackedContractSpendKind::Unrecognized),
                }
            }
        }
    }

    fn validate(&self) -> Result<(), IndexError> {
        validate_kind(&self.kind)?;
        let rebuilt = Self::new(self.kind.clone())?;
        if rebuilt.id != self.id {
            return Err(IndexError::Corrupt(
                "tracked contract identity disagrees with descriptor",
            ));
        }
        Ok(())
    }

    fn lock_script(&self) -> Result<Vec<u8>, IndexError> {
        match &self.kind {
            TrackedContractKind::ShakedexV2(descriptor) => {
                Ok(shakedex_lock_script(&descriptor.seller_public_key).to_vec())
            }
            TrackedContractKind::HnsHtlcV1(descriptor) => htlc_lock_script(descriptor),
        }
    }
}

fn canonical_contract_identity(kind: &TrackedContractKind) -> Vec<u8> {
    // This public identity format is deliberately independent of serde and its
    // field ordering. Integer fields are fixed-width big-endian values.
    let mut identity = Writer::with_capacity(160);
    identity.write_bytes(CONTRACT_ID_DOMAIN);
    identity.write_u8(CONTRACT_ID_ENCODING_VERSION);
    match kind {
        TrackedContractKind::ShakedexV2(descriptor) => {
            identity.write_u8(SHAKEDEX_V2_CONTRACT_TAG);
            identity.write_bytes(&descriptor.name_hash);
            identity.write_bytes(&descriptor.seller_public_key);
            identity.write_bytes(&descriptor.value.to_be_bytes());
        }
        TrackedContractKind::HnsHtlcV1(descriptor) => {
            identity.write_u8(HNS_HTLC_V1_CONTRACT_TAG);
            identity.write_bytes(&descriptor.value.to_be_bytes());
            identity.write_bytes(&descriptor.hashlock);
            identity.write_bytes(&descriptor.receiver_public_key);
            identity.write_bytes(&descriptor.refund_public_key);
            identity.write_bytes(&descriptor.refund_locktime.to_be_bytes());
        }
    }
    identity.finish()
}

/// Result of an idempotent immutable registration write.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractRegistrationOutcome {
    /// A new registration was persisted.
    Registered,
    /// The exact registration was already persisted.
    AlreadyRegistered,
}

/// A revealed on-chain preimage. Debug output is deliberately redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct RevealedPreimage([u8; HNS_HTLC_PREIMAGE_BYTES]);

impl RevealedPreimage {
    /// Explicit settlement-only access to the already public chain value.
    #[must_use]
    pub const fn expose_for_settlement(&self) -> &[u8; HNS_HTLC_PREIMAGE_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for RevealedPreimage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RevealedPreimage([REDACTED])")
    }
}

impl Serialize for RevealedPreimage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for RevealedPreimage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
        Err(serde::de::Error::custom(
            "revealed preimages cannot be reconstructed through public serde",
        ))
    }
}

/// Authoritative confirmed spend classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrackedContractSpendKind {
    /// Consensus accepted the spend, but its witness/output shape is outside
    /// this tracker's pinned wallet profile. No preimage is disclosed.
    Unrecognized,
    /// Shakedex seller-authorized TRANSFER branch.
    ShakedexFulfillment,
    /// Shakedex seller-signed TRANSFER recovery branch.
    ShakedexRecovery,
    /// HNS HTLC receiver branch with a validated revealed preimage.
    HtlcRedemption { preimage: RevealedPreimage },
    /// HNS HTLC absolute-timelock refund branch.
    HtlcRefund,
}

/// One currently active confirmed funding coin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractFunding {
    /// Registered contract.
    pub contract_id: ContractId,
    /// Exact active UTXO.
    pub coin: Coin,
    /// Active-chain block containing the funding output.
    pub block_hash: BlockHash,
    /// Active-chain funding height.
    pub height: Height,
    /// Funding transaction position.
    pub transaction_position: u32,
    /// Funding output position.
    pub output_position: u32,
}

/// One durable active-chain tracking event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrackedContractEvent {
    /// A matching funding output became active.
    Funding(TrackedContractFunding),
    /// A matching funding output was spent through an authenticated branch.
    Spend {
        /// Registered contract.
        contract_id: ContractId,
        /// Complete prior funding record needed for exact disconnect recovery.
        funding: TrackedContractFunding,
        /// Canonical spending transaction ID.
        spending_txid: Txid,
        /// Active-chain spending block.
        block_hash: BlockHash,
        /// Active-chain spending height.
        height: Height,
        /// Spending transaction position.
        transaction_position: u32,
        /// Input which spends the funding outpoint.
        input_position: u32,
        /// Verified protocol branch.
        kind: TrackedContractSpendKind,
    },
}

#[derive(Serialize, Deserialize)]
enum StoredTrackedContractSpendKind {
    Unrecognized,
    ShakedexFulfillment,
    ShakedexRecovery,
    HtlcRedemption {
        preimage: [u8; HNS_HTLC_PREIMAGE_BYTES],
    },
    HtlcRefund,
}

impl From<&TrackedContractSpendKind> for StoredTrackedContractSpendKind {
    fn from(kind: &TrackedContractSpendKind) -> Self {
        match kind {
            TrackedContractSpendKind::Unrecognized => Self::Unrecognized,
            TrackedContractSpendKind::ShakedexFulfillment => Self::ShakedexFulfillment,
            TrackedContractSpendKind::ShakedexRecovery => Self::ShakedexRecovery,
            TrackedContractSpendKind::HtlcRedemption { preimage } => Self::HtlcRedemption {
                preimage: *preimage.expose_for_settlement(),
            },
            TrackedContractSpendKind::HtlcRefund => Self::HtlcRefund,
        }
    }
}

impl From<StoredTrackedContractSpendKind> for TrackedContractSpendKind {
    fn from(kind: StoredTrackedContractSpendKind) -> Self {
        match kind {
            StoredTrackedContractSpendKind::Unrecognized => Self::Unrecognized,
            StoredTrackedContractSpendKind::ShakedexFulfillment => Self::ShakedexFulfillment,
            StoredTrackedContractSpendKind::ShakedexRecovery => Self::ShakedexRecovery,
            StoredTrackedContractSpendKind::HtlcRedemption { preimage } => Self::HtlcRedemption {
                preimage: RevealedPreimage(preimage),
            },
            StoredTrackedContractSpendKind::HtlcRefund => Self::HtlcRefund,
        }
    }
}

#[derive(Serialize, Deserialize)]
enum StoredTrackedContractEvent {
    Funding(TrackedContractFunding),
    Spend {
        contract_id: ContractId,
        funding: TrackedContractFunding,
        spending_txid: Txid,
        block_hash: BlockHash,
        height: Height,
        transaction_position: u32,
        input_position: u32,
        kind: StoredTrackedContractSpendKind,
    },
}

impl From<&TrackedContractEvent> for StoredTrackedContractEvent {
    fn from(event: &TrackedContractEvent) -> Self {
        match event {
            TrackedContractEvent::Funding(funding) => Self::Funding(funding.clone()),
            TrackedContractEvent::Spend {
                contract_id,
                funding,
                spending_txid,
                block_hash,
                height,
                transaction_position,
                input_position,
                kind,
            } => Self::Spend {
                contract_id: *contract_id,
                funding: funding.clone(),
                spending_txid: *spending_txid,
                block_hash: *block_hash,
                height: *height,
                transaction_position: *transaction_position,
                input_position: *input_position,
                kind: kind.into(),
            },
        }
    }
}

impl From<StoredTrackedContractEvent> for TrackedContractEvent {
    fn from(event: StoredTrackedContractEvent) -> Self {
        match event {
            StoredTrackedContractEvent::Funding(funding) => Self::Funding(funding),
            StoredTrackedContractEvent::Spend {
                contract_id,
                funding,
                spending_txid,
                block_hash,
                height,
                transaction_position,
                input_position,
                kind,
            } => Self::Spend {
                contract_id,
                funding,
                spending_txid,
                block_hash,
                height,
                transaction_position,
                input_position,
                kind: kind.into(),
            },
        }
    }
}

impl TrackedContractEvent {
    fn contract_id(&self) -> ContractId {
        match self {
            Self::Funding(funding) => funding.contract_id,
            Self::Spend { contract_id, .. } => *contract_id,
        }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Self::Funding(funding) => event_key(
                funding.contract_id,
                funding.height,
                funding.transaction_position,
                0,
                funding.output_position,
                funding.coin.outpoint.txid,
            ),
            Self::Spend {
                contract_id,
                spending_txid,
                height,
                transaction_position,
                input_position,
                ..
            } => event_key(
                *contract_id,
                *height,
                *transaction_position,
                1,
                *input_position,
                *spending_txid,
            ),
        }
    }
}

/// Opaque exclusive continuation for contract funding or event pages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractCursor {
    key: Vec<u8>,
}

/// One bounded active-funding page.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractFundingPage {
    /// Currently active funding coins in outpoint order.
    pub entries: Vec<TrackedContractFunding>,
    /// Exclusive continuation when more data may exist.
    pub continuation: Option<TrackedContractCursor>,
}

/// One bounded confirmed-event page.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractEventPage {
    /// Confirmed events in height/transaction/event order.
    pub entries: Vec<TrackedContractEvent>,
    /// Exclusive continuation when more data may exist.
    pub continuation: Option<TrackedContractCursor>,
}

/// Stage one immutable public registration in an ordinary node-store batch.
pub fn register_tracked_contract<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
    profile: WalletIndexProfile,
    registration: &ContractRegistration,
) -> Result<ContractRegistrationOutcome, IndexError> {
    require_contract_profile(profile)?;
    registration.validate()?;
    let key = registration_key(registration.id);
    if let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? {
        let stored: ContractRegistration = decode_record(b"contract-registration-v1", &key, &raw)?;
        if stored != *registration {
            return Err(IndexError::Corrupt(
                "tracked contract registration key is occupied by different terms",
            ));
        }
        let binding_key = address_key(&registration.funding_address()?);
        let binding = snapshot
            .get(ColumnFamily::TxIndex, &binding_key)?
            .ok_or(IndexError::Corrupt(
                "tracked contract registration has no address binding",
            ))?;
        if decode_address_bindings(&binding_key, &binding)?
            .binary_search(&registration.id)
            .is_err()
        {
            return Err(IndexError::Corrupt(
                "tracked contract registration address binding mismatch",
            ));
        }
        return Ok(ContractRegistrationOutcome::AlreadyRegistered);
    }

    let address = registration.funding_address()?;
    let address_key = address_key(&address);
    let mut address_bindings = snapshot
        .get(ColumnFamily::TxIndex, &address_key)?
        .as_deref()
        .map(|raw| decode_address_bindings(&address_key, raw))
        .transpose()?
        .unwrap_or_default();
    if address_bindings.len() >= MAX_TRACKED_CONTRACTS_PER_ADDRESS {
        return Err(IndexError::ContractAddressCapacity);
    }
    match address_bindings.binary_search(&registration.id) {
        Ok(_) => {
            return Err(IndexError::Corrupt(
                "contract address binding exists without registration",
            ));
        }
        Err(position) => address_bindings.insert(position, registration.id),
    }
    let count = snapshot
        .get(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)?
        .as_deref()
        .map(decode_registration_count)
        .transpose()?
        .unwrap_or(0);
    if count >= MAX_TRACKED_CONTRACTS {
        return Err(IndexError::ContractCapacity);
    }
    let next = count.checked_add(1).ok_or(IndexError::ContractCapacity)?;
    batch.put(
        ColumnFamily::TxIndex,
        &key,
        &encode_record(b"contract-registration-v1", &key, registration)?,
    )?;
    batch.put(
        ColumnFamily::TxIndex,
        &address_key,
        &encode_address_bindings(&address_key, &address_bindings)?,
    )?;
    batch.put(
        ColumnFamily::TxIndex,
        REGISTRATION_COUNT_KEY,
        &encode_registration_count(next),
    )?;
    Ok(ContractRegistrationOutcome::Registered)
}

/// Read one immutable public contract registration.
pub fn tracked_contract<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    id: ContractId,
) -> Result<Option<ContractRegistration>, IndexError> {
    require_contract_profile(profile)?;
    load_registration(snapshot, id)
}

/// Validate the complete bounded registration/address topology at startup.
pub fn validate_tracked_contract_registry<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
) -> Result<(), IndexError> {
    if !profile.wallet {
        return Ok(());
    }
    let expected = snapshot
        .get(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)?
        .as_deref()
        .map(decode_registration_count)
        .transpose()?
        .unwrap_or(0);
    if expected > MAX_TRACKED_CONTRACTS {
        return Err(IndexError::Corrupt(
            "tracked contract count exceeds schema bound",
        ));
    }

    let registrations = validate_registry_prefix(snapshot, REGISTRATION_PREFIX, |key, raw| {
        let registration: ContractRegistration =
            decode_record(b"contract-registration-v1", key, raw)?;
        registration.validate()?;
        if registration_key(registration.id) != key {
            return Err(IndexError::Corrupt(
                "tracked contract registration key/value binding mismatch",
            ));
        }
        let binding_key = address_key(&registration.funding_address()?);
        let binding = snapshot
            .get(ColumnFamily::TxIndex, &binding_key)?
            .ok_or(IndexError::Corrupt(
                "tracked contract registration has no address binding",
            ))?;
        if decode_address_bindings(&binding_key, &binding)?
            .binary_search(&registration.id)
            .is_err()
        {
            return Err(IndexError::Corrupt(
                "tracked contract registration address binding mismatch",
            ));
        }
        Ok(())
    })?;
    let mut binding_total = 0_u32;
    let addresses = validate_registry_prefix(snapshot, ADDRESS_PREFIX, |key, raw| {
        let ids = decode_address_bindings(key, raw)?;
        for id in ids {
            let registration = load_registration(snapshot, id)?.ok_or(IndexError::Corrupt(
                "tracked contract address points to missing registration",
            ))?;
            if address_key(&registration.funding_address()?) != key {
                return Err(IndexError::Corrupt(
                    "tracked contract address key disagrees with registration",
                ));
            }
            binding_total = binding_total.checked_add(1).ok_or(IndexError::Corrupt(
                "tracked contract address binding count overflow",
            ))?;
            if binding_total > expected {
                return Err(IndexError::Corrupt(
                    "tracked contract address bindings exceed registry count",
                ));
            }
        }
        Ok(())
    })?;
    if registrations != expected
        || binding_total != expected
        || (expected != 0 && addresses == 0)
    {
        return Err(IndexError::Corrupt(
            "tracked contract registry count/topology mismatch",
        ));
    }
    Ok(())
}

/// Read one bounded page of currently active contract fundings.
pub fn tracked_contract_fundings<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    id: ContractId,
    cursor: Option<&TrackedContractCursor>,
    limit: usize,
) -> Result<TrackedContractFundingPage, IndexError> {
    require_contract_profile(profile)?;
    validate_page_limit(limit)?;
    ensure_registration(snapshot, id)?;
    let prefix = funding_prefix(id);
    validate_cursor(&prefix, cursor)?;
    let page = snapshot.scan_prefix_page(
        ColumnFamily::TxIndex,
        &prefix,
        cursor.map(|cursor| cursor.key.as_slice()),
        PrefixScanBudget {
            max_entries: limit,
            max_bytes: MAX_QUERY_BYTES,
        },
    )?;
    let entries = page
        .entries
        .iter()
        .map(|(key, raw)| decode_funding(id, key, raw))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TrackedContractFundingPage {
        entries,
        continuation: page
            .continuation
            .map(|key| TrackedContractCursor { key }),
    })
}

/// Read one active funding by exact registered contract and outpoint.
pub fn tracked_contract_funding<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    id: ContractId,
    outpoint: &Outpoint,
) -> Result<Option<TrackedContractFunding>, IndexError> {
    require_contract_profile(profile)?;
    ensure_registration(snapshot, id)?;
    load_funding(snapshot, id, outpoint)
}

/// Read one bounded page of confirmed contract events.
pub fn tracked_contract_events<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    id: ContractId,
    cursor: Option<&TrackedContractCursor>,
    limit: usize,
) -> Result<TrackedContractEventPage, IndexError> {
    require_contract_profile(profile)?;
    validate_page_limit(limit)?;
    ensure_registration(snapshot, id)?;
    let prefix = event_prefix(id);
    validate_cursor(&prefix, cursor)?;
    let page = snapshot.scan_prefix_page(
        ColumnFamily::TxIndex,
        &prefix,
        cursor.map(|cursor| cursor.key.as_slice()),
        PrefixScanBudget {
            max_entries: limit,
            max_bytes: MAX_QUERY_BYTES,
        },
    )?;
    let entries = page
        .entries
        .iter()
        .map(|(key, raw)| {
            let event: StoredTrackedContractEvent =
                decode_record(b"contract-event-v1", key, raw)?;
            let event = TrackedContractEvent::from(event);
            if event.contract_id() != id || event.key() != *key {
                return Err(IndexError::Corrupt(
                    "tracked contract event key/value binding mismatch",
                ));
            }
            Ok(event)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TrackedContractEventPage {
        entries,
        continuation: page
            .continuation
            .map(|key| TrackedContractCursor { key }),
    })
}

pub(crate) fn stage_connect<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
    block: &Block,
    height: Height,
    profile: WalletIndexProfile,
) -> Result<(), IndexError> {
    if !profile.wallet {
        return Ok(());
    }
    let block_hash = block.hash();
    let created = block_created_coins(block, height)?;
    let mut tracked_created = HashMap::<Outpoint, (ContractRegistration, TrackedContractFunding)>::new();

    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        let txid = transaction.txid();
        for (output_position, output) in transaction.outputs.iter().enumerate() {
            if output.is_unspendable() {
                continue;
            }
            let Some(registration) = matching_contract_for_output(snapshot, output)? else {
                continue;
            };
            if !registration.matches_funding_output(output)? {
                continue;
            }
            let output_position =
                u32::try_from(output_position).map_err(|_| IndexError::PositionOverflow)?;
            let outpoint = Outpoint {
                txid,
                index: output_position,
            };
            let coin = created
                .get(&outpoint)
                .cloned()
                .ok_or(IndexError::Corrupt("tracked funding coin was not constructed"))?;
            let funding = TrackedContractFunding {
                contract_id: registration.id,
                coin,
                block_hash,
                height,
                transaction_position,
                output_position,
            };
            put_funding(batch, &funding)?;
            put_event(batch, &TrackedContractEvent::Funding(funding.clone()))?;
            tracked_created.insert(outpoint, (registration, funding));
        }
    }

    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        for (input_position, input) in transaction.inputs.iter().enumerate() {
            if input.previous_output.is_null() {
                continue;
            }
            let coin = match created.get(&input.previous_output) {
                Some(coin) => coin.clone(),
                None => load_coin(snapshot, &input.previous_output)?.ok_or_else(|| {
                    IndexError::MissingInputCoin(input.previous_output.clone())
                })?,
            };
            let Some(registration) = matching_contract_for_output(
                snapshot,
                &Output {
                    value: coin.value,
                    address: coin.address.clone(),
                    covenant: coin.covenant.clone(),
                },
            )?
            else {
                continue;
            };
            let funding = if let Some((created_registration, funding)) =
                tracked_created.get(&input.previous_output)
            {
                if created_registration.id != registration.id || funding.coin != coin {
                    return Err(IndexError::Corrupt(
                        "same-block tracked funding disagrees with descriptor selection",
                    ));
                }
                funding.clone()
            } else {
                let Some(funding) = load_funding(
                    snapshot,
                    registration.id,
                    &input.previous_output,
                )?
                else {
                    continue;
                };
                funding
            };
            let kind = registration.classify_spend(transaction, input_position, &funding.coin)?;
            let input_position =
                u32::try_from(input_position).map_err(|_| IndexError::PositionOverflow)?;
            let event = TrackedContractEvent::Spend {
                contract_id: registration.id,
                funding: funding.clone(),
                spending_txid: transaction.txid(),
                block_hash,
                height,
                transaction_position,
                input_position,
                kind,
            };
            batch.delete(
                ColumnFamily::TxIndex,
                &funding_key(registration.id, &input.previous_output),
            )?;
            put_event(batch, &event)?;
        }
    }
    Ok(())
}

pub(crate) fn stage_disconnect<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
    block: &Block,
    undo: &BlockUndo,
    profile: WalletIndexProfile,
) -> Result<(), IndexError> {
    if !profile.wallet {
        return Ok(());
    }
    let created = block_created_coins(block, undo.height)?;
    let restored = undo
        .spent_coins
        .iter()
        .map(|coin| (coin.outpoint.clone(), coin.clone()))
        .collect::<HashMap<_, _>>();

    // Restore spends first. A funding created and spent in this same block is
    // then removed by the funding reversal below, leaving the exact pre-state.
    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        for (input_position, input) in transaction.inputs.iter().enumerate() {
            if input.previous_output.is_null() {
                continue;
            }
            let Some(coin) = created
                .get(&input.previous_output)
                .or_else(|| restored.get(&input.previous_output))
            else {
                return Err(IndexError::MissingInputCoin(input.previous_output.clone()));
            };
            let Some(registration) = matching_contract_for_output(
                snapshot,
                &Output {
                    value: coin.value,
                    address: coin.address.clone(),
                    covenant: coin.covenant.clone(),
                },
            )?
            else {
                continue;
            };
            let input_position_u32 =
                u32::try_from(input_position).map_err(|_| IndexError::PositionOverflow)?;
            let key = event_key(
                registration.id,
                undo.height,
                transaction_position,
                1,
                input_position_u32,
                transaction.txid(),
            );
            let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? else {
                continue;
            };
            let stored: StoredTrackedContractEvent =
                decode_record(b"contract-event-v1", &key, &raw)?;
            let stored = TrackedContractEvent::from(stored);
            let kind = registration.classify_spend(transaction, input_position, coin)?;
            let TrackedContractEvent::Spend {
                funding: prior_funding,
                ..
            } = &stored
            else {
                return Err(IndexError::Corrupt(
                    "tracked spend key contains a funding event",
                ));
            };
            let expected = TrackedContractEvent::Spend {
                contract_id: registration.id,
                funding: prior_funding.clone(),
                spending_txid: transaction.txid(),
                block_hash: undo.block_hash,
                height: undo.height,
                transaction_position,
                input_position: input_position_u32,
                kind,
            };
            if stored != expected || stored.key() != key {
                return Err(IndexError::Corrupt(
                    "tracked spend event disagrees with disconnected block",
                ));
            }
            if prior_funding.contract_id != registration.id || prior_funding.coin != *coin {
                return Err(IndexError::Corrupt(
                    "tracked spend contains inconsistent prior funding",
                ));
            }
            put_funding(batch, prior_funding)?;
            batch.delete(ColumnFamily::TxIndex, &key)?;
        }
    }

    for (transaction_position, transaction) in block.transactions.iter().enumerate() {
        let transaction_position =
            u32::try_from(transaction_position).map_err(|_| IndexError::PositionOverflow)?;
        for (output_position, output) in transaction.outputs.iter().enumerate() {
            if output.is_unspendable() {
                continue;
            }
            let Some(registration) = matching_contract_for_output(snapshot, output)? else {
                continue;
            };
            if !registration.matches_funding_output(output)? {
                continue;
            }
            let output_position =
                u32::try_from(output_position).map_err(|_| IndexError::PositionOverflow)?;
            let outpoint = Outpoint {
                txid: transaction.txid(),
                index: output_position,
            };
            let key = event_key(
                registration.id,
                undo.height,
                transaction_position,
                0,
                output_position,
                transaction.txid(),
            );
            let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? else {
                continue;
            };
            let stored: StoredTrackedContractEvent =
                decode_record(b"contract-event-v1", &key, &raw)?;
            let stored = TrackedContractEvent::from(stored);
            let funding = TrackedContractFunding {
                contract_id: registration.id,
                coin: created
                    .get(&outpoint)
                    .cloned()
                    .ok_or(IndexError::Corrupt("disconnected funding coin is absent"))?,
                block_hash: undo.block_hash,
                height: undo.height,
                transaction_position,
                output_position,
            };
            let expected = TrackedContractEvent::Funding(funding);
            if stored != expected || stored.key() != key {
                return Err(IndexError::Corrupt(
                    "tracked funding event disagrees with disconnected block",
                ));
            }
            batch.delete(
                ColumnFamily::TxIndex,
                &funding_key(registration.id, &outpoint),
            )?;
            batch.delete(ColumnFamily::TxIndex, &key)?;
        }
    }
    Ok(())
}

fn validate_kind(kind: &TrackedContractKind) -> Result<(), IndexError> {
    match kind {
        TrackedContractKind::ShakedexV2(descriptor) => {
            if descriptor.name_hash == [0; 32]
                || descriptor.value == 0
                || !valid_compressed_key(&descriptor.seller_public_key)
            {
                return Err(IndexError::InvalidContract);
            }
        }
        TrackedContractKind::HnsHtlcV1(descriptor) => {
            if descriptor.value == 0
                || descriptor.hashlock == [0; 32]
                || descriptor.refund_locktime & LOCKTIME_MASK == 0
                || !valid_compressed_key(&descriptor.receiver_public_key)
                || !valid_compressed_key(&descriptor.refund_public_key)
                || descriptor.receiver_public_key == descriptor.refund_public_key
            {
                return Err(IndexError::InvalidContract);
            }
            let script = htlc_lock_script(descriptor)?;
            if script.len() > HNS_HTLC_MAX_SCRIPT_BYTES {
                return Err(IndexError::InvalidContract);
            }
        }
    }
    Ok(())
}

fn valid_compressed_key(key: &[u8; 33]) -> bool {
    Secp256k1Verifier
        .validate_public_key(key)
        .is_ok()
}

fn canonical_signature(signature: &[u8], expected_hash_type: u8) -> bool {
    let Ok(signature): Result<&[u8; 65], _> = signature.try_into() else {
        return false;
    };
    if signature[64] != expected_hash_type {
        return false;
    }
    let Some(compact): Option<&[u8; 64]> = signature
        .get(..64)
        .and_then(|compact| compact.try_into().ok())
    else {
        return false;
    };
    Secp256k1Verifier
        .validate_compact_signature(compact)
        .is_ok()
}

fn shakedex_lock_script(public_key: &[u8; 33]) -> [u8; 44] {
    let mut script = [0_u8; 44];
    script[0] = OP_TYPE;
    script[1] = OP_9;
    script[2] = OP_EQUAL;
    script[3] = OP_IF;
    script[4] = 33;
    script[5..38].copy_from_slice(public_key);
    script[38] = OP_CHECKSIG;
    script[39] = OP_ELSE;
    script[40] = OP_TYPE;
    script[41] = OP_10;
    script[42] = OP_EQUAL;
    script[43] = OP_ENDIF;
    script
}

fn htlc_lock_script(descriptor: &HnsHtlcDescriptor) -> Result<Vec<u8>, IndexError> {
    let locktime = encode_script_number(u64::from(descriptor.refund_locktime));
    let mut script = Vec::with_capacity(109_usize.saturating_add(locktime.len()));
    script.extend_from_slice(&[OP_IF, OP_SHA256, 32]);
    script.extend_from_slice(&descriptor.hashlock);
    script.extend_from_slice(&[OP_EQUALVERIFY, 33]);
    script.extend_from_slice(&descriptor.receiver_public_key);
    script.push(OP_ELSE);
    push_minimal_data(&mut script, &locktime)?;
    script.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP, 33]);
    script.extend_from_slice(&descriptor.refund_public_key);
    script.extend_from_slice(&[OP_ENDIF, OP_CHECKSIG]);
    Ok(script)
}

fn encode_script_number(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut encoded = Vec::new();
    while value != 0 {
        encoded.push((value & 0xff) as u8);
        value >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded
}

fn push_minimal_data(script: &mut Vec<u8>, data: &[u8]) -> Result<(), IndexError> {
    match data {
        [] => script.push(OP_0),
        [value] if (1..=16).contains(value) => script.push(OP_1 + value - 1),
        _ if data.len() <= 75 => {
            script.push(u8::try_from(data.len()).map_err(|_| IndexError::InvalidContract)?);
            script.extend_from_slice(data);
        }
        _ => return Err(IndexError::InvalidContract),
    }
    Ok(())
}

fn require_contract_profile(profile: WalletIndexProfile) -> Result<(), IndexError> {
    if profile.wallet {
        Ok(())
    } else {
        Err(IndexError::Disabled("tracked-contract"))
    }
}

fn validate_page_limit(limit: usize) -> Result<(), IndexError> {
    if (1..=MAX_QUERY_ENTRIES).contains(&limit) {
        Ok(())
    } else {
        Err(IndexError::InvalidLimit)
    }
}

fn validate_cursor(
    prefix: &[u8],
    cursor: Option<&TrackedContractCursor>,
) -> Result<(), IndexError> {
    if cursor.is_some_and(|cursor| !cursor.key.starts_with(prefix)) {
        Err(IndexError::Corrupt(
            "tracked contract continuation belongs to another query",
        ))
    } else {
        Ok(())
    }
}

fn validate_registry_prefix<S: ReadSnapshot>(
    snapshot: &S,
    prefix: &[u8],
    mut validate: impl FnMut(&[u8], &[u8]) -> Result<(), IndexError>,
) -> Result<u32, IndexError> {
    let mut cursor = None::<Vec<u8>>;
    let mut total = 0_u32;
    loop {
        let page = snapshot.scan_prefix_page(
            ColumnFamily::TxIndex,
            prefix,
            cursor.as_deref(),
            PrefixScanBudget {
                max_entries: MAX_QUERY_ENTRIES,
                max_bytes: MAX_QUERY_BYTES,
            },
        )?;
        for (key, raw) in &page.entries {
            validate(key, raw)?;
            total = total.checked_add(1).ok_or(IndexError::Corrupt(
                "tracked contract registry count overflow",
            ))?;
            if total > MAX_TRACKED_CONTRACTS {
                return Err(IndexError::Corrupt(
                    "tracked contract registry exceeds schema bound",
                ));
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if cursor.as_ref().is_some_and(|previous| previous >= &next) {
            return Err(IndexError::Corrupt(
                "tracked contract registry continuation did not advance",
            ));
        }
        cursor = Some(next);
    }
    Ok(total)
}

fn ensure_registration<S: ReadSnapshot>(
    snapshot: &S,
    id: ContractId,
) -> Result<ContractRegistration, IndexError> {
    load_registration(snapshot, id)?.ok_or(IndexError::UnknownContract)
}

fn load_registration<S: ReadSnapshot>(
    snapshot: &S,
    id: ContractId,
) -> Result<Option<ContractRegistration>, IndexError> {
    let key = registration_key(id);
    snapshot
        .get(ColumnFamily::TxIndex, &key)?
        .as_deref()
        .map(|raw| {
            let registration: ContractRegistration =
                decode_record(b"contract-registration-v1", &key, raw)?;
            registration.validate()?;
            if registration.id != id {
                return Err(IndexError::Corrupt(
                    "tracked contract registration key/value binding mismatch",
                ));
            }
            Ok(registration)
        })
        .transpose()
}

fn matching_contract_for_output<S: ReadSnapshot>(
    snapshot: &S,
    output: &Output,
) -> Result<Option<ContractRegistration>, IndexError> {
    let key = address_key(&output.address);
    let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? else {
        return Ok(None);
    };
    let mut matched = None;
    for id in decode_address_bindings(&key, &raw)? {
        let registration = load_registration(snapshot, id)?.ok_or(IndexError::Corrupt(
            "tracked contract address points to missing registration",
        ))?;
        if registration.funding_address()? != output.address {
            return Err(IndexError::Corrupt(
                "tracked contract address binding disagrees with registration",
            ));
        }
        if registration.matches_funding_output(output)? {
            if matched.is_some() {
                return Err(IndexError::Corrupt(
                    "multiple tracked contract descriptors match one funding output",
                ));
            }
            matched = Some(registration);
        }
    }
    Ok(matched)
}

fn put_funding<B: WriteBatch>(
    batch: &mut B,
    funding: &TrackedContractFunding,
) -> Result<(), IndexError> {
    let key = funding_key(funding.contract_id, &funding.coin.outpoint);
    batch.put(
        ColumnFamily::TxIndex,
        &key,
        &encode_record(b"contract-funding-v1", &key, funding)?,
    )?;
    Ok(())
}

fn load_funding<S: ReadSnapshot>(
    snapshot: &S,
    id: ContractId,
    outpoint: &Outpoint,
) -> Result<Option<TrackedContractFunding>, IndexError> {
    let key = funding_key(id, outpoint);
    snapshot
        .get(ColumnFamily::TxIndex, &key)?
        .as_deref()
        .map(|raw| decode_funding(id, &key, raw))
        .transpose()
}

fn decode_funding(
    id: ContractId,
    key: &[u8],
    raw: &[u8],
) -> Result<TrackedContractFunding, IndexError> {
    let funding: TrackedContractFunding = decode_record(b"contract-funding-v1", key, raw)?;
    if funding.contract_id != id || funding_key(id, &funding.coin.outpoint) != key {
        return Err(IndexError::Corrupt(
            "tracked contract funding key/value binding mismatch",
        ));
    }
    Ok(funding)
}

fn put_event<B: WriteBatch>(
    batch: &mut B,
    event: &TrackedContractEvent,
) -> Result<(), IndexError> {
    let key = event.key();
    let stored = StoredTrackedContractEvent::from(event);
    batch.put(
        ColumnFamily::TxIndex,
        &key,
        &encode_record(b"contract-event-v1", &key, &stored)?,
    )?;
    Ok(())
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

fn registration_key(id: ContractId) -> Vec<u8> {
    prefixed_id(REGISTRATION_PREFIX, id)
}

fn address_key(address: &Address) -> Vec<u8> {
    let mut writer = Writer::with_capacity(ADDRESS_PREFIX.len() + 42);
    writer.write_bytes(ADDRESS_PREFIX);
    address.write_to(&mut writer);
    writer.finish()
}

fn funding_prefix(id: ContractId) -> Vec<u8> {
    prefixed_id(FUNDING_PREFIX, id)
}

fn funding_key(id: ContractId, outpoint: &Outpoint) -> Vec<u8> {
    let mut key = funding_prefix(id);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.index.to_be_bytes());
    key
}

fn event_prefix(id: ContractId) -> Vec<u8> {
    prefixed_id(EVENT_PREFIX, id)
}

fn event_key(
    id: ContractId,
    height: Height,
    transaction_position: u32,
    event_kind: u8,
    item_position: u32,
    txid: Txid,
) -> Vec<u8> {
    let mut key = event_prefix(id);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&transaction_position.to_be_bytes());
    key.push(event_kind);
    key.extend_from_slice(&item_position.to_be_bytes());
    key.extend_from_slice(txid.as_bytes());
    key
}

fn prefixed_id(prefix: &[u8], id: ContractId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn encode_record<T: Serialize>(
    domain: &[u8],
    key: &[u8],
    value: &T,
) -> Result<Vec<u8>, IndexError> {
    let body = serde_json::to_vec(value)
        .map_err(|_| IndexError::Corrupt("tracked contract serialization failed"))?;
    let mut raw = Vec::with_capacity(1 + body.len() + CHECKSUM_BYTES);
    raw.push(RECORD_VERSION);
    raw.extend_from_slice(&body);
    raw.extend_from_slice(&bound_checksum(domain, key, &raw));
    Ok(raw)
}

fn decode_record<T: DeserializeOwned>(
    domain: &[u8],
    key: &[u8],
    raw: &[u8],
) -> Result<T, IndexError> {
    if raw.len() <= 1 + CHECKSUM_BYTES || raw.first().copied() != Some(RECORD_VERSION) {
        return Err(IndexError::Corrupt("invalid tracked contract record"));
    }
    let body_len = raw
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or(IndexError::Corrupt("invalid tracked contract record"))?;
    let (body, checksum) = raw.split_at(body_len);
    if checksum != bound_checksum(domain, key, body).as_slice() {
        return Err(IndexError::Corrupt(
            "invalid tracked contract record checksum",
        ));
    }
    serde_json::from_slice(
        body.get(1..)
            .ok_or(IndexError::Corrupt("invalid tracked contract record"))?,
    )
    .map_err(|_| IndexError::Corrupt("invalid tracked contract record payload"))
}

fn encode_address_bindings(key: &[u8], ids: &[ContractId]) -> Result<Vec<u8>, IndexError> {
    if ids.is_empty()
        || ids.len() > MAX_TRACKED_CONTRACTS_PER_ADDRESS
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(IndexError::Corrupt(
            "invalid tracked contract address candidate set",
        ));
    }
    let count = u16::try_from(ids.len()).map_err(|_| IndexError::ContractAddressCapacity)?;
    let mut raw = Vec::with_capacity(
        ADDRESS_BINDING_HEADER_BYTES + ids.len().saturating_mul(32) + CHECKSUM_BYTES,
    );
    raw.push(RECORD_VERSION);
    raw.extend_from_slice(&count.to_be_bytes());
    for id in ids {
        raw.extend_from_slice(id.as_bytes());
    }
    raw.extend_from_slice(&bound_checksum(b"contract-address-v1", key, &raw));
    Ok(raw)
}

fn decode_address_bindings(key: &[u8], raw: &[u8]) -> Result<Vec<ContractId>, IndexError> {
    if raw.len() < ADDRESS_BINDING_HEADER_BYTES + 32 + CHECKSUM_BYTES
        || raw.first().copied() != Some(RECORD_VERSION)
    {
        return Err(IndexError::Corrupt("invalid contract address binding"));
    }
    let count = usize::from(u16::from_be_bytes(
        raw.get(1..ADDRESS_BINDING_HEADER_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(IndexError::Corrupt("invalid contract address binding"))?,
    ));
    if count == 0 || count > MAX_TRACKED_CONTRACTS_PER_ADDRESS {
        return Err(IndexError::Corrupt(
            "invalid tracked contract address candidate count",
        ));
    }
    let body_len = ADDRESS_BINDING_HEADER_BYTES
        .checked_add(count.checked_mul(32).ok_or(IndexError::Corrupt(
            "tracked contract address candidate length overflow",
        ))?)
        .ok_or(IndexError::Corrupt(
            "tracked contract address candidate length overflow",
        ))?;
    if raw.len() != body_len + CHECKSUM_BYTES {
        return Err(IndexError::Corrupt("invalid contract address binding"));
    }
    let (body, checksum) = raw.split_at(body_len);
    if checksum != bound_checksum(b"contract-address-v1", key, body).as_slice() {
        return Err(IndexError::Corrupt(
            "invalid contract address binding checksum",
        ));
    }
    let ids = body
        .get(ADDRESS_BINDING_HEADER_BYTES..)
        .ok_or(IndexError::Corrupt("invalid contract address binding"))?
        .chunks_exact(32)
        .map(|bytes| {
            let id: [u8; 32] = bytes
                .try_into()
                .map_err(|_| IndexError::Corrupt("invalid contract address identity"))?;
            Ok(ContractId(id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(IndexError::Corrupt(
            "tracked contract address candidates are not sorted and unique",
        ));
    }
    Ok(ids)
}

fn encode_registration_count(count: u32) -> Vec<u8> {
    let mut raw = Vec::with_capacity(1 + 4 + CHECKSUM_BYTES);
    raw.push(RECORD_VERSION);
    raw.extend_from_slice(&count.to_le_bytes());
    raw.extend_from_slice(&bound_checksum(
        b"contract-count-v1",
        REGISTRATION_COUNT_KEY,
        &raw,
    ));
    raw
}

fn decode_registration_count(raw: &[u8]) -> Result<u32, IndexError> {
    if raw.len() != 1 + 4 + CHECKSUM_BYTES || raw.first().copied() != Some(RECORD_VERSION) {
        return Err(IndexError::Corrupt("invalid tracked contract count"));
    }
    let (body, checksum) = raw.split_at(5);
    if checksum
        != bound_checksum(b"contract-count-v1", REGISTRATION_COUNT_KEY, body).as_slice()
    {
        return Err(IndexError::Corrupt(
            "invalid tracked contract count checksum",
        ));
    }
    Ok(u32::from_le_bytes(
        body.get(1..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(IndexError::Corrupt("invalid tracked contract count"))?,
    ))
}

fn bound_checksum(domain: &[u8], key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut writer = Writer::with_capacity(domain.len() + key.len() + value.len() + 24);
    writer.write_varbytes(domain);
    writer.write_varbytes(key);
    writer.write_varbytes(value);
    blake2b_256(&writer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{hex_encode, Covenant, Header, Input, Witness};
    use hns_state::{write_coin_to_batch, TreeRoot};
    use hns_store::{MemoryStore, Store};

    const GENERATOR_KEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
        0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
        0x5b, 0x16, 0xf8, 0x17, 0x98,
    ];

    fn alternate_generator_key() -> [u8; 33] {
        let mut key = GENERATOR_KEY;
        key[0] = 3;
        key
    }

    fn low_s_signature(hash_type: u8) -> Vec<u8> {
        let mut signature = vec![1; 65];
        signature[64] = hash_type;
        signature
    }

    fn profile() -> WalletIndexProfile {
        WalletIndexProfile {
            wallet: true,
            ..WalletIndexProfile::default()
        }
    }

    fn htlc(preimage: [u8; 32]) -> ContractRegistration {
        ContractRegistration::hns_htlc_v1(HnsHtlcDescriptor {
            value: 50,
            hashlock: Sha256::digest(preimage).into(),
            receiver_public_key: GENERATOR_KEY,
            refund_public_key: alternate_generator_key(),
            refund_locktime: 500,
        })
        .expect("HTLC registration")
    }

    fn block(transactions: Vec<Transaction>) -> Block {
        Block {
            header: Header::default(),
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

    #[test]
    fn htlc_registration_funding_redeem_disconnect_and_restart_reads_are_exact() {
        let store = MemoryStore::new();
        let preimage = [9; 32];
        let registration = htlc(preimage);
        let snapshot = store.snapshot().expect("snapshot");
        let mut register = store.batch();
        assert_eq!(
            register_tracked_contract(&snapshot, &mut register, profile(), &registration)
                .expect("register"),
            ContractRegistrationOutcome::Registered
        );
        drop(snapshot);
        store.commit(register).expect("commit registration");

        let funding_transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 50,
                address: registration.funding_address().expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        let funding_block = block(vec![funding_transaction.clone()]);
        let snapshot = store.snapshot().expect("snapshot");
        let mut connect = store.batch();
        stage_connect(&snapshot, &mut connect, &funding_block, 10, profile())
            .expect("funding connect");
        drop(snapshot);
        store.commit(connect).expect("funding commit");

        let funding = Coin {
            outpoint: Outpoint {
                txid: funding_transaction.txid(),
                index: 0,
            },
            value: 50,
            height: 10,
            coinbase: true,
            address: registration.funding_address().expect("address"),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let mut state = store.batch();
        write_coin_to_batch(&mut state, &funding).expect("seed UTXO");
        store.commit(state).expect("commit UTXO");

        let script = registration.lock_script().expect("script");
        let spending_transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: funding.outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![
                        low_s_signature(HNS_HTLC_SIGHASH_ALL),
                        preimage.to_vec(),
                        vec![1],
                        script,
                    ],
                },
            }],
            outputs: Vec::new(),
            locktime: 0,
        };
        let spending_block = block(vec![spending_transaction]);
        let snapshot = store.snapshot().expect("snapshot");
        let mut spend = store.batch();
        stage_connect(&snapshot, &mut spend, &spending_block, 11, profile())
            .expect("spend connect");
        drop(snapshot);
        store.commit(spend).expect("spend commit");

        let snapshot = store.snapshot().expect("restart snapshot");
        assert_eq!(
            tracked_contract(&snapshot, profile(), registration.id).expect("contract"),
            Some(registration.clone())
        );
        assert!(tracked_contract_fundings(&snapshot, profile(), registration.id, None, 8)
            .expect("fundings")
            .entries
            .is_empty());
        let events = tracked_contract_events(&snapshot, profile(), registration.id, None, 8)
            .expect("events");
        assert_eq!(events.entries.len(), 2);
        let TrackedContractEvent::Spend { kind, .. } = &events.entries[1] else {
            panic!("second event must be spend");
        };
        let TrackedContractSpendKind::HtlcRedemption { preimage: observed } = kind else {
            panic!("spend must be redemption");
        };
        assert_eq!(observed.expose_for_settlement(), &preimage);

        let mut disconnect = store.batch();
        stage_disconnect(
            &snapshot,
            &mut disconnect,
            &spending_block,
            &undo(&spending_block, 11, vec![funding.clone()]),
            profile(),
        )
        .expect("spend disconnect");
        drop(snapshot);
        store.commit(disconnect).expect("disconnect commit");
        let snapshot = store.snapshot().expect("restored snapshot");
        assert_eq!(
            tracked_contract_fundings(&snapshot, profile(), registration.id, None, 8)
                .expect("restored funding")
                .entries[0]
                .coin,
            funding
        );
        assert_eq!(
            tracked_contract_events(&snapshot, profile(), registration.id, None, 8)
                .expect("restored events")
                .entries
                .len(),
            1
        );
        drop(snapshot);

        // An optional derivative index must not strengthen consensus. A spend
        // outside the pinned wallet profile is recorded without a preimage
        // instead of rejecting canonical block connection.
        let unrecognized_spend = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: funding.outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![
                        low_s_signature(HIP1_SELLER_FULFILLMENT_SIGHASH),
                        preimage.to_vec(),
                        vec![1],
                        registration.lock_script().expect("script"),
                    ],
                },
            }],
            outputs: Vec::new(),
            locktime: 0,
        };
        let unrecognized_block = block(vec![unrecognized_spend]);
        let snapshot = store.snapshot().expect("unrecognized snapshot");
        let mut unrecognized = store.batch();
        stage_connect(
            &snapshot,
            &mut unrecognized,
            &unrecognized_block,
            12,
            profile(),
        )
        .expect("non-profile spend must not reject block indexing");
        drop(snapshot);
        store.commit(unrecognized).expect("unrecognized commit");
        let snapshot = store.snapshot().expect("unrecognized read");
        let events = tracked_contract_events(&snapshot, profile(), registration.id, None, 8)
            .expect("unrecognized events");
        assert!(matches!(
            events.entries.last(),
            Some(TrackedContractEvent::Spend {
                kind: TrackedContractSpendKind::Unrecognized,
                ..
            })
        ));
    }

    #[test]
    fn ordinary_same_block_children_do_not_make_the_optional_index_reject_a_block() {
        let store = MemoryStore::new();
        let parent = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 25,
                address: Address::new(0, vec![7; 20]).expect("ordinary address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        let child = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: parent.txid(),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: Vec::new(),
            locktime: 0,
        };
        let snapshot = store.snapshot().expect("pre-block snapshot");
        let mut batch = store.batch();
        stage_connect(&snapshot, &mut batch, &block(vec![parent, child]), 1, profile())
            .expect("an untracked same-block child cannot strengthen consensus");
    }

    #[test]
    fn preimage_debug_and_cross_contract_cursor_do_not_disclose_or_cross_queries() {
        let secret = RevealedPreimage([0x5a; 32]);
        assert_eq!(format!("{secret:?}"), "RevealedPreimage([REDACTED])");
        assert!(!format!("{secret:?}").contains("5a"));
        let public_kind = TrackedContractSpendKind::HtlcRedemption {
            preimage: secret.clone(),
        };
        let public_json = serde_json::to_string(&public_kind).expect("public serialization");
        assert!(public_json.contains("[REDACTED]"));
        assert!(!public_json.contains("90"));
        assert!(serde_json::from_str::<TrackedContractSpendKind>(&public_json).is_err());

        let stored_kind = StoredTrackedContractSpendKind::from(&public_kind);
        let stored_json = serde_json::to_string(&stored_kind).expect("internal serialization");
        let restored_kind: TrackedContractSpendKind =
            serde_json::from_str::<StoredTrackedContractSpendKind>(&stored_json)
                .expect("internal deserialization")
                .into();
        let TrackedContractSpendKind::HtlcRedemption { preimage } = restored_kind else {
            panic!("internal stored branch changed");
        };
        assert_eq!(preimage.expose_for_settlement(), &[0x5a; 32]);

        let first = htlc([1; 32]);
        let second = htlc([2; 32]);
        let cursor = TrackedContractCursor {
            key: event_prefix(first.id),
        };
        assert!(matches!(
            validate_cursor(&event_prefix(second.id), Some(&cursor)),
            Err(IndexError::Corrupt(_))
        ));
    }

    #[test]
    fn registry_checksum_corruption_fails_point_and_startup_reads() {
        let store = MemoryStore::new();
        let registration = htlc([3; 32]);
        let snapshot = store.snapshot().expect("snapshot");
        let mut registration_batch = store.batch();
        register_tracked_contract(
            &snapshot,
            &mut registration_batch,
            profile(),
            &registration,
        )
        .expect("registration");
        drop(snapshot);
        store
            .commit(registration_batch)
            .expect("registration commit");

        let key = registration_key(registration.id);
        let snapshot = store.snapshot().expect("registered snapshot");
        let mut raw = snapshot
            .get(ColumnFamily::TxIndex, &key)
            .expect("registration read")
            .expect("registration value");
        drop(snapshot);
        raw[CHECKSUM_BYTES] ^= 1;
        let mut corruption = store.batch();
        corruption
            .put(ColumnFamily::TxIndex, &key, &raw)
            .expect("stage corruption");
        store.commit(corruption).expect("commit corruption");

        let snapshot = store.snapshot().expect("corrupt snapshot");
        assert!(matches!(
            tracked_contract(&snapshot, profile(), registration.id),
            Err(IndexError::Corrupt(_))
        ));
        assert!(matches!(
            validate_tracked_contract_registry(&snapshot, profile()),
            Err(IndexError::Corrupt(_))
        ));
    }

    #[test]
    fn one_address_tracks_multiple_bounded_exact_descriptor_candidates() {
        let store = MemoryStore::new();
        let first = htlc([6; 32]);
        let TrackedContractKind::HnsHtlcV1(mut second_descriptor) = first.kind.clone() else {
            panic!("HTLC fixture kind");
        };
        second_descriptor.value = 75;
        let second = ContractRegistration::hns_htlc_v1(second_descriptor)
            .expect("second registration");
        assert_ne!(first.id, second.id);
        assert_eq!(
            first.funding_address().expect("first address"),
            second.funding_address().expect("second address")
        );

        for registration in [&first, &second] {
            let snapshot = store.snapshot().expect("registration snapshot");
            let mut batch = store.batch();
            assert_eq!(
                register_tracked_contract(&snapshot, &mut batch, profile(), registration)
                    .expect("shared-address registration"),
                ContractRegistrationOutcome::Registered
            );
            drop(snapshot);
            store.commit(batch).expect("registration commit");
        }
        let snapshot = store.snapshot().expect("registry snapshot");
        validate_tracked_contract_registry(&snapshot, profile()).expect("shared-address registry");
        let address = second.funding_address().expect("funding address");
        let bindings = decode_address_bindings(
            &address_key(&address),
            &snapshot
                .get(ColumnFamily::TxIndex, &address_key(&address))
                .expect("binding read")
                .expect("binding"),
        )
        .expect("binding decode");
        assert_eq!(bindings.len(), 2);

        let funding = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 75,
                address,
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        let funding_block = block(vec![funding]);
        let mut batch = store.batch();
        stage_connect(&snapshot, &mut batch, &funding_block, 20, profile())
            .expect("exact candidate connect");
        drop(snapshot);
        store.commit(batch).expect("funding commit");
        let snapshot = store.snapshot().expect("funding snapshot");
        assert!(tracked_contract_events(&snapshot, profile(), first.id, None, 8)
            .expect("first events")
            .entries
            .is_empty());
        assert_eq!(
            tracked_contract_events(&snapshot, profile(), second.id, None, 8)
                .expect("second events")
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn per_address_candidate_cap_rejects_amplification() {
        let store = MemoryStore::new();
        let registration = htlc([7; 32]);
        let key = address_key(&registration.funding_address().expect("address"));
        let candidates = (0..MAX_TRACKED_CONTRACTS_PER_ADDRESS)
            .map(|index| {
                let mut id = [0_u8; 32];
                id[30..].copy_from_slice(
                    &u16::try_from(index).expect("bounded candidate index").to_be_bytes(),
                );
                ContractId(id)
            })
            .collect::<Vec<_>>();
        let mut seed = store.batch();
        seed.put(
            ColumnFamily::TxIndex,
            &key,
            &encode_address_bindings(&key, &candidates).expect("bounded candidate encoding"),
        )
        .expect("seed candidates");
        store.commit(seed).expect("candidate commit");
        let snapshot = store.snapshot().expect("candidate snapshot");
        let mut batch = store.batch();
        assert!(matches!(
            register_tracked_contract(&snapshot, &mut batch, profile(), &registration),
            Err(IndexError::ContractAddressCapacity)
        ));
    }

    #[test]
    fn shakedex_and_htlc_supported_branches_are_descriptor_bound() {
        let shakedex = ContractRegistration::shakedex_v2(ShakedexV2Descriptor {
            name_hash: [4; 32],
            seller_public_key: GENERATOR_KEY,
            value: 42,
        })
        .expect("Shakedex registration");
        let shakedex_coin = Coin {
            outpoint: Outpoint {
                txid: Txid::new([4; 32]),
                index: 0,
            },
            value: 42,
            height: 10,
            coinbase: false,
            address: shakedex.funding_address().expect("Shakedex address"),
            covenant: Covenant {
                kind: CovenantKind::Finalize,
                items: vec![vec![4; 32]],
            },
        };
        let shakedex_script = shakedex.lock_script().expect("Shakedex script");
        let fulfillment = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: shakedex_coin.outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![
                        low_s_signature(HIP1_SELLER_FULFILLMENT_SIGHASH),
                        shakedex_script.clone(),
                    ],
                },
            }],
            outputs: vec![Output {
                value: 42,
                address: Address::new(0, vec![1; 32]).expect("output address"),
                covenant: Covenant {
                    kind: CovenantKind::Transfer,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        assert_eq!(
            shakedex
                .classify_spend(&fulfillment, 0, &shakedex_coin)
                .expect("fulfillment"),
            TrackedContractSpendKind::ShakedexFulfillment
        );

        let mut recovery = fulfillment.clone();
        recovery.inputs[0].witness.items[0] =
            low_s_signature(HIP1_SELLER_RECOVERY_SIGHASH);
        assert_eq!(
            shakedex
                .classify_spend(&recovery, 0, &shakedex_coin)
                .expect("recovery"),
            TrackedContractSpendKind::ShakedexRecovery
        );

        let mut invented_direct_finalize = fulfillment.clone();
        invented_direct_finalize.inputs[0].witness.items = vec![shakedex_script];
        invented_direct_finalize.outputs[0].covenant.kind = CovenantKind::Finalize;
        assert_eq!(
            shakedex
                .classify_spend(&invented_direct_finalize, 0, &shakedex_coin)
                .expect("direct FINALIZE shape"),
            TrackedContractSpendKind::Unrecognized
        );

        let htlc = htlc([5; 32]);
        let htlc_coin = Coin {
            outpoint: Outpoint {
                txid: Txid::new([5; 32]),
                index: 0,
            },
            value: 50,
            height: 11,
            coinbase: false,
            address: htlc.funding_address().expect("HTLC address"),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let refund = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: htlc_coin.outpoint.clone(),
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![
                        low_s_signature(HNS_HTLC_SIGHASH_ALL),
                        Vec::new(),
                        htlc.lock_script().expect("HTLC script"),
                    ],
                },
            }],
            outputs: Vec::new(),
            locktime: 500,
        };
        assert_eq!(
            htlc.classify_spend(&refund, 0, &htlc_coin)
                .expect("refund"),
            TrackedContractSpendKind::HtlcRefund
        );
    }

    #[test]
    fn canonical_hns_rs_script_and_descriptor_vectors_are_stable() {
        let registration = htlc([9; 32]);
        assert_eq!(
            hex_encode(&registration.lock_script().expect("HTLC script")),
            "63a8208c0cc17a04942cc4f8e0fe0b302606d3108860c126428ba2ceeb5f9ed41c2b0588210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986702f401b175210379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179868ac"
        );
        assert_eq!(
            hex_encode(&registration.funding_address().expect("HTLC address").hash),
            "ed7855dd956284eb9b2907b2d4d7b2b093eb240b96fa0a48f60b4b044e4f4bc1"
        );
        assert_eq!(
            hex_encode(registration.id.as_bytes()),
            "8a9211ce1e65b45dca793f18c564ef71afc111ea40ce35d7824dfdab7a91d659"
        );
        assert_eq!(
            hex_encode(&canonical_contract_identity(&registration.kind)),
            "686e732d77616c6c65742d696e6465782f636f6e74726163742d6964010200000000000000328c0cc17a04942cc4f8e0fe0b302606d3108860c126428ba2ceeb5f9ed41c2b050279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798000001f4"
        );

        let shakedex = ContractRegistration::shakedex_v2(ShakedexV2Descriptor {
            name_hash: [1; 32],
            seller_public_key: GENERATOR_KEY,
            value: 42,
        })
        .expect("Shakedex registration");
        assert_eq!(
            hex_encode(&shakedex.lock_script().expect("Shakedex script")),
            "d0598763210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac67d05a8768"
        );
        assert_eq!(
            hex_encode(&shakedex.funding_address().expect("Shakedex address").hash),
            "92d36bbd3068288e42234ada1a37fab2a989a3283337b1b434cfc94cd2879f35"
        );
        assert_eq!(
            hex_encode(shakedex.id.as_bytes()),
            "019b8754adf9acf305d8e845ea72c31db964feeae36148bb508a6841a1332d60"
        );
        assert_eq!(
            hex_encode(&canonical_contract_identity(&shakedex.kind)),
            "686e732d77616c6c65742d696e6465782f636f6e74726163742d6964010101010101010101010101010101010101010101010101010101010101010101010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798000000000000002a"
        );
    }

    #[test]
    fn noncurve_keys_zero_locktimes_and_noncanonical_signatures_fail_closed() {
        let mut invalid_key = GENERATOR_KEY;
        invalid_key[1..].fill(0xff);
        assert!(matches!(
            ContractRegistration::hns_htlc_v1(HnsHtlcDescriptor {
                value: 1,
                hashlock: [1; 32],
                receiver_public_key: invalid_key,
                refund_public_key: alternate_generator_key(),
                refund_locktime: 1,
            }),
            Err(IndexError::InvalidContract)
        ));
        assert!(matches!(
            ContractRegistration::hns_htlc_v1(HnsHtlcDescriptor {
                value: 1,
                hashlock: [1; 32],
                receiver_public_key: GENERATOR_KEY,
                refund_public_key: alternate_generator_key(),
                refund_locktime: 0x8000_0000,
            }),
            Err(IndexError::InvalidContract)
        ));

        let htlc_signature = low_s_signature(HNS_HTLC_SIGHASH_ALL);
        assert!(canonical_signature(
            &htlc_signature,
            HNS_HTLC_SIGHASH_ALL
        ));
        assert!(!canonical_signature(
            &htlc_signature,
            HIP1_SELLER_FULFILLMENT_SIGHASH
        ));
        let shakedex_signature = low_s_signature(HIP1_SELLER_FULFILLMENT_SIGHASH);
        assert!(canonical_signature(
            &shakedex_signature,
            HIP1_SELLER_FULFILLMENT_SIGHASH
        ));
        let recovery_signature = low_s_signature(HIP1_SELLER_RECOVERY_SIGHASH);
        assert!(canonical_signature(
            &recovery_signature,
            HIP1_SELLER_RECOVERY_SIGHASH
        ));
        let mut malformed = vec![0xff; 65];
        malformed[64] = HNS_HTLC_SIGHASH_ALL;
        assert!(!canonical_signature(
            &malformed,
            HNS_HTLC_SIGHASH_ALL
        ));
    }
}
