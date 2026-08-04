//! Durable, active-chain tracking for registered Shakedex and HNS HTLC locks.
//!
//! Registrations contain public transaction terms only. They are immutable,
//! bounded, and must be committed before broadcasting a funding transaction.
//! Confirmed funding/spend events are written in the canonical block batch and
//! are therefore recovered on restart and reversed exactly with a reorg.

use std::collections::{HashMap, HashSet};

use hns_primitives::{
    blake2b_256, sha3_256, Address, Block, BlockHash, Coin, CovenantKind, Height, Outpoint, Output,
    Transaction, Txid, Writer,
};
use hns_secp256k1::Secp256k1Verifier;
use hns_state::{decode_coin, encode_outpoint_key, BlockUndo};
use hns_store::{ColumnFamily, PrefixScanBudget, ReadSnapshot, WriteBatch};
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{IndexError, WalletIndexProfile, MAX_QUERY_BYTES, MAX_QUERY_ENTRIES};

mod serde_compressed_public_key {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(key: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| D::Error::invalid_length(bytes.len(), &"33 bytes"))
    }
}

/// Maximum active public contract registrations in one node store.
pub const MAX_TRACKED_CONTRACTS: u32 = 16_384;
/// Maximum active public descriptors sharing one script address.
pub const MAX_TRACKED_CONTRACTS_PER_ADDRESS: usize = 256;
/// Maximum durable completed-contract retirement proofs in one node store.
///
/// Retirements are deliberately irreversible and never garbage-collected:
/// this independent bound keeps their restart validation and storage cost
/// finite without reusing an already-consumed descriptor identity.
pub const MAX_RETIRED_TRACKED_CONTRACTS: u32 = 65_536;
/// Maximum confirmed rows which one completed-contract retirement may consume.
pub const MAX_TRACKED_CONTRACT_RETIREMENT_EVENTS: u32 = 4_096;

const REGISTRATION_PREFIX: &[u8] = b"wallet-index/v1/contract/registration/";
const ADDRESS_PREFIX: &[u8] = b"wallet-index/v1/contract/address/";
const OBSERVATION_PREFIX: &[u8] = b"wallet-index/v1/contract/observation/";
const FUNDING_PREFIX: &[u8] = b"wallet-index/v1/contract/funding/";
const EVENT_PREFIX: &[u8] = b"wallet-index/v1/contract/event/";
const RETIREMENT_PREFIX: &[u8] = b"wallet-index/v1/contract/retirement/";
const REGISTRATION_COUNT_KEY: &[u8] = b"wallet-index/v1/contract/count";
const RETIREMENT_COUNT_KEY: &[u8] = b"wallet-index/v1/contract/retirement-count";
const LIFECYCLE_SEQUENCE_KEY: &[u8] = b"wallet-index/v1/contract/lifecycle-sequence";
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
const RETIRED_EVENT_COMMITMENT_DOMAIN: &[u8] = b"hns-wallet-index/completed-retirement-events-v1";
const CONTRACT_ID_ENCODING_VERSION: u8 = 1;
const SHAKEDEX_V2_CONTRACT_TAG: u8 = 1;
const HNS_HTLC_V1_CONTRACT_TAG: u8 = 2;

// The exact script opcodes used by hns-rs Shakedex-v2 and HNS-HTLC-v1.
const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
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
    /// Construct an identity from its stable raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

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
    #[serde(with = "serde_compressed_public_key")]
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
    #[serde(with = "serde_compressed_public_key")]
    pub receiver_public_key: [u8; 33],
    /// Refund key for the absolute-timelock branch.
    #[serde(with = "serde_compressed_public_key")]
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
        let input = transaction
            .inputs
            .get(input_position)
            .ok_or(IndexError::Corrupt(
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
            TrackedContractKind::HnsHtlcV1(descriptor) => match input.witness.items.as_slice() {
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
            },
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

/// Result of an idempotent never-confirmed registration retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractRetirementOutcome {
    /// The never-confirmed registration and its active capacity were removed.
    Retired,
    /// The exact registration was already absent.
    AlreadyAbsent,
}

/// Result of an idempotent completed-contract retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CompletedContractRetirementOutcome {
    /// The completed active lifecycle became an immutable retirement proof.
    Retired,
    /// The exact lifecycle was already retired with the same public terms.
    AlreadyRetired,
}

/// Exact durable undo-retirement boundary authorizing completed retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractRollbackBoundary {
    /// Last canonical height whose undo has been irreversibly retired.
    pub pruned_through: Height,
    /// Canonical block at `pruned_through` when the proof was committed.
    pub block_hash: BlockHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ContractObservationState {
    // Existing v1 registrations predate authoritative observation state. They
    // remain readable but can never be treated as never confirmed.
    LegacyUnknown,
    NeverConfirmed,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ContractObservationRecord {
    contract_id: ContractId,
    lifecycle_revision: u64,
    state: ContractObservationState,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// Immutable proof that one exact, previously confirmed descriptor lifecycle
/// was retired only after its complete active-chain history became
/// non-rollbackable by this node store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletedContractRetirement {
    /// Original immutable public registration. The consumed ID is never reused.
    pub registration: ContractRegistration,
    /// Exact monotonic lifecycle revision consumed by this transition.
    pub lifecycle_revision: u64,
    /// Number of confirmed funding/spend rows consumed atomically.
    pub confirmed_event_count: u32,
    /// Lowest consumed canonical event height.
    pub minimum_event_height: Height,
    /// Highest consumed canonical event height.
    pub maximum_event_height: Height,
    /// SHA-256 commitment to the exact ordered event keys and stored bytes.
    pub ordered_event_commitment: [u8; 32],
    /// Last confirmed row, necessarily an exact terminal spend.
    pub terminal_event: TrackedContractEvent,
    /// Settlement-sensitive preimages retained from every consumed redemption.
    pub revealed_preimages: Vec<RetiredRevealedPreimage>,
    /// Undo-pruning checkpoint which made every consumed row irreversible.
    pub rollback_boundary: ContractRollbackBoundary,
    /// Durable acknowledgement that this exact descriptor will never be funded
    /// or registered again after retirement.
    pub permanent_abandonment_acknowledged: bool,
}

/// One internally retained revealed preimage from retired event history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetiredRevealedPreimage {
    /// Funding outpoint consumed by the redemption.
    pub funding_outpoint: Outpoint,
    /// Canonical transaction which revealed the value.
    pub spending_txid: Txid,
    /// Previously public chain value, still redacted by public serde/debug.
    pub preimage: RevealedPreimage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredRetiredRevealedPreimage {
    funding_outpoint: Outpoint,
    spending_txid: Txid,
    preimage: [u8; HNS_HTLC_PREIMAGE_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredCompletedContractRetirement {
    registration: ContractRegistration,
    lifecycle_revision: u64,
    confirmed_event_count: u32,
    minimum_event_height: Height,
    maximum_event_height: Height,
    ordered_event_commitment: [u8; 32],
    terminal_event: StoredTrackedContractEvent,
    revealed_preimages: Vec<StoredRetiredRevealedPreimage>,
    rollback_boundary: ContractRollbackBoundary,
    permanent_abandonment_acknowledged: bool,
}

impl From<StoredCompletedContractRetirement> for CompletedContractRetirement {
    fn from(stored: StoredCompletedContractRetirement) -> Self {
        Self {
            registration: stored.registration,
            lifecycle_revision: stored.lifecycle_revision,
            confirmed_event_count: stored.confirmed_event_count,
            minimum_event_height: stored.minimum_event_height,
            maximum_event_height: stored.maximum_event_height,
            ordered_event_commitment: stored.ordered_event_commitment,
            terminal_event: stored.terminal_event.into(),
            revealed_preimages: stored
                .revealed_preimages
                .into_iter()
                .map(|evidence| RetiredRevealedPreimage {
                    funding_outpoint: evidence.funding_outpoint,
                    spending_txid: evidence.spending_txid,
                    preimage: RevealedPreimage(evidence.preimage),
                })
                .collect(),
            rollback_boundary: stored.rollback_boundary,
            permanent_abandonment_acknowledged: stored.permanent_abandonment_acknowledged,
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
    if let Some(retirement) = load_stored_completed_retirement(snapshot, registration.id)? {
        validate_stored_completed_retirement(snapshot, &retirement, None)?;
        if retirement.registration != *registration {
            return Err(IndexError::Corrupt(
                "retired tracked contract identity disagrees with registration terms",
            ));
        }
        return Err(IndexError::ContractRetired);
    }
    let key = registration_key(registration.id);
    if let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? {
        let stored: ContractRegistration = decode_record(b"contract-registration-v1", &key, &raw)?;
        if stored != *registration {
            return Err(IndexError::Corrupt(
                "tracked contract registration key is occupied by different terms",
            ));
        }
        let binding_key = address_key(&registration.funding_address()?);
        let binding =
            snapshot
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
        if load_observation(snapshot, registration.id)?.is_none() {
            let lifecycle_revision = next_lifecycle_revision(snapshot, batch)?;
            put_observation(
                batch,
                ContractObservationRecord {
                    contract_id: registration.id,
                    lifecycle_revision,
                    state: ContractObservationState::LegacyUnknown,
                },
            )?;
        }
        return Ok(ContractRegistrationOutcome::AlreadyRegistered);
    }

    if snapshot
        .get(ColumnFamily::TxIndex, &observation_key(registration.id))?
        .is_some()
    {
        return Err(IndexError::Corrupt(
            "tracked contract observation exists without registration",
        ));
    }
    if prefix_has_entry(snapshot, &funding_prefix(registration.id))?
        || prefix_has_entry(snapshot, &event_prefix(registration.id))?
    {
        return Err(IndexError::Corrupt(
            "tracked contract history exists without registration",
        ));
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
    let lifecycle_revision = next_lifecycle_revision(snapshot, batch)?;
    batch.put(
        ColumnFamily::TxIndex,
        &key,
        &encode_record(b"contract-registration-v1", &key, registration)?,
    )?;
    put_observation(
        batch,
        ContractObservationRecord {
            contract_id: registration.id,
            lifecycle_revision,
            state: ContractObservationState::NeverConfirmed,
        },
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

/// Read the durable lifecycle revision for one active registration.
pub fn tracked_contract_lifecycle_revision<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    id: ContractId,
) -> Result<Option<u64>, IndexError> {
    require_contract_profile(profile)?;
    if load_registration(snapshot, id)?.is_none() {
        return Ok(None);
    }
    Ok(load_observation(snapshot, id)?.map(|record| record.lifecycle_revision))
}

/// Atomically remove an exact registration only when durable monotonic state
/// proves that no matching funding output has ever been confirmed.
///
/// The caller must also serialize this mutation against mempool changes, prove
/// that the same current accepted ordinary/airdrop generation contains no
/// matching funding and no retained transaction orphans, and durably abandon
/// every broadcast/rebroadcast source for this descriptor. A previously evicted
/// transaction can otherwise confirm after deletion without being tracked.
/// Confirmed funding/event prefixes are checked again here. Legacy registrations
/// without an authoritative confirmation record fail closed.
pub fn retire_never_confirmed_tracked_contract<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
    profile: WalletIndexProfile,
    registration: &ContractRegistration,
    expected_lifecycle_revision: u64,
) -> Result<ContractRetirementOutcome, IndexError> {
    require_contract_profile(profile)?;
    registration.validate()?;
    let key = registration_key(registration.id);
    let Some(raw) = snapshot.get(ColumnFamily::TxIndex, &key)? else {
        if let Some(retirement) = load_stored_completed_retirement(snapshot, registration.id)? {
            validate_stored_completed_retirement(snapshot, &retirement, None)?;
            if retirement.registration != *registration {
                return Err(IndexError::Corrupt(
                    "retired tracked contract identity disagrees with retirement request",
                ));
            }
            return Err(IndexError::ContractRetired);
        }
        if snapshot
            .get(ColumnFamily::TxIndex, &observation_key(registration.id))?
            .is_some()
        {
            return Err(IndexError::Corrupt(
                "tracked contract observation exists without registration",
            ));
        }
        let binding_key = address_key(&registration.funding_address()?);
        if snapshot
            .get(ColumnFamily::TxIndex, &binding_key)?
            .as_deref()
            .map(|raw| decode_address_bindings(&binding_key, raw))
            .transpose()?
            .is_some_and(|ids| ids.binary_search(&registration.id).is_ok())
        {
            return Err(IndexError::Corrupt(
                "tracked contract address binding exists without registration",
            ));
        }
        if prefix_has_entry(snapshot, &funding_prefix(registration.id))?
            || prefix_has_entry(snapshot, &event_prefix(registration.id))?
        {
            return Err(IndexError::Corrupt(
                "tracked contract history exists without registration",
            ));
        }
        return Ok(ContractRetirementOutcome::AlreadyAbsent);
    };
    let stored: ContractRegistration = decode_record(b"contract-registration-v1", &key, &raw)?;
    if stored != *registration {
        return Err(IndexError::Corrupt(
            "tracked contract retirement terms disagree with registration",
        ));
    }

    let observation = load_observation(snapshot, registration.id)?
        .ok_or(IndexError::ContractConfirmationUnknown)?;
    if observation.lifecycle_revision != expected_lifecycle_revision {
        return Err(IndexError::StaleContractLifecycle {
            expected: expected_lifecycle_revision,
            actual: observation.lifecycle_revision,
        });
    }
    match observation.state {
        ContractObservationState::NeverConfirmed => {}
        ContractObservationState::LegacyUnknown => {
            return Err(IndexError::ContractConfirmationUnknown);
        }
        ContractObservationState::Confirmed => return Err(IndexError::ContractConfirmed),
    }
    if prefix_has_entry(snapshot, &funding_prefix(registration.id))?
        || prefix_has_entry(snapshot, &event_prefix(registration.id))?
    {
        return Err(IndexError::ContractConfirmed);
    }

    let binding_key = address_key(&registration.funding_address()?);
    let binding = snapshot
        .get(ColumnFamily::TxIndex, &binding_key)?
        .ok_or(IndexError::Corrupt(
            "tracked contract registration has no address binding",
        ))?;
    let mut ids = decode_address_bindings(&binding_key, &binding)?;
    let position = ids
        .binary_search(&registration.id)
        .map_err(|_| IndexError::Corrupt("tracked contract address binding mismatch"))?;
    ids.remove(position);
    let count = snapshot
        .get(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)?
        .as_deref()
        .map(decode_registration_count)
        .transpose()?
        .ok_or(IndexError::Corrupt(
            "tracked contract count is absent while registry is non-empty",
        ))?;
    let next = count.checked_sub(1).ok_or(IndexError::Corrupt(
        "tracked contract count underflow during retirement",
    ))?;

    batch.delete(ColumnFamily::TxIndex, &key)?;
    batch.delete(ColumnFamily::TxIndex, &observation_key(registration.id))?;
    if ids.is_empty() {
        batch.delete(ColumnFamily::TxIndex, &binding_key)?;
    } else {
        batch.put(
            ColumnFamily::TxIndex,
            &binding_key,
            &encode_address_bindings(&binding_key, &ids)?,
        )?;
    }
    if next == 0 {
        batch.delete(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)?;
    } else {
        batch.put(
            ColumnFamily::TxIndex,
            REGISTRATION_COUNT_KEY,
            &encode_registration_count(next),
        )?;
    }
    Ok(ContractRetirementOutcome::Retired)
}

/// Atomically retire one exact confirmed descriptor lifecycle after every
/// event it could need for disconnect is below the node's irreversible undo
/// frontier.
///
/// The caller must derive `rollback_boundary` from the same canonical snapshot
/// and serialize this mutation against chain and mempool changes. It must also
/// durably abandon every funding/rebroadcast source and acknowledge that this
/// content-derived descriptor identity can never be registered again. This
/// layer independently requires an empty active-funding prefix, walks the
/// complete bounded event history, proves exact funding/spend pairing, retains
/// every revealed preimage, and refuses to delete any row above the boundary.
pub fn retire_completed_tracked_contract<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
    profile: WalletIndexProfile,
    registration: &ContractRegistration,
    expected_lifecycle_revision: u64,
    rollback_boundary: ContractRollbackBoundary,
    permanent_abandonment_acknowledged: bool,
) -> Result<
    (
        CompletedContractRetirementOutcome,
        CompletedContractRetirement,
    ),
    IndexError,
> {
    require_contract_profile(profile)?;
    registration.validate()?;
    if !permanent_abandonment_acknowledged {
        return Err(IndexError::ContractRollbackRequired);
    }

    if let Some(stored) = load_stored_completed_retirement(snapshot, registration.id)? {
        validate_stored_completed_retirement(
            snapshot,
            &stored,
            Some(rollback_boundary.pruned_through),
        )?;
        if stored.registration != *registration {
            return Err(IndexError::Corrupt(
                "retired tracked contract identity disagrees with retirement request",
            ));
        }
        if stored.lifecycle_revision != expected_lifecycle_revision {
            return Err(IndexError::StaleContractLifecycle {
                expected: expected_lifecycle_revision,
                actual: stored.lifecycle_revision,
            });
        }
        return Ok((
            CompletedContractRetirementOutcome::AlreadyRetired,
            stored.into(),
        ));
    }

    let key = registration_key(registration.id);
    let raw = snapshot
        .get(ColumnFamily::TxIndex, &key)?
        .ok_or(IndexError::UnknownContract)?;
    let stored_registration: ContractRegistration =
        decode_record(b"contract-registration-v1", &key, &raw)?;
    if stored_registration != *registration {
        return Err(IndexError::Corrupt(
            "completed retirement terms disagree with registration",
        ));
    }
    let observation = load_observation(snapshot, registration.id)?
        .ok_or(IndexError::ContractConfirmationUnknown)?;
    if observation.lifecycle_revision != expected_lifecycle_revision {
        return Err(IndexError::StaleContractLifecycle {
            expected: expected_lifecycle_revision,
            actual: observation.lifecycle_revision,
        });
    }
    if observation.state != ContractObservationState::Confirmed {
        return Err(IndexError::ContractRollbackRequired);
    }
    if prefix_has_entry(snapshot, &funding_prefix(registration.id))? {
        return Err(IndexError::ContractRollbackRequired);
    }

    let history = analyze_completed_history(snapshot, registration)?;
    if history.maximum_event_height > rollback_boundary.pruned_through {
        return Err(IndexError::ContractRollbackRequired);
    }

    let retirement_count = snapshot
        .get(ColumnFamily::TxIndex, RETIREMENT_COUNT_KEY)?
        .as_deref()
        .map(decode_retirement_count)
        .transpose()?
        .unwrap_or(0);
    if retirement_count >= MAX_RETIRED_TRACKED_CONTRACTS {
        return Err(IndexError::ContractRetirementCapacity);
    }
    let next_retirement_count = retirement_count
        .checked_add(1)
        .ok_or(IndexError::ContractRetirementCapacity)?;

    let binding_key = address_key(&registration.funding_address()?);
    let binding = snapshot
        .get(ColumnFamily::TxIndex, &binding_key)?
        .ok_or(IndexError::Corrupt(
            "tracked contract registration has no address binding",
        ))?;
    let mut ids = decode_address_bindings(&binding_key, &binding)?;
    let position = ids
        .binary_search(&registration.id)
        .map_err(|_| IndexError::Corrupt("tracked contract address binding mismatch"))?;
    ids.remove(position);
    let active_count = snapshot
        .get(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)?
        .as_deref()
        .map(decode_registration_count)
        .transpose()?
        .ok_or(IndexError::Corrupt(
            "tracked contract count is absent while registry is non-empty",
        ))?;
    let next_active_count = active_count.checked_sub(1).ok_or(IndexError::Corrupt(
        "tracked contract count underflow during completed retirement",
    ))?;

    let retirement = StoredCompletedContractRetirement {
        registration: registration.clone(),
        lifecycle_revision: expected_lifecycle_revision,
        confirmed_event_count: history.event_count,
        minimum_event_height: history.minimum_event_height,
        maximum_event_height: history.maximum_event_height,
        ordered_event_commitment: history.ordered_event_commitment,
        terminal_event: history.terminal_event,
        revealed_preimages: history.revealed_preimages,
        rollback_boundary,
        permanent_abandonment_acknowledged,
    };
    let retirement_key = retirement_key(registration.id);
    batch.put(
        ColumnFamily::TxIndex,
        &retirement_key,
        &encode_record(
            b"contract-completed-retirement-v1",
            &retirement_key,
            &retirement,
        )?,
    )?;
    batch.put(
        ColumnFamily::TxIndex,
        RETIREMENT_COUNT_KEY,
        &encode_retirement_count(next_retirement_count),
    )?;
    batch.delete(ColumnFamily::TxIndex, &key)?;
    batch.delete(ColumnFamily::TxIndex, &observation_key(registration.id))?;
    for event_key in history.event_keys {
        batch.delete(ColumnFamily::TxIndex, &event_key)?;
    }
    if ids.is_empty() {
        batch.delete(ColumnFamily::TxIndex, &binding_key)?;
    } else {
        batch.put(
            ColumnFamily::TxIndex,
            &binding_key,
            &encode_address_bindings(&binding_key, &ids)?,
        )?;
    }
    if next_active_count == 0 {
        batch.delete(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)?;
    } else {
        batch.put(
            ColumnFamily::TxIndex,
            REGISTRATION_COUNT_KEY,
            &encode_registration_count(next_active_count),
        )?;
    }

    Ok((
        CompletedContractRetirementOutcome::Retired,
        retirement.into(),
    ))
}

/// Read the immutable completed-retirement proof for one consumed descriptor.
pub fn completed_tracked_contract_retirement<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    id: ContractId,
) -> Result<Option<CompletedContractRetirement>, IndexError> {
    require_contract_profile(profile)?;
    let Some(retirement) = load_stored_completed_retirement(snapshot, id)? else {
        return Ok(None);
    };
    validate_stored_completed_retirement(snapshot, &retirement, None)?;
    Ok(Some(retirement.into()))
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
    let lifecycle_sequence = load_lifecycle_sequence(snapshot)?;

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
        let binding =
            snapshot
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
        let _ = load_observation(snapshot, registration.id)?;
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
    let observations = validate_registry_prefix(snapshot, OBSERVATION_PREFIX, |key, raw| {
        let record: ContractObservationRecord =
            decode_record(b"contract-observation-v1", key, raw)?;
        if observation_key(record.contract_id) != key {
            return Err(IndexError::Corrupt(
                "tracked contract observation key/value binding mismatch",
            ));
        }
        if load_registration(snapshot, record.contract_id)?.is_none() {
            return Err(IndexError::Corrupt(
                "tracked contract observation points to missing registration",
            ));
        }
        if record.lifecycle_revision == 0 || record.lifecycle_revision > lifecycle_sequence {
            return Err(IndexError::Corrupt(
                "tracked contract lifecycle revision exceeds its sequence",
            ));
        }
        if record.state == ContractObservationState::NeverConfirmed
            && (prefix_has_entry(snapshot, &funding_prefix(record.contract_id))?
                || prefix_has_entry(snapshot, &event_prefix(record.contract_id))?)
        {
            return Err(IndexError::Corrupt(
                "never-confirmed tracked contract has confirmed activity",
            ));
        }
        Ok(())
    })?;
    if registrations != expected || binding_total != expected || (expected != 0 && addresses == 0) {
        return Err(IndexError::Corrupt(
            "tracked contract registry count/topology mismatch",
        ));
    }
    if observations > registrations {
        return Err(IndexError::Corrupt(
            "tracked contract observations exceed registry count",
        ));
    }
    Ok(())
}

/// Validate every immutable completed-retirement proof against the current
/// undo frontier and canonical height index during startup.
///
/// `canonical_hash_at` must read from the same immutable snapshot. A tombstone
/// without a current pruning checkpoint, above a regressed checkpoint, or
/// bound to a non-canonical boundary/terminal block fails startup closed.
pub fn validate_completed_tracked_contract_retirements<
    S: ReadSnapshot,
    F: FnMut(Height) -> Result<Option<BlockHash>, IndexError>,
>(
    snapshot: &S,
    profile: WalletIndexProfile,
    current_rollback_boundary: Option<ContractRollbackBoundary>,
    mut canonical_hash_at: F,
) -> Result<(), IndexError> {
    if !profile.wallet {
        return Ok(());
    }
    let expected_raw = snapshot.get(ColumnFamily::TxIndex, RETIREMENT_COUNT_KEY)?;
    let expected = expected_raw
        .as_deref()
        .map(decode_retirement_count)
        .transpose()?
        .unwrap_or(0);
    if expected > MAX_RETIRED_TRACKED_CONTRACTS || (expected == 0 && expected_raw.is_some()) {
        return Err(IndexError::Corrupt(
            "tracked contract retirement count exceeds schema bound",
        ));
    }

    let mut cursor = None::<Vec<u8>>;
    let mut total = 0_u32;
    loop {
        let page = snapshot.scan_prefix_page(
            ColumnFamily::TxIndex,
            RETIREMENT_PREFIX,
            cursor.as_deref(),
            PrefixScanBudget {
                max_entries: MAX_QUERY_ENTRIES,
                max_bytes: MAX_QUERY_BYTES,
            },
        )?;
        for (key, raw) in &page.entries {
            total = total.checked_add(1).ok_or(IndexError::Corrupt(
                "tracked contract retirement count overflow",
            ))?;
            if total > MAX_RETIRED_TRACKED_CONTRACTS {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement registry exceeds schema bound",
                ));
            }
            let retirement: StoredCompletedContractRetirement =
                decode_record(b"contract-completed-retirement-v1", key, raw)?;
            if retirement_key(retirement.registration.id) != *key {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement key/value binding mismatch",
                ));
            }
            let current = current_rollback_boundary.ok_or(IndexError::Corrupt(
                "tracked contract retirement exists without an undo-pruning checkpoint",
            ))?;
            validate_stored_completed_retirement(
                snapshot,
                &retirement,
                Some(current.pruned_through),
            )?;
            if canonical_hash_at(retirement.rollback_boundary.pruned_through)?
                != Some(retirement.rollback_boundary.block_hash)
            {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement rollback block is not canonical",
                ));
            }
            let terminal: TrackedContractEvent = retirement.terminal_event.clone().into();
            let TrackedContractEvent::Spend {
                height, block_hash, ..
            } = terminal
            else {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement terminal evidence is not a spend",
                ));
            };
            if canonical_hash_at(height)? != Some(block_hash) {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement terminal block is not canonical",
                ));
            }
        }
        let Some(next) = page.continuation else {
            break;
        };
        if cursor.as_ref().is_some_and(|previous| previous >= &next) {
            return Err(IndexError::Corrupt(
                "tracked contract retirement continuation did not advance",
            ));
        }
        cursor = Some(next);
    }
    if total != expected {
        return Err(IndexError::Corrupt(
            "tracked contract retirement count/topology mismatch",
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
        continuation: page.continuation.map(|key| TrackedContractCursor { key }),
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
            let event: StoredTrackedContractEvent = decode_record(b"contract-event-v1", key, raw)?;
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
        continuation: page.continuation.map(|key| TrackedContractCursor { key }),
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
    let mut tracked_created =
        HashMap::<Outpoint, (ContractRegistration, TrackedContractFunding)>::new();

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
            let coin = created.get(&outpoint).cloned().ok_or(IndexError::Corrupt(
                "tracked funding coin was not constructed",
            ))?;
            let funding = TrackedContractFunding {
                contract_id: registration.id,
                coin,
                block_hash,
                height,
                transaction_position,
                output_position,
            };
            mark_contract_confirmed(snapshot, batch, registration.id)?;
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
                None => load_coin(snapshot, &input.previous_output)?
                    .ok_or_else(|| IndexError::MissingInputCoin(input.previous_output.clone()))?,
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
                let Some(funding) =
                    load_funding(snapshot, registration.id, &input.previous_output)?
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
    Secp256k1Verifier.validate_public_key(key).is_ok()
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

struct CompletedHistoryAnalysis {
    event_keys: Vec<Vec<u8>>,
    event_count: u32,
    minimum_event_height: Height,
    maximum_event_height: Height,
    ordered_event_commitment: [u8; 32],
    terminal_event: StoredTrackedContractEvent,
    revealed_preimages: Vec<StoredRetiredRevealedPreimage>,
}

fn analyze_completed_history<S: ReadSnapshot>(
    snapshot: &S,
    registration: &ContractRegistration,
) -> Result<CompletedHistoryAnalysis, IndexError> {
    let prefix = event_prefix(registration.id);
    let mut cursor = None::<Vec<u8>>;
    let mut previous_key = None::<Vec<u8>>;
    let mut event_keys = Vec::new();
    let mut active_fundings = HashMap::<Outpoint, TrackedContractFunding>::new();
    let mut seen_funding_outpoints = HashSet::<Outpoint>::new();
    let mut terminal_event = None::<StoredTrackedContractEvent>;
    let mut revealed_preimages = Vec::new();
    let mut minimum_event_height = None::<Height>;
    let mut maximum_event_height = None::<Height>;
    let mut commitment = Sha256::new();
    commitment.update(RETIRED_EVENT_COMMITMENT_DOMAIN);

    loop {
        let page = snapshot.scan_prefix_page(
            ColumnFamily::TxIndex,
            &prefix,
            cursor.as_deref(),
            PrefixScanBudget {
                max_entries: MAX_QUERY_ENTRIES,
                max_bytes: MAX_QUERY_BYTES,
            },
        )?;
        for (key, raw) in &page.entries {
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= key)
            {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement event order did not advance",
                ));
            }
            let next_count = u32::try_from(event_keys.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(IndexError::ContractRetirementHistoryCapacity)?;
            if next_count > MAX_TRACKED_CONTRACT_RETIREMENT_EVENTS {
                return Err(IndexError::ContractRetirementHistoryCapacity);
            }
            let stored: StoredTrackedContractEvent = decode_record(b"contract-event-v1", key, raw)?;
            let event: TrackedContractEvent = stored.clone().into();
            if event.contract_id() != registration.id || event.key() != *key {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement event key/value binding mismatch",
                ));
            }
            let height = match &event {
                TrackedContractEvent::Funding(funding) => funding.height,
                TrackedContractEvent::Spend { height, .. } => *height,
            };
            minimum_event_height =
                Some(minimum_event_height.map_or(height, |minimum| minimum.min(height)));
            maximum_event_height =
                Some(maximum_event_height.map_or(height, |maximum| maximum.max(height)));

            match &event {
                TrackedContractEvent::Funding(funding) => {
                    if funding.contract_id != registration.id
                        || !registration.matches_funding_output(&Output {
                            value: funding.coin.value,
                            address: funding.coin.address.clone(),
                            covenant: funding.coin.covenant.clone(),
                        })?
                        || !seen_funding_outpoints.insert(funding.coin.outpoint.clone())
                        || active_fundings
                            .insert(funding.coin.outpoint.clone(), funding.clone())
                            .is_some()
                    {
                        return Err(IndexError::Corrupt(
                            "tracked contract retirement funding history is inconsistent",
                        ));
                    }
                }
                TrackedContractEvent::Spend {
                    funding,
                    spending_txid,
                    kind,
                    ..
                } => {
                    let prior = active_fundings.remove(&funding.coin.outpoint).ok_or(
                        IndexError::Corrupt(
                            "tracked contract retirement spend has no prior funding event",
                        ),
                    )?;
                    if prior != *funding || !spend_kind_matches_registration(registration, kind) {
                        return Err(IndexError::Corrupt(
                            "tracked contract retirement spend history is inconsistent",
                        ));
                    }
                    if let TrackedContractSpendKind::HtlcRedemption { preimage } = kind {
                        revealed_preimages.push(StoredRetiredRevealedPreimage {
                            funding_outpoint: funding.coin.outpoint.clone(),
                            spending_txid: *spending_txid,
                            preimage: *preimage.expose_for_settlement(),
                        });
                    }
                }
            }

            let key_len = u64::try_from(key.len())
                .map_err(|_| IndexError::ContractRetirementHistoryCapacity)?;
            let raw_len = u64::try_from(raw.len())
                .map_err(|_| IndexError::ContractRetirementHistoryCapacity)?;
            commitment.update(key_len.to_be_bytes());
            commitment.update(key);
            commitment.update(raw_len.to_be_bytes());
            commitment.update(raw);
            previous_key = Some(key.clone());
            event_keys.push(key.clone());
            terminal_event = Some(stored);
        }
        let Some(next) = page.continuation else {
            break;
        };
        if cursor.as_ref().is_some_and(|previous| previous >= &next) {
            return Err(IndexError::Corrupt(
                "tracked contract retirement continuation did not advance",
            ));
        }
        cursor = Some(next);
    }

    if !active_fundings.is_empty() {
        return Err(IndexError::ContractRollbackRequired);
    }
    let terminal_event = terminal_event.ok_or(IndexError::ContractRollbackRequired)?;
    if !matches!(terminal_event, StoredTrackedContractEvent::Spend { .. }) {
        return Err(IndexError::ContractRollbackRequired);
    }
    let event_count = u32::try_from(event_keys.len())
        .map_err(|_| IndexError::ContractRetirementHistoryCapacity)?;
    let minimum_event_height = minimum_event_height.ok_or(IndexError::ContractRollbackRequired)?;
    let maximum_event_height = maximum_event_height.ok_or(IndexError::ContractRollbackRequired)?;
    commitment.update(event_count.to_be_bytes());

    Ok(CompletedHistoryAnalysis {
        event_keys,
        event_count,
        minimum_event_height,
        maximum_event_height,
        ordered_event_commitment: commitment.finalize().into(),
        terminal_event,
        revealed_preimages,
    })
}

fn spend_kind_matches_registration(
    registration: &ContractRegistration,
    kind: &TrackedContractSpendKind,
) -> bool {
    matches!(
        (&registration.kind, kind),
        (_, TrackedContractSpendKind::Unrecognized)
            | (
                TrackedContractKind::ShakedexV2(_),
                TrackedContractSpendKind::ShakedexFulfillment
                    | TrackedContractSpendKind::ShakedexRecovery
            )
            | (
                TrackedContractKind::HnsHtlcV1(_),
                TrackedContractSpendKind::HtlcRedemption { .. }
                    | TrackedContractSpendKind::HtlcRefund
            )
    )
}

fn load_stored_completed_retirement<S: ReadSnapshot>(
    snapshot: &S,
    id: ContractId,
) -> Result<Option<StoredCompletedContractRetirement>, IndexError> {
    let key = retirement_key(id);
    snapshot
        .get(ColumnFamily::TxIndex, &key)?
        .as_deref()
        .map(|raw| {
            let retirement: StoredCompletedContractRetirement =
                decode_record(b"contract-completed-retirement-v1", &key, raw)?;
            if retirement.registration.id != id {
                return Err(IndexError::Corrupt(
                    "tracked contract retirement key/value binding mismatch",
                ));
            }
            Ok(retirement)
        })
        .transpose()
}

fn validate_stored_completed_retirement<S: ReadSnapshot>(
    snapshot: &S,
    retirement: &StoredCompletedContractRetirement,
    current_pruned_through: Option<Height>,
) -> Result<(), IndexError> {
    retirement.registration.validate()?;
    if !retirement.permanent_abandonment_acknowledged
        || retirement.lifecycle_revision == 0
        || retirement.confirmed_event_count < 2
        || retirement.confirmed_event_count > MAX_TRACKED_CONTRACT_RETIREMENT_EVENTS
        || retirement.minimum_event_height > retirement.maximum_event_height
        || retirement.maximum_event_height > retirement.rollback_boundary.pruned_through
        || retirement.ordered_event_commitment == [0; 32]
        || current_pruned_through
            .is_some_and(|height| height < retirement.rollback_boundary.pruned_through)
    {
        return Err(IndexError::Corrupt(
            "tracked contract retirement proof has an invalid rollback binding",
        ));
    }
    let lifecycle_sequence = load_lifecycle_sequence(snapshot)?;
    if retirement.lifecycle_revision > lifecycle_sequence {
        return Err(IndexError::Corrupt(
            "tracked contract retirement lifecycle exceeds its sequence",
        ));
    }
    let terminal: TrackedContractEvent = retirement.terminal_event.clone().into();
    let TrackedContractEvent::Spend {
        contract_id,
        funding,
        spending_txid,
        height,
        kind,
        ..
    } = &terminal
    else {
        return Err(IndexError::Corrupt(
            "tracked contract retirement terminal evidence is not a spend",
        ));
    };
    if *contract_id != retirement.registration.id
        || funding.contract_id != retirement.registration.id
        || funding.height < retirement.minimum_event_height
        || funding.height > retirement.maximum_event_height
        || *height != retirement.maximum_event_height
        || !retirement.registration.matches_funding_output(&Output {
            value: funding.coin.value,
            address: funding.coin.address.clone(),
            covenant: funding.coin.covenant.clone(),
        })?
        || !spend_kind_matches_registration(&retirement.registration, kind)
    {
        return Err(IndexError::Corrupt(
            "tracked contract retirement terminal evidence is inconsistent",
        ));
    }
    if retirement.revealed_preimages.len()
        > usize::try_from(retirement.confirmed_event_count)
            .map_err(|_| IndexError::Corrupt("tracked contract retirement count overflow"))?
    {
        return Err(IndexError::Corrupt(
            "tracked contract retirement preimage count is invalid",
        ));
    }
    match &retirement.registration.kind {
        TrackedContractKind::HnsHtlcV1(descriptor) => {
            let mut seen_evidence = HashSet::new();
            for evidence in &retirement.revealed_preimages {
                let observed_hash: [u8; 32] = Sha256::digest(evidence.preimage).into();
                if observed_hash != descriptor.hashlock
                    || !seen_evidence
                        .insert((evidence.funding_outpoint.clone(), evidence.spending_txid))
                {
                    return Err(IndexError::Corrupt(
                        "tracked contract retirement retained an invalid preimage",
                    ));
                }
            }
            if let TrackedContractSpendKind::HtlcRedemption { preimage } = kind {
                if !retirement.revealed_preimages.iter().any(|evidence| {
                    evidence.funding_outpoint == funding.coin.outpoint
                        && evidence.spending_txid == *spending_txid
                        && evidence.preimage == *preimage.expose_for_settlement()
                }) {
                    return Err(IndexError::Corrupt(
                        "tracked contract retirement dropped its terminal revealed preimage",
                    ));
                }
            }
        }
        TrackedContractKind::ShakedexV2(_) if !retirement.revealed_preimages.is_empty() => {
            return Err(IndexError::Corrupt(
                "Shakedex retirement contains unrelated revealed preimages",
            ));
        }
        TrackedContractKind::ShakedexV2(_) => {}
    }
    if load_registration(snapshot, retirement.registration.id)?.is_some()
        || load_observation(snapshot, retirement.registration.id)?.is_some()
        || prefix_has_entry(snapshot, &funding_prefix(retirement.registration.id))?
        || prefix_has_entry(snapshot, &event_prefix(retirement.registration.id))?
    {
        return Err(IndexError::Corrupt(
            "retired tracked contract still has active topology or history",
        ));
    }
    let binding_key = address_key(&retirement.registration.funding_address()?);
    if snapshot
        .get(ColumnFamily::TxIndex, &binding_key)?
        .as_deref()
        .map(|raw| decode_address_bindings(&binding_key, raw))
        .transpose()?
        .is_some_and(|ids| ids.binary_search(&retirement.registration.id).is_ok())
    {
        return Err(IndexError::Corrupt(
            "retired tracked contract remains in the active address binding",
        ));
    }
    Ok(())
}

fn observation_key(id: ContractId) -> Vec<u8> {
    prefixed_id(OBSERVATION_PREFIX, id)
}

fn load_lifecycle_sequence<S: ReadSnapshot>(snapshot: &S) -> Result<u64, IndexError> {
    snapshot
        .get(ColumnFamily::TxIndex, LIFECYCLE_SEQUENCE_KEY)?
        .as_deref()
        .map(decode_lifecycle_sequence)
        .transpose()
        .map(|sequence| sequence.unwrap_or(0))
}

fn next_lifecycle_revision<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
) -> Result<u64, IndexError> {
    let next = load_lifecycle_sequence(snapshot)?
        .checked_add(1)
        .ok_or(IndexError::Corrupt(
            "tracked contract lifecycle sequence exhausted",
        ))?;
    batch.put(
        ColumnFamily::TxIndex,
        LIFECYCLE_SEQUENCE_KEY,
        &encode_lifecycle_sequence(next),
    )?;
    Ok(next)
}

fn load_observation<S: ReadSnapshot>(
    snapshot: &S,
    id: ContractId,
) -> Result<Option<ContractObservationRecord>, IndexError> {
    let key = observation_key(id);
    snapshot
        .get(ColumnFamily::TxIndex, &key)?
        .as_deref()
        .map(|raw| {
            let record: ContractObservationRecord =
                decode_record(b"contract-observation-v1", &key, raw)?;
            if record.contract_id != id
                || record.lifecycle_revision == 0
                || record.lifecycle_revision > load_lifecycle_sequence(snapshot)?
            {
                return Err(IndexError::Corrupt(
                    "tracked contract observation key/value binding mismatch",
                ));
            }
            Ok(record)
        })
        .transpose()
}

fn put_observation<B: WriteBatch>(
    batch: &mut B,
    record: ContractObservationRecord,
) -> Result<(), IndexError> {
    let key = observation_key(record.contract_id);
    batch.put(
        ColumnFamily::TxIndex,
        &key,
        &encode_record(b"contract-observation-v1", &key, &record)?,
    )?;
    Ok(())
}

fn mark_contract_confirmed<S: ReadSnapshot, B: WriteBatch>(
    snapshot: &S,
    batch: &mut B,
    id: ContractId,
) -> Result<(), IndexError> {
    let existing = load_observation(snapshot, id)?;
    if existing.is_some_and(|record| record.state == ContractObservationState::Confirmed) {
        return Ok(());
    }
    let lifecycle_revision = match existing {
        Some(record) => record.lifecycle_revision,
        None => next_lifecycle_revision(snapshot, batch)?,
    };
    put_observation(
        batch,
        ContractObservationRecord {
            contract_id: id,
            lifecycle_revision,
            state: ContractObservationState::Confirmed,
        },
    )
}

fn prefix_has_entry<S: ReadSnapshot>(snapshot: &S, prefix: &[u8]) -> Result<bool, IndexError> {
    let page = snapshot.scan_prefix_page(
        ColumnFamily::TxIndex,
        prefix,
        None,
        PrefixScanBudget {
            max_entries: 1,
            max_bytes: MAX_QUERY_BYTES,
        },
    )?;
    if page.entries.is_empty() && page.continuation.is_some() {
        return Err(IndexError::Corrupt(
            "tracked contract prefix probe made no progress",
        ));
    }
    Ok(!page.entries.is_empty())
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

fn put_event<B: WriteBatch>(batch: &mut B, event: &TrackedContractEvent) -> Result<(), IndexError> {
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

fn retirement_key(id: ContractId) -> Vec<u8> {
    prefixed_id(RETIREMENT_PREFIX, id)
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
        .map(|bytes| -> Result<ContractId, IndexError> {
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
    if checksum != bound_checksum(b"contract-count-v1", REGISTRATION_COUNT_KEY, body).as_slice() {
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

fn encode_retirement_count(count: u32) -> Vec<u8> {
    let mut raw = Vec::with_capacity(1 + 4 + CHECKSUM_BYTES);
    raw.push(RECORD_VERSION);
    raw.extend_from_slice(&count.to_le_bytes());
    raw.extend_from_slice(&bound_checksum(
        b"contract-retirement-count-v1",
        RETIREMENT_COUNT_KEY,
        &raw,
    ));
    raw
}

fn decode_retirement_count(raw: &[u8]) -> Result<u32, IndexError> {
    if raw.len() != 1 + 4 + CHECKSUM_BYTES || raw.first().copied() != Some(RECORD_VERSION) {
        return Err(IndexError::Corrupt(
            "invalid tracked contract retirement count",
        ));
    }
    let (body, checksum) = raw.split_at(5);
    if checksum
        != bound_checksum(b"contract-retirement-count-v1", RETIREMENT_COUNT_KEY, body).as_slice()
    {
        return Err(IndexError::Corrupt(
            "invalid tracked contract retirement count checksum",
        ));
    }
    Ok(u32::from_le_bytes(
        body.get(1..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(IndexError::Corrupt(
                "invalid tracked contract retirement count",
            ))?,
    ))
}

fn encode_lifecycle_sequence(sequence: u64) -> Vec<u8> {
    let mut raw = Vec::with_capacity(1 + 8 + CHECKSUM_BYTES);
    raw.push(RECORD_VERSION);
    raw.extend_from_slice(&sequence.to_le_bytes());
    raw.extend_from_slice(&bound_checksum(
        b"contract-lifecycle-sequence-v1",
        LIFECYCLE_SEQUENCE_KEY,
        &raw,
    ));
    raw
}

fn decode_lifecycle_sequence(raw: &[u8]) -> Result<u64, IndexError> {
    if raw.len() != 1 + 8 + CHECKSUM_BYTES || raw.first().copied() != Some(RECORD_VERSION) {
        return Err(IndexError::Corrupt(
            "invalid tracked contract lifecycle sequence",
        ));
    }
    let (body, checksum) = raw.split_at(9);
    if checksum
        != bound_checksum(
            b"contract-lifecycle-sequence-v1",
            LIFECYCLE_SEQUENCE_KEY,
            body,
        )
        .as_slice()
    {
        return Err(IndexError::Corrupt(
            "invalid tracked contract lifecycle sequence checksum",
        ));
    }
    let sequence = u64::from_le_bytes(
        body.get(1..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(IndexError::Corrupt(
                "invalid tracked contract lifecycle sequence",
            ))?,
    );
    if sequence == 0 {
        return Err(IndexError::Corrupt(
            "invalid tracked contract lifecycle sequence",
        ));
    }
    Ok(sequence)
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
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
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
        assert!(
            tracked_contract_fundings(&snapshot, profile(), registration.id, None, 8)
                .expect("fundings")
                .entries
                .is_empty()
        );
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
    fn production_next_completed_retirement_is_pruning_bound_and_restart_exact() {
        let store = MemoryStore::new();
        let preimage = [0x6a; 32];
        let registration = htlc(preimage);
        let snapshot = store.snapshot().expect("registration snapshot");
        let mut register = store.batch();
        register_tracked_contract(&snapshot, &mut register, profile(), &registration)
            .expect("register completed fixture");
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
                address: registration.funding_address().expect("funding address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        let funding_block = block(vec![funding_transaction.clone()]);
        let snapshot = store.snapshot().expect("funding snapshot");
        let mut connect = store.batch();
        stage_connect(&snapshot, &mut connect, &funding_block, 10, profile())
            .expect("connect funding");
        drop(snapshot);
        store.commit(connect).expect("commit funding");

        let funding = Coin {
            outpoint: Outpoint {
                txid: funding_transaction.txid(),
                index: 0,
            },
            value: 50,
            height: 10,
            coinbase: true,
            address: registration.funding_address().expect("funding address"),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let mut state = store.batch();
        write_coin_to_batch(&mut state, &funding).expect("seed funding coin");
        store.commit(state).expect("commit funding coin");
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
                        registration.lock_script().expect("HTLC script"),
                    ],
                },
            }],
            outputs: Vec::new(),
            locktime: 0,
        };
        let spending_block = block(vec![spending_transaction.clone()]);
        let snapshot = store.snapshot().expect("spend snapshot");
        let mut spend = store.batch();
        stage_connect(&snapshot, &mut spend, &spending_block, 11, profile())
            .expect("connect spend");
        drop(snapshot);
        store.commit(spend).expect("commit spend");

        let snapshot = store.snapshot().expect("completed snapshot");
        let lifecycle_revision =
            tracked_contract_lifecycle_revision(&snapshot, profile(), registration.id)
                .expect("lifecycle read")
                .expect("lifecycle revision");
        let mut unacknowledged = store.batch();
        assert!(matches!(
            retire_completed_tracked_contract(
                &snapshot,
                &mut unacknowledged,
                profile(),
                &registration,
                lifecycle_revision,
                ContractRollbackBoundary {
                    pruned_through: 11,
                    block_hash: spending_block.hash(),
                },
                false,
            ),
            Err(IndexError::ContractRollbackRequired)
        ));
        let mut too_early = store.batch();
        assert!(matches!(
            retire_completed_tracked_contract(
                &snapshot,
                &mut too_early,
                profile(),
                &registration,
                lifecycle_revision,
                ContractRollbackBoundary {
                    pruned_through: 10,
                    block_hash: funding_block.hash(),
                },
                true,
            ),
            Err(IndexError::ContractRollbackRequired)
        ));

        let rollback_boundary = ContractRollbackBoundary {
            pruned_through: 11,
            block_hash: spending_block.hash(),
        };
        let mut retire = store.batch();
        let (outcome, proof) = retire_completed_tracked_contract(
            &snapshot,
            &mut retire,
            profile(),
            &registration,
            lifecycle_revision,
            rollback_boundary,
            true,
        )
        .expect("completed retirement");
        assert_eq!(outcome, CompletedContractRetirementOutcome::Retired);
        assert_eq!(proof.confirmed_event_count, 2);
        assert_eq!(proof.minimum_event_height, 10);
        assert_eq!(proof.maximum_event_height, 11);
        assert_ne!(proof.ordered_event_commitment, [0; 32]);
        assert_eq!(proof.revealed_preimages.len(), 1);
        assert_eq!(
            proof.revealed_preimages[0].preimage.expose_for_settlement(),
            &preimage
        );
        drop(snapshot);
        store.commit(retire).expect("commit retirement");

        let snapshot = store.snapshot().expect("restart snapshot");
        assert_eq!(
            tracked_contract(&snapshot, profile(), registration.id).expect("active lookup"),
            None
        );
        let restarted =
            completed_tracked_contract_retirement(&snapshot, profile(), registration.id)
                .expect("retirement lookup")
                .expect("retirement proof");
        assert_eq!(restarted, proof);
        validate_tracked_contract_registry(&snapshot, profile()).expect("active topology");
        validate_completed_tracked_contract_retirements(
            &snapshot,
            profile(),
            Some(rollback_boundary),
            |height| Ok((height == 11).then_some(spending_block.hash())),
        )
        .expect("retirement restart validation");
        let mut reregister = store.batch();
        assert!(matches!(
            register_tracked_contract(&snapshot, &mut reregister, profile(), &registration),
            Err(IndexError::ContractRetired)
        ));
        let mut retry = store.batch();
        let (retry_outcome, retry_proof) = retire_completed_tracked_contract(
            &snapshot,
            &mut retry,
            profile(),
            &registration,
            lifecycle_revision,
            rollback_boundary,
            true,
        )
        .expect("idempotent completed retirement");
        assert_eq!(
            retry_outcome,
            CompletedContractRetirementOutcome::AlreadyRetired
        );
        assert_eq!(retry_proof, proof);
    }

    #[test]
    fn production_next_retirement_startup_refuses_missing_or_changed_rollback_authority() {
        let store = MemoryStore::new();
        let registration = htlc([0x6b; 32]);
        let lifecycle_revision = 7;
        let terminal = StoredTrackedContractEvent::Spend {
            contract_id: registration.id,
            funding: TrackedContractFunding {
                contract_id: registration.id,
                coin: Coin {
                    outpoint: Outpoint {
                        txid: Txid::new([0x71; 32]),
                        index: 1,
                    },
                    value: 50,
                    height: 20,
                    coinbase: false,
                    address: registration.funding_address().expect("funding address"),
                    covenant: Covenant {
                        kind: CovenantKind::None,
                        items: Vec::new(),
                    },
                },
                block_hash: BlockHash::new([0x72; 32]),
                height: 20,
                transaction_position: 1,
                output_position: 1,
            },
            spending_txid: Txid::new([0x73; 32]),
            block_hash: BlockHash::new([0x74; 32]),
            height: 21,
            transaction_position: 2,
            input_position: 1,
            kind: StoredTrackedContractSpendKind::HtlcRefund,
        };
        let boundary = ContractRollbackBoundary {
            pruned_through: 21,
            block_hash: BlockHash::new([0x75; 32]),
        };
        let tombstone = StoredCompletedContractRetirement {
            registration: registration.clone(),
            lifecycle_revision,
            confirmed_event_count: 2,
            minimum_event_height: 20,
            maximum_event_height: 21,
            ordered_event_commitment: [0x76; 32],
            terminal_event: terminal,
            revealed_preimages: Vec::new(),
            rollback_boundary: boundary,
            permanent_abandonment_acknowledged: true,
        };
        let key = retirement_key(registration.id);
        let mut seed = store.batch();
        seed.put(
            ColumnFamily::TxIndex,
            LIFECYCLE_SEQUENCE_KEY,
            &encode_lifecycle_sequence(lifecycle_revision),
        )
        .expect("seed lifecycle");
        seed.put(
            ColumnFamily::TxIndex,
            RETIREMENT_COUNT_KEY,
            &encode_retirement_count(1),
        )
        .expect("seed retirement count");
        seed.put(
            ColumnFamily::TxIndex,
            &key,
            &encode_record(b"contract-completed-retirement-v1", &key, &tombstone)
                .expect("encode tombstone"),
        )
        .expect("seed tombstone");
        store.commit(seed).expect("commit tombstone");

        let snapshot = store.snapshot().expect("restart snapshot");
        assert!(validate_completed_tracked_contract_retirements(
            &snapshot,
            profile(),
            None,
            |_| Ok(None),
        )
        .is_err());
        assert!(validate_completed_tracked_contract_retirements(
            &snapshot,
            profile(),
            Some(ContractRollbackBoundary {
                pruned_through: 20,
                block_hash: BlockHash::new([0x77; 32]),
            }),
            |_| Ok(None),
        )
        .is_err());
        assert!(validate_completed_tracked_contract_retirements(
            &snapshot,
            profile(),
            Some(boundary),
            |height| Ok((height == 21).then_some(BlockHash::new([0x78; 32]))),
        )
        .is_err());
        validate_completed_tracked_contract_retirements(
            &snapshot,
            profile(),
            Some(boundary),
            |height| {
                Ok(match height {
                    21 => Some(boundary.block_hash),
                    _ => None,
                })
            },
        )
        .expect_err("terminal block also needs exact canonical authority");
        validate_completed_tracked_contract_retirements(
            &snapshot,
            profile(),
            Some(boundary),
            |height| {
                Ok(match height {
                    21 => Some(BlockHash::new([0x74; 32])),
                    _ => None,
                })
            },
        )
        .expect_err("rollback checkpoint hash must remain canonical too");
    }

    #[test]
    fn production_next_completed_retirement_rejects_reused_funding_outpoint_history() {
        let store = MemoryStore::new();
        let registration = htlc([0x6c; 32]);
        let outpoint = Outpoint {
            txid: Txid::new([0x81; 32]),
            index: 0,
        };
        let funding = TrackedContractFunding {
            contract_id: registration.id,
            coin: Coin {
                outpoint: outpoint.clone(),
                value: 50,
                height: 30,
                coinbase: false,
                address: registration.funding_address().expect("funding address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            },
            block_hash: BlockHash::new([0x82; 32]),
            height: 30,
            transaction_position: 0,
            output_position: 0,
        };
        let first_spend = TrackedContractEvent::Spend {
            contract_id: registration.id,
            funding: funding.clone(),
            spending_txid: Txid::new([0x83; 32]),
            block_hash: BlockHash::new([0x84; 32]),
            height: 31,
            transaction_position: 0,
            input_position: 0,
            kind: TrackedContractSpendKind::HtlcRefund,
        };
        let mut reused_funding = funding.clone();
        reused_funding.height = 32;
        reused_funding.block_hash = BlockHash::new([0x85; 32]);
        let second_spend = TrackedContractEvent::Spend {
            contract_id: registration.id,
            funding: reused_funding.clone(),
            spending_txid: Txid::new([0x86; 32]),
            block_hash: BlockHash::new([0x87; 32]),
            height: 33,
            transaction_position: 0,
            input_position: 0,
            kind: TrackedContractSpendKind::HtlcRefund,
        };
        let mut seed = store.batch();
        for event in [
            TrackedContractEvent::Funding(funding),
            first_spend,
            TrackedContractEvent::Funding(reused_funding),
            second_spend,
        ] {
            put_event(&mut seed, &event).expect("seed corrupt event history");
        }
        store.commit(seed).expect("commit corrupt event history");
        let snapshot = store.snapshot().expect("history snapshot");
        assert!(matches!(
            analyze_completed_history(&snapshot, &registration),
            Err(IndexError::Corrupt(_))
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
        stage_connect(
            &snapshot,
            &mut batch,
            &block(vec![parent, child]),
            1,
            profile(),
        )
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
        register_tracked_contract(&snapshot, &mut registration_batch, profile(), &registration)
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
    fn never_confirmed_contract_retirement_reclaims_shared_address_and_active_count() {
        let store = MemoryStore::new();
        let first = htlc([0x31; 32]);
        let TrackedContractKind::HnsHtlcV1(mut second_descriptor) = first.kind.clone() else {
            panic!("HTLC fixture kind");
        };
        second_descriptor.value = 75;
        let second =
            ContractRegistration::hns_htlc_v1(second_descriptor).expect("second registration");
        assert_eq!(
            first.funding_address().expect("first address"),
            second.funding_address().expect("second address")
        );

        for registration in [&first, &second] {
            let snapshot = store.snapshot().expect("registration snapshot");
            let mut batch = store.batch();
            assert_eq!(
                register_tracked_contract(&snapshot, &mut batch, profile(), registration)
                    .expect("registration"),
                ContractRegistrationOutcome::Registered
            );
            drop(snapshot);
            store.commit(batch).expect("registration commit");
        }

        let snapshot = store.snapshot().expect("retirement snapshot");
        let first_revision = tracked_contract_lifecycle_revision(&snapshot, profile(), first.id)
            .expect("lifecycle read")
            .expect("lifecycle revision");
        let mut retire = store.batch();
        assert_eq!(
            retire_never_confirmed_tracked_contract(
                &snapshot,
                &mut retire,
                profile(),
                &first,
                first_revision,
            )
            .expect("never-confirmed retirement"),
            ContractRetirementOutcome::Retired
        );
        drop(snapshot);
        store.commit(retire).expect("retirement commit");

        let snapshot = store.snapshot().expect("retired snapshot");
        validate_tracked_contract_registry(&snapshot, profile()).expect("reduced registry");
        assert_eq!(
            tracked_contract(&snapshot, profile(), first.id).expect("first lookup"),
            None
        );
        assert_eq!(
            tracked_contract(&snapshot, profile(), second.id).expect("second lookup"),
            Some(second.clone())
        );
        let binding_key = address_key(&first.funding_address().expect("shared address"));
        assert_eq!(
            decode_address_bindings(
                &binding_key,
                &snapshot
                    .get(ColumnFamily::TxIndex, &binding_key)
                    .expect("binding read")
                    .expect("remaining binding"),
            )
            .expect("binding decode"),
            vec![second.id]
        );
        assert_eq!(
            decode_registration_count(
                &snapshot
                    .get(ColumnFamily::TxIndex, REGISTRATION_COUNT_KEY)
                    .expect("count read")
                    .expect("remaining count"),
            )
            .expect("count decode"),
            1
        );
        let mut retry = store.batch();
        assert_eq!(
            retire_never_confirmed_tracked_contract(
                &snapshot,
                &mut retry,
                profile(),
                &first,
                first_revision,
            )
            .expect("idempotent retirement"),
            ContractRetirementOutcome::AlreadyAbsent
        );
        drop(snapshot);

        let snapshot = store.snapshot().expect("reactivation snapshot");
        let mut reactivate = store.batch();
        assert_eq!(
            register_tracked_contract(&snapshot, &mut reactivate, profile(), &first)
                .expect("exact re-registration"),
            ContractRegistrationOutcome::Registered
        );
        drop(snapshot);
        store
            .commit(reactivate)
            .expect("exact re-registration commit");
        let snapshot = store.snapshot().expect("reactivated snapshot");
        validate_tracked_contract_registry(&snapshot, profile()).expect("reactivated registry");
        assert_eq!(
            load_observation(&snapshot, first.id)
                .expect("observation read")
                .expect("observation")
                .state,
            ContractObservationState::NeverConfirmed
        );
        assert_ne!(
            tracked_contract_lifecycle_revision(&snapshot, profile(), first.id)
                .expect("new lifecycle read")
                .expect("new lifecycle revision"),
            first_revision
        );
    }

    #[test]
    fn never_confirmed_contract_retirement_never_forgets_confirmation_or_legacy_uncertainty() {
        let store = MemoryStore::new();
        let registration = htlc([0x32; 32]);
        let snapshot = store.snapshot().expect("registration snapshot");
        let mut register = store.batch();
        register_tracked_contract(&snapshot, &mut register, profile(), &registration)
            .expect("registration");
        drop(snapshot);
        store.commit(register).expect("registration commit");
        let snapshot = store.snapshot().expect("lifecycle snapshot");
        let lifecycle_revision =
            tracked_contract_lifecycle_revision(&snapshot, profile(), registration.id)
                .expect("lifecycle read")
                .expect("lifecycle revision");
        drop(snapshot);

        let funding_transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 50,
                address: registration.funding_address().expect("funding address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        let funding_block = block(vec![funding_transaction]);
        let snapshot = store.snapshot().expect("connect snapshot");
        let mut connect = store.batch();
        stage_connect(&snapshot, &mut connect, &funding_block, 42, profile())
            .expect("funding connect");
        drop(snapshot);
        store.commit(connect).expect("funding commit");

        let snapshot = store.snapshot().expect("disconnect snapshot");
        let mut disconnect = store.batch();
        stage_disconnect(
            &snapshot,
            &mut disconnect,
            &funding_block,
            &undo(&funding_block, 42, Vec::new()),
            profile(),
        )
        .expect("funding disconnect");
        drop(snapshot);
        store.commit(disconnect).expect("disconnect commit");

        let snapshot = store.snapshot().expect("reorged snapshot");
        assert!(
            tracked_contract_fundings(&snapshot, profile(), registration.id, None, 1)
                .expect("funding page")
                .entries
                .is_empty()
        );
        assert!(
            tracked_contract_events(&snapshot, profile(), registration.id, None, 1)
                .expect("event page")
                .entries
                .is_empty()
        );
        assert_eq!(
            load_observation(&snapshot, registration.id)
                .expect("observation read")
                .expect("observation")
                .state,
            ContractObservationState::Confirmed
        );
        let mut retire = store.batch();
        assert!(matches!(
            retire_never_confirmed_tracked_contract(
                &snapshot,
                &mut retire,
                profile(),
                &registration,
                lifecycle_revision,
            ),
            Err(IndexError::ContractConfirmed)
        ));
        drop(snapshot);

        let legacy = htlc([0x33; 32]);
        let snapshot = store.snapshot().expect("legacy registration snapshot");
        let mut register = store.batch();
        register_tracked_contract(&snapshot, &mut register, profile(), &legacy)
            .expect("legacy registration");
        drop(snapshot);
        store.commit(register).expect("legacy registration commit");
        let mut erase_state = store.batch();
        erase_state
            .delete(ColumnFamily::TxIndex, &observation_key(legacy.id))
            .expect("stage legacy state removal");
        store
            .commit(erase_state)
            .expect("legacy state removal commit");

        let snapshot = store.snapshot().expect("legacy snapshot");
        validate_tracked_contract_registry(&snapshot, profile())
            .expect("legacy registry remains readable");
        let mut retire = store.batch();
        assert!(matches!(
            retire_never_confirmed_tracked_contract(&snapshot, &mut retire, profile(), &legacy, 0,),
            Err(IndexError::ContractConfirmationUnknown)
        ));
        let mut migrate = store.batch();
        assert_eq!(
            register_tracked_contract(&snapshot, &mut migrate, profile(), &legacy)
                .expect("legacy idempotent registration"),
            ContractRegistrationOutcome::AlreadyRegistered
        );
        drop(snapshot);
        store.commit(migrate).expect("legacy marker commit");
        let snapshot = store.snapshot().expect("marked legacy snapshot");
        assert_eq!(
            load_observation(&snapshot, legacy.id)
                .expect("legacy observation read")
                .expect("legacy observation")
                .state,
            ContractObservationState::LegacyUnknown
        );
    }

    #[test]
    fn one_address_tracks_multiple_bounded_exact_descriptor_candidates() {
        let store = MemoryStore::new();
        let first = htlc([6; 32]);
        let TrackedContractKind::HnsHtlcV1(mut second_descriptor) = first.kind.clone() else {
            panic!("HTLC fixture kind");
        };
        second_descriptor.value = 75;
        let second =
            ContractRegistration::hns_htlc_v1(second_descriptor).expect("second registration");
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
        assert!(
            tracked_contract_events(&snapshot, profile(), first.id, None, 8)
                .expect("first events")
                .entries
                .is_empty()
        );
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
                    &u16::try_from(index)
                        .expect("bounded candidate index")
                        .to_be_bytes(),
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
        recovery.inputs[0].witness.items[0] = low_s_signature(HIP1_SELLER_RECOVERY_SIGHASH);
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
            htlc.classify_spend(&refund, 0, &htlc_coin).expect("refund"),
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
        assert!(canonical_signature(&htlc_signature, HNS_HTLC_SIGHASH_ALL));
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
        assert!(!canonical_signature(&malformed, HNS_HTLC_SIGHASH_ALL));
    }
}
