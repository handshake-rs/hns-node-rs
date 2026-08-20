//! Typed noncustodial wallet backend over the canonical node runtime.

use std::{collections::HashMap, sync::Arc};

use hns_chain::{
    tx_index_entries_for_block, BlockIndexRecord, BlockStatus, HeaderRecord, RawBlockRecord,
    TxIndexEntry,
};
use hns_consensus::{
    hsd_wallet_renewal_height, is_coinbase, is_finalize_source_covenant, is_name_expired,
    is_transfer_mature, is_transfer_source_covenant, name_lifecycle,
    renewal_commitment_height_is_valid, transaction_sigops, transaction_weight,
    transfer_maturity_height, validate_block_commitments, validate_transaction_sanity, Network,
    HSD_CONSENSUS_PROFILE,
};
use hns_marketplace_protocol::DenuoPublicationAcceptanceExpectation;
use hns_mempool::{
    minimum_policy_fee, sigop_adjusted_virtual_size, Admission, MempoolInfo, MempoolSnapshot,
    HSD_MINIMUM_RELAY_FEE_RATE,
};
use hns_p2p::{BroadcastReport, Inventory, LivePeerManager, OutboundPriority, Packet};
use hns_primitives::{
    blake2b_256, hash_name, Address, Block, BlockHash, Coin, Covenant, CovenantKind, Height,
    NameHash, NameLifecycleState, NameState, Outpoint, Output, Transaction, Txid, Writer,
    MAX_RESOURCE_SIZE,
};
use hns_state::{
    decode_coin, decode_name_state, encode_coin, encode_name_state, encode_outpoint_key,
    load_stored_name_tree_root, prove_persisted_name_tree, TreeRoot,
};
use hns_store::{ColumnFamily, ReadSnapshot, Store};
use hns_urkel::UrkelProof;
use hns_wallet_index::{
    completed_tracked_contract_retirement, incoming_transfers, script_history, script_utxos,
    spending_transaction, tracked_contract, tracked_contract_events, tracked_contract_funding,
    tracked_contract_fundings, tracked_contract_lifecycle_revision, CompletedContractRetirement,
    CompletedContractRetirementOutcome, ContractId, ContractRegistration,
    ContractRegistrationOutcome, ContractRetirementOutcome, ContractRollbackBoundary,
    IncomingTransferCursor, IncomingTransferEntry, IndexError, ScriptHistoryCursor,
    ScriptHistoryEntry, ScriptHistoryPage, ScriptId, ScriptUtxo, ScriptUtxoCursor, ScriptUtxoPage,
    SpendingTransaction, TrackedContractCursor, TrackedContractEvent, TrackedContractFunding,
    TrackedContractSpendKind, WalletIndexProfile, MAX_QUERY_ENTRIES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    best_block_tip_from_snapshot, chain_epoch_from_snapshot, load_block, load_header_record,
    load_undo_pruning_checkpoint, median_time_past_with_lookup, read_canonical_hash,
    CanonicalEpoch, CanonicalStateWriter, CanonicalWriterError, DenuoNameMarketAdmission,
    DenuoNameMarketEventPage, DenuoNameMarketSnapshotPage, DenuoRelayHandle,
    LivePeerManager as ReexportedLivePeerManager, NodeReadHandle, NodeRuntime,
};

/// Maximum mempool entries sampled by one fee estimate.
pub const MAX_FEE_ESTIMATE_SAMPLES: usize = 4_096;
/// Maximum accepted confirmation target.
pub const MAX_FEE_ESTIMATE_TARGET_BLOCKS: u32 = 1_008;
/// Maximum transaction IDs inspected by one wallet mempool page.
pub const MAX_WALLET_MEMPOOL_SCAN: usize = 4_096;
/// Maximum relevant inputs plus outputs returned by one wallet mempool page.
pub const MAX_WALLET_MEMPOOL_ITEMS: usize = 4_096;
/// Maximum sorted-unique script identities reconciled in one mempool scan.
pub const MAX_WALLET_RESTORE_SCRIPTS: usize = 10_000;
/// Maximum confirmed rows returned by one global restoration page.
pub const MAX_WALLET_CONFIRMED_PAGE_ITEMS: usize = MAX_QUERY_ENTRIES;
/// Maximum script-prefix pages examined by one confirmed restoration call.
pub const MAX_WALLET_CONFIRMED_SCRIPT_EXAMINATIONS: usize = 256;
/// Version of the bounded incoming-TRANSFER candidate projection.
pub const INCOMING_TRANSFER_PROJECTION_VERSION: u8 = 1;
/// Version of the pruning-safe active NameState-owner Coin projection.
pub const ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION: u8 = 1;
/// Maximum script-prefix pages examined by one incoming-TRANSFER call.
pub const MAX_WALLET_INCOMING_TRANSFER_SCRIPT_EXAMINATIONS: usize = 256;
/// Maximum distinct retained block bodies decoded by one incoming-TRANSFER call.
pub const MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES: usize = 4;
/// Maximum outpoints inspected by one immutable spending-evidence capture.
pub const MAX_WALLET_OUTPOINT_SPEND_BATCH: usize = 4_096;
/// Maximum input coins resolved by one transaction-bound fee quote.
pub const MAX_WALLET_FEE_QUOTE_INPUTS: usize = 4_096;
/// Version of the immutable name-action preparation evidence contract.
pub const NAME_ACTION_CONTEXT_VERSION: u8 = 1;
/// Version of the pruning-safe Coin-backed name-action evidence contract.
pub const NAME_ACTION_CONTEXT_V2_VERSION: u8 = 2;
/// Fixed maximum number of distinct name-action ineligibility reasons.
pub const MAX_NAME_ACTION_INELIGIBILITY_REASONS: usize = 9;

const CONFIRMED_SCRIPT_SET_DOMAIN: &[u8] = b"hns-node/wallet-confirmed-script-set/v1";
const INCOMING_TRANSFER_SCRIPT_SET_DOMAIN: &[u8] =
    b"hns-node/wallet-incoming-transfer-script-set/v1";
const MEMPOOL_SCRIPT_SET_DOMAIN: &[u8] = b"hns-node/wallet-mempool-script-set/v1";
const MEMPOOL_CONTRACT_DOMAIN: &[u8] = b"hns-node/wallet-mempool-contract/v1";
const CONFIRMED_CURSOR_VERSION: u8 = 1;
const INCOMING_TRANSFER_CURSOR_VERSION: u8 = 1;
const MEMPOOL_CURSOR_VERSION: u8 = 1;

/// Opaque query-bound cursor for a single immutable mempool generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletMempoolCursor {
    binding_version: u8,
    chain_epoch: u64,
    instance_nonce: [u8; 32],
    generation: u64,
    query_id: [u8; 32],
    after_txid: Txid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ConfirmedScriptsPosition {
    History {
        script_index: usize,
        cursor: Option<ScriptHistoryCursor>,
    },
    Utxo {
        script_index: usize,
        cursor: Option<ScriptUtxoCursor>,
    },
}

/// Opaque continuation for a durable-chain-epoch-bound confirmed restore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedScriptsCursor {
    binding_version: u8,
    chain_epoch: u64,
    script_set_id: [u8; 32],
    position: ConfirmedScriptsPosition,
}

/// One confirmed history row tied to its sorted request position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedScriptHistory {
    /// Position in the caller's sorted-unique script set.
    pub script_index: usize,
    /// Exact active-chain history row.
    pub entry: ScriptHistoryEntry,
    /// Canonical block-header time, when available from the same snapshot.
    pub block_time: Option<u64>,
}

/// One confirmed active UTXO tied to its sorted request position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedScriptUtxo {
    /// Position in the caller's sorted-unique script set.
    pub script_index: usize,
    /// Exact active-chain UTXO row.
    pub entry: ScriptUtxo,
}

/// One bounded global page of confirmed history followed by active UTXOs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedScriptsPage {
    /// Durable chain generation shared by every page in this restore.
    pub chain_epoch: u64,
    /// Active tip captured with this page.
    pub tip: Option<WalletChainTip>,
    /// History rows for one traversed script, in canonical index order.
    pub history: Vec<ConfirmedScriptHistory>,
    /// UTXO rows for one traversed script, in outpoint order.
    pub utxos: Vec<ConfirmedScriptUtxo>,
    /// Script-prefix pages examined during this bounded call.
    pub script_examinations: usize,
    /// Exclusive continuation, rejected after a chain-generation change.
    pub continuation: Option<ConfirmedScriptsCursor>,
}

/// Opaque continuation for one exact incoming-TRANSFER candidate query.
///
/// This is an unkeyed query binding, not an authentication token or capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingTransfersCursor {
    binding_version: u8,
    chain_epoch: u64,
    tip: Option<WalletChainTip>,
    script_set_id: [u8; 32],
    script_index: usize,
    inner: Option<IncomingTransferCursor>,
}

/// Strength of the source-transaction binding for one incoming TRANSFER.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncomingTransferSourceBinding {
    /// Retained block bytes were decoded and matched at the exact transaction
    /// and output ordinal, including the header's body commitments.
    RetainedBodyVerified,
    /// Compact source evidence was corroborated against active durable node
    /// indexes and the UTXO set, but the pruned transaction preimage is absent.
    PrunedTrustedNodeProjection,
}

impl IncomingTransferSourceBinding {
    /// Stable wallet-RPC vocabulary for this evidence strength.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetainedBodyVerified => "retained_body_verified",
            Self::PrunedTrustedNodeProjection => "pruned_trusted_node_projection",
        }
    }
}

/// One active incoming-TRANSFER candidate tied to its sorted request position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletIncomingTransfer {
    /// Position in the caller's complete sorted-unique script set.
    pub script_index: usize,
    /// Exact active incoming-TRANSFER index row.
    pub entry: IncomingTransferEntry,
    /// Total output count of the source transaction.
    pub source_output_count: u32,
    /// Exact active-chain inclusion and transaction ordinal.
    pub inclusion: TransactionInclusion,
    /// Whether retained source bytes were available for exact verification.
    pub source_binding: IncomingTransferSourceBinding,
}

/// One bounded page of active incoming-TRANSFER candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingTransfersPage {
    /// Projection contract version, independent of the wallet RPC envelope.
    pub projection_version: u8,
    /// Durable canonical-chain generation shared by the whole page.
    pub chain_epoch: u64,
    /// Exact active tip captured in the same immutable snapshot.
    pub tip: Option<WalletChainTip>,
    /// Candidates for one traversed recipient script, in durable index order.
    pub entries: Vec<WalletIncomingTransfer>,
    /// Script-prefix pages examined by this bounded call.
    pub script_examinations: usize,
    /// Exclusive continuation bound to this exact query and chain snapshot.
    pub continuation: Option<IncomingTransfersCursor>,
}

/// One unconfirmed output paying a requested script.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolScriptOutput {
    /// Zero-based position in the caller's sorted-unique script set.
    pub script_index: usize,
    /// Unconfirmed output identity.
    pub outpoint: Outpoint,
    /// Value in HNS atomic units.
    pub value: u64,
}

/// One unconfirmed spend of a requested script.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolScriptSpend {
    /// Zero-based position in the caller's sorted-unique script set.
    pub script_index: usize,
    /// Confirmed or unconfirmed output being spent.
    pub outpoint: Outpoint,
}

/// Script-relevant activity from one contextual-mempool transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolScriptActivity {
    /// Canonical transaction ID.
    pub txid: Txid,
    /// Exact contextual-mempool admission time supplied to policy admission.
    pub admitted_at: u64,
    /// Outputs paying the requested script.
    pub received: Vec<MempoolScriptOutput>,
    /// Inputs spending confirmed or unconfirmed outputs of the requested script.
    pub spent: Vec<MempoolScriptSpend>,
}

/// One bounded global-scan page of script-relevant mempool activity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolScriptPage {
    /// Durable chain generation captured with this mempool page.
    pub chain_epoch: u64,
    /// Active tip captured with this mempool page.
    pub tip: Option<WalletChainTip>,
    /// Random non-persisted identity of the in-memory mempool instance.
    pub instance_nonce: [u8; 32],
    /// Exact immutable mempool generation used for the page.
    pub generation: u64,
    /// Relevant transactions in deterministic txid order.
    pub entries: Vec<MempoolScriptActivity>,
    /// Exclusive continuation if more transaction IDs remain to inspect.
    pub continuation: Option<WalletMempoolCursor>,
}

/// One unconfirmed event for an immutable registered contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MempoolContractEvent {
    /// An exact funding output is in the contextual mempool.
    Funding {
        /// Funding outpoint.
        outpoint: Outpoint,
        /// Funding value in HNS atomic units.
        value: u64,
    },
    /// An exact confirmed or unconfirmed funding is spent in the mempool.
    Spend {
        /// Funding outpoint.
        funding_outpoint: Outpoint,
        /// Spending input position.
        input_position: u32,
        /// Descriptor-bound spend branch.
        kind: TrackedContractSpendKind,
    },
}

/// Contract-relevant activity from one contextual-mempool transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolContractActivity {
    /// Canonical transaction ID.
    pub txid: Txid,
    /// Exact contextual-mempool admission time supplied to policy admission.
    pub admitted_at: u64,
    /// Descriptor-verified events in transaction order.
    pub events: Vec<MempoolContractEvent>,
}

/// One bounded global-scan page of registered-contract mempool activity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolContractPage {
    /// Durable chain generation captured with this mempool page.
    pub chain_epoch: u64,
    /// Active tip captured with this mempool page.
    pub tip: Option<WalletChainTip>,
    /// Random non-persisted identity of the in-memory mempool instance.
    pub instance_nonce: [u8; 32],
    /// Exact immutable mempool generation used for the page.
    pub generation: u64,
    /// Relevant transactions in deterministic txid order.
    pub entries: Vec<MempoolContractActivity>,
    /// Exclusive continuation if more transaction IDs remain to inspect.
    pub continuation: Option<WalletMempoolCursor>,
}

/// Opaque active-funding cursor bound to a contract and durable chain epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletContractFundingCursor {
    chain_epoch: u64,
    contract_id: ContractId,
    inner: TrackedContractCursor,
}

/// One chain-epoch-bound page of active confirmed contract fundings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletContractFundingPage {
    /// Durable chain generation for this page.
    pub chain_epoch: u64,
    /// Active tip captured with this page.
    pub tip: Option<WalletChainTip>,
    /// Currently active exact funding coins.
    pub entries: Vec<TrackedContractFunding>,
    /// Exclusive continuation rejected after reorg or contract substitution.
    pub continuation: Option<WalletContractFundingCursor>,
}

/// Opaque confirmed-event cursor bound to a contract and durable chain epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletContractEventCursor {
    chain_epoch: u64,
    contract_id: ContractId,
    inner: TrackedContractCursor,
}

/// One chain-epoch-bound page of durable confirmed contract events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletContractEventPage {
    /// Durable chain generation for this page.
    pub chain_epoch: u64,
    /// Active tip captured with this page.
    pub tip: Option<WalletChainTip>,
    /// Confirmed events in canonical order.
    pub entries: Vec<TrackedContractEvent>,
    /// Exclusive continuation rejected after reorg or contract substitution.
    pub continuation: Option<WalletContractEventCursor>,
}

/// Exact authority-bearing snapshot expected by never-confirmed retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractRetirementRequest {
    /// Complete public registration being retired.
    pub registration: ContractRegistration,
    /// Exact durable lifecycle revision observed with this registration.
    pub expected_lifecycle_revision: u64,
    /// Durable chain generation observed by the caller.
    pub expected_chain_epoch: u64,
    /// Exact authenticated tip observed in that generation.
    pub expected_tip: Option<WalletChainTip>,
    /// Process-local immutable mempool identity observed by the caller.
    pub expected_mempool_instance_nonce: [u8; 32],
    /// Exact immutable mempool generation observed by the caller.
    pub expected_mempool_generation: u64,
}

/// Typed in-process preparation context for never-confirmed retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractRetirementContext {
    /// Active registration, when present.
    pub registration: Option<ContractRegistration>,
    /// Durable lifecycle revision, when a marker exists. Revision presence is
    /// not an eligibility claim: `LegacyUnknown` markers still fail closed.
    pub lifecycle_revision: Option<u64>,
    /// Durable chain generation captured with the lifecycle.
    pub chain_epoch: u64,
    /// Exact authenticated tip captured with the lifecycle.
    pub tip: Option<WalletChainTip>,
    /// Process-local immutable mempool identity captured with the lifecycle.
    pub mempool_instance_nonce: [u8; 32],
    /// Exact immutable mempool generation captured with the lifecycle.
    pub mempool_generation: u64,
}

/// Committed never-confirmed retirement and its exact proof binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedContractRetirement {
    /// Content-derived registration identity.
    pub contract_id: ContractId,
    /// Idempotent durable mutation result.
    pub outcome: ContractRetirementOutcome,
    /// Lifecycle revision targeted by this request, including idempotent retry.
    pub lifecycle_revision: u64,
    /// Durable chain generation used for the proof and mutation.
    pub chain_epoch: u64,
    /// Exact authenticated tip used for the proof and mutation.
    pub tip: Option<WalletChainTip>,
    /// Process-local mempool identity used for the proof.
    pub mempool_instance_nonce: [u8; 32],
    /// Exact immutable mempool generation scanned for matching funding.
    pub mempool_generation: u64,
}

struct TrackedContractRetirementPlan {
    epoch: CanonicalEpoch,
    registration: ContractRegistration,
    lifecycle_revision: u64,
    chain_epoch: u64,
    tip: Option<WalletChainTip>,
    mempool_instance_nonce: [u8; 32],
    mempool_generation: u64,
}

/// Exact authority-bearing request for irreversible completed retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletedTrackedContractRetirementRequest {
    /// Complete public registration being permanently consumed.
    pub registration: ContractRegistration,
    /// Exact durable lifecycle revision observed with this registration.
    pub expected_lifecycle_revision: u64,
    /// Durable chain generation observed by the caller.
    pub expected_chain_epoch: u64,
    /// Exact authenticated tip observed in that generation.
    pub expected_tip: Option<WalletChainTip>,
    /// Exact undo-pruning checkpoint which must still authorize deletion.
    pub expected_rollback_boundary: ContractRollbackBoundary,
    /// Process-local immutable mempool identity observed by the caller.
    pub expected_mempool_instance_nonce: [u8; 32],
    /// Exact immutable mempool generation observed by the caller.
    pub expected_mempool_generation: u64,
    /// Explicit acknowledgement that no party controlled by the caller will
    /// ever fund, rebroadcast funding for, or re-register this descriptor.
    /// Later matching outputs remain consensus-valid but deliberately
    /// untracked by this retired lifecycle.
    pub acknowledge_permanent_descriptor_abandonment: bool,
}

/// Typed in-process preparation context for completed retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletedTrackedContractRetirementContext {
    /// Active registration, when this lifecycle is not yet retired.
    pub registration: Option<ContractRegistration>,
    /// Existing immutable proof, when this lifecycle is already retired.
    pub retirement: Option<CompletedContractRetirement>,
    /// Active or retired lifecycle revision.
    pub lifecycle_revision: Option<u64>,
    /// Durable chain generation captured with the lifecycle.
    pub chain_epoch: u64,
    /// Exact authenticated tip captured with the lifecycle.
    pub tip: Option<WalletChainTip>,
    /// Current undo-pruning authority. Absence makes completion ineligible.
    pub rollback_boundary: Option<ContractRollbackBoundary>,
    /// Process-local immutable mempool identity captured with the lifecycle.
    pub mempool_instance_nonce: [u8; 32],
    /// Exact immutable mempool generation captured with the lifecycle.
    pub mempool_generation: u64,
}

/// Committed completed retirement and its exact canonical proof binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletedTrackedContractRetirement {
    /// Idempotent durable mutation result.
    pub outcome: CompletedContractRetirementOutcome,
    /// Immutable persisted proof, including the descriptor and event digest.
    pub retirement: CompletedContractRetirement,
    /// Durable chain generation used for the proof and mutation.
    pub chain_epoch: u64,
    /// Exact authenticated tip used for the proof and mutation.
    pub tip: Option<WalletChainTip>,
    /// Process-local mempool identity used for the proof.
    pub mempool_instance_nonce: [u8; 32],
    /// Exact immutable mempool generation scanned for future funding.
    pub mempool_generation: u64,
}

struct CompletedTrackedContractRetirementPlan {
    epoch: CanonicalEpoch,
    registration: ContractRegistration,
    lifecycle_revision: u64,
    chain_epoch: u64,
    tip: Option<WalletChainTip>,
    rollback_boundary: ContractRollbackBoundary,
    mempool_instance_nonce: [u8; 32],
    mempool_generation: u64,
    permanent_abandonment_acknowledged: bool,
}

/// Current canonical active-chain tip.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletChainTip {
    /// Active-chain block hash.
    pub hash: BlockHash,
    /// Active-chain height.
    pub height: Height,
    /// HSD-compatible median timestamp of this tip and up to ten ancestors.
    pub median_time_past: u64,
    /// Exact authenticated name-tree root available for proofs at this tip.
    pub tree_root: TreeRoot,
}

/// Durable chain generation and exact active tip from one immutable read.
///
/// This is the script-free initial binding a separate wallet can capture before
/// disclosing any derived script identities to the node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletChainSnapshot {
    /// Durable monotonic canonical-chain generation.
    pub chain_epoch: u64,
    /// Exact active tip captured with `chain_epoch`, or `None` before the chain
    /// has initialized.
    pub tip: Option<WalletChainTip>,
}

/// Active-chain hash lookup captured with its immutable chain binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockHashEvidence {
    /// Durable chain generation containing the lookup and tip.
    pub chain_epoch: u64,
    /// Active tip captured with the lookup.
    pub tip: Option<WalletChainTip>,
    /// Height requested by the caller.
    pub height: Height,
    /// Active-chain hash at `height`, when that height exists.
    pub hash: Option<BlockHash>,
}

/// Confirmed transaction inclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionInclusion {
    /// Active-chain block hash.
    pub block_hash: BlockHash,
    /// Active-chain block height.
    pub height: Height,
    /// Exact zero-based block transaction position when retained block bytes
    /// make it derivable. Pruned legacy transaction-index rows do not persist
    /// this ordinal, so callers must never substitute a fabricated value.
    pub transaction_position: Option<u32>,
    /// Number of confirmations at the atomically read tip.
    pub confirmations: u32,
}

/// One queried outpoint and its active-chain spender, if any.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutpointSpendingEntry {
    /// Outpoint supplied by the caller.
    pub outpoint: Outpoint,
    /// Active-chain spending transaction evidence.
    pub spending: Option<SpendingTransaction>,
}

/// Ordered outpoint-spend evidence captured from one immutable chain snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutpointSpendingEvidence {
    /// Durable chain generation shared by every result.
    pub chain_epoch: u64,
    /// Active tip captured with every result.
    pub tip: Option<WalletChainTip>,
    /// Exactly one entry per requested outpoint, in request order.
    pub entries: Vec<OutpointSpendingEntry>,
}

/// Wallet-facing transaction status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is admitted to the contextual node mempool.
    Mempool,
    /// Transaction is included in the active chain.
    Confirmed(TransactionInclusion),
    /// Transaction is absent from both configured indexes and mempool.
    Unknown,
}

/// Raw transaction availability in one combined evidence capture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// Exact raw transaction retained by the mempool or active block store.
    Retained(Transaction),
    /// Confirmed inclusion is known, but pruning retired the raw block payload.
    Pruned,
    /// The transaction is unknown to the configured active indexes and mempool.
    Absent,
}

/// Status, inclusion, payload, and chain context from one stable generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionEvidence {
    /// Durable chain generation read from the same store snapshot.
    pub chain_epoch: u64,
    /// Random non-persisted identity of the captured mempool instance.
    pub mempool_instance_nonce: [u8; 32],
    /// Exact immutable contextual-mempool generation.
    pub mempool_generation: u64,
    /// Active tip used for confirmation depth and canonical binding.
    pub tip: Option<WalletChainTip>,
    /// Mempool/confirmed/unknown classification.
    pub status: TransactionStatus,
    /// Active inclusion, identical to the confirmed status payload when set.
    pub inclusion: Option<TransactionInclusion>,
    /// Raw transaction availability in this same capture.
    pub payload: TransactionPayload,
}

/// Fee estimate source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FeeEstimateSource {
    /// No bounded mempool sample existed; minimum relay policy was returned.
    MinimumRelay,
    /// A bounded deterministic mempool fee-rate quantile was used.
    Mempool,
}

/// Bounded fee-rate estimate in atomic units per 1,000 policy virtual bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Requested confirmation target.
    pub target_blocks: u32,
    /// Estimated atomic units per 1,000 policy virtual bytes.
    pub atomic_units_per_kvb: u64,
    /// Mempool entries inspected, bounded by [`MAX_FEE_ESTIMATE_SAMPLES`].
    pub sampled_transactions: usize,
    /// Evidence source for the estimate.
    pub source: FeeEstimateSource,
}

/// Exact HSD fee-policy quote for one caller-supplied canonical transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionFeeQuote {
    /// Canonical transaction ID of the quoted raw transaction.
    pub txid: Txid,
    /// Durable chain generation used to resolve every input coin.
    pub chain_epoch: u64,
    /// Active tip captured with the chain snapshot.
    pub tip: Option<WalletChainTip>,
    /// Random non-persisted identity of the captured mempool instance.
    pub mempool_instance_nonce: [u8; 32],
    /// Exact immutable contextual-mempool generation used for input resolution
    /// and rate sampling.
    pub mempool_generation: u64,
    /// Requested confirmation target.
    pub target_blocks: u32,
    /// Estimated rate in atomic units per 1,000 HSD policy virtual bytes.
    pub rate_atomic_units_per_1000_policy_vbytes: u64,
    /// Number of mempool entries in the bounded rate sample.
    pub rate_sample_count: usize,
    /// Evidence source for the sampled rate.
    pub rate_source: FeeEstimateSource,
    /// Exact consensus transaction weight.
    pub transaction_weight: usize,
    /// Exact sigop count using node-resolved input coins.
    pub transaction_sigops: u32,
    /// HSD sigop-adjusted policy virtual size.
    pub sigop_adjusted_policy_vbytes: usize,
    /// HSD minimum policy fee at the sampled rate, in atomic units.
    pub minimum_policy_fee_atomic_units: u64,
    /// Fee paid by the supplied transaction from node-resolved input values,
    /// in atomic units.
    pub actual_fee_atomic_units: u64,
    /// Whether the supplied transaction pays at least this quote's minimum.
    pub meets_minimum_policy_fee: bool,
    /// Additional atomic units needed to meet this quote's minimum.
    pub minimum_policy_fee_shortfall_atomic_units: u64,
}

/// Current name proof bound to the active durable tree root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameProofResult {
    /// Active tip captured with the root and proof.
    pub tip: Option<WalletChainTip>,
    /// Active name-tree root used to generate the proof.
    pub root: TreeRoot,
    /// Canonical inclusion/non-inclusion proof.
    pub proof: UrkelProof,
}

/// Strength of the source binding for an active NameState-owner Coin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveNameOwnerCoinSourceBinding {
    /// The exact Coin was loaded from the active UTXO set and corroborated
    /// against current NameState, the canonical transaction index, and the
    /// active chain. No retained transaction body or cryptographic output
    /// proof is implied.
    TrustedNodeActiveUtxoProjection,
}

impl ActiveNameOwnerCoinSourceBinding {
    /// Stable wallet-RPC vocabulary for this evidence strength.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedNodeActiveUtxoProjection => "trusted_node_active_utxo_projection",
        }
    }
}

/// Pruning-safe current NameState and exact active owner Coin evidence.
///
/// This is bounded discovery/current-active-UTXO evidence from a trusted node.
/// It is neither a cryptographic proof that the output bytes produced the
/// transaction ID nor signing authority. `transaction_position` remains null
/// because this projection deliberately never loads a retained block body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveNameOwnerCoinEvidence {
    /// Projection contract version, independent of the wallet RPC envelope.
    pub projection_version: u8,
    /// Durable canonical-chain generation containing every field.
    pub chain_epoch: u64,
    /// Exact initialized active tip captured in the same immutable snapshot.
    pub tip: WalletChainTip,
    /// Exact canonical bytes stored for the current NameState value.
    pub current_state_bytes: Vec<u8>,
    /// Decoded current NameState bound to `current_state_bytes` and its key.
    pub current_state: NameState,
    /// Exact active UTXO selected by `current_state.owner`.
    pub owner_coin: Coin,
    /// Canonical active-chain inclusion; transaction position is unavailable.
    pub inclusion: TransactionInclusion,
    /// Explicit trusted-node projection strength.
    pub source_binding: ActiveNameOwnerCoinSourceBinding,
}

/// Current and root-bound name evidence from one immutable chain snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameEvidence {
    /// Durable chain generation containing every field in this result.
    pub chain_epoch: u64,
    /// Active tip whose tree root equals `proof.root` when a tip exists.
    pub tip: Option<WalletChainTip>,
    /// Latest active NameState column value, including pending interval changes.
    pub current_state: Option<NameState>,
    /// State value authenticated by the interval-committed proof root.
    pub proof_state: Option<NameState>,
    /// Root-bound inclusion/non-inclusion proof.
    pub proof: NameProofResult,
    /// Owner transaction selected by `current_state`, when it has an owner.
    pub current_owner: Option<NameOwnerTransaction>,
    /// Owner transaction selected by `proof_state`, when it has an owner.
    pub proof_owner: Option<NameOwnerTransaction>,
}

/// Current owner transaction and exact owner output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameOwnerTransaction {
    /// Current name state whose owner was followed.
    pub name_state: NameState,
    /// Owner outpoint from the current name state.
    pub owner: Outpoint,
    /// Confirmed owner transaction.
    pub transaction: Transaction,
    /// Exact owner output selected by `owner.index`.
    pub owner_output: Output,
    /// Active-chain inclusion.
    pub inclusion: TransactionInclusion,
}

/// Candidate name covenant the external wallet intends to construct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameAction {
    /// Begin transfer to a covenant-committed recipient.
    Transfer,
    /// Finalize a mature pending transfer.
    Finalize,
}

/// Fixed, bounded reason vocabulary for a candidate-specific action decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameActionIneligibility {
    NameNotRegistered,
    NameExpiredAtCandidate,
    LifecycleNotClosed,
    TransferAlreadyPending,
    TransferNotPending,
    TransferNotMature,
    OwnerCovenantInvalidForAction,
    RenewalCommitmentInvalid,
    OwnerSpentInMempool,
}

/// Canonical transfer lockup evidence at the candidate inclusion height.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameTransferContext {
    pub lockup_blocks: u32,
    pub current_transfer_height: Option<Height>,
    pub finalize_maturity_height: Option<Height>,
    pub finalize_eligible_at_candidate: bool,
}

/// HSD wallet-selected renewal commitment and consensus-window evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameRenewalContext {
    pub maturity_blocks: u32,
    pub period_blocks: u32,
    pub hsd_selected_height: Height,
    pub hsd_selected_hash: BlockHash,
    pub valid_at_candidate: bool,
}

/// One immutable, candidate-specific TRANSFER or FINALIZE preparation capture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameActionContext {
    pub context_version: u8,
    pub action: NameAction,
    pub network: Network,
    pub network_id: u8,
    pub genesis_hash: BlockHash,
    pub consensus_profile: String,
    pub chain_epoch: u64,
    pub tip: WalletChainTip,
    pub candidate_inclusion_height: Height,
    pub mempool_instance_nonce: [u8; 32],
    pub mempool_generation: u64,
    pub owner_spender_txid: Option<Txid>,
    pub name_hash: NameHash,
    pub current_state: NameState,
    pub owner: NameOwnerTransaction,
    pub lifecycle: NameLifecycleState,
    pub transfer: NameTransferContext,
    pub renewal: NameRenewalContext,
    pub ineligibility_reasons: Vec<NameActionIneligibility>,
}

impl NameActionContext {
    /// The action is eligible only when no fixed fail-closed reason applies.
    #[must_use]
    pub fn eligible(&self) -> bool {
        self.ineligibility_reasons.is_empty()
    }
}

/// Pruning-safe active-owner projection embedded in a version-2 name action.
///
/// The Coin comes from the active UTXO set and is corroborated by the current
/// NameState and canonical transaction index. It is trusted-node evidence,
/// not a transaction-output proof or an assertion that a wallet owns the
/// corresponding private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameActionActiveOwnerCoin {
    /// Projection version shared with [`ActiveNameOwnerCoinEvidence`].
    pub projection_version: u8,
    /// Exact active Coin selected by the current NameState owner outpoint.
    pub owner_coin: Coin,
    /// Canonical inclusion with an intentionally unavailable transaction
    /// position because no raw block body is read.
    pub inclusion: TransactionInclusion,
    /// Explicit trusted-node projection strength.
    pub source_binding: ActiveNameOwnerCoinSourceBinding,
}

/// One pruning-safe, candidate-specific TRANSFER or FINALIZE evidence capture.
///
/// This public evidence cannot construct, sign, approve, quote, admit, or
/// broadcast a transaction. In particular, the node does not know whether the
/// active Coin's address belongs to the caller; a wallet must establish that
/// relationship independently from its own derivation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameActionContextV2 {
    pub context_version: u8,
    pub action: NameAction,
    pub network: Network,
    pub network_id: u8,
    pub genesis_hash: BlockHash,
    pub consensus_profile: String,
    pub chain_epoch: u64,
    pub tip: WalletChainTip,
    pub candidate_inclusion_height: Height,
    pub mempool_instance_nonce: [u8; 32],
    pub mempool_generation: u64,
    pub owner_spender_txid: Option<Txid>,
    pub name_hash: NameHash,
    /// Exact canonical bytes stored for the current NameState value.
    pub current_state_bytes: Vec<u8>,
    /// Decoded current state bound to `current_state_bytes` and `name_hash`.
    pub current_state: NameState,
    pub active_owner: NameActionActiveOwnerCoin,
    pub lifecycle: NameLifecycleState,
    pub transfer: NameTransferContext,
    pub renewal: NameRenewalContext,
    pub ineligibility_reasons: Vec<NameActionIneligibility>,
}

impl NameActionContextV2 {
    /// The action is contextually eligible only when no fixed reason applies.
    /// Eligibility remains public evidence and never grants spending authority.
    #[must_use]
    pub fn eligible(&self) -> bool {
        self.ineligibility_reasons.is_empty()
    }
}

/// Result of contextual admission and actual P2P inventory fanout.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BroadcastResult {
    /// Canonical transaction ID.
    pub txid: Txid,
    /// Whether this call newly admitted the transaction to the mempool.
    pub newly_admitted: bool,
    /// Ready peers targeted by inventory fanout.
    pub attempted_peers: usize,
    /// Peer queues that accepted the inventory.
    pub queued_peers: usize,
    /// Peer queues that rejected the inventory.
    pub failed_peers: usize,
}

/// Typed wallet backend failure.
#[derive(Debug, Error)]
pub enum WalletBackendError {
    /// Canonical node runtime or storage failed.
    #[error("wallet backend node failure: {0}")]
    Node(String),
    /// Required optional index is disabled.
    #[error("wallet backend index is disabled: {0}")]
    IndexDisabled(&'static str),
    /// Indexed data is inconsistent with the active chain.
    #[error("wallet backend index corruption: {0}")]
    Corrupt(&'static str),
    /// Confirmed inclusion is indexed but the configured pruning profile no
    /// longer retains the raw block payload.
    #[error("wallet backend raw transaction payload was pruned")]
    PayloadPruned,
    /// No immutable public contract registration exists for the requested ID.
    #[error("wallet tracked-contract registration is unknown")]
    UnknownContract,
    /// Public contract terms are malformed or conflict with an existing lock.
    #[error("wallet tracked-contract registration is invalid or conflicts")]
    InvalidContract,
    /// Active public contract registry capacity is exhausted.
    #[error("wallet tracked-contract registry is full")]
    ContractCapacity,
    /// Immutable retirement tombstone registry capacity is exhausted.
    #[error("wallet tracked-contract retirement registry is full")]
    ContractRetirementCapacity,
    /// One lifecycle has more confirmed rows than the bounded atomic
    /// retirement proof walk permits.
    #[error("wallet tracked-contract retirement history exceeds its hard bound")]
    ContractRetirementHistoryCapacity,
    /// Retirement requires the lifecycle-specific history state, no retained
    /// transaction orphans, and no matching ordinary or airdrop funding in the
    /// exact currently bound mempool generation.
    #[error("wallet tracked-contract registration is not eligible for retirement")]
    ContractNotRetirable,
    /// Completed retirement is above the durable undo-pruned frontier or lacks
    /// a complete terminal history proof.
    #[error("wallet tracked-contract history still requires rollback authority")]
    ContractRollbackRequired,
    /// Completed retirement requires an explicit permanent descriptor-lifecycle
    /// abandonment acknowledgement.
    #[error("wallet tracked-contract permanent abandonment was not acknowledged")]
    PermanentContractAbandonmentRequired,
    /// The undo-pruning checkpoint changed after retirement preparation.
    #[error("wallet tracked-contract rollback boundary changed; retry")]
    StaleContractRollbackBoundary,
    /// A retirement request belongs to an older exact registration lifecycle.
    #[error("wallet tracked-contract lifecycle changed from {expected} to {actual:?}")]
    StaleContractLifecycle { expected: u64, actual: Option<u64> },
    /// A continuation belongs to an older immutable mempool generation.
    #[error("wallet mempool generation changed from {expected} to {actual}")]
    StaleMempoolGeneration { expected: u64, actual: u64 },
    /// A continuation belongs to another process-local mempool instance.
    #[error("wallet mempool instance changed; restart reconciliation")]
    StaleMempoolInstance,
    /// A mempool continuation belongs to another script set or contract.
    #[error("wallet mempool continuation belongs to another query")]
    InvalidMempoolCursor,
    /// A confirmed restoration continuation belongs to an older chain epoch.
    #[error("wallet chain epoch changed from {expected} to {actual}")]
    StaleChainEpoch { expected: u64, actual: u64 },
    /// A canonical writer generation overlapped an authority-bearing read.
    #[error("wallet canonical generation changed during read; retry")]
    StaleCanonicalRead,
    /// A confirmed restoration continuation belongs to another script set or
    /// contains an impossible traversal position.
    #[error("wallet confirmed restoration cursor is invalid")]
    InvalidConfirmedCursor,
    /// An incoming-TRANSFER continuation belongs to another chain tip, script
    /// set, or traversal position.
    #[error("wallet incoming-TRANSFER cursor is invalid")]
    InvalidIncomingTransferCursor,
    /// A confirmed restoration result bound is invalid.
    #[error("wallet confirmed restoration limit must be between 1 and {MAX_WALLET_CONFIRMED_PAGE_ITEMS}")]
    InvalidConfirmedPageLimit,
    /// An incoming-TRANSFER result bound is invalid.
    #[error("wallet incoming-TRANSFER limit must be between 1 and {MAX_QUERY_ENTRIES}")]
    InvalidIncomingTransferPageLimit,
    /// A point or contract index page bound is invalid.
    #[error("wallet index page limit must be between 1 and {MAX_QUERY_ENTRIES}")]
    InvalidIndexPageLimit,
    /// A mempool scan bound is invalid.
    #[error("wallet mempool scan limit must be between 1 and {MAX_WALLET_MEMPOOL_SCAN}")]
    InvalidMempoolScanLimit,
    /// Outpoint-spend evidence batch is empty or oversized.
    #[error(
        "wallet outpoint-spend batch must contain 1..={MAX_WALLET_OUTPOINT_SPEND_BATCH} entries"
    )]
    InvalidOutpointBatch,
    /// Script restoration set is empty, oversized, unsorted, or duplicated.
    #[error("wallet restoration scripts must be sorted, unique, and contain 1..={MAX_WALLET_RESTORE_SCRIPTS} entries")]
    InvalidScriptSet,
    /// Relevant data exceeded the response item envelope.
    #[error("wallet mempool result exceeds {MAX_WALLET_MEMPOOL_ITEMS} relevant items")]
    MempoolResultLimit,
    /// Contextual mempool policy rejected the transaction.
    #[error("wallet transaction rejected: {0}")]
    Rejected(String),
    /// Transaction is retained as an orphan and was not relayed as accepted.
    #[error("wallet transaction is an unresolved orphan: {0:?}")]
    Orphan(Txid),
    /// Fee target is outside its bounded range.
    #[error("fee target must be between 1 and {MAX_FEE_ESTIMATE_TARGET_BLOCKS}")]
    InvalidFeeTarget,
    /// A transaction cannot be quoted because it is structurally or
    /// economically invalid, or is a coinbase transaction rather than an
    /// ordinary wallet transaction.
    #[error("transaction is not eligible for a wallet fee quote")]
    InvalidFeeQuoteTransaction,
    /// A transaction input cannot be resolved from the bound active UTXO set
    /// or immutable mempool generation.
    #[error("transaction fee quote input coin is unavailable")]
    FeeQuoteInputUnavailable,
    /// Requested name has no current owner outpoint.
    #[error("current name state has no owner")]
    NameHasNoOwner,
    /// Requested name has no active state in the current chain snapshot.
    #[error("current name state is absent")]
    NameStateMissing,
    /// Local Denuo relay or typed name-market admission failed.
    #[error("Denuo name-market operation failed: {0}")]
    DenuoNameMarket(String),
    /// Current name evidence requires an initialized active chain.
    #[error("wallet name evidence requires an initialized active chain")]
    ChainUninitialized,
    /// Current owner output index is absent from its transaction.
    #[error("current name owner output is missing")]
    OwnerOutputMissing,
}

/// Cloneable, typed first-party Handshake wallet backend.
///
/// It contains no wallet keys and cannot sign. Mutating broadcast first enters
/// the canonical contextual mempool admission path and only then announces
/// inventory to live peers.
#[derive(Clone)]
pub struct WalletBackend {
    read: NodeReadHandle,
    writer: CanonicalStateWriter,
    peers: LivePeerManager,
    denuo_relay: DenuoRelayHandle,
}

impl std::fmt::Debug for WalletBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WalletBackend")
            .field("network", &self.read.network())
            .field("index_profile", &self.read.wallet_index_profile())
            .finish_non_exhaustive()
    }
}

impl NodeRuntime {
    /// Bind typed wallet reads/writes to this runtime and live peer manager.
    #[must_use]
    pub fn wallet_backend(&self, peers: ReexportedLivePeerManager) -> WalletBackend {
        WalletBackend {
            read: self.read(),
            writer: self.writer(),
            peers,
            denuo_relay: self.denuo_relay(),
        }
    }
}

impl WalletBackend {
    /// Commit one exact canonical local Denuo publication before propagating
    /// its typed message to every exactly admitted V2 peer.
    pub async fn publish_denuo_name_market(
        &self,
        envelope_bytes: &[u8],
        expectation: DenuoPublicationAcceptanceExpectation,
        now: u64,
    ) -> Result<(DenuoNameMarketAdmission, BroadcastReport, Vec<u8>), WalletBackendError> {
        let (admission, receipt) = self
            .denuo_relay
            .submit_name_market_handoff(envelope_bytes, expectation, now)
            .map_err(|error| WalletBackendError::DenuoNameMarket(error.to_string()))?;
        let report = if let Some(message) = admission.rebroadcast.as_ref() {
            self.peers
                .broadcast_denuo_name_market(admission.revision.max(1), message)
                .await
        } else {
            BroadcastReport::default()
        };
        Ok((admission, report, receipt))
    }

    /// Read one bounded process-local Denuo event page. Event bytes remain
    /// untrusted marketplace input; the wallet must verify and reconcile them
    /// against its current chain authority before use.
    pub fn get_denuo_name_market_events(
        &self,
        expected_instance_nonce: Option<[u8; 32]>,
        after_revision: u64,
        limit: usize,
    ) -> Result<DenuoNameMarketEventPage, WalletBackendError> {
        let instance_nonce = *self
            .read
            .published_mempool()
            .map_err(node_error)?
            .snapshot()
            .instance_nonce();
        let cursor_reset =
            expected_instance_nonce.is_some_and(|expected| expected != instance_nonce);
        let effective_after_revision = if cursor_reset { 0 } else { after_revision };
        let mut page = self
            .denuo_relay
            .name_market_events(instance_nonce, effective_after_revision, limit)
            .map_err(|error| WalletBackendError::DenuoNameMarket(error.to_string()))?;
        page.cursor_reset = cursor_reset;
        Ok(page)
    }

    /// Read one coherent bounded page over the latest seller/name relay state.
    pub fn get_denuo_name_market_snapshot(
        &self,
        expected_revision: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<DenuoNameMarketSnapshotPage, WalletBackendError> {
        let instance_nonce = *self
            .read
            .published_mempool()
            .map_err(node_error)?
            .snapshot()
            .instance_nonce();
        self.denuo_relay
            .name_market_snapshot(instance_nonce, expected_revision, offset, limit)
            .map_err(|error| WalletBackendError::DenuoNameMarket(error.to_string()))
    }

    /// Read the active chain tip.
    pub async fn get_chain_tip(&self) -> Result<Option<WalletChainTip>, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| wallet_chain_tip(snapshot)).await
    }

    /// Read the durable chain generation and exact active tip atomically.
    ///
    /// Unlike script restoration, this operation takes no wallet-derived
    /// identities. It is suitable for establishing a complete initial wallet
    /// snapshot binding before any script query.
    pub async fn get_chain_snapshot(&self) -> Result<WalletChainSnapshot, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            Ok(WalletChainSnapshot {
                chain_epoch: chain_epoch_from_snapshot(snapshot).map_err(node_error)?,
                tip: wallet_chain_tip(snapshot)?,
            })
        })
        .await
    }

    /// Read the active-chain hash at one exact height.
    pub async fn get_block_hash(
        &self,
        height: Height,
    ) -> Result<Option<BlockHash>, WalletBackendError> {
        self.get_block_hash_evidence(height)
            .await
            .map(|evidence| evidence.hash)
    }

    /// Read an active-chain hash together with the exact snapshot binding.
    pub async fn get_block_hash_evidence(
        &self,
        height: Height,
    ) -> Result<BlockHashEvidence, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            Ok(BlockHashEvidence {
                chain_epoch: chain_epoch_from_snapshot(snapshot).map_err(node_error)?,
                tip: wallet_chain_tip(snapshot)?,
                height,
                hash: read_canonical_hash(snapshot, height).map_err(node_error)?,
            })
        })
        .await
    }

    /// Read a transaction from the contextual mempool or active tx index.
    pub async fn get_raw_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<Transaction>, WalletBackendError> {
        match self.get_transaction_evidence(txid).await?.payload {
            TransactionPayload::Retained(transaction) => Ok(Some(transaction)),
            TransactionPayload::Pruned => Err(WalletBackendError::PayloadPruned),
            TransactionPayload::Absent => Ok(None),
        }
    }

    /// Return one generation-stable status/inclusion/payload evidence capture.
    pub async fn get_transaction_evidence(
        &self,
        txid: Txid,
    ) -> Result<TransactionEvidence, WalletBackendError> {
        let transaction_index = self.read.transaction_index;
        let read = self.read.clone();
        blocking_mempool_read(read, move |_, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            let tip = wallet_chain_tip(snapshot)?;
            if let Some(transaction) = mempool.transaction(&txid).cloned() {
                if transaction_index
                    && load_transaction_index_and_inclusion(snapshot, txid)?.is_some()
                {
                    return Err(WalletBackendError::Corrupt(
                        "transaction is simultaneously active-chain confirmed and in mempool",
                    ));
                }
                return Ok(TransactionEvidence {
                    chain_epoch,
                    mempool_instance_nonce: *mempool.instance_nonce(),
                    mempool_generation: mempool.generation(),
                    tip,
                    status: TransactionStatus::Mempool,
                    inclusion: None,
                    payload: TransactionPayload::Retained(transaction),
                });
            }
            if !transaction_index {
                return Err(WalletBackendError::IndexDisabled("transaction"));
            }
            let Some((index, mut inclusion)) =
                load_transaction_index_and_inclusion(snapshot, txid)?
            else {
                return Ok(TransactionEvidence {
                    chain_epoch,
                    mempool_instance_nonce: *mempool.instance_nonce(),
                    mempool_generation: mempool.generation(),
                    tip,
                    status: TransactionStatus::Unknown,
                    inclusion: None,
                    payload: TransactionPayload::Absent,
                });
            };
            let payload = match load_block(snapshot, &index.block_hash).map_err(node_error)? {
                Some(block) => {
                    let (position, transaction) = block
                        .transactions
                        .into_iter()
                        .enumerate()
                        .find(|(_, transaction)| transaction.txid() == txid)
                        .ok_or(WalletBackendError::Corrupt(
                            "indexed transaction is absent from its block",
                        ))?;
                    inclusion.transaction_position =
                        Some(u32::try_from(position).map_err(|_| {
                            WalletBackendError::Corrupt("block transaction position exceeds u32")
                        })?);
                    TransactionPayload::Retained(transaction)
                }
                None => TransactionPayload::Pruned,
            };
            Ok(TransactionEvidence {
                chain_epoch,
                mempool_instance_nonce: *mempool.instance_nonce(),
                mempool_generation: mempool.generation(),
                tip,
                status: TransactionStatus::Confirmed(inclusion.clone()),
                inclusion: Some(inclusion),
                payload,
            })
        })
        .await
    }

    /// Return mempool/confirmed/unknown status from a combined stable capture.
    pub async fn get_transaction_status(
        &self,
        txid: Txid,
    ) -> Result<TransactionStatus, WalletBackendError> {
        self.get_transaction_evidence(txid)
            .await
            .map(|evidence| evidence.status)
    }

    /// Return active-chain inclusion from a combined stable capture.
    pub async fn get_transaction_inclusion(
        &self,
        txid: Txid,
    ) -> Result<Option<TransactionInclusion>, WalletBackendError> {
        self.get_transaction_evidence(txid)
            .await
            .map(|evidence| evidence.inclusion)
    }

    /// Return one bounded point-query page of active-chain script history.
    /// Multi-script restoration must use [`Self::get_confirmed_scripts_page`].
    pub async fn get_script_history(
        &self,
        script: ScriptId,
        cursor: Option<ScriptHistoryCursor>,
        limit: usize,
    ) -> Result<ScriptHistoryPage, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            script_history(snapshot, profile, script, cursor.as_ref(), limit)
                .map_err(wallet_index_error)
        })
        .await
    }

    /// Return one bounded point-query page of active script UTXOs.
    /// Multi-script restoration must use [`Self::get_confirmed_scripts_page`].
    pub async fn get_script_utxos(
        &self,
        script: ScriptId,
        cursor: Option<ScriptUtxoCursor>,
        limit: usize,
    ) -> Result<ScriptUtxoPage, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            script_utxos(snapshot, profile, script, cursor.as_ref(), limit)
                .map_err(wallet_index_error)
        })
        .await
    }

    /// Traverse confirmed history and active UTXOs for one restoration set.
    ///
    /// The request must be sorted and unique. Result indexes refer to that
    /// sorted order. A reorganization changes the durable chain epoch and
    /// invalidates the continuation before another page can be returned.
    pub async fn get_confirmed_scripts_page(
        &self,
        scripts: Vec<ScriptId>,
        cursor: Option<ConfirmedScriptsCursor>,
        limit: usize,
    ) -> Result<ConfirmedScriptsPage, WalletBackendError> {
        if !(1..=MAX_WALLET_CONFIRMED_PAGE_ITEMS).contains(&limit) {
            return Err(WalletBackendError::InvalidConfirmedPageLimit);
        }
        validate_script_set(&scripts)?;
        let profile = self.read.wallet_index_profile();
        if !profile.wallet {
            return Err(WalletBackendError::IndexDisabled("wallet"));
        }
        let script_set_id = confirmed_script_set_id(&scripts)?;
        let read = self.read.clone();
        blocking_chain_collection_read(read, move |_, snapshot| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            let tip = wallet_chain_tip(snapshot)?;
            let mut position = match cursor {
                Some(cursor) => {
                    if cursor.binding_version != CONFIRMED_CURSOR_VERSION {
                        return Err(WalletBackendError::InvalidConfirmedCursor);
                    }
                    if cursor.chain_epoch != chain_epoch {
                        return Err(WalletBackendError::StaleChainEpoch {
                            expected: cursor.chain_epoch,
                            actual: chain_epoch,
                        });
                    }
                    if cursor.script_set_id != script_set_id {
                        return Err(WalletBackendError::InvalidConfirmedCursor);
                    }
                    cursor.position
                }
                None => ConfirmedScriptsPosition::History {
                    script_index: 0,
                    cursor: None,
                },
            };
            let mut script_examinations = 0usize;
            let mut block_times = HashMap::<BlockHash, Option<u64>>::new();

            loop {
                if script_examinations == MAX_WALLET_CONFIRMED_SCRIPT_EXAMINATIONS {
                    return Ok(ConfirmedScriptsPage {
                        chain_epoch,
                        tip,
                        history: Vec::new(),
                        utxos: Vec::new(),
                        script_examinations,
                        continuation: Some(ConfirmedScriptsCursor {
                            binding_version: CONFIRMED_CURSOR_VERSION,
                            chain_epoch,
                            script_set_id,
                            position,
                        }),
                    });
                }
                script_examinations = script_examinations.saturating_add(1);
                match position {
                    ConfirmedScriptsPosition::History {
                        script_index,
                        cursor,
                    } => {
                        let script = scripts
                            .get(script_index)
                            .copied()
                            .ok_or(WalletBackendError::InvalidConfirmedCursor)?;
                        let page =
                            script_history(snapshot, profile, script, cursor.as_ref(), limit)
                                .map_err(wallet_index_error)?;
                        let history = page
                            .entries
                            .into_iter()
                            .map(|entry| {
                                let block_time =
                                    load_block_time(snapshot, &mut block_times, entry.block_hash)?;
                                Ok(ConfirmedScriptHistory {
                                    script_index,
                                    entry,
                                    block_time,
                                })
                            })
                            .collect::<Result<Vec<_>, WalletBackendError>>()?;
                        let next_position = if let Some(cursor) = page.continuation {
                            ConfirmedScriptsPosition::History {
                                script_index,
                                cursor: Some(cursor),
                            }
                        } else if script_index + 1 < scripts.len() {
                            ConfirmedScriptsPosition::History {
                                script_index: script_index + 1,
                                cursor: None,
                            }
                        } else {
                            ConfirmedScriptsPosition::Utxo {
                                script_index: 0,
                                cursor: None,
                            }
                        };
                        if history.is_empty() {
                            position = next_position;
                            continue;
                        }
                        return Ok(ConfirmedScriptsPage {
                            chain_epoch,
                            tip,
                            history,
                            utxos: Vec::new(),
                            script_examinations,
                            continuation: Some(ConfirmedScriptsCursor {
                                binding_version: CONFIRMED_CURSOR_VERSION,
                                chain_epoch,
                                script_set_id,
                                position: next_position,
                            }),
                        });
                    }
                    ConfirmedScriptsPosition::Utxo {
                        script_index,
                        cursor,
                    } => {
                        let script = scripts
                            .get(script_index)
                            .copied()
                            .ok_or(WalletBackendError::InvalidConfirmedCursor)?;
                        let page = script_utxos(snapshot, profile, script, cursor.as_ref(), limit)
                            .map_err(wallet_index_error)?;
                        let utxos = page
                            .entries
                            .into_iter()
                            .map(|entry| ConfirmedScriptUtxo {
                                script_index,
                                entry,
                            })
                            .collect::<Vec<_>>();
                        let next_position = if let Some(cursor) = page.continuation {
                            Some(ConfirmedScriptsPosition::Utxo {
                                script_index,
                                cursor: Some(cursor),
                            })
                        } else if script_index + 1 < scripts.len() {
                            Some(ConfirmedScriptsPosition::Utxo {
                                script_index: script_index + 1,
                                cursor: None,
                            })
                        } else {
                            None
                        };
                        if utxos.is_empty() {
                            let Some(next_position) = next_position else {
                                return Ok(ConfirmedScriptsPage {
                                    chain_epoch,
                                    tip,
                                    history: Vec::new(),
                                    utxos,
                                    script_examinations,
                                    continuation: None,
                                });
                            };
                            position = next_position;
                            continue;
                        }
                        return Ok(ConfirmedScriptsPage {
                            chain_epoch,
                            tip,
                            history: Vec::new(),
                            utxos,
                            script_examinations,
                            continuation: next_position.map(|position| ConfirmedScriptsCursor {
                                binding_version: CONFIRMED_CURSOR_VERSION,
                                chain_epoch,
                                script_set_id,
                                position,
                            }),
                        });
                    }
                }
            }
        })
        .await
    }

    /// Traverse active incoming-TRANSFER candidates for one restoration set.
    ///
    /// The caller supplies the durable chain epoch obtained before disclosing
    /// its complete sorted-unique script set. Every candidate is corroborated
    /// against the transaction index, active chain, block/header status, and
    /// byte-exact active UTXO in one immutable snapshot. Retained block bodies
    /// additionally bind the exact transaction and output bytes; pruned bodies
    /// are labeled as a weaker trusted-node projection.
    pub async fn get_incoming_transfers_page(
        &self,
        scripts: Vec<ScriptId>,
        expected_chain_epoch: u64,
        cursor: Option<IncomingTransfersCursor>,
        limit: usize,
    ) -> Result<IncomingTransfersPage, WalletBackendError> {
        if !(1..=MAX_QUERY_ENTRIES).contains(&limit) {
            return Err(WalletBackendError::InvalidIncomingTransferPageLimit);
        }
        validate_script_set(&scripts)?;
        let profile = self.read.wallet_index_profile();
        if !profile.wallet {
            return Err(WalletBackendError::IndexDisabled("wallet"));
        }
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let script_set_id = incoming_transfer_script_set_id(&scripts)?;
        let read = self.read.clone();
        blocking_chain_collection_read(read, move |_, snapshot| {
            incoming_transfers_page_from_snapshot(
                snapshot,
                profile,
                &scripts,
                expected_chain_epoch,
                script_set_id,
                cursor,
                limit,
            )
        })
        .await
    }

    /// Return the active-chain spending transaction for one outpoint.
    pub async fn get_spending_transaction(
        &self,
        outpoint: Outpoint,
    ) -> Result<Option<SpendingTransaction>, WalletBackendError> {
        let mut evidence = self.get_outpoint_spending_evidence(vec![outpoint]).await?;
        evidence
            .entries
            .pop()
            .map(|entry| entry.spending)
            .ok_or(WalletBackendError::Corrupt(
                "single-outpoint spending evidence omitted its result",
            ))
    }

    /// Return one ordered result per outpoint from one immutable chain read.
    pub async fn get_outpoint_spending_evidence(
        &self,
        outpoints: Vec<Outpoint>,
    ) -> Result<OutpointSpendingEvidence, WalletBackendError> {
        if outpoints.is_empty() || outpoints.len() > MAX_WALLET_OUTPOINT_SPEND_BATCH {
            return Err(WalletBackendError::InvalidOutpointBatch);
        }
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_collection_read(read, move |_, snapshot| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            let tip = wallet_chain_tip(snapshot)?;
            let entries = outpoints
                .into_iter()
                .map(|outpoint| {
                    let spending = spending_transaction(snapshot, profile, &outpoint)
                        .map_err(wallet_index_error)?;
                    Ok(OutpointSpendingEntry { outpoint, spending })
                })
                .collect::<Result<Vec<_>, WalletBackendError>>()?;
            Ok(OutpointSpendingEvidence {
                chain_epoch,
                tip,
                entries,
            })
        })
        .await
    }

    /// Persist one immutable public Shakedex/HTLC registration before funding.
    pub async fn register_tracked_contract(
        &self,
        registration: ContractRegistration,
    ) -> Result<ContractRegistrationOutcome, WalletBackendError> {
        if !self.read.wallet_index_profile().wallet {
            return Err(WalletBackendError::IndexDisabled("tracked-contract"));
        }
        self.writer
            .execute(None, "register wallet contract", move |node| {
                node.register_wallet_contract(registration)
            })
            .await
            .map_err(wallet_writer_error)
    }

    /// Capture the in-process lifecycle and exact chain/mempool binding needed
    /// to prepare a never-confirmed retirement request.
    pub async fn get_tracked_contract_retirement_context(
        &self,
        id: ContractId,
    ) -> Result<TrackedContractRetirementContext, WalletBackendError> {
        if !self.read.wallet_index_profile().wallet {
            return Err(WalletBackendError::IndexDisabled("tracked-contract"));
        }
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_mempool_read(read, move |_, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            Ok(TrackedContractRetirementContext {
                registration: tracked_contract(snapshot, profile, id)
                    .map_err(wallet_index_error)?,
                lifecycle_revision: tracked_contract_lifecycle_revision(snapshot, profile, id)
                    .map_err(wallet_index_error)?,
                chain_epoch,
                tip: wallet_chain_tip(snapshot)?,
                mempool_instance_nonce: *mempool.instance_nonce(),
                mempool_generation: mempool.generation(),
            })
        })
        .await
    }

    /// Retire one never-confirmed registration and reclaim its active global
    /// and per-address capacity after the caller explicitly abandons every
    /// previously broadcast funding transaction.
    ///
    /// The caller context binds the target lifecycle plus one exact durable-
    /// chain and immutable-mempool generation. The bound publication must have
    /// no retained transaction orphans; accepted ordinary transactions and
    /// airdrop outputs are scanned for exact funding. After the internal stable
    /// scan, any intervening canonical writer command rejects compare-and-
    /// commit. Completed or legacy registrations are not eligible for this
    /// narrow lifecycle operation.
    pub async fn retire_never_confirmed_tracked_contract(
        &self,
        request: TrackedContractRetirementRequest,
    ) -> Result<TrackedContractRetirement, WalletBackendError> {
        if !self.read.wallet_index_profile().wallet {
            return Err(WalletBackendError::IndexDisabled("tracked-contract"));
        }
        request
            .registration
            .funding_address()
            .map_err(wallet_index_error)?;
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        let plan = blocking_mempool_read(read, move |_, snapshot, mempool, mempool_info, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            if request.expected_chain_epoch != chain_epoch {
                return Err(WalletBackendError::StaleChainEpoch {
                    expected: request.expected_chain_epoch,
                    actual: chain_epoch,
                });
            }
            let tip = wallet_chain_tip(snapshot)?;
            if request.expected_tip != tip {
                return Err(WalletBackendError::StaleCanonicalRead);
            }
            if request.expected_mempool_instance_nonce != *mempool.instance_nonce() {
                return Err(WalletBackendError::StaleMempoolInstance);
            }
            if request.expected_mempool_generation != mempool.generation() {
                return Err(WalletBackendError::StaleMempoolGeneration {
                    expected: request.expected_mempool_generation,
                    actual: mempool.generation(),
                });
            }

            if let Some(stored) = tracked_contract(snapshot, profile, request.registration.id)
                .map_err(wallet_index_error)?
            {
                if stored != request.registration {
                    return Err(WalletBackendError::InvalidContract);
                }
                let actual_lifecycle_revision =
                    tracked_contract_lifecycle_revision(snapshot, profile, stored.id)
                        .map_err(wallet_index_error)?;
                if actual_lifecycle_revision != Some(request.expected_lifecycle_revision) {
                    return Err(WalletBackendError::StaleContractLifecycle {
                        expected: request.expected_lifecycle_revision,
                        actual: actual_lifecycle_revision,
                    });
                }
                if !tracked_contract_fundings(snapshot, profile, stored.id, None, 1)
                    .map_err(wallet_index_error)?
                    .entries
                    .is_empty()
                    || !tracked_contract_events(snapshot, profile, stored.id, None, 1)
                        .map_err(wallet_index_error)?
                        .entries
                        .is_empty()
                {
                    return Err(WalletBackendError::ContractNotRetirable);
                }
                // Retained transaction orphans are not part of the immutable
                // transaction snapshot. Requiring the exact published pool to
                // have none keeps the proof complete without cloning orphan
                // bodies into every publication. The canonical-writer epoch
                // below rejects any orphan mutation after this stable read.
                if mempool_info.orphan_count != 0 {
                    return Err(WalletBackendError::ContractNotRetirable);
                }
                for txid in mempool.txids() {
                    let transaction =
                        mempool
                            .transaction(&txid)
                            .ok_or(WalletBackendError::Corrupt(
                                "published mempool references an absent transaction",
                            ))?;
                    if transaction_contains_contract_funding(&stored, transaction)? {
                        return Err(WalletBackendError::ContractNotRetirable);
                    }
                }
                // Accepted airdrop proofs become CovenantKind::None coinbase
                // outputs and can therefore satisfy an HNS-HTLC descriptor.
                // Claims use CovenantKind::Claim and cannot match either
                // supported funding profile.
                for airdrop in mempool.airdrops() {
                    let address =
                        Address::new(airdrop.proof.version, airdrop.proof.address.clone())
                            .map_err(|_| {
                                WalletBackendError::Corrupt(
                                    "accepted airdrop proof has an invalid output address",
                                )
                            })?;
                    let value = airdrop.value.checked_sub(airdrop.fee).ok_or(
                        WalletBackendError::Corrupt(
                            "accepted airdrop proof fee exceeds its output value",
                        ),
                    )?;
                    if stored
                        .matches_funding_output(&Output {
                            value,
                            address,
                            covenant: Covenant {
                                kind: CovenantKind::None,
                                items: Vec::new(),
                            },
                        })
                        .map_err(wallet_index_error)?
                    {
                        return Err(WalletBackendError::ContractNotRetirable);
                    }
                }
            }

            Ok(TrackedContractRetirementPlan {
                epoch: epoch.clone(),
                registration: request.registration,
                lifecycle_revision: request.expected_lifecycle_revision,
                chain_epoch,
                tip,
                mempool_instance_nonce: *mempool.instance_nonce(),
                mempool_generation: mempool.generation(),
            })
        })
        .await?;
        let TrackedContractRetirementPlan {
            epoch,
            registration,
            lifecycle_revision,
            chain_epoch,
            tip,
            mempool_instance_nonce,
            mempool_generation,
        } = plan;
        let contract_id = registration.id;
        let outcome = self
            .writer
            .execute_at(
                epoch,
                "retire never-confirmed wallet contract",
                move |node| {
                    node.retire_never_confirmed_wallet_contract(registration, lifecycle_revision)
                },
            )
            .await
            .map_err(wallet_writer_error)?;
        Ok(TrackedContractRetirement {
            contract_id,
            outcome,
            lifecycle_revision,
            chain_epoch,
            tip,
            mempool_instance_nonce,
            mempool_generation,
        })
    }

    /// Capture the exact lifecycle, canonical, mempool, and undo-pruning
    /// bindings needed to prepare an irreversible completed retirement.
    pub async fn get_completed_tracked_contract_retirement_context(
        &self,
        id: ContractId,
    ) -> Result<CompletedTrackedContractRetirementContext, WalletBackendError> {
        if !self.read.wallet_index_profile().wallet {
            return Err(WalletBackendError::IndexDisabled("tracked-contract"));
        }
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_mempool_read(read, move |_, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            let registration =
                tracked_contract(snapshot, profile, id).map_err(wallet_index_error)?;
            let retirement = completed_tracked_contract_retirement(snapshot, profile, id)
                .map_err(wallet_index_error)?;
            if registration.is_some() && retirement.is_some() {
                return Err(WalletBackendError::Corrupt(
                    "tracked contract is both active and retired",
                ));
            }
            let lifecycle_revision = match (&registration, &retirement) {
                (Some(_), None) => tracked_contract_lifecycle_revision(snapshot, profile, id)
                    .map_err(wallet_index_error)?,
                (None, Some(retirement)) => Some(retirement.lifecycle_revision),
                (None, None) => None,
                (Some(_), Some(_)) => unreachable!("checked above"),
            };
            let rollback_boundary = load_undo_pruning_checkpoint(snapshot)
                .map_err(node_error)?
                .map(|checkpoint| ContractRollbackBoundary {
                    pruned_through: checkpoint.pruned_through,
                    block_hash: checkpoint.block_hash,
                });
            Ok(CompletedTrackedContractRetirementContext {
                registration,
                retirement,
                lifecycle_revision,
                chain_epoch,
                tip: wallet_chain_tip(snapshot)?,
                rollback_boundary,
                mempool_instance_nonce: *mempool.instance_nonce(),
                mempool_generation: mempool.generation(),
            })
        })
        .await
    }

    /// Permanently retire one fully spent descriptor lifecycle after its
    /// complete confirmed history falls below the irreversible undo frontier.
    ///
    /// This is a first-party typed operation only; it is intentionally absent
    /// from wallet RPC. The exact published mempool must contain no orphans and
    /// no matching future funding, and the caller must explicitly acknowledge
    /// permanent descriptor abandonment. The acknowledgement cannot prevent a
    /// third party from creating a later consensus-valid matching output; such
    /// an output is deliberately outside this retired lifecycle and untracked.
    pub async fn retire_completed_tracked_contract(
        &self,
        request: CompletedTrackedContractRetirementRequest,
    ) -> Result<CompletedTrackedContractRetirement, WalletBackendError> {
        if !self.read.wallet_index_profile().wallet {
            return Err(WalletBackendError::IndexDisabled("tracked-contract"));
        }
        if !request.acknowledge_permanent_descriptor_abandonment {
            return Err(WalletBackendError::PermanentContractAbandonmentRequired);
        }
        request
            .registration
            .funding_address()
            .map_err(wallet_index_error)?;
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        let plan = blocking_mempool_read(read, move |_, snapshot, mempool, mempool_info, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            if request.expected_chain_epoch != chain_epoch {
                return Err(WalletBackendError::StaleChainEpoch {
                    expected: request.expected_chain_epoch,
                    actual: chain_epoch,
                });
            }
            let tip = wallet_chain_tip(snapshot)?;
            if request.expected_tip != tip {
                return Err(WalletBackendError::StaleCanonicalRead);
            }
            let rollback_boundary = load_undo_pruning_checkpoint(snapshot)
                .map_err(node_error)?
                .map(|checkpoint| ContractRollbackBoundary {
                    pruned_through: checkpoint.pruned_through,
                    block_hash: checkpoint.block_hash,
                })
                .ok_or(WalletBackendError::ContractRollbackRequired)?;
            if request.expected_rollback_boundary != rollback_boundary {
                return Err(WalletBackendError::StaleContractRollbackBoundary);
            }
            if request.expected_mempool_instance_nonce != *mempool.instance_nonce() {
                return Err(WalletBackendError::StaleMempoolInstance);
            }
            if request.expected_mempool_generation != mempool.generation() {
                return Err(WalletBackendError::StaleMempoolGeneration {
                    expected: request.expected_mempool_generation,
                    actual: mempool.generation(),
                });
            }

            let active = tracked_contract(snapshot, profile, request.registration.id)
                .map_err(wallet_index_error)?;
            let retired =
                completed_tracked_contract_retirement(snapshot, profile, request.registration.id)
                    .map_err(wallet_index_error)?;
            match (active, retired) {
                (Some(stored), None) => {
                    if stored != request.registration {
                        return Err(WalletBackendError::InvalidContract);
                    }
                    let actual_lifecycle_revision =
                        tracked_contract_lifecycle_revision(snapshot, profile, stored.id)
                            .map_err(wallet_index_error)?;
                    if actual_lifecycle_revision != Some(request.expected_lifecycle_revision) {
                        return Err(WalletBackendError::StaleContractLifecycle {
                            expected: request.expected_lifecycle_revision,
                            actual: actual_lifecycle_revision,
                        });
                    }
                    if !tracked_contract_fundings(snapshot, profile, stored.id, None, 1)
                        .map_err(wallet_index_error)?
                        .entries
                        .is_empty()
                    {
                        return Err(WalletBackendError::ContractNotRetirable);
                    }
                }
                (None, Some(retirement)) => {
                    if retirement.registration != request.registration {
                        return Err(WalletBackendError::InvalidContract);
                    }
                    if retirement.lifecycle_revision != request.expected_lifecycle_revision {
                        return Err(WalletBackendError::StaleContractLifecycle {
                            expected: request.expected_lifecycle_revision,
                            actual: Some(retirement.lifecycle_revision),
                        });
                    }
                }
                (None, None) => return Err(WalletBackendError::UnknownContract),
                (Some(_), Some(_)) => {
                    return Err(WalletBackendError::Corrupt(
                        "tracked contract is both active and retired",
                    ));
                }
            }

            if mempool_info.orphan_count != 0 {
                return Err(WalletBackendError::ContractNotRetirable);
            }
            for txid in mempool.txids() {
                let transaction = mempool
                    .transaction(&txid)
                    .ok_or(WalletBackendError::Corrupt(
                        "published mempool references an absent transaction",
                    ))?;
                if transaction_contains_contract_funding(&request.registration, transaction)? {
                    return Err(WalletBackendError::ContractNotRetirable);
                }
            }
            for airdrop in mempool.airdrops() {
                let address = Address::new(airdrop.proof.version, airdrop.proof.address.clone())
                    .map_err(|_| {
                        WalletBackendError::Corrupt(
                            "accepted airdrop proof has an invalid output address",
                        )
                    })?;
                let value =
                    airdrop
                        .value
                        .checked_sub(airdrop.fee)
                        .ok_or(WalletBackendError::Corrupt(
                            "accepted airdrop proof fee exceeds its output value",
                        ))?;
                if request
                    .registration
                    .matches_funding_output(&Output {
                        value,
                        address,
                        covenant: Covenant {
                            kind: CovenantKind::None,
                            items: Vec::new(),
                        },
                    })
                    .map_err(wallet_index_error)?
                {
                    return Err(WalletBackendError::ContractNotRetirable);
                }
            }

            Ok(CompletedTrackedContractRetirementPlan {
                epoch: epoch.clone(),
                registration: request.registration,
                lifecycle_revision: request.expected_lifecycle_revision,
                chain_epoch,
                tip,
                rollback_boundary,
                mempool_instance_nonce: *mempool.instance_nonce(),
                mempool_generation: mempool.generation(),
                permanent_abandonment_acknowledged: request
                    .acknowledge_permanent_descriptor_abandonment,
            })
        })
        .await?;
        let CompletedTrackedContractRetirementPlan {
            epoch,
            registration,
            lifecycle_revision,
            chain_epoch,
            tip,
            rollback_boundary,
            mempool_instance_nonce,
            mempool_generation,
            permanent_abandonment_acknowledged,
        } = plan;
        let (outcome, retirement) = self
            .writer
            .execute_at(epoch, "retire completed wallet contract", move |node| {
                node.retire_completed_wallet_contract(
                    registration,
                    lifecycle_revision,
                    rollback_boundary,
                    permanent_abandonment_acknowledged,
                )
            })
            .await
            .map_err(wallet_writer_error)?;
        Ok(CompletedTrackedContractRetirement {
            outcome,
            retirement,
            chain_epoch,
            tip,
            mempool_instance_nonce,
            mempool_generation,
        })
    }

    /// Read one immutable public Shakedex/HTLC registration.
    pub async fn get_tracked_contract(
        &self,
        id: ContractId,
    ) -> Result<Option<ContractRegistration>, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            tracked_contract(snapshot, profile, id).map_err(wallet_index_error)
        })
        .await
    }

    /// Read one immutable completed-retirement proof. This is a typed local
    /// read and is intentionally not projected through wallet RPC.
    pub async fn get_completed_tracked_contract_retirement(
        &self,
        id: ContractId,
    ) -> Result<Option<CompletedContractRetirement>, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            completed_tracked_contract_retirement(snapshot, profile, id).map_err(wallet_index_error)
        })
        .await
    }

    /// Read one bounded page of active confirmed contract fundings.
    pub async fn get_tracked_contract_fundings(
        &self,
        id: ContractId,
        cursor: Option<WalletContractFundingCursor>,
        limit: usize,
    ) -> Result<WalletContractFundingPage, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            let inner = match cursor {
                Some(cursor) => {
                    if cursor.chain_epoch != chain_epoch {
                        return Err(WalletBackendError::StaleChainEpoch {
                            expected: cursor.chain_epoch,
                            actual: chain_epoch,
                        });
                    }
                    if cursor.contract_id != id {
                        return Err(WalletBackendError::InvalidConfirmedCursor);
                    }
                    Some(cursor.inner)
                }
                None => None,
            };
            let page = tracked_contract_fundings(snapshot, profile, id, inner.as_ref(), limit)
                .map_err(wallet_index_error)?;
            Ok(WalletContractFundingPage {
                chain_epoch,
                tip: wallet_chain_tip(snapshot)?,
                entries: page.entries,
                continuation: page.continuation.map(|inner| WalletContractFundingCursor {
                    chain_epoch,
                    contract_id: id,
                    inner,
                }),
            })
        })
        .await
    }

    /// Read one bounded page of durable confirmed contract events.
    pub async fn get_tracked_contract_events(
        &self,
        id: ContractId,
        cursor: Option<WalletContractEventCursor>,
        limit: usize,
    ) -> Result<WalletContractEventPage, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            let inner = match cursor {
                Some(cursor) => {
                    if cursor.chain_epoch != chain_epoch {
                        return Err(WalletBackendError::StaleChainEpoch {
                            expected: cursor.chain_epoch,
                            actual: chain_epoch,
                        });
                    }
                    if cursor.contract_id != id {
                        return Err(WalletBackendError::InvalidConfirmedCursor);
                    }
                    Some(cursor.inner)
                }
                None => None,
            };
            let page = tracked_contract_events(snapshot, profile, id, inner.as_ref(), limit)
                .map_err(wallet_index_error)?;
            Ok(WalletContractEventPage {
                chain_epoch,
                tip: wallet_chain_tip(snapshot)?,
                entries: page.entries,
                continuation: page.continuation.map(|inner| WalletContractEventCursor {
                    chain_epoch,
                    contract_id: id,
                    inner,
                }),
            })
        })
        .await
    }

    /// Reconcile one script against an immutable, globally paginated mempool.
    pub async fn get_mempool_script_activity(
        &self,
        script: ScriptId,
        cursor: Option<WalletMempoolCursor>,
        scan_limit: usize,
    ) -> Result<MempoolScriptPage, WalletBackendError> {
        self.get_mempool_scripts_activity(vec![script], cursor, scan_limit)
            .await
    }

    /// Reconcile a bounded sorted-unique restoration set in one global scan.
    pub async fn get_mempool_scripts_activity(
        &self,
        scripts: Vec<ScriptId>,
        cursor: Option<WalletMempoolCursor>,
        scan_limit: usize,
    ) -> Result<MempoolScriptPage, WalletBackendError> {
        validate_mempool_scan_limit(scan_limit)?;
        validate_script_set(&scripts)?;
        let query_id = script_set_id(MEMPOOL_SCRIPT_SET_DOMAIN, &scripts)?;
        let read = self.read.clone();
        blocking_mempool_read(read, move |_, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            let tip = wallet_chain_tip(snapshot)?;
            let script_positions = scripts
                .iter()
                .copied()
                .enumerate()
                .map(|(position, script)| (script, position))
                .collect::<HashMap<_, _>>();
            let (txids, continuation) =
                mempool_scan_page(mempool, cursor.as_ref(), scan_limit, query_id, chain_epoch)?;
            let mut entries = Vec::new();
            let mut relevant_items = 0usize;
            for txid in txids {
                let admitted_at = mempool
                    .entry(&txid)
                    .ok_or(WalletBackendError::Corrupt(
                        "published mempool references absent entry metadata",
                    ))?
                    .admitted_at;
                let transaction = mempool
                    .transaction(&txid)
                    .ok_or(WalletBackendError::Corrupt(
                        "published mempool references an absent transaction",
                    ))?;
                let mut received = Vec::new();
                let mut spent = Vec::new();
                for (output_position, output) in transaction.outputs.iter().enumerate() {
                    let Some(script_index) = script_positions
                        .get(&ScriptId::from_address(&output.address))
                        .copied()
                    else {
                        continue;
                    };
                    relevant_items = relevant_items.saturating_add(1);
                    if relevant_items > MAX_WALLET_MEMPOOL_ITEMS {
                        return Err(WalletBackendError::MempoolResultLimit);
                    }
                    received.push(MempoolScriptOutput {
                        script_index,
                        outpoint: Outpoint {
                            txid,
                            index: u32::try_from(output_position).map_err(|_| {
                                WalletBackendError::Corrupt("mempool output position exceeds u32")
                            })?,
                        },
                        value: output.value,
                    });
                }
                for input in &transaction.inputs {
                    if input.previous_output.is_null() {
                        continue;
                    }
                    let Some(coin) =
                        resolve_mempool_coin(snapshot, mempool, &input.previous_output)?
                    else {
                        return Err(WalletBackendError::Corrupt(
                            "contextual mempool input coin is unavailable",
                        ));
                    };
                    let Some(script_index) = script_positions
                        .get(&ScriptId::from_address(&coin.address))
                        .copied()
                    else {
                        continue;
                    };
                    relevant_items = relevant_items.saturating_add(1);
                    if relevant_items > MAX_WALLET_MEMPOOL_ITEMS {
                        return Err(WalletBackendError::MempoolResultLimit);
                    }
                    spent.push(MempoolScriptSpend {
                        script_index,
                        outpoint: input.previous_output.clone(),
                    });
                }
                if !received.is_empty() || !spent.is_empty() {
                    entries.push(MempoolScriptActivity {
                        txid,
                        admitted_at,
                        received,
                        spent,
                    });
                }
            }
            Ok(MempoolScriptPage {
                chain_epoch,
                tip,
                instance_nonce: *mempool.instance_nonce(),
                generation: mempool.generation(),
                entries,
                continuation,
            })
        })
        .await
    }

    /// Reconcile one registered contract against the same immutable mempool.
    pub async fn get_mempool_tracked_contract_activity(
        &self,
        id: ContractId,
        cursor: Option<WalletMempoolCursor>,
        scan_limit: usize,
    ) -> Result<MempoolContractPage, WalletBackendError> {
        validate_mempool_scan_limit(scan_limit)?;
        let profile = self.read.wallet_index_profile();
        let query_id = mempool_contract_query_id(id);
        let read = self.read.clone();
        blocking_mempool_read(read, move |_, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            let tip = wallet_chain_tip(snapshot)?;
            let registration = tracked_contract(snapshot, profile, id)
                .map_err(wallet_index_error)?
                .ok_or(WalletBackendError::UnknownContract)?;
            let (txids, continuation) =
                mempool_scan_page(mempool, cursor.as_ref(), scan_limit, query_id, chain_epoch)?;
            let mut entries = Vec::new();
            let mut relevant_items = 0usize;
            for txid in txids {
                let admitted_at = mempool
                    .entry(&txid)
                    .ok_or(WalletBackendError::Corrupt(
                        "published mempool references absent entry metadata",
                    ))?
                    .admitted_at;
                let transaction = mempool
                    .transaction(&txid)
                    .ok_or(WalletBackendError::Corrupt(
                        "published mempool references an absent transaction",
                    ))?;
                let mut events = Vec::new();
                for (input_position, input) in transaction.inputs.iter().enumerate() {
                    if input.previous_output.is_null() {
                        continue;
                    }
                    let Some(coin) =
                        resolve_mempool_coin(snapshot, mempool, &input.previous_output)?
                    else {
                        return Err(WalletBackendError::Corrupt(
                            "contextual mempool input coin is unavailable",
                        ));
                    };
                    if !registration
                        .matches_funding_output(&Output {
                            value: coin.value,
                            address: coin.address.clone(),
                            covenant: coin.covenant.clone(),
                        })
                        .map_err(wallet_index_error)?
                    {
                        continue;
                    }
                    let parent_is_mempool =
                        mempool.transaction(&input.previous_output.txid).is_some();
                    if !parent_is_mempool
                        && tracked_contract_funding(snapshot, profile, id, &input.previous_output)
                            .map_err(wallet_index_error)?
                            .is_none()
                    {
                        continue;
                    }
                    let kind = registration
                        .classify_spend(transaction, input_position, &coin)
                        .map_err(wallet_index_error)?;
                    relevant_items = relevant_items.saturating_add(1);
                    if relevant_items > MAX_WALLET_MEMPOOL_ITEMS {
                        return Err(WalletBackendError::MempoolResultLimit);
                    }
                    events.push(MempoolContractEvent::Spend {
                        funding_outpoint: input.previous_output.clone(),
                        input_position: u32::try_from(input_position).map_err(|_| {
                            WalletBackendError::Corrupt("mempool input position exceeds u32")
                        })?,
                        kind,
                    });
                }
                for (output_position, output) in transaction.outputs.iter().enumerate() {
                    if !registration
                        .matches_funding_output(output)
                        .map_err(wallet_index_error)?
                    {
                        continue;
                    }
                    relevant_items = relevant_items.saturating_add(1);
                    if relevant_items > MAX_WALLET_MEMPOOL_ITEMS {
                        return Err(WalletBackendError::MempoolResultLimit);
                    }
                    events.push(MempoolContractEvent::Funding {
                        outpoint: Outpoint {
                            txid,
                            index: u32::try_from(output_position).map_err(|_| {
                                WalletBackendError::Corrupt("mempool output position exceeds u32")
                            })?,
                        },
                        value: output.value,
                    });
                }
                if !events.is_empty() {
                    entries.push(MempoolContractActivity {
                        txid,
                        admitted_at,
                        events,
                    });
                }
            }
            Ok(MempoolContractPage {
                chain_epoch,
                tip,
                instance_nonce: *mempool.instance_nonce(),
                generation: mempool.generation(),
                entries,
                continuation,
            })
        })
        .await
    }

    /// Contextually admit and announce one already signed transaction.
    pub async fn broadcast_transaction(
        &self,
        transaction: Transaction,
    ) -> Result<BroadcastResult, WalletBackendError> {
        let txid = transaction.txid();
        let already_known = self
            .read
            .published_mempool_snapshot()
            .map_err(node_error)?
            .transaction(&txid)
            .is_some();
        let newly_admitted = if already_known {
            false
        } else {
            match self
                .writer
                .mining_engine_accept_peer_transaction(transaction)
                .await
                .map_err(node_error)?
            {
                Admission::Accepted(accepted) if accepted == txid => true,
                Admission::Accepted(_) => {
                    return Err(WalletBackendError::Corrupt(
                        "mempool returned a different transaction ID",
                    ));
                }
                Admission::Rejected { reason } => {
                    return Err(WalletBackendError::Rejected(reason));
                }
                Admission::Orphan(orphan) => return Err(WalletBackendError::Orphan(orphan)),
            }
        };
        let report = self
            .peers
            .broadcast(
                Arc::new(Packet::Inv(vec![Inventory::transaction(txid)])),
                OutboundPriority::Normal,
            )
            .await;
        Ok(BroadcastResult {
            txid,
            newly_admitted,
            attempted_peers: report.attempted,
            queued_peers: report.queued,
            failed_peers: report.failed.len(),
        })
    }

    /// Estimate a bounded fee rate from a deterministic mempool sample.
    pub async fn estimate_fee_rate(
        &self,
        target_blocks: u32,
    ) -> Result<FeeEstimate, WalletBackendError> {
        if !(1..=MAX_FEE_ESTIMATE_TARGET_BLOCKS).contains(&target_blocks) {
            return Err(WalletBackendError::InvalidFeeTarget);
        }
        let snapshot = self.read.published_mempool_snapshot().map_err(node_error)?;
        Ok(estimate_fee_rate_from_snapshot(&snapshot, target_blocks))
    }

    /// Quote the exact HSD minimum policy fee for one canonical raw
    /// transaction against a caller-bound chain and mempool snapshot.
    ///
    /// Input coins are resolved only by the node from the captured active UTXO
    /// set or captured mempool parents. The caller cannot supply coin, sigop,
    /// weight, policy-size, or fee evidence through this boundary. The result
    /// is exact only for these serialized transaction and witness bytes; a
    /// wallet must quote the final signed artifact again before broadcast.
    pub async fn quote_transaction_fee(
        &self,
        transaction: Transaction,
        target_blocks: u32,
        expected_chain_epoch: u64,
        expected_mempool_instance_nonce: [u8; 32],
        expected_mempool_generation: u64,
    ) -> Result<TransactionFeeQuote, WalletBackendError> {
        if !(1..=MAX_FEE_ESTIMATE_TARGET_BLOCKS).contains(&target_blocks) {
            return Err(WalletBackendError::InvalidFeeTarget);
        }
        validate_transaction_sanity(&transaction)
            .map_err(|_| WalletBackendError::InvalidFeeQuoteTransaction)?;
        if is_coinbase(&transaction) || transaction.inputs.len() > MAX_WALLET_FEE_QUOTE_INPUTS {
            return Err(WalletBackendError::InvalidFeeQuoteTransaction);
        }

        let read = self.read.clone();
        blocking_mempool_read(read, move |_, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            if chain_epoch != expected_chain_epoch {
                return Err(WalletBackendError::StaleChainEpoch {
                    expected: expected_chain_epoch,
                    actual: chain_epoch,
                });
            }
            if mempool.instance_nonce() != &expected_mempool_instance_nonce {
                return Err(WalletBackendError::StaleMempoolInstance);
            }
            if mempool.generation() != expected_mempool_generation {
                return Err(WalletBackendError::StaleMempoolGeneration {
                    expected: expected_mempool_generation,
                    actual: mempool.generation(),
                });
            }
            transaction_fee_quote_from_snapshot(
                snapshot,
                mempool,
                &transaction,
                target_blocks,
                chain_epoch,
                wallet_chain_tip(snapshot)?,
            )
        })
        .await
    }

    /// Capture every public input needed to prepare one TRANSFER or FINALIZE
    /// against an exact active-chain and mempool generation.
    ///
    /// The node does not construct or sign the action. The caller must retain
    /// this binding, reject any reported owner spender, and use the same exact
    /// generation when requoting the final signed transaction.
    pub async fn get_name_action_context(
        &self,
        action: NameAction,
        name_hash: NameHash,
        expected_chain_epoch: u64,
        expected_mempool_instance_nonce: [u8; 32],
        expected_mempool_generation: u64,
    ) -> Result<NameActionContext, WalletBackendError> {
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let read = self.read.clone();
        blocking_mempool_read(read, move |read, snapshot, mempool, _, epoch| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            if chain_epoch != epoch.chain_epoch {
                return Err(WalletBackendError::Corrupt(
                    "published and durable chain generations disagree",
                ));
            }
            if chain_epoch != expected_chain_epoch {
                return Err(WalletBackendError::StaleChainEpoch {
                    expected: expected_chain_epoch,
                    actual: chain_epoch,
                });
            }
            if mempool.instance_nonce() != &expected_mempool_instance_nonce {
                return Err(WalletBackendError::StaleMempoolInstance);
            }
            if mempool.generation() != expected_mempool_generation {
                return Err(WalletBackendError::StaleMempoolGeneration {
                    expected: expected_mempool_generation,
                    actual: mempool.generation(),
                });
            }

            let network = read.network();
            let network_params = network.params();
            let name_params = network_params.names;
            let tip = wallet_chain_tip(snapshot)?.ok_or(WalletBackendError::ChainUninitialized)?;
            let canonical_genesis = read_canonical_hash(snapshot, 0)
                .map_err(node_error)?
                .ok_or(WalletBackendError::Corrupt(
                    "initialized chain has no canonical genesis",
                ))?;
            if canonical_genesis != network_params.genesis_hash {
                return Err(WalletBackendError::Corrupt(
                    "canonical genesis disagrees with the selected network",
                ));
            }
            let candidate_inclusion_height =
                tip.height
                    .checked_add(1)
                    .ok_or(WalletBackendError::Corrupt(
                        "candidate inclusion height overflows u32",
                    ))?;

            let current_state = load_current_name_state(snapshot, name_hash)?
                .ok_or(WalletBackendError::NameStateMissing)?;
            if current_state.name_hash != name_hash {
                return Err(WalletBackendError::Corrupt(
                    "current name state disagrees with its requested key",
                ));
            }
            if current_state.owner.is_null() {
                return Err(WalletBackendError::NameHasNoOwner);
            }
            let owner = load_name_owner(snapshot, &current_state, true)?
                .ok_or(WalletBackendError::NameHasNoOwner)?;
            validate_name_action_owner(snapshot, &current_state, &owner)?;

            let owner_spender_txid = mempool.spending_transaction(&owner.owner);
            let lifecycle = name_lifecycle(&current_state, candidate_inclusion_height, name_params);
            let expired_at_candidate =
                is_name_expired(&current_state, candidate_inclusion_height, name_params);
            let current_transfer_height =
                (current_state.transfer != 0).then_some(current_state.transfer);
            let finalize_maturity_height =
                current_transfer_height.map(|height| transfer_maturity_height(height, name_params));
            let finalize_eligible_at_candidate = is_transfer_mature(
                current_state.transfer,
                candidate_inclusion_height,
                name_params,
            );

            let hsd_selected_height = hsd_wallet_renewal_height(tip.height, name_params);
            let hsd_selected_hash = read_canonical_hash(snapshot, hsd_selected_height)
                .map_err(node_error)?
                .ok_or(WalletBackendError::Corrupt(
                    "HSD-selected renewal height is absent from the active chain",
                ))?;
            let renewal_valid_at_candidate = renewal_commitment_height_is_valid(
                hsd_selected_height,
                candidate_inclusion_height,
                name_params,
            );
            let ineligibility_reasons = name_action_ineligibility_reasons(
                action,
                &current_state,
                owner.owner_output.covenant.kind,
                lifecycle,
                expired_at_candidate,
                finalize_eligible_at_candidate,
                renewal_valid_at_candidate,
                owner_spender_txid,
            )?;

            Ok(NameActionContext {
                context_version: NAME_ACTION_CONTEXT_VERSION,
                action,
                network,
                network_id: network.canonical_id(),
                genesis_hash: network_params.genesis_hash,
                consensus_profile: HSD_CONSENSUS_PROFILE.to_owned(),
                chain_epoch,
                tip,
                candidate_inclusion_height,
                mempool_instance_nonce: *mempool.instance_nonce(),
                mempool_generation: mempool.generation(),
                owner_spender_txid,
                name_hash,
                current_state,
                owner,
                lifecycle,
                transfer: NameTransferContext {
                    lockup_blocks: name_params.transfer_lockup,
                    current_transfer_height,
                    finalize_maturity_height,
                    finalize_eligible_at_candidate,
                },
                renewal: NameRenewalContext {
                    maturity_blocks: name_params.renewal_maturity,
                    period_blocks: name_params.renewal_period,
                    hsd_selected_height,
                    hsd_selected_hash,
                    valid_at_candidate: renewal_valid_at_candidate,
                },
                ineligibility_reasons,
            })
        })
        .await
    }

    /// Capture pruning-safe public evidence for one TRANSFER or FINALIZE.
    ///
    /// Unlike version 1, this method never loads the owner transaction or its
    /// containing raw block. It binds the current NameState to the exact active
    /// owner Coin and canonical transaction index, then derives the same
    /// candidate-height policy and immutable-mempool spender evidence. The
    /// result is not wallet ownership, signing authority, transaction
    /// construction, approval, fee evidence, admission, or broadcast.
    pub async fn get_name_action_context_v2(
        &self,
        action: NameAction,
        name_hash: NameHash,
        expected_chain_epoch: u64,
        expected_mempool_instance_nonce: [u8; 32],
        expected_mempool_generation: u64,
    ) -> Result<NameActionContextV2, WalletBackendError> {
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let read = self.read.clone();
        blocking_mempool_read(read, move |read, snapshot, mempool, _, epoch| {
            name_action_context_v2_from_snapshot(
                read.network(),
                snapshot,
                mempool,
                epoch.chain_epoch,
                action,
                name_hash,
                expected_chain_epoch,
                expected_mempool_instance_nonce,
                expected_mempool_generation,
            )
        })
        .await
    }

    /// Return pruning-safe current NameState and active owner Coin evidence.
    ///
    /// The expected durable chain epoch is checked inside the immutable
    /// snapshot before the NameState, UTXO, or transaction index is read. The
    /// result never loads a raw block body and therefore remains available
    /// after payload pruning, with a deliberately unavailable transaction
    /// position. It is trusted-node discovery/current-UTXO evidence only, not
    /// a transaction-output proof or authorization to spend the Coin.
    pub async fn get_active_name_owner_coin(
        &self,
        name_hash: NameHash,
        expected_chain_epoch: u64,
    ) -> Result<ActiveNameOwnerCoinEvidence, WalletBackendError> {
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            active_name_owner_coin_from_snapshot(snapshot, name_hash, expected_chain_epoch)
        })
        .await
    }

    /// Read current active name state by canonical name hash.
    pub async fn get_name_state(
        &self,
        name_hash: NameHash,
    ) -> Result<Option<NameState>, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            load_current_name_state(snapshot, name_hash)
        })
        .await
    }

    /// Generate a tip-bound inclusion/non-inclusion name proof.
    pub async fn get_name_proof(
        &self,
        name_hash: NameHash,
    ) -> Result<NameProofResult, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| name_proof(snapshot, name_hash)).await
    }

    /// Read current state, proof state, and both owners in one chain snapshot.
    ///
    /// Handshake commits its authenticated name tree at interval boundaries,
    /// while the current NameState column also contains pending interval
    /// changes. Both views are returned explicitly so an adapter cannot
    /// accidentally claim that the proof authenticates `current_state`.
    pub async fn get_name_evidence(
        &self,
        name_hash: NameHash,
    ) -> Result<NameEvidence, WalletBackendError> {
        let transaction_index = self.read.transaction_index;
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
            let current_state = load_current_name_state(snapshot, name_hash)?;
            let proof = name_proof(snapshot, name_hash)?;
            let proof_raw = proof.proof.verify_value(proof.root).map_err(node_error)?;
            let proof_state = proof_raw
                .as_deref()
                .map(|raw| decode_name_state(&name_hash, raw))
                .transpose()
                .map_err(node_error)?;
            let current_owner = current_state
                .as_ref()
                .map(|state| load_name_owner(snapshot, state, transaction_index))
                .transpose()?
                .flatten();
            let proof_owner = if proof_state == current_state {
                current_owner.clone()
            } else {
                proof_state
                    .as_ref()
                    .map(|state| load_name_owner(snapshot, state, transaction_index))
                    .transpose()?
                    .flatten()
            };
            Ok(NameEvidence {
                chain_epoch,
                tip: proof.tip.clone(),
                current_state,
                proof_state,
                proof,
                current_owner,
                proof_owner,
            })
        })
        .await
    }

    /// Follow current name ownership to its confirmed transaction and output.
    pub async fn get_name_owner_transaction(
        &self,
        name_hash: NameHash,
    ) -> Result<Option<NameOwnerTransaction>, WalletBackendError> {
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            let Some(name_state) = load_current_name_state(snapshot, name_hash)? else {
                return Ok(None);
            };
            if name_state.owner.is_null() {
                return Err(WalletBackendError::NameHasNoOwner);
            }
            load_name_owner(snapshot, &name_state, true)
        })
        .await
    }
}

fn wallet_chain_tip<S: ReadSnapshot>(
    snapshot: &S,
) -> Result<Option<WalletChainTip>, WalletBackendError> {
    let Some(tip) = best_block_tip_from_snapshot(snapshot).map_err(node_error)? else {
        return Ok(None);
    };
    let tip_header = load_header_record(snapshot, &tip.hash)
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt("active tip header is missing"))?;
    if tip_header.height != tip.height {
        return Err(WalletBackendError::Corrupt(
            "active tip header height disagrees with the block index",
        ));
    }
    let mut lookup = |hash: &BlockHash| load_header_record(snapshot, hash);
    let median_time_past =
        median_time_past_with_lookup(&tip_header, &mut lookup).map_err(node_error)?;
    let tree_root = load_stored_name_tree_root(snapshot).map_err(node_error)?;
    Ok(Some(WalletChainTip {
        hash: tip.hash,
        height: tip.height,
        median_time_past,
        tree_root,
    }))
}

struct IncomingTransferBodyCache {
    hash: BlockHash,
    retained: Option<RetainedIncomingTransferBody>,
}

struct RetainedIncomingTransferBody {
    block: Block,
    transaction_indexes: Vec<TxIndexEntry>,
}

#[allow(clippy::too_many_arguments)]
fn incoming_transfers_page_from_snapshot<S: ReadSnapshot>(
    snapshot: &S,
    profile: WalletIndexProfile,
    scripts: &[ScriptId],
    expected_chain_epoch: u64,
    script_set_id: [u8; 32],
    cursor: Option<IncomingTransfersCursor>,
    limit: usize,
) -> Result<IncomingTransfersPage, WalletBackendError> {
    // This request binding deliberately occurs before the first incoming-index
    // prefix scan or raw-body read. The enclosing canonical-read fence performs
    // only its own Meta/block-index point reads before entering this helper.
    let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
    if expected_chain_epoch != chain_epoch {
        return Err(WalletBackendError::StaleChainEpoch {
            expected: expected_chain_epoch,
            actual: chain_epoch,
        });
    }

    let tip = wallet_chain_tip(snapshot)?;
    let (mut script_index, mut inner) = match cursor {
        Some(cursor) => {
            if cursor.binding_version != INCOMING_TRANSFER_CURSOR_VERSION {
                return Err(WalletBackendError::InvalidIncomingTransferCursor);
            }
            if cursor.chain_epoch != chain_epoch {
                return Err(WalletBackendError::StaleChainEpoch {
                    expected: cursor.chain_epoch,
                    actual: chain_epoch,
                });
            }
            if cursor.tip != tip
                || cursor.script_set_id != script_set_id
                || cursor.script_index >= scripts.len()
            {
                return Err(WalletBackendError::InvalidIncomingTransferCursor);
            }
            (cursor.script_index, cursor.inner)
        }
        None => (0, None),
    };

    let mut script_examinations = 0usize;
    let mut body_cache = None;
    let mut retained_body_decodes = 0usize;

    loop {
        if script_examinations == MAX_WALLET_INCOMING_TRANSFER_SCRIPT_EXAMINATIONS {
            return Ok(IncomingTransfersPage {
                projection_version: INCOMING_TRANSFER_PROJECTION_VERSION,
                chain_epoch,
                tip: tip.clone(),
                entries: Vec::new(),
                script_examinations,
                continuation: Some(incoming_transfers_cursor(
                    chain_epoch,
                    &tip,
                    script_set_id,
                    script_index,
                    inner,
                )),
            });
        }

        let script = scripts
            .get(script_index)
            .copied()
            .ok_or(WalletBackendError::InvalidIncomingTransferCursor)?;
        script_examinations = script_examinations.saturating_add(1);
        let page = incoming_transfers(snapshot, profile, script, inner.as_ref(), limit)
            .map_err(wallet_index_error)?;
        let mut entries = Vec::with_capacity(page.entries.len());
        let mut last_emitted = inner.clone();

        for record in page.entries {
            let row_cursor = incoming_transfer_row_cursor(&record.entry);
            let Some((inclusion, source_binding)) = corroborate_incoming_transfer(
                snapshot,
                &record.entry,
                record.source_output_count,
                tip.as_ref(),
                &mut body_cache,
                &mut retained_body_decodes,
            )?
            else {
                return Ok(IncomingTransfersPage {
                    projection_version: INCOMING_TRANSFER_PROJECTION_VERSION,
                    chain_epoch,
                    tip: tip.clone(),
                    entries,
                    script_examinations,
                    continuation: Some(incoming_transfers_cursor(
                        chain_epoch,
                        &tip,
                        script_set_id,
                        script_index,
                        last_emitted,
                    )),
                });
            };
            last_emitted = Some(row_cursor);
            entries.push(WalletIncomingTransfer {
                script_index,
                entry: record.entry,
                source_output_count: record.source_output_count,
                inclusion,
                source_binding,
            });
        }

        let next = if let Some(cursor) = page.continuation {
            Some((script_index, Some(cursor)))
        } else if script_index + 1 < scripts.len() {
            Some((script_index + 1, None))
        } else {
            None
        };

        if entries.is_empty() {
            let Some((next_script_index, next_inner)) = next else {
                return Ok(IncomingTransfersPage {
                    projection_version: INCOMING_TRANSFER_PROJECTION_VERSION,
                    chain_epoch,
                    tip,
                    entries,
                    script_examinations,
                    continuation: None,
                });
            };
            script_index = next_script_index;
            inner = next_inner;
            continue;
        }

        return Ok(IncomingTransfersPage {
            projection_version: INCOMING_TRANSFER_PROJECTION_VERSION,
            chain_epoch,
            tip: tip.clone(),
            entries,
            script_examinations,
            continuation: next.map(|(script_index, inner)| {
                incoming_transfers_cursor(chain_epoch, &tip, script_set_id, script_index, inner)
            }),
        });
    }
}

fn incoming_transfers_cursor(
    chain_epoch: u64,
    tip: &Option<WalletChainTip>,
    script_set_id: [u8; 32],
    script_index: usize,
    inner: Option<IncomingTransferCursor>,
) -> IncomingTransfersCursor {
    IncomingTransfersCursor {
        binding_version: INCOMING_TRANSFER_CURSOR_VERSION,
        chain_epoch,
        tip: tip.clone(),
        script_set_id,
        script_index,
        inner,
    }
}

fn incoming_transfer_row_cursor(entry: &IncomingTransferEntry) -> IncomingTransferCursor {
    IncomingTransferCursor {
        height: entry.height,
        transaction_position: entry.transaction_position,
        txid: entry.coin.outpoint.txid,
        output_index: entry.coin.outpoint.index,
    }
}

fn incoming_transfer_source_status_is_authoritative(status: &BlockStatus) -> bool {
    // `body_present` is the independently corroborated retention branch below,
    // and `undo_present` is rollback durability rather than source authority.
    // Every other consensus/state bit must remain satisfied after pruning.
    status.header_context_valid
        && status.checkpoint_valid
        && status.deployment_state_valid
        && status.body_syntax_valid
        && status.absolute_finality_valid
        && status.relative_locks_valid
        && status.scripts_valid
        && status.covenant_links_valid
        && status.covenants_context_valid
        && status.claims_and_airdrops_valid
        && status.utxo_connected
        && status.name_state_connected
        && status.tree_root_valid
        && status.active_chain
        && !status.failed
}

fn corroborate_incoming_transfer<S: ReadSnapshot>(
    snapshot: &S,
    entry: &IncomingTransferEntry,
    source_output_count: u32,
    tip: Option<&WalletChainTip>,
    body_cache: &mut Option<IncomingTransferBodyCache>,
    retained_body_decodes: &mut usize,
) -> Result<Option<(TransactionInclusion, IncomingTransferSourceBinding)>, WalletBackendError> {
    let txid = entry.coin.outpoint.txid;
    let transaction_index = load_required_incoming_transfer_tx_index(snapshot, txid)?;
    if transaction_index.block_hash != entry.block_hash
        || transaction_index.height != entry.height
        || transaction_index.output_count != source_output_count
        || entry.coin.height != entry.height
        || entry.coin.outpoint.index >= source_output_count
    {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER transaction index disagrees with compact source evidence",
        ));
    }

    if read_canonical_hash(snapshot, entry.height).map_err(node_error)? != Some(entry.block_hash) {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER source block is not canonical at its recorded height",
        ));
    }

    let block_index = load_required_incoming_transfer_block_index(snapshot, entry.block_hash)?;
    let header = load_required_incoming_transfer_header(snapshot, entry.block_hash)?;
    if block_index.height != entry.height
        || header.height != entry.height
        || block_index.prev_hash != header.header.prev_block
        || block_index.chainwork != header.chainwork
        || block_index.status != header.status
    {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER block index and header metadata disagree",
        ));
    }
    if !incoming_transfer_source_status_is_authoritative(&block_index.status) {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER source block lacks durable active consensus status",
        ));
    }
    if entry.transaction_position >= block_index.tx_count {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER transaction ordinal exceeds its block transaction count",
        ));
    }

    let active_coin = snapshot
        .get(
            ColumnFamily::Utxo,
            &encode_outpoint_key(&entry.coin.outpoint),
        )
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER active UTXO is missing",
        ))?;
    if active_coin != encode_coin(&entry.coin) {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER active UTXO differs from indexed source coin",
        ));
    }

    let tip = tip.ok_or(WalletBackendError::Corrupt(
        "incoming TRANSFER evidence exists without an active tip",
    ))?;
    let confirmations = tip
        .height
        .checked_sub(entry.height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER source height exceeds the active tip",
        ))?;
    let inclusion = TransactionInclusion {
        block_hash: entry.block_hash,
        height: entry.height,
        transaction_position: Some(entry.transaction_position),
        confirmations,
    };

    let source_binding = if block_index.status.body_present {
        let cached = body_cache
            .as_ref()
            .filter(|cached| cached.hash == entry.block_hash);
        if cached.is_some_and(|cached| cached.retained.is_none()) {
            return Err(WalletBackendError::Corrupt(
                "incoming TRANSFER block body status changed inside one snapshot",
            ));
        }
        if cached.is_none() {
            if *retained_body_decodes == MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES {
                return Ok(None);
            }
            let block = load_required_incoming_transfer_block(snapshot, entry.block_hash)?;
            let transaction_indexes =
                tx_index_entries_for_block(&block, entry.height).map_err(|_| {
                    WalletBackendError::Corrupt(
                        "incoming TRANSFER retained transaction indexes cannot be recomputed",
                    )
                })?;
            *retained_body_decodes = retained_body_decodes.saturating_add(1);
            *body_cache = Some(IncomingTransferBodyCache {
                hash: entry.block_hash,
                retained: Some(RetainedIncomingTransferBody {
                    block,
                    transaction_indexes,
                }),
            });
        }
        let retained = body_cache
            .as_ref()
            .and_then(|cached| cached.retained.as_ref())
            .ok_or(WalletBackendError::Corrupt(
                "incoming TRANSFER retained block cache is inconsistent",
            ))?;
        validate_retained_incoming_transfer(
            retained,
            &block_index,
            &header,
            &transaction_index,
            entry,
            source_output_count,
        )?;
        IncomingTransferSourceBinding::RetainedBodyVerified
    } else {
        let cached = body_cache
            .as_ref()
            .filter(|cached| cached.hash == entry.block_hash);
        if cached.is_some_and(|cached| cached.retained.is_some()) {
            return Err(WalletBackendError::Corrupt(
                "incoming TRANSFER block body status changed inside one snapshot",
            ));
        }
        if cached.is_none() {
            if snapshot
                .get(ColumnFamily::Blocks, entry.block_hash.as_bytes())
                .map_err(node_error)?
                .is_some()
            {
                return Err(WalletBackendError::Corrupt(
                    "incoming TRANSFER pruned status retains a raw block body",
                ));
            }
            *body_cache = Some(IncomingTransferBodyCache {
                hash: entry.block_hash,
                retained: None,
            });
        }
        IncomingTransferSourceBinding::PrunedTrustedNodeProjection
    };

    Ok(Some((inclusion, source_binding)))
}

fn load_required_incoming_transfer_tx_index<S: ReadSnapshot>(
    snapshot: &S,
    txid: Txid,
) -> Result<TxIndexEntry, WalletBackendError> {
    let raw = snapshot
        .get(ColumnFamily::TxIndex, txid.as_bytes())
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER source transaction index is missing",
        ))?;
    let index = TxIndexEntry::decode(&raw).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER source transaction index is malformed")
    })?;
    if index.txid != txid {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER source transaction index key binding is invalid",
        ));
    }
    Ok(index)
}

fn load_required_incoming_transfer_block_index<S: ReadSnapshot>(
    snapshot: &S,
    hash: BlockHash,
) -> Result<BlockIndexRecord, WalletBackendError> {
    let raw = snapshot
        .get(ColumnFamily::BlockIndex, hash.as_bytes())
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER source block index is missing",
        ))?;
    let record = BlockIndexRecord::decode(&raw).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER source block index is malformed")
    })?;
    if record.hash != hash {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER source block index key binding is invalid",
        ));
    }
    Ok(record)
}

fn load_required_incoming_transfer_header<S: ReadSnapshot>(
    snapshot: &S,
    hash: BlockHash,
) -> Result<HeaderRecord, WalletBackendError> {
    let raw = snapshot
        .get(ColumnFamily::Headers, hash.as_bytes())
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER source header is missing",
        ))?;
    let record = HeaderRecord::decode(&raw)
        .map_err(|_| WalletBackendError::Corrupt("incoming TRANSFER source header is malformed"))?;
    if record.hash != hash || record.header.hash() != hash {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER source header key binding is invalid",
        ));
    }
    Ok(record)
}

fn load_required_incoming_transfer_block<S: ReadSnapshot>(
    snapshot: &S,
    hash: BlockHash,
) -> Result<Block, WalletBackendError> {
    let raw = snapshot
        .get(ColumnFamily::Blocks, hash.as_bytes())
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER retained block body is missing",
        ))?;
    let record = RawBlockRecord::decode(&raw).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER raw block record is malformed")
    })?;
    if record.hash != hash {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER raw block key binding is invalid",
        ));
    }
    record.decode_block().map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER retained block body is malformed")
    })
}

fn validate_retained_incoming_transfer(
    retained: &RetainedIncomingTransferBody,
    block_index: &BlockIndexRecord,
    header: &HeaderRecord,
    transaction_index: &TxIndexEntry,
    entry: &IncomingTransferEntry,
    source_output_count: u32,
) -> Result<(), WalletBackendError> {
    let block = &retained.block;
    if block.header != header.header {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER retained block header disagrees with the header index",
        ));
    }
    validate_block_commitments(block).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER retained block commitments are invalid")
    })?;
    let transaction_count = u32::try_from(block.transactions.len()).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER retained block transaction count overflows")
    })?;
    if transaction_count != block_index.tx_count {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER retained block transaction count disagrees with its index",
        ));
    }
    let transaction_position = usize::try_from(entry.transaction_position).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER retained transaction ordinal overflows")
    })?;
    let transaction =
        block
            .transactions
            .get(transaction_position)
            .ok_or(WalletBackendError::Corrupt(
                "incoming TRANSFER retained transaction ordinal is absent",
            ))?;
    if retained.transaction_indexes.get(transaction_position) != Some(transaction_index) {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER durable transaction index differs from retained block offsets",
        ));
    }
    if transaction.txid() != transaction_index.txid {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER retained transaction ordinal has the wrong transaction ID",
        ));
    }
    let output_count = u32::try_from(transaction.outputs.len()).map_err(|_| {
        WalletBackendError::Corrupt("incoming TRANSFER retained transaction output count overflows")
    })?;
    if output_count != source_output_count || output_count != transaction_index.output_count {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER retained transaction output count disagrees with its evidence",
        ));
    }
    let output = usize::try_from(entry.coin.outpoint.index)
        .ok()
        .and_then(|position| transaction.outputs.get(position))
        .ok_or(WalletBackendError::Corrupt(
            "incoming TRANSFER retained source output is absent",
        ))?;
    if output.value != entry.coin.value
        || output.address != entry.coin.address
        || output.covenant != entry.coin.covenant
    {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER retained source output differs from its active coin",
        ));
    }
    if is_coinbase(transaction) != entry.coin.coinbase {
        return Err(WalletBackendError::Corrupt(
            "incoming TRANSFER retained transaction coinbase state disagrees with its active coin",
        ));
    }
    Ok(())
}

fn load_block_time<S: ReadSnapshot>(
    snapshot: &S,
    cache: &mut HashMap<BlockHash, Option<u64>>,
    block_hash: BlockHash,
) -> Result<Option<u64>, WalletBackendError> {
    if let Some(time) = cache.get(&block_hash) {
        return Ok(*time);
    }
    let time = snapshot
        .get(ColumnFamily::Headers, block_hash.as_bytes())
        .map_err(node_error)?
        .map(|raw| {
            let record = HeaderRecord::decode(&raw).map_err(node_error)?;
            if record.hash != block_hash || record.header.hash() != block_hash {
                return Err(WalletBackendError::Corrupt(
                    "wallet history header identity is inconsistent",
                ));
            }
            Ok(record.header.time)
        })
        .transpose()?;
    cache.insert(block_hash, time);
    Ok(time)
}

#[allow(clippy::too_many_arguments)]
fn name_action_context_v2_from_snapshot<S: ReadSnapshot>(
    network: Network,
    snapshot: &S,
    mempool: &MempoolSnapshot,
    published_chain_epoch: u64,
    action: NameAction,
    name_hash: NameHash,
    expected_chain_epoch: u64,
    expected_mempool_instance_nonce: [u8; 32],
    expected_mempool_generation: u64,
) -> Result<NameActionContextV2, WalletBackendError> {
    // Preserve this ordering. A stale caller must be rejected before the
    // requested NameState, owner UTXO, or transaction index is touched, and
    // an old process-local mempool binding must not turn this method into a
    // name-existence oracle.
    let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
    if chain_epoch != published_chain_epoch {
        return Err(WalletBackendError::Corrupt(
            "published and durable chain generations disagree",
        ));
    }
    if chain_epoch != expected_chain_epoch {
        return Err(WalletBackendError::StaleChainEpoch {
            expected: expected_chain_epoch,
            actual: chain_epoch,
        });
    }
    if mempool.instance_nonce() != &expected_mempool_instance_nonce {
        return Err(WalletBackendError::StaleMempoolInstance);
    }
    if mempool.generation() != expected_mempool_generation {
        return Err(WalletBackendError::StaleMempoolGeneration {
            expected: expected_mempool_generation,
            actual: mempool.generation(),
        });
    }

    let network_params = network.params();
    let name_params = network_params.names;
    let tip = wallet_chain_tip(snapshot)?.ok_or(WalletBackendError::ChainUninitialized)?;
    let canonical_genesis = read_canonical_hash(snapshot, 0)
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "initialized chain has no canonical genesis",
        ))?;
    if canonical_genesis != network_params.genesis_hash {
        return Err(WalletBackendError::Corrupt(
            "canonical genesis disagrees with the selected network",
        ));
    }

    let active_owner =
        active_name_owner_coin_from_snapshot(snapshot, name_hash, expected_chain_epoch)?;
    if active_owner.chain_epoch != chain_epoch || active_owner.tip != tip {
        return Err(WalletBackendError::Corrupt(
            "name action active owner has a different chain generation or tip",
        ));
    }
    let candidate_inclusion_height =
        active_owner
            .tip
            .height
            .checked_add(1)
            .ok_or(WalletBackendError::Corrupt(
                "candidate inclusion height overflows u32",
            ))?;

    let owner_spender_txid = mempool.spending_transaction(&active_owner.owner_coin.outpoint);
    let lifecycle = name_lifecycle(
        &active_owner.current_state,
        candidate_inclusion_height,
        name_params,
    );
    let expired_at_candidate = is_name_expired(
        &active_owner.current_state,
        candidate_inclusion_height,
        name_params,
    );
    let current_transfer_height =
        (active_owner.current_state.transfer != 0).then_some(active_owner.current_state.transfer);
    let finalize_maturity_height =
        current_transfer_height.map(|height| transfer_maturity_height(height, name_params));
    let finalize_eligible_at_candidate = is_transfer_mature(
        active_owner.current_state.transfer,
        candidate_inclusion_height,
        name_params,
    );

    let hsd_selected_height = hsd_wallet_renewal_height(active_owner.tip.height, name_params);
    let hsd_selected_hash = read_canonical_hash(snapshot, hsd_selected_height)
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "HSD-selected renewal height is absent from the active chain",
        ))?;
    let renewal_valid_at_candidate = renewal_commitment_height_is_valid(
        hsd_selected_height,
        candidate_inclusion_height,
        name_params,
    );
    let ineligibility_reasons = name_action_ineligibility_reasons(
        action,
        &active_owner.current_state,
        active_owner.owner_coin.covenant.kind,
        lifecycle,
        expired_at_candidate,
        finalize_eligible_at_candidate,
        renewal_valid_at_candidate,
        owner_spender_txid,
    )?;

    Ok(NameActionContextV2 {
        context_version: NAME_ACTION_CONTEXT_V2_VERSION,
        action,
        network,
        network_id: network.canonical_id(),
        genesis_hash: network_params.genesis_hash,
        consensus_profile: HSD_CONSENSUS_PROFILE.to_owned(),
        chain_epoch,
        tip: active_owner.tip,
        candidate_inclusion_height,
        mempool_instance_nonce: *mempool.instance_nonce(),
        mempool_generation: mempool.generation(),
        owner_spender_txid,
        name_hash,
        current_state_bytes: active_owner.current_state_bytes,
        current_state: active_owner.current_state,
        active_owner: NameActionActiveOwnerCoin {
            projection_version: active_owner.projection_version,
            owner_coin: active_owner.owner_coin,
            inclusion: active_owner.inclusion,
            source_binding: active_owner.source_binding,
        },
        lifecycle,
        transfer: NameTransferContext {
            lockup_blocks: name_params.transfer_lockup,
            current_transfer_height,
            finalize_maturity_height,
            finalize_eligible_at_candidate,
        },
        renewal: NameRenewalContext {
            maturity_blocks: name_params.renewal_maturity,
            period_blocks: name_params.renewal_period,
            hsd_selected_height,
            hsd_selected_hash,
            valid_at_candidate: renewal_valid_at_candidate,
        },
        ineligibility_reasons,
    })
}

fn active_name_owner_coin_from_snapshot<S: ReadSnapshot>(
    snapshot: &S,
    name_hash: NameHash,
    expected_chain_epoch: u64,
) -> Result<ActiveNameOwnerCoinEvidence, WalletBackendError> {
    // Preserve this ordering: a stale caller must be rejected before the
    // requested name, owner UTXO, or transaction index is touched.
    let chain_epoch = chain_epoch_from_snapshot(snapshot).map_err(node_error)?;
    if chain_epoch != expected_chain_epoch {
        return Err(WalletBackendError::StaleChainEpoch {
            expected: expected_chain_epoch,
            actual: chain_epoch,
        });
    }

    let tip = wallet_chain_tip(snapshot)?.ok_or(WalletBackendError::ChainUninitialized)?;
    let current_state_bytes = snapshot
        .get(ColumnFamily::NameState, name_hash.as_bytes())
        .map_err(node_error)?
        .ok_or(WalletBackendError::NameStateMissing)?;
    let current_state = decode_name_state(&name_hash, &current_state_bytes).map_err(node_error)?;
    if current_state.is_null()
        || current_state.name_hash != name_hash
        || encode_name_state(&current_state).map_err(node_error)? != current_state_bytes
    {
        return Err(WalletBackendError::Corrupt(
            "current name state is not canonically bound to its requested key",
        ));
    }
    let canonical_name = std::str::from_utf8(&current_state.name)
        .map_err(|_| WalletBackendError::Corrupt("current name state contains a non-ASCII name"))?;
    if hash_name(canonical_name)
        .map_err(|_| WalletBackendError::Corrupt("current name state contains an invalid name"))?
        != name_hash
    {
        return Err(WalletBackendError::Corrupt(
            "current name state name does not hash to its requested key",
        ));
    }
    if current_state.owner.is_null() {
        return Err(WalletBackendError::NameHasNoOwner);
    }

    let raw_coin = snapshot
        .get(
            ColumnFamily::Utxo,
            &encode_outpoint_key(&current_state.owner),
        )
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "current name owner is absent from the active UTXO set",
        ))?;
    let owner_coin = decode_coin(&raw_coin)
        .map_err(|_| WalletBackendError::Corrupt("current name owner UTXO cannot be decoded"))?;
    if encode_coin(&owner_coin) != raw_coin {
        return Err(WalletBackendError::Corrupt(
            "current name owner UTXO is not canonically encoded",
        ));
    }

    let Some((transaction_index, inclusion)) =
        load_transaction_index_and_inclusion(snapshot, current_state.owner.txid)?
    else {
        return Err(WalletBackendError::Corrupt(
            "current name owner transaction is absent from the active index",
        ));
    };
    if current_state.owner.index >= transaction_index.output_count {
        return Err(WalletBackendError::OwnerOutputMissing);
    }
    validate_active_name_owner_coin(&current_state, &owner_coin, &inclusion)?;

    Ok(ActiveNameOwnerCoinEvidence {
        projection_version: ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION,
        chain_epoch,
        tip,
        current_state_bytes,
        current_state,
        owner_coin,
        inclusion,
        source_binding: ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection,
    })
}

fn validate_active_name_owner_coin(
    state: &NameState,
    coin: &Coin,
    inclusion: &TransactionInclusion,
) -> Result<(), WalletBackendError> {
    if coin.outpoint != state.owner
        || coin.height != inclusion.height
        || inclusion.transaction_position.is_some()
    {
        return Err(WalletBackendError::Corrupt(
            "current name state, owner UTXO, and transaction inclusion disagree",
        ));
    }
    if state.registered && coin.value != state.value {
        return Err(WalletBackendError::Corrupt(
            "registered current name owner value disagrees with current name state",
        ));
    }
    if !matches!(
        coin.covenant.kind,
        CovenantKind::Claim
            | CovenantKind::Reveal
            | CovenantKind::Register
            | CovenantKind::Update
            | CovenantKind::Renew
            | CovenantKind::Transfer
            | CovenantKind::Finalize
    ) || coin.covenant.item_hash(0) != Some(*state.name_hash.as_bytes())
        || coin.covenant.item_u32(1) != Some(state.height)
    {
        return Err(WalletBackendError::Corrupt(
            "current name owner covenant identity disagrees with current name state",
        ));
    }

    match coin.covenant.kind {
        CovenantKind::Claim => {
            if !coin.coinbase
                || state.registered
                || coin.covenant.items.len() != 6
                || coin.covenant.item(2) != Some(state.name.as_slice())
                || coin
                    .covenant
                    .item_u8(3)
                    .is_none_or(|flags| flags & 1 != u8::from(state.weak))
                || coin.covenant.item_hash(4).is_none()
                || coin.covenant.item_u32(5) != Some(state.claimed)
                || state.renewal != coin.height
            {
                return Err(WalletBackendError::Corrupt(
                    "active CLAIM owner coin disagrees with current name state",
                ));
            }
        }
        CovenantKind::Reveal => {
            if coin.coinbase
                || state.registered
                || coin.covenant.items.len() != 3
                || coin.covenant.item_hash(2).is_none()
                || coin.value != state.highest
            {
                return Err(WalletBackendError::Corrupt(
                    "active REVEAL owner coin disagrees with current name state",
                ));
            }
        }
        CovenantKind::Register => {
            if coin.coinbase
                || coin.covenant.items.len() != 4
                || coin.covenant.item(2).is_none_or(|data| {
                    data.len() > MAX_RESOURCE_SIZE || (!data.is_empty() && data != state.data)
                })
                || coin.covenant.item_hash(3).is_none()
                || !state.registered
                || state.transfer != 0
                || state.renewal != coin.height
            {
                return Err(WalletBackendError::Corrupt(
                    "active REGISTER owner coin disagrees with current name state",
                ));
            }
        }
        CovenantKind::Update => {
            if coin.coinbase
                || coin.covenant.items.len() != 3
                || coin.covenant.item(2).is_none_or(|data| {
                    data.len() > MAX_RESOURCE_SIZE || (!data.is_empty() && data != state.data)
                })
                || !state.registered
                || state.transfer != 0
            {
                return Err(WalletBackendError::Corrupt(
                    "active UPDATE owner coin disagrees with current name state",
                ));
            }
        }
        CovenantKind::Renew => {
            if coin.coinbase
                || coin.covenant.items.len() != 3
                || coin.covenant.item_hash(2).is_none()
                || !state.registered
                || state.transfer != 0
                || state.renewal != coin.height
            {
                return Err(WalletBackendError::Corrupt(
                    "active RENEW owner coin disagrees with current name state",
                ));
            }
        }
        CovenantKind::Transfer => {
            if coin.coinbase
                || !state.registered
                || coin.covenant.items.len() != 4
                || coin.covenant.item_u8(2).is_none_or(|version| version > 31)
                || coin
                    .covenant
                    .item(3)
                    .is_none_or(|recipient| !(2..=40).contains(&recipient.len()))
                || state.transfer == 0
                || state.transfer != coin.height
            {
                return Err(WalletBackendError::Corrupt(
                    "active TRANSFER owner coin disagrees with current name state",
                ));
            }
        }
        CovenantKind::Finalize => {
            let prior_renewals = coin.covenant.item_u32(5);
            if coin.coinbase
                || !state.registered
                || coin.covenant.items.len() != 7
                || coin.covenant.item(2) != Some(state.name.as_slice())
                || coin
                    .covenant
                    .item_u8(3)
                    .is_none_or(|flags| flags & 1 != u8::from(state.weak))
                || coin.covenant.item_u32(4) != Some(state.claimed)
                || prior_renewals.and_then(|renewals| renewals.checked_add(1))
                    != Some(state.renewals)
                || coin.covenant.item_hash(6).is_none()
                || state.transfer != 0
                || state.renewal != coin.height
            {
                return Err(WalletBackendError::Corrupt(
                    "active FINALIZE owner coin disagrees with current name state",
                ));
            }
        }
        _ if state.transfer != 0 => {
            return Err(WalletBackendError::Corrupt(
                "non-TRANSFER owner coin backs a pending-transfer name state",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn load_current_name_state<S: ReadSnapshot>(
    snapshot: &S,
    name_hash: NameHash,
) -> Result<Option<NameState>, WalletBackendError> {
    snapshot
        .get(ColumnFamily::NameState, name_hash.as_bytes())
        .map_err(node_error)?
        .as_deref()
        .map(|raw| decode_name_state(&name_hash, raw))
        .transpose()
        .map_err(node_error)
}

fn name_proof<S: ReadSnapshot>(
    snapshot: &S,
    name_hash: NameHash,
) -> Result<NameProofResult, WalletBackendError> {
    let tip = wallet_chain_tip(snapshot)?;
    let root = load_stored_name_tree_root(snapshot).map_err(node_error)?;
    if tip.as_ref().is_some_and(|tip| tip.tree_root != root) {
        return Err(WalletBackendError::Corrupt(
            "wallet tip and name proof roots disagree",
        ));
    }
    let proof = prove_persisted_name_tree(snapshot, root, name_hash).map_err(node_error)?;
    Ok(NameProofResult { tip, root, proof })
}

fn load_name_owner<S: ReadSnapshot>(
    snapshot: &S,
    name_state: &NameState,
    transaction_index: bool,
) -> Result<Option<NameOwnerTransaction>, WalletBackendError> {
    if name_state.owner.is_null() {
        return Ok(None);
    }
    if !transaction_index {
        return Err(WalletBackendError::IndexDisabled("transaction"));
    }
    let owner = name_state.owner.clone();
    let Some((transaction, inclusion)) = load_confirmed_transaction(snapshot, owner.txid)? else {
        return Err(WalletBackendError::Corrupt(
            "name owner transaction is absent from the active index",
        ));
    };
    let owner_output = transaction
        .outputs
        .get(usize::try_from(owner.index).map_err(|_| WalletBackendError::OwnerOutputMissing)?)
        .cloned()
        .ok_or(WalletBackendError::OwnerOutputMissing)?;
    Ok(Some(NameOwnerTransaction {
        name_state: name_state.clone(),
        owner,
        transaction,
        owner_output,
        inclusion,
    }))
}

fn validate_name_action_owner<S: ReadSnapshot>(
    snapshot: &S,
    state: &NameState,
    owner: &NameOwnerTransaction,
) -> Result<(), WalletBackendError> {
    if &owner.name_state != state || owner.owner != state.owner {
        return Err(WalletBackendError::Corrupt(
            "name action owner disagrees with current name state",
        ));
    }
    if state.registered && owner.owner_output.value != state.value {
        return Err(WalletBackendError::Corrupt(
            "registered name action owner value disagrees with current name state",
        ));
    }
    if owner.owner_output.covenant.item_hash(0) != Some(*state.name_hash.as_bytes())
        || owner.owner_output.covenant.item_u32(1) != Some(state.height)
    {
        return Err(WalletBackendError::Corrupt(
            "name action owner covenant identity disagrees with current name state",
        ));
    }
    let raw = snapshot
        .get(ColumnFamily::Utxo, &encode_outpoint_key(&owner.owner))
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "current name owner is absent from the active UTXO set",
        ))?;
    let coin = decode_coin(&raw)
        .map_err(|_| WalletBackendError::Corrupt("current name owner UTXO cannot be decoded"))?;
    if coin.outpoint != owner.owner
        || coin.height != owner.inclusion.height
        || coin.value != owner.owner_output.value
        || coin.address != owner.owner_output.address
        || coin.covenant != owner.owner_output.covenant
    {
        return Err(WalletBackendError::Corrupt(
            "current name owner transaction and active UTXO disagree",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn name_action_ineligibility_reasons(
    action: NameAction,
    state: &NameState,
    owner_covenant: CovenantKind,
    lifecycle: NameLifecycleState,
    expired_at_candidate: bool,
    finalize_eligible_at_candidate: bool,
    renewal_valid_at_candidate: bool,
    owner_spender_txid: Option<Txid>,
) -> Result<Vec<NameActionIneligibility>, WalletBackendError> {
    let mut reasons = Vec::with_capacity(MAX_NAME_ACTION_INELIGIBILITY_REASONS);
    if !state.registered {
        reasons.push(NameActionIneligibility::NameNotRegistered);
    }
    if expired_at_candidate {
        reasons.push(NameActionIneligibility::NameExpiredAtCandidate);
    }
    if lifecycle != NameLifecycleState::Closed {
        reasons.push(NameActionIneligibility::LifecycleNotClosed);
    }
    match action {
        NameAction::Transfer => {
            if state.transfer != 0 {
                reasons.push(NameActionIneligibility::TransferAlreadyPending);
            }
            if !is_transfer_source_covenant(owner_covenant) {
                reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
        }
        NameAction::Finalize => {
            if state.transfer == 0 {
                reasons.push(NameActionIneligibility::TransferNotPending);
            } else if !finalize_eligible_at_candidate {
                reasons.push(NameActionIneligibility::TransferNotMature);
            }
            if !is_finalize_source_covenant(owner_covenant) {
                reasons.push(NameActionIneligibility::OwnerCovenantInvalidForAction);
            }
            if !renewal_valid_at_candidate {
                reasons.push(NameActionIneligibility::RenewalCommitmentInvalid);
            }
        }
    }
    if owner_spender_txid.is_some() {
        reasons.push(NameActionIneligibility::OwnerSpentInMempool);
    }
    if reasons.len() > MAX_NAME_ACTION_INELIGIBILITY_REASONS {
        return Err(WalletBackendError::Corrupt(
            "name action ineligibility reason bound exceeded",
        ));
    }
    Ok(reasons)
}

async fn blocking_chain_read<T, F>(
    read: NodeReadHandle,
    operation: F,
) -> Result<T, WalletBackendError>
where
    T: Send + 'static,
    F: FnOnce(
            &NodeReadHandle,
            &hns_store::StoreHandleSnapshot<'_>,
        ) -> Result<T, WalletBackendError>
        + Send
        + 'static,
{
    blocking_chain_read_with_admission(read, false, operation).await
}

async fn blocking_chain_collection_read<T, F>(
    read: NodeReadHandle,
    operation: F,
) -> Result<T, WalletBackendError>
where
    T: Send + 'static,
    F: FnOnce(
            &NodeReadHandle,
            &hns_store::StoreHandleSnapshot<'_>,
        ) -> Result<T, WalletBackendError>
        + Send
        + 'static,
{
    blocking_chain_read_with_admission(read, true, operation).await
}

async fn blocking_chain_read_with_admission<T, F>(
    read: NodeReadHandle,
    collection: bool,
    operation: F,
) -> Result<T, WalletBackendError>
where
    T: Send + 'static,
    F: FnOnce(
            &NodeReadHandle,
            &hns_store::StoreHandleSnapshot<'_>,
        ) -> Result<T, WalletBackendError>
        + Send
        + 'static,
{
    read.ensure_storage_operational().map_err(node_error)?;
    let concurrency = if collection {
        &read.collection_concurrency
    } else {
        &read.point_read_concurrency
    };
    let permit = Arc::clone(concurrency)
        .try_acquire_owned()
        .map_err(|_| WalletBackendError::Node("wallet read concurrency exhausted".to_owned()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read.ensure_storage_operational().map_err(node_error)?;
        let epoch = read.canonical_epoch().chain();
        let snapshot = read.store.snapshot().map_err(node_error)?;
        if chain_epoch_from_snapshot(&snapshot).map_err(node_error)? != epoch.chain_epoch
            || best_block_tip_from_snapshot(&snapshot)
                .map_err(node_error)?
                .as_ref()
                != epoch.tip.as_ref()
        {
            return Err(WalletBackendError::StaleCanonicalRead);
        }
        let result = operation(&read, &snapshot);
        if !read.canonical_chain_generation_is_stable(&epoch) {
            return Err(WalletBackendError::StaleCanonicalRead);
        }
        result
    })
    .await
    .map_err(node_error)?
}

async fn blocking_mempool_read<T, F>(
    read: NodeReadHandle,
    operation: F,
) -> Result<T, WalletBackendError>
where
    T: Send + 'static,
    F: FnOnce(
            &NodeReadHandle,
            &hns_store::StoreHandleSnapshot<'_>,
            &MempoolSnapshot,
            &MempoolInfo,
            &CanonicalEpoch,
        ) -> Result<T, WalletBackendError>
        + Send
        + 'static,
{
    read.ensure_storage_operational().map_err(node_error)?;
    let permit = Arc::clone(&read.collection_concurrency)
        .try_acquire_owned()
        .map_err(|_| WalletBackendError::Node("wallet read concurrency exhausted".to_owned()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let epoch = read.canonical_epoch();
        let published_mempool = read.published_mempool().map_err(node_error)?;
        let mempool = published_mempool.snapshot();
        let snapshot = read.store.snapshot().map_err(node_error)?;
        if chain_epoch_from_snapshot(&snapshot).map_err(node_error)? != epoch.chain_epoch
            || best_block_tip_from_snapshot(&snapshot)
                .map_err(node_error)?
                .as_ref()
                != epoch.tip.as_ref()
        {
            return Err(WalletBackendError::StaleCanonicalRead);
        }
        let result = operation(&read, &snapshot, &mempool, &published_mempool.info, &epoch);
        if !read.canonical_generation_is_stable(&epoch) {
            return Err(WalletBackendError::StaleCanonicalRead);
        }
        result
    })
    .await
    .map_err(node_error)?
}

fn validate_mempool_scan_limit(scan_limit: usize) -> Result<(), WalletBackendError> {
    if (1..=MAX_WALLET_MEMPOOL_SCAN).contains(&scan_limit) {
        Ok(())
    } else {
        Err(WalletBackendError::InvalidMempoolScanLimit)
    }
}

fn validate_script_set(scripts: &[ScriptId]) -> Result<(), WalletBackendError> {
    if scripts.is_empty()
        || scripts.len() > MAX_WALLET_RESTORE_SCRIPTS
        || scripts.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(WalletBackendError::InvalidScriptSet)
    } else {
        Ok(())
    }
}

fn confirmed_script_set_id(scripts: &[ScriptId]) -> Result<[u8; 32], WalletBackendError> {
    script_set_id(CONFIRMED_SCRIPT_SET_DOMAIN, scripts)
}

fn incoming_transfer_script_set_id(scripts: &[ScriptId]) -> Result<[u8; 32], WalletBackendError> {
    script_set_id(INCOMING_TRANSFER_SCRIPT_SET_DOMAIN, scripts)
}

fn script_set_id(domain: &[u8], scripts: &[ScriptId]) -> Result<[u8; 32], WalletBackendError> {
    let count = u32::try_from(scripts.len()).map_err(|_| WalletBackendError::InvalidScriptSet)?;
    let mut identity = Writer::with_capacity(domain.len() + 4 + scripts.len().saturating_mul(32));
    identity.write_bytes(domain);
    identity.write_u32_be(count);
    for script in scripts {
        identity.write_bytes(script.as_bytes());
    }
    Ok(blake2b_256(&identity.finish()))
}

fn mempool_contract_query_id(id: ContractId) -> [u8; 32] {
    let mut identity = Writer::with_capacity(MEMPOOL_CONTRACT_DOMAIN.len() + 32);
    identity.write_bytes(MEMPOOL_CONTRACT_DOMAIN);
    identity.write_bytes(id.as_bytes());
    blake2b_256(&identity.finish())
}

fn transaction_contains_contract_funding(
    registration: &ContractRegistration,
    transaction: &Transaction,
) -> Result<bool, WalletBackendError> {
    for output in &transaction.outputs {
        if registration
            .matches_funding_output(output)
            .map_err(wallet_index_error)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn mempool_scan_page(
    mempool: &MempoolSnapshot,
    cursor: Option<&WalletMempoolCursor>,
    scan_limit: usize,
    query_id: [u8; 32],
    chain_epoch: u64,
) -> Result<(Vec<Txid>, Option<WalletMempoolCursor>), WalletBackendError> {
    if let Some(cursor) = cursor {
        if cursor.binding_version != MEMPOOL_CURSOR_VERSION {
            return Err(WalletBackendError::InvalidMempoolCursor);
        }
        if cursor.chain_epoch != chain_epoch {
            return Err(WalletBackendError::StaleChainEpoch {
                expected: cursor.chain_epoch,
                actual: chain_epoch,
            });
        }
        if cursor.instance_nonce != *mempool.instance_nonce() {
            return Err(WalletBackendError::StaleMempoolInstance);
        }
        if cursor.generation != mempool.generation() {
            return Err(WalletBackendError::StaleMempoolGeneration {
                expected: cursor.generation,
                actual: mempool.generation(),
            });
        }
        if cursor.query_id != query_id {
            return Err(WalletBackendError::InvalidMempoolCursor);
        }
    }
    let mut txids = mempool
        .txids()
        .filter(|txid| cursor.is_none_or(|cursor| *txid > cursor.after_txid))
        .take(scan_limit.saturating_add(1))
        .collect::<Vec<_>>();
    let has_more = txids.len() > scan_limit;
    if has_more {
        txids.truncate(scan_limit);
    }
    let continuation = if has_more {
        txids.last().copied().map(|after_txid| WalletMempoolCursor {
            binding_version: MEMPOOL_CURSOR_VERSION,
            chain_epoch,
            instance_nonce: *mempool.instance_nonce(),
            generation: mempool.generation(),
            query_id,
            after_txid,
        })
    } else {
        None
    };
    Ok((txids, continuation))
}

fn estimate_fee_rate_from_snapshot(snapshot: &MempoolSnapshot, target_blocks: u32) -> FeeEstimate {
    let mut rates = snapshot
        .txids()
        .take(MAX_FEE_ESTIMATE_SAMPLES)
        .filter_map(|txid| snapshot.entry(&txid))
        .map(|entry| {
            entry
                .fee
                .saturating_mul(1_000)
                .checked_div(u64::try_from(entry.policy_size.max(1)).unwrap_or(u64::MAX))
                .unwrap_or(u64::MAX)
                .max(HSD_MINIMUM_RELAY_FEE_RATE)
        })
        .collect::<Vec<_>>();
    if rates.is_empty() {
        return FeeEstimate {
            target_blocks,
            atomic_units_per_kvb: HSD_MINIMUM_RELAY_FEE_RATE,
            sampled_transactions: 0,
            source: FeeEstimateSource::MinimumRelay,
        };
    }
    rates.sort_unstable_by(|left, right| right.cmp(left));
    let relaxed_target = usize::try_from(target_blocks.saturating_sub(1)).unwrap_or(usize::MAX);
    let denominator = usize::try_from(MAX_FEE_ESTIMATE_TARGET_BLOCKS).unwrap_or(usize::MAX);
    let index = rates
        .len()
        .saturating_sub(1)
        .saturating_mul(relaxed_target)
        .checked_div(denominator)
        .unwrap_or(0)
        .min(rates.len().saturating_sub(1));
    FeeEstimate {
        target_blocks,
        atomic_units_per_kvb: rates[index],
        sampled_transactions: rates.len(),
        source: FeeEstimateSource::Mempool,
    }
}

fn transaction_fee_quote_from_snapshot<S: ReadSnapshot>(
    snapshot: &S,
    mempool: &MempoolSnapshot,
    transaction: &Transaction,
    target_blocks: u32,
    chain_epoch: u64,
    tip: Option<WalletChainTip>,
) -> Result<TransactionFeeQuote, WalletBackendError> {
    let mut input_coins = Vec::with_capacity(transaction.inputs.len());
    for input in &transaction.inputs {
        if input.previous_output.is_null() {
            return Err(WalletBackendError::InvalidFeeQuoteTransaction);
        }
        input_coins.push(resolve_fee_quote_input_coin(
            snapshot,
            mempool,
            &input.previous_output,
        )?);
    }
    let sigops = transaction_sigops(transaction, &input_coins).map_err(|_| {
        WalletBackendError::Corrupt("resolved fee-quote inputs cannot produce a sigop count")
    })?;
    let input_value = input_coins.iter().try_fold(0u64, |total, coin| {
        total
            .checked_add(coin.value)
            .ok_or(WalletBackendError::InvalidFeeQuoteTransaction)
    })?;
    let output_value = transaction.outputs.iter().try_fold(0u64, |total, output| {
        total
            .checked_add(output.value)
            .ok_or(WalletBackendError::InvalidFeeQuoteTransaction)
    })?;
    let actual_fee = input_value
        .checked_sub(output_value)
        .ok_or(WalletBackendError::InvalidFeeQuoteTransaction)?;
    let weight = transaction_weight(transaction);
    let policy_size = sigop_adjusted_virtual_size(transaction, sigops);
    let estimate = estimate_fee_rate_from_snapshot(mempool, target_blocks);
    let minimum_fee = minimum_policy_fee(policy_size, estimate.atomic_units_per_kvb);
    Ok(TransactionFeeQuote {
        txid: transaction.txid(),
        chain_epoch,
        tip,
        mempool_instance_nonce: *mempool.instance_nonce(),
        mempool_generation: mempool.generation(),
        target_blocks,
        rate_atomic_units_per_1000_policy_vbytes: estimate.atomic_units_per_kvb,
        rate_sample_count: estimate.sampled_transactions,
        rate_source: estimate.source,
        transaction_weight: weight,
        transaction_sigops: sigops,
        sigop_adjusted_policy_vbytes: policy_size,
        minimum_policy_fee_atomic_units: minimum_fee,
        actual_fee_atomic_units: actual_fee,
        meets_minimum_policy_fee: actual_fee >= minimum_fee,
        minimum_policy_fee_shortfall_atomic_units: minimum_fee.saturating_sub(actual_fee),
    })
}

fn resolve_fee_quote_input_coin<S: ReadSnapshot>(
    snapshot: &S,
    mempool: &MempoolSnapshot,
    outpoint: &Outpoint,
) -> Result<Coin, WalletBackendError> {
    if let Some(parent) = mempool.transaction(&outpoint.txid) {
        let output = usize::try_from(outpoint.index)
            .ok()
            .and_then(|index| parent.outputs.get(index))
            .ok_or(WalletBackendError::FeeQuoteInputUnavailable)?;
        return Ok(Coin {
            outpoint: outpoint.clone(),
            value: output.value,
            height: 0,
            coinbase: false,
            address: output.address.clone(),
            covenant: output.covenant.clone(),
        });
    }
    let raw = snapshot
        .get(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))
        .map_err(node_error)?
        .ok_or(WalletBackendError::FeeQuoteInputUnavailable)?;
    let coin = decode_coin(&raw).map_err(|_| {
        WalletBackendError::Corrupt("active UTXO coin cannot be decoded for a fee quote")
    })?;
    if coin.outpoint != *outpoint {
        return Err(WalletBackendError::Corrupt(
            "UTXO payload disagrees with requested fee-quote input",
        ));
    }
    Ok(coin)
}

fn resolve_mempool_coin<S: ReadSnapshot>(
    snapshot: &S,
    mempool: &MempoolSnapshot,
    outpoint: &Outpoint,
) -> Result<Option<Coin>, WalletBackendError> {
    if let Some(parent) = mempool.transaction(&outpoint.txid) {
        let Some(output) = usize::try_from(outpoint.index)
            .ok()
            .and_then(|index| parent.outputs.get(index))
        else {
            return Err(WalletBackendError::Corrupt(
                "mempool child references an absent parent output",
            ));
        };
        return Ok(Some(Coin {
            outpoint: outpoint.clone(),
            value: output.value,
            height: 0,
            coinbase: false,
            address: output.address.clone(),
            covenant: output.covenant.clone(),
        }));
    }
    snapshot
        .get(ColumnFamily::Utxo, &encode_outpoint_key(outpoint))
        .map_err(node_error)?
        .as_deref()
        .map(decode_coin)
        .transpose()
        .map_err(node_error)
}

fn load_confirmed_transaction<S: ReadSnapshot>(
    snapshot: &S,
    txid: Txid,
) -> Result<Option<(Transaction, TransactionInclusion)>, WalletBackendError> {
    let Some((index, mut inclusion)) = load_transaction_index_and_inclusion(snapshot, txid)? else {
        return Ok(None);
    };
    let block = load_block(snapshot, &index.block_hash)
        .map_err(node_error)?
        .ok_or(WalletBackendError::PayloadPruned)?;
    let (position, transaction) = block
        .transactions
        .into_iter()
        .enumerate()
        .find(|(_, transaction)| transaction.txid() == txid)
        .ok_or(WalletBackendError::Corrupt(
            "indexed transaction is absent from its block",
        ))?;
    inclusion.transaction_position = Some(
        u32::try_from(position)
            .map_err(|_| WalletBackendError::Corrupt("block transaction position exceeds u32"))?,
    );
    Ok(Some((transaction, inclusion)))
}

fn load_transaction_index_and_inclusion<S: ReadSnapshot>(
    snapshot: &S,
    txid: Txid,
) -> Result<Option<(TxIndexEntry, TransactionInclusion)>, WalletBackendError> {
    let Some(raw) = snapshot
        .get(ColumnFamily::TxIndex, txid.as_bytes())
        .map_err(node_error)?
    else {
        return Ok(None);
    };
    let index = TxIndexEntry::decode(&raw).map_err(node_error)?;
    if index.txid != txid
        || read_canonical_hash(snapshot, index.height).map_err(node_error)?
            != Some(index.block_hash)
    {
        return Err(WalletBackendError::Corrupt(
            "transaction index is not bound to the active chain",
        ));
    }
    let tip = best_block_tip_from_snapshot(snapshot)
        .map_err(node_error)?
        .ok_or(WalletBackendError::Corrupt(
            "transaction index exists without an active tip",
        ))?;
    let confirmations = tip
        .height
        .checked_sub(index.height)
        .and_then(|depth| depth.checked_add(1))
        .ok_or(WalletBackendError::Corrupt(
            "transaction height exceeds active tip",
        ))?;
    Ok(Some((
        index.clone(),
        TransactionInclusion {
            block_hash: index.block_hash,
            height: index.height,
            transaction_position: None,
            confirmations,
        },
    )))
}

fn node_error(error: impl std::fmt::Display) -> WalletBackendError {
    WalletBackendError::Node(error.to_string())
}

fn wallet_index_error(error: IndexError) -> WalletBackendError {
    match error {
        IndexError::Disabled(component) => WalletBackendError::IndexDisabled(component),
        IndexError::InvalidLimit => WalletBackendError::InvalidIndexPageLimit,
        IndexError::Corrupt(reason) => WalletBackendError::Corrupt(reason),
        IndexError::UnknownContract => WalletBackendError::UnknownContract,
        IndexError::InvalidContract => WalletBackendError::InvalidContract,
        IndexError::ContractCapacity | IndexError::ContractAddressCapacity => {
            WalletBackendError::ContractCapacity
        }
        IndexError::ContractRetirementCapacity => WalletBackendError::ContractRetirementCapacity,
        IndexError::ContractRetirementHistoryCapacity => {
            WalletBackendError::ContractRetirementHistoryCapacity
        }
        IndexError::ContractRollbackRequired => WalletBackendError::ContractRollbackRequired,
        IndexError::ContractRetired => WalletBackendError::InvalidContract,
        IndexError::ContractConfirmed | IndexError::ContractConfirmationUnknown => {
            WalletBackendError::ContractNotRetirable
        }
        IndexError::StaleContractLifecycle { expected, actual } => {
            WalletBackendError::StaleContractLifecycle {
                expected,
                actual: Some(actual),
            }
        }
        other => node_error(other),
    }
}

fn wallet_writer_error(error: anyhow::Error) -> WalletBackendError {
    if let Some(writer) = error.downcast_ref::<CanonicalWriterError>() {
        if matches!(
            writer,
            CanonicalWriterError::StaleEpoch { .. } | CanonicalWriterError::StaleChainEpoch { .. }
        ) {
            return WalletBackendError::StaleCanonicalRead;
        }
    }
    if let Some(index) = error.downcast_ref::<IndexError>() {
        return match index {
            IndexError::Disabled(component) => WalletBackendError::IndexDisabled(component),
            IndexError::InvalidLimit => WalletBackendError::InvalidIndexPageLimit,
            IndexError::Corrupt(reason) => WalletBackendError::Corrupt(reason),
            IndexError::UnknownContract => WalletBackendError::UnknownContract,
            IndexError::InvalidContract => WalletBackendError::InvalidContract,
            IndexError::ContractCapacity | IndexError::ContractAddressCapacity => {
                WalletBackendError::ContractCapacity
            }
            IndexError::ContractRetirementCapacity => {
                WalletBackendError::ContractRetirementCapacity
            }
            IndexError::ContractRetirementHistoryCapacity => {
                WalletBackendError::ContractRetirementHistoryCapacity
            }
            IndexError::ContractRollbackRequired => WalletBackendError::ContractRollbackRequired,
            IndexError::ContractRetired => WalletBackendError::InvalidContract,
            IndexError::ContractConfirmed | IndexError::ContractConfirmationUnknown => {
                WalletBackendError::ContractNotRetirable
            }
            IndexError::StaleContractLifecycle { expected, actual } => {
                WalletBackendError::StaleContractLifecycle {
                    expected: *expected,
                    actual: Some(*actual),
                }
            }
            _ => node_error(index),
        };
    }
    node_error(error)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use hns_chain::{
        write_block_index_to_batch, write_canonical_height_to_batch, write_raw_block_to_batch,
        write_record_to_batch, write_tx_index_for_block_to_batch, write_tx_index_to_batch,
        BlockStatus, RawBlockSource,
    };
    use hns_consensus::{block_merkle_root, block_witness_root, Network};
    use hns_mempool::MemoryMempool;
    use hns_p2p::LivePeerConfig;
    use hns_primitives::{Address, CovenantKind, Header, Input, Outpoint, Uint256, Witness};
    use hns_state::{encode_coin, write_coin_to_batch, write_name_state_to_batch};
    use hns_store::{
        encode_u64, MemoryStore, MetaKey, PrefixScanBudget, PrefixScanPage, ReadSnapshot,
        ScanEntry, Store, StoreError, WriteBatch,
    };

    use crate::{NodeConfig, NodeService, DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY};

    const GENERATOR_KEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    struct IncomingReadCountingSnapshot<S> {
        inner: S,
        prefix_pages: Cell<usize>,
        block_gets: Cell<usize>,
        name_state_gets: Cell<usize>,
        utxo_gets: Cell<usize>,
        tx_index_gets: Cell<usize>,
    }

    impl<S> IncomingReadCountingSnapshot<S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                prefix_pages: Cell::new(0),
                block_gets: Cell::new(0),
                name_state_gets: Cell::new(0),
                utxo_gets: Cell::new(0),
                tx_index_gets: Cell::new(0),
            }
        }
    }

    impl<S: ReadSnapshot> ReadSnapshot for IncomingReadCountingSnapshot<S> {
        fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
            if family == ColumnFamily::Blocks {
                self.block_gets.set(self.block_gets.get().saturating_add(1));
            }
            if family == ColumnFamily::NameState {
                self.name_state_gets
                    .set(self.name_state_gets.get().saturating_add(1));
            }
            if family == ColumnFamily::Utxo {
                self.utxo_gets.set(self.utxo_gets.get().saturating_add(1));
            }
            if family == ColumnFamily::TxIndex {
                self.tx_index_gets
                    .set(self.tx_index_gets.get().saturating_add(1));
            }
            self.inner.get(family, key)
        }

        fn scan_prefix(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
        ) -> Result<Vec<ScanEntry>, StoreError> {
            self.prefix_pages
                .set(self.prefix_pages.get().saturating_add(1));
            self.inner.scan_prefix(family, prefix)
        }

        fn scan_prefix_page(
            &self,
            family: ColumnFamily,
            prefix: &[u8],
            start_after: Option<&[u8]>,
            budget: PrefixScanBudget,
        ) -> Result<PrefixScanPage, StoreError> {
            self.prefix_pages
                .set(self.prefix_pages.get().saturating_add(1));
            self.inner
                .scan_prefix_page(family, prefix, start_after, budget)
        }
    }

    fn complete_wallet_profile() -> WalletIndexProfile {
        WalletIndexProfile {
            wallet: true,
            ..WalletIndexProfile::default()
        }
    }

    fn incoming_transfer_authoritative_status(body_present: bool) -> BlockStatus {
        BlockStatus {
            header_context_valid: true,
            checkpoint_valid: true,
            deployment_state_valid: true,
            body_present,
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
            undo_present: false,
            active_chain: true,
            failed: false,
        }
    }

    fn incoming_transfer_test_output() -> Output {
        Output {
            value: 50,
            address: Address::new(0, vec![0x21; 20]).expect("fixture owner address"),
            covenant: Covenant {
                kind: CovenantKind::Transfer,
                items: vec![
                    vec![0x31; 32],
                    2_u32.to_le_bytes().to_vec(),
                    vec![0],
                    vec![0x41; 20],
                ],
            },
        }
    }

    fn incoming_transfer_chain_fixture(
        body_present: bool,
        write_body: bool,
    ) -> (MemoryStore, IncomingTransferEntry, WalletChainTip) {
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![incoming_transfer_test_output()],
            locktime: 0,
        };
        let mut block = Block {
            header: Header::default(),
            transactions: vec![transaction.clone()],
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        let hash = block.hash();
        let status = incoming_transfer_authoritative_status(body_present);
        let block_index = BlockIndexRecord {
            hash,
            height: 0,
            prev_hash: block.header.prev_block,
            chainwork: Uint256::ONE,
            status: status.clone(),
            tx_count: 1,
            validated_at: None,
        };
        let header = HeaderRecord {
            hash,
            height: 0,
            chainwork: Uint256::ONE,
            header: block.header.clone(),
            status,
        };
        let coin = Coin {
            outpoint: Outpoint {
                txid: transaction.txid(),
                index: 0,
            },
            value: transaction.outputs[0].value,
            height: 0,
            coinbase: true,
            address: transaction.outputs[0].address.clone(),
            covenant: transaction.outputs[0].covenant.clone(),
        };
        let entry = IncomingTransferEntry {
            recipient_version: 0,
            recipient_hash: vec![0x41; 20],
            name_hash: [0x31; 32],
            start_height: 2,
            coin: coin.clone(),
            block_hash: hash,
            height: 0,
            transaction_position: 0,
        };

        let store = MemoryStore::new();
        let mut batch = store.batch();
        write_record_to_batch(&mut batch, &header).expect("write header fixture");
        write_block_index_to_batch(&mut batch, &block_index).expect("write block-index fixture");
        write_canonical_height_to_batch(&mut batch, 0, hash).expect("write canonical fixture");
        write_tx_index_for_block_to_batch(&mut batch, &block, 0)
            .expect("write transaction-index fixture");
        write_coin_to_batch(&mut batch, &coin).expect("write UTXO fixture");
        if write_body {
            write_raw_block_to_batch(
                &mut batch,
                &RawBlockRecord::from_block(&block, RawBlockSource::Fixture),
            )
            .expect("write raw-block fixture");
        }
        store.commit(batch).expect("commit incoming fixture");

        (
            store,
            entry,
            WalletChainTip {
                hash,
                height: 0,
                median_time_past: block.header.time,
                tree_root: TreeRoot::ZERO,
            },
        )
    }

    #[derive(Clone, Copy)]
    enum ActiveNameOwnerFixtureKind {
        Transfer,
        Finalize,
    }

    struct ActiveNameOwnerFixture {
        store: MemoryStore,
        chain_epoch: u64,
        name_hash: NameHash,
        state: NameState,
        state_bytes: Vec<u8>,
        coin: Coin,
        inclusion: TransactionInclusion,
        owner_block_hash: BlockHash,
    }

    fn active_name_owner_fixture(
        kind: ActiveNameOwnerFixtureKind,
        owner_body_present: bool,
        write_owner_body: bool,
    ) -> ActiveNameOwnerFixture {
        const CHAIN_EPOCH: u64 = 7;
        const OWNER_HEIGHT: Height = 1;
        let name = b"alpha".to_vec();
        let name_hash = hash_name("alpha").expect("fixture name hash");
        let start_height = 0_u32;
        let covenant = match kind {
            ActiveNameOwnerFixtureKind::Transfer => Covenant {
                kind: CovenantKind::Transfer,
                items: vec![
                    name_hash.as_bytes().to_vec(),
                    start_height.to_le_bytes().to_vec(),
                    vec![0],
                    vec![0x41; 20],
                ],
            },
            ActiveNameOwnerFixtureKind::Finalize => Covenant {
                kind: CovenantKind::Finalize,
                items: vec![
                    name_hash.as_bytes().to_vec(),
                    start_height.to_le_bytes().to_vec(),
                    name.clone(),
                    vec![0],
                    0_u32.to_le_bytes().to_vec(),
                    0_u32.to_le_bytes().to_vec(),
                    vec![0x42; 32],
                ],
            },
        };
        let owner_output = Output {
            value: 50,
            address: Address::new(0, vec![0x21; 20]).expect("fixture owner address"),
            covenant,
        };
        let owner_transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([0x17; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![owner_output.clone()],
            locktime: 0,
        };

        let genesis_header_value = Network::Regtest.params().genesis_header();
        let genesis_hash = Network::Regtest.params().genesis_hash;
        let owner_time = genesis_header_value.time.saturating_add(1);

        let mut owner_block = Block {
            header: Header {
                prev_block: genesis_hash,
                time: owner_time,
                ..Header::default()
            },
            transactions: vec![owner_transaction.clone()],
        };
        owner_block.header.merkle_root = block_merkle_root(&owner_block);
        owner_block.header.witness_root = block_witness_root(&owner_block);
        let owner_block_hash = owner_block.hash();
        let owner_outpoint = Outpoint {
            txid: owner_transaction.txid(),
            index: 0,
        };
        let coin = Coin {
            outpoint: owner_outpoint.clone(),
            value: owner_output.value,
            height: OWNER_HEIGHT,
            coinbase: false,
            address: owner_output.address,
            covenant: owner_output.covenant,
        };
        let mut state = NameState::null(name_hash);
        state.name = name;
        state.height = start_height;
        state.owner = owner_outpoint;
        state.value = coin.value;
        state.highest = coin.value;
        state.registered = true;
        match kind {
            ActiveNameOwnerFixtureKind::Transfer => {
                state.transfer = OWNER_HEIGHT;
            }
            ActiveNameOwnerFixtureKind::Finalize => {
                state.renewal = OWNER_HEIGHT;
                state.renewals = 1;
            }
        }
        let state_bytes = encode_name_state(&state).expect("encode fixture NameState");

        let genesis_status = incoming_transfer_authoritative_status(false);
        let owner_status = incoming_transfer_authoritative_status(owner_body_present);
        let genesis_index = BlockIndexRecord {
            hash: genesis_hash,
            height: 0,
            prev_hash: BlockHash::ZERO,
            chainwork: Uint256::ONE,
            status: genesis_status.clone(),
            tx_count: 1,
            validated_at: None,
        };
        let owner_index = BlockIndexRecord {
            hash: owner_block_hash,
            height: OWNER_HEIGHT,
            prev_hash: genesis_hash,
            chainwork: Uint256::ONE,
            status: owner_status.clone(),
            tx_count: 1,
            validated_at: None,
        };
        let genesis_header = HeaderRecord {
            hash: genesis_hash,
            height: 0,
            chainwork: genesis_index.chainwork,
            header: genesis_header_value,
            status: genesis_status,
        };
        let owner_header = HeaderRecord {
            hash: owner_block_hash,
            height: OWNER_HEIGHT,
            chainwork: owner_index.chainwork,
            header: owner_block.header.clone(),
            status: owner_status,
        };

        let store = MemoryStore::new();
        let mut batch = store.batch();
        write_record_to_batch(&mut batch, &genesis_header).expect("write genesis header");
        write_record_to_batch(&mut batch, &owner_header).expect("write owner header");
        write_block_index_to_batch(&mut batch, &genesis_index).expect("write genesis index");
        write_block_index_to_batch(&mut batch, &owner_index).expect("write owner index");
        write_canonical_height_to_batch(&mut batch, 0, genesis_hash)
            .expect("write canonical genesis");
        write_canonical_height_to_batch(&mut batch, OWNER_HEIGHT, owner_block_hash)
            .expect("write canonical owner block");
        write_tx_index_for_block_to_batch(&mut batch, &owner_block, OWNER_HEIGHT)
            .expect("write owner transaction index");
        write_coin_to_batch(&mut batch, &coin).expect("write active owner UTXO");
        write_name_state_to_batch(&mut batch, &state).expect("write current NameState");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                owner_block_hash.as_bytes(),
            )
            .expect("write best block");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::ChainEpoch.as_bytes(),
                &encode_u64(CHAIN_EPOCH),
            )
            .expect("write chain epoch");
        batch
            .put(
                ColumnFamily::Meta,
                MetaKey::NameTreeRoot.as_bytes(),
                TreeRoot::ZERO.as_bytes(),
            )
            .expect("write name tree root");
        if write_owner_body {
            write_raw_block_to_batch(
                &mut batch,
                &RawBlockRecord::from_block(&owner_block, RawBlockSource::Fixture),
            )
            .expect("write owner body");
        }
        store.commit(batch).expect("commit active owner fixture");

        ActiveNameOwnerFixture {
            store,
            chain_epoch: CHAIN_EPOCH,
            name_hash,
            state,
            state_bytes,
            coin,
            inclusion: TransactionInclusion {
                block_hash: owner_block_hash,
                height: OWNER_HEIGHT,
                transaction_position: None,
                confirmations: 1,
            },
            owner_block_hash,
        }
    }

    fn incoming_transfer_recipient_script(recipient: u8) -> ScriptId {
        let mut descriptor = Writer::with_capacity(22);
        descriptor.write_u8(0);
        descriptor.write_u8(20);
        descriptor.write_bytes(&[recipient; 20]);
        ScriptId::from_descriptor(&descriptor.finish())
    }

    fn incoming_transfer_retained_chain_fixture(
        block_count: u32,
        chain_epoch: u64,
    ) -> (MemoryStore, Vec<ScriptId>, Vec<Txid>) {
        let store = MemoryStore::new();
        let profile = complete_wallet_profile();
        let recipient = 0x61;
        let mut previous = BlockHash::ZERO;
        let mut tip = None;
        let mut txids = Vec::new();

        for height in 0..block_count {
            let output = Output {
                value: 100 + u64::from(height),
                address: Address::new(0, vec![0x51; 20]).expect("fixture owner address"),
                covenant: Covenant {
                    kind: CovenantKind::Transfer,
                    items: vec![
                        vec![u8::try_from(height).expect("fixture height"); 32],
                        2_u32.to_le_bytes().to_vec(),
                        vec![0],
                        vec![recipient; 20],
                    ],
                },
            };
            let transaction = Transaction {
                version: 0,
                inputs: vec![Input {
                    previous_output: Outpoint::null(),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                }],
                outputs: vec![output.clone()],
                locktime: 0,
            };
            let mut block = Block {
                header: Header {
                    nonce: height.saturating_add(1),
                    time: u64::from(height).saturating_add(1),
                    prev_block: previous,
                    ..Header::default()
                },
                transactions: vec![transaction.clone()],
            };
            block.header.merkle_root = block_merkle_root(&block);
            block.header.witness_root = block_witness_root(&block);
            let hash = block.hash();
            let status = incoming_transfer_authoritative_status(true);
            let block_index = BlockIndexRecord {
                hash,
                height,
                prev_hash: previous,
                chainwork: Uint256::from_u64(u64::from(height).saturating_add(1)),
                status: status.clone(),
                tx_count: 1,
                validated_at: None,
            };
            let header = HeaderRecord {
                hash,
                height,
                chainwork: block_index.chainwork,
                header: block.header.clone(),
                status,
            };
            let coin = Coin {
                outpoint: Outpoint {
                    txid: transaction.txid(),
                    index: 0,
                },
                value: output.value,
                height,
                coinbase: true,
                address: output.address,
                covenant: output.covenant,
            };

            let snapshot = store.snapshot().expect("pre-connect snapshot");
            let mut batch = store.batch();
            hns_wallet_index::stage_connect(&snapshot, &mut batch, &block, height, profile)
                .expect("stage incoming index fixture");
            write_record_to_batch(&mut batch, &header).expect("write header fixture");
            write_block_index_to_batch(&mut batch, &block_index)
                .expect("write block-index fixture");
            write_canonical_height_to_batch(&mut batch, height, hash)
                .expect("write canonical fixture");
            write_tx_index_for_block_to_batch(&mut batch, &block, height)
                .expect("write transaction-index fixture");
            write_coin_to_batch(&mut batch, &coin).expect("write UTXO fixture");
            write_raw_block_to_batch(
                &mut batch,
                &RawBlockRecord::from_block(&block, RawBlockSource::Fixture),
            )
            .expect("write raw-block fixture");
            drop(snapshot);
            store.commit(batch).expect("commit retained fixture block");

            txids.push(transaction.txid());
            previous = hash;
            tip = Some(hash);
        }

        let tip = tip.expect("retained fixture must contain a block");
        let mut meta = store.batch();
        meta.put(
            ColumnFamily::Meta,
            MetaKey::BestBlockHash.as_bytes(),
            tip.as_bytes(),
        )
        .expect("write best-block binding");
        meta.put(
            ColumnFamily::Meta,
            MetaKey::ChainEpoch.as_bytes(),
            &encode_u64(chain_epoch),
        )
        .expect("write chain epoch");
        meta.put(
            ColumnFamily::Meta,
            MetaKey::NameTreeRoot.as_bytes(),
            TreeRoot::ZERO.as_bytes(),
        )
        .expect("write tree root");
        store
            .commit(meta)
            .expect("commit retained fixture metadata");

        (
            store,
            vec![incoming_transfer_recipient_script(recipient)],
            txids,
        )
    }

    #[test]
    fn incoming_transfer_stale_epoch_precedes_prefix_scans_and_block_reads() {
        let store = MemoryStore::new();
        let snapshot = IncomingReadCountingSnapshot::new(store.snapshot().expect("snapshot"));
        let scripts = vec![ScriptId::from_descriptor(b"incoming-stale")];
        let result = incoming_transfers_page_from_snapshot(
            &snapshot,
            complete_wallet_profile(),
            &scripts,
            1,
            incoming_transfer_script_set_id(&scripts).expect("script-set ID"),
            None,
            16,
        );
        assert!(matches!(
            result,
            Err(WalletBackendError::StaleChainEpoch {
                expected: 1,
                actual: 0
            })
        ));
        assert_eq!(snapshot.prefix_pages.get(), 0);
        assert_eq!(snapshot.block_gets.get(), 0);
    }

    #[test]
    fn incoming_transfer_cursor_binds_version_epoch_tip_script_set_and_position() {
        let store = MemoryStore::new();
        let snapshot = store.snapshot().expect("snapshot");
        let mut scripts = vec![
            ScriptId::from_descriptor(b"incoming-cursor-a"),
            ScriptId::from_descriptor(b"incoming-cursor-b"),
        ];
        scripts.sort_unstable();
        let script_set_id = incoming_transfer_script_set_id(&scripts).expect("script-set ID");
        let valid = IncomingTransfersCursor {
            binding_version: INCOMING_TRANSFER_CURSOR_VERSION,
            chain_epoch: 0,
            tip: None,
            script_set_id,
            script_index: 0,
            inner: None,
        };

        let mut wrong_version = valid.clone();
        wrong_version.binding_version = INCOMING_TRANSFER_CURSOR_VERSION.saturating_add(1);
        assert!(matches!(
            incoming_transfers_page_from_snapshot(
                &snapshot,
                complete_wallet_profile(),
                &scripts,
                0,
                script_set_id,
                Some(wrong_version),
                16,
            ),
            Err(WalletBackendError::InvalidIncomingTransferCursor)
        ));

        let mut wrong_epoch = valid.clone();
        wrong_epoch.chain_epoch = 1;
        assert!(matches!(
            incoming_transfers_page_from_snapshot(
                &snapshot,
                complete_wallet_profile(),
                &scripts,
                0,
                script_set_id,
                Some(wrong_epoch),
                16,
            ),
            Err(WalletBackendError::StaleChainEpoch {
                expected: 1,
                actual: 0
            })
        ));

        let mut wrong_tip = valid.clone();
        wrong_tip.tip = Some(WalletChainTip {
            hash: BlockHash::ZERO,
            height: 0,
            median_time_past: 0,
            tree_root: TreeRoot::ZERO,
        });
        assert!(matches!(
            incoming_transfers_page_from_snapshot(
                &snapshot,
                complete_wallet_profile(),
                &scripts,
                0,
                script_set_id,
                Some(wrong_tip),
                16,
            ),
            Err(WalletBackendError::InvalidIncomingTransferCursor)
        ));

        let mut wrong_script_set = valid.clone();
        wrong_script_set.script_set_id[0] ^= 1;
        assert!(matches!(
            incoming_transfers_page_from_snapshot(
                &snapshot,
                complete_wallet_profile(),
                &scripts,
                0,
                script_set_id,
                Some(wrong_script_set),
                16,
            ),
            Err(WalletBackendError::InvalidIncomingTransferCursor)
        ));

        let mut wrong_position = valid;
        wrong_position.script_index = scripts.len();
        assert!(matches!(
            incoming_transfers_page_from_snapshot(
                &snapshot,
                complete_wallet_profile(),
                &scripts,
                0,
                script_set_id,
                Some(wrong_position),
                16,
            ),
            Err(WalletBackendError::InvalidIncomingTransferCursor)
        ));
    }

    #[test]
    fn incoming_transfer_empty_script_walk_is_bounded_and_resumable() {
        let store = MemoryStore::new();
        let snapshot = store.snapshot().expect("snapshot");
        let mut scripts = (0..=MAX_WALLET_INCOMING_TRANSFER_SCRIPT_EXAMINATIONS)
            .map(|index| ScriptId::from_descriptor(&index.to_be_bytes()))
            .collect::<Vec<_>>();
        scripts.sort_unstable();
        let script_set_id = incoming_transfer_script_set_id(&scripts).expect("script-set ID");
        let first = incoming_transfers_page_from_snapshot(
            &snapshot,
            complete_wallet_profile(),
            &scripts,
            0,
            script_set_id,
            None,
            16,
        )
        .expect("bounded empty page");
        assert!(first.entries.is_empty());
        assert_eq!(
            first.script_examinations,
            MAX_WALLET_INCOMING_TRANSFER_SCRIPT_EXAMINATIONS
        );
        let continuation = first.continuation.expect("bounded continuation");
        assert_eq!(continuation.script_index, 256);
        assert!(continuation.inner.is_none());

        let complete = incoming_transfers_page_from_snapshot(
            &snapshot,
            complete_wallet_profile(),
            &scripts,
            0,
            script_set_id,
            Some(continuation),
            16,
        )
        .expect("empty traversal completion");
        assert!(complete.entries.is_empty());
        assert_eq!(complete.script_examinations, 1);
        assert!(complete.continuation.is_none());
    }

    #[test]
    fn incoming_transfer_corroboration_labels_retained_and_pruned_sources() {
        for (body_present, write_body, expected_binding, expected_decodes) in [
            (
                true,
                true,
                IncomingTransferSourceBinding::RetainedBodyVerified,
                1,
            ),
            (
                false,
                false,
                IncomingTransferSourceBinding::PrunedTrustedNodeProjection,
                0,
            ),
        ] {
            let (store, entry, tip) = incoming_transfer_chain_fixture(body_present, write_body);
            let snapshot = store.snapshot().expect("snapshot");
            let mut cache = None;
            let mut retained_decodes = 0;
            let (inclusion, binding) = corroborate_incoming_transfer(
                &snapshot,
                &entry,
                1,
                Some(&tip),
                &mut cache,
                &mut retained_decodes,
            )
            .expect("corroboration")
            .expect("body budget");
            assert_eq!(binding, expected_binding);
            assert_eq!(retained_decodes, expected_decodes);
            assert_eq!(inclusion.transaction_position, Some(0));
            assert_eq!(inclusion.confirmations, 1);
        }
    }

    #[test]
    fn incoming_transfer_body_presence_must_match_status_both_directions() {
        for (body_present, write_body) in [(true, false), (false, true)] {
            let (store, entry, tip) = incoming_transfer_chain_fixture(body_present, write_body);
            let snapshot = store.snapshot().expect("snapshot");
            let mut cache = None;
            let mut retained_decodes = 0;
            assert!(matches!(
                corroborate_incoming_transfer(
                    &snapshot,
                    &entry,
                    1,
                    Some(&tip),
                    &mut cache,
                    &mut retained_decodes,
                ),
                Err(WalletBackendError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn incoming_transfer_requires_pruning_stable_consensus_status() {
        let (store, entry, tip) = incoming_transfer_chain_fixture(true, true);
        let snapshot = store.snapshot().expect("snapshot");
        let mut block_index = BlockIndexRecord::decode(
            &snapshot
                .get(ColumnFamily::BlockIndex, entry.block_hash.as_bytes())
                .expect("block-index read")
                .expect("block index"),
        )
        .expect("decode block index");
        let mut header = HeaderRecord::decode(
            &snapshot
                .get(ColumnFamily::Headers, entry.block_hash.as_bytes())
                .expect("header read")
                .expect("header"),
        )
        .expect("decode header");
        block_index.status.scripts_valid = false;
        header.status.scripts_valid = false;
        drop(snapshot);
        let mut batch = store.batch();
        write_block_index_to_batch(&mut batch, &block_index).expect("rewrite block index");
        write_record_to_batch(&mut batch, &header).expect("rewrite header");
        store.commit(batch).expect("commit status corruption");

        let snapshot = store.snapshot().expect("corrupt snapshot");
        let mut cache = None;
        let mut retained_decodes = 0;
        assert!(matches!(
            corroborate_incoming_transfer(
                &snapshot,
                &entry,
                1,
                Some(&tip),
                &mut cache,
                &mut retained_decodes,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
        assert_eq!(retained_decodes, 0);
    }

    #[test]
    fn incoming_transfer_retained_body_binds_tx_index_offset_and_length() {
        let (store, entry, tip) = incoming_transfer_chain_fixture(true, true);
        let snapshot = store.snapshot().expect("snapshot");
        let mut transaction_index = TxIndexEntry::decode(
            &snapshot
                .get(ColumnFamily::TxIndex, entry.coin.outpoint.txid.as_bytes())
                .expect("transaction-index read")
                .expect("transaction index"),
        )
        .expect("decode transaction index");
        transaction_index.tx_offset = transaction_index.tx_offset.saturating_add(1);
        drop(snapshot);
        let mut batch = store.batch();
        write_tx_index_to_batch(&mut batch, &transaction_index).expect("rewrite transaction index");
        store.commit(batch).expect("commit offset corruption");

        let snapshot = store.snapshot().expect("corrupt snapshot");
        let mut cache = None;
        let mut retained_decodes = 0;
        assert!(matches!(
            corroborate_incoming_transfer(
                &snapshot,
                &entry,
                1,
                Some(&tip),
                &mut cache,
                &mut retained_decodes,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
        assert_eq!(retained_decodes, 1);
    }

    #[test]
    fn incoming_transfer_fifth_retained_block_resumes_without_loss_or_duplicate() {
        let chain_epoch = 9;
        let (store, scripts, expected_txids) = incoming_transfer_retained_chain_fixture(
            u32::try_from(MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES)
                .expect("fixture bound")
                .saturating_add(1),
            chain_epoch,
        );
        let script_set_id = incoming_transfer_script_set_id(&scripts).expect("script-set ID");

        let first_snapshot =
            IncomingReadCountingSnapshot::new(store.snapshot().expect("first snapshot"));
        let first = incoming_transfers_page_from_snapshot(
            &first_snapshot,
            complete_wallet_profile(),
            &scripts,
            chain_epoch,
            script_set_id,
            None,
            16,
        )
        .expect("first retained page");
        assert_eq!(
            first.entries.len(),
            MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES
        );
        assert_eq!(
            first_snapshot.block_gets.get(),
            MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES
        );
        assert!(first.entries.iter().all(|entry| {
            entry.source_binding == IncomingTransferSourceBinding::RetainedBodyVerified
        }));
        let continuation = first.continuation.expect("body-budget continuation");

        let second_snapshot =
            IncomingReadCountingSnapshot::new(store.snapshot().expect("second snapshot"));
        let second = incoming_transfers_page_from_snapshot(
            &second_snapshot,
            complete_wallet_profile(),
            &scripts,
            chain_epoch,
            script_set_id,
            Some(continuation),
            16,
        )
        .expect("resumed retained page");
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second_snapshot.block_gets.get(), 1);
        assert!(second.continuation.is_none());

        let actual_txids = first
            .entries
            .iter()
            .chain(&second.entries)
            .map(|entry| entry.entry.coin.outpoint.txid)
            .collect::<Vec<_>>();
        assert_eq!(actual_txids, expected_txids);
    }

    #[test]
    fn active_name_owner_coin_is_pruning_safe_and_never_reads_blocks() {
        for kind in [
            ActiveNameOwnerFixtureKind::Transfer,
            ActiveNameOwnerFixtureKind::Finalize,
        ] {
            for (body_present, write_body) in [(true, true), (false, false)] {
                let fixture = active_name_owner_fixture(kind, body_present, write_body);
                let snapshot = IncomingReadCountingSnapshot::new(
                    fixture.store.snapshot().expect("active owner snapshot"),
                );
                let evidence = active_name_owner_coin_from_snapshot(
                    &snapshot,
                    fixture.name_hash,
                    fixture.chain_epoch,
                )
                .expect("pruning-safe active owner evidence");
                assert_eq!(
                    evidence.projection_version,
                    ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION
                );
                assert_eq!(evidence.chain_epoch, fixture.chain_epoch);
                assert_eq!(evidence.tip.hash, fixture.owner_block_hash);
                assert_eq!(evidence.tip.height, fixture.inclusion.height);
                assert_eq!(evidence.current_state_bytes, fixture.state_bytes);
                assert_eq!(evidence.current_state, fixture.state);
                assert_eq!(evidence.owner_coin, fixture.coin);
                assert_eq!(evidence.inclusion, fixture.inclusion);
                assert_eq!(evidence.inclusion.transaction_position, None);
                assert_eq!(
                    evidence.source_binding,
                    ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection
                );
                assert_eq!(snapshot.block_gets.get(), 0);
                assert_eq!(snapshot.name_state_gets.get(), 1);
                assert_eq!(snapshot.utxo_gets.get(), 1);
                assert_eq!(snapshot.tx_index_gets.get(), 1);
            }
        }
    }

    #[test]
    fn name_action_context_v2_is_coin_backed_and_never_reads_owner_blocks() {
        let mempool = MemoryMempool::new().unwrap().snapshot();
        for (kind, action) in [
            (ActiveNameOwnerFixtureKind::Transfer, NameAction::Finalize),
            (ActiveNameOwnerFixtureKind::Finalize, NameAction::Transfer),
        ] {
            for (body_present, write_body) in [(true, true), (false, false)] {
                let fixture = active_name_owner_fixture(kind, body_present, write_body);
                let snapshot = IncomingReadCountingSnapshot::new(
                    fixture.store.snapshot().expect("name action snapshot"),
                );
                let context = name_action_context_v2_from_snapshot(
                    Network::Regtest,
                    &snapshot,
                    &mempool,
                    fixture.chain_epoch,
                    action,
                    fixture.name_hash,
                    fixture.chain_epoch,
                    *mempool.instance_nonce(),
                    mempool.generation(),
                )
                .expect("pruning-safe name action context");

                assert_eq!(context.context_version, NAME_ACTION_CONTEXT_V2_VERSION);
                assert_eq!(context.action, action);
                assert_eq!(context.network, Network::Regtest);
                assert_eq!(context.network_id, Network::Regtest.canonical_id());
                assert_eq!(context.genesis_hash, Network::Regtest.params().genesis_hash);
                assert_eq!(context.consensus_profile, HSD_CONSENSUS_PROFILE);
                assert_eq!(context.chain_epoch, fixture.chain_epoch);
                assert_eq!(context.tip.hash, fixture.owner_block_hash);
                assert_eq!(context.candidate_inclusion_height, context.tip.height + 1);
                assert_eq!(context.mempool_instance_nonce, *mempool.instance_nonce());
                assert_eq!(context.mempool_generation, mempool.generation());
                assert_eq!(context.name_hash, fixture.name_hash);
                assert_eq!(context.current_state_bytes, fixture.state_bytes);
                assert_eq!(context.current_state, fixture.state);
                assert_eq!(
                    context.active_owner.projection_version,
                    ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION
                );
                assert_eq!(context.active_owner.owner_coin, fixture.coin);
                assert_eq!(context.active_owner.inclusion, fixture.inclusion);
                assert_eq!(context.active_owner.inclusion.transaction_position, None);
                assert_eq!(
                    context.active_owner.source_binding,
                    ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection
                );
                assert_eq!(context.owner_spender_txid, None);
                assert_eq!(
                    context.transfer.lockup_blocks,
                    Network::Regtest.params().names.transfer_lockup
                );
                assert_eq!(
                    context.renewal.maturity_blocks,
                    Network::Regtest.params().names.renewal_maturity
                );
                assert_eq!(
                    context.renewal.period_blocks,
                    Network::Regtest.params().names.renewal_period
                );
                assert_eq!(context.eligible(), context.ineligibility_reasons.is_empty());
                assert!(
                    context.ineligibility_reasons.len() <= MAX_NAME_ACTION_INELIGIBILITY_REASONS
                );
                assert_eq!(snapshot.block_gets.get(), 0);
                assert_eq!(snapshot.name_state_gets.get(), 1);
                assert_eq!(snapshot.utxo_gets.get(), 1);
                assert_eq!(snapshot.tx_index_gets.get(), 1);
            }
        }
    }

    #[test]
    fn name_action_context_v2_rejects_every_stale_binding_before_authority_reads() {
        let mempool = MemoryMempool::new().unwrap().snapshot();

        let assert_no_authority_reads = |snapshot: &IncomingReadCountingSnapshot<_>| {
            assert_eq!(snapshot.name_state_gets.get(), 0);
            assert_eq!(snapshot.utxo_gets.get(), 0);
            assert_eq!(snapshot.tx_index_gets.get(), 0);
            assert_eq!(snapshot.block_gets.get(), 0);
        };

        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let snapshot = IncomingReadCountingSnapshot::new(
            fixture.store.snapshot().expect("published epoch snapshot"),
        );
        assert!(matches!(
            name_action_context_v2_from_snapshot(
                Network::Regtest,
                &snapshot,
                &mempool,
                fixture.chain_epoch.saturating_add(1),
                NameAction::Finalize,
                fixture.name_hash,
                fixture.chain_epoch,
                *mempool.instance_nonce(),
                mempool.generation(),
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
        assert_no_authority_reads(&snapshot);

        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let snapshot = IncomingReadCountingSnapshot::new(
            fixture.store.snapshot().expect("stale chain snapshot"),
        );
        assert!(matches!(
            name_action_context_v2_from_snapshot(
                Network::Regtest,
                &snapshot,
                &mempool,
                fixture.chain_epoch,
                NameAction::Finalize,
                fixture.name_hash,
                fixture.chain_epoch.saturating_add(1),
                *mempool.instance_nonce(),
                mempool.generation(),
            ),
            Err(WalletBackendError::StaleChainEpoch { .. })
        ));
        assert_no_authority_reads(&snapshot);

        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let snapshot = IncomingReadCountingSnapshot::new(
            fixture.store.snapshot().expect("stale instance snapshot"),
        );
        assert!(matches!(
            name_action_context_v2_from_snapshot(
                Network::Regtest,
                &snapshot,
                &mempool,
                fixture.chain_epoch,
                NameAction::Finalize,
                fixture.name_hash,
                fixture.chain_epoch,
                [0; 32],
                mempool.generation(),
            ),
            Err(WalletBackendError::StaleMempoolInstance)
        ));
        assert_no_authority_reads(&snapshot);

        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let snapshot = IncomingReadCountingSnapshot::new(
            fixture.store.snapshot().expect("stale generation snapshot"),
        );
        assert!(matches!(
            name_action_context_v2_from_snapshot(
                Network::Regtest,
                &snapshot,
                &mempool,
                fixture.chain_epoch,
                NameAction::Finalize,
                fixture.name_hash,
                fixture.chain_epoch,
                *mempool.instance_nonce(),
                mempool.generation().saturating_add(1),
            ),
            Err(WalletBackendError::StaleMempoolGeneration { .. })
        ));
        assert_no_authority_reads(&snapshot);
    }

    #[test]
    fn name_action_context_v2_rejects_wrong_network_before_authority_reads() {
        let mempool = MemoryMempool::new().unwrap().snapshot();
        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let snapshot = IncomingReadCountingSnapshot::new(
            fixture.store.snapshot().expect("wrong-network snapshot"),
        );
        assert!(matches!(
            name_action_context_v2_from_snapshot(
                Network::Mainnet,
                &snapshot,
                &mempool,
                fixture.chain_epoch,
                NameAction::Finalize,
                fixture.name_hash,
                fixture.chain_epoch,
                *mempool.instance_nonce(),
                mempool.generation(),
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
        assert_eq!(snapshot.name_state_gets.get(), 0);
        assert_eq!(snapshot.utxo_gets.get(), 0);
        assert_eq!(snapshot.tx_index_gets.get(), 0);
        assert_eq!(snapshot.block_gets.get(), 0);
    }

    #[test]
    fn active_name_owner_coin_checks_epoch_before_authority_reads() {
        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, true, true);
        let snapshot = IncomingReadCountingSnapshot::new(
            fixture.store.snapshot().expect("active owner snapshot"),
        );
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &snapshot,
                fixture.name_hash,
                fixture.chain_epoch.saturating_add(1),
            ),
            Err(WalletBackendError::StaleChainEpoch {
                expected,
                actual,
            }) if expected == fixture.chain_epoch + 1 && actual == fixture.chain_epoch
        ));
        assert_eq!(snapshot.name_state_gets.get(), 0);
        assert_eq!(snapshot.utxo_gets.get(), 0);
        assert_eq!(snapshot.tx_index_gets.get(), 0);
        assert_eq!(snapshot.block_gets.get(), 0);
    }

    #[test]
    fn active_name_owner_coin_rejects_missing_or_mismatched_active_utxo_and_name_key() {
        let missing = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, false, false);
        let mut batch = missing.store.batch();
        batch
            .delete(
                ColumnFamily::Utxo,
                &encode_outpoint_key(&missing.coin.outpoint),
            )
            .expect("delete owner UTXO");
        missing.store.commit(batch).expect("commit missing UTXO");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &missing.store.snapshot().expect("missing UTXO snapshot"),
                missing.name_hash,
                missing.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));

        let mismatched =
            active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, false, false);
        let mut wrong_coin = mismatched.coin.clone();
        wrong_coin.value = wrong_coin.value.saturating_add(1);
        let mut batch = mismatched.store.batch();
        write_coin_to_batch(&mut batch, &wrong_coin).expect("rewrite mismatched owner UTXO");
        mismatched
            .store
            .commit(batch)
            .expect("commit mismatched owner UTXO");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &mismatched
                    .store
                    .snapshot()
                    .expect("mismatched UTXO snapshot"),
                mismatched.name_hash,
                mismatched.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));

        let wrong_outpoint =
            active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, false, false);
        let mut wrong_coin = wrong_outpoint.coin.clone();
        wrong_coin.outpoint.index = wrong_coin.outpoint.index.saturating_add(1);
        let mut batch = wrong_outpoint.store.batch();
        batch
            .put(
                ColumnFamily::Utxo,
                &encode_outpoint_key(&wrong_outpoint.coin.outpoint),
                &encode_coin(&wrong_coin),
            )
            .expect("rewrite key-mismatched owner UTXO");
        wrong_outpoint
            .store
            .commit(batch)
            .expect("commit key-mismatched owner UTXO");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &wrong_outpoint
                    .store
                    .snapshot()
                    .expect("key-mismatched UTXO snapshot"),
                wrong_outpoint.name_hash,
                wrong_outpoint.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));

        let mismatched_name =
            active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, false, false);
        let mut wrong_state = mismatched_name.state.clone();
        wrong_state.name = b"bravo".to_vec();
        let mut batch = mismatched_name.store.batch();
        write_name_state_to_batch(&mut batch, &wrong_state)
            .expect("rewrite name-key-mismatched state");
        mismatched_name
            .store
            .commit(batch)
            .expect("commit name-key mismatch");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &mismatched_name
                    .store
                    .snapshot()
                    .expect("name-key mismatch snapshot"),
                mismatched_name.name_hash,
                mismatched_name.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
    }

    #[test]
    fn active_name_owner_coin_rejects_noncanonical_transaction_index() {
        let missing = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let mut batch = missing.store.batch();
        batch
            .delete(ColumnFamily::TxIndex, missing.coin.outpoint.txid.as_bytes())
            .expect("delete owner transaction index");
        missing
            .store
            .commit(batch)
            .expect("commit missing transaction index");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &missing
                    .store
                    .snapshot()
                    .expect("missing transaction-index snapshot"),
                missing.name_hash,
                missing.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));

        let reorged = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let mut batch = reorged.store.batch();
        write_canonical_height_to_batch(
            &mut batch,
            reorged.coin.height,
            BlockHash::new([0x91; 32]),
        )
        .expect("rewrite canonical owner height");
        reorged
            .store
            .commit(batch)
            .expect("commit canonical mismatch");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &reorged.store.snapshot().expect("reorged snapshot"),
                reorged.name_hash,
                reorged.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));

        let wrong_txid =
            active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        let snapshot = wrong_txid
            .store
            .snapshot()
            .expect("transaction index snapshot");
        let mut transaction_index = TxIndexEntry::decode(
            &snapshot
                .get(
                    ColumnFamily::TxIndex,
                    wrong_txid.coin.outpoint.txid.as_bytes(),
                )
                .expect("transaction index read")
                .expect("transaction index"),
        )
        .expect("decode transaction index");
        drop(snapshot);
        transaction_index.txid = Txid::new([0x92; 32]);
        let mut batch = wrong_txid.store.batch();
        batch
            .put(
                ColumnFamily::TxIndex,
                wrong_txid.coin.outpoint.txid.as_bytes(),
                &transaction_index.encode(),
            )
            .expect("rewrite mismatched transaction index");
        wrong_txid
            .store
            .commit(batch)
            .expect("commit transaction-index mismatch");
        assert!(matches!(
            active_name_owner_coin_from_snapshot(
                &wrong_txid
                    .store
                    .snapshot()
                    .expect("transaction-index mismatch snapshot"),
                wrong_txid.name_hash,
                wrong_txid.chain_epoch,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
    }

    #[test]
    fn active_name_owner_coin_binds_transfer_and_finalize_state() {
        let transfer =
            active_name_owner_fixture(ActiveNameOwnerFixtureKind::Transfer, false, false);
        assert!(validate_active_name_owner_coin(
            &transfer.state,
            &transfer.coin,
            &transfer.inclusion,
        )
        .is_ok());
        let mut wrong_transfer = transfer.state.clone();
        wrong_transfer.transfer = 0;
        assert!(matches!(
            validate_active_name_owner_coin(&wrong_transfer, &transfer.coin, &transfer.inclusion,),
            Err(WalletBackendError::Corrupt(_))
        ));
        let mut unregistered_transfer = transfer.state.clone();
        unregistered_transfer.registered = false;
        assert!(matches!(
            validate_active_name_owner_coin(
                &unregistered_transfer,
                &transfer.coin,
                &transfer.inclusion,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));
        let mut coinbase_transfer = transfer.coin.clone();
        coinbase_transfer.coinbase = true;
        assert!(matches!(
            validate_active_name_owner_coin(
                &transfer.state,
                &coinbase_transfer,
                &transfer.inclusion,
            ),
            Err(WalletBackendError::Corrupt(_))
        ));

        let finalized =
            active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, false, false);
        assert!(validate_active_name_owner_coin(
            &finalized.state,
            &finalized.coin,
            &finalized.inclusion,
        )
        .is_ok());
        let mut invalid = Vec::new();

        let mut state = finalized.state.clone();
        state.transfer = finalized.coin.height;
        invalid.push((state, finalized.coin.clone()));

        let mut state = finalized.state.clone();
        state.renewal = 0;
        invalid.push((state, finalized.coin.clone()));

        let mut state = finalized.state.clone();
        state.registered = false;
        invalid.push((state, finalized.coin.clone()));

        let mut coin = finalized.coin.clone();
        coin.coinbase = true;
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.covenant.items[0] = vec![0x93; 32];
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.covenant.items[1] = 2_u32.to_le_bytes().to_vec();
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.covenant.items[2] = b"bravo".to_vec();
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.covenant.items[3] = vec![1];
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.covenant.items[4] = 1_u32.to_le_bytes().to_vec();
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.covenant.items[5] = 1_u32.to_le_bytes().to_vec();
        invalid.push((finalized.state.clone(), coin));

        let mut coin = finalized.coin.clone();
        coin.value = coin.value.saturating_add(1);
        invalid.push((finalized.state.clone(), coin));

        for (state, coin) in invalid {
            assert!(matches!(
                validate_active_name_owner_coin(&state, &coin, &finalized.inclusion),
                Err(WalletBackendError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn active_name_owner_coin_enforces_regular_covenant_shapes_and_coinbase_origin() {
        let fixture = active_name_owner_fixture(ActiveNameOwnerFixtureKind::Finalize, false, false);
        let name_hash = fixture.name_hash.as_bytes().to_vec();
        let start = fixture.state.height.to_le_bytes().to_vec();
        let mut valid = Vec::new();

        let mut state = fixture.state.clone();
        state.registered = false;
        state.value = 0;
        state.highest = 0;
        state.claimed = 5;
        state.renewals = 0;
        state.weak = true;
        let mut coin = fixture.coin.clone();
        coin.coinbase = true;
        coin.covenant = Covenant {
            kind: CovenantKind::Claim,
            items: vec![
                name_hash.clone(),
                start.clone(),
                state.name.clone(),
                vec![1],
                vec![0x41; 32],
                state.claimed.to_le_bytes().to_vec(),
            ],
        };
        valid.push((state, coin));

        let mut state = fixture.state.clone();
        state.registered = false;
        state.value = 0;
        state.highest = fixture.coin.value;
        state.renewal = 0;
        state.claimed = 0;
        state.renewals = 0;
        let mut coin = fixture.coin.clone();
        coin.covenant = Covenant {
            kind: CovenantKind::Reveal,
            items: vec![name_hash.clone(), start.clone(), vec![0x42; 32]],
        };
        valid.push((state, coin));

        let mut state = fixture.state.clone();
        state.renewals = 0;
        let mut coin = fixture.coin.clone();
        coin.covenant = Covenant {
            kind: CovenantKind::Register,
            items: vec![name_hash.clone(), start.clone(), Vec::new(), vec![0x43; 32]],
        };
        valid.push((state, coin));

        let state = fixture.state.clone();
        let mut coin = fixture.coin.clone();
        coin.covenant = Covenant {
            kind: CovenantKind::Update,
            items: vec![name_hash.clone(), start.clone(), Vec::new()],
        };
        valid.push((state, coin));

        let state = fixture.state.clone();
        let mut coin = fixture.coin.clone();
        coin.covenant = Covenant {
            kind: CovenantKind::Renew,
            items: vec![name_hash, start, vec![0x44; 32]],
        };
        valid.push((state, coin));

        for (state, coin) in valid {
            assert!(validate_active_name_owner_coin(&state, &coin, &fixture.inclusion).is_ok());

            let mut malformed = coin.clone();
            malformed.covenant.items.push(Vec::new());
            assert!(matches!(
                validate_active_name_owner_coin(&state, &malformed, &fixture.inclusion),
                Err(WalletBackendError::Corrupt(_))
            ));

            let mut wrong_origin = coin;
            wrong_origin.coinbase = !wrong_origin.coinbase;
            assert!(matches!(
                validate_active_name_owner_coin(&state, &wrong_origin, &fixture.inclusion),
                Err(WalletBackendError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn name_action_eligibility_uses_fixed_bounded_candidate_reasons() {
        let mut state = NameState::null(NameHash::new([0x31; 32]));
        state.height = 1;
        state.renewal = 1;
        state.owner = Outpoint {
            txid: Txid::new([0x32; 32]),
            index: 0,
        };
        state.registered = true;
        let eligible = name_action_ineligibility_reasons(
            NameAction::Transfer,
            &state,
            CovenantKind::Register,
            NameLifecycleState::Closed,
            false,
            false,
            true,
            None,
        )
        .expect("bounded reasons");
        assert!(eligible.is_empty());

        state.transfer = 100;
        let blocked = name_action_ineligibility_reasons(
            NameAction::Finalize,
            &state,
            CovenantKind::Transfer,
            NameLifecycleState::Closed,
            false,
            false,
            true,
            Some(Txid::new([0x33; 32])),
        )
        .expect("bounded reasons");
        assert_eq!(
            blocked,
            vec![
                NameActionIneligibility::TransferNotMature,
                NameActionIneligibility::OwnerSpentInMempool,
            ]
        );
        assert!(blocked.len() <= MAX_NAME_ACTION_INELIGIBILITY_REASONS);
    }

    #[tokio::test]
    async fn typed_backend_reads_are_bounded_and_broadcast_is_not_a_success_stub() {
        let config = NodeConfig {
            network: Network::Regtest,
            wallet_index: true,
            ..NodeConfig::default()
        };
        let node = NodeService::try_new(config).unwrap();
        let runtime = NodeRuntime::spawn(node, DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY).unwrap();
        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest)).unwrap();
        let backend = runtime.wallet_backend(peers);

        assert_eq!(backend.get_chain_tip().await.unwrap(), None);
        assert_eq!(
            backend.get_chain_snapshot().await.unwrap(),
            WalletChainSnapshot {
                chain_epoch: 0,
                tip: None,
            }
        );
        assert_eq!(backend.get_block_hash(0).await.unwrap(), None);
        assert_eq!(
            backend.estimate_fee_rate(6).await.unwrap(),
            FeeEstimate {
                target_blocks: 6,
                atomic_units_per_kvb: HSD_MINIMUM_RELAY_FEE_RATE,
                sampled_transactions: 0,
                source: FeeEstimateSource::MinimumRelay,
            }
        );
        assert!(matches!(
            backend.estimate_fee_rate(0).await,
            Err(WalletBackendError::InvalidFeeTarget)
        ));
        let unknown = backend
            .get_transaction_evidence(Txid::new([7; 32]))
            .await
            .unwrap();
        assert_eq!(unknown.status, TransactionStatus::Unknown);
        assert_eq!(unknown.inclusion, None);
        assert_eq!(unknown.payload, TransactionPayload::Absent);
        assert_eq!(unknown.tip, None);
        assert!(matches!(
            backend
                .get_active_name_owner_coin(
                    NameHash::new([8; 32]),
                    unknown.chain_epoch.saturating_add(1),
                )
                .await,
            Err(WalletBackendError::StaleChainEpoch { .. })
        ));
        assert!(matches!(
            backend
                .get_active_name_owner_coin(NameHash::new([8; 32]), unknown.chain_epoch)
                .await,
            Err(WalletBackendError::ChainUninitialized)
        ));
        assert!(matches!(
            backend
                .get_name_action_context(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch.saturating_add(1),
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::StaleChainEpoch { .. })
        ));
        assert!(matches!(
            backend
                .get_name_action_context(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch,
                    [0; 32],
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::StaleMempoolInstance)
        ));
        assert!(matches!(
            backend
                .get_name_action_context(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch,
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation.saturating_add(1),
                )
                .await,
            Err(WalletBackendError::StaleMempoolGeneration { .. })
        ));
        assert!(matches!(
            backend
                .get_name_action_context(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch,
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::ChainUninitialized)
        ));
        assert!(matches!(
            backend
                .get_name_action_context_v2(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch.saturating_add(1),
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::StaleChainEpoch { .. })
        ));
        assert!(matches!(
            backend
                .get_name_action_context_v2(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch,
                    [0; 32],
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::StaleMempoolInstance)
        ));
        assert!(matches!(
            backend
                .get_name_action_context_v2(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch,
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation.saturating_add(1),
                )
                .await,
            Err(WalletBackendError::StaleMempoolGeneration { .. })
        ));
        assert!(matches!(
            backend
                .get_name_action_context_v2(
                    NameAction::Transfer,
                    NameHash::new([8; 32]),
                    unknown.chain_epoch,
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::ChainUninitialized)
        ));

        let quote_candidate = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([0x51; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 1,
                address: Address::new(0, vec![0x52; 20]).unwrap(),
                covenant: hns_primitives::Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        assert!(matches!(
            backend
                .quote_transaction_fee(
                    quote_candidate.clone(),
                    6,
                    unknown.chain_epoch,
                    [0; 32],
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::StaleMempoolInstance)
        ));
        assert!(matches!(
            backend
                .quote_transaction_fee(
                    quote_candidate,
                    6,
                    unknown.chain_epoch,
                    unknown.mempool_instance_nonce,
                    unknown.mempool_generation,
                )
                .await,
            Err(WalletBackendError::FeeQuoteInputUnavailable)
        ));

        let name = backend
            .get_name_evidence(NameHash::new([8; 32]))
            .await
            .unwrap();
        assert_eq!(name.current_state, None);
        assert_eq!(name.proof_state, None);
        assert_eq!(name.current_owner, None);
        assert_eq!(name.proof_owner, None);
        assert_eq!(name.tip, name.proof.tip);
        assert!(backend
            .get_script_history(ScriptId::from_descriptor(b"empty"), None, 16)
            .await
            .unwrap()
            .entries
            .is_empty());

        let mut scripts = vec![
            ScriptId::from_descriptor(b"restore-0"),
            ScriptId::from_descriptor(b"restore-1"),
        ];
        scripts.sort_unstable();
        let mempool_page = backend
            .get_mempool_scripts_activity(scripts.clone(), None, 128)
            .await
            .unwrap();
        assert_ne!(mempool_page.instance_nonce, [0; 32]);
        assert!(mempool_page.entries.is_empty());
        assert!(mempool_page.continuation.is_none());
        let confirmed_page = backend
            .get_confirmed_scripts_page(scripts.clone(), None, 128)
            .await
            .unwrap();
        assert!(confirmed_page.history.is_empty());
        assert!(confirmed_page.utxos.is_empty());
        assert!(confirmed_page.continuation.is_none());
        assert_eq!(confirmed_page.tip, None);
        assert_eq!(confirmed_page.script_examinations, 4);
        assert!(matches!(
            backend
                .get_confirmed_scripts_page(
                    scripts.clone(),
                    Some(ConfirmedScriptsCursor {
                        binding_version: CONFIRMED_CURSOR_VERSION,
                        chain_epoch: confirmed_page.chain_epoch.saturating_add(1),
                        script_set_id: confirmed_script_set_id(&scripts).unwrap(),
                        position: ConfirmedScriptsPosition::History {
                            script_index: 0,
                            cursor: None,
                        },
                    }),
                    128,
                )
                .await,
            Err(WalletBackendError::StaleChainEpoch { .. })
        ));
        assert!(matches!(
            backend
                .get_mempool_scripts_activity(vec![scripts[0], scripts[0]], None, 128)
                .await,
            Err(WalletBackendError::InvalidScriptSet)
        ));

        let mut empty_scripts = (0..=MAX_WALLET_CONFIRMED_SCRIPT_EXAMINATIONS / 2)
            .map(|index| ScriptId::from_descriptor(&index.to_be_bytes()))
            .collect::<Vec<_>>();
        empty_scripts.sort_unstable();
        let bounded_empty_page = backend
            .get_confirmed_scripts_page(empty_scripts.clone(), None, 128)
            .await
            .unwrap();
        assert!(bounded_empty_page.history.is_empty());
        assert!(bounded_empty_page.utxos.is_empty());
        assert_eq!(
            bounded_empty_page.script_examinations,
            MAX_WALLET_CONFIRMED_SCRIPT_EXAMINATIONS
        );
        let bounded_empty_continuation = bounded_empty_page
            .continuation
            .expect("empty traversal must yield resumable progress at its work bound");
        let bounded_empty_completion = backend
            .get_confirmed_scripts_page(empty_scripts, Some(bounded_empty_continuation), 128)
            .await
            .unwrap();
        assert!(bounded_empty_completion.history.is_empty());
        assert!(bounded_empty_completion.utxos.is_empty());
        assert_eq!(bounded_empty_completion.script_examinations, 2);
        assert!(bounded_empty_completion.continuation.is_none());

        let registration =
            ContractRegistration::shakedex_v2(hns_wallet_index::ShakedexV2Descriptor {
                name_hash: [3; 32],
                seller_public_key: GENERATOR_KEY,
                value: 1_000,
            })
            .unwrap();
        assert_eq!(
            backend
                .register_tracked_contract(registration.clone())
                .await
                .unwrap(),
            ContractRegistrationOutcome::Registered
        );
        assert_eq!(
            backend
                .register_tracked_contract(registration.clone())
                .await
                .unwrap(),
            ContractRegistrationOutcome::AlreadyRegistered
        );
        assert_eq!(
            backend.get_tracked_contract(registration.id).await.unwrap(),
            Some(registration.clone())
        );
        assert!(backend
            .get_tracked_contract_events(registration.id, None, 8)
            .await
            .unwrap()
            .entries
            .is_empty());
        assert!(backend
            .get_mempool_tracked_contract_activity(registration.id, None, 128)
            .await
            .unwrap()
            .entries
            .is_empty());

        let unsigned = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([9; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: Vec::new(),
            locktime: 0,
        };
        assert!(matches!(
            backend.broadcast_transaction(unsigned).await,
            Err(WalletBackendError::Rejected(reason))
                if reason == "mining_engine-transaction-relay-disabled"
        ));

        drop(backend);
        runtime.shutdown_unclean().await.unwrap();
    }

    #[tokio::test]
    async fn never_confirmed_contract_retirement_is_generation_and_lifecycle_bound() {
        let config = NodeConfig {
            network: Network::Regtest,
            wallet_index: true,
            ..NodeConfig::default()
        };
        let node = NodeService::try_new(config).unwrap();
        let runtime = NodeRuntime::spawn(node, DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY).unwrap();
        let (peers, _peer_events) =
            LivePeerManager::new(LivePeerConfig::for_network(Network::Regtest)).unwrap();
        let backend = runtime.wallet_backend(peers);
        let registration =
            ContractRegistration::shakedex_v2(hns_wallet_index::ShakedexV2Descriptor {
                name_hash: [0x71; 32],
                seller_public_key: GENERATOR_KEY,
                value: 1_000,
            })
            .unwrap();
        let matching_funding = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::null(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 1_000,
                address: registration.funding_address().unwrap(),
                covenant: hns_primitives::Covenant {
                    kind: CovenantKind::Finalize,
                    items: vec![vec![0x71; 32]],
                },
            }],
            locktime: 0,
        };
        assert!(transaction_contains_contract_funding(&registration, &matching_funding).unwrap());
        let mut wrong_funding = matching_funding;
        wrong_funding.outputs[0].value = 999;
        assert!(!transaction_contains_contract_funding(&registration, &wrong_funding).unwrap());
        assert_eq!(
            backend
                .register_tracked_contract(registration.clone())
                .await
                .unwrap(),
            ContractRegistrationOutcome::Registered
        );
        let binding = backend
            .get_tracked_contract_retirement_context(registration.id)
            .await
            .unwrap();
        assert_eq!(binding.registration, Some(registration.clone()));
        let lifecycle_revision = binding
            .lifecycle_revision
            .expect("new registration lifecycle revision");
        let request = TrackedContractRetirementRequest {
            registration: registration.clone(),
            expected_lifecycle_revision: lifecycle_revision,
            expected_chain_epoch: binding.chain_epoch,
            expected_tip: binding.tip.clone(),
            expected_mempool_instance_nonce: binding.mempool_instance_nonce,
            expected_mempool_generation: binding.mempool_generation,
        };

        let mut wrong_instance = request.clone();
        wrong_instance.expected_mempool_instance_nonce = [0; 32];
        assert!(matches!(
            backend
                .retire_never_confirmed_tracked_contract(wrong_instance)
                .await,
            Err(WalletBackendError::StaleMempoolInstance)
        ));
        let mut wrong_generation = request.clone();
        wrong_generation.expected_mempool_generation = binding.mempool_generation.saturating_add(1);
        assert!(matches!(
            backend
                .retire_never_confirmed_tracked_contract(wrong_generation)
                .await,
            Err(WalletBackendError::StaleMempoolGeneration { .. })
        ));
        let mut wrong_chain = request.clone();
        wrong_chain.expected_chain_epoch = binding.chain_epoch.saturating_add(1);
        assert!(matches!(
            backend
                .retire_never_confirmed_tracked_contract(wrong_chain)
                .await,
            Err(WalletBackendError::StaleChainEpoch { .. })
        ));

        let retired = backend
            .retire_never_confirmed_tracked_contract(request.clone())
            .await
            .unwrap();
        assert_eq!(retired.contract_id, registration.id);
        assert_eq!(retired.outcome, ContractRetirementOutcome::Retired);
        assert_eq!(retired.lifecycle_revision, lifecycle_revision);
        assert_eq!(retired.chain_epoch, binding.chain_epoch);
        assert_eq!(retired.tip, binding.tip);
        assert_eq!(
            retired.mempool_instance_nonce,
            binding.mempool_instance_nonce
        );
        assert_eq!(retired.mempool_generation, binding.mempool_generation);
        assert_eq!(
            backend.get_tracked_contract(registration.id).await.unwrap(),
            None
        );

        let retry = backend
            .retire_never_confirmed_tracked_contract(request.clone())
            .await
            .unwrap();
        assert_eq!(retry.outcome, ContractRetirementOutcome::AlreadyAbsent);
        assert_eq!(
            backend
                .register_tracked_contract(registration.clone())
                .await
                .unwrap(),
            ContractRegistrationOutcome::Registered
        );
        assert_eq!(
            backend.get_tracked_contract(registration.id).await.unwrap(),
            Some(registration.clone())
        );
        assert!(matches!(
            backend
                .retire_never_confirmed_tracked_contract(request)
                .await,
            Err(WalletBackendError::StaleContractLifecycle {
                expected,
                actual: Some(actual),
            }) if expected == lifecycle_revision && actual != lifecycle_revision
        ));

        drop(backend);
        runtime.shutdown_unclean().await.unwrap();
    }

    #[test]
    fn fee_quote_uses_node_resolved_coin_and_exact_hsd_policy_units() {
        let outpoint = Outpoint {
            txid: Txid::new([0x61; 32]),
            index: 7,
        };
        let coin = Coin {
            outpoint: outpoint.clone(),
            value: 50_000,
            height: 10,
            coinbase: false,
            address: Address::new(0, vec![0x62; 20]).unwrap(),
            covenant: hns_primitives::Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::Utxo,
                &encode_outpoint_key(&outpoint),
                &encode_coin(&coin),
            )
            .unwrap();
        store.commit(batch).unwrap();
        let snapshot = store.snapshot().unwrap();
        let mempool = MemoryMempool::new().unwrap().snapshot();
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: outpoint,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 49_000,
                address: Address::new(0, vec![0x63; 20]).unwrap(),
                covenant: hns_primitives::Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };

        let quote =
            transaction_fee_quote_from_snapshot(&snapshot, &mempool, &transaction, 6, 9, None)
                .unwrap();
        assert_eq!(quote.txid, transaction.txid());
        assert_eq!(quote.chain_epoch, 9);
        assert_eq!(quote.mempool_instance_nonce, *mempool.instance_nonce());
        assert_eq!(quote.mempool_generation, mempool.generation());
        assert_eq!(quote.transaction_sigops, 1);
        assert_eq!(quote.transaction_weight, transaction_weight(&transaction));
        assert_eq!(
            quote.sigop_adjusted_policy_vbytes,
            sigop_adjusted_virtual_size(&transaction, 1)
        );
        assert_eq!(
            quote.rate_atomic_units_per_1000_policy_vbytes,
            HSD_MINIMUM_RELAY_FEE_RATE
        );
        assert_eq!(quote.rate_sample_count, 0);
        assert_eq!(quote.rate_source, FeeEstimateSource::MinimumRelay);
        assert_eq!(
            quote.minimum_policy_fee_atomic_units,
            minimum_policy_fee(
                quote.sigop_adjusted_policy_vbytes,
                HSD_MINIMUM_RELAY_FEE_RATE,
            )
        );
        assert_eq!(quote.actual_fee_atomic_units, 1_000);
        assert!(quote.meets_minimum_policy_fee);
        assert_eq!(quote.minimum_policy_fee_shortfall_atomic_units, 0);

        let mut underpaid = transaction;
        underpaid.outputs[0].value = 49_999;
        let underpaid_quote =
            transaction_fee_quote_from_snapshot(&snapshot, &mempool, &underpaid, 6, 9, None)
                .unwrap();
        assert_eq!(underpaid_quote.actual_fee_atomic_units, 1);
        assert!(!underpaid_quote.meets_minimum_policy_fee);
        assert_eq!(
            underpaid_quote.minimum_policy_fee_shortfall_atomic_units,
            underpaid_quote
                .minimum_policy_fee_atomic_units
                .saturating_sub(1)
        );

        let mut overspend = underpaid;
        overspend.outputs[0].value = 50_001;
        assert!(matches!(
            transaction_fee_quote_from_snapshot(&snapshot, &mempool, &overspend, 6, 9, None,),
            Err(WalletBackendError::InvalidFeeQuoteTransaction)
        ));
    }

    #[test]
    fn mempool_cursor_rejects_another_process_local_instance() {
        let first = MemoryMempool::new()
            .expect("first mempool initialization")
            .snapshot();
        let second = MemoryMempool::new()
            .expect("second mempool initialization")
            .snapshot();
        assert_ne!(first.instance_nonce(), &[0; 32]);
        assert_ne!(second.instance_nonce(), &[0; 32]);
        assert_ne!(first.instance_nonce(), second.instance_nonce());

        let query_id = [0x42; 32];
        let cursor = WalletMempoolCursor {
            binding_version: MEMPOOL_CURSOR_VERSION,
            chain_epoch: 1,
            instance_nonce: *first.instance_nonce(),
            generation: first.generation(),
            query_id,
            after_txid: Txid::ZERO,
        };
        assert!(matches!(
            mempool_scan_page(&second, Some(&cursor), 1, query_id, 1),
            Err(WalletBackendError::StaleMempoolInstance)
        ));
    }
}
