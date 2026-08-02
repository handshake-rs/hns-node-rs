//! Typed noncustodial wallet backend over the canonical node runtime.

use std::{collections::HashMap, sync::Arc};

use hns_chain::TxIndexEntry;
use hns_mempool::{Admission, MempoolSnapshot, HSD_MINIMUM_RELAY_FEE_RATE};
use hns_p2p::{Inventory, LivePeerManager, OutboundPriority, Packet};
use hns_primitives::{
    blake2b_256, BlockHash, Coin, Height, NameHash, NameState, Outpoint, Output, Transaction,
    Txid, Writer,
};
use hns_state::{
    decode_coin, decode_name_state, encode_outpoint_key, load_stored_name_tree_root,
    prove_persisted_name_tree, TreeRoot,
};
use hns_store::{ColumnFamily, ReadSnapshot, Store};
use hns_urkel::UrkelProof;
use hns_wallet_index::{
    script_history, script_utxos, spending_transaction, tracked_contract,
    tracked_contract_events, tracked_contract_funding, tracked_contract_fundings, ContractId,
    ContractRegistration, ContractRegistrationOutcome, IndexError, ScriptHistoryCursor,
    ScriptHistoryEntry, ScriptHistoryPage, ScriptId, ScriptUtxo, ScriptUtxoCursor,
    ScriptUtxoPage, SpendingTransaction, TrackedContractCursor, TrackedContractEvent,
    TrackedContractFunding, TrackedContractSpendKind, MAX_QUERY_ENTRIES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    best_block_tip_from_snapshot, chain_epoch_from_snapshot, load_block, read_canonical_hash,
    CanonicalEpoch, CanonicalStateWriter, LivePeerManager as ReexportedLivePeerManager,
    NodeReadHandle, NodeRuntime,
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

const CONFIRMED_SCRIPT_SET_DOMAIN: &[u8] = b"hns-node/wallet-confirmed-script-set/v1";
const MEMPOOL_SCRIPT_SET_DOMAIN: &[u8] = b"hns-node/wallet-mempool-script-set/v1";
const MEMPOOL_CONTRACT_DOMAIN: &[u8] = b"hns-node/wallet-mempool-contract/v1";
const CONFIRMED_CURSOR_VERSION: u8 = 1;
const MEMPOOL_CURSOR_VERSION: u8 = 1;

/// Opaque query-bound cursor for a single immutable mempool generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletMempoolCursor {
    binding_version: u8,
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
    /// Outputs paying the requested script.
    pub received: Vec<MempoolScriptOutput>,
    /// Inputs spending confirmed or unconfirmed outputs of the requested script.
    pub spent: Vec<MempoolScriptSpend>,
}

/// One bounded global-scan page of script-relevant mempool activity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolScriptPage {
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
    /// Descriptor-verified events in transaction order.
    pub events: Vec<MempoolContractEvent>,
}

/// One bounded global-scan page of registered-contract mempool activity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolContractPage {
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

/// Current canonical active-chain tip.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletChainTip {
    /// Active-chain block hash.
    pub hash: BlockHash,
    /// Active-chain height.
    pub height: Height,
    /// Exact authenticated name-tree root available for proofs at this tip.
    pub tree_root: TreeRoot,
}

/// Confirmed transaction inclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionInclusion {
    /// Active-chain block hash.
    pub block_hash: BlockHash,
    /// Active-chain block height.
    pub height: Height,
    /// Number of confirmations at the atomically read tip.
    pub confirmations: u32,
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
    /// Immutable public contract registry capacity is exhausted.
    #[error("wallet tracked-contract registry is full")]
    ContractCapacity,
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
    /// A confirmed restoration result bound is invalid.
    #[error("wallet confirmed restoration limit must be between 1 and {MAX_WALLET_CONFIRMED_PAGE_ITEMS}")]
    InvalidConfirmedPageLimit,
    /// A point or contract index page bound is invalid.
    #[error("wallet index page limit must be between 1 and {MAX_QUERY_ENTRIES}")]
    InvalidIndexPageLimit,
    /// A mempool scan bound is invalid.
    #[error("wallet mempool scan limit must be between 1 and {MAX_WALLET_MEMPOOL_SCAN}")]
    InvalidMempoolScanLimit,
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
    /// Requested name has no current owner outpoint.
    #[error("current name state has no owner")]
    NameHasNoOwner,
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
        }
    }
}

impl WalletBackend {
    /// Read the active chain tip.
    pub async fn get_chain_tip(&self) -> Result<Option<WalletChainTip>, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| wallet_chain_tip(snapshot)).await
    }

    /// Read the active-chain hash at one exact height.
    pub async fn get_block_hash(
        &self,
        height: Height,
    ) -> Result<Option<BlockHash>, WalletBackendError> {
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            read_canonical_hash(snapshot, height).map_err(node_error)
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
        blocking_mempool_read(read, move |_, snapshot, mempool, epoch| {
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
            let Some((index, inclusion)) =
                load_transaction_index_and_inclusion(snapshot, txid)?
            else {
                return Ok(TransactionEvidence {
                    chain_epoch,
                    mempool_generation: mempool.generation(),
                    tip,
                    status: TransactionStatus::Unknown,
                    inclusion: None,
                    payload: TransactionPayload::Absent,
                });
            };
            let payload = match load_block(snapshot, &index.block_hash).map_err(node_error)? {
                Some(block) => TransactionPayload::Retained(
                    block
                        .transactions
                        .into_iter()
                        .find(|transaction| transaction.txid() == txid)
                        .ok_or(WalletBackendError::Corrupt(
                            "indexed transaction is absent from its block",
                        ))?,
                ),
                None => TransactionPayload::Pruned,
            };
            Ok(TransactionEvidence {
                chain_epoch,
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
                        let page = script_history(
                            snapshot,
                            profile,
                            script,
                            cursor.as_ref(),
                            limit,
                        )
                        .map_err(wallet_index_error)?;
                        let history = page
                            .entries
                            .into_iter()
                            .map(|entry| ConfirmedScriptHistory {
                                script_index,
                                entry,
                            })
                            .collect::<Vec<_>>();
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
                        let page = script_utxos(
                            snapshot,
                            profile,
                            script,
                            cursor.as_ref(),
                            limit,
                        )
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

    /// Return the active-chain spending transaction for one outpoint.
    pub async fn get_spending_transaction(
        &self,
        outpoint: Outpoint,
    ) -> Result<Option<SpendingTransaction>, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_chain_read(read, move |_, snapshot| {
            spending_transaction(snapshot, profile, &outpoint).map_err(wallet_index_error)
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
            let page = tracked_contract_fundings(
                snapshot,
                profile,
                id,
                inner.as_ref(),
                limit,
            )
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
            let page = tracked_contract_events(
                snapshot,
                profile,
                id,
                inner.as_ref(),
                limit,
            )
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
        blocking_mempool_read(read, move |_, snapshot, mempool, _| {
            let script_positions = scripts
                .iter()
                .copied()
                .enumerate()
                .map(|(position, script)| (script, position))
                .collect::<HashMap<_, _>>();
            let (txids, continuation) =
                mempool_scan_page(mempool, cursor.as_ref(), scan_limit, query_id)?;
            let mut entries = Vec::new();
            let mut relevant_items = 0usize;
            for txid in txids {
                let transaction = mempool.transaction(&txid).ok_or(
                    WalletBackendError::Corrupt(
                        "published mempool references an absent transaction",
                    ),
                )?;
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
                                WalletBackendError::Corrupt(
                                    "mempool output position exceeds u32",
                                )
                            })?,
                        },
                        value: output.value,
                    });
                }
                for input in &transaction.inputs {
                    if input.previous_output.is_null() {
                        continue;
                    }
                    let Some(coin) = resolve_mempool_coin(snapshot, mempool, &input.previous_output)?
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
                        received,
                        spent,
                    });
                }
            }
            Ok(MempoolScriptPage {
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
        blocking_mempool_read(read, move |_, snapshot, mempool, _| {
            let registration = tracked_contract(snapshot, profile, id)
                .map_err(wallet_index_error)?
                .ok_or(WalletBackendError::UnknownContract)?;
            let (txids, continuation) =
                mempool_scan_page(mempool, cursor.as_ref(), scan_limit, query_id)?;
            let mut entries = Vec::new();
            let mut relevant_items = 0usize;
            for txid in txids {
                let transaction = mempool.transaction(&txid).ok_or(
                    WalletBackendError::Corrupt(
                        "published mempool references an absent transaction",
                    ),
                )?;
                let mut events = Vec::new();
                for (input_position, input) in transaction.inputs.iter().enumerate() {
                    if input.previous_output.is_null() {
                        continue;
                    }
                    let Some(coin) = resolve_mempool_coin(snapshot, mempool, &input.previous_output)?
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
                    let parent_is_mempool = mempool
                        .transaction(&input.previous_output.txid)
                        .is_some();
                    if !parent_is_mempool
                        && tracked_contract_funding(
                            snapshot,
                            profile,
                            id,
                            &input.previous_output,
                        )
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
                                WalletBackendError::Corrupt(
                                    "mempool output position exceeds u32",
                                )
                            })?,
                        },
                        value: output.value,
                    });
                }
                if !events.is_empty() {
                    entries.push(MempoolContractActivity { txid, events });
                }
            }
            Ok(MempoolContractPage {
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
            return Ok(FeeEstimate {
                target_blocks,
                atomic_units_per_kvb: HSD_MINIMUM_RELAY_FEE_RATE,
                sampled_transactions: 0,
                source: FeeEstimateSource::MinimumRelay,
            });
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
        Ok(FeeEstimate {
            target_blocks,
            atomic_units_per_kvb: rates[index],
            sampled_transactions: rates.len(),
            source: FeeEstimateSource::Mempool,
        })
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
            let proof_raw = proof
                .proof
                .verify_value(proof.root)
                .map_err(node_error)?;
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
    let tree_root = load_stored_name_tree_root(snapshot).map_err(node_error)?;
    Ok(Some(WalletChainTip {
        hash: tip.hash,
        height: tip.height,
        tree_root,
    }))
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
    if tip
        .as_ref()
        .is_some_and(|tip| tip.tree_root != root)
    {
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
        .get(
            usize::try_from(owner.index).map_err(|_| WalletBackendError::OwnerOutputMissing)?,
        )
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
        let mempool = read.published_mempool_snapshot().map_err(node_error)?;
        let snapshot = read.store.snapshot().map_err(node_error)?;
        if chain_epoch_from_snapshot(&snapshot).map_err(node_error)? != epoch.chain_epoch
            || best_block_tip_from_snapshot(&snapshot)
                .map_err(node_error)?
                .as_ref()
                != epoch.tip.as_ref()
        {
            return Err(WalletBackendError::StaleCanonicalRead);
        }
        let result = operation(&read, &snapshot, &mempool, &epoch);
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

fn script_set_id(
    domain: &[u8],
    scripts: &[ScriptId],
) -> Result<[u8; 32], WalletBackendError> {
    let count = u32::try_from(scripts.len())
        .map_err(|_| WalletBackendError::InvalidScriptSet)?;
    let mut identity = Writer::with_capacity(
        domain.len() + 4 + scripts.len().saturating_mul(32),
    );
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

fn mempool_scan_page(
    mempool: &MempoolSnapshot,
    cursor: Option<&WalletMempoolCursor>,
    scan_limit: usize,
    query_id: [u8; 32],
) -> Result<(Vec<Txid>, Option<WalletMempoolCursor>), WalletBackendError> {
    if let Some(cursor) = cursor {
        if cursor.binding_version != MEMPOOL_CURSOR_VERSION {
            return Err(WalletBackendError::InvalidMempoolCursor);
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
    let Some((index, inclusion)) = load_transaction_index_and_inclusion(snapshot, txid)? else {
        return Ok(None);
    };
    let block = load_block(snapshot, &index.block_hash)
        .map_err(node_error)?
        .ok_or(WalletBackendError::PayloadPruned)?;
    let transaction = block
        .transactions
        .into_iter()
        .find(|transaction| transaction.txid() == txid)
        .ok_or(WalletBackendError::Corrupt(
            "indexed transaction is absent from its block",
        ))?;
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
        other => node_error(other),
    }
}

fn wallet_writer_error(error: anyhow::Error) -> WalletBackendError {
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
            _ => node_error(index),
        };
    }
    node_error(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_consensus::Network;
    use hns_mempool::MemoryMempool;
    use hns_p2p::LivePeerConfig;
    use hns_primitives::{Input, Outpoint, Witness};

    use crate::{NodeConfig, NodeService, DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY};

    const GENERATOR_KEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
        0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
        0x5b, 0x16, 0xf8, 0x17, 0x98,
    ];

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
            .get_confirmed_scripts_page(
                empty_scripts,
                Some(bounded_empty_continuation),
                128,
            )
            .await
            .unwrap();
        assert!(bounded_empty_completion.history.is_empty());
        assert!(bounded_empty_completion.utxos.is_empty());
        assert_eq!(bounded_empty_completion.script_examinations, 2);
        assert!(bounded_empty_completion.continuation.is_none());

        let registration = ContractRegistration::shakedex_v2(
            hns_wallet_index::ShakedexV2Descriptor {
                name_hash: [3; 32],
                seller_public_key: GENERATOR_KEY,
                value: 1_000,
            },
        )
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
            backend
                .get_tracked_contract(registration.id)
                .await
                .unwrap(),
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
            instance_nonce: *first.instance_nonce(),
            generation: first.generation(),
            query_id,
            after_txid: Txid::ZERO,
        };
        assert!(matches!(
            mempool_scan_page(&second, Some(&cursor), 1, query_id),
            Err(WalletBackendError::StaleMempoolInstance)
        ));
    }
}
