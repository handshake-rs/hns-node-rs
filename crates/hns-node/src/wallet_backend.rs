//! Typed noncustodial wallet backend over the canonical node runtime.

use std::sync::Arc;

use hns_chain::TxIndexEntry;
use hns_mempool::{Admission, HSD_MINIMUM_RELAY_FEE_RATE};
use hns_p2p::{Inventory, LivePeerManager, OutboundPriority, Packet};
use hns_primitives::{BlockHash, Height, NameHash, NameState, Outpoint, Output, Transaction, Txid};
use hns_state::{
    decode_name_state, load_stored_name_tree_root, prove_persisted_name_tree, TreeRoot,
};
use hns_store::{ColumnFamily, ReadSnapshot, Store};
use hns_urkel::UrkelProof;
use hns_wallet_index::{
    script_history, script_utxos, spending_transaction, IndexError, ScriptHistoryCursor,
    ScriptHistoryPage, ScriptId, ScriptUtxoCursor, ScriptUtxoPage, SpendingTransaction,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    best_block_tip_from_snapshot, load_block, read_canonical_hash, CanonicalStateWriter,
    LivePeerManager as ReexportedLivePeerManager, NodeReadHandle, NodeRuntime,
};

/// Maximum mempool entries sampled by one fee estimate.
pub const MAX_FEE_ESTIMATE_SAMPLES: usize = 4_096;
/// Maximum accepted confirmation target.
pub const MAX_FEE_ESTIMATE_TARGET_BLOCKS: u32 = 1_008;

/// Current canonical active-chain tip.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletChainTip {
    /// Active-chain block hash.
    pub hash: BlockHash,
    /// Active-chain height.
    pub height: Height,
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
    /// Active name-tree root used to generate the proof.
    pub root: TreeRoot,
    /// Canonical inclusion/non-inclusion proof.
    pub proof: UrkelProof,
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
        blocking_read(read, move |_, snapshot| {
            best_block_tip_from_snapshot(snapshot)
                .map(|tip| {
                    tip.map(|tip| WalletChainTip {
                        hash: tip.hash,
                        height: tip.height,
                    })
                })
                .map_err(node_error)
        })
        .await
    }

    /// Read a transaction from the contextual mempool or active tx index.
    pub async fn get_raw_transaction(
        &self,
        txid: Txid,
    ) -> Result<Option<Transaction>, WalletBackendError> {
        if let Some(transaction) = self
            .read
            .published_mempool_snapshot()
            .map_err(node_error)?
            .transaction(&txid)
            .cloned()
        {
            return Ok(Some(transaction));
        }
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let read = self.read.clone();
        blocking_read(read, move |_, snapshot| {
            load_confirmed_transaction(snapshot, txid).map(|value| value.map(|(tx, _)| tx))
        })
        .await
    }

    /// Return mempool/confirmed/unknown status.
    pub async fn get_transaction_status(
        &self,
        txid: Txid,
    ) -> Result<TransactionStatus, WalletBackendError> {
        if self
            .read
            .published_mempool_snapshot()
            .map_err(node_error)?
            .transaction(&txid)
            .is_some()
        {
            return Ok(TransactionStatus::Mempool);
        }
        Ok(match self.get_transaction_inclusion(txid).await? {
            Some(inclusion) => TransactionStatus::Confirmed(inclusion),
            None => TransactionStatus::Unknown,
        })
    }

    /// Return active-chain inclusion, if confirmed.
    pub async fn get_transaction_inclusion(
        &self,
        txid: Txid,
    ) -> Result<Option<TransactionInclusion>, WalletBackendError> {
        if !self.read.transaction_index {
            return Err(WalletBackendError::IndexDisabled("transaction"));
        }
        let read = self.read.clone();
        blocking_read(read, move |_, snapshot| {
            load_transaction_inclusion(snapshot, txid)
        })
        .await
    }

    /// Return one bounded page of active-chain script history.
    pub async fn get_script_history(
        &self,
        script: ScriptId,
        cursor: Option<ScriptHistoryCursor>,
        limit: usize,
    ) -> Result<ScriptHistoryPage, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_read(read, move |_, snapshot| {
            script_history(snapshot, profile, script, cursor.as_ref(), limit)
                .map_err(wallet_index_error)
        })
        .await
    }

    /// Return one bounded page of active script UTXOs.
    pub async fn get_script_utxos(
        &self,
        script: ScriptId,
        cursor: Option<ScriptUtxoCursor>,
        limit: usize,
    ) -> Result<ScriptUtxoPage, WalletBackendError> {
        let profile = self.read.wallet_index_profile();
        let read = self.read.clone();
        blocking_read(read, move |_, snapshot| {
            script_utxos(snapshot, profile, script, cursor.as_ref(), limit)
                .map_err(wallet_index_error)
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
        blocking_read(read, move |_, snapshot| {
            spending_transaction(snapshot, profile, &outpoint).map_err(wallet_index_error)
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
        blocking_read(read, move |_, snapshot| {
            snapshot
                .get(ColumnFamily::NameState, name_hash.as_bytes())
                .map_err(node_error)?
                .as_deref()
                .map(|raw| decode_name_state(&name_hash, raw))
                .transpose()
                .map_err(node_error)
        })
        .await
    }

    /// Generate a current inclusion/non-inclusion name proof.
    pub async fn get_name_proof(
        &self,
        name_hash: NameHash,
    ) -> Result<NameProofResult, WalletBackendError> {
        let read = self.read.clone();
        blocking_read(read, move |_, snapshot| {
            let root = load_stored_name_tree_root(snapshot).map_err(node_error)?;
            let proof = prove_persisted_name_tree(snapshot, root, name_hash).map_err(node_error)?;
            Ok(NameProofResult { root, proof })
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
        blocking_read(read, move |_, snapshot| {
            let Some(raw) = snapshot
                .get(ColumnFamily::NameState, name_hash.as_bytes())
                .map_err(node_error)?
            else {
                return Ok(None);
            };
            let name_state = decode_name_state(&name_hash, &raw).map_err(node_error)?;
            if name_state.owner.is_null() {
                return Err(WalletBackendError::NameHasNoOwner);
            }
            let owner = name_state.owner.clone();
            let Some((transaction, inclusion)) = load_confirmed_transaction(snapshot, owner.txid)?
            else {
                return Err(WalletBackendError::Corrupt(
                    "current name owner transaction is absent from the active index",
                ));
            };
            let owner_output = transaction
                .outputs
                .get(
                    usize::try_from(owner.index)
                        .map_err(|_| WalletBackendError::OwnerOutputMissing)?,
                )
                .cloned()
                .ok_or(WalletBackendError::OwnerOutputMissing)?;
            Ok(Some(NameOwnerTransaction {
                name_state,
                owner,
                transaction,
                owner_output,
                inclusion,
            }))
        })
        .await
    }
}

async fn blocking_read<T, F>(read: NodeReadHandle, operation: F) -> Result<T, WalletBackendError>
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
    let permit = Arc::clone(&read.point_read_concurrency)
        .try_acquire_owned()
        .map_err(|_| WalletBackendError::Node("wallet read concurrency exhausted".to_owned()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read.ensure_storage_operational().map_err(node_error)?;
        let snapshot = read.store.snapshot().map_err(node_error)?;
        let result = operation(&read, &snapshot)?;
        read.ensure_storage_operational().map_err(node_error)?;
        Ok(result)
    })
    .await
    .map_err(node_error)?
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

fn load_transaction_inclusion<S: ReadSnapshot>(
    snapshot: &S,
    txid: Txid,
) -> Result<Option<TransactionInclusion>, WalletBackendError> {
    load_transaction_index_and_inclusion(snapshot, txid)
        .map(|value| value.map(|(_, inclusion)| inclusion))
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
        IndexError::Corrupt(reason) => WalletBackendError::Corrupt(reason),
        other => node_error(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_consensus::Network;
    use hns_p2p::LivePeerConfig;
    use hns_primitives::{Input, Outpoint, Witness};

    use crate::{NodeConfig, NodeService, DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY};

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
        assert_eq!(
            backend
                .get_transaction_status(Txid::new([7; 32]))
                .await
                .unwrap(),
            TransactionStatus::Unknown
        );
        assert!(backend
            .get_script_history(ScriptId::from_descriptor(b"empty"), None, 16)
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
}
