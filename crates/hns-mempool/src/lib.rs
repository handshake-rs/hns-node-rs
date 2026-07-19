#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
};

use hns_consensus::{is_coinbase, validate_transaction_sanity};
use hns_primitives::{Amount, Outpoint, Transaction, Txid};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub txid: Txid,
    pub fee: Amount,
    pub size: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub transaction_count: usize,
    pub bytes: usize,
    pub total_fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Admission {
    Accepted(Txid),
    Rejected { reason: String },
    Orphan(Txid),
}

pub trait Mempool {
    fn info(&self) -> MempoolInfo;

    fn entries(&self) -> Vec<MempoolEntry>;

    fn submit(&mut self, transaction: Transaction) -> Result<Admission, MempoolError>;
}

pub trait MempoolView {
    type Error: std::error::Error + Send + Sync + 'static;

    fn has_coin(&self, outpoint: &Outpoint) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UncheckedMempoolView;

impl MempoolView for UncheckedMempoolView {
    type Error = Infallible;

    fn has_coin(&self, _outpoint: &Outpoint) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryMempool {
    entries: HashMap<Txid, MempoolEntry>,
    transactions: HashMap<Txid, Transaction>,
    orphans: HashMap<Txid, Transaction>,
    spent_outpoints: HashMap<Outpoint, Txid>,
}

impl MemoryMempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn transaction(&self, txid: &Txid) -> Option<&Transaction> {
        self.transactions.get(txid)
    }

    pub fn orphan(&self, txid: &Txid) -> Option<&Transaction> {
        self.orphans.get(txid)
    }

    pub fn orphans(&self) -> Vec<Txid> {
        let mut txids = self.orphans.keys().copied().collect::<Vec<_>>();
        txids.sort_by_key(|txid| txid.into_inner());
        txids
    }

    pub fn submit_with_view<V: MempoolView>(
        &mut self,
        transaction: Transaction,
        view: &V,
    ) -> Result<Admission, MempoolError> {
        let admission = self.submit_checked(transaction, view)?;

        if matches!(admission, Admission::Accepted(_)) {
            self.promote_orphans(view)?;
        }

        Ok(admission)
    }

    fn submit_checked<V: MempoolView>(
        &mut self,
        transaction: Transaction,
        view: &V,
    ) -> Result<Admission, MempoolError> {
        let txid = transaction.txid();

        if self.entries.contains_key(&txid) || self.orphans.contains_key(&txid) {
            return Ok(Admission::Rejected {
                reason: "duplicate".to_owned(),
            });
        }

        if let Err(error) = validate_transaction_sanity(&transaction) {
            return Ok(Admission::Rejected {
                reason: error.to_string(),
            });
        }

        if is_coinbase(&transaction) {
            return Ok(Admission::Rejected {
                reason: "coinbase".to_owned(),
            });
        }

        if self.conflicts_with_mempool(&transaction) {
            return Ok(Admission::Rejected {
                reason: "mempool-conflict".to_owned(),
            });
        }

        if self.has_missing_inputs(&transaction, view)? {
            self.orphans.insert(txid, transaction);
            return Ok(Admission::Orphan(txid));
        }

        self.accept(transaction);
        Ok(Admission::Accepted(txid))
    }

    fn accept(&mut self, transaction: Transaction) {
        let txid = transaction.txid();
        let entry = MempoolEntry {
            txid,
            fee: 0,
            size: transaction.encode().len(),
        };

        for input in &transaction.inputs {
            self.spent_outpoints
                .insert(input.previous_output.clone(), txid);
        }

        self.entries.insert(txid, entry);
        self.transactions.insert(txid, transaction);
    }

    fn promote_orphans<V: MempoolView>(&mut self, view: &V) -> Result<(), MempoolError> {
        loop {
            let promotable = self
                .orphans
                .iter()
                .filter_map(|(txid, transaction)| {
                    match self.has_missing_inputs(transaction, view) {
                        Ok(false) if !self.conflicts_with_mempool(transaction) => Some(Ok(*txid)),
                        Ok(_) => None,
                        Err(error) => Some(Err(error)),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;

            if promotable.is_empty() {
                return Ok(());
            }

            for txid in promotable {
                if let Some(transaction) = self.orphans.remove(&txid) {
                    self.accept(transaction);
                }
            }
        }
    }

    fn conflicts_with_mempool(&self, transaction: &Transaction) -> bool {
        let mut seen = HashSet::new();

        transaction.inputs.iter().any(|input| {
            !seen.insert(input.previous_output.clone())
                || self.spent_outpoints.contains_key(&input.previous_output)
        })
    }

    fn has_missing_inputs<V: MempoolView>(
        &self,
        transaction: &Transaction,
        view: &V,
    ) -> Result<bool, MempoolError> {
        for input in &transaction.inputs {
            if self.has_mempool_output(&input.previous_output) {
                continue;
            }

            if !view
                .has_coin(&input.previous_output)
                .map_err(|error| MempoolError::View(error.to_string()))?
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn has_mempool_output(&self, outpoint: &Outpoint) -> bool {
        self.transactions
            .get(&outpoint.txid)
            .and_then(|transaction| transaction.outputs.get(outpoint.index as usize))
            .is_some()
    }
}

impl Mempool for MemoryMempool {
    fn info(&self) -> MempoolInfo {
        MempoolInfo {
            transaction_count: self.entries.len(),
            bytes: self.entries.values().map(|entry| entry.size).sum(),
            total_fee: self.entries.values().map(|entry| entry.fee).sum(),
        }
    }

    fn entries(&self) -> Vec<MempoolEntry> {
        let mut entries: Vec<_> = self.entries.values().cloned().collect();
        entries.sort_by_key(|entry| entry.txid.into_inner());
        entries
    }

    fn submit(&mut self, transaction: Transaction) -> Result<Admission, MempoolError> {
        self.submit_with_view(transaction, &UncheckedMempoolView)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("mempool is not implemented in the scaffold")]
    Unimplemented,
    #[error("transaction policy rejected input: {0}")]
    Policy(String),
    #[error("mempool view failed: {0}")]
    View(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{Address, Covenant, CovenantKind, Input, Output, Txid, Witness};
    use std::collections::HashSet;

    fn covenant() -> Covenant {
        Covenant {
            kind: CovenantKind::None,
            items: Vec::new(),
        }
    }

    fn output(value: u64) -> Output {
        Output {
            value,
            address: Address::new(0, vec![3; 20]).expect("address"),
            covenant: covenant(),
        }
    }

    fn outpoint(byte: u8, index: u32) -> Outpoint {
        Outpoint {
            txid: Txid::new([byte; 32]),
            index,
        }
    }

    fn transaction(previous_output: Outpoint) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(10)],
            locktime: 0,
        }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(50)],
            locktime: 0,
        }
    }

    #[derive(Default)]
    struct FixedView {
        coins: HashSet<Outpoint>,
    }

    impl FixedView {
        fn with_coin(outpoint: Outpoint) -> Self {
            Self {
                coins: HashSet::from([outpoint]),
            }
        }
    }

    impl MempoolView for FixedView {
        type Error = Infallible;

        fn has_coin(&self, outpoint: &Outpoint) -> Result<bool, Self::Error> {
            Ok(self.coins.contains(outpoint))
        }
    }

    #[test]
    fn memory_mempool_accepts_and_rejects_duplicate() {
        let transaction = transaction(outpoint(1, 0));
        let txid = transaction.txid();
        let mut mempool = MemoryMempool::new();

        assert_eq!(
            mempool.submit(transaction.clone()).expect("submit"),
            Admission::Accepted(txid)
        );
        assert!(matches!(
            mempool.submit(transaction).expect("duplicate"),
            Admission::Rejected { reason } if reason == "duplicate"
        ));

        assert_eq!(mempool.info().transaction_count, 1);
        assert_eq!(mempool.entries().len(), 1);
    }

    #[test]
    fn memory_mempool_rejects_coinbase_and_conflicts() {
        let mut mempool = MemoryMempool::new();
        assert!(matches!(
            mempool.submit(coinbase()).expect("coinbase"),
            Admission::Rejected { reason } if reason == "coinbase"
        ));

        let first = transaction(outpoint(2, 0));
        let mut second = transaction(outpoint(2, 0));
        second.locktime = 1;
        mempool.submit(first).expect("first");

        assert!(matches!(
            mempool.submit(second).expect("conflict"),
            Admission::Rejected { reason } if reason == "mempool-conflict"
        ));
    }

    #[test]
    fn memory_mempool_tracks_orphans_and_promotes_children() {
        let parent_prevout = outpoint(3, 0);
        let parent = transaction(parent_prevout.clone());
        let parent_output = Outpoint {
            txid: parent.txid(),
            index: 0,
        };
        let child = transaction(parent_output);
        let child_txid = child.txid();
        let mut mempool = MemoryMempool::new();
        let view = FixedView::with_coin(parent_prevout);

        assert_eq!(
            mempool.submit_with_view(child, &view).expect("child"),
            Admission::Orphan(child_txid)
        );
        assert_eq!(mempool.orphans(), vec![child_txid]);

        assert!(matches!(
            mempool.submit_with_view(parent, &view).expect("parent"),
            Admission::Accepted(_)
        ));
        assert!(mempool.orphan(&child_txid).is_none());
        assert!(mempool.transaction(&child_txid).is_some());
        assert_eq!(mempool.info().transaction_count, 2);
    }
}
