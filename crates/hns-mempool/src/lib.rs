#![forbid(unsafe_code)]

//! Bounded, dependency-aware Handshake mempool foundations.
//!
//! The pool deliberately separates structural admission, UTXO resolution,
//! script authorization, and contextual covenant/name validation. Production
//! callers must install complete verifiers; the default `submit` boundary
//! remains fail closed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use hns_consensus::{
    is_coinbase, is_final_transaction, transaction_sigops, transaction_weight,
    validate_transaction_sanity, verify_sequence_locks, verify_transaction_covenant_links,
    ConsensusError, SequenceLockView, TransactionInputVerifier, MAX_BLOCK_SIGOPS,
    WITNESS_SCALE_FACTOR,
};
use hns_primitives::{Amount, Coin, CovenantKind, Height, Outpoint, Transaction, Txid};
use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_TRANSACTIONS: usize = 50_000;
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_ORPHANS: usize = 1_024;
pub const DEFAULT_MAX_ORPHAN_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_ANCESTORS: usize = 25;
pub const DEFAULT_MAX_DESCENDANTS: usize = 25;
pub const MAX_MEMPOOL_TRANSACTIONS: usize = 250_000;
pub const MAX_MEMPOOL_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_ORPHANS: usize = 8_192;
pub const MAX_ORPHAN_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PACKAGE_MEMBERS: usize = 1_000;
pub const MAX_TX_SIGOPS: u32 = MAX_BLOCK_SIGOPS / 5;
pub const BYTES_PER_SIGOP: usize = 20;
/// HSD's pinned default minimum relay fee in atomic units per 1,000 policy
/// virtual bytes. Network-specific HSD defaults currently use this same value.
pub const HSD_MINIMUM_RELAY_FEE_RATE: Amount = 1_000;

/// HSD's mempool fee/ranking size is the larger of serialized transaction
/// weight and its sigop cost, rounded up to virtual bytes. Consensus block-fit
/// accounting continues to use the unadjusted transaction weight.
pub fn sigop_adjusted_virtual_size(transaction: &Transaction, sigops: u32) -> usize {
    let sigop_weight = u128::from(sigops) * (BYTES_PER_SIGOP as u128);
    let weight = (transaction_weight(transaction) as u128).max(sigop_weight);
    let size = (weight + (WITNESS_SCALE_FACTOR - 1) as u128) / WITNESS_SCALE_FACTOR as u128;
    usize::try_from(size).unwrap_or(usize::MAX)
}

/// Match HSD `policy.getMinFee`: use the floor of rate-times-policy-size and,
/// for any non-empty sub-kilobyte result, charge one full rate unit.
pub fn minimum_policy_fee(policy_size: usize, rate: Amount) -> Amount {
    if policy_size == 0 || rate == 0 {
        return 0;
    }
    let fee = u128::from(rate) * (policy_size as u128) / 1_000;
    if fee == 0 {
        rate
    } else {
        u64::try_from(fee).unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolLimits {
    pub maximum_transactions: usize,
    pub maximum_bytes: usize,
    pub maximum_orphans: usize,
    pub maximum_orphan_bytes: usize,
    pub maximum_ancestors: usize,
    pub maximum_descendants: usize,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            maximum_transactions: DEFAULT_MAX_TRANSACTIONS,
            maximum_bytes: DEFAULT_MAX_BYTES,
            maximum_orphans: DEFAULT_MAX_ORPHANS,
            maximum_orphan_bytes: DEFAULT_MAX_ORPHAN_BYTES,
            maximum_ancestors: DEFAULT_MAX_ANCESTORS,
            maximum_descendants: DEFAULT_MAX_DESCENDANTS,
        }
    }
}

impl MempoolLimits {
    pub fn validate(&self) -> Result<(), MempoolError> {
        if self.maximum_transactions == 0
            || self.maximum_bytes == 0
            || self.maximum_orphans == 0
            || self.maximum_orphan_bytes == 0
            || self.maximum_ancestors == 0
            || self.maximum_descendants == 0
        {
            return Err(MempoolError::Configuration(
                "mempool bounds must be non-zero".to_owned(),
            ));
        }
        if self.maximum_transactions > MAX_MEMPOOL_TRANSACTIONS {
            return Err(MempoolError::LimitExceeded {
                context: "mempool transactions",
                limit: MAX_MEMPOOL_TRANSACTIONS,
                actual: self.maximum_transactions,
            });
        }
        if self.maximum_bytes > MAX_MEMPOOL_BYTES {
            return Err(MempoolError::LimitExceeded {
                context: "mempool bytes",
                limit: MAX_MEMPOOL_BYTES,
                actual: self.maximum_bytes,
            });
        }
        if self.maximum_orphans > MAX_ORPHANS {
            return Err(MempoolError::LimitExceeded {
                context: "mempool orphans",
                limit: MAX_ORPHANS,
                actual: self.maximum_orphans,
            });
        }
        if self.maximum_orphan_bytes > MAX_ORPHAN_BYTES {
            return Err(MempoolError::LimitExceeded {
                context: "mempool orphan bytes",
                limit: MAX_ORPHAN_BYTES,
                actual: self.maximum_orphan_bytes,
            });
        }
        if self.maximum_ancestors > MAX_PACKAGE_MEMBERS
            || self.maximum_descendants > MAX_PACKAGE_MEMBERS
        {
            return Err(MempoolError::Configuration(format!(
                "ancestor and descendant limits may not exceed {MAX_PACKAGE_MEMBERS}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolContext {
    pub next_height: Height,
    pub parent_median_time: u64,
    pub coinbase_maturity: u32,
    /// Minimum fee in native atomic units per 1,000 HSD policy virtual bytes.
    pub minimum_relay_fee_rate: Amount,
    /// Production admission sets this to true. Tests and oracle harnesses may
    /// explicitly disable it while retaining every other admission check.
    pub require_complete_verifiers: bool,
}

impl MempoolContext {
    pub const fn testing(next_height: Height, parent_median_time: u64) -> Self {
        Self {
            next_height,
            parent_median_time,
            coinbase_maturity: 0,
            minimum_relay_fee_rate: 0,
            require_complete_verifiers: false,
        }
    }
}

/// Storage-independent contextual validation boundary. Complete production
/// implementations must verify deployment flags, name state, claims, airdrops,
/// and every policy which is intentionally outside transaction syntax.
pub trait ContextualTransactionVerifier: Send + Sync {
    fn verify(
        &self,
        transaction: &Transaction,
        input_coins: &[Coin],
        context: &MempoolContext,
        // Already accepted name-covenant transactions in deterministic
        // admission order. Contextual name validation replays this overlay.
        accepted_name_transactions: &[&Transaction],
    ) -> Result<(), ConsensusError>;

    fn is_consensus_complete(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RejectUnverifiedContext;

impl ContextualTransactionVerifier for RejectUnverifiedContext {
    fn verify(
        &self,
        _transaction: &Transaction,
        _input_coins: &[Coin],
        _context: &MempoolContext,
        _accepted_name_transactions: &[&Transaction],
    ) -> Result<(), ConsensusError> {
        Err(ConsensusError::Authorization(
            "contextual mempool verifier is not configured".to_owned(),
        ))
    }
}

/// Chain view required by admission. Mempool-created outputs are resolved by
/// the pool itself and are represented as unconfirmed sequence-lock inputs.
pub trait MempoolView: SequenceLockView {
    fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, ConsensusError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub txid: Txid,
    pub fee: Amount,
    pub base_size: usize,
    pub witness_size: usize,
    pub weight: usize,
    pub policy_size: usize,
    pub sigops: u32,
    pub opens: u32,
    pub updates: u32,
    pub renewals: u32,
    pub parents: Vec<Txid>,
    pub ancestor_count: usize,
    pub ancestor_fee: Amount,
    pub ancestor_weight: usize,
    pub ancestor_policy_size: usize,
    pub sequence: u64,
}

impl MempoolEntry {
    pub fn fee_rate_numerator(&self) -> Amount {
        self.fee
    }

    pub fn fee_rate_denominator(&self) -> usize {
        self.policy_size.max(1)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub transaction_count: usize,
    pub bytes: usize,
    pub total_fee: Amount,
    pub orphan_count: usize,
    pub orphan_bytes: usize,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Admission {
    Accepted(Txid),
    Rejected { reason: String },
    Orphan(Txid),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MempoolRevalidation {
    pub changed: bool,
    pub removed: usize,
    pub readmitted: usize,
    pub promoted_orphans: usize,
    pub retained_transactions: usize,
    pub retained_orphans: usize,
    pub generation: u64,
}

pub trait Mempool {
    fn info(&self) -> MempoolInfo;

    fn entries(&self) -> Vec<MempoolEntry>;

    /// The compatibility boundary intentionally rejects unverified input. Use
    /// `submit_with_context` for real admission.
    fn submit(&mut self, transaction: Transaction) -> Result<Admission, MempoolError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolPackage {
    pub txids: Vec<Txid>,
    pub fee: Amount,
    pub weight: usize,
    pub policy_size: usize,
    pub sigops: u32,
    pub opens: u32,
    pub updates: u32,
    pub renewals: u32,
    pub exclusive_names: Vec<[u8; 32]>,
    pub oldest_sequence: u64,
}

impl MempoolPackage {
    pub fn is_empty(&self) -> bool {
        self.txids.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct MempoolSnapshot {
    generation: u64,
    entries: BTreeMap<Txid, MempoolEntry>,
    transactions: BTreeMap<Txid, Transaction>,
    parents: BTreeMap<Txid, BTreeSet<Txid>>,
    exclusive_names: BTreeMap<Txid, Vec<[u8; 32]>>,
}

impl MempoolSnapshot {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    pub fn transaction(&self, txid: &Txid) -> Option<&Transaction> {
        self.transactions.get(txid)
    }

    pub fn txids(&self) -> impl Iterator<Item = Txid> + '_ {
        self.entries.keys().copied()
    }

    pub fn package_for(
        &self,
        txid: Txid,
        already_selected: &HashSet<Txid>,
    ) -> Result<MempoolPackage, MempoolError> {
        if !self.entries.contains_key(&txid) {
            return Err(MempoolError::UnknownTransaction(txid));
        }
        let mut visiting = HashSet::new();
        let mut ordered = Vec::new();
        self.visit_package(txid, already_selected, &mut visiting, &mut ordered)?;
        if ordered.len() > MAX_PACKAGE_MEMBERS {
            return Err(MempoolError::LimitExceeded {
                context: "template package members",
                limit: MAX_PACKAGE_MEMBERS,
                actual: ordered.len(),
            });
        }

        let mut fee = 0u64;
        let mut weight = 0usize;
        let mut policy_size = 0usize;
        let mut sigops = 0u32;
        let mut opens = 0u32;
        let mut updates = 0u32;
        let mut renewals = 0u32;
        let mut names = BTreeSet::new();
        let mut oldest_sequence = u64::MAX;
        for member in &ordered {
            let entry = self
                .entries
                .get(member)
                .ok_or(MempoolError::UnknownTransaction(*member))?;
            fee = fee
                .checked_add(entry.fee)
                .ok_or(MempoolError::FeeOverflow)?;
            weight = weight
                .checked_add(entry.weight)
                .ok_or(MempoolError::WeightOverflow)?;
            policy_size = policy_size
                .checked_add(entry.policy_size)
                .ok_or(MempoolError::WeightOverflow)?;
            sigops = sigops.saturating_add(entry.sigops);
            opens = opens.saturating_add(entry.opens);
            updates = updates.saturating_add(entry.updates);
            renewals = renewals.saturating_add(entry.renewals);
            oldest_sequence = oldest_sequence.min(entry.sequence);
            if let Some(member_names) = self.exclusive_names.get(member) {
                for name in member_names {
                    if !names.insert(*name) {
                        return Err(MempoolError::Policy(
                            "package contains conflicting exclusive name operations".to_owned(),
                        ));
                    }
                }
            }
        }

        Ok(MempoolPackage {
            txids: ordered,
            fee,
            weight,
            policy_size,
            sigops,
            opens,
            updates,
            renewals,
            exclusive_names: names.into_iter().collect(),
            oldest_sequence: if oldest_sequence == u64::MAX {
                0
            } else {
                oldest_sequence
            },
        })
    }

    fn visit_package(
        &self,
        txid: Txid,
        already_selected: &HashSet<Txid>,
        visiting: &mut HashSet<Txid>,
        ordered: &mut Vec<Txid>,
    ) -> Result<(), MempoolError> {
        if already_selected.contains(&txid) || ordered.contains(&txid) {
            return Ok(());
        }
        if !visiting.insert(txid) {
            return Err(MempoolError::DependencyCycle(txid));
        }
        if let Some(parents) = self.parents.get(&txid) {
            for parent in parents {
                self.visit_package(*parent, already_selected, visiting, ordered)?;
            }
        }
        visiting.remove(&txid);
        ordered.push(txid);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct OrphanEntry {
    transaction: Transaction,
    bytes: usize,
    sequence: u64,
}

struct ResolvedInputs {
    coins: Vec<Coin>,
    parents: BTreeSet<Txid>,
}

struct CovenantMetrics {
    opens: u32,
    updates: u32,
    renewals: u32,
    exclusive_names: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct MemoryMempool {
    limits: MempoolLimits,
    entries: HashMap<Txid, MempoolEntry>,
    transactions: HashMap<Txid, Transaction>,
    orphans: HashMap<Txid, OrphanEntry>,
    spent_outpoints: HashMap<Outpoint, Txid>,
    parents: HashMap<Txid, BTreeSet<Txid>>,
    children: HashMap<Txid, BTreeSet<Txid>>,
    exclusive_names: HashMap<Txid, Vec<[u8; 32]>>,
    exclusive_name_owners: HashMap<[u8; 32], Txid>,
    bytes: usize,
    orphan_bytes: usize,
    generation: u64,
    next_sequence: u64,
}

impl Default for MemoryMempool {
    fn default() -> Self {
        Self::with_limits(MempoolLimits::default()).expect("default mempool limits are valid")
    }
}

impl MemoryMempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: MempoolLimits) -> Result<Self, MempoolError> {
        limits.validate()?;
        Ok(Self {
            limits,
            entries: HashMap::new(),
            transactions: HashMap::new(),
            orphans: HashMap::new(),
            spent_outpoints: HashMap::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
            exclusive_names: HashMap::new(),
            exclusive_name_owners: HashMap::new(),
            bytes: 0,
            orphan_bytes: 0,
            generation: 0,
            next_sequence: 1,
        })
    }

    pub fn limits(&self) -> &MempoolLimits {
        &self.limits
    }

    pub fn transaction(&self, txid: &Txid) -> Option<&Transaction> {
        self.transactions.get(txid)
    }

    pub fn orphan(&self, txid: &Txid) -> Option<&Transaction> {
        self.orphans.get(txid).map(|entry| &entry.transaction)
    }

    pub fn orphans(&self) -> Vec<Txid> {
        let mut items = self
            .orphans
            .iter()
            .map(|(txid, entry)| (entry.sequence, *txid))
            .collect::<Vec<_>>();
        items.sort();
        items.into_iter().map(|(_, txid)| txid).collect()
    }

    pub fn snapshot(&self) -> MempoolSnapshot {
        MempoolSnapshot {
            generation: self.generation,
            entries: self
                .entries
                .iter()
                .map(|(txid, entry)| (*txid, entry.clone()))
                .collect(),
            transactions: self
                .transactions
                .iter()
                .map(|(txid, transaction)| (*txid, transaction.clone()))
                .collect(),
            parents: self
                .parents
                .iter()
                .map(|(txid, parents)| (*txid, parents.clone()))
                .collect(),
            exclusive_names: self
                .exclusive_names
                .iter()
                .map(|(txid, names)| (*txid, names.clone()))
                .collect(),
        }
    }

    pub fn submit_with_context<V: MempoolView>(
        &mut self,
        transaction: Transaction,
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
    ) -> Result<Admission, MempoolError> {
        let admission = self.submit_checked(
            transaction,
            context,
            view,
            input_verifier,
            contextual_verifier,
        )?;
        if matches!(admission, Admission::Accepted(_)) {
            self.promote_orphans(context, view, input_verifier, contextual_verifier)?;
        }
        Ok(admission)
    }

    /// Reconcile one newly connected active block and atomically revalidate
    /// every retained transaction against the resulting chain context. This
    /// mirrors HSD's post-block contract invalidation while also refreshing
    /// locks, maturity, scripts, fees, ancestry, and newly resolvable orphans.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_connected_with_context<V: MempoolView>(
        &mut self,
        connected_transactions: &[Transaction],
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
    ) -> Result<MempoolRevalidation, MempoolError> {
        self.reconcile_chain_transition_with_context(
            connected_transactions,
            &[],
            context,
            view,
            input_verifier,
            contextual_verifier,
        )
    }

    /// Rebuild the pool after an atomic chain transition. Transactions from
    /// disconnected blocks are considered before the prior pool so their
    /// older HSD name-state updates take precedence over newer conflicts.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_chain_transition_with_context<V: MempoolView>(
        &mut self,
        connected_transactions: &[Transaction],
        disconnected_transactions: &[Transaction],
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
    ) -> Result<MempoolRevalidation, MempoolError> {
        let previous_transactions = self.entries.keys().copied().collect::<BTreeSet<_>>();
        let previous_orphans = self.orphans.keys().copied().collect::<BTreeSet<_>>();
        let previous_generation = self.generation;

        let connected_txids = connected_transactions
            .iter()
            .map(Transaction::txid)
            .collect::<BTreeSet<_>>();
        let connected_spends = connected_transactions
            .iter()
            .flat_map(|transaction| {
                transaction
                    .inputs
                    .iter()
                    .map(|input| input.previous_output.clone())
            })
            .collect::<HashSet<_>>();

        let mut source = self.clone();
        source.remove_confirmed(connected_transactions);
        for txid in &connected_txids {
            source.remove_orphan(txid);
        }

        let accepted = source
            .entries
            .values()
            .map(|entry| (entry.sequence, entry.txid))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|(_, txid)| source.transactions.get(&txid).cloned())
            .collect::<Vec<_>>();
        let mut ordered_orphans = source
            .orphans
            .iter()
            .map(|(txid, orphan)| (orphan.sequence, *txid, orphan.transaction.clone()))
            .collect::<Vec<_>>();
        ordered_orphans.sort_by_key(|(sequence, txid, _)| (*sequence, *txid));
        let disconnected_txids = disconnected_transactions
            .iter()
            .map(Transaction::txid)
            .collect::<BTreeSet<_>>();
        let mut candidates = disconnected_transactions
            .iter()
            .cloned()
            .map(|transaction| (transaction, false))
            .collect::<Vec<_>>();
        candidates.extend(accepted.into_iter().map(|transaction| (transaction, false)));
        candidates.extend(
            ordered_orphans
                .into_iter()
                .map(|(_, _, transaction)| (transaction, true)),
        );
        let mut invalidated_transactions = previous_transactions
            .difference(&connected_txids)
            .filter(|txid| !source.entries.contains_key(txid))
            .copied()
            .collect::<HashSet<_>>();
        let mut candidate_txids = BTreeSet::new();
        let mut seen = HashSet::new();
        let mut rebuilt = Self::with_limits(self.limits.clone())?;
        for (transaction, allow_orphan) in candidates {
            let txid = transaction.txid();
            if !seen.insert(txid) {
                continue;
            }
            candidate_txids.insert(txid);
            if connected_txids.contains(&txid) {
                continue;
            }
            if disconnected_txids.contains(&txid) {
                invalidated_transactions.remove(&txid);
            }
            if transaction.inputs.iter().any(|input| {
                connected_spends.contains(&input.previous_output)
                    || invalidated_transactions.contains(&input.previous_output.txid)
            }) {
                invalidated_transactions.insert(txid);
                continue;
            }
            match rebuilt.submit_checked(
                transaction,
                context,
                view,
                input_verifier,
                contextual_verifier,
            )? {
                Admission::Accepted(_) => {}
                Admission::Orphan(_) if allow_orphan => {}
                Admission::Orphan(_) => {
                    rebuilt.remove_orphan(&txid);
                    invalidated_transactions.insert(txid);
                }
                Admission::Rejected { .. } => {
                    invalidated_transactions.insert(txid);
                }
            }
        }
        loop {
            let descendants = rebuilt
                .orphans
                .iter()
                .filter(|(_, orphan)| {
                    orphan.transaction.inputs.iter().any(|input| {
                        connected_spends.contains(&input.previous_output)
                            || invalidated_transactions.contains(&input.previous_output.txid)
                    })
                })
                .map(|(txid, _)| *txid)
                .collect::<Vec<_>>();
            if descendants.is_empty() {
                break;
            }
            for txid in descendants {
                rebuilt.remove_orphan(&txid);
                invalidated_transactions.insert(txid);
            }
        }
        rebuilt.promote_orphans(context, view, input_verifier, contextual_verifier)?;
        invalidated_transactions.extend(
            candidate_txids
                .difference(&connected_txids)
                .filter(|txid| {
                    !rebuilt.entries.contains_key(txid) && !rebuilt.orphans.contains_key(txid)
                })
                .copied(),
        );
        loop {
            let descendants =
                rebuilt
                    .orphans
                    .iter()
                    .filter(|(_, orphan)| {
                        orphan.transaction.inputs.iter().any(|input| {
                            invalidated_transactions.contains(&input.previous_output.txid)
                        })
                    })
                    .map(|(txid, _)| *txid)
                    .collect::<Vec<_>>();
            if descendants.is_empty() {
                break;
            }
            for txid in descendants {
                rebuilt.remove_orphan(&txid);
                invalidated_transactions.insert(txid);
            }
        }

        let retained_transactions = rebuilt.entries.keys().copied().collect::<BTreeSet<_>>();
        let retained_orphans = rebuilt.orphans.keys().copied().collect::<BTreeSet<_>>();
        let changed =
            retained_transactions != previous_transactions || retained_orphans != previous_orphans;
        let previous_members = previous_transactions
            .union(&previous_orphans)
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_members = retained_transactions
            .union(&retained_orphans)
            .copied()
            .collect::<BTreeSet<_>>();
        let removed = previous_members.difference(&retained_members).count();
        let readmitted = disconnected_txids
            .intersection(&retained_transactions)
            .count();
        let promoted_orphans = previous_orphans
            .intersection(&retained_transactions)
            .count();
        let generation = if changed {
            previous_generation.saturating_add(1).max(1)
        } else {
            previous_generation
        };
        if changed {
            rebuilt.generation = generation;
            *self = rebuilt;
        }
        Ok(MempoolRevalidation {
            changed,
            removed,
            readmitted,
            promoted_orphans,
            retained_transactions: retained_transactions.len(),
            retained_orphans: retained_orphans.len(),
            generation,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_checked<V: MempoolView>(
        &mut self,
        transaction: Transaction,
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
    ) -> Result<Admission, MempoolError> {
        let txid = transaction.txid();
        if self.entries.contains_key(&txid) || self.orphans.contains_key(&txid) {
            return Ok(rejected("duplicate"));
        }
        if let Err(error) = validate_transaction_sanity(&transaction) {
            return Ok(rejected(error.to_string()));
        }
        if is_coinbase(&transaction) {
            return Ok(rejected("coinbase"));
        }
        let covenant_metrics = match covenant_metrics(&transaction) {
            Ok(metrics) => metrics,
            Err(error) => return Ok(rejected(error.to_string())),
        };
        if covenant_metrics
            .exclusive_names
            .iter()
            .any(|name| self.exclusive_name_owners.contains_key(name))
        {
            return Ok(rejected("name-already-in-mempool"));
        }
        if !is_final_transaction(
            &transaction,
            context.next_height,
            context.parent_median_time,
        ) {
            return Ok(rejected("non-final"));
        }
        if self.conflicts_with_mempool(&transaction) {
            return Ok(rejected("mempool-conflict"));
        }

        let resolved = self.resolve_inputs(&transaction, view)?;
        let Some(ResolvedInputs {
            coins: input_coins,
            parents: direct_parents,
        }) = resolved
        else {
            return if self.insert_orphan(transaction)? {
                Ok(Admission::Orphan(txid))
            } else {
                Ok(rejected("orphan-capacity"))
            };
        };

        if context.require_complete_verifiers
            && (!input_verifier.is_consensus_complete()
                || !contextual_verifier.is_consensus_complete())
        {
            return Ok(rejected("consensus-verifier-incomplete"));
        }

        for coin in &input_coins {
            if coin.coinbase {
                let depth = context.next_height.checked_sub(coin.height);
                if depth.is_none_or(|depth| depth < context.coinbase_maturity) {
                    return Ok(rejected("premature-coinbase-spend"));
                }
            }
        }

        let sequence_view = AdmissionSequenceView {
            pool: self,
            base: view,
        };
        if !verify_sequence_locks(
            &transaction,
            context.next_height,
            context.parent_median_time,
            &sequence_view,
        )
        .map_err(|error| MempoolError::Consensus(error.to_string()))?
        {
            return Ok(rejected("non-BIP68-final"));
        }

        let sigops = transaction_sigops(&transaction, &input_coins)
            .map_err(|error| MempoolError::Consensus(error.to_string()))?;
        if sigops > MAX_TX_SIGOPS {
            return Ok(rejected("bad-txns-too-many-sigops"));
        }

        for (index, coin) in input_coins.iter().enumerate() {
            if let Err(error) = input_verifier.verify_input(&transaction, index, coin) {
                return Ok(rejected(error.to_string()));
            }
        }
        if let Err(error) = verify_transaction_covenant_links(&transaction, &input_coins) {
            return Ok(rejected(error.to_string()));
        }
        let accepted_name_transactions = self.accepted_name_transactions();
        if let Err(error) = contextual_verifier.verify(
            &transaction,
            &input_coins,
            context,
            &accepted_name_transactions,
        ) {
            return Ok(rejected(error.to_string()));
        }

        let input_value = input_coins.iter().try_fold(0u64, |total, coin| {
            total
                .checked_add(coin.value)
                .ok_or(MempoolError::FeeOverflow)
        })?;
        let output_value = transaction.outputs.iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.value)
                .ok_or(MempoolError::FeeOverflow)
        })?;
        let Some(fee) = input_value.checked_sub(output_value) else {
            return Ok(rejected("input-value-below-output-value"));
        };
        let weight = transaction_weight(&transaction);
        let policy_size = sigop_adjusted_virtual_size(&transaction, sigops);
        let minimum_fee = minimum_policy_fee(policy_size, context.minimum_relay_fee_rate);
        if fee < minimum_fee {
            return Ok(rejected("insufficient-fee"));
        }

        let ancestors = self.collect_ancestors(&direct_parents)?;
        if ancestors.len() > self.limits.maximum_ancestors {
            return Ok(rejected("too-many-ancestors"));
        }
        for ancestor in &ancestors {
            if self.descendant_count(*ancestor)? >= self.limits.maximum_descendants {
                return Ok(rejected("too-many-descendants"));
            }
        }

        let encoded_size = transaction.encode().len();
        if self.entries.len() >= self.limits.maximum_transactions {
            return Ok(rejected("mempool-full"));
        }
        let projected_bytes = self
            .bytes
            .checked_add(encoded_size)
            .ok_or(MempoolError::WeightOverflow)?;
        if projected_bytes > self.limits.maximum_bytes {
            return Ok(rejected("mempool-full"));
        }

        let CovenantMetrics {
            opens,
            updates,
            renewals,
            exclusive_names,
        } = covenant_metrics;
        let ancestor_fee = ancestors.iter().try_fold(fee, |total, ancestor| {
            total
                .checked_add(
                    self.entries
                        .get(ancestor)
                        .ok_or(MempoolError::UnknownTransaction(*ancestor))?
                        .fee,
                )
                .ok_or(MempoolError::FeeOverflow)
        })?;
        let ancestor_weight = ancestors.iter().try_fold(weight, |total, ancestor| {
            total
                .checked_add(
                    self.entries
                        .get(ancestor)
                        .ok_or(MempoolError::UnknownTransaction(*ancestor))?
                        .weight,
                )
                .ok_or(MempoolError::WeightOverflow)
        })?;
        let ancestor_policy_size = ancestors.iter().try_fold(policy_size, |total, ancestor| {
            total
                .checked_add(
                    self.entries
                        .get(ancestor)
                        .ok_or(MempoolError::UnknownTransaction(*ancestor))?
                        .policy_size,
                )
                .ok_or(MempoolError::WeightOverflow)
        })?;
        let sequence = self.take_sequence();
        let entry = MempoolEntry {
            txid,
            fee,
            base_size: transaction.base_size(),
            witness_size: transaction.witness_size(),
            weight,
            policy_size,
            sigops,
            opens,
            updates,
            renewals,
            parents: direct_parents.iter().copied().collect(),
            ancestor_count: ancestors.len(),
            ancestor_fee,
            ancestor_weight,
            ancestor_policy_size,
            sequence,
        };

        for input in &transaction.inputs {
            self.spent_outpoints
                .insert(input.previous_output.clone(), txid);
        }
        for parent in &direct_parents {
            self.children.entry(*parent).or_default().insert(txid);
        }
        self.parents.insert(txid, direct_parents);
        self.children.entry(txid).or_default();
        for name in &exclusive_names {
            self.exclusive_name_owners.insert(*name, txid);
        }
        self.exclusive_names.insert(txid, exclusive_names);
        self.bytes = projected_bytes;
        self.entries.insert(txid, entry);
        self.transactions.insert(txid, transaction);
        self.advance_generation();
        Ok(Admission::Accepted(txid))
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_orphans<V: MempoolView>(
        &mut self,
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
    ) -> Result<(), MempoolError> {
        loop {
            let ordered = self
                .orphans
                .iter()
                .map(|(txid, entry)| (entry.sequence, *txid))
                .collect::<BTreeSet<_>>();
            let mut promoted = false;
            for (_, txid) in ordered {
                let Some(orphan) = self.remove_orphan(&txid) else {
                    continue;
                };
                match self.submit_checked(
                    orphan.transaction,
                    context,
                    view,
                    input_verifier,
                    contextual_verifier,
                )? {
                    Admission::Accepted(_) => promoted = true,
                    Admission::Orphan(_) | Admission::Rejected { .. } => {}
                }
            }
            if !promoted {
                return Ok(());
            }
        }
    }

    /// Remove every accepted and orphan transaction while retaining the
    /// configured resource bounds. This is the fail-closed reconciliation path
    /// for reorganizations until disconnected transactions can be contextually
    /// re-admitted through the complete consensus verifier.
    pub fn clear(&mut self) -> usize {
        let removed = self.entries.len().saturating_add(self.orphans.len());
        if removed == 0 {
            return 0;
        }
        self.entries.clear();
        self.transactions.clear();
        self.orphans.clear();
        self.spent_outpoints.clear();
        self.parents.clear();
        self.children.clear();
        self.exclusive_names.clear();
        self.exclusive_name_owners.clear();
        self.bytes = 0;
        self.orphan_bytes = 0;
        self.advance_generation();
        removed
    }

    pub fn remove_transaction(&mut self, txid: Txid, include_descendants: bool) -> usize {
        let removed = self.remove_transaction_without_generation(txid, include_descendants);
        if removed > 0 {
            self.advance_generation();
        }
        removed
    }

    /// Reconcile transactions included in a connected block. Included entries
    /// are removed while their children remain eligible against the new chain
    /// view. Conflicting entries and their descendants are removed. One block
    /// reconciliation advances the immutable mempool generation at most once.
    pub fn remove_confirmed(&mut self, transactions: &[Transaction]) -> usize {
        let mut removed = 0;
        for transaction in transactions {
            let confirmed_txid = transaction.txid();
            let conflicts = transaction
                .inputs
                .iter()
                .filter_map(|input| self.spent_outpoints.get(&input.previous_output).copied())
                .filter(|conflict| *conflict != confirmed_txid)
                .collect::<BTreeSet<_>>();
            for conflict in conflicts {
                removed += self.remove_transaction_without_generation(conflict, true);
            }
            if self.remove_entry_only(confirmed_txid) {
                removed += 1;
            }
        }
        if removed > 0 {
            self.advance_generation();
        }
        removed
    }

    fn remove_transaction_without_generation(
        &mut self,
        txid: Txid,
        include_descendants: bool,
    ) -> usize {
        let mut removals = if include_descendants {
            self.collect_descendants(txid).unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        removals.insert(txid);
        let mut ordered = removals.into_iter().collect::<Vec<_>>();
        ordered.sort_by_key(|member| {
            std::cmp::Reverse(
                self.entries
                    .get(member)
                    .map_or(0, |entry| entry.ancestor_count),
            )
        });
        let mut removed = 0;
        for member in ordered {
            if self.remove_entry_only(member) {
                removed += 1;
            }
        }
        removed
    }

    fn resolve_inputs<V: MempoolView>(
        &self,
        transaction: &Transaction,
        view: &V,
    ) -> Result<Option<ResolvedInputs>, MempoolError> {
        let mut coins = Vec::with_capacity(transaction.inputs.len());
        let mut parents = BTreeSet::new();
        for input in &transaction.inputs {
            if let Some(parent) = self.transactions.get(&input.previous_output.txid) {
                let Some(output) = parent.outputs.get(input.previous_output.index as usize) else {
                    return Ok(None);
                };
                parents.insert(input.previous_output.txid);
                coins.push(Coin {
                    outpoint: input.previous_output.clone(),
                    value: output.value,
                    height: 0,
                    coinbase: false,
                    address: output.address.clone(),
                    covenant: output.covenant.clone(),
                });
                continue;
            }
            let Some(coin) = view
                .coin(&input.previous_output)
                .map_err(|error| MempoolError::View(error.to_string()))?
            else {
                return Ok(None);
            };
            coins.push(coin);
        }
        Ok(Some(ResolvedInputs { coins, parents }))
    }

    fn insert_orphan(&mut self, transaction: Transaction) -> Result<bool, MempoolError> {
        let txid = transaction.txid();
        let bytes = transaction.encode().len();
        if bytes > self.limits.maximum_orphan_bytes {
            return Ok(false);
        }
        while self.orphans.len() >= self.limits.maximum_orphans
            || self.orphan_bytes.saturating_add(bytes) > self.limits.maximum_orphan_bytes
        {
            let oldest = self
                .orphans
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(txid, _)| *txid);
            let Some(oldest) = oldest else {
                break;
            };
            self.remove_orphan(&oldest);
        }
        if self.orphans.len() >= self.limits.maximum_orphans
            || self.orphan_bytes.saturating_add(bytes) > self.limits.maximum_orphan_bytes
        {
            return Ok(false);
        }
        let sequence = self.take_sequence();
        self.orphan_bytes = self.orphan_bytes.saturating_add(bytes);
        self.orphans.insert(
            txid,
            OrphanEntry {
                transaction,
                bytes,
                sequence,
            },
        );
        Ok(true)
    }

    fn remove_orphan(&mut self, txid: &Txid) -> Option<OrphanEntry> {
        let orphan = self.orphans.remove(txid)?;
        self.orphan_bytes = self.orphan_bytes.saturating_sub(orphan.bytes);
        Some(orphan)
    }

    fn conflicts_with_mempool(&self, transaction: &Transaction) -> bool {
        let mut seen = HashSet::new();
        transaction.inputs.iter().any(|input| {
            !seen.insert(input.previous_output.clone())
                || self.spent_outpoints.contains_key(&input.previous_output)
        })
    }

    fn accepted_name_transactions(&self) -> Vec<&Transaction> {
        let mut ordered = self
            .entries
            .iter()
            .filter_map(|(txid, entry)| {
                let transaction = self.transactions.get(txid)?;
                transaction
                    .outputs
                    .iter()
                    .any(|output| output.covenant.kind.is_name())
                    .then_some((entry.sequence, *txid, transaction))
            })
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(sequence, txid, _)| (*sequence, *txid));
        ordered
            .into_iter()
            .map(|(_, _, transaction)| transaction)
            .collect()
    }

    fn collect_ancestors(
        &self,
        direct_parents: &BTreeSet<Txid>,
    ) -> Result<BTreeSet<Txid>, MempoolError> {
        let mut ancestors = BTreeSet::new();
        let mut pending = direct_parents.iter().copied().collect::<Vec<_>>();
        while let Some(parent) = pending.pop() {
            if !ancestors.insert(parent) {
                continue;
            }
            if ancestors.len() > MAX_PACKAGE_MEMBERS {
                return Err(MempoolError::LimitExceeded {
                    context: "mempool ancestors",
                    limit: MAX_PACKAGE_MEMBERS,
                    actual: ancestors.len(),
                });
            }
            let parent_parents = self
                .parents
                .get(&parent)
                .ok_or(MempoolError::UnknownTransaction(parent))?;
            pending.extend(parent_parents.iter().copied());
        }
        Ok(ancestors)
    }

    fn collect_descendants(&self, txid: Txid) -> Result<BTreeSet<Txid>, MempoolError> {
        let mut descendants = BTreeSet::new();
        let mut pending = self
            .children
            .get(&txid)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        while let Some(child) = pending.pop() {
            if !descendants.insert(child) {
                continue;
            }
            if descendants.len() > MAX_PACKAGE_MEMBERS {
                return Err(MempoolError::LimitExceeded {
                    context: "mempool descendants",
                    limit: MAX_PACKAGE_MEMBERS,
                    actual: descendants.len(),
                });
            }
            if let Some(children) = self.children.get(&child) {
                pending.extend(children.iter().copied());
            }
        }
        Ok(descendants)
    }

    fn descendant_count(&self, txid: Txid) -> Result<usize, MempoolError> {
        Ok(self.collect_descendants(txid)?.len())
    }

    fn remove_entry_only(&mut self, txid: Txid) -> bool {
        let Some(transaction) = self.transactions.remove(&txid) else {
            return false;
        };
        let affected_descendants = self
            .collect_descendants(txid)
            .expect("accepted mempool descendants stay within configured bounds");
        let Some(_entry) = self.entries.remove(&txid) else {
            self.transactions.insert(txid, transaction);
            return false;
        };
        self.bytes = self.bytes.saturating_sub(transaction.encode().len());
        for input in &transaction.inputs {
            if self.spent_outpoints.get(&input.previous_output) == Some(&txid) {
                self.spent_outpoints.remove(&input.previous_output);
            }
        }
        if let Some(parents) = self.parents.remove(&txid) {
            for parent in parents {
                if let Some(children) = self.children.get_mut(&parent) {
                    children.remove(&txid);
                }
            }
        }
        if let Some(children) = self.children.remove(&txid) {
            for child in children {
                if let Some(parents) = self.parents.get_mut(&child) {
                    parents.remove(&txid);
                }
            }
        }
        self.refresh_cached_ancestry(&affected_descendants);
        if let Some(names) = self.exclusive_names.remove(&txid) {
            for name in names {
                if self.exclusive_name_owners.get(&name) == Some(&txid) {
                    self.exclusive_name_owners.remove(&name);
                }
            }
        }
        true
    }

    fn refresh_cached_ancestry(&mut self, descendants: &BTreeSet<Txid>) {
        for txid in descendants {
            let direct_parents = self
                .parents
                .get(txid)
                .cloned()
                .expect("accepted mempool entry has a parent set");
            let ancestors = self
                .collect_ancestors(&direct_parents)
                .expect("accepted mempool ancestry stays within configured bounds");
            let current = self
                .entries
                .get(txid)
                .expect("retained descendant has a mempool entry");
            let ancestor_fee = ancestors.iter().fold(current.fee, |total, ancestor| {
                total
                    .checked_add(
                        self.entries
                            .get(ancestor)
                            .expect("retained ancestor has a mempool entry")
                            .fee,
                    )
                    .expect("admitted ancestry fee remains representable")
            });
            let ancestor_weight = ancestors.iter().fold(current.weight, |total, ancestor| {
                total
                    .checked_add(
                        self.entries
                            .get(ancestor)
                            .expect("retained ancestor has a mempool entry")
                            .weight,
                    )
                    .expect("admitted ancestry weight remains representable")
            });
            let ancestor_policy_size =
                ancestors
                    .iter()
                    .fold(current.policy_size, |total, ancestor| {
                        total
                            .checked_add(
                                self.entries
                                    .get(ancestor)
                                    .expect("retained ancestor has a mempool entry")
                                    .policy_size,
                            )
                            .expect("admitted ancestry policy size remains representable")
                    });
            let entry = self
                .entries
                .get_mut(txid)
                .expect("retained descendant has a mutable mempool entry");
            entry.parents = direct_parents.into_iter().collect();
            entry.ancestor_count = ancestors.len();
            entry.ancestor_fee = ancestor_fee;
            entry.ancestor_weight = ancestor_weight;
            entry.ancestor_policy_size = ancestor_policy_size;
        }
    }

    fn take_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1).max(1);
        sequence
    }

    fn advance_generation(&mut self) {
        self.generation = self.generation.saturating_add(1).max(1);
    }
}

impl Mempool for MemoryMempool {
    fn info(&self) -> MempoolInfo {
        MempoolInfo {
            transaction_count: self.entries.len(),
            bytes: self.bytes,
            total_fee: self
                .entries
                .values()
                .fold(0u64, |total, entry| total.saturating_add(entry.fee)),
            orphan_count: self.orphans.len(),
            orphan_bytes: self.orphan_bytes,
            generation: self.generation,
        }
    }

    fn entries(&self) -> Vec<MempoolEntry> {
        let mut entries = self.entries.values().cloned().collect::<Vec<_>>();
        entries.sort_by_key(|entry| (entry.sequence, entry.txid));
        entries
    }

    fn submit(&mut self, _transaction: Transaction) -> Result<Admission, MempoolError> {
        Ok(rejected("verified-mempool-context-required"))
    }
}

struct AdmissionSequenceView<'a, V> {
    pool: &'a MemoryMempool,
    base: &'a V,
}

impl<V: MempoolView> SequenceLockView for AdmissionSequenceView<'_, V> {
    fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
        if self.pool.transactions.contains_key(&outpoint.txid) {
            return Ok(None);
        }
        self.base.coin_height(outpoint)
    }

    fn median_time_past(&self, height: Height) -> Result<u64, ConsensusError> {
        self.base.median_time_past(height)
    }
}

fn rejected(reason: impl Into<String>) -> Admission {
    Admission::Rejected {
        reason: reason.into(),
    }
}

fn covenant_metrics(transaction: &Transaction) -> Result<CovenantMetrics, MempoolError> {
    let mut opens = 0u32;
    let mut updates = 0u32;
    let mut renewals = 0u32;
    let mut names = BTreeSet::new();
    for output in &transaction.outputs {
        match output.covenant.kind {
            CovenantKind::Open => {
                opens = opens.saturating_add(1);
                updates = updates.saturating_add(1);
            }
            CovenantKind::Claim
            | CovenantKind::Update
            | CovenantKind::Transfer
            | CovenantKind::Revoke => updates = updates.saturating_add(1),
            CovenantKind::Register | CovenantKind::Renew | CovenantKind::Finalize => {
                renewals = renewals.saturating_add(1)
            }
            _ => {}
        }
        if matches!(
            output.covenant.kind,
            CovenantKind::Claim
                | CovenantKind::Open
                | CovenantKind::Register
                | CovenantKind::Update
                | CovenantKind::Renew
                | CovenantKind::Transfer
                | CovenantKind::Finalize
                | CovenantKind::Revoke
        ) {
            let name_hash: [u8; 32] = output
                .covenant
                .item(0)
                .ok_or_else(|| MempoolError::Policy("name covenant has no hash".to_owned()))?
                .try_into()
                .map_err(|_| MempoolError::Policy("name covenant hash length".to_owned()))?;
            names.insert(name_hash);
        }
    }
    Ok(CovenantMetrics {
        opens,
        updates,
        renewals,
        exclusive_names: names.into_iter().collect(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("mempool configuration failed: {0}")]
    Configuration(String),
    #[error("mempool consensus validation failed: {0}")]
    Consensus(String),
    #[error("mempool dependency graph contains a cycle at {0:?}")]
    DependencyCycle(Txid),
    #[error("mempool fee arithmetic overflow")]
    FeeOverflow,
    #[error("{context} limit exceeded: limit {limit}, actual {actual}")]
    LimitExceeded {
        context: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("transaction policy rejected input: {0}")]
    Policy(String),
    #[error("mempool transaction {0:?} is unknown")]
    UnknownTransaction(Txid),
    #[error("mempool view failed: {0}")]
    View(String),
    #[error("mempool weight arithmetic overflow")]
    WeightOverflow,
}

#[cfg(test)]
mod tests {
    use hns_primitives::MAX_BLOCK_WEIGHT;

    use super::*;
    use hns_consensus::{ConsensusError, TransactionInputVerifier};
    use hns_primitives::{sha3_256, Address, Covenant, Input, Output, Witness};

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

    fn transaction(previous_output: Outpoint, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output(value)],
            locktime: 0,
        }
    }

    #[derive(Default)]
    struct FixedView {
        coins: HashMap<Outpoint, Coin>,
        times: HashMap<Height, u64>,
    }

    impl FixedView {
        fn with_coin(outpoint: Outpoint, value: Amount) -> Self {
            let coin = Coin {
                outpoint: outpoint.clone(),
                value,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            };
            Self {
                coins: HashMap::from([(outpoint, coin)]),
                times: HashMap::from([(0, 0), (1, 1), (2, 2)]),
            }
        }
    }

    impl SequenceLockView for FixedView {
        fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
            Ok(self.coins.get(outpoint).map(|coin| coin.height))
        }

        fn median_time_past(&self, height: Height) -> Result<u64, ConsensusError> {
            Ok(self.times.get(&height).copied().unwrap_or(0))
        }
    }

    impl MempoolView for FixedView {
        fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, ConsensusError> {
            Ok(self.coins.get(outpoint).cloned())
        }
    }

    struct FailingView;

    impl SequenceLockView for FailingView {
        fn coin_height(&self, _outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
            Err(ConsensusError::View("injected view failure".to_owned()))
        }

        fn median_time_past(&self, _height: Height) -> Result<u64, ConsensusError> {
            Err(ConsensusError::View("injected view failure".to_owned()))
        }
    }

    impl MempoolView for FailingView {
        fn coin(&self, _outpoint: &Outpoint) -> Result<Option<Coin>, ConsensusError> {
            Err(ConsensusError::View("injected view failure".to_owned()))
        }
    }

    #[derive(Clone, Copy)]
    struct AllowInputs;

    impl TransactionInputVerifier for AllowInputs {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct AllowContext;

    impl ContextualTransactionVerifier for AllowContext {
        fn verify(
            &self,
            _transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            _accepted_name_transactions: &[&Transaction],
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    struct RequireNameOverlay;

    impl ContextualTransactionVerifier for RequireNameOverlay {
        fn verify(
            &self,
            transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            accepted_name_transactions: &[&Transaction],
        ) -> Result<(), ConsensusError> {
            let name = transaction
                .outputs
                .first()
                .and_then(|output| output.covenant.item(2))
                .unwrap_or_default();
            let expected = usize::from(name == b"overlay-two");
            if accepted_name_transactions.len() != expected {
                return Err(ConsensusError::ContextualCovenant(format!(
                    "expected {expected} accepted name transactions, got {}",
                    accepted_name_transactions.len()
                )));
            }
            Ok(())
        }
    }

    struct RejectName(&'static [u8]);

    impl ContextualTransactionVerifier for RejectName {
        fn verify(
            &self,
            transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            _accepted_name_transactions: &[&Transaction],
        ) -> Result<(), ConsensusError> {
            let rejected = transaction
                .outputs
                .iter()
                .any(|output| output.covenant.item(2) == Some(self.0));
            if rejected {
                return Err(ConsensusError::ContextualCovenant(
                    "name invalidated by new active context".to_owned(),
                ));
            }
            Ok(())
        }
    }

    fn open_transaction(previous_output: Outpoint, value: u64, name: &[u8]) -> Transaction {
        let mut transaction = transaction(previous_output, value);
        transaction.outputs[0].covenant = Covenant {
            kind: CovenantKind::Open,
            items: vec![
                sha3_256(name).to_vec(),
                0u32.to_le_bytes().to_vec(),
                name.to_vec(),
            ],
        };
        transaction
    }

    fn submit(pool: &mut MemoryMempool, transaction: Transaction, view: &FixedView) -> Admission {
        pool.submit_with_context(
            transaction,
            &MempoolContext::testing(2, 2),
            view,
            &AllowInputs,
            &AllowContext,
        )
        .expect("admission")
    }

    #[test]
    fn compatibility_submit_is_fail_closed() {
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            pool.submit(transaction(outpoint(1, 0), 9)).expect("submit"),
            Admission::Rejected { reason } if reason == "verified-mempool-context-required"
        ));
    }

    #[test]
    fn contextual_verifier_receives_name_transactions_in_admission_order() {
        let first_input = outpoint(0xd1, 0);
        let second_input = outpoint(0xd2, 0);
        let mut view = FixedView::with_coin(first_input.clone(), 20);
        let second_coin = Coin {
            outpoint: second_input.clone(),
            value: 20,
            height: 1,
            coinbase: false,
            address: Address::new(0, vec![3; 20]).expect("address"),
            covenant: covenant(),
        };
        view.coins.insert(second_input.clone(), second_coin);
        let mut pool = MemoryMempool::new();
        let context = MempoolContext::testing(2, 2);
        assert!(matches!(
            pool.submit_with_context(
                open_transaction(first_input, 15, b"overlay-one"),
                &context,
                &view,
                &AllowInputs,
                &RequireNameOverlay,
            )
            .expect("first name admission"),
            Admission::Accepted(_)
        ));
        assert!(matches!(
            pool.submit_with_context(
                open_transaction(second_input, 15, b"overlay-two"),
                &context,
                &view,
                &AllowInputs,
                &RequireNameOverlay,
            )
            .expect("second name admission"),
            Admission::Accepted(_)
        ));
    }

    #[test]
    fn exclusive_name_index_releases_when_transaction_is_removed() {
        let first_input = outpoint(0xe1, 0);
        let replacement_input = outpoint(0xe2, 0);
        let mut view = FixedView::with_coin(first_input.clone(), 20);
        view.coins.insert(
            replacement_input.clone(),
            Coin {
                outpoint: replacement_input.clone(),
                value: 20,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            },
        );
        let first = open_transaction(first_input, 15, b"exclusive-name");
        let first_txid = first.txid();
        let replacement = open_transaction(replacement_input, 15, b"exclusive-name");
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, first, &view),
            Admission::Accepted(txid) if txid == first_txid
        ));
        assert!(matches!(
            submit(&mut pool, replacement.clone(), &view),
            Admission::Rejected { reason } if reason == "name-already-in-mempool"
        ));
        assert_eq!(pool.remove_transaction(first_txid, false), 1);
        assert!(matches!(
            submit(&mut pool, replacement, &view),
            Admission::Accepted(_)
        ));
    }

    #[test]
    fn connected_block_revalidation_atomically_removes_stale_context() {
        let stale_input = outpoint(0xf1, 0);
        let retained_input = outpoint(0xf2, 0);
        let mut view = FixedView::with_coin(stale_input.clone(), 20);
        view.coins.insert(
            retained_input.clone(),
            Coin {
                outpoint: retained_input.clone(),
                value: 20,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            },
        );
        let stale = open_transaction(stale_input, 15, b"stale-context");
        let stale_txid = stale.txid();
        let retained = open_transaction(retained_input, 15, b"retained-context");
        let retained_txid = retained.txid();
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, stale, &view),
            Admission::Accepted(_)
        ));
        assert!(matches!(
            submit(&mut pool, retained, &view),
            Admission::Accepted(_)
        ));
        let previous_generation = pool.info().generation;
        let summary = pool
            .reconcile_connected_with_context(
                &[],
                &MempoolContext::testing(3, 3),
                &view,
                &AllowInputs,
                &RejectName(b"stale-context"),
            )
            .expect("revalidation");
        assert!(summary.changed);
        assert_eq!(summary.removed, 1);
        assert_eq!(summary.retained_transactions, 1);
        assert_eq!(summary.retained_orphans, 0);
        assert_eq!(summary.generation, previous_generation + 1);
        assert!(pool.transaction(&stale_txid).is_none());
        assert!(pool.transaction(&retained_txid).is_some());

        let stable = pool
            .reconcile_connected_with_context(
                &[],
                &MempoolContext::testing(3, 3),
                &view,
                &AllowInputs,
                &RejectName(b"stale-context"),
            )
            .expect("stable revalidation");
        assert!(!stable.changed);
        assert_eq!(stable.generation, summary.generation);
    }

    #[test]
    fn connected_block_revalidation_promotes_newly_resolvable_orphan() {
        let input = outpoint(0xf3, 0);
        let transaction = transaction(input.clone(), 9);
        let txid = transaction.txid();
        let mut view = FixedView::default();
        let mut pool = MemoryMempool::new();
        assert_eq!(
            submit(&mut pool, transaction, &view),
            Admission::Orphan(txid)
        );
        view.coins.insert(
            input.clone(),
            Coin {
                outpoint: input,
                value: 20,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            },
        );
        let previous_generation = pool.info().generation;
        let summary = pool
            .reconcile_connected_with_context(
                &[],
                &MempoolContext::testing(3, 3),
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("revalidation");
        assert!(summary.changed);
        assert_eq!(summary.promoted_orphans, 1);
        assert_eq!(summary.retained_transactions, 1);
        assert_eq!(summary.retained_orphans, 0);
        assert_eq!(summary.generation, previous_generation + 1);
        assert!(pool.orphan(&txid).is_none());
        assert!(pool.transaction(&txid).is_some());
    }

    #[test]
    fn connected_block_revalidation_removes_orphaned_conflict_descendants() {
        let parent_input = outpoint(0xf4, 0);
        let missing_input = outpoint(0xf5, 0);
        let view = FixedView::with_coin(parent_input.clone(), 20);
        let parent = transaction(parent_input.clone(), 15);
        let parent_txid = parent.txid();
        let mut orphan = transaction(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            10,
        );
        orphan.inputs.push(Input {
            previous_output: missing_input,
            sequence: u32::MAX,
            witness: Witness::default(),
        });
        let orphan_txid = orphan.txid();
        let orphan_descendant = transaction(
            Outpoint {
                txid: orphan_txid,
                index: 0,
            },
            5,
        );
        let orphan_descendant_txid = orphan_descendant.txid();
        let conflicting_block_transaction = transaction(parent_input, 14);
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, parent, &view),
            Admission::Accepted(_)
        ));
        assert_eq!(
            submit(&mut pool, orphan, &view),
            Admission::Orphan(orphan_txid)
        );
        assert_eq!(
            submit(&mut pool, orphan_descendant, &view),
            Admission::Orphan(orphan_descendant_txid)
        );

        let previous_generation = pool.info().generation;
        let summary = pool
            .reconcile_connected_with_context(
                &[conflicting_block_transaction],
                &MempoolContext::testing(3, 3),
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("revalidation");
        assert!(summary.changed);
        assert_eq!(summary.removed, 3);
        assert_eq!(summary.retained_transactions, 0);
        assert_eq!(summary.retained_orphans, 0);
        assert_eq!(summary.generation, previous_generation + 1);
        assert!(pool.transaction(&parent_txid).is_none());
        assert!(pool.orphan(&orphan_txid).is_none());
        assert!(pool.orphan(&orphan_descendant_txid).is_none());
    }

    #[test]
    fn chain_transition_readmits_disconnected_parent_before_existing_child() {
        let parent_input = outpoint(0xf6, 0);
        let parent = transaction(parent_input.clone(), 15);
        let parent_txid = parent.txid();
        let parent_output = Outpoint {
            txid: parent_txid,
            index: 0,
        };
        let child = transaction(parent_output.clone(), 10);
        let child_txid = child.txid();
        let old_view = FixedView::with_coin(parent_output, 15);
        let final_view = FixedView::with_coin(parent_input, 20);
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, child, &old_view),
            Admission::Accepted(_)
        ));
        let previous_generation = pool.info().generation;

        let summary = pool
            .reconcile_chain_transition_with_context(
                &[],
                &[parent],
                &MempoolContext::testing(3, 3),
                &final_view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("revalidation");
        assert!(summary.changed);
        assert_eq!(summary.removed, 0);
        assert_eq!(summary.readmitted, 1);
        assert_eq!(summary.retained_transactions, 2);
        assert_eq!(summary.retained_orphans, 0);
        assert_eq!(summary.generation, previous_generation + 1);
        assert!(pool.transaction(&parent_txid).is_some());
        assert!(pool.transaction(&child_txid).is_some());
        assert_eq!(
            pool.snapshot().entry(&child_txid).expect("child").parents,
            vec![parent_txid]
        );
    }

    #[test]
    fn chain_transition_prefers_older_disconnected_name_update() {
        let existing_input = outpoint(0xf7, 0);
        let disconnected_input = outpoint(0xf8, 0);
        let mut view = FixedView::with_coin(existing_input.clone(), 20);
        view.coins.insert(
            disconnected_input.clone(),
            Coin {
                outpoint: disconnected_input.clone(),
                value: 20,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            },
        );
        let existing = open_transaction(existing_input, 15, b"older-wins");
        let existing_txid = existing.txid();
        let disconnected = open_transaction(disconnected_input, 14, b"older-wins");
        let disconnected_txid = disconnected.txid();
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, existing, &view),
            Admission::Accepted(_)
        ));
        let previous_generation = pool.info().generation;

        let summary = pool
            .reconcile_chain_transition_with_context(
                &[],
                &[disconnected],
                &MempoolContext::testing(3, 3),
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("revalidation");
        assert!(summary.changed);
        assert_eq!(summary.removed, 1);
        assert_eq!(summary.readmitted, 1);
        assert_eq!(summary.retained_transactions, 1);
        assert_eq!(summary.generation, previous_generation + 1);
        assert!(pool.transaction(&existing_txid).is_none());
        assert!(pool.transaction(&disconnected_txid).is_some());
    }

    #[test]
    fn connected_block_revalidation_failure_preserves_original_pool() {
        let input = outpoint(0xf9, 0);
        let view = FixedView::with_coin(input.clone(), 20);
        let transaction = transaction(input, 9);
        let txid = transaction.txid();
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, transaction, &view),
            Admission::Accepted(_)
        ));
        let previous_generation = pool.info().generation;
        let error = pool
            .reconcile_connected_with_context(
                &[],
                &MempoolContext::testing(3, 3),
                &FailingView,
                &AllowInputs,
                &AllowContext,
            )
            .expect_err("injected revalidation failure");
        assert!(error.to_string().contains("injected view failure"));
        assert_eq!(pool.info().generation, previous_generation);
        assert!(pool.transaction(&txid).is_some());
    }

    #[test]
    fn dependency_graph_accounts_fee_and_promotes_orphans() {
        let parent_input = outpoint(1, 0);
        let view = FixedView::with_coin(parent_input.clone(), 20);
        let parent = transaction(parent_input, 15);
        let parent_txid = parent.txid();
        let child = transaction(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            10,
        );
        let child_txid = child.txid();
        let mut pool = MemoryMempool::new();

        assert_eq!(
            submit(&mut pool, child, &view),
            Admission::Orphan(child_txid)
        );
        assert!(
            matches!(submit(&mut pool, parent, &view), Admission::Accepted(id) if id == parent_txid)
        );
        assert!(pool.orphan(&child_txid).is_none());
        assert!(pool.transaction(&child_txid).is_some());

        let snapshot = pool.snapshot();
        let package = snapshot
            .package_for(child_txid, &HashSet::new())
            .expect("package");
        assert_eq!(package.txids, vec![parent_txid, child_txid]);
        assert_eq!(package.fee, 10);
        assert_eq!(
            package.policy_size,
            snapshot.entry(&parent_txid).expect("parent").policy_size
                + snapshot.entry(&child_txid).expect("child").policy_size
        );
        assert_eq!(
            snapshot.entry(&child_txid).expect("entry").ancestor_count,
            1
        );
    }

    #[test]
    fn native_sigop_accounting_enforces_hsd_transaction_policy() {
        let input = outpoint(12, 0);
        let mut view = FixedView::with_coin(input.clone(), 1_000);
        view.coins.get_mut(&input).expect("funding coin").address =
            Address::new(0, vec![0x55; 32]).expect("script-hash address");
        let mut oversized = transaction(input.clone(), 900);
        let checkmultisig_count = usize::try_from(MAX_TX_SIGOPS / 20).expect("sigop test length");
        let mut oversized_script = vec![0xae; checkmultisig_count];
        oversized_script.push(0xac);
        oversized.inputs[0].witness = Witness {
            items: vec![oversized_script],
        };
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, oversized, &view),
            Admission::Rejected { reason } if reason == "bad-txns-too-many-sigops"
        ));
        assert!(pool.snapshot().is_empty());

        let mut accepted = transaction(input, 900);
        accepted.inputs[0].witness = Witness {
            items: vec![vec![0xae; 2]],
        };
        let txid = accepted.txid();
        assert!(matches!(
            submit(&mut pool, accepted.clone(), &view),
            Admission::Accepted(id) if id == txid
        ));
        let entry = pool
            .snapshot()
            .entry(&txid)
            .expect("accepted entry")
            .clone();
        assert_eq!(entry.sigops, 40);
        assert_eq!(
            entry.policy_size,
            sigop_adjusted_virtual_size(&accepted, entry.sigops)
        );
        assert_eq!(entry.fee_rate_denominator(), entry.policy_size);
    }

    #[test]
    fn sigop_adjusted_policy_size_sets_minimum_relay_fee() {
        assert_eq!(minimum_policy_fee(0, 3), 0);
        assert_eq!(minimum_policy_fee(88, 0), 0);
        assert_eq!(minimum_policy_fee(88, 3), 3);
        assert_eq!(minimum_policy_fee(20_000, 3), 60);
        let input = outpoint(13, 0);
        let mut view = FixedView::with_coin(input.clone(), 1_000);
        view.coins.get_mut(&input).expect("funding coin").address =
            Address::new(0, vec![0x66; 32]).expect("script-hash address");
        let context = MempoolContext {
            minimum_relay_fee_rate: 3,
            ..MempoolContext::testing(2, 2)
        };
        let mut underpaying = transaction(input.clone(), 950);
        underpaying.inputs[0].witness = Witness {
            items: vec![vec![0xae; 200]],
        };
        let sigops = 4_000;
        assert_eq!(sigop_adjusted_virtual_size(&underpaying, sigops), 20_000);
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            pool.submit_with_context(underpaying, &context, &view, &AllowInputs, &AllowContext)
                .expect("underpaying admission"),
            Admission::Rejected { reason } if reason == "insufficient-fee"
        ));

        let mut exact_fee = transaction(input, 940);
        exact_fee.inputs[0].witness = Witness {
            items: vec![vec![0xae; 200]],
        };
        assert!(matches!(
            pool.submit_with_context(exact_fee, &context, &view, &AllowInputs, &AllowContext)
                .expect("exact-fee admission"),
            Admission::Accepted(_)
        ));
    }

    #[test]
    fn conflicting_and_over_limit_transactions_fail_closed() {
        let input = outpoint(2, 0);
        let view = FixedView::with_coin(input.clone(), 20);
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            maximum_transactions: 1,
            maximum_bytes: 1_000_000,
            maximum_orphans: 2,
            maximum_orphan_bytes: 1_000_000,
            maximum_ancestors: 2,
            maximum_descendants: 2,
        })
        .expect("limits");
        let first = transaction(input.clone(), 10);
        assert!(matches!(
            submit(&mut pool, first, &view),
            Admission::Accepted(_)
        ));

        let conflict = transaction(input, 9);
        assert!(matches!(
            submit(&mut pool, conflict, &view),
            Admission::Rejected { reason } if reason == "mempool-conflict"
        ));

        let other = outpoint(3, 0);
        let other_view = FixedView::with_coin(other.clone(), 20);
        assert!(matches!(
            submit(&mut pool, transaction(other, 10), &other_view),
            Admission::Rejected { reason } if reason == "mempool-full"
        ));
    }

    #[test]
    fn confirmed_parent_removal_preserves_child() {
        let parent_input = outpoint(4, 0);
        let view = FixedView::with_coin(parent_input.clone(), 20);
        let parent = transaction(parent_input, 15);
        let parent_txid = parent.txid();
        let child = transaction(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            10,
        );
        let child_txid = child.txid();
        let grandchild = transaction(
            Outpoint {
                txid: child_txid,
                index: 0,
            },
            7,
        );
        let grandchild_txid = grandchild.txid();
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, parent.clone(), &view),
            Admission::Accepted(_)
        ));
        assert!(matches!(
            submit(&mut pool, child, &view),
            Admission::Accepted(_)
        ));
        assert!(matches!(
            submit(&mut pool, grandchild, &view),
            Admission::Accepted(_)
        ));
        let generation_before = pool.info().generation;

        assert_eq!(pool.remove_confirmed(&[parent]), 1);
        assert_eq!(pool.info().generation, generation_before + 1);
        assert!(pool.transaction(&parent_txid).is_none());
        assert!(pool.transaction(&child_txid).is_some());
        let snapshot = pool.snapshot();
        let child = snapshot.entry(&child_txid).expect("child");
        assert!(child.parents.is_empty());
        assert_eq!(child.ancestor_count, 0);
        assert_eq!(child.ancestor_fee, child.fee);
        assert_eq!(child.ancestor_weight, child.weight);
        assert_eq!(child.ancestor_policy_size, child.policy_size);

        let grandchild = snapshot.entry(&grandchild_txid).expect("grandchild");
        assert_eq!(grandchild.parents, vec![child_txid]);
        assert_eq!(grandchild.ancestor_count, 1);
        assert_eq!(grandchild.ancestor_fee, child.fee + grandchild.fee);
        assert_eq!(grandchild.ancestor_weight, child.weight + grandchild.weight);
        assert_eq!(
            grandchild.ancestor_policy_size,
            child.policy_size + grandchild.policy_size
        );
    }

    #[test]
    fn orphan_capacity_failure_is_reported_as_rejection() {
        let missing = outpoint(9, 0);
        let view = FixedView::default();
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            maximum_orphan_bytes: 1,
            ..MempoolLimits::default()
        })
        .expect("limits");
        assert!(matches!(
            submit(&mut pool, transaction(missing, 1), &view),
            Admission::Rejected { reason } if reason == "orphan-capacity"
        ));
        assert_eq!(pool.info().orphan_count, 0);
    }

    #[test]
    fn clear_is_single_generation_fail_closed_reconciliation() {
        let input = outpoint(10, 0);
        let view = FixedView::with_coin(input.clone(), 20);
        let mut pool = MemoryMempool::new();
        assert!(matches!(
            submit(&mut pool, transaction(input, 10), &view),
            Admission::Accepted(_)
        ));
        let missing = outpoint(11, 0);
        assert!(matches!(
            submit(&mut pool, transaction(missing, 1), &FixedView::default()),
            Admission::Orphan(_)
        ));
        let generation_before = pool.info().generation;
        assert_eq!(pool.clear(), 2);
        assert_eq!(pool.info().generation, generation_before + 1);
        assert_eq!(pool.clear(), 0);
        assert_eq!(pool.info().generation, generation_before + 1);
        assert!(pool.snapshot().is_empty());
    }

    #[test]
    fn complete_verifier_gate_is_explicit() {
        let input = outpoint(5, 0);
        let view = FixedView::with_coin(input.clone(), 20);
        let mut pool = MemoryMempool::new();
        let context = MempoolContext {
            require_complete_verifiers: true,
            ..MempoolContext::testing(2, 2)
        };
        assert!(matches!(
            pool.submit_with_context(
                transaction(input, 10),
                &context,
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("admission"),
            Admission::Rejected { reason } if reason == "consensus-verifier-incomplete"
        ));
    }

    #[test]
    fn configured_limits_are_hard_bounded() {
        assert!(MempoolLimits {
            maximum_transactions: MAX_MEMPOOL_TRANSACTIONS + 1,
            ..MempoolLimits::default()
        }
        .validate()
        .is_err());
        assert!(MempoolLimits {
            maximum_bytes: MAX_MEMPOOL_BYTES + 1,
            ..MempoolLimits::default()
        }
        .validate()
        .is_err());
        assert!(MempoolLimits::default().maximum_bytes > MAX_BLOCK_WEIGHT);
    }
}
