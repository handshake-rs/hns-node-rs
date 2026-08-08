#![forbid(unsafe_code)]

//! Bounded, dependency-aware Handshake mempool foundations.
//!
//! The pool deliberately separates structural admission, UTXO resolution,
//! script authorization, and contextual covenant/name validation. Production
//! callers must install complete verifiers; the default `submit` boundary
//! remains fail closed.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use hns_consensus::{
    is_coinbase, is_final_transaction, reserved_name, transaction_sigops, transaction_weight,
    validate_transaction_sanity, verify_airdrop_output, verify_claim_output, verify_sequence_locks,
    verify_transaction_covenant_links, AirdropFlags, ClaimConsensusError, ClaimFlags,
    ConsensusError, Network, SequenceLockView, TransactionInputVerifier, VerifiedClaim, COIN,
    MAX_BLOCK_SIGOPS, WITNESS_SCALE_FACTOR,
};
use hns_primitives::{
    hash_name, Address, AirdropProof, AirdropSignatureVerifier, Amount, Claim, Coin, Covenant,
    CovenantKind, DnssecVerifier, Height, Outpoint, Output, OwnershipProof, Transaction, Txid,
    MAX_BLOCK_WEIGHT,
};
use rand::{rngs::OsRng, TryRngCore};
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
/// Maximum retained payload that may be copied by an atomic contextual
/// revalidation. This independently bounds transient rebuild allocations even
/// when the configured retained-pool limit is much larger.
pub const MAX_REVALIDATION_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PACKAGE_MEMBERS: usize = 1_000;
pub const MAX_TX_SIGOPS: u32 = MAX_BLOCK_SIGOPS / 5;
pub const BYTES_PER_SIGOP: usize = 20;
pub const HSD_MAX_STANDARD_TX_VERSION: u32 = 0;
pub const HSD_MAX_STANDARD_TX_WEIGHT: usize = MAX_BLOCK_WEIGHT / 10;
pub const HSD_MAX_P2WSH_STACK: usize = 100;
pub const HSD_MAX_P2WSH_PUSH: usize = 80;
pub const HSD_MAX_P2WSH_SIZE: usize = 3_600;
pub const HSD_ABSURD_FEE_FACTOR: Amount = 10_000;
pub const HSD_MEMPOOL_MAX_SIZE: usize = 100 * 1_000_000;
pub const HSD_MEMPOOL_EXPIRY_TIME: u64 = 72 * 60 * 60;
pub const HSD_MEMPOOL_TRIM_NUMERATOR: usize = 9;
pub const HSD_MEMPOOL_TRIM_DENOMINATOR: usize = 10;
pub const HSD_FREE_THRESHOLD: Amount = COIN * 144 / 250;
pub const HSD_LIMIT_FREE_RELAY: u64 = 15;
pub const HSD_FREE_DECAY_SECONDS: u64 = 600;
pub const HSD_FREE_RELAY_MULTIPLIER: u64 = 10 * 1_000;
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

fn transaction_priority(
    transaction: &Transaction,
    input_coins: &[Coin],
    mempool_parents: &BTreeSet<Txid>,
    next_height: Height,
    policy_size: usize,
) -> u128 {
    let weighted_value =
        transaction
            .inputs
            .iter()
            .zip(input_coins)
            .fold(0u128, |total, (input, coin)| {
                if mempool_parents.contains(&input.previous_output.txid)
                    || coin.height > next_height
                {
                    return total;
                }
                let age = u128::from(next_height - coin.height);
                total.saturating_add(u128::from(coin.value).saturating_mul(age))
            });
    weighted_value / (policy_size.max(1) as u128)
}

fn standardness_rejection(transaction: &Transaction) -> Option<&'static str> {
    if transaction.version > HSD_MAX_STANDARD_TX_VERSION {
        return Some("version");
    }
    if transaction_weight(transaction) > HSD_MAX_STANDARD_TX_WEIGHT {
        return Some("tx-size");
    }
    let mut nulldata = 0usize;
    for output in &transaction.outputs {
        let address = &output.address;
        let is_nulldata = address.version == 31;
        if address.version != 0 && !is_nulldata {
            return Some("address");
        }
        if is_nulldata {
            nulldata = nulldata.saturating_add(1);
            continue;
        }
        if matches!(output.covenant.kind, CovenantKind::Unknown(_)) {
            return Some("covenant");
        }
        if matches!(output.covenant.kind, CovenantKind::None | CovenantKind::Bid) {
            let dust_threshold = standard_output_dust_threshold(output, HSD_MINIMUM_RELAY_FEE_RATE);
            if output.value < dust_threshold {
                return Some("dust");
            }
        }
    }
    (nulldata > 1).then_some("multi-op-return")
}

pub fn standard_output_dust_threshold(output: &Output, rate: Amount) -> Amount {
    if !matches!(output.covenant.kind, CovenantKind::None | CovenantKind::Bid)
        || output.address.version == 31
    {
        return 0;
    }
    minimum_policy_fee(output.encode().len().saturating_add(67), rate).saturating_mul(3)
}

fn has_standard_inputs(transaction: &Transaction, input_coins: &[Coin]) -> bool {
    transaction
        .inputs
        .iter()
        .zip(input_coins)
        .all(|(input, coin)| standard_witness(&input.witness.items, &coin.address))
}

fn standard_witness(items: &[Vec<u8>], address: &hns_primitives::Address) -> bool {
    if items.is_empty() {
        return true;
    }
    if address.version == 0 && address.hash.len() == 20 {
        return items.len() == 2 && items[0].len() == 65 && items[1].len() == 33;
    }
    if address.version == 0 && address.hash.len() == 32 {
        let Some((redeem, arguments)) = items.split_last() else {
            return false;
        };
        if arguments.len() > HSD_MAX_P2WSH_STACK
            || arguments
                .iter()
                .any(|argument| argument.len() > HSD_MAX_P2WSH_PUSH)
            || redeem.len() > HSD_MAX_P2WSH_SIZE
        {
            return false;
        }
        if redeem.len() == 35 && redeem[0] == 33 && redeem[34] == 0xac {
            return arguments.len() == 1 && arguments[0].len() == 65;
        }
        if redeem.len() == 25
            && redeem[0] == 0x76
            && redeem[1] == 0xc0
            && redeem[2] == 20
            && redeem[23] == 0x88
            && redeem[24] == 0xac
        {
            return arguments.len() == 2 && arguments[0].len() == 65 && arguments[1].len() == 33;
        }
        if let Some(required) = standard_multisig_required(redeem) {
            return arguments.len() == required.saturating_add(1)
                && arguments.first().is_some_and(Vec::is_empty)
                && arguments[1..].iter().all(|signature| signature.len() == 65);
        }
        return true;
    }
    items.len() <= HSD_MAX_P2WSH_STACK && items.iter().all(|item| item.len() <= HSD_MAX_P2WSH_PUSH)
}

fn standard_multisig_required(script: &[u8]) -> Option<usize> {
    if script.len() < 4 || *script.last()? != 0xae {
        return None;
    }
    let required = small_integer(*script.first()?)?;
    let total = small_integer(script[script.len().checked_sub(2)?])?;
    if required == 0 || total == 0 || required > total {
        return None;
    }
    let mut cursor = 1usize;
    for _ in 0..total {
        if script.get(cursor).copied() != Some(33) {
            return None;
        }
        cursor = cursor.checked_add(34)?;
    }
    (cursor.checked_add(2)? == script.len() && small_integer(*script.get(cursor)?) == Some(total))
        .then_some(required)
}

fn small_integer(opcode: u8) -> Option<usize> {
    match opcode {
        0x00 => Some(0),
        0x51..=0x60 => Some(usize::from(opcode - 0x50)),
        _ => None,
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
    /// Wall-clock lifetime for accepted root packages. HSD defaults to 72
    /// hours and expires descendants atomically with their dependency root.
    pub expiry_time: u64,
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
            expiry_time: HSD_MEMPOOL_EXPIRY_TIME,
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
            || self.expiry_time == 0
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
    /// Injected UNIX time used only for local relay expiry/rate policy. It is
    /// deliberately separate from consensus median time.
    pub current_time: u64,
    pub coinbase_maturity: u32,
    /// Minimum fee in native atomic units per 1,000 HSD policy virtual bytes.
    pub minimum_relay_fee_rate: Amount,
    /// HSD enables transaction/output and witness-shape standardness on
    /// mainnet and leaves it configurable on the other networks.
    pub require_standard: bool,
    /// HSD's default wallet-safety ceiling rejects fees above 10,000 times the
    /// minimum relay fee for the transaction's policy size.
    pub reject_absurd_fees: bool,
    /// Require HSD's confirmed-coin age/value priority for transactions below
    /// the minimum relay fee.
    pub relay_priority: bool,
    /// Apply HSD's exponentially decaying low-fee relay rate limiter.
    pub limit_free: bool,
    /// Thousand-policy-bytes per minute, matching HSD's option unit.
    pub limit_free_relay: u64,
    /// Production admission sets this to true. Tests and oracle harnesses may
    /// explicitly disable it while retaining every other admission check.
    pub require_complete_verifiers: bool,
}

impl MempoolContext {
    pub const fn testing(next_height: Height, parent_median_time: u64) -> Self {
        Self {
            next_height,
            parent_median_time,
            current_time: 0,
            coinbase_maturity: 0,
            minimum_relay_fee_rate: 0,
            require_standard: false,
            reject_absurd_fees: false,
            relay_priority: false,
            limit_free: false,
            limit_free_relay: HSD_LIMIT_FREE_RELAY,
            require_complete_verifiers: false,
        }
    }
}

/// Storage-independent contextual validation boundary. Complete production
/// implementations must verify deployment flags, name state, claims, airdrops,
/// and every policy which is intentionally outside transaction syntax.
pub struct AcceptedNameTransactions<'a> {
    revision: u64,
    transactions: &'a BTreeMap<(u64, Txid), Arc<Transaction>>,
}

impl AcceptedNameTransactions<'_> {
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Transaction> {
        self.transactions.values().map(Arc::as_ref)
    }
}

pub trait ContextualTransactionVerifier: Send + Sync {
    fn verify(
        &self,
        transaction: &Transaction,
        input_coins: &[Coin],
        context: &MempoolContext,
        accepted_name_transactions: &AcceptedNameTransactions<'_>,
    ) -> Result<(), ConsensusError>;

    /// Publish a successfully admitted transaction to an implementation's
    /// incremental contextual cache. The supplied view reflects any trim or
    /// expiry removals performed by the same atomic admission.
    fn transaction_accepted(
        &self,
        _transaction: &Transaction,
        _accepted_name_transactions: &AcceptedNameTransactions<'_>,
    ) {
    }

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
        _accepted_name_transactions: &AcceptedNameTransactions<'_>,
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

/// Durable active-chain lookup required by airdrop admission. The pool keeps
/// its own position index; this view prevents reusing allocations already
/// consumed by the active chain.
pub trait AirdropMempoolView {
    fn airdrop_position_spent(&self, position: u32) -> Result<bool, ConsensusError>;
}

/// Active-chain name-state and commit-ancestry validation required after a
/// DNSSEC proof has been authenticated and bound to its exact claim output.
pub trait ClaimMempoolView {
    fn verify_claim_context(
        &self,
        output: &Output,
        claim: &VerifiedClaim,
        context: &ClaimMempoolContext,
    ) -> Result<ClaimContextValidation, ConsensusError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClaimContextValidation {
    Valid,
    Rejected { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimMempoolContext {
    pub next_height: Height,
    pub transaction_start: Height,
    pub current_time: u64,
    pub parent_time: u64,
    pub network: Network,
    pub hardening: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimMempoolEntry {
    pub hash: [u8; 32],
    pub name_hash: [u8; 32],
    pub name: Vec<u8>,
    pub address: Address,
    pub value: Amount,
    pub fee: Amount,
    pub policy_size: usize,
    pub coinbase_weight: usize,
    pub memory_usage: usize,
    pub weak: bool,
    pub commit_hash: [u8; 32],
    pub commit_height: Height,
    pub inception: u64,
    pub expiration: u64,
    pub admitted_at: u64,
    pub sequence: u64,
    pub claim: Claim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClaimAdmission {
    Accepted([u8; 32]),
    Rejected { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AirdropMempoolContext {
    pub next_height: Height,
    pub transaction_start: Height,
    pub current_time: u64,
    pub airstop: bool,
    pub hardening: bool,
    pub goosig_disabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AirdropMempoolEntry {
    pub hash: [u8; 32],
    pub position: u32,
    pub value: Amount,
    pub fee: Amount,
    pub policy_size: usize,
    pub coinbase_weight: usize,
    pub memory_usage: usize,
    pub admitted_at: u64,
    pub sequence: u64,
    pub proof: AirdropProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AirdropAdmission {
    Accepted([u8; 32]),
    Rejected { reason: String },
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
    pub admitted_at: u64,
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
    pub claim_count: usize,
    pub airdrop_count: usize,
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
    pub retained_claims: usize,
    pub retained_airdrops: usize,
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

/// Immutable ordered map backed by a persistent AVL tree.
///
/// Keys, values, and untouched subtrees are structurally shared. Capturing or
/// cloning a root is O(1); insertion, replacement, and removal copy O(log N)
/// nodes under adversarial key order. AVL height depends only on the number of
/// records, never on attacker-influenced hashes or randomized priorities.
#[derive(Clone, Debug)]
struct PersistentMap<K, V> {
    root: Option<Arc<PersistentMapNode<K, V>>>,
    len: usize,
    /// Number of nodes allocated by the operation which produced this root.
    /// This is retained in production because it is a constant-size field and
    /// makes complexity assertions deterministic without a global test hook.
    mutation_nodes: usize,
    total_mutation_nodes: usize,
}

#[derive(Debug)]
struct PersistentMapNode<K, V> {
    key: K,
    value: V,
    height: u16,
    size: usize,
    left: Option<Arc<Self>>,
    right: Option<Arc<Self>>,
}

struct PersistentMapIter<'a, K, V> {
    stack: Vec<&'a PersistentMapNode<K, V>>,
    remaining: usize,
}

impl<K, V> Default for PersistentMap<K, V> {
    fn default() -> Self {
        Self {
            root: None,
            len: 0,
            mutation_nodes: 0,
            total_mutation_nodes: 0,
        }
    }
}

impl<K: Ord + Clone, V: Clone> PersistentMap<K, V> {
    const fn len(&self) -> usize {
        self.len
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn get(&self, key: &K) -> Option<&V> {
        let mut node = self.root.as_deref();
        while let Some(current) = node {
            match key.cmp(&current.key) {
                Ordering::Less => node = current.left.as_deref(),
                Ordering::Greater => node = current.right.as_deref(),
                Ordering::Equal => return Some(&current.value),
            }
        }
        None
    }

    fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    fn keys(&self) -> impl ExactSizeIterator<Item = &K> {
        self.iter().map(|(key, _)| key)
    }

    fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }

    fn iter(&self) -> PersistentMapIter<'_, K, V> {
        let mut iter = PersistentMapIter {
            stack: Vec::new(),
            remaining: self.len,
        };
        iter.push_left(self.root.as_deref());
        iter
    }

    /// Iterate strictly after `lower` in O(log N + returned records).
    fn iter_after(&self, lower: Option<&K>) -> PersistentMapIter<'_, K, V> {
        let Some(lower) = lower else {
            return self.iter();
        };
        let mut stack = Vec::new();
        let mut remaining = 0usize;
        let mut node = self.root.as_deref();
        while let Some(current) = node {
            if current.key <= *lower {
                node = current.right.as_deref();
            } else {
                stack.push(current);
                remaining = remaining
                    .checked_add(1)
                    .and_then(|count| count.checked_add(persistent_map_size(&current.right)))
                    .expect("persistent map range length overflow");
                node = current.left.as_deref();
            }
        }
        PersistentMapIter { stack, remaining }
    }

    fn insert(&self, key: K, value: V) -> (Self, Option<V>) {
        let mut mutation_nodes = 0;
        let (root, previous) = persistent_map_insert(&self.root, key, value, &mut mutation_nodes);
        (
            Self {
                root,
                len: if previous.is_none() {
                    self.len
                        .checked_add(1)
                        .expect("persistent mempool map length overflow")
                } else {
                    self.len
                },
                mutation_nodes,
                total_mutation_nodes: self.total_mutation_nodes.saturating_add(mutation_nodes),
            },
            previous,
        )
    }

    fn remove(&self, key: &K) -> (Self, Option<V>) {
        let mut mutation_nodes = 0;
        let (root, previous) = persistent_map_remove(&self.root, key, &mut mutation_nodes);
        (
            Self {
                root,
                len: if previous.is_some() {
                    self.len
                        .checked_sub(1)
                        .expect("persistent mempool map length underflow")
                } else {
                    self.len
                },
                mutation_nodes,
                total_mutation_nodes: self.total_mutation_nodes.saturating_add(mutation_nodes),
            },
            previous,
        )
    }

    #[cfg(test)]
    fn height(&self) -> usize {
        usize::from(persistent_map_height(&self.root))
    }

    #[cfg(test)]
    fn is_same_root(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }
}

impl<'a, K, V> PersistentMapIter<'a, K, V> {
    fn push_left(&mut self, mut node: Option<&'a PersistentMapNode<K, V>>) {
        while let Some(current) = node {
            self.stack.push(current);
            node = current.left.as_deref();
        }
    }
}

impl<'a, K, V> Iterator for PersistentMapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        self.remaining = self
            .remaining
            .checked_sub(1)
            .expect("persistent map iterator length underflow");
        Some((&node.key, &node.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V> ExactSizeIterator for PersistentMapIter<'_, K, V> {
    fn len(&self) -> usize {
        self.remaining
    }
}

fn persistent_map_height<K, V>(node: &Option<Arc<PersistentMapNode<K, V>>>) -> u16 {
    node.as_ref().map_or(0, |node| node.height)
}

fn persistent_map_size<K, V>(node: &Option<Arc<PersistentMapNode<K, V>>>) -> usize {
    node.as_ref().map_or(0, |node| node.size)
}

fn persistent_map_node<K, V>(
    key: K,
    value: V,
    left: Option<Arc<PersistentMapNode<K, V>>>,
    right: Option<Arc<PersistentMapNode<K, V>>>,
    mutation_nodes: &mut usize,
) -> Arc<PersistentMapNode<K, V>> {
    *mutation_nodes = mutation_nodes.saturating_add(1);
    Arc::new(PersistentMapNode {
        key,
        value,
        height: persistent_map_height(&left)
            .max(persistent_map_height(&right))
            .checked_add(1)
            .expect("persistent mempool map height overflow"),
        size: persistent_map_size(&left)
            .checked_add(persistent_map_size(&right))
            .and_then(|size| size.checked_add(1))
            .expect("persistent mempool map subtree length overflow"),
        left,
        right,
    })
}

fn persistent_map_balance_factor<K, V>(node: &PersistentMapNode<K, V>) -> i32 {
    i32::from(persistent_map_height(&node.left)) - i32::from(persistent_map_height(&node.right))
}

fn persistent_map_rotate_left<K: Clone, V: Clone>(
    root: &Arc<PersistentMapNode<K, V>>,
    mutation_nodes: &mut usize,
) -> Arc<PersistentMapNode<K, V>> {
    let pivot = root
        .right
        .as_ref()
        .expect("persistent map left rotation requires a right child");
    let left = persistent_map_node(
        root.key.clone(),
        root.value.clone(),
        root.left.clone(),
        pivot.left.clone(),
        mutation_nodes,
    );
    persistent_map_node(
        pivot.key.clone(),
        pivot.value.clone(),
        Some(left),
        pivot.right.clone(),
        mutation_nodes,
    )
}

fn persistent_map_rotate_right<K: Clone, V: Clone>(
    root: &Arc<PersistentMapNode<K, V>>,
    mutation_nodes: &mut usize,
) -> Arc<PersistentMapNode<K, V>> {
    let pivot = root
        .left
        .as_ref()
        .expect("persistent map right rotation requires a left child");
    let right = persistent_map_node(
        root.key.clone(),
        root.value.clone(),
        pivot.right.clone(),
        root.right.clone(),
        mutation_nodes,
    );
    persistent_map_node(
        pivot.key.clone(),
        pivot.value.clone(),
        pivot.left.clone(),
        Some(right),
        mutation_nodes,
    )
}

fn persistent_map_balance<K: Clone, V: Clone>(
    key: K,
    value: V,
    left: Option<Arc<PersistentMapNode<K, V>>>,
    right: Option<Arc<PersistentMapNode<K, V>>>,
    mutation_nodes: &mut usize,
) -> Arc<PersistentMapNode<K, V>> {
    let mut root = persistent_map_node(key, value, left, right, mutation_nodes);
    if persistent_map_balance_factor(&root) > 1 {
        if persistent_map_balance_factor(
            root.left
                .as_ref()
                .expect("persistent map left-heavy node has a left child"),
        ) < 0
        {
            let rotated = persistent_map_rotate_left(
                root.left
                    .as_ref()
                    .expect("persistent map left-heavy node has a left child"),
                mutation_nodes,
            );
            root = persistent_map_node(
                root.key.clone(),
                root.value.clone(),
                Some(rotated),
                root.right.clone(),
                mutation_nodes,
            );
        }
        return persistent_map_rotate_right(&root, mutation_nodes);
    }
    if persistent_map_balance_factor(&root) < -1 {
        if persistent_map_balance_factor(
            root.right
                .as_ref()
                .expect("persistent map right-heavy node has a right child"),
        ) > 0
        {
            let rotated = persistent_map_rotate_right(
                root.right
                    .as_ref()
                    .expect("persistent map right-heavy node has a right child"),
                mutation_nodes,
            );
            root = persistent_map_node(
                root.key.clone(),
                root.value.clone(),
                root.left.clone(),
                Some(rotated),
                mutation_nodes,
            );
        }
        return persistent_map_rotate_left(&root, mutation_nodes);
    }
    root
}

fn persistent_map_insert<K: Ord + Clone, V: Clone>(
    root: &Option<Arc<PersistentMapNode<K, V>>>,
    key: K,
    value: V,
    mutation_nodes: &mut usize,
) -> (Option<Arc<PersistentMapNode<K, V>>>, Option<V>) {
    let Some(node) = root else {
        return (
            Some(persistent_map_node(key, value, None, None, mutation_nodes)),
            None,
        );
    };
    match key.cmp(&node.key) {
        Ordering::Less => {
            let (left, previous) = persistent_map_insert(&node.left, key, value, mutation_nodes);
            (
                Some(persistent_map_balance(
                    node.key.clone(),
                    node.value.clone(),
                    left,
                    node.right.clone(),
                    mutation_nodes,
                )),
                previous,
            )
        }
        Ordering::Greater => {
            let (right, previous) = persistent_map_insert(&node.right, key, value, mutation_nodes);
            (
                Some(persistent_map_balance(
                    node.key.clone(),
                    node.value.clone(),
                    node.left.clone(),
                    right,
                    mutation_nodes,
                )),
                previous,
            )
        }
        Ordering::Equal => (
            Some(persistent_map_node(
                key,
                value,
                node.left.clone(),
                node.right.clone(),
                mutation_nodes,
            )),
            Some(node.value.clone()),
        ),
    }
}

fn persistent_map_remove_min<K: Clone, V: Clone>(
    root: &Arc<PersistentMapNode<K, V>>,
    mutation_nodes: &mut usize,
) -> (Option<Arc<PersistentMapNode<K, V>>>, K, V) {
    let Some(left) = root.left.as_ref() else {
        return (root.right.clone(), root.key.clone(), root.value.clone());
    };
    let (new_left, key, value) = persistent_map_remove_min(left, mutation_nodes);
    (
        Some(persistent_map_balance(
            root.key.clone(),
            root.value.clone(),
            new_left,
            root.right.clone(),
            mutation_nodes,
        )),
        key,
        value,
    )
}

fn persistent_map_remove<K: Ord + Clone, V: Clone>(
    root: &Option<Arc<PersistentMapNode<K, V>>>,
    key: &K,
    mutation_nodes: &mut usize,
) -> (Option<Arc<PersistentMapNode<K, V>>>, Option<V>) {
    let Some(node) = root else {
        return (None, None);
    };
    match key.cmp(&node.key) {
        Ordering::Less => {
            let (left, previous) = persistent_map_remove(&node.left, key, mutation_nodes);
            if previous.is_none() {
                return (root.clone(), None);
            }
            (
                Some(persistent_map_balance(
                    node.key.clone(),
                    node.value.clone(),
                    left,
                    node.right.clone(),
                    mutation_nodes,
                )),
                previous,
            )
        }
        Ordering::Greater => {
            let (right, previous) = persistent_map_remove(&node.right, key, mutation_nodes);
            if previous.is_none() {
                return (root.clone(), None);
            }
            (
                Some(persistent_map_balance(
                    node.key.clone(),
                    node.value.clone(),
                    node.left.clone(),
                    right,
                    mutation_nodes,
                )),
                previous,
            )
        }
        Ordering::Equal => {
            let previous = Some(node.value.clone());
            match (&node.left, &node.right) {
                (None, _) => (node.right.clone(), previous),
                (_, None) => (node.left.clone(), previous),
                (Some(left), Some(right)) => {
                    let (right, successor_key, successor_value) =
                        persistent_map_remove_min(right, mutation_nodes);
                    (
                        Some(persistent_map_balance(
                            successor_key,
                            successor_value,
                            Some(left.clone()),
                            right,
                            mutation_nodes,
                        )),
                        previous,
                    )
                }
            }
        }
    }
}

fn persistent_map_replace<K: Ord + Clone, V: Clone>(
    map: &mut PersistentMap<K, V>,
    key: K,
    value: V,
) -> Option<V> {
    let (next, previous) = map.insert(key, value);
    debug_assert!(
        next.mutation_nodes > 0,
        "persistent replacement copies one path"
    );
    *map = next;
    previous
}

fn persistent_map_delete<K: Ord + Clone, V: Clone>(
    map: &mut PersistentMap<K, V>,
    key: &K,
) -> Option<V> {
    let (next, previous) = map.remove(key);
    debug_assert!(
        previous.is_some() || next.mutation_nodes == 0,
        "missing persistent deletion retains the existing root"
    );
    *map = next;
    previous
}

type SpecialPoolKey = (u64, [u8; 32]);

/// Immutable, structurally shared view used by template and bounded read
/// workers. Every field is one persistent root, so capture and clone are O(1).
#[derive(Clone, Debug)]
pub struct MempoolSnapshot {
    instance_nonce: [u8; 32],
    generation: u64,
    entries: PersistentMap<Txid, Arc<MempoolEntry>>,
    transactions: PersistentMap<Txid, Arc<Transaction>>,
    spent_outpoints: PersistentMap<Outpoint, Txid>,
    parents: PersistentMap<Txid, Arc<BTreeSet<Txid>>>,
    children: PersistentMap<Txid, Arc<BTreeSet<Txid>>>,
    exclusive_names: PersistentMap<Txid, Arc<Vec<[u8; 32]>>>,
    claims: PersistentMap<[u8; 32], Arc<ClaimMempoolEntry>>,
    claims_by_sequence: PersistentMap<SpecialPoolKey, Arc<ClaimMempoolEntry>>,
    airdrops: PersistentMap<[u8; 32], Arc<AirdropMempoolEntry>>,
    airdrops_by_sequence: PersistentMap<SpecialPoolKey, Arc<AirdropMempoolEntry>>,
}

impl MempoolSnapshot {
    fn empty(instance_nonce: [u8; 32]) -> Self {
        Self {
            instance_nonce,
            generation: 0,
            entries: PersistentMap::default(),
            transactions: PersistentMap::default(),
            spent_outpoints: PersistentMap::default(),
            parents: PersistentMap::default(),
            children: PersistentMap::default(),
            exclusive_names: PersistentMap::default(),
            claims: PersistentMap::default(),
            claims_by_sequence: PersistentMap::default(),
            airdrops: PersistentMap::default(),
            airdrops_by_sequence: PersistentMap::default(),
        }
    }

    /// Cryptographically random, nonzero identity for this in-memory mempool
    /// instance. It is intentionally not persisted across process restarts.
    pub const fn instance_nonce(&self) -> &[u8; 32] {
        &self.instance_nonce
    }

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
        self.entries.get(txid).map(Arc::as_ref)
    }

    pub fn transaction(&self, txid: &Txid) -> Option<&Transaction> {
        self.transactions.get(txid).map(Arc::as_ref)
    }

    /// Exact transaction spending `outpoint` in this immutable generation.
    ///
    /// Lookup is O(log N) and avoids a full mempool scan for race-sensitive
    /// wallet preparation.
    pub fn spending_transaction(&self, outpoint: &Outpoint) -> Option<Txid> {
        self.spent_outpoints.get(outpoint).copied()
    }

    pub fn txids(&self) -> impl ExactSizeIterator<Item = Txid> + '_ {
        self.entries.keys().copied()
    }

    pub fn claim(&self, hash: &[u8; 32]) -> Option<&ClaimMempoolEntry> {
        self.claims.get(hash).map(Arc::as_ref)
    }

    pub fn claims(&self) -> impl Iterator<Item = &ClaimMempoolEntry> {
        self.claims.values().map(Arc::as_ref)
    }

    pub fn airdrop(&self, hash: &[u8; 32]) -> Option<&AirdropMempoolEntry> {
        self.airdrops.get(hash).map(Arc::as_ref)
    }

    pub fn airdrops(&self) -> impl Iterator<Item = &AirdropMempoolEntry> {
        self.airdrops.values().map(Arc::as_ref)
    }

    /// Parents in deterministic txid order. Lookup is O(log N) and iteration
    /// is O(parent count), bounded by the configured ancestor envelope.
    pub fn parents(&self, txid: &Txid) -> impl Iterator<Item = Txid> + '_ {
        self.parents
            .get(txid)
            .into_iter()
            .flat_map(|parents| parents.iter().copied())
    }

    /// Children in deterministic txid order. Lookup is O(log N) and iteration
    /// is O(child count), bounded by the configured descendant envelope.
    pub fn children(&self, txid: &Txid) -> impl Iterator<Item = Txid> + '_ {
        self.children
            .get(txid)
            .into_iter()
            .flat_map(|children| children.iter().copied())
    }

    /// Claims in exact admission order without sorting or payload cloning.
    pub fn claims_in_sequence(&self) -> impl Iterator<Item = &ClaimMempoolEntry> {
        self.claims_by_sequence.values().map(Arc::as_ref)
    }

    /// Airdrops in exact admission order without sorting or payload cloning.
    pub fn airdrops_in_sequence(&self) -> impl Iterator<Item = &AirdropMempoolEntry> {
        self.airdrops_by_sequence.values().map(Arc::as_ref)
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
        let mut emitted = HashSet::new();
        let mut ordered = Vec::new();
        let mut dependency_visits = 0usize;
        self.visit_package(
            txid,
            already_selected,
            &mut visiting,
            &mut emitted,
            &mut ordered,
            &mut dependency_visits,
        )?;
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
                for name in member_names.iter() {
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
        emitted: &mut HashSet<Txid>,
        ordered: &mut Vec<Txid>,
        dependency_visits: &mut usize,
    ) -> Result<(), MempoolError> {
        *dependency_visits = dependency_visits.saturating_add(1);
        if already_selected.contains(&txid) || emitted.contains(&txid) {
            return Ok(());
        }
        if !visiting.insert(txid) {
            return Err(MempoolError::DependencyCycle(txid));
        }
        if let Some(parents) = self.parents.get(&txid) {
            for parent in parents.iter() {
                self.visit_package(
                    *parent,
                    already_selected,
                    visiting,
                    emitted,
                    ordered,
                    dependency_visits,
                )?;
            }
        }
        visiting.remove(&txid);
        emitted.insert(txid);
        ordered.push(txid);
        Ok(())
    }
}

fn random_mempool_instance_nonce() -> Result<[u8; 32], MempoolError> {
    let mut nonce = [0; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|error| MempoolError::InstanceNonce(error.to_string()))?;
    if nonce == [0; 32] {
        return Err(MempoolError::InstanceNonce(
            "operating-system randomness returned the reserved zero value".to_owned(),
        ));
    }
    Ok(nonce)
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

type OrderedTxidKey = (u64, Txid);

/// Immutable, structurally shared transaction-id generation.
///
/// The persistent AVL tree gives RPC an O(1) snapshot clone while admissions
/// and removals path-copy only O(log N) nodes, even when workers retain older
/// generations. Iteration remains deterministic in `(sequence, txid)` order.
#[derive(Clone, Debug, Default)]
pub struct OrderedTxidSnapshot {
    root: Option<Arc<OrderedTxidNode>>,
    len: usize,
}

#[derive(Debug)]
struct OrderedTxidNode {
    key: OrderedTxidKey,
    height: u16,
    left: Option<Arc<Self>>,
    right: Option<Arc<Self>>,
}

pub struct OrderedTxidIter<'a> {
    stack: Vec<&'a OrderedTxidNode>,
    remaining: usize,
}

impl OrderedTxidSnapshot {
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_same_generation(&self, other: &Self) -> bool {
        self.len == other.len
            && match (&self.root, &other.root) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }

    pub fn txids(&self) -> impl Iterator<Item = Txid> + '_ {
        self.iter().map(|(_, txid)| *txid)
    }

    fn iter(&self) -> OrderedTxidIter<'_> {
        let mut iter = OrderedTxidIter {
            stack: Vec::new(),
            remaining: self.len,
        };
        iter.push_left(self.root.as_deref());
        iter
    }

    fn insert(&self, key: OrderedTxidKey) -> (Self, bool) {
        let (root, inserted) = ordered_txid_insert(&self.root, key);
        (
            Self {
                root,
                len: if inserted {
                    self.len
                        .checked_add(1)
                        .expect("persistent mempool txid count overflow")
                } else {
                    self.len
                },
            },
            inserted,
        )
    }

    fn remove(&self, key: &OrderedTxidKey) -> (Self, bool) {
        let (root, removed) = ordered_txid_remove(&self.root, key);
        (
            Self {
                root,
                len: if removed {
                    self.len
                        .checked_sub(1)
                        .expect("persistent mempool txid count underflow")
                } else {
                    self.len
                },
            },
            removed,
        )
    }
}

impl<'a> OrderedTxidIter<'a> {
    fn push_left(&mut self, mut node: Option<&'a OrderedTxidNode>) {
        while let Some(current) = node {
            self.stack.push(current);
            node = current.left.as_deref();
        }
    }
}

impl<'a> Iterator for OrderedTxidIter<'a> {
    type Item = &'a OrderedTxidKey;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        self.remaining = self
            .remaining
            .checked_sub(1)
            .expect("persistent mempool iterator length underflow");
        Some(&node.key)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for OrderedTxidIter<'_> {}

fn ordered_txid_height(node: &Option<Arc<OrderedTxidNode>>) -> u16 {
    node.as_ref().map_or(0, |node| node.height)
}

fn ordered_txid_node(
    key: OrderedTxidKey,
    left: Option<Arc<OrderedTxidNode>>,
    right: Option<Arc<OrderedTxidNode>>,
) -> Arc<OrderedTxidNode> {
    Arc::new(OrderedTxidNode {
        key,
        height: ordered_txid_height(&left)
            .max(ordered_txid_height(&right))
            .checked_add(1)
            .expect("persistent mempool AVL height overflow"),
        left,
        right,
    })
}

fn ordered_txid_balance_factor(node: &OrderedTxidNode) -> i32 {
    i32::from(ordered_txid_height(&node.left)) - i32::from(ordered_txid_height(&node.right))
}

fn ordered_txid_rotate_left(root: &Arc<OrderedTxidNode>) -> Arc<OrderedTxidNode> {
    let pivot = root
        .right
        .as_ref()
        .expect("left rotation requires a right child");
    let left = ordered_txid_node(root.key, root.left.clone(), pivot.left.clone());
    ordered_txid_node(pivot.key, Some(left), pivot.right.clone())
}

fn ordered_txid_rotate_right(root: &Arc<OrderedTxidNode>) -> Arc<OrderedTxidNode> {
    let pivot = root
        .left
        .as_ref()
        .expect("right rotation requires a left child");
    let right = ordered_txid_node(root.key, pivot.right.clone(), root.right.clone());
    ordered_txid_node(pivot.key, pivot.left.clone(), Some(right))
}

fn ordered_txid_balance(
    key: OrderedTxidKey,
    left: Option<Arc<OrderedTxidNode>>,
    right: Option<Arc<OrderedTxidNode>>,
) -> Arc<OrderedTxidNode> {
    let mut root = ordered_txid_node(key, left, right);
    if ordered_txid_balance_factor(&root) > 1 {
        if ordered_txid_balance_factor(
            root.left
                .as_ref()
                .expect("left-heavy node has a left child"),
        ) < 0
        {
            let rotated = ordered_txid_rotate_left(
                root.left
                    .as_ref()
                    .expect("left-heavy node has a left child"),
            );
            root = ordered_txid_node(root.key, Some(rotated), root.right.clone());
        }
        return ordered_txid_rotate_right(&root);
    }
    if ordered_txid_balance_factor(&root) < -1 {
        if ordered_txid_balance_factor(
            root.right
                .as_ref()
                .expect("right-heavy node has a right child"),
        ) > 0
        {
            let rotated = ordered_txid_rotate_right(
                root.right
                    .as_ref()
                    .expect("right-heavy node has a right child"),
            );
            root = ordered_txid_node(root.key, root.left.clone(), Some(rotated));
        }
        return ordered_txid_rotate_left(&root);
    }
    root
}

fn ordered_txid_insert(
    root: &Option<Arc<OrderedTxidNode>>,
    key: OrderedTxidKey,
) -> (Option<Arc<OrderedTxidNode>>, bool) {
    let Some(node) = root else {
        return (Some(ordered_txid_node(key, None, None)), true);
    };
    match key.cmp(&node.key) {
        Ordering::Less => {
            let (left, inserted) = ordered_txid_insert(&node.left, key);
            if !inserted {
                return (root.clone(), false);
            }
            (
                Some(ordered_txid_balance(node.key, left, node.right.clone())),
                true,
            )
        }
        Ordering::Greater => {
            let (right, inserted) = ordered_txid_insert(&node.right, key);
            if !inserted {
                return (root.clone(), false);
            }
            (
                Some(ordered_txid_balance(node.key, node.left.clone(), right)),
                true,
            )
        }
        Ordering::Equal => (root.clone(), false),
    }
}

fn ordered_txid_remove_min(
    root: &Arc<OrderedTxidNode>,
) -> (Option<Arc<OrderedTxidNode>>, OrderedTxidKey) {
    let Some(left) = root.left.as_ref() else {
        return (root.right.clone(), root.key);
    };
    let (new_left, minimum) = ordered_txid_remove_min(left);
    (
        Some(ordered_txid_balance(root.key, new_left, root.right.clone())),
        minimum,
    )
}

fn ordered_txid_remove(
    root: &Option<Arc<OrderedTxidNode>>,
    key: &OrderedTxidKey,
) -> (Option<Arc<OrderedTxidNode>>, bool) {
    let Some(node) = root else {
        return (None, false);
    };
    match key.cmp(&node.key) {
        Ordering::Less => {
            let (left, removed) = ordered_txid_remove(&node.left, key);
            if !removed {
                return (root.clone(), false);
            }
            (
                Some(ordered_txid_balance(node.key, left, node.right.clone())),
                true,
            )
        }
        Ordering::Greater => {
            let (right, removed) = ordered_txid_remove(&node.right, key);
            if !removed {
                return (root.clone(), false);
            }
            (
                Some(ordered_txid_balance(node.key, node.left.clone(), right)),
                true,
            )
        }
        Ordering::Equal => match (&node.left, &node.right) {
            (None, _) => (node.right.clone(), true),
            (_, None) => (node.left.clone(), true),
            (Some(left), Some(right)) => {
                let (right, successor) = ordered_txid_remove_min(right);
                (
                    Some(ordered_txid_balance(successor, Some(left.clone()), right)),
                    true,
                )
            }
        },
    }
}

#[derive(Clone, Debug)]
pub struct MemoryMempool {
    limits: MempoolLimits,
    entries: HashMap<Txid, Arc<MempoolEntry>>,
    ordered_txids: OrderedTxidSnapshot,
    /// Exact dependency-root membership ordered by original admission time.
    /// This replaces a full-pool scan and sort with O(log N) root mutations.
    expiry_roots: BTreeSet<(u64, Txid)>,
    /// Cached minimum of `expiry_roots`, making the common not-due check O(1).
    next_expiry_root: Option<(u64, Txid)>,
    transactions: HashMap<Txid, Arc<Transaction>>,
    /// Name-covenant transactions keyed by immutable admission order. The
    /// contextual verifier borrows this index in O(1) and only iterates it when
    /// rebuilding after a name-set change it did not incrementally observe.
    name_transactions: BTreeMap<(u64, Txid), Arc<Transaction>>,
    name_revision: u64,
    orphans: HashMap<Txid, OrphanEntry>,
    orphan_order: BTreeSet<(u64, Txid)>,
    orphans_by_parent: HashMap<Txid, BTreeSet<(u64, Txid)>>,
    spent_outpoints: HashMap<Outpoint, Txid>,
    parents: HashMap<Txid, Arc<BTreeSet<Txid>>>,
    children: HashMap<Txid, Arc<BTreeSet<Txid>>>,
    exclusive_names: HashMap<Txid, Arc<Vec<[u8; 32]>>>,
    exclusive_name_owners: HashMap<[u8; 32], Txid>,
    claims: HashMap<[u8; 32], Arc<ClaimMempoolEntry>>,
    claim_names: HashMap<[u8; 32], [u8; 32]>,
    airdrops: HashMap<[u8; 32], Arc<AirdropMempoolEntry>>,
    airdrop_positions: HashMap<u32, [u8; 32]>,
    /// Template-visible immutable roots, updated with every corresponding
    /// live-index mutation before the generation is published.
    snapshot_state: MempoolSnapshot,
    bytes: usize,
    // Wider than the public `Amount` so add/remove remains reversible even
    // when the compatibility summary saturates at `u64::MAX`.
    total_fee: u128,
    orphan_bytes: usize,
    free_count: f64,
    last_free_time: u64,
    generation: u64,
    next_sequence: u64,
    #[cfg(test)]
    expiry_root_checks: usize,
    #[cfg(test)]
    orphan_promotion_attempts: usize,
}

impl MemoryMempool {
    /// Construct an empty pool with a fallibly acquired nonzero OS-random
    /// process-local instance nonce.
    pub fn new() -> Result<Self, MempoolError> {
        Self::with_limits(MempoolLimits::default())
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        Self::with_validated_limits_and_instance_nonce(MempoolLimits::default(), [0xa5; 32])
            .expect("deterministic test mempool configuration")
    }

    pub fn with_limits(limits: MempoolLimits) -> Result<Self, MempoolError> {
        limits.validate()?;
        let instance_nonce = random_mempool_instance_nonce()?;
        Self::with_validated_limits_and_instance_nonce(limits, instance_nonce)
    }

    fn with_validated_limits_and_instance_nonce(
        limits: MempoolLimits,
        instance_nonce: [u8; 32],
    ) -> Result<Self, MempoolError> {
        if instance_nonce == [0; 32] {
            return Err(MempoolError::InstanceNonce(
                "mempool instance nonce used the reserved zero value".to_owned(),
            ));
        }
        Ok(Self {
            limits,
            entries: HashMap::new(),
            ordered_txids: OrderedTxidSnapshot::default(),
            expiry_roots: BTreeSet::new(),
            next_expiry_root: None,
            transactions: HashMap::new(),
            name_transactions: BTreeMap::new(),
            name_revision: 0,
            orphans: HashMap::new(),
            orphan_order: BTreeSet::new(),
            orphans_by_parent: HashMap::new(),
            spent_outpoints: HashMap::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
            exclusive_names: HashMap::new(),
            exclusive_name_owners: HashMap::new(),
            claims: HashMap::new(),
            claim_names: HashMap::new(),
            airdrops: HashMap::new(),
            airdrop_positions: HashMap::new(),
            snapshot_state: MempoolSnapshot::empty(instance_nonce),
            bytes: 0,
            total_fee: 0,
            orphan_bytes: 0,
            free_count: 0.0,
            last_free_time: 0,
            generation: 0,
            next_sequence: 1,
            #[cfg(test)]
            expiry_root_checks: 0,
            #[cfg(test)]
            orphan_promotion_attempts: 0,
        })
    }

    pub fn limits(&self) -> &MempoolLimits {
        &self.limits
    }

    pub fn transaction(&self, txid: &Txid) -> Option<&Transaction> {
        self.transactions.get(txid).map(Arc::as_ref)
    }

    pub fn ordered_txids_snapshot(&self) -> OrderedTxidSnapshot {
        self.ordered_txids.clone()
    }

    pub fn claim(&self, hash: &[u8; 32]) -> Option<&Claim> {
        self.claims.get(hash).map(|entry| &entry.claim)
    }

    pub fn claim_entries(&self) -> Vec<ClaimMempoolEntry> {
        let mut entries = self
            .claims
            .values()
            .map(|entry| entry.as_ref().clone())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| (entry.sequence, entry.hash));
        entries
    }

    /// Return at most `limit` claims strictly after an admission-order cursor.
    /// The lookup is O(log N), traversal is O(limit), and returned payloads are
    /// shared with the live pool and retained template generations.
    pub fn claim_entries_page(
        &self,
        after: Option<(u64, [u8; 32])>,
        limit: usize,
    ) -> Vec<Arc<ClaimMempoolEntry>> {
        self.snapshot_state
            .claims_by_sequence
            .iter_after(after.as_ref())
            .take(limit.min(MAX_MEMPOOL_TRANSACTIONS))
            .map(|(_, entry)| entry.clone())
            .collect()
    }

    pub fn airdrop(&self, hash: &[u8; 32]) -> Option<&AirdropProof> {
        self.airdrops.get(hash).map(|entry| &entry.proof)
    }

    pub fn airdrop_entries(&self) -> Vec<AirdropMempoolEntry> {
        let mut entries = self
            .airdrops
            .values()
            .map(|entry| entry.as_ref().clone())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| (entry.sequence, entry.hash));
        entries
    }

    /// Return at most `limit` airdrops strictly after an admission-order
    /// cursor with the same O(log N + limit) and payload-sharing guarantees as
    /// `claim_entries_page`.
    pub fn airdrop_entries_page(
        &self,
        after: Option<(u64, [u8; 32])>,
        limit: usize,
    ) -> Vec<Arc<AirdropMempoolEntry>> {
        self.snapshot_state
            .airdrops_by_sequence
            .iter_after(after.as_ref())
            .take(limit.min(MAX_MEMPOOL_TRANSACTIONS))
            .map(|(_, entry)| entry.clone())
            .collect()
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
        debug_assert_eq!(self.snapshot_state.generation, self.generation);
        self.snapshot_state.clone()
    }

    /// Admit one HSD DNSSEC ownership claim against the exact next-block
    /// deployment, parent-time, active name state, and canonical commit
    /// ancestry. Claims are coinbase inputs, not ordinary transactions.
    pub fn submit_claim_with_context<V: ClaimMempoolView>(
        &mut self,
        claim: Claim,
        context: &ClaimMempoolContext,
        view: &V,
        dnssec: &dyn DnssecVerifier,
    ) -> Result<ClaimAdmission, MempoolError> {
        if context.next_height < context.transaction_start {
            return Ok(rejected_claim("no-tx-allowed-yet"));
        }
        let encoded = match claim.encode() {
            Ok(encoded) => encoded,
            Err(_) => return Ok(rejected_claim("bad-claim-proof")),
        };
        let hash = claim.hash();
        let txid = Txid::new(hash);
        if self.claims.contains_key(&hash)
            || self.airdrops.contains_key(&hash)
            || self.entries.contains_key(&txid)
            || self.orphans.contains_key(&txid)
        {
            return Ok(rejected_claim("txn-already-in-mempool"));
        }
        let authenticated = match authenticate_claim(&claim, context, dnssec) {
            Ok(authenticated) => authenticated,
            Err(reason) => return Ok(rejected_claim(reason)),
        };
        let name_hash = *authenticated.verified.name_hash.as_bytes();
        if self.claim_names.contains_key(&name_hash)
            || self.exclusive_name_owners.contains_key(&name_hash)
        {
            return Ok(rejected_claim("name-already-in-mempool"));
        }
        match view
            .verify_claim_context(&authenticated.output, &authenticated.verified, context)
            .map_err(|error| MempoolError::View(error.to_string()))?
        {
            ClaimContextValidation::Valid => {}
            ClaimContextValidation::Rejected { reason } => {
                return Ok(rejected_claim(reason));
            }
        }

        let memory_usage = 500usize
            .checked_add(claim.blob.len())
            .ok_or(MempoolError::WeightOverflow)?;
        let projected_bytes = self
            .bytes
            .checked_add(memory_usage)
            .ok_or(MempoolError::WeightOverflow)?;
        let policy_size = encoded.len().div_ceil(WITNESS_SCALE_FACTOR);
        let coinbase_weight = claim_coinbase_weight(
            claim.blob.len(),
            &authenticated.output,
            authenticated.verified.name.len(),
        );
        let claim_fee = authenticated.verified.fee;
        let counts_toward_total_fee = authenticated.verified.commit_height == 1;
        let sequence = self.take_sequence();
        let entry = Arc::new(ClaimMempoolEntry {
            hash,
            name_hash,
            name: authenticated.verified.name,
            address: authenticated.output.address,
            value: authenticated.verified.value,
            fee: authenticated.verified.fee,
            policy_size,
            coinbase_weight,
            memory_usage,
            weak: authenticated.verified.weak,
            commit_hash: authenticated.verified.commit_hash,
            commit_height: authenticated.verified.commit_height,
            inception: authenticated.inception,
            expiration: authenticated.expiration,
            admitted_at: context.current_time,
            sequence,
            claim,
        });
        self.claim_names.insert(name_hash, hash);
        let previous = self.claims.insert(hash, entry.clone());
        debug_assert!(previous.is_none(), "accepted claim hash is unique");
        let previous = persistent_map_replace(&mut self.snapshot_state.claims, hash, entry.clone());
        debug_assert!(previous.is_none(), "accepted snapshot claim hash is unique");
        let previous = persistent_map_replace(
            &mut self.snapshot_state.claims_by_sequence,
            (sequence, hash),
            entry,
        );
        debug_assert!(previous.is_none(), "accepted claim sequence is unique");
        self.bytes = projected_bytes;
        if counts_toward_total_fee {
            self.total_fee = self.total_fee.saturating_add(u128::from(claim_fee));
        }
        self.advance_generation();
        if !self.limit_size_claim(hash, context.current_time) {
            return Ok(rejected_claim("mempool-full"));
        }
        Ok(ClaimAdmission::Accepted(hash))
    }

    /// Revalidate every retained claim after an active-chain transition.
    /// This catches proof-window expiry, deployment changes, claim-period
    /// closure, commit reorgs, and name-state replacement conflicts.
    pub fn revalidate_claims_with_context<V: ClaimMempoolView>(
        &mut self,
        context: &ClaimMempoolContext,
        view: &V,
        dnssec: &dyn DnssecVerifier,
    ) -> Result<bool, MempoolError> {
        let before_transactions = self.entries.keys().copied().collect::<BTreeSet<_>>();
        let before_claims = self.claims.keys().copied().collect::<BTreeSet<_>>();
        let before_airdrops = self.airdrops.keys().copied().collect::<BTreeSet<_>>();
        let mut invalid = Vec::new();
        for entry in self.claims.values() {
            let valid = if context.next_height < context.transaction_start {
                false
            } else {
                match authenticate_claim(&entry.claim, context, dnssec) {
                    Ok(authenticated)
                        if authenticated.verified.name_hash.as_bytes() == &entry.name_hash =>
                    {
                        matches!(
                            view.verify_claim_context(
                                &authenticated.output,
                                &authenticated.verified,
                                context,
                            )
                            .map_err(|error| MempoolError::View(error.to_string()))?,
                            ClaimContextValidation::Valid
                        )
                    }
                    _ => false,
                }
            };
            if !valid {
                invalid.push(entry.hash);
            }
        }
        for hash in &invalid {
            self.remove_claim_without_generation(hash);
        }
        self.enforce_size_limit(context.current_time);
        let changed = self.entries.keys().copied().collect::<BTreeSet<_>>() != before_transactions
            || self.claims.keys().copied().collect::<BTreeSet<_>>() != before_claims
            || self.airdrops.keys().copied().collect::<BTreeSet<_>>() != before_airdrops;
        if changed {
            self.advance_generation();
        }
        Ok(changed)
    }

    /// Re-admit claims recovered from disconnected coinbases after the active
    /// name state and canonical commit index have been atomically rewound.
    /// Older disconnected claims take precedence over retained name conflicts.
    pub fn reconcile_claims_with_context<V: ClaimMempoolView>(
        &mut self,
        disconnected_transactions: &[Transaction],
        context: &ClaimMempoolContext,
        view: &V,
        dnssec: &dyn DnssecVerifier,
    ) -> Result<bool, MempoolError> {
        let before_claims = self.claims.keys().copied().collect::<BTreeSet<_>>();
        let before_transactions = self.entries.keys().copied().collect::<BTreeSet<_>>();
        let before_generation = self.generation;
        self.revalidate_claims_with_context(context, view, dnssec)?;
        for coinbase in disconnected_transactions
            .iter()
            .filter(|transaction| is_coinbase(transaction))
        {
            for (index, input) in coinbase.inputs.iter().enumerate().skip(1) {
                let Some(output) = coinbase.outputs.get(index) else {
                    continue;
                };
                if output.covenant.kind != CovenantKind::Claim {
                    continue;
                }
                let Some(blob) = input.witness.items.first() else {
                    continue;
                };
                let claim = Claim { blob: blob.clone() };
                let hash = claim.hash();
                if self.claims.contains_key(&hash) {
                    continue;
                }
                let Some(name_hash) = output.covenant.item_hash(0) else {
                    continue;
                };
                let mut candidate = self.clone();
                if let Some(conflict) = candidate.claim_names.get(&name_hash).copied() {
                    candidate.remove_claim_without_generation(&conflict);
                }
                if let Some(conflict) = candidate.exclusive_name_owners.get(&name_hash).copied() {
                    candidate.remove_transaction_without_generation(conflict, true);
                }
                if matches!(
                    candidate.submit_claim_with_context(claim, context, view, dnssec)?,
                    ClaimAdmission::Accepted(_)
                ) {
                    *self = candidate;
                }
            }
        }
        let after_claims = self.claims.keys().copied().collect::<BTreeSet<_>>();
        let after_transactions = self.entries.keys().copied().collect::<BTreeSet<_>>();
        let changed = before_claims != after_claims
            || before_transactions != after_transactions
            || self.generation != before_generation;
        if changed && self.generation == before_generation {
            self.advance_generation();
        }
        Ok(changed)
    }

    /// Admit one HSD airdrop/faucet proof against the active deployment flags
    /// and durable allocation bitfield. Proofs are indexed independently from
    /// ordinary transactions because they become coinbase inputs rather than
    /// standalone transactions.
    pub fn submit_airdrop_with_context<V: AirdropMempoolView>(
        &mut self,
        proof: AirdropProof,
        context: &AirdropMempoolContext,
        view: &V,
        signatures: &dyn AirdropSignatureVerifier,
    ) -> Result<AirdropAdmission, MempoolError> {
        if context.next_height < context.transaction_start {
            return Ok(rejected_airdrop("no-tx-allowed-yet"));
        }
        let raw = proof
            .encode()
            .map_err(|error| MempoolError::Consensus(error.to_string()))?;
        let hash = proof
            .hash()
            .map_err(|error| MempoolError::Consensus(error.to_string()))?;
        let txid = Txid::new(hash);
        if self.airdrops.contains_key(&hash)
            || self.claims.contains_key(&hash)
            || self.entries.contains_key(&txid)
            || self.orphans.contains_key(&txid)
        {
            return Ok(rejected_airdrop("txn-already-in-mempool"));
        }
        if !proof.is_sane() {
            return Ok(rejected_airdrop("bad-airdrop-proof"));
        }
        if context.airstop {
            return Ok(rejected_airdrop("bad-airdrop-disabled"));
        }
        if context.goosig_disabled {
            match proof.key() {
                Ok(key) if key.is_goo() => {
                    return Ok(rejected_airdrop("bad-goosig-disabled"));
                }
                Err(_) => return Ok(rejected_airdrop("bad-airdrop-proof")),
                _ => {}
            }
        }

        let position = proof
            .position()
            .map_err(|error| MempoolError::Consensus(error.to_string()))?;
        if view
            .airdrop_position_spent(position)
            .map_err(|error| MempoolError::View(error.to_string()))?
        {
            return Ok(rejected_airdrop("bad-txns-inputs-missingorspent"));
        }
        if self.airdrop_positions.contains_key(&position) {
            return Ok(rejected_airdrop("position-already-in-mempool"));
        }
        if context.hardening && proof.key().is_ok_and(|key| key.is_weak()) {
            return Ok(rejected_airdrop("bad-airdrop-rsa1024"));
        }

        let address = match Address::new(proof.version, proof.address.clone()) {
            Ok(address) => address,
            Err(_) => return Ok(rejected_airdrop("bad-airdrop-proof")),
        };
        let output = Output {
            value: proof.value().saturating_sub(proof.fee),
            address,
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let verified = match verify_airdrop_output(
            &raw,
            &output,
            AirdropFlags {
                airstop: context.airstop,
                hardening: context.hardening,
                goosig_disabled: context.goosig_disabled,
            },
            signatures,
        ) {
            Ok(verified) => verified,
            Err(_) => return Ok(rejected_airdrop("bad-airdrop-proof")),
        };
        if verified.position != position {
            return Err(MempoolError::Consensus(
                "verified airdrop position changed during admission".to_owned(),
            ));
        }

        let memory_usage = 300usize
            .checked_add(raw.len())
            .ok_or(MempoolError::WeightOverflow)?;
        let projected_bytes = self
            .bytes
            .checked_add(memory_usage)
            .ok_or(MempoolError::WeightOverflow)?;
        let policy_size = raw.len().div_ceil(WITNESS_SCALE_FACTOR);
        let coinbase_weight = airdrop_coinbase_weight(raw.len(), &output);
        let airdrop_fee = proof.fee;
        let sequence = self.take_sequence();
        let entry = Arc::new(AirdropMempoolEntry {
            hash,
            position,
            value: verified.value,
            fee: proof.fee,
            policy_size,
            coinbase_weight,
            memory_usage,
            admitted_at: context.current_time,
            sequence,
            proof,
        });
        self.airdrop_positions.insert(position, hash);
        let previous = self.airdrops.insert(hash, entry.clone());
        debug_assert!(previous.is_none(), "accepted airdrop hash is unique");
        let previous =
            persistent_map_replace(&mut self.snapshot_state.airdrops, hash, entry.clone());
        debug_assert!(
            previous.is_none(),
            "accepted snapshot airdrop hash is unique"
        );
        let previous = persistent_map_replace(
            &mut self.snapshot_state.airdrops_by_sequence,
            (sequence, hash),
            entry,
        );
        debug_assert!(previous.is_none(), "accepted airdrop sequence is unique");
        self.bytes = projected_bytes;
        self.total_fee = self.total_fee.saturating_add(u128::from(airdrop_fee));
        self.advance_generation();
        if !self.limit_size_airdrop(hash, context.current_time) {
            return Ok(rejected_airdrop("mempool-full"));
        }
        Ok(AirdropAdmission::Accepted(hash))
    }

    /// Revalidate retained proofs after an active-chain transition. Connected
    /// coinbases are removed by `remove_confirmed`; this pass applies changed
    /// deployment flags and the newly committed durable allocation field.
    pub fn revalidate_airdrops_with_context<V: AirdropMempoolView>(
        &mut self,
        context: &AirdropMempoolContext,
        view: &V,
        signatures: &dyn AirdropSignatureVerifier,
    ) -> Result<bool, MempoolError> {
        let before_transactions = self.entries.keys().copied().collect::<BTreeSet<_>>();
        let mut invalid = Vec::new();
        for entry in self.airdrops.values() {
            let proof = &entry.proof;
            let invalid_context = context.next_height < context.transaction_start
                || context.airstop
                || view
                    .airdrop_position_spent(entry.position)
                    .map_err(|error| MempoolError::View(error.to_string()))?;
            let valid_proof = if invalid_context {
                false
            } else {
                let address = Address::new(proof.version, proof.address.clone());
                address.is_ok_and(|address| {
                    let output = Output {
                        value: proof.value().saturating_sub(proof.fee),
                        address,
                        covenant: Covenant {
                            kind: CovenantKind::None,
                            items: Vec::new(),
                        },
                    };
                    proof.encode().is_ok_and(|raw| {
                        verify_airdrop_output(
                            &raw,
                            &output,
                            AirdropFlags {
                                airstop: context.airstop,
                                hardening: context.hardening,
                                goosig_disabled: context.goosig_disabled,
                            },
                            signatures,
                        )
                        .is_ok_and(|verified| verified.position == entry.position)
                    })
                })
            };
            if !valid_proof {
                invalid.push(entry.hash);
            }
        }
        for hash in &invalid {
            self.remove_airdrop_without_generation(hash);
        }
        let before_limit = self.airdrops.len();
        self.enforce_size_limit(context.current_time);
        let changed = !invalid.is_empty()
            || self.airdrops.len() != before_limit
            || self.entries.keys().copied().collect::<BTreeSet<_>>() != before_transactions;
        if changed {
            self.advance_generation();
        }
        Ok(changed)
    }

    /// Reconcile the special pool after a reorganization. Proofs recovered
    /// from disconnected coinbases are considered after the durable bitfield
    /// has been rewound and before templates observe the new generation.
    pub fn reconcile_airdrops_with_context<V: AirdropMempoolView>(
        &mut self,
        disconnected_transactions: &[Transaction],
        context: &AirdropMempoolContext,
        view: &V,
        signatures: &dyn AirdropSignatureVerifier,
    ) -> Result<bool, MempoolError> {
        let before = self.airdrops.keys().copied().collect::<BTreeSet<_>>();
        let before_generation = self.generation;
        self.revalidate_airdrops_with_context(context, view, signatures)?;
        for coinbase in disconnected_transactions
            .iter()
            .filter(|transaction| is_coinbase(transaction))
        {
            for (index, input) in coinbase.inputs.iter().enumerate().skip(1) {
                if coinbase
                    .outputs
                    .get(index)
                    .is_none_or(|output| output.covenant.kind != CovenantKind::None)
                {
                    continue;
                }
                let Some(raw) = input.witness.items.first() else {
                    continue;
                };
                let Ok(proof) = AirdropProof::decode(raw) else {
                    continue;
                };
                let hash = proof
                    .hash()
                    .map_err(|error| MempoolError::Consensus(error.to_string()))?;
                let position = proof
                    .position()
                    .map_err(|error| MempoolError::Consensus(error.to_string()))?;
                if self.airdrops.contains_key(&hash) {
                    continue;
                }
                if let Some(conflict) = self.airdrop_positions.get(&position).copied() {
                    self.remove_airdrop_without_generation(&conflict);
                }
                let _ = self.submit_airdrop_with_context(proof, context, view, signatures)?;
            }
        }
        let after = self.airdrops.keys().copied().collect::<BTreeSet<_>>();
        let changed = before != after || self.generation != before_generation;
        if changed && self.generation == before_generation {
            self.advance_generation();
        }
        Ok(changed)
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
        if let Admission::Accepted(txid) = &admission {
            self.promote_orphans_from([*txid], context, view, input_verifier, contextual_verifier)?;
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
        let revalidation_bytes = self.bytes.saturating_add(self.orphan_bytes);
        if revalidation_bytes > MAX_REVALIDATION_BYTES {
            return Err(MempoolError::LimitExceeded {
                context: "mempool revalidation memory",
                limit: MAX_REVALIDATION_BYTES,
                actual: revalidation_bytes,
            });
        }

        let previous_transactions = self.entries.keys().copied().collect::<BTreeSet<_>>();
        let previous_orphans = self.orphans.keys().copied().collect::<BTreeSet<_>>();
        let previous_claims = self.claims.keys().copied().collect::<BTreeSet<_>>();
        let previous_airdrops = self.airdrops.keys().copied().collect::<BTreeSet<_>>();
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
            .map(|entry| (entry.sequence, entry.txid, entry.admitted_at))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|(_, txid, admitted_at)| {
                source
                    .transactions
                    .get(&txid)
                    .map(|transaction| (transaction.as_ref().clone(), admitted_at))
            })
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
            .map(|transaction| (transaction, false, context.current_time, true))
            .collect::<Vec<_>>();
        candidates.extend(
            accepted
                .into_iter()
                .map(|(transaction, admitted_at)| (transaction, false, admitted_at, false)),
        );
        candidates.extend(
            ordered_orphans
                .into_iter()
                .map(|(_, _, transaction)| (transaction, true, context.current_time, true)),
        );
        let mut invalidated_transactions = previous_transactions
            .difference(&connected_txids)
            .filter(|txid| !source.entries.contains_key(txid))
            .copied()
            .collect::<HashSet<_>>();
        let mut candidate_txids = BTreeSet::new();
        let mut seen = HashSet::new();
        let mut rebuilt = Self::with_validated_limits_and_instance_nonce(
            self.limits.clone(),
            source.snapshot_state.instance_nonce,
        )?;
        rebuilt.free_count = self.free_count;
        rebuilt.last_free_time = self.last_free_time;
        rebuilt.claims = source.claims.clone();
        rebuilt.claim_names = source.claim_names.clone();
        rebuilt.airdrops = source.airdrops.clone();
        rebuilt.airdrop_positions = source.airdrop_positions.clone();
        rebuilt.snapshot_state.claims = source.snapshot_state.claims.clone();
        rebuilt.snapshot_state.claims_by_sequence =
            source.snapshot_state.claims_by_sequence.clone();
        rebuilt.snapshot_state.airdrops = source.snapshot_state.airdrops.clone();
        rebuilt.snapshot_state.airdrops_by_sequence =
            source.snapshot_state.airdrops_by_sequence.clone();
        rebuilt.bytes = rebuilt
            .claims
            .values()
            .fold(0usize, |total, entry| {
                total.saturating_add(entry.memory_usage)
            })
            .saturating_add(rebuilt.airdrops.values().fold(0usize, |total, entry| {
                total.saturating_add(entry.memory_usage)
            }));
        rebuilt.total_fee = rebuilt
            .claims
            .values()
            .filter(|entry| entry.commit_height == 1)
            .fold(0u128, |total, entry| {
                total.saturating_add(u128::from(entry.fee))
            })
            .saturating_add(rebuilt.airdrops.values().fold(0u128, |total, entry| {
                total.saturating_add(u128::from(entry.fee))
            }));
        rebuilt.next_sequence = self.next_sequence;
        // A rebuild is a distinct contextual prefix even when it happens to
        // retain the same number of name transactions at the same chain tip.
        rebuilt.name_revision = self.name_revision.saturating_add(1).max(1);
        for (transaction, allow_orphan, admitted_at, charge_free_relay) in candidates {
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
            match rebuilt.submit_checked_at(
                transaction,
                context,
                view,
                input_verifier,
                contextual_verifier,
                admitted_at,
                charge_free_relay,
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
        let promotion_roots = rebuilt
            .entries
            .keys()
            .copied()
            .chain(connected_txids.iter().copied())
            .collect::<BTreeSet<_>>();
        rebuilt.promote_orphans_from(
            promotion_roots,
            context,
            view,
            input_verifier,
            contextual_verifier,
        )?;
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
        let retained_claims = rebuilt.claims.keys().copied().collect::<BTreeSet<_>>();
        let retained_airdrops = rebuilt.airdrops.keys().copied().collect::<BTreeSet<_>>();
        let changed = retained_transactions != previous_transactions
            || retained_orphans != previous_orphans
            || retained_claims != previous_claims
            || retained_airdrops != previous_airdrops;
        let previous_members = previous_transactions
            .union(&previous_orphans)
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_members = retained_transactions
            .union(&retained_orphans)
            .copied()
            .collect::<BTreeSet<_>>();
        let removed = previous_members
            .difference(&retained_members)
            .count()
            .saturating_add(previous_claims.difference(&retained_claims).count())
            .saturating_add(previous_airdrops.difference(&retained_airdrops).count());
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
            rebuilt.set_generation(generation);
            *self = rebuilt;
        }
        Ok(MempoolRevalidation {
            changed,
            removed,
            readmitted,
            promoted_orphans,
            retained_transactions: retained_transactions.len(),
            retained_orphans: retained_orphans.len(),
            retained_claims: retained_claims.len(),
            retained_airdrops: retained_airdrops.len(),
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
        self.submit_checked_at(
            transaction,
            context,
            view,
            input_verifier,
            contextual_verifier,
            context.current_time,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_checked_at<V: MempoolView>(
        &mut self,
        transaction: Transaction,
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
        admitted_at: u64,
        charge_free_relay: bool,
    ) -> Result<Admission, MempoolError> {
        let txid = transaction.txid();
        if self.entries.contains_key(&txid)
            || self.orphans.contains_key(&txid)
            || self.claims.contains_key(txid.as_bytes())
            || self.airdrops.contains_key(txid.as_bytes())
        {
            return Ok(rejected("duplicate"));
        }
        if let Err(error) = validate_transaction_sanity(&transaction) {
            return Ok(rejected(error.to_string()));
        }
        if is_coinbase(&transaction) {
            return Ok(rejected("coinbase"));
        }
        if context.require_standard {
            if let Some(reason) = standardness_rejection(&transaction) {
                return Ok(rejected(reason));
            }
        }
        let covenant_metrics = match covenant_metrics(&transaction) {
            Ok(metrics) => metrics,
            Err(error) => return Ok(rejected(error.to_string())),
        };
        if covenant_metrics.exclusive_names.iter().any(|name| {
            self.exclusive_name_owners.contains_key(name) || self.claim_names.contains_key(name)
        }) {
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
        if context.require_standard && !has_standard_inputs(&transaction, &input_coins) {
            return Ok(rejected("bad-txns-nonstandard-inputs"));
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

        let sighash_cache = hns_consensus::SignatureHashCache::new(&transaction);
        for (index, coin) in input_coins.iter().enumerate() {
            if let Err(error) = input_verifier.verify_input_with_cache(&sighash_cache, index, coin)
            {
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
            if context.relay_priority
                && transaction_priority(
                    &transaction,
                    &input_coins,
                    &direct_parents,
                    context.next_height,
                    policy_size,
                ) <= u128::from(HSD_FREE_THRESHOLD)
            {
                return Ok(rejected("insufficient priority"));
            }
            if context.limit_free
                && charge_free_relay
                && !self.allow_free_relay(
                    policy_size,
                    context.current_time,
                    context.limit_free_relay,
                )
            {
                return Ok(rejected("rate limited free transaction"));
            }
        }
        if context.reject_absurd_fees && fee > minimum_fee.saturating_mul(HSD_ABSURD_FEE_FACTOR) {
            return Ok(rejected("absurdly-high-fee"));
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
        let projected_bytes = self
            .bytes
            .checked_add(encoded_size)
            .ok_or(MempoolError::WeightOverflow)?;

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
            admitted_at,
            sequence,
        };

        for input in &transaction.inputs {
            let previous = self
                .spent_outpoints
                .insert(input.previous_output.clone(), txid);
            debug_assert!(previous.is_none(), "accepted outpoint spend is unique");
            let mirrored = persistent_map_replace(
                &mut self.snapshot_state.spent_outpoints,
                input.previous_output.clone(),
                txid,
            );
            debug_assert!(
                mirrored.is_none(),
                "accepted snapshot outpoint spend is unique"
            );
        }
        for parent in &direct_parents {
            let children = self.children.entry(*parent).or_default();
            Arc::make_mut(children).insert(txid);
            let children = children.clone();
            let previous =
                persistent_map_replace(&mut self.snapshot_state.children, *parent, children);
            debug_assert!(
                previous.is_some(),
                "accepted parent has a snapshot child set"
            );
        }
        let direct_parents = Arc::new(direct_parents);
        let previous = self.parents.insert(txid, direct_parents.clone());
        debug_assert!(
            previous.is_none(),
            "accepted transaction parent set is unique"
        );
        let previous =
            persistent_map_replace(&mut self.snapshot_state.parents, txid, direct_parents);
        debug_assert!(previous.is_none(), "accepted snapshot parent set is unique");
        let children = self.children.entry(txid).or_default().clone();
        let previous = persistent_map_replace(&mut self.snapshot_state.children, txid, children);
        debug_assert!(previous.is_none(), "accepted snapshot child set is unique");
        for name in &exclusive_names {
            self.exclusive_name_owners.insert(*name, txid);
        }
        let has_name_covenants = transaction
            .outputs
            .iter()
            .any(|output| output.covenant.kind.is_name());
        let exclusive_names = Arc::new(exclusive_names);
        let previous = self.exclusive_names.insert(txid, exclusive_names.clone());
        debug_assert!(previous.is_none(), "accepted exclusive-name set is unique");
        let previous = persistent_map_replace(
            &mut self.snapshot_state.exclusive_names,
            txid,
            exclusive_names,
        );
        debug_assert!(previous.is_none(), "accepted snapshot name set is unique");
        self.bytes = projected_bytes;
        self.total_fee = self.total_fee.saturating_add(u128::from(fee));
        let (ordered_txids, inserted) = self.ordered_txids.insert((sequence, txid));
        debug_assert!(inserted, "accepted mempool txid index entry is unique");
        self.ordered_txids = ordered_txids;
        let entry = Arc::new(entry);
        let transaction = Arc::new(transaction);
        let previous = self.entries.insert(txid, entry.clone());
        debug_assert!(previous.is_none(), "accepted mempool entry is unique");
        let previous = persistent_map_replace(&mut self.snapshot_state.entries, txid, entry);
        debug_assert!(previous.is_none(), "accepted snapshot entry is unique");
        let previous = self.transactions.insert(txid, transaction.clone());
        debug_assert!(previous.is_none(), "accepted mempool transaction is unique");
        let previous = persistent_map_replace(
            &mut self.snapshot_state.transactions,
            txid,
            transaction.clone(),
        );
        debug_assert!(
            previous.is_none(),
            "accepted snapshot transaction is unique"
        );
        if has_name_covenants {
            let previous = self
                .name_transactions
                .insert((sequence, txid), transaction.clone());
            debug_assert!(previous.is_none(), "accepted name transaction is unique");
            self.advance_name_revision();
        }
        if self
            .parents
            .get(&txid)
            .is_some_and(|parents| parents.is_empty())
        {
            self.insert_expiry_root((admitted_at, txid));
        }
        self.advance_generation();
        if !self.limit_size(txid, context.current_time) {
            return Ok(rejected("mempool-full"));
        }
        let accepted_name_transactions = self.accepted_name_transactions();
        contextual_verifier.transaction_accepted(&transaction, &accepted_name_transactions);
        Ok(Admission::Accepted(txid))
    }

    fn allow_free_relay(&mut self, policy_size: usize, now: u64, limit: u64) -> bool {
        let elapsed = if now >= self.last_free_time {
            (now - self.last_free_time) as f64
        } else {
            -((self.last_free_time - now) as f64)
        };
        let decay = 1.0 - 1.0 / HSD_FREE_DECAY_SECONDS as f64;
        self.free_count *= decay.powf(elapsed);
        self.last_free_time = now;
        let threshold = limit.saturating_mul(HSD_FREE_RELAY_MULTIPLIER) as f64;
        if self.free_count > threshold {
            return false;
        }
        self.free_count += policy_size as f64;
        true
    }

    /// Mirror HSD's `limitSize`: expire complete dependency-root packages
    /// first, then trim an over-capacity pool to 90% by the lower-ranked roots.
    /// A root's rank is the better of its own fee rate and the aggregate rate
    /// of its complete descendant package, so a high-fee child protects its
    /// low-fee ancestors from being separated.
    fn limit_size(&mut self, added: Txid, now: u64) -> bool {
        self.enforce_size_limit(now);
        self.entries.contains_key(&added)
    }

    fn limit_size_claim(&mut self, added: [u8; 32], now: u64) -> bool {
        self.enforce_size_limit(now);
        self.claims.contains_key(&added)
    }

    fn limit_size_airdrop(&mut self, added: [u8; 32], now: u64) -> bool {
        self.enforce_size_limit(now);
        self.airdrops.contains_key(&added)
    }

    fn enforce_size_limit(&mut self, now: u64) {
        while let Some((admitted_at, txid)) = self.next_expiry_root {
            #[cfg(test)]
            {
                self.expiry_root_checks = self.expiry_root_checks.saturating_add(1);
            }
            if now < admitted_at.saturating_add(self.limits.expiry_time) {
                break;
            }
            let removed = self.remove_transaction_without_generation(txid, true);
            if removed == 0 {
                // Fail closed against an internally stale key and guarantee
                // forward progress even in non-debug builds.
                self.remove_expiry_root((admitted_at, txid));
            }
            debug_assert_ne!(
                removed, 0,
                "expiry index referenced a missing transaction root"
            );
        }

        if self.member_count() <= self.limits.maximum_transactions
            && self.bytes <= self.limits.maximum_bytes
        {
            return;
        }

        let target_transactions = self
            .limits
            .maximum_transactions
            .saturating_mul(HSD_MEMPOOL_TRIM_NUMERATOR)
            / HSD_MEMPOOL_TRIM_DENOMINATOR;
        let target_bytes = self
            .limits
            .maximum_bytes
            .saturating_mul(HSD_MEMPOOL_TRIM_NUMERATOR)
            / HSD_MEMPOOL_TRIM_DENOMINATOR;
        let mut roots = Vec::new();
        for entry in self.entries.values() {
            if self
                .parents
                .get(&entry.txid)
                .is_some_and(|parents| !parents.is_empty())
            {
                continue;
            }
            let (fee, policy_size) = self.eviction_rate(entry.txid);
            roots.push((entry.txid, fee, policy_size, entry.admitted_at));
        }
        roots.sort_by(|left, right| {
            let left_rate = u128::from(left.1) * (right.2 as u128);
            let right_rate = u128::from(right.1) * (left.2 as u128);
            left_rate
                .cmp(&right_rate)
                .then_with(|| left.3.cmp(&right.3))
                .then_with(|| left.0.cmp(&right.0))
        });
        for (txid, _, _, _) in roots {
            self.remove_transaction_without_generation(txid, true);
            if self.member_count() <= target_transactions && self.bytes <= target_bytes {
                break;
            }
        }
        if self.member_count() <= target_transactions && self.bytes <= target_bytes {
            return;
        }

        let mut claims = self
            .claims
            .values()
            .map(|entry| {
                (
                    entry.hash,
                    entry.fee,
                    entry.policy_size.max(1),
                    entry.sequence,
                )
            })
            .collect::<Vec<_>>();
        claims.sort_by(|left, right| {
            let left_rate = u128::from(left.1) * (right.2 as u128);
            let right_rate = u128::from(right.1) * (left.2 as u128);
            left_rate
                .cmp(&right_rate)
                .then_with(|| left.3.cmp(&right.3))
                .then_with(|| left.0.cmp(&right.0))
        });
        for (hash, _, _, _) in claims {
            self.remove_claim_without_generation(&hash);
            if self.member_count() <= target_transactions && self.bytes <= target_bytes {
                break;
            }
        }
        if self.member_count() <= target_transactions && self.bytes <= target_bytes {
            return;
        }

        let mut airdrops = self
            .airdrops
            .values()
            .map(|entry| {
                (
                    entry.hash,
                    entry.fee,
                    entry.policy_size.max(1),
                    entry.sequence,
                )
            })
            .collect::<Vec<_>>();
        airdrops.sort_by(|left, right| {
            let left_rate = u128::from(left.1) * (right.2 as u128);
            let right_rate = u128::from(right.1) * (left.2 as u128);
            left_rate
                .cmp(&right_rate)
                .then_with(|| left.3.cmp(&right.3))
                .then_with(|| left.0.cmp(&right.0))
        });
        for (hash, _, _, _) in airdrops {
            self.remove_airdrop_without_generation(&hash);
            if self.member_count() <= target_transactions && self.bytes <= target_bytes {
                break;
            }
        }
    }

    fn insert_expiry_root(&mut self, key: (u64, Txid)) {
        let inserted = self.expiry_roots.insert(key);
        debug_assert!(inserted, "new dependency root has one expiry index entry");
        if self.next_expiry_root.is_none_or(|current| key < current) {
            self.next_expiry_root = Some(key);
        }
    }

    fn remove_expiry_root(&mut self, key: (u64, Txid)) -> bool {
        let removed = self.expiry_roots.remove(&key);
        if removed && self.next_expiry_root == Some(key) {
            self.next_expiry_root = self.expiry_roots.iter().next().copied();
        }
        removed
    }

    fn member_count(&self) -> usize {
        self.entries
            .len()
            .saturating_add(self.claims.len())
            .saturating_add(self.airdrops.len())
    }

    fn eviction_rate(&self, txid: Txid) -> (Amount, usize) {
        let entry = self
            .entries
            .get(&txid)
            .expect("accepted eviction root has a mempool entry");
        let descendants = self
            .collect_descendants(txid)
            .expect("accepted mempool descendants stay within configured bounds");
        let (descendant_fee, descendant_size) =
            descendants
                .iter()
                .fold((entry.fee, entry.policy_size), |(fee, size), descendant| {
                    let child = self
                        .entries
                        .get(descendant)
                        .expect("accepted descendant has a mempool entry");
                    (
                        fee.saturating_add(child.fee),
                        size.saturating_add(child.policy_size),
                    )
                });
        let descendant_rate = u128::from(descendant_fee) * (entry.policy_size as u128);
        let own_rate = u128::from(entry.fee) * (descendant_size as u128);
        if descendant_rate > own_rate {
            (descendant_fee, descendant_size.max(1))
        } else {
            (entry.fee, entry.policy_size.max(1))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_orphans_from<V, I>(
        &mut self,
        accepted_parents: I,
        context: &MempoolContext,
        view: &V,
        input_verifier: &dyn TransactionInputVerifier,
        contextual_verifier: &dyn ContextualTransactionVerifier,
    ) -> Result<(), MempoolError>
    where
        V: MempoolView,
        I: IntoIterator<Item = Txid>,
    {
        let mut ready = BTreeSet::new();
        for parent in accepted_parents {
            if let Some(children) = self.orphans_by_parent.get(&parent) {
                ready.extend(children.iter().copied());
            }
        }
        while let Some((sequence, txid)) = ready.pop_first() {
            if self
                .orphans
                .get(&txid)
                .is_none_or(|orphan| orphan.sequence != sequence)
            {
                continue;
            }
            #[cfg(test)]
            {
                self.orphan_promotion_attempts = self.orphan_promotion_attempts.saturating_add(1);
            }
            let Some(orphan) = self.remove_orphan(&txid) else {
                continue;
            };
            if let Admission::Accepted(promoted) = self.submit_checked(
                orphan.transaction,
                context,
                view,
                input_verifier,
                contextual_verifier,
            )? {
                if let Some(children) = self.orphans_by_parent.get(&promoted) {
                    ready.extend(children.iter().copied());
                }
            }
        }
        Ok(())
    }

    /// Remove every accepted and orphan transaction while retaining the
    /// configured resource bounds. This is the fail-closed reconciliation path
    /// for reorganizations until disconnected transactions can be contextually
    /// re-admitted through the complete consensus verifier.
    pub fn clear(&mut self) -> usize {
        let removed = self
            .entries
            .len()
            .saturating_add(self.orphans.len())
            .saturating_add(self.claims.len())
            .saturating_add(self.airdrops.len());
        self.free_count = 0.0;
        self.last_free_time = 0;
        if removed == 0 {
            return 0;
        }
        self.entries.clear();
        self.ordered_txids = OrderedTxidSnapshot::default();
        self.expiry_roots.clear();
        self.next_expiry_root = None;
        self.transactions.clear();
        if !self.name_transactions.is_empty() {
            self.name_transactions.clear();
            self.advance_name_revision();
        }
        self.orphans.clear();
        self.orphan_order.clear();
        self.orphans_by_parent.clear();
        self.spent_outpoints.clear();
        self.parents.clear();
        self.children.clear();
        self.exclusive_names.clear();
        self.exclusive_name_owners.clear();
        self.claims.clear();
        self.claim_names.clear();
        self.airdrops.clear();
        self.airdrop_positions.clear();
        self.snapshot_state = MempoolSnapshot::empty(self.snapshot_state.instance_nonce);
        self.bytes = 0;
        self.total_fee = 0;
        self.orphan_bytes = 0;
        self.advance_generation();
        removed
    }

    pub fn remove_claim(&mut self, hash: &[u8; 32]) -> bool {
        let removed = self.remove_claim_without_generation(hash);
        if removed {
            self.advance_generation();
        }
        removed
    }

    fn remove_claim_without_generation(&mut self, hash: &[u8; 32]) -> bool {
        let Some(entry) = self.claims.remove(hash) else {
            return false;
        };
        let mirrored = persistent_map_delete(&mut self.snapshot_state.claims, hash);
        debug_assert!(
            mirrored
                .as_ref()
                .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &entry)),
            "live and snapshot claim indexes share the removed entry"
        );
        let ordered = persistent_map_delete(
            &mut self.snapshot_state.claims_by_sequence,
            &(entry.sequence, entry.hash),
        );
        debug_assert!(
            ordered
                .as_ref()
                .is_some_and(|ordered| Arc::ptr_eq(ordered, &entry)),
            "claim admission-order index shares the removed entry"
        );
        if self.claim_names.get(&entry.name_hash) == Some(hash) {
            self.claim_names.remove(&entry.name_hash);
        }
        self.bytes = self.bytes.saturating_sub(entry.memory_usage);
        if entry.commit_height == 1 {
            self.total_fee = self.total_fee.saturating_sub(u128::from(entry.fee));
        }
        true
    }

    pub fn remove_airdrop(&mut self, hash: &[u8; 32]) -> bool {
        let removed = self.remove_airdrop_without_generation(hash);
        if removed {
            self.advance_generation();
        }
        removed
    }

    fn remove_airdrop_without_generation(&mut self, hash: &[u8; 32]) -> bool {
        let Some(entry) = self.airdrops.remove(hash) else {
            return false;
        };
        let mirrored = persistent_map_delete(&mut self.snapshot_state.airdrops, hash);
        debug_assert!(
            mirrored
                .as_ref()
                .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &entry)),
            "live and snapshot airdrop indexes share the removed entry"
        );
        let ordered = persistent_map_delete(
            &mut self.snapshot_state.airdrops_by_sequence,
            &(entry.sequence, entry.hash),
        );
        debug_assert!(
            ordered
                .as_ref()
                .is_some_and(|ordered| Arc::ptr_eq(ordered, &entry)),
            "airdrop admission-order index shares the removed entry"
        );
        if self.airdrop_positions.get(&entry.position) == Some(hash) {
            self.airdrop_positions.remove(&entry.position);
        }
        self.bytes = self.bytes.saturating_sub(entry.memory_usage);
        self.total_fee = self.total_fee.saturating_sub(u128::from(entry.fee));
        true
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
        for coinbase in transactions
            .iter()
            .filter(|transaction| is_coinbase(transaction))
        {
            for (index, input) in coinbase.inputs.iter().enumerate().skip(1) {
                let Some(output) = coinbase.outputs.get(index) else {
                    continue;
                };
                if output.covenant.kind == CovenantKind::Claim {
                    let Some(name_hash) = output.covenant.item_hash(0) else {
                        continue;
                    };
                    let Some(hash) = self.claim_names.get(&name_hash).copied() else {
                        continue;
                    };
                    removed += usize::from(self.remove_claim_without_generation(&hash));
                    continue;
                }
                if output.covenant.kind != CovenantKind::None {
                    continue;
                }
                let Some(raw) = input.witness.items.first() else {
                    continue;
                };
                let Ok(proof) = AirdropProof::decode(raw) else {
                    continue;
                };
                let Ok(position) = proof.position() else {
                    continue;
                };
                let Some(hash) = self.airdrop_positions.get(&position).copied() else {
                    continue;
                };
                removed += usize::from(self.remove_airdrop_without_generation(&hash));
            }
        }
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
            let oldest = self.orphan_order.first().map(|(_, txid)| *txid);
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
        let parents = transaction
            .inputs
            .iter()
            .map(|input| input.previous_output.txid)
            .collect::<BTreeSet<_>>();
        self.orphan_bytes = self.orphan_bytes.saturating_add(bytes);
        self.orphans.insert(
            txid,
            OrphanEntry {
                transaction,
                bytes,
                sequence,
            },
        );
        let inserted = self.orphan_order.insert((sequence, txid));
        debug_assert!(inserted, "orphan admission-order key is unique");
        for parent in parents {
            self.orphans_by_parent
                .entry(parent)
                .or_default()
                .insert((sequence, txid));
        }
        Ok(true)
    }

    fn remove_orphan(&mut self, txid: &Txid) -> Option<OrphanEntry> {
        let orphan = self.orphans.remove(txid)?;
        self.orphan_bytes = self.orphan_bytes.saturating_sub(orphan.bytes);
        let removed = self.orphan_order.remove(&(orphan.sequence, *txid));
        debug_assert!(removed, "removed orphan has an admission-order key");
        let parents = orphan
            .transaction
            .inputs
            .iter()
            .map(|input| input.previous_output.txid)
            .collect::<BTreeSet<_>>();
        for parent in parents {
            let remove_parent = self
                .orphans_by_parent
                .get_mut(&parent)
                .is_some_and(|children| {
                    children.remove(&(orphan.sequence, *txid));
                    children.is_empty()
                });
            if remove_parent {
                self.orphans_by_parent.remove(&parent);
            }
        }
        Some(orphan)
    }

    fn conflicts_with_mempool(&self, transaction: &Transaction) -> bool {
        let mut seen = HashSet::new();
        transaction.inputs.iter().any(|input| {
            !seen.insert(input.previous_output.clone())
                || self.spent_outpoints.contains_key(&input.previous_output)
        })
    }

    fn accepted_name_transactions(&self) -> AcceptedNameTransactions<'_> {
        AcceptedNameTransactions {
            revision: self.name_revision,
            transactions: &self.name_transactions,
        }
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
            .map(|children| children.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
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
        let Some(entry) = self.entries.remove(&txid) else {
            self.transactions.insert(txid, transaction);
            return false;
        };
        let mirrored_transaction =
            persistent_map_delete(&mut self.snapshot_state.transactions, &txid);
        debug_assert!(
            mirrored_transaction
                .as_ref()
                .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &transaction)),
            "live and snapshot transaction indexes share the removed payload"
        );
        let mirrored_entry = persistent_map_delete(&mut self.snapshot_state.entries, &txid);
        debug_assert!(
            mirrored_entry
                .as_ref()
                .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &entry)),
            "live and snapshot entry indexes share the removed record"
        );
        self.remove_expiry_root((entry.admitted_at, txid));
        self.bytes = self.bytes.saturating_sub(transaction.encode().len());
        self.total_fee = self.total_fee.saturating_sub(u128::from(entry.fee));
        let (ordered_txids, removed) = self.ordered_txids.remove(&(entry.sequence, txid));
        debug_assert!(removed, "removed mempool txid has an ordered index entry");
        self.ordered_txids = ordered_txids;
        if self
            .name_transactions
            .remove(&(entry.sequence, txid))
            .is_some()
        {
            self.advance_name_revision();
        }
        for input in &transaction.inputs {
            if self.spent_outpoints.get(&input.previous_output) == Some(&txid) {
                self.spent_outpoints.remove(&input.previous_output);
                let mirrored = persistent_map_delete(
                    &mut self.snapshot_state.spent_outpoints,
                    &input.previous_output,
                );
                debug_assert_eq!(mirrored, Some(txid));
            }
        }
        if let Some(parents) = self.parents.remove(&txid) {
            let mirrored = persistent_map_delete(&mut self.snapshot_state.parents, &txid);
            debug_assert!(
                mirrored
                    .as_ref()
                    .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &parents)),
                "live and snapshot parent indexes share the removed set"
            );
            for parent in parents.iter().copied() {
                if let Some(children) = self.children.get_mut(&parent) {
                    Arc::make_mut(children).remove(&txid);
                    let previous = persistent_map_replace(
                        &mut self.snapshot_state.children,
                        parent,
                        children.clone(),
                    );
                    debug_assert!(previous.is_some(), "retained parent has snapshot children");
                }
            }
        }
        if let Some(children) = self.children.remove(&txid) {
            let mirrored = persistent_map_delete(&mut self.snapshot_state.children, &txid);
            debug_assert!(
                mirrored
                    .as_ref()
                    .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &children)),
                "live and snapshot child indexes share the removed set"
            );
            for child in children.iter().copied() {
                if let Some(parents) = self.parents.get_mut(&child) {
                    let was_root = parents.is_empty();
                    Arc::make_mut(parents).remove(&txid);
                    let previous = persistent_map_replace(
                        &mut self.snapshot_state.parents,
                        child,
                        parents.clone(),
                    );
                    debug_assert!(previous.is_some(), "retained child has snapshot parents");
                    if !was_root && parents.is_empty() {
                        let child_admitted_at = self
                            .entries
                            .get(&child)
                            .expect("retained child has a mempool entry")
                            .admitted_at;
                        self.insert_expiry_root((child_admitted_at, child));
                    }
                }
            }
        }
        self.refresh_cached_ancestry(&affected_descendants);
        if let Some(names) = self.exclusive_names.remove(&txid) {
            let mirrored = persistent_map_delete(&mut self.snapshot_state.exclusive_names, &txid);
            debug_assert!(
                mirrored
                    .as_ref()
                    .is_some_and(|mirrored| Arc::ptr_eq(mirrored, &names)),
                "live and snapshot name indexes share the removed set"
            );
            for name in names.iter() {
                if self.exclusive_name_owners.get(name) == Some(&txid) {
                    self.exclusive_name_owners.remove(name);
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
            let entry = Arc::make_mut(entry);
            entry.parents = direct_parents.iter().copied().collect();
            entry.ancestor_count = ancestors.len();
            entry.ancestor_fee = ancestor_fee;
            entry.ancestor_weight = ancestor_weight;
            entry.ancestor_policy_size = ancestor_policy_size;
            let entry = self
                .entries
                .get(txid)
                .expect("refreshed descendant has a mempool entry")
                .clone();
            let previous = persistent_map_replace(&mut self.snapshot_state.entries, *txid, entry);
            debug_assert!(
                previous.is_some(),
                "refreshed descendant has a snapshot entry"
            );
        }
    }

    fn take_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1).max(1);
        sequence
    }

    fn advance_generation(&mut self) {
        self.set_generation(self.generation.saturating_add(1).max(1));
    }

    fn advance_name_revision(&mut self) {
        self.name_revision = self.name_revision.saturating_add(1).max(1);
    }

    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.snapshot_state.generation = generation;
    }
}

impl Mempool for MemoryMempool {
    fn info(&self) -> MempoolInfo {
        MempoolInfo {
            transaction_count: self.entries.len(),
            claim_count: self.claims.len(),
            airdrop_count: self.airdrops.len(),
            bytes: self.bytes,
            total_fee: Amount::try_from(self.total_fee).unwrap_or(Amount::MAX),
            orphan_count: self.orphans.len(),
            orphan_bytes: self.orphan_bytes,
            generation: self.generation,
        }
    }

    fn entries(&self) -> Vec<MempoolEntry> {
        self.ordered_txids
            .txids()
            .map(|txid| {
                self.entries
                    .get(&txid)
                    .expect("ordered mempool index references an accepted entry")
                    .as_ref()
                    .clone()
            })
            .collect()
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

fn rejected_claim(reason: impl Into<String>) -> ClaimAdmission {
    ClaimAdmission::Rejected {
        reason: reason.into(),
    }
}

fn rejected_airdrop(reason: impl Into<String>) -> AirdropAdmission {
    AirdropAdmission::Rejected {
        reason: reason.into(),
    }
}

struct AuthenticatedClaim {
    output: Output,
    verified: VerifiedClaim,
    inception: u64,
    expiration: u64,
}

fn authenticate_claim(
    claim: &Claim,
    context: &ClaimMempoolContext,
    dnssec: &dyn DnssecVerifier,
) -> Result<AuthenticatedClaim, &'static str> {
    let proof = OwnershipProof::decode(&claim.blob).map_err(|_| "bad-claim-proof")?;
    if !proof.is_sane() {
        return Err("bad-claim-proof");
    }
    let name = proof.name().ok_or("bad-claim-proof")?;
    let reserved = reserved_name(name).ok_or("bad-claim-proof")?;
    let data = proof
        .claim_data(context.network.claim_prefix())
        .map_err(|_| "bad-claim-data")?
        .ok_or("bad-claim-data")?;
    if context.network == Network::Mainnet
        && context.next_height
            < context
                .network
                .params()
                .deflation_height
                .saturating_add(100)
        && data.commit_height != 1
    {
        return Err("bad-claim-replacement");
    }
    if data.commit_height == 1 && data.fee > 1_000 * COIN {
        return Err("absurdly-high-fee");
    }
    if data.version == 31 {
        return Err("bad-claim-nulldata");
    }
    let (inception, expiration) = proof.window();
    if context.parent_time < u64::from(inception) || context.parent_time > u64::from(expiration) {
        return Err("bad-claim-time");
    }
    let name = reserved.name;
    let name_hash = hash_name(std::str::from_utf8(&name).map_err(|_| "bad-claim-proof")?)
        .map_err(|_| "bad-claim-proof")?;
    let address = Address::new(data.version, data.address.clone()).map_err(|_| "bad-claim-data")?;
    let output = Output {
        value: reserved
            .value
            .checked_sub(data.fee)
            .ok_or("bad-claim-data")?,
        address,
        covenant: Covenant {
            kind: CovenantKind::Claim,
            items: vec![
                name_hash.as_bytes().to_vec(),
                context.next_height.to_le_bytes().to_vec(),
                name,
                vec![u8::from(proof.is_weak())],
                data.commit_hash.to_vec(),
                data.commit_height.to_le_bytes().to_vec(),
            ],
        },
    };
    let verified = verify_claim_output(
        &claim.blob,
        &output,
        context.next_height,
        context.parent_time,
        context.network,
        ClaimFlags {
            hardened: context.hardening,
        },
        dnssec,
    )
    .map_err(|error| match error {
        ClaimConsensusError::WeakDisabled => "invalid-covenant",
        ClaimConsensusError::InitialFee => "absurdly-high-fee",
        ClaimConsensusError::InvalidTime => "bad-claim-time",
        ClaimConsensusError::Data(_) | ClaimConsensusError::MissingData => "bad-claim-data",
        _ => "bad-claim-proof",
    })?;
    Ok(AuthenticatedClaim {
        output,
        verified,
        inception: u64::from(inception),
        expiration: u64::from(expiration),
    })
}

/// HSD `BlockClaim.getWeight`: one count-byte delta, the ownership proof's
/// witness varbytes, and the base input/output contribution at scale four.
fn claim_coinbase_weight(proof_size: usize, output: &Output, name_size: usize) -> usize {
    let address_size = 2usize.saturating_add(output.address.hash.len());
    let base_size = 1usize
        .saturating_add(8)
        .saturating_add(address_size)
        .saturating_add(90)
        .saturating_add(name_size);
    1usize
        .saturating_add(varint_size(proof_size as u64))
        .saturating_add(proof_size)
        .saturating_add(base_size.saturating_mul(WITNESS_SCALE_FACTOR))
}

/// HSD `BlockAirdrop.getWeight`: one count-byte delta, the special input's
/// witness varbytes, and the base input/output contribution at scale four.
fn airdrop_coinbase_weight(proof_size: usize, output: &Output) -> usize {
    let address_size = 2usize.saturating_add(output.address.hash.len());
    let base_size = 1usize
        .saturating_add(8)
        .saturating_add(address_size)
        .saturating_add(5);
    1usize
        .saturating_add(varint_size(proof_size as u64))
        .saturating_add(proof_size)
        .saturating_add(base_size.saturating_mul(WITNESS_SCALE_FACTOR))
}

fn varint_size(value: u64) -> usize {
    match value {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
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
    #[error("mempool instance nonce initialization failed: {0}")]
    InstanceNonce(String),
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
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};

    use hns_primitives::MAX_BLOCK_WEIGHT;

    use super::*;
    use hns_consensus::{ConsensusError, OpenSslDnssecVerifier, TransactionInputVerifier};
    use hns_primitives::{
        sha3_256, Address, Block, Covenant, Input, Output, UnavailableAirdropSignatureVerifier,
        Witness,
    };

    fn test_mempool() -> MemoryMempool {
        MemoryMempool::new_for_test()
    }

    #[test]
    fn reserved_zero_instance_nonce_fails_closed() {
        assert!(matches!(
            MemoryMempool::with_validated_limits_and_instance_nonce(
                MempoolLimits::default(),
                [0; 32],
            ),
            Err(MempoolError::InstanceNonce(_))
        ));
    }

    fn decode_fixture_hex(raw: &str) -> Vec<u8> {
        raw.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid fixture hex"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect()
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
            address: Address::new(0, vec![3; 20]).expect("address"),
            covenant: covenant(),
        }
    }

    fn fixture_airdrop() -> AirdropProof {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let raw = decode_fixture_hex(fixture["faucet"]["raw"].as_str().expect("faucet raw"));
        AirdropProof::decode(&raw).expect("faucet proof")
    }

    fn fixture_claim_block() -> (serde_json::Value, Block) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-history-v1.json"
        ))
        .expect("mainnet claim fixture");
        let block = Block::decode(&decode_fixture_hex(
            fixture["block"]["raw"].as_str().expect("claim block raw"),
        ))
        .expect("mainnet claim block");
        (fixture, block)
    }

    fn claim_context(fixture: &serde_json::Value) -> ClaimMempoolContext {
        ClaimMempoolContext {
            next_height: u32::try_from(fixture["block"]["height"].as_u64().expect("height"))
                .expect("height fits u32"),
            transaction_start: 0,
            current_time: 100,
            parent_time: fixture["canonicalContext"]["parentTime"]
                .as_u64()
                .expect("parent time"),
            network: Network::Mainnet,
            hardening: false,
        }
    }

    fn airdrop_context() -> AirdropMempoolContext {
        AirdropMempoolContext {
            next_height: 2,
            transaction_start: 0,
            current_time: 100,
            airstop: false,
            hardening: false,
            goosig_disabled: false,
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
        spent_airdrops: HashSet<u32>,
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
                spent_airdrops: HashSet::new(),
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

    impl AirdropMempoolView for FixedView {
        fn airdrop_position_spent(&self, position: u32) -> Result<bool, ConsensusError> {
            Ok(self.spent_airdrops.contains(&position))
        }
    }

    impl ClaimMempoolView for FixedView {
        fn verify_claim_context(
            &self,
            _output: &Output,
            _claim: &VerifiedClaim,
            _context: &ClaimMempoolContext,
        ) -> Result<ClaimContextValidation, ConsensusError> {
            Ok(ClaimContextValidation::Valid)
        }
    }

    fn validate_persistent_map_node<K: Ord + std::fmt::Debug, V>(
        node: Option<&PersistentMapNode<K, V>>,
        minimum: Option<&K>,
        maximum: Option<&K>,
    ) -> (usize, u16) {
        let Some(node) = node else {
            return (0, 0);
        };
        assert!(minimum.is_none_or(|minimum| &node.key > minimum));
        assert!(maximum.is_none_or(|maximum| &node.key < maximum));
        let (left_size, left_height) =
            validate_persistent_map_node(node.left.as_deref(), minimum, Some(&node.key));
        let (right_size, right_height) =
            validate_persistent_map_node(node.right.as_deref(), Some(&node.key), maximum);
        let size = left_size.saturating_add(right_size).saturating_add(1);
        assert_eq!(node.size, size);
        assert_eq!(node.height, left_height.max(right_height).saturating_add(1));
        assert!(
            left_height.abs_diff(right_height) <= 1,
            "persistent map AVL balance violated at {:?}: left={left_height}, right={right_height}",
            node.key
        );
        (size, node.height)
    }

    fn validate_persistent_map<K: Ord + Clone + std::fmt::Debug, V: Clone>(
        map: &PersistentMap<K, V>,
    ) {
        let (size, height) = validate_persistent_map_node(map.root.as_deref(), None, None);
        assert_eq!(size, map.len());
        assert_eq!(usize::from(height), map.height());
        assert_eq!(map.iter().len(), map.len());
        assert_eq!(map.iter().count(), map.len());
    }

    fn assert_snapshot_mirror_exact(pool: &MemoryMempool) {
        let snapshot = &pool.snapshot_state;
        assert_eq!(snapshot.generation, pool.generation);
        assert_eq!(snapshot.entries.len(), pool.entries.len());
        assert_eq!(snapshot.transactions.len(), pool.transactions.len());
        assert_eq!(snapshot.spent_outpoints.len(), pool.spent_outpoints.len());
        assert_eq!(snapshot.parents.len(), pool.parents.len());
        assert_eq!(snapshot.children.len(), pool.children.len());
        assert_eq!(snapshot.exclusive_names.len(), pool.exclusive_names.len());
        assert_eq!(snapshot.claims.len(), pool.claims.len());
        assert_eq!(snapshot.claims_by_sequence.len(), pool.claims.len());
        assert_eq!(snapshot.airdrops.len(), pool.airdrops.len());
        assert_eq!(snapshot.airdrops_by_sequence.len(), pool.airdrops.len());

        for (txid, entry) in &pool.entries {
            assert!(Arc::ptr_eq(
                entry,
                snapshot.entries.get(txid).expect("mirrored entry")
            ));
        }
        for (txid, transaction) in &pool.transactions {
            assert!(Arc::ptr_eq(
                transaction,
                snapshot
                    .transactions
                    .get(txid)
                    .expect("mirrored transaction")
            ));
        }
        for (outpoint, txid) in &pool.spent_outpoints {
            assert_eq!(snapshot.spending_transaction(outpoint), Some(*txid));
        }
        for (txid, parents) in &pool.parents {
            assert!(Arc::ptr_eq(
                parents,
                snapshot.parents.get(txid).expect("mirrored parent set")
            ));
        }
        for (txid, children) in &pool.children {
            assert!(Arc::ptr_eq(
                children,
                snapshot.children.get(txid).expect("mirrored child set")
            ));
        }
        for (txid, names) in &pool.exclusive_names {
            assert!(Arc::ptr_eq(
                names,
                snapshot
                    .exclusive_names
                    .get(txid)
                    .expect("mirrored exclusive-name set")
            ));
        }
        for (hash, claim) in &pool.claims {
            assert!(Arc::ptr_eq(
                claim,
                snapshot.claims.get(hash).expect("mirrored claim")
            ));
            assert!(Arc::ptr_eq(
                claim,
                snapshot
                    .claims_by_sequence
                    .get(&(claim.sequence, *hash))
                    .expect("ordered mirrored claim")
            ));
        }
        for (hash, airdrop) in &pool.airdrops {
            assert!(Arc::ptr_eq(
                airdrop,
                snapshot.airdrops.get(hash).expect("mirrored airdrop")
            ));
            assert!(Arc::ptr_eq(
                airdrop,
                snapshot
                    .airdrops_by_sequence
                    .get(&(airdrop.sequence, *hash))
                    .expect("ordered mirrored airdrop")
            ));
        }

        validate_persistent_map(&snapshot.entries);
        validate_persistent_map(&snapshot.transactions);
        validate_persistent_map(&snapshot.spent_outpoints);
        validate_persistent_map(&snapshot.parents);
        validate_persistent_map(&snapshot.children);
        validate_persistent_map(&snapshot.exclusive_names);
        validate_persistent_map(&snapshot.claims);
        validate_persistent_map(&snapshot.claims_by_sequence);
        validate_persistent_map(&snapshot.airdrops);
        validate_persistent_map(&snapshot.airdrops_by_sequence);
    }

    fn snapshot_total_mutation_nodes(snapshot: &MempoolSnapshot) -> usize {
        [
            snapshot.entries.total_mutation_nodes,
            snapshot.transactions.total_mutation_nodes,
            snapshot.spent_outpoints.total_mutation_nodes,
            snapshot.parents.total_mutation_nodes,
            snapshot.children.total_mutation_nodes,
            snapshot.exclusive_names.total_mutation_nodes,
            snapshot.claims.total_mutation_nodes,
            snapshot.claims_by_sequence.total_mutation_nodes,
            snapshot.airdrops.total_mutation_nodes,
            snapshot.airdrops_by_sequence.total_mutation_nodes,
        ]
        .into_iter()
        .fold(0usize, usize::saturating_add)
    }

    fn assert_snapshot_roots_identical(left: &MempoolSnapshot, right: &MempoolSnapshot) {
        assert!(left.entries.is_same_root(&right.entries));
        assert!(left.transactions.is_same_root(&right.transactions));
        assert!(left.spent_outpoints.is_same_root(&right.spent_outpoints));
        assert!(left.parents.is_same_root(&right.parents));
        assert!(left.children.is_same_root(&right.children));
        assert!(left.exclusive_names.is_same_root(&right.exclusive_names));
        assert!(left.claims.is_same_root(&right.claims));
        assert!(left
            .claims_by_sequence
            .is_same_root(&right.claims_by_sequence));
        assert!(left.airdrops.is_same_root(&right.airdrops));
        assert!(left
            .airdrops_by_sequence
            .is_same_root(&right.airdrops_by_sequence));
    }

    fn assert_cached_info_exact(pool: &MemoryMempool) {
        let expected_ordered_txids = pool
            .entries
            .values()
            .map(|entry| (entry.sequence, entry.txid))
            .collect::<BTreeSet<_>>();
        let expected_expiry_roots = pool
            .entries
            .values()
            .filter(|entry| {
                pool.parents
                    .get(&entry.txid)
                    .is_some_and(|parents| parents.is_empty())
            })
            .map(|entry| (entry.admitted_at, entry.txid))
            .collect::<BTreeSet<_>>();
        let expected_bytes = pool
            .transactions
            .values()
            .fold(0usize, |total, transaction| {
                total.saturating_add(transaction.encode().len())
            })
            .saturating_add(pool.claims.values().fold(0usize, |total, entry| {
                total.saturating_add(entry.memory_usage)
            }))
            .saturating_add(pool.airdrops.values().fold(0usize, |total, entry| {
                total.saturating_add(entry.memory_usage)
            }));
        let expected_orphan_bytes = pool
            .orphans
            .values()
            .fold(0usize, |total, entry| total.saturating_add(entry.bytes));
        let expected_total_fee = pool
            .entries
            .values()
            .fold(0u128, |total, entry| {
                total.saturating_add(u128::from(entry.fee))
            })
            .saturating_add(
                pool.claims
                    .values()
                    .filter(|entry| entry.commit_height == 1)
                    .fold(0u128, |total, entry| {
                        total.saturating_add(u128::from(entry.fee))
                    }),
            )
            .saturating_add(pool.airdrops.values().fold(0u128, |total, entry| {
                total.saturating_add(u128::from(entry.fee))
            }));
        let info = pool.info();
        assert_eq!(info.transaction_count, pool.entries.len());
        assert_eq!(info.claim_count, pool.claims.len());
        assert_eq!(info.airdrop_count, pool.airdrops.len());
        assert_eq!(info.orphan_count, pool.orphans.len());
        assert_eq!(info.bytes, expected_bytes);
        assert_eq!(info.orphan_bytes, expected_orphan_bytes);
        assert_eq!(pool.total_fee, expected_total_fee);
        assert_eq!(
            pool.ordered_txids.iter().copied().collect::<BTreeSet<_>>(),
            expected_ordered_txids
        );
        assert_eq!(pool.expiry_roots, expected_expiry_roots);
        assert_eq!(
            pool.next_expiry_root,
            expected_expiry_roots.iter().next().copied()
        );
        assert_eq!(
            info.total_fee,
            Amount::try_from(expected_total_fee).unwrap_or(Amount::MAX)
        );
        assert_snapshot_mirror_exact(pool);
    }

    fn ordered_test_key(sequence: u64) -> OrderedTxidKey {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&sequence.to_be_bytes());
        (sequence, Txid::new(raw))
    }

    fn reference_visit_package(
        snapshot: &MempoolSnapshot,
        txid: Txid,
        visiting: &mut HashSet<Txid>,
        ordered: &mut Vec<Txid>,
    ) -> Result<(), MempoolError> {
        if ordered.contains(&txid) {
            return Ok(());
        }
        if !visiting.insert(txid) {
            return Err(MempoolError::DependencyCycle(txid));
        }
        if let Some(parents) = snapshot.parents.get(&txid) {
            for parent in parents.iter().copied() {
                reference_visit_package(snapshot, parent, visiting, ordered)?;
            }
        }
        visiting.remove(&txid);
        ordered.push(txid);
        Ok(())
    }

    fn validate_ordered_txid_node(
        node: Option<&OrderedTxidNode>,
        minimum: Option<OrderedTxidKey>,
        maximum: Option<OrderedTxidKey>,
    ) -> (usize, u16) {
        let Some(node) = node else {
            return (0, 0);
        };
        assert!(minimum.is_none_or(|minimum| node.key > minimum));
        assert!(maximum.is_none_or(|maximum| node.key < maximum));
        let (left_count, left_height) =
            validate_ordered_txid_node(node.left.as_deref(), minimum, Some(node.key));
        let (right_count, right_height) =
            validate_ordered_txid_node(node.right.as_deref(), Some(node.key), maximum);
        assert_eq!(node.height, left_height.max(right_height).saturating_add(1));
        assert!(
            left_height.abs_diff(right_height) <= 1,
            "persistent AVL balance violated at {:?}: left={left_height}, right={right_height}",
            node.key
        );
        (
            left_count
                .checked_add(right_count)
                .and_then(|count| count.checked_add(1))
                .expect("test node count"),
            node.height,
        )
    }

    fn validate_ordered_txid_snapshot(snapshot: &OrderedTxidSnapshot) -> u16 {
        let (count, height) = validate_ordered_txid_node(snapshot.root.as_deref(), None, None);
        assert_eq!(count, snapshot.len());
        assert_eq!(snapshot.is_empty(), count == 0);
        height
    }

    fn collect_ordered_txid_node_pointers(
        node: Option<&Arc<OrderedTxidNode>>,
        pointers: &mut HashSet<usize>,
    ) {
        let Some(node) = node else {
            return;
        };
        pointers.insert(Arc::as_ptr(node) as usize);
        collect_ordered_txid_node_pointers(node.left.as_ref(), pointers);
        collect_ordered_txid_node_pointers(node.right.as_ref(), pointers);
    }

    fn count_shared_ordered_txid_nodes(
        node: Option<&Arc<OrderedTxidNode>>,
        pointers: &HashSet<usize>,
    ) -> usize {
        let Some(node) = node else {
            return 0;
        };
        usize::from(pointers.contains(&(Arc::as_ptr(node) as usize)))
            .saturating_add(count_shared_ordered_txid_nodes(
                node.left.as_ref(),
                pointers,
            ))
            .saturating_add(count_shared_ordered_txid_nodes(
                node.right.as_ref(),
                pointers,
            ))
    }

    #[test]
    fn persistent_map_is_adversarially_balanced_and_range_bounded() {
        const MEMBERS: u64 = 4_096;
        let mut map = PersistentMap::default();
        for key in 0..MEMBERS {
            let previous_height = map.height();
            let (next, previous) = map.insert(key, Arc::new(key));
            assert!(previous.is_none());
            assert!(
                next.mutation_nodes <= 8usize.saturating_mul(previous_height.saturating_add(1)),
                "insertion copied {} nodes at height {previous_height}",
                next.mutation_nodes
            );
            map = next;
        }
        validate_persistent_map(&map);
        assert!(
            map.height()
                <= 2usize
                    .saturating_mul(usize::try_from(MEMBERS.ilog2() + 1).expect("height bound")),
            "sorted attacker-controlled keys produced height {}",
            map.height()
        );

        let lower = MEMBERS - 17;
        let mut tail = map.iter_after(Some(&lower));
        assert_eq!(tail.len(), 16);
        assert_eq!(tail.size_hint(), (16, Some(16)));
        assert_eq!(tail.next().map(|(key, _)| *key), Some(lower + 1));
        assert_eq!(tail.len(), 15);
        assert_eq!(tail.last().map(|(key, _)| *key), Some(MEMBERS - 1));

        let retained = map.clone();
        let cloned = retained.clone();
        assert!(retained.is_same_root(&cloned));
        assert_eq!(
            retained.total_mutation_nodes, cloned.total_mutation_nodes,
            "O(1) clone must allocate no tree nodes"
        );
        for key in (0..MEMBERS).rev() {
            let previous_height = map.height();
            let (next, previous) = map.remove(&key);
            assert_eq!(previous.as_deref(), Some(&key));
            assert!(
                next.mutation_nodes <= 8usize.saturating_mul(previous_height.saturating_add(1)),
                "removal copied {} nodes at height {previous_height}",
                next.mutation_nodes
            );
            map = next;
        }
        assert!(map.is_empty());
        assert_eq!(retained.len(), usize::try_from(MEMBERS).expect("members"));
        assert_eq!(retained.get(&0).map(Arc::as_ref), Some(&0));
        validate_persistent_map(&retained);
    }

    #[test]
    fn shared_ancestor_package_matches_reference_with_linear_dependency_work() {
        let txids = (0..6u64)
            .map(|sequence| ordered_test_key(sequence).1)
            .collect::<Vec<_>>();
        let dependencies = [
            Vec::new(),
            vec![txids[0]],
            vec![txids[0]],
            vec![txids[1], txids[2]],
            vec![txids[1], txids[2]],
            vec![txids[3], txids[4]],
        ];
        let mut snapshot = MempoolSnapshot::empty([0xa5; 32]);
        for (sequence, (txid, parents)) in txids.iter().zip(dependencies.iter()).enumerate() {
            let entry = Arc::new(MempoolEntry {
                txid: *txid,
                fee: 1,
                base_size: 1,
                witness_size: 0,
                weight: 1,
                policy_size: 1,
                sigops: 0,
                opens: 0,
                updates: 0,
                renewals: 0,
                parents: parents.clone(),
                ancestor_count: 0,
                ancestor_fee: 1,
                ancestor_weight: 1,
                ancestor_policy_size: 1,
                admitted_at: 0,
                sequence: u64::try_from(sequence).expect("sequence"),
            });
            persistent_map_replace(&mut snapshot.entries, *txid, entry);
            persistent_map_replace(
                &mut snapshot.parents,
                *txid,
                Arc::new(parents.iter().copied().collect()),
            );
            persistent_map_replace(&mut snapshot.exclusive_names, *txid, Arc::new(Vec::new()));
        }

        let mut reference = Vec::new();
        reference_visit_package(&snapshot, txids[5], &mut HashSet::new(), &mut reference)
            .expect("reference package");
        let package = snapshot
            .package_for(txids[5], &HashSet::new())
            .expect("persistent package");
        assert_eq!(package.txids, reference);
        assert_eq!(package.txids, txids);

        let mut visiting = HashSet::new();
        let mut emitted = HashSet::new();
        let mut ordered = Vec::new();
        let mut dependency_visits = 0usize;
        snapshot
            .visit_package(
                txids[5],
                &HashSet::new(),
                &mut visiting,
                &mut emitted,
                &mut ordered,
                &mut dependency_visits,
            )
            .expect("counted package");
        let dependency_edges = dependencies.iter().map(Vec::len).sum::<usize>();
        assert_eq!(dependency_visits, dependency_edges + 1);
        assert_eq!(emitted.len(), txids.len());
        assert_eq!(ordered, reference);
    }

    #[test]
    fn persistent_ordered_txids_bound_sorted_mutation_and_share_generations() {
        const MEMBERS: u64 = 4_096;
        let mut snapshot = OrderedTxidSnapshot::default();
        for sequence in 0..MEMBERS {
            let (next, inserted) = snapshot.insert(ordered_test_key(sequence));
            assert!(inserted);
            snapshot = next;
        }
        let height = validate_ordered_txid_snapshot(&snapshot);
        assert!(
            height <= 2 * u16::try_from(MEMBERS.ilog2() + 1).expect("height bound"),
            "sorted insertions produced an unexpectedly tall AVL: {height}"
        );

        let ordered = snapshot.iter().copied().collect::<Vec<_>>();
        assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(ordered.len(), usize::try_from(MEMBERS).expect("members"));
        let mut iterator = snapshot.iter();
        let mut remaining = usize::try_from(MEMBERS).expect("members");
        while iterator.next().is_some() {
            remaining -= 1;
            assert_eq!(iterator.size_hint(), (remaining, Some(remaining)));
            assert_eq!(iterator.len(), remaining);
        }
        assert_eq!(iterator.size_hint(), (0, Some(0)));

        let (duplicate, inserted) = snapshot.insert(ordered_test_key(MEMBERS / 2));
        assert!(!inserted);
        assert!(snapshot.is_same_generation(&duplicate));
        let (missing, removed) = snapshot.remove(&ordered_test_key(MEMBERS + 9));
        assert!(!removed);
        assert!(snapshot.is_same_generation(&missing));

        let retained = snapshot.clone();
        let mut retained_pointers = HashSet::new();
        collect_ordered_txid_node_pointers(retained.root.as_ref(), &mut retained_pointers);
        let (extended, inserted) = snapshot.insert(ordered_test_key(MEMBERS));
        assert!(inserted);
        assert_eq!(extended.len(), retained.len() + 1);
        assert_eq!(retained.len(), usize::try_from(MEMBERS).expect("members"));
        let shared = count_shared_ordered_txid_nodes(extended.root.as_ref(), &retained_pointers);
        assert!(
            shared >= retained.len().saturating_sub(64),
            "path-copy insertion shared only {shared} of {} retained nodes",
            retained.len()
        );
        validate_ordered_txid_snapshot(&extended);

        let mut reduced = extended;
        for sequence in 0..=MEMBERS {
            let (next, removed) = reduced.remove(&ordered_test_key(sequence));
            assert!(removed, "missing sorted removal {sequence}");
            reduced = next;
            if sequence % 256 == 0 || sequence == MEMBERS {
                validate_ordered_txid_snapshot(&reduced);
            }
        }
        assert!(reduced.is_empty());
        assert_eq!(retained.len(), usize::try_from(MEMBERS).expect("members"));
        assert_eq!(
            retained.txids().next(),
            Some(ordered_test_key(0).1),
            "old generation changed after persistent removals"
        );
        validate_ordered_txid_snapshot(&retained);
    }

    #[test]
    fn claim_admission_indexes_revalidates_and_reconciles_coinbases() {
        let (fixture, block) = fixture_claim_block();
        let coinbase = block.transactions[0].clone();
        let blob = coinbase.inputs[1].witness.items[0].clone();
        let claim = Claim { blob };
        let hash = claim.hash();
        let context = claim_context(&fixture);
        let view = FixedView::default();
        let dnssec = OpenSslDnssecVerifier;
        let mut pool = test_mempool();
        assert_eq!(
            pool.submit_claim_with_context(claim.clone(), &context, &view, &dnssec)
                .expect("claim admission"),
            ClaimAdmission::Accepted(hash)
        );
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().claim_count, 1);
        assert_eq!(pool.info().bytes, 500 + claim.blob.len());
        let retained_claims = pool.snapshot();
        let claim_page = pool.claim_entries_page(None, 1);
        assert_eq!(claim_page.len(), 1);
        assert!(Arc::ptr_eq(
            &claim_page[0],
            pool.claims.get(&hash).expect("live claim")
        ));
        assert!(Arc::ptr_eq(
            pool.claims.get(&hash).expect("live claim"),
            retained_claims.claims.get(&hash).expect("snapshot claim")
        ));
        let claim_cursor = (claim_page[0].sequence, hash);
        assert!(pool.claim_entries_page(Some(claim_cursor), 1).is_empty());
        assert!(matches!(
            pool.submit_claim_with_context(claim.clone(), &context, &view, &dnssec)
                .expect("duplicate claim"),
            ClaimAdmission::Rejected { reason } if reason == "txn-already-in-mempool"
        ));

        let mut bounded = MemoryMempool::with_limits(MempoolLimits {
            maximum_bytes: 500 + claim.blob.len() - 1,
            ..MempoolLimits::default()
        })
        .expect("bounded claim pool");
        assert!(matches!(
            bounded
                .submit_claim_with_context(claim.clone(), &context, &view, &dnssec)
                .expect("bounded claim admission"),
            ClaimAdmission::Rejected { reason } if reason == "mempool-full"
        ));
        assert_cached_info_exact(&bounded);
        assert_eq!(bounded.info().claim_count, 0);

        assert_eq!(pool.remove_confirmed(std::slice::from_ref(&coinbase)), 1);
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().claim_count, 0);
        assert_eq!(
            retained_claims.claim(&hash).map(|entry| &entry.claim),
            Some(&claim)
        );
        assert!(pool
            .reconcile_claims_with_context(&[coinbase], &context, &view, &dnssec)
            .expect("claim disconnect reconciliation"));
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().claim_count, 2);
    }

    #[test]
    fn airdrop_admission_indexes_revalidates_and_removes_confirmed_proofs() {
        let proof = fixture_airdrop();
        let hash = proof.hash().expect("proof hash");
        let position = proof.position().expect("proof position");
        let raw_size = proof.encode().expect("proof raw").len();
        let mut pool = test_mempool();
        let view = FixedView::default();
        assert_eq!(
            pool.submit_airdrop_with_context(
                proof.clone(),
                &airdrop_context(),
                &view,
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("airdrop admission"),
            AirdropAdmission::Accepted(hash)
        );
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().airdrop_count, 1);
        let retained_airdrops = pool.snapshot();
        let airdrop_page = pool.airdrop_entries_page(None, 1);
        assert_eq!(airdrop_page.len(), 1);
        assert!(Arc::ptr_eq(
            &airdrop_page[0],
            pool.airdrops.get(&hash).expect("live airdrop")
        ));
        assert!(Arc::ptr_eq(
            pool.airdrops.get(&hash).expect("live airdrop"),
            retained_airdrops
                .airdrops
                .get(&hash)
                .expect("snapshot airdrop")
        ));
        let airdrop_cursor = (airdrop_page[0].sequence, hash);
        assert!(pool
            .airdrop_entries_page(Some(airdrop_cursor), 1)
            .is_empty());

        let mut bounded = MemoryMempool::with_limits(MempoolLimits {
            maximum_bytes: 300 + raw_size - 1,
            ..MempoolLimits::default()
        })
        .expect("bounded airdrop pool");
        assert!(matches!(
            bounded
                .submit_airdrop_with_context(
                    proof.clone(),
                    &airdrop_context(),
                    &view,
                    &UnavailableAirdropSignatureVerifier,
                )
                .expect("bounded admission"),
            AirdropAdmission::Rejected { reason } if reason == "mempool-full"
        ));
        assert_cached_info_exact(&bounded);
        assert_eq!(bounded.info().airdrop_count, 0);
        assert_eq!(pool.info().bytes, 300 + raw_size);
        assert_eq!(pool.info().total_fee, proof.fee);
        assert!(matches!(
            pool.submit_airdrop_with_context(
                proof.clone(),
                &airdrop_context(),
                &view,
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("duplicate admission"),
            AirdropAdmission::Rejected { reason } if reason == "txn-already-in-mempool"
        ));

        let mut spent_view = FixedView::default();
        spent_view.spent_airdrops.insert(position);
        assert!(pool
            .revalidate_airdrops_with_context(
                &airdrop_context(),
                &spent_view,
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("spent revalidation"));
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().airdrop_count, 0);
        assert_eq!(
            retained_airdrops.airdrop(&hash).map(|entry| &entry.proof),
            Some(&proof)
        );

        let disabled = AirdropMempoolContext {
            airstop: true,
            ..airdrop_context()
        };
        assert!(matches!(
            pool.submit_airdrop_with_context(
                proof.clone(),
                &disabled,
                &view,
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("disabled admission"),
            AirdropAdmission::Rejected { reason } if reason == "bad-airdrop-disabled"
        ));

        assert!(matches!(
            pool.submit_airdrop_with_context(
                proof.clone(),
                &airdrop_context(),
                &view,
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("readmit"),
            AirdropAdmission::Accepted(_)
        ));
        assert_cached_info_exact(&pool);
        let coinbase = Transaction {
            version: 0,
            inputs: vec![
                Input {
                    previous_output: Outpoint::null(),
                    sequence: 0,
                    witness: Witness::default(),
                },
                Input {
                    previous_output: Outpoint::null(),
                    sequence: u32::MAX,
                    witness: Witness {
                        items: vec![proof.encode().expect("proof raw")],
                    },
                },
            ],
            outputs: vec![output(1), output(proof.value() - proof.fee)],
            locktime: 2,
        };
        assert_eq!(pool.remove_confirmed(std::slice::from_ref(&coinbase)), 1);
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().airdrop_count, 0);
        assert!(pool
            .reconcile_airdrops_with_context(
                &[coinbase],
                &airdrop_context(),
                &view,
                &UnavailableAirdropSignatureVerifier,
            )
            .expect("disconnect reconciliation"));
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().airdrop_count, 1);
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
            _accepted_name_transactions: &AcceptedNameTransactions<'_>,
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
            accepted_name_transactions: &AcceptedNameTransactions<'_>,
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

    struct IncrementalNameOverlayProbe {
        cached_revision: AtomicU64,
        rebuilds: AtomicUsize,
        replayed_transactions: AtomicUsize,
    }

    impl Default for IncrementalNameOverlayProbe {
        fn default() -> Self {
            Self {
                cached_revision: AtomicU64::new(u64::MAX),
                rebuilds: AtomicUsize::new(0),
                replayed_transactions: AtomicUsize::new(0),
            }
        }
    }

    impl ContextualTransactionVerifier for IncrementalNameOverlayProbe {
        fn verify(
            &self,
            _transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            accepted: &AcceptedNameTransactions<'_>,
        ) -> Result<(), ConsensusError> {
            if self
                .cached_revision
                .swap(accepted.revision(), AtomicOrdering::Relaxed)
                != accepted.revision()
            {
                self.rebuilds.fetch_add(1, AtomicOrdering::Relaxed);
                self.replayed_transactions
                    .fetch_add(accepted.iter().count(), AtomicOrdering::Relaxed);
            }
            Ok(())
        }

        fn transaction_accepted(
            &self,
            _transaction: &Transaction,
            accepted: &AcceptedNameTransactions<'_>,
        ) {
            self.cached_revision
                .store(accepted.revision(), AtomicOrdering::Relaxed);
        }
    }

    struct RejectName(&'static [u8]);

    impl ContextualTransactionVerifier for RejectName {
        fn verify(
            &self,
            transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            _accepted_name_transactions: &AcceptedNameTransactions<'_>,
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
        submit_at(pool, transaction, view, 0)
    }

    fn submit_at(
        pool: &mut MemoryMempool,
        transaction: Transaction,
        view: &FixedView,
        current_time: u64,
    ) -> Admission {
        let context = MempoolContext {
            current_time,
            ..MempoolContext::testing(2, 2)
        };
        pool.submit_with_context(transaction, &context, view, &AllowInputs, &AllowContext)
            .expect("admission")
    }

    #[test]
    fn compatibility_submit_is_fail_closed() {
        let mut pool = test_mempool();
        assert!(matches!(
            pool.submit(transaction(outpoint(1, 0), 9)).expect("submit"),
            Admission::Rejected { reason } if reason == "verified-mempool-context-required"
        ));
    }

    #[test]
    fn ordered_txid_snapshot_is_generation_stable_across_mutation() {
        let first_input = outpoint(0xc1, 0);
        let second_input = outpoint(0xc2, 0);
        let mut view = FixedView::with_coin(first_input.clone(), 20);
        view.coins.insert(
            second_input.clone(),
            Coin {
                outpoint: second_input.clone(),
                value: 20,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            },
        );
        let first = transaction(first_input, 15);
        let first_txid = first.txid();
        let second = transaction(second_input, 14);
        let second_txid = second.txid();
        let mut pool = test_mempool();
        assert!(matches!(
            submit(&mut pool, first, &view),
            Admission::Accepted(_)
        ));
        let first_generation = pool.ordered_txids_snapshot();
        assert_eq!(
            first_generation
                .iter()
                .map(|(_, txid)| *txid)
                .collect::<Vec<_>>(),
            vec![first_txid]
        );

        assert!(matches!(
            submit(&mut pool, second, &view),
            Admission::Accepted(_)
        ));
        let second_generation = pool.ordered_txids_snapshot();
        assert_eq!(
            first_generation
                .iter()
                .map(|(_, txid)| *txid)
                .collect::<Vec<_>>(),
            vec![first_txid],
            "a retained RPC view must not observe later admission"
        );
        assert_eq!(
            second_generation
                .iter()
                .map(|(_, txid)| *txid)
                .collect::<Vec<_>>(),
            vec![first_txid, second_txid]
        );

        assert_eq!(pool.remove_transaction(first_txid, false), 1);
        assert_eq!(
            second_generation
                .iter()
                .map(|(_, txid)| *txid)
                .collect::<Vec<_>>(),
            vec![first_txid, second_txid],
            "a retained RPC view must not observe later removal"
        );
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn full_snapshot_capture_is_o1_and_shares_transaction_payloads() {
        let first_input = outpoint(0xb1, 0);
        let second_input = outpoint(0xb2, 0);
        let mut view = FixedView::with_coin(first_input.clone(), 20);
        view.coins.insert(
            second_input.clone(),
            Coin {
                outpoint: second_input.clone(),
                value: 20,
                height: 1,
                coinbase: false,
                address: Address::new(0, vec![3; 20]).expect("address"),
                covenant: covenant(),
            },
        );
        let mut first = transaction(first_input.clone(), 15);
        first.inputs[0].witness.items.push(vec![0x5a; 16 * 1024]);
        let first_txid = first.txid();
        let second = transaction(second_input, 14);
        let second_txid = second.txid();
        let mut pool = test_mempool();
        assert!(matches!(
            submit(&mut pool, first.clone(), &view),
            Admission::Accepted(id) if id == first_txid
        ));

        let retained = pool.snapshot();
        assert_eq!(
            retained.spending_transaction(&first_input),
            Some(first_txid)
        );
        let allocations = snapshot_total_mutation_nodes(&retained);
        let cloned = retained.clone();
        assert_snapshot_roots_identical(&retained, &cloned);
        assert_eq!(snapshot_total_mutation_nodes(&cloned), allocations);
        assert!(Arc::ptr_eq(
            pool.transactions
                .get(&first_txid)
                .expect("live transaction"),
            retained
                .transactions
                .get(&first_txid)
                .expect("snapshot transaction")
        ));

        assert!(matches!(
            submit(&mut pool, second, &view),
            Admission::Accepted(id) if id == second_txid
        ));
        assert_eq!(retained.transaction(&first_txid), Some(&first));
        assert!(retained.transaction(&second_txid).is_none());
        assert!(Arc::ptr_eq(
            pool.transactions
                .get(&first_txid)
                .expect("live transaction"),
            retained
                .transactions
                .get(&first_txid)
                .expect("retained transaction")
        ));

        assert_eq!(pool.remove_transaction(first_txid, false), 1);
        assert_eq!(retained.transaction(&first_txid), Some(&first));
        assert_eq!(
            retained.spending_transaction(&first_input),
            Some(first_txid)
        );
        assert!(pool.snapshot().spending_transaction(&first_input).is_none());
        assert!(pool.transaction(&first_txid).is_none());
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn parent_removal_path_copies_only_logarithmic_paths_per_affected_descendant() {
        const MEMBERS: usize = 16;
        let root_input = outpoint(0xb3, 0);
        let mut pool = test_mempool();
        let root = transaction(root_input.clone(), 1_000);
        assert!(matches!(
            submit(&mut pool, root, &FixedView::with_coin(root_input, 1_001)),
            Admission::Accepted(_)
        ));
        let mut txids = pool.snapshot().txids().collect::<Vec<_>>();
        for index in 1..MEMBERS {
            let parent = *txids.last().expect("chain parent");
            let child = transaction(
                Outpoint {
                    txid: parent,
                    index: 0,
                },
                1_000u64.saturating_sub(u64::try_from(index).expect("index")),
            );
            let child_txid = child.txid();
            assert!(matches!(
                submit(&mut pool, child, &FixedView::default()),
                Admission::Accepted(id) if id == child_txid
            ));
            txids.push(child_txid);
        }
        let root_txid = txids[0];
        let retained = pool.snapshot();
        let before_allocations = snapshot_total_mutation_nodes(&retained);
        assert_eq!(
            retained.children(&root_txid).collect::<Vec<_>>(),
            vec![txids[1]]
        );

        assert_eq!(pool.remove_transaction(root_txid, false), 1);
        let current = pool.snapshot();
        let copied = snapshot_total_mutation_nodes(&current)
            .checked_sub(before_allocations)
            .expect("allocation counters are monotonic");
        let logarithmic_height = usize::try_from(MEMBERS.ilog2() + 2).expect("height");
        let affected_records = MEMBERS.saturating_sub(1).saturating_add(10);
        let bound = affected_records
            .saturating_mul(8)
            .saturating_mul(logarithmic_height);
        assert!(
            copied <= bound,
            "parent removal copied {copied} nodes, bound {bound} for {} descendants",
            MEMBERS - 1
        );
        assert!(current.parents(&txids[1]).next().is_none());
        assert!(current.children(&root_txid).next().is_none());
        for (index, txid) in txids.iter().enumerate().skip(1) {
            assert_eq!(
                current
                    .entry(txid)
                    .expect("retained descendant")
                    .ancestor_count,
                index - 1
            );
        }
        assert_eq!(
            retained.transaction(&root_txid).map(Transaction::txid),
            Some(root_txid)
        );
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn randomized_serial_admission_removal_and_reconcile_matches_set_oracle() {
        const MEMBERS: usize = 64;
        const OPERATIONS: usize = 384;
        let mut view = FixedView::default();
        let mut candidates = Vec::with_capacity(MEMBERS);
        for index in 0..MEMBERS {
            let byte = u8::try_from(index + 1).expect("fixture index");
            let input = outpoint(byte, 0);
            view.coins.insert(
                input.clone(),
                Coin {
                    outpoint: input.clone(),
                    value: 100,
                    height: 1,
                    coinbase: false,
                    address: Address::new(0, vec![3; 20]).expect("address"),
                    covenant: covenant(),
                },
            );
            candidates.push(transaction(input, 90));
        }

        let mut pool = test_mempool();
        let mut expected = BTreeSet::new();
        let mut state = 0x4d59_5df4_d0f3_3173u64;
        for operation in 0..OPERATIONS {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let index = usize::try_from(state % MEMBERS as u64).expect("candidate index");
            let candidate = candidates[index].clone();
            let txid = candidate.txid();
            match (state >> 32) & 3 {
                0 => {
                    let admission = submit(&mut pool, candidate, &view);
                    if expected.insert(txid) {
                        assert!(matches!(admission, Admission::Accepted(id) if id == txid));
                    } else {
                        assert!(matches!(admission, Admission::Rejected { .. }));
                    }
                }
                1 => {
                    let was_present = expected.remove(&txid);
                    assert_eq!(
                        pool.remove_transaction(txid, false),
                        usize::from(was_present)
                    );
                }
                2 => {
                    let was_present = expected.remove(&txid);
                    let summary = pool
                        .reconcile_connected_with_context(
                            std::slice::from_ref(&candidate),
                            &MempoolContext::testing(3, 3),
                            &view,
                            &AllowInputs,
                            &AllowContext,
                        )
                        .expect("deterministic reconcile");
                    assert_eq!(summary.changed, was_present);
                }
                _ if operation % 31 == 0 => {
                    assert_eq!(pool.clear(), expected.len());
                    expected.clear();
                }
                _ => {
                    let snapshot = pool.snapshot();
                    let clone = snapshot.clone();
                    assert_snapshot_roots_identical(&snapshot, &clone);
                }
            }
            assert_eq!(pool.snapshot().txids().collect::<BTreeSet<_>>(), expected);
            assert_cached_info_exact(&pool);
        }
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
        let mut pool = test_mempool();
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
    fn incremental_name_context_does_not_replay_the_growing_prefix() {
        const ADMISSIONS: usize = 64;
        let mut view = FixedView::default();
        let mut candidates = Vec::with_capacity(ADMISSIONS + 1);
        for index in 0..=ADMISSIONS {
            let byte = u8::try_from(index + 0x20).expect("fixture byte");
            let input = outpoint(byte, 0);
            view.coins.insert(
                input.clone(),
                Coin {
                    outpoint: input.clone(),
                    value: 20,
                    height: 1,
                    coinbase: false,
                    address: Address::new(0, vec![3; 20]).expect("address"),
                    covenant: covenant(),
                },
            );
            candidates.push(open_transaction(
                input,
                15,
                format!("incremental-{index}").as_bytes(),
            ));
        }

        let verifier = IncrementalNameOverlayProbe::default();
        let context = MempoolContext::testing(2, 2);
        let mut pool = test_mempool();
        for candidate in candidates.iter().take(ADMISSIONS).cloned() {
            assert!(matches!(
                pool.submit_with_context(candidate, &context, &view, &AllowInputs, &verifier,)
                    .expect("name admission"),
                Admission::Accepted(_)
            ));
        }
        assert_eq!(verifier.rebuilds.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            verifier.replayed_transactions.load(AtomicOrdering::Relaxed),
            0,
            "incremental acceptance must not replay an expanding prefix"
        );

        assert_eq!(pool.remove_transaction(candidates[0].txid(), false), 1);
        assert!(matches!(
            pool.submit_with_context(
                candidates[ADMISSIONS].clone(),
                &context,
                &view,
                &AllowInputs,
                &verifier,
            )
            .expect("post-removal admission"),
            Admission::Accepted(_)
        ));
        assert_eq!(verifier.rebuilds.load(AtomicOrdering::Relaxed), 2);
        assert_eq!(
            verifier.replayed_transactions.load(AtomicOrdering::Relaxed),
            ADMISSIONS - 1,
            "a removal rebuilds the retained prefix exactly once"
        );
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
        let mut pool = test_mempool();
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
        let mut pool = test_mempool();
        assert!(matches!(
            submit(&mut pool, stale, &view),
            Admission::Accepted(_)
        ));
        assert!(matches!(
            submit(&mut pool, retained, &view),
            Admission::Accepted(_)
        ));
        assert_cached_info_exact(&pool);
        let instance_nonce = *pool.snapshot().instance_nonce();
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
        assert_eq!(pool.snapshot().instance_nonce(), &instance_nonce);
        assert_cached_info_exact(&pool);

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
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn connected_block_revalidation_promotes_newly_resolvable_orphan() {
        let input = outpoint(0xf3, 0);
        let transaction = transaction(input.clone(), 9);
        let txid = transaction.txid();
        let mut view = FixedView::default();
        let mut pool = test_mempool();
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
        let mut pool = test_mempool();
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
        let mut pool = test_mempool();
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
        assert_cached_info_exact(&pool);
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
        let mut pool = test_mempool();
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
        let mut pool = test_mempool();
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
    fn connected_block_revalidation_enforces_transient_memory_budget() {
        let input = outpoint(0xfa, 0);
        let view = FixedView::with_coin(input.clone(), 20);
        let transaction = transaction(input, 9);
        let txid = transaction.txid();
        let mut pool = test_mempool();
        assert!(matches!(
            submit(&mut pool, transaction, &view),
            Admission::Accepted(_)
        ));
        let previous_generation = pool.info().generation;
        pool.bytes = MAX_REVALIDATION_BYTES + 1;

        let error = pool
            .reconcile_connected_with_context(
                &[],
                &MempoolContext::testing(3, 3),
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect_err("oversized revalidation must fail before cloning");

        assert!(matches!(
            error,
            MempoolError::LimitExceeded {
                context: "mempool revalidation memory",
                limit: MAX_REVALIDATION_BYTES,
                actual,
            } if actual == MAX_REVALIDATION_BYTES + 1
        ));
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
        let mut pool = test_mempool();

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
    fn reverse_orphan_chain_promotes_only_parent_indexed_descendants() {
        const DEPTH: usize = 20;
        const UNRELATED: usize = 128;

        let root_input = outpoint(0x71, 0);
        let view = FixedView::with_coin(root_input.clone(), 10_000);
        let root = transaction(root_input, 9_999);
        let mut chain = vec![root];
        for depth in 0..DEPTH {
            let parent = chain.last().expect("parent").txid();
            chain.push(transaction(
                Outpoint {
                    txid: parent,
                    index: 0,
                },
                9_998 - u64::try_from(depth).expect("depth"),
            ));
        }

        let mut pool = test_mempool();
        for transaction in chain.iter().skip(1).rev().cloned() {
            assert!(matches!(
                submit(&mut pool, transaction, &view),
                Admission::Orphan(_)
            ));
        }
        for index in 0..UNRELATED {
            let mut raw = [0x91; 32];
            raw[..8].copy_from_slice(&u64::try_from(index).expect("index").to_le_bytes());
            assert!(matches!(
                submit(
                    &mut pool,
                    transaction(
                        Outpoint {
                            txid: Txid::new(raw),
                            index: 0,
                        },
                        1,
                    ),
                    &view,
                ),
                Admission::Orphan(_)
            ));
        }

        assert!(matches!(
            submit(&mut pool, chain[0].clone(), &view),
            Admission::Accepted(_)
        ));
        assert_eq!(pool.orphan_promotion_attempts, DEPTH);
        assert_eq!(pool.info().transaction_count, DEPTH + 1);
        assert_eq!(pool.info().orphan_count, UNRELATED);
        assert_eq!(pool.orphan_order.len(), UNRELATED);
        assert_eq!(
            pool.orphans_by_parent
                .values()
                .map(BTreeSet::len)
                .sum::<usize>(),
            UNRELATED
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
        let mut pool = test_mempool();
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
            relay_priority: true,
            ..MempoolContext::testing(2, 2)
        };
        let mut underpaying = transaction(input.clone(), 950);
        underpaying.inputs[0].witness = Witness {
            items: vec![vec![0xae; 200]],
        };
        let sigops = 4_000;
        assert_eq!(sigop_adjusted_virtual_size(&underpaying, sigops), 20_000);
        let mut pool = test_mempool();
        assert!(matches!(
            pool.submit_with_context(underpaying, &context, &view, &AllowInputs, &AllowContext)
                .expect("underpaying admission"),
            Admission::Rejected { reason } if reason == "insufficient priority"
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
    fn hsd_free_relay_priority_is_strictly_above_the_threshold() {
        let input = outpoint(0xed, 0);
        let prototype = transaction(input.clone(), 0);
        let prototype_coin = FixedView::with_coin(input.clone(), 1)
            .coins
            .remove(&input)
            .expect("prototype coin");
        let sigops = transaction_sigops(&prototype, &[prototype_coin]).expect("sigops");
        let policy_size = sigop_adjusted_virtual_size(&prototype, sigops);
        let context = MempoolContext {
            minimum_relay_fee_rate: HSD_MINIMUM_RELAY_FEE_RATE,
            relay_priority: true,
            ..MempoolContext::testing(2, 2)
        };
        for (priority, accepted) in [(HSD_FREE_THRESHOLD, false), (HSD_FREE_THRESHOLD + 1, true)] {
            let value = priority.saturating_mul(policy_size as u64);
            let candidate = transaction(input.clone(), value);
            let admission = test_mempool()
                .submit_with_context(
                    candidate,
                    &context,
                    &FixedView::with_coin(input.clone(), value),
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("priority admission");
            assert_eq!(matches!(admission, Admission::Accepted(_)), accepted);
            if !accepted {
                assert!(matches!(
                    admission,
                    Admission::Rejected { reason } if reason == "insufficient priority"
                ));
            }
        }
    }

    #[test]
    fn hsd_free_relay_limiter_uses_strict_threshold_and_ten_minute_decay() {
        let mut pool = test_mempool();
        let threshold = HSD_LIMIT_FREE_RELAY.saturating_mul(HSD_FREE_RELAY_MULTIPLIER);
        pool.free_count = threshold as f64;
        pool.last_free_time = 100;
        assert!(pool.allow_free_relay(1, 100, HSD_LIMIT_FREE_RELAY));
        assert!(!pool.allow_free_relay(1, 100, HSD_LIMIT_FREE_RELAY));
        assert!(pool.allow_free_relay(1, 700, HSD_LIMIT_FREE_RELAY));
        let expected = (threshold as f64 + 1.0)
            * (1.0 - 1.0 / HSD_FREE_DECAY_SECONDS as f64).powf(HSD_FREE_DECAY_SECONDS as f64)
            + 1.0;
        assert!((pool.free_count - expected).abs() < 1e-9);

        let context = MempoolContext {
            current_time: 1_000,
            minimum_relay_fee_rate: HSD_MINIMUM_RELAY_FEE_RATE,
            limit_free: true,
            limit_free_relay: 0,
            ..MempoolContext::testing(2, 2)
        };
        let first_input = outpoint(0xee, 0);
        let first = transaction(first_input.clone(), 1_000);
        let mut admissions = test_mempool();
        assert!(matches!(
            admissions
                .submit_with_context(
                    first,
                    &context,
                    &FixedView::with_coin(first_input, 1_000),
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("first free admission"),
            Admission::Accepted(_)
        ));
        let second_input = outpoint(0xef, 0);
        assert!(matches!(
            admissions
                .submit_with_context(
                    transaction(second_input.clone(), 1_000),
                    &context,
                    &FixedView::with_coin(second_input, 1_000),
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("second free admission"),
            Admission::Rejected { reason } if reason == "rate limited free transaction"
        ));
    }

    #[test]
    fn hsd_revalidation_does_not_recharge_retained_free_transactions() {
        let mut pool = test_mempool();
        let input = outpoint(0xf0, 0);
        let view = FixedView::with_coin(input.clone(), 1_000);
        let context = MempoolContext {
            current_time: 1_000,
            minimum_relay_fee_rate: HSD_MINIMUM_RELAY_FEE_RATE,
            limit_free: true,
            limit_free_relay: 0,
            ..MempoolContext::testing(2, 2)
        };
        assert!(matches!(
            pool.submit_with_context(
                transaction(input, 1_000),
                &context,
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("free admission"),
            Admission::Accepted(_)
        ));
        let charged = pool.free_count;
        let result = pool
            .reconcile_chain_transition_with_context(
                &[],
                &[],
                &context,
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("retained free revalidation");
        assert!(!result.changed);
        assert_eq!(result.retained_transactions, 1);
        assert_eq!(pool.free_count, charged);
    }

    #[test]
    fn hsd_standardness_and_absurd_fee_policy_are_enforced() {
        let input = outpoint(0xfa, 0);
        let view = FixedView::with_coin(input.clone(), 20_000_000);
        let standard_context = MempoolContext {
            require_standard: true,
            ..MempoolContext::testing(2, 2)
        };
        let mut candidate = transaction(input, 3_000);
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate.clone(),
                    &standard_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("version policy"),
            Admission::Rejected { reason } if reason == "version"
        ));

        candidate.version = 0;
        candidate.outputs[0].address = Address::new(1, vec![3; 20]).expect("unknown address");
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate.clone(),
                    &standard_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("address policy"),
            Admission::Rejected { reason } if reason == "address"
        ));

        candidate.outputs[0].address = Address::new(0, vec![3; 20]).expect("address");
        candidate.outputs[0].value = 1;
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate.clone(),
                    &standard_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("dust policy"),
            Admission::Rejected { reason } if reason == "dust"
        ));

        candidate.outputs = vec![
            Output {
                value: 0,
                address: Address::new(31, vec![1; 2]).expect("nulldata"),
                covenant: covenant(),
            },
            Output {
                value: 0,
                address: Address::new(31, vec![2; 2]).expect("nulldata"),
                covenant: covenant(),
            },
        ];
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate.clone(),
                    &standard_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("nulldata policy"),
            Admission::Rejected { reason } if reason == "multi-op-return"
        ));

        candidate.outputs = vec![output(3_000)];
        candidate.inputs[0].witness.items = vec![vec![0; 65]];
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate.clone(),
                    &standard_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("input policy"),
            Admission::Rejected { reason } if reason == "bad-txns-nonstandard-inputs"
        ));

        candidate.inputs[0].witness.items = vec![vec![0; 65], vec![2; 33]];
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate.clone(),
                    &standard_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("standard admission"),
            Admission::Accepted(_)
        ));

        let absurd_context = MempoolContext {
            minimum_relay_fee_rate: HSD_MINIMUM_RELAY_FEE_RATE,
            reject_absurd_fees: true,
            ..standard_context
        };
        assert!(matches!(
            test_mempool()
                .submit_with_context(
                    candidate,
                    &absurd_context,
                    &view,
                    &AllowInputs,
                    &AllowContext,
                )
                .expect("absurd fee policy"),
            Admission::Rejected { reason } if reason == "absurdly-high-fee"
        ));
    }

    #[test]
    fn hsd_expiry_evicts_an_old_dependency_root_and_all_descendants() {
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            expiry_time: 10,
            maximum_transactions: 10,
            ..MempoolLimits::default()
        })
        .expect("limits");
        let root_input = outpoint(0xe1, 0);
        let root = transaction(root_input.clone(), 999);
        let root_txid = root.txid();
        assert!(matches!(
            submit_at(&mut pool, root, &FixedView::with_coin(root_input, 1_000), 1),
            Admission::Accepted(_)
        ));
        let child = transaction(
            Outpoint {
                txid: root_txid,
                index: 0,
            },
            998,
        );
        let child_txid = child.txid();
        assert!(matches!(
            submit_at(&mut pool, child, &FixedView::default(), 2),
            Admission::Accepted(_)
        ));

        let trigger_input = outpoint(0xe2, 0);
        let trigger = transaction(trigger_input.clone(), 999);
        let trigger_txid = trigger.txid();
        assert!(matches!(
            submit_at(
                &mut pool,
                trigger,
                &FixedView::with_coin(trigger_input, 1_000),
                11,
            ),
            Admission::Accepted(_)
        ));
        assert!(pool.transaction(&root_txid).is_none());
        assert!(pool.transaction(&child_txid).is_none());
        assert!(pool.transaction(&trigger_txid).is_some());
        assert_eq!(pool.info().transaction_count, 1);
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn under_capacity_admissions_probe_only_the_earliest_expiry_root() {
        const ADMISSIONS: usize = 4_096;
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            maximum_transactions: ADMISSIONS + 1,
            expiry_time: u64::MAX,
            ..MempoolLimits::default()
        })
        .expect("limits");

        for sequence in 0..ADMISSIONS {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(
                &u64::try_from(sequence)
                    .expect("test sequence fits u64")
                    .to_be_bytes(),
            );
            let input = Outpoint {
                txid: Txid::new(raw),
                index: 0,
            };
            assert!(matches!(
                submit_at(
                    &mut pool,
                    transaction(input.clone(), 999),
                    &FixedView::with_coin(input, 1_000),
                    100,
                ),
                Admission::Accepted(_)
            ));
        }

        assert_eq!(pool.info().transaction_count, ADMISSIONS);
        assert_eq!(pool.expiry_roots.len(), ADMISSIONS);
        assert_eq!(
            pool.expiry_root_checks, ADMISSIONS,
            "the common under-capacity path must not scan all dependency roots"
        );
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn child_becoming_a_root_keeps_its_original_expiry_age() {
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            expiry_time: 10,
            ..MempoolLimits::default()
        })
        .expect("limits");
        let parent_input = outpoint(0xd1, 0);
        let parent = transaction(parent_input.clone(), 999);
        let parent_txid = parent.txid();
        assert!(matches!(
            submit_at(
                &mut pool,
                parent.clone(),
                &FixedView::with_coin(parent_input, 1_000),
                1,
            ),
            Admission::Accepted(_)
        ));
        let child = transaction(
            Outpoint {
                txid: parent_txid,
                index: 0,
            },
            998,
        );
        let child_txid = child.txid();
        assert!(matches!(
            submit_at(&mut pool, child, &FixedView::default(), 2),
            Admission::Accepted(_)
        ));

        assert_eq!(pool.remove_confirmed(&[parent]), 1);
        assert_eq!(pool.next_expiry_root, Some((2, child_txid)));
        assert_cached_info_exact(&pool);

        let trigger_input = outpoint(0xd2, 0);
        let trigger = transaction(trigger_input.clone(), 999);
        let trigger_txid = trigger.txid();
        assert!(matches!(
            submit_at(
                &mut pool,
                trigger,
                &FixedView::with_coin(trigger_input, 1_000),
                12,
            ),
            Admission::Accepted(_)
        ));
        assert!(pool.transaction(&child_txid).is_none());
        assert!(pool.transaction(&trigger_txid).is_some());
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn hsd_chain_transition_revalidation_preserves_expiry_age() {
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            expiry_time: 10,
            ..MempoolLimits::default()
        })
        .expect("limits");
        let input = outpoint(0xe9, 0);
        let view = FixedView::with_coin(input.clone(), 1_000);
        assert!(matches!(
            submit_at(&mut pool, transaction(input, 999), &view, 1),
            Admission::Accepted(_)
        ));
        let context = MempoolContext {
            current_time: 11,
            ..MempoolContext::testing(2, 2)
        };
        let revalidation = pool
            .reconcile_chain_transition_with_context(
                &[],
                &[],
                &context,
                &view,
                &AllowInputs,
                &AllowContext,
            )
            .expect("expiry revalidation");
        assert!(revalidation.changed);
        assert_eq!(revalidation.removed, 1);
        assert_eq!(revalidation.retained_transactions, 0);
        assert_eq!(pool.info().transaction_count, 0);
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn hsd_fee_eviction_uses_descendant_package_rate() {
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            maximum_transactions: 3,
            ..MempoolLimits::default()
        })
        .expect("limits");
        let root_input = outpoint(0xe3, 0);
        let root = transaction(root_input.clone(), 999);
        let root_txid = root.txid();
        assert!(matches!(
            submit_at(&mut pool, root, &FixedView::with_coin(root_input, 1_000), 1),
            Admission::Accepted(_)
        ));
        let child = transaction(
            Outpoint {
                txid: root_txid,
                index: 0,
            },
            1,
        );
        let child_txid = child.txid();
        assert!(matches!(
            submit_at(&mut pool, child, &FixedView::default(), 2),
            Admission::Accepted(_)
        ));

        let standalone_input = outpoint(0xe4, 0);
        let standalone = transaction(standalone_input.clone(), 900);
        let standalone_txid = standalone.txid();
        assert!(matches!(
            submit_at(
                &mut pool,
                standalone,
                &FixedView::with_coin(standalone_input, 1_000),
                3,
            ),
            Admission::Accepted(_)
        ));
        let candidate_input = outpoint(0xe5, 0);
        let candidate = transaction(candidate_input.clone(), 998);
        let candidate_txid = candidate.txid();
        assert!(matches!(
            submit_at(
                &mut pool,
                candidate,
                &FixedView::with_coin(candidate_input, 1_000),
                4,
            ),
            Admission::Rejected { reason } if reason == "mempool-full"
        ));
        assert!(pool.transaction(&root_txid).is_some());
        assert!(pool.transaction(&child_txid).is_some());
        assert!(pool.transaction(&standalone_txid).is_none());
        assert!(pool.transaction(&candidate_txid).is_none());
        assert_eq!(pool.info().transaction_count, 2);
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn hsd_fee_eviction_retains_a_high_fee_new_candidate() {
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            maximum_transactions: 2,
            ..MempoolLimits::default()
        })
        .expect("limits");
        for (byte, output_value, current_time) in [(0xe6, 999, 1), (0xe7, 998, 2)] {
            let input = outpoint(byte, 0);
            assert!(matches!(
                submit_at(
                    &mut pool,
                    transaction(input.clone(), output_value),
                    &FixedView::with_coin(input, 1_000),
                    current_time,
                ),
                Admission::Accepted(_)
            ));
        }
        let high_fee_input = outpoint(0xe8, 0);
        let high_fee = transaction(high_fee_input.clone(), 900);
        let high_fee_txid = high_fee.txid();
        assert!(matches!(
            submit_at(
                &mut pool,
                high_fee,
                &FixedView::with_coin(high_fee_input, 1_000),
                3,
            ),
            Admission::Accepted(_)
        ));
        assert_eq!(pool.info().transaction_count, 1);
        assert!(pool.transaction(&high_fee_txid).is_some());
        assert_cached_info_exact(&pool);
    }

    #[test]
    fn hsd_equal_rate_eviction_removes_oldest_roots_first() {
        let mut pool = MemoryMempool::with_limits(MempoolLimits {
            maximum_transactions: 2,
            ..MempoolLimits::default()
        })
        .expect("limits");
        let mut newest = None;
        for (byte, current_time) in [(0xea, 1), (0xeb, 2), (0xec, 3)] {
            let input = outpoint(byte, 0);
            let candidate = transaction(input.clone(), 999);
            newest = Some(candidate.txid());
            assert!(matches!(
                submit_at(
                    &mut pool,
                    candidate,
                    &FixedView::with_coin(input, 1_000),
                    current_time,
                ),
                Admission::Accepted(_)
            ));
        }
        let newest = newest.expect("newest transaction");
        assert_eq!(pool.info().transaction_count, 1);
        assert!(pool.transaction(&newest).is_some());
        assert_eq!(pool.entries()[0].admitted_at, 3);
        assert_cached_info_exact(&pool);
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
            expiry_time: HSD_MEMPOOL_EXPIRY_TIME,
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
        let mut pool = test_mempool();
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
        assert_cached_info_exact(&pool);
        let generation_before = pool.info().generation;

        assert_eq!(pool.remove_confirmed(&[parent]), 1);
        assert_cached_info_exact(&pool);
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
        let mut pool = test_mempool();
        let instance_nonce = *pool.snapshot().instance_nonce();
        assert!(matches!(
            submit(&mut pool, transaction(input, 10), &view),
            Admission::Accepted(_)
        ));
        let missing = outpoint(11, 0);
        assert!(matches!(
            submit(&mut pool, transaction(missing, 1), &FixedView::default()),
            Admission::Orphan(_)
        ));
        assert_cached_info_exact(&pool);
        let generation_before = pool.info().generation;
        assert_eq!(pool.clear(), 2);
        assert_cached_info_exact(&pool);
        assert_eq!(pool.info().generation, generation_before + 1);
        assert_eq!(pool.clear(), 0);
        assert_eq!(pool.info().generation, generation_before + 1);
        assert!(pool.snapshot().is_empty());
        assert_eq!(pool.snapshot().instance_nonce(), &instance_nonce);
    }

    #[test]
    fn complete_verifier_gate_is_explicit() {
        let input = outpoint(5, 0);
        let view = FixedView::with_coin(input.clone(), 20);
        let mut pool = test_mempool();
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
