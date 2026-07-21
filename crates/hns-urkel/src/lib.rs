//! Correctness-first Handshake Urkel foundations.
//!
//! The in-memory radix tree in this crate follows the hashing and bit-order
//! rules used by the pinned HSD/Urkel oracle:
//!
//! - keys are traversed most-significant bit first;
//! - an empty tree has the all-zero root;
//! - leaves hash as `BLAKE2b-256(0x00 || key || BLAKE2b-256(value))`;
//! - uncompressed internal nodes hash as `BLAKE2b-256(0x01 || left || right)`;
//! - compressed internal nodes hash as
//!   `BLAKE2b-256(0x02 || u16le(prefix_bits) || prefix || left || right)`.
//!
//! `MemoryUrkel` deliberately rebuilds an immutable compressed radix tree from
//! a sorted map when a root or proof is requested. It is intended for oracle
//! parity, deterministic state-root checks, and tests. It is not represented as
//! the production persistent HNS name tree: the `NameTree` implementation below
//! remains explicitly non-authoritative until persistence, HSD proof-codec
//! parity, snapshots, undo, and crash recovery are independently qualified.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use hns_primitives::{blake2b_256, blake2b_256_many, NameHash, MAX_TX_SIZE};
use serde::{Deserialize, Serialize};

pub const URKEL_BITS: usize = 256;
pub const EMPTY_ROOT: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TreeRoot([u8; 32]);

impl TreeRoot {
    pub const ZERO: Self = Self(EMPTY_ROOT);

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ProofKind {
    Inclusion,
    NonInclusion,
}

/// Opaque HSD proof bytes. The production interface intentionally does not
/// invent a wire representation while the exact HSD/Urkel proof codec remains
/// unported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UrkelProof {
    pub name_hash: NameHash,
    pub kind: ProofKind,
    pub raw: Vec<u8>,
}

pub trait UrkelVerifier: Send + Sync {
    fn verify(&self, proof: &UrkelProof, root: TreeRoot) -> Result<(), UrkelError>;

    fn is_consensus_complete(&self) -> bool {
        false
    }
}

/// Immutable view of one authenticated tree generation.
pub trait NameTreeSnapshot: Send + Sync {
    fn root(&self) -> TreeRoot;
    fn get(&self, name_hash: &NameHash) -> Result<Option<Vec<u8>>, UrkelError>;
    fn prove(&self, name_hash: &NameHash) -> Result<UrkelProof, UrkelError>;
}

/// Staged tree mutation. Implementations must make `commit` atomic: callers may
/// observe either the old root or the new root, never a partial mutation.
pub trait NameTreeBatch {
    fn put(&mut self, name_hash: NameHash, value: Vec<u8>) -> Result<(), UrkelError>;
    fn remove(&mut self, name_hash: &NameHash) -> Result<(), UrkelError>;
    fn commit(self: Box<Self>) -> Result<TreeRoot, UrkelError>;
}

pub trait NameTree: Send + Sync {
    fn snapshot(&self) -> Result<Box<dyn NameTreeSnapshot>, UrkelError>;
    fn batch(&self) -> Result<Box<dyn NameTreeBatch>, UrkelError>;

    fn is_consensus_complete(&self) -> bool {
        false
    }
}

/// Exact-root, history-independent, in-memory Urkel oracle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MemoryUrkel {
    entries: BTreeMap<NameHash, Vec<u8>>,
}

impl MemoryUrkel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries<I>(entries: I) -> Result<Self, UrkelError>
    where
        I: IntoIterator<Item = (NameHash, Vec<u8>)>,
    {
        let mut tree = Self::new();
        for (key, value) in entries {
            tree.insert(key, value)?;
        }
        Ok(tree)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, key: &NameHash) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    pub fn insert(&mut self, key: NameHash, value: Vec<u8>) -> Result<Option<Vec<u8>>, UrkelError> {
        validate_value_size(value.len())?;
        Ok(self.entries.insert(key, value))
    }

    pub fn remove(&mut self, key: &NameHash) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    pub fn root(&self) -> TreeRoot {
        TreeRoot::new(build_root(&self.entries).hash())
    }

    pub fn prove_memory(&self, key: NameHash) -> MemoryProof {
        let root = build_root(&self.entries);
        let mut steps = Vec::new();
        let terminal = prove_node(&root, key.as_bytes(), 0, &mut steps);
        MemoryProof {
            key,
            steps,
            terminal,
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = (&NameHash, &[u8])> {
        self.entries
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
    }
}

pub fn root_from_entries<I>(entries: I) -> Result<TreeRoot, UrkelError>
where
    I: IntoIterator<Item = (NameHash, Vec<u8>)>,
{
    Ok(MemoryUrkel::from_entries(entries)?.root())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProof {
    pub key: NameHash,
    pub steps: Vec<MemoryProofStep>,
    pub terminal: MemoryProofTerminal,
}

impl MemoryProof {
    pub fn verify(&self, expected_root: TreeRoot) -> Result<Option<Vec<u8>>, UrkelError> {
        if self.steps.len() > URKEL_BITS {
            return Err(UrkelError::InvalidProof(
                "proof contains more than 256 branch steps".to_owned(),
            ));
        }

        let key = self.key.as_bytes();
        let mut depth = 0usize;
        for step in &self.steps {
            step.prefix.validate()?;
            let next_depth = depth
                .checked_add(step.prefix.bit_len())
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    UrkelError::InvalidProof("proof path length overflowed".to_owned())
                })?;
            if next_depth > URKEL_BITS {
                return Err(UrkelError::InvalidProof(
                    "proof path exceeds the 256-bit key".to_owned(),
                ));
            }
            if !step.prefix.matches_key(key, depth) {
                return Err(UrkelError::InvalidProof(
                    "compressed proof prefix does not match the key".to_owned(),
                ));
            }
            depth += step.prefix.bit_len();
            let branch = key_bit(key, depth);
            if branch != step.branch {
                return Err(UrkelError::InvalidProof(
                    "proof branch does not match the key".to_owned(),
                ));
            }
            depth += 1;
        }

        let (mut hash, value) = match &self.terminal {
            MemoryProofTerminal::Empty => (EMPTY_ROOT, None),
            MemoryProofTerminal::Inclusion { value } => {
                (hash_leaf(key, &blake2b_256(value)), Some(value.clone()))
            }
            MemoryProofTerminal::Collision { key, value_hash } => {
                if key.as_bytes() == self.key.as_bytes() {
                    return Err(UrkelError::InvalidProof(
                        "non-inclusion collision uses the requested key".to_owned(),
                    ));
                }
                (hash_leaf(key.as_bytes(), value_hash), None)
            }
            MemoryProofTerminal::DeadEnd {
                prefix,
                left,
                right,
            } => {
                prefix.validate()?;
                if prefix.matches_key(key, depth) {
                    return Err(UrkelError::InvalidProof(
                        "dead-end prefix unexpectedly matches the requested key".to_owned(),
                    ));
                }
                (hash_internal(prefix, left, right), None)
            }
        };

        for step in self.steps.iter().rev() {
            hash = if step.branch == 0 {
                hash_internal(&step.prefix, &hash, &step.sibling)
            } else {
                hash_internal(&step.prefix, &step.sibling, &hash)
            };
        }

        if hash != expected_root.into_inner() {
            return Err(UrkelError::RootMismatch {
                expected: expected_root,
                actual: TreeRoot::new(hash),
            });
        }

        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProofStep {
    pub prefix: BitPrefix,
    pub branch: u8,
    pub sibling: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryProofTerminal {
    Empty,
    Inclusion {
        value: Vec<u8>,
    },
    Collision {
        key: NameHash,
        value_hash: [u8; 32],
    },
    DeadEnd {
        prefix: BitPrefix,
        left: [u8; 32],
        right: [u8; 32],
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BitPrefix {
    bit_len: u16,
    bytes: Vec<u8>,
}

impl BitPrefix {
    fn from_key_range(key: &[u8; 32], start: usize, bit_len: usize) -> Self {
        debug_assert!(start <= URKEL_BITS);
        debug_assert!(bit_len <= URKEL_BITS - start);
        let mut bytes = vec![0u8; bit_len.div_ceil(8)];
        for offset in 0..bit_len {
            set_packed_bit(&mut bytes, offset, key_bit(key, start + offset));
        }
        Self {
            bit_len: bit_len as u16,
            bytes,
        }
    }

    fn bit_len(&self) -> usize {
        usize::from(self.bit_len)
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn bit(&self, index: usize) -> u8 {
        debug_assert!(index < self.bit_len());
        packed_bit(&self.bytes, index)
    }

    fn count_key(&self, key: &[u8; 32], depth: usize) -> usize {
        let mut count = 0usize;
        for offset in 0..self.bit_len() {
            if self.bit(offset) != key_bit(key, depth + offset) {
                break;
            }
            count += 1;
        }
        count
    }

    fn matches_key(&self, key: &[u8; 32], depth: usize) -> bool {
        depth
            .checked_add(self.bit_len())
            .is_some_and(|end| end <= URKEL_BITS)
            && self.count_key(key, depth) == self.bit_len()
    }

    fn split(&self, front_bits: usize) -> (Self, Self) {
        debug_assert!(front_bits < self.bit_len());
        let mut front = vec![0u8; front_bits.div_ceil(8)];
        let back_bits = self.bit_len() - front_bits - 1;
        let mut back = vec![0u8; back_bits.div_ceil(8)];
        for index in 0..front_bits {
            set_packed_bit(&mut front, index, self.bit(index));
        }
        for index in 0..back_bits {
            set_packed_bit(&mut back, index, self.bit(front_bits + 1 + index));
        }
        (
            Self {
                bit_len: front_bits as u16,
                bytes: front,
            },
            Self {
                bit_len: back_bits as u16,
                bytes: back,
            },
        )
    }

    fn validate(&self) -> Result<(), UrkelError> {
        let bit_len = self.bit_len();
        if bit_len > URKEL_BITS {
            return Err(UrkelError::InvalidProof(
                "compressed prefix exceeds 256 bits".to_owned(),
            ));
        }
        let expected_len = bit_len.div_ceil(8);
        if self.bytes.len() != expected_len {
            return Err(UrkelError::InvalidProof(format!(
                "compressed prefix uses {} bytes for {bit_len} bits",
                self.bytes.len()
            )));
        }
        if bit_len % 8 != 0 && !self.bytes.is_empty() {
            let used = bit_len % 8;
            let trailing_mask = (1u8 << (8 - used)) - 1;
            if self.bytes[self.bytes.len() - 1] & trailing_mask != 0 {
                return Err(UrkelError::InvalidProof(
                    "compressed prefix has non-zero trailing bits".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Node {
    Null,
    Internal {
        prefix: BitPrefix,
        left: Box<Node>,
        right: Box<Node>,
    },
    Leaf {
        key: NameHash,
        value: Vec<u8>,
    },
}

impl Node {
    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Null => EMPTY_ROOT,
            Self::Leaf { key, value } => hash_leaf(key.as_bytes(), &blake2b_256(value)),
            Self::Internal {
                prefix,
                left,
                right,
            } => hash_internal(prefix, &left.hash(), &right.hash()),
        }
    }
}

fn build_root(entries: &BTreeMap<NameHash, Vec<u8>>) -> Node {
    let mut root = Node::Null;
    for (key, value) in entries {
        root = insert_node(root, *key, value.clone(), 0);
    }
    root
}

fn insert_node(node: Node, key: NameHash, value: Vec<u8>, depth: usize) -> Node {
    match node {
        Node::Null => Node::Leaf { key, value },
        Node::Leaf {
            key: existing_key,
            value: existing_value,
        } => {
            if existing_key == key {
                return Node::Leaf { key, value };
            }
            let shared = common_key_bits(existing_key.as_bytes(), key.as_bytes(), depth);
            let branch_depth = depth + shared;
            let prefix = BitPrefix::from_key_range(key.as_bytes(), depth, shared);
            let new_leaf = Node::Leaf { key, value };
            let old_leaf = Node::Leaf {
                key: existing_key,
                value: existing_value,
            };
            internal_from(
                prefix,
                new_leaf,
                old_leaf,
                key_bit(key.as_bytes(), branch_depth),
            )
        }
        Node::Internal {
            prefix,
            left,
            right,
        } => {
            let shared = prefix.count_key(key.as_bytes(), depth);
            if shared != prefix.bit_len() {
                let branch_depth = depth + shared;
                let (front, back) = prefix.split(shared);
                let existing = Node::Internal {
                    prefix: back,
                    left,
                    right,
                };
                return internal_from(
                    front,
                    Node::Leaf { key, value },
                    existing,
                    key_bit(key.as_bytes(), branch_depth),
                );
            }

            let branch_depth = depth + prefix.bit_len();
            let branch = key_bit(key.as_bytes(), branch_depth);
            if branch == 0 {
                Node::Internal {
                    prefix,
                    left: Box::new(insert_node(*left, key, value, branch_depth + 1)),
                    right,
                }
            } else {
                Node::Internal {
                    prefix,
                    left,
                    right: Box::new(insert_node(*right, key, value, branch_depth + 1)),
                }
            }
        }
    }
}

fn internal_from(prefix: BitPrefix, first: Node, second: Node, branch: u8) -> Node {
    debug_assert!(branch <= 1);
    if branch == 0 {
        Node::Internal {
            prefix,
            left: Box::new(first),
            right: Box::new(second),
        }
    } else {
        Node::Internal {
            prefix,
            left: Box::new(second),
            right: Box::new(first),
        }
    }
}

fn prove_node(
    node: &Node,
    key: &[u8; 32],
    depth: usize,
    steps: &mut Vec<MemoryProofStep>,
) -> MemoryProofTerminal {
    match node {
        Node::Null => MemoryProofTerminal::Empty,
        Node::Leaf {
            key: leaf_key,
            value,
        } => {
            if leaf_key.as_bytes() == key {
                MemoryProofTerminal::Inclusion {
                    value: value.clone(),
                }
            } else {
                MemoryProofTerminal::Collision {
                    key: *leaf_key,
                    value_hash: blake2b_256(value),
                }
            }
        }
        Node::Internal {
            prefix,
            left,
            right,
        } => {
            if !prefix.matches_key(key, depth) {
                return MemoryProofTerminal::DeadEnd {
                    prefix: prefix.clone(),
                    left: left.hash(),
                    right: right.hash(),
                };
            }
            let branch_depth = depth + prefix.bit_len();
            let branch = key_bit(key, branch_depth);
            let (next, sibling) = if branch == 0 {
                (left.as_ref(), right.hash())
            } else {
                (right.as_ref(), left.hash())
            };
            steps.push(MemoryProofStep {
                prefix: prefix.clone(),
                branch,
                sibling,
            });
            prove_node(next, key, branch_depth + 1, steps)
        }
    }
}

fn hash_leaf(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    blake2b_256_many([&[0x00][..], &key[..], &value_hash[..]])
}

fn hash_internal(prefix: &BitPrefix, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if prefix.bit_len() == 0 {
        return blake2b_256_many([&[0x01][..], &left[..], &right[..]]);
    }
    let size = (prefix.bit_len() as u16).to_le_bytes();
    blake2b_256_many([
        &[0x02][..],
        &size[..],
        prefix.bytes(),
        &left[..],
        &right[..],
    ])
}

fn key_bit(key: &[u8; 32], index: usize) -> u8 {
    debug_assert!(index < URKEL_BITS);
    (key[index / 8] >> (7 - (index % 8))) & 1
}

fn packed_bit(bytes: &[u8], index: usize) -> u8 {
    (bytes[index / 8] >> (7 - (index % 8))) & 1
}

fn set_packed_bit(bytes: &mut [u8], index: usize, bit: u8) {
    debug_assert!(bit <= 1);
    bytes[index / 8] |= bit << (7 - (index % 8));
}

fn common_key_bits(left: &[u8; 32], right: &[u8; 32], depth: usize) -> usize {
    let mut count = 0usize;
    for index in depth..URKEL_BITS {
        if key_bit(left, index) != key_bit(right, index) {
            break;
        }
        count += 1;
    }
    count
}

fn validate_value_size(size: usize) -> Result<(), UrkelError> {
    if size > MAX_TX_SIZE {
        return Err(UrkelError::ValueTooLarge(size));
    }
    Ok(())
}

/// Atomic in-memory tree useful for tests, fixtures, and shadow diagnostics.
/// It intentionally reports `is_consensus_complete() == false` because it is
/// not the qualified persistent implementation and does not expose HSD wire
/// proof bytes.
#[derive(Clone, Debug, Default)]
pub struct InMemoryNameTree {
    tree: Arc<RwLock<MemoryUrkel>>,
}

impl InMemoryNameTree {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
struct InMemorySnapshot {
    tree: MemoryUrkel,
}

impl NameTreeSnapshot for InMemorySnapshot {
    fn root(&self) -> TreeRoot {
        self.tree.root()
    }

    fn get(&self, name_hash: &NameHash) -> Result<Option<Vec<u8>>, UrkelError> {
        Ok(self.tree.get(name_hash).map(ToOwned::to_owned))
    }

    fn prove(&self, _name_hash: &NameHash) -> Result<UrkelProof, UrkelError> {
        Err(UrkelError::ProofCodecUnavailable)
    }
}

#[derive(Debug)]
struct InMemoryBatch {
    target: Arc<RwLock<MemoryUrkel>>,
    staged: MemoryUrkel,
}

impl NameTreeBatch for InMemoryBatch {
    fn put(&mut self, name_hash: NameHash, value: Vec<u8>) -> Result<(), UrkelError> {
        self.staged.insert(name_hash, value)?;
        Ok(())
    }

    fn remove(&mut self, name_hash: &NameHash) -> Result<(), UrkelError> {
        self.staged.remove(name_hash);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<TreeRoot, UrkelError> {
        let root = self.staged.root();
        let mut target = self
            .target
            .write()
            .map_err(|_| UrkelError::Storage("in-memory tree lock poisoned".to_owned()))?;
        *target = self.staged;
        Ok(root)
    }
}

impl NameTree for InMemoryNameTree {
    fn snapshot(&self) -> Result<Box<dyn NameTreeSnapshot>, UrkelError> {
        let tree = self
            .tree
            .read()
            .map_err(|_| UrkelError::Storage("in-memory tree lock poisoned".to_owned()))?
            .clone();
        Ok(Box::new(InMemorySnapshot { tree }))
    }

    fn batch(&self) -> Result<Box<dyn NameTreeBatch>, UrkelError> {
        let staged = self
            .tree
            .read()
            .map_err(|_| UrkelError::Storage("in-memory tree lock poisoned".to_owned()))?
            .clone();
        Ok(Box::new(InMemoryBatch {
            target: Arc::clone(&self.tree),
            staged,
        }))
    }
}

/// Explicit unavailable implementation used by pre-authority compositions. It
/// never returns a synthetic zero root or silently stores uncommitted state.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableNameTree;

impl NameTree for UnavailableNameTree {
    fn snapshot(&self) -> Result<Box<dyn NameTreeSnapshot>, UrkelError> {
        Err(UrkelError::Unavailable)
    }

    fn batch(&self) -> Result<Box<dyn NameTreeBatch>, UrkelError> {
        Err(UrkelError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableUrkelVerifier;

impl UrkelVerifier for UnavailableUrkelVerifier {
    fn verify(&self, _proof: &UrkelProof, _root: TreeRoot) -> Result<(), UrkelError> {
        Err(UrkelError::Unavailable)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UrkelError {
    #[error("the consensus Urkel implementation is unavailable")]
    Unavailable,
    #[error("the exact HSD Urkel proof codec is unavailable")]
    ProofCodecUnavailable,
    #[error("urkel value size {0} exceeds the configured bound")]
    ValueTooLarge(usize),
    #[error("invalid urkel proof: {0}")]
    InvalidProof(String),
    #[error("urkel root mismatch: expected {expected:?}, got {actual:?}")]
    RootMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
    #[error("urkel storage failure: {0}")]
    Storage(String),
    #[error("urkel codec failure: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    fn key(hex_tail: u32) -> NameHash {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&hex_tail.to_be_bytes());
        NameHash::new(bytes)
    }

    fn decode_hex_32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut output = [0u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex");
        }
        output
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RootFixture {
        states: Vec<StateFixture>,
        incremental_roots: Vec<RootStep>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct StateFixture {
        name_hash: String,
        encoded: String,
    }

    #[derive(Deserialize)]
    struct RootStep {
        root: String,
    }

    #[test]
    fn exact_roots_match_the_pinned_hsd_urkel_fixture() {
        let fixture: RootFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/state-urkel-v1.json"
        ))
        .expect("fixture");
        assert_eq!(fixture.states.len(), fixture.incremental_roots.len());

        let mut tree = MemoryUrkel::new();
        for (state, expected) in fixture.states.iter().zip(&fixture.incremental_roots) {
            tree.insert(
                NameHash::new(decode_hex_32(&state.name_hash)),
                decode_hex(&state.encoded),
            )
            .expect("insert");
            assert_eq!(tree.root(), TreeRoot::new(decode_hex_32(&expected.root)));
        }
    }

    #[test]
    fn roots_are_history_independent() {
        let entries = (0..64)
            .map(|index| (key(index * 17 + 3), format!("value-{index}").into_bytes()))
            .collect::<Vec<_>>();
        let forward = MemoryUrkel::from_entries(entries.clone()).expect("forward");
        let reverse = MemoryUrkel::from_entries(entries.into_iter().rev()).expect("reverse");
        assert_eq!(forward.root(), reverse.root());
    }

    #[test]
    fn inclusion_and_non_inclusion_proofs_verify() {
        let tree = MemoryUrkel::from_entries([
            (key(7), b"alpha".to_vec()),
            (key(0x0102_030b), b"beta".to_vec()),
            (key(0xff00_ff00), b"gamma".to_vec()),
        ])
        .expect("tree");
        let root = tree.root();

        let inclusion = tree.prove_memory(key(0x0102_030b));
        assert_eq!(
            inclusion.verify(root).expect("verify inclusion"),
            Some(b"beta".to_vec())
        );

        let absence = tree.prove_memory(key(0x0102_030c));
        assert_eq!(absence.verify(root).expect("verify absence"), None);
    }

    #[test]
    fn in_memory_tree_commits_atomically_and_remains_non_authoritative() {
        let tree = InMemoryNameTree::new();
        let before = tree.snapshot().expect("snapshot");
        assert_eq!(before.root(), TreeRoot::ZERO);

        let mut batch = tree.batch().expect("batch");
        batch.put(key(1), b"one".to_vec()).expect("put");
        assert_eq!(before.root(), TreeRoot::ZERO);
        let committed = batch.commit().expect("commit");
        assert_ne!(committed, TreeRoot::ZERO);
        assert_eq!(tree.snapshot().expect("snapshot").root(), committed);
        assert!(!tree.is_consensus_complete());
    }

    #[test]
    fn unavailable_boundaries_fail_closed() {
        let tree = UnavailableNameTree;
        assert!(matches!(tree.snapshot(), Err(UrkelError::Unavailable)));
        assert!(matches!(tree.batch(), Err(UrkelError::Unavailable)));

        let verifier = UnavailableUrkelVerifier;
        let proof = UrkelProof {
            name_hash: key(7),
            kind: ProofKind::NonInclusion,
            raw: Vec::new(),
        };
        assert!(matches!(
            verifier.verify(&proof, TreeRoot::ZERO),
            Err(UrkelError::Unavailable)
        ));
    }
}
