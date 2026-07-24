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
//! remains explicitly non-authoritative until persistence, durable snapshots,
//! undo, compaction, and crash recovery are independently qualified.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, RwLock},
};

#[cfg(test)]
use std::collections::BTreeSet;

use hns_primitives::{blake2b_256, blake2b_256_many, NameHash, MAX_TX_SIZE};
use serde::{Deserialize, Serialize};

pub const URKEL_BITS: usize = 256;
pub const EMPTY_ROOT: [u8; 32] = [0; 32];
pub const MAX_HSD_PROOF_SIZE: usize = 82_469;
pub const MAX_URKEL_NODE_RECORD_SIZE: usize = 1 + 32 + 4 + MAX_TX_SIZE;

const HSD_PROOF_DEADEND: u16 = 0;
const HSD_PROOF_SHORT: u16 = 1;
const HSD_PROOF_COLLISION: u16 = 2;
const HSD_PROOF_EXISTS: u16 = 3;

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
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

/// Exact HSD/Urkel proof bytes bound to the requested name hash and expected
/// inclusion class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UrkelProof {
    pub name_hash: NameHash,
    pub kind: ProofKind,
    pub raw: Vec<u8>,
}

impl UrkelProof {
    pub fn decode(&self) -> Result<HsdUrkelProof, UrkelError> {
        HsdUrkelProof::decode(&self.raw)
    }

    pub fn verify_value(&self, root: TreeRoot) -> Result<Option<Vec<u8>>, UrkelError> {
        let proof = self.decode()?;
        if proof.kind() != self.kind {
            return Err(UrkelError::InvalidProof(
                "proof terminal type does not match its declared kind".to_owned(),
            ));
        }
        proof.verify(root, &self.name_hash)
    }
}

/// Structured form of the exact `urkel/lib/proof.js` wire format used by HSD.
/// Prefix and node fields remain private so callers cannot construct an
/// unchecked representation; proofs enter through `decode` or the native tree
/// generator and leave through canonical `encode`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HsdUrkelProof {
    depth: u16,
    nodes: Vec<HsdProofNode>,
    terminal: HsdProofTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HsdProofNode {
    prefix: BitPrefix,
    sibling: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HsdProofTerminal {
    DeadEnd,
    Short {
        prefix: BitPrefix,
        left: [u8; 32],
        right: [u8; 32],
    },
    Collision {
        key: NameHash,
        value_hash: [u8; 32],
    },
    Exists {
        value: Vec<u8>,
    },
}

impl HsdUrkelProof {
    pub fn decode(raw: &[u8]) -> Result<Self, UrkelError> {
        if raw.len() > MAX_HSD_PROOF_SIZE {
            return Err(UrkelError::Codec(format!(
                "HSD proof uses {} bytes, exceeding {MAX_HSD_PROOF_SIZE}",
                raw.len()
            )));
        }

        let mut reader = HsdProofReader::new(raw);
        let field = reader.read_u16()?;
        let proof_type = field >> 14;
        let depth = field & 0x3fff;
        if usize::from(depth) > URKEL_BITS {
            return Err(UrkelError::Codec(format!(
                "HSD proof depth {depth} exceeds {URKEL_BITS}"
            )));
        }

        let count = usize::from(reader.read_u16()?);
        if count > URKEL_BITS {
            return Err(UrkelError::Codec(format!(
                "HSD proof node count {count} exceeds {URKEL_BITS}"
            )));
        }
        let prefix_field = reader.read_vec(count.div_ceil(8))?;
        let mut nodes = Vec::with_capacity(count);
        for index in 0..count {
            let prefix = if packed_bit(&prefix_field, index) == 1 {
                let prefix = reader.read_prefix()?;
                if prefix.bit_len() == 0 {
                    return Err(UrkelError::Codec(
                        "HSD proof node encodes an empty explicit prefix".to_owned(),
                    ));
                }
                prefix
            } else {
                BitPrefix::default()
            };
            nodes.push(HsdProofNode {
                prefix,
                sibling: reader.read_hash()?,
            });
        }

        let terminal = match proof_type {
            HSD_PROOF_DEADEND => HsdProofTerminal::DeadEnd,
            HSD_PROOF_SHORT => {
                let prefix = reader.read_prefix()?;
                if prefix.bit_len() == 0 {
                    return Err(UrkelError::Codec(
                        "HSD short proof has an empty prefix".to_owned(),
                    ));
                }
                HsdProofTerminal::Short {
                    prefix,
                    left: reader.read_hash()?,
                    right: reader.read_hash()?,
                }
            }
            HSD_PROOF_COLLISION => HsdProofTerminal::Collision {
                key: NameHash::new(reader.read_hash()?),
                value_hash: reader.read_hash()?,
            },
            HSD_PROOF_EXISTS => {
                let size = usize::from(reader.read_u16()?);
                HsdProofTerminal::Exists {
                    value: reader.read_vec(size)?,
                }
            }
            _ => unreachable!("two-bit HSD proof type"),
        };

        let proof = Self {
            depth,
            nodes,
            terminal,
        };
        proof.validate_sane()?;
        Ok(proof)
    }

    pub fn encode(&self) -> Result<Vec<u8>, UrkelError> {
        self.validate_sane()?;
        let proof_type = match self.terminal {
            HsdProofTerminal::DeadEnd => HSD_PROOF_DEADEND,
            HsdProofTerminal::Short { .. } => HSD_PROOF_SHORT,
            HsdProofTerminal::Collision { .. } => HSD_PROOF_COLLISION,
            HsdProofTerminal::Exists { .. } => HSD_PROOF_EXISTS,
        };
        let field = (proof_type << 14) | self.depth;
        let mut raw = Vec::new();
        raw.extend_from_slice(&field.to_le_bytes());
        raw.extend_from_slice(&(self.nodes.len() as u16).to_le_bytes());

        let field_offset = raw.len();
        raw.resize(field_offset + self.nodes.len().div_ceil(8), 0);
        for (index, node) in self.nodes.iter().enumerate() {
            if node.prefix.bit_len() != 0 {
                set_packed_bit(&mut raw[field_offset..], index, 1);
                node.prefix.write_hsd(&mut raw);
            }
            raw.extend_from_slice(&node.sibling);
        }

        match &self.terminal {
            HsdProofTerminal::DeadEnd => {}
            HsdProofTerminal::Short {
                prefix,
                left,
                right,
            } => {
                prefix.write_hsd(&mut raw);
                raw.extend_from_slice(left);
                raw.extend_from_slice(right);
            }
            HsdProofTerminal::Collision { key, value_hash } => {
                raw.extend_from_slice(key.as_bytes());
                raw.extend_from_slice(value_hash);
            }
            HsdProofTerminal::Exists { value } => {
                raw.extend_from_slice(&(value.len() as u16).to_le_bytes());
                raw.extend_from_slice(value);
            }
        }

        if raw.len() > MAX_HSD_PROOF_SIZE {
            return Err(UrkelError::Codec(format!(
                "encoded HSD proof uses {} bytes, exceeding {MAX_HSD_PROOF_SIZE}",
                raw.len()
            )));
        }
        Ok(raw)
    }

    pub fn kind(&self) -> ProofKind {
        match self.terminal {
            HsdProofTerminal::Exists { .. } => ProofKind::Inclusion,
            _ => ProofKind::NonInclusion,
        }
    }

    pub fn depth(&self) -> u16 {
        self.depth
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn verify(
        &self,
        expected_root: TreeRoot,
        key: &NameHash,
    ) -> Result<Option<Vec<u8>>, UrkelError> {
        self.validate_sane()?;
        let key_bytes = key.as_bytes();
        let (mut hash, value) = match &self.terminal {
            HsdProofTerminal::DeadEnd => (EMPTY_ROOT, None),
            HsdProofTerminal::Short {
                prefix,
                left,
                right,
            } => {
                if prefix.matches_key(key_bytes, usize::from(self.depth)) {
                    return Err(UrkelError::InvalidProof(
                        "short proof prefix follows the requested key".to_owned(),
                    ));
                }
                (hash_internal(prefix, left, right), None)
            }
            HsdProofTerminal::Collision {
                key: collision,
                value_hash,
            } => {
                if collision == key {
                    return Err(UrkelError::InvalidProof(
                        "collision proof uses the requested key".to_owned(),
                    ));
                }
                (hash_leaf(collision.as_bytes(), value_hash), None)
            }
            HsdProofTerminal::Exists { value } => (
                hash_leaf(key_bytes, &blake2b_256(value)),
                Some(value.clone()),
            ),
        };

        let mut depth = usize::from(self.depth);
        for node in self.nodes.iter().rev() {
            let prefix_bits = node.prefix.bit_len();
            if depth < prefix_bits + 1 {
                return Err(UrkelError::InvalidProof(
                    "proof depth precedes a compressed ancestor".to_owned(),
                ));
            }
            depth -= 1;
            hash = if key_bit(key_bytes, depth) == 1 {
                hash_internal(&node.prefix, &node.sibling, &hash)
            } else {
                hash_internal(&node.prefix, &hash, &node.sibling)
            };
            depth -= prefix_bits;
            if !node.prefix.matches_key(key_bytes, depth) {
                return Err(UrkelError::InvalidProof(
                    "compressed ancestor prefix does not match the requested key".to_owned(),
                ));
            }
        }

        if depth != 0 {
            return Err(UrkelError::InvalidProof(
                "proof does not return to the tree root".to_owned(),
            ));
        }
        if hash != expected_root.into_inner() {
            return Err(UrkelError::RootMismatch {
                expected: expected_root,
                actual: TreeRoot::new(hash),
            });
        }
        Ok(value)
    }

    fn validate_sane(&self) -> Result<(), UrkelError> {
        if usize::from(self.depth) > URKEL_BITS {
            return Err(UrkelError::InvalidProof(
                "proof depth exceeds 256 bits".to_owned(),
            ));
        }
        if self.nodes.len() > URKEL_BITS {
            return Err(UrkelError::InvalidProof(
                "proof contains more than 256 ancestor nodes".to_owned(),
            ));
        }
        for node in &self.nodes {
            node.prefix.validate()?;
        }
        match &self.terminal {
            HsdProofTerminal::Short { prefix, .. } => {
                prefix.validate()?;
                if prefix.bit_len() == 0 {
                    return Err(UrkelError::InvalidProof(
                        "short proof has an empty prefix".to_owned(),
                    ));
                }
            }
            HsdProofTerminal::Exists { value } if value.len() > u16::MAX as usize => {
                return Err(UrkelError::InvalidProof(
                    "included proof value exceeds 65535 bytes".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeUrkelVerifier;

impl UrkelVerifier for NativeUrkelVerifier {
    fn verify(&self, proof: &UrkelProof, root: TreeRoot) -> Result<(), UrkelError> {
        proof.verify_value(root).map(|_| ())
    }

    fn is_consensus_complete(&self) -> bool {
        true
    }
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
        let entries = self.entries.iter().collect::<Vec<_>>();
        sorted_entries_root(&entries, 0)
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

    pub fn prove_hsd(&self, key: NameHash) -> Result<UrkelProof, UrkelError> {
        let structured = self.prove_memory(key).to_hsd_proof()?;
        Ok(UrkelProof {
            name_hash: key,
            kind: structured.kind(),
            raw: structured.encode()?,
        })
    }

    /// Encode every reachable node under its authenticated hash. Records are
    /// history-independent and content-addressed: an unchanged subtree keeps
    /// the same key and bytes across generations.
    pub fn node_records(&self) -> Result<BTreeMap<TreeRoot, Vec<u8>>, UrkelError> {
        self.node_records_with_root().map(|(_, records)| records)
    }

    /// Encode every reachable node and return the root computed by that same
    /// traversal. Large trees must not be rebuilt merely to assert that the
    /// record traversal produced the expected root.
    pub fn node_records_with_root(
        &self,
    ) -> Result<(TreeRoot, BTreeMap<TreeRoot, Vec<u8>>), UrkelError> {
        let mut records = BTreeMap::new();
        let root = build_root(&self.entries).collect_records(&mut records)?;
        Ok((root, records))
    }

    /// Recompute the root while retaining canonical bytes only for the path
    /// from `target` to that root. Offline corruption diagnosis therefore
    /// remains linear in tree size without retaining every encoded record.
    pub fn record_path_to_root(
        &self,
        target: TreeRoot,
    ) -> Result<(TreeRoot, usize, Option<Vec<(TreeRoot, Vec<u8>)>>), UrkelError> {
        let entries = self.entries.iter().collect::<Vec<_>>();
        let record_count = entries
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_sub(usize::from(!entries.is_empty())))
            .ok_or_else(|| UrkelError::Codec("record count overflowed".to_owned()))?;
        let (root, path) = sorted_entries_record_path(&entries, 0, target)?;
        Ok((root, record_count, path))
    }

    pub fn entries(&self) -> impl Iterator<Item = (&NameHash, &[u8])> {
        self.entries
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
    }
}

/// Canonical durable representation of one content-addressed Urkel node.
/// The record bytes are not HSD's filesystem format; their authenticated hash
/// is exactly the HSD/Urkel node hash used by roots and proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UrkelNodeRecord {
    Leaf {
        key: NameHash,
        value: Vec<u8>,
    },
    Internal {
        prefix: BitPrefix,
        left: TreeRoot,
        right: TreeRoot,
    },
}

impl UrkelNodeRecord {
    const LEAF_TAG: u8 = 0;
    const INTERNAL_TAG: u8 = 1;

    pub fn decode(raw: &[u8]) -> Result<Self, UrkelError> {
        if raw.len() > MAX_URKEL_NODE_RECORD_SIZE {
            return Err(UrkelError::Codec(format!(
                "Urkel node record uses {} bytes, exceeding {MAX_URKEL_NODE_RECORD_SIZE}",
                raw.len()
            )));
        }
        let Some((&tag, payload)) = raw.split_first() else {
            return Err(UrkelError::Codec("empty Urkel node record".to_owned()));
        };
        match tag {
            Self::LEAF_TAG => {
                if payload.len() < 36 {
                    return Err(UrkelError::Codec("truncated Urkel leaf record".to_owned()));
                }
                let key = NameHash::new(payload[..32].try_into().expect("leaf key"));
                let size = u32::from_le_bytes(payload[32..36].try_into().expect("value size"));
                let size = usize::try_from(size).map_err(|_| {
                    UrkelError::Codec("Urkel leaf value length does not fit usize".to_owned())
                })?;
                validate_value_size(size)?;
                let expected = 36usize
                    .checked_add(size)
                    .ok_or_else(|| UrkelError::Codec("Urkel leaf length overflowed".to_owned()))?;
                if payload.len() != expected {
                    return Err(UrkelError::Codec(format!(
                        "Urkel leaf record declares {size} value bytes but contains {}",
                        payload.len().saturating_sub(36)
                    )));
                }
                Ok(Self::Leaf {
                    key,
                    value: payload[36..].to_vec(),
                })
            }
            Self::INTERNAL_TAG => {
                if payload.len() < 66 {
                    return Err(UrkelError::Codec(
                        "truncated Urkel internal record".to_owned(),
                    ));
                }
                let bit_len = usize::from(u16::from_le_bytes(
                    payload[..2].try_into().expect("prefix size"),
                ));
                if bit_len > URKEL_BITS {
                    return Err(UrkelError::Codec(format!(
                        "Urkel internal prefix uses {bit_len} bits"
                    )));
                }
                let prefix_bytes = bit_len.div_ceil(8);
                let expected = 2usize
                    .checked_add(prefix_bytes)
                    .and_then(|size| size.checked_add(64))
                    .ok_or_else(|| {
                        UrkelError::Codec("Urkel internal length overflowed".to_owned())
                    })?;
                if payload.len() != expected {
                    return Err(UrkelError::Codec(format!(
                        "Urkel internal record uses {} payload bytes; expected {expected}",
                        payload.len()
                    )));
                }
                let prefix = BitPrefix {
                    bit_len: bit_len as u16,
                    bytes: payload[2..2 + prefix_bytes].to_vec(),
                };
                prefix.validate()?;
                let left = TreeRoot::new(
                    payload[2 + prefix_bytes..34 + prefix_bytes]
                        .try_into()
                        .expect("left hash"),
                );
                let right = TreeRoot::new(
                    payload[34 + prefix_bytes..66 + prefix_bytes]
                        .try_into()
                        .expect("right hash"),
                );
                if left == TreeRoot::ZERO || right == TreeRoot::ZERO {
                    return Err(UrkelError::Codec(
                        "compressed Urkel internal node has an empty child".to_owned(),
                    ));
                }
                Ok(Self::Internal {
                    prefix,
                    left,
                    right,
                })
            }
            other => Err(UrkelError::Codec(format!(
                "unknown Urkel node-record tag {other}"
            ))),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, UrkelError> {
        match self {
            Self::Leaf { key, value } => {
                validate_value_size(value.len())?;
                let size = u32::try_from(value.len()).map_err(|_| {
                    UrkelError::Codec("Urkel leaf value exceeds u32 length".to_owned())
                })?;
                let mut raw = Vec::with_capacity(37 + value.len());
                raw.push(Self::LEAF_TAG);
                raw.extend_from_slice(key.as_bytes());
                raw.extend_from_slice(&size.to_le_bytes());
                raw.extend_from_slice(value);
                Ok(raw)
            }
            Self::Internal {
                prefix,
                left,
                right,
            } => {
                prefix.validate()?;
                if *left == TreeRoot::ZERO || *right == TreeRoot::ZERO {
                    return Err(UrkelError::InvalidNode(
                        "compressed internal node has an empty child".to_owned(),
                    ));
                }
                let mut raw = Vec::with_capacity(67 + prefix.bytes().len());
                raw.push(Self::INTERNAL_TAG);
                raw.extend_from_slice(&(prefix.bit_len() as u16).to_le_bytes());
                raw.extend_from_slice(prefix.bytes());
                raw.extend_from_slice(left.as_bytes());
                raw.extend_from_slice(right.as_bytes());
                Ok(raw)
            }
        }
    }

    pub fn root(&self) -> TreeRoot {
        match self {
            Self::Leaf { key, value } => {
                TreeRoot::new(hash_leaf(key.as_bytes(), &blake2b_256(value)))
            }
            Self::Internal {
                prefix,
                left,
                right,
            } => TreeRoot::new(hash_internal(prefix, left.as_bytes(), right.as_bytes())),
        }
    }
}

/// Result of applying path-local immutable mutations to a content-addressed
/// tree. `records` contains only nodes constructed by the mutation; unchanged
/// subtrees remain referenced by their existing authenticated hashes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrkelRecordUpdate {
    root: TreeRoot,
    records: BTreeMap<TreeRoot, Vec<u8>>,
}

impl UrkelRecordUpdate {
    pub const fn root(&self) -> TreeRoot {
        self.root
    }

    pub fn records(&self) -> &BTreeMap<TreeRoot, Vec<u8>> {
        &self.records
    }

    pub fn into_records(self) -> BTreeMap<TreeRoot, Vec<u8>> {
        self.records
    }
}

/// Apply inserts/replacements (`Some(value)`) and removals (`None`) by loading
/// only affected paths from an immutable content-addressed root. Newly built
/// nodes are returned for atomic persistence; old nodes remain valid for
/// historical roots and undo.
pub fn update_record_tree<F, I>(
    root: TreeRoot,
    updates: I,
    load: F,
) -> Result<UrkelRecordUpdate, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
    I: IntoIterator<Item = (NameHash, Option<Vec<u8>>)>,
{
    apply_record_updates(root, updates, load, BTreeMap::new())
}

/// Apply path-local mutations after loading all affected paths breadth-first.
/// One loader call can resolve many content-addressed nodes at the same tree
/// depth, allowing persistent stores to use a true database MultiGet instead
/// of crossing the storage boundary once per node and mutation.
///
/// Constructed nodes remain in the mutation context, and an uncommon node not
/// present on an original affected path (for example a deletion sibling needed
/// for prefix compression) falls back to a one-record batch. The result is
/// byte-identical to [`update_record_tree`].
pub fn update_record_tree_batched<F, I>(
    root: TreeRoot,
    updates: I,
    batch_size: usize,
    mut load_many: F,
) -> Result<UrkelRecordUpdate, UrkelError>
where
    F: FnMut(&[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, UrkelError>,
    I: IntoIterator<Item = (NameHash, Option<Vec<u8>>)>,
{
    if batch_size == 0 {
        return Err(UrkelError::InvalidNode(
            "record mutation batch size must be non-zero".to_owned(),
        ));
    }
    let updates = updates.into_iter().collect::<Vec<_>>();
    let keys = updates.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    let loaded = prefetch_record_paths(root, &keys, batch_size, &mut load_many)?;
    let load_one = move |record_root: TreeRoot| {
        let mut values = load_many(&[record_root])?;
        if values.len() != 1 {
            return Err(UrkelError::Storage(format!(
                "record mutation loader returned {} records for one key",
                values.len()
            )));
        }
        Ok(values.pop().expect("one mutation record"))
    };
    apply_record_updates(root, updates, load_one, loaded)
}

/// Apply mutations from a storage-native prefetched path union. The fallback
/// loader is retained for uncommon compression siblings that are not on an
/// affected key path.
pub fn update_record_tree_prefetched<F, I, P>(
    root: TreeRoot,
    updates: I,
    prefetched: P,
    load: F,
) -> Result<UrkelRecordUpdate, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
    I: IntoIterator<Item = (NameHash, Option<Vec<u8>>)>,
    P: IntoIterator<Item = (TreeRoot, Vec<u8>)>,
{
    let mut loaded = BTreeMap::new();
    for (record_root, raw) in prefetched {
        let record = decode_verified_record(record_root, &raw)?;
        if let Some(existing) = loaded.insert(record_root, record.clone()) {
            if existing != record {
                return Err(UrkelError::NodeHashCollision(record_root));
            }
        }
    }
    apply_record_updates(root, updates, load, loaded)
}

/// Apply one mutation set by tracing the affected Patricia frontier once and
/// rebuilding its canonical union bottom-up.
///
/// The point-update implementation above is useful for small mutations, but
/// it reconstructs and hashes a shared ancestor once for every key. Interval
/// commits can contain thousands of distinct keys. This implementation keeps
/// unchanged subtrees as authenticated opaque roots, expands only paths that
/// contain a mutation, and then hashes every final frontier node once.
///
/// Duplicate keys retain the ordinary sequential API's last-write-wins
/// behavior. The result is history-independent and byte-identical at the root
/// to applying the same final key/value map with [`update_record_tree`].
pub fn update_record_tree_mutation_trie_prefetched<F, I, P>(
    root: TreeRoot,
    updates: I,
    prefetched: P,
    load: F,
) -> Result<UrkelRecordUpdate, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
    I: IntoIterator<Item = (NameHash, Option<Vec<u8>>)>,
    P: IntoIterator<Item = (TreeRoot, Vec<u8>)>,
{
    let mut mutations = BTreeMap::<NameHash, Option<Vec<u8>>>::new();
    for (key, value) in updates {
        if let Some(value) = value.as_ref() {
            validate_value_size(value.len())?;
        }
        mutations.insert(key, value);
    }
    if mutations.is_empty() {
        return Ok(UrkelRecordUpdate {
            root,
            records: BTreeMap::new(),
        });
    }

    let mut loaded = BTreeMap::new();
    for (record_root, raw) in prefetched {
        let record = decode_verified_record(record_root, &raw)?;
        if let Some(existing) = loaded.insert(record_root, record.clone()) {
            if existing != record {
                return Err(UrkelError::NodeHashCollision(record_root));
            }
        }
    }

    let mutations = mutations
        .into_iter()
        .map(|(key, value)| RecordMutation { key, value })
        .collect::<Vec<_>>();
    let mutation_refs = mutations.iter().collect::<Vec<_>>();
    let mut context = RecordMutationContext {
        load,
        loaded,
        records: BTreeMap::new(),
    };
    let mut frontier = Vec::new();
    collect_record_mutation_frontier(
        &mut context,
        root,
        0,
        NameHash::new([0; 32]),
        &mutation_refs,
        &mut frontier,
    )?;
    frontier.sort_unstable_by_key(RecordMutationFrontier::representative);
    for adjacent in frontier.windows(2) {
        if adjacent[0].representative() == adjacent[1].representative() {
            return Err(UrkelError::InvalidNode(
                "mutation frontier contains overlapping authenticated ranges".to_owned(),
            ));
        }
    }
    let root = build_record_mutation_frontier(&mut context, &frontier, 0)?;
    Ok(UrkelRecordUpdate {
        root,
        records: context.records,
    })
}

#[derive(Debug)]
struct RecordMutation {
    key: NameHash,
    value: Option<Vec<u8>>,
}

#[derive(Debug)]
enum RecordMutationFrontier {
    Existing {
        root: TreeRoot,
        original_depth: usize,
        representative: NameHash,
    },
    Leaf {
        key: NameHash,
        value: Vec<u8>,
    },
}

impl RecordMutationFrontier {
    const fn representative(&self) -> NameHash {
        match self {
            Self::Existing { representative, .. } => *representative,
            Self::Leaf { key, .. } => *key,
        }
    }
}

fn collect_record_mutation_frontier<F>(
    context: &mut RecordMutationContext<F>,
    root: TreeRoot,
    depth: usize,
    path_key: NameHash,
    mutations: &[&RecordMutation],
    frontier: &mut Vec<RecordMutationFrontier>,
) -> Result<(), UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    if root == TreeRoot::ZERO {
        for mutation in mutations {
            if let Some(value) = mutation.value.as_ref() {
                frontier.push(RecordMutationFrontier::Leaf {
                    key: mutation.key,
                    value: value.clone(),
                });
            }
        }
        return Ok(());
    }

    let record = context.load_record(root)?;
    match record {
        UrkelNodeRecord::Leaf {
            key: existing_key,
            value: existing_value,
        } => {
            let mut existing = Some((root, existing_value));
            for mutation in mutations {
                if mutation.key == existing_key {
                    existing = mutation
                        .value
                        .as_ref()
                        .map(|value| (TreeRoot::ZERO, value.clone()));
                } else if let Some(value) = mutation.value.as_ref() {
                    frontier.push(RecordMutationFrontier::Leaf {
                        key: mutation.key,
                        value: value.clone(),
                    });
                }
            }
            if let Some((existing_root, value)) = existing {
                if existing_root == root {
                    frontier.push(RecordMutationFrontier::Existing {
                        root,
                        original_depth: depth,
                        representative: existing_key,
                    });
                } else {
                    frontier.push(RecordMutationFrontier::Leaf {
                        key: existing_key,
                        value,
                    });
                }
            }
        }
        UrkelNodeRecord::Internal {
            prefix,
            left,
            right,
        } => {
            let branch_depth = checked_branch_depth(&prefix, depth)?;
            let mut left_mutations = Vec::new();
            let mut right_mutations = Vec::new();
            for mutation in mutations {
                if !prefix.matches_key(mutation.key.as_bytes(), depth) {
                    if let Some(value) = mutation.value.as_ref() {
                        frontier.push(RecordMutationFrontier::Leaf {
                            key: mutation.key,
                            value: value.clone(),
                        });
                    }
                    continue;
                }
                if key_bit(mutation.key.as_bytes(), branch_depth) == 0 {
                    left_mutations.push(*mutation);
                } else {
                    right_mutations.push(*mutation);
                }
            }

            if left_mutations.is_empty() && right_mutations.is_empty() {
                frontier.push(RecordMutationFrontier::Existing {
                    root,
                    original_depth: depth,
                    representative: internal_record_representative(path_key, depth, &prefix, 0),
                });
                return Ok(());
            }

            let left_path = internal_record_representative(path_key, depth, &prefix, 0);
            if left_mutations.is_empty() {
                frontier.push(RecordMutationFrontier::Existing {
                    root: left,
                    original_depth: branch_depth + 1,
                    representative: left_path,
                });
            } else {
                collect_record_mutation_frontier(
                    context,
                    left,
                    branch_depth + 1,
                    left_path,
                    &left_mutations,
                    frontier,
                )?;
            }

            let right_path = internal_record_representative(path_key, depth, &prefix, 1);
            if right_mutations.is_empty() {
                frontier.push(RecordMutationFrontier::Existing {
                    root: right,
                    original_depth: branch_depth + 1,
                    representative: right_path,
                });
            } else {
                collect_record_mutation_frontier(
                    context,
                    right,
                    branch_depth + 1,
                    right_path,
                    &right_mutations,
                    frontier,
                )?;
            }
        }
    }
    Ok(())
}

fn internal_record_representative(
    path_key: NameHash,
    depth: usize,
    prefix: &BitPrefix,
    branch: u8,
) -> NameHash {
    debug_assert!(branch <= 1);
    let mut key = *path_key.as_bytes();
    for index in 0..prefix.bit_len() {
        set_key_bit(&mut key, depth + index, prefix.bit(index));
    }
    set_key_bit(&mut key, depth + prefix.bit_len(), branch);
    NameHash::new(key)
}

fn build_record_mutation_frontier<F>(
    context: &mut RecordMutationContext<F>,
    frontier: &[RecordMutationFrontier],
    depth: usize,
) -> Result<TreeRoot, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    match frontier {
        [] => return Ok(TreeRoot::ZERO),
        [item] => return attach_record_mutation_frontier(context, item, depth),
        _ => {}
    }

    let first = frontier
        .first()
        .expect("nonempty mutation frontier")
        .representative();
    let last = frontier
        .last()
        .expect("nonempty mutation frontier")
        .representative();
    let shared = common_key_bits(first.as_bytes(), last.as_bytes(), depth);
    let branch_depth = depth.checked_add(shared).ok_or_else(|| {
        UrkelError::InvalidNode("mutation frontier branch depth overflowed".to_owned())
    })?;
    if branch_depth >= URKEL_BITS {
        return Err(UrkelError::InvalidNode(
            "mutation frontier contains colliding key ranges".to_owned(),
        ));
    }
    let split = frontier
        .partition_point(|item| key_bit(item.representative().as_bytes(), branch_depth) == 0);
    if split == 0 || split == frontier.len() {
        return Err(UrkelError::InvalidNode(
            "mutation frontier failed to partition at its first divergent bit".to_owned(),
        ));
    }
    let left = build_record_mutation_frontier(context, &frontier[..split], branch_depth + 1)?;
    let right = build_record_mutation_frontier(context, &frontier[split..], branch_depth + 1)?;
    context.intern_final(UrkelNodeRecord::Internal {
        prefix: BitPrefix::from_key_range(first.as_bytes(), depth, shared),
        left,
        right,
    })
}

fn attach_record_mutation_frontier<F>(
    context: &mut RecordMutationContext<F>,
    frontier: &RecordMutationFrontier,
    depth: usize,
) -> Result<TreeRoot, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    match frontier {
        RecordMutationFrontier::Leaf { key, value } => {
            context.intern_final(UrkelNodeRecord::Leaf {
                key: *key,
                value: value.clone(),
            })
        }
        RecordMutationFrontier::Existing {
            root,
            original_depth,
            representative,
        } => {
            if depth == *original_depth {
                return Ok(*root);
            }
            match context.load_record(*root)? {
                UrkelNodeRecord::Leaf { .. } => Ok(*root),
                UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    let prefix =
                        rebase_record_prefix(&prefix, *representative, *original_depth, depth)?;
                    context.intern_final(UrkelNodeRecord::Internal {
                        prefix,
                        left,
                        right,
                    })
                }
            }
        }
    }
}

fn rebase_record_prefix(
    prefix: &BitPrefix,
    representative: NameHash,
    original_depth: usize,
    depth: usize,
) -> Result<BitPrefix, UrkelError> {
    let (leading, skipped) = if depth < original_depth {
        (original_depth - depth, 0)
    } else {
        (0, depth - original_depth)
    };
    if skipped > prefix.bit_len() {
        return Err(UrkelError::InvalidNode(
            "mutation frontier entered an opaque subtree beyond its branch".to_owned(),
        ));
    }
    let bit_len = leading
        .checked_add(prefix.bit_len() - skipped)
        .ok_or_else(|| {
            UrkelError::InvalidNode("mutation frontier prefix length overflowed".to_owned())
        })?;
    if depth
        .checked_add(bit_len)
        .is_none_or(|branch_depth| branch_depth >= URKEL_BITS)
    {
        return Err(UrkelError::InvalidNode(
            "mutation frontier prefix exceeds the key boundary".to_owned(),
        ));
    }
    let mut bytes = vec![0u8; bit_len.div_ceil(8)];
    for index in 0..leading {
        set_packed_bit(
            &mut bytes,
            index,
            key_bit(representative.as_bytes(), depth + index),
        );
    }
    for index in skipped..prefix.bit_len() {
        set_packed_bit(&mut bytes, leading + index - skipped, prefix.bit(index));
    }
    Ok(BitPrefix {
        bit_len: bit_len as u16,
        bytes,
    })
}

fn apply_record_updates<F, I>(
    root: TreeRoot,
    updates: I,
    load: F,
    loaded: BTreeMap<TreeRoot, UrkelNodeRecord>,
) -> Result<UrkelRecordUpdate, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
    I: IntoIterator<Item = (NameHash, Option<Vec<u8>>)>,
{
    let mut context = RecordMutationContext {
        load,
        loaded,
        records: BTreeMap::new(),
    };
    if root != TreeRoot::ZERO {
        context.load_record(root)?;
    }

    let mut current = root;
    for (key, value) in updates {
        current = match value {
            Some(value) => {
                validate_value_size(value.len())?;
                context.insert(current, key, value, 0)?.0
            }
            None => context.remove(current, key, 0)?.0,
        };
    }
    context.retain_records_reachable_from(current)?;

    Ok(UrkelRecordUpdate {
        root: current,
        records: context.records,
    })
}

fn prefetch_record_paths<F>(
    root: TreeRoot,
    keys: &[NameHash],
    batch_size: usize,
    load_many: &mut F,
) -> Result<BTreeMap<TreeRoot, UrkelNodeRecord>, UrkelError>
where
    F: FnMut(&[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, UrkelError>,
{
    let mut loaded = BTreeMap::new();
    if root == TreeRoot::ZERO || keys.is_empty() {
        return Ok(loaded);
    }

    let mut frontier: BTreeMap<TreeRoot, Vec<(NameHash, usize)>> = BTreeMap::from([(
        root,
        keys.iter().copied().map(|key| (key, 0usize)).collect(),
    )]);
    while !frontier.is_empty() {
        let requested = frontier
            .keys()
            .filter(|record_root| !loaded.contains_key(*record_root))
            .copied()
            .collect::<Vec<_>>();
        for chunk in requested.chunks(batch_size) {
            let values = load_many(chunk)?;
            if values.len() != chunk.len() {
                return Err(UrkelError::Storage(format!(
                    "record mutation loader returned {} records for {} keys",
                    values.len(),
                    chunk.len()
                )));
            }
            for (record_root, value) in chunk.iter().copied().zip(values) {
                let raw = value.ok_or(UrkelError::MissingNode(record_root))?;
                loaded.insert(record_root, decode_verified_record(record_root, &raw)?);
            }
        }

        let mut next = BTreeMap::<TreeRoot, Vec<(NameHash, usize)>>::new();
        for (record_root, traversals) in frontier {
            let record = loaded.get(&record_root).ok_or_else(|| {
                UrkelError::InvalidNode(format!(
                    "prefetched Urkel record {record_root:?} is unavailable"
                ))
            })?;
            let UrkelNodeRecord::Internal {
                prefix,
                left,
                right,
            } = record
            else {
                continue;
            };
            for (key, depth) in traversals {
                if !prefix.matches_key(key.as_bytes(), depth) {
                    continue;
                }
                let branch_depth = checked_branch_depth(prefix, depth)?;
                let child = if key_bit(key.as_bytes(), branch_depth) == 0 {
                    *left
                } else {
                    *right
                };
                next.entry(child).or_default().push((key, branch_depth + 1));
            }
        }
        frontier = next;
    }
    Ok(loaded)
}

struct RecordMutationContext<F> {
    load: F,
    loaded: BTreeMap<TreeRoot, UrkelNodeRecord>,
    records: BTreeMap<TreeRoot, Vec<u8>>,
}

impl<F> RecordMutationContext<F>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    fn retain_records_reachable_from(&mut self, root: TreeRoot) -> Result<(), UrkelError> {
        let mut pending = vec![root];
        let mut reachable = HashSet::with_capacity(self.records.len());
        while let Some(root) = pending.pop() {
            if !self.records.contains_key(&root) || !reachable.insert(root) {
                continue;
            }
            let record = self.loaded.get(&root).ok_or_else(|| {
                UrkelError::InvalidNode(format!(
                    "constructed urkel record {root:?} is missing from the mutation cache"
                ))
            })?;
            if let UrkelNodeRecord::Internal { left, right, .. } = record {
                pending.push(*left);
                pending.push(*right);
            }
        }
        self.records
            .retain(|record_root, _| reachable.contains(record_root));
        Ok(())
    }

    fn load_record(&mut self, root: TreeRoot) -> Result<UrkelNodeRecord, UrkelError> {
        if root == TreeRoot::ZERO {
            return Err(UrkelError::InvalidNode(
                "attempted to load the empty Urkel root as a record".to_owned(),
            ));
        }
        if let Some(record) = self.loaded.get(&root) {
            return Ok(record.clone());
        }
        let record = load_verified_record(root, &mut self.load)?;
        self.loaded.insert(root, record.clone());
        Ok(record)
    }

    fn intern(&mut self, record: UrkelNodeRecord) -> Result<TreeRoot, UrkelError> {
        let root = record.root();
        let raw = record.encode()?;
        if let Some(existing) = self.records.insert(root, raw.clone()) {
            if existing != raw {
                return Err(UrkelError::NodeHashCollision(root));
            }
        }
        self.loaded.insert(root, record);
        Ok(root)
    }

    fn intern_final(&mut self, record: UrkelNodeRecord) -> Result<TreeRoot, UrkelError> {
        let root = record.root();
        let raw = record.encode()?;
        if let Some(existing) = self.loaded.get(&root) {
            if existing != &record {
                return Err(UrkelError::NodeHashCollision(root));
            }
            return Ok(root);
        }
        if let Some(existing) = self.records.insert(root, raw.clone()) {
            if existing != raw {
                return Err(UrkelError::NodeHashCollision(root));
            }
        }
        self.loaded.insert(root, record);
        Ok(root)
    }

    fn insert(
        &mut self,
        root: TreeRoot,
        key: NameHash,
        value: Vec<u8>,
        depth: usize,
    ) -> Result<(TreeRoot, bool), UrkelError> {
        if root == TreeRoot::ZERO {
            let root = self.intern(UrkelNodeRecord::Leaf { key, value })?;
            return Ok((root, true));
        }

        match self.load_record(root)? {
            UrkelNodeRecord::Leaf {
                key: existing_key,
                value: existing_value,
            } => {
                if existing_key == key {
                    if existing_value == value {
                        return Ok((root, false));
                    }
                    let next = self.intern(UrkelNodeRecord::Leaf { key, value })?;
                    return Ok((next, next != root));
                }
                if depth >= URKEL_BITS {
                    return Err(UrkelError::InvalidNode(
                        "distinct Urkel leaves collide beyond the key boundary".to_owned(),
                    ));
                }
                let shared = common_key_bits(existing_key.as_bytes(), key.as_bytes(), depth);
                let branch_depth = depth.checked_add(shared).ok_or_else(|| {
                    UrkelError::InvalidNode("Urkel insertion depth overflowed".to_owned())
                })?;
                if branch_depth >= URKEL_BITS {
                    return Err(UrkelError::InvalidNode(
                        "distinct Urkel leaves have no divergent key bit".to_owned(),
                    ));
                }
                let prefix = BitPrefix::from_key_range(key.as_bytes(), depth, shared);
                let leaf = self.intern(UrkelNodeRecord::Leaf { key, value })?;
                let branch = key_bit(key.as_bytes(), branch_depth);
                let (left, right) = if branch == 0 {
                    (leaf, root)
                } else {
                    (root, leaf)
                };
                let next = self.intern(UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                })?;
                Ok((next, true))
            }
            UrkelNodeRecord::Internal {
                prefix,
                left,
                right,
            } => {
                let branch_depth = checked_branch_depth(&prefix, depth)?;
                let shared = prefix.count_key(key.as_bytes(), depth);
                if shared != prefix.bit_len() {
                    let (front, back) = prefix.split(shared);
                    let existing = self.intern(UrkelNodeRecord::Internal {
                        prefix: back,
                        left,
                        right,
                    })?;
                    let leaf = self.intern(UrkelNodeRecord::Leaf { key, value })?;
                    let branch = key_bit(key.as_bytes(), depth + shared);
                    let (left, right) = if branch == 0 {
                        (leaf, existing)
                    } else {
                        (existing, leaf)
                    };
                    let next = self.intern(UrkelNodeRecord::Internal {
                        prefix: front,
                        left,
                        right,
                    })?;
                    return Ok((next, true));
                }

                let branch = key_bit(key.as_bytes(), branch_depth);
                let (child, changed) = if branch == 0 {
                    self.insert(left, key, value, branch_depth + 1)?
                } else {
                    self.insert(right, key, value, branch_depth + 1)?
                };
                if !changed {
                    return Ok((root, false));
                }
                let (left, right) = if branch == 0 {
                    (child, right)
                } else {
                    (left, child)
                };
                let next = self.intern(UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                })?;
                Ok((next, next != root))
            }
        }
    }

    fn remove(
        &mut self,
        root: TreeRoot,
        key: NameHash,
        depth: usize,
    ) -> Result<(TreeRoot, bool), UrkelError> {
        if root == TreeRoot::ZERO {
            return Ok((root, false));
        }

        match self.load_record(root)? {
            UrkelNodeRecord::Leaf {
                key: existing_key, ..
            } => {
                if existing_key == key {
                    Ok((TreeRoot::ZERO, true))
                } else {
                    Ok((root, false))
                }
            }
            UrkelNodeRecord::Internal {
                prefix,
                left,
                right,
            } => {
                let branch_depth = checked_branch_depth(&prefix, depth)?;
                if !prefix.matches_key(key.as_bytes(), depth) {
                    return Ok((root, false));
                }
                let branch = key_bit(key.as_bytes(), branch_depth);
                let (next_child, changed) = if branch == 0 {
                    self.remove(left, key, branch_depth + 1)?
                } else {
                    self.remove(right, key, branch_depth + 1)?
                };
                if !changed {
                    return Ok((root, false));
                }

                let sibling = if branch == 0 { right } else { left };
                if next_child == TreeRoot::ZERO {
                    return match self.load_record(sibling)? {
                        UrkelNodeRecord::Leaf { .. } => Ok((sibling, true)),
                        UrkelNodeRecord::Internal {
                            prefix: sibling_prefix,
                            left,
                            right,
                        } => {
                            let joined = prefix.join(&sibling_prefix, branch ^ 1)?;
                            checked_branch_depth(&joined, depth)?;
                            let next = self.intern(UrkelNodeRecord::Internal {
                                prefix: joined,
                                left,
                                right,
                            })?;
                            Ok((next, true))
                        }
                    };
                }

                let (left, right) = if branch == 0 {
                    (next_child, right)
                } else {
                    (left, next_child)
                };
                let next = self.intern(UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                })?;
                Ok((next, true))
            }
        }
    }
}

fn checked_branch_depth(prefix: &BitPrefix, depth: usize) -> Result<usize, UrkelError> {
    let branch_depth = depth
        .checked_add(prefix.bit_len())
        .ok_or_else(|| UrkelError::InvalidNode("Urkel path depth overflowed".to_owned()))?;
    if branch_depth >= URKEL_BITS {
        return Err(UrkelError::InvalidNode(
            "Urkel internal path exceeds the key".to_owned(),
        ));
    }
    Ok(branch_depth)
}

/// Produce an exact HSD proof by loading only the records on the requested
/// path. Each content-addressed record is decoded canonically and rehashed
/// before it is trusted.
pub fn prove_hsd_from_records<F>(
    root: TreeRoot,
    key: NameHash,
    mut load: F,
) -> Result<UrkelProof, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    let mut steps = Vec::new();
    let mut depth = 0usize;
    let mut current = root;
    let terminal = loop {
        if current == TreeRoot::ZERO {
            break MemoryProofTerminal::Empty;
        }
        let record = load_verified_record(current, &mut load)?;
        match record {
            UrkelNodeRecord::Leaf {
                key: leaf_key,
                value,
            } => {
                break if leaf_key == key {
                    MemoryProofTerminal::Inclusion { value }
                } else {
                    MemoryProofTerminal::Collision {
                        key: leaf_key,
                        value_hash: blake2b_256(&value),
                    }
                };
            }
            UrkelNodeRecord::Internal {
                prefix,
                left,
                right,
            } => {
                if !prefix.matches_key(key.as_bytes(), depth) {
                    break MemoryProofTerminal::DeadEnd {
                        prefix,
                        left: left.into_inner(),
                        right: right.into_inner(),
                    };
                }
                let branch_depth = depth.checked_add(prefix.bit_len()).ok_or_else(|| {
                    UrkelError::InvalidNode("Urkel proof path depth overflowed".to_owned())
                })?;
                if branch_depth >= URKEL_BITS {
                    return Err(UrkelError::InvalidNode(
                        "Urkel internal path exceeds the key".to_owned(),
                    ));
                }
                let branch = key_bit(key.as_bytes(), branch_depth);
                let (next, sibling) = if branch == 0 {
                    (left, right)
                } else {
                    (right, left)
                };
                steps.push(MemoryProofStep {
                    prefix,
                    branch,
                    sibling: sibling.into_inner(),
                });
                current = next;
                depth = branch_depth + 1;
            }
        }
    };

    let proof = MemoryProof {
        key,
        steps,
        terminal,
    };
    proof.verify(root)?;
    let structured = proof.to_hsd_proof()?;
    Ok(UrkelProof {
        name_hash: key,
        kind: structured.kind(),
        raw: structured.encode()?,
    })
}

/// Validate every unique record reachable from `root`, including canonical
/// decoding, content hashes, non-empty internal children, and bounded depth.
pub fn validate_record_tree<F>(root: TreeRoot, mut load: F) -> Result<usize, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    reachable_record_roots([root], &mut load).map(|roots| roots.len())
}

/// Reconstruct an immutable logical tree from content-addressed records. This
/// is intended for snapshot APIs and audits; steady-state proof generation
/// should traverse only the requested path.
pub fn materialize_record_tree<F>(root: TreeRoot, mut load: F) -> Result<MemoryUrkel, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    if root == TreeRoot::ZERO {
        return Ok(MemoryUrkel::new());
    }

    let mut entries = BTreeMap::new();
    let mut seen = HashSet::new();
    let mut pending = vec![root];
    while let Some(current) = pending.pop() {
        if !seen.insert(current) {
            continue;
        }
        match load_verified_record(current, &mut load)? {
            UrkelNodeRecord::Leaf { key, value } => {
                if entries.insert(key, value).is_some() {
                    return Err(UrkelError::InvalidNode(
                        "Urkel record tree contains a duplicate leaf key".to_owned(),
                    ));
                }
            }
            UrkelNodeRecord::Internal { left, right, .. } => {
                pending.push(right);
                pending.push(left);
            }
        }
    }

    let tree = MemoryUrkel::from_entries(entries)?;
    let actual = tree.root();
    if actual != root {
        return Err(UrkelError::NodeHashMismatch {
            expected: root,
            actual,
        });
    }
    Ok(tree)
}

/// Validate and collect the union of all content-addressed nodes reachable
/// from one or more retained roots. Shared historical subtrees are returned
/// once while depth-sensitive validation is preserved for every distinct path.
pub fn reachable_record_roots<F, I>(roots: I, mut load: F) -> Result<HashSet<TreeRoot>, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
    I: IntoIterator<Item = TreeRoot>,
{
    let mut seen_nodes = HashSet::new();
    let mut seen_paths = HashSet::new();
    let mut pending = roots
        .into_iter()
        .filter(|root| *root != TreeRoot::ZERO)
        .map(|root| (root, 0usize))
        .collect::<Vec<_>>();
    while let Some((current, depth)) = pending.pop() {
        if !seen_paths.insert((current, depth)) {
            continue;
        }
        seen_nodes.insert(current);
        match load_verified_record(current, &mut load)? {
            UrkelNodeRecord::Leaf { .. } => {}
            UrkelNodeRecord::Internal {
                prefix,
                left,
                right,
            } => {
                let child_depth = depth
                    .checked_add(prefix.bit_len())
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        UrkelError::InvalidNode("Urkel record depth overflowed".to_owned())
                    })?;
                if child_depth > URKEL_BITS {
                    return Err(UrkelError::InvalidNode(
                        "Urkel record path exceeds the key".to_owned(),
                    ));
                }
                pending.push((right, child_depth));
                pending.push((left, child_depth));
            }
        }
    }
    Ok(seen_nodes)
}

/// Validate the reachable union of several retained roots with bounded bulk
/// reads. Most immutable nodes occur at one depth even when many historical
/// roots share them, so the primary depth is stored directly beside the root;
/// only the uncommon alternate-depth path needs a second set. This preserves
/// depth-sensitive validation without retaining two full root sets.
pub fn validate_record_trees_batched<F, I>(
    roots: I,
    maximum_batch: usize,
    load_many: F,
) -> Result<usize, UrkelError>
where
    F: FnMut(&[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, UrkelError>,
    I: IntoIterator<Item = TreeRoot>,
{
    reachable_record_roots_batched(roots, maximum_batch, load_many).map(|reachable| reachable.len())
}

/// Validate the reachable union until a caller-validated immutable subtree is
/// reached. The terminal receives the absolute path depth of that subtree so
/// it can preserve the same 256-bit path bound as a complete traversal.
pub fn validate_record_trees_batched_until<F, I, T>(
    roots: I,
    maximum_batch: usize,
    terminal: T,
    load_many: F,
) -> Result<usize, UrkelError>
where
    F: FnMut(&[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, UrkelError>,
    I: IntoIterator<Item = TreeRoot>,
    T: FnMut(TreeRoot, u16) -> Result<bool, UrkelError>,
{
    reachable_record_roots_batched_until(roots, maximum_batch, terminal, load_many)
        .map(|reachable| reachable.len())
}

/// Validated, deduplicated content-addressed roots reachable from a retained
/// root set. The retained depth value is also the primary path-depth evidence
/// used during validation, so compaction does not need a second full hash set.
#[derive(Debug)]
pub struct ReachableRecordRoots {
    primary_depths: HashMap<TreeRoot, u16>,
}

impl ReachableRecordRoots {
    pub fn contains(&self, root: &TreeRoot) -> bool {
        self.primary_depths.contains_key(root)
    }

    pub fn is_empty(&self) -> bool {
        self.primary_depths.is_empty()
    }

    pub fn len(&self) -> usize {
        self.primary_depths.len()
    }
}

/// Validate and retain the reachable union using bounded storage MultiGet
/// batches. This is the collection form used by streaming compaction.
pub fn reachable_record_roots_batched<F, I>(
    roots: I,
    maximum_batch: usize,
    load_many: F,
) -> Result<ReachableRecordRoots, UrkelError>
where
    F: FnMut(&[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, UrkelError>,
    I: IntoIterator<Item = TreeRoot>,
{
    reachable_record_roots_batched_until(roots, maximum_batch, |_root, _depth| Ok(false), load_many)
}

fn reachable_record_roots_batched_until<F, I, T>(
    roots: I,
    maximum_batch: usize,
    mut terminal: T,
    mut load_many: F,
) -> Result<ReachableRecordRoots, UrkelError>
where
    F: FnMut(&[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, UrkelError>,
    I: IntoIterator<Item = TreeRoot>,
    T: FnMut(TreeRoot, u16) -> Result<bool, UrkelError>,
{
    if maximum_batch == 0 {
        return Err(UrkelError::InvalidNode(
            "Urkel validation batch size is zero".to_owned(),
        ));
    }

    let mut primary_depths = HashMap::<TreeRoot, u16>::new();
    let mut alternate_depths = HashSet::<(TreeRoot, u16)>::new();
    let mut pending = roots
        .into_iter()
        .filter(|root| *root != TreeRoot::ZERO)
        .map(|root| (root, 0u16))
        .collect::<Vec<_>>();

    while !pending.is_empty() {
        let mut work = Vec::with_capacity(maximum_batch.min(pending.len()));
        while work.len() < maximum_batch {
            let Some((current, depth)) = pending.pop() else {
                break;
            };
            if terminal(current, depth)? {
                continue;
            }
            let unseen_path = match primary_depths.entry(current) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(depth);
                    true
                }
                std::collections::hash_map::Entry::Occupied(entry) if *entry.get() == depth => {
                    false
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    alternate_depths.insert((current, depth))
                }
            };
            if unseen_path {
                work.push((current, depth));
            }
        }
        if work.is_empty() {
            continue;
        }

        let mut unique_roots = Vec::with_capacity(work.len());
        let mut requested = HashSet::with_capacity(work.len());
        for (root, _) in &work {
            if requested.insert(*root) {
                unique_roots.push(*root);
            }
        }
        let raw_records = load_many(&unique_roots)?;
        if raw_records.len() != unique_roots.len() {
            return Err(UrkelError::Storage(format!(
                "Urkel bulk loader returned {} records for {} roots",
                raw_records.len(),
                unique_roots.len()
            )));
        }
        let mut records = HashMap::with_capacity(unique_roots.len());
        for (root, raw) in unique_roots.into_iter().zip(raw_records) {
            let raw = raw.ok_or(UrkelError::MissingNode(root))?;
            records.insert(root, decode_verified_record(root, &raw)?);
        }

        for (current, depth) in work {
            match records
                .get(&current)
                .expect("every validation root has one decoded bulk result")
            {
                UrkelNodeRecord::Leaf { .. } => {}
                UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    let child_depth = usize::from(depth)
                        .checked_add(prefix.bit_len())
                        .and_then(|value| value.checked_add(1))
                        .ok_or_else(|| {
                            UrkelError::InvalidNode("Urkel record depth overflowed".to_owned())
                        })?;
                    if child_depth > URKEL_BITS {
                        return Err(UrkelError::InvalidNode(
                            "Urkel record path exceeds the key".to_owned(),
                        ));
                    }
                    let child_depth = u16::try_from(child_depth).map_err(|_| {
                        UrkelError::InvalidNode("Urkel record depth overflowed".to_owned())
                    })?;
                    pending.push((*right, child_depth));
                    pending.push((*left, child_depth));
                }
            }
        }
    }
    Ok(ReachableRecordRoots { primary_depths })
}

/// Validate the record directly bound by `root` without traversing unrelated
/// descendants. State transitions use this constant-work guard before header
/// comparison; startup performs the full reachable-tree validation above.
pub fn validate_record_root<F>(root: TreeRoot, mut load: F) -> Result<(), UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    if root != TreeRoot::ZERO {
        load_verified_record(root, &mut load)?;
    }
    Ok(())
}

fn load_verified_record<F>(expected: TreeRoot, load: &mut F) -> Result<UrkelNodeRecord, UrkelError>
where
    F: FnMut(TreeRoot) -> Result<Option<Vec<u8>>, UrkelError>,
{
    let raw = load(expected)?.ok_or(UrkelError::MissingNode(expected))?;
    decode_verified_record(expected, &raw)
}

fn decode_verified_record(expected: TreeRoot, raw: &[u8]) -> Result<UrkelNodeRecord, UrkelError> {
    let record = UrkelNodeRecord::decode(raw)?;
    let actual = record.root();
    if actual != expected {
        return Err(UrkelError::NodeHashMismatch { expected, actual });
    }
    if record.encode()? != raw {
        return Err(UrkelError::InvalidNode(
            "Urkel node record is not canonically encoded".to_owned(),
        ));
    }
    Ok(record)
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

    pub fn to_hsd_proof(&self) -> Result<HsdUrkelProof, UrkelError> {
        if self.steps.len() > URKEL_BITS {
            return Err(UrkelError::InvalidProof(
                "proof contains more than 256 branch steps".to_owned(),
            ));
        }
        let mut depth = 0usize;
        let mut nodes = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            step.prefix.validate()?;
            depth = depth
                .checked_add(step.prefix.bit_len())
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    UrkelError::InvalidProof("proof path length overflowed".to_owned())
                })?;
            if depth > URKEL_BITS {
                return Err(UrkelError::InvalidProof(
                    "proof path exceeds the 256-bit key".to_owned(),
                ));
            }
            nodes.push(HsdProofNode {
                prefix: step.prefix.clone(),
                sibling: step.sibling,
            });
        }

        let terminal = match &self.terminal {
            MemoryProofTerminal::Empty => HsdProofTerminal::DeadEnd,
            MemoryProofTerminal::Inclusion { value } => HsdProofTerminal::Exists {
                value: value.clone(),
            },
            MemoryProofTerminal::Collision { key, value_hash } => HsdProofTerminal::Collision {
                key: *key,
                value_hash: *value_hash,
            },
            MemoryProofTerminal::DeadEnd {
                prefix,
                left,
                right,
            } => HsdProofTerminal::Short {
                prefix: prefix.clone(),
                left: *left,
                right: *right,
            },
        };
        let proof = HsdUrkelProof {
            depth: depth as u16,
            nodes,
            terminal,
        };
        proof.validate_sane()?;
        Ok(proof)
    }

    pub fn encode_hsd(&self) -> Result<Vec<u8>, UrkelError> {
        self.to_hsd_proof()?.encode()
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

    pub fn bit_len(&self) -> usize {
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

    pub fn matches_key(&self, key: &[u8; 32], depth: usize) -> bool {
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

    fn join(&self, suffix: &Self, branch: u8) -> Result<Self, UrkelError> {
        self.validate()?;
        suffix.validate()?;
        if branch > 1 {
            return Err(UrkelError::InvalidNode(
                "compressed-prefix branch bit exceeds one".to_owned(),
            ));
        }
        let bit_len = self
            .bit_len()
            .checked_add(1)
            .and_then(|size| size.checked_add(suffix.bit_len()))
            .ok_or_else(|| {
                UrkelError::InvalidNode("compressed-prefix join overflowed".to_owned())
            })?;
        if bit_len > URKEL_BITS {
            return Err(UrkelError::InvalidNode(
                "compressed-prefix join exceeds 256 bits".to_owned(),
            ));
        }

        let mut bytes = vec![0u8; bit_len.div_ceil(8)];
        for index in 0..self.bit_len() {
            set_packed_bit(&mut bytes, index, self.bit(index));
        }
        set_packed_bit(&mut bytes, self.bit_len(), branch);
        for index in 0..suffix.bit_len() {
            set_packed_bit(&mut bytes, self.bit_len() + 1 + index, suffix.bit(index));
        }
        Ok(Self {
            bit_len: bit_len as u16,
            bytes,
        })
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
        if !bit_len.is_multiple_of(8) && !self.bytes.is_empty() {
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

    fn write_hsd(&self, output: &mut Vec<u8>) {
        let bit_len = self.bit_len();
        debug_assert!(bit_len <= URKEL_BITS);
        if bit_len >= 0x80 {
            output.push(0x80 | ((bit_len >> 8) as u8));
        }
        output.push(bit_len as u8);
        output.extend_from_slice(&self.bytes);
    }
}

struct HsdProofReader<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> HsdProofReader<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, UrkelError> {
        let value = *self.raw.get(self.offset).ok_or_else(|| {
            UrkelError::Codec(format!(
                "unexpected end of HSD proof at byte {}",
                self.offset
            ))
        })?;
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, UrkelError> {
        let bytes: [u8; 2] = self
            .read_slice(2)?
            .try_into()
            .expect("two-byte proof field");
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], UrkelError> {
        Ok(self.read_slice(32)?.try_into().expect("32-byte proof hash"))
    }

    fn read_vec(&mut self, size: usize) -> Result<Vec<u8>, UrkelError> {
        Ok(self.read_slice(size)?.to_vec())
    }

    fn read_prefix(&mut self) -> Result<BitPrefix, UrkelError> {
        let first = self.read_u8()?;
        let bit_len = if first & 0x80 != 0 {
            (usize::from(first & 0x7f) << 8) | usize::from(self.read_u8()?)
        } else {
            usize::from(first)
        };
        if bit_len > URKEL_BITS {
            return Err(UrkelError::Codec(format!(
                "HSD proof prefix uses {bit_len} bits"
            )));
        }
        let prefix = BitPrefix {
            bit_len: bit_len as u16,
            bytes: self.read_vec(bit_len.div_ceil(8))?,
        };
        prefix.validate()?;
        Ok(prefix)
    }

    fn read_slice(&mut self, size: usize) -> Result<&'a [u8], UrkelError> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or_else(|| UrkelError::Codec("HSD proof offset overflowed".to_owned()))?;
        let bytes = self.raw.get(self.offset..end).ok_or_else(|| {
            UrkelError::Codec(format!(
                "unexpected end of HSD proof at byte {}",
                self.offset
            ))
        })?;
        self.offset = end;
        Ok(bytes)
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

    fn collect_records(
        &self,
        records: &mut BTreeMap<TreeRoot, Vec<u8>>,
    ) -> Result<TreeRoot, UrkelError> {
        let record = match self {
            Self::Null => return Ok(TreeRoot::ZERO),
            Self::Leaf { key, value } => UrkelNodeRecord::Leaf {
                key: *key,
                value: value.clone(),
            },
            Self::Internal {
                prefix,
                left,
                right,
            } => UrkelNodeRecord::Internal {
                prefix: prefix.clone(),
                left: left.collect_records(records)?,
                right: right.collect_records(records)?,
            },
        };
        let root = record.root();
        let raw = record.encode()?;
        if let Some(existing) = records.insert(root, raw.clone()) {
            if existing != raw {
                return Err(UrkelError::NodeHashCollision(root));
            }
        }
        Ok(root)
    }
}

fn sorted_entries_root(entries: &[(&NameHash, &Vec<u8>)], depth: usize) -> TreeRoot {
    match entries {
        [] => TreeRoot::ZERO,
        [(key, value)] => TreeRoot::new(hash_leaf(key.as_bytes(), &blake2b_256(value))),
        _ => {
            let first = entries.first().expect("nonempty entries").0;
            let last = entries.last().expect("nonempty entries").0;
            let shared = common_key_bits(first.as_bytes(), last.as_bytes(), depth);
            let branch_depth = depth + shared;
            debug_assert!(branch_depth < URKEL_BITS);
            let split =
                entries.partition_point(|(key, _)| key_bit(key.as_bytes(), branch_depth) == 0);
            debug_assert!(split > 0 && split < entries.len());
            let left = sorted_entries_root(&entries[..split], branch_depth + 1);
            let right = sorted_entries_root(&entries[split..], branch_depth + 1);
            let prefix = BitPrefix::from_key_range(first.as_bytes(), depth, shared);
            TreeRoot::new(hash_internal(&prefix, left.as_bytes(), right.as_bytes()))
        }
    }
}

fn sorted_entries_record_path(
    entries: &[(&NameHash, &Vec<u8>)],
    depth: usize,
    target: TreeRoot,
) -> Result<(TreeRoot, Option<Vec<(TreeRoot, Vec<u8>)>>), UrkelError> {
    match entries {
        [] => Ok((TreeRoot::ZERO, None)),
        [(key, value)] => {
            let root = TreeRoot::new(hash_leaf(key.as_bytes(), &blake2b_256(value)));
            let path = if root == target {
                Some(vec![(
                    root,
                    UrkelNodeRecord::Leaf {
                        key: **key,
                        value: (*value).clone(),
                    }
                    .encode()?,
                )])
            } else {
                None
            };
            Ok((root, path))
        }
        _ => {
            let first = entries.first().expect("nonempty entries").0;
            let last = entries.last().expect("nonempty entries").0;
            let shared = common_key_bits(first.as_bytes(), last.as_bytes(), depth);
            let branch_depth = depth.checked_add(shared).ok_or_else(|| {
                UrkelError::InvalidNode("sorted entry branch depth overflowed".to_owned())
            })?;
            if branch_depth >= URKEL_BITS {
                return Err(UrkelError::InvalidNode(
                    "sorted entries contain colliding key ranges".to_owned(),
                ));
            }
            let split =
                entries.partition_point(|(key, _)| key_bit(key.as_bytes(), branch_depth) == 0);
            if split == 0 || split == entries.len() {
                return Err(UrkelError::InvalidNode(
                    "sorted entries failed to partition at their first divergent bit".to_owned(),
                ));
            }
            let (left, left_path) =
                sorted_entries_record_path(&entries[..split], branch_depth + 1, target)?;
            let (right, right_path) =
                sorted_entries_record_path(&entries[split..], branch_depth + 1, target)?;
            if left_path.is_some() && right_path.is_some() {
                return Err(UrkelError::InvalidNode(
                    "target node appears in both sorted subtrees".to_owned(),
                ));
            }
            let record = UrkelNodeRecord::Internal {
                prefix: BitPrefix::from_key_range(first.as_bytes(), depth, shared),
                left,
                right,
            };
            let root = record.root();
            let mut path = if root == target {
                Vec::new()
            } else {
                left_path.or(right_path).unwrap_or_default()
            };
            if root == target || !path.is_empty() {
                path.push((root, record.encode()?));
                Ok((root, Some(path)))
            } else {
                Ok((root, None))
            }
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

fn set_key_bit(bytes: &mut [u8; 32], index: usize, bit: u8) {
    debug_assert!(index < URKEL_BITS);
    debug_assert!(bit <= 1);
    let mask = 1 << (7 - (index % 8));
    bytes[index / 8] = (bytes[index / 8] & !mask) | (bit << (7 - (index % 8)));
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
/// not the qualified persistent implementation and has no durable snapshot,
/// compaction, undo, or crash-recovery contract.
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

    fn prove(&self, name_hash: &NameHash) -> Result<UrkelProof, UrkelError> {
        self.tree.prove_hsd(*name_hash)
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
    #[error("urkel value size {0} exceeds the configured bound")]
    ValueTooLarge(usize),
    #[error("invalid urkel proof: {0}")]
    InvalidProof(String),
    #[error("invalid urkel node: {0}")]
    InvalidNode(String),
    #[error("missing content-addressed urkel node {0:?}")]
    MissingNode(TreeRoot),
    #[error("urkel node hash mismatch: expected {expected:?}, got {actual:?}")]
    NodeHashMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
    #[error("distinct urkel node records collide at {0:?}")]
    NodeHashCollision(TreeRoot),
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

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofFixture {
        entries: Vec<ProofEntry>,
        root: String,
        proofs: Vec<CanonicalProof>,
        mutations: Vec<ProofMutation>,
    }

    #[derive(Deserialize)]
    struct ProofEntry {
        key: String,
        value: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CanonicalProof {
        id: String,
        root: String,
        key: String,
        kind: String,
        #[serde(rename = "type")]
        proof_type: String,
        depth: u16,
        node_count: usize,
        raw: String,
        value: Option<String>,
        verify_code: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofMutation {
        id: String,
        root: String,
        key: String,
        raw: String,
        decode_accepted: bool,
        canonical_raw: Option<String>,
        verify_code: Option<u32>,
    }

    fn proof_fixture() -> ProofFixture {
        serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/urkel-proofs-v1.json"
        ))
        .expect("proof fixture")
    }

    fn fixture_tree(fixture: &ProofFixture) -> MemoryUrkel {
        MemoryUrkel::from_entries(fixture.entries.iter().map(|entry| {
            (
                NameHash::new(decode_hex_32(&entry.key)),
                decode_hex(&entry.value),
            )
        }))
        .expect("fixture tree")
    }

    #[test]
    fn exact_roots_match_the_pinned_hsd_urkel_fixture() {
        let fixture: RootFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/state-urkel-v1.json"
        ))
        .expect("fixture");
        assert_eq!(fixture.states.len(), fixture.incremental_roots.len());

        let mut tree = MemoryUrkel::new();
        let mut record_root = TreeRoot::ZERO;
        let mut records = BTreeMap::new();
        for (state, expected) in fixture.states.iter().zip(&fixture.incremental_roots) {
            let name_hash = NameHash::new(decode_hex_32(&state.name_hash));
            let value = decode_hex(&state.encoded);
            tree.insert(name_hash, value.clone()).expect("insert");
            let update = update_record_tree(record_root, [(name_hash, Some(value))], |hash| {
                Ok(records.get(&hash).cloned())
            })
            .expect("incremental record update");
            record_root = update.root();
            records.extend(update.into_records());
            let expected = TreeRoot::new(decode_hex_32(&expected.root));
            assert_eq!(tree.root(), expected);
            assert_eq!(record_root, expected);
        }

        let reachable = tree.node_records().expect("materialized records");
        for (hash, raw) in &reachable {
            assert_eq!(records.get(hash), Some(raw));
        }
        assert_eq!(
            validate_record_tree(record_root, |hash| Ok(records.get(&hash).cloned()))
                .expect("incremental record tree"),
            reachable.len()
        );
    }

    #[test]
    fn record_path_reconstruction_is_bounded_and_rooted() {
        let tree = MemoryUrkel::from_entries(
            (0..64).map(|index| (key(index), format!("value-{index}").into_bytes())),
        )
        .expect("tree");
        let (expected_root, records) = tree.node_records_with_root().expect("records");
        let target = records
            .keys()
            .copied()
            .find(|root| *root != expected_root)
            .expect("non-root record");

        let (actual_root, record_count, path) = tree
            .record_path_to_root(target)
            .expect("target record path");
        let path = path.expect("target is reachable");
        assert_eq!(actual_root, expected_root);
        assert_eq!(record_count, records.len());
        assert_eq!(path.first().map(|(root, _)| *root), Some(target));
        assert_eq!(path.last().map(|(root, _)| *root), Some(expected_root));
        for (root, raw) in &path {
            assert_eq!(records.get(root), Some(raw));
        }

        let mut missing = [0xff; 32];
        while records.contains_key(&TreeRoot::new(missing)) {
            missing[0] = missing[0].wrapping_sub(1);
        }
        let (missing_root, missing_count, missing_path) = tree
            .record_path_to_root(TreeRoot::new(missing))
            .expect("missing record path");
        assert_eq!(missing_root, expected_root);
        assert_eq!(missing_count, records.len());
        assert!(missing_path.is_none());
    }

    #[test]
    fn record_updates_and_removals_are_path_local_and_history_independent() {
        let mut tree = MemoryUrkel::from_entries(
            (0..64).map(|index| (key(index), format!("value-{index}").into_bytes())),
        )
        .expect("tree");
        let mut root = tree.root();
        let mut records = tree.node_records().expect("records");
        let total_records = records.len();
        let historical_root = root;
        let historical_proof = prove_hsd_from_records(historical_root, key(31), |hash| {
            Ok(records.get(&hash).cloned())
        })
        .expect("historical proof");

        let replacement = b"replacement-value".to_vec();
        let mut loaded = BTreeSet::new();
        let update = update_record_tree(root, [(key(31), Some(replacement.clone()))], |hash| {
            loaded.insert(hash);
            Ok(records.get(&hash).cloned())
        })
        .expect("path-local replacement");
        tree.insert(key(31), replacement).expect("replace oracle");
        assert_eq!(update.root(), tree.root());
        assert!(loaded.len() < total_records);
        assert!(update.records().len() < total_records);
        root = update.root();
        records.extend(update.into_records());

        let unchanged = update_record_tree(
            root,
            [(key(31), Some(b"replacement-value".to_vec()))],
            |hash| Ok(records.get(&hash).cloned()),
        )
        .expect("unchanged replacement");
        assert_eq!(unchanged.root(), root);
        assert!(unchanged.records().is_empty());

        let mut removal_order = (0..64).step_by(2).collect::<Vec<_>>();
        removal_order.extend((1..64).step_by(2));
        for index in removal_order {
            let update = update_record_tree(root, [(key(index), None)], |hash| {
                Ok(records.get(&hash).cloned())
            })
            .expect("path-local removal");
            assert!(tree.remove(&key(index)).is_some());
            assert_eq!(update.root(), tree.root(), "remove key {index}");
            root = update.root();
            records.extend(update.into_records());
        }
        assert_eq!(root, TreeRoot::ZERO);
        assert_eq!(
            prove_hsd_from_records(historical_root, key(31), |hash| {
                Ok(records.get(&hash).cloned())
            })
            .expect("retained historical proof")
            .raw,
            historical_proof.raw
        );

        let unchanged =
            update_record_tree(root, [(key(99), None)], |_| Ok(None)).expect("absent removal");
        assert_eq!(unchanged.root(), TreeRoot::ZERO);
        assert!(unchanged.records().is_empty());
    }

    #[test]
    fn deterministic_mixed_record_mutations_match_rebuild_oracle() {
        fn next(seed: &mut u64) -> u64 {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        }

        fn mixed_key(index: u64) -> NameHash {
            NameHash::new(blake2b_256(&index.to_le_bytes()))
        }

        let mut seed = 0x6d65_7368_6d69_6e65u64;
        let mut tree = MemoryUrkel::new();
        let mut root = TreeRoot::ZERO;
        let mut records = BTreeMap::new();
        for step in 0..1_000u64 {
            let index = next(&mut seed) % 128;
            let name_hash = mixed_key(index);
            let value = if next(&mut seed).is_multiple_of(4) {
                None
            } else {
                Some(format!("mixed-{index}-{step}").into_bytes())
            };
            let update = update_record_tree(root, [(name_hash, value.clone())], |hash| {
                Ok(records.get(&hash).cloned())
            })
            .expect("mixed incremental mutation");
            match value {
                Some(value) => {
                    tree.insert(name_hash, value).expect("oracle insert");
                }
                None => {
                    tree.remove(&name_hash);
                }
            }
            assert_eq!(update.root(), tree.root(), "mixed step {step}");
            root = update.root();
            records.extend(update.into_records());

            let probe = mixed_key(next(&mut seed) % 128);
            assert_eq!(
                prove_hsd_from_records(root, probe, |hash| Ok(records.get(&hash).cloned()))
                    .expect("mixed proof")
                    .verify_value(root)
                    .expect("verify mixed proof"),
                tree.get(&probe).map(ToOwned::to_owned),
                "mixed proof step {step}"
            );
            if step.is_multiple_of(50) {
                let expected_nodes = tree.len().saturating_mul(2).saturating_sub(1);
                assert_eq!(
                    validate_record_tree(root, |hash| Ok(records.get(&hash).cloned()))
                        .expect("mixed record tree"),
                    expected_nodes
                );
            }
        }
    }

    #[test]
    fn batched_retained_tree_validation_matches_reachable_union() {
        let first = MemoryUrkel::from_entries(
            (0..32u32).map(|index| (key(index), format!("first-{index}").into_bytes())),
        )
        .expect("first tree");
        let second = MemoryUrkel::from_entries(
            (16..48u32).map(|index| (key(index), format!("second-{index}").into_bytes())),
        )
        .expect("second tree");
        let mut records = first.node_records().expect("first records");
        records.extend(second.node_records().expect("second records"));
        let roots = [first.root(), second.root()];
        let expected = reachable_record_roots(roots, |root| Ok(records.get(&root).cloned()))
            .expect("reachable union");

        let mut calls = 0usize;
        let actual = reachable_record_roots_batched(roots, 3, |requested| {
            calls += 1;
            assert!(!requested.is_empty());
            assert!(requested.len() <= 3);
            Ok(requested
                .iter()
                .map(|root| records.get(root).cloned())
                .collect())
        })
        .expect("batched validation");

        assert_eq!(actual.len(), expected.len());
        assert!(!actual.is_empty());
        assert!(expected.iter().all(|root| actual.contains(root)));
        assert_eq!(
            validate_record_trees_batched(roots, 3, |requested| {
                Ok(requested
                    .iter()
                    .map(|root| records.get(root).cloned())
                    .collect())
            })
            .expect("batched count"),
            expected.len()
        );
        assert!(calls > 1);
    }

    #[test]
    fn batched_validation_stops_at_prevalidated_subtrees() {
        let base = MemoryUrkel::from_entries(
            (0..32u32).map(|index| (key(index), format!("base-{index}").into_bytes())),
        )
        .expect("base tree");
        let base_records = base.node_records().expect("base records");
        let update = update_record_tree(
            base.root(),
            [(key(10_000), Some(b"overlay".to_vec()))],
            |root| Ok(base_records.get(&root).cloned()),
        )
        .expect("overlay update");
        let overlay_root = update.root();
        let overlay_records = update.into_records();
        let mut terminals = 0usize;
        let loaded = validate_record_trees_batched_until(
            [overlay_root],
            8,
            |root, _depth| {
                let terminal = base_records.contains_key(&root);
                terminals += usize::from(terminal);
                Ok(terminal)
            },
            |requested| {
                assert!(
                    requested
                        .iter()
                        .all(|root| !base_records.contains_key(root)),
                    "prevalidated base records must not reach the loader"
                );
                Ok(requested
                    .iter()
                    .map(|root| overlay_records.get(root).cloned())
                    .collect())
            },
        )
        .expect("overlay validation");

        assert_eq!(loaded, overlay_records.len());
        assert!(terminals > 0);
    }

    #[test]
    fn batched_retained_tree_validation_fails_closed() {
        let tree = MemoryUrkel::from_entries([(key(1), b"one".to_vec())]).expect("tree");
        assert!(matches!(
            validate_record_trees_batched([tree.root()], 0, |_| Ok(Vec::new())),
            Err(UrkelError::InvalidNode(message)) if message.contains("batch size")
        ));
        assert!(matches!(
            validate_record_trees_batched([tree.root()], 4, |_| Ok(Vec::new())),
            Err(UrkelError::Storage(message)) if message.contains("returned 0 records")
        ));
        assert!(matches!(
            validate_record_trees_batched([tree.root()], 4, |_| Ok(vec![None])),
            Err(UrkelError::MissingNode(root)) if root == tree.root()
        ));
    }

    #[test]
    fn multi_mutation_update_returns_only_final_reachable_records() {
        let tree = MemoryUrkel::from_entries(
            (0..64).map(|index| (key(index), format!("value-{index}").into_bytes())),
        )
        .expect("tree");
        let base_records = tree.node_records().expect("base records");
        let update = update_record_tree(
            tree.root(),
            (8..24).map(|index| {
                (
                    key(index),
                    Some(format!("replacement-{index}").into_bytes()),
                )
            }),
            |hash| Ok(base_records.get(&hash).cloned()),
        )
        .expect("multi-mutation update");

        let mut merged = base_records;
        merged.extend(update.records().clone());
        let reachable =
            reachable_record_roots([update.root()], |hash| Ok(merged.get(&hash).cloned()))
                .expect("reachable final tree");
        assert!(
            update
                .records()
                .keys()
                .all(|record_root| reachable.contains(record_root)),
            "the staged update must not retain superseded intra-block paths"
        );
    }

    #[test]
    fn batched_record_mutation_matches_point_loading_with_fewer_boundaries() {
        let tree = MemoryUrkel::from_entries(
            (0..512).map(|index| (key(index), format!("value-{index}").into_bytes())),
        )
        .expect("tree");
        let records = tree.node_records().expect("records");
        let updates = (96..224)
            .map(|index| {
                (
                    key(index),
                    Some(format!("replacement-{index}").into_bytes()),
                )
            })
            .collect::<Vec<_>>();

        let mut point_calls = 0usize;
        let point = update_record_tree(tree.root(), updates.clone(), |record_root| {
            point_calls += 1;
            Ok(records.get(&record_root).cloned())
        })
        .expect("point-loaded mutation");

        let mut batch_calls = 0usize;
        let mut maximum_batch = 0usize;
        let batched =
            update_record_tree_batched(tree.root(), updates.clone(), 1_024, |record_roots| {
                batch_calls += 1;
                maximum_batch = maximum_batch.max(record_roots.len());
                Ok(record_roots
                    .iter()
                    .map(|record_root| records.get(record_root).cloned())
                    .collect())
            })
            .expect("batch-loaded mutation");
        let prefetched =
            update_record_tree_prefetched(tree.root(), updates, records.clone(), |_record_root| {
                panic!("complete prefetched tree must not fall back to point loading")
            })
            .expect("prefetched mutation");

        assert_eq!(batched.root(), point.root());
        assert_eq!(batched.records(), point.records());
        assert_eq!(prefetched, point);
        assert!(maximum_batch > 1, "fixture must exercise a real MultiGet");
        assert!(
            batch_calls * 4 < point_calls,
            "batch calls {batch_calls} did not materially reduce {point_calls} point loads"
        );
    }

    #[test]
    fn mutation_trie_matches_sequential_updates_and_reuses_opaque_subtrees() {
        let entries = (0..1_024)
            .map(|index| (key(index), format!("value-{index}").into_bytes()))
            .collect::<Vec<_>>();
        let tree = MemoryUrkel::from_entries(entries.clone()).expect("tree");
        let records = tree.node_records().expect("records");
        let updates = (128..384)
            .map(|index| {
                (
                    key(index),
                    Some(format!("replacement-{index}").into_bytes()),
                )
            })
            .chain((384..512).map(|index| (key(index), None)))
            .chain(
                (2_000..2_128)
                    .map(|index| (key(index), Some(format!("inserted-{index}").into_bytes()))),
            )
            .collect::<Vec<_>>();

        let expected = update_record_tree(tree.root(), updates.clone(), |record_root| {
            Ok(records.get(&record_root).cloned())
        })
        .expect("sequential update");
        let actual = update_record_tree_mutation_trie_prefetched(
            tree.root(),
            updates,
            records.clone(),
            |_record_root| panic!("complete prefetch must cover mutation-trie fallback loads"),
        )
        .expect("mutation-trie update");

        assert_eq!(actual.root(), expected.root());
        let mut merged = records;
        merged.extend(actual.records().clone());
        validate_record_tree(actual.root(), |record_root| {
            Ok(merged.get(&record_root).cloned())
        })
        .expect("validate mutation-trie result");
        assert!(
            actual.records().len() < 1_500,
            "shared frontier should remain proportional to the final path union"
        );
    }

    #[test]
    fn mutation_trie_matches_history_independent_randomized_roots() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next_key = || {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_exact_mut(8) {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                chunk.copy_from_slice(&seed.to_be_bytes());
            }
            NameHash::new(bytes)
        };

        let mut entries = BTreeMap::new();
        while entries.len() < 400 {
            let key = next_key();
            entries.insert(key, key.as_bytes()[..8].to_vec());
        }
        let tree = MemoryUrkel::from_entries(
            entries
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect::<Vec<_>>(),
        )
        .expect("base tree");
        let records = tree.node_records().expect("base records");
        let existing = entries.keys().copied().collect::<Vec<_>>();
        let mut updates = Vec::new();
        for (index, key) in existing.iter().copied().enumerate().take(180) {
            let value = if index % 3 == 0 {
                None
            } else {
                Some(format!("updated-{index}").into_bytes())
            };
            updates.push((key, value.clone()));
            entries.entry(key).and_modify(|current| {
                if let Some(value) = value.as_ref() {
                    *current = value.clone();
                }
            });
            if value.is_none() {
                entries.remove(&key);
            }
        }
        for index in 0..160 {
            let key = next_key();
            let value = format!("new-{index}").into_bytes();
            updates.push((key, Some(value.clone())));
            entries.insert(key, value);
        }
        let duplicate = existing[200];
        updates.push((duplicate, Some(b"superseded".to_vec())));
        updates.push((duplicate, Some(b"final".to_vec())));
        entries.insert(duplicate, b"final".to_vec());
        updates.reverse();
        updates.rotate_left(73);

        // Restore last-write-wins expected state after deliberately scrambling
        // the input sequence.
        let mut expected_entries = tree
            .entries()
            .map(|(key, value)| (*key, value.to_vec()))
            .collect::<BTreeMap<_, _>>();
        for (key, value) in &updates {
            match value {
                Some(value) => {
                    expected_entries.insert(*key, value.clone());
                }
                None => {
                    expected_entries.remove(key);
                }
            }
        }
        let expected = MemoryUrkel::from_entries(expected_entries).expect("expected tree");
        let actual = update_record_tree_mutation_trie_prefetched(
            tree.root(),
            updates,
            records.clone(),
            |_record_root| panic!("complete prefetch must cover randomized mutation loads"),
        )
        .expect("randomized mutation-trie update");

        assert_eq!(actual.root(), expected.root());
        let mut merged = records;
        merged.extend(actual.records().clone());
        assert_eq!(
            materialize_record_tree(actual.root(), |record_root| {
                Ok(merged.get(&record_root).cloned())
            })
            .expect("materialize updated tree"),
            expected
        );
    }

    #[test]
    fn batched_record_mutation_handles_removals_and_fails_closed() {
        let tree = MemoryUrkel::from_entries(
            (0..128).map(|index| (key(index), format!("value-{index}").into_bytes())),
        )
        .expect("tree");
        let records = tree.node_records().expect("records");
        let updates = (16..48)
            .map(|index| (key(index), None))
            .chain(
                (128..160)
                    .map(|index| (key(index), Some(format!("inserted-{index}").into_bytes()))),
            )
            .collect::<Vec<_>>();
        let expected = update_record_tree(tree.root(), updates.clone(), |record_root| {
            Ok(records.get(&record_root).cloned())
        })
        .expect("point-loaded mixed mutation");
        let actual = update_record_tree_batched(tree.root(), updates.clone(), 7, |record_roots| {
            Ok(record_roots
                .iter()
                .map(|record_root| records.get(record_root).cloned())
                .collect())
        })
        .expect("batch-loaded mixed mutation");
        assert_eq!(actual, expected);

        assert!(matches!(
            update_record_tree_batched(tree.root(), updates.clone(), 0, |_| Ok(Vec::new())),
            Err(UrkelError::InvalidNode(message)) if message.contains("batch size")
        ));
        assert!(matches!(
            update_record_tree_batched(tree.root(), updates, 7, |_| Ok(Vec::new())),
            Err(UrkelError::Storage(message)) if message.contains("returned 0 records")
        ));
    }

    #[test]
    fn exact_proofs_match_the_pinned_hsd_urkel_fixture() {
        let fixture = proof_fixture();
        let populated = fixture_tree(&fixture);
        assert_eq!(
            populated.root(),
            TreeRoot::new(decode_hex_32(&fixture.root))
        );
        let empty = MemoryUrkel::new();
        let empty_records = BTreeMap::new();
        let populated_records = populated.node_records().expect("node records");
        let mut incremental_root = TreeRoot::ZERO;
        let mut incremental_records = BTreeMap::new();
        for entry in &fixture.entries {
            let update = update_record_tree(
                incremental_root,
                [(
                    NameHash::new(decode_hex_32(&entry.key)),
                    Some(decode_hex(&entry.value)),
                )],
                |hash| Ok(incremental_records.get(&hash).cloned()),
            )
            .expect("incremental fixture insert");
            incremental_root = update.root();
            incremental_records.extend(update.into_records());
        }
        assert_eq!(incremental_root, populated.root());
        for (hash, raw) in &populated_records {
            assert_eq!(incremental_records.get(hash), Some(raw));
        }
        assert_eq!(populated_records.len(), fixture.entries.len() * 2 - 1);
        assert_eq!(
            validate_record_tree(populated.root(), |hash| {
                Ok(populated_records.get(&hash).cloned())
            })
            .expect("record tree"),
            populated_records.len()
        );
        let verifier = NativeUrkelVerifier;
        assert!(verifier.is_consensus_complete());

        for expected in &fixture.proofs {
            assert_eq!(expected.verify_code, 0, "{}", expected.id);
            let raw = decode_hex(&expected.raw);
            let key = NameHash::new(decode_hex_32(&expected.key));
            let root = TreeRoot::new(decode_hex_32(&expected.root));
            let proof = HsdUrkelProof::decode(&raw)
                .unwrap_or_else(|error| panic!("{} failed to decode: {error}", expected.id));
            assert_eq!(
                proof.encode().expect("canonical encode"),
                raw,
                "{}",
                expected.id
            );
            assert_eq!(proof.depth(), expected.depth, "{}", expected.id);
            assert_eq!(proof.node_count(), expected.node_count, "{}", expected.id);

            let kind = match expected.kind.as_str() {
                "inclusion" => ProofKind::Inclusion,
                "nonInclusion" => ProofKind::NonInclusion,
                other => panic!("{} has unknown fixture kind {other}", expected.id),
            };
            assert_eq!(proof.kind(), kind, "{}", expected.id);
            let encoded_type = u16::from_le_bytes([raw[0], raw[1]]) >> 14;
            let expected_type = match expected.proof_type.as_str() {
                "TYPE_DEADEND" => HSD_PROOF_DEADEND,
                "TYPE_SHORT" => HSD_PROOF_SHORT,
                "TYPE_COLLISION" => HSD_PROOF_COLLISION,
                "TYPE_EXISTS" => HSD_PROOF_EXISTS,
                other => panic!("{} has unknown fixture type {other}", expected.id),
            };
            assert_eq!(encoded_type, expected_type, "{}", expected.id);

            let value = proof
                .verify(root, &key)
                .unwrap_or_else(|error| panic!("{} failed to verify: {error}", expected.id));
            assert_eq!(
                value,
                expected.value.as_deref().map(decode_hex),
                "{}",
                expected.id
            );

            let native = if root == TreeRoot::ZERO {
                &empty
            } else {
                &populated
            };
            assert_eq!(
                native.prove_memory(key).encode_hsd().expect("native proof"),
                raw,
                "{}",
                expected.id
            );
            let records = if root == TreeRoot::ZERO {
                &empty_records
            } else {
                &incremental_records
            };
            assert_eq!(
                prove_hsd_from_records(root, key, |hash| Ok(records.get(&hash).cloned()))
                    .expect("content-addressed proof")
                    .raw,
                raw,
                "{}",
                expected.id
            );

            let wrapped = UrkelProof {
                name_hash: key,
                kind,
                raw,
            };
            verifier.verify(&wrapped, root).unwrap_or_else(|error| {
                panic!("{} wrapper verification failed: {error}", expected.id)
            });
        }
    }

    #[test]
    fn malformed_and_cross_root_proof_fixture_fails_closed() {
        let fixture = proof_fixture();

        for expected in &fixture.mutations {
            let raw = decode_hex(&expected.raw);
            let decoded = HsdUrkelProof::decode(&raw);
            assert_eq!(decoded.is_ok(), expected.decode_accepted, "{}", expected.id);
            let Ok(proof) = decoded else {
                continue;
            };
            assert_eq!(
                proof.encode().expect("canonical encode"),
                decode_hex(expected.canonical_raw.as_deref().expect("canonical raw")),
                "{}",
                expected.id
            );
            let root = TreeRoot::new(decode_hex_32(&expected.root));
            let key = NameHash::new(decode_hex_32(&expected.key));
            assert_eq!(
                proof.verify(root, &key).is_ok(),
                expected.verify_code == Some(0),
                "{}",
                expected.id
            );
        }

        let inclusion = fixture
            .proofs
            .iter()
            .find(|proof| proof.kind == "inclusion")
            .expect("inclusion proof");
        let mislabeled = UrkelProof {
            name_hash: NameHash::new(decode_hex_32(&inclusion.key)),
            kind: ProofKind::NonInclusion,
            raw: decode_hex(&inclusion.raw),
        };
        assert!(matches!(
            mislabeled.verify_value(TreeRoot::new(decode_hex_32(&inclusion.root))),
            Err(UrkelError::InvalidProof(_))
        ));
        assert!(matches!(
            HsdUrkelProof::decode(&vec![0; MAX_HSD_PROOF_SIZE + 1]),
            Err(UrkelError::Codec(_))
        ));
    }

    #[test]
    fn content_addressed_nodes_reject_missing_corrupt_and_noncanonical_records() {
        let tree = MemoryUrkel::from_entries([
            (key(7), b"alpha".to_vec()),
            (key(11), b"beta".to_vec()),
            (key(19), b"gamma".to_vec()),
        ])
        .expect("tree");
        let root = tree.root();
        let records = tree.node_records().expect("records");

        let mut missing = records.clone();
        missing.remove(&root);
        assert!(matches!(
            prove_hsd_from_records(root, key(7), |hash| Ok(missing.get(&hash).cloned())),
            Err(UrkelError::MissingNode(hash)) if hash == root
        ));
        assert!(matches!(
            update_record_tree(root, [(key(7), Some(b"changed".to_vec()))], |hash| {
                Ok(missing.get(&hash).cloned())
            }),
            Err(UrkelError::MissingNode(hash)) if hash == root
        ));

        let mut path = Vec::new();
        prove_hsd_from_records(root, key(7), |hash| {
            path.push(hash);
            Ok(records.get(&hash).cloned())
        })
        .expect("proof path");
        let missing_path_root = *path.last().expect("path leaf");
        assert_ne!(missing_path_root, root);
        let mut missing_path = records.clone();
        missing_path.remove(&missing_path_root);
        assert!(matches!(
            update_record_tree(root, [(key(7), Some(b"changed".to_vec()))], |hash| {
                Ok(missing_path.get(&hash).cloned())
            }),
            Err(UrkelError::MissingNode(hash)) if hash == missing_path_root
        ));

        let mut corrupt = records.clone();
        let root_record = corrupt.get_mut(&root).expect("root record");
        *root_record.last_mut().expect("record byte") ^= 1;
        assert!(matches!(
            validate_record_tree(root, |hash| Ok(corrupt.get(&hash).cloned())),
            Err(UrkelError::NodeHashMismatch { expected, .. }) if expected == root
        ));
        assert!(matches!(
            update_record_tree(root, [(key(7), Some(b"changed".to_vec()))], |hash| {
                Ok(corrupt.get(&hash).cloned())
            }),
            Err(UrkelError::NodeHashMismatch { expected, .. }) if expected == root
        ));

        let mut trailing = records;
        trailing.get_mut(&root).expect("root record").push(0);
        assert!(matches!(
            validate_record_tree(root, |hash| Ok(trailing.get(&hash).cloned())),
            Err(UrkelError::Codec(_))
        ));
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

        let snapshot = tree.snapshot().expect("proof snapshot");
        let proof = snapshot.prove(&key(1)).expect("proof");
        assert_eq!(proof.kind, ProofKind::Inclusion);
        assert_eq!(
            proof.verify_value(snapshot.root()).expect("verify proof"),
            Some(b"one".to_vec())
        );
        NativeUrkelVerifier
            .verify(&proof, snapshot.root())
            .expect("native verifier");
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
