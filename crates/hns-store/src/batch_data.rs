//! Ownership and accounting shared by overlays and backend batches.

use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::{Hash, Hasher},
    ops::Deref,
    sync::Arc,
};

use crate::{ColumnFamily, StoreError, WriteBatch};

/// Immutable, cheaply cloned bytes. Owning the vector inside the shared handle
/// lets deferred publication recover its original allocation with `into_vec`.
/// Cloning this type never clones the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedBytes(Arc<Vec<u8>>);

impl SharedBytes {
    pub fn into_vec(self) -> Vec<u8> {
        Arc::try_unwrap(self.0).unwrap_or_else(|shared| (*shared).clone())
    }

    pub fn retained_capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl From<Vec<u8>> for SharedBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Arc::new(value))
    }
}

impl From<&[u8]> for SharedBytes {
    fn from(value: &[u8]) -> Self {
        Self::from(value.to_vec())
    }
}

impl Deref for SharedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Hashes, outpoints and height keys fit inline. Variable-length wallet keys
/// share their immutable allocation with checkpoint journal entries.
#[derive(Clone, Debug)]
pub(crate) enum CompactKey {
    Inline { bytes: [u8; 36], len: u8 },
    Shared(Arc<[u8]>),
}

impl CompactKey {
    pub(crate) fn new(key: &[u8]) -> Self {
        if key.len() <= 36 {
            let mut bytes = [0; 36];
            bytes[..key.len()].copy_from_slice(key);
            Self::Inline {
                bytes,
                len: key.len() as u8,
            }
        } else {
            Self::Shared(Arc::from(key))
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { bytes, len } => &bytes[..usize::from(*len)],
            Self::Shared(bytes) => bytes,
        }
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Self::Inline { .. } => 0,
            Self::Shared(bytes) => bytes.len().saturating_add(2 * size_of::<usize>()),
        }
    }
}

impl Deref for CompactKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl AsRef<[u8]> for CompactKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl Borrow<[u8]> for CompactKey {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}
impl PartialEq for CompactKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for CompactKey {}
impl Hash for CompactKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}
impl PartialOrd for CompactKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for CompactKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

/// A batch that stores admission charges in its own final-operation records.
/// Callers compute and admit a replacement before invoking either mutator.
/// Checkpoint charges describe retained originals, independent of the final
/// operation charge; the caller releases them only after checkpoint commit.
pub trait AccountedWriteBatch: WriteBatch {
    fn operation_charge(&self, family: ColumnFamily, key: &[u8]) -> u64;

    fn put_accounted(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        value: &[u8],
        charge: u64,
    ) -> Result<(), StoreError> {
        self.put_shared_accounted(family, key, SharedBytes::from(value), charge)
    }

    fn delete_accounted(
        &mut self,
        family: ColumnFamily,
        key: &[u8],
        charge: u64,
    ) -> Result<(), StoreError> {
        self.delete_with_charge(family, key, charge)
    }

    fn checkpoint_retained_charge(&self) -> u64;

    /// Additional charge for the original value and one journal entry if the
    /// next write is this key's first change in the current checkpoint.
    fn checkpoint_replacement_charge(&self, family: ColumnFamily, key: &[u8]) -> u64;
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BatchOperation {
    pub(crate) value: Option<SharedBytes>,
    pub(crate) charge: u64,
    pub(crate) checkpointed: bool,
}

impl BatchOperation {
    pub(crate) fn new(value: Option<SharedBytes>, charge: u64) -> Self {
        Self {
            value,
            charge,
            checkpointed: false,
        }
    }
}

impl From<Option<Vec<u8>>> for BatchOperation {
    fn from(value: Option<Vec<u8>>) -> Self {
        Self::new(value.map(SharedBytes::from), 0)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StoreKey {
    pub(crate) family: ColumnFamily,
    pub(crate) key: CompactKey,
}
impl StoreKey {
    pub(crate) fn new(family: ColumnFamily, key: &[u8]) -> Self {
        Self {
            family,
            key: CompactKey::new(key),
        }
    }
}

// Borrow a composite (family, byte slice) key without constructing an owned
// long-key Arc during read-only admission checks. Both forms use exactly the
// same byte hashing/equality as StoreKey's derived Hash/Eq implementations.
trait StoreKeyView {
    fn family(&self) -> ColumnFamily;
    fn bytes(&self) -> &[u8];
}
impl StoreKeyView for StoreKey {
    fn family(&self) -> ColumnFamily {
        self.family
    }
    fn bytes(&self) -> &[u8] {
        &self.key
    }
}
struct BorrowedStoreKey<'a> {
    family: ColumnFamily,
    key: &'a [u8],
}
impl StoreKeyView for BorrowedStoreKey<'_> {
    fn family(&self) -> ColumnFamily {
        self.family
    }
    fn bytes(&self) -> &[u8] {
        self.key
    }
}
impl Hash for dyn StoreKeyView + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.family().hash(state);
        self.bytes().hash(state);
    }
}
impl PartialEq for dyn StoreKeyView + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.family() == other.family() && self.bytes() == other.bytes()
    }
}
impl Eq for dyn StoreKeyView + '_ {}
impl<'a> Borrow<dyn StoreKeyView + 'a> for StoreKey {
    fn borrow(&self) -> &(dyn StoreKeyView + 'a) {
        self
    }
}

pub(crate) fn get_batch_operation<'a>(
    operations: &'a BatchOperations,
    family: ColumnFamily,
    key: &[u8],
) -> Option<&'a BatchOperation> {
    let borrowed = BorrowedStoreKey { family, key };
    operations.get(&borrowed as &dyn StoreKeyView)
}

pub(crate) type BatchOperations = HashMap<StoreKey, BatchOperation>;
pub(crate) type CheckpointEntry = (StoreKey, Option<BatchOperation>);
#[derive(Clone, Debug, Default)]
pub(crate) struct BatchCheckpoint {
    pub(crate) journal: Vec<CheckpointEntry>,
    pub(crate) retained_charge: u64,
}

// One key, journal slot and allocator/vector growth allowance, including
// the initial four-slot Vec reservation. The old value's
// own charge remains retained separately. This is deterministic across hosts.
pub(crate) const CHECKPOINT_ENTRY_FRAMING_BYTES: u64 = 384;
pub(crate) fn checkpoint_entry_charge(key: &[u8], previous: Option<&BatchOperation>) -> u64 {
    if previous.is_some_and(|operation| operation.checkpointed) {
        return 0;
    }
    let retained_value = previous.map_or(0, |operation| {
        // Ordinary writes have no external meter but still provide accurate
        // journal accounting if the batch is subsequently metered.
        operation.charge.max(
            operation
                .value
                .as_ref()
                .map_or(0, |value| value.retained_capacity() as u64),
        )
    });
    retained_value
        .saturating_add(key.len() as u64)
        .saturating_add(CHECKPOINT_ENTRY_FRAMING_BYTES)
}

pub(crate) fn replace_batch_operation(
    operations: &mut BatchOperations,
    checkpoint: &mut Option<BatchCheckpoint>,
    key: StoreKey,
    mut operation: BatchOperation,
) {
    let Some(checkpoint) = checkpoint else {
        operations.insert(key, operation);
        return;
    };
    let previous = operations.get(&key);
    let already_recorded = previous.is_some_and(|previous| previous.checkpointed);
    let additional = checkpoint_entry_charge(&key.key, previous);
    operation.checkpointed = true;
    let previous = operations.insert(key.clone(), operation);
    if !already_recorded {
        checkpoint.journal.push((key, previous));
        checkpoint.retained_charge = checkpoint.retained_charge.saturating_add(additional);
    }
}

pub(crate) fn begin_batch_checkpoint(
    checkpoint: &mut Option<BatchCheckpoint>,
) -> Result<(), StoreError> {
    if checkpoint.is_some() {
        return Err(StoreError::Backend(
            "write batch checkpoint is already active".to_owned(),
        ));
    }
    *checkpoint = Some(BatchCheckpoint::default());
    Ok(())
}

pub(crate) fn commit_batch_checkpoint(
    operations: &mut BatchOperations,
    checkpoint: &mut Option<BatchCheckpoint>,
) -> Result<(), StoreError> {
    let Some(checkpoint) = checkpoint.take() else {
        return Err(StoreError::Backend(
            "write batch checkpoint is not active".to_owned(),
        ));
    };
    for (key, _) in checkpoint.journal {
        if let Some(operation) = operations.get_mut(&key) {
            operation.checkpointed = false;
        }
    }
    Ok(())
}

pub(crate) fn rollback_batch_checkpoint(
    operations: &mut BatchOperations,
    checkpoint: &mut Option<BatchCheckpoint>,
) -> Result<(), StoreError> {
    let Some(checkpoint) = checkpoint.take() else {
        return Err(StoreError::Backend(
            "write batch checkpoint is not active".to_owned(),
        ));
    };
    for (key, previous) in checkpoint.journal.into_iter().rev() {
        match previous {
            Some(previous) => {
                operations.insert(key, previous);
            }
            None => {
                operations.remove(&key);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn compact_keys_preserve_byte_hashing_and_order_across_inline_boundary() {
        let keys = [
            vec![],
            vec![0],
            vec![0; 32],
            vec![0; 36],
            vec![0; 37],
            vec![1],
            vec![255; 80],
        ];
        let mut hashed = HashMap::new();
        let mut ordered = BTreeMap::new();
        for (index, key) in keys.iter().enumerate() {
            let compact = CompactKey::new(key);
            assert_eq!(compact.heap_bytes() == 0, key.len() <= 36);
            hashed.insert(compact.clone(), index);
            ordered.insert(compact, index);
        }
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(hashed.get(key.as_slice()), Some(&index));
        }
        let mut expected = keys.to_vec();
        expected.sort();
        assert_eq!(
            ordered.keys().map(|key| key.to_vec()).collect::<Vec<_>>(),
            expected
        );
        println!("staging layout bytes: compact_key={} operation={} hash_entry={} checkpoint_entry={} shared_handle={}", size_of::<CompactKey>(), size_of::<BatchOperation>(), size_of::<(StoreKey, BatchOperation)>(), size_of::<CheckpointEntry>(), size_of::<SharedBytes>());
    }

    #[test]
    fn borrowed_backend_lookup_matches_short_long_and_column_family_keys() {
        let mut operations = BatchOperations::new();
        for length in [0, 4, 32, 36, 37, 96] {
            let key = vec![7; length];
            operations.insert(
                StoreKey::new(ColumnFamily::Meta, &key),
                BatchOperation::new(None, 100 + length as u64),
            );
            operations.insert(
                StoreKey::new(ColumnFamily::Utxo, &key),
                BatchOperation::new(None, 200 + length as u64),
            );
        }
        for length in [0, 4, 32, 36, 37, 96] {
            let key = vec![7; length];
            assert_eq!(
                get_batch_operation(&operations, ColumnFamily::Meta, &key)
                    .unwrap()
                    .charge,
                100 + length as u64
            );
            assert_eq!(
                get_batch_operation(&operations, ColumnFamily::Utxo, &key)
                    .unwrap()
                    .charge,
                200 + length as u64
            );
            assert!(get_batch_operation(&operations, ColumnFamily::Headers, &key).is_none());
        }
    }

    #[test]
    fn shared_bytes_recover_original_allocation_after_other_readers_drop() {
        let bytes = vec![7; 8_192];
        let pointer = bytes.as_ptr();
        let shared = SharedBytes::from(bytes);
        let reader = shared.clone();
        assert_eq!(shared.as_ptr(), pointer);
        assert_eq!(reader.as_ptr(), pointer);
        drop(reader);
        let recovered = shared.into_vec();
        assert_eq!(recovered.as_ptr(), pointer);
    }
}
