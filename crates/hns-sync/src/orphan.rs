use std::collections::{BTreeMap, HashMap, VecDeque};

use hns_primitives::{Block, BlockHash};
use serde::{Deserialize, Serialize};

use crate::SyncError;

#[derive(Clone, Debug)]
pub struct OrphanLimits {
    pub maximum_blocks: usize,
    pub maximum_bytes: usize,
}

impl Default for OrphanLimits {
    fn default() -> Self {
        Self {
            maximum_blocks: 1_024,
            maximum_bytes: 64 * 1024 * 1024,
        }
    }
}

impl OrphanLimits {
    pub fn validate(&self) -> Result<(), SyncError> {
        if self.maximum_blocks == 0 || self.maximum_bytes == 0 {
            return Err(SyncError::Configuration(
                "orphan limits must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrphanSnapshot {
    pub blocks: usize,
    pub bytes: usize,
    pub evicted: u64,
}

#[derive(Clone, Debug, Default)]
pub struct OrphanInsertOutcome {
    pub inserted: bool,
    pub evicted: Vec<Block>,
}

/// Result of one bounded release from a parent's insertion-ordered children.
#[derive(Clone, Debug, Default)]
pub struct OrphanChildrenOutcome {
    pub children: Vec<Block>,
    pub children_remain: bool,
}

#[derive(Clone, Debug)]
struct OrphanEntry {
    block: Block,
    size: usize,
    insertion_id: u64,
}

#[derive(Clone, Debug)]
pub struct BoundedOrphanPool {
    limits: OrphanLimits,
    entries: HashMap<BlockHash, OrphanEntry>,
    children: BTreeMap<BlockHash, VecDeque<BlockHash>>,
    insertion_order: BTreeMap<u64, BlockHash>,
    next_insertion_id: u64,
    bytes: usize,
    evicted: u64,
}

impl BoundedOrphanPool {
    pub fn new(limits: OrphanLimits) -> Result<Self, SyncError> {
        limits.validate()?;
        Ok(Self {
            limits,
            entries: HashMap::new(),
            children: BTreeMap::new(),
            insertion_order: BTreeMap::new(),
            next_insertion_id: 0,
            bytes: 0,
            evicted: 0,
        })
    }

    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn insert(&mut self, block: Block) -> Result<bool, SyncError> {
        Ok(self.insert_with_evictions(block)?.inserted)
    }

    pub fn insert_with_evictions(
        &mut self,
        block: Block,
    ) -> Result<OrphanInsertOutcome, SyncError> {
        let hash = block.hash();
        if self.entries.contains_key(&hash) {
            return Ok(OrphanInsertOutcome::default());
        }
        let size = block.encode().len();
        if size > self.limits.maximum_bytes {
            return Err(SyncError::LimitExceeded {
                context: "single orphan block bytes",
                limit: self.limits.maximum_bytes,
                actual: size,
            });
        }
        let insertion_id = self.next_insertion_id;
        let next_insertion_id = insertion_id.checked_add(1).ok_or_else(|| {
            SyncError::Dependency("orphan insertion sequence exhausted".to_owned())
        })?;
        let mut evicted = Vec::new();
        while self.entries.len() >= self.limits.maximum_blocks
            || self.bytes.saturating_add(size) > self.limits.maximum_bytes
        {
            let Some(block) = self.evict_oldest() else {
                break;
            };
            evicted.push(block);
        }
        let parent = block.header.prev_block;
        self.entries.insert(
            hash,
            OrphanEntry {
                block,
                size,
                insertion_id,
            },
        );
        self.children.entry(parent).or_default().push_back(hash);
        self.insertion_order.insert(insertion_id, hash);
        self.next_insertion_id = next_insertion_id;
        self.bytes = self.bytes.saturating_add(size);
        Ok(OrphanInsertOutcome {
            inserted: true,
            evicted,
        })
    }

    pub fn remove(&mut self, hash: &BlockHash) -> Option<Block> {
        let entry = self.entries.remove(hash)?;
        self.insertion_order.remove(&entry.insertion_id);
        self.bytes = self.bytes.saturating_sub(entry.size);
        let parent = entry.block.header.prev_block;
        if let Some(children) = self.children.get_mut(&parent) {
            children.retain(|child| child != hash);
            if children.is_empty() {
                self.children.remove(&parent);
            }
        }
        Some(entry.block)
    }

    pub fn take_children(&mut self, parent: BlockHash) -> Vec<Block> {
        let hashes = self.children.remove(&parent).unwrap_or_default();
        hashes
            .into_iter()
            .filter_map(|hash| self.remove_without_child_index(&hash))
            .collect()
    }

    /// Removes no more than `maximum_children` children while retaining the
    /// exact indexed remainder. A zero bound is rejected without mutation.
    pub fn take_children_bounded(
        &mut self,
        parent: BlockHash,
        maximum_children: usize,
    ) -> Result<OrphanChildrenOutcome, SyncError> {
        if maximum_children == 0 {
            return Err(SyncError::Configuration(
                "orphan child removal limit must be non-zero".to_owned(),
            ));
        }

        let Some(children) = self.children.get(&parent) else {
            return Ok(OrphanChildrenOutcome::default());
        };
        let take = children.len().min(maximum_children);
        let hashes = children.iter().take(take).copied().collect::<Vec<_>>();
        if let Some(hash) = hashes.iter().find(|hash| !self.entries.contains_key(hash)) {
            return Err(SyncError::Dependency(format!(
                "orphan child index references missing block {hash:?}"
            )));
        }

        let children_remain = {
            let children = self.children.get_mut(&parent).ok_or_else(|| {
                SyncError::Dependency(
                    "orphan child index disappeared during bounded removal".to_owned(),
                )
            })?;
            children.drain(..take);
            !children.is_empty()
        };
        if !children_remain {
            self.children.remove(&parent);
        }

        let mut blocks = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let block = self.remove_without_child_index(&hash).ok_or_else(|| {
                SyncError::Dependency(format!(
                    "orphan block {hash:?} disappeared during bounded child removal"
                ))
            })?;
            blocks.push(block);
        }
        Ok(OrphanChildrenOutcome {
            children: blocks,
            children_remain,
        })
    }

    pub fn snapshot(&self) -> OrphanSnapshot {
        OrphanSnapshot {
            blocks: self.entries.len(),
            bytes: self.bytes,
            evicted: self.evicted,
        }
    }

    fn evict_oldest(&mut self) -> Option<Block> {
        while let Some((_, hash)) = self.insertion_order.pop_first() {
            if let Some(block) = self.remove(&hash) {
                self.evicted = self.evicted.saturating_add(1);
                return Some(block);
            }
        }
        None
    }

    fn remove_without_child_index(&mut self, hash: &BlockHash) -> Option<Block> {
        let entry = self.entries.remove(hash)?;
        self.insertion_order.remove(&entry.insertion_id);
        self.bytes = self.bytes.saturating_sub(entry.size);
        Some(entry.block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::Header;

    fn block(byte: u8, parent: BlockHash) -> Block {
        let header = Header {
            nonce: u32::from(byte),
            prev_block: parent,
            ..Header::default()
        };
        Block {
            header,
            transactions: Vec::new(),
        }
    }

    #[test]
    fn orphan_pool_is_bounded_and_children_are_released() {
        let mut pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("pool");
        let parent = BlockHash::new([1; 32]);
        let first = block(1, parent);
        let first_hash = first.hash();
        let second = block(2, parent);
        let third = block(3, parent);
        pool.insert(first).expect("first");
        pool.insert(second).expect("second");
        pool.insert(third).expect("third");
        assert!(!pool.contains(&first_hash));
        assert_eq!(pool.snapshot().blocks, 2);
        assert_eq!(pool.take_children(parent).len(), 2);
        assert_eq!(pool.snapshot().blocks, 0);
        assert!(pool.insertion_order.is_empty());
    }

    #[test]
    fn bounded_child_release_preserves_exact_remainder() {
        let mut pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 4,
            maximum_bytes: 1_000_000,
        })
        .expect("pool");
        let parent = BlockHash::new([2; 32]);
        let first = block(1, parent);
        let second = block(2, parent);
        let third = block(3, parent);
        let expected_first = [first.hash(), second.hash()];
        let expected_last = third.hash();
        let expected_last_bytes = third.encode().len();
        pool.insert(first).expect("first");
        pool.insert(second).expect("second");
        pool.insert(third).expect("third");

        let first_batch = pool
            .take_children_bounded(parent, 2)
            .expect("bounded children");
        assert_eq!(
            first_batch
                .children
                .iter()
                .map(Block::hash)
                .collect::<Vec<_>>(),
            expected_first
        );
        assert!(first_batch.children_remain);
        assert_eq!(pool.snapshot().blocks, 1);
        assert_eq!(pool.snapshot().bytes, expected_last_bytes);
        assert_eq!(pool.insertion_order.len(), 1);
        assert!(pool.contains(&expected_last));
        assert_eq!(
            pool.children
                .get(&parent)
                .expect("remaining child index")
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [expected_last]
        );

        let last_batch = pool
            .take_children_bounded(parent, 2)
            .expect("remaining child");
        assert_eq!(last_batch.children.len(), 1);
        assert_eq!(last_batch.children[0].hash(), expected_last);
        assert!(!last_batch.children_remain);
        assert_eq!(pool.snapshot().blocks, 0);
        assert!(pool.insertion_order.is_empty());
        assert!(!pool.children.contains_key(&parent));
    }

    #[test]
    fn zero_child_release_limit_fails_without_mutation() {
        let mut pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("pool");
        let parent = BlockHash::new([3; 32]);
        let child = block(1, parent);
        let child_hash = child.hash();
        pool.insert(child).expect("child");
        let before = pool.snapshot();

        let error = pool
            .take_children_bounded(parent, 0)
            .expect_err("zero limit must fail");
        assert!(matches!(error, SyncError::Configuration(_)));
        assert_eq!(pool.snapshot(), before);
        assert!(pool.contains(&child_hash));
        assert_eq!(pool.children.get(&parent).map(VecDeque::len), Some(1));
        assert_eq!(pool.insertion_order.len(), 1);
    }

    #[test]
    fn bounded_children_can_be_repeatedly_drained_in_order() {
        let mut pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 7,
            maximum_bytes: 1_000_000,
        })
        .expect("pool");
        let parent = BlockHash::new([4; 32]);
        let mut expected = Vec::new();
        for byte in 1..=7 {
            let child = block(byte, parent);
            expected.push(child.hash());
            pool.insert(child).expect("child");
        }

        let mut released = Vec::new();
        for expected_to_remain in [true, true, true, false] {
            let outcome = pool
                .take_children_bounded(parent, 2)
                .expect("bounded children");
            released.extend(outcome.children.iter().map(Block::hash));
            assert_eq!(outcome.children_remain, expected_to_remain);
        }
        assert_eq!(released, expected);
        assert_eq!(pool.snapshot().blocks, 0);
        assert!(pool.insertion_order.is_empty());

        let empty = pool.take_children_bounded(parent, 2).expect("empty parent");
        assert!(empty.children.is_empty());
        assert!(!empty.children_remain);
    }

    #[test]
    fn removal_and_eviction_preserve_bounded_child_order() {
        let mut pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 3,
            maximum_bytes: 1_000_000,
        })
        .expect("pool");
        let parent = BlockHash::new([5; 32]);
        let first = block(1, parent);
        let first_hash = first.hash();
        let second = block(2, parent);
        let second_hash = second.hash();
        let third = block(3, parent);
        let third_hash = third.hash();
        let fourth = block(4, parent);
        let fourth_hash = fourth.hash();
        let fifth = block(5, parent);
        let fifth_hash = fifth.hash();
        let fifth_bytes = fifth.encode().len();
        pool.insert(first).expect("first");
        pool.insert(second).expect("second");
        pool.insert(third).expect("third");

        assert_eq!(
            pool.remove(&second_hash).map(|block| block.hash()),
            Some(second_hash)
        );
        pool.insert(fourth).expect("fourth");
        let outcome = pool.insert_with_evictions(fifth).expect("fifth");
        assert_eq!(
            outcome.evicted.iter().map(Block::hash).collect::<Vec<_>>(),
            [first_hash]
        );
        assert!(!pool.contains(&first_hash));
        assert!(!pool.contains(&second_hash));

        let batch = pool
            .take_children_bounded(parent, 2)
            .expect("bounded children");
        assert_eq!(
            batch.children.iter().map(Block::hash).collect::<Vec<_>>(),
            [third_hash, fourth_hash]
        );
        assert!(batch.children_remain);
        assert_eq!(
            pool.insertion_order.values().copied().collect::<Vec<_>>(),
            [fifth_hash]
        );
        assert_eq!(pool.snapshot().blocks, 1);
        assert_eq!(pool.snapshot().bytes, fifth_bytes);
        assert_eq!(pool.snapshot().evicted, 1);

        assert_eq!(
            pool.remove(&fifth_hash).map(|block| block.hash()),
            Some(fifth_hash)
        );
        assert!(!pool.children.contains_key(&parent));
        assert!(pool.insertion_order.is_empty());
        assert_eq!(pool.snapshot().blocks, 0);
        assert_eq!(pool.snapshot().bytes, 0);
    }

    #[test]
    fn restored_child_receives_one_new_insertion_identity() {
        let mut pool = BoundedOrphanPool::new(OrphanLimits {
            maximum_blocks: 2,
            maximum_bytes: 1_000_000,
        })
        .expect("pool");
        let parent = BlockHash::new([6; 32]);
        let released = block(1, parent);
        let released_hash = released.hash();
        let retained = block(2, parent);
        let retained_hash = retained.hash();
        pool.insert(released.clone()).expect("released child");
        pool.insert(retained).expect("retained child");

        let batch = pool
            .take_children_bounded(parent, 1)
            .expect("bounded child");
        assert_eq!(batch.children.len(), 1);
        assert_eq!(batch.children[0].hash(), released_hash);
        assert!(batch.children_remain);
        assert_eq!(
            pool.insertion_order.values().copied().collect::<Vec<_>>(),
            [retained_hash]
        );

        pool.insert(released).expect("restored child");
        assert_eq!(
            pool.insertion_order.values().copied().collect::<Vec<_>>(),
            [retained_hash, released_hash]
        );

        let newcomer = block(3, parent);
        let newcomer_hash = newcomer.hash();
        let outcome = pool
            .insert_with_evictions(newcomer)
            .expect("evict true oldest child");
        assert_eq!(
            outcome.evicted.iter().map(Block::hash).collect::<Vec<_>>(),
            [retained_hash]
        );
        assert!(pool.contains(&released_hash));
        assert!(pool.contains(&newcomer_hash));
        assert_eq!(
            pool.insertion_order.values().copied().collect::<Vec<_>>(),
            [released_hash, newcomer_hash]
        );
    }
}
