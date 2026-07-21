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

#[derive(Clone, Debug)]
struct OrphanEntry {
    block: Block,
    size: usize,
}

#[derive(Clone, Debug)]
pub struct BoundedOrphanPool {
    limits: OrphanLimits,
    entries: HashMap<BlockHash, OrphanEntry>,
    children: BTreeMap<BlockHash, Vec<BlockHash>>,
    insertion_order: VecDeque<BlockHash>,
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
            insertion_order: VecDeque::new(),
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
        self.entries.insert(hash, OrphanEntry { block, size });
        self.children.entry(parent).or_default().push(hash);
        self.insertion_order.push_back(hash);
        self.bytes = self.bytes.saturating_add(size);
        Ok(OrphanInsertOutcome {
            inserted: true,
            evicted,
        })
    }

    pub fn remove(&mut self, hash: &BlockHash) -> Option<Block> {
        let entry = self.entries.remove(hash)?;
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

    pub fn snapshot(&self) -> OrphanSnapshot {
        OrphanSnapshot {
            blocks: self.entries.len(),
            bytes: self.bytes,
            evicted: self.evicted,
        }
    }

    fn evict_oldest(&mut self) -> Option<Block> {
        while let Some(hash) = self.insertion_order.pop_front() {
            if let Some(block) = self.remove(&hash) {
                self.evicted = self.evicted.saturating_add(1);
                return Some(block);
            }
        }
        None
    }

    fn remove_without_child_index(&mut self, hash: &BlockHash) -> Option<Block> {
        let entry = self.entries.remove(hash)?;
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
    }
}
