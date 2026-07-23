use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::Mutex,
};

use hns_primitives::{blake2b_256, Reader, Writer};
use hns_store::{
    decode_name_page, ColumnFamily, NamePageAddress, NamePageAppender, NamePageBuilder,
    NamePageError, NamePagePush, NamePageRecord, ReadSnapshot, ScanEntry, SegmentManifest,
    StoreError, NAME_PAGE_BYTES,
};
use hns_urkel::{TreeRoot, UrkelError, UrkelNodeRecord};
use serde::{Deserialize, Serialize};

const DEFAULT_PAGE_CACHE_PAGES: usize = 512;
const NAME_PAGE_STATE_VERSION: u32 = 1;
const NAME_PAGE_STATE_BODY_BYTES: usize = 4 + 8 + 4 + 8 + 32 + 1 + 8 + 1 + 4;
const NAME_PAGE_STATE_BYTES: usize = NAME_PAGE_STATE_BODY_BYTES + 32;
pub const NAME_PAGE_STATE_KEY: &[u8] = b"name-page-state/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamePageRootLocator {
    pub generation: u64,
    pub address: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamePageState {
    pub manifest: SegmentManifest,
    pub root: TreeRoot,
    pub root_address: Option<NamePageAddress>,
    pub committed_height: Option<u32>,
}

impl NamePageState {
    pub fn encode(&self) -> Result<Vec<u8>, PageTreeError> {
        self.validate()?;
        let mut writer = Writer::with_capacity(NAME_PAGE_STATE_BYTES);
        writer.write_u32(NAME_PAGE_STATE_VERSION);
        writer.write_u64(self.manifest.generation);
        writer.write_u32(self.manifest.active_segment);
        writer.write_u64(self.manifest.durable_bytes);
        writer.write_bytes(self.root.as_bytes());
        match self.root_address {
            Some(address) => {
                writer.write_u8(1);
                writer.write_u64(address.raw());
            }
            None => {
                writer.write_u8(0);
                writer.write_u64(0);
            }
        }
        match self.committed_height {
            Some(height) => {
                writer.write_u8(1);
                writer.write_u32(height);
            }
            None => {
                writer.write_u8(0);
                writer.write_u32(0);
            }
        }
        let mut raw = writer.finish();
        if raw.len() != NAME_PAGE_STATE_BODY_BYTES {
            return Err(PageTreeError::StateCodec(
                "name-page state body has an unexpected length".to_owned(),
            ));
        }
        raw.extend_from_slice(&blake2b_256(&raw));
        Ok(raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, PageTreeError> {
        if raw.len() != NAME_PAGE_STATE_BYTES {
            return Err(PageTreeError::StateCodec(format!(
                "name-page state contains {} bytes; expected {NAME_PAGE_STATE_BYTES}",
                raw.len()
            )));
        }
        let (body, checksum) = raw.split_at(NAME_PAGE_STATE_BODY_BYTES);
        if checksum != blake2b_256(body) {
            return Err(PageTreeError::StateCodec(
                "name-page state checksum mismatch".to_owned(),
            ));
        }
        let mut reader = Reader::new(body, NAME_PAGE_STATE_BODY_BYTES)
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let version = reader
            .read_u32()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        if version != NAME_PAGE_STATE_VERSION {
            return Err(PageTreeError::StateCodec(format!(
                "unsupported name-page state version {version}"
            )));
        }
        let generation = reader
            .read_u64()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let active_segment = reader
            .read_u32()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let durable_bytes = reader
            .read_u64()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let root = TreeRoot::new(
            reader
                .read_hash()
                .map_err(|error| PageTreeError::StateCodec(error.to_string()))?,
        );
        let root_address = match reader
            .read_u8()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?
        {
            0 => {
                let reserved = reader
                    .read_u64()
                    .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
                if reserved != 0 {
                    return Err(PageTreeError::RootLocatorInvariant);
                }
                None
            }
            1 => {
                Some(NamePageAddress::from_raw(reader.read_u64().map_err(
                    |error| PageTreeError::StateCodec(error.to_string()),
                )?))
            }
            value => {
                return Err(PageTreeError::StateCodec(format!(
                    "invalid name-page root-address flag {value}"
                )))
            }
        };
        let committed_height = match reader
            .read_u8()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?
        {
            0 => {
                let reserved = reader
                    .read_u32()
                    .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
                if reserved != 0 {
                    return Err(PageTreeError::StateCodec(
                        "name-page state absent height has nonzero payload".to_owned(),
                    ));
                }
                None
            }
            1 => Some(
                reader
                    .read_u32()
                    .map_err(|error| PageTreeError::StateCodec(error.to_string()))?,
            ),
            value => {
                return Err(PageTreeError::StateCodec(format!(
                    "invalid name-page committed-height flag {value}"
                )))
            }
        };
        reader
            .ensure_finished()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let state = Self {
            manifest: SegmentManifest {
                generation,
                active_segment,
                durable_bytes,
            },
            root,
            root_address,
            committed_height,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn root_locator(&self) -> Option<NamePageRootLocator> {
        self.root_address
            .map(|address| NamePageRootLocator::new(self.manifest.generation, address))
    }

    fn validate(&self) -> Result<(), PageTreeError> {
        if !self
            .manifest
            .durable_bytes
            .is_multiple_of(NAME_PAGE_BYTES as u64)
            || (self.root == TreeRoot::ZERO) != self.root_address.is_none()
        {
            return Err(PageTreeError::RootLocatorInvariant);
        }
        if let Some(address) = self.root_address {
            let page_end = u64::from(address.page())
                .checked_add(1)
                .and_then(|page| page.checked_mul(NAME_PAGE_BYTES as u64))
                .ok_or(PageTreeError::OffsetOverflow)?;
            if address.segment() != self.manifest.active_segment
                || page_end > self.manifest.durable_bytes
            {
                return Err(PageTreeError::RootLocatorInvariant);
            }
        }
        Ok(())
    }
}

impl NamePageRootLocator {
    pub const fn new(generation: u64, address: NamePageAddress) -> Self {
        Self {
            generation,
            address: address.raw(),
        }
    }

    pub const fn page_address(self) -> NamePageAddress {
        NamePageAddress::from_raw(self.address)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedNamePages {
    generation: u64,
    segment: u32,
    first_page: u32,
    pages: Vec<Vec<NamePageRecord>>,
    addresses: BTreeMap<TreeRoot, NamePageAddress>,
}

impl PackedNamePages {
    pub fn root_locator(&self, root: TreeRoot) -> Option<NamePageRootLocator> {
        self.addresses
            .get(&root)
            .copied()
            .map(|address| NamePageRootLocator::new(self.generation, address))
    }

    pub fn address(&self, root: TreeRoot) -> Option<NamePageAddress> {
        self.addresses.get(&root).copied()
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn record_count(&self) -> usize {
        self.pages.iter().map(Vec::len).sum()
    }

    pub fn append(
        &self,
        appender: &mut NamePageAppender,
    ) -> Result<SegmentManifest, PageTreeError> {
        if appender.generation() != self.generation
            || appender.segment() != self.segment
            || appender.next_page() != self.first_page
        {
            return Err(PageTreeError::AppenderPosition);
        }
        for records in &self.pages {
            let actual = appender.append(records)?;
            for (record, address) in records.iter().zip(actual) {
                let expected = self.addresses.get(&TreeRoot::new(record.key)).ok_or(
                    PageTreeError::MissingPackedAddress(TreeRoot::new(record.key)),
                )?;
                if *expected != address {
                    return Err(PageTreeError::AppenderPosition);
                }
            }
        }
        appender.sync_data().map_err(PageTreeError::from)
    }
}

#[derive(Debug)]
struct CachedNamePage {
    records: Vec<NamePageRecord>,
}

#[derive(Debug)]
struct PageCache {
    capacity: usize,
    pages: HashMap<u32, CachedNamePage>,
    order: VecDeque<u32>,
}

impl PageCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            pages: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn touch(&mut self, page: u32) {
        if let Some(position) = self.order.iter().position(|candidate| *candidate == page) {
            self.order.remove(position);
        }
        self.order.push_back(page);
    }

    fn insert(&mut self, page: u32, value: CachedNamePage) {
        if !self.pages.contains_key(&page) && self.pages.len() == self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.pages.remove(&evicted);
            }
        }
        self.pages.insert(page, value);
        self.touch(page);
    }
}

/// Traversal-local hash-to-address discovery. Only a retained root locator is
/// needed durably: loading an internal page record discovers both child
/// hashes and their physical addresses for the next traversal step.
#[derive(Debug)]
pub struct NamePageTreeReader {
    file: Mutex<File>,
    generation: u64,
    segment: u32,
    addresses: Mutex<HashMap<TreeRoot, NamePageAddress>>,
    cache: Mutex<PageCache>,
}

pub struct NamePageSnapshot<'a, S: ReadSnapshot> {
    base: &'a S,
    pages: &'a NamePageTreeReader,
}

impl<'a, S: ReadSnapshot> NamePageSnapshot<'a, S> {
    pub const fn new(base: &'a S, pages: &'a NamePageTreeReader) -> Self {
        Self { base, pages }
    }
}

impl<S: ReadSnapshot> ReadSnapshot for NamePageSnapshot<'_, S> {
    fn get(&self, family: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        if family != ColumnFamily::NameTreeNodes {
            return self.base.get(family, key);
        }
        let root: [u8; 32] = key.try_into().map_err(|_| {
            StoreError::Schema(format!(
                "name-page node key contains {} bytes; expected 32",
                key.len()
            ))
        })?;
        self.pages
            .load(TreeRoot::new(root))
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        if family != ColumnFamily::NameTreeNodes {
            return self.base.get_many(family, keys);
        }
        keys.iter()
            .map(|key| self.get(ColumnFamily::NameTreeNodes, key))
            .collect()
    }

    fn scan_prefix(
        &self,
        family: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Vec<ScanEntry>, StoreError> {
        if family == ColumnFamily::NameTreeNodes {
            return Err(StoreError::FeatureDisabled("name-page hash-index scan"));
        }
        self.base.scan_prefix(family, prefix)
    }
}

impl NamePageTreeReader {
    pub fn open(
        path: impl AsRef<Path>,
        root: TreeRoot,
        locator: NamePageRootLocator,
    ) -> Result<Self, PageTreeError> {
        Self::open_with_cache(path, root, locator, DEFAULT_PAGE_CACHE_PAGES)
    }

    pub fn open_with_cache(
        path: impl AsRef<Path>,
        root: TreeRoot,
        locator: NamePageRootLocator,
        cache_pages: usize,
    ) -> Result<Self, PageTreeError> {
        let address = locator.page_address();
        let file = File::open(path).map_err(PageTreeError::io)?;
        let mut addresses = HashMap::new();
        if root != TreeRoot::ZERO {
            addresses.insert(root, address);
        }
        Ok(Self {
            file: Mutex::new(file),
            generation: locator.generation,
            segment: address.segment(),
            addresses: Mutex::new(addresses),
            cache: Mutex::new(PageCache::new(cache_pages)),
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn segment(&self) -> u32 {
        self.segment
    }

    pub fn load(&self, root: TreeRoot) -> Result<Option<Vec<u8>>, PageTreeError> {
        if root == TreeRoot::ZERO {
            return Ok(None);
        }
        let Some(address) = self
            .addresses
            .lock()
            .map_err(|_| PageTreeError::Poisoned)?
            .get(&root)
            .copied()
        else {
            return Ok(None);
        };
        if address.segment() != self.segment {
            return Err(PageTreeError::WrongSegment {
                expected: self.segment,
                actual: address.segment(),
            });
        }
        self.ensure_page(address.page())?;
        let mut cache = self.cache.lock().map_err(|_| PageTreeError::Poisoned)?;
        cache.touch(address.page());
        let page = cache
            .pages
            .get(&address.page())
            .ok_or(PageTreeError::MissingCachedPage(address.page()))?;
        let record = page
            .records
            .get(usize::from(address.slot()))
            .ok_or(PageTreeError::SlotOutOfRange(address))?;
        if record.key != *root.as_bytes() {
            return Err(PageTreeError::RecordKeyMismatch {
                expected: root,
                actual: TreeRoot::new(record.key),
            });
        }
        let decoded = UrkelNodeRecord::decode(&record.canonical)?;
        let actual = decoded.root();
        if actual != root {
            return Err(PageTreeError::RecordKeyMismatch {
                expected: root,
                actual,
            });
        }
        match decoded {
            UrkelNodeRecord::Leaf { .. } if !record.children.is_empty() => {
                return Err(PageTreeError::ChildLocatorMismatch(root));
            }
            UrkelNodeRecord::Internal { left, right, .. } if record.children.len() == 2 => {
                let mut addresses = self.addresses.lock().map_err(|_| PageTreeError::Poisoned)?;
                insert_discovered_address(&mut addresses, left, record.children[0])?;
                insert_discovered_address(&mut addresses, right, record.children[1])?;
            }
            UrkelNodeRecord::Internal { .. } => {
                return Err(PageTreeError::ChildLocatorMismatch(root));
            }
            UrkelNodeRecord::Leaf { .. } => {}
        }
        Ok(Some(record.canonical.clone()))
    }

    pub fn known_addresses(&self) -> Result<HashMap<TreeRoot, NamePageAddress>, PageTreeError> {
        self.addresses
            .lock()
            .map_err(|_| PageTreeError::Poisoned)
            .map(|addresses| addresses.clone())
    }

    fn ensure_page(&self, page_number: u32) -> Result<(), PageTreeError> {
        {
            let cache = self.cache.lock().map_err(|_| PageTreeError::Poisoned)?;
            if cache.pages.contains_key(&page_number) {
                return Ok(());
            }
        }
        let offset = u64::from(page_number)
            .checked_mul(NAME_PAGE_BYTES as u64)
            .ok_or(PageTreeError::OffsetOverflow)?;
        let mut encoded = vec![0u8; NAME_PAGE_BYTES];
        {
            let mut file = self.file.lock().map_err(|_| PageTreeError::Poisoned)?;
            file.seek(SeekFrom::Start(offset))
                .map_err(PageTreeError::io)?;
            file.read_exact(&mut encoded).map_err(PageTreeError::io)?;
        }
        let decoded = decode_name_page(&encoded)?;
        let mut records = Vec::with_capacity(usize::from(decoded.record_count()));
        for slot in 0..decoded.record_count() {
            let record = decoded.record(slot)?;
            records.push(NamePageRecord {
                key: record.key,
                children: record.children.into_iter().flatten().collect(),
                canonical: record.canonical.to_vec(),
            });
        }
        self.cache
            .lock()
            .map_err(|_| PageTreeError::Poisoned)?
            .insert(page_number, CachedNamePage { records });
        Ok(())
    }
}

fn insert_discovered_address(
    addresses: &mut HashMap<TreeRoot, NamePageAddress>,
    root: TreeRoot,
    address: NamePageAddress,
) -> Result<(), PageTreeError> {
    match addresses.insert(root, address) {
        Some(existing) if existing != address => Err(PageTreeError::AddressConflict(root)),
        Some(_) | None => Ok(()),
    }
}

pub fn pack_name_page_records(
    generation: u64,
    segment: u32,
    first_page: u32,
    records: &BTreeMap<TreeRoot, Vec<u8>>,
    known_addresses: &HashMap<TreeRoot, NamePageAddress>,
) -> Result<PackedNamePages, PageTreeError> {
    let mut order = Vec::with_capacity(records.len());
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for root in records.keys().copied() {
        visit_new_record(
            root,
            records,
            known_addresses,
            &mut visiting,
            &mut visited,
            &mut order,
        )?;
    }

    let mut addresses = BTreeMap::new();
    let mut pages = Vec::<Vec<NamePageRecord>>::new();
    let mut page_number = first_page;
    let mut builder = NamePageBuilder::new(segment, page_number)?;
    for root in order {
        let canonical = records
            .get(&root)
            .ok_or(PageTreeError::MissingPackedRecord(root))?;
        let decoded = UrkelNodeRecord::decode(canonical)?;
        if decoded.root() != root {
            return Err(PageTreeError::RecordKeyMismatch {
                expected: root,
                actual: decoded.root(),
            });
        }
        let children = match decoded {
            UrkelNodeRecord::Leaf { .. } => Vec::new(),
            UrkelNodeRecord::Internal { left, right, .. } => vec![
                resolve_child_address(left, &addresses, known_addresses)?,
                resolve_child_address(right, &addresses, known_addresses)?,
            ],
        };
        let mut record = NamePageRecord {
            key: *root.as_bytes(),
            children,
            canonical: canonical.clone(),
        };
        loop {
            match builder.push(record)? {
                NamePagePush::Added(address) => {
                    addresses.insert(root, address);
                    break;
                }
                NamePagePush::Full(returned) => {
                    pages.push(builder.records().to_vec());
                    page_number = page_number
                        .checked_add(1)
                        .ok_or(PageTreeError::OffsetOverflow)?;
                    builder = NamePageBuilder::new(segment, page_number)?;
                    record = returned;
                }
            }
        }
    }
    if !builder.is_empty() {
        pages.push(builder.records().to_vec());
    }
    Ok(PackedNamePages {
        generation,
        segment,
        first_page,
        pages,
        addresses,
    })
}

fn visit_new_record(
    root: TreeRoot,
    records: &BTreeMap<TreeRoot, Vec<u8>>,
    known_addresses: &HashMap<TreeRoot, NamePageAddress>,
    visiting: &mut HashSet<TreeRoot>,
    visited: &mut HashSet<TreeRoot>,
    order: &mut Vec<TreeRoot>,
) -> Result<(), PageTreeError> {
    if visited.contains(&root) {
        return Ok(());
    }
    if !visiting.insert(root) {
        return Err(PageTreeError::RecordCycle(root));
    }
    let raw = records
        .get(&root)
        .ok_or(PageTreeError::MissingPackedRecord(root))?;
    let record = UrkelNodeRecord::decode(raw)?;
    if record.root() != root {
        return Err(PageTreeError::RecordKeyMismatch {
            expected: root,
            actual: record.root(),
        });
    }
    if let UrkelNodeRecord::Internal { left, right, .. } = record {
        for child in [left, right] {
            if records.contains_key(&child) {
                visit_new_record(child, records, known_addresses, visiting, visited, order)?;
            } else if !known_addresses.contains_key(&child) {
                return Err(PageTreeError::MissingChildAddress(child));
            }
        }
    }
    visiting.remove(&root);
    visited.insert(root);
    order.push(root);
    Ok(())
}

fn resolve_child_address(
    root: TreeRoot,
    new_addresses: &BTreeMap<TreeRoot, NamePageAddress>,
    known_addresses: &HashMap<TreeRoot, NamePageAddress>,
) -> Result<NamePageAddress, PageTreeError> {
    new_addresses
        .get(&root)
        .copied()
        .or_else(|| known_addresses.get(&root).copied())
        .ok_or(PageTreeError::MissingChildAddress(root))
}

#[derive(Debug, thiserror::Error)]
pub enum PageTreeError {
    #[error("name-page codec failed: {0}")]
    Page(#[from] NamePageError),
    #[error("Urkel record failed: {0}")]
    Urkel(#[from] UrkelError),
    #[error("name-page I/O failed: {0}")]
    Io(String),
    #[error("name-page state codec failed: {0}")]
    StateCodec(String),
    #[error("name-page state root and locator violate their invariant")]
    RootLocatorInvariant,
    #[error("name-page mutex was poisoned")]
    Poisoned,
    #[error("name-page offset overflowed")]
    OffsetOverflow,
    #[error("name-page address belongs to segment {actual}, expected {expected}")]
    WrongSegment { expected: u32, actual: u32 },
    #[error("name-page cache did not retain page {0}")]
    MissingCachedPage(u32),
    #[error("name-page address {0:?} has an out-of-range slot")]
    SlotOutOfRange(NamePageAddress),
    #[error("name-page record key is {actual:?}, expected {expected:?}")]
    RecordKeyMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
    #[error("name-page record {0:?} has inconsistent child locators")]
    ChildLocatorMismatch(TreeRoot),
    #[error("name-page traversal discovered conflicting addresses for {0:?}")]
    AddressConflict(TreeRoot),
    #[error("name-page pack is missing record {0:?}")]
    MissingPackedRecord(TreeRoot),
    #[error("name-page pack is missing child address {0:?}")]
    MissingChildAddress(TreeRoot),
    #[error("name-page pack contains a cycle at {0:?}")]
    RecordCycle(TreeRoot),
    #[error("name-page pack is missing the predicted address for {0:?}")]
    MissingPackedAddress(TreeRoot),
    #[error("name-page appender position does not match the prepared pack")]
    AppenderPosition,
}

impl PageTreeError {
    fn io(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::NameHash;
    use hns_urkel::{
        prove_hsd_from_records, update_record_tree, validate_record_tree, MemoryUrkel,
    };

    #[test]
    fn append_only_pages_mutate_from_root_and_child_locators_without_hash_index() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-name-pages-{}-{nonce}.pages",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let alpha = NameHash::new([0x11; 32]);
        let beta = NameHash::new([0x88; 32]);
        let gamma = NameHash::new([0xf1; 32]);
        let initial =
            MemoryUrkel::from_entries([(alpha, b"alpha-v1".to_vec()), (beta, b"beta-v1".to_vec())])
                .expect("initial tree");
        let initial_root = initial.root();
        let initial_records = initial.node_records().expect("initial records");
        let mut appender = NamePageAppender::create_new(&path, 1, 0).expect("create pages");
        let initial_pack = pack_name_page_records(1, 0, 0, &initial_records, &HashMap::new())
            .expect("pack initial records");
        assert_eq!(initial_pack.record_count(), initial_records.len());
        initial_pack.append(&mut appender).expect("append initial");
        let initial_locator = initial_pack
            .root_locator(initial_root)
            .expect("initial root locator");

        let reader = NamePageTreeReader::open_with_cache(&path, initial_root, initial_locator, 2)
            .expect("open initial reader");
        let update = update_record_tree(
            initial_root,
            [
                (alpha, Some(b"alpha-v2".to_vec())),
                (gamma, Some(b"gamma-v1".to_vec())),
            ],
            |root| {
                reader
                    .load(root)
                    .map_err(|error| UrkelError::Storage(error.to_string()))
            },
        )
        .expect("path-local update");
        let updated_root = update.root();
        assert_ne!(updated_root, initial_root);
        let known = reader.known_addresses().expect("known addresses");
        let update_pack =
            pack_name_page_records(1, 0, appender.next_page(), update.records(), &known)
                .expect("pack update");
        assert!(update_pack.record_count() < initial_records.len() + update.records().len());
        update_pack.append(&mut appender).expect("append update");
        let updated_locator = update_pack
            .root_locator(updated_root)
            .expect("updated root locator");

        let updated_reader =
            NamePageTreeReader::open_with_cache(&path, updated_root, updated_locator, 2)
                .expect("open updated reader");
        let loaded = validate_record_tree(updated_root, |root| {
            updated_reader
                .load(root)
                .map_err(|error| UrkelError::Storage(error.to_string()))
        })
        .expect("validate updated pages");
        assert!(loaded >= 3);
        let proof = prove_hsd_from_records(updated_root, gamma, |root| {
            updated_reader
                .load(root)
                .map_err(|error| UrkelError::Storage(error.to_string()))
        })
        .expect("page-backed proof");
        assert_eq!(
            proof.verify_value(updated_root).expect("verify proof"),
            Some(b"gamma-v1".to_vec())
        );

        drop(updated_reader);
        drop(reader);
        drop(appender);
        std::fs::remove_file(path).expect("remove page fixture");
    }
}
