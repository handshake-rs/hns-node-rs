use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use hns_primitives::{blake2b_256, NameHash, Reader, Writer};
use hns_store::{
    decode_name_page, ColumnFamily, NamePageAddress, NamePageAppender, NamePageBuilder,
    NamePageError, NamePagePush, NamePageRecord, NameTreePathRecord, ReadSnapshot, ScanEntry,
    SegmentManifest, StoreError, NAME_PAGE_BYTES,
};
#[cfg(not(unix))]
use hns_store::{read_name_page_directory, read_name_page_record};
#[cfg(unix)]
use hns_store::{
    read_name_page_directory_at, read_name_page_subpages_at, NamePageDirectory, NamePageSubpage,
    PositionedNamePageReader,
};
use hns_urkel::{TreeRoot, UrkelError, UrkelNodeRecord, URKEL_BITS};
use serde::{Deserialize, Serialize};

const DEFAULT_PAGE_CACHE_PAGES: usize = 512;
#[cfg(unix)]
const NAME_PAGE_READ_AHEAD_PAGES: usize = 64;
#[cfg(unix)]
const NAME_PAGE_READ_AHEAD_CACHE_PAGES: usize = 128;
#[cfg(unix)]
const NAME_PAGE_READ_AHEAD_WORKERS: usize = 4;
const NAME_PAGE_STATE_VERSION: u32 = 2;
const LEGACY_NAME_PAGE_STATE_VERSION: u32 = 1;
const LEGACY_NAME_PAGE_STATE_BODY_BYTES: usize = 4 + 8 + 4 + 8 + 32 + 1 + 8 + 1 + 4;
const LEGACY_NAME_PAGE_STATE_BYTES: usize = LEGACY_NAME_PAGE_STATE_BODY_BYTES + 32;
const NAME_PAGE_STATE_BODY_BYTES: usize =
    LEGACY_NAME_PAGE_STATE_BODY_BYTES + 1 + std::mem::size_of::<u32>();
const NAME_PAGE_STATE_BYTES: usize = NAME_PAGE_STATE_BODY_BYTES + 32;
pub const NAME_PAGE_STATE_KEY: &[u8] = b"name-page-state/v1";
pub const NAME_PAGE_SEGMENT_BLOCKS: u32 = 360;
const NAME_PAGE_ROOT_RECORD_VERSION: u32 = 1;
const NAME_PAGE_ROOT_RECORD_BODY_BYTES: usize = 4 + 32 + 8 + 8 + 4;
const NAME_PAGE_ROOT_RECORD_BYTES: usize = NAME_PAGE_ROOT_RECORD_BODY_BYTES + 32;
pub const NAME_PAGE_ROOT_PREFIX: &[u8] = b"name-page-root/v1/";
const NAME_PAGE_BOOTSTRAP_PARALLEL_SUBTREES: usize = 4_096;
const NAME_PAGE_BOOTSTRAP_READ_BATCH: usize = 1_024;

#[cfg(unix)]
struct ReadAheadNamePage {
    directory: NamePageDirectory,
    subpages: Vec<NamePageSubpage>,
}

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
    pub last_sealed_height: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamePageRootRecord {
    pub root: TreeRoot,
    pub locator: NamePageRootLocator,
    pub height: u32,
}

impl NamePageRootRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(NAME_PAGE_ROOT_RECORD_BYTES);
        writer.write_u32(NAME_PAGE_ROOT_RECORD_VERSION);
        writer.write_bytes(self.root.as_bytes());
        writer.write_u64(self.locator.generation);
        writer.write_u64(self.locator.address);
        writer.write_u32(self.height);
        let mut raw = writer.finish();
        debug_assert_eq!(raw.len(), NAME_PAGE_ROOT_RECORD_BODY_BYTES);
        raw.extend_from_slice(&blake2b_256(&raw));
        raw
    }

    pub fn decode(raw: &[u8]) -> Result<Self, PageTreeError> {
        if raw.len() != NAME_PAGE_ROOT_RECORD_BYTES {
            return Err(PageTreeError::StateCodec(format!(
                "name-page root record contains {} bytes; expected {NAME_PAGE_ROOT_RECORD_BYTES}",
                raw.len()
            )));
        }
        let (body, checksum) = raw.split_at(NAME_PAGE_ROOT_RECORD_BODY_BYTES);
        if checksum != blake2b_256(body) {
            return Err(PageTreeError::StateCodec(
                "name-page root record checksum mismatch".to_owned(),
            ));
        }
        let mut reader = Reader::new(body, NAME_PAGE_ROOT_RECORD_BODY_BYTES)
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let version = reader
            .read_u32()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        if version != NAME_PAGE_ROOT_RECORD_VERSION {
            return Err(PageTreeError::StateCodec(format!(
                "unsupported name-page root record version {version}"
            )));
        }
        let record = Self {
            root: TreeRoot::new(
                reader
                    .read_hash()
                    .map_err(|error| PageTreeError::StateCodec(error.to_string()))?,
            ),
            locator: NamePageRootLocator {
                generation: reader
                    .read_u64()
                    .map_err(|error| PageTreeError::StateCodec(error.to_string()))?,
                address: reader
                    .read_u64()
                    .map_err(|error| PageTreeError::StateCodec(error.to_string()))?,
            },
            height: reader
                .read_u32()
                .map_err(|error| PageTreeError::StateCodec(error.to_string()))?,
        };
        reader
            .ensure_finished()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        if record.root == TreeRoot::ZERO {
            return Err(PageTreeError::RootLocatorInvariant);
        }
        Ok(record)
    }
}

pub fn name_page_root_key(root: TreeRoot) -> Vec<u8> {
    let mut key = Vec::with_capacity(NAME_PAGE_ROOT_PREFIX.len() + 32);
    key.extend_from_slice(NAME_PAGE_ROOT_PREFIX);
    key.extend_from_slice(root.as_bytes());
    key
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
        match self.last_sealed_height {
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
        if raw.len() != NAME_PAGE_STATE_BYTES && raw.len() != LEGACY_NAME_PAGE_STATE_BYTES {
            return Err(PageTreeError::StateCodec(format!(
                "name-page state contains {} bytes; expected {NAME_PAGE_STATE_BYTES} or {LEGACY_NAME_PAGE_STATE_BYTES}",
                raw.len()
            )));
        }
        let body_bytes = raw.len() - 32;
        let (body, checksum) = raw.split_at(body_bytes);
        if checksum != blake2b_256(body) {
            return Err(PageTreeError::StateCodec(
                "name-page state checksum mismatch".to_owned(),
            ));
        }
        let mut reader = Reader::new(body, body_bytes)
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        let version = reader
            .read_u32()
            .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
        if version != NAME_PAGE_STATE_VERSION && version != LEGACY_NAME_PAGE_STATE_VERSION {
            return Err(PageTreeError::StateCodec(format!(
                "unsupported name-page state version {version}"
            )));
        }
        if (version == NAME_PAGE_STATE_VERSION) != (body_bytes == NAME_PAGE_STATE_BODY_BYTES) {
            return Err(PageTreeError::StateCodec(
                "name-page state version does not match its encoded length".to_owned(),
            ));
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
        let last_sealed_height = if version == LEGACY_NAME_PAGE_STATE_VERSION {
            None
        } else {
            match reader
                .read_u8()
                .map_err(|error| PageTreeError::StateCodec(error.to_string()))?
            {
                0 => {
                    let reserved = reader
                        .read_u32()
                        .map_err(|error| PageTreeError::StateCodec(error.to_string()))?;
                    if reserved != 0 {
                        return Err(PageTreeError::StateCodec(
                            "name-page state absent seal height has nonzero payload".to_owned(),
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
                        "invalid name-page seal-height flag {value}"
                    )))
                }
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
            last_sealed_height,
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
            if address.segment() > self.manifest.active_segment {
                return Err(PageTreeError::RootLocatorInvariant);
            }
            if address.segment() == self.manifest.active_segment
                && page_end > self.manifest.durable_bytes
            {
                return Err(PageTreeError::RootLocatorInvariant);
            }
        }
        if self
            .last_sealed_height
            .is_some_and(|height| height == 0 || !height.is_multiple_of(NAME_PAGE_SEGMENT_BLOCKS))
        {
            return Err(PageTreeError::RootLocatorInvariant);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamedNamePages {
    pub manifest: SegmentManifest,
    pub root_address: Option<NamePageAddress>,
    pub record_count: u64,
    pub page_count: u64,
    pub parallel_subtrees: usize,
}

#[derive(Debug)]
struct BootstrapFrontier {
    root: TreeRoot,
    depth: usize,
    raw: Option<Vec<u8>>,
}

#[derive(Debug)]
struct BootstrapSkeletonNode {
    root: TreeRoot,
    raw: Vec<u8>,
    left: TreeRoot,
    right: TreeRoot,
}

#[derive(Debug)]
struct BootstrapParent {
    root: TreeRoot,
    raw: Vec<u8>,
    child_depth: usize,
    right: TreeRoot,
    left_address: Option<NamePageAddress>,
}

#[derive(Debug)]
struct BootstrapTask {
    root: TreeRoot,
    pending_root: TreeRoot,
    pending_depth: usize,
    pending_raw: Option<Vec<u8>>,
    parents: Vec<BootstrapParent>,
    result: Option<NamePageAddress>,
}

impl BootstrapTask {
    fn new(frontier: BootstrapFrontier) -> Self {
        Self {
            root: frontier.root,
            pending_root: frontier.root,
            pending_depth: frontier.depth,
            pending_raw: frontier.raw,
            parents: Vec::new(),
            result: None,
        }
    }

    fn is_complete(&self) -> bool {
        self.result.is_some()
    }

    fn pending_request(&self) -> Option<TreeRoot> {
        (!self.is_complete() && self.pending_raw.is_none()).then_some(self.pending_root)
    }

    fn take_preloaded(&mut self) -> Option<Vec<u8>> {
        self.pending_raw.take()
    }

    fn accept(
        &mut self,
        raw: Vec<u8>,
        seen: &mut HashSet<TreeRoot>,
        emitter: &mut StreamingPageEmitter<'_>,
    ) -> Result<(), PageTreeError> {
        let root = self.pending_root;
        let depth = self.pending_depth;
        let record = decode_bootstrap_record(root, &raw)?;
        match record {
            UrkelNodeRecord::Leaf { .. } => {
                let address = emitter.emit(root, raw, Vec::new())?;
                self.complete(address, seen, emitter)
            }
            UrkelNodeRecord::Internal {
                prefix,
                left,
                right,
            } => {
                let child_depth = bootstrap_child_depth(depth, prefix.bit_len())?;
                insert_bootstrap_root(seen, left)?;
                self.parents.push(BootstrapParent {
                    root,
                    raw,
                    child_depth,
                    right,
                    left_address: None,
                });
                self.pending_root = left;
                self.pending_depth = child_depth;
                Ok(())
            }
        }
    }

    fn complete(
        &mut self,
        mut address: NamePageAddress,
        seen: &mut HashSet<TreeRoot>,
        emitter: &mut StreamingPageEmitter<'_>,
    ) -> Result<(), PageTreeError> {
        loop {
            let Some(parent) = self.parents.last_mut() else {
                self.result = Some(address);
                return Ok(());
            };
            if parent.left_address.is_none() {
                parent.left_address = Some(address);
                insert_bootstrap_root(seen, parent.right)?;
                self.pending_root = parent.right;
                self.pending_depth = parent.child_depth;
                return Ok(());
            }

            let parent = self.parents.pop().expect("parent exists");
            let left_address = parent.left_address.expect("left child completed");
            address = emitter.emit(parent.root, parent.raw, vec![left_address, address])?;
        }
    }
}

struct StreamingPageEmitter<'a> {
    appender: &'a mut NamePageAppender,
    builder: Option<NamePageBuilder>,
    pending_addresses: Vec<NamePageAddress>,
    first_page: u32,
    record_count: u64,
}

impl<'a> StreamingPageEmitter<'a> {
    fn new(appender: &'a mut NamePageAppender) -> Result<Self, PageTreeError> {
        let first_page = appender.next_page();
        Ok(Self {
            builder: Some(NamePageBuilder::new(appender.segment(), first_page)?),
            appender,
            pending_addresses: Vec::new(),
            first_page,
            record_count: 0,
        })
    }

    fn emit(
        &mut self,
        root: TreeRoot,
        canonical: Vec<u8>,
        children: Vec<NamePageAddress>,
    ) -> Result<NamePageAddress, PageTreeError> {
        let mut record = NamePageRecord {
            key: *root.as_bytes(),
            children,
            canonical,
        };
        loop {
            match self
                .builder
                .as_mut()
                .expect("streaming page builder exists")
                .push(record)?
            {
                NamePagePush::Added(address) => {
                    self.pending_addresses.push(address);
                    self.record_count = self
                        .record_count
                        .checked_add(1)
                        .ok_or(PageTreeError::OffsetOverflow)?;
                    return Ok(address);
                }
                NamePagePush::Full(returned) => {
                    self.flush_page()?;
                    record = returned;
                }
            }
        }
    }

    fn flush_page(&mut self) -> Result<(), PageTreeError> {
        let builder = self.builder.take().expect("streaming page builder exists");
        if builder.is_empty() {
            return Err(PageTreeError::Page(NamePageError::EmptyPage));
        }
        let actual = self.appender.append(builder.records())?;
        if actual != self.pending_addresses {
            return Err(PageTreeError::AppenderPosition);
        }
        self.pending_addresses.clear();
        self.builder = Some(NamePageBuilder::new(
            self.appender.segment(),
            self.appender.next_page(),
        )?);
        Ok(())
    }

    fn finish(mut self) -> Result<(SegmentManifest, u64, u64), PageTreeError> {
        if self
            .builder
            .as_ref()
            .is_some_and(|builder| !builder.is_empty())
        {
            self.flush_page()?;
        }
        let manifest = self.appender.sync_data()?;
        let page_count = u64::from(self.appender.next_page() - self.first_page);
        Ok((manifest, self.record_count, page_count))
    }
}

pub fn stream_name_page_tree<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
    appender: &mut NamePageAppender,
) -> Result<StreamedNamePages, PageTreeError> {
    stream_name_page_tree_with_parallelism(
        snapshot,
        root,
        appender,
        NAME_PAGE_BOOTSTRAP_PARALLEL_SUBTREES,
    )
}

fn stream_name_page_tree_with_parallelism<T: ReadSnapshot>(
    snapshot: &T,
    root: TreeRoot,
    appender: &mut NamePageAppender,
    target_subtrees: usize,
) -> Result<StreamedNamePages, PageTreeError> {
    let target_subtrees = target_subtrees.max(1);
    let mut emitter = StreamingPageEmitter::new(appender)?;
    if root == TreeRoot::ZERO {
        let (manifest, record_count, page_count) = emitter.finish()?;
        return Ok(StreamedNamePages {
            manifest,
            root_address: None,
            record_count,
            page_count,
            parallel_subtrees: 0,
        });
    }

    let mut seen = HashSet::new();
    insert_bootstrap_root(&mut seen, root)?;
    let mut frontier = vec![BootstrapFrontier {
        root,
        depth: 0,
        raw: None,
    }];
    let mut skeleton = Vec::new();

    while frontier.len() < target_subtrees {
        let requests = frontier
            .iter()
            .filter(|node| node.raw.is_none())
            .map(|node| node.root)
            .collect::<Vec<_>>();
        if !requests.is_empty() {
            let loaded = load_bootstrap_records(snapshot, &requests)?;
            let mut loaded = loaded.into_iter();
            for node in &mut frontier {
                if node.raw.is_none() {
                    node.raw = Some(loaded.next().expect("one result per request"));
                }
            }
            debug_assert!(loaded.next().is_none());
        }

        let mut next = Vec::with_capacity(frontier.len().saturating_mul(2));
        let mut expanded = false;
        for node in frontier {
            let raw = node.raw.expect("frontier record loaded");
            match decode_bootstrap_record(node.root, &raw)? {
                UrkelNodeRecord::Leaf { .. } => next.push(BootstrapFrontier {
                    root: node.root,
                    depth: node.depth,
                    raw: Some(raw),
                }),
                UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                } => {
                    expanded = true;
                    let child_depth = bootstrap_child_depth(node.depth, prefix.bit_len())?;
                    insert_bootstrap_root(&mut seen, left)?;
                    insert_bootstrap_root(&mut seen, right)?;
                    skeleton.push(BootstrapSkeletonNode {
                        root: node.root,
                        raw,
                        left,
                        right,
                    });
                    next.push(BootstrapFrontier {
                        root: left,
                        depth: child_depth,
                        raw: None,
                    });
                    next.push(BootstrapFrontier {
                        root: right,
                        depth: child_depth,
                        raw: None,
                    });
                }
            }
        }
        frontier = next;
        if !expanded {
            break;
        }
    }

    let parallel_subtrees = frontier.len();
    let mut tasks = frontier
        .into_iter()
        .map(BootstrapTask::new)
        .collect::<Vec<_>>();
    loop {
        let mut progressed = false;
        for task in &mut tasks {
            if let Some(raw) = task.take_preloaded() {
                task.accept(raw, &mut seen, &mut emitter)?;
                progressed = true;
            }
        }

        let requests = tasks
            .iter()
            .enumerate()
            .filter_map(|(index, task)| task.pending_request().map(|root| (index, root)))
            .collect::<Vec<_>>();
        if requests.is_empty() {
            if tasks.iter().all(BootstrapTask::is_complete) {
                break;
            }
            if !progressed {
                return Err(PageTreeError::StateCodec(
                    "name-page bootstrap made no traversal progress".to_owned(),
                ));
            }
            continue;
        }
        for chunk in requests.chunks(NAME_PAGE_BOOTSTRAP_READ_BATCH) {
            let roots = chunk.iter().map(|(_, root)| *root).collect::<Vec<_>>();
            let loaded = load_bootstrap_records(snapshot, &roots)?;
            for ((task_index, _), raw) in chunk.iter().zip(loaded) {
                tasks[*task_index].accept(raw, &mut seen, &mut emitter)?;
            }
        }
    }

    let mut addresses = HashMap::with_capacity(tasks.len().saturating_mul(2));
    for task in tasks {
        let address = task.result.ok_or_else(|| {
            PageTreeError::StateCodec("name-page bootstrap task has no result".to_owned())
        })?;
        if addresses.insert(task.root, address).is_some() {
            return Err(PageTreeError::DuplicateRecord(task.root));
        }
    }
    for node in skeleton.into_iter().rev() {
        let left = addresses
            .remove(&node.left)
            .ok_or(PageTreeError::MissingChildAddress(node.left))?;
        let right = addresses
            .remove(&node.right)
            .ok_or(PageTreeError::MissingChildAddress(node.right))?;
        let address = emitter.emit(node.root, node.raw, vec![left, right])?;
        if addresses.insert(node.root, address).is_some() {
            return Err(PageTreeError::DuplicateRecord(node.root));
        }
    }
    let root_address = addresses
        .remove(&root)
        .ok_or(PageTreeError::MissingPackedAddress(root))?;
    if !addresses.is_empty() {
        return Err(PageTreeError::StateCodec(
            "name-page bootstrap retained unreachable addresses".to_owned(),
        ));
    }

    let (manifest, record_count, page_count) = emitter.finish()?;
    Ok(StreamedNamePages {
        manifest,
        root_address: Some(root_address),
        record_count,
        page_count,
        parallel_subtrees,
    })
}

fn load_bootstrap_records<T: ReadSnapshot>(
    snapshot: &T,
    roots: &[TreeRoot],
) -> Result<Vec<Vec<u8>>, PageTreeError> {
    let keys = roots
        .iter()
        .map(|root| root.as_bytes().as_slice())
        .collect::<Vec<_>>();
    let loaded = snapshot.get_many(ColumnFamily::NameTreeNodes, &keys)?;
    if loaded.len() != roots.len() {
        return Err(PageTreeError::StateCodec(format!(
            "name-page bootstrap requested {} records but received {}",
            roots.len(),
            loaded.len()
        )));
    }
    roots
        .iter()
        .zip(loaded)
        .map(|(root, raw)| raw.ok_or(PageTreeError::MissingPackedRecord(*root)))
        .collect()
}

fn decode_bootstrap_record(
    expected: TreeRoot,
    raw: &[u8],
) -> Result<UrkelNodeRecord, PageTreeError> {
    let record = UrkelNodeRecord::decode(raw)?;
    let actual = record.root();
    if actual != expected {
        return Err(PageTreeError::RecordKeyMismatch { expected, actual });
    }
    Ok(record)
}

fn bootstrap_child_depth(depth: usize, prefix_bits: usize) -> Result<usize, PageTreeError> {
    let child_depth = depth
        .checked_add(prefix_bits)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            PageTreeError::Urkel(UrkelError::InvalidNode(
                "Urkel record depth overflowed".to_owned(),
            ))
        })?;
    if child_depth > URKEL_BITS {
        return Err(PageTreeError::Urkel(UrkelError::InvalidNode(
            "Urkel record path exceeds the key".to_owned(),
        )));
    }
    Ok(child_depth)
}

fn insert_bootstrap_root(
    seen: &mut HashSet<TreeRoot>,
    root: TreeRoot,
) -> Result<(), PageTreeError> {
    if root == TreeRoot::ZERO {
        return Err(PageTreeError::Urkel(UrkelError::InvalidNode(
            "Urkel record tree contains an empty child".to_owned(),
        )));
    }
    if !seen.insert(root) {
        return Err(PageTreeError::DuplicateRecord(root));
    }
    Ok(())
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

struct LoadedNamePageRecord {
    canonical: Vec<u8>,
    discovered: Vec<(TreeRoot, NamePageAddress)>,
}

#[derive(Debug)]
struct NamePagePathWork {
    root: TreeRoot,
    traversals: Vec<(NameHash, usize)>,
}

#[derive(Debug)]
struct PageCache {
    capacity: usize,
    pages: HashMap<(u32, u32), CachedNamePage>,
    order: VecDeque<(u32, u32)>,
    loads: u64,
}

impl PageCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            pages: HashMap::new(),
            order: VecDeque::new(),
            loads: 0,
        }
    }

    fn touch(&mut self, page: (u32, u32)) {
        if let Some(position) = self.order.iter().position(|candidate| *candidate == page) {
            self.order.remove(position);
        }
        self.order.push_back(page);
    }

    fn insert(&mut self, page: (u32, u32), value: CachedNamePage) {
        if !self.pages.contains_key(&page) && self.pages.len() == self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.pages.remove(&evicted);
            }
        }
        self.pages.insert(page, value);
        self.touch(page);
        self.loads = self.loads.saturating_add(1);
    }
}

/// Traversal-local hash-to-address discovery. Only a retained root locator is
/// needed durably: loading an internal page record discovers both child
/// hashes and their physical addresses for the next traversal step.
#[derive(Debug)]
pub struct NamePageTreeReader {
    files: Mutex<HashMap<u32, File>>,
    generation: u64,
    root_segment: u32,
    addresses: Mutex<HashMap<TreeRoot, NamePageAddress>>,
    cache: Mutex<PageCache>,
    path_page_reads: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedPageRecord {
    root: TreeRoot,
    maximum_path_bits: u16,
}

/// Result of one physical-order audit of the immutable authenticated page
/// store. Roots remain sorted only for the short legacy-overlay audit and are
/// released with this value before steady-state operation.
#[derive(Debug)]
pub struct NamePageValidation {
    pub segments: usize,
    pub pages: u64,
    pub records: u64,
    pub bytes: u64,
    roots: Vec<ValidatedPageRecord>,
}

impl NamePageValidation {
    pub fn maximum_path_bits(&self, root: TreeRoot) -> Option<u16> {
        self.roots
            .binary_search_by_key(&root, |record| record.root)
            .ok()
            .map(|index| self.roots[index].maximum_path_bits)
    }
}

pub struct NamePageSnapshot<'a, S: ReadSnapshot> {
    base: &'a S,
    pages: &'a NamePageTreeReader,
    fallback_legacy_nodes: bool,
}

impl<'a, S: ReadSnapshot> NamePageSnapshot<'a, S> {
    pub const fn new(base: &'a S, pages: &'a NamePageTreeReader) -> Self {
        Self {
            base,
            pages,
            fallback_legacy_nodes: false,
        }
    }

    pub const fn with_legacy_fallback(base: &'a S, pages: &'a NamePageTreeReader) -> Self {
        Self {
            base,
            pages,
            fallback_legacy_nodes: true,
        }
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
        match self
            .pages
            .load(TreeRoot::new(root))
            .map_err(|error| StoreError::Backend(error.to_string()))?
        {
            Some(raw) => Ok(Some(raw)),
            None if self.fallback_legacy_nodes => self.base.get(family, key),
            None => Ok(None),
        }
    }

    fn get_many(
        &self,
        family: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        if family != ColumnFamily::NameTreeNodes {
            return self.base.get_many(family, keys);
        }
        let roots = keys
            .iter()
            .map(|key| {
                let root: [u8; 32] = (*key).try_into().map_err(|_| {
                    StoreError::Schema(format!(
                        "name-page node key contains {} bytes; expected 32",
                        key.len()
                    ))
                })?;
                Ok(TreeRoot::new(root))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let mut loaded = self
            .pages
            .load_many(&roots)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        if !self.fallback_legacy_nodes {
            return Ok(loaded);
        }

        let missing = loaded
            .iter()
            .enumerate()
            .filter_map(|(index, value)| value.is_none().then_some((index, keys[index])))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(loaded);
        }
        let missing_keys = missing.iter().map(|(_, key)| *key).collect::<Vec<_>>();
        let legacy = self.base.get_many(family, &missing_keys)?;
        if legacy.len() != missing.len() {
            return Err(StoreError::Backend(format!(
                "legacy name-tree multi-get returned {} records for {} keys",
                legacy.len(),
                missing.len()
            )));
        }
        for ((index, _), value) in missing.into_iter().zip(legacy) {
            loaded[index] = value;
        }
        Ok(loaded)
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

    fn prefetch_name_tree_paths(
        &self,
        root: [u8; 32],
        keys: &[[u8; 32]],
    ) -> Result<Option<Vec<NameTreePathRecord>>, StoreError> {
        let keys = keys.iter().copied().map(NameHash::new).collect::<Vec<_>>();
        self.pages
            .prefetch_paths(TreeRoot::new(root), &keys)
            .map(|records| {
                records.map(|records| {
                    records
                        .into_iter()
                        .map(|(root, canonical)| NameTreePathRecord {
                            root: *root.as_bytes(),
                            canonical,
                        })
                        .collect()
                })
            })
            .map_err(|error| StoreError::Backend(error.to_string()))
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
        let mut paths = BTreeMap::new();
        paths.insert(address.segment(), path.as_ref().to_path_buf());
        Self::open_segments_with_cache(&paths, root, locator, cache_pages)
    }

    pub fn open_segments(
        paths: &BTreeMap<u32, PathBuf>,
        root: TreeRoot,
        locator: NamePageRootLocator,
    ) -> Result<Self, PageTreeError> {
        Self::open_segments_with_cache(paths, root, locator, DEFAULT_PAGE_CACHE_PAGES)
    }

    pub fn open_segments_with_cache(
        paths: &BTreeMap<u32, PathBuf>,
        root: TreeRoot,
        locator: NamePageRootLocator,
        cache_pages: usize,
    ) -> Result<Self, PageTreeError> {
        let address = locator.page_address();
        let mut files = HashMap::with_capacity(paths.len());
        for (segment, path) in paths {
            files.insert(
                *segment,
                File::open(path)
                    .map_err(|error| PageTreeError::Io(format!("{}: {error}", path.display())))?,
            );
        }
        if !files.contains_key(&address.segment()) {
            return Err(PageTreeError::MissingSegment(address.segment()));
        }
        let mut addresses = HashMap::new();
        if root != TreeRoot::ZERO {
            addresses.insert(root, address);
        }
        Ok(Self {
            files: Mutex::new(files),
            generation: locator.generation,
            root_segment: address.segment(),
            addresses: Mutex::new(addresses),
            cache: Mutex::new(PageCache::new(cache_pages)),
            path_page_reads: AtomicU64::new(0),
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn segment(&self) -> u32 {
        self.root_segment
    }

    pub fn insert_root(
        &self,
        root: TreeRoot,
        locator: NamePageRootLocator,
    ) -> Result<(), PageTreeError> {
        let address = locator.page_address();
        if locator.generation != self.generation {
            return Err(PageTreeError::WrongGeneration {
                expected: self.generation,
                actual: locator.generation,
            });
        }
        if !self
            .files
            .lock()
            .map_err(|_| PageTreeError::Poisoned)?
            .contains_key(&address.segment())
        {
            return Err(PageTreeError::MissingSegment(address.segment()));
        }
        let mut addresses = self.addresses.lock().map_err(|_| PageTreeError::Poisoned)?;
        insert_discovered_address(&mut addresses, root, address)
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
        self.ensure_page(address)?;
        let loaded = {
            let cache_key = (address.segment(), address.page());
            let mut cache = self.cache.lock().map_err(|_| PageTreeError::Poisoned)?;
            cache.touch(cache_key);
            let page = cache
                .pages
                .get(&cache_key)
                .ok_or(PageTreeError::MissingCachedPage(address))?;
            read_cached_name_page_record(page, root, address)?
        };
        self.insert_discovered(loaded.discovered)?;
        Ok(Some(loaded.canonical))
    }

    pub fn load_many(&self, roots: &[TreeRoot]) -> Result<Vec<Option<Vec<u8>>>, PageTreeError> {
        let known = self.addresses.lock().map_err(|_| PageTreeError::Poisoned)?;
        let mut grouped = BTreeMap::<(u32, u32), Vec<(usize, TreeRoot, NamePageAddress)>>::new();
        for (index, root) in roots.iter().copied().enumerate() {
            if root == TreeRoot::ZERO {
                continue;
            }
            if let Some(address) = known.get(&root).copied() {
                grouped
                    .entry((address.segment(), address.page()))
                    .or_default()
                    .push((index, root, address));
            }
        }
        drop(known);

        let mut loaded = vec![None; roots.len()];
        for (cache_key, requests) in grouped {
            let page_address = requests
                .first()
                .map(|(_, _, address)| *address)
                .expect("page group is non-empty");
            self.ensure_page(page_address)?;
            let mut discovered = Vec::with_capacity(requests.len().saturating_mul(2));
            {
                let mut cache = self.cache.lock().map_err(|_| PageTreeError::Poisoned)?;
                cache.touch(cache_key);
                let page = cache
                    .pages
                    .get(&cache_key)
                    .ok_or(PageTreeError::MissingCachedPage(page_address))?;
                for (index, root, address) in requests {
                    let record = read_cached_name_page_record(page, root, address)?;
                    loaded[index] = Some(record.canonical);
                    discovered.extend(record.discovered);
                }
            }
            self.insert_discovered(discovered)?;
        }
        Ok(loaded)
    }

    /// Traverse an affected path union in descending physical page order.
    /// Child locators point backward, so every incoming traversal for a page
    /// is known before that page is decoded and no logical tree depth can
    /// force the same page to be reread.
    pub fn prefetch_paths(
        &self,
        root: TreeRoot,
        keys: &[NameHash],
    ) -> Result<Option<BTreeMap<TreeRoot, Vec<u8>>>, PageTreeError> {
        if root == TreeRoot::ZERO || keys.is_empty() {
            return Ok(Some(BTreeMap::new()));
        }
        let Some(root_address) = self
            .addresses
            .lock()
            .map_err(|_| PageTreeError::Poisoned)?
            .get(&root)
            .copied()
        else {
            return Ok(None);
        };

        let mut pending = BTreeMap::<(u32, u32), BTreeMap<u16, NamePagePathWork>>::new();
        insert_name_page_path_work(
            &mut pending,
            root,
            root_address,
            keys.iter().copied().map(|key| (key, 0usize)),
        )?;
        let mut records = BTreeMap::<TreeRoot, Vec<u8>>::new();
        #[cfg(unix)]
        let path_files = self
            .files
            .lock()
            .map_err(|_| PageTreeError::Poisoned)?
            .iter()
            .map(|(segment, file)| {
                file.try_clone()
                    .map(|file| (*segment, file))
                    .map_err(PageTreeError::io)
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        #[cfg(unix)]
        let mut page_read_ahead = BTreeMap::<(u32, u32), ReadAheadNamePage>::new();

        while let Some(page_key) = pending.last_key_value().map(|(page, _)| *page) {
            let page_address = NamePageAddress::new(page_key.0, page_key.1, 0)?;
            #[cfg(unix)]
            let prepared_page =
                read_ahead_name_page(&path_files, &pending, &mut page_read_ahead, page_key)?;
            #[cfg(not(unix))]
            let directory = {
                let mut files = self.files.lock().map_err(|_| PageTreeError::Poisoned)?;
                let file = files
                    .get_mut(&page_address.segment())
                    .ok_or(PageTreeError::MissingSegment(page_address.segment()))?;
                read_name_page_directory(file, page_address.page())?
            };
            let (_, mut page_work) = pending.pop_last().expect("pending page exists");
            self.path_page_reads.fetch_add(1, Ordering::Relaxed);
            #[cfg(not(unix))]
            let mut files = self.files.lock().map_err(|_| PageTreeError::Poisoned)?;
            #[cfg(not(unix))]
            let file = files
                .get_mut(&page_address.segment())
                .ok_or(PageTreeError::MissingSegment(page_address.segment()))?;
            #[cfg(unix)]
            let ReadAheadNamePage {
                directory,
                subpages,
            } = prepared_page;
            #[cfg(unix)]
            let mut page_reader = PositionedNamePageReader::with_prefetched(
                path_files
                    .get(&page_address.segment())
                    .ok_or(PageTreeError::MissingSegment(page_address.segment()))?,
                page_address.page(),
                &directory,
                subpages,
            )?;
            while let Some((slot, work)) = page_work.pop_last() {
                let address = NamePageAddress::new(page_key.0, page_key.1, slot)?;
                #[cfg(unix)]
                let record = page_reader.record(address.slot())?;
                #[cfg(not(unix))]
                let record =
                    read_name_page_record(file, page_address.page(), &directory, address.slot())?;
                let loaded = validate_loaded_name_page_record(record, work.root)?;
                if let Some(existing) = records.insert(work.root, loaded.canonical.clone()) {
                    if existing != loaded.canonical {
                        return Err(PageTreeError::StateCodec(
                            "page path prefetch found conflicting canonical records".to_owned(),
                        ));
                    }
                }
                self.insert_discovered(loaded.discovered.clone())?;

                let decoded = UrkelNodeRecord::decode(&loaded.canonical)?;
                let UrkelNodeRecord::Internal {
                    prefix,
                    left,
                    right,
                } = decoded
                else {
                    continue;
                };
                let [(discovered_left, left_address), (discovered_right, right_address)] =
                    loaded.discovered.as_slice()
                else {
                    return Err(PageTreeError::ChildLocatorMismatch(work.root));
                };
                if *discovered_left != left || *discovered_right != right {
                    return Err(PageTreeError::ChildLocatorMismatch(work.root));
                }
                for (key, depth) in work.traversals {
                    if !prefix.matches_key(key.as_bytes(), depth) {
                        continue;
                    }
                    let branch_depth = page_branch_depth(&prefix, depth)?;
                    let (child, child_address) = if key_bit_at(key.as_bytes(), branch_depth) == 0 {
                        (left, *left_address)
                    } else {
                        (right, *right_address)
                    };
                    if child_address >= address {
                        return Err(PageTreeError::ChildLocatorMismatch(work.root));
                    }
                    let traversal = std::iter::once((key, branch_depth + 1));
                    if (child_address.segment(), child_address.page()) == page_key {
                        insert_name_page_slot_work(
                            &mut page_work,
                            child,
                            child_address,
                            traversal,
                        )?;
                    } else {
                        insert_name_page_path_work(&mut pending, child, child_address, traversal)?;
                    }
                }
            }
        }

        Ok(Some(records))
    }

    pub fn known_addresses(&self) -> Result<HashMap<TreeRoot, NamePageAddress>, PageTreeError> {
        self.addresses
            .lock()
            .map_err(|_| PageTreeError::Poisoned)
            .map(|addresses| addresses.clone())
    }

    /// Validate every committed page exactly once in physical order. Page
    /// records are append-postordered, so child hash/address consistency,
    /// acyclicity, canonical encoding, and maximum path depth can all be
    /// proven while retaining only a compact address-indexed summary.
    pub fn validate_committed_pages(&self) -> Result<NamePageValidation, PageTreeError> {
        let mut files = self.files.lock().map_err(|_| PageTreeError::Poisoned)?;
        let mut segments = files.keys().copied().collect::<Vec<_>>();
        segments.sort_unstable();
        let mut indexed = BTreeMap::<u32, Vec<Vec<ValidatedPageRecord>>>::new();
        let mut page_count = 0u64;
        let mut record_count = 0u64;
        let mut byte_count = 0u64;
        let mut encoded = vec![0u8; NAME_PAGE_BYTES];

        for segment in segments.iter().copied() {
            let file = files
                .get_mut(&segment)
                .ok_or(PageTreeError::MissingSegment(segment))?;
            let bytes = file.metadata().map_err(PageTreeError::io)?.len();
            if !bytes.is_multiple_of(NAME_PAGE_BYTES as u64) {
                return Err(PageTreeError::UnalignedSegment { segment, bytes });
            }
            let pages = bytes / NAME_PAGE_BYTES as u64;
            let pages_u32 = u32::try_from(pages)
                .map_err(|_| PageTreeError::PageCountOverflow { segment, pages })?;
            NamePageAddress::new(segment, pages_u32.saturating_sub(1), 0)?;
            file.seek(SeekFrom::Start(0)).map_err(PageTreeError::io)?;
            let segment_capacity =
                usize::try_from(pages_u32).map_err(|_| PageTreeError::OffsetOverflow)?;
            let mut segment_pages = Vec::with_capacity(segment_capacity);

            for page_number in 0..pages_u32 {
                file.read_exact(&mut encoded).map_err(PageTreeError::io)?;
                let page = decode_name_page(&encoded)?;
                if page.record_count() == 0 {
                    return Err(PageTreeError::EmptyCommittedPage {
                        segment,
                        page: page_number,
                    });
                }
                let mut current = Vec::with_capacity(usize::from(page.record_count()));
                for slot in 0..page.record_count() {
                    let raw = page.record(slot)?;
                    let root = TreeRoot::new(raw.key);
                    let decoded = UrkelNodeRecord::decode(raw.canonical)?;
                    let actual = decoded.root();
                    if actual != root {
                        return Err(PageTreeError::RecordKeyMismatch {
                            expected: root,
                            actual,
                        });
                    }
                    if decoded.encode()? != raw.canonical {
                        return Err(PageTreeError::Urkel(UrkelError::InvalidNode(
                            "Urkel node record is not canonically encoded".to_owned(),
                        )));
                    }
                    let maximum_path_bits = match decoded {
                        UrkelNodeRecord::Leaf { .. } => {
                            if raw.children != [None, None] {
                                return Err(PageTreeError::ChildLocatorMismatch(root));
                            }
                            0
                        }
                        UrkelNodeRecord::Internal {
                            prefix,
                            left,
                            right,
                        } => {
                            let [Some(left_address), Some(right_address)] = raw.children else {
                                return Err(PageTreeError::ChildLocatorMismatch(root));
                            };
                            let left_record = earlier_page_record(
                                &indexed,
                                &segment_pages,
                                &current,
                                segment,
                                page_number,
                                left_address,
                            )
                            .ok_or(PageTreeError::MissingEarlierRecord(left_address))?;
                            let right_record = earlier_page_record(
                                &indexed,
                                &segment_pages,
                                &current,
                                segment,
                                page_number,
                                right_address,
                            )
                            .ok_or(PageTreeError::MissingEarlierRecord(right_address))?;
                            if left_record.root != left || right_record.root != right {
                                return Err(PageTreeError::ChildLocatorMismatch(root));
                            }
                            let branch_bits = prefix.bit_len().checked_add(1).ok_or_else(|| {
                                PageTreeError::Urkel(UrkelError::InvalidNode(
                                    "Urkel record depth overflowed".to_owned(),
                                ))
                            })?;
                            let maximum_child = usize::from(
                                left_record
                                    .maximum_path_bits
                                    .max(right_record.maximum_path_bits),
                            );
                            let maximum =
                                branch_bits.checked_add(maximum_child).ok_or_else(|| {
                                    PageTreeError::Urkel(UrkelError::InvalidNode(
                                        "Urkel record depth overflowed".to_owned(),
                                    ))
                                })?;
                            if maximum > URKEL_BITS {
                                return Err(PageTreeError::Urkel(UrkelError::InvalidNode(
                                    "Urkel record path exceeds the key".to_owned(),
                                )));
                            }
                            u16::try_from(maximum).map_err(|_| {
                                PageTreeError::Urkel(UrkelError::InvalidNode(
                                    "Urkel record depth overflowed".to_owned(),
                                ))
                            })?
                        }
                    };
                    current.push(ValidatedPageRecord {
                        root,
                        maximum_path_bits,
                    });
                    record_count = record_count
                        .checked_add(1)
                        .ok_or(PageTreeError::OffsetOverflow)?;
                }
                segment_pages.push(current);
                page_count = page_count
                    .checked_add(1)
                    .ok_or(PageTreeError::OffsetOverflow)?;
            }
            indexed.insert(segment, segment_pages);
            byte_count = byte_count
                .checked_add(bytes)
                .ok_or(PageTreeError::OffsetOverflow)?;
        }
        drop(files);

        let addresses = self.addresses.lock().map_err(|_| PageTreeError::Poisoned)?;
        for (root, address) in addresses.iter() {
            let record = indexed_page_record(&indexed, *address)
                .ok_or(PageTreeError::MissingEarlierRecord(*address))?;
            if record.root != *root {
                return Err(PageTreeError::RecordKeyMismatch {
                    expected: *root,
                    actual: record.root,
                });
            }
        }
        drop(addresses);

        let capacity = usize::try_from(record_count).map_err(|_| PageTreeError::OffsetOverflow)?;
        let mut roots = Vec::with_capacity(capacity);
        for segments in indexed.into_values() {
            for page in segments {
                roots.extend(page);
            }
        }
        roots.sort_unstable_by_key(|record| record.root);
        if roots.windows(2).any(|pair| {
            pair[0].root == pair[1].root && pair[0].maximum_path_bits != pair[1].maximum_path_bits
        }) {
            return Err(PageTreeError::StateCodec(
                "duplicate name-page roots derived inconsistent path depths".to_owned(),
            ));
        }
        roots.dedup_by_key(|record| record.root);

        Ok(NamePageValidation {
            segments: segments.len(),
            pages: page_count,
            records: record_count,
            bytes: byte_count,
            roots,
        })
    }

    #[cfg(test)]
    fn page_load_count(&self) -> Result<u64, PageTreeError> {
        self.cache
            .lock()
            .map_err(|_| PageTreeError::Poisoned)
            .map(|cache| cache.loads)
    }

    #[cfg(test)]
    fn path_page_read_count(&self) -> u64 {
        self.path_page_reads.load(Ordering::Relaxed)
    }

    fn insert_discovered(
        &self,
        discovered: Vec<(TreeRoot, NamePageAddress)>,
    ) -> Result<(), PageTreeError> {
        if discovered.is_empty() {
            return Ok(());
        }
        let mut addresses = self.addresses.lock().map_err(|_| PageTreeError::Poisoned)?;
        for (root, address) in discovered {
            insert_discovered_address(&mut addresses, root, address)?;
        }
        Ok(())
    }

    fn ensure_page(&self, address: NamePageAddress) -> Result<(), PageTreeError> {
        let cache_key = (address.segment(), address.page());
        {
            let cache = self.cache.lock().map_err(|_| PageTreeError::Poisoned)?;
            if cache.pages.contains_key(&cache_key) {
                return Ok(());
            }
        }
        let offset = u64::from(address.page())
            .checked_mul(NAME_PAGE_BYTES as u64)
            .ok_or(PageTreeError::OffsetOverflow)?;
        let mut encoded = vec![0u8; NAME_PAGE_BYTES];
        {
            let mut files = self.files.lock().map_err(|_| PageTreeError::Poisoned)?;
            let file = files
                .get_mut(&address.segment())
                .ok_or(PageTreeError::MissingSegment(address.segment()))?;
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
            .insert(cache_key, CachedNamePage { records });
        Ok(())
    }
}

#[cfg(unix)]
fn read_ahead_name_page(
    files: &HashMap<u32, File>,
    pending: &BTreeMap<(u32, u32), BTreeMap<u16, NamePagePathWork>>,
    cache: &mut BTreeMap<(u32, u32), ReadAheadNamePage>,
    target: (u32, u32),
) -> Result<ReadAheadNamePage, PageTreeError> {
    if !cache.contains_key(&target) {
        let retained_pages =
            NAME_PAGE_READ_AHEAD_CACHE_PAGES.saturating_sub(NAME_PAGE_READ_AHEAD_PAGES);
        while cache.len() > retained_pages {
            cache.pop_first();
        }
        let candidates = pending
            .keys()
            .rev()
            .copied()
            .filter(|page| !cache.contains_key(page))
            .take(NAME_PAGE_READ_AHEAD_PAGES)
            .map(|page| {
                let slots = pending
                    .get(&page)
                    .expect("read-ahead candidate remains pending")
                    .keys()
                    .copied()
                    .collect::<Vec<_>>();
                (page, slots)
            })
            .collect::<Vec<_>>();
        let worker_count = NAME_PAGE_READ_AHEAD_WORKERS.min(candidates.len()).max(1);
        let chunk_size = candidates.len().div_ceil(worker_count);
        let loaded = std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(worker_count);
            for chunk in candidates.chunks(chunk_size) {
                workers.push(scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(page, slots)| {
                            let file = files
                                .get(&page.0)
                                .ok_or(PageTreeError::MissingSegment(page.0))?;
                            let directory = read_name_page_directory_at(file, page.1)?;
                            let subpages =
                                read_name_page_subpages_at(file, page.1, &directory, slots)?;
                            Ok((
                                *page,
                                ReadAheadNamePage {
                                    directory,
                                    subpages,
                                },
                            ))
                        })
                        .collect::<Result<Vec<_>, PageTreeError>>()
                }));
            }
            let mut loaded = Vec::with_capacity(candidates.len());
            for worker in workers {
                loaded.extend(worker.join().map_err(|_| {
                    PageTreeError::StateCodec(
                        "name-page directory read-ahead worker panicked".to_owned(),
                    )
                })??);
            }
            Ok::<_, PageTreeError>(loaded)
        })?;
        cache.extend(loaded);
    }
    cache.remove(&target).ok_or_else(|| {
        PageTreeError::StateCodec("name-page read-ahead missed its target".to_owned())
    })
}

fn insert_name_page_path_work<I>(
    pending: &mut BTreeMap<(u32, u32), BTreeMap<u16, NamePagePathWork>>,
    root: TreeRoot,
    address: NamePageAddress,
    traversals: I,
) -> Result<(), PageTreeError>
where
    I: IntoIterator<Item = (NameHash, usize)>,
{
    insert_name_page_slot_work(
        pending
            .entry((address.segment(), address.page()))
            .or_default(),
        root,
        address,
        traversals,
    )
}

fn insert_name_page_slot_work<I>(
    page: &mut BTreeMap<u16, NamePagePathWork>,
    root: TreeRoot,
    address: NamePageAddress,
    traversals: I,
) -> Result<(), PageTreeError>
where
    I: IntoIterator<Item = (NameHash, usize)>,
{
    let work = page
        .entry(address.slot())
        .or_insert_with(|| NamePagePathWork {
            root,
            traversals: Vec::new(),
        });
    if work.root != root {
        return Err(PageTreeError::AddressConflict(root));
    }
    work.traversals.extend(traversals);
    Ok(())
}

fn page_branch_depth(prefix: &hns_urkel::BitPrefix, depth: usize) -> Result<usize, PageTreeError> {
    let branch_depth = depth.checked_add(prefix.bit_len()).ok_or_else(|| {
        PageTreeError::Urkel(UrkelError::InvalidNode(
            "Urkel record depth overflowed".to_owned(),
        ))
    })?;
    if branch_depth >= URKEL_BITS {
        return Err(PageTreeError::Urkel(UrkelError::InvalidNode(
            "Urkel internal path exceeds the key".to_owned(),
        )));
    }
    Ok(branch_depth)
}

fn key_bit_at(key: &[u8; 32], bit: usize) -> u8 {
    (key[bit / 8] >> (7 - bit % 8)) & 1
}

fn earlier_page_record<'a>(
    prior_segments: &'a BTreeMap<u32, Vec<Vec<ValidatedPageRecord>>>,
    current_segment_pages: &'a [Vec<ValidatedPageRecord>],
    current_page: &'a [ValidatedPageRecord],
    segment: u32,
    page: u32,
    address: NamePageAddress,
) -> Option<&'a ValidatedPageRecord> {
    if address.segment() < segment {
        return indexed_page_record(prior_segments, address);
    }
    if address.segment() != segment {
        return None;
    }
    if address.page() < page {
        return current_segment_pages
            .get(address.page() as usize)?
            .get(usize::from(address.slot()));
    }
    if address.page() == page {
        return current_page.get(usize::from(address.slot()));
    }
    None
}

fn indexed_page_record(
    indexed: &BTreeMap<u32, Vec<Vec<ValidatedPageRecord>>>,
    address: NamePageAddress,
) -> Option<&ValidatedPageRecord> {
    indexed
        .get(&address.segment())?
        .get(address.page() as usize)?
        .get(usize::from(address.slot()))
}

fn read_cached_name_page_record(
    page: &CachedNamePage,
    expected: TreeRoot,
    address: NamePageAddress,
) -> Result<LoadedNamePageRecord, PageTreeError> {
    let record = page
        .records
        .get(usize::from(address.slot()))
        .ok_or(PageTreeError::SlotOutOfRange(address))?;
    validate_loaded_name_page_record(record.clone(), expected)
}

fn validate_loaded_name_page_record(
    record: NamePageRecord,
    expected: TreeRoot,
) -> Result<LoadedNamePageRecord, PageTreeError> {
    if record.key != *expected.as_bytes() {
        return Err(PageTreeError::RecordKeyMismatch {
            expected,
            actual: TreeRoot::new(record.key),
        });
    }
    let decoded = UrkelNodeRecord::decode(&record.canonical)?;
    let actual = decoded.root();
    if actual != expected {
        return Err(PageTreeError::RecordKeyMismatch { expected, actual });
    }
    let discovered = match decoded {
        UrkelNodeRecord::Leaf { .. } if !record.children.is_empty() => {
            return Err(PageTreeError::ChildLocatorMismatch(expected));
        }
        UrkelNodeRecord::Internal { left, right, .. } if record.children.len() == 2 => {
            vec![(left, record.children[0]), (right, record.children[1])]
        }
        UrkelNodeRecord::Internal { .. } => {
            return Err(PageTreeError::ChildLocatorMismatch(expected));
        }
        UrkelNodeRecord::Leaf { .. } => Vec::new(),
    };
    Ok(LoadedNamePageRecord {
        canonical: record.canonical,
        discovered,
    })
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
    #[error("name-page store access failed: {0}")]
    Store(#[from] StoreError),
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
    #[error("name-page locator belongs to generation {actual}, expected {expected}")]
    WrongGeneration { expected: u64, actual: u64 },
    #[error("name-page segment {0} is unavailable")]
    MissingSegment(u32),
    #[error("name-page segment {segment} has non-page-aligned length {bytes}")]
    UnalignedSegment { segment: u32, bytes: u64 },
    #[error("name-page segment {segment} contains {pages} pages, exceeding its address space")]
    PageCountOverflow { segment: u32, pages: u64 },
    #[error("name-page segment {segment} page {page} is empty")]
    EmptyCommittedPage { segment: u32, page: u32 },
    #[error("name-page child or root address {0:?} does not name an earlier committed record")]
    MissingEarlierRecord(NamePageAddress),
    #[error("name-page cache did not retain address {0:?}")]
    MissingCachedPage(NamePageAddress),
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
    #[error("name-page bootstrap encountered duplicate record {0:?}")]
    DuplicateRecord(TreeRoot),
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
    use hns_store::{MemoryStore, Store, WriteBatch};
    use hns_urkel::{
        prove_hsd_from_records, update_record_tree, validate_record_tree, MemoryUrkel,
    };

    #[test]
    fn name_page_state_round_trips_seals_and_decodes_legacy_state() {
        let state = NamePageState {
            manifest: SegmentManifest {
                generation: 7,
                active_segment: 1,
                durable_bytes: 0,
            },
            root: TreeRoot::ZERO,
            root_address: None,
            committed_height: Some(205),
            last_sealed_height: Some(360),
        };
        let encoded = state.encode().expect("encode state");
        assert_eq!(
            NamePageState::decode(&encoded).expect("decode state"),
            state
        );

        let mut legacy_body = encoded[..LEGACY_NAME_PAGE_STATE_BODY_BYTES].to_vec();
        legacy_body[..4].copy_from_slice(&LEGACY_NAME_PAGE_STATE_VERSION.to_le_bytes());
        let mut legacy = legacy_body.clone();
        legacy.extend_from_slice(&blake2b_256(&legacy_body));
        let decoded = NamePageState::decode(&legacy).expect("decode legacy state");
        assert_eq!(decoded.last_sealed_height, None);
        assert_eq!(decoded.committed_height, state.committed_height);
        assert_eq!(decoded.manifest, state.manifest);
    }

    #[test]
    fn bootstrap_streams_one_read_tree_into_equivalent_pages() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-name-pages-stream-{}-{nonce}.pages",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let entries = (0u8..64)
            .map(|index| {
                let mut key = [0u8; 32];
                key[0] = index;
                key[31] = index.rotate_left(3);
                (NameHash::new(key), vec![index; usize::from(index % 11 + 1)])
            })
            .collect::<Vec<_>>();
        let tree = MemoryUrkel::from_entries(entries.clone()).expect("tree");
        let root = tree.root();
        let records = tree.node_records().expect("records");
        let store = MemoryStore::new();
        let mut batch = store.batch();
        for (record_root, raw) in &records {
            batch
                .put(ColumnFamily::NameTreeNodes, record_root.as_bytes(), raw)
                .expect("stage record");
        }
        store.commit(batch).expect("commit records");
        let snapshot = store.snapshot().expect("snapshot");
        let mut appender = NamePageAppender::create_new(&path, 9, 0).expect("create pages");
        let streamed = stream_name_page_tree_with_parallelism(&snapshot, root, &mut appender, 4)
            .expect("stream pages");
        assert_eq!(streamed.record_count, records.len() as u64);
        assert_eq!(
            streamed.manifest.durable_bytes,
            streamed.page_count * NAME_PAGE_BYTES as u64
        );
        assert!(streamed.parallel_subtrees >= 4);

        let locator = NamePageRootLocator::new(
            streamed.manifest.generation,
            streamed.root_address.expect("root address"),
        );
        let reader =
            NamePageTreeReader::open_with_cache(&path, root, locator, 2).expect("open pages");
        let audited = reader
            .validate_committed_pages()
            .expect("linear page audit");
        assert_eq!(audited.segments, 1);
        assert_eq!(audited.pages, streamed.page_count);
        assert_eq!(audited.records, records.len() as u64);
        assert_eq!(audited.bytes, streamed.manifest.durable_bytes);
        assert!(audited.maximum_path_bits(root).is_some());
        assert_eq!(
            validate_record_tree(root, |record_root| {
                reader
                    .load(record_root)
                    .map_err(|error| UrkelError::Storage(error.to_string()))
            })
            .expect("validate streamed tree"),
            records.len()
        );
        for (key, value) in entries.iter().step_by(9) {
            let proof = prove_hsd_from_records(root, *key, |record_root| {
                reader
                    .load(record_root)
                    .map_err(|error| UrkelError::Storage(error.to_string()))
            })
            .expect("page proof");
            assert_eq!(
                proof.verify_value(root).expect("verify proof"),
                Some(value.clone())
            );
        }

        drop(reader);
        drop(appender);
        std::fs::remove_file(path).expect("remove page fixture");
    }

    #[test]
    fn bootstrap_rejects_a_duplicate_subtree_before_publication() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-name-pages-duplicate-{}-{nonce}.pages",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let tree = MemoryUrkel::from_entries([
            (NameHash::new([0x11; 32]), b"left".to_vec()),
            (NameHash::new([0x91; 32]), b"right".to_vec()),
        ])
        .expect("tree");
        let records = tree.node_records().expect("records");
        let root_record = UrkelNodeRecord::decode(records.get(&tree.root()).expect("root record"))
            .expect("decode root");
        let UrkelNodeRecord::Internal {
            prefix,
            left,
            right: _,
        } = root_record
        else {
            panic!("two-leaf tree must have an internal root");
        };
        let duplicate = UrkelNodeRecord::Internal {
            prefix,
            left,
            right: left,
        };
        let duplicate_root = duplicate.root();
        let store = MemoryStore::new();
        let mut batch = store.batch();
        batch
            .put(
                ColumnFamily::NameTreeNodes,
                duplicate_root.as_bytes(),
                &duplicate.encode().expect("encode duplicate"),
            )
            .expect("stage duplicate");
        batch
            .put(
                ColumnFamily::NameTreeNodes,
                left.as_bytes(),
                records.get(&left).expect("left record"),
            )
            .expect("stage child");
        store.commit(batch).expect("commit records");

        let snapshot = store.snapshot().expect("snapshot");
        let mut appender = NamePageAppender::create_new(&path, 1, 0).expect("create pages");
        assert!(matches!(
            stream_name_page_tree_with_parallelism(
                &snapshot,
                duplicate_root,
                &mut appender,
                1
            ),
            Err(PageTreeError::DuplicateRecord(root)) if root == left
        ));
        assert_eq!(std::fs::metadata(&path).expect("page metadata").len(), 0);

        drop(appender);
        std::fs::remove_file(path).expect("remove page fixture");
    }

    #[test]
    fn page_multi_get_coalesces_cyclic_requests_with_a_one_page_cache() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-name-pages-multi-get-{}-{nonce}.pages",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let entries = (0u8..128)
            .map(|index| {
                let mut key = [0u8; 32];
                key[0] = index;
                key[31] = index.reverse_bits();
                (NameHash::new(key), vec![index; 2_048])
            })
            .collect::<Vec<_>>();
        let tree = MemoryUrkel::from_entries(entries.clone()).expect("tree");
        let root = tree.root();
        let records = tree.node_records().expect("records");
        let packed =
            pack_name_page_records(3, 0, 0, &records, &HashMap::new()).expect("pack records");
        assert!(packed.page_count() > 2);
        let mut appender = NamePageAppender::create_new(&path, 3, 0).expect("create pages");
        packed.append(&mut appender).expect("append pages");
        let root_locator = packed.root_locator(root).expect("root locator");
        let reader =
            NamePageTreeReader::open_with_cache(&path, root, root_locator, 1).expect("reader");

        let before = reader.path_page_read_count();
        let prefetched = reader
            .prefetch_paths(
                root,
                &entries.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
            )
            .expect("physical-order path prefetch")
            .expect("page-backed root");
        let after = reader.path_page_read_count();
        assert_eq!(prefetched, records);
        assert_eq!(after - before, packed.page_count() as u64);
        drop(reader);

        let reader =
            NamePageTreeReader::open_with_cache(&path, root, root_locator, 1).expect("reader");
        let mut by_page = BTreeMap::<u32, Vec<TreeRoot>>::new();
        for record_root in records.keys().copied() {
            let address = packed.address(record_root).expect("record address");
            reader
                .insert_root(
                    record_root,
                    NamePageRootLocator::new(packed.generation, address),
                )
                .expect("seed address");
            by_page.entry(address.page()).or_default().push(record_root);
        }
        assert_eq!(by_page.len(), packed.page_count());
        let mut requests = Vec::new();
        for round in 0..5 {
            for roots in by_page.values() {
                requests.push(roots[round % roots.len()]);
            }
        }
        let before = reader.page_load_count().expect("load count");
        let loaded = reader.load_many(&requests).expect("page multi-get");
        let after = reader.page_load_count().expect("load count");
        assert_eq!(after - before, by_page.len() as u64);
        for (root, raw) in requests.iter().zip(loaded) {
            assert_eq!(
                raw.as_deref(),
                Some(records.get(root).expect("canonical record").as_slice())
            );
        }

        drop(reader);
        drop(appender);
        std::fs::remove_file(path).expect("remove page fixture");
    }

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
        let second_path = std::env::temp_dir().join(format!(
            "hsrd-name-pages-{}-{nonce}-second.pages",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&second_path);

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
        let mut second_appender =
            NamePageAppender::create_new(&second_path, 1, 1).expect("create second segment");
        let update_pack = pack_name_page_records(1, 1, 0, update.records(), &known)
            .expect("pack cross-segment update");
        assert!(update_pack.record_count() < initial_records.len() + update.records().len());
        update_pack
            .append(&mut second_appender)
            .expect("append update");
        let updated_locator = update_pack
            .root_locator(updated_root)
            .expect("updated root locator");

        let paths = BTreeMap::from([(0, path.clone()), (1, second_path.clone())]);
        let updated_reader =
            NamePageTreeReader::open_segments_with_cache(&paths, updated_root, updated_locator, 2)
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
        drop(second_appender);
        std::fs::remove_file(path).expect("remove page fixture");
        std::fs::remove_file(second_path).expect("remove second page fixture");
    }
}
