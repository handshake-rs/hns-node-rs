#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use hns_primitives::blake2b_256;
use thiserror::Error;

use crate::{SegmentManifest, SegmentPageRead};

const NAME_PAGE_MAGIC: &[u8; 8] = b"HSGNPG01";
const NAME_PAGE_VERSION: u16 = 1;
const NAME_PAGE_HEADER_BYTES: usize = 8 + 2 + 2 + 4 + 4 + 4;
const NAME_PAGE_CHECKSUM_BYTES: usize = 32;
const NAME_PAGE_INDEX_BYTES: usize = 2;
const NAME_PAGE_RECORD_FIXED_BYTES: usize = 32 + 2 + 2 + 1 + 1;
const NAME_PAGE_CHILD_BYTES: usize = 8;
const NAME_PAGE_ADDRESS_FIELD_MAX: u32 = (1 << 24) - 1;
pub const NAME_PAGE_BYTES: usize = 64 * 1024;
pub const NAME_SUBPAGE_BYTES: usize = 4 * 1024;
const NAME_SUBPAGE_COUNT: usize = NAME_PAGE_BYTES / NAME_SUBPAGE_BYTES;
const NAME_SUBPAGE_DATA_COUNT: usize = NAME_SUBPAGE_COUNT - 1;
const NAME_SUBPAGE_INDEX_MAGIC: &[u8; 8] = b"HSGNPI02";
const NAME_SUBPAGE_RECORD_MAGIC: &[u8; 8] = b"HSGNPR02";
const NAME_SUBPAGE_VERSION: u16 = 2;
const NAME_SUBPAGE_CHECKSUM_BYTES: usize = 32;
const NAME_SUBPAGE_INDEX_HEADER_BYTES: usize = 8 + 2 + 2 + 1 + 3;
const NAME_SUBPAGE_INDEX_ENTRY_BYTES: usize = 2;
const NAME_SUBPAGE_RECORD_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 2 + 2 + 4;
const NAME_SUBPAGE_LOCAL_RECORD_MAX: usize = u8::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamePageAddress(u64);

impl NamePageAddress {
    pub fn new(segment: u32, page: u32, slot: u16) -> Result<Self, NamePageError> {
        if segment > NAME_PAGE_ADDRESS_FIELD_MAX {
            return Err(NamePageError::AddressFieldOverflow {
                field: "segment",
                value: segment,
                maximum: NAME_PAGE_ADDRESS_FIELD_MAX,
            });
        }
        if page > NAME_PAGE_ADDRESS_FIELD_MAX {
            return Err(NamePageError::AddressFieldOverflow {
                field: "page",
                value: page,
                maximum: NAME_PAGE_ADDRESS_FIELD_MAX,
            });
        }
        Ok(Self(
            (u64::from(segment) << 40) | (u64::from(page) << 16) | u64::from(slot),
        ))
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn segment(self) -> u32 {
        ((self.0 >> 40) & 0x00ff_ffff) as u32
    }

    pub const fn page(self) -> u32 {
        ((self.0 >> 16) & 0x00ff_ffff) as u32
    }

    pub const fn slot(self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamePageRecord {
    pub key: [u8; 32],
    pub children: Vec<NamePageAddress>,
    pub canonical: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamePageRecordRef<'a> {
    pub key: [u8; 32],
    pub children: [Option<NamePageAddress>; 2],
    pub canonical: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamePageRecordLocation {
    pub key: [u8; 32],
    pub children: [Option<NamePageAddress>; 2],
    record_offset: usize,
    record_end: usize,
    payload_offset: usize,
    payload_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamePageDirectory {
    layout: NamePageDirectoryLayout,
}

/// Opaque page-local bytes prepared by positioned read-ahead. Version-1
/// records share one covering payload span; version-2 records retain only the
/// independently authenticated subpages selected by the traversal.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamePagePrefetch {
    page: u32,
    legacy_span: Option<NamePageLegacySpan>,
    subpages: Vec<NamePageSubpage>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NamePageLegacySpan {
    start: usize,
    encoded: Vec<u8>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NamePageSubpage {
    subpage: u8,
    encoded: Vec<u8>,
}

/// Page-local positioned reader. Version-2 record subpages are immutable and
/// cached after one aligned read, so several affected paths sharing a physical
/// subpage never issue duplicate I/O.
#[cfg(unix)]
pub struct PositionedNamePageReader<'a> {
    file: &'a File,
    page: u32,
    directory: &'a NamePageDirectory,
    legacy_span: Option<NamePageLegacySpan>,
    subpages: BTreeMap<u8, Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NamePageDirectoryLayout {
    Legacy {
        encoded: Vec<u8>,
        record_count: u16,
        directory_end: usize,
        payload_end: usize,
    },
    Subpages {
        encoded_index: Vec<u8>,
        record_count: u16,
        subpage_count: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamePageRef<'a> {
    layout: NamePageRefLayout<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamePageRefLayout<'a> {
    Legacy {
        encoded: &'a [u8],
        record_count: u16,
        directory_end: usize,
        payload_end: usize,
    },
    Subpages {
        encoded: &'a [u8],
        record_count: u16,
        subpage_count: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamePageFileInspection {
    pub pages: u64,
    pub valid_bytes: u64,
    pub file_bytes: u64,
    pub torn_tail: bool,
}

#[derive(Debug)]
pub struct NamePageAppender {
    file: File,
    generation: u64,
    segment: u32,
    next_page: u32,
    poisoned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamePagePush {
    Added(NamePageAddress),
    Full(NamePageRecord),
}

#[derive(Clone, Debug)]
pub struct NamePageBuilder {
    segment: u32,
    page: u32,
    records: Vec<NamePageRecord>,
    keys: BTreeSet<[u8; 32]>,
    subpage_record_counts: Vec<usize>,
    subpage_record_bytes: Vec<usize>,
}

impl NamePageBuilder {
    pub fn new(segment: u32, page: u32) -> Result<Self, NamePageError> {
        NamePageAddress::new(segment, page, 0)?;
        Ok(Self {
            segment,
            page,
            records: Vec::new(),
            keys: BTreeSet::new(),
            subpage_record_counts: Vec::new(),
            subpage_record_bytes: Vec::new(),
        })
    }

    /// Add in topological order. A full result returns ownership of the record
    /// unchanged so the caller can seal this page and retry on the next page.
    pub fn push(&mut self, record: NamePageRecord) -> Result<NamePagePush, NamePageError> {
        validate_name_page_record(self.records.len(), &record)?;
        if self.keys.contains(&record.key) {
            return Err(NamePageError::DuplicateKey);
        }
        let added_bytes = name_page_record_bytes(&record)?;
        let index_required = NAME_SUBPAGE_INDEX_HEADER_BYTES
            .checked_add(
                self.records
                    .len()
                    .checked_add(1)
                    .and_then(|count| count.checked_mul(NAME_SUBPAGE_INDEX_ENTRY_BYTES))
                    .ok_or(NamePageError::OffsetOverflow)?,
            )
            .and_then(|bytes| bytes.checked_add(NAME_SUBPAGE_CHECKSUM_BYTES))
            .ok_or(NamePageError::OffsetOverflow)?;
        if index_required > NAME_SUBPAGE_BYTES {
            return Ok(NamePagePush::Full(record));
        }
        let mut subpage = self.subpage_record_counts.len().saturating_sub(1);
        let current_count = self
            .subpage_record_counts
            .get(subpage)
            .copied()
            .unwrap_or(0);
        let current_bytes = self.subpage_record_bytes.get(subpage).copied().unwrap_or(0);
        let mut required = name_subpage_required_bytes(
            current_count
                .checked_add(1)
                .ok_or(NamePageError::OffsetOverflow)?,
            current_bytes
                .checked_add(added_bytes)
                .ok_or(NamePageError::OffsetOverflow)?,
        )?;
        if current_count >= NAME_SUBPAGE_LOCAL_RECORD_MAX || required > NAME_SUBPAGE_BYTES {
            if self.subpage_record_counts.len() == NAME_SUBPAGE_DATA_COUNT {
                return Ok(NamePagePush::Full(record));
            }
            subpage = self.subpage_record_counts.len();
            required = name_subpage_required_bytes(1, added_bytes)?;
            if required > NAME_SUBPAGE_BYTES {
                return Err(NamePageError::RecordTooLarge {
                    index: self.records.len(),
                    actual: added_bytes,
                    maximum: NAME_SUBPAGE_BYTES
                        - NAME_SUBPAGE_RECORD_HEADER_BYTES
                        - NAME_SUBPAGE_CHECKSUM_BYTES,
                });
            }
            self.subpage_record_counts.push(0);
            self.subpage_record_bytes.push(0);
        } else if self.subpage_record_counts.is_empty() {
            self.subpage_record_counts.push(0);
            self.subpage_record_bytes.push(0);
        }
        let slot = u16::try_from(self.records.len())
            .map_err(|_| NamePageError::TooManyRecords(self.records.len()))?;
        let address = NamePageAddress::new(self.segment, self.page, slot)?;
        self.keys.insert(record.key);
        self.records.push(record);
        self.subpage_record_counts[subpage] += 1;
        self.subpage_record_bytes[subpage] =
            required - NAME_SUBPAGE_RECORD_HEADER_BYTES - NAME_SUBPAGE_CHECKSUM_BYTES;
        Ok(NamePagePush::Added(address))
    }

    pub fn finish(self) -> Result<Vec<u8>, NamePageError> {
        if self.records.is_empty() {
            return Err(NamePageError::EmptyPage);
        }
        encode_name_subpage_page(&self.records)
    }

    pub fn records(&self) -> &[NamePageRecord] {
        &self.records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl NamePageAppender {
    pub fn create_new(
        path: impl AsRef<Path>,
        generation: u64,
        segment: u32,
    ) -> Result<Self, NamePageError> {
        NamePageAddress::new(segment, 0, 0)?;
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(path)
            .map_err(name_page_io)?;
        Ok(Self {
            file,
            generation,
            segment,
            next_page: 0,
            poisoned: false,
        })
    }

    pub fn open_at_committed_tail(
        path: impl AsRef<Path>,
        manifest: SegmentManifest,
    ) -> Result<Self, NamePageError> {
        NamePageAddress::new(manifest.active_segment, 0, 0)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .map_err(name_page_io)?;
        let actual = file.metadata().map_err(name_page_io)?.len();
        if actual != manifest.durable_bytes || !actual.is_multiple_of(NAME_PAGE_BYTES as u64) {
            return Err(NamePageError::UncommittedTail {
                committed: manifest.durable_bytes,
                actual,
            });
        }
        validate_last_committed_page(&mut file, manifest.durable_bytes)?;
        let next_page_u64 = manifest.durable_bytes / NAME_PAGE_BYTES as u64;
        let next_page =
            u32::try_from(next_page_u64).map_err(|_| NamePageError::PageIndexOverflow {
                pages: next_page_u64,
            })?;
        if next_page > NAME_PAGE_ADDRESS_FIELD_MAX {
            return Err(NamePageError::PageIndexOverflow {
                pages: next_page_u64,
            });
        }
        Ok(Self {
            file,
            generation: manifest.generation,
            segment: manifest.active_segment,
            next_page,
            poisoned: false,
        })
    }

    /// Write one complete immutable page. State mutation prepares records in
    /// memory first, so consensus failure cannot leave a partially published
    /// page or locator in the RocksDB batch.
    pub fn append(
        &mut self,
        records: &[NamePageRecord],
    ) -> Result<Vec<NamePageAddress>, NamePageError> {
        if self.poisoned {
            return Err(NamePageError::AppenderPoisoned);
        }
        if records.is_empty() {
            return Err(NamePageError::EmptyPage);
        }
        if self.next_page > NAME_PAGE_ADDRESS_FIELD_MAX {
            return Err(NamePageError::PageIndexOverflow {
                pages: u64::from(self.next_page),
            });
        }
        let encoded = encode_name_subpage_page(records)?;
        let mut addresses = Vec::with_capacity(records.len());
        for slot in 0..records.len() {
            addresses.push(NamePageAddress::new(
                self.segment,
                self.next_page,
                u16::try_from(slot).map_err(|_| NamePageError::TooManyRecords(records.len()))?,
            )?);
        }
        self.poisoned = true;
        self.file.write_all(&encoded).map_err(name_page_io)?;
        self.next_page = self
            .next_page
            .checked_add(1)
            .ok_or(NamePageError::PageIndexOverflow {
                pages: u64::from(self.next_page) + 1,
            })?;
        self.poisoned = false;
        Ok(addresses)
    }

    pub fn sync_data(&mut self) -> Result<SegmentManifest, NamePageError> {
        if self.poisoned {
            return Err(NamePageError::AppenderPoisoned);
        }
        self.file.sync_data().map_err(name_page_io)?;
        let durable_bytes = u64::from(self.next_page)
            .checked_mul(NAME_PAGE_BYTES as u64)
            .ok_or(NamePageError::OffsetOverflow)?;
        Ok(SegmentManifest {
            generation: self.generation,
            active_segment: self.segment,
            durable_bytes,
        })
    }

    pub const fn next_page(&self) -> u32 {
        self.next_page
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn segment(&self) -> u32 {
        self.segment
    }
}

impl<'a> NamePageRef<'a> {
    pub const fn record_count(self) -> u16 {
        match self.layout {
            NamePageRefLayout::Legacy { record_count, .. }
            | NamePageRefLayout::Subpages { record_count, .. } => record_count,
        }
    }

    pub fn record(self, slot: u16) -> Result<NamePageRecordRef<'a>, NamePageError> {
        match self.layout {
            NamePageRefLayout::Legacy {
                encoded,
                record_count,
                directory_end,
                payload_end,
            } => {
                let location = decode_name_page_record_location(
                    encoded,
                    record_count,
                    directory_end,
                    payload_end,
                    slot,
                )?;
                let payload_end = location
                    .payload_offset
                    .checked_add(location.payload_length)
                    .ok_or(NamePageError::DirectoryInvariant)?;
                let canonical = encoded
                    .get(location.payload_offset..payload_end)
                    .ok_or(NamePageError::DirectoryInvariant)?;
                Ok(NamePageRecordRef {
                    key: location.key,
                    children: location.children,
                    canonical,
                })
            }
            NamePageRefLayout::Subpages {
                encoded,
                record_count,
                subpage_count,
            } => {
                let (subpage, local_slot) =
                    decode_name_subpage_index_location(encoded, record_count, subpage_count, slot)?;
                let start = usize::from(subpage)
                    .checked_mul(NAME_SUBPAGE_BYTES)
                    .ok_or(NamePageError::OffsetOverflow)?;
                let end = start
                    .checked_add(NAME_SUBPAGE_BYTES)
                    .ok_or(NamePageError::OffsetOverflow)?;
                let block = encoded
                    .get(start..end)
                    .ok_or(NamePageError::DirectoryInvariant)?;
                decode_name_subpage_record_prevalidated(block, subpage, local_slot)
            }
        }
    }
}

impl NamePageDirectory {
    pub const fn record_count(&self) -> u16 {
        match &self.layout {
            NamePageDirectoryLayout::Legacy { record_count, .. }
            | NamePageDirectoryLayout::Subpages { record_count, .. } => *record_count,
        }
    }

    pub fn resident_bytes(&self) -> usize {
        match &self.layout {
            NamePageDirectoryLayout::Legacy { encoded, .. } => encoded.len(),
            NamePageDirectoryLayout::Subpages { encoded_index, .. } => encoded_index.len(),
        }
    }

    pub fn record(&self, slot: u16) -> Result<NamePageRecordLocation, NamePageError> {
        match &self.layout {
            NamePageDirectoryLayout::Legacy {
                encoded,
                record_count,
                directory_end,
                payload_end,
            } => decode_name_page_record_location(
                encoded,
                *record_count,
                *directory_end,
                *payload_end,
                slot,
            ),
            NamePageDirectoryLayout::Subpages { .. } => Err(NamePageError::DirectoryInvariant),
        }
    }

    fn subpage_location(&self, slot: u16) -> Result<Option<(u8, u8)>, NamePageError> {
        match &self.layout {
            NamePageDirectoryLayout::Legacy { .. } => Ok(None),
            NamePageDirectoryLayout::Subpages {
                encoded_index,
                record_count,
                subpage_count,
            } => decode_name_subpage_index_location(
                encoded_index,
                *record_count,
                *subpage_count,
                slot,
            )
            .map(Some),
        }
    }

    fn contains_subpage(&self, subpage: u8) -> bool {
        matches!(
            &self.layout,
            NamePageDirectoryLayout::Subpages { subpage_count, .. }
                if subpage != 0 && subpage <= *subpage_count
        )
    }
}

#[cfg(unix)]
impl<'a> PositionedNamePageReader<'a> {
    pub fn new(file: &'a File, page: u32, directory: &'a NamePageDirectory) -> Self {
        Self {
            file,
            page,
            directory,
            legacy_span: None,
            subpages: BTreeMap::new(),
        }
    }

    pub fn with_prefetched(
        file: &'a File,
        page: u32,
        directory: &'a NamePageDirectory,
        prefetched: NamePagePrefetch,
    ) -> Result<Self, NamePageError> {
        let mut reader = Self::new(file, page, directory);
        if prefetched.page != page {
            return Err(NamePageError::DirectoryInvariant);
        }
        if let Some(span) = prefetched.legacy_span {
            if directory.contains_subpage(1)
                || span.encoded.is_empty()
                || span
                    .start
                    .checked_add(span.encoded.len())
                    .is_none_or(|end| end > NAME_PAGE_BYTES)
            {
                return Err(NamePageError::DirectoryInvariant);
            }
            reader.legacy_span = Some(span);
        }
        for subpage in prefetched.subpages {
            if !directory.contains_subpage(subpage.subpage) {
                return Err(NamePageError::DirectoryInvariant);
            }
            if reader
                .subpages
                .insert(subpage.subpage, subpage.encoded)
                .is_some()
            {
                return Err(NamePageError::DirectoryInvariant);
            }
        }
        Ok(reader)
    }

    pub fn record(&mut self, slot: u16) -> Result<NamePageRecord, NamePageError> {
        let Some((subpage, local_slot)) = self.directory.subpage_location(slot)? else {
            if let Some(span) = &self.legacy_span {
                let location = self.directory.record(slot)?;
                if let Some(start) = location.payload_offset.checked_sub(span.start) {
                    if let Some(end) = start.checked_add(location.payload_length) {
                        if let Some(canonical) = span.encoded.get(start..end) {
                            return Ok(NamePageRecord {
                                key: location.key,
                                children: location.children.into_iter().flatten().collect(),
                                canonical: canonical.to_vec(),
                            });
                        }
                    }
                }
            }
            return read_name_page_record_at(self.file, self.page, self.directory, slot);
        };
        if !self.subpages.contains_key(&subpage) {
            let offset = u64::from(self.page)
                .checked_mul(NAME_PAGE_BYTES as u64)
                .and_then(|page_offset| {
                    page_offset.checked_add(u64::from(subpage) * NAME_SUBPAGE_BYTES as u64)
                })
                .ok_or(NamePageError::OffsetOverflow)?;
            let mut encoded = vec![0u8; NAME_SUBPAGE_BYTES];
            self.file
                .read_exact_at(&mut encoded, offset)
                .map_err(name_page_io)?;
            decode_name_subpage_record_header(&encoded, subpage)?;
            self.subpages.insert(subpage, encoded);
        }
        let encoded = self
            .subpages
            .get(&subpage)
            .ok_or(NamePageError::DirectoryInvariant)?;
        let record = decode_name_subpage_record_prevalidated(encoded, subpage, local_slot)?;
        Ok(NamePageRecord {
            key: record.key,
            children: record.children.into_iter().flatten().collect(),
            canonical: record.canonical.to_vec(),
        })
    }

    pub fn cached_subpages(&self) -> usize {
        self.subpages.len()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum NamePageError {
    #[error("name page has {actual} bytes; expected exactly {expected}")]
    Length { actual: usize, expected: usize },
    #[error("name page has invalid magic")]
    InvalidMagic,
    #[error("name page version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("name page checksum mismatch")]
    ChecksumMismatch,
    #[error("name page reserved bits are nonzero")]
    ReservedBits,
    #[error("name page record has {0} children; expected zero or two")]
    ChildCount(usize),
    #[error("name page contains too many records: {0}")]
    TooManyRecords(usize),
    #[error("name page record {0} has an empty canonical payload")]
    EmptyRecord(usize),
    #[error("name page contains duplicate content key")]
    DuplicateKey,
    #[error("name page record {index} payload has {actual} bytes; maximum is {maximum}")]
    RecordTooLarge {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("name records need {required} bytes; page capacity is {capacity}")]
    PageFull { required: usize, capacity: usize },
    #[error("name page directory invariant failed")]
    DirectoryInvariant,
    #[error("name page slot {slot} is outside record count {records}")]
    SlotOutOfRange { slot: u16, records: u16 },
    #[error("name page address {field} {value} exceeds {maximum}")]
    AddressFieldOverflow {
        field: &'static str,
        value: u32,
        maximum: u32,
    },
    #[error("name page offset arithmetic overflowed")]
    OffsetOverflow,
    #[error("cannot append an empty name page")]
    EmptyPage,
    #[error("name page file has uncommitted tail: committed {committed}, actual {actual}")]
    UncommittedTail { committed: u64, actual: u64 },
    #[error("committed name-page tail {committed} is not a complete-page boundary")]
    CommittedTailNotBoundary { committed: u64 },
    #[error("name page count {pages} exceeds the compact address space")]
    PageIndexOverflow { pages: u64 },
    #[error("name page appender is poisoned by an incomplete write")]
    AppenderPoisoned,
    #[error("name page I/O failed: {0}")]
    Io(String),
}

pub fn encode_name_page(records: &[NamePageRecord]) -> Result<Vec<u8>, NamePageError> {
    let record_count =
        u16::try_from(records.len()).map_err(|_| NamePageError::TooManyRecords(records.len()))?;
    let index_bytes = records
        .len()
        .checked_mul(NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut directory_bytes = index_bytes;
    let mut payload_bytes = 0usize;
    let mut keys = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        if !keys.insert(record.key) {
            return Err(NamePageError::DuplicateKey);
        }
        validate_name_page_record(index, record)?;
        directory_bytes = directory_bytes
            .checked_add(NAME_PAGE_RECORD_FIXED_BYTES)
            .and_then(|bytes| bytes.checked_add(record.children.len() * NAME_PAGE_CHILD_BYTES))
            .ok_or(NamePageError::OffsetOverflow)?;
        payload_bytes = payload_bytes
            .checked_add(record.canonical.len())
            .ok_or(NamePageError::OffsetOverflow)?;
    }
    let directory_end = NAME_PAGE_HEADER_BYTES
        .checked_add(directory_bytes)
        .ok_or(NamePageError::OffsetOverflow)?;
    let payload_end = directory_end
        .checked_add(payload_bytes)
        .ok_or(NamePageError::OffsetOverflow)?;
    let capacity = NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES;
    if payload_end > capacity {
        return Err(NamePageError::PageFull {
            required: payload_end + NAME_PAGE_CHECKSUM_BYTES,
            capacity: NAME_PAGE_BYTES,
        });
    }
    let directory_end_u32 =
        u32::try_from(directory_end).map_err(|_| NamePageError::OffsetOverflow)?;
    let payload_end_u32 = u32::try_from(payload_end).map_err(|_| NamePageError::OffsetOverflow)?;

    let mut encoded = vec![0u8; NAME_PAGE_BYTES];
    let mut header = 0usize;
    write_bytes(&mut encoded, &mut header, NAME_PAGE_MAGIC)?;
    write_bytes(&mut encoded, &mut header, &NAME_PAGE_VERSION.to_le_bytes())?;
    write_bytes(&mut encoded, &mut header, &record_count.to_le_bytes())?;
    write_bytes(&mut encoded, &mut header, &directory_end_u32.to_le_bytes())?;
    write_bytes(&mut encoded, &mut header, &payload_end_u32.to_le_bytes())?;
    write_bytes(&mut encoded, &mut header, &0u32.to_le_bytes())?;
    debug_assert_eq!(header, NAME_PAGE_HEADER_BYTES);

    let mut entry_cursor = NAME_PAGE_HEADER_BYTES + index_bytes;
    let mut payload_cursor = directory_end;
    for (slot, record) in records.iter().enumerate() {
        let index_offset = NAME_PAGE_HEADER_BYTES + slot * NAME_PAGE_INDEX_BYTES;
        let entry_offset_u16 =
            u16::try_from(entry_cursor).map_err(|_| NamePageError::OffsetOverflow)?;
        encoded[index_offset..index_offset + 2].copy_from_slice(&entry_offset_u16.to_le_bytes());

        write_bytes(&mut encoded, &mut entry_cursor, &record.key)?;
        let payload_offset_u16 =
            u16::try_from(payload_cursor).map_err(|_| NamePageError::OffsetOverflow)?;
        let payload_length_u16 =
            u16::try_from(record.canonical.len()).map_err(|_| NamePageError::RecordTooLarge {
                index: slot,
                actual: record.canonical.len(),
                maximum: usize::from(u16::MAX),
            })?;
        write_bytes(
            &mut encoded,
            &mut entry_cursor,
            &payload_offset_u16.to_le_bytes(),
        )?;
        write_bytes(
            &mut encoded,
            &mut entry_cursor,
            &payload_length_u16.to_le_bytes(),
        )?;
        write_bytes(
            &mut encoded,
            &mut entry_cursor,
            &[record.children.len() as u8, 0],
        )?;
        for child in &record.children {
            write_bytes(&mut encoded, &mut entry_cursor, &child.raw().to_le_bytes())?;
        }
        write_bytes(&mut encoded, &mut payload_cursor, &record.canonical)?;
    }
    debug_assert_eq!(entry_cursor, directory_end);
    debug_assert_eq!(payload_cursor, payload_end);
    let checksum_offset = NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES;
    let checksum = blake2b_256(&encoded[..checksum_offset]);
    encoded[checksum_offset..].copy_from_slice(&checksum);
    Ok(encoded)
}

/// Encode the current page layout: one authenticated 4 KiB slot index followed
/// by up to fifteen independently authenticated 4 KiB record subpages. A
/// lookup reads the index once and only the subpages containing selected
/// records; the enclosing append unit remains one crash-atomic 64 KiB page.
pub fn encode_name_subpage_page(records: &[NamePageRecord]) -> Result<Vec<u8>, NamePageError> {
    let ranges = plan_name_subpage_ranges(records)?;
    let record_count =
        u16::try_from(records.len()).map_err(|_| NamePageError::TooManyRecords(records.len()))?;
    let subpage_count =
        u8::try_from(ranges.len()).map_err(|_| NamePageError::TooManyRecords(records.len()))?;
    let mut encoded = vec![0u8; NAME_PAGE_BYTES];

    let mut cursor = 0usize;
    write_bytes(&mut encoded, &mut cursor, NAME_SUBPAGE_INDEX_MAGIC)?;
    write_bytes(
        &mut encoded,
        &mut cursor,
        &NAME_SUBPAGE_VERSION.to_le_bytes(),
    )?;
    write_bytes(&mut encoded, &mut cursor, &record_count.to_le_bytes())?;
    write_bytes(&mut encoded, &mut cursor, &[subpage_count, 0, 0, 0])?;
    debug_assert_eq!(cursor, NAME_SUBPAGE_INDEX_HEADER_BYTES);
    for (subpage_index, (start, end)) in ranges.iter().copied().enumerate() {
        let subpage = u8::try_from(subpage_index + 1).map_err(|_| NamePageError::OffsetOverflow)?;
        for local_slot in 0..end - start {
            write_bytes(
                &mut encoded,
                &mut cursor,
                &[
                    subpage,
                    u8::try_from(local_slot)
                        .map_err(|_| NamePageError::TooManyRecords(end.saturating_sub(start)))?,
                ],
            )?;
        }
        let block_start = (subpage_index + 1)
            .checked_mul(NAME_SUBPAGE_BYTES)
            .ok_or(NamePageError::OffsetOverflow)?;
        let block_end = block_start
            .checked_add(NAME_SUBPAGE_BYTES)
            .ok_or(NamePageError::OffsetOverflow)?;
        encode_name_record_subpage(
            encoded
                .get_mut(block_start..block_end)
                .ok_or(NamePageError::DirectoryInvariant)?,
            subpage,
            &records[start..end],
        )?;
    }
    let index_checksum_offset = NAME_SUBPAGE_BYTES - NAME_SUBPAGE_CHECKSUM_BYTES;
    if cursor > index_checksum_offset {
        return Err(NamePageError::PageFull {
            required: cursor + NAME_SUBPAGE_CHECKSUM_BYTES,
            capacity: NAME_SUBPAGE_BYTES,
        });
    }
    let checksum = blake2b_256(&encoded[..index_checksum_offset]);
    encoded[index_checksum_offset..NAME_SUBPAGE_BYTES].copy_from_slice(&checksum);
    Ok(encoded)
}

fn plan_name_subpage_ranges(
    records: &[NamePageRecord],
) -> Result<Vec<(usize, usize)>, NamePageError> {
    if records.is_empty() {
        return Err(NamePageError::EmptyPage);
    }
    let index_required = NAME_SUBPAGE_INDEX_HEADER_BYTES
        .checked_add(
            records
                .len()
                .checked_mul(NAME_SUBPAGE_INDEX_ENTRY_BYTES)
                .ok_or(NamePageError::OffsetOverflow)?,
        )
        .and_then(|bytes| bytes.checked_add(NAME_SUBPAGE_CHECKSUM_BYTES))
        .ok_or(NamePageError::OffsetOverflow)?;
    if index_required > NAME_SUBPAGE_BYTES {
        return Err(NamePageError::PageFull {
            required: index_required,
            capacity: NAME_SUBPAGE_BYTES,
        });
    }

    let mut keys = BTreeSet::new();
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let mut count = 0usize;
    let mut record_bytes = 0usize;
    for (index, record) in records.iter().enumerate() {
        if !keys.insert(record.key) {
            return Err(NamePageError::DuplicateKey);
        }
        validate_name_page_record(index, record)?;
        let added = name_page_record_bytes(record)?;
        let next_count = count.checked_add(1).ok_or(NamePageError::OffsetOverflow)?;
        let next_bytes = record_bytes
            .checked_add(added)
            .ok_or(NamePageError::OffsetOverflow)?;
        let required = name_subpage_required_bytes(next_count, next_bytes)?;
        if count >= NAME_SUBPAGE_LOCAL_RECORD_MAX || required > NAME_SUBPAGE_BYTES {
            if count == 0 {
                return Err(NamePageError::RecordTooLarge {
                    index,
                    actual: added,
                    maximum: NAME_SUBPAGE_BYTES
                        - NAME_SUBPAGE_RECORD_HEADER_BYTES
                        - NAME_SUBPAGE_CHECKSUM_BYTES,
                });
            }
            ranges.push((start, index));
            if ranges.len() == NAME_SUBPAGE_DATA_COUNT {
                return Err(NamePageError::PageFull {
                    required: NAME_PAGE_BYTES + 1,
                    capacity: NAME_PAGE_BYTES,
                });
            }
            start = index;
            count = 1;
            record_bytes = added;
            let required = name_subpage_required_bytes(count, record_bytes)?;
            if required > NAME_SUBPAGE_BYTES {
                return Err(NamePageError::RecordTooLarge {
                    index,
                    actual: added,
                    maximum: NAME_SUBPAGE_BYTES
                        - NAME_SUBPAGE_RECORD_HEADER_BYTES
                        - NAME_SUBPAGE_CHECKSUM_BYTES,
                });
            }
        } else {
            count = next_count;
            record_bytes = next_bytes;
        }
    }
    ranges.push((start, records.len()));
    if ranges.len() > NAME_SUBPAGE_DATA_COUNT {
        return Err(NamePageError::PageFull {
            required: NAME_PAGE_BYTES + 1,
            capacity: NAME_PAGE_BYTES,
        });
    }
    Ok(ranges)
}

fn name_subpage_required_bytes(
    record_count: usize,
    record_bytes: usize,
) -> Result<usize, NamePageError> {
    if record_count > NAME_SUBPAGE_LOCAL_RECORD_MAX {
        return Ok(NAME_SUBPAGE_BYTES + 1);
    }
    NAME_SUBPAGE_RECORD_HEADER_BYTES
        .checked_add(record_bytes)
        .and_then(|bytes| bytes.checked_add(NAME_SUBPAGE_CHECKSUM_BYTES))
        .ok_or(NamePageError::OffsetOverflow)
}

fn encode_name_record_subpage(
    encoded: &mut [u8],
    subpage: u8,
    records: &[NamePageRecord],
) -> Result<(), NamePageError> {
    if encoded.len() != NAME_SUBPAGE_BYTES {
        return Err(NamePageError::Length {
            actual: encoded.len(),
            expected: NAME_SUBPAGE_BYTES,
        });
    }
    let record_count =
        u8::try_from(records.len()).map_err(|_| NamePageError::TooManyRecords(records.len()))?;
    if record_count == 0 || usize::from(subpage) > NAME_SUBPAGE_DATA_COUNT {
        return Err(NamePageError::DirectoryInvariant);
    }
    let index_bytes = records
        .len()
        .checked_mul(NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut directory_bytes = index_bytes;
    let mut payload_bytes = 0usize;
    for (index, record) in records.iter().enumerate() {
        validate_name_page_record(index, record)?;
        directory_bytes = directory_bytes
            .checked_add(NAME_PAGE_RECORD_FIXED_BYTES)
            .and_then(|bytes| bytes.checked_add(record.children.len() * NAME_PAGE_CHILD_BYTES))
            .ok_or(NamePageError::OffsetOverflow)?;
        payload_bytes = payload_bytes
            .checked_add(record.canonical.len())
            .ok_or(NamePageError::OffsetOverflow)?;
    }
    let directory_end = NAME_SUBPAGE_RECORD_HEADER_BYTES
        .checked_add(directory_bytes)
        .ok_or(NamePageError::OffsetOverflow)?;
    let payload_end = directory_end
        .checked_add(payload_bytes)
        .ok_or(NamePageError::OffsetOverflow)?;
    let checksum_offset = NAME_SUBPAGE_BYTES - NAME_SUBPAGE_CHECKSUM_BYTES;
    if payload_end > checksum_offset {
        return Err(NamePageError::PageFull {
            required: payload_end + NAME_SUBPAGE_CHECKSUM_BYTES,
            capacity: NAME_SUBPAGE_BYTES,
        });
    }

    let mut cursor = 0usize;
    write_bytes(encoded, &mut cursor, NAME_SUBPAGE_RECORD_MAGIC)?;
    write_bytes(encoded, &mut cursor, &NAME_SUBPAGE_VERSION.to_le_bytes())?;
    write_bytes(encoded, &mut cursor, &[subpage, record_count])?;
    write_bytes(
        encoded,
        &mut cursor,
        &u16::try_from(directory_end)
            .map_err(|_| NamePageError::OffsetOverflow)?
            .to_le_bytes(),
    )?;
    write_bytes(
        encoded,
        &mut cursor,
        &u16::try_from(payload_end)
            .map_err(|_| NamePageError::OffsetOverflow)?
            .to_le_bytes(),
    )?;
    write_bytes(encoded, &mut cursor, &0u32.to_le_bytes())?;
    debug_assert_eq!(cursor, NAME_SUBPAGE_RECORD_HEADER_BYTES);

    let mut entry_cursor = NAME_SUBPAGE_RECORD_HEADER_BYTES + index_bytes;
    let mut payload_cursor = directory_end;
    for (slot, record) in records.iter().enumerate() {
        let index_offset = NAME_SUBPAGE_RECORD_HEADER_BYTES + slot * NAME_PAGE_INDEX_BYTES;
        encoded[index_offset..index_offset + 2].copy_from_slice(
            &u16::try_from(entry_cursor)
                .map_err(|_| NamePageError::OffsetOverflow)?
                .to_le_bytes(),
        );
        write_bytes(encoded, &mut entry_cursor, &record.key)?;
        write_bytes(
            encoded,
            &mut entry_cursor,
            &u16::try_from(payload_cursor)
                .map_err(|_| NamePageError::OffsetOverflow)?
                .to_le_bytes(),
        )?;
        write_bytes(
            encoded,
            &mut entry_cursor,
            &u16::try_from(record.canonical.len())
                .map_err(|_| NamePageError::RecordTooLarge {
                    index: slot,
                    actual: record.canonical.len(),
                    maximum: usize::from(u16::MAX),
                })?
                .to_le_bytes(),
        )?;
        write_bytes(
            encoded,
            &mut entry_cursor,
            &[record.children.len() as u8, 0],
        )?;
        for child in &record.children {
            write_bytes(encoded, &mut entry_cursor, &child.raw().to_le_bytes())?;
        }
        write_bytes(encoded, &mut payload_cursor, &record.canonical)?;
    }
    debug_assert_eq!(entry_cursor, directory_end);
    debug_assert_eq!(payload_cursor, payload_end);
    let checksum = blake2b_256(&encoded[..checksum_offset]);
    encoded[checksum_offset..].copy_from_slice(&checksum);
    Ok(())
}

fn validate_name_page_record(index: usize, record: &NamePageRecord) -> Result<(), NamePageError> {
    if !record.children.is_empty() && record.children.len() != 2 {
        return Err(NamePageError::ChildCount(record.children.len()));
    }
    if record.canonical.is_empty() {
        return Err(NamePageError::EmptyRecord(index));
    }
    if record.canonical.len() > usize::from(u16::MAX) {
        return Err(NamePageError::RecordTooLarge {
            index,
            actual: record.canonical.len(),
            maximum: usize::from(u16::MAX),
        });
    }
    Ok(())
}

fn name_page_record_bytes(record: &NamePageRecord) -> Result<usize, NamePageError> {
    NAME_PAGE_INDEX_BYTES
        .checked_add(NAME_PAGE_RECORD_FIXED_BYTES)
        .and_then(|bytes| bytes.checked_add(record.children.len() * NAME_PAGE_CHILD_BYTES))
        .and_then(|bytes| bytes.checked_add(record.canonical.len()))
        .ok_or(NamePageError::OffsetOverflow)
}

fn decode_name_subpage_index(encoded: &[u8]) -> Result<(u16, u8), NamePageError> {
    if encoded.len() < NAME_SUBPAGE_BYTES {
        return Err(NamePageError::Length {
            actual: encoded.len(),
            expected: NAME_SUBPAGE_BYTES,
        });
    }
    if &encoded[..8] != NAME_SUBPAGE_INDEX_MAGIC {
        return Err(NamePageError::InvalidMagic);
    }
    let checksum_offset = NAME_SUBPAGE_BYTES - NAME_SUBPAGE_CHECKSUM_BYTES;
    if encoded[checksum_offset..NAME_SUBPAGE_BYTES] != blake2b_256(&encoded[..checksum_offset]) {
        return Err(NamePageError::ChecksumMismatch);
    }
    let mut cursor = 8usize;
    let version = read_u16(encoded, &mut cursor)?;
    if version != NAME_SUBPAGE_VERSION {
        return Err(NamePageError::UnsupportedVersion(version));
    }
    let record_count = read_u16(encoded, &mut cursor)?;
    let subpage_count = read_u8(encoded, &mut cursor)?;
    if read_array::<3>(encoded, &mut cursor)? != [0; 3]
        || record_count == 0
        || subpage_count == 0
        || usize::from(subpage_count) > NAME_SUBPAGE_DATA_COUNT
    {
        return Err(NamePageError::DirectoryInvariant);
    }
    let index_end = NAME_SUBPAGE_INDEX_HEADER_BYTES
        .checked_add(usize::from(record_count) * NAME_SUBPAGE_INDEX_ENTRY_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    if index_end > checksum_offset {
        return Err(NamePageError::DirectoryInvariant);
    }
    let mut expected_local = vec![0u16; usize::from(subpage_count) + 1];
    let mut previous_subpage = 0u8;
    for slot in 0..record_count {
        let (subpage, local_slot) = decode_name_subpage_index_location_unchecked(encoded, slot)?;
        if subpage == 0
            || subpage > subpage_count
            || subpage < previous_subpage
            || u16::from(local_slot) != expected_local[usize::from(subpage)]
        {
            return Err(NamePageError::DirectoryInvariant);
        }
        expected_local[usize::from(subpage)] += 1;
        previous_subpage = subpage;
    }
    if expected_local[1..].contains(&0) {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok((record_count, subpage_count))
}

fn decode_name_subpage_index_location(
    encoded: &[u8],
    record_count: u16,
    subpage_count: u8,
    slot: u16,
) -> Result<(u8, u8), NamePageError> {
    if slot >= record_count {
        return Err(NamePageError::SlotOutOfRange {
            slot,
            records: record_count,
        });
    }
    let (subpage, local_slot) = decode_name_subpage_index_location_unchecked(encoded, slot)?;
    if subpage == 0 || subpage > subpage_count {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok((subpage, local_slot))
}

fn decode_name_subpage_index_location_unchecked(
    encoded: &[u8],
    slot: u16,
) -> Result<(u8, u8), NamePageError> {
    let offset = NAME_SUBPAGE_INDEX_HEADER_BYTES
        .checked_add(usize::from(slot) * NAME_SUBPAGE_INDEX_ENTRY_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    let entry = encoded
        .get(offset..offset + NAME_SUBPAGE_INDEX_ENTRY_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    Ok((entry[0], entry[1]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NameSubpageRecordHeader {
    record_count: u8,
    directory_end: usize,
    payload_end: usize,
}

fn decode_name_subpage_record_header(
    encoded: &[u8],
    expected_subpage: u8,
) -> Result<NameSubpageRecordHeader, NamePageError> {
    let header = parse_name_subpage_record_header(encoded, expected_subpage)?;
    let checksum_offset = NAME_SUBPAGE_BYTES - NAME_SUBPAGE_CHECKSUM_BYTES;
    if encoded[checksum_offset..] != blake2b_256(&encoded[..checksum_offset]) {
        return Err(NamePageError::ChecksumMismatch);
    }
    validate_name_subpage_record_directory(encoded, header)?;
    Ok(header)
}

fn parse_name_subpage_record_header(
    encoded: &[u8],
    expected_subpage: u8,
) -> Result<NameSubpageRecordHeader, NamePageError> {
    if encoded.len() != NAME_SUBPAGE_BYTES {
        return Err(NamePageError::Length {
            actual: encoded.len(),
            expected: NAME_SUBPAGE_BYTES,
        });
    }
    if &encoded[..8] != NAME_SUBPAGE_RECORD_MAGIC {
        return Err(NamePageError::InvalidMagic);
    }
    let checksum_offset = NAME_SUBPAGE_BYTES - NAME_SUBPAGE_CHECKSUM_BYTES;
    let mut cursor = 8usize;
    let version = read_u16(encoded, &mut cursor)?;
    if version != NAME_SUBPAGE_VERSION {
        return Err(NamePageError::UnsupportedVersion(version));
    }
    let subpage = read_u8(encoded, &mut cursor)?;
    let record_count = read_u8(encoded, &mut cursor)?;
    let directory_end = usize::from(read_u16(encoded, &mut cursor)?);
    let payload_end = usize::from(read_u16(encoded, &mut cursor)?);
    if read_u32(encoded, &mut cursor)? != 0 || subpage != expected_subpage || record_count == 0 {
        return Err(NamePageError::DirectoryInvariant);
    }
    let index_end = NAME_SUBPAGE_RECORD_HEADER_BYTES
        .checked_add(usize::from(record_count) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    if index_end > directory_end || directory_end > payload_end || payload_end > checksum_offset {
        return Err(NamePageError::DirectoryInvariant);
    }
    let header = NameSubpageRecordHeader {
        record_count,
        directory_end,
        payload_end,
    };
    Ok(header)
}

fn decode_name_subpage_record_location(
    encoded: &[u8],
    header: NameSubpageRecordHeader,
    slot: u8,
) -> Result<NamePageRecordLocation, NamePageError> {
    if slot >= header.record_count {
        return Err(NamePageError::SlotOutOfRange {
            slot: u16::from(slot),
            records: u16::from(header.record_count),
        });
    }
    let index_end = NAME_SUBPAGE_RECORD_HEADER_BYTES
        .checked_add(usize::from(header.record_count) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    let index_offset = NAME_SUBPAGE_RECORD_HEADER_BYTES
        .checked_add(usize::from(slot) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    let mut index_cursor = index_offset;
    let record_offset = usize::from(read_u16(encoded, &mut index_cursor)?);
    if record_offset < index_end
        || record_offset + NAME_PAGE_RECORD_FIXED_BYTES > header.directory_end
    {
        return Err(NamePageError::DirectoryInvariant);
    }
    let mut cursor = record_offset;
    let key = read_array::<32>(encoded, &mut cursor)?;
    let payload_offset = usize::from(read_u16(encoded, &mut cursor)?);
    let payload_length = usize::from(read_u16(encoded, &mut cursor)?);
    let child_count = usize::from(read_u8(encoded, &mut cursor)?);
    if child_count != 0 && child_count != 2 {
        return Err(NamePageError::ChildCount(child_count));
    }
    if read_u8(encoded, &mut cursor)? != 0 {
        return Err(NamePageError::ReservedBits);
    }
    let record_end = cursor
        .checked_add(child_count * NAME_PAGE_CHILD_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    if record_end > header.directory_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    let mut children = [None; 2];
    for child in children.iter_mut().take(child_count) {
        *child = Some(NamePageAddress::from_raw(read_u64(encoded, &mut cursor)?));
    }
    let canonical_end = payload_offset
        .checked_add(payload_length)
        .ok_or(NamePageError::DirectoryInvariant)?;
    if payload_offset < header.directory_end || canonical_end > header.payload_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok(NamePageRecordLocation {
        key,
        children,
        record_offset,
        record_end,
        payload_offset,
        payload_length,
    })
}

fn validate_name_subpage_record_directory(
    encoded: &[u8],
    header: NameSubpageRecordHeader,
) -> Result<(), NamePageError> {
    let index_end = NAME_SUBPAGE_RECORD_HEADER_BYTES
        .checked_add(usize::from(header.record_count) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut expected_entry = index_end;
    let mut expected_payload = header.directory_end;
    let mut keys = BTreeSet::new();
    for slot in 0..header.record_count {
        let location = decode_name_subpage_record_location(encoded, header, slot)?;
        if location.record_offset != expected_entry || location.payload_offset != expected_payload {
            return Err(NamePageError::DirectoryInvariant);
        }
        if !keys.insert(location.key) {
            return Err(NamePageError::DuplicateKey);
        }
        expected_entry = location.record_end;
        expected_payload = expected_payload
            .checked_add(location.payload_length)
            .ok_or(NamePageError::OffsetOverflow)?;
    }
    if expected_entry != header.directory_end || expected_payload != header.payload_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok(())
}

fn decode_name_subpage_record<'a>(
    encoded: &'a [u8],
    subpage: u8,
    slot: u8,
) -> Result<NamePageRecordRef<'a>, NamePageError> {
    let header = decode_name_subpage_record_header(encoded, subpage)?;
    decode_name_subpage_record_with_header(encoded, header, slot)
}

fn decode_name_subpage_record_prevalidated<'a>(
    encoded: &'a [u8],
    subpage: u8,
    slot: u8,
) -> Result<NamePageRecordRef<'a>, NamePageError> {
    let header = parse_name_subpage_record_header(encoded, subpage)?;
    decode_name_subpage_record_with_header(encoded, header, slot)
}

fn decode_name_subpage_record_with_header(
    encoded: &[u8],
    header: NameSubpageRecordHeader,
    slot: u8,
) -> Result<NamePageRecordRef<'_>, NamePageError> {
    let location = decode_name_subpage_record_location(encoded, header, slot)?;
    let payload_end = location
        .payload_offset
        .checked_add(location.payload_length)
        .ok_or(NamePageError::DirectoryInvariant)?;
    Ok(NamePageRecordRef {
        key: location.key,
        children: location.children,
        canonical: encoded
            .get(location.payload_offset..payload_end)
            .ok_or(NamePageError::DirectoryInvariant)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamePageHeader {
    record_count: u16,
    directory_end: usize,
    payload_end: usize,
}

fn decode_name_page_header(encoded: &[u8]) -> Result<NamePageHeader, NamePageError> {
    if encoded.len() < NAME_PAGE_HEADER_BYTES {
        return Err(NamePageError::Length {
            actual: encoded.len(),
            expected: NAME_PAGE_HEADER_BYTES,
        });
    }
    if &encoded[..8] != NAME_PAGE_MAGIC {
        return Err(NamePageError::InvalidMagic);
    }
    let mut cursor = 8;
    let version = read_u16(encoded, &mut cursor)?;
    if version != NAME_PAGE_VERSION {
        return Err(NamePageError::UnsupportedVersion(version));
    }
    let record_count = read_u16(encoded, &mut cursor)?;
    let directory_end = usize::try_from(read_u32(encoded, &mut cursor)?)
        .map_err(|_| NamePageError::OffsetOverflow)?;
    let payload_end = usize::try_from(read_u32(encoded, &mut cursor)?)
        .map_err(|_| NamePageError::OffsetOverflow)?;
    if read_u32(encoded, &mut cursor)? != 0 {
        return Err(NamePageError::ReservedBits);
    }
    let index_end = NAME_PAGE_HEADER_BYTES
        .checked_add(usize::from(record_count) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    let checksum_offset = NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES;
    if index_end > directory_end || directory_end > payload_end || payload_end > checksum_offset {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok(NamePageHeader {
        record_count,
        directory_end,
        payload_end,
    })
}

fn decode_name_page_record_location(
    encoded: &[u8],
    record_count: u16,
    directory_end: usize,
    payload_end: usize,
    slot: u16,
) -> Result<NamePageRecordLocation, NamePageError> {
    if slot >= record_count {
        return Err(NamePageError::SlotOutOfRange {
            slot,
            records: record_count,
        });
    }
    let index_end = NAME_PAGE_HEADER_BYTES
        .checked_add(usize::from(record_count) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    let index_offset = NAME_PAGE_HEADER_BYTES
        .checked_add(usize::from(slot) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    let mut index_cursor = index_offset;
    let record_offset = usize::from(read_u16(encoded, &mut index_cursor)?);
    if record_offset < index_end || record_offset + NAME_PAGE_RECORD_FIXED_BYTES > directory_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    let mut cursor = record_offset;
    let key = read_array::<32>(encoded, &mut cursor)?;
    let payload_offset = usize::from(read_u16(encoded, &mut cursor)?);
    let payload_length = usize::from(read_u16(encoded, &mut cursor)?);
    let child_count = usize::from(read_u8(encoded, &mut cursor)?);
    if child_count != 0 && child_count != 2 {
        return Err(NamePageError::ChildCount(child_count));
    }
    if read_u8(encoded, &mut cursor)? != 0 {
        return Err(NamePageError::ReservedBits);
    }
    let record_end = cursor
        .checked_add(child_count * NAME_PAGE_CHILD_BYTES)
        .ok_or(NamePageError::DirectoryInvariant)?;
    if record_end > directory_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    let mut children = [None; 2];
    for child in children.iter_mut().take(child_count) {
        *child = Some(NamePageAddress::from_raw(read_u64(encoded, &mut cursor)?));
    }
    let canonical_end = payload_offset
        .checked_add(payload_length)
        .ok_or(NamePageError::DirectoryInvariant)?;
    if payload_offset < directory_end || canonical_end > payload_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok(NamePageRecordLocation {
        key,
        children,
        record_offset,
        record_end,
        payload_offset,
        payload_length,
    })
}

fn validate_name_page_directory(
    encoded: &[u8],
    header: NamePageHeader,
) -> Result<(), NamePageError> {
    let index_end = NAME_PAGE_HEADER_BYTES
        .checked_add(usize::from(header.record_count) * NAME_PAGE_INDEX_BYTES)
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut expected_entry = index_end;
    let mut expected_payload = header.directory_end;
    let mut keys = BTreeSet::new();
    for slot in 0..header.record_count {
        let location = decode_name_page_record_location(
            encoded,
            header.record_count,
            header.directory_end,
            header.payload_end,
            slot,
        )?;
        if location.record_offset != expected_entry || location.payload_offset != expected_payload {
            return Err(NamePageError::DirectoryInvariant);
        }
        if !keys.insert(location.key) {
            return Err(NamePageError::DuplicateKey);
        }
        expected_entry = location.record_end;
        expected_payload = expected_payload
            .checked_add(location.payload_length)
            .ok_or(NamePageError::OffsetOverflow)?;
    }
    if expected_entry != header.directory_end || expected_payload != header.payload_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok(())
}

pub fn decode_name_page(encoded: &[u8]) -> Result<NamePageRef<'_>, NamePageError> {
    if encoded.len() != NAME_PAGE_BYTES {
        return Err(NamePageError::Length {
            actual: encoded.len(),
            expected: NAME_PAGE_BYTES,
        });
    }
    if &encoded[..8] == NAME_SUBPAGE_INDEX_MAGIC {
        let (record_count, subpage_count) =
            decode_name_subpage_index(&encoded[..NAME_SUBPAGE_BYTES])?;
        let mut keys = BTreeSet::new();
        let mut mapped_counts = vec![0u16; usize::from(subpage_count) + 1];
        let mut headers = Vec::with_capacity(usize::from(subpage_count));
        for subpage in 1..=subpage_count {
            let start = usize::from(subpage) * NAME_SUBPAGE_BYTES;
            let end = start + NAME_SUBPAGE_BYTES;
            headers.push(decode_name_subpage_record_header(
                &encoded[start..end],
                subpage,
            )?);
        }
        for slot in 0..record_count {
            let (subpage, local_slot) =
                decode_name_subpage_index_location(encoded, record_count, subpage_count, slot)?;
            let start = usize::from(subpage)
                .checked_mul(NAME_SUBPAGE_BYTES)
                .ok_or(NamePageError::OffsetOverflow)?;
            let end = start
                .checked_add(NAME_SUBPAGE_BYTES)
                .ok_or(NamePageError::OffsetOverflow)?;
            let block = encoded
                .get(start..end)
                .ok_or(NamePageError::DirectoryInvariant)?;
            let header = headers
                .get(usize::from(subpage) - 1)
                .copied()
                .ok_or(NamePageError::DirectoryInvariant)?;
            let record = decode_name_subpage_record_with_header(block, header, local_slot)?;
            if !keys.insert(record.key) {
                return Err(NamePageError::DuplicateKey);
            }
            mapped_counts[usize::from(subpage)] += 1;
        }
        for subpage in 1..=subpage_count {
            let header = headers[usize::from(subpage) - 1];
            if u16::from(header.record_count) != mapped_counts[usize::from(subpage)] {
                return Err(NamePageError::DirectoryInvariant);
            }
        }
        let used_end = (usize::from(subpage_count) + 1) * NAME_SUBPAGE_BYTES;
        if encoded[used_end..].iter().any(|byte| *byte != 0) {
            return Err(NamePageError::DirectoryInvariant);
        }
        return Ok(NamePageRef {
            layout: NamePageRefLayout::Subpages {
                encoded,
                record_count,
                subpage_count,
            },
        });
    }
    if &encoded[..8] != NAME_PAGE_MAGIC {
        return Err(NamePageError::InvalidMagic);
    }
    let checksum_offset = NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES;
    if encoded[checksum_offset..] != blake2b_256(&encoded[..checksum_offset]) {
        return Err(NamePageError::ChecksumMismatch);
    }
    let header = decode_name_page_header(encoded)?;
    let page = NamePageRef {
        layout: NamePageRefLayout::Legacy {
            encoded,
            record_count: header.record_count,
            directory_end: header.directory_end,
            payload_end: header.payload_end,
        },
    };
    validate_name_page_directory(encoded, header)?;
    Ok(page)
}

/// Read and validate only a page's compact record directory. The canonical
/// payload remains content-addressed and is read separately; full-page
/// checksums remain mandatory during publication, recovery, and scrub.
pub fn read_name_page_directory<R: Read + Seek>(
    reader: &mut R,
    page: u32,
) -> Result<NamePageDirectory, NamePageError> {
    let page_offset = u64::from(page)
        .checked_mul(NAME_PAGE_BYTES as u64)
        .ok_or(NamePageError::OffsetOverflow)?;
    reader
        .seek(SeekFrom::Start(page_offset))
        .map_err(name_page_io)?;
    let mut encoded = vec![0u8; 8];
    reader.read_exact(&mut encoded).map_err(name_page_io)?;
    if encoded.as_slice() == NAME_SUBPAGE_INDEX_MAGIC {
        encoded.resize(NAME_SUBPAGE_BYTES, 0);
        reader.read_exact(&mut encoded[8..]).map_err(name_page_io)?;
        let (record_count, subpage_count) = decode_name_subpage_index(&encoded)?;
        return Ok(NamePageDirectory {
            layout: NamePageDirectoryLayout::Subpages {
                encoded_index: encoded,
                record_count,
                subpage_count,
            },
        });
    }
    encoded.resize(NAME_PAGE_HEADER_BYTES, 0);
    reader.read_exact(&mut encoded[8..]).map_err(name_page_io)?;
    let header = decode_name_page_header(&encoded)?;
    encoded.resize(header.directory_end, 0);
    reader
        .read_exact(&mut encoded[NAME_PAGE_HEADER_BYTES..])
        .map_err(name_page_io)?;
    validate_name_page_directory(&encoded, header)?;
    Ok(NamePageDirectory {
        layout: NamePageDirectoryLayout::Legacy {
            encoded,
            record_count: header.record_count,
            directory_end: header.directory_end,
            payload_end: header.payload_end,
        },
    })
}

/// Read one canonical record selected by a validated compact directory.
pub fn read_name_page_record<R: Read + Seek>(
    reader: &mut R,
    page: u32,
    directory: &NamePageDirectory,
    slot: u16,
) -> Result<NamePageRecord, NamePageError> {
    if let Some((subpage, local_slot)) = directory.subpage_location(slot)? {
        let offset = u64::from(page)
            .checked_mul(NAME_PAGE_BYTES as u64)
            .and_then(|page_offset| {
                page_offset.checked_add(u64::from(subpage) * NAME_SUBPAGE_BYTES as u64)
            })
            .ok_or(NamePageError::OffsetOverflow)?;
        reader.seek(SeekFrom::Start(offset)).map_err(name_page_io)?;
        let mut encoded = vec![0u8; NAME_SUBPAGE_BYTES];
        reader.read_exact(&mut encoded).map_err(name_page_io)?;
        let record = decode_name_subpage_record(&encoded, subpage, local_slot)?;
        return Ok(NamePageRecord {
            key: record.key,
            children: record.children.into_iter().flatten().collect(),
            canonical: record.canonical.to_vec(),
        });
    }
    let location = directory.record(slot)?;
    let page_offset = u64::from(page)
        .checked_mul(NAME_PAGE_BYTES as u64)
        .and_then(|offset| offset.checked_add(location.payload_offset as u64))
        .ok_or(NamePageError::OffsetOverflow)?;
    reader
        .seek(SeekFrom::Start(page_offset))
        .map_err(name_page_io)?;
    let mut canonical = vec![0u8; location.payload_length];
    reader.read_exact(&mut canonical).map_err(name_page_io)?;
    Ok(NamePageRecord {
        key: location.key,
        children: location.children.into_iter().flatten().collect(),
        canonical,
    })
}

/// Positioned variant of [`read_name_page_directory`] for concurrent immutable
/// page read-ahead without sharing or mutating a file cursor.
#[cfg(unix)]
pub fn read_name_page_directory_at(
    file: &File,
    page: u32,
) -> Result<NamePageDirectory, NamePageError> {
    let page_offset = u64::from(page)
        .checked_mul(NAME_PAGE_BYTES as u64)
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut encoded = vec![0u8; 8];
    file.read_exact_at(&mut encoded, page_offset)
        .map_err(name_page_io)?;
    if encoded.as_slice() == NAME_SUBPAGE_INDEX_MAGIC {
        encoded.resize(NAME_SUBPAGE_BYTES, 0);
        file.read_exact_at(&mut encoded[8..], page_offset + 8)
            .map_err(name_page_io)?;
        let (record_count, subpage_count) = decode_name_subpage_index(&encoded)?;
        return Ok(NamePageDirectory {
            layout: NamePageDirectoryLayout::Subpages {
                encoded_index: encoded,
                record_count,
                subpage_count,
            },
        });
    }
    encoded.resize(NAME_PAGE_HEADER_BYTES, 0);
    file.read_exact_at(&mut encoded[8..], page_offset + 8)
        .map_err(name_page_io)?;
    let header = decode_name_page_header(&encoded)?;
    encoded.resize(header.directory_end, 0);
    file.read_exact_at(
        &mut encoded[NAME_PAGE_HEADER_BYTES..],
        page_offset
            .checked_add(NAME_PAGE_HEADER_BYTES as u64)
            .ok_or(NamePageError::OffsetOverflow)?,
    )
    .map_err(name_page_io)?;
    validate_name_page_directory(&encoded, header)?;
    Ok(NamePageDirectory {
        layout: NamePageDirectoryLayout::Legacy {
            encoded,
            record_count: header.record_count,
            directory_end: header.directory_end,
            payload_end: header.payload_end,
        },
    })
}

/// Prepare the physical bytes selected by a set of logical record slots using
/// one positioned read for a version-1 covering payload span, or one read per
/// deduplicated and authenticated version-2 record subpage.
#[cfg(unix)]
pub fn prefetch_name_page_records_at(
    file: &File,
    page: u32,
    directory: &NamePageDirectory,
    slots: &[u16],
) -> Result<NamePagePrefetch, NamePageError> {
    let mut selected = BTreeSet::new();
    for slot in slots {
        if let Some((subpage, _)) = directory.subpage_location(*slot)? {
            selected.insert(subpage);
        }
    }
    let page_offset = u64::from(page)
        .checked_mul(NAME_PAGE_BYTES as u64)
        .ok_or(NamePageError::OffsetOverflow)?;
    if selected.is_empty() {
        let mut span_start = usize::MAX;
        let mut span_end = 0usize;
        for slot in slots {
            let location = directory.record(*slot)?;
            span_start = span_start.min(location.payload_offset);
            span_end = span_end.max(
                location
                    .payload_offset
                    .checked_add(location.payload_length)
                    .ok_or(NamePageError::OffsetOverflow)?,
            );
        }
        let legacy_span = if span_start < span_end {
            let mut encoded = vec![0u8; span_end - span_start];
            file.read_exact_at(
                &mut encoded,
                page_offset
                    .checked_add(span_start as u64)
                    .ok_or(NamePageError::OffsetOverflow)?,
            )
            .map_err(name_page_io)?;
            Some(NamePageLegacySpan {
                start: span_start,
                encoded,
            })
        } else {
            None
        };
        return Ok(NamePagePrefetch {
            page,
            legacy_span,
            subpages: Vec::new(),
        });
    }
    let subpages = selected
        .into_iter()
        .map(|subpage| {
            let offset = page_offset
                .checked_add(u64::from(subpage) * NAME_SUBPAGE_BYTES as u64)
                .ok_or(NamePageError::OffsetOverflow)?;
            let mut encoded = vec![0u8; NAME_SUBPAGE_BYTES];
            file.read_exact_at(&mut encoded, offset)
                .map_err(name_page_io)?;
            decode_name_subpage_record_header(&encoded, subpage)?;
            Ok(NamePageSubpage { subpage, encoded })
        })
        .collect::<Result<Vec<_>, NamePageError>>()?;
    Ok(NamePagePrefetch {
        page,
        legacy_span: None,
        subpages,
    })
}

/// Positioned variant of [`read_name_page_record`] for immutable page
/// traversal that can overlap independent physical reads.
#[cfg(unix)]
pub fn read_name_page_record_at(
    file: &File,
    page: u32,
    directory: &NamePageDirectory,
    slot: u16,
) -> Result<NamePageRecord, NamePageError> {
    if let Some((subpage, local_slot)) = directory.subpage_location(slot)? {
        let offset = u64::from(page)
            .checked_mul(NAME_PAGE_BYTES as u64)
            .and_then(|page_offset| {
                page_offset.checked_add(u64::from(subpage) * NAME_SUBPAGE_BYTES as u64)
            })
            .ok_or(NamePageError::OffsetOverflow)?;
        let mut encoded = vec![0u8; NAME_SUBPAGE_BYTES];
        file.read_exact_at(&mut encoded, offset)
            .map_err(name_page_io)?;
        let record = decode_name_subpage_record(&encoded, subpage, local_slot)?;
        return Ok(NamePageRecord {
            key: record.key,
            children: record.children.into_iter().flatten().collect(),
            canonical: record.canonical.to_vec(),
        });
    }
    let location = directory.record(slot)?;
    let offset = u64::from(page)
        .checked_mul(NAME_PAGE_BYTES as u64)
        .and_then(|page_offset| page_offset.checked_add(location.payload_offset as u64))
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut canonical = vec![0u8; location.payload_length];
    file.read_exact_at(&mut canonical, offset)
        .map_err(name_page_io)?;
    Ok(NamePageRecord {
        key: location.key,
        children: location.children.into_iter().flatten().collect(),
        canonical,
    })
}

pub fn plan_name_page_reads<I>(
    generation: u64,
    addresses: I,
) -> Result<Vec<SegmentPageRead>, NamePageError>
where
    I: IntoIterator<Item = NamePageAddress>,
{
    let mut reads = BTreeSet::new();
    for address in addresses {
        let offset = u64::from(address.page())
            .checked_mul(NAME_PAGE_BYTES as u64)
            .ok_or(NamePageError::OffsetOverflow)?;
        reads.insert(SegmentPageRead {
            generation,
            segment: address.segment(),
            offset,
            length: NAME_PAGE_BYTES as u64,
        });
    }
    Ok(reads.into_iter().collect())
}

/// Full checksum audit for an immutable page file. Normal clean startup only
/// validates the last committed page and then verifies nodes on demand or via
/// retained-root traversal; qualification and compaction use this complete
/// scan.
pub fn inspect_name_page_file(
    path: impl AsRef<Path>,
) -> Result<NamePageFileInspection, NamePageError> {
    let mut file = File::open(path).map_err(name_page_io)?;
    let file_bytes = file.metadata().map_err(name_page_io)?.len();
    let complete_pages = file_bytes / NAME_PAGE_BYTES as u64;
    let valid_bytes = complete_pages
        .checked_mul(NAME_PAGE_BYTES as u64)
        .ok_or(NamePageError::OffsetOverflow)?;
    let mut encoded = vec![0u8; NAME_PAGE_BYTES];
    for _ in 0..complete_pages {
        file.read_exact(&mut encoded).map_err(name_page_io)?;
        decode_name_page(&encoded)?;
    }
    Ok(NamePageFileInspection {
        pages: complete_pages,
        valid_bytes,
        file_bytes,
        torn_tail: valid_bytes != file_bytes,
    })
}

/// Recover from a crash by validating the final authoritative page and
/// discarding any complete or partial pages beyond the manifest tail.
pub fn truncate_name_pages_to_committed_tail(
    path: impl AsRef<Path>,
    committed_bytes: u64,
) -> Result<(), NamePageError> {
    if !committed_bytes.is_multiple_of(NAME_PAGE_BYTES as u64) {
        return Err(NamePageError::CommittedTailNotBoundary {
            committed: committed_bytes,
        });
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(name_page_io)?;
    let actual = file.metadata().map_err(name_page_io)?.len();
    if committed_bytes > actual {
        return Err(NamePageError::UncommittedTail {
            committed: committed_bytes,
            actual,
        });
    }
    validate_last_committed_page(&mut file, committed_bytes)?;
    file.set_len(committed_bytes).map_err(name_page_io)?;
    file.sync_all().map_err(name_page_io)
}

fn validate_last_committed_page(
    file: &mut File,
    committed_bytes: u64,
) -> Result<(), NamePageError> {
    if committed_bytes == 0 {
        return Ok(());
    }
    if !committed_bytes.is_multiple_of(NAME_PAGE_BYTES as u64) {
        return Err(NamePageError::CommittedTailNotBoundary {
            committed: committed_bytes,
        });
    }
    let offset = committed_bytes
        .checked_sub(NAME_PAGE_BYTES as u64)
        .ok_or(NamePageError::OffsetOverflow)?;
    file.seek(SeekFrom::Start(offset)).map_err(name_page_io)?;
    let mut encoded = vec![0u8; NAME_PAGE_BYTES];
    file.read_exact(&mut encoded).map_err(name_page_io)?;
    decode_name_page(&encoded)?;
    Ok(())
}

fn name_page_io(error: std::io::Error) -> NamePageError {
    NamePageError::Io(error.to_string())
}

fn write_bytes(encoded: &mut [u8], cursor: &mut usize, value: &[u8]) -> Result<(), NamePageError> {
    let end = cursor
        .checked_add(value.len())
        .ok_or(NamePageError::OffsetOverflow)?;
    let target = encoded
        .get_mut(*cursor..end)
        .ok_or(NamePageError::DirectoryInvariant)?;
    target.copy_from_slice(value);
    *cursor = end;
    Ok(())
}

fn read_u8(encoded: &[u8], cursor: &mut usize) -> Result<u8, NamePageError> {
    Ok(read_array::<1>(encoded, cursor)?[0])
}

fn read_u16(encoded: &[u8], cursor: &mut usize) -> Result<u16, NamePageError> {
    Ok(u16::from_le_bytes(read_array(encoded, cursor)?))
}

fn read_u32(encoded: &[u8], cursor: &mut usize) -> Result<u32, NamePageError> {
    Ok(u32::from_le_bytes(read_array(encoded, cursor)?))
}

fn read_u64(encoded: &[u8], cursor: &mut usize) -> Result<u64, NamePageError> {
    Ok(u64::from_le_bytes(read_array(encoded, cursor)?))
}

fn read_array<const N: usize>(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], NamePageError> {
    let end = cursor.checked_add(N).ok_or(NamePageError::OffsetOverflow)?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or(NamePageError::DirectoryInvariant)?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| NamePageError::DirectoryInvariant)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    fn address(page: u32, slot: u16) -> NamePageAddress {
        NamePageAddress::new(3, page, slot).expect("address")
    }

    fn leaf(key: u8, size: usize) -> NamePageRecord {
        NamePageRecord {
            key: [key; 32],
            children: Vec::new(),
            canonical: vec![key; size],
        }
    }

    fn test_file() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hsrd-name-pages-{}-{}",
            std::process::id(),
            NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn compact_address_round_trips_all_fields_and_checks_bounds() {
        let address = NamePageAddress::new(0x00ab_cdef, 0x0012_3456, 0x789a).expect("address");
        assert_eq!(address.segment(), 0x00ab_cdef);
        assert_eq!(address.page(), 0x0012_3456);
        assert_eq!(address.slot(), 0x789a);
        assert_eq!(NamePageAddress::from_raw(address.raw()), address);
        assert!(matches!(
            NamePageAddress::new(1 << 24, 0, 0),
            Err(NamePageError::AddressFieldOverflow {
                field: "segment",
                ..
            })
        ));
    }

    #[test]
    fn packed_page_round_trips_leaf_and_internal_without_payload_copy() {
        let leaf = leaf(0x11, 70);
        let internal = NamePageRecord {
            key: [0x22; 32],
            children: vec![address(7, 4), address(8, 5)],
            canonical: vec![0x33; 74],
        };
        let encoded = encode_name_page(&[leaf.clone(), internal.clone()]).expect("encode");
        let page = decode_name_page(&encoded).expect("decode");
        assert_eq!(page.record_count(), 2);

        let actual_leaf = page.record(0).expect("leaf");
        assert_eq!(actual_leaf.key, leaf.key);
        assert_eq!(actual_leaf.children, [None, None]);
        assert_eq!(actual_leaf.canonical, leaf.canonical);

        let actual_internal = page.record(1).expect("internal");
        assert_eq!(actual_internal.key, internal.key);
        assert_eq!(
            actual_internal.children,
            [Some(internal.children[0]), Some(internal.children[1])]
        );
        assert_eq!(actual_internal.canonical, internal.canonical);
        assert!(matches!(
            page.record(2),
            Err(NamePageError::SlotOutOfRange {
                slot: 2,
                records: 2
            })
        ));
    }

    #[test]
    fn compact_directory_reads_selected_records_without_loading_a_full_page() {
        let leaf = leaf(0x31, 70);
        let internal = NamePageRecord {
            key: [0x32; 32],
            children: vec![address(9, 6), address(9, 7)],
            canonical: vec![0x33; 74],
        };
        let encoded = encode_name_page(&[leaf.clone(), internal.clone()]).expect("encode");
        let mut reader = std::io::Cursor::new(encoded.clone());
        let directory = read_name_page_directory(&mut reader, 0).expect("read directory");
        assert_eq!(directory.record_count(), 2);
        assert!(directory.resident_bytes() < NAME_PAGE_BYTES);
        assert_eq!(
            read_name_page_record(&mut reader, 0, &directory, 0).expect("read leaf"),
            leaf
        );
        assert_eq!(
            read_name_page_record(&mut reader, 0, &directory, 1).expect("read internal"),
            internal
        );
        assert!(matches!(
            read_name_page_record(&mut reader, 0, &directory, 2),
            Err(NamePageError::SlotOutOfRange {
                slot: 2,
                records: 2
            })
        ));

        #[cfg(unix)]
        {
            let path = test_file();
            fs::write(&path, encoded).expect("write positioned fixture");
            let file = File::open(&path).expect("open positioned fixture");
            let positioned =
                read_name_page_directory_at(&file, 0).expect("read positioned directory");
            assert_eq!(positioned, directory);
            assert_eq!(
                read_name_page_record_at(&file, 0, &positioned, 1).expect("read positioned record"),
                internal
            );
            let prefetched = prefetch_name_page_records_at(&file, 0, &positioned, &[0, 1])
                .expect("prefetch legacy payload span");
            assert!(prefetched.legacy_span.is_some());
            let mut cached =
                PositionedNamePageReader::with_prefetched(&file, 0, &positioned, prefetched)
                    .expect("positioned legacy reader with prefetch");
            assert_eq!(cached.record(0).expect("cached leaf"), leaf);
            assert_eq!(cached.record(1).expect("cached internal"), internal);
            let trailing_prefetch = prefetch_name_page_records_at(&file, 0, &positioned, &[1])
                .expect("prefetch trailing legacy payload");
            let mut fallback =
                PositionedNamePageReader::with_prefetched(&file, 0, &positioned, trailing_prefetch)
                    .expect("positioned legacy reader with trailing prefetch");
            assert_eq!(fallback.record(0).expect("record before cached span"), leaf);
            assert_eq!(fallback.record(1).expect("record in cached span"), internal);
            fs::remove_file(path).expect("remove positioned fixture");
        }
    }

    #[test]
    fn packed_page_checksum_covers_records_directory_and_unused_tail() {
        let mut encoded = encode_name_page(&[leaf(0x44, 70)]).expect("encode");
        encoded[NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES - 1] ^= 1;
        assert_eq!(
            decode_name_page(&encoded),
            Err(NamePageError::ChecksumMismatch)
        );
    }

    #[test]
    fn packed_page_rejects_oversubscription_and_malformed_arity() {
        assert!(matches!(
            encode_name_page(&[leaf(0x55, NAME_PAGE_BYTES)]),
            Err(NamePageError::RecordTooLarge { .. }) | Err(NamePageError::PageFull { .. })
        ));
        let malformed = NamePageRecord {
            key: [0x66; 32],
            children: vec![address(1, 1)],
            canonical: vec![0x66; 70],
        };
        assert_eq!(
            encode_name_page(&[malformed]),
            Err(NamePageError::ChildCount(1))
        );
        assert_eq!(
            encode_name_page(&[leaf(0x77, 70), leaf(0x77, 70)]),
            Err(NamePageError::DuplicateKey)
        );
    }

    #[test]
    fn packed_page_rejects_noncanonical_directory_even_with_a_valid_checksum() {
        let mut encoded = encode_name_page(&[leaf(0x81, 70), leaf(0x82, 70)]).expect("encode");
        let first_index = NAME_PAGE_HEADER_BYTES;
        let first_entry = u16::from_le_bytes(
            encoded[first_index..first_index + 2]
                .try_into()
                .expect("index"),
        );
        encoded[first_index + 2..first_index + 4].copy_from_slice(&first_entry.to_le_bytes());
        let checksum_offset = NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES;
        let checksum = blake2b_256(&encoded[..checksum_offset]);
        encoded[checksum_offset..].copy_from_slice(&checksum);
        assert_eq!(
            decode_name_page(&encoded),
            Err(NamePageError::DirectoryInvariant)
        );
    }

    #[test]
    fn one_page_packs_five_hundred_average_internal_records() {
        let records = (0u16..500)
            .map(|index| NamePageRecord {
                key: {
                    let mut key = [0u8; 32];
                    key[..2].copy_from_slice(&index.to_le_bytes());
                    key
                },
                children: vec![address(1, index), address(2, index)],
                canonical: vec![0x91; 70],
            })
            .collect::<Vec<_>>();
        let encoded = encode_name_page(&records).expect("pack 500 records");
        assert_eq!(
            decode_name_page(&encoded).expect("decode").record_count(),
            500
        );
    }

    #[test]
    fn incremental_builder_assigns_stable_slots_and_returns_full_record() {
        let mut builder = NamePageBuilder::new(12, 34).expect("builder");
        let mut rejected = None;
        for index in 0u16..600 {
            let record = NamePageRecord {
                key: {
                    let mut key = [0u8; 32];
                    key[..2].copy_from_slice(&index.to_le_bytes());
                    key
                },
                children: vec![address(1, index), address(2, index)],
                canonical: vec![0xa3; 70],
            };
            match builder.push(record).expect("push") {
                NamePagePush::Added(actual) => {
                    assert_eq!(
                        actual,
                        NamePageAddress::new(12, 34, index).expect("expected")
                    );
                }
                NamePagePush::Full(record) => {
                    rejected = Some(record);
                    break;
                }
            }
        }
        assert_eq!(builder.records().len(), 480);
        assert_eq!(
            rejected.expect("full record").key[..2],
            480u16.to_le_bytes()
        );
        let encoded = builder.finish().expect("finish");
        assert_eq!(
            decode_name_page(&encoded).expect("decode").record_count(),
            480
        );
    }

    #[test]
    fn authenticated_subpages_bound_hot_reads_and_cache_shared_blocks() {
        let records = (0u16..96)
            .map(|index| NamePageRecord {
                key: {
                    let mut key = [0u8; 32];
                    key[..2].copy_from_slice(&index.to_le_bytes());
                    key
                },
                children: vec![address(1, index), address(2, index)],
                canonical: vec![(index & 0xff) as u8; 70],
            })
            .collect::<Vec<_>>();
        let encoded = encode_name_subpage_page(&records).expect("encode subpages");
        let page = decode_name_page(&encoded).expect("decode subpages");
        assert_eq!(page.record_count(), 96);
        for slot in [0u16, 31, 32, 63, 64, 95] {
            let actual = page.record(slot).expect("subpage record");
            assert_eq!(actual.key, records[usize::from(slot)].key);
            assert_eq!(actual.canonical, records[usize::from(slot)].canonical);
        }

        let mut cursor = std::io::Cursor::new(encoded.clone());
        let directory = read_name_page_directory(&mut cursor, 0).expect("subpage index");
        assert_eq!(directory.record_count(), 96);
        assert_eq!(directory.resident_bytes(), NAME_SUBPAGE_BYTES);
        assert_eq!(
            read_name_page_record(&mut cursor, 0, &directory, 63).expect("selected subpage record"),
            records[63]
        );

        #[cfg(unix)]
        {
            let path = test_file();
            fs::write(&path, encoded).expect("write subpage fixture");
            let file = File::open(&path).expect("open subpage fixture");
            let positioned =
                read_name_page_directory_at(&file, 0).expect("positioned subpage index");
            let prefetched = prefetch_name_page_records_at(&file, 0, &positioned, &[32, 63])
                .expect("prefetch shared subpage");
            assert_eq!(prefetched.subpages.len(), 1);
            let mut reader =
                PositionedNamePageReader::with_prefetched(&file, 0, &positioned, prefetched)
                    .expect("positioned reader with prefetch");
            assert_eq!(reader.cached_subpages(), 1);
            assert_eq!(reader.record(32).expect("first shared record"), records[32]);
            assert_eq!(
                reader.record(63).expect("second shared record"),
                records[63]
            );
            assert_eq!(reader.cached_subpages(), 1);
            assert_eq!(reader.record(64).expect("next subpage record"), records[64]);
            assert_eq!(reader.cached_subpages(), 2);
            fs::remove_file(path).expect("remove subpage fixture");
        }
    }

    #[test]
    fn authenticated_subpage_corruption_fails_before_record_use() {
        let records = (0u8..40).map(|key| leaf(key, 70)).collect::<Vec<_>>();
        let mut encoded = encode_name_subpage_page(&records).expect("encode subpages");
        encoded[NAME_SUBPAGE_BYTES + 200] ^= 1;
        assert_eq!(
            decode_name_page(&encoded),
            Err(NamePageError::ChecksumMismatch)
        );
        let mut cursor = std::io::Cursor::new(encoded);
        let directory = read_name_page_directory(&mut cursor, 0).expect("intact index");
        assert_eq!(
            read_name_page_record(&mut cursor, 0, &directory, 0),
            Err(NamePageError::ChecksumMismatch)
        );
    }

    #[test]
    fn name_page_read_plan_coalesces_addresses_on_the_same_page() {
        let reads = plan_name_page_reads(19, [address(4, 1), address(4, 200), address(7, 3)])
            .expect("plan");
        assert_eq!(
            reads,
            vec![
                SegmentPageRead {
                    generation: 19,
                    segment: 3,
                    offset: 4 * NAME_PAGE_BYTES as u64,
                    length: NAME_PAGE_BYTES as u64,
                },
                SegmentPageRead {
                    generation: 19,
                    segment: 3,
                    offset: 7 * NAME_PAGE_BYTES as u64,
                    length: NAME_PAGE_BYTES as u64,
                },
            ]
        );
    }

    #[test]
    fn page_appender_publishes_only_the_synced_manifest_tail() {
        let path = test_file();
        let mut appender = NamePageAppender::create_new(&path, 23, 6).expect("create");
        let records = vec![leaf(0xa1, 70), leaf(0xa2, 70)];
        let addresses = appender.append(&records).expect("append");
        assert_eq!(
            addresses,
            vec![
                NamePageAddress::new(6, 0, 0).expect("first"),
                NamePageAddress::new(6, 0, 1).expect("second"),
            ]
        );
        let manifest = appender.sync_data().expect("sync");
        assert_eq!(manifest.durable_bytes, NAME_PAGE_BYTES as u64);
        drop(appender);

        let inspection = inspect_name_page_file(&path).expect("inspect");
        assert_eq!(inspection.pages, 1);
        assert!(!inspection.torn_tail);
        let reopened = NamePageAppender::open_at_committed_tail(&path, manifest).expect("reopen");
        assert_eq!(reopened.next_page(), 1);
        drop(reopened);
        fs::remove_file(path).expect("remove test pages");
    }

    #[test]
    fn page_recovery_discards_complete_and_partial_uncommitted_pages() {
        let path = test_file();
        let mut appender = NamePageAppender::create_new(&path, 29, 8).expect("create");
        appender.append(&[leaf(0xb1, 70)]).expect("committed");
        let manifest = appender.sync_data().expect("sync");
        appender.append(&[leaf(0xb2, 70)]).expect("orphan");
        drop(appender);

        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open partial tail");
        file.write_all(&[0u8; 17]).expect("partial tail");
        file.sync_all().expect("sync partial tail");
        drop(file);
        let before = inspect_name_page_file(&path).expect("inspect before");
        assert_eq!(before.pages, 2);
        assert!(before.torn_tail);
        assert!(matches!(
            NamePageAppender::open_at_committed_tail(&path, manifest),
            Err(NamePageError::UncommittedTail { .. })
        ));

        truncate_name_pages_to_committed_tail(&path, manifest.durable_bytes).expect("recover");
        let after = inspect_name_page_file(&path).expect("inspect after");
        assert_eq!(after.pages, 1);
        assert!(!after.torn_tail);
        NamePageAppender::open_at_committed_tail(&path, manifest).expect("open recovered");
        fs::remove_file(path).expect("remove test pages");
    }

    #[test]
    fn page_recovery_rejects_non_page_manifest_boundary() {
        let path = test_file();
        let appender = NamePageAppender::create_new(&path, 31, 9).expect("create");
        drop(appender);
        assert_eq!(
            truncate_name_pages_to_committed_tail(&path, 1),
            Err(NamePageError::CommittedTailNotBoundary { committed: 1 })
        );
        fs::remove_file(path).expect("remove test pages");
    }
}
