use std::{
    collections::BTreeSet,
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
    encoded: Vec<u8>,
    record_count: u16,
    directory_end: usize,
    payload_end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamePageRef<'a> {
    encoded: &'a [u8],
    record_count: u16,
    directory_end: usize,
    payload_end: usize,
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
    record_bytes: usize,
}

impl NamePageBuilder {
    pub fn new(segment: u32, page: u32) -> Result<Self, NamePageError> {
        NamePageAddress::new(segment, page, 0)?;
        Ok(Self {
            segment,
            page,
            records: Vec::new(),
            keys: BTreeSet::new(),
            record_bytes: 0,
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
        let next_record_bytes = self
            .record_bytes
            .checked_add(added_bytes)
            .ok_or(NamePageError::OffsetOverflow)?;
        let required = NAME_PAGE_HEADER_BYTES
            .checked_add(NAME_PAGE_CHECKSUM_BYTES)
            .and_then(|bytes| bytes.checked_add(next_record_bytes))
            .ok_or(NamePageError::OffsetOverflow)?;
        if required > NAME_PAGE_BYTES {
            if self.records.is_empty() {
                return Err(NamePageError::PageFull {
                    required,
                    capacity: NAME_PAGE_BYTES,
                });
            }
            return Ok(NamePagePush::Full(record));
        }
        let slot = u16::try_from(self.records.len())
            .map_err(|_| NamePageError::TooManyRecords(self.records.len()))?;
        let address = NamePageAddress::new(self.segment, self.page, slot)?;
        self.keys.insert(record.key);
        self.records.push(record);
        self.record_bytes = next_record_bytes;
        Ok(NamePagePush::Added(address))
    }

    pub fn finish(self) -> Result<Vec<u8>, NamePageError> {
        if self.records.is_empty() {
            return Err(NamePageError::EmptyPage);
        }
        encode_name_page(&self.records)
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
        let encoded = encode_name_page(records)?;
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
        self.record_count
    }

    pub fn record(self, slot: u16) -> Result<NamePageRecordRef<'a>, NamePageError> {
        let location = decode_name_page_record_location(
            self.encoded,
            self.record_count,
            self.directory_end,
            self.payload_end,
            slot,
        )?;
        let payload_end = location
            .payload_offset
            .checked_add(location.payload_length)
            .ok_or(NamePageError::DirectoryInvariant)?;
        let canonical = self
            .encoded
            .get(location.payload_offset..payload_end)
            .ok_or(NamePageError::DirectoryInvariant)?;
        Ok(NamePageRecordRef {
            key: location.key,
            children: location.children,
            canonical,
        })
    }
}

impl NamePageDirectory {
    pub const fn record_count(&self) -> u16 {
        self.record_count
    }

    pub fn record(&self, slot: u16) -> Result<NamePageRecordLocation, NamePageError> {
        decode_name_page_record_location(
            &self.encoded,
            self.record_count,
            self.directory_end,
            self.payload_end,
            slot,
        )
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
    if &encoded[..8] != NAME_PAGE_MAGIC {
        return Err(NamePageError::InvalidMagic);
    }
    let checksum_offset = NAME_PAGE_BYTES - NAME_PAGE_CHECKSUM_BYTES;
    if encoded[checksum_offset..] != blake2b_256(&encoded[..checksum_offset]) {
        return Err(NamePageError::ChecksumMismatch);
    }
    let header = decode_name_page_header(encoded)?;
    let page = NamePageRef {
        encoded,
        record_count: header.record_count,
        directory_end: header.directory_end,
        payload_end: header.payload_end,
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
    let mut encoded = vec![0u8; NAME_PAGE_HEADER_BYTES];
    reader.read_exact(&mut encoded).map_err(name_page_io)?;
    let header = decode_name_page_header(&encoded)?;
    encoded.resize(header.directory_end, 0);
    reader
        .read_exact(&mut encoded[NAME_PAGE_HEADER_BYTES..])
        .map_err(name_page_io)?;
    validate_name_page_directory(&encoded, header)?;
    Ok(NamePageDirectory {
        encoded,
        record_count: header.record_count,
        directory_end: header.directory_end,
        payload_end: header.payload_end,
    })
}

/// Read one canonical record selected by a validated compact directory.
pub fn read_name_page_record<R: Read + Seek>(
    reader: &mut R,
    page: u32,
    directory: &NamePageDirectory,
    slot: u16,
) -> Result<NamePageRecord, NamePageError> {
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
        let mut reader = std::io::Cursor::new(encoded);
        let directory = read_name_page_directory(&mut reader, 0).expect("read directory");
        assert_eq!(directory.record_count(), 2);
        assert!(directory.encoded.len() < NAME_PAGE_BYTES);
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
        assert_eq!(builder.records().len(), 519);
        assert_eq!(
            rejected.expect("full record").key[..2],
            519u16.to_le_bytes()
        );
        let encoded = builder.finish().expect("finish");
        assert_eq!(
            decode_name_page(&encoded).expect("decode").record_count(),
            519
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
