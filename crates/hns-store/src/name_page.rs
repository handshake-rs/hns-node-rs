use std::collections::BTreeSet;

use hns_primitives::blake2b_256;
use thiserror::Error;

use crate::SegmentPageRead;

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
pub struct NamePageRef<'a> {
    encoded: &'a [u8],
    record_count: u16,
    directory_end: usize,
    payload_end: usize,
}

impl<'a> NamePageRef<'a> {
    pub const fn record_count(self) -> u16 {
        self.record_count
    }

    pub fn record(self, slot: u16) -> Result<NamePageRecordRef<'a>, NamePageError> {
        if slot >= self.record_count {
            return Err(NamePageError::SlotOutOfRange {
                slot,
                records: self.record_count,
            });
        }
        let index_offset = NAME_PAGE_HEADER_BYTES
            .checked_add(usize::from(slot) * NAME_PAGE_INDEX_BYTES)
            .ok_or(NamePageError::DirectoryInvariant)?;
        let mut index_cursor = index_offset;
        let record_offset = usize::from(read_u16(self.encoded, &mut index_cursor)?);
        if record_offset < NAME_PAGE_HEADER_BYTES
            || record_offset + NAME_PAGE_RECORD_FIXED_BYTES > self.directory_end
        {
            return Err(NamePageError::DirectoryInvariant);
        }
        let mut cursor = record_offset;
        let key = read_array::<32>(self.encoded, &mut cursor)?;
        let payload_offset = usize::from(read_u16(self.encoded, &mut cursor)?);
        let payload_length = usize::from(read_u16(self.encoded, &mut cursor)?);
        let child_count = usize::from(read_u8(self.encoded, &mut cursor)?);
        if child_count != 0 && child_count != 2 {
            return Err(NamePageError::ChildCount(child_count));
        }
        if read_u8(self.encoded, &mut cursor)? != 0 {
            return Err(NamePageError::ReservedBits);
        }
        let children_end = cursor
            .checked_add(child_count * NAME_PAGE_CHILD_BYTES)
            .ok_or(NamePageError::DirectoryInvariant)?;
        if children_end > self.directory_end {
            return Err(NamePageError::DirectoryInvariant);
        }
        let mut children = [None; 2];
        for child in children.iter_mut().take(child_count) {
            *child = Some(NamePageAddress::from_raw(read_u64(
                self.encoded,
                &mut cursor,
            )?));
        }
        let payload_end = payload_offset
            .checked_add(payload_length)
            .ok_or(NamePageError::DirectoryInvariant)?;
        if payload_offset < self.directory_end || payload_end > self.payload_end {
            return Err(NamePageError::DirectoryInvariant);
        }
        let canonical = self
            .encoded
            .get(payload_offset..payload_end)
            .ok_or(NamePageError::DirectoryInvariant)?;
        Ok(NamePageRecordRef {
            key,
            children,
            canonical,
        })
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
    if index_end > directory_end || directory_end > payload_end || payload_end > checksum_offset {
        return Err(NamePageError::DirectoryInvariant);
    }
    let page = NamePageRef {
        encoded,
        record_count,
        directory_end,
        payload_end,
    };
    let mut expected_entry = index_end;
    let mut expected_payload = directory_end;
    let mut keys = BTreeSet::new();
    for slot in 0..record_count {
        let index_offset = NAME_PAGE_HEADER_BYTES + usize::from(slot) * NAME_PAGE_INDEX_BYTES;
        let mut index_cursor = index_offset;
        let record_offset = usize::from(read_u16(encoded, &mut index_cursor)?);
        if record_offset != expected_entry {
            return Err(NamePageError::DirectoryInvariant);
        }
        let mut entry_cursor = record_offset;
        let key = read_array::<32>(encoded, &mut entry_cursor)?;
        if !keys.insert(key) {
            return Err(NamePageError::DuplicateKey);
        }
        let payload_offset = usize::from(read_u16(encoded, &mut entry_cursor)?);
        let payload_length = usize::from(read_u16(encoded, &mut entry_cursor)?);
        let child_count = usize::from(read_u8(encoded, &mut entry_cursor)?);
        if child_count != 0 && child_count != 2 {
            return Err(NamePageError::ChildCount(child_count));
        }
        if read_u8(encoded, &mut entry_cursor)? != 0 {
            return Err(NamePageError::ReservedBits);
        }
        entry_cursor = entry_cursor
            .checked_add(child_count * NAME_PAGE_CHILD_BYTES)
            .ok_or(NamePageError::OffsetOverflow)?;
        if entry_cursor > directory_end || payload_offset != expected_payload {
            return Err(NamePageError::DirectoryInvariant);
        }
        expected_entry = entry_cursor;
        expected_payload = expected_payload
            .checked_add(payload_length)
            .ok_or(NamePageError::OffsetOverflow)?;
        page.record(slot)?;
    }
    if expected_entry != directory_end || expected_payload != payload_end {
        return Err(NamePageError::DirectoryInvariant);
    }
    Ok(page)
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
    use super::*;

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
}
