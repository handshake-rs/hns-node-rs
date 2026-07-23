use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::Path,
};

use hns_primitives::blake2b_256;
use thiserror::Error;

const SEGMENT_FRAME_MAGIC: &[u8; 8] = b"HSGSEG01";
const SEGMENT_FRAME_FIXED_BYTES: usize = 8 + 4 + 1 + 1 + 2 + 32 + 4;
const SEGMENT_FRAME_CHECKSUM_BYTES: usize = 32;
const SEGMENT_LOCATOR_BYTES: usize = 8 + 4 + 8 + 4;
const SEGMENT_MANIFEST_MAGIC: &[u8; 8] = b"HSGMAN01";
const SEGMENT_MANIFEST_VERSION: u32 = 1;
const SEGMENT_MANIFEST_BODY_BYTES: usize = 8 + 4 + 8;
const SEGMENT_MANIFEST_BYTES: usize = 8 + 4 + SEGMENT_MANIFEST_BODY_BYTES + 32;
pub const SEGMENT_MAX_HINTS: usize = 2;
const MAX_SEGMENT_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const SEGMENT_PAGE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SegmentKind {
    Block = 1,
    Undo = 2,
}

impl TryFrom<u8> for SegmentKind {
    type Error = SegmentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Block),
            2 => Ok(Self::Undo),
            other => Err(SegmentError::UnknownKind(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SegmentLocator {
    pub generation: u64,
    pub segment: u32,
    pub offset: u64,
    pub frame_length: u32,
}

impl SegmentLocator {
    fn encode_into(self, encoded: &mut Vec<u8>) {
        encoded.extend_from_slice(&self.generation.to_le_bytes());
        encoded.extend_from_slice(&self.segment.to_le_bytes());
        encoded.extend_from_slice(&self.offset.to_le_bytes());
        encoded.extend_from_slice(&self.frame_length.to_le_bytes());
    }

    fn decode(encoded: &[u8], cursor: &mut usize) -> Result<Self, SegmentError> {
        Ok(Self {
            generation: read_u64(encoded, cursor)?,
            segment: read_u32(encoded, cursor)?,
            offset: read_u64(encoded, cursor)?,
            frame_length: read_u32(encoded, cursor)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentRecord {
    pub kind: SegmentKind,
    /// Consensus identity of `payload`: an Urkel node root, block hash, or
    /// block hash owning an undo record. Higher layers rederive and verify it.
    pub key: [u8; 32],
    /// Local child locations are acceleration hints, not authenticated data.
    /// A caller must hash the loaded child's canonical payload and compare it
    /// with the child root encoded in its authenticated parent.
    pub hints: Vec<SegmentLocator>,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentRecordRef<'a> {
    pub kind: SegmentKind,
    pub key: [u8; 32],
    pub hints: [Option<SegmentLocator>; SEGMENT_MAX_HINTS],
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SegmentPageRead {
    pub generation: u64,
    pub segment: u32,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentScan {
    pub records: Vec<(SegmentLocator, SegmentRecord)>,
    pub valid_bytes: u64,
    pub torn_tail: bool,
}

/// The RocksDB state batch stores this authoritative durable tail beside root
/// locators. Segment bytes are synced first. Bytes beyond `durable_bytes` are
/// therefore unreachable crash residue and may be truncated during recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentManifest {
    pub generation: u64,
    pub active_segment: u32,
    pub durable_bytes: u64,
}

impl SegmentManifest {
    pub fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(SEGMENT_MANIFEST_BYTES);
        encoded.extend_from_slice(SEGMENT_MANIFEST_MAGIC);
        encoded.extend_from_slice(&SEGMENT_MANIFEST_VERSION.to_le_bytes());
        encoded.extend_from_slice(&self.generation.to_le_bytes());
        encoded.extend_from_slice(&self.active_segment.to_le_bytes());
        encoded.extend_from_slice(&self.durable_bytes.to_le_bytes());
        let checksum = blake2b_256(&encoded);
        encoded.extend_from_slice(&checksum);
        debug_assert_eq!(encoded.len(), SEGMENT_MANIFEST_BYTES);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, SegmentError> {
        if encoded.len() != SEGMENT_MANIFEST_BYTES {
            return Err(SegmentError::ManifestLength {
                actual: encoded.len(),
                expected: SEGMENT_MANIFEST_BYTES,
            });
        }
        if &encoded[..8] != SEGMENT_MANIFEST_MAGIC {
            return Err(SegmentError::InvalidManifestMagic);
        }
        let mut cursor = 8;
        let version = read_u32(encoded, &mut cursor)?;
        if version != SEGMENT_MANIFEST_VERSION {
            return Err(SegmentError::UnsupportedManifestVersion(version));
        }
        let manifest = Self {
            generation: read_u64(encoded, &mut cursor)?,
            active_segment: read_u32(encoded, &mut cursor)?,
            durable_bytes: read_u64(encoded, &mut cursor)?,
        };
        let checksum = encoded.get(cursor..).ok_or(SegmentError::ManifestLength {
            actual: encoded.len(),
            expected: SEGMENT_MANIFEST_BYTES,
        })?;
        if checksum != blake2b_256(&encoded[..cursor]) {
            return Err(SegmentError::ManifestChecksumMismatch);
        }
        Ok(manifest)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentFileInspection {
    pub records: u64,
    pub valid_bytes: u64,
    pub file_bytes: u64,
    pub torn_tail: bool,
}

#[derive(Debug)]
pub struct SegmentAppender {
    file: File,
    generation: u64,
    segment: u32,
    next_offset: u64,
    poisoned: bool,
}

impl SegmentAppender {
    pub fn create_new(
        path: impl AsRef<Path>,
        generation: u64,
        segment: u32,
    ) -> Result<Self, SegmentError> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(path)
            .map_err(segment_io)?;
        Ok(Self {
            file,
            generation,
            segment,
            next_offset: 0,
            poisoned: false,
        })
    }

    /// Open only when the file ends at the tail committed in the authoritative
    /// RocksDB manifest. Recovery must explicitly remove any orphan or torn
    /// suffix first.
    pub fn open_at_committed_tail(
        path: impl AsRef<Path>,
        manifest: SegmentManifest,
    ) -> Result<Self, SegmentError> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .map_err(segment_io)?;
        let inspection = inspect_open_segment_file(&mut file)?;
        if inspection.torn_tail || inspection.file_bytes != manifest.durable_bytes {
            return Err(SegmentError::UncommittedTail {
                committed: manifest.durable_bytes,
                actual: inspection.file_bytes,
                torn: inspection.torn_tail,
            });
        }
        Ok(Self {
            file,
            generation: manifest.generation,
            segment: manifest.active_segment,
            next_offset: manifest.durable_bytes,
            poisoned: false,
        })
    }

    pub fn append(&mut self, record: &SegmentRecord) -> Result<SegmentLocator, SegmentError> {
        if self.poisoned {
            return Err(SegmentError::AppenderPoisoned);
        }
        let encoded = encode_segment_record(record)?;
        let frame_length = u32::try_from(encoded.len())
            .map_err(|_| SegmentError::LengthOverflow(encoded.len()))?;
        let next_offset = self
            .next_offset
            .checked_add(u64::from(frame_length))
            .ok_or(SegmentError::LocatorOverflow)?;
        let locator = SegmentLocator {
            generation: self.generation,
            segment: self.segment,
            offset: self.next_offset,
            frame_length,
        };
        self.poisoned = true;
        self.file.write_all(&encoded).map_err(segment_io)?;
        self.next_offset = next_offset;
        self.poisoned = false;
        Ok(locator)
    }

    /// Sync appended frames before publishing this tail in a RocksDB state
    /// transaction. The returned manifest is not authoritative until that
    /// transaction commits.
    pub fn sync_data(&mut self) -> Result<SegmentManifest, SegmentError> {
        if self.poisoned {
            return Err(SegmentError::AppenderPoisoned);
        }
        self.file.sync_data().map_err(segment_io)?;
        Ok(SegmentManifest {
            generation: self.generation,
            active_segment: self.segment,
            durable_bytes: self.next_offset,
        })
    }

    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SegmentError {
    #[error("segment frame contains unknown record kind {0}")]
    UnknownKind(u8),
    #[error("segment frame contains {actual} locator hints; maximum is {maximum}")]
    TooManyHints { actual: usize, maximum: usize },
    #[error("segment frame size {actual} exceeds maximum {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("segment frame length {0} cannot be represented")]
    LengthOverflow(usize),
    #[error("segment frame is truncated: need {required} bytes, have {available}")]
    Truncated { required: usize, available: usize },
    #[error("segment frame magic is invalid")]
    InvalidMagic,
    #[error("segment frame reserved bits are nonzero")]
    ReservedBits,
    #[error("segment frame length {declared} disagrees with encoded fields ({expected})")]
    LengthMismatch { declared: usize, expected: usize },
    #[error("segment frame checksum mismatch")]
    ChecksumMismatch,
    #[error("segment locator range overflows")]
    LocatorOverflow,
    #[error("segment manifest has invalid magic")]
    InvalidManifestMagic,
    #[error("segment manifest version {0} is unsupported")]
    UnsupportedManifestVersion(u32),
    #[error("segment manifest length {actual} does not equal {expected}")]
    ManifestLength { actual: usize, expected: usize },
    #[error("segment manifest checksum mismatch")]
    ManifestChecksumMismatch,
    #[error(
        "segment file has uncommitted tail: committed {committed}, actual {actual}, torn {torn}"
    )]
    UncommittedTail {
        committed: u64,
        actual: u64,
        torn: bool,
    },
    #[error("committed segment tail {committed} is not a complete-frame boundary")]
    CommittedTailNotBoundary { committed: u64 },
    #[error("segment appender is poisoned by an incomplete write")]
    AppenderPoisoned,
    #[error("segment I/O failed: {0}")]
    Io(String),
}

pub fn encode_segment_record(record: &SegmentRecord) -> Result<Vec<u8>, SegmentError> {
    if record.hints.len() > SEGMENT_MAX_HINTS {
        return Err(SegmentError::TooManyHints {
            actual: record.hints.len(),
            maximum: SEGMENT_MAX_HINTS,
        });
    }
    let hint_bytes = record
        .hints
        .len()
        .checked_mul(SEGMENT_LOCATOR_BYTES)
        .ok_or(SegmentError::LengthOverflow(record.hints.len()))?;
    let frame_length = SEGMENT_FRAME_FIXED_BYTES
        .checked_add(hint_bytes)
        .and_then(|length| length.checked_add(record.payload.len()))
        .and_then(|length| length.checked_add(SEGMENT_FRAME_CHECKSUM_BYTES))
        .ok_or(SegmentError::LengthOverflow(record.payload.len()))?;
    if frame_length > MAX_SEGMENT_FRAME_BYTES {
        return Err(SegmentError::FrameTooLarge {
            actual: frame_length,
            maximum: MAX_SEGMENT_FRAME_BYTES,
        });
    }
    let frame_length_u32 =
        u32::try_from(frame_length).map_err(|_| SegmentError::LengthOverflow(frame_length))?;
    let payload_length = u32::try_from(record.payload.len())
        .map_err(|_| SegmentError::LengthOverflow(record.payload.len()))?;

    let mut encoded = Vec::with_capacity(frame_length);
    encoded.extend_from_slice(SEGMENT_FRAME_MAGIC);
    encoded.extend_from_slice(&frame_length_u32.to_le_bytes());
    encoded.push(record.kind as u8);
    encoded.push(
        u8::try_from(record.hints.len())
            .map_err(|_| SegmentError::LengthOverflow(record.hints.len()))?,
    );
    encoded.extend_from_slice(&0u16.to_le_bytes());
    encoded.extend_from_slice(&record.key);
    encoded.extend_from_slice(&payload_length.to_le_bytes());
    for hint in &record.hints {
        hint.encode_into(&mut encoded);
    }
    encoded.extend_from_slice(&record.payload);
    let checksum = blake2b_256(&encoded);
    encoded.extend_from_slice(&checksum);
    debug_assert_eq!(encoded.len(), frame_length);
    Ok(encoded)
}

pub fn decode_segment_record(encoded: &[u8]) -> Result<(SegmentRecord, usize), SegmentError> {
    let (record, frame_length) = decode_segment_record_ref(encoded)?;
    Ok((
        SegmentRecord {
            kind: record.kind,
            key: record.key,
            hints: record.hints.into_iter().flatten().collect(),
            payload: record.payload.to_vec(),
        },
        frame_length,
    ))
}

/// Decode a frame directly from a cached page without copying its canonical
/// payload. The returned slice cannot outlive the verified frame bytes.
pub fn decode_segment_record_ref(
    encoded: &[u8],
) -> Result<(SegmentRecordRef<'_>, usize), SegmentError> {
    if encoded.len() < 12 {
        return Err(SegmentError::Truncated {
            required: 12,
            available: encoded.len(),
        });
    }
    if &encoded[..8] != SEGMENT_FRAME_MAGIC {
        return Err(SegmentError::InvalidMagic);
    }
    let mut cursor = 8;
    let frame_length = read_u32(encoded, &mut cursor)? as usize;
    if frame_length > MAX_SEGMENT_FRAME_BYTES {
        return Err(SegmentError::FrameTooLarge {
            actual: frame_length,
            maximum: MAX_SEGMENT_FRAME_BYTES,
        });
    }
    if encoded.len() < frame_length {
        return Err(SegmentError::Truncated {
            required: frame_length,
            available: encoded.len(),
        });
    }
    if frame_length < SEGMENT_FRAME_FIXED_BYTES + SEGMENT_FRAME_CHECKSUM_BYTES {
        return Err(SegmentError::LengthMismatch {
            declared: frame_length,
            expected: SEGMENT_FRAME_FIXED_BYTES + SEGMENT_FRAME_CHECKSUM_BYTES,
        });
    }

    let kind = SegmentKind::try_from(read_u8(encoded, &mut cursor)?)?;
    let hint_count = read_u8(encoded, &mut cursor)? as usize;
    if hint_count > SEGMENT_MAX_HINTS {
        return Err(SegmentError::TooManyHints {
            actual: hint_count,
            maximum: SEGMENT_MAX_HINTS,
        });
    }
    if read_u16(encoded, &mut cursor)? != 0 {
        return Err(SegmentError::ReservedBits);
    }
    let key = read_array::<32>(encoded, &mut cursor)?;
    let payload_length = read_u32(encoded, &mut cursor)? as usize;
    let hint_bytes = hint_count
        .checked_mul(SEGMENT_LOCATOR_BYTES)
        .ok_or(SegmentError::LengthOverflow(hint_count))?;
    let expected_length = SEGMENT_FRAME_FIXED_BYTES
        .checked_add(hint_bytes)
        .and_then(|length| length.checked_add(payload_length))
        .and_then(|length| length.checked_add(SEGMENT_FRAME_CHECKSUM_BYTES))
        .ok_or(SegmentError::LengthOverflow(payload_length))?;
    if frame_length != expected_length {
        return Err(SegmentError::LengthMismatch {
            declared: frame_length,
            expected: expected_length,
        });
    }

    let mut hints = [None; SEGMENT_MAX_HINTS];
    for hint in hints.iter_mut().take(hint_count) {
        *hint = Some(SegmentLocator::decode(encoded, &mut cursor)?);
    }
    let payload_end = cursor
        .checked_add(payload_length)
        .ok_or(SegmentError::LengthOverflow(payload_length))?;
    let payload = encoded
        .get(cursor..payload_end)
        .ok_or(SegmentError::Truncated {
            required: payload_end,
            available: encoded.len(),
        })?;
    let checksum_end = payload_end
        .checked_add(SEGMENT_FRAME_CHECKSUM_BYTES)
        .ok_or(SegmentError::LengthOverflow(payload_end))?;
    let checksum = encoded
        .get(payload_end..checksum_end)
        .ok_or(SegmentError::Truncated {
            required: checksum_end,
            available: encoded.len(),
        })?;
    if checksum != blake2b_256(&encoded[..payload_end]) {
        return Err(SegmentError::ChecksumMismatch);
    }
    Ok((
        SegmentRecordRef {
            kind,
            key,
            hints,
            payload,
        },
        frame_length,
    ))
}

/// Scan complete frames without accepting corruption as a recoverable tail.
/// Only an incomplete final frame is classified as torn. Callers may truncate
/// to `valid_bytes` after first preserving recovery evidence.
pub fn scan_segment_prefix(
    generation: u64,
    segment: u32,
    encoded: &[u8],
) -> Result<SegmentScan, SegmentError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < encoded.len() {
        match decode_segment_record(&encoded[offset..]) {
            Ok((record, frame_length)) => {
                let locator = SegmentLocator {
                    generation,
                    segment,
                    offset: u64::try_from(offset)
                        .map_err(|_| SegmentError::LengthOverflow(offset))?,
                    frame_length: u32::try_from(frame_length)
                        .map_err(|_| SegmentError::LengthOverflow(frame_length))?,
                };
                records.push((locator, record));
                offset = offset
                    .checked_add(frame_length)
                    .ok_or(SegmentError::LengthOverflow(frame_length))?;
            }
            Err(SegmentError::Truncated { .. }) => {
                return Ok(SegmentScan {
                    records,
                    valid_bytes: u64::try_from(offset)
                        .map_err(|_| SegmentError::LengthOverflow(offset))?,
                    torn_tail: true,
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(SegmentScan {
        records,
        valid_bytes: u64::try_from(offset).map_err(|_| SegmentError::LengthOverflow(offset))?,
        torn_tail: false,
    })
}

pub fn inspect_segment_file(path: impl AsRef<Path>) -> Result<SegmentFileInspection, SegmentError> {
    let mut file = File::open(path).map_err(segment_io)?;
    inspect_open_segment_file(&mut file)
}

/// Validate the authoritative prefix, then discard any complete-or-torn
/// uncommitted suffix. The caller supplies `committed_bytes` only from a
/// checksum-verified manifest loaded from the atomic RocksDB state batch.
pub fn truncate_segment_to_committed_tail(
    path: impl AsRef<Path>,
    committed_bytes: u64,
) -> Result<SegmentFileInspection, SegmentError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(segment_io)?;
    let file_bytes = file.metadata().map_err(segment_io)?.len();
    if committed_bytes > file_bytes {
        return Err(SegmentError::UncommittedTail {
            committed: committed_bytes,
            actual: file_bytes,
            torn: false,
        });
    }
    validate_segment_prefix_boundary(&mut file, committed_bytes)?;
    file.set_len(committed_bytes).map_err(segment_io)?;
    file.sync_all().map_err(segment_io)?;
    inspect_open_segment_file(&mut file)
}

fn inspect_open_segment_file(file: &mut File) -> Result<SegmentFileInspection, SegmentError> {
    let file_bytes = file.metadata().map_err(segment_io)?.len();
    file.seek(SeekFrom::Start(0)).map_err(segment_io)?;
    let mut records = 0u64;
    let mut offset = 0u64;
    while offset < file_bytes {
        let remaining = file_bytes - offset;
        if remaining < 12 {
            return Ok(SegmentFileInspection {
                records,
                valid_bytes: offset,
                file_bytes,
                torn_tail: true,
            });
        }
        let Some(encoded) = read_next_frame(file, remaining)? else {
            return Ok(SegmentFileInspection {
                records,
                valid_bytes: offset,
                file_bytes,
                torn_tail: true,
            });
        };
        let (_, frame_length) = decode_segment_record_ref(&encoded)?;
        offset = offset
            .checked_add(
                u64::try_from(frame_length)
                    .map_err(|_| SegmentError::LengthOverflow(frame_length))?,
            )
            .ok_or(SegmentError::LocatorOverflow)?;
        records = records
            .checked_add(1)
            .ok_or(SegmentError::LengthOverflow(records as usize))?;
    }
    Ok(SegmentFileInspection {
        records,
        valid_bytes: offset,
        file_bytes,
        torn_tail: false,
    })
}

fn validate_segment_prefix_boundary(
    file: &mut File,
    committed_bytes: u64,
) -> Result<(), SegmentError> {
    file.seek(SeekFrom::Start(0)).map_err(segment_io)?;
    let mut offset = 0u64;
    while offset < committed_bytes {
        let remaining = committed_bytes - offset;
        if remaining < 12 {
            return Err(SegmentError::CommittedTailNotBoundary {
                committed: committed_bytes,
            });
        }
        let encoded =
            read_next_frame(file, remaining)?.ok_or(SegmentError::CommittedTailNotBoundary {
                committed: committed_bytes,
            })?;
        let (_, frame_length) = decode_segment_record_ref(&encoded)?;
        offset = offset
            .checked_add(
                u64::try_from(frame_length)
                    .map_err(|_| SegmentError::LengthOverflow(frame_length))?,
            )
            .ok_or(SegmentError::LocatorOverflow)?;
    }
    if offset != committed_bytes {
        return Err(SegmentError::CommittedTailNotBoundary {
            committed: committed_bytes,
        });
    }
    Ok(())
}

/// Returns `None` only when the remaining bytes contain an incomplete frame.
fn read_next_frame(file: &mut File, remaining: u64) -> Result<Option<Vec<u8>>, SegmentError> {
    let mut header = [0u8; 12];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(segment_io(error)),
    }
    if &header[..8] != SEGMENT_FRAME_MAGIC {
        return Err(SegmentError::InvalidMagic);
    }
    let frame_length = u32::from_le_bytes(
        header[8..12]
            .try_into()
            .expect("twelve-byte frame header contains four-byte length"),
    ) as usize;
    if frame_length > MAX_SEGMENT_FRAME_BYTES {
        return Err(SegmentError::FrameTooLarge {
            actual: frame_length,
            maximum: MAX_SEGMENT_FRAME_BYTES,
        });
    }
    if frame_length < SEGMENT_FRAME_FIXED_BYTES + SEGMENT_FRAME_CHECKSUM_BYTES {
        return Err(SegmentError::LengthMismatch {
            declared: frame_length,
            expected: SEGMENT_FRAME_FIXED_BYTES + SEGMENT_FRAME_CHECKSUM_BYTES,
        });
    }
    if u64::try_from(frame_length).map_err(|_| SegmentError::LengthOverflow(frame_length))?
        > remaining
    {
        return Ok(None);
    }
    let mut encoded = vec![0u8; frame_length];
    encoded[..12].copy_from_slice(&header);
    match file.read_exact(&mut encoded[12..]) {
        Ok(()) => Ok(Some(encoded)),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(segment_io(error)),
    }
}

fn segment_io(error: std::io::Error) -> SegmentError {
    SegmentError::Io(error.to_string())
}

/// Convert arbitrary record locators into a sorted, duplicate-free page plan.
/// Frames spanning pages add every intersected page. The executor may satisfy
/// multiple breadth-first node requests from one page read.
pub fn plan_segment_page_reads<I>(locators: I) -> Result<Vec<SegmentPageRead>, SegmentError>
where
    I: IntoIterator<Item = SegmentLocator>,
{
    let mut pages = BTreeSet::new();
    for locator in locators {
        if locator.frame_length == 0 {
            return Err(SegmentError::LengthMismatch {
                declared: 0,
                expected: SEGMENT_FRAME_FIXED_BYTES + SEGMENT_FRAME_CHECKSUM_BYTES,
            });
        }
        let end = locator
            .offset
            .checked_add(u64::from(locator.frame_length))
            .ok_or(SegmentError::LocatorOverflow)?;
        let first = locator.offset / SEGMENT_PAGE_BYTES * SEGMENT_PAGE_BYTES;
        let last_byte = end.checked_sub(1).ok_or(SegmentError::LocatorOverflow)?;
        let last = last_byte / SEGMENT_PAGE_BYTES * SEGMENT_PAGE_BYTES;
        let mut page = first;
        loop {
            pages.insert(SegmentPageRead {
                generation: locator.generation,
                segment: locator.segment,
                offset: page,
                length: SEGMENT_PAGE_BYTES,
            });
            if page == last {
                break;
            }
            page = page
                .checked_add(SEGMENT_PAGE_BYTES)
                .ok_or(SegmentError::LocatorOverflow)?;
        }
    }
    Ok(pages.into_iter().collect())
}

fn read_u8(encoded: &[u8], cursor: &mut usize) -> Result<u8, SegmentError> {
    Ok(read_array::<1>(encoded, cursor)?[0])
}

fn read_u16(encoded: &[u8], cursor: &mut usize) -> Result<u16, SegmentError> {
    Ok(u16::from_le_bytes(read_array(encoded, cursor)?))
}

fn read_u32(encoded: &[u8], cursor: &mut usize) -> Result<u32, SegmentError> {
    Ok(u32::from_le_bytes(read_array(encoded, cursor)?))
}

fn read_u64(encoded: &[u8], cursor: &mut usize) -> Result<u64, SegmentError> {
    Ok(u64::from_le_bytes(read_array(encoded, cursor)?))
}

fn read_array<const N: usize>(encoded: &[u8], cursor: &mut usize) -> Result<[u8; N], SegmentError> {
    let end = cursor
        .checked_add(N)
        .ok_or(SegmentError::LengthOverflow(N))?;
    let bytes = encoded.get(*cursor..end).ok_or(SegmentError::Truncated {
        required: end,
        available: encoded.len(),
    })?;
    *cursor = end;
    bytes.try_into().map_err(|_| SegmentError::Truncated {
        required: end,
        available: encoded.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    fn locator(offset: u64, frame_length: u32) -> SegmentLocator {
        SegmentLocator {
            generation: 7,
            segment: 3,
            offset,
            frame_length,
        }
    }

    fn record(payload: &[u8]) -> SegmentRecord {
        SegmentRecord {
            kind: SegmentKind::Block,
            key: [0x42; 32],
            hints: vec![locator(64, 96), locator(160, 80)],
            payload: payload.to_vec(),
        }
    }

    fn test_file() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hsrd-segment-{}-{}",
            std::process::id(),
            NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn segment_frame_round_trips_canonical_payload_and_local_hints() {
        let expected = record(b"canonical urkel node");
        let encoded = encode_segment_record(&expected).expect("encode");
        let (borrowed, borrowed_consumed) =
            decode_segment_record_ref(&encoded).expect("borrowed decode");
        let (actual, consumed) = decode_segment_record(&encoded).expect("decode");
        assert_eq!(borrowed.kind, expected.kind);
        assert_eq!(borrowed.key, expected.key);
        assert_eq!(
            borrowed.hints,
            [Some(expected.hints[0]), Some(expected.hints[1])]
        );
        assert_eq!(borrowed.payload, expected.payload);
        assert_eq!(borrowed_consumed, encoded.len());
        assert_eq!(actual, expected);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn segment_frame_rejects_complete_corruption() {
        let mut encoded = encode_segment_record(&record(b"node")).expect("encode");
        let payload = SEGMENT_FRAME_FIXED_BYTES + (2 * SEGMENT_LOCATOR_BYTES);
        encoded[payload] ^= 1;
        assert_eq!(
            decode_segment_record(&encoded),
            Err(SegmentError::ChecksumMismatch)
        );
        assert_eq!(
            scan_segment_prefix(7, 3, &encoded),
            Err(SegmentError::ChecksumMismatch)
        );
    }

    #[test]
    fn segment_scan_preserves_complete_prefix_before_torn_tail() {
        let first = encode_segment_record(&record(b"first")).expect("first");
        let second = encode_segment_record(&record(b"second")).expect("second");
        let mut encoded = first.clone();
        encoded.extend_from_slice(&second[..second.len() - 5]);

        let scan = scan_segment_prefix(7, 3, &encoded).expect("scan");
        assert!(scan.torn_tail);
        assert_eq!(scan.valid_bytes, first.len() as u64);
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.records[0].0, locator(0, first.len() as u32));
        assert_eq!(scan.records[0].1.payload, b"first");
    }

    #[test]
    fn page_plan_coalesces_shared_pages_and_covers_spanning_frames() {
        let plan = plan_segment_page_reads([
            locator(8, 64),
            locator(SEGMENT_PAGE_BYTES - 10, 20),
            locator(SEGMENT_PAGE_BYTES + 100, 40),
        ])
        .expect("plan");
        assert_eq!(
            plan,
            vec![
                SegmentPageRead {
                    generation: 7,
                    segment: 3,
                    offset: 0,
                    length: SEGMENT_PAGE_BYTES,
                },
                SegmentPageRead {
                    generation: 7,
                    segment: 3,
                    offset: SEGMENT_PAGE_BYTES,
                    length: SEGMENT_PAGE_BYTES,
                },
            ]
        );
    }

    #[test]
    fn page_plan_rejects_zero_length_and_overflowing_locators() {
        assert!(matches!(
            plan_segment_page_reads([locator(0, 0)]),
            Err(SegmentError::LengthMismatch { declared: 0, .. })
        ));
        assert_eq!(
            plan_segment_page_reads([locator(u64::MAX, 2)]),
            Err(SegmentError::LocatorOverflow)
        );
    }

    #[test]
    fn manifest_is_checksummed_and_rejects_version_or_body_corruption() {
        let manifest = SegmentManifest {
            generation: 9,
            active_segment: 4,
            durable_bytes: 123_456,
        };
        let encoded = manifest.encode();
        assert_eq!(SegmentManifest::decode(&encoded), Ok(manifest));

        let mut corrupt = encoded.clone();
        corrupt[20] ^= 1;
        assert_eq!(
            SegmentManifest::decode(&corrupt),
            Err(SegmentError::ManifestChecksumMismatch)
        );
        let mut unknown = encoded;
        unknown[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            SegmentManifest::decode(&unknown),
            Err(SegmentError::UnsupportedManifestVersion(2))
        );
    }

    #[test]
    fn appender_requires_the_exact_committed_tail() {
        let path = test_file();
        let mut appender = SegmentAppender::create_new(&path, 11, 2).expect("create");
        let first = appender.append(&record(b"first")).expect("first");
        let manifest = appender.sync_data().expect("sync first");
        assert_eq!(manifest.durable_bytes, u64::from(first.frame_length));
        drop(appender);

        let inspection = inspect_segment_file(&path).expect("inspect");
        assert_eq!(inspection.records, 1);
        assert!(!inspection.torn_tail);
        let mut reopened =
            SegmentAppender::open_at_committed_tail(&path, manifest).expect("reopen");
        reopened.append(&record(b"second")).expect("second");
        let second_manifest = reopened.sync_data().expect("sync second");
        assert!(second_manifest.durable_bytes > manifest.durable_bytes);
        drop(reopened);

        assert!(matches!(
            SegmentAppender::open_at_committed_tail(&path, manifest),
            Err(SegmentError::UncommittedTail {
                committed,
                actual,
                torn: false,
            }) if committed == manifest.durable_bytes && actual == second_manifest.durable_bytes
        ));
        fs::remove_file(path).expect("remove test segment");
    }

    #[test]
    fn recovery_discards_complete_and_torn_bytes_after_manifest_tail() {
        let path = test_file();
        let mut appender = SegmentAppender::create_new(&path, 13, 5).expect("create");
        appender.append(&record(b"committed")).expect("committed");
        let manifest = appender.sync_data().expect("sync committed");
        appender
            .append(&record(b"complete orphan"))
            .expect("orphan");
        drop(appender);

        let torn = encode_segment_record(&record(b"torn orphan")).expect("encode torn");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open raw tail");
        file.write_all(&torn[..torn.len() - 7])
            .expect("write torn tail");
        file.sync_all().expect("sync raw tail");
        drop(file);

        let before = inspect_segment_file(&path).expect("inspect before recovery");
        assert!(before.torn_tail);
        assert_eq!(before.records, 2);
        assert!(before.file_bytes > manifest.durable_bytes);

        let recovered =
            truncate_segment_to_committed_tail(&path, manifest.durable_bytes).expect("recover");
        assert!(!recovered.torn_tail);
        assert_eq!(recovered.records, 1);
        assert_eq!(recovered.file_bytes, manifest.durable_bytes);
        SegmentAppender::open_at_committed_tail(&path, manifest).expect("open recovered");
        fs::remove_file(path).expect("remove test segment");
    }

    #[test]
    fn recovery_rejects_a_manifest_tail_inside_a_frame() {
        let path = test_file();
        let mut appender = SegmentAppender::create_new(&path, 17, 1).expect("create");
        let locator = appender.append(&record(b"frame")).expect("append");
        appender.sync_data().expect("sync");
        drop(appender);

        assert_eq!(
            truncate_segment_to_committed_tail(&path, u64::from(locator.frame_length) - 1),
            Err(SegmentError::CommittedTailNotBoundary {
                committed: u64::from(locator.frame_length) - 1,
            })
        );
        fs::remove_file(path).expect("remove test segment");
    }
}
