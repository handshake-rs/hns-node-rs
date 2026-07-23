use std::{
    collections::{BTreeSet, HashMap},
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

use hns_primitives::blake2b_256;
use thiserror::Error;

const SEGMENT_FRAME_MAGIC: &[u8; 8] = b"HSGSEG01";
const SEGMENT_FRAME_FIXED_BYTES: usize = 8 + 4 + 1 + 1 + 2 + 32 + 4;
const SEGMENT_FRAME_CHECKSUM_BYTES: usize = 32;
const SEGMENT_LOCATOR_BYTES: usize = 8 + 4 + 8 + 4;
const SEGMENT_VALUE_MAGIC: &[u8; 8] = b"HSGLOC01";
const SEGMENT_VALUE_VERSION: u8 = 1;
const SEGMENT_VALUE_BODY_BYTES: usize = 8 + 1 + 1 + 2 + SEGMENT_LOCATOR_BYTES;
const SEGMENT_VALUE_BYTES: usize = SEGMENT_VALUE_BODY_BYTES + 32;
const SEGMENT_MANIFEST_MAGIC: &[u8; 8] = b"HSGMAN01";
const SEGMENT_MANIFEST_VERSION: u32 = 1;
const SEGMENT_MANIFEST_BODY_BYTES: usize = 8 + 4 + 8;
const SEGMENT_MANIFEST_BYTES: usize = 8 + 4 + SEGMENT_MANIFEST_BODY_BYTES + 32;
pub const SEGMENT_MAX_HINTS: usize = 2;
const MAX_SEGMENT_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const SEGMENT_PAGE_BYTES: u64 = 64 * 1024;
pub const SEGMENT_TARGET_BYTES: u64 = 256 * 1024 * 1024;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentValueLocator {
    pub kind: SegmentKind,
    pub locator: SegmentLocator,
}

impl SegmentValueLocator {
    pub fn encode(self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(SEGMENT_VALUE_BYTES);
        encoded.extend_from_slice(SEGMENT_VALUE_MAGIC);
        encoded.push(SEGMENT_VALUE_VERSION);
        encoded.push(self.kind as u8);
        encoded.extend_from_slice(&0u16.to_le_bytes());
        self.locator.encode_into(&mut encoded);
        let checksum = blake2b_256(&encoded);
        encoded.extend_from_slice(&checksum);
        debug_assert_eq!(encoded.len(), SEGMENT_VALUE_BYTES);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Option<Self>, SegmentError> {
        if !encoded.starts_with(SEGMENT_VALUE_MAGIC) {
            return Ok(None);
        }
        if encoded.len() != SEGMENT_VALUE_BYTES {
            return Err(SegmentError::ValueLocatorLength {
                actual: encoded.len(),
                expected: SEGMENT_VALUE_BYTES,
            });
        }
        let (body, checksum) = encoded.split_at(SEGMENT_VALUE_BODY_BYTES);
        if checksum != blake2b_256(body) {
            return Err(SegmentError::ValueLocatorChecksumMismatch);
        }
        let mut cursor = SEGMENT_VALUE_MAGIC.len();
        let version = read_u8(body, &mut cursor)?;
        if version != SEGMENT_VALUE_VERSION {
            return Err(SegmentError::UnsupportedValueLocatorVersion(version));
        }
        let kind = SegmentKind::try_from(read_u8(body, &mut cursor)?)?;
        if read_u16(body, &mut cursor)? != 0 {
            return Err(SegmentError::ReservedBits);
        }
        let locator = SegmentLocator::decode(body, &mut cursor)?;
        if cursor != body.len() || locator.frame_length == 0 {
            return Err(SegmentError::ValueLocatorLength {
                actual: cursor,
                expected: body.len(),
            });
        }
        Ok(Some(Self { kind, locator }))
    }
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

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn segment(&self) -> u32 {
        self.segment
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArchivePayload {
    pub kind: SegmentKind,
    pub key: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct ArchiveChannel {
    kind: SegmentKind,
    manifest: SegmentManifest,
    appender: Option<SegmentAppender>,
}

#[derive(Debug)]
pub(crate) struct PreparedArchive {
    pub locators: Vec<SegmentValueLocator>,
    pub block_manifest: SegmentManifest,
    pub undo_manifest: SegmentManifest,
}

#[derive(Debug)]
pub(crate) struct SegmentArchiveWriter {
    block: ArchiveChannel,
    undo: ArchiveChannel,
}

#[derive(Debug)]
pub struct SegmentArchive {
    directory: PathBuf,
    writer: Mutex<SegmentArchiveWriter>,
    readers: Mutex<HashMap<(SegmentKind, u64, u32), Arc<File>>>,
}

impl SegmentArchive {
    pub(crate) fn create_new(directory: PathBuf, generation: u64) -> Result<Self, SegmentError> {
        std::fs::create_dir_all(&directory).map_err(segment_io)?;
        prepare_new_archive_directory(&directory)?;
        let block = create_archive_channel(&directory, SegmentKind::Block, generation, 0)?;
        let undo = create_archive_channel(&directory, SegmentKind::Undo, generation, 0)?;
        sync_directory(&directory)?;
        Ok(Self {
            directory,
            writer: Mutex::new(SegmentArchiveWriter { block, undo }),
            readers: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn recover(
        directory: PathBuf,
        block_manifest: SegmentManifest,
        undo_manifest: SegmentManifest,
    ) -> Result<Self, SegmentError> {
        std::fs::create_dir_all(&directory).map_err(segment_io)?;
        let block = recover_archive_channel(&directory, SegmentKind::Block, block_manifest)?;
        let undo = recover_archive_channel(&directory, SegmentKind::Undo, undo_manifest)?;
        Ok(Self {
            directory,
            writer: Mutex::new(SegmentArchiveWriter { block, undo }),
            readers: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn writer(&self) -> Result<MutexGuard<'_, SegmentArchiveWriter>, SegmentError> {
        self.writer.lock().map_err(|_| SegmentError::Poisoned)
    }

    pub(crate) fn prepare_locked(
        &self,
        writer: &mut SegmentArchiveWriter,
        payloads: &mut [ArchivePayload],
    ) -> Result<PreparedArchive, SegmentError> {
        writer.prepare(&self.directory, payloads)
    }

    pub(crate) fn rollback_locked(
        &self,
        writer: &mut SegmentArchiveWriter,
    ) -> Result<(), SegmentError> {
        writer.rollback(&self.directory)
    }

    pub fn resolve(
        &self,
        expected_kind: SegmentKind,
        key: &[u8],
        encoded: &[u8],
    ) -> Result<Option<Vec<u8>>, SegmentError> {
        let Some(value) = SegmentValueLocator::decode(encoded)? else {
            return Ok(None);
        };
        if value.kind != expected_kind {
            return Err(SegmentError::ValueLocatorKind {
                expected: expected_kind,
                actual: value.kind,
            });
        }
        let expected_key: [u8; 32] = key
            .try_into()
            .map_err(|_| SegmentError::RecordKeyMismatch)?;
        {
            let writer = self.writer()?;
            let manifest = match expected_kind {
                SegmentKind::Block => writer.block.manifest,
                SegmentKind::Undo => writer.undo.manifest,
            };
            let end = value
                .locator
                .offset
                .checked_add(u64::from(value.locator.frame_length))
                .ok_or(SegmentError::LocatorOverflow)?;
            if value.locator.generation != manifest.generation
                || value.locator.segment > manifest.active_segment
                || (value.locator.segment == manifest.active_segment
                    && end > manifest.durable_bytes)
            {
                return Err(SegmentError::LocatorBeyondManifest);
            }
        }
        let path = archive_file_path(
            &self.directory,
            value.kind,
            value.locator.generation,
            value.locator.segment,
        );
        let file = {
            let mut readers = self.readers.lock().map_err(|_| SegmentError::Poisoned)?;
            Arc::clone(
                readers
                    .entry((value.kind, value.locator.generation, value.locator.segment))
                    .or_insert(Arc::new(File::open(&path).map_err(segment_io)?)),
            )
        };
        let mut frame = vec![0u8; value.locator.frame_length as usize];
        read_exact_at(&file, &mut frame, value.locator.offset)?;
        let (record, consumed) = decode_segment_record_ref(&frame)?;
        if consumed != frame.len() || record.kind != expected_kind || record.key != expected_key {
            return Err(SegmentError::RecordKeyMismatch);
        }
        Ok(Some(record.payload.to_vec()))
    }

    pub fn manifests(&self) -> Result<(SegmentManifest, SegmentManifest), SegmentError> {
        let writer = self.writer()?;
        Ok((writer.block.manifest, writer.undo.manifest))
    }
}

impl SegmentArchiveWriter {
    pub(crate) fn prepare(
        &mut self,
        directory: &Path,
        payloads: &mut [ArchivePayload],
    ) -> Result<PreparedArchive, SegmentError> {
        let mut locators = Vec::with_capacity(payloads.len());
        let mut touched_block = false;
        let mut touched_undo = false;
        for payload in payloads {
            let channel = match payload.kind {
                SegmentKind::Block => {
                    touched_block = true;
                    &mut self.block
                }
                SegmentKind::Undo => {
                    touched_undo = true;
                    &mut self.undo
                }
            };
            let record = SegmentRecord {
                kind: payload.kind,
                key: payload.key,
                hints: Vec::new(),
                payload: std::mem::take(&mut payload.payload),
            };
            rotate_archive_channel_if_due(directory, channel, &record)?;
            let locator = channel
                .appender
                .as_mut()
                .ok_or(SegmentError::AppenderPoisoned)?
                .append(&record)?;
            locators.push(SegmentValueLocator {
                kind: payload.kind,
                locator,
            });
        }
        let block_manifest = if touched_block {
            self.block
                .appender
                .as_mut()
                .ok_or(SegmentError::AppenderPoisoned)?
                .sync_data()?
        } else {
            self.block.manifest
        };
        let undo_manifest = if touched_undo {
            self.undo
                .appender
                .as_mut()
                .ok_or(SegmentError::AppenderPoisoned)?
                .sync_data()?
        } else {
            self.undo.manifest
        };
        Ok(PreparedArchive {
            locators,
            block_manifest,
            undo_manifest,
        })
    }

    pub(crate) fn commit_prepared(&mut self, prepared: &PreparedArchive) {
        self.block.manifest = prepared.block_manifest;
        self.undo.manifest = prepared.undo_manifest;
    }

    pub(crate) fn rollback(&mut self, directory: &Path) -> Result<(), SegmentError> {
        rollback_archive_channel(directory, &mut self.block)?;
        rollback_archive_channel(directory, &mut self.undo)
    }
}

fn create_archive_channel(
    directory: &Path,
    kind: SegmentKind,
    generation: u64,
    segment: u32,
) -> Result<ArchiveChannel, SegmentError> {
    let path = archive_file_path(directory, kind, generation, segment);
    let mut appender = SegmentAppender::create_new(path, generation, segment)?;
    let manifest = appender.sync_data()?;
    Ok(ArchiveChannel {
        kind,
        manifest,
        appender: Some(appender),
    })
}

fn recover_archive_channel(
    directory: &Path,
    kind: SegmentKind,
    manifest: SegmentManifest,
) -> Result<ArchiveChannel, SegmentError> {
    remove_unpublished_archive_segments(
        directory,
        kind,
        manifest.generation,
        manifest.active_segment,
    )?;
    for segment in 0..manifest.active_segment {
        let path = archive_file_path(directory, kind, manifest.generation, segment);
        let inspection = inspect_segment_file(path)?;
        if inspection.torn_tail {
            return Err(SegmentError::CommittedTailNotBoundary {
                committed: inspection.valid_bytes,
            });
        }
    }
    let path = archive_file_path(
        directory,
        kind,
        manifest.generation,
        manifest.active_segment,
    );
    truncate_segment_to_committed_tail(&path, manifest.durable_bytes)?;
    let appender = SegmentAppender::open_at_committed_tail(path, manifest)?;
    Ok(ArchiveChannel {
        kind,
        manifest,
        appender: Some(appender),
    })
}

fn rotate_archive_channel_if_due(
    directory: &Path,
    channel: &mut ArchiveChannel,
    record: &SegmentRecord,
) -> Result<(), SegmentError> {
    let encoded_bytes = u64::try_from(encoded_segment_record_length(record)?)
        .map_err(|_| SegmentError::LengthOverflow(record.payload.len()))?;
    let appender = channel
        .appender
        .as_mut()
        .ok_or(SegmentError::AppenderPoisoned)?;
    if appender.next_offset() == 0
        || appender
            .next_offset()
            .checked_add(encoded_bytes)
            .ok_or(SegmentError::LocatorOverflow)?
            <= SEGMENT_TARGET_BYTES
    {
        return Ok(());
    }
    appender.sync_data()?;
    let generation = appender.generation();
    let segment = appender
        .segment()
        .checked_add(1)
        .ok_or(SegmentError::LocatorOverflow)?;
    channel.appender.take();
    let path = archive_file_path(directory, channel.kind, generation, segment);
    let mut next = SegmentAppender::create_new(path, generation, segment)?;
    next.sync_data()?;
    sync_directory(directory)?;
    channel.appender = Some(next);
    Ok(())
}

fn rollback_archive_channel(
    directory: &Path,
    channel: &mut ArchiveChannel,
) -> Result<(), SegmentError> {
    channel.appender.take();
    remove_unpublished_archive_segments(
        directory,
        channel.kind,
        channel.manifest.generation,
        channel.manifest.active_segment,
    )?;
    let path = archive_file_path(
        directory,
        channel.kind,
        channel.manifest.generation,
        channel.manifest.active_segment,
    );
    truncate_segment_to_committed_tail(&path, channel.manifest.durable_bytes)?;
    channel.appender = Some(SegmentAppender::open_at_committed_tail(
        path,
        channel.manifest,
    )?);
    Ok(())
}

fn archive_kind_name(kind: SegmentKind) -> &'static str {
    match kind {
        SegmentKind::Block => "block",
        SegmentKind::Undo => "undo",
    }
}

fn archive_file_path(
    directory: &Path,
    kind: SegmentKind,
    generation: u64,
    segment: u32,
) -> PathBuf {
    directory.join(format!(
        "{}-g{generation:016x}-s{segment:08x}.seg",
        archive_kind_name(kind)
    ))
}

fn parse_archive_file_name(name: &str) -> Option<(SegmentKind, u64, u32)> {
    let raw = name.strip_suffix(".seg")?;
    let (kind, raw) = raw.split_once("-g")?;
    let kind = match kind {
        "block" => SegmentKind::Block,
        "undo" => SegmentKind::Undo,
        _ => return None,
    };
    let (generation, segment) = raw.split_once("-s")?;
    Some((
        kind,
        u64::from_str_radix(generation, 16).ok()?,
        u32::from_str_radix(segment, 16).ok()?,
    ))
}

fn prepare_new_archive_directory(directory: &Path) -> Result<(), SegmentError> {
    let mut empty_archives = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(segment_io)? {
        let entry = entry.map_err(segment_io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if parse_archive_file_name(&name).is_none() {
            continue;
        }
        if entry.metadata().map_err(segment_io)?.len() != 0 {
            return Err(SegmentError::ArchiveInitializationConflict(name));
        }
        empty_archives.push(entry.path());
    }
    for path in &empty_archives {
        std::fs::remove_file(path).map_err(segment_io)?;
    }
    if !empty_archives.is_empty() {
        sync_directory(directory)?;
    }
    Ok(())
}

fn remove_unpublished_archive_segments(
    directory: &Path,
    kind: SegmentKind,
    generation: u64,
    active_segment: u32,
) -> Result<(), SegmentError> {
    let mut removed = false;
    for entry in std::fs::read_dir(directory).map_err(segment_io)? {
        let entry = entry.map_err(segment_io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((candidate_kind, candidate_generation, segment)) = parse_archive_file_name(&name)
        else {
            continue;
        };
        if candidate_kind == kind && candidate_generation == generation && segment > active_segment
        {
            std::fs::remove_file(entry.path()).map_err(segment_io)?;
            removed = true;
        }
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), SegmentError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(segment_io)
}

#[cfg(unix)]
fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> Result<(), SegmentError> {
    file.read_exact_at(buffer, offset).map_err(segment_io)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> Result<(), SegmentError> {
    while !buffer.is_empty() {
        let read = file.seek_read(buffer, offset).map_err(segment_io)?;
        if read == 0 {
            return Err(segment_io(std::io::Error::from(ErrorKind::UnexpectedEof)));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or(SegmentError::LocatorOverflow)?;
        buffer = &mut buffer[read..];
    }
    Ok(())
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
    #[error("segment value locator version {0} is unsupported")]
    UnsupportedValueLocatorVersion(u8),
    #[error("segment value locator length {actual} does not equal {expected}")]
    ValueLocatorLength { actual: usize, expected: usize },
    #[error("segment value locator checksum mismatch")]
    ValueLocatorChecksumMismatch,
    #[error("segment value locator kind {actual:?} does not match {expected:?}")]
    ValueLocatorKind {
        expected: SegmentKind,
        actual: SegmentKind,
    },
    #[error("segment record key does not match its durable lookup key")]
    RecordKeyMismatch,
    #[error("segment value locator lies beyond its authoritative manifest")]
    LocatorBeyondManifest,
    #[error("segment mutex was poisoned")]
    Poisoned,
    #[error("cannot initialize an unbound archive over non-empty segment {0}")]
    ArchiveInitializationConflict(String),
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

fn encoded_segment_record_length(record: &SegmentRecord) -> Result<usize, SegmentError> {
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
    Ok(frame_length)
}

pub fn encode_segment_record(record: &SegmentRecord) -> Result<Vec<u8>, SegmentError> {
    let frame_length = encoded_segment_record_length(record)?;
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
    fn unpublished_archive_prepare_is_manifest_invisible_and_reversible() {
        let directory = test_file();
        let _ = std::fs::remove_dir_all(&directory);
        let archive = SegmentArchive::create_new(directory.clone(), 1).expect("create archive");
        let before = archive.manifests().expect("initial manifests");
        let key = [0x71; 32];
        let mut payloads = vec![ArchivePayload {
            kind: SegmentKind::Block,
            key,
            payload: b"prepared but unpublished".to_vec(),
        }];
        let prepared = {
            let mut writer = archive.writer().expect("writer");
            archive
                .prepare_locked(&mut writer, &mut payloads)
                .expect("prepare payload")
        };
        assert!(matches!(
            archive.resolve(SegmentKind::Block, &key, &prepared.locators[0].encode()),
            Err(SegmentError::LocatorBeyondManifest)
        ));
        {
            let mut writer = archive.writer().expect("writer");
            archive
                .rollback_locked(&mut writer)
                .expect("roll back prepare");
        }
        assert_eq!(archive.manifests().expect("rolled-back manifests"), before);
        let block_path = archive_file_path(&directory, SegmentKind::Block, 1, 0);
        assert_eq!(
            std::fs::metadata(block_path)
                .expect("rolled-back block file")
                .len(),
            0
        );
        drop(archive);
        std::fs::remove_dir_all(directory).expect("remove archive fixture");
    }

    #[test]
    fn archive_initialization_never_erases_unbound_payloads() {
        let directory = test_file();
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create archive directory");
        let orphan = archive_file_path(&directory, SegmentKind::Block, 1, 0);
        std::fs::write(&orphan, b"unbound payload bytes").expect("write orphan");

        assert!(matches!(
            SegmentArchive::create_new(directory.clone(), 1),
            Err(SegmentError::ArchiveInitializationConflict(_))
        ));
        assert_eq!(
            std::fs::read(&orphan).expect("read preserved orphan"),
            b"unbound payload bytes"
        );
        std::fs::remove_dir_all(directory).expect("remove archive fixture");
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
