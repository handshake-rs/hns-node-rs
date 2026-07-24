use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hns_node::{STORAGE_MAINTENANCE_MARKER, STORAGE_MAINTENANCE_MARKER_BODY};
use hns_primitives::{blake2b_256, hex_encode};
use hns_store::{
    decode_u32, open_store, ColumnFamily, DurabilityPolicy, MetaKey, ReadSnapshot,
    SegmentArchiveInventory, SegmentArchiveScrub, SegmentMigrationReport, Store, StoreBackend,
    StoreConfig, BLOCK_SEGMENT_MANIFEST_KEY, INTERVAL_SCHEMA_VERSION, INTERVAL_STORAGE_PROFILE,
    LEGACY_SCHEMA_VERSION, LEGACY_STORAGE_PROFILE, PRE_INTERVAL_SCHEMA_VERSION,
    PRE_INTERVAL_STORAGE_PROFILE, SCHEMA_VERSION, SEGMENT_MIGRATION_MAX_BATCH_RECORDS,
    STORAGE_PROFILE, UNDO_SEGMENT_MANIFEST_KEY,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: u32 = 1;
const FALLBACK_MANIFEST: &str = ".hsrd-storage-fallback.json";
const AUDIT_COPY_MARKER: &str = ".hsrd-state-audit-copy";
const AUDIT_COPY_MARKER_BODY: &str = "hsrd-state-audit-copy-v1\n";

#[derive(Debug, Parser)]
#[command(
    about = "Audit or migrate hsrd block/undo segments while the node is stopped",
    long_about = "Audit or migrate hsrd block/undo segments while the node is stopped. The data directory must contain the exact .hsrd-storage-maintenance marker documented in storage-schema.md, and the database must have a clean-shutdown marker."
)]
struct Arguments {
    /// Offline hsrd data root containing chain/, name-pages/, and payload-segments/.
    #[arg(long)]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a clean RocksDB checkpoint and byte-stable external-file fallback before rollout.
    Backup {
        /// New fallback data root. It must be absolute, outside --data-dir, and not exist.
        #[arg(long)]
        backup_dir: PathBuf,
    },
    /// Validate manifests and every committed frame, then report inline/archive inventory.
    Inventory,
    /// Idempotently rewrite legacy inline block/undo values into append-only segments.
    MigrateInline {
        /// Maximum number of logical payloads in one atomic RocksDB/archive commit.
        #[arg(long, default_value_t = 32)]
        batch_records: usize,
    },
}

#[derive(Clone, Debug, Serialize)]
struct StoreIdentity {
    storage_schema: u32,
    storage_profile: String,
}

#[derive(Debug, Serialize)]
struct InventoryOutput {
    schema_version: u32,
    operation: &'static str,
    storage_schema: u32,
    storage_profile: String,
    inventory: SegmentArchiveInventory,
    scrub: SegmentArchiveScrub,
    committed_frames_validated: bool,
}

#[derive(Debug, Serialize)]
struct MigrationOutput {
    schema_version: u32,
    operation: &'static str,
    storage_schema: u32,
    storage_profile: String,
    before: SegmentArchiveInventory,
    pre_migration_scrub: SegmentArchiveScrub,
    migration: SegmentMigrationReport,
    after: SegmentArchiveInventory,
    committed_frames_validated: bool,
}

#[derive(Debug, Serialize)]
struct BackupManifestBody {
    schema_version: u32,
    operation: &'static str,
    source: StoreIdentity,
    created_unix_seconds: u64,
    rocks_checkpoint: bool,
    name_pages_copied: bool,
    payload_segments_copied: bool,
}

#[derive(Debug, Serialize)]
struct BackupManifest {
    body: BackupManifestBody,
    body_blake2b_256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("hsrd-storage-maintenance: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    if let Command::MigrateInline { batch_records } = &arguments.command {
        if !(1..=SEGMENT_MIGRATION_MAX_BATCH_RECORDS).contains(batch_records) {
            bail!("--batch-records must be between 1 and {SEGMENT_MIGRATION_MAX_BATCH_RECORDS}");
        }
    }
    let data_dir = require_offline_maintenance_root(&arguments.data_dir)?;
    let raw = open_store(&StoreConfig {
        path: data_dir.join("chain"),
        backend: StoreBackend::RocksDb,
        durability: DurabilityPolicy::Sync,
    })
    .context("failed to acquire the offline hsrd RocksDB")?;
    let identity = validate_clean_store(&raw)?;
    if let Command::Backup { backup_dir } = &arguments.command {
        let output = create_fallback_backup(&data_dir, backup_dir, &raw, identity)?;
        return write_output(&output);
    }
    require_current_store(&identity)?;
    if matches!(&arguments.command, Command::Inventory) {
        require_archive_manifests(&raw)?;
    }
    let store = raw
        .with_segment_archive(data_dir.join("payload-segments"))
        .context("failed to recover block/undo segments")?;

    match arguments.command {
        Command::Backup { .. } => unreachable!("backup returned before archive attachment"),
        Command::Inventory => {
            let inventory = store.segment_archive_inventory()?;
            let scrub = store.scrub_segment_archive()?;
            let output = InventoryOutput {
                schema_version: OUTPUT_SCHEMA_VERSION,
                operation: "inventory",
                storage_schema: SCHEMA_VERSION,
                storage_profile: String::from_utf8_lossy(STORAGE_PROFILE).into_owned(),
                inventory,
                scrub,
                committed_frames_validated: true,
            };
            write_output(&output)
        }
        Command::MigrateInline { batch_records } => {
            let before = store.segment_archive_inventory()?;
            let pre_migration_scrub = store.scrub_segment_archive()?;
            let migration = store.migrate_inline_segment_payloads(batch_records)?;
            let after = store.segment_archive_inventory()?;
            if after.blocks.inline_records != 0 || after.undo.inline_records != 0 {
                bail!("inline payload migration completed with legacy values still present");
            }
            let output = MigrationOutput {
                schema_version: OUTPUT_SCHEMA_VERSION,
                operation: "migrate-inline",
                storage_schema: SCHEMA_VERSION,
                storage_profile: String::from_utf8_lossy(STORAGE_PROFILE).into_owned(),
                before,
                pre_migration_scrub,
                migration,
                after,
                committed_frames_validated: true,
            };
            write_output(&output)
        }
    }
}

fn require_offline_maintenance_root(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", path.display()))?;
    if !canonical.is_dir() {
        bail!("{} is not a directory", canonical.display());
    }
    let marker = canonical.join(STORAGE_MAINTENANCE_MARKER);
    let body = fs::read_to_string(&marker)
        .with_context(|| format!("missing offline-maintenance marker {}", marker.display()))?;
    if body != STORAGE_MAINTENANCE_MARKER_BODY {
        bail!(
            "offline-maintenance marker {} has invalid contents",
            marker.display()
        );
    }
    Ok(canonical)
}

fn validate_clean_store(store: &hns_store::StoreHandle) -> Result<StoreIdentity> {
    let snapshot = store.snapshot()?;
    let schema = snapshot
        .get(ColumnFamily::Meta, MetaKey::SchemaVersion.as_bytes())?
        .context("storage schema marker is missing")?;
    let schema = decode_u32(&schema).context("storage schema marker is malformed")?;
    let profile = snapshot
        .get(ColumnFamily::Meta, MetaKey::StorageProfile.as_bytes())?
        .context("storage profile marker is missing")?;
    let supported = (schema == SCHEMA_VERSION && profile.as_slice() == STORAGE_PROFILE)
        || (schema == LEGACY_SCHEMA_VERSION && profile.as_slice() == LEGACY_STORAGE_PROFILE)
        || (schema == INTERVAL_SCHEMA_VERSION && profile.as_slice() == INTERVAL_STORAGE_PROFILE)
        || (schema == PRE_INTERVAL_SCHEMA_VERSION
            && profile.as_slice() == PRE_INTERVAL_STORAGE_PROFILE);
    if !supported {
        bail!(
            "unsupported or ambiguous storage schema/profile {schema}/`{}`",
            String::from_utf8_lossy(&profile)
        );
    }
    let clean = snapshot
        .get(ColumnFamily::Meta, MetaKey::CleanShutdown.as_bytes())?
        .context("clean-shutdown marker is missing")?;
    if clean.as_slice() != [1] {
        bail!("storage maintenance requires an explicit clean node shutdown");
    }
    Ok(StoreIdentity {
        storage_schema: schema,
        storage_profile: String::from_utf8_lossy(&profile).into_owned(),
    })
}

fn require_current_store(identity: &StoreIdentity) -> Result<()> {
    if identity.storage_schema != SCHEMA_VERSION
        || identity.storage_profile.as_bytes() != STORAGE_PROFILE
    {
        bail!(
            "this operation requires current storage schema/profile {SCHEMA_VERSION}/`{}`; found {}/`{}`",
            String::from_utf8_lossy(STORAGE_PROFILE),
            identity.storage_schema,
            identity.storage_profile
        );
    }
    Ok(())
}

fn require_archive_manifests(store: &hns_store::StoreHandle) -> Result<()> {
    let snapshot = store.snapshot()?;
    let block = snapshot.get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)?;
    let undo = snapshot.get(ColumnFamily::Snapshots, UNDO_SEGMENT_MANIFEST_KEY)?;
    if block.is_none() || undo.is_none() {
        bail!("segment inventory requires initialized block and undo manifests");
    }
    Ok(())
}

fn write_output(output: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout().lock(), output)?;
    println!();
    Ok(())
}

fn create_fallback_backup(
    source: &Path,
    requested_backup: &Path,
    store: &hns_store::StoreHandle,
    identity: StoreIdentity,
) -> Result<BackupManifest> {
    let backup = create_empty_backup_root(source, requested_backup)?;
    store
        .create_rocks_checkpoint(&backup.join("chain"))
        .context("failed to create RocksDB checkpoint")?;
    write_synced_file(
        &backup.join("chain").join(AUDIT_COPY_MARKER),
        AUDIT_COPY_MARKER_BODY.as_bytes(),
    )?;
    sync_directory(&backup.join("chain"))?;
    let name_pages_copied =
        copy_optional_tree(&source.join("name-pages"), &backup.join("name-pages"))
            .context("failed to copy authenticated name pages")?;
    let payload_segments_copied = copy_optional_tree(
        &source.join("payload-segments"),
        &backup.join("payload-segments"),
    )
    .context("failed to copy block/undo payload segments")?;
    let body = BackupManifestBody {
        schema_version: OUTPUT_SCHEMA_VERSION,
        operation: "backup",
        source: identity,
        created_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_secs(),
        rocks_checkpoint: true,
        name_pages_copied,
        payload_segments_copied,
    };
    let canonical_body = serde_json::to_vec(&body)?;
    let manifest = BackupManifest {
        body,
        body_blake2b_256: hex_encode(&blake2b_256(&canonical_body)),
    };
    let encoded = serde_json::to_vec_pretty(&manifest)?;
    write_synced_file(&backup.join(FALLBACK_MANIFEST), &encoded)?;
    sync_directory(&backup)?;
    Ok(manifest)
}

fn create_empty_backup_root(source: &Path, requested: &Path) -> Result<PathBuf> {
    if !requested.is_absolute() || requested.components().any(|part| part.as_os_str() == "..") {
        bail!("--backup-dir must be absolute and contain no parent traversal");
    }
    if requested.try_exists()? {
        bail!("backup target {} already exists", requested.display());
    }
    let parent = requested
        .parent()
        .context("--backup-dir has no parent directory")?
        .canonicalize()
        .context("failed to resolve backup parent directory")?;
    let name = requested
        .file_name()
        .context("--backup-dir has no final path component")?;
    let backup = parent.join(name);
    if backup.starts_with(source) {
        bail!("backup target must not be inside the source data directory");
    }
    fs::create_dir(&backup)
        .with_context(|| format!("failed to create backup root {}", backup.display()))?;
    sync_directory(&parent)?;
    Ok(backup)
}

fn copy_optional_tree(source: &Path, destination: &Path) -> Result<bool> {
    if !source.try_exists()? {
        return Ok(false);
    }
    copy_tree(source, destination)?;
    Ok(true)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to inspect {}", source.display()))?;
    if !metadata.is_dir() {
        bail!(
            "external storage path {} is not a directory",
            source.display()
        );
    }
    fs::create_dir(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("failed to read {}", source.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .with_context(|| format!("failed to inspect {}", source_path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "refusing symlink in external storage tree {}",
                source_path.display()
            );
        }
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            OpenOptions::new()
                .read(true)
                .open(&destination_path)?
                .sync_all()?;
        } else {
            bail!(
                "refusing special file in external storage tree {}",
                source_path.display()
            );
        }
    }
    sync_directory(destination)
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("failed to open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

#[cfg(all(test, feature = "rocksdb-backend"))]
mod tests {
    use super::*;
    use hns_store::{initialize_schema, mark_clean_shutdown};

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hsrd-storage-maintenance-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn fallback_backup_is_complete_reopenable_and_external_file_independent() {
        let root = test_root("backup");
        let source = root.join("source");
        let backup = root.join("fallback");
        fs::create_dir_all(source.join("name-pages")).expect("name pages");
        fs::create_dir_all(source.join("payload-segments")).expect("payload segments");
        fs::write(
            source.join("name-pages/name.pages"),
            b"immutable name pages",
        )
        .expect("write name pages");
        fs::write(
            source.join("payload-segments/block.seg"),
            b"immutable block segment",
        )
        .expect("write block segment");
        let store = open_store(&StoreConfig {
            path: source.join("chain"),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        })
        .expect("open source");
        initialize_schema(&store).expect("initialize source");
        mark_clean_shutdown(&store).expect("mark source clean");
        let identity = validate_clean_store(&store).expect("validate source");

        let manifest =
            create_fallback_backup(&source, &backup, &store, identity).expect("create fallback");
        assert!(manifest.body.rocks_checkpoint);
        assert!(manifest.body.name_pages_copied);
        assert!(manifest.body.payload_segments_copied);
        assert!(backup.join(FALLBACK_MANIFEST).is_file());
        assert_eq!(
            fs::read(backup.join("chain").join(AUDIT_COPY_MARKER)).expect("audit marker"),
            AUDIT_COPY_MARKER_BODY.as_bytes()
        );
        assert_eq!(
            fs::read(backup.join("name-pages/name.pages")).expect("backup name pages"),
            b"immutable name pages"
        );
        assert_eq!(
            fs::read(backup.join("payload-segments/block.seg")).expect("backup segment"),
            b"immutable block segment"
        );
        fs::write(source.join("name-pages/name.pages"), b"changed source").expect("change source");
        assert_eq!(
            fs::read(backup.join("name-pages/name.pages")).expect("independent backup"),
            b"immutable name pages"
        );
        drop(store);

        let reopened = open_store(&StoreConfig {
            path: backup.join("chain"),
            backend: StoreBackend::RocksDb,
            durability: DurabilityPolicy::Sync,
        })
        .expect("reopen checkpoint");
        validate_clean_store(&reopened).expect("validate checkpoint");
        drop(reopened);
        fs::remove_dir_all(root).expect("remove backup fixture");
    }

    #[test]
    fn maintenance_marker_requires_exact_body() {
        let root = test_root("marker");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join(STORAGE_MAINTENANCE_MARKER), b"wrong\n").expect("write wrong marker");
        assert!(require_offline_maintenance_root(&root).is_err());
        fs::write(
            root.join(STORAGE_MAINTENANCE_MARKER),
            STORAGE_MAINTENANCE_MARKER_BODY,
        )
        .expect("write marker");
        assert_eq!(
            require_offline_maintenance_root(&root).expect("valid marker"),
            root.canonicalize().expect("canonical root")
        );
        fs::remove_dir_all(root).expect("remove marker fixture");
    }
}
