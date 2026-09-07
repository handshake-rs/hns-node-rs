use std::{
    collections::HashSet,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use hns_chain::{read_canonical_hash, HeaderRecord};
use hns_consensus::Network;
use hns_state::{
    diagnose_committed_name_tree_node, load_stored_name_tree_commit_root,
    load_stored_name_tree_root, name_page_root_key, visit_name_tree_snapshot_pins_bounded,
    NamePageRootLocator, NamePageRootRecord, NamePageState, NamePageTreeReader,
    NameTreeSnapshotPin, NameTreeSnapshotPinScanLimits, StateError, TreeRoot, NAME_PAGE_STATE_KEY,
    NAME_TREE_SNAPSHOT_PIN_COMPAT_MAX_BYTES, NAME_TREE_SNAPSHOT_PIN_COMPAT_MAX_RECORDS,
    NAME_TREE_SNAPSHOT_PIN_SCAN_PAGE_BYTES, NAME_TREE_SNAPSHOT_PIN_SCAN_PAGE_RECORDS,
};
use hns_store::{
    open_store, ColumnFamily, DurabilityPolicy, PrefixScanBudget, ReadSnapshot, Store,
    StoreBackend, StoreConfig, StoreError, WriteBatch, NAME_PAGE_BYTES,
};

const DIAGNOSTIC_MAX_ELAPSED: Duration = Duration::from_secs(30 * 60);
const DIAGNOSTIC_MAX_PAGE_SEGMENTS: u64 = 1_000_000;
const DIAGNOSTIC_MAX_DURABLE_PAGE_BYTES: u64 = 150_000_000_000;
const DIAGNOSTIC_MAX_MISSING_PIN_LOCATORS: u64 = 4_096;
const DIAGNOSTIC_MAX_LOCATOR_PUBLICATION_BYTES: u64 = 1024 * 1024;
const DIAGNOSTIC_MAX_REPORTED_MATCHING_PINS: u64 = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalTip {
    height: u32,
    hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageStorageLimits {
    max_segments: u64,
    max_durable_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RepairLimits {
    max_records: u64,
    max_publication_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RepairEnvelope {
    records: u64,
    publication_bytes: u64,
}

impl RepairEnvelope {
    fn add(&mut self, record_bytes: u64, limits: RepairLimits) -> Result<(), StateError> {
        let records = self.records.saturating_add(1);
        if records > limits.max_records {
            return Err(StateError::ResourceLimit {
                context: "name-page missing-pin locator repair records",
                limit: limits.max_records,
                actual: records,
            });
        }
        let publication_bytes = self.publication_bytes.saturating_add(record_bytes);
        if publication_bytes > limits.max_publication_bytes {
            return Err(StateError::ResourceLimit {
                context: "name-page missing-pin locator repair publication bytes",
                limit: limits.max_publication_bytes,
                actual: publication_bytes,
            });
        }
        self.records = records;
        self.publication_bytes = publication_bytes;
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(about = "Diagnose the offline hsrd committed name tree from canonical state and undo")]
struct Arguments {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    find_node: Option<String>,
    #[arg(long)]
    metadata_only: bool,
    #[arg(long)]
    locate_page_record: bool,
    #[arg(long)]
    repair_page_locator: bool,
    #[arg(long)]
    repair_missing_pin_locators: bool,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    if arguments.repair_missing_pin_locators && arguments.repair_page_locator {
        anyhow::bail!(
            "--repair-page-locator and --repair-missing-pin-locators are mutually exclusive"
        );
    }
    if arguments.repair_page_locator && arguments.find_node.is_none() {
        anyhow::bail!("--repair-page-locator requires --find-node");
    }
    let started = Instant::now();
    let deadline = started
        .checked_add(DIAGNOSTIC_MAX_ELAPSED)
        .unwrap_or(started);
    let store = open_store(&StoreConfig {
        path: arguments.data_dir.join("chain"),
        backend: StoreBackend::RocksDb,
        durability: DurabilityPolicy::Sync,
    })
    .context("failed to open hsrd chain store")?
    .with_segment_archive(arguments.data_dir.join("payload-segments"))
    .context("failed to open hsrd payload segments")?;
    let snapshot = store.snapshot()?;
    let tip = stream_canonical_tip(&snapshot, deadline)?;
    let tip_height = tip.height;
    let canonical_hash = read_canonical_hash(&snapshot, tip_height)?
        .context("canonical tip height has no block hash")?;
    if canonical_hash.as_bytes() != &tip.hash {
        anyhow::bail!("canonical tip scan and point lookup disagree");
    }
    ensure_deadline(deadline, "name-tree diagnostic")?;
    let find_node = arguments
        .find_node
        .as_deref()
        .map(parse_hash)
        .transpose()?
        .map(TreeRoot::new);
    let stored_root =
        load_stored_name_tree_root(&snapshot).context("failed to read stored name-tree root")?;
    let committed_root = load_stored_name_tree_commit_root(&snapshot)
        .context("failed to read committed name-tree root")?;
    let mut missing_pin_locators = Vec::new();
    let mut matching_pins = Vec::new();
    let mut repair_envelope = RepairEnvelope::default();
    let repair_limits = RepairLimits {
        max_records: DIAGNOSTIC_MAX_MISSING_PIN_LOCATORS,
        max_publication_bytes: DIAGNOSTIC_MAX_LOCATOR_PUBLICATION_BYTES,
    };
    let pin_summary = visit_name_tree_snapshot_pins_bounded(
        &snapshot,
        NameTreeSnapshotPinScanLimits {
            max_records: NAME_TREE_SNAPSHOT_PIN_COMPAT_MAX_RECORDS,
            max_bytes: NAME_TREE_SNAPSHOT_PIN_COMPAT_MAX_BYTES,
            page_budget: PrefixScanBudget {
                max_entries: NAME_TREE_SNAPSHOT_PIN_SCAN_PAGE_RECORDS,
                max_bytes: NAME_TREE_SNAPSHOT_PIN_SCAN_PAGE_BYTES,
            },
            deadline,
        },
        |pin| {
            ensure_state_deadline(deadline, "name-tree diagnostic snapshot-pin inventory")?;
            if Some(pin.root) == find_node {
                let actual = u64::try_from(matching_pins.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                if actual > DIAGNOSTIC_MAX_REPORTED_MATCHING_PINS {
                    return Err(StateError::ResourceLimit {
                        context: "name-tree diagnostic matching snapshot pins",
                        limit: DIAGNOSTIC_MAX_REPORTED_MATCHING_PINS,
                        actual,
                    });
                }
                matching_pins.push(pin.clone());
            }
            if pin.root != TreeRoot::ZERO
                && snapshot
                    .get(ColumnFamily::Snapshots, &name_page_root_key(pin.root))?
                    .is_none()
            {
                repair_envelope.add(locator_publication_bytes(pin.root)?, repair_limits)?;
                missing_pin_locators.push(pin.clone());
            }
            Ok(())
        },
    )
    .context("failed to inventory name-tree snapshot pins")?;
    ensure_deadline(deadline, "name-tree diagnostic")?;
    let page_state = snapshot
        .get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)?
        .map(|raw| NamePageState::decode(&raw))
        .transpose()
        .context("failed to decode name-page state")?;
    if let Some(state) = &page_state {
        validate_page_storage_envelope(
            state.manifest.active_segment,
            state.manifest.durable_bytes,
            production_page_storage_limits(),
        )?;
    }
    let target_page_record = find_node
        .map(|target| {
            snapshot
                .get(ColumnFamily::Snapshots, &name_page_root_key(target))?
                .map(|raw| NamePageRootRecord::decode(&raw))
                .transpose()
                .map_err(anyhow::Error::from)
        })
        .transpose()?
        .flatten();
    let target_legacy_record = find_node
        .map(|target| snapshot.get(ColumnFamily::NameTreeNodes, target.as_bytes()))
        .transpose()?
        .flatten();
    if let (Some(state), Some(record)) = (&page_state, &target_page_record) {
        validate_durable_page_locator(record.locator, state, production_page_storage_limits())?;
    }
    let page_reader = page_state
        .as_ref()
        .map(|state| -> Result<NamePageTreeReader> {
            let locator = state
                .root_locator()
                .context("non-empty name-page state has no root locator")?;
            NamePageTreeReader::open_generation(
                arguments.data_dir.join("name-pages"),
                state.manifest.generation,
                state.manifest.active_segment,
                state.root,
                locator,
            )
            .context("failed to open name-page reader")
        })
        .transpose()?;
    if let (Some(reader), Some(target), Some(record)) =
        (&page_reader, find_node, &target_page_record)
    {
        reader
            .insert_root(target, record.locator)
            .context("failed to seed target page locator")?;
    }
    let target_page_record_loads = match (&page_reader, find_node, &target_page_record) {
        (Some(reader), Some(target), Some(_)) => Some(
            reader
                .load(target)
                .context("failed to load target page record")?
                .is_some(),
        ),
        _ => None,
    };
    let located_page_record = match (
        arguments.locate_page_record || arguments.repair_page_locator,
        &page_reader,
        find_node,
    ) {
        (true, Some(reader), Some(target)) => reader
            .locate_record(target)
            .context("failed to locate target in committed page files")?,
        _ => None,
    };
    if let (Some(state), Some(locator)) = (&page_state, located_page_record) {
        validate_durable_page_locator(locator, state, production_page_storage_limits())?;
    }
    ensure_deadline(deadline, "name-tree diagnostic page lookup")?;
    let metadata = serde_json::json!({
        "tip_height": tip_height,
        "tip_hash": canonical_hash.to_hex(),
        "stored_root": hex::encode(stored_root.as_bytes()),
        "committed_root": hex::encode(committed_root.as_bytes()),
        "snapshot_pin_count": pin_summary.records,
        "snapshot_pin_bytes": pin_summary.bytes,
        "snapshot_pins_missing_page_root_record": missing_pin_locators.iter().map(|pin| {
            serde_json::json!({
                "height": pin.height,
                "block_hash": pin.block_hash.to_hex(),
                "root": hex::encode(pin.root.as_bytes()),
            })
        }).collect::<Vec<_>>(),
        "find_node": arguments.find_node,
        "find_node_matches_stored_root": find_node == Some(stored_root),
        "find_node_matches_committed_root": find_node == Some(committed_root),
        "find_node_snapshot_pins": matching_pins.iter().map(|pin| {
            serde_json::json!({
                "height": pin.height,
                "block_hash": pin.block_hash.to_hex(),
            })
        }).collect::<Vec<_>>(),
        "find_node_legacy_record_present": target_legacy_record.is_some(),
        "find_node_page_root_record": target_page_record.as_ref().map(|record| serde_json::json!({
            "height": record.height,
            "generation": record.locator.generation,
            "address": record.locator.address,
        })),
        "find_node_page_record_loads": target_page_record_loads,
        "find_node_located_page_record": located_page_record.map(|locator| serde_json::json!({
            "generation": locator.generation,
            "address": locator.address,
            "segment": locator.page_address().segment(),
            "page": locator.page_address().page(),
            "slot": locator.page_address().slot(),
        })),
        "page_state": page_state.as_ref().map(|state| serde_json::json!({
            "generation": state.manifest.generation,
            "active_segment": state.manifest.active_segment,
            "durable_bytes": state.manifest.durable_bytes,
            "root": hex::encode(state.root.as_bytes()),
            "committed_height": state.committed_height,
            "last_sealed_height": state.last_sealed_height,
        })),
    });
    if arguments.repair_missing_pin_locators {
        let reader = page_reader
            .as_ref()
            .context("missing-pin repair has no page reader")?;
        let mut unique_roots = HashSet::with_capacity(missing_pin_locators.len());
        for pin in &missing_pin_locators {
            ensure_deadline(deadline, "name-tree missing-pin canonical validation")?;
            if !unique_roots.insert(pin.root) {
                anyhow::bail!(
                    "multiple missing snapshot pins refer to root {}; one durable root locator cannot represent conflicting pin heights",
                    hex::encode(pin.root.as_bytes())
                );
            }
            validate_canonical_snapshot_pin(&snapshot, pin)?;
        }
        ensure_deadline(deadline, "name-tree missing-pin page scan")?;
        let located = reader
            .locate_records(missing_pin_locators.iter().map(|pin| pin.root))
            .context("failed to locate missing snapshot-pin roots")?;
        ensure_deadline(deadline, "name-tree missing-pin page scan")?;
        if located.len() != missing_pin_locators.len() {
            let absent = missing_pin_locators
                .iter()
                .filter(|pin| !located.contains_key(&pin.root))
                .map(|pin| hex::encode(pin.root.as_bytes()))
                .collect::<Vec<_>>();
            anyhow::bail!(
                "{} snapshot-pin roots are absent from committed pages: {}",
                absent.len(),
                absent.join(",")
            );
        }
        let mut repaired = Vec::with_capacity(missing_pin_locators.len());
        for pin in &missing_pin_locators {
            ensure_deadline(deadline, "name-tree missing-pin repair planning")?;
            let locator = *located
                .get(&pin.root)
                .expect("every missing pin was located");
            let state = page_state
                .as_ref()
                .expect("page reader construction requires page state");
            validate_durable_page_locator(locator, state, production_page_storage_limits())?;
            repaired.push((pin.clone(), locator));
        }
        if repair_envelope.records != u64::try_from(repaired.len()).unwrap_or(u64::MAX) {
            anyhow::bail!("missing-pin repair envelope disagrees with the bounded repair plan");
        }
        ensure_deadline(deadline, "name-tree missing-pin repair publication")?;
        let mut batch = store.batch();
        for (pin, locator) in &repaired {
            ensure_deadline(deadline, "name-tree missing-pin repair batch construction")?;
            let record = NamePageRootRecord {
                root: pin.root,
                locator: *locator,
                height: pin.height,
            };
            batch.put(
                ColumnFamily::Snapshots,
                &name_page_root_key(pin.root),
                &record.encode(),
            )?;
        }
        ensure_deadline(deadline, "name-tree missing-pin repair commit")?;
        drop(snapshot);
        store
            .commit(batch)
            .context("failed to publish recovered snapshot-pin locators")?;
        for (pin, locator) in &repaired {
            ensure_post_commit_deadline(deadline, "snapshot-pin locator repair")?;
            reader
                .insert_root(pin.root, *locator)
                .context("failed to seed recovered snapshot-pin locator")?;
            if reader
                .load(pin.root)
                .context("failed to verify recovered snapshot-pin locator")?
                .is_none()
            {
                anyhow::bail!(
                    "recovered locator for height {} did not load its record",
                    pin.height
                );
            }
        }
        println!(
            "{}",
            serde_json::json!({
                "metadata": metadata,
                "repair": {
                    "published": repaired.len(),
                    "publication_bytes": repair_envelope.publication_bytes,
                    "roots": repaired.iter().map(|(pin, locator)| serde_json::json!({
                        "height": pin.height,
                        "root": hex::encode(pin.root.as_bytes()),
                        "generation": locator.generation,
                        "address": locator.address,
                    })).collect::<Vec<_>>(),
                }
            })
        );
        return Ok(());
    }
    if arguments.repair_page_locator {
        let target = find_node.expect("repair-page-locator requirement checked before I/O");
        if matching_pins.len() != 1 {
            anyhow::bail!(
                "repair target belongs to {} snapshot pins; expected exactly one",
                matching_pins.len()
            );
        }
        let pin = &matching_pins[0];
        validate_canonical_snapshot_pin(&snapshot, pin)?;
        if target_page_record.is_some() {
            anyhow::bail!("repair target already has a durable page-root locator");
        }
        let locator =
            located_page_record.context("repair target is absent from committed page files")?;
        let record = NamePageRootRecord {
            root: target,
            locator,
            height: pin.height,
        };
        let mut single_repair_envelope = RepairEnvelope::default();
        single_repair_envelope.add(locator_publication_bytes(target)?, repair_limits)?;
        ensure_deadline(deadline, "name-tree page-locator repair publication")?;
        let mut batch = store.batch();
        batch.put(
            ColumnFamily::Snapshots,
            &name_page_root_key(target),
            &record.encode(),
        )?;
        drop(snapshot);
        store
            .commit(batch)
            .context("failed to publish recovered page-root locator")?;
        ensure_post_commit_deadline(deadline, "page-root locator repair")?;
        let reader = page_reader.context("repair target has no page reader")?;
        reader
            .insert_root(target, locator)
            .context("failed to seed recovered page-root locator")?;
        if reader
            .load(target)
            .context("failed to verify recovered page-root locator")?
            .is_none()
        {
            anyhow::bail!("recovered page-root locator did not load its canonical record");
        }
        println!(
            "{}",
            serde_json::json!({
                "metadata": metadata,
                "repair": {
                    "published": true,
                    "publication_bytes": single_repair_envelope.publication_bytes,
                    "height": pin.height,
                    "root": hex::encode(target.as_bytes()),
                    "generation": locator.generation,
                    "address": locator.address,
                }
            })
        );
        return Ok(());
    }
    if arguments.metadata_only {
        println!("{metadata}");
        return Ok(());
    }
    ensure_deadline(deadline, "name-tree diagnostic reconstruction")?;
    let (committed_root, name_count, record_count, path) = diagnose_committed_name_tree_node(
        &snapshot,
        Network::Mainnet.params().names.tree_interval,
        tip_height,
        find_node.unwrap_or(TreeRoot::ZERO),
    )
    .context("failed to reconstruct committed name tree")?;
    ensure_deadline(deadline, "name-tree diagnostic reconstruction")?;
    println!(
        "{}",
        serde_json::json!({
            "tip_height": tip_height,
            "tip_hash": canonical_hash.to_hex(),
            "committed_root": hex::encode(committed_root.as_bytes()),
            "name_count": name_count,
            "record_count": record_count,
            "metadata": metadata,
            "find_node_present": path.is_some(),
            "find_node_path_records": path.as_ref().map(Vec::len),
        })
    );
    Ok(())
}

fn stream_canonical_tip(snapshot: &impl ReadSnapshot, deadline: Instant) -> Result<CanonicalTip> {
    let mut expected_height = 0u64;
    let mut tip = None;
    snapshot
        .visit_prefix(ColumnFamily::HeightIndex, b"", &mut |key, value| {
            ensure_store_deadline(deadline, "name-tree diagnostic canonical-height scan")?;
            let key: [u8; 4] = key.try_into().map_err(|_| {
                StoreError::Schema(format!(
                    "canonical height key contains {} bytes; expected 4",
                    key.len()
                ))
            })?;
            let height = u32::from_be_bytes(key);
            if u64::from(height) != expected_height {
                return Err(StoreError::Schema(format!(
                    "canonical height index expected height {expected_height}, found {height}"
                )));
            }
            let hash: [u8; 32] = value.try_into().map_err(|_| {
                StoreError::Schema(format!(
                    "canonical hash at height {height} contains {} bytes; expected 32",
                    value.len()
                ))
            })?;
            tip = Some(CanonicalTip { height, hash });
            expected_height = expected_height.checked_add(1).ok_or_else(|| {
                StoreError::Schema("canonical height count overflowed".to_owned())
            })?;
            Ok(())
        })
        .context("failed to stream canonical height index")?;
    ensure_deadline(deadline, "name-tree diagnostic canonical-height scan")?;
    tip.context("active chain has no canonical tip")
}

fn validate_page_storage_envelope(
    active_segment: u32,
    durable_bytes: u64,
    limits: PageStorageLimits,
) -> Result<(), StateError> {
    let segments = u64::from(active_segment).saturating_add(1);
    if segments > limits.max_segments {
        return Err(StateError::ResourceLimit {
            context: "name-page diagnostic active segments",
            limit: limits.max_segments,
            actual: segments,
        });
    }
    if durable_bytes > limits.max_durable_bytes {
        return Err(StateError::ResourceLimit {
            context: "name-page diagnostic durable page bytes",
            limit: limits.max_durable_bytes,
            actual: durable_bytes,
        });
    }
    Ok(())
}

const fn production_page_storage_limits() -> PageStorageLimits {
    PageStorageLimits {
        max_segments: DIAGNOSTIC_MAX_PAGE_SEGMENTS,
        max_durable_bytes: DIAGNOSTIC_MAX_DURABLE_PAGE_BYTES,
    }
}

fn validate_durable_page_locator(
    locator: NamePageRootLocator,
    state: &NamePageState,
    limits: PageStorageLimits,
) -> Result<(), StateError> {
    if locator.generation != state.manifest.generation {
        return Err(StateError::Codec(format!(
            "name-page locator generation {} disagrees with active generation {}",
            locator.generation, state.manifest.generation
        )));
    }
    let address = locator.page_address();
    if address.segment() > state.manifest.active_segment {
        return Err(StateError::Codec(format!(
            "name-page locator segment {} exceeds active segment {}",
            address.segment(),
            state.manifest.active_segment
        )));
    }
    let page_end = u64::from(address.page())
        .saturating_add(1)
        .saturating_mul(NAME_PAGE_BYTES as u64);
    if page_end > limits.max_durable_bytes {
        return Err(StateError::ResourceLimit {
            context: "name-page diagnostic locator page bytes",
            limit: limits.max_durable_bytes,
            actual: page_end,
        });
    }
    if address.segment() == state.manifest.active_segment && page_end > state.manifest.durable_bytes
    {
        return Err(StateError::Codec(format!(
            "name-page locator at segment {} page {} extends beyond durable active-segment bytes {}",
            address.segment(),
            address.page(),
            state.manifest.durable_bytes
        )));
    }
    Ok(())
}

fn locator_publication_bytes(root: TreeRoot) -> Result<u64, StateError> {
    let key = name_page_root_key(root);
    let value = NamePageRootRecord {
        root,
        locator: NamePageRootLocator {
            generation: 0,
            address: 0,
        },
        height: 0,
    }
    .encode();
    key.len()
        .checked_add(value.len())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| StateError::Codec("page-root publication byte count overflowed".to_owned()))
}

fn ensure_deadline(deadline: Instant, context: &'static str) -> Result<()> {
    if Instant::now() >= deadline {
        anyhow::bail!("{context} exceeded its monotonic deadline");
    }
    Ok(())
}

fn ensure_store_deadline(deadline: Instant, context: &'static str) -> Result<(), StoreError> {
    if Instant::now() >= deadline {
        return Err(StoreError::DeadlineExceeded { context });
    }
    Ok(())
}

fn ensure_state_deadline(deadline: Instant, context: &'static str) -> Result<(), StateError> {
    if Instant::now() >= deadline {
        return Err(StateError::DeadlineExceeded { context });
    }
    Ok(())
}

fn ensure_post_commit_deadline(deadline: Instant, repair: &'static str) -> Result<()> {
    if Instant::now() >= deadline {
        anyhow::bail!(
            "{repair} committed atomically, but post-commit verification exceeded its monotonic deadline"
        );
    }
    Ok(())
}

fn parse_hash(raw: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(raw).context("node hash is not hexadecimal")?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("node hash has {} bytes; expected 32", bytes.len())
    })
}

fn validate_canonical_snapshot_pin(
    snapshot: &impl ReadSnapshot,
    pin: &NameTreeSnapshotPin,
) -> Result<()> {
    if read_canonical_hash(snapshot, pin.height)? != Some(pin.block_hash) {
        anyhow::bail!(
            "snapshot pin at height {} is not bound to the canonical block",
            pin.height
        );
    }
    let next_height = pin
        .height
        .checked_add(1)
        .context("snapshot pin height overflowed")?;
    let next_hash = read_canonical_hash(snapshot, next_height)?
        .context("snapshot pin has no next canonical header")?;
    let next_raw = snapshot
        .get(ColumnFamily::Headers, next_hash.as_bytes())?
        .context("snapshot pin next canonical header is missing")?;
    let next_header =
        HeaderRecord::decode(&next_raw).context("snapshot pin next header is malformed")?;
    if next_header.hash != next_hash
        || next_header.height != next_height
        || TreeRoot::new(next_header.header.tree_root) != pin.root
    {
        anyhow::bail!(
            "snapshot pin at height {} does not match the next canonical header commitment",
            pin.height
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_store::{MemoryStore, NamePageAddress, SegmentManifest};

    #[test]
    fn page_storage_envelope_accepts_exact_limits_and_rejects_one_over() {
        let limits = PageStorageLimits {
            max_segments: 7,
            max_durable_bytes: 11,
        };
        validate_page_storage_envelope(6, 11, limits).expect("exact limits");

        let segment_error =
            validate_page_storage_envelope(7, 11, limits).expect_err("one segment over must fail");
        assert!(matches!(
            segment_error,
            StateError::ResourceLimit {
                context: "name-page diagnostic active segments",
                limit: 7,
                actual: 8,
            }
        ));

        let byte_error = validate_page_storage_envelope(6, 12, limits)
            .expect_err("one durable byte over must fail");
        assert!(matches!(
            byte_error,
            StateError::ResourceLimit {
                context: "name-page diagnostic durable page bytes",
                limit: 11,
                actual: 12,
            }
        ));
    }

    #[test]
    fn repair_envelope_accepts_exact_limits_and_rejects_each_one_over() {
        let limits = RepairLimits {
            max_records: 2,
            max_publication_bytes: 10,
        };
        let mut exact = RepairEnvelope::default();
        exact.add(4, limits).expect("first repair");
        exact.add(6, limits).expect("exact repair envelope");
        assert_eq!(
            exact,
            RepairEnvelope {
                records: 2,
                publication_bytes: 10,
            }
        );

        let count_error = exact.add(0, limits).expect_err("one record over must fail");
        assert!(matches!(
            count_error,
            StateError::ResourceLimit {
                context: "name-page missing-pin locator repair records",
                limit: 2,
                actual: 3,
            }
        ));
        assert_eq!(exact.records, 2, "failed additions must not mutate totals");

        let mut bytes = RepairEnvelope::default();
        let byte_error = bytes
            .add(11, limits)
            .expect_err("one publication byte over must fail");
        assert!(matches!(
            byte_error,
            StateError::ResourceLimit {
                context: "name-page missing-pin locator repair publication bytes",
                limit: 10,
                actual: 11,
            }
        ));
        assert_eq!(bytes, RepairEnvelope::default());
    }

    #[test]
    fn durable_locator_accepts_exact_tail_and_rejects_one_page_over() {
        let page_bytes = NAME_PAGE_BYTES as u64;
        let limits = PageStorageLimits {
            max_segments: 3,
            max_durable_bytes: 3 * page_bytes,
        };
        let state = NamePageState {
            manifest: SegmentManifest {
                generation: 7,
                active_segment: 2,
                durable_bytes: 3 * page_bytes,
            },
            root: TreeRoot::ZERO,
            root_address: None,
            committed_height: None,
            last_sealed_height: None,
        };
        let exact = NamePageRootLocator::new(
            7,
            NamePageAddress::new(2, 2, 0).expect("exact-tail address"),
        );
        validate_durable_page_locator(exact, &state, limits).expect("exact durable tail");

        let one_over =
            NamePageRootLocator::new(7, NamePageAddress::new(2, 3, 0).expect("one-over address"));
        let error = validate_durable_page_locator(
            one_over,
            &NamePageState {
                manifest: SegmentManifest {
                    durable_bytes: 4 * page_bytes,
                    ..state.manifest
                },
                ..state.clone()
            },
            limits,
        )
        .expect_err("one page beyond the byte limit must fail");
        assert!(matches!(
            error,
            StateError::ResourceLimit {
                context: "name-page diagnostic locator page bytes",
                limit,
                actual,
            } if limit == 3 * page_bytes && actual == 4 * page_bytes
        ));

        let active_tail_error = validate_durable_page_locator(
            one_over,
            &state,
            PageStorageLimits {
                max_durable_bytes: 4 * page_bytes,
                ..limits
            },
        )
        .expect_err("one page beyond the durable active tail must fail");
        assert!(active_tail_error
            .to_string()
            .contains("extends beyond durable active-segment bytes"));
    }

    #[test]
    fn canonical_tip_scan_streams_and_rejects_a_gap() {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .expect("test deadline");
        let store = MemoryStore::new();
        let mut batch = store.batch();
        for height in 0u32..=2 {
            batch
                .put(
                    ColumnFamily::HeightIndex,
                    &height.to_be_bytes(),
                    &[u8::try_from(height + 1).expect("test tag"); 32],
                )
                .expect("stage canonical height");
        }
        store.commit(batch).expect("commit canonical heights");
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            stream_canonical_tip(&snapshot, deadline).expect("stream tip"),
            CanonicalTip {
                height: 2,
                hash: [3; 32],
            }
        );

        let gap_store = MemoryStore::new();
        let mut gap_batch = gap_store.batch();
        for height in [0u32, 2] {
            gap_batch
                .put(
                    ColumnFamily::HeightIndex,
                    &height.to_be_bytes(),
                    &[u8::try_from(height + 1).expect("test tag"); 32],
                )
                .expect("stage gapped height");
        }
        gap_store.commit(gap_batch).expect("commit gapped heights");
        let gap_snapshot = gap_store.snapshot().expect("gap snapshot");
        let error =
            stream_canonical_tip(&gap_snapshot, deadline).expect_err("height gap must fail");
        assert!(format!("{error:#}").contains("expected height 1, found 2"));
    }
}
