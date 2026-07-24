use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use hns_chain::{read_canonical_hash, HeaderRecord};
use hns_consensus::Network;
use hns_state::{
    diagnose_committed_name_tree_node, load_name_tree_snapshot_pins,
    load_stored_name_tree_commit_root, load_stored_name_tree_root, name_page_root_key,
    NamePageRootRecord, NamePageState, NamePageTreeReader, NameTreeSnapshotPin, TreeRoot,
    NAME_PAGE_STATE_KEY,
};
use hns_store::{
    open_store, ColumnFamily, DurabilityPolicy, ReadSnapshot, Store, StoreBackend, StoreConfig,
    WriteBatch,
};

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
    let store = open_store(&StoreConfig {
        path: arguments.data_dir.join("chain"),
        backend: StoreBackend::RocksDb,
        durability: DurabilityPolicy::Sync,
    })
    .context("failed to open hsrd chain store")?
    .with_segment_archive(arguments.data_dir.join("payload-segments"))
    .context("failed to open hsrd payload segments")?;
    let snapshot = store.snapshot()?;
    let heights = snapshot.scan_prefix(ColumnFamily::HeightIndex, b"")?;
    let (height_key, hash_bytes) = heights
        .last()
        .context("active chain has no canonical tip")?;
    let tip_height = u32::from_be_bytes(
        height_key
            .as_slice()
            .try_into()
            .context("canonical tip height is malformed")?,
    );
    let canonical_hash = read_canonical_hash(&snapshot, tip_height)?
        .context("canonical tip height has no block hash")?;
    if canonical_hash.as_bytes() != hash_bytes.as_slice() {
        anyhow::bail!("canonical tip scan and point lookup disagree");
    }
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
    let pins = load_name_tree_snapshot_pins(&snapshot)
        .context("failed to read name-tree snapshot pins")?;
    let mut missing_pin_locators = Vec::new();
    for pin in &pins {
        if pin.root != TreeRoot::ZERO
            && snapshot
                .get(ColumnFamily::Snapshots, &name_page_root_key(pin.root))?
                .is_none()
        {
            missing_pin_locators.push(pin.clone());
        }
    }
    let page_state = snapshot
        .get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)?
        .map(|raw| NamePageState::decode(&raw))
        .transpose()
        .context("failed to decode name-page state")?;
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
    let page_reader = page_state
        .as_ref()
        .map(|state| -> Result<NamePageTreeReader> {
            let paths = (0..=state.manifest.active_segment)
                .map(|segment| {
                    (
                        segment,
                        arguments.data_dir.join("name-pages").join(format!(
                            "name-g{:016x}-s{segment:08x}.pages",
                            state.manifest.generation
                        )),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let locator = state
                .root_locator()
                .context("non-empty name-page state has no root locator")?;
            NamePageTreeReader::open_segments(&paths, state.root, locator)
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
    let metadata = serde_json::json!({
        "tip_height": tip_height,
        "tip_hash": canonical_hash.to_hex(),
        "stored_root": hex::encode(stored_root.as_bytes()),
        "committed_root": hex::encode(committed_root.as_bytes()),
        "snapshot_pin_count": pins.len(),
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
        "find_node_snapshot_pins": pins.iter().filter(|pin| Some(pin.root) == find_node).map(|pin| {
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
        if arguments.repair_page_locator {
            anyhow::bail!(
                "--repair-page-locator and --repair-missing-pin-locators are mutually exclusive"
            );
        }
        let reader = page_reader
            .as_ref()
            .context("missing-pin repair has no page reader")?;
        for pin in &missing_pin_locators {
            validate_canonical_snapshot_pin(&snapshot, pin)?;
        }
        let located = reader
            .locate_records(missing_pin_locators.iter().map(|pin| pin.root))
            .context("failed to locate missing snapshot-pin roots")?;
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
        let mut batch = store.batch();
        let mut repaired = Vec::with_capacity(missing_pin_locators.len());
        for pin in &missing_pin_locators {
            let locator = *located
                .get(&pin.root)
                .expect("every missing pin was located");
            let record = NamePageRootRecord {
                root: pin.root,
                locator,
                height: pin.height,
            };
            batch.put(
                ColumnFamily::Snapshots,
                &name_page_root_key(pin.root),
                &record.encode(),
            )?;
            repaired.push((pin.clone(), locator));
        }
        drop(snapshot);
        store
            .commit(batch)
            .context("failed to publish recovered snapshot-pin locators")?;
        for (pin, locator) in &repaired {
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
        let target = find_node.context("--repair-page-locator requires --find-node")?;
        let matching_pins = pins
            .iter()
            .filter(|pin| pin.root == target)
            .cloned()
            .collect::<Vec<_>>();
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
    let (committed_root, name_count, record_count, path) = diagnose_committed_name_tree_node(
        &snapshot,
        Network::Mainnet.params().names.tree_interval,
        tip_height,
        find_node.unwrap_or(TreeRoot::ZERO),
    )
    .context("failed to reconstruct committed name tree")?;
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
