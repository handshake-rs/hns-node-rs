use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use clap::Parser;
use hns_consensus::Network;
use hns_primitives::{hex_encode, Coin, Writer};
use hns_state::{
    decode_coin, derive_working_name_tree_root, encode_outpoint_key, BlockUndo, NamePageRootRecord,
    NamePageSnapshot, NamePageState, NamePageTreeReader, NAME_PAGE_ROOT_PREFIX,
    NAME_PAGE_STATE_KEY,
};
use hns_store::{
    open_store, ColumnFamily, DurabilityPolicy, MetaKey, ReadSnapshot, Store, StoreBackend,
    StoreConfig, StoreError, BLOCK_SEGMENT_MANIFEST_KEY, UNDO_SEGMENT_MANIFEST_KEY,
};
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const AUDIT_COPY_MARKER: &str = ".hsrd-state-audit-copy";
const AUDIT_COPY_MARKER_BODY: &str = "hsrd-state-audit-copy-v1\n";
const DIGEST_DOMAIN: &[u8] = b"meshmine-state-manifest-v1\0";
const UTXO_PROJECTION: [&str; 6] = [
    "outpoint", "value", "height", "coinbase", "address", "covenant",
];
const EXCLUDED_HSD_UTXO_FIELDS: [&str; 1] = ["origin_transaction_version"];

#[derive(Debug, Parser)]
#[command(
    about = "Export a constant-space semantic state manifest from an offline hsrd database copy"
)]
struct Arguments {
    /// Copied hsrd RocksDB chain directory. The live node database is refused.
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Debug, Serialize)]
struct Manifest {
    schema_version: u32,
    producer: &'static str,
    network: String,
    height: u32,
    block_hash: String,
    genesis_hash: String,
    components: Components,
}

#[derive(Debug, Serialize)]
struct Components {
    utxo: UtxoManifest,
    names: DigestManifest,
    roots: RootManifest,
    undo: UndoManifest,
}

#[derive(Debug, Serialize)]
struct DigestManifest {
    count: u64,
    digest: String,
}

#[derive(Debug, Serialize)]
struct UtxoManifest {
    count: u64,
    digest: String,
    total_value: u64,
    semantic_projection: &'static [&'static str],
    excluded_hsd_archival_fields: &'static [&'static str],
}

#[derive(Debug, Serialize)]
struct RootManifest {
    working: String,
    committed: String,
}

#[derive(Debug, Serialize)]
struct UndoManifest {
    count: u64,
    digest: String,
    minimum_height: Option<u32>,
    maximum_height: Option<u32>,
}

#[derive(Debug)]
struct OrderedDigest {
    hasher: Blake2bVar,
    count: u64,
    previous_key: Option<Vec<u8>>,
}

impl OrderedDigest {
    fn new(component: &[u8]) -> Self {
        let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output size");
        hasher.update(DIGEST_DOMAIN);
        hasher.update(component);
        Self {
            hasher,
            count: 0,
            previous_key: None,
        }
    }

    fn push(&mut self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        if self
            .previous_key
            .as_deref()
            .is_some_and(|previous| previous >= key)
        {
            return Err(StoreError::Schema(
                "state manifest input is not in strict key order".to_owned(),
            ));
        }

        let key_len = u32::try_from(key.len())
            .map_err(|_| StoreError::Schema("manifest key exceeds u32".to_owned()))?
            .to_be_bytes();
        let value_len = u64::try_from(value.len())
            .map_err(|_| StoreError::Schema("manifest value exceeds u64".to_owned()))?
            .to_be_bytes();
        self.hasher.update(&[0x01]);
        self.hasher.update(&key_len);
        self.hasher.update(key);
        self.hasher.update(&value_len);
        self.hasher.update(value);
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| StoreError::Schema("manifest record count overflow".to_owned()))?;
        self.previous_key = Some(key.to_vec());
        Ok(())
    }

    fn finish(mut self) -> DigestManifest {
        let count = self.count;
        let count_bytes = count.to_be_bytes();
        self.hasher.update(&[0x02]);
        self.hasher.update(&count_bytes);
        let mut digest = [0; 32];
        self.hasher
            .finalize_variable(&mut digest)
            .expect("valid BLAKE2b output buffer");
        DigestManifest {
            count,
            digest: hex_encode(&digest),
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("hsrd-state-manifest: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    let data_dir = require_audit_copy(&arguments.data_dir)?;
    let store = open_store(&StoreConfig {
        path: data_dir.clone(),
        backend: StoreBackend::RocksDb,
        durability: DurabilityPolicy::Sync,
    })
    .context("failed to open copied hsrd store")?;
    let snapshot = store
        .snapshot()
        .context("failed to inspect copied hsrd segment manifests")?;
    let block_segments = snapshot
        .get(ColumnFamily::Snapshots, BLOCK_SEGMENT_MANIFEST_KEY)
        .context("failed to inspect copied block-segment manifest")?;
    let undo_segments = snapshot
        .get(ColumnFamily::Snapshots, UNDO_SEGMENT_MANIFEST_KEY)
        .context("failed to inspect copied undo-segment manifest")?;
    drop(snapshot);
    let store = match (block_segments, undo_segments) {
        (None, None) => store,
        (Some(_), Some(_)) => {
            let backup_root = data_dir.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "copied chain directory {} has no backup root",
                    data_dir.display()
                )
            })?;
            let payload_segments = backup_root.join("payload-segments");
            if !payload_segments.is_dir() {
                bail!(
                    "copied store has segment manifests but sibling archive {} is missing",
                    payload_segments.display()
                );
            }
            store
                .with_segment_archive(payload_segments)
                .context("failed to attach copied block/undo segment archive")?
        }
        _ => bail!("copied store has only one of the block/undo segment manifests"),
    };
    let snapshot = store.snapshot().context("failed to snapshot hsrd store")?;

    let network = required_meta(&snapshot, MetaKey::Network, "network")?;
    let network = decode_network_binding(&network)?;
    let genesis_hash = required_hash_meta(&snapshot, MetaKey::GenesisHash, "genesis hash")?;
    let block_hash = required_hash_meta(&snapshot, MetaKey::BestBlockHash, "best block hash")?;
    let stored_root =
        required_hash_meta(&snapshot, MetaKey::NameTreeRoot, "stored name-tree root")?;
    let committed_root = required_hash_meta(
        &snapshot,
        MetaKey::NameTreeCommitRoot,
        "committed name-tree root",
    )?;
    if stored_root != committed_root {
        bail!("stored and committed name-tree roots disagree");
    }

    let height = active_chain_height(&snapshot, &block_hash)?;
    let utxo = audit_utxos(&snapshot)?;
    let names = audit_raw_component(&snapshot, ColumnFamily::NameState, b"name-state")?;
    let page_reader = open_name_page_reader(&snapshot, &data_dir)?;
    let working_root = match page_reader.as_ref() {
        Some(reader) => derive_working_name_tree_root(&NamePageSnapshot::with_legacy_fallback(
            &snapshot, reader,
        )),
        None => derive_working_name_tree_root(&snapshot),
    }
    .context("failed to derive current working name-tree root")?;
    let undo = audit_undo(&snapshot)?;

    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        producer: "hsrd",
        network,
        height,
        block_hash: hex_encode(&block_hash),
        genesis_hash: hex_encode(&genesis_hash),
        components: Components {
            utxo,
            names,
            roots: RootManifest {
                working: hex_encode(working_root.as_bytes()),
                committed: hex_encode(&committed_root),
            },
            undo,
        },
    };

    serde_json::to_writer_pretty(std::io::stdout().lock(), &manifest)?;
    println!();
    Ok(())
}

fn open_name_page_reader<S: ReadSnapshot>(
    snapshot: &S,
    chain_dir: &Path,
) -> Result<Option<NamePageTreeReader>> {
    let Some(raw) = snapshot
        .get(ColumnFamily::Snapshots, NAME_PAGE_STATE_KEY)
        .context("failed to read name-page state")?
    else {
        return Ok(None);
    };
    let state = NamePageState::decode(&raw).context("failed to decode name-page state")?;
    let root_locator = state
        .root_locator()
        .context("non-empty name-page state has no root locator")?;
    let root = chain_dir
        .parent()
        .context("chain directory has no parent for name-page segments")?;
    let directory = root.join("name-pages");
    let mut paths = BTreeMap::new();
    for segment in 0..=state.manifest.active_segment {
        let path = directory.join(format!(
            "name-g{:016x}-s{segment:08x}.pages",
            state.manifest.generation
        ));
        if !path.is_file() {
            bail!("name-page segment {} is missing", path.display());
        }
        paths.insert(segment, path);
    }
    let reader = NamePageTreeReader::open_segments(&paths, state.root, root_locator)
        .context("failed to open name-page segments")?;
    for (key, raw) in snapshot
        .scan_prefix(ColumnFamily::Snapshots, NAME_PAGE_ROOT_PREFIX)
        .context("failed to scan name-page root locators")?
    {
        let record =
            NamePageRootRecord::decode(&raw).context("failed to decode name-page root locator")?;
        if key != hns_state::name_page_root_key(record.root) {
            bail!("name-page root locator key does not match its record");
        }
        reader
            .insert_root(record.root, record.locator)
            .context("failed to seed name-page root locator")?;
    }
    Ok(Some(reader))
}

fn decode_network_binding(binding: &[u8]) -> Result<String> {
    let [canonical_id] = binding else {
        bail!(
            "network metadata must contain exactly one canonical network byte, got {} bytes",
            binding.len()
        );
    };
    let network = Network::from_canonical_id(*canonical_id)
        .with_context(|| format!("unknown canonical network id {canonical_id}"))?;
    Ok(network.to_string())
}

fn require_audit_copy(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", path.display()))?;
    if !canonical.is_dir() {
        bail!("{} is not a directory", canonical.display());
    }
    let marker = canonical.join(AUDIT_COPY_MARKER);
    let body = fs::read_to_string(&marker)
        .with_context(|| format!("missing offline-copy marker {}", marker.display()))?;
    if body != AUDIT_COPY_MARKER_BODY {
        bail!(
            "offline-copy marker {} has invalid contents",
            marker.display()
        );
    }
    Ok(canonical)
}

fn required_meta<S: ReadSnapshot>(
    snapshot: &S,
    key: MetaKey,
    label: &str,
) -> Result<Vec<u8>, StoreError> {
    snapshot
        .get(ColumnFamily::Meta, key.as_bytes())?
        .ok_or_else(|| StoreError::Schema(format!("missing {label} metadata")))
}

fn required_hash_meta<S: ReadSnapshot>(
    snapshot: &S,
    key: MetaKey,
    label: &str,
) -> Result<[u8; 32], StoreError> {
    required_meta(snapshot, key, label)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            StoreError::Schema(format!(
                "{label} metadata is {} bytes, expected 32",
                bytes.len()
            ))
        })
}

fn active_chain_height<S: ReadSnapshot>(
    snapshot: &S,
    expected_tip: &[u8; 32],
) -> Result<u32, StoreError> {
    let mut expected_height = 0u32;
    let mut last_hash = None;
    snapshot.visit_prefix(ColumnFamily::HeightIndex, b"", &mut |key, value| {
        let key: [u8; 4] = key.try_into().map_err(|_| {
            StoreError::Schema("active-chain height key is not four bytes".to_owned())
        })?;
        let height = u32::from_be_bytes(key);
        if height != expected_height {
            return Err(StoreError::Schema(format!(
                "active chain skips height {expected_height}; next key is {height}"
            )));
        }
        let hash: [u8; 32] = value.try_into().map_err(|_| {
            StoreError::Schema(format!(
                "active-chain hash at height {height} is not 32 bytes"
            ))
        })?;
        last_hash = Some(hash);
        expected_height = expected_height
            .checked_add(1)
            .ok_or_else(|| StoreError::Schema("active-chain height overflow".to_owned()))?;
        Ok(())
    })?;
    let tip = last_hash
        .as_ref()
        .ok_or_else(|| StoreError::Schema("active chain is empty".to_owned()))?;
    if tip != expected_tip {
        return Err(StoreError::Schema(
            "best-block metadata disagrees with active-chain tip".to_owned(),
        ));
    }
    Ok(expected_height - 1)
}

fn audit_utxos<S: ReadSnapshot>(snapshot: &S) -> Result<UtxoManifest, StoreError> {
    let mut digest = OrderedDigest::new(b"utxo");
    let mut total_value = 0u64;
    let mut group_txid: Option<[u8; 32]> = None;
    let mut group = Vec::<(u32, Vec<u8>)>::new();
    snapshot.visit_prefix(ColumnFamily::Utxo, b"", &mut |key, value| {
        let coin = decode_coin(value)
            .map_err(|error| StoreError::Schema(format!("invalid UTXO coin: {error}")))?;
        if encode_outpoint_key(&coin.outpoint) != key {
            return Err(StoreError::Schema(
                "UTXO key disagrees with encoded coin outpoint".to_owned(),
            ));
        }
        let txid = *coin.outpoint.txid.as_bytes();
        if group_txid.is_some_and(|current| current != txid) {
            flush_utxo_group(
                &mut digest,
                group_txid.take().expect("group txid"),
                &mut group,
            )?;
        }
        group_txid = Some(txid);
        total_value = total_value
            .checked_add(coin.value)
            .ok_or_else(|| StoreError::Schema("UTXO value total overflow".to_owned()))?;
        group.push((coin.outpoint.index, canonical_coin(&coin)));
        Ok(())
    })?;
    if let Some(txid) = group_txid {
        flush_utxo_group(&mut digest, txid, &mut group)?;
    }
    let component = digest.finish();
    Ok(UtxoManifest {
        count: component.count,
        digest: component.digest,
        total_value,
        semantic_projection: &UTXO_PROJECTION,
        excluded_hsd_archival_fields: &EXCLUDED_HSD_UTXO_FIELDS,
    })
}

fn flush_utxo_group(
    digest: &mut OrderedDigest,
    txid: [u8; 32],
    group: &mut Vec<(u32, Vec<u8>)>,
) -> Result<(), StoreError> {
    group.sort_unstable_by_key(|(index, _)| *index);
    let mut previous_index = None;
    for (index, value) in group.drain(..) {
        if previous_index == Some(index) {
            return Err(StoreError::Schema(format!(
                "duplicate UTXO index {index} for transaction {}",
                hex_encode(&txid)
            )));
        }
        previous_index = Some(index);
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(&txid);
        key.extend_from_slice(&index.to_be_bytes());
        digest.push(&key, &value)?;
    }
    Ok(())
}

fn canonical_coin(coin: &Coin) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u64(coin.value);
    writer.write_u32(coin.height);
    writer.write_u8(u8::from(coin.coinbase));
    coin.address.write_to(&mut writer);
    coin.covenant.write_to(&mut writer);
    writer.finish()
}

fn audit_raw_component<S: ReadSnapshot>(
    snapshot: &S,
    family: ColumnFamily,
    domain: &[u8],
) -> Result<DigestManifest, StoreError> {
    let mut digest = OrderedDigest::new(domain);
    snapshot.visit_prefix(family, b"", &mut |key, value| digest.push(key, value))?;
    Ok(digest.finish())
}

fn audit_undo<S: ReadSnapshot>(snapshot: &S) -> Result<UndoManifest, StoreError> {
    let mut digest = OrderedDigest::new(b"hsrd-undo");
    let mut minimum_height: Option<u32> = None;
    let mut maximum_height: Option<u32> = None;
    snapshot.visit_prefix(ColumnFamily::Undo, b"", &mut |key, value| {
        let undo = BlockUndo::decode(value)
            .map_err(|error| StoreError::Schema(format!("invalid block undo: {error}")))?;
        if undo.block_hash.as_bytes() != key {
            return Err(StoreError::Schema(
                "block-undo key disagrees with encoded hash".to_owned(),
            ));
        }
        minimum_height = Some(
            minimum_height
                .map(|current| current.min(undo.height))
                .unwrap_or(undo.height),
        );
        maximum_height = Some(
            maximum_height
                .map(|current| current.max(undo.height))
                .unwrap_or(undo.height),
        );
        digest.push(key, value)
    })?;
    let component = digest.finish();
    Ok(UndoManifest {
        count: component.count,
        digest: component.digest,
        minimum_height,
        maximum_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{Address, Covenant, CovenantKind, Outpoint, Txid};
    use hns_state::encode_coin;
    use hns_store::{MemoryStore, WriteBatch};

    #[test]
    fn ordered_digest_is_order_and_domain_sensitive() {
        let mut left = OrderedDigest::new(b"utxo");
        left.push(b"a", b"one").expect("first");
        left.push(b"b", b"two").expect("second");
        let left = left.finish();

        let mut right = OrderedDigest::new(b"name-state");
        right.push(b"a", b"one").expect("first");
        right.push(b"b", b"two").expect("second");
        let right = right.finish();

        assert_ne!(left.digest, right.digest);
        assert_eq!(left.count, 2);
        assert_eq!(
            left.digest,
            "52bd2bf297d56178e215aa204234faaa0fbe8efc03caa28ac8b059401894fc7b"
        );
    }

    #[test]
    fn ordered_digest_rejects_duplicate_or_reversed_keys() {
        let mut digest = OrderedDigest::new(b"utxo");
        digest.push(b"b", b"one").expect("first");
        assert!(digest.push(b"b", b"duplicate").is_err());
        assert!(digest.push(b"a", b"reversed").is_err());
    }

    #[test]
    fn audit_copy_marker_is_fail_closed() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-state-manifest-marker-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create");
        assert!(require_audit_copy(&path).is_err());
        fs::write(path.join(AUDIT_COPY_MARKER), AUDIT_COPY_MARKER_BODY).expect("marker");
        assert_eq!(
            require_audit_copy(&path).expect("accepted"),
            path.canonicalize().expect("canonical")
        );
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn network_binding_uses_canonical_network_names() {
        for (canonical_id, expected) in [
            (0, "mainnet"),
            (1, "testnet"),
            (2, "regtest"),
            (3, "simnet"),
        ] {
            assert_eq!(
                decode_network_binding(&[canonical_id]).expect("canonical network"),
                expected
            );
        }
        assert!(decode_network_binding(&[]).is_err());
        assert!(decode_network_binding(&[0, 1]).is_err());
        assert!(decode_network_binding(&[4]).is_err());
    }

    #[test]
    fn utxo_audit_canonicalizes_little_endian_store_indexes() {
        let store = MemoryStore::new();
        let txid = Txid::new([0x42; 32]);
        let mut batch = store.batch();
        for (index, value) in [(1, 3), (256, 5)] {
            let coin = Coin {
                outpoint: Outpoint { txid, index },
                value,
                height: 7,
                coinbase: false,
                address: Address::new(0, vec![0x51; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            };
            batch
                .put(
                    ColumnFamily::Utxo,
                    &encode_outpoint_key(&coin.outpoint),
                    &encode_coin(&coin),
                )
                .expect("put coin");
        }
        store.commit(batch).expect("commit");

        let snapshot = store.snapshot().expect("snapshot");
        let manifest = audit_utxos(&snapshot).expect("audit");
        assert_eq!(manifest.count, 2);
        assert_eq!(manifest.total_value, 8);

        let mut expected = OrderedDigest::new(b"utxo");
        for (index, value) in [(1, 3), (256, 5)] {
            let coin = Coin {
                outpoint: Outpoint { txid, index },
                value,
                height: 7,
                coinbase: false,
                address: Address::new(0, vec![0x51; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            };
            let mut key = txid.as_bytes().to_vec();
            key.extend_from_slice(&index.to_be_bytes());
            expected
                .push(&key, &canonical_coin(&coin))
                .expect("canonical coin");
        }
        assert_eq!(manifest.digest, expected.finish().digest);
    }
}
