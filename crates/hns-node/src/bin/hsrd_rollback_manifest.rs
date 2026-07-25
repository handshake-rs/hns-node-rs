use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use clap::Parser;
use hns_chain::{read_canonical_hash, BlockIndexRecord, RawBlockRecord};
use hns_consensus::Network;
use hns_primitives::{hex_encode, Block, BlockHash, Coin, Outpoint};
use hns_state::{encode_coin, encode_name_state, BlockUndo};
use hns_store::{
    open_store, ColumnFamily, DurabilityPolicy, MetaKey, ReadSnapshot, Store, StoreBackend,
    StoreConfig,
};
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    about = "Export a read-only normalized disconnect/reconnect transcript from a stopped hsrd node"
)]
struct Arguments {
    /// hsrd node data directory containing chain/ and payload-segments/.
    #[arg(long)]
    data_dir: PathBuf,

    /// Write the manifest to this path instead of standard output.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct Manifest {
    schema_version: u32,
    producer: &'static str,
    network: &'static str,
    source_height: u32,
    source_block_hash: String,
    first_height: u32,
    keep_blocks: u32,
    tree_interval: u32,
    source_airdrop_field_size: usize,
    source_airdrop_field_digest: String,
    source_airdrop_spent: u64,
    records: Vec<Transition>,
}

#[derive(Debug, Serialize)]
struct Transition {
    height: u32,
    block_hash: String,
    previous_block_hash: String,
    raw_block_size: usize,
    raw_block_digest: String,
    roots: Roots,
    spent_coins: Vec<CoinTransition>,
    created_coins: Vec<CoinTransition>,
    airdrop_positions: Vec<u32>,
    names: Vec<NameTransition>,
}

#[derive(Debug, Serialize)]
struct Roots {
    previous_committed: String,
    resulting_committed: String,
    interval_boundary: bool,
}

#[derive(Debug, Serialize)]
struct CoinTransition {
    outpoint: String,
    coin: String,
}

#[derive(Debug, Serialize)]
struct NameTransition {
    name_hash: String,
    before: Option<String>,
    after: Option<String>,
}

struct LoadedTransition {
    height: u32,
    block_hash: BlockHash,
    raw: Vec<u8>,
    block: Block,
    undo: BlockUndo,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("hsrd-rollback-manifest: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    let data_dir = arguments
        .data_dir
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", arguments.data_dir.display()))?;
    let chain_dir = data_dir.join("chain");
    let segments_dir = data_dir.join("payload-segments");
    if !chain_dir.is_dir() {
        bail!("chain directory {} is missing", chain_dir.display());
    }
    if !segments_dir.is_dir() {
        bail!(
            "payload segment directory {} is missing",
            segments_dir.display()
        );
    }

    let store = open_store(&StoreConfig {
        path: chain_dir,
        backend: StoreBackend::RocksDb,
        durability: DurabilityPolicy::Sync,
    })
    .context("failed to open stopped hsrd store (is the node still running?)")?
    .with_segment_archive(segments_dir)
    .context("failed to attach hsrd block/undo segment archive")?;
    let snapshot = store.snapshot().context("failed to snapshot hsrd store")?;

    let network = decode_network(&required_meta(&snapshot, MetaKey::Network, "network")?)?;
    let params = network.params();
    let keep_blocks = params.block.keep_blocks;
    let tree_interval = params.names.tree_interval;
    let source_block_hash = BlockHash::new(required_hash_meta(
        &snapshot,
        MetaKey::BestBlockHash,
        "best block",
    )?);
    let source_height = active_chain_height(&snapshot, &source_block_hash)?;
    let first_height = source_height
        .saturating_sub(keep_blocks.saturating_sub(1))
        .max(1);
    let current_committed = required_hash_meta(
        &snapshot,
        MetaKey::NameTreeCommitRoot,
        "committed name-tree root",
    )?;
    let source_airdrop_field = required_meta(&snapshot, MetaKey::AirdropField, "airdrop field")?;
    let source_airdrop_field_digest = digest(&source_airdrop_field);
    let source_airdrop_spent = source_airdrop_field
        .iter()
        .map(|byte| u64::from(byte.count_ones()))
        .sum();
    let mut reversed_airdrop_field = source_airdrop_field.clone();

    let mut loaded = Vec::with_capacity((source_height - first_height + 1) as usize);
    let mut changed_names = BTreeSet::<[u8; 32]>::new();
    for height in first_height..=source_height {
        let block_hash = read_canonical_hash(&snapshot, height)
            .with_context(|| format!("failed to read canonical hash at height {height}"))?
            .ok_or_else(|| anyhow::anyhow!("missing canonical hash at height {height}"))?;
        let raw_record = load_raw_block(&snapshot, &block_hash, height)?;
        let raw = raw_record.bytes;
        let block = Block::decode(&raw)
            .with_context(|| format!("failed to decode active block at height {height}"))?;
        if block.hash() != block_hash {
            bail!("active raw block hash mismatch at height {height}");
        }
        let undo = load_undo(&snapshot, &block_hash, height)?;
        if undo.height != height || undo.block_hash != block_hash {
            bail!("block undo identity mismatch at height {height}");
        }
        for name in &undo.previous_name_states {
            changed_names.insert(*name.name_hash.as_bytes());
        }
        loaded.push(LoadedTransition {
            height,
            block_hash,
            raw,
            block,
            undo,
        });
    }

    let mut name_overlay = BTreeMap::<[u8; 32], Option<Vec<u8>>>::new();
    for name_hash in changed_names {
        let value = snapshot
            .get(ColumnFamily::NameState, &name_hash)
            .with_context(|| {
                format!(
                    "failed to read current name state {}",
                    hex_encode(&name_hash)
                )
            })?;
        name_overlay.insert(name_hash, value);
    }

    let mut records = Vec::with_capacity(loaded.len());
    for (offset, item) in loaded.iter().enumerate().rev() {
        let next_tree_root = loaded
            .get(offset + 1)
            .map(|next| next.block.header.tree_root)
            .unwrap_or(current_committed);
        validate_roots(item, tree_interval, next_tree_root)?;
        let names = reverse_names(&mut name_overlay, &item.undo)?;
        let (spent_coins, created_coins) = normalize_coins(item)?;
        let mut airdrop_positions = item.undo.airdrop_positions.clone();
        airdrop_positions.sort_unstable();
        if airdrop_positions.windows(2).any(|pair| pair[0] == pair[1]) {
            bail!("duplicate airdrop undo position at height {}", item.height);
        }
        apply_airdrop_positions(
            &mut reversed_airdrop_field,
            &airdrop_positions,
            false,
            item.height,
        )?;
        records.push(Transition {
            height: item.height,
            block_hash: hex_encode(item.block_hash.as_bytes()),
            previous_block_hash: hex_encode(item.block.header.prev_block.as_bytes()),
            raw_block_size: item.raw.len(),
            raw_block_digest: digest(&item.raw),
            roots: Roots {
                previous_committed: hex_encode(item.undo.previous_committed_tree_root.as_bytes()),
                resulting_committed: hex_encode(item.undo.resulting_committed_tree_root.as_bytes()),
                interval_boundary: item.undo.name_tree_interval_boundary,
            },
            spent_coins,
            created_coins,
            airdrop_positions,
            names,
        });
    }
    records.reverse();
    let mut reconnected_airdrop_field = reversed_airdrop_field;
    for record in &records {
        apply_airdrop_positions(
            &mut reconnected_airdrop_field,
            &record.airdrop_positions,
            true,
            record.height,
        )?;
    }
    if reconnected_airdrop_field != source_airdrop_field {
        bail!("airdrop field did not round-trip through retained transitions");
    }

    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        producer: "hsrd",
        network: network_name(network),
        source_height,
        source_block_hash: hex_encode(source_block_hash.as_bytes()),
        first_height,
        keep_blocks,
        tree_interval,
        source_airdrop_field_size: source_airdrop_field.len(),
        source_airdrop_field_digest,
        source_airdrop_spent,
        records,
    };
    match arguments.output {
        Some(path) => {
            let file = File::create(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &manifest)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        None => {
            serde_json::to_writer_pretty(std::io::stdout().lock(), &manifest)?;
            println!();
        }
    }
    Ok(())
}

fn apply_airdrop_positions(
    field: &mut [u8],
    positions: &[u32],
    spend: bool,
    height: u32,
) -> Result<()> {
    for position in positions {
        let position = usize::try_from(*position)
            .map_err(|_| anyhow::anyhow!("airdrop position exceeds usize"))?;
        let byte = position >> 3;
        let Some(value) = field.get_mut(byte) else {
            bail!("airdrop position {position} is out of range at height {height}");
        };
        let mask = 1 << (7 - (position & 7));
        let currently_spent = *value & mask != 0;
        if currently_spent != !spend {
            bail!(
                "airdrop position {position} has invalid {} state at height {height}",
                if spend { "reconnect" } else { "disconnect" }
            );
        }
        if spend {
            *value |= mask;
        } else {
            *value &= !mask;
        }
    }
    Ok(())
}

fn load_raw_block<S: ReadSnapshot>(
    snapshot: &S,
    block_hash: &BlockHash,
    height: u32,
) -> Result<RawBlockRecord> {
    let bytes = snapshot
        .get(ColumnFamily::Blocks, block_hash.as_bytes())
        .with_context(|| format!("failed to read raw block at height {height}"))?
        .ok_or_else(|| anyhow::anyhow!("raw block at height {height} is not retained"))?;
    let record = RawBlockRecord::decode(&bytes)
        .with_context(|| format!("failed to decode raw block record at height {height}"))?;
    if record.hash != *block_hash {
        bail!("raw block record identity mismatch at height {height}");
    }
    Ok(record)
}

fn load_undo<S: ReadSnapshot>(
    snapshot: &S,
    block_hash: &BlockHash,
    height: u32,
) -> Result<BlockUndo> {
    let bytes = snapshot
        .get(ColumnFamily::Undo, block_hash.as_bytes())
        .with_context(|| format!("failed to read undo at height {height}"))?
        .ok_or_else(|| anyhow::anyhow!("undo at height {height} is not retained"))?;
    BlockUndo::decode(&bytes).with_context(|| format!("failed to decode undo at height {height}"))
}

fn validate_roots(
    item: &LoadedTransition,
    tree_interval: u32,
    next_tree_root: [u8; 32],
) -> Result<()> {
    let undo = &item.undo;
    let previous = item.block.header.tree_root;
    let boundary = item.height.is_multiple_of(tree_interval);
    let resulting = if boundary { next_tree_root } else { previous };
    if undo.name_tree_interval_boundary != boundary {
        bail!("name-tree interval flag mismatch at height {}", item.height);
    }
    if undo.previous_tree_root.as_bytes() != &previous
        || undo.previous_committed_tree_root.as_bytes() != &previous
    {
        bail!("previous committed root mismatch at height {}", item.height);
    }
    if undo.resulting_tree_root.as_bytes() != &resulting
        || undo.resulting_committed_tree_root.as_bytes() != &resulting
    {
        bail!(
            "resulting committed root mismatch at height {}",
            item.height
        );
    }
    Ok(())
}

fn reverse_names(
    overlay: &mut BTreeMap<[u8; 32], Option<Vec<u8>>>,
    undo: &BlockUndo,
) -> Result<Vec<NameTransition>> {
    let mut names = Vec::with_capacity(undo.previous_name_states.len());
    for change in &undo.previous_name_states {
        let key = *change.name_hash.as_bytes();
        let after = overlay
            .get(&key)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "name overlay is missing changed name {} at height {}",
                    hex_encode(&key),
                    undo.height
                )
            })?
            .clone();
        let before = change
            .previous
            .as_ref()
            .map(encode_name_state)
            .transpose()
            .with_context(|| {
                format!(
                    "failed to encode previous name {} at height {}",
                    hex_encode(&key),
                    undo.height
                )
            })?;
        overlay.insert(key, before.clone());
        names.push(NameTransition {
            name_hash: hex_encode(&key),
            before: before.map(|bytes| hex_encode(&bytes)),
            after: after.map(|bytes| hex_encode(&bytes)),
        });
    }
    names.sort_unstable_by(|left, right| left.name_hash.cmp(&right.name_hash));
    if names
        .windows(2)
        .any(|pair| pair[0].name_hash == pair[1].name_hash)
    {
        bail!("duplicate name undo at height {}", undo.height);
    }
    Ok(names)
}

fn normalize_coins(item: &LoadedTransition) -> Result<(Vec<CoinTransition>, Vec<CoinTransition>)> {
    let mut surviving_created = BTreeMap::<Vec<u8>, Coin>::new();
    let mut external_spends = BTreeSet::<Vec<u8>>::new();

    for (transaction_index, transaction) in item.block.transactions.iter().enumerate() {
        if transaction_index > 0 {
            for input in &transaction.inputs {
                let key = outpoint_key(&input.previous_output);
                if surviving_created.remove(&key).is_none() && !external_spends.insert(key.clone())
                {
                    bail!(
                        "duplicate external spend {} at height {}",
                        hex_encode(&key),
                        item.height
                    );
                }
            }
        }
        let txid = transaction.txid();
        for (output_index, output) in transaction.outputs.iter().enumerate() {
            if output.is_unspendable() {
                continue;
            }
            let index = u32::try_from(output_index)
                .map_err(|_| anyhow::anyhow!("output index exceeds u32"))?;
            let outpoint = Outpoint { txid, index };
            let key = outpoint_key(&outpoint);
            let coin = Coin {
                outpoint,
                value: output.value,
                height: item.height,
                coinbase: transaction_index == 0,
                address: output.address.clone(),
                covenant: output.covenant.clone(),
            };
            if surviving_created.insert(key.clone(), coin).is_some() {
                bail!(
                    "duplicate created outpoint {} at height {}",
                    hex_encode(&key),
                    item.height
                );
            }
        }
    }

    let undo_created = item
        .undo
        .created_coins
        .iter()
        .map(outpoint_key)
        .collect::<BTreeSet<_>>();
    if undo_created.len() != item.undo.created_coins.len() {
        bail!("duplicate created coin undo at height {}", item.height);
    }
    let derived_created = surviving_created.keys().cloned().collect::<BTreeSet<_>>();
    if undo_created != derived_created {
        bail!(
            "created coin undo disagrees with block semantics at height {}",
            item.height
        );
    }

    let mut undo_spent = BTreeMap::<Vec<u8>, &Coin>::new();
    for coin in &item.undo.spent_coins {
        let key = outpoint_key(&coin.outpoint);
        if undo_spent.insert(key.clone(), coin).is_some() {
            bail!("duplicate spent coin undo at height {}", item.height);
        }
    }
    if undo_spent.keys().cloned().collect::<BTreeSet<_>>() != external_spends {
        bail!(
            "spent coin undo disagrees with external block inputs at height {}",
            item.height
        );
    }

    let spent = undo_spent
        .into_iter()
        .map(|(key, coin)| CoinTransition {
            outpoint: hex_encode(&key),
            coin: hex_encode(&encode_coin(coin)),
        })
        .collect();
    let created = surviving_created
        .into_iter()
        .map(|(key, coin)| CoinTransition {
            outpoint: hex_encode(&key),
            coin: hex_encode(&encode_coin(&coin)),
        })
        .collect();
    Ok((spent, created))
}

fn outpoint_key(outpoint: &Outpoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(outpoint.txid.as_bytes());
    key.extend_from_slice(&outpoint.index.to_le_bytes());
    key
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output size");
    hasher.update(bytes);
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    hex_encode(&output)
}

fn required_meta<S: ReadSnapshot>(snapshot: &S, key: MetaKey, label: &str) -> Result<Vec<u8>> {
    snapshot
        .get(ColumnFamily::Meta, key.as_bytes())
        .with_context(|| format!("failed to read {label}"))?
        .ok_or_else(|| anyhow::anyhow!("{label} metadata is missing"))
}

fn required_hash_meta<S: ReadSnapshot>(
    snapshot: &S,
    key: MetaKey,
    label: &str,
) -> Result<[u8; 32]> {
    let bytes = required_meta(snapshot, key, label)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{label} must be 32 bytes, got {}", bytes.len()))
}

fn active_chain_height<S: ReadSnapshot>(snapshot: &S, block_hash: &BlockHash) -> Result<u32> {
    let bytes = snapshot
        .get(ColumnFamily::BlockIndex, block_hash.as_bytes())
        .context("failed to read best block index")?
        .ok_or_else(|| anyhow::anyhow!("best block index is missing"))?;
    let record = BlockIndexRecord::decode(&bytes).context("failed to decode best block index")?;
    if record.hash != *block_hash {
        bail!("best block index hash does not match metadata");
    }
    Ok(record.height)
}

fn decode_network(binding: &[u8]) -> Result<Network> {
    match binding {
        [0] => Ok(Network::Mainnet),
        [1] => Ok(Network::Testnet),
        [2] => Ok(Network::Regtest),
        [3] => Ok(Network::Simnet),
        _ => bail!("invalid hsrd network binding"),
    }
}

const fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
        Network::Simnet => "simnet",
    }
}
