# Storage schema

`hns-store` owns persistence. Runtime crates use typed `Store`, `ReadSnapshot`,
and `WriteBatch` traits and do not issue raw RocksDB calls directly. All
consensus-critical writes use atomic batches.

## Current schema boundary

The current persistent schema version is **5**. Version 5 changes both the
encoded block-status bit assignments and the UTXO `Coin` payload by persisting
the spent output address required for script authorization. Existing
pre-authority databases must be reindexed; the node intentionally refuses an
implicit migration.

Durable identity also binds:

- network ID;
- genesis hash;
- storage profile `hsrd-mining-v1`;
- schema version;
- chain epoch.

A mismatch fails closed.

## Backend and durability

- Default backend: RocksDB.
- Durability policies:
  - `sync`: WAL enabled and fsync before commit returns;
  - `wal`: WAL enabled, operating system schedules fsync.
- Required features: column families, atomic batches, true read snapshots,
  prefix iteration, cache/compaction tuning, and crash recovery.
- The in-memory backend exists for deterministic tests.
- SQLite is not a consensus-state backend.

A `RocksSnapshot` contains a real `rocksdb::Snapshot` tied to one sequence
number. It is not a clone of the live database handle.

## Column families

- `meta`: schema version, network, genesis hash, storage profile, best header,
  best block, mining generation, chain epoch, and future recovery metadata.
- `headers`: `header_hash -> HeaderRecord` including header bytes, height,
  unsigned 256-bit chainwork, and granular status.
- `height_index`: `height -> canonical_header_hash`.
- `block_index`: `block_hash -> BlockIndexRecord` including height, parent,
  chainwork, status, transaction count, and validation timestamp.
- `blocks`: hash-addressed raw block records with source/checksum metadata.
- `tx_index`: bounded differential/debug transaction index; not required in a
  future lean production profile.
- `utxo`: `outpoint -> Coin { value, height, coinbase, address, covenant }`.
- `name_state`: typed name-state records; currently not consensus-complete.
- `undo`: block UTXO/name undo records.
- `peers`, `orphans`, `mempool_persist`, `snapshots`: reserved operational
  records as their subsystems mature.

## Block status bit layout

Version 5 stores a `u32` bitset:

| Bit | Field | Meaning |
|---:|---|---|
| 0 | `header_context_valid` | PoW, parent, difficulty, and time context passed |
| 1 | `checkpoint_valid` | checkpoint policy passed |
| 2 | `deployment_state_valid` | activation/deployment context passed |
| 3 | `body_present` | raw body is durable |
| 4 | `body_syntax_valid` | block/transaction syntax and commitments passed |
| 5 | `absolute_finality_valid` | height/time locktime passed |
| 6 | `relative_locks_valid` | relative sequence locks passed |
| 7 | `scripts_valid` | witness/script authorization passed |
| 8 | `covenant_links_valid` | non-coinbase input/output linkage passed |
| 9 | `covenants_context_valid` | full contextual covenant/name rules passed |
| 10 | `claims_and_airdrops_valid` | claim/airdrop proof and accounting passed |
| 11 | `utxo_connected` | UTXO mutation is connected |
| 12 | `name_state_connected` | name-state mutation is connected |
| 13 | `tree_root_valid` | resulting Urkel root equals the header root |
| 14 | `undo_present` | disconnect data is durable |
| 15 | `active_chain` | record belongs to the canonical chain |
| 16 | `failed` | permanent invalidity was observed |

The fields are deliberately non-overlapping. In particular,
`covenant_links_valid` must not be promoted to contextual/name-state validity.

## Atomic connect and disconnect

A direct connect writes one batch containing the validated state mutation,
undo, indexes, canonical height, best block, mining generation, and chain epoch.
A direct disconnect writes the inverse batch.

A multi-block reorganization uses:

1. one immutable base snapshot;
2. one `StagingOverlay` that provides read-your-writes semantics;
3. one underlying store batch;
4. staged disconnects and connects;
5. final best-work and tip consistency checks;
6. one commit.

The overlay records pending puts/deletes without exposing them to other readers.
On failure, dropping the batch leaves every durable key unchanged. Intermediate
reorganization tips are never committed.

## Fixture integrity

The HSD fixture manifest is itself versioned. Each entry contains a relative
path and exact BLAKE2b-256 digest. Both the Rust loader and the static CI check
verify the bytes before a fixture is trusted by tests.

## Future snapshots

Fast-sync snapshot manifests remain separate from consensus state. A production
manifest must bind network, height, block hash, header-chain commitment, UTXO
root, name-tree root, chunk hashes, producer identity, signatures, and trust
mode. Import and background replay are not yet implemented.
