# Storage Schema

`hns-store` owns persistence. Runtime crates use typed traits and do not issue raw RocksDB calls directly. All consensus-critical writes use atomic write batches.

## Backend

- Default backend: RocksDB.
- Required features: column families, atomic write batches, read snapshots, prefix iteration, configurable block cache, compaction tuning, and crash recovery.
- Non-goal: SQLite for chain, block, UTXO, name-state, undo, or tx-index data.

## Column Families

- `meta`: schema version, network, genesis hash, best header hash, best block hash, finalized checkpoint, assume-valid hash, snapshot manifest hash, prune horizon, mining generation, and clean shutdown marker.
- `headers`: `header_hash -> HeaderRecord { raw_header, height, chainwork, prev_hash, time, bits, tree_root, status }`; chainwork is stored as an unsigned 256-bit big-endian integer.
- `height_index`: `height -> canonical_header_hash`.
- `block_index`: `block_hash -> BlockIndexRecord { height, prev_hash, chainwork, status, tx_count, raw_block_present, undo_present, validated_at }`; chainwork uses the same unsigned 256-bit big-endian encoding.
- `blocks`: `block_hash -> RawBlock { bytes, compression, source, checksum }`.
- `tx_index`: optional bounded differential/debug index; disabled in the lean production profile.
- `utxo`: `outpoint -> Coin { height, coinbase, value, address_or_script, covenant }`.
- `name_state`: `name_hash -> NameStateRecord { name, state, owner, value, renewal, transfer, revoked, height, weak }`.
- `undo`: `block_hash -> BlockUndo { spent_coins, previous_name_states, removed_names, metadata }`.
- `peers`: `network_group/address -> PeerRecord { services, last_height, score, last_success, last_failure, banned_until }`.
- `orphans`: `block_hash -> OrphanBlockRecord { raw_block, prev_hash, received_at, peer_id }`.
- `mempool_persist`: optional fee estimator, recent reject filters, and rebroadcast metadata. The mempool itself remains in memory.
- `snapshots`: snapshot manifest, chunk hashes, signatures, imported height, state roots, and trusted/untrusted mode.

## Block Status

Block index status should be bitflags:

- `header_valid`: header PoW, linkage, difficulty, and checkpoint rules passed.
- `body_present`: raw block is stored.
- `body_valid`: merkle/witness/tree commitments and block-level syntax passed.
- `tx_valid`: transaction and covenant consensus checks passed.
- `scripts_valid`: script verification completed or explicitly deferred under assume-valid policy.
- `state_connected`: UTXO and name state are connected to the active chain.
- `undo_present`: disconnect data is stored.
- `failed`: permanently invalid block data was observed.

## Atomic Connect

Connecting a block writes one batch:

- update `block_index` validation and active-chain status;
- insert or delete `utxo` entries;
- insert, update, or delete `name_state` entries;
- write `undo`;
- update `height_index`;
- update `meta.best_block_hash`;
- optionally write `tx_index` entries;
- prune consumed orphan records.

Disconnecting a block writes the inverse batch using `undo`. Reorgs are composed as a sequence of disconnect batches followed by connect batches.

## Cache Policy

- UTXO cache and name-state cache are configurable independently.
- Dirty cache entries flush by size, block count, elapsed time, or shutdown.
- Flush order preserves recoverability: raw block and undo before active-chain promotion.
- Store snapshots are used for mining and bounded diagnostic reads so neither holds validation locks.

## Snapshots

Snapshot manifests are stored separately from consensus state. A manifest includes network, height, block hash, header chain commitment, external UTXO root, external name-state root, chunk hashes, producer identity, signatures, and mode.

Untrusted snapshot mode imports state for fast boot, then schedules background replay to verify it. Trusted snapshot mode skips background replay only when the operator explicitly enables it.
