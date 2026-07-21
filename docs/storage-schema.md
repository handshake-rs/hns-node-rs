# Storage schema

`hns-store` owns persistence. Runtime crates use typed `Store`, `ReadSnapshot`,
and `WriteBatch` traits and do not issue raw RocksDB calls directly. Every
consensus-critical transition is prepared against an immutable snapshot and
committed through an atomic batch.

## Current schema boundary

The current persistent schema version is **11** and the storage profile is
**`hsrd-mining-v7`**. This is an intentional clean-reindex boundary.

Version 11 contains the authority, state, shadow-synchronization, and mining
publication schema, durable HSD airdrop duplicate prevention, and active-chain
deployment-state persistence:

- granular block-status bit assignments;
- spent output address in the UTXO `Coin` codec;
- expanded HSD-compatible `NameState` encoding;
- block undo version 5 with previous/resulting name-tree roots and airdrop
  positions to clear on disconnect;
- mandatory 32-byte `name-tree-root` metadata binding;
- mandatory 27,195-byte MSB-first `airdrop-field` metadata binding for all
  217,557 HSD airdrop and faucet allocation positions;
- separate best-header and active-best-block bindings;
- chain-epoch and mining-generation metadata;
- a versioned, checksummed `sync-checkpoint` metadata record;
- versioned and checksummed solved-block publication intents stored under
  `publication/v1/<block-hash>` in the `snapshots` column family.
- versioned deployment-state records stored under
  `deployment-state/v1/<block-hash>` in the `snapshots` column family. Each
  value binds the block height and all four HSD threshold states; active-chain
  startup recomputes period transitions and rejects missing or inconsistent
  entries.

A schema/profile mismatch, nonempty unversioned database, missing/malformed
root or airdrop-field binding, or network/genesis mismatch fails closed. The
node does not stamp or implicitly migrate ambiguous state.

Durable identity binds:

- network ID;
- genesis hash;
- schema version;
- storage profile;
- chain epoch.

## Backend and durability

- Default backend: RocksDB.
- Durability policies:
  - `sync`: WAL enabled and fsync before commit returns;
  - `wal`: WAL enabled while the operating system schedules fsync.
- Required behavior: column families, atomic batches, true read snapshots,
  prefix iteration, bounded caches, explicit compaction policy, and crash
  recovery.
- The in-memory backend exists for deterministic tests.
- SQLite is not a consensus-state backend.

`RocksSnapshot` owns an actual RocksDB snapshot at one sequence number. It is
not a clone of the live database handle.

## Metadata keys

The `meta` column family currently contains:

- `schema-version`
- `network`
- `genesis-hash`
- `storage-profile`
- `best-header-hash`
- `best-block-hash`
- `mining-generation`
- `chain-epoch`
- `name-tree-root`
- `airdrop-field`
- `sync-checkpoint`
- `clean-shutdown`

The `name-tree-root` value is exactly 32 bytes and must equal the root rebuilt
from materialized non-null `name_state` records at every committed active
state.

The `airdrop-field` follows HSD's bit order: position zero is the high bit of
byte zero. A special issuance sets its authenticated position in the same
atomic batch as UTXO and undo state; duplicate positions fail before commit,
and disconnect clears exactly the positions recorded in block undo.

The synchronization checkpoint is operational progress, not consensus state.
It is versioned and checksummed, and startup cross-checks it against durable
headers and body availability before use. Corrupt or stale checkpoint data
cannot promote a block or grant authority.

## Column families

- `meta`: schema and chain identity, active bindings, root binding, generation,
  epoch, sync checkpoint, and recovery markers.
- `headers`: `header_hash -> HeaderRecord` including bytes, height, unsigned
  256-bit chainwork, and granular status.
- `height_index`: `height -> canonical_header_hash` for the active/canonical
  selected header path.
- `block_index`: `block_hash -> BlockIndexRecord` including height, parent,
  chainwork, status, transaction count, and validation timestamp.
- `blocks`: hash-addressed raw block records with source and integrity metadata.
  Shadow-network downloads are retained as non-active records.
- `tx_index`: bounded differential/debug transaction index; not required in a
  future lean production profile.
- `utxo`: `outpoint -> Coin { value, height, coinbase, address, covenant }`.
- `name_state`: HSD-compatible non-null `NameState` value records keyed by
  32-byte name hash.
- `undo`: block UTXO/name/airdrop undo records, including pre-state and
  post-state roots.
- `snapshots`: operational durable records. The mining engine uses the bounded
  `publication/v1/<block-hash>` namespace for solved-block publication intents.
  Each intent commits to its mining generation, job ID, block hash, creation
  time, and exact raw block and is checksummed on decode.
- `peers`, `orphans`, `mempool_persist`: reserved operational records as those
  subsystems mature. Current peer scores, reconnect state, orphan bodies, and
  the mining-engine mempool/template cache are process-local and bounded
  in memory.

Null name states are represented by absence. Persisting a null state is treated
as corruption by the correctness-first root rebuild.

## Publication-intent invariant

A solved-block publication intent is not consensus acceptance and is not an
independent authorization token. Its lifecycle is:

1. the current private mining-authority capability and durable snapshot bind
   the solved candidate;
2. the checksummed intent is committed;
3. the candidate is connected through the ordinary local block-admission path;
4. only a locally accepted active block may enter parallel critical peer
   fan-out or restart retry;
5. the intent is deleted after at least one ready peer writer completes the block socket write;
6. if no peer completes the write, the locally accepted block remains active and the
   intent remains pending for retry.

An intent whose block is not locally accepted cannot be broadcast by the retry
path. The queue is bounded by configuration and by a hard maximum.

## Block status bit layout

Schema version 11 preserves the existing `u32` status layout:

| Bit | Field | Meaning |
|---:|---|---|
| 0 | `header_context_valid` | PoW, parent, difficulty, and time context passed |
| 1 | `checkpoint_valid` | checkpoint policy passed |
| 2 | `deployment_state_valid` | activation/deployment context passed |
| 3 | `body_present` | raw body is durable |
| 4 | `body_syntax_valid` | block/transaction syntax and commitments passed |
| 5 | `absolute_finality_valid` | height/time locktime passed |
| 6 | `relative_locks_valid` | relative sequence locks passed |
| 7 | `scripts_valid` | configured witness/script authorization passed |
| 8 | `covenant_links_valid` | non-coinbase input/output linkage passed |
| 9 | `covenants_context_valid` | configured contextual name transitions passed |
| 10 | `claims_and_airdrops_valid` | special issuance proof/accounting passed |
| 11 | `utxo_connected` | UTXO mutation is connected |
| 12 | `name_state_connected` | name-state mutation is connected |
| 13 | `tree_root_valid` | header pre-state root and durable resulting root passed |
| 14 | `undo_present` | disconnect data is durable |
| 15 | `active_chain` | record belongs to the active chain |
| 16 | `failed` | permanent invalidity was observed |

Shadow bodies set only evidence justified by their validation path. In
particular, body presence or syntax validity does not imply scripts, contextual
covenants, claims/airdrops, UTXO connection, name-state connection, root
validity, undo availability, or active-chain membership.

## Handshake name-root timing

For active block `H`:

1. read one immutable parent-state snapshot;
2. verify the stored root equals the materialized name-state root;
3. require `header(H).tree_root` to equal that inherited root;
4. validate and stage block `H` transitions;
5. compute the resulting root from the base snapshot plus staged overrides;
6. write name states, resulting root, and undo in one batch;
7. block `H+1` must commit to that resulting root.

Undo stores both roots:

- `previous_tree_root`: root committed by the disconnected block;
- `resulting_tree_root`: root expected before disconnect.

Disconnect first verifies current durable/materialized state against the
recorded resulting root, stages inverse name mutations, recomputes the restored
root, verifies it against the previous root, and writes the restored root in
the same batch.

## Atomic connect, disconnect, and reorganization

A direct connect or disconnect uses one immutable snapshot and one batch.

A multi-block reorganization uses:

1. one immutable base snapshot;
2. one `StagingOverlay` with read-your-writes semantics;
3. one underlying store batch;
4. staged disconnects and connects;
5. root, ancestry, status, body, work, and final-tip checks;
6. one commit.

Dropping a failed staged batch leaves every durable key unchanged. Intermediate
reorganization tips and roots are never committed.

Header-only shadow import uses a separate invariant: the next in-memory header
index is published only after the matching durable header/best-header batch
commits. A storage error cannot leave the live header index ahead of disk.

## Synchronization checkpoint

The shadow-sync checkpoint records:

- format version and checksum;
- monotonically increasing sequence;
- synchronization stage;
- best header;
- active tip;
- contiguous stored-body tip;
- target peer height;
- update time.

It does not persist in-memory validation jobs, peer scores, inflight requests,
or orphan bodies. A `Validating` checkpoint resumes as block download, and the
contiguous stored-body tip is recomputed from canonical durable data.

## Fixture integrity

The HSD fixture manifest is versioned. Every entry has a safe relative path and
an exact BLAKE2b-256 digest. Both the Rust loader and static validator check the
exact bytes before fixture use.

## Migration policy

Schema 11/profile `hsrd-mining-v7` requires an explicit clean reindex from every
prior handoff. No automatic in-place migration is attempted while `hsrd`
remains pre-authority. A failed or interrupted reindex must not modify the
previous database.

## Future persistent Urkel store

The current root path rebuilds the authenticated tree from all durable
`NameState` records. This prioritizes correctness and oracle parity over
performance. The same sequence-consistent store snapshot can now materialize a
root-checked immutable tree for exact HSD proof generation; that view remains
pinned if the live store advances and rejects a corrupt durable root binding
before returning a proof. A production persistent incremental Urkel store must
preserve the same exact roots and canonical proof bytes while adding node
persistence, incremental proof serving, interval snapshots, undo, compaction,
and crash recovery. It must not silently replace the current root calculation
until differential replay proves equality.
