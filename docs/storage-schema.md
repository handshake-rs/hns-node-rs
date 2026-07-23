# Storage schema

`hns-store` owns persistence. Runtime crates use typed `Store`, `ReadSnapshot`,
and `WriteBatch` traits and do not issue raw RocksDB calls directly. Every
consensus-critical transition is prepared against an immutable snapshot and
committed through an atomic batch.

## Current schema boundary

The current persistent schema version is **16** and the storage profile is
**`hsrd-mining-v12`**. This is an intentional clean-reindex boundary.

Version 16 contains the authority, state, shadow-synchronization, and mining
publication schema, durable HSD airdrop duplicate prevention, active-chain
deployment-state persistence, content-addressed authenticated name nodes, and
durable interval-root retention metadata:

- granular block-status bit assignments;
- spent output address in the UTXO `Coin` codec;
- HSD-compatible omission of null-data-address and `REVOKE` covenant outputs
  from UTXO and undo admission after all value and covenant validation;
- expanded HSD-compatible `NameState` encoding;
- block undo version 6 with previous/resulting working and interval-committed
  name-tree roots plus airdrop positions to clear on disconnect;
- mandatory 32-byte `name-tree-root` working-state metadata binding;
- mandatory 32-byte `name-tree-commit-root` binding for HSD's last
  `treeInterval` commitment used by candidate headers and mining templates;
- canonical content-addressed `name_tree_nodes` records keyed by their exact
  HSD/Urkel node hash and staged atomically with name-state/root changes;
- versioned, checksummed `name-tree-snapshot/v1/<height-be>` records written in
  the `snapshots` column family at each network name-tree interval; each value
  binds its active block hash and resulting root;
- mandatory 27,195-byte MSB-first `airdrop-field` metadata binding for all
  217,557 HSD airdrop and faucet allocation positions;
- separate best-header and active-best-block bindings;
- chain-epoch and mining-generation metadata;
- a versioned, checksummed `sync-checkpoint` metadata record;
- versioned and checksummed solved-block publication intents stored under
  `publication/v1/<block-hash>` in the `snapshots` column family;
- versioned deployment-state records stored under
  `deployment-state/v1/<block-hash>` in the `snapshots` column family. Each
  value binds the block height and all four HSD threshold states; active-chain
  startup recomputes period transitions and rejects missing or inconsistent
  entries;
- an optional versioned, checksummed `name-tree-compaction/v1` checkpoint that
  binds the last compacted active height/tip and exact retained/deleted counts;
- an optional versioned, checksummed `undo-pruning/v1` checkpoint that binds
  the last retired canonical height/block and cumulative retired undo count.

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
- Point-oriented column families share one bounded 192 MiB LRU block cache;
  raw blocks and undo data use a separate 32 MiB cache so one-pass replay reads
  cannot evict hot UTXO, name-state, or Urkel pages. Every column family uses a
  10-bit full Bloom filter, cached high-priority index/filter blocks, and pinned
  level-zero index/filter blocks. Bulk block/undo data blocks are 32 KiB.
- RocksDB receives four combined background flush/compaction jobs. This matches
  the current four-core canary host and lets flush/compaction use otherwise idle
  cores; deployment-scale stall, CPU-contention, and memory qualification remain
  required on other hardware profiles.
- Aggregate WAL retention across all column families is capped at 256 MiB.
  RocksDB otherwise derives a multi-gigabyte allowance from the sum of every
  column family's write buffers, which amplified mainnet replay disk use.
- Incremental name-tree updates persist only newly constructed records reachable
  from that block's final root. Superseded paths constructed within the same
  atomic update were never durable roots and are not written; records reachable
  from prior block roots and retained snapshot pins remain content-addressed and
  independently verifiable.
- Snapshot reads expose ordered batched point lookup. The RocksDB implementation
  uses one snapshot-bound multi-get, while atomic staging overlays resolve their
  own replacements/deletions first and batch only missing keys against the base
  snapshot.
- One atomic activation snapshot has bounded read-through caches for immutable
  name-tree nodes and materialized name state, including absent name-state
  lookups. Overlay writes/deletes always take precedence and the caches are
  discarded with that snapshot.
- Name-tree garbage collection validates the complete retained-root union
  before mutation, preflights durable key shape without materializing values,
  and streams unreachable deletes in 65,536-key commits. Its completion
  checkpoint is written last; an interrupted run is safe and idempotent because
  only unreachable content-addressed records can have been deleted.
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
- `name-tree-commit-root`
- `airdrop-field`
- `sync-checkpoint`
- `clean-shutdown`

The `name-tree-root` value is exactly 32 bytes and must equal the working root
rebuilt from materialized non-null `name_state` records after every active
block. `name-tree-commit-root` is also exactly 32 bytes; it advances to the
working root only when the connected height is divisible by the network's
name-tree interval. Candidate headers and mining templates use this committed
root between boundaries, matching HSD's durable tree versus in-memory
transaction split.

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
  Shadow-network downloads are retained as non-active records. A body whose
  authenticated commitments prove permanent invalidity is retained with a
  failed block/header status; known descendants inherit failure atomically with
  best-header fallback. The opt-in state connector may likewise promote an
  exact candidate-derived contextual failure from a body-valid alternate to
  failed status. Uncommitted body mismatches and classified local state faults
  are not branch evidence.
- `tx_index`: bounded differential/debug transaction index; not required in a
  future lean production profile.
- `utxo`: `outpoint -> Coin { value, height, coinbase, address, covenant }`.
- `name_state`: HSD-compatible non-null `NameState` value records keyed by
  32-byte name hash.
- `name_tree_nodes`: canonical leaf/internal node records keyed by their exact
  authenticated root. Historical records are retained for undo and snapshot
  reachability. Explicit compaction validates every retained root before
  atomically deleting unreachable records.
- `undo`: block UTXO/name/airdrop undo records, including pre-state and
  post-state roots. With explicit undo retirement enabled, the HSD-protected
  prefix and newest per-network reorg window remain while the intervening
  active records are deleted.
- `snapshots`: operational durable records. The mining engine uses the bounded
  `publication/v1/<block-hash>` namespace for solved-block publication intents.
  Each intent commits to its mining generation, job ID, block hash, creation
  time, and exact raw block and is checksummed on decode. State persistence uses
  `name-tree-snapshot/v1/<height-be>` for network-interval root pins and
  `name-tree-compaction/v1` for the atomically published last compaction result,
  plus `undo-pruning/v1` for the atomically advanced undo-retirement boundary.
  `startup-audit/v1` is a checksummed commitment to the schema/profile,
  network/genesis, best header, active tip, chain epoch, mining generation,
  working and committed name roots, airdrop field, complete interval-pin set,
  and maintenance checkpoints. It is written atomically with the clean marker.
  A missing, corrupt, or mismatched commitment selects exhaustive startup
  validation rather than authorizing a shortcut. A matching commitment bounds
  synchronous chain validation to the complete network reorganization/undo
  horizon; full historical validation remains the unclean-start route and a
  requirement for the offline scrub campaign.
- `peers`: `address-book/v1` stores one bounded, checksummed, versioned, and
  network-bound snapshot of discovered IP peers. Each entry retains services,
  advertised time, connection attempts, last success, last attempt, and stable
  selection sequence. Explicit operator peers are configuration, not cache
  data. The cache is refreshed every 120 seconds and at clean runtime shutdown;
  invalid records are discarded and replaced without becoming consensus input.
  `ban-list/v1` separately stores at most 16,384 normalized IP bans with their
  creation, expiry, and stable sequence metadata. It is persisted immediately
  when score 100 is crossed, compacted on HSD-style expiry, retried on the same
  120-second cadence, and flushed at shutdown. The record has independent
  version, checksum, generation, and network binding; earliest-expiring bans
  are evicted first if the hard bound is reached.
- `orphans`, `mempool_persist`: reserved operational records as those
  subsystems mature. Subthreshold per-connection peer scores, socket reconnect
  timers, inflight requests, orphan bodies, and the mining-engine
  mempool/template cache remain process-local and bounded in memory.

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

Schema version 14 preserves the existing `u32` status layout:

| Bit | Field | Meaning |
|---:|---|---|
| 0 | `header_context_valid` | PoW, parent, difficulty, and time context passed |
| 1 | `checkpoint_valid` | checkpoint policy passed |
| 2 | `deployment_state_valid` | activation/deployment context passed |
| 3 | `body_present` | raw body is durable |
| 4 | `body_syntax_valid` | full syntax, or the checkpoint-backed historical commitment/name-limit body stage, is satisfied |
| 5 | `absolute_finality_valid` | height/time locktime passed |
| 6 | `relative_locks_valid` | relative locks executed or checkpoint-satisfied |
| 7 | `scripts_valid` | witness/script authorization executed or checkpoint-satisfied |
| 8 | `covenant_links_valid` | non-coinbase linkage executed or checkpoint-satisfied |
| 9 | `covenants_context_valid` | configured contextual name transitions passed |
| 10 | `claims_and_airdrops_valid` | full issuance proof/accounting, or historical sanity/allocation/context, is satisfied |
| 11 | `utxo_connected` | UTXO mutation is connected |
| 12 | `name_state_connected` | name-state mutation is connected |
| 13 | `tree_root_valid` | header pre-state root and durable resulting root passed |
| 14 | `undo_present` | disconnect data is durable |
| 15 | `active_chain` | record belongs to the active chain |
| 16 | `failed` | permanent invalidity was observed |

For a block on exact hardcoded-checkpoint ancestry, a true stage bit may mean
the stage is satisfied by HSD's canonical historical assumption rather than
locally executed. `checkpoint_valid` together with the record height/hash and
canonical header ancestry supplies that provenance; the state engine rejects
arbitrary partial historical plans. Shadow bodies set only evidence justified
by their validation path. In particular, body presence or syntax-stage
validity does not imply scripts, contextual covenants, claims/airdrops, UTXO
connection, name-state connection, root validity, undo availability, or
active-chain membership.

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

It does not persist in-memory validation jobs, subthreshold peer scores,
inflight requests, or orphan bodies. Peer bans are an independent operational
record rather than checkpoint authority. A `Validating` checkpoint resumes as
block download, and the contiguous stored-body tip is recomputed from canonical
durable data.

## Fixture integrity

The HSD fixture manifest is versioned. Every entry has a safe relative path and
an exact BLAKE2b-256 digest. Both the Rust loader and static validator check the
exact bytes before fixture use.

## Migration policy

Schema 16/profile `hsrd-mining-v12` requires an explicit clean reindex from every
prior handoff. Earlier hsrd profiles may contain impossible-to-spend outputs
that HSD never admitted to its coin database. No automatic in-place migration
is attempted while `hsrd` remains pre-authority. A failed or interrupted
reindex must not modify the previous database.

## Persistent Urkel status

Steady-state inserts, replacements, and removals now traverse only affected
content-addressed paths from the bound root. They construct changed ancestors,
stage previously unseen records with the `NameState` and root changes in the
same atomic batch, and retain old nodes for historical roots and undo. The
staging overlay exposes newly built records to later steps of a one-batch
reorganization. Proof reads likewise traverse only the requested path and
rehash every loaded record.

Startup still performs the independent O(N) rebuild from materialized
`NameState` and validates every node reachable from the bound root. The rebuild
also remains a differential-test oracle; it is no longer the steady-state root
construction path. Pinned HSD incremental roots and canonical proof bytes match
the path-local implementation, including multi-name history and reverse undo.

Active connects write a versioned, checksummed root pin whenever the height is
divisible by the network's HSD `treeInterval`; disconnect removes the exact
matching pin. Undo retirement removes that pin in the same atomic batch once
the interval can no longer be disconnected. Startup requires every retained
active interval height to have a matching block/undo/root pin, requires pruned
intervals to have no pin, rejects pins outside the retained active interval
path, and fully validates each pinned reachable tree.

The explicit compactor first validates and unions all nodes reachable from the
current bound root, every previous/resulting root in retained undo, and every
interval pin. It validates all stored node keys before staging any deletion,
then removes only records outside that union in bounded synced chunks over the
same stable snapshot. Malformed pins and missing/corrupt reachable nodes fail
before the first mutation. An interrupted chunked run may leave extra garbage,
but cannot delete a root validated as retained; retry is idempotent. State
transitions and compaction remain serialized by the node coordinator.

The node coordinator exposes forced maintenance and HSD-shaped opt-in startup
scheduling. In undo-pruned mining mode the same scheduler also runs during
native replay. A nonzero height interval (10,000 by default) prevents repeated
work at the same tip. The checksummed height/tip/count completion checkpoint is
written only after every deletion chunk succeeds; malformed checkpoints fail
startup. API-v10 status reports the configured policy and last completed
result. During the serialized pass it serves an explicitly marked, timestamped
cached diagnostic snapshot, while authority-bearing reads continue waiting for
live state. Unclean RocksDB reopen tests verify that interrupted deletion
resumes safely and that a completion checkpoint agrees with the compacted node
set.

Undo retirement is separately opt-in. It uses HSD's exact network constants:
no height through `pruneAfterHeight` is retired, and the newest `keepBlocks`
remain disconnectable. The target comparison is strict, matching HSD. Each
retirement deletes the undo bytes, clears the matching header/block status,
deletes any matching interval pin, and advances `undo-pruning/v1` in the same
batch. Startup validates the protected prefix, retired band, retained suffix,
canonical checkpoint binding, root continuity, and the absence/presence of
interval pins on the retired/retained sides; missed retirements are caught up
in bounded batches. Reorganizations crossing the retired band fail before any
state mutation. A store with a pruning checkpoint cannot later open with
retirement disabled.

Production closure still requires deployment-scale performance and priority
isolation plus RocksDB mid-commit process-kill/fault injection without weakening
historical-root reachability or the startup oracle.
