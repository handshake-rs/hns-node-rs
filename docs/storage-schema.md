# Storage schema

`hns-store` owns persistence. Runtime crates use typed `Store`, `ReadSnapshot`,
and `WriteBatch` traits and do not issue raw RocksDB calls directly. Every
consensus-critical transition is prepared against an immutable snapshot and
committed through an atomic batch.

## Current schema boundary

The current persistent schema version is **19** and the storage profile is
**`hsrd-mining-v15`**. Schema 18/profile `hsrd-mining-v14` and schema
17/profile `hsrd-mining-v13` receive an atomic profile cutover. Schema
16/profile `hsrd-mining-v12` uses the resumable, backup-first
interval-accumulator migration. Other combinations fail closed.

Version 19 contains the authority, state, native synchronization, and mining
publication schema plus the optimized storage tiers:

- granular block-status bit assignments;
- spent output address in the UTXO `Coin` codec;
- HSD-compatible omission of null-data-address and `REVOKE` covenant outputs
  from UTXO and undo admission after all value and covenant validation;
- expanded HSD-compatible `NameState` encoding;
- block undo version 7 with previous/resulting committed roots, reversible
  interval-accumulator state, and airdrop positions to clear on disconnect;
- a checksummed accumulator that composes per-block name changes and commits
  the authenticated tree only at HSD's network `treeInterval` cadence;
- exact changed-name undo for new blocks. A startup compatibility bridge for
  earlier candidate data accepts only an accumulator whose counts are a
  subset of the complete canonical pending-interval undo counts, validates
  every height/root transition and the reconstructed committed boundary root,
  then atomically replaces only the accumulator key. This preserves the raw
  legacy counts needed by disconnect without rewriting undo or name state;
- mandatory 32-byte `name-tree-root` metadata equal to the last committed root;
- mandatory 32-byte `name-tree-commit-root` binding for HSD's last
  `treeInterval` commitment used by candidate headers and mining templates;
- append-only 64 KiB name-page publication units with traversal-local child
  addresses, root locators, one authenticated 4 KiB slot index, up to fifteen
  authenticated 4 KiB record subpages, bounded path-local subpage reuse, and
  monotonic physical seals every 360 heights without changing consensus-root
  timing. Pruned mode rewrites the reachable union into a fresh generation
  after sixteen sealed segments. Legacy schema-18 pages remain readable in
  place;
- checksummed block and undo frames in 256 MiB physical segments. RocksDB stores
  compact locators and authoritative manifests; legacy inline values remain
  readable during migration;
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
  the last retired canonical height/block and cumulative retired undo count;
- optional, bounded, fenced complete-state namespaces. A namespace stores a
  fixed checksummed control record under
  `authenticated-namespace-control/v1/<namespace-id>` in `meta` and at most
  16 MiB of complete canonical state under
  `authenticated-namespace-state/v1/<namespace-id>` in `snapshots`.

A schema/profile mismatch outside the two reviewed migrations, nonempty
unversioned database, missing/malformed root or airdrop-field binding, or
network/genesis mismatch fails closed.

Durable identity binds:

- network ID;
- genesis hash;
- schema version;
- storage profile;
- chain epoch.

### Fenced complete-state namespaces

The namespace ID is a nonzero, embedding-derived 32-byte identity for one
logical state lineage. Acquisition requires an already initialized current
schema and `sync` durability. It durably increments a checked, nonzero `u64`
fencing epoch before exposing a non-cloneable sole-owner lease. Live owner
cells are shared by every clone of the physical Memory or RocksDB backend, but
unrelated namespaces do not retain the registry lock during durable I/O.

The fixed control record binds its format version, namespace ID, fencing epoch,
initialized flag, minimum accepted revision, and domain-separated complete
state digest; a second domain-separated digest checks the control body. A
replacement compares both the exact prior revision and exact prior complete
bytes under the same backend publication lock that atomically writes the new
control and complete state. Revisions may start at zero but must strictly
advance on replacement. Retrying an exact proposal already present at the same
revision returns an idempotent committed result. Partial topology, malformed
control, digest mismatch, zero/exhausted epochs, stale fencing, empty state,
and over-capacity state fail closed.

Ordinary batches reject both reserved prefixes when staging and recheck them at
commit. RocksDB reads the state as a pinned slice and checks its limit before a
Rust-owned copy. A known injected failure before `write_opt` retains a usable
lease; a backend write error or post-write acknowledgement failure fences every
backend clone until a true close/reopen resolves the atomic old/new outcome.

When a segment archive has been attached, its weak registration is shared by the
physical backend. Namespace operations through the archive retain the order
registration, archive writer, then backend publication. A surviving raw alias
remains rejected even between wrapper instances, a lease obtained before
attachment is fenced on its next operation, and a second live archive wrapper
is rejected. After process restart, durable block/undo manifests likewise
prevent raw namespace acquisition until archive recovery is attached.
Namespace publication never appends or rewrites segment files.
This registration protects the namespace API and its reserved records; it does
not retrofit generic raw `Store` aliases. Embeddings must continue to move the
physical handle into the archive wrapper and retain no generic raw alias after
attachment.

The state digest and checksum detect corruption; they do not authenticate an
offline writer or detect replay of an older whole-database checkpoint. HRM,
HNSA, or HNSR authority must remain disabled until the embedding also maintains
and validates the required minimum revision in separately protected storage,
with an explicit reset/recovery procedure. These additive optional records do
not by themselves change schema 19 or storage profile `hsrd-mining-v15`; making
one mandatory is a later reviewed profile boundary.

## Backend and durability

- Default backend: RocksDB.
- Durability policies:
  - `sync`: WAL enabled and fsync before commit returns;
  - `wal`: WAL enabled while the operating system schedules fsync.
- Required behavior: column families, atomic batches, true read snapshots,
  prefix iteration, bounded caches, explicit compaction policy, and crash
  recovery.
- Point-oriented column families share one bounded 192 MiB LRU block cache.
  The RocksDB `blocks` and `undo` families contain locator-sized values for new
  data and retain a separate 32 MiB legacy cache. Every column family uses a
  10-bit full Bloom filter, cached high-priority index/filter blocks, and pinned
  level-zero index/filter blocks. Bulk block/undo data blocks are 32 KiB.
- RocksDB receives four combined background flush/compaction jobs. This matches
  the current four-core canary host and lets flush/compaction use otherwise idle
  cores; deployment-scale stall, CPU-contention, and memory qualification remain
  required on other hardware profiles.
- Aggregate WAL retention across all column families is capped at 256 MiB.
  RocksDB otherwise derives a multi-gigabyte allowance from the sum of every
  column family's write buffers, which amplified mainnet replay disk use.
- Interval-boundary name-tree updates append only newly constructed records
  reachable from the final root. Non-boundary blocks update `NameState`, undo,
  and the accumulator without writing authenticated nodes. Segment bytes are
  synced before their locator/manifests enter the atomic RocksDB state batch.
- Snapshot reads expose ordered batched point lookup. The RocksDB implementation
  uses one snapshot-bound multi-get, while atomic staging overlays resolve their
  own replacements/deletions first and batch only missing keys against the base
  snapshot.
- Prefix consumers that cannot prove a small result use the storage-native
  cursor API. One page is bounded independently by record count and combined
  key/value bytes, and returns the last emitted key as an exclusive
  continuation token. RocksDB seeks directly to that token on the same
  immutable snapshot; the hard API ceilings are 4,096 records and 64 MiB plus
  one 4 KiB key/framing envelope per page. A value larger than the selected
  byte budget fails instead of bypassing the bound. Full `scan_prefix` remains
  only for callers whose domain is
  intrinsically bounded or explicit offline analysis.
- One atomic activation snapshot has a 65,536-entry read-through cache,
  including misses, for immutable metadata, headers, height/block/transaction
  indexes, UTXOs, name state, and snapshot records. A separate 131,072-entry
  positive cache covers content-addressed name-tree nodes. Overlay
  writes/deletes always take precedence and both caches are discarded with that
  snapshot.
- Every block deduplicates its non-coinbase inputs and spendable output
  collision keys, resolves them with one snapshot-bound UTXO multi-get, and
  retains the decoded results in an outpoint hash map through validation and
  spend staging.
- Name-tree garbage collection validates the complete retained-root union
  before mutation, preflights durable key shape without materializing values,
  and streams unreachable deletes in 65,536-key commits. Its completion
  checkpoint is written last; an interrupted run is safe and idempotent because
  only unreachable content-addressed records can have been deleted.
- The in-memory backend exists for deterministic tests.
- SQLite is not a consensus-state backend.

`RocksSnapshot` owns an actual RocksDB snapshot at one sequence number. It is
not a clone of the live database handle.

## Block data management and asymptotic bounds

Let:

- `N` be the records in the selected RocksDB column family;
- `H` be all durable header records;
- `B` be all durable block-index records;
- `C` be the length of the selected best-header ancestry, with `C <= H`;
- `Q` be the number of active canonical-height entries, with `Q <= B`;
- `M` be the network median-time-past ancestry span;
- `W` be the network difficulty ancestry window, including the adjacent
  suitable-block lookups;
- `P` be one configured cursor page, bounded by both records and bytes;
- `A` be a failed header root plus all of its known descendants;
- `D` be the total disconnect/connect length of one canonical fallback or
  reorganization;
- `K` be the headers in one live import batch, with `K <= 2,000`;
- `R` be the block-index records in one live cache publication, with
  `R <= 1,024`;
- `L` be live block plus undo locators;
- `F` be the live segment-frame bytes copied by generation compaction;
- `S` be physical segment files;
- `I` be the transactions' unique input/output collision keys in one block.

The design uses hash-addressed primary records, a canonical-height secondary
index, compact immutable segment locators, append-only generation files, and a
bounded rollback window. Consensus identity remains the block hash and
authenticated state roots; physical addresses are replaceable acceleration
metadata.

| Operation | Data structure and algorithm | Time | Peak working memory | I/O amplification |
|---|---|---:|---:|---|
| Header-index startup/recovery | 4,096-record/4 MiB cursor pages decode `headers` into a hash map. Recovery first proves key/header identity, exactly one root when nonempty, contiguous parent/height, exact proof-derived work, and failure ancestry; then it constructs parent-to-children adjacency, an ordered viable-work set, and the best ancestry's canonical-height map. Production recovery validates every resident branch against the selected network's exact genesis, durable context/checkpoint bits, difficulty, median time, checkpoints, PoW, one common future-time bound, and chainwork. | `O(H log H + H(M + W) + C)`; ancestry lookups during the all-branch consensus pass are expected `O(1)` resident-map reads | final `O(H)` across header, canonical, child-edge, and viable entries plus one bounded page; the `O(C)` final canonical map is reconstructed in place without a second ancestry vector | reads every durable header once; the consensus pass performs no per-ancestor RocksDB reads and the storage API never returns an unbounded page |
| Block-index startup/status | One bounded cursor pass builds exact alternate/failed counters and a 4,096-record FIFO cache. An independent bounded audit pages every `block_index` record and reverse-binds its header/status/height, then pages `height_index` and proves exact contiguity from zero through `best-block-hash`. | expected `O(B + (B + Q) log N)` startup including point bindings; `O(1)` status reads afterward | `O(P bytes + 4,096 records)` rather than `O(B)` | two sequential `block_index` passes; the binding audit adds header/canonical point reads for each block record and block/header point reads for each active height; status refresh performs no durable scan |
| Live header/canonical lookup | Resident hash maps keyed by header hash and height | expected `O(1)` | covered by the final `O(H)` header index | no storage I/O |
| Durable block/body point lookup | Bloom-filtered LSM point read by 32-byte hash; a block/undo locator then selects one checksummed frame | expected `O(log N + frame bytes)` | `O(frame bytes)` | one LSM lookup plus one frame read; absent keys normally stop at Bloom/filter metadata |
| Active canonical height lookup | `height_index` big-endian key to active block hash, then optional point reads | expected `O(log N)` per lookup | `O(1)` excluding returned values | point reads only; no chain scan |
| Bounded prefix page | RocksDB seek to an exclusive continuation, then ordered iterator | `O(log N + P)` | `O(P bytes)` | reads only iterator/filter/data blocks covering the returned page |
| Header batch import | A batch-local hash map validates at most 2,000 parents and identifies the next best header. Direct extension appends canonical entries. For a non-direct higher-work tip, height-aligned parent walks over the resident and staged maps build only a bounded reorganization delta: at most 16,384 disconnects and 16,384 connects. | expected `O(K log H + D)` including viable-set publication; resident/staged parent reads are expected `O(1)` | `O(K + D)` incremental working memory beyond the resident `O(H)` index; no complete ancestry or replacement canonical map is retained | one atomic `O(K)` header/best-binding WAL batch; delta planning performs no RocksDB reads and memory publishes only after commit |
| Failed-header propagation | Persistent child adjacency discovers `A` under a 16,384-record descendant limit and 30-second traversal deadline; the viable-work set skips affected candidates; bounded parent walks derive a `D`-entry canonical delta. Each affected hash probes its durable block-index record, and at most `R` existing records enter an incremental cache publication. | `O(A + D + R)` in-memory traversal and validation, up to `O((A + R) log B)` block-index lookup cost, plus `O(A log H)` ordered-set removals during in-memory publication | `O(A + D + R)` plan and staged deltas beyond the resident indexes; the fixed 4,096-record block cache remains in place and is not cloned | up to `A` block-index existence point reads plus `R` stale-state validation point reads, then one atomic `O(A + R)` header/block-index batch with the single invalid-root raw body and best-header binding; no intermediate failure state is visible |
| Block state connect | hash-map deduplication plus snapshot-bound multi-get for `I` UTXO keys, then one atomic batch | expected `O(I)` hashing plus LSM point/write costs | `O(I + staged state)` | one multi-get domain and one WAL/memtable publication; segment payloads are appended once |
| Reorganization | one immutable snapshot and read-your-writes overlay across `D` disconnect/connect steps | proportional to blocks and state touched across `D` | proportional to staged reorg state | one final atomic WAL batch; no intermediate tips are published |
| Payload pruning | canonical-height point traversal in at most 1,024 heights per startup transaction, with a larger backlog processed across multiple bounded transactions, or one at-most-360-height authenticated interval during connect | `O(batch heights)` | `O(batch heights)` locator/status mutations | deletes locators/status and advances one checkpoint; historical block payload bytes are not reread |
| Compaction plan | streaming inventory of `blocks` and `undo`, plus `S` file metadata reads | `O(N + S)` | `O(1)` counters and iterator blocks | reads locator values only; it does not read payload frames |
| Segment generation compaction | cursor pages over one stable snapshot; copy each of `L` live frames once; publish all replacement locators and both manifests atomically | `O(N + F)` | `O(P bytes + largest frame + L locator batch)` | reads old live frames once, writes `F` new bytes once, rereads the new generation for checksum scrub, and writes one locator WAL/SST batch; old and new generations coexist until publication |
| Name proof/path update | Patricia traversal with page/subpage coalescing and content-hash verification | `O(tree depth)` per independent path, with shared paths composed once | bounded affected-path frontier and page cache | one 4 KiB authenticated index plus only selected 4 KiB record subpages on version-2 pages |

Header paging bounds each storage result, not final header-index residency.
Recovery deliberately retains all `H` headers, up to `H - 1` child edges, up to
`H` viable-work entries, and `C` canonical entries so live fork choice,
descendant failure, and header RPC lookups do not return to disk scans. Peak
startup memory is the final `O(H)` structures plus the last decoded page. The
recovery walk inserts its `C` final canonical entries in place and neither
retains a separate ancestry vector nor an old and new full header index. A live
non-direct higher-work import instead retains only its at-most-`K` staged
headers and a bounded `O(D)` disconnect/connect delta, then mutates the resident
canonical map in place after the durable commit. Production RSS qualification
must cover the linear `O(H)` recovery baseline and the bounded `O(K + D)` live
increment; the independent 4,096-record block cache does not bound header
memory and its live publications stage at most `R` records rather than cloning
the cache.

Strict production recovery has no synthetic-root or fixture bypass. For a
nonempty index, the sole height-zero record and reconstructed canonical height
zero must equal the configured network genesis. The all-branch consensus pass
captures the host wall clock once and applies the same
`now + MAX_FUTURE_BLOCK_TIME` bound to every record, avoiding
iteration-order-dependent time decisions. A production host therefore requires
a sane wall clock before startup; headers beyond the common bound fail closed.

The complete header consensus audit and bidirectional block/header/height-index
audit run before a clean startup checkpoint can shorten deeper validation. A
matching `startup-audit/v1` checkpoint bounds active raw-body, undo,
deployment, authenticated-name-root, and interval-pin revalidation to the
configured reorganization horizon; it never skips the all-header or all-block
index audits. Non-active raw bodies are not all decoded at startup. A body
availability query authenticates the exact raw frame and its header/status
binding, and any later stored-block activation exact-binds the body, block
index, and header before rerunning the complete strict import policy. Durable
status bits are cached evidence, not activation authority.

`startup-audit/v1`, the clean marker, RocksDB checksums, frame checksums, and
manifests are unkeyed crash-consistency and corruption-detection mechanisms.
The startup record binds selected metadata, roots, pins, and maintenance
checkpoints; it does not bind the complete UTXO keyspace or every logical
database record. Neither the matching-checkpoint route nor the deeper unclean
startup route is a full replay from genesis, and neither authenticates the store
against a hostile offline writer. Production use therefore requires exclusive
custody by the dedicated `hsrd` service identity and trusted, audited offline
maintenance, with no untrusted writer to the data root or external
page/segment paths. After a custody breach, rebuild through a full trusted
replay or use a separately protected keyed/trusted complete-state commitment
once such a mechanism exists; the current schema provides no such commitment.

The final locator publication is intentionally atomic: exposing a mixture of
manifests and generations would make crash recovery ambiguous. Therefore
generation compaction cannot have constant memory in `L`; instead, preflight
places explicit ceilings on live records, live frame bytes, estimated
key/locator bytes, and each iterator page. The defaults cap the final locator
key/value payload at 128 MiB and copied live frames at 64 GiB. Exceeding any
budget fails before a replacement generation is created. Production operators
must choose lower host-specific limits when RocksDB WriteBatch overhead and
normal process memory leave less headroom.

The durable `height_index` is the mandatory canonical-order index for connected
active blocks. Header-only fork choice reconstructs its separate canonical
height map from the durable best-header ancestry and keeps that map resident.
`block_index` stores status and ancestry by hash, while raw bodies and undo are
independently hash-addressed. `tx_index` is optional because it amplifies every
connect, disconnect, and reorganization and is not required for consensus,
relay, or template construction. No secondary index is authoritative without
its matching block/header status and active-tip binding in the same atomic
transition.

The rollback invariant is independent of physical compaction: no height at or
below `pruneAfterHeight` is retired, and at least the newest network
`keepBlocks` plus the pending authenticated-tree interval remain available.
Pruning advances block and undo frontiers with their canonical hashes in the
same batch that clears presence bits and interval pins. A reorganization that
would cross either retired frontier fails before mutation.

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
- `height_index`: `height -> canonical_block_hash` for the connected active
  block path. The independently selected header path is reconstructed from
  `best-header-hash` and resident header ancestry.
- `block_index`: `block_hash -> BlockIndexRecord` including height, parent,
  chainwork, status, transaction count, and validation timestamp.
- `blocks`: hash-addressed raw block records with source and integrity metadata.
  New values are compact checksummed locators into append-only block segments;
  snapshots resolve and revalidate the frame transparently.
  Shadow-network downloads are retained as non-active records. A body whose
  authenticated commitments prove permanent invalidity is retained with a
  failed block/header status; known descendants inherit failure atomically with
  best-header fallback. The opt-in state connector may likewise promote an
  exact candidate-derived contextual failure from a body-valid alternate to
  failed status. Uncommitted body mismatches and classified local state faults
  are not branch evidence.
- `tx_index`: optional active-chain transaction lookup for historical
  diagnostics. The mining profile leaves it disabled by default; consensus,
  UTXO validation, block relay, reorganization, and template construction do
  not read it. `--transaction-index` (alias `--index-tx`) opts in before the
  first indexed block. Enabling it after unindexed history exists fails closed
  until an offline rebuild or a new data directory is used.
  Versioned `wallet-index/v1/` subspaces in the same column family optionally
  store script history, outpoint spenders, script UTXOs, immutable public
  Shakedex/HTLC registrations and address bindings, monotonic confirmation
  records, active contract fundings, and confirmed contract events. Their keys cannot collide with fixed 32-byte
  transaction keys. Every derivative value is checksummed against its exact
  key; UTXO reads reconstruct the script/outpoint key and contract reads verify
  descriptor/content/address topology, so relocated values fail closed. The
  complete wallet profile also owns a separate
  `wallet-index/v1/name-transfer/` derivative namespace. `active/` rows are
  sorted by covenant-recipient ID, confirmation height, transaction position,
  txid, and output index; they never enter script history, script UTXOs,
  spenders, or balances. `evidence/<txid>` retains one fixed 77-byte source
  inclusion record (block hash, height, transaction ordinal, and total output
  count, with txid key/checksum binding). The count is nonzero and bounded by a
  conservative ceiling from the minimum canonical output encoding and
  transaction base-size limit (71,428), independently of the 600 live-reference
  limit.
  `evidence-state/<txid>` stores its sorted live TRANSFER output indices under
  the consensus 600-update bound, and every wallet-indexed block writes an
  `undo/<block-hash>` marker containing created/spent row counts and separate
  domain-separated digests of the canonical sorted key/value effects. The
  marker is a fixed 141 bytes. Created effects are capped at the 600 update
  bucket; spent effects and the combined marker count are each capped at the
  checked 1,200 sum of the independent update and renewal buckets. It never
  duplicates Coins or active rows. Neither evidence nor marker retains the raw
  source transaction or witness. Empty markers use canonical nonzero digests,
  making a block
  with no TRANSFER activity distinguishable from a lost or semantically wrong
  derivative marker. Any spend of a TRANSFER removes the active row regardless
  of successor.
  Disconnect reconstructs and verifies created effects from the authenticated
  block and spent effects from consensus undo Coins plus retained evidence,
  restoring only pre-block spent coins. Pruning independently reconstructs and
  verifies the spent commitment from consensus undo before retiring evidence.
  Evidence whose last output was spent remains until that exact spender undo is
  atomically pruned; a missing or mismatched marker fails closed.
  After body pruning this compact Coin-based node evidence is a trusted-node
  projection, not a cryptographic binding of the `Coin` output bytes to txid.
  A future query must corroborate the canonical `TxIndexEntry`
  txid/hash/height/output count, active-chain block and retained transaction
  position, evidence-state membership, and byte-exact active UTXO in one
  durable snapshot; when the body exists it must also verify the exact txid,
  position, output count, and referenced output bytes.
  Every value and its full key are checksum-bound and all decoders enforce hard
  byte/count bounds.
  The
  public contract ID uses a domain-separated, versioned canonical binary
  encoding with a fixed kind tag and big-endian integer fields; JSON/serde is
  used only as a checksummed record payload and never defines durable identity.
  IDs intentionally omit network identity, while every stored funding/event is
  constrained by this database's independently validated network/genesis
  binding. Each address key contains a sorted checksummed list of at most 256
  descriptor IDs because script addresses do not commit every tracked funding
  term; the global registry remains capped at 16,384 and output matching checks
  complete descriptor terms. Consensus-valid spends outside the pinned wallet
  branch profile are durably classified `Unrecognized` and reversed normally,
  so the optional tracker does not strengthen consensus based on local branch
  shape; storage corruption still fails the node closed.
  Confirmed HTLC events retain raw revealed preimages in their internal durable
  representation, while public DTO serde is redacted and non-round-trippable.
  `wallet-index/v1/contract/observation/<contract-id>` stores a checksummed
  lifecycle revision and `NeverConfirmed`, `Confirmed`, or fail-
  closed `LegacyUnknown` state. `wallet-index/v1/contract/lifecycle-sequence`
  allocates revisions across serialized node registration and is retained
  across retirement. New
  registration writes `NeverConfirmed`; the first matching connected funding
  writes `Confirmed` in the canonical block batch, and disconnect never clears
  it. Exact never-confirmed retirement requires the caller's matching revision plus empty funding/event
  prefixes, then atomically deletes the registration and observation, removes
  its address membership, and decrements/deletes the active count. No tombstone
  is needed because no chain event existed; an exact later registration is a
  fresh lifecycle. The typed node wrapper additionally requires no retained
  transaction orphans and scans the exact accepted ordinary/airdrop generation
  before exact-epoch commit.
  `wallet-index/v1/contract/retirement/<contract-id>` holds an immutable,
  checksummed completed-lifecycle tombstone. It preserves the exact descriptor,
  lifecycle revision, terminal spend, every revealed preimage with its
  outpoint/transaction binding, event count and min/max heights, the exact
  undo-pruning checkpoint, a permanent-abandonment acknowledgement, and a
  domain-separated SHA-256 commitment over each ordered deleted event key and
  stored value followed by the event count. Retirement requires a bounded
  complete funding/spend pairing walk, no reused funding outpoint, no active
  funding, and every event at or below the authoritative pruned-undo frontier.
  The tombstone, event deletion, active address/count reclamation, and
  observation/registration deletion share one batch. A separate checksummed
  `wallet-index/v1/contract/retirement-count` caps immutable tombstones at
  65,536; one transition is capped at 4,096 event rows. Startup checks every
  tombstone against the current pruning frontier and canonical boundary and
  terminal hashes. Retired IDs cannot be registered again. These finite
  lifetime bounds keep untrusted registration unavailable despite reclaiming
  active slots. The checksummed
  `wallet-index-profile/v1` snapshot record prevents partially
  indexed history
  from being enabled after startup; see
  [Handshake wallet indexes](HNS_NODE_WALLET_INDEX.md).
  Profile payload version 4 is a downgrade fence for confirmed incoming
  TRANSFER indexing and compact source-inclusion evidence. Versions 1 through
  3 remain decodable for diagnosis, but a legacy profile with the complete
  `wallet` component enabled and any chain history or existing wallet-index
  keys is never rewritten during normal startup. It requires a fresh v4 sync
  unless a future separately qualified offline migration proves every active
  TRANSFER and reconstructs its exact canonical transaction ordinal and total
  output count. History-only and spender-only legacy profiles may
  update the version fence because they never claimed wallet TRANSFER evidence.
  Older binaries reject version 4 rather than silently ignoring
  recipient/evidence state or pruning it incorrectly.
  Effective transaction-index, script-history, spender, and wallet capabilities
  are immutable once chain history or relevant index keys exist. Startup
  rejects both additions and removals; redundant raw flags with identical
  effective capabilities remain acceptable. Index-mode and profile changes are
  preflighted and published in one atomic batch only after storage-mode
  compatibility checks pass.
- `utxo`: `outpoint -> Coin { value, height, coinbase, address, covenant }`.
- `name_state`: HSD-compatible non-null `NameState` value records keyed by
  32-byte name hash.
- `name_tree_nodes`: read-only migration/fallback records from profiles before
  authenticated pages. Page-backed operation never adds LSM records. Legacy
  compaction is disabled until every retained fallback root is explicitly
  retired.
- `undo`: block UTXO/name/airdrop undo records, including pre-state and
  post-state roots and reversible accumulator data. New values are compact
  locators into append-only undo segments. With explicit undo retirement
  enabled, the HSD-protected prefix and newest per-network reorg window remain
  addressable while intervening locator records are deleted.
- `snapshots`: operational durable records. The mining engine uses the bounded
  `publication/v1/<block-hash>` namespace for solved-block publication intents.
  Each intent commits to its mining generation, job ID, block hash, creation
  time, and exact raw block and is checksummed on decode. State persistence uses
  `name-tree-snapshot/v1/<height-be>` for network-interval root pins and
  `name-tree-compaction/v1` for the atomically published last compaction result,
  plus `undo-pruning/v1` for the atomically advanced undo-retirement boundary.
  `name-page-state/v1`, per-root page locators, block/undo segment manifests,
  `transaction-index-mode/v1`, and `wallet-index-profile/v1` bind the optimized
  storage tiers.
  `startup-audit/v1` is an unkeyed checksummed consistency record binding the
  schema/profile, network/genesis, best header, active tip, chain epoch, mining
  generation, working and committed name roots, airdrop field, complete
  interval-pin set, and maintenance checkpoints. It is written atomically with
  the clean marker. A missing, corrupt, or mismatched record selects exhaustive
  startup validation rather than authorizing a shortcut. The strict all-branch
  header consensus audit and the complete block/header/canonical-index binding
  audit run regardless. A matching record bounds deeper active body, undo,
  deployment, name-root, and pin validation to the complete network
  reorganization/undo horizon. The unclean-start route and offline scrub
  perform deeper historical structural, body, and name-state audits, but do not
  replay all consensus state from genesis or authenticate arbitrary logical
  database changes by a hostile writer.
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
  `hip76-requester-policy/v1` stores only the process-wide HIP-76 requester
  selection and its monotonic generation; it never stores provider consent,
  peer authority, request IDs, or DNS bytes.
  `hip76-requester-policy-floor/v1` independently checksums the minimum
  generation and network binding. Both fixed-size records commit atomically;
  startup accepts both or neither and rejects corruption, network mismatch, or
  generation rollback.
  `odoh-target-cache/v1` stores at most 16 verified public HIP-77 target
  locators, signed records, selected configuration indexes, expiry and sequence
  high-water values, plus requester opt-out/revocation policy.
  `odoh-durable-floor/v1` independently checksums the
  minimum cache generation, policy generation, and trusted-time high-water.
  Both ODoH records are written in one atomic batch; startup accepts both or
  neither and rejects rollback, clock regression, corruption, network mismatch,
  or address-policy mismatch.
  `hnsr-runtime-state/v1` contains checksummed requester/opaque-relay policy,
  counters, configuration identity, and fail-closed live-work counts.
  `hnsr-durable-floor/v1` independently binds the state, requester, and relay
  generation floors plus trusted-time high-water. Both records commit
  atomically and restore only under a fresh process session. Reservations,
  circuits, queued bytes, route actions, and peer authority remain memory-only.
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

Native header import uses a separate invariant: the next in-memory header
index is published only after the matching durable header/best-header batch
commits. A storage error cannot leave the live header index ahead of disk.

## Synchronization checkpoint

The native-sync checkpoint records:

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

Schemas 17/profile `hsrd-mining-v13` and 18/profile `hsrd-mining-v14` already
have interval semantics and receive only the atomic schema/profile cutover.
Schema 16/profile `hsrd-mining-v12` backs up every rewritten undo and the old
root/profile bindings before the final marker changes. Page bootstrap and
segment-manifest initialization are idempotent; restart truncates unpublished
tails. Older or mixed profiles require an explicit reindex.

The operator workflow is specified in
[`storage-rollout.md`](storage-rollout.md). `hsrd-storage-maintenance backup`
accepts each reviewed source profile and publishes a complete fallback marker
only after the RocksDB checkpoint and independent external-file copies are
synced. `inventory` validates every committed archive frame.
`migrate-inline` converts legacy block/undo values in bounded idempotent
transactions. It advances through each hash prefix with the same exclusive
record/byte-bounded cursor rather than materializing the prefix, and mixed
inline/locator operation remains supported when disk headroom is insufficient.

## Persistent Urkel status

At each consensus interval, inserts, replacements, and removals form one sorted
Patricia mutation frontier. It retains unaffected subtrees as opaque
authenticated roots and reconstructs each final shared path once. Changed
records are packed bottom-up
into append-only pages; unchanged child locators can point into sealed older
segments. Proof reads traverse only the requested path and rehash every loaded
canonical record.

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
startup. Current API-v15 status retains the configured policy and
last-completed result fields introduced in API-v10. During the serialized pass
it serves an explicitly marked, timestamped
cached diagnostic snapshot, while authority-bearing reads continue waiting for
live state. Unclean RocksDB reopen tests verify that interrupted deletion
resumes safely and that a completion checkpoint agrees with the compacted node
set.

Pruned mode is the default mining profile. It uses HSD's exact network
constants: no height through `pruneAfterHeight` is retired, and the newest
`keepBlocks` remain disconnectable and serveable. The target comparison is
strict, matching HSD. Each retirement deletes both raw-block and undo
locators, clears their matching header/block presence bits, deletes any
matching interval pin, and advances the checksummed `undo-pruning/v1`
checkpoint in the same batch.

Checkpoint version 2 records independent block and undo frontiers, hashes, and
counts. Version 1 undo-only checkpoints decode without mutation and drive a
bounded raw-block backfill that never rereads historical payload bytes.
Startup validates the protected prefix, retired band, retained suffix,
canonical checkpoint bindings, root continuity, and the absence/presence of
interval pins on the retired/retained sides; missed retirements are caught up
in bounded batches. Reorganizations crossing the retired band fail before any
state mutation. A store with a pruning checkpoint cannot later open in
`archive` mode.

Deleting RocksDB locators does not itself shrink append-only segment files.
When dead committed frames exceed 256 MiB, pruned startup rewrites only live
locators into a fresh generation. New files are synced before one RocksDB batch
publishes every replacement locator and both manifests. Recovery keeps the
manifest-selected generation and removes either unpublished new files or
superseded predecessors. The stopped-node
`hsrd-storage-maintenance compact` command performs the same rewrite with full
pre/post frame scrubs and a JSON reclamation report. It first performs a
read-only, budget-checked plan. `compact --dry-run` reports the exact live,
physical, reclaimable, and estimated atomic-locator bytes without creating a
generation. Mutating compaction refuses to start below its configured reclaim
threshold or above any record/byte budget.

Segment bytes are synced before RocksDB publication, but a write error does not
prove that RocksDB rejected the batch. After any such ambiguous error the
process retains both generations and a shared fence covers every clone of the
RocksDB backend and archived store. New snapshots, all commits (including
metadata-only batches), checkpoints, and archive maintenance reject until the
database is truly closed and reopened; constructing another wrapper around a
poisoned backend is not recovery. Reopen reads the atomic manifests: old
manifests discard the unpublished generation, while new manifests retain it and
retire the predecessor. The same backend fence applies to an ambiguous
payload-free RocksDB write. Deterministic before-write and after-write fault
tests prove both outcomes and the fence, including the case where the complete
RocksDB batch is applied and then an error is returned. External process-kill
testing remains a rollout evidence requirement.

RocksDB can also report a successful replacement-locator/manifest commit before
the in-process archive fails to swap its writer, invalidate cached readers,
remove predecessors, or sync the directory. Every such post-commit
installation error marks the archive reopen-required and is reported as
committed-but-install-incomplete; new snapshots, archive payload reads
(including through existing snapshots), writes, and maintenance cannot continue
through that archive instance. Reopen trusts the already committed new
manifests and completes generation recovery. A failure injected before
predecessor cleanup leaves both complete generations for that decision. A later
cleanup failure may already have removed part of the old generation, but it
cannot remove the manifest-selected new generation; it is still reopen-only and
must not be retried in process.

Append-only name pages use the same publish-then-retire generation discipline.
At sixteen sealed 360-block segments, a synchronized pruned node streams the
current tree once, builds its authenticated hash-to-address index, and appends
only divergent subtrees for the other roots still required by undo and
interval pins. Initial native-sync catch-up and native-sync startup defer that
routine rewrite until the scheduler reaches `Synced`; a 128-segment emergency
threshold continues to bound a catch-up generation. One RocksDB batch replaces
`name-page-state/v1`, publishes every retained root locator in the new
generation, and deletes stale locators. Only then are the old files removed.
Recovery follows the manifest-selected generation, so a crash before
publication removes the future generation and a crash after publication
removes the superseded one.

Production closure still requires deployment-scale performance and priority
isolation plus repeated external RocksDB process-kill campaigns without
weakening historical-root reachability or the startup oracle. In-process phase
faults are deterministic regression coverage, not evidence that a particular
filesystem, kernel, or storage device honors the expected persistence order.
A complete non-pruned qualification is also mandatory: on the reviewed
production-scale dataset, all hsrd-owned live and temporary storage must remain
within a 150,000,000,000-byte peak and final envelope, while the launch
supervisor independently preserves at least 10,000,000,000 free filesystem
bytes. Its retained evidence identifies `baseline_mode: full_non_pruned` and is
compared at the same pinned height, binary, host, filesystem, and measurement
scope with the pruned run; the pruned final footprint must be nonzero and
smaller. An at-or-below 90,000,000,000-byte observation is optional,
informational, and never a qualification or release criterion.

This storage schema never owns or deletes an HSD data root. Qualification
records `hsd_blocks_deleted: false`. Any later HSD block-data retirement is a
separate destructive cutover that requires independently verified hsrd
tip/root/state and retained-reorg behavior, a tested HSD wallet
backup-and-restore, an approved rollback/evidence-retention plan, and explicit
operator approval for the exact paths and retention date.
