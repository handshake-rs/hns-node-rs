# Native synchronization and mining-path performance

Performance work must preserve consensus, crash consistency, and reorganization
atomicity. The target is to remove redundant storage and coordination work until
the irreducible costs are block decoding, cryptographic verification,
authenticated-tree mutation, and one durable commit per bounded state slice.

## Reproducible measurements

Measure an already-running native mainnet node:

```bash
python3 scripts/measure-hsrd-native-sync.py \
  --hsrd-url http://127.0.0.1:12047 \
  --authorization-header-file /absolute/path/hsrd-authorization-header \
  --duration-seconds 60 --interval-seconds 2 \
  --output /path/to/native-sync-measurement.json
```

The sampler accepts a loopback HTTP origin unless remote access is explicitly
enabled. It reads authorization from an absolute, non-symlink, mode-0600 file
and never writes the value to arguments, reports, or logs. Each report is bound
to one runtime instance and rejects counter regression, runtime errors, or
malformed diagnostics.

Sampler schema 2 records:

- overall and interval header, body, state, and byte rates;
- active-state slice count, block count, total duration, and planning,
  state-commit, and post-commit phase durations;
- peer-event and validation-result backlogs;
- stored-to-active buffer depth, pending and inflight body work, active stalls,
  ready peers, failures, and unavailable evidence.

Measure the local mining critical path:

```bash
cargo run --locked --release -p hns-node --bin hsrd-performance-gate
```

`hsrd-performance-gate` imports canonical HSD regtest genesis, warms ten blocks,
then builds and connects 100 native blocks. It reports count, P50, P95, P99,
maximum, failure count, and unavailable evidence for template assembly, cached
job preparation, tip-to-job work, solved-candidate validation, and local
connection. This is a regression gate, not a full-mainnet IBD completion claim
or an ASIC/WAN qualification.

## Chokepoint model

The live pipeline has five distinct resource domains:

```text
Brontide peer tasks
       |
       v
peer-event coordinator -> body scheduler -> stateless validation workers
       |                                      |
       +<----------- ordered results ----------+
       |
       v
durable body batch
       |
       v
single contextual state writer -> one synchronous RocksDB transaction
```

Brontide is required HNS transport, but current replay is not transport-crypto
limited. Ready peers can be at the network header tip while the contiguous
stored-body frontier remains ahead of active state. A process trace of that
condition was dominated by random RocksDB point reads and synchronous durability
boundaries. The active writer used only part of one CPU core; body acquisition
also paused when the coordinator was occupied by a multi-second state slice.

This produces two coupled limits:

1. Buffered replay is limited by contextual state transition, authenticated
   name-tree mutation, point reads, batch construction, and durable commit.
2. When the stored buffer drains, coordinator latency delays peer-event
   consumption, scheduler replenishment, and validation-result commits.

The phase and backlog counters make these cases distinguishable. A high
`active_state_last_commit_micros` with a nonzero stored-active buffer identifies
local state/storage work. Growing `peer_event_backlog` or
`validation_result_backlog` identifies coordinator starvation. Zero buffer with
idle inflight work identifies acquisition/scheduling rather than state replay.

## Implemented replay refactor

Network maintenance retains its configured polling cadence, while active-state
work has a separate 10 ms minimum cadence. The activation branch connects
exactly one atomic slice per scheduler turn and uses delay-on-missed-tick
semantics, guaranteeing an inter-slice opportunity for peer events, validation
results, and shutdown. Ordered validation completion no longer recursively
invokes another state slice. This removes both the immediate slice-to-slice
feedback loop and the general polling interval as a replay throughput ceiling.

Direct canonical progress remains limited to eight connected blocks per atomic
slice. A real divergent best-work branch retains the configured reorganization
bound so disconnect and replacement connect remain one transaction. Increasing
the direct slice without separating coordinator and state ownership is not a
safe throughput optimization: it amortizes durability but proportionally
extends network starvation and shutdown latency.

The state path removes redundant reads at several levels:

- Every non-coinbase input and spendable output collision key in a block is
  deduplicated, fetched with one snapshot-bound UTXO multi-get, decoded once,
  and retained in an outpoint hash map. In-block outputs still override the
  base snapshot and duplicate-spend, collision, and maturity checks are
  unchanged.
- One atomic activation overlay caches up to 65,536 immutable base point reads,
  including misses, for metadata, headers, height/block/transaction indexes,
  UTXOs, name state, and snapshot records. Staged puts and deletes always take
  precedence.
- Content-addressed Urkel nodes use a separate 131,072-entry positive cache.
  Two or more name mutations traverse their independent paths with bounded
  breadth-first multi-get. Newly constructed records are collision-checked in
  one multi-get, and superseded records that never formed a committed root are
  discarded.
- Header-by-height and median-time values are memoized for the lifetime of each
  block transition.
- A strict body already stored by the native validation pipeline reuses its
  exact durable header/body/finality evidence after checking record identity,
  header equality, transaction count, merkle/witness commitments, status
  prerequisites, parent shape, body availability, and historical-route
  evidence. Activation still performs deployment, relative
  lock, script, covenant, claim/airdrop, UTXO, name-state, Urkel-root, undo, and
  active-chain validation in the atomic state transaction.
- Empty-pool direct replay skips post-commit mempool snapshot construction.

These caches are activation-snapshot local. They cannot expose stale data across
commits or replace durable validation.

## Complexity and storage round trips

| Operation | CPU/data-structure cost | Base-store access shape |
|---|---|---|
| Body scheduling | bounded `O(P × W)` over peers and request window | none |
| Block UTXO resolution | `O(I + O)` dedup and hash lookup | one multi-get per block |
| Header/MTP context | `O(H)` unique heights, with `H` bounded by requested contexts | one read per unique staged key |
| `K` name mutations | `O(K × 256)` authenticated-path hashing | breadth-first batched reads for `K >= 2` |
| Eight-block direct slice | sequential consensus work over block contents | one stable snapshot and one sync commit |
| Reorganization | `O(D + C + transactions + name paths)` | one stable snapshot and one atomic commit |

Without the staged point cache, repeated validation layers can turn one logical
key dependency into several Rust/RocksDB crossings. With it, base point reads
are bounded by the number of unique keys in the slice. UTXO multi-get changes
the FFI/storage scheduling cost from `O(I + O)` calls to one call while
preserving the same number of logical key probes.

## Optimal ownership boundary

The long-term topology is a dedicated chain-state actor that exclusively owns
the mutable `NodeService` consensus state. The network coordinator should own
peer sessions and the body scheduler, submit bounded activation commands, and
consume immutable completion records. That separation permits a larger or
adaptive commit batch without blocking peer-event intake.

It must not be implemented as concurrent consensus writers or as unlocked
snapshots. Required properties are:

- exactly one ordered state writer;
- one snapshot and one atomic batch for a complete direct slice or reorg;
- backpressure on activation commands and immutable result messages;
- generation/tip fencing so stale commands are rejected before mutation;
- shutdown only between transactions;
- diagnostic reads served from immutable published snapshots;
- contextual-invalid evidence returned to the coordinator for durable branch
  rejection and scheduler cleanup.

The current network-first coordinator is the safe first stage. The schema-2
backlog and phase distributions decide whether actor separation is warranted:
split ownership when coordinator backlog grows during otherwise healthy state
slices; continue storage optimization when state-commit time dominates without
backlog.

## RocksDB and compaction

Point-oriented column families share a bounded 192 MiB cache. Raw blocks and
undo use a separate 32 MiB cache so sequential replay cannot evict hot UTXO,
name-state, header, and Urkel pages. Bloom filters, cached index/filter blocks,
bounded WAL retention, and four background jobs constrain read and write
amplification.

Name-tree compaction validates the complete retained-root union before deletion,
performs a key-only preflight, and commits unreachable keys in 65,536-key
chunks. The completion checkpoint is written last. A crash may leave extra
unreachable records but cannot delete a validated reachable record; retry is
idempotent. Cached diagnostic snapshots keep status RPC responsive while the
state lock is occupied by compaction.

## Non-negotiable gates

Optimization is accepted only with:

- exact UTXO, name-state, Urkel-root, deployment, undo, disconnect, reconnect,
  and reorganization results;
- independently generated invalid blocks and transactions rejected at the same
  rule boundary;
- no new failed, unavailable, or terminal-error evidence;
- restart and crash recovery of the exact committed tip;
- sustained phase/backlog measurements on persistent mainnet storage;
- template-to-job, candidate-validation, local-connect, and first-peer
  publication latency distributions;
- reproducible builds and a reviewed migration and fallback procedure.
