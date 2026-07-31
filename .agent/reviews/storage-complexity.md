# Independent storage-complexity audit

Date: 2026-07-31
Agent: `/root/storage_complexity_audit`
Ledger assignment: `audit-storage-complexity-5c631e`
Disposition: **production-pruning blocker**

## Scope and reviewed snapshot

This was a read-only implementation audit except for this assigned report. The
primary scope was:

- `crates/hns-node/src/lib.rs`
- `crates/hns-state/src/page_tree.rs`
- `crates/hns-store/src/lib.rs`
- `docs/storage-schema.md`

The call graph required reading the retained-root implementation in
`crates/hns-state/src/lib.rs` and the relevant consensus constants.

Reviewed SHA-256 values:

| File | SHA-256 |
|---|---|
| `crates/hns-node/src/lib.rs` | `862fb5030ba1ae559af2f8bfb88750c1284d6edfe2ac9498a41df14b9216d9a4` |
| `crates/hns-state/src/page_tree.rs` | `383baf108fabeedd9dc39ea027b50724666aadacbfecc56a7baa9bc74d089963` |
| `crates/hns-state/src/lib.rs` | `6c4e9a51d8b498ed4eebfa2e686d7285e4844650f617741e66e20a701b526605` |
| `crates/hns-store/src/lib.rs` | `46c6bc70f2664e8e5ca89e098c9a6a0448dfee559ef5b5fc6e8515a14020e3c5` |
| `docs/storage-schema.md` | `62910fe0258dddac752e74ab9f75338b847a295ad75213e353d2fb14eb314bf0` |

These hashes identify the audited snapshot. Concurrent owners may replace them
after acting on this report.

## Executive result

The ordinary direct-connect and production RPC paths do not scan chain history.
The page reader now resolves only operation-scoped roots, derives segment paths
without enumerating the generation, opens files lazily, and caps open segment
files at eight.

The explicit name-page generation compactor is different. It is invoked only
during pruned startup, before RPC/native services are shared, so it does not
hold a live global node lock and cannot be reached by an RPC. However, its
retained-undo selection, locator selection, reachable-address index, output
generation, and atomic locator batch have no production resource, elapsed-time,
or temporary-disk ceilings. The retained-undo implementation can legitimately
materialize tens of gigabytes at mainnet codec ceilings. This blocks claiming
production-scale pruning completion.

## P0: retained undo is fully materialized

Severity: **high; release blocker for production pruning**

Exact call graph:

1. `NodeService::try_with_state` runs pruning and automatic physical
   maintenance during construction at `crates/hns-node/src/lib.rs:1326-1331`.
2. `NodeState::compact_pruned_name_pages_if_due` admits compaction once
   `active_segment >= 16` at `crates/hns-node/src/lib.rs:7299-7319`.
3. `NamePageStorage::compact_generation` calls
   `retained_name_tree_roots(&snapshot)` at
   `crates/hns-node/src/lib.rs:3355-3369`.
4. `retained_name_tree_roots` calls unpaged
   `scan_prefix(ColumnFamily::Undo, b"")`, decodes every complete `BlockUndo`,
   and retains every decoded undo in a `BTreeMap` at
   `crates/hns-state/src/lib.rs:3201-3220`.
5. For an archived store, `StoreHandleSnapshot::scan_prefix` first obtains the
   complete vector and then resolves every block/undo locator to its full
   payload into another complete vector at
   `crates/hns-store/src/lib.rs:1956-1977`.
6. The RocksDB implementation itself pushes every matching key/value into a
   `Vec` at `crates/hns-store/src/lib.rs:2567-2590`.

This is not merely linear time with bounded memory. It is `O(U)` full payload
residency followed by `O(U)` decoded object residency, where `U` is all retained
undo bytes.

### Mainnet theoretical calculation

The reviewed constants are:

- mainnet `prune_after_height = 1_000` and `keep_blocks = 288` at
  `crates/hns-consensus/src/lib.rs:173-174`;
- `MAX_BLOCK_WEIGHT = 4_000_000` at
  `crates/hns-primitives/src/lib.rs:36`;
- `BLOCK_UNDO_CODEC_MAX = MAX_BLOCK_WEIGHT * 8`, or 32,000,000 bytes, at
  `crates/hns-state/src/lib.rs:75`.

After the prune frontier is established, the legitimate retained domain is the
protected heights `0..=1_000` plus the newest 288 heights: 1,289 undo records.
The raw codec ceiling alone is therefore:

```text
1,289 * 32,000,000 = 41,248,000,000 bytes
                       41.248 decimal GB
                       38.415 GiB
```

This excludes decoded vectors/maps, allocator overhead, RocksDB/cache memory,
the reachable-node index, and the replacement page generation. Real chain data
will normally be much smaller, but production limits must be structural rather
than dependent on average block contents.

### Required correction

Retained-root selection should:

- iterate `Undo` with `scan_prefix_page` on one immutable snapshot;
- impose independent per-page record and byte budgets;
- decode only the fixed identity/root fields needed by this operation, or
  decode one bounded page and immediately discard full undo objects;
- retain only a compact
  `block_hash -> (height, resulting_committed_root)` validation tuple plus the
  root set;
- reject a non-advancing cursor;
- count and enforce total records and total decoded bytes before generation
  creation.

If a compact `BlockUndo` header decoder is introduced, it must still validate
version, minimum length, key/hash identity, and every root used for authority.
A partial parser must not silently accept a malformed tail that the complete
codec would reject; either separately validate the complete record in the
bounded page or define a checksummed fixed metadata record maintained
atomically with each undo.

## P0: name-page compaction has no total work or disk envelope

Severity: **high; same release blocker**

`NamePageStorage::compact_generation` also:

- materializes every `NAME_PAGE_ROOT_PREFIX` entry into `old_records` and
  `old_keys` with unpaged `scan_prefix` at
  `crates/hns-node/src/lib.rs:3371-3387`;
- streams the current tree, then retains an all-reachable-node
  `HashMap<TreeRoot, NamePageAddress>` at
  `crates/hns-node/src/lib.rs:3400-3457`;
- writes a complete replacement generation while the previous generation
  remains durable;
- deletes every old locator and publishes every retained locator in one
  uncapped RocksDB batch at `crates/hns-node/src/lib.rs:3474-3510`;
- checks output bytes only after publication at
  `crates/hns-node/src/lib.rs:3524-3542`.

There is no maximum input-locator count/bytes, retained-root count,
reachable-node count, page count, output bytes, atomic batch bytes, elapsed
time, cancellation point, or required free-space reserve. The sixteen-segment
threshold at `crates/hns-node/src/lib.rs:7304` is a lower trigger, not an upper
bound: a process can run far beyond sixteen segments before its next restart.

This path is crash-safe in publication ordering, but crash safety is not a
resource bound. A disk-full failure before commit is recoverable, yet can still
consume the filesystem reserve and prevent restart.

### Required API shape

Add an explicit `NamePageCompactionLimits` (or equivalent reviewed type)
covering at least:

- `scan_page_records` and `scan_page_bytes`;
- `max_undo_records` and `max_undo_decoded_bytes`;
- `max_locator_records` and `max_locator_bytes`;
- `max_retained_roots`;
- `max_reachable_records`;
- `max_output_pages` and `max_output_bytes`;
- `max_atomic_locator_records` and `max_atomic_locator_bytes`;
- `minimum_free_bytes_after_projected_output`;
- `maximum_elapsed` or an equivalent cooperative deadline/cancellation budget.

Preflight must finish before creating the future generation and must account
for old/new coexistence. Mutation-time counters must enforce the same limits
again because preflight estimates are not authority. Limit refusal must leave
no future generation and must not set the ambiguous-commit fence; an error after
the database commit attempt must retain the existing reopen-only behavior.

For large reachable sets, replace the all-node in-memory `known` hash map with a
bounded-memory external index or enforce a qualified hard maximum whose peak RSS
is covered by the performance gate.

## P1: other recovery vectors remain unpaged

Severity: **medium; startup availability, not live request safety**

Two related recovery paths still grow with retained history:

- `load_name_tree_snapshot_pins` fully scans and materializes its prefix at
  `crates/hns-state/src/lib.rs:3139-3155`. Archive mode retains historical pins,
  so this domain is not bounded by mainnet's 288-block recent suffix.
- an exhaustive/mismatched-checkpoint startup fully scans and sorts
  `HeightIndex` at `crates/hns-node/src/lib.rs:4600-4618`. The complete
  block/header binding audit is correctly cursor-paged elsewhere at
  `crates/hns-node/src/lib.rs:7421-7525`, but this later active-state audit is
  not.

Both are startup/recovery operations and therefore do not violate the
request-lock requirement. They should still use cursor pages and one-record
lookahead so an unclean restart has bounded transient memory. The wording at
`docs/storage-schema.md:102-110`, which reserves full scans for intrinsically
bounded or explicit offline domains, does not accurately cover these
chain-growing startup vectors.

## P1: deep alternate-branch planning is not early-bounded

Severity: **medium; not an ordinary direct extension**

`NodeService::accept_block` takes the O(1) direct-extension route at
`crates/hns-node/src/lib.rs:1522-1542`. For an alternate higher-work candidate,
it calls `best_chain_activation_plan` at `crates/hns-node/src/lib.rs:1544-1577`.
That planner materializes the complete disconnect/connect path at
`crates/hns-node/src/lib.rs:5721-5785`.

Native synchronization limits the eventual connect batch to at most 1,024 and
direct IBD slices to 288, but it computes the complete plan before truncation at
`crates/hns-node/src/shadow_sync.rs:2693-2783`. A deep candidate can therefore
cause `O(D)` time and memory before the configured bound is applied. The public
`apply_reorg` path itself has no defense-in-depth length/byte ceiling.

Recommended follow-up:

- add `plan_reorg_between_bounded` with independent disconnect/connect and
  estimated staged-byte limits, aborting as soon as any limit is crossed;
- enforce the same limits in `apply_reorg_classified`;
- use header ancestor skip pointers/binary lifting if bounded fork discovery
  still needs sublinear ancestry location;
- retain the existing one-commit atomicity or fail closed and require a trusted
  replay when a replacement exceeds the qualified atomic envelope.

This does not change the conclusion that an ordinary direct block connection
performs no chain-history scan.

## Cleared paths

### Ordinary block connection

The page-backed direct-connect route at
`crates/hns-node/src/lib.rs:6219-6316` calls `reader_for_roots` with an empty
required-root iterator. `reader_for_roots` performs only point lookups for roots
explicitly supplied by its caller at `crates/hns-node/src/lib.rs:3308-3353`.
There is no locator-prefix scan.

The direct state transition at `crates/hns-node/src/lib.rs:6318-6439` is
proportional to the block's affected inputs/state. Its pruning work is capped by
the authenticated name interval: `stage_due_undo_prune` rejects backlog larger
than one interval and processes at most that interval at
`crates/hns-node/src/lib.rs:7645-7724`.

Disconnect and reorganization select rollback roots by keyed undo reads at
`crates/hns-node/src/lib.rs:4004-4031`, then perform one locator point read for
each distinct required root through `reader_for_roots`. They do not scan the
historical locator namespace. Their work is proportional to the requested
disconnect/connect set, subject to the separate bounded-planning finding above.

### Page file handling

`NamePageTreeReader::open_generation` derives segment paths without directory
enumeration and opens no file during construction at
`crates/hns-state/src/page_tree.rs:1673-1746`.

Segment files are opened on demand and held in an eight-entry LRU-like cache at
`crates/hns-state/src/page_tree.rs:30-31,108-155`. The regression
`generation_reader_opens_segments_lazily_with_a_bounded_fd_cache` at
`crates/hns-state/src/page_tree.rs:2840-2929` checks zero construction opens,
bounded residency, and reopening after eviction.

`ordinary_page_reader_does_not_scan_historical_root_locators` at
`crates/hns-node/src/lib.rs:10593-10660` injects 1,024 historical locators,
proves an ordinary reader performs zero locator scans/gets, and proves one
rollback root costs one point lookup. An additional end-to-end direct block
transition test with many sealed segments would strengthen this helper-level
regression.

### Production RPC

Runtime listener construction uses `rpc_diagnostic_service`, not the legacy
full-entry snapshot, at `crates/hns-node/src/lib.rs:1827-1858`.
`RpcReadContext::service_for_request` at
`crates/hns-node/src/lib.rs:2201-2331` performs keyed header, block, transaction
index, block-body, UTXO, or name-state reads according to the already-dispatched
method. `getrawtransaction` searches only the consensus-bounded selected block.

The full scans in `rpc_entries` at `crates/hns-node/src/lib.rs:5283-5369` are
reachable through the public legacy snapshot helper, but repository call sites
outside its definition are tests. Neither production RPC listener calls it.
This distinction should remain protected by a production-listener regression.

### Block/undo segment compaction

The segment archive implementation has real structural bounds:

- 1,024 records and 8 MiB per scan page;
- 1,000,000 live records;
- 64 GiB live frame bytes;
- 128 MiB estimated atomic locator bytes.

They are defined at `crates/hns-store/src/lib.rs:66-74,981-1025`, preflighted at
`crates/hns-store/src/lib.rs:1180-1235`, and rechecked against the stable
snapshot while cursor paging at `crates/hns-store/src/lib.rs:1252-1405`.
Inventory uses the underlying Rocks snapshot's streaming `visit_prefix` with
constant counters at `crates/hns-store/src/lib.rs:1670-1715,2624-2644`.

The library does not itself enforce a free-space reserve or elapsed-time
deadline, so the automatic pruned-startup caller still relies on its finite
64-GiB output cap and external operational supervision. The name-page
compactor lacks even that finite output cap and is the immediate blocker.

## Required tests before clearing the blocker

At minimum:

1. A retained-undo fixture whose aggregate payload exceeds several cursor pages
   proves peak page residency never exceeds the configured byte budget.
2. Near-maximum individual undo payloads prove one oversized selected page
   fails closed without bypassing its byte limit.
3. Thousands of root locators prove paging, monotonic cursors, total-count
   refusal, and no pre-refusal generation creation.
4. A large current tree proves reachable-record/page/output counters stop at
   exact limits and remove an uncommitted future generation.
5. A deliberately insufficient free-space/reserve preflight refuses before
   generation creation.
6. A forced elapsed deadline during streaming removes the unpublished
   generation and leaves the old state usable.
7. Atomic-locator batch limit tests fail before the database commit attempt.
8. Existing before-write, ambiguous-write, after-commit, reopen, and legacy-root
   migration tests pass unchanged.
9. An end-to-end ordinary page-backed direct connect with thousands of stale
   locator records and more than eight segment files proves zero locator-prefix
   scans, bounded open FDs, and path-local page reads.
10. Bounded reorg-plan tests prove exact-limit acceptance and one-over-limit
    rejection before full path materialization.

## Audit commands

The following read-only commands supplied the evidence:

```sh
jq . .agent/coordination.json
rg -n "retained_name_tree_roots|NAME_PAGE_ROOT_PREFIX|compact_generation|scan_prefix|scan_prefix_page" \
  crates/hns-node/src/lib.rs crates/hns-state/src/page_tree.rs \
  crates/hns-state/src/lib.rs crates/hns-store/src/lib.rs docs/storage-schema.md
rg -n "rpc_snapshot|rpc_entries|rpc_diagnostic_snapshot|rpc_service" crates/hns-node/src
rg -n "best_chain_activation_plan|MAX_ACTIVE_STATE_CONNECT_BATCH|MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE" \
  crates/hns-node/src/lib.rs crates/hns-node/src/shadow_sync.rs
nl -ba crates/hns-node/src/lib.rs
nl -ba crates/hns-state/src/page_tree.rs
nl -ba crates/hns-state/src/lib.rs
nl -ba crates/hns-store/src/lib.rs
nl -ba docs/storage-schema.md
sha256sum crates/hns-node/src/lib.rs crates/hns-state/src/page_tree.rs \
  crates/hns-state/src/lib.rs crates/hns-store/src/lib.rs docs/storage-schema.md
awk 'BEGIN { records=1001+288; per=4000000*8; print records, per, records*per }'
```

No heavy Rust build or test campaign was run, as directed.
