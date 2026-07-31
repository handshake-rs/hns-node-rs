# Independent P0-1 resolution audit

Disposition: **BLOCKED**.

The final authoritative input reviewed was `crates/hns-node/src/lib.rs` at
728,970 bytes and SHA-256
`47e8e9111ff3ca5e9adbdcd6fc6d556f7a9c23324c1e2788445566f973c8fe42`.
The new meter is a material improvement, and the three focused debug
regressions pass, but the original P0-1 acceptance criteria are not all
satisfied. The production archived-store commit and physical name-page output
still contain effects outside the meter, and the tests exercise synthetic or
early-rejection paths rather than those production escapes.

## Acceptance decision

| Criterion | Decision | Evidence |
| --- | --- | --- |
| 1. Budget the actual write/staging path | **Not met** | Node-side `WriteBatch` calls are metered, but the meter is discarded before the production archived-store commit adds/replaces operations, and physical name-page pages never traverse the metered batch. |
| 2. Reject before the ceiling with overflow-safe, stable errors | **Partially met** | Meter arithmetic and pre-copy rejection are correct for calls that reach the decorator. There is no corresponding check for the effects added after the decorator is removed. |
| 3. Exact/one-over tests across generated undo, disconnect, tx index, names/pages, and multi-block replacement | **Not met** | The exact/one-over coverage is an in-memory decorator test with hand-authored values. It does not generate a large undo through block connection, pack/append a name page, use the archived RocksDB commit, or perform a multiple-block reorg. |
| 4. Rejected reorg leaves database, page tail, indexes, mining, and mempool unchanged | **Partially met** | The integrated test proves this for an early rejection at the first connect write. It does not force rejection after a physical page append or during the production archive transformation. |

## What is correctly closed inside the node-side batch path

- The production limit remains 256 MiB at
  `crates/hns-node/src/lib.rs:194-209`. The three-copy staging charge explicitly
  covers source, backend-batch, and overlay/deferred-map representations; the
  two-copy publication charge covers source plus backend after the overlay is
  consumed.
- `ReorgStagedEffectMeter::operation_charge` and `charge` use saturating
  conversions, addition, and multiplication, and return the stable
  `StoreError::LimitExceeded` context `"reorganization staged effect bytes"`
  before updating `consumed` (`crates/hns-node/src/lib.rs:3584-3630`). With the
  production limit, any arithmetic saturation is greater than the limit and
  therefore fails closed.
- `ReorgMeteredBatch::put` and `delete` charge before calling the wrapped
  operation (`crates/hns-node/src/lib.rs:3633-3671`). Consequently a rejected
  operation is absent from both the backend batch and `StagingOverlay`.
- Every call remains cumulative, including a delete followed by a put of the
  same key. That matches `StagedBatch`, whose underlying batch retains every
  operation even though its read-your-writes map replaces the visible value
  (`crates/hns-store/src/lib.rs:951-973`).
- The decorator is correctly supplied to disconnect and connect staging
  (`crates/hns-node/src/lib.rs:8951-9058`), so generated undo, UTXO, name-state,
  deployment, header/block/height, raw-block, transaction-index, pin, and meta
  mutations made through their generic `WriteBatch` argument reach the meter.
  The same cumulative meter is carried into the database records emitted by
  page preparation (`crates/hns-node/src/lib.rs:9103-9148`).
- The publication order remains atomic at the logical state boundary: cache
  updates are validated before the store commit and published only after it
  succeeds (`crates/hns-node/src/lib.rs:9184-9239`). Page preparation failures
  invoke tail rollback, while an ambiguous commit fences instead of truncating
  (`crates/hns-node/src/lib.rs:9128-9173`, `:9242-9254`).

These properties close the original defect for mutations that actually pass
through `ReorgMeteredBatch`; they do not make that decorator authoritative for
the complete production mutation.

## Source blocker 1: production archive effects occur after the meter is gone

A data-directory node always wraps its RocksDB store in the payload segment
archive (`crates/hns-node/src/lib.rs:6257-6265`, `:6367-6373`). During a reorg,
the node unwraps the staging decorator, reconstructs a two-copy decorator for
page metadata, then unwraps it again and discards `_meter` before calling the
bare store commit (`crates/hns-node/src/lib.rs:9120-9155`).

That bare production commit is not a transparent submission of the already
metered operations. `commit_archived_store_handle`:

- extracts every block/undo payload from the batch;
- constructs and writes a framed segment record for each payload;
- replaces each batch payload with a segment locator; and
- appends two snapshot-manifest puts to the same atomic database batch.

Those mutations occur at `crates/hns-store/src/lib.rs:2841-2887`. In particular,
the two `batch.put` calls at `:2869-2879` cannot reach
`ReorgMeteredBatch`, and segment encoding retains a full payload plus a full
framed encoding before submission (`crates/hns-store/src/segment.rs:417-438`,
`:1399-1450`). Every connected reorg generates an undo payload, so this is the
normal production path rather than an optional corner case.

The per-operation 128-byte allowance is useful conservatism for operations the
decorator observes, but there is no source invariant or test proving that its
unused headroom covers an arbitrary exact-bound batch plus these later
locator/frame/manifest effects. A batch may leave the meter exactly exhausted;
the archived commit can then add cumulative submitted bytes without a meter or
a stable resource-limit error. This fails criteria 1 and 2.

Closure requires either carrying the same meter through an archive-aware commit
API, or charging a proved deterministic upper bound for segment frames,
locators, both manifests, and final backend framing before any segment append
or database-batch growth. The exact-limit regression must use the resulting
production commit path.

## Source blocker 2: physical name-page output is not an observed operation

Deferred `NameTreeNodes` values are charged during overlay staging, and the
snapshot locator/state records are charged during page publication. The actual
fixed-size pages are different retained/submitted representations, however.
`prepare_root` packs records, computes `page_count`, and appends/syncs the pages
directly through `NamePageAppender` (`crates/hns-node/src/lib.rs:4779-4844`).
Only after that append does it submit the root locator and page-state records
through the metered batch (`:4852-4870`).

`preflight_append_pages` enforces the separate 150,000,000,000-byte generation
ceiling and filesystem reserve (`crates/hns-node/src/lib.rs:4643-4661`); it does
not charge `page_count * NAME_PAGE_BYTES` to the reorg's 256 MiB staged-effect
budget. Packing also materializes canonical records into fixed 64 KiB page
buffers, including final-page padding. The fixed three-copy raw-node charge has
no proved bound tying it to those physical page bytes. Thus the meter does not
yet establish the required claim that every deferred page effect is charged to
the one reorg budget.

The existing rollback at `crates/hns-node/src/lib.rs:9141-9147` is the correct
atomic response if a later metered metadata put fails, but it is not a substitute
for charging the physical output before append.

## Regression coverage gap

The focused tests all pass, but their scope is narrower than their names imply:

- `reorg_meter_exact_limit_covers_generated_disconnect_index_name_and_page_writes`
  uses `StoreHandle::memory` and directly submits hand-authored byte vectors
  (`crates/hns-node/src/lib.rs:11068-11151`). Its "generated large undo" is a
  2 MiB `Vec` directly put into `ColumnFamily::Undo`; no block connection
  generates it. Its transaction index, name state, deferred node, and
  `page-publication` value are likewise direct puts. It never invokes
  `NamePageStorage::prepare_root`, a segment archive, or RocksDB. The same-key
  delete/put assertion at `:11153-11159` verifies decorator replacement
  semantics, but not a multiple-block reorg.
- `reorg_meter_rejects_one_budget_byte_over_before_any_staging_copy` is another
  isolated memory-batch test (`crates/hns-node/src/lib.rs:11238-11281`). It does
  correctly prove one-byte-over rejection before the wrapped batch and overlay
  copy, but only at that local boundary.
- `staged_effect_rejection_preserves_database_pages_indexes_mining_and_mempool`
  is an integrated `NodeService` test with transaction indexing and page storage,
  and its unchanged-state assertions are valuable. It still uses a memory store
  (`crates/hns-node/src/lib.rs:18427-18440`) and deliberately sets the allowance
  to the measured disconnect prefix so the first connect write is rejected
  (`:18450-18510`). Therefore it never appends a name page, reaches index
  preparation, or enters the archived production commit. Its assertions at
  `:18512-18557` prove early-rejection atomicity only.

Independent debug reruns on the authoritative source passed:

```text
cargo +1.89.0 test --locked -p hns-node --lib --all-features reorg_meter_
2 passed; 0 failed

cargo +1.89.0 test --locked -p hns-node --lib --all-features \
  staged_effect_rejection_preserves_database_pages_indexes_mining_and_mempool
1 passed; 0 failed
```

Acceptance criterion 3 still needs an end-to-end exact/one-over suite that
generates the large undo through connect processing, enables the real tx-index
path, crosses actual name-state and name-page publication, exercises at least
two replacement blocks with read-your-writes dependencies, and uses the
archived RocksDB backend. Criterion 4 needs a late rejection after page bytes
have been appended but before commit, proving tail rollback and all listed
logical publications remain unchanged; the production archive limit path also
needs an unchanged/fail-before-append assertion.

## External evidence remains a separate blocker

This **BLOCKED** disposition is a source/test-acceptance blocker, independent of
the external qualification record. Even after P0-1 is closed, production
completion still requires exact-release sustained fuzz and persistent
performance evidence, the fresh unpruned mainnet synchronization requested for
this release, deployment-custody evidence, and all seven external campaigns.
The repository accurately lists those missing records at
`docs/readiness.md:370-413`, and the verifier requires all seven gate files at
`scripts/run-production-assurance.sh:198-206`.

The absence of those external records is not evidence of another source defect;
it means production completion cannot be claimed even after this source blocker
is fixed.
