# Independent pre-push production audit

Disposition: **BLOCKED**. The integrated tree must not be released or described as production-complete until finding P0-1 is fixed and regression-tested. The seven external production-assurance campaigns also remain required release evidence; their absence is an evidence blocker, not a claim that the corresponding source paths are defective.

## P0-1 — reorg staged-effect ceiling is not authoritative

The production limits advertise at most 1,024 disconnects, 1,024 connects, 128 MiB of reconciliation bodies, and 256 MiB of staged effects (`crates/hns-node/src/lib.rs:194-198`, `NodeReorgLimits::PRODUCTION` at approximately `:3539-3552`). The mutation boundary invokes `preflight_reorg_staged_effects` before creating the overlay/batch (`crates/hns-node/src/lib.rs:8791-8839`).

That preflight does not measure the staged mutation it purports to bound. `preflight_reorg_staged_effects` (`crates/hns-node/src/lib.rs:5236-5294`) sums:

- encoded connect and disconnect bodies (subject to the separate 128 MiB limit),
- a fixed 64 KiB reserve for each connect/disconnect, and
- stored undo value bytes for disconnects only.

It does **not** include connect-side generated `BlockUndo` values, UTXO/name/deployment/header/block/height/transaction-index writes, deferred name-tree page nodes, or actual batch operation/framing bytes. Connect processing generates and writes a new undo (`connect_block_to_batch_with_services`, `crates/hns-state/src/lib.rs`, ending in the `ColumnFamily::Undo` put), while `BLOCK_UNDO_CODEC_MAX` is `MAX_BLOCK_WEIGHT * 8` (32,000,000 bytes; `crates/hns-state/src/lib.rs:100`). The encoder itself builds the complete value before the put. The write path then retains value copies in the underlying `RocksBatch` and the `StagingOverlay` (`crates/hns-store/src/lib.rs:686-735`, `:939-973`). Therefore 64 KiB per connect is not a conservative upper bound, and a request that passes preflight can retain substantially more than 256 MiB before atomic commit. There are no exact-limit/one-byte-over tests exercising the real connect-side staged byte total.

Required invariant: **before and throughout a reorg, every byte retained or submitted as part of the atomic mutation must be charged to one deterministic production budget; staging must fail before exceeding the limit.** At minimum the charge must cover keys, values, operation framing, connect-generated undo, all state/index mutations, and deferred name-tree records. Account for the simultaneous overlay and backend-batch representations (or remove the duplication). A fixed per-block allowance is acceptable only if it is a proved upper bound for all valid blocks and all enabled indexes/storage profiles.

Acceptance criteria:

1. Enforce the budget in the actual `WriteBatch`/staging path (or an equivalent conservative estimator used by that exact path), not only in a body/undo pre-scan.
2. Reject before commit/allocation growth crosses the configured ceiling, with overflow-safe arithmetic and a stable resource-limit error.
3. Add exact-limit and one-byte/one-operation-over tests including: connect-generated large undo, disconnect undo, transaction index enabled, name-state/name-page effects, and multiple-block read-your-writes replacement semantics.
4. Demonstrate that a rejected reorg leaves the durable database, page-file tail, in-memory index, mining generation, and mempool publication unchanged.

## Required external evidence

The repository correctly fails closed on missing evidence, but production completion is not yet established by source/unit tests. `docs/readiness.md:370-413` identifies the exact-release campaigns still required, and `scripts/run-production-assurance.sh:198-206` requires records for all of them:

- production-scale pruning,
- RocksDB fault injection,
- sustained reorg/partition recovery,
- WAN/load latency,
- physical gateway/ASIC validation,
- long-duration multi-peer soak, and
- production mempool/template differential testing.

The sustained fuzz campaign and persistent performance gate must likewise be run against the exact release worktree/artifacts; the scripts' existence is not execution evidence. A fresh unpruned mainnet synchronization from an empty HSRD data directory is additional operational qualification requested for this release.

## Areas independently cleared in this source review

- Both production RPC listeners classify known/unknown/unsupported methods before constructing node state, so unsupported methods do not trigger state collection.
- Request body, global request concurrency, point-read concurrency, collection concurrency, and execution timeout envelopes are present. Blocking workers retain their worker permit after an HTTP timeout, preventing detached work from escaping the worker bounds.
- Point RPCs use keyed reads/snapshots; collection RPCs use bounded/cursor-backed reads. RocksDB scans do not hold the global node mutex. The parent-authority special path holds it only for constant-count keyed reads.
- Production mempool enumeration is capped and uses an ordered transaction-id view rather than a full unbounded storage scan.
- Header/reorg planners, alternate-header storage, block-cache mutation, retained-root discovery, page generation, pruning, and compaction now expose explicit cardinality/byte/deadline envelopes. Full legacy/offline materialization remains clearly separated from ordinary production startup/steady state.
- Sustained fuzz and persistent-RocksDB performance harnesses are fail-closed and source-bound, but remain evidence until actually executed for this release.

## Non-blocking documentation correction

`docs/storage-schema.md:167-168` still describes non-direct activation as reconstructing the complete ancestry and describes a fixed 4,096-record block-cache clone. The integrated implementation now uses bounded ancestry/reorg planning and an incremental bounded cache update. Correct the complexity table so operators are not auditing obsolete behavior.
