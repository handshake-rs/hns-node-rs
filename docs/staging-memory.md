# Staging allocation qualification — 2026-11-01

The ownership changes substantially reduce checkpoint and cache peaks, and
remove allocations from shared reads and admission lookups. The isolated replay
workload uses fewer allocations and requests fewer bytes over its lifetime, but
its peak rises by 16,148 bytes (0.236%). These are measurements of requested Rust
allocations, not process RSS or mainnet throughput.

## Method and source identity

The probe is
[`crates/hns-store/tests/staging_allocations.rs`](../crates/hns-store/tests/staging_allocations.rs).
Its allocator instrumentation exists only in that integration-test executable.
Thread-local counters record successful allocation/reallocation calls, total
requested allocation bytes, and maximum concurrently live requested bytes. Every
workload must return its live total to zero. Counting is disabled before printing.

Both runs used Rust 1.97.1 (`8bab26f4f`, LLVM 22.1.6), release optimization,
`aarch64-unknown-linux-gnu`, and serial Cargo builds on the same ARM host. Cargo
used the workspace's prebuilt RocksDB 10.4.2 archive with `ROCKSDB_COMPILE=0` and
the required local configuration. No running database or device logs were used.

The baseline was a detached checkout of
`f2393746393f617a016f911e61fcede717e32ae6`. The five comparative workloads were
copied into that checkout before the implementation changed and then run
unchanged against the current implementation. Additional shared-read,
replacement-capacity, long-key, and short-key tests apply only to the current
implementation.

The comparison invokes the actual `StagingOverlay`, its checkpoint machinery,
and `MemoryBatch` materialization. It does **not** instantiate the old node-only
`ReorgOperationCharges` wrapper, so its baseline excludes the duplicate key map
and accounting journal removed by this patch. Do not infer an end-to-end node
memory percentage from the isolated replay row. No obsolete accounting
implementation is retained in the test suite.

The counts exclude allocator metadata and fragmentation, native RocksDB
allocations, kernel/page-cache memory, and a mainnet node's resident chain state.
The cache workloads generate base values on demand instead of retaining an
unmeasured database full of input buffers. The checkpoint and replacement
workloads keep their caller input vectors live while submitting each write.

## Comparative results

All values are exact bytes or allocation calls from the probe; percentages are
relative changes from the baseline. A reallocation counts as one call and its
new requested size contributes to cumulative requested bytes.

| Workload | Baseline calls | Current calls | Baseline cumulative bytes | Current cumulative bytes | Baseline peak bytes | Current peak bytes | Peak change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16,384 UTXOs, mixed checkpoint commit/rollback, reads, materialization | 131,553 | 61,908 | 19,056,940 | 15,481,192 | 6,832,880 | 6,849,028 | +0.236% |
| One key overwritten 128 times with 64 KiB values, rollback | 531 | 395 | 16,801,976 | 16,783,988 | 8,466,824 | 197,912 | −97.663% |
| Same overwrites, checkpoint commit | 531 | 395 | 16,932,792 | 16,849,396 | 8,466,824 | 197,912 | −97.663% |
| State cache: 8,192 distinct 8 KiB values | 24,591 | 18,374 | 136,118,488 | 84,033,736 | 68,215,100 | 16,483,916 | −75.835% |
| Name-node cache: 8,192 distinct 8 KiB values | 24,590 | 20,354 | 136,085,484 | 100,647,120 | 68,182,096 | 32,975,748 | −51.636% |

Replay allocation calls fall by 52.941% and cumulative requested bytes by
18.763%. Shared value handles and per-operation accounting add retained
metadata, explaining why fewer allocations do not establish a lower peak in
this unmetered replay case. Checkpoint cumulative allocations change much less
than their peak because every caller still creates and submits its new input;
the improvement releases intermediate versions instead of retaining all 128.

The cache results include point-read output buffers and exercise admission
beyond the configured cache budgets. The state/name reservations are 16/32 MiB,
with the existing 65,536/131,072-entry ceilings. Each retained entry reserves its
key length, value capacity, and 256 bytes of framing; each admitted column family
also reserves 512 bytes. An oversized entry is returned without retention.

## Ownership and framing checks

Ordinary integration tests prove that an owned 256 KiB input keeps its original
allocation after `put_shared`, and that 4,096 alternating overlay/cache shared
reads allocate **zero** bytes. Repeated existing, missing, and cross-family
accounting lookups for 96-byte keys likewise allocate zero bytes in both
`MemoryBatch` and `RocksBatch`, before and after a checkpointed write.

Additional current-only workloads measured:

| Workload | Calls | Cumulative requested bytes | Peak live bytes |
| --- | ---: | ---: | ---: |
| 128 ordinary replacements alternating 64 KiB, 128 KiB, 1 KiB, 64 KiB | 391 | 16,848,940 | 328,528 |
| Same logical lengths, moving vectors with 1 MiB capacity | 263 | 134,223,916 | 2,098,000 |

The latter case verifies that retained capacity remains 1 MiB even when the
logical value is much shorter. The budget must account for that capacity.

The adversarial materialization workload inserts 14,337 distinct keys—one past
the preceding hash-table capacity—with empty or 32-byte values. The backend
reserves its final table capacity before the overlay drains, preventing repeated
backend growth while the source table remains live. It measures real allocator
peaks against `2 × (key bytes + value bytes + framing) × row count`:

| Key bytes | Value bytes | Measured peak | Two representations, 128-byte framing | Final two representations, 192-byte framing |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 0 | 5,095,980 | 3,784,968 | 5,620,104 |
| 4 | 32 | 5,554,764 | 4,702,536 | 6,537,672 |
| 8 | 0 | 5,095,980 | 3,899,664 | 5,734,800 |
| 8 | 32 | 5,554,764 | 4,817,232 | 6,652,368 |
| 36 | 0 | 5,095,980 | 4,702,536 | 6,537,672 |
| 36 | 32 | 5,554,764 | 5,620,104 | 7,455,240 |

Keeping 128-byte framing while lowering the representation count to two would
undercharge five of these six cases. The final model uses **192-byte framing
and two representations**, and the profile asserts that every measured peak
fits that allowance. The tightest measured case has 524,124 bytes of allowance
above its requested-allocation peak. This is workload evidence on this ABI,
not a universal proof about allocator overhead or every possible workload.

The node additionally admits the prior current operation during replacement,
charges original checkpoint values and journal entries separately, and records
the maximum admitted peak in diagnostics. The fixed 256 MiB reorganization
ceiling remains unchanged. See the exact
[ownership accounting contract](storage-schema.md#reorganization-ownership-accounting).

## Reproduction and artifact hashes

Follow the prebuilt-library requirements in [node qualification](testing.md),
then run:

```sh
cargo test --locked --release -j 1 -p hns-store
cargo test --locked --release -j 1 -p hns-store --test staging_allocations -- \
  --ignored --nocapture --test-threads=1
```

The normal store run passed 104 unit tests and two allocator integration tests;
the explicit final run passed all three allocation profiles, including the
assertion for the selected 192-byte model in all six short-key cases. The final
run reproduced every allocation count and peak in the tables above.

SHA-256 identities captured for the measurement artifacts:

| Artifact | SHA-256 |
| --- | --- |
| Baseline copied harness | `80d6de033b15ed9631661f7aae9360e92d0904f80f1601566eba550cd992cf19` |
| Current measured harness before binding the final framing assertion | `c97ccab3649d36ba157e29846259f0238254b72a58609de3bb0d6069e832cd8f` |
| Final harness with the 192-byte assertion | `b70723448331b347c1992de78abb9e53cf7c2fa0af14c5faa0ef0e9c03eb70bb` |
| `crates/hns-store/src/lib.rs` | `04aeb180c873b09e2b0a7dba2acb00e8f326b11e43b80b746a2961b0b8facf06` |
| `crates/hns-store/src/staging.rs` | `ca153d62a2eddefb88c2329eda212502c45f7f068379042740cc4d8e3bfdbdb3` |
| `crates/hns-store/src/batch_data.rs` | `61fe95636eafd309b8aab6a8804feb2e658e62ac532612ddd8043d0cc57695f7` |
| `crates/hns-store/src/rocks.rs` | `06eed5a1f89d6e1c284f0b5ce41a029c2b33356d0be105042b3c7a59bb3dce30` |

These hashes identify this measurement point, rather than promising that later
source revisions produce identical allocator behavior. A compiler, allocator,
representation, checkpoint, or table-capacity change warrants rerunning the
profiles. Production qualification still requires sustained native sync,
reorganizations, crash/reopen behavior, and deployment-specific memory evidence.
