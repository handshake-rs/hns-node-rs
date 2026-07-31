# Independent P0-1 closure audit

Disposition: **P0-1 CLOSED. No pre-push source blocker remains on the exact reviewed hashes. Production completion remains BLOCKED on external qualification evidence.**

This is a source-and-debug-test decision about the reorganization staged-effect
budget identified in the original production audit. It is not a release test,
does not supersede the repository's fail-closed production-assurance gates, and
does not claim that the requested external campaigns have run.

## Authoritative inputs

The two owners froze their files before this audit's final validation. I
independently re-read and hashed the exact inputs after all focused reruns:

| File | Bytes | Lines | SHA-256 |
| --- | ---: | ---: | --- |
| `crates/hns-store/src/lib.rs` | 252,827 | 6,875 | `5ab94a5ed28bcf7cdd8ee966307dc44f064a00c8bbbe82d11d73b7350099a17c` |
| `crates/hns-node/src/lib.rs` | 760,560 | 19,448 | `66fd54f8489dbd0226bc984d5ebd75d101f513d5b4d065a0edf0916038dedb09` |

Both files remained byte-identical after the independent tests. `git diff
--check` also passed for both. This audit was read-only with respect to source.

## Acceptance decision

| Original P0-1 criterion | Decision | Exact-source evidence |
| --- | --- | --- |
| 1. Enforce one budget in the actual write/staging path | **Met** | Every reorg `WriteBatch` mutation is charged by `ReorgMeteredBatch`; the same meter then charges page-packing scratch, fixed-size page output, publication writes, and the archive transformation (`hns-node/src/lib.rs:3594-3825`, `:9130-9141`, `:9299-9343`; `hns-store/src/lib.rs:1461-1489`, `:2912-2933`). |
| 2. Reject before growth crosses the ceiling, with overflow-safe stable error semantics | **Met** | Conversions, additions, and multiplication saturate; `consumed` changes only after acceptance; the stable context is `"reorganization staged effect bytes"` (`hns-node/src/lib.rs:3628-3708`). Page packing/output are charged before their allocations/appends (`:4886-4916`, `:4941-5005`). Archive effects are calculated read-only and charged once before extraction, encoding, append, locator replacement, or manifest insertion (`hns-store/src/lib.rs:2912-2966`, `:3129-3243`). |
| 3. Exact/one-over coverage including generated undo, disconnect, tx index, names/pages, and multi-block read-your-writes | **Met** | Exact and one-byte-over component tests cover cumulative staging, packing, physical page output, and archive publication (`hns-node/src/lib.rs:11328-11595`; `hns-store/src/lib.rs:6061-6360`). The real archived RocksDB test generates a 64 KiB-plus undo through block connection, performs a real replacement `NameState` write, enables tx indexing, appends a page, and connects a child spending its parent's staged output (`hns-node/src/lib.rs:19021-19336`). |
| 4. Rejection leaves durable and published state unchanged | **Met** | The late archived rejection test compares the complete logical database image, byte images of all payload segment files, page file and state, block/header tips, block and tx indexes, mining snapshot/generation, and a real unrelated mempool entry (`hns-node/src/lib.rs:19203-19335`). Successful rollback leaves no fence; rollback failure instead fences storage and revokes authority (`:5078-5117`, `:11683-11737`). |

## Why the budget is now authoritative

### Actual reorganization operations

The production ceiling remains 256 MiB. Each staging operation is charged as
three complete key/value representations plus 128 bytes of per-operation
framing, while post-overlay database publication is charged as two
representations (`crates/hns-node/src/lib.rs:194-219`). These are not input-body
estimates: `ReorgMeteredBatch::put` and `delete` charge immediately before the
wrapped operation, so connect-generated undo, disconnect restoration, UTXO,
name state, block/header/height, transaction-index, snapshot, and metadata
writes cannot enter either the overlay or backend batch after rejection
(`:3710-3763`). Repeated writes to the same logical key remain cumulative.

One `ReorgStagedEffectMeter` is constructed around the production
`StagingOverlay` (`:9130-9141`). After disconnect/connect processing, that same
meter is moved—not recreated—into the two-copy publication decorator
(`:9299-9304`), then extracted and passed to the store's archive-aware commit
(`:9331-9343`). The stable `LimitExceeded` context distinguishes a budget
preflight rejection from an ambiguous database outcome.

### Name-page packing and physical output

The prior resolution audit correctly found that deferred logical nodes did not
prove a bound for page-pack scratch or fixed 64 KiB output. The final source
closes both boundaries:

- `charge_name_page_packing` sums each canonical record plus a conservative
  1 KiB per-record envelope before `pack_name_page_records` constructs its
  lookup, traversal, address, builder, and retained logical-record structures
  (`hns-node/src/lib.rs:3682-3697`, `:3770-3810`, `:4886-4897`, `:4941-4956`).
- Once packing reveals the exact page count, the meter charges two complete
  fixed-size page representations plus framing before
  `append_with_reserve` allocates its encoded page or writes it
  (`:3665-3680`, `:4904-4916`, `:4995-5005`). The physical 64 KiB buffer is
  created inside `NamePageAppender::append_with_reserve` only after this call
  (`crates/hns-store/src/name_page.rs:390-426`).
- Root locators, pins, page-state metadata, and any segment-seal state still
  traverse the metered `WriteBatch`.

The accounting is conservative rather than ABI-dependent. It counts the
logical pack structures separately from the encoded/durable page pair, and all
arithmetic fails closed by saturation against the much smaller production
limit.

### Archive transformation

The prior audit's remaining normal-production escape was the payload archive,
which transforms an already staged block/undo value after the node-side
decorator has been removed. The final store API carries the caller's same meter
into that transformation through the public `AtomicWriteEffectBudget` contract
and `StoreHandle::commit_with_effect_budget`
(`crates/hns-store/src/lib.rs:671-688`, `:1461-1489`).

While holding the archive publication lock, `commit_archived_store_handle`
walks the actual batch without extracting values and derives one saturated
additional charge. It calls `charge_additional` exactly once. Only after that
succeeds may it move payloads, encode/append/sync frames, replace values with
locators, add the two manifests, and submit the database batch (`:2912-2979`).
The charge explicitly covers:

- one extracted raw key/value representation;
- two complete frame representations (encoded userspace frame and physical
  output);
- three locator representations (`PreparedArchive`, encoded handle batch, and
  native RocksDB batch); and
- four manifest representations (prepared struct, temporary encoding, handle
  batch, and native RocksDB batch).

Those multiplicities and fixed-format bounds are explicit at
`crates/hns-store/src/lib.rs:88-116`. The calculator uses actual payload and key
lengths, counts every matching put including repeated keys, uses saturated
arithmetic, and adds the two fixed-width manifests only when an archive-aware
budget and at least one payload are present (`:3129-3243`). It does not rely on
unused allowance from the earlier node charges.

The exact RocksDB regression independently reconstructs the expected formula,
binds the empty-frame and manifest constants to their encoders, starts with a
nonzero cumulative consumption, and proves both sides of the boundary
(`:6061-6360`). A one-byte-short limit returns the exact stable context and
actual value while leaving `consumed`, segment lengths, raw block/undo/meta
keys, and both manifest bytes unchanged. The exact cumulative limit succeeds
and validates raw locators, frame lengths and files, metadata, and resolved
payload bytes.

## Late rejection and recovery semantics

A page-backed reorg necessarily prepares and syncs page bytes before the final
database transaction. The production code now treats only the archive
`LimitExceeded` result as provably pre-archive-mutation. That error returns to
the outer path, which truncates the already prepared page tail
(`crates/hns-node/src/lib.rs:9341-9375`). Other commit errors remain ambiguous:
the page subsystem is fenced and the node requires restart rather than
destroying potentially committed data (`:9356-9363`).

`rollback_uncommitted_tail` drops the live appender, removes unpublished
successor segments, truncates to the committed manifest boundary, reopens at
that exact tail, and restores generation accounting (`:5078-5106`). If removal,
truncate, or reopen cannot prove that state, it self-fences before returning the
error (`:5107-5117`). The segment-seal rollback and forced rollback-failure
regressions prove both the successful and fail-closed branches
(`:11611-11737`). In-memory indexes and page state are published only after the
store closure succeeds (`:9365-9383`).

## Regression quality

The real late-rejection regression is not vacuous. It opens a data-directory
node with Sync RocksDB, payload segments, name pages, transaction indexing, and
a live mining/mempool service (`crates/hns-node/src/lib.rs:19021-19066`). It
then:

- establishes an existing name-page boundary and two distinct eligible names;
- produces a replacement OPEN that is observed as a real `NameState` write;
- connects a 2,048-output parent, producing an instrumented encoded undo of at
  least 64 KiB;
- connects a second replacement block that spends the parent's staged output,
  proving multi-block overlay read-your-writes;
- seeds and retrieves an unrelated accepted mempool transaction; and
- arms the fault only after at least one physical page is appended, then makes
  the archive's next real preflight charge reject (`:19068-19256`).

After rejection it proves the complete logical database image and full
payload-segment file image are byte-identical, the old chain remains active,
replacement block and transaction indexes are absent, mining state is
unchanged, the mempool entry is still retrievable, the page tail/state are
byte-identical, and storage is not fenced because rollback succeeded
(`:19258-19335`). This complements—not substitutes for—the exact arithmetic
tests at each boundary.

## Validation record

I independently reran the following on the frozen hashes using Rust 1.89.0,
`--locked`, and the default debug profile. All used
`CARGO_TARGET_DIR=<HOST_CACHE>/hsrd-production-audit-target-20260731`:

```text
cargo +1.89.0 test --locked -p hns-store --all-features --lib \
  archived_rocks_effect_budget_is_exact_and_rejects_before_any_publication \
  --no-fail-fast
1 passed; 0 failed; 75 filtered out

cargo +1.89.0 test --locked -p hns-node --lib --all-features \
  archive_budget_rejection_after_name_page_append_rolls_back_entire_reorg \
  --no-fail-fast
1 passed; 0 failed; 154 filtered out

cargo +1.89.0 test --locked -p hns-node --lib --all-features reorg_meter_ \
  --no-fail-fast
4 passed; 0 failed; 151 filtered out

cargo +1.89.0 test --locked -p hns-node --lib --all-features rollback_ \
  --no-fail-fast
2 passed; 0 failed; 153 filtered out

cargo +1.89.0 test --locked -p hns-node --lib --all-features \
  staged_effect_rejection_preserves_database_pages_indexes_mining_and_mempool \
  --no-fail-fast
1 passed; 0 failed; 154 filtered out
```

The frozen owner validation additionally records:

- `hns-store`: 76/76 all-feature library tests, 66/66 no-default tests, docs,
  strict all-target Clippy in both feature modes, Rustfmt, and diff checks.
- `hns-node`: 155/155 all-feature library tests, 147/147 no-default tests,
  strict all-target Clippy in both feature modes, Rustfmt, and diff checks.

One all-feature node-suite attempt on the same source reported 145 passes and
10 failures solely because `/tmp` could not preserve the production 10 GB
name-page filesystem reserve. No source changed. Repeating the exact suite with
a private temporary directory on `/home`, whose filesystem satisfied the
reserve, passed 155/155. The store owner likewise used a sufficiently sized
temporary filesystem for its archive/page tests. This is environmental
provenance, not a waived test or a relaxation of the production reserve.

No release-profile command was run for this audit, and no pre-existing release
artifact was used. That preserves the requested order: commit and push the
frozen source first, then build and test the release artifact from that exact
published commit.

## Independent challenges resolved before freeze

During review I required the source owners to account for representations and
failure branches that were initially missing or insufficiently demonstrated:

- archive locator accounting increased to include `PreparedArchive`, and
  manifest accounting increased to include both the retained prepared struct
  and temporary encoding;
- page-packing scratch was charged before its maps and logical clones, distinct
  from the physical page charge;
- the exact archive regression's rejected-meter assertion was corrected;
- the real reorg fixture was made to generate a genuine `NameState` write and
  a generated large undo rather than relying on hand-authored values;
- rollback failure was made self-fencing and gained an authority-revocation
  regression; and
- rollback across a prepared segment seal gained direct coverage.

The hashes above include all of those corrections.

## External evidence remains open and separate

Closing P0-1 means the exact reviewed source is eligible for commit/push and
subsequent exact-release qualification. It does **not** make the overall system
production-complete. The following evidence still has to be produced against
the exact published release source/artifact:

- sustained fuzz campaigns and the persistent performance gate;
- a fresh, empty-directory, unpruned mainnet HSRD synchronization;
- deployment custody and wallet backup/restore evidence; and
- production-scale pruning, RocksDB fault injection, sustained
  reorg/partition recovery, WAN/load latency, physical gateway/ASIC validation,
  long-duration multi-peer operation, and production mempool/template
  differential testing.

Those are release-evidence blockers, not findings that reopen the source-level
reorganization budget defect.
