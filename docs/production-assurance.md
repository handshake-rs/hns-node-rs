# Production assurance

Production approval is an evidence decision, not a source-code label. This
repository provides executable software gates and a fail-closed verifier for
evidence that must be collected on production-scale storage, real networks, and
physical mining hardware. The verifier does not manufacture or infer those
external results.

## Test tiers

The tiers are intentionally separate:

| Tier | Command | What it proves |
|---|---|---|
| Local smoke | `scripts/run-production-assurance.sh smoke --evidence-dir NEW_DIR` | The fast in-memory performance scenario (ten warm-up and 100 measured regtest blocks) and a live two-node regtest negotiation pass. A dirty tree is recorded and is acceptable only for development. |
| Scheduled software | `scripts/run-production-assurance.sh scheduled --evidence-dir NEW_DIR` | The persistent RocksDB/Sync performance scenario (4,096 setup and 100 measured regtest blocks), a live two-node pass, and every sanitizer-instrumented fuzz target for the configured per-target duration. The complete worktree must be clean. |
| External verification | `scripts/run-production-assurance.sh verify-external --evidence-dir DIR` | Seven independently collected production records have the required identity, metrics, review, and artifact hashes. It does not run the external campaigns. |
| Release | `scripts/run-production-assurance.sh release --evidence-dir DIR` | Scheduled software gates plus all external records. The complete worktree must be clean and any missing or failed evidence rejects the release. |

`NEW_DIR` must not exist. Refusing to reuse an evidence directory prevents a
new run from silently inheriting an older successful artifact. `release`
expects `DIR/external/` to exist and creates the new `DIR/software/` subtree.
Automated clean-tree and digest checks bind the start and completion
boundaries. A tracked or non-ignored difference present at either boundary
fails. A transient mutation restored between those boundaries is not
reconstructible from the retained evidence, so release collection requires
reviewed, exclusive, trusted source-tree custody for the entire run. Keep
evidence and corpora outside the repository.

The evidence verifier itself has positive, missing-record, tampered-artifact,
unrelated-binary, unrelated-configuration, blank-identity, typed-artifact
mismatch, list/count mismatch, 150,000,000,000-byte full-baseline envelope,
per-fault-point minimum, and tool-pin regressions:

```bash
scripts/run-production-assurance.sh self-test
```

The normal `scripts/check.sh` gate runs the deterministic performance binary.
Its default workload is the fast in-memory smoke. Weekly and manually
dispatched CI runs the scheduled tier with three minutes per fuzz target and
retains its machine-readable evidence for 30 days. The scheduled tier refuses
a shorter budget; the release tier requires at least 30 minutes per target.
That CI result is software qualification only; it cannot satisfy external
gates or the separately reviewed local-state custody prerequisite.

## Sustained fuzz campaigns

The qualification toolchain is exactly `nightly-2025-08-07` with
`cargo-fuzz 0.13.2`; another cargo-fuzz version fails before a target runs, and
scheduled/release orchestration rejects a different nightly name or stable
project compiler. The stable compiler is exactly Rust 1.97.1. Run all ten
targets:

```bash
scripts/run-sustained-fuzz.sh \
  --duration-seconds 1800 \
  --output-dir /new/evidence/sustained-fuzz
```

Use `--target NAME` repeatedly for triage, not release qualification. A
persistent corpus may be supplied with `--corpus-root`; otherwise the corpus is
retained inside the immutable output directory. The runner fixes the seed,
per-input timeout, RSS limit, and sanitizer configuration, retains one log and
crash directory per target, and writes `summary.json` with:

- start/end commit, Git tree, full worktree digest, and dirty state, including
  non-ignored untracked files; a change during the campaign fails the run;
- exact Rust and cargo-fuzz versions;
- every selected target, including `not_run` targets after an earlier failure;
- start/end times, exit status, configuration, log hashes, and crash hashes.

A crash, timeout, build failure, missing cargo-fuzz installation, or unexecuted
selected target makes the campaign fail. Tool-version probing is advisory and
cannot suppress the failure summary.

## Deterministic performance gates

Both software scenarios build and connect 100 measured native regtest blocks.
They fail when any exclusive P99 limit is met or exceeded:

| Metric | Exclusive P99 limit |
|---|---:|
| Tip to prepared job | 25,000 µs |
| Candidate validation | 5,000 µs |
| Local block connection | 50,000 µs |

### Fast in-memory smoke

The default scenario imports canonical HSD regtest genesis into the in-memory
backend, connects ten unmeasured warm-up blocks, and then connects the 100
measured blocks. This is the scenario used by `scripts/check.sh` and the
`smoke` assurance tier. Run it directly and retain its schema-v2 report:

```bash
cargo run --locked --release -p hns-node \
  --bin hsrd-performance-gate -- \
  --json-output /new/evidence/deterministic-performance.json
```

This fast workload is a correctness and latency regression signal. It does not
exercise RocksDB, synchronous durability, or saturated block-index-cache
occupancy.

### Persistent RocksDB/Sync software qualification

The `scheduled` and `release` tiers replace the in-memory scenario with
`persistent-rocksdb-sync`. That scenario imports canonical HSD regtest genesis,
connects exactly 4,096 unmeasured setup blocks, requires both cache capacity and
observed occupancy to be exactly 4,096, and then connects 100 measured blocks
while requiring final occupancy to remain exactly 4,096. The observed backend
must be RocksDB and durability must be `Sync`.

Run the same scenario directly with:

```bash
cargo run --locked --release -p hns-node \
  --bin hsrd-performance-gate -- \
  --scenario persistent-rocksdb-sync \
  --json-output /new/evidence/persistent-performance.json
```

The assurance script intentionally omits `--data-root`. The gate creates a
unique root, marks ownership, closes the database after measurement, verifies
the marker, and removes only that automatically created root. The scheduled
and release verifier requires the schema-v2
`automatic-create-new-scoped-cleanup` policy and rejects the evidence if the
reported root still exists. The JSON report remains in the assurance evidence
directory.

For diagnosis only, a direct invocation may add `--data-root` with a fresh,
nonexistent path. The gate creates and retains that caller-selected root and
refuses to reuse an existing path. This retained-root form is not accepted as
scheduled or release evidence because those tiers require automatic scoped
cleanup.

Each schema-v2 report records the package version; requested and observed
backend, durability, preparation counts, and cache observations; root policy;
thresholds; status; evidence checks; and count/P50/P95/P99/maximum for each
measured stage. Both scenarios are deterministic local regtest gates. Neither
is full-mainnet IBD, production pruning, RocksDB fault injection, WAN/load,
sustained reorganization/partition, physical gateway/ASIC, long-duration
multi-peer, or production mempool/template differential evidence. See
[`performance.md`](performance.md) for the implementation and complexity
model.

## Local durable-state custody prerequisite

Before any campaign can support production release, the live data root and all
external name-page and block/undo segment paths must be writable only by the
dedicated `hsrd` service identity and trusted, audited offline maintenance.
Retain a reviewed record of numeric owners/groups, modes, ACLs,
parent-directory and mount controls, every privileged writer (including
OS/root, storage, backup, and hypervisor access), and the exact maintenance
binaries and access window. The evidence directory must likewise have a
documented writer and reviewer boundary.

The release verifier authenticates supplied artifacts; it cannot reconstruct
past host access or prove that no privileged writer modified a logical
database. Clean/startup markers, RocksDB checksums, and evidence hashes are
unkeyed consistency mechanisms, not hostile-writer authentication. Shared or
unaccounted write access therefore blocks release even when every automated
gate passes. A suspected custody breach invalidates campaigns derived from that
store: withhold authority, preserve it as evidence, and rebuild through a full
trusted replay. The current node has no separately protected complete-state
commitment that can substitute for that replay.

## Full non-pruned archive qualification

Use the dedicated supervisor for a fresh native mainnet archive sync. It fixes
the production profile inside the script; do not append ad hoc node arguments
or reuse an existing data directory. Commit and push the exact candidate,
verify that the remote contains that commit and that its worktree is clean, and
only then run any release-profile command. Build the exact candidate:

```bash
cargo +1.97.1 build --locked --release -p hns-node --bin hsrd
```

Before deleting any Cargo build target to recover space, copy that exact output
to a new private artifact path outside every build target. Keep the artifact as
an executable, nonsymlink regular file; make it non-writable; record its
SHA-256; and verify the recorded digest:

```bash
umask 077
install -d -m 0700 /ABS/private/hsrd-candidate
artifact=/ABS/private/hsrd-candidate/hsrd-0.3.1-COMMIT
[[ ! -e "$artifact" && ! -L "$artifact" ]]
install -m 0500 -- target/release/hsrd "$artifact"
cmp --silent -- target/release/hsrd "$artifact"
sha256sum -- "$artifact" >"$artifact.sha256"
sha256sum --check --strict "$artifact.sha256"
```

Only after that verification may the build target be removed. Treat the
artifact path, contents, inode, ownership, mode, and link count as immutable
for the entire campaign, including every `resume`: do not delete, move,
replace, relink, `chmod`, or `chown` it. The supervisor repeatedly validates
the configured path, file identity, and digest and terminates on a mismatch.

Prepare an authorization file containing exactly one private HTTP
`Authorization` value, set its mode to `0600`, and choose absolute, fresh,
empty data and evidence directories. The filesystem containing the data root
must have at least the 150,000,000,000-byte operational limit plus the separate
10,000,000,000-byte reserve available before launch.

```bash
scripts/run-full-sync-qualification.sh run \
  --binary /ABS/private/hsrd-candidate/hsrd-0.3.1-COMMIT \
  --data-root /ABS/fresh-mainnet-archive \
  --evidence-dir /ABS/full-sync-evidence \
  --auth-file /ABS/private/rpc-authorization-header \
  --limit-bytes 150000000000 \
  --filesystem-reserve-bytes 10000000000 \
  --sample-seconds 60 \
  --completion-samples 5 \
  --maximum-samples 250000 \
  --shutdown-grace-seconds 120 \
  --rpc-port 12037
```

Operate the same immutable campaign only through its evidence directory:

```bash
scripts/run-full-sync-qualification.sh status \
  --evidence-dir /ABS/full-sync-evidence
scripts/run-full-sync-qualification.sh resume \
  --evidence-dir /ABS/full-sync-evidence
scripts/run-full-sync-qualification.sh stop \
  --evidence-dir /ABS/full-sync-evidence
```

`resume` first rejects live or mismatched runner, child, or log-scanner
processes, changed executable identity, prior terminal integrity failures, and
ambiguous evidence journals. An abrupt host loss may be resumed only after the
supervisor has reconciled the durable authorization-scanned log journal; never
delete, rename, or hand-edit a partial log, counter, state file, or attempt
summary. `stop` requests a bounded graceful shutdown and does not turn an
incomplete attempt into a pass.

Qualification requires five consecutive synchronized samples followed by a
graceful zero-status child exit. The retained bundle includes exact campaign
configuration, source/build and host provenance, per-attempt summaries,
periodic disk/RSS/tip samples, bounded authorization-scanned logs, a log
manifest, and the final verdict. The supervisor repeatedly binds the running
`/proc` executable image to the selected file. Authorization material is never
placed in process arguments; mutation or disclosure is terminal.

The values have intentionally different meanings:

- 150,000,000,000 bytes is the sampled operational stop;
- 10,000,000,000 bytes is the separately sampled free-filesystem reserve;
- 90,000,000,000 bytes may be reported as an informational at-or-below
  comparison only. It is not a stop, qualification criterion, release gate, or
  assumed footprint.

Directory sampling can miss a transient allocation and is not a filesystem
quota or an exact high-water meter. Consequently this bundle cannot by itself
populate the external pruning record's exact `peak_disk_bytes`. The
production-scale pruning campaign must add independently reviewed peak
accounting, prove both peak and final values are at most the
150,000,000,000-byte envelope, and retain inventories, the pruned comparison,
the rollback exercise, and its other required metrics. A dirty-source run is
diagnostic only; release evidence must bind the clean candidate commit/tree,
exact executable, and build manifest.

The supervisor never deletes HSD data. Do not remove an HSD chain to make room
during qualification. A later removal remains a separate destructive change
requiring an exact target, explicit approval, a tested HSD wallet
backup-and-restore, retained comparison evidence, and a rollback plan. A wallet
file copy alone is not proof of recoverability.

## External evidence layout

The release evidence root must contain exactly these logical records. Additional
raw artifacts are allowed.

```text
DIR/
├── external/
│   ├── production-scale-pruning.json
│   ├── rocksdb-fault-injection.json
│   ├── sustained-reorg-partition.json
│   ├── wan-load-latency.json
│   ├── physical-gateway-asic.json
│   ├── long-duration-multi-peer.json
│   ├── mempool-template-differential.json
│   └── raw/
│       ├── hsrd                         # exact executable used by every gate
│       ├── hsrd-build-manifest.json     # typed, source-bound build manifest
│       ├── GATE-campaign-configuration.json
│       │                                # typed, source-bound exact inputs
│       └── ... logs, packet captures, inventories, and reports ...
├── software/                         # created by the release command
└── release-summary.json              # written only after every gate passes
```

Each external JSON record uses schema version 2:

```json
{
  "schema_version": 2,
  "gate": "sustained_reorg_partition",
  "status": "pass",
  "source_revision": "40-lowercase-hex-git-commit",
  "source_tree": "40-lowercase-hex-git-tree",
  "started_at": "2026-07-29T00:00:00Z",
  "completed_at": "2026-07-29T06:30:00Z",
  "operator": "operator identity",
  "reviewer": "independent reviewer identity",
  "tool": {
    "name": "campaign harness",
    "version": "immutable version or digest"
  },
  "configuration": {
    "network": "mainnet",
    "binary_sha256": "64-lowercase-hex-digest",
    "binary_manifest_path": "external/raw/hsrd-build-manifest.json",
    "campaign_config_path": "external/raw/reorg-campaign-configuration.json",
    "campaign_config_sha256": "64-lowercase-hex-digest",
    "topology_id": "reviewed topology identifier",
    "state_oracle_revision": "immutable oracle revision",
    "peer_ids": ["peer-a", "peer-b", "peer-c"],
    "partition_cycle_ids": ["partition-a", "partition-b", "partition-c"],
    "partition_schedule_sha256": "64-lowercase-hex-digest",
    "competing_chain_manifest_sha256": "64-lowercase-hex-digest"
  },
  "metrics": {
    "duration_seconds": 23400,
    "peer_count": 3,
    "partition_cycles": 3
  },
  "artifacts": [
    {
      "path": "external/raw/reorg-partition.log",
      "sha256": "64-lowercase-hex-digest"
    },
    {
      "type": "hsrd_binary",
      "path": "external/raw/hsrd",
      "sha256": "64-lowercase-hex-digest"
    },
    {
      "type": "hsrd_build_manifest",
      "path": "external/raw/hsrd-build-manifest.json",
      "sha256": "64-lowercase-hex-digest"
    },
    {
      "type": "hsrd_campaign_configuration",
      "path": "external/raw/reorg-campaign-configuration.json",
      "sha256": "64-lowercase-hex-digest"
    },
    {
      "type": "partition_schedule",
      "path": "external/raw/partition-schedule.json",
      "sha256": "64-lowercase-hex-digest"
    },
    {
      "type": "competing_chain_manifest",
      "path": "external/raw/competing-chain-manifest.json",
      "sha256": "64-lowercase-hex-digest"
    }
  ]
}
```

Every path is relative to `DIR`, must remain inside it, and must identify a
regular file whose SHA-256 matches. Required artifacts have the exact `type`
listed below; relabeling a digest in `configuration` does not satisfy the
corresponding typed artifact check. Operator and reviewer must be distinct. The
commit and tree must match the release checkout. `tool`, `configuration`, and
`metrics` must be nonempty. Hashing is streamed in bounded 1 MiB chunks so
large traces are not materialized in memory; raw commands, environment
inventory, topology, limits, and fault schedule belong in the retained
artifacts.

## Shared executable and configuration identity

Every external record, not only the pruning record, must set
`configuration.network` to `mainnet` and list exactly one verified artifact of
each of these types:

- `hsrd_binary`: the exact executable exercised by the campaign;
- `hsrd_build_manifest`: the source-bound manifest for that executable;
- `hsrd_campaign_configuration`: the exact gate inputs, including every
  gate-specific identity and artifact digest.

`configuration.binary_sha256` must equal the streamed digest of the
`hsrd_binary`. `configuration.binary_manifest_path` must identify the typed
build manifest. All seven records must identify the same binary path/digest and
the same build-manifest path/digest. A single artifact path cannot be listed
twice under different types. The build command, stable toolchain, and reported
Rust/Cargo versions are pinned to 1.97.1. The manifest is schema version 1:

```json
{
  "schema_version": 1,
  "artifact_type": "hsrd_build_manifest",
  "source_revision": "40-lowercase-hex-git-commit",
  "source_tree": "40-lowercase-hex-git-tree",
  "build": {
    "command": "cargo +1.97.1 build --locked --release -p hns-node --bin hsrd",
    "rust_toolchain": "1.97.1",
    "rustc_version": "complete rustc --version output",
    "cargo_version": "complete cargo --version output"
  },
  "binary": {
    "type": "hsrd_binary",
    "name": "hsrd",
    "path": "external/raw/hsrd",
    "sha256": "64-lowercase-hex-digest"
  }
}
```

The manifest revision and tree must match the release checkout and external
record. Its binary path and digest must match the verified typed binary.

The campaign configuration is also schema version 1:

```json
{
  "schema_version": 1,
  "artifact_type": "hsrd_campaign_configuration",
  "gate": "sustained_reorg_partition",
  "source_revision": "40-lowercase-hex-git-commit",
  "source_tree": "40-lowercase-hex-git-tree",
  "configuration": {
    "network": "mainnet",
    "binary_sha256": "64-lowercase-hex-digest",
    "binary_manifest_path": "external/raw/hsrd-build-manifest.json",
    "topology_id": "reviewed topology identifier",
    "state_oracle_revision": "immutable oracle revision",
    "peer_ids": ["peer-a", "peer-b", "peer-c"],
    "partition_cycle_ids": ["partition-a", "partition-b", "partition-c"],
    "partition_schedule_sha256": "64-lowercase-hex-digest",
    "competing_chain_manifest_sha256": "64-lowercase-hex-digest"
  }
}
```

Its `configuration` object is byte-value independent JSON data and must equal
the record configuration after removing only `campaign_config_path` and
`campaign_config_sha256`. The record path must identify the typed campaign
artifact, and its configured digest must equal the artifact's streamed digest.
This deliberately has no self-referential digest inside the campaign file.
Changing a network, peer list, device, schedule, oracle, or other input after
collection therefore invalidates the evidence instead of merely changing an
unverified label.

## Minimum acceptance criteria

These are release minimums enforced by
`scripts/run-production-assurance.sh verify-external`. A team may impose
stricter limits without changing the verifier. Lowering a minimum requires a
reviewed source change; a record cannot choose its own threshold.

### Production-scale pruning

`gate` is `production_scale_pruning`. Configuration fixes
`baseline_mode: "full_non_pruned"`, `pruned_mode: "prune_history"`, and
`rollback_horizon_blocks: 288`; the reported rollback horizon must equal that
configuration. It also binds nonempty host, filesystem, and byte-accounting
scope identities plus these typed artifact digests:

- `dataset_manifest_sha256` → `dataset_manifest`;
- `baseline_config_sha256` → `baseline_configuration`;
- `pruned_config_sha256` → `pruned_configuration`.

Minimum metrics are 300,000 block records, 20,000,000 UTXOs, 10,000,000 name
records, and at least one reclaimed byte. Pre/post inventory validation, exact
restart-tip agreement, and fallback restore verification must all be true.

The full non-pruned baseline must report positive `peak_disk_bytes` and
`final_disk_bytes`, each no greater than exactly 150,000,000,000 bytes, with
the peak covering the final measurement. The launch supervisor separately
enforces a 10,000,000,000-byte free-filesystem reserve. A 90,000,000,000-byte
comparison may be retained only as informational, non-gating telemetry. The
same campaign reports a positive `pruned_final_disk_bytes` strictly below the
non-pruned final value. Configuration binds a production-scale dataset height.
The separate hashed baseline and pruned configurations make
`comparison_scope_identical: true` reviewable rather than the only description
of the compared modes. The record must also contain a positive duration and
peak RSS,
`resource_limits_respected: true`, zero RocksDB background errors, and
`hsd_blocks_deleted: false`. Reviewed hard RSS/runtime limits remain in the
deployment configuration and raw artifacts because one universal hardware
ceiling would be misleading.

Collect the offline backup, inventory, compaction, restart, rollback, and state
manifest outputs described in
[`storage-rollout.md`](storage-rollout.md). Hash both inventories, state
manifests, service logs, and fallback verification. A synthetic small database
cannot satisfy this gate.

This harness never deletes HSD block data. Any later HSD-data removal is a
separate destructive operation and requires, before approval: an independently
verified complete hsrd chain; a tested wallet backup and restore; a documented
rollback and retention plan that preserves required comparison evidence; and
explicit operator authorization for the exact deletion target. None of those
conditions authorizes deletion during this assurance run.

### RocksDB fault injection

`gate` is `rocksdb_fault_injection`. Exercise at least eight distinct durable
publication/commit/reopen injection points with at least 100 seeded iterations
at every point. The record must therefore report `injection_points >= 8`,
`iterations_per_point >= 100`, and
`iterations >= injection_points * iterations_per_point` (at least 800 at the
minimum). Required zero counts are reopen failures, tip mismatches, root
mismatches, and unexpected authority grants.

Configuration fixes `storage_backend: "rocksdb"`, names the host and
filesystem, and lists at least eight distinct `injection_point_ids`; the list
length must equal the reported injection-point count. It binds
`dataset_manifest_sha256`, `fault_schedule_sha256`, and
`seed_manifest_sha256` to exactly one typed `dataset_manifest`,
`fault_schedule`, and `seed_manifest` artifact respectively.

Retain the fault schedule, exact injected process/write failures, every reopen
result, state/root comparisons, and authority diagnostics. Unit fault tests
establish harness behavior but do not replace the process-level campaign.

### Reorganization and partition

`gate` is `sustained_reorg_partition`. Run for at least six hours with at least
three peers, three partition/heal cycles, and one real greater-work
reorganization. State-parity mismatches and unexpected authority grants must be
zero.

Configuration requires a nonempty `topology_id` and
`state_oracle_revision`, distinct nonempty `peer_ids` and
`partition_cycle_ids` whose lengths equal the corresponding metrics, and
digest bindings from `partition_schedule_sha256` to a typed
`partition_schedule` artifact and from `competing_chain_manifest_sha256` to a
typed `competing_chain_manifest` artifact.

Retain topology, packet-control commands, competing-chain identities, before
and after state manifests, disconnect/reconnect transcripts, and restart logs.

### WAN and load latency

`gate` is `wan_load_latency`. Run for at least one hour across at least two
sites and 1,000 samples. Job-delivery P99 must be at most 250 ms and
candidate-to-first-peer P99 at most 500 ms. Failed and unavailable samples must
both be zero.

Configuration requires a nonempty `topology_id` and `clock_sync_profile`, plus
at least two distinct nonempty `site_ids`; their length must equal
`metrics.site_count`. `load_profile_sha256` and `network_profile_sha256` must
match exactly one typed `load_profile` and `network_profile` artifact.

Retain all distributions, not only means; clock synchronization evidence;
network shaping or provider/site descriptions; node load; peer backlogs; and
raw timestamped samples.

### Physical gateway and ASIC

`gate` is `physical_gateway_asic`. Run a physical device for at least four
hours, observe at least 1,000 jobs, one valid share, one valid block candidate,
and three fallback/recovery cycles. Job-switch P99 must be at most 250 ms;
invalid jobs and unreconciled receipts must be zero.

Configuration fixes `device_kind: "physical_asic"` and requires nonempty
`device_id`, `device_model`, `firmware_version`, and `gateway_version`.
Distinct `fallback_cycle_ids` must match the reported recovery-cycle count.
`gateway_binary_sha256` and `fallback_plan_sha256` bind exactly one typed
`gateway_binary` and `fallback_plan` artifact. A device label without those
bindings is not physical-hardware evidence.

Retain hashed device/gateway identities, firmware and gateway versions, job and
share transcripts, capture receipts, fallback timelines, and telemetry. An
emulator or software miner cannot satisfy this record.

### Long-duration multi-peer operation

`gate` is `long_duration_multi_peer`. Run at least 24 hours with at least eight
peers and three controlled restarts. Tip divergences, database recovery
failures, and unexpected authority grants must be zero.

Configuration requires a nonempty `topology_id`, at least eight distinct
nonempty `peer_ids`, and at least three distinct `restart_ids`; both list
lengths must equal their reported counts. `peer_set_sha256`,
`restart_schedule_sha256`, and `authority_policy_sha256` bind exactly one typed
`peer_set_manifest`, `restart_schedule`, and `authority_policy` artifact.

Retain peer diversity/topology, periodic state snapshots, backlog/resource
series, restart checkpoints, shutdown classification, and final state parity.

### Mempool/template/publication differential

`gate` is `mempool_template_differential`. Configuration requires nonblank
`oracle_name`, immutable `oracle_revision`, and `normalization_revision`.
`oracle_binary_sha256`, `corpus_manifest_sha256`, and
`mempool_policy_sha256` must match exactly one typed `oracle_binary`,
`corpus_manifest`, and `mempool_policy` artifact. An empty revision or a
free-form oracle label without an actual binary digest is rejected. Exercise
at least 10,000 transaction decisions, 1,000 template comparisons, and 100
reorganization-reconciliation cases. Mempool, template, and publication
mismatches must be zero.

Retain normalized inputs and decisions, complete template commitments and
ordering, mempool generations, publication-intent/receipt state, and the
oracle command/version. Fixture-only or noncontextual parser parity is not this
production gate.

## Release decision

The `release` command is deliberately conjunctive: persistent RocksDB/Sync
deterministic performance, two-node negotiation, all sustained fuzz targets,
all seven external records, exact commit/tree identity, artifact integrity, and
every minimum must pass.
Only then does it write `release-summary.json`, which hashes every software and
external evidence file in the completed bundle.
“Harness available”, “campaign started”, an omitted sample, or an unavailable
oracle is not a pass. Until a release evidence bundle satisfies that command,
these areas remain production-hardening work and mainnet operation remains a
supervised canary.

Passing smoke or scheduled software assurance leaves all seven external gates
open. Those gates close only through their separately collected and verified
records. Local durable-state custody is an additional prerequisite: the script
cannot reconstruct historical writer access, so a missing or unreviewed custody
record still blocks operator approval even if the automated records pass.
