# Storage rollout, migration, and fallback

This procedure is deliberately offline. It preserves one known-good data root
before changing schema/profile markers or replacing inline block and undo
values. Never run the maintenance command against a node that did not complete
its clean shutdown.

## Safety invariants

- The data root, its parent, external name-page and block/undo segment paths,
  and fallback copies are controlled by documented service/maintenance
  principals. Only the dedicated `hsrd` identity and trusted, audited offline
  maintenance may write the live store; shared or unaccounted write access
  blocks production release.
- The exact marker `.hsrd-storage-maintenance` with body
  `hsrd-storage-maintenance-v1\n` is required by the maintenance command.
- The normal node refuses to start while that marker exists.
- RocksDB's process lock and the durable clean-shutdown byte must both agree
  that the node is offline.
- A fallback backup publishes `.hsrd-storage-fallback.json` last. Its absence
  means the backup is incomplete and must not be used.
- The RocksDB portion is a native consistent checkpoint. External name-page
  and block/undo segment files are independent byte copies, not links to a file
  that the new node may later append.
- Migration commits segment bytes and `fsync`s them before atomically replacing
  an inline RocksDB value with a locator. Restart discards every unpublished
  complete or torn tail.
- A database write error after external bytes are synced is treated as
  potentially committed. The current process retains both generations and
  fences every clone of the archived/RocksDB store; new snapshots, all commits
  (including metadata-only batches), checkpoints, and maintenance reject.
  Recovery requires closing and reopening RocksDB, not merely constructing a
  new archive wrapper. Reopen selects old or new files from the atomic
  manifests before cleanup.
- If the replacement locator/manifest batch commits successfully but archive
  installation or predecessor cleanup then fails, the caller reports
  committed-but-install-incomplete and the archive is likewise reopen-required.
  A pre-cleanup failure retains both generations; a later cleanup failure may
  have removed predecessor files, but the committed new generation remains
  authoritative and reopen completes recovery.
- Compaction creates no rewrite generation until a read-only plan has passed
  record, live-frame-byte, atomic-locator-byte, cursor-record, and cursor-byte
  budgets.
- No maintenance command deletes the source data root or a fallback backup.

Before production cutover, retain the numeric owner/group, modes, ACLs,
parent-directory and mount controls, privileged writers, and exact maintenance
binary identity with the release evidence. The checksummed maintenance marker,
clean marker, startup audit, RocksDB checksums, and state manifest are unkeyed
consistency evidence, not authentication against an offline writer. Suspected
loss of custody invalidates the rollout evidence: preserve the store, withhold
authority, and rebuild through a full trusted replay (or a future qualified,
separately protected complete-state commitment).

## 1. Build and identify the rollout binary

From a clean, reviewed source revision:

```sh
cargo build --locked --release --manifest-path Cargo.toml \
  -p hns-node --bin hsrd --bin hsrd-storage-maintenance \
  --bin hsrd-state-manifest
sha256sum target/release/hsrd \
  target/release/hsrd-storage-maintenance \
  target/release/hsrd-state-manifest
git rev-parse HEAD
rustc --version --verbose
```

Record the revision, compiler output, and three hashes with the deployment.
Do not substitute an untracked build between backup, rollout, and audit.

## 2. Stop cleanly and create the pre-rollout fallback

Let `DATA` be the hsrd data root, not its `chain/` child. Let `BACKUP` be a new
absolute path outside `DATA`.

```sh
systemctl --user stop meshmine-hsrd-mainnet-canary.service
printf 'hsrd-storage-maintenance-v1\n' > "$DATA/.hsrd-storage-maintenance"

target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" \
  backup --backup-dir "$BACKUP"
```

`backup` accepts the reviewed schema/profile sources 16/`hsrd-mining-v12`,
17/`hsrd-mining-v13`, 18/`hsrd-mining-v14`, and 19/`hsrd-mining-v15`. It
requires a clean-shutdown marker, creates `BACKUP/chain` with RocksDB's
checkpoint API, copies any `name-pages/` and `payload-segments/`, installs the
offline state-audit marker inside the checkpoint, syncs every copied file and
directory, and writes the checksummed fallback manifest last.

Confirm that `BACKUP/.hsrd-storage-fallback.json` exists. Keep the maintenance
marker in place until the backup and any desired state-manifest comparison have
finished. Remove it only immediately before starting the node:

```sh
rm "$DATA/.hsrd-storage-maintenance"
systemctl --user start meshmine-hsrd-mainnet-canary.service
```

On first current-binary open, schemas 17 and 18 receive an atomic profile
cutover. Schema 16 runs the resumable, backup-first interval-accumulator
migration. Existing schema-18 pages remain readable; all new name pages use
authenticated subpages. The node bootstraps missing name pages and block/undo
manifests. Ambiguous marker combinations fail closed.

## 3. Audit the current layout

After the upgraded node completes a clean shutdown, recreate the marker and
run:

```sh
target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" inventory
```

The command first performs the normal bounded recovery and then explicitly
scrubs the checksum and complete-frame boundary of every committed block and
undo segment. It validates both manifests, removes only unpublished future
segments, and truncates only bytes beyond the authoritative active tails. The
JSON separates legacy inline records/bytes from archived records/frame bytes
and locator bytes and reports the scrubbed segment/record/byte totals.

## 4. Plan and run payload-segment compaction

Compaction is optional and useful only after logical pruning leaves enough dead
frames. Always retain the fallback and run the read-only command first:

```sh
target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" \
  compact --dry-run \
  --max-live-records 1000000 \
  --max-live-frame-bytes 68719476736 \
  --max-atomic-locator-bytes 134217728 \
  --scan-page-records 1024 \
  --scan-page-bytes 8388608 \
  --min-reclaim-bytes 268435456 \
  > hsrd-compaction-plan.json
```

Opening the archive first performs normal manifest-driven recovery: it may
truncate bytes beyond an authoritative active tail or remove a generation that
no manifest selects. After that recovery, `--dry-run` performs no compaction
publication and creates no rewrite generation; it does perform the exhaustive
committed-frame scrub. It must report:

- `mutation_performed: false`;
- `committed_frames_validated: true`;
- `reclaim_threshold_met: true` before a production rewrite;
- live records, live frame bytes, and estimated atomic locator bytes below the
  supplied host-specific limits; and
- enough free disk for `plan.live_frame_bytes`, RocksDB WAL/SST amplification,
  the ordinary operating reserve, and the untouched fallback. The command does
  not guess a filesystem reserve.

Use the exact reviewed limits from the retained plan for mutation:

```sh
target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" \
  compact \
  --max-live-records 1000000 \
  --max-live-frame-bytes 68719476736 \
  --max-atomic-locator-bytes 134217728 \
  --scan-page-records 1024 \
  --scan-page-bytes 8388608 \
  --min-reclaim-bytes 268435456 \
  > hsrd-compaction-result.json

target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" inventory \
  > hsrd-post-compaction-inventory.json
```

The mutation repeats the plan after acquiring the database, uses one immutable
snapshot, and refuses to proceed if the observed live record/frame totals
change. Iterator working memory is bounded by the cursor page, but all new
locators and both manifests are deliberately published in one atomic RocksDB
batch. The final batch therefore remains proportional to live records and is
bounded by `--max-live-records` plus `--max-atomic-locator-bytes`.

Acceptance requires all of the following:

1. Pre- and post-scrubs report no checksum or frame-boundary error.
2. `after_frame_bytes <= before_frame_bytes`, and `reclaimed_frame_bytes`
   equals their difference.
3. `live_records` equals the sum of post-inventory archived block and undo
   records; every retained-horizon disconnect/reconnect test still passes.
4. A clean reopen followed by `inventory` selects only the reported generation
   and reproduces the exact tip, roots, pruning checkpoints, and state
   manifest.
5. On a disposable copy, deterministic before-write and after-write regression
   tests pass:

   ```sh
   cargo test --locked -p hns-store \
     rocks_segment_publication_faults_recover_the_complete_old_or_new_batch
   cargo test --locked -p hns-store \
     compaction_post_write_error_reopens_the_new_generation_without_data_loss
   ```

6. The external fault campaign kills the process at segment-sync,
   before/within/after RocksDB write, manifest-install, and predecessor-cleanup
   boundaries. Run at least 100 seeded trials per boundary on the deployment
   filesystem. Every reopen must select a complete old or new generation, pass
   the full scrub and state manifest, and preserve all rollback-window blocks.
   Retained metrics must report `injection_points >= 8`,
   `iterations_per_point >= 100`, and
   `iterations >= injection_points * iterations_per_point`.
7. Production-scale pruning is measured on mainnet-scale state, not a reduced
   fixture: at least 300,000 block records, 20,000,000 UTXOs, 10,000,000 name
   records, and the complete 288-block rollback horizon. Retain
   `duration_seconds > 0`, `peak_rss_bytes > 0`, `peak_disk_bytes > 0`,
   `resource_limits_respected: true`, and `rocksdb_background_errors: 0`
   alongside the reviewed host RSS/disk/runtime envelope. Pre/post inventory,
   restart-tip agreement, fallback restore, and at least one reclaimed byte
   must also pass.
8. The same production-scale evidence includes a complete non-pruned hsrd
   baseline, identified by `baseline_mode: full_non_pruned`. Measure all
   hsrd-owned live and temporary files on the qualification volume, including
   RocksDB WAL/SST files, block/undo segments, name pages, and transient
   rewrite/compaction files. The launch supervisor stops at a sampled
   150,000,000,000-byte data-root cutoff and independently requires
   10,000,000,000 free filesystem bytes. The retained exact
   `peak_disk_bytes` and `final_disk_bytes` must each be at most
   `150000000000`. An at-or-below `90000000000` observation may be retained as
   informational telemetry only and must not affect qualification or release.
   Run the pruned comparison at the same pinned height with the same binary,
   host, filesystem, and measurement scope; retain
   `pruned_final_disk_bytes > 0` and
   `pruned_final_disk_bytes < final_disk_bytes`. The evidence must also record
   `hsd_blocks_deleted: false`: neither qualification run authorizes removal of
   the HSD data used for parity and rollback.

The deterministic tests establish control-flow invariants. They do not replace
external process-kill, filesystem, controller-cache, or power-loss evidence.
If the command reports an uncertain database outcome or a committed but
incomplete archive installation, do not retry in the same process. For an
uncertain database write, do not reuse any clone of that RocksDB handle.
Preserve every remaining generation and the logs, fully close the database,
then reopen it with the same binary; recovery will use the database manifests
before deleting anything.

## 5. Optional inline-payload conversion

Legacy inline values are semantically valid and may remain indefinitely. They
do not block mining or new append-only writes. Convert them only when the disk
preflight is safe:

1. Read `blocks.inline_bytes + undo.inline_bytes` from `inventory`.
2. Keep the fallback backup intact.
3. Ensure free space covers those inline bytes, segment framing, RocksDB
   compaction headroom, and the normal operational reserve.
4. If that bound does not fit, continue in mixed mode or migrate a copied data
   root. Do not trade away the fallback to make the conversion fit.

Run bounded, restart-idempotent conversion:

```sh
target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" \
  migrate-inline --batch-records 32

target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" inventory
```

The final inventory must report zero inline block and undo records. Old payload
bytes can remain in obsolete RocksDB SST files until normal or explicit
compaction retires them; their temporary presence is expected. The command may
be rerun after interruption and will skip every already published locator. It
walks each hash prefix with record- and byte-bounded exclusive cursor pages,
performs the exhaustive scrub before its first write, and checksums/syncs newly
appended frames through the same publication path used during normal block
commit.

Remove the maintenance marker before restart. A startup with the marker still
present is intentionally rejected.

## 6. Semantic verification

The backup checkpoint already contains the exact
`.hsrd-state-audit-copy` marker required by `hsrd-state-manifest`:

```sh
target/release/hsrd-state-manifest \
  --data-dir "$BACKUP/chain" > hsrd-pre-rollout-state.json
```

At a pinned block hash, compare this with the HSD manifest as described in
[`state-parity.md`](state-parity.md). Repeat the manifest after rollout and
retain both outputs. A state manifest does not replace the retained-horizon
disconnect/reconnect campaign.

HSD block-data retirement is a separate destructive cutover, not part of this
maintenance procedure or the production-assurance campaign. Keep the HSD data
unchanged until all of the following are independently complete:

1. hsrd has reproduced the pinned tip, consensus roots, state manifest, and
   retained-horizon disconnect/reconnect results, then completed the approved
   sustained multi-peer qualification;
2. the HSD wallet backup has been restored into an isolated test environment
   and its expected accounts, names, and spend authority have been verified;
3. an operator-reviewed rollback and evidence-retention plan identifies what
   HSD data remains recoverable, where the verified wallet backup is retained,
   and how hsrd can be rolled back without depending on the candidate deletion;
   and
4. the named cutover authority explicitly approves the exact HSD block-data
   paths and retention date.

Until that approval exists, `hsd_blocks_deleted` remains `false`. No hsrd
storage command deletes HSD data, and an informational at-or-below-90 GB hsrd
observation does not imply permission to do so.

## 7. Fallback

Never start a node directly on the only fallback copy. Preserve it as the
reference artifact.

1. Stop the upgraded node. Leave its data root intact.
2. Move that root to a uniquely named failed-rollout path on the same
   filesystem; do not overwrite or delete it.
3. Reflink or copy the complete fallback root to a new replacement path.
4. Verify the copied fallback manifest and run `hsrd-state-manifest` against
   its `chain/` directory.
5. Point the service at the replacement path.
6. Use the binary matching the backed-up schema/profile. A schema-16/17 backup
   is the rollback input for its pinned prior binary, schema 18 uses the
   schema-18 storage-aware binary, and schema 19 requires the current
   authenticated-subpage binary.
7. Start without a maintenance marker and confirm the exact tip hash, height,
   roots, deployment diagnostics, and mining generation before restoring
   authority.

Keeping both the failed-rollout root and pristine fallback makes the operation
reversible and preserves evidence for diagnosis. Nothing in this procedure
changes chain-selection or consensus semantics.
