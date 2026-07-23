# Storage rollout, migration, and fallback

This procedure is deliberately offline. It preserves one known-good data root
before changing schema/profile markers or replacing inline block and undo
values. Never run the maintenance command against a node that did not complete
its clean shutdown.

## Safety invariants

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
- No maintenance command deletes the source data root or a fallback backup.

## 1. Build and identify the rollout binary

From a clean, reviewed source revision:

```sh
cargo build --locked --release --manifest-path hsrd/Cargo.toml \
  -p hns-node --bin hsrd --bin hsrd-storage-maintenance \
  --bin hsrd-state-manifest
sha256sum hsrd/target/release/hsrd \
  hsrd/target/release/hsrd-storage-maintenance \
  hsrd/target/release/hsrd-state-manifest
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

hsrd/target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" \
  backup --backup-dir "$BACKUP"
```

`backup` accepts the reviewed schema/profile sources 16/`hsrd-mining-v12`,
17/`hsrd-mining-v13`, and 18/`hsrd-mining-v14`. It requires a clean-shutdown
marker, creates `BACKUP/chain` with RocksDB's checkpoint API, copies any
`name-pages/` and `payload-segments/`, installs the offline state-audit marker
inside the checkpoint, syncs every copied file and directory, and writes the
checksummed fallback manifest last.

Confirm that `BACKUP/.hsrd-storage-fallback.json` exists. Keep the maintenance
marker in place until the backup and any desired state-manifest comparison have
finished. Remove it only immediately before starting the node:

```sh
rm "$DATA/.hsrd-storage-maintenance"
systemctl --user start meshmine-hsrd-mainnet-canary.service
```

On first current-binary open, schema 17 receives an atomic profile cutover.
Schema 16 runs the resumable, backup-first interval-accumulator migration.
The node then bootstraps authenticated name pages and block/undo manifests.
Ambiguous marker combinations fail closed.

## 3. Audit the current layout

After the upgraded node completes a clean shutdown, recreate the marker and
run:

```sh
hsrd/target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" inventory
```

The command first performs the normal bounded recovery and then explicitly
scrubs the checksum and complete-frame boundary of every committed block and
undo segment. It validates both manifests, removes only unpublished future
segments, and truncates only bytes beyond the authoritative active tails. The
JSON separates legacy inline records/bytes from archived records/frame bytes
and locator bytes and reports the scrubbed segment/record/byte totals.

## 4. Optional inline-payload conversion

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
hsrd/target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" \
  migrate-inline --batch-records 32

hsrd/target/release/hsrd-storage-maintenance \
  --data-dir "$DATA" inventory
```

The final inventory must report zero inline block and undo records. Old payload
bytes can remain in obsolete RocksDB SST files until normal or explicit
compaction retires them; their temporary presence is expected. The command may
be rerun after interruption and will skip every already published locator. It
performs the exhaustive scrub before its first write; newly appended frames are
checksummed and synced by the same publication path used during normal block
commit.

Remove the maintenance marker before restart. A startup with the marker still
present is intentionally rejected.

## 5. Semantic verification

The backup checkpoint already contains the exact
`.hsrd-state-audit-copy` marker required by `hsrd-state-manifest`:

```sh
hsrd/target/release/hsrd-state-manifest \
  --data-dir "$BACKUP/chain" > hsrd-pre-rollout-state.json
```

At a pinned block hash, compare this with the HSD manifest as described in
[`state-parity.md`](state-parity.md). Repeat the manifest after rollout and
retain both outputs. A state manifest does not replace the retained-horizon
disconnect/reconnect campaign.

## 6. Fallback

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
   is the rollback input for the pinned prior binary; schema 18 requires the
   current storage-aware binary.
7. Start without a maintenance marker and confirm the exact tip hash, height,
   roots, deployment diagnostics, and mining generation before restoring
   authority.

Keeping both the failed-rollout root and pristine fallback makes the operation
reversible and preserves evidence for diagnosis. Nothing in this procedure
changes chain-selection or consensus semantics.
