# Legacy interval-accumulator recovery

This runbook is only for a mainnet data root written by an older 0.3.5
candidate that exits during startup with:

```text
name-tree accumulator names disagree with canonical undo
```

Those candidates could include valid no-op `BID` or `REDEEM` touches in raw
undo while omitting them from the pending interval accumulator. Current `main`
can repair only that exact legacy form: the stored counts must be a strict
subset of the canonical undo counts, every pending undo and root binding must
validate, and rewinding the current `NameState` view must reproduce the
committed interval-boundary root. The only write is an atomic replacement of
the accumulator key, followed by an exact readback and the normal strict
audit.

This is a narrowly bounded compatibility recovery. It does not qualify the
candidate as a release, qualify wallet indexes, or repair any other mismatch.
Do not use it when the failure text or data provenance differs.

## Build an exact, nonpublishing candidate

The manual **hsrd arm64 recovery candidate** workflow builds the exact current,
reviewed `linux/arm64` commit on canonical `main`. It rejects a short commit
ID, a checkout/`HEAD` mismatch, an older or non-main source, a source before
the guarded repair, a workflow definition that is not current `main`, or a
dispatch outside the canonical repository's `main` branch. If `main` advances
between review and execution, review the new head and dispatch again rather
than building the older commit.

Set `EXPECTED_COMMIT` to the full reviewed commit. Record the workflow run ID
before downloading anything:

```sh
EXPECTED_COMMIT=FULL_40_CHARACTER_COMMIT

gh workflow run hsrd-recovery-candidate.yml \
  --repo handshake-rs/hns-node-rs \
  --ref main \
  --field expected_commit="$EXPECTED_COMMIT"

gh run list \
  --repo handshake-rs/hns-node-rs \
  --workflow hsrd-recovery-candidate.yml \
  --event workflow_dispatch \
  --limit 5
```

Wait for the selected run to finish successfully. Do not substitute a later
run merely because its artifact has a similar name:

```sh
RUN_ID=RECORDED_RUN_ID
gh run watch "$RUN_ID" --repo handshake-rs/hns-node-rs --exit-status
gh run view "$RUN_ID" \
  --repo handshake-rs/hns-node-rs \
  --json databaseId,event,headBranch,headSha,conclusion,workflowName | \
  jq -e --arg commit "$EXPECTED_COMMIT" --argjson run_id "$RUN_ID" '
    .databaseId == $run_id
    and .event == "workflow_dispatch"
    and .headBranch == "main"
    and .headSha == $commit
    and .conclusion == "success"
    and .workflowName == "hsrd arm64 recovery candidate"
  '

ARTIFACT="hsrd-recovery-arm64-$EXPECTED_COMMIT"
BUNDLE="$PWD/$ARTIFACT"
test ! -e "$BUNDLE"
mkdir "$BUNDLE"
gh run download "$RUN_ID" \
  --repo handshake-rs/hns-node-rs \
  --name "$ARTIFACT" \
  --dir "$BUNDLE"
```

The artifact expires after seven days. It contains exactly one OCI archive,
`BUILD-PROVENANCE.json`, and `SHA256SUMS`; the workflow does not create a Git
tag or GitHub Release and does not publish to GHCR or another registry. Keep a
separate retained copy with the incident record if recovery will happen after
artifact expiry.

Verify the downloaded bundle before import:

```sh
ACTUAL_FILES=$(find "$BUNDLE" -maxdepth 1 -type f -printf '%f\n' | sort)
EXPECTED_FILES=$(printf '%s\n' \
  BUILD-PROVENANCE.json \
  SHA256SUMS \
  "hsrd-recovery-linux-arm64-$EXPECTED_COMMIT.oci.tar" | sort)
test "$ACTUAL_FILES" = "$EXPECTED_FILES"

(
  cd "$BUNDLE"
  sha256sum --check SHA256SUMS
)

jq -e \
  --arg archive "hsrd-recovery-linux-arm64-$EXPECTED_COMMIT.oci.tar" \
  --arg commit "$EXPECTED_COMMIT" \
  --argjson run_id "$RUN_ID" '
  .schema_version == 1
  and .artifact_contract == "hsrd-arm64-recovery-candidate-v1"
  and .production_release == false
  and .source.expected_commit == $commit
  and (.source.tree | test("^[0-9a-f]{40}$"))
  and .source.origin_main_at_build == $commit
  and .source.workflow_definition_commit == $commit
  and (.source.workflow_file_ref
    == "handshake-rs/hns-node-rs/.github/workflows/hsrd-recovery-candidate.yml@refs/heads/main")
  and .build.run_id == $run_id
  and .build.platform == "linux/arm64"
  and (.build.imported_image_id | test("^sha256:[0-9a-f]{64}$"))
  and .build.imported_image_id == .build.config_digest
  and .archive.name == $archive
  and .archive.bytes > 0
  and .distribution.registry_published == false
' "$BUNDLE/BUILD-PROVENANCE.json"
```

The provenance binds the full source commit and tree, the current-main
workflow-definition commit and workflow file/ref identity, OCI manifest and
configuration digests, the imported Docker image ID, the archive SHA-256 and
size, and the workflow run and attempt. Preserve that JSON and the checksums
with the operator record.

Import the OCI archive into the local Docker content store explicitly. This
creates only a local reference; it neither pulls nor pushes a registry tag:

```sh
SHORT_COMMIT=$(printf '%.12s' "$EXPECTED_COMMIT")
ARCHIVE="$BUNDLE/hsrd-recovery-linux-arm64-$EXPECTED_COMMIT.oci.tar"
IMAGE="hsrd-recovery-candidate:$SHORT_COMMIT"

skopeo copy "oci-archive:$ARCHIVE" "docker-daemon:$IMAGE"

EXPECTED_IMAGE_ID=$(jq -r '.build.imported_image_id' \
  "$BUNDLE/BUILD-PROVENANCE.json")
docker image inspect "$IMAGE" | jq -e \
  --arg commit "$EXPECTED_COMMIT" \
  --arg image_id "$EXPECTED_IMAGE_ID" '
    length == 1
    and .[0].Id == $image_id
    and .[0].Architecture == "arm64"
    and .[0].Os == "linux"
    and .[0].Config.Labels["org.opencontainers.image.revision"] == $commit
  '
```

Do not retag this candidate as a version or replace a deployed image reference
with an unrecorded local name.

## Stop the restart loop before backup

Do not back up a data root while any process can open it. Identify the exact
container and the mount whose destination is `/var/lib/hsrd`; `DATA` below is
the mount source, not its `chain/` child. Record the old container's image ID,
command, mounts, and restart count with the incident evidence.

Disable automatic restart before stopping the looping container. Stop every
other container or service that mounts the same root, including an older
fallback container. Do not remove them yet:

```sh
OLD_CONTAINER=EXACT_LOOPING_CONTAINER
docker inspect "$OLD_CONTAINER"
docker update --restart=no "$OLD_CONTAINER"
docker stop --time 120 "$OLD_CONTAINER"

test "$(docker inspect --format '{{.State.Running}}' "$OLD_CONTAINER")" = false
```

Confirm that every container sharing `DATA` is stopped and that the RocksDB
lock has no holder. `fuser` must print no process for the lock:

```sh
DATA=/absolute/path/to/exact/hsrd/data-root
sudo fuser --verbose "$DATA/chain/LOCK"
```

Do not continue while the restart policy is nonzero, a container is running,
or a lock holder remains.

## Make a cold whole-root rollback copy

The preceding failed starts marked the store unclean, so the normal
clean-marker-gated storage-maintenance backup is not applicable. Do not forge
a clean marker. Make a stopped, byte-preserving copy of the entire data root,
including `chain/`, `name-pages/`, `payload-segments/`, root-level identity and
profile files, and any other root-level markers. A copy of `chain/` alone is
not a rollback point.

Place the backup outside `DATA`, preferably on a separate filesystem. Measure
allocated source bytes and destination free bytes first. Retain at least the
source allocation plus an operator reserve; this example uses 10 GiB:

```sh
BACKUP_PARENT=/absolute/path/on/backup/filesystem
BACKUP="$BACKUP_PARENT/hsrd-before-interval-recovery"
SOURCE_BYTES=$(sudo du --summarize --block-size=1 "$DATA" | awk '{print $1}')
FREE_BYTES=$(df --output=avail --block-size=1 "$BACKUP_PARENT" | tail -n 1)
RESERVE_BYTES=10737418240
test "$FREE_BYTES" -ge "$((SOURCE_BYTES + RESERVE_BYTES))"
test ! -e "$BACKUP"
mkdir -p "$BACKUP"

sudo rsync --archive --hard-links --acls --xattrs --sparse --numeric-ids \
  --info=progress2 "$DATA/" "$BACKUP/"

sudo rsync --archive --hard-links --acls --xattrs --sparse --numeric-ids \
  --checksum --dry-run --itemize-changes --delete "$DATA/" "$BACKUP/"
```

The checksum dry run must report no differences. Record the source and backup
paths, filesystems, byte counts, commands, and exit statuses. If capacity,
copying, or verification fails, leave the node stopped and resolve the backup
failure before attempting recovery.

## Run once without synchronization or restart

Confirm the old container is still stopped. Select the existing data root's
exact storage profile; do not change an archive store to pruned or a pruned
store to archive. The incident profile must also have no transaction or wallet
indexes. `STORAGE_MODE` below must therefore be the previously recorded
`pruned` or `archive` value.

Start one isolated candidate with no restart policy and no Docker network.
Explicit application arguments disable native synchronization and P2P
discovery. Do not add `--wallet-index`, `--transaction-index`,
`--script-history-index`, or `--spender-index`; indexes cannot be enabled after
unindexed active history without a qualified offline reindex or a new data
root.

```sh
RECOVERY_CONTAINER=hsrd-interval-recovery-once
STORAGE_MODE=RECORDED_PRUNED_OR_ARCHIVE

docker run --detach \
  --name "$RECOVERY_CONTAINER" \
  --restart=no \
  --stop-timeout 120 \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 512 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
  --ulimit nofile=65536:65536 \
  --mount "type=bind,src=$DATA,dst=/var/lib/hsrd" \
  "$IMAGE" \
  --network mainnet \
  --data-dir /var/lib/hsrd \
  --storage-mode "$STORAGE_MODE" \
  --rpc-bind 127.0.0.1:12037 \
  --no-native-sync \
  --no-p2p-discovery
```

Follow only this container's logs. The expected evidence, in order, is:

```sh
test "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' \
  "$RECOVERY_CONTAINER")" = no
docker logs --follow "$RECOVERY_CONTAINER"
```

```text
reconciled legacy name-tree accumulator from canonical undo
hsrd rpc server started
```

The reconciliation log is emitted only after the one-key commit, exact
readback, boundary-root reconstruction, and strict re-audit succeed. Once the
RPC-start log appears, query status through the isolated container's loopback:

```sh
docker exec "$RECOVERY_CONTAINER" \
  curl --fail --silent --show-error \
  http://127.0.0.1:12037/api/v1/status | jq .
```

Then stop the candidate cleanly and require a zero exit status:

```sh
docker stop --time 120 "$RECOVERY_CONTAINER"
test "$(docker inspect --format '{{.State.ExitCode}}' \
  "$RECOVERY_CONTAINER")" = 0
```

Keep the cold backup and candidate evidence. Only after review may the
deployment resume from this repaired root using the same exact image identity
and storage/index profile. Re-enable ordinary synchronization separately;
never re-enable a restart policy until one controlled start and clean stop
have succeeded. Wallet controls and marketplace consumers require their own
documented profile and qualification gates; this repair does not enable them.

## Fail closed and roll back

Stop and preserve logs if any expected step differs. In particular:

- a non-subset accumulator, invalid height/hash/root continuity, missing undo,
  resource limit, or boundary-root mismatch fails before replacing the key;
- a reconciliation log followed by a later startup failure means the one-key
  replacement and strict readback succeeded but another invariant failed;
- RPC startup without the reconciliation log does not prove this incident was
  repaired; and
- an I/O error, forced kill, host restart, or uncertain stop leaves the root
  unclean and requires a new assessment.

Leave every restart policy disabled. Never start the older candidate against a
root that the repaired candidate opened. If rollback is required, stop all
writers, confirm the RocksDB lock is free, preserve the failed post-attempt
root separately, and restore the complete cold copy as one unit. Never merge
individual RocksDB, name-page, payload-segment, or marker files between the
two roots.
