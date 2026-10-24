# Storage rollout, migration, and fallback

This is the operational path for the current `hsrd` source tree. The on-disk
schema is **21** with profile **`hsrd-rocks-fresh-v1`**. `pruned` and `archive`
are runtime storage modes, not schema profiles. The authoritative values are
`SCHEMA_VERSION` and `STORAGE_PROFILE` in `crates/hns-store/src/lib.rs`.

The former `hsrd-storage-maintenance` executable and its `backup`, `inventory`,
`compact`, `migrate-inline`, `fence-inspect`, and `fence-clear` commands were
removed. Do not use an older copy of this guide to operate a current data root.
The current binaries are listed in `crates/hns-node/Cargo.toml`. The node still
rejects a `.hsrd-storage-maintenance` marker at startup, but there is no
current maintenance command that requires creating one.

## Compatibility boundary

| Existing store | Current code behavior | Operational path |
| --- | --- | --- |
| Empty directory | Initializes schema 21 and the current profile. | Start with the final network, storage mode, and wallet-index profile. |
| Schema 21 / `hsrd-rocks-fresh-v1` | Opens after identity, archive, and startup recovery checks. | Upgrade the binary with a complete fallback and verify the exact active tip and state. |
| Schema 19 / `hsrd-mining-v15` | The store layer has a narrow marker and mixed-index fallback transition. It does not rebuild or qualify historical consensus state. | Keep the source unchanged and use a fresh synchronized data root unless this exact transition has separately passed full production qualification. |
| Other schema/profile pairs or a nonempty unversioned store | Refused by schema initialization. | Use a fresh synchronized data root. Do not edit markers or copy selected column families. |

The node's current storage path is intentionally fresh-first. A marker
transition is not evidence that an older physical store is safe for authority.
An in-place historical conversion needs its own implementation and qualification.
See [storage schema](storage-schema.md) and [state parity](state-parity.md).

## 1. Identify the candidate and preserve the source

Build the exact candidate revision and record its identity. On the workspace
ARM host, use the prebuilt RocksDB archive and Cargo settings specified in
[node qualification](testing.md); do not compile bundled RocksDB.

```sh
git rev-parse HEAD
cargo build --locked --release -p hns-node \
  --bin hsrd --bin hsrd-state-manifest --bin hsrd-rollback-manifest
HSRD_TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
sha256sum "$HSRD_TARGET_DIR/release/hsrd" \
  "$HSRD_TARGET_DIR/release/hsrd-state-manifest" \
  "$HSRD_TARGET_DIR/release/hsrd-rollback-manifest"
```

Record the source binary, arguments, network, storage mode, wallet-index
profile, service identity, filesystem, and observed schema/profile. Preserve
the existing service and its data root. Before any binary replacement, take a
verified, complete fallback while the source is stopped cleanly or through a
qualified filesystem snapshot procedure that covers all files coherently.
The complete root includes `chain/`, `payload-segments/`, and `name-pages/` when
present. RocksDB's process lock prevents a second process from opening the
live database; a RocksDB-only checkpoint does not copy the external files.

Keep the fallback immutable. Record file counts, sizes, digests or an
authenticated backup manifest, ownership, modes, and restore location. Test a
restore into a distinct directory with the source binary before treating the
copy as a fallback. A clean-shutdown marker and checksums establish
consistency, not protection against an untrusted offline writer.

## 2. Run a fresh candidate beside the source

Create a new, empty data root with enough capacity for a full synchronization
and retained rollback horizon. Give the candidate its own RPC/P2P ports and
service identity. Keep mining authority and public ShakeScape relay roles on
the source until cutover, so the candidate does not duplicate advertisements
or act as a second authority. Start the candidate with its intended final
`pruned` or `archive` mode and wallet-index profile; a pruned or incomplete
index cannot later be assumed to contain archive history or complete wallet
evidence.

Follow the active, stored, best-header, and peer targets through
`/api/v1/status`, `/api/v1/sync`, and `/api/v1/native-sync`. A running process,
zero restarts, a rising validated-body count, or `failed_blocks=0` alone does
not establish synchronization. Require the active tip itself to advance and
eventually match the best header by hash, height, and chainwork. Retain the
source data root and diagnostic logs while investigating a stalled tip.

## 3. Compare a pinned state and rollback horizon

Capture both nodes at the **same network, genesis, active height, and block
hash**. Stop them cleanly or create independently qualified consistent copies
of their complete data roots. `hsrd-state-manifest` accepts a copied `chain/`
directory with an exact `.hsrd-state-audit-copy` marker; the copied
`payload-segments/` and `name-pages/` must remain alongside it. Never put that
marker on the live store. The exporter and its marker requirements are in
[state parity](state-parity.md).

```sh
HSRD_TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
"$HSRD_TARGET_DIR/release/hsrd-state-manifest" \
  --data-dir /absolute/candidate-copy/chain \
  > /absolute/evidence/candidate-state.json
"$HSRD_TARGET_DIR/release/hsrd-rollback-manifest" \
  --data-dir /absolute/candidate-copy \
  --output /absolute/evidence/candidate-rollback.json
```

Compare the active block identity, UTXO and name-state digests/counts, working
and committed name roots, deployment state, and the complete retained
disconnect/reconnect transcript. A height match or snapshot hash alone is
insufficient. If comparing against HSD, qualify its independent exporter as
described in [state parity](state-parity.md). Preserve the raw evidence and
source/configuration identities.

## 4. Cut over and verify

Run the applicable [production assurance](production-assurance.md) gates on
the exact candidate. Include persistent RocksDB/Sync, sustained multi-peer
operation, pruning or archive behavior, fault injection, and restart on the
deployment filesystem. Current online payload and name-page compaction are
part of the node; there is no standalone maintenance CLI for an offline
compaction campaign. Where a required external gate calls for pre/post
inventory or fallback verification, provide independently reviewed evidence
from a current, qualified method. If that method is unavailable, the gate is
unqualified.

Stop the source and candidate cleanly. Preserve both roots. Point the service
at the qualified candidate root and exact binary, start it, then verify the
network, schema/profile, active tip, name roots, pruning checkpoint, peer
progress, and configured authority gate. Check the ShakeScape board and relay
roles only after their intended public endpoint has been switched. Retain the
source binary, data root, configuration, and evidence until the rollback window
has closed.

## Fallback

On a failed cutover, stop the candidate. Leave its root intact for diagnosis.
Restore the source service using its unchanged root or a tested copy of the
complete fallback, and use the exact source binary and configuration. Verify
its network, active tip, roots, and authority gate before restoring public
traffic. Do not start an older binary on a candidate root with an unsupported
schema/profile.

This procedure never deletes an HSD data root. HSD data retirement remains a
separate, explicitly authorized operation after independent state, wallet,
rollback, and recovery qualification.
