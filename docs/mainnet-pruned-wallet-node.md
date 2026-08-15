# Mainnet pruned wallet-index node

This runbook installs one source-identified `hsrd` binary and starts a fresh,
outbound-only mainnet node on the mounted 1 TB encrypted volume. The profile is
pruned, synchronously durable, authenticated, and has `--wallet-index` present
from genesis. It does not enable mining, transaction relay, inbound P2P, Denuo
roles, HIP-76, ODoH, HNSR, or the mainnet canary.

The node is a noncustodial chain backend. Wallet seeds and private keys belong
in `hns-wallet-rs`, not in this data directory or service.

## Fixed deployment identity

This host profile deliberately fixes these paths:

```bash
NODE_MOUNT=/media/den/64d4d61b-c06f-44ec-9f28-ab6fd78e43f9
NODE_ROOT="$NODE_MOUNT/hsrd"
NODE_DATA="$NODE_ROOT/mainnet-pruned-wallet-v1"
NODE_BIN_DIR="$NODE_ROOT/bin"
NODE_SECRET_DIR="$NODE_ROOT/secrets"
NODE_AUTH="$NODE_SECRET_DIR/mainnet-pruned-wallet-v1.authorization"
NODE_TARGET="$NODE_MOUNT/codex-build-cache/hns-node-rs-audit/target"
NODE_TMP="$NODE_MOUNT/codex-build-cache/hns-node-rs-audit/tmp"
NODE_ROCKS=/home/den/.cache/codex/rocksdb-10.4.2-aarch64/lib

set -euo pipefail

node_installed_process_running() {
  local node_proc node_exe node_base
  for node_proc in /proc/[0-9]*/exe; do
    node_exe=$(readlink -f "$node_proc" 2>/dev/null || true)
    test -n "$node_exe" || continue
    node_exe=${node_exe%" (deleted)"}
    node_base=${node_exe##*/}
    if [[ "$node_exe" == "$NODE_BIN_DIR/"* ]] &&
      [[ "$node_base" =~ ^hsrd-[0-9a-f]{40}$ ]]; then
      return 0
    fi
  done
  return 1
}
```

Run every following block in this same Bash. The fail-fast options are part of
the safety contract: without them a failed mount, absence, permission, hash, or
service check could otherwise be followed by a mutating command. Do not use
`set -x`; it could expose the Authorization value during later checks. The data
directory is a new profile and must not be replaced with, copied from, or
overlaid on an archive node.

## Stopped-state preflight

The mount is manually unlocked and mounted on this host. The unit is therefore
static and has no `[Install]` section: start it manually after the volume is
available and never run `systemctl enable` for it.

From a clean `hns-node-rs` `main` checkout:

```bash
test "$(findmnt -n -o UUID -T "$NODE_MOUNT")" = \
  64d4d61b-c06f-44ec-9f28-ab6fd78e43f9
test "$(findmnt -n -o OPTIONS -T "$NODE_MOUNT")" != ""
findmnt -n -o OPTIONS -T "$NODE_MOUNT" | tr ',' '\n' | grep -Fx rw
test -f "$NODE_ROCKS/librocksdb.a"
test ! -e "$NODE_DATA"
test ! -L "$NODE_DATA"
test -z "$(systemctl --user list-units --state=active --plain --no-legend \
  'hsrd-mainnet-pruned-wallet@*.service')"
if pgrep -x hsrd >/dev/null; then
  printf '%s\n' 'an hsrd process is already running' >&2
  exit 1
fi
if node_installed_process_running; then
  printf '%s\n' 'a commit-named hsrd process is already running' >&2
  exit 1
fi
if pgrep -x cargo >/dev/null || pgrep -x rustc >/dev/null; then
  printf '%s\n' 'Cargo or rustc is already running' >&2
  exit 1
fi
test -z "$(git status --porcelain)"
git fetch origin main
test "$(git branch --show-current)" = main
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
```

The absence checks are intentional. `--wallet-index` cannot truthfully be
enabled after an unindexed mainnet history has already been synchronized. A
fresh root must start with its final index profile.

Confirm that the preserved archive remains a distinct path and do not change
its owner, mode, schema, or contents:

```text
/media/den/64d4d61b-c06f-44ec-9f28-ab6fd78e43f9/Backups/namehold-hsrd/mainnet-archive-2026-08-09-before-wallet-rpc
```

## Build the production feature set

Run the repository qualification gate before this step. `scripts/check.sh`
builds release targets with `--all-features`; that artifact can contain the
`experimental-authority` feature. After every other Cargo command is finished,
relink the installation candidate with the default production feature set and
the required prebuilt RocksDB archive:

```bash
CARGO_TARGET_DIR="$NODE_TARGET" \
TMPDIR="$NODE_TMP" \
ROCKSDB_COMPILE=0 \
ROCKSDB_LIB_DIR="$NODE_ROCKS" \
ROCKSDB_STATIC=1 \
cargo build --locked --release -p hns-node --bin hsrd
```

Positively prove that this post-gate artifact excludes the
`experimental-authority` feature. A version string or checksum cannot reveal
Cargo feature selection, but the fail-closed authority-mode validator can:

```bash
NODE_SOURCE="$NODE_TARGET/release/hsrd"
if NODE_FEATURE_PROBE=$("$NODE_SOURCE" \
  --network regtest \
  --authority-mode native-experimental \
  --acknowledge-incomplete-consensus \
  --no-native-sync \
  --check-config 2>&1); then
  printf '%s\n' 'default-feature hsrd unexpectedly admitted experimental authority' >&2
  exit 1
fi
printf '%s\n' "$NODE_FEATURE_PROBE" | grep -F \
  "native experimental authority requires the \`experimental-authority\` Cargo feature"
unset NODE_FEATURE_PROBE
```

Do not start synchronization until this build and all other Cargo work have
stopped. Do not permit Cargo to fall back to compiling bundled RocksDB on this
ARM host.

## Install an immutable candidate

The complete 40-character source revision is the systemd instance and binary
identity. There is no mutable `current` symlink.

```bash
NODE_REV=$(git rev-parse HEAD)
test "${#NODE_REV}" -eq 40
printf '%s\n' "$NODE_REV" | grep -Eq '^[0-9a-f]{40}$'
NODE_DEST="$NODE_BIN_DIR/hsrd-$NODE_REV"

install -d -m 0700 "$NODE_ROOT" "$NODE_BIN_DIR" "$NODE_SECRET_DIR"
test ! -e "$NODE_DEST"
test ! -L "$NODE_DEST"
test ! -e "$NODE_DEST.sha256"
test ! -L "$NODE_DEST.sha256"
install -m 0500 "$NODE_SOURCE" "$NODE_DEST"
sha256sum -- "$NODE_DEST" > "$NODE_DEST.sha256"
chmod 0400 "$NODE_DEST.sha256"
sha256sum --check --strict "$NODE_DEST.sha256"
test "$(stat -c %a "$NODE_DEST")" = 500
test "$(stat -c %a "$NODE_DEST.sha256")" = 400
"$NODE_DEST" --version
```

Do not overwrite an installed revision. A later source revision receives a new
binary, checksum, and unit instance.

## Create the private RPC credential

Create the credential once without printing it or putting it in an argument or
environment variable. `hsrd` removes the one terminal line ending and requires
the remaining value to be visible ASCII with no surrounding whitespace.

```bash
test ! -e "$NODE_AUTH"
test ! -L "$NODE_AUTH"
(
  set -eu
  umask 077
  node_auth_tmp=$(mktemp \
    "$NODE_SECRET_DIR/.mainnet-pruned-wallet-v1.authorization.XXXXXX")
  trap 'rm -f -- "$node_auth_tmp"' EXIT
  {
    printf 'Bearer '
    openssl rand -hex 32
  } > "$node_auth_tmp"
  test "$(wc -c < "$node_auth_tmp")" -eq 72
  chmod 0600 "$node_auth_tmp"
  ln -- "$node_auth_tmp" "$NODE_AUTH"
  rm -- "$node_auth_tmp"
  trap - EXIT
)
chmod 0600 "$NODE_AUTH"
test "$(wc -c < "$NODE_AUTH")" -eq 72
test "$(stat -c %u "$NODE_AUTH")" -eq "$(id -u)"
test "$(stat -c %a "$NODE_AUTH")" = 600
test "$(stat -c %h "$NODE_AUTH")" = 1
```

Back up the wallet seed through the wallet's dedicated process later. Do not
copy this RPC credential into browser storage, logs, shell history, or wallet
seed backups.

## Validate and install the service contract

The checked-in unit binds directly to the commit-named binary, checksum,
credential, fresh data root, and expected mount. It intentionally has no
`[Install]` section.

First validate the same arguments without creating or opening the database. A
configuration failure therefore leaves the fresh-root precondition intact:

```bash
"$NODE_DEST" \
  --network mainnet \
  --data-dir "$NODE_DATA" \
  --rpc-bind 127.0.0.1:12037 \
  --rpc-authorization-header-file "$NODE_AUTH" \
  --rpc-max-request-bytes 65536 \
  --rpc-max-concurrent-requests 32 \
  --rpc-execution-timeout-ms 5000 \
  --rpc-max-collection-entries 50000 \
  --authority-mode native \
  --storage-durability sync \
  --wallet-index \
  --storage-mode pruned \
  --native-sync \
  --p2p-discovery \
  --maximum-known-addresses 4096 \
  --maximum-inbound 0 \
  --maximum-outbound 8 \
  --active-state-connect-batch 32 \
  --validation-workers 2 \
  --validation-queue 128 \
  --orphan-blocks 1024 \
  --orphan-bytes 67108864 \
  --native-sync-poll-ms 250 \
  --no-hip76-requester \
  --no-odoh-requester \
  --no-hnsr-requester \
  --no-hnsr-relay \
  --log-filter info \
  --check-config
```

Create the data root only after the profile, binary, checksum, credential, and
configuration have passed their preflight:

```bash
test ! -e "$NODE_DATA"
test ! -L "$NODE_DATA"
install -d -m 0700 "$NODE_DATA"
```

Install the template, then verify the actual source-revision instance so
systemd resolves `%i` to the installed binary rather than a synthetic test
name:

```bash
NODE_SERVICE="hsrd-mainnet-pruned-wallet@$NODE_REV.service"
install -d -m 0700 "$HOME/.config/systemd/user"
install -m 0600 deploy/hsrd-mainnet-pruned-wallet@.service \
  "$HOME/.config/systemd/user/hsrd-mainnet-pruned-wallet@.service"
systemctl --user daemon-reload
systemd-analyze --user verify "$NODE_SERVICE"
test "$(systemctl --user is-enabled "$NODE_SERVICE" 2>&1)" = static
```

## Manual start and acceptance

Start this exact instance. Do not enable it:

```bash
systemctl --user start "$NODE_SERVICE"
systemctl --user --no-pager --full status "$NODE_SERVICE"
```

`Type=simple` does not make `systemctl start` wait for the RPC socket. Use a
bounded connection-refused retry, then prove that the first reachable listener
rejects an unauthenticated request and that the unit stayed active:

```bash
NODE_HTTP_CODE=$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' \
  --retry 30 \
  --retry-connrefused \
  --retry-delay 1 \
  --retry-max-time 60 \
  --connect-timeout 1 \
  --max-time 2 \
  http://127.0.0.1:12037/api/v1/status)
test "$NODE_HTTP_CODE" = 401
test "$(systemctl --user show "$NODE_SERVICE" \
  --property ActiveState --value)" = active
```

For authenticated checks, feed the header through standard input so the secret
does not appear in the process argument list:

```bash
node_rpc_get() {
  local node_path=$1
  {
    printf 'Authorization: '
    tr -d '\r\n' < "$NODE_AUTH"
    printf '\n'
  } | curl --fail --silent --show-error --header @- \
    "http://127.0.0.1:12037$node_path"
}

node_rpc_wallet() {
  local node_body=$1
  {
    printf 'Authorization: '
    tr -d '\r\n' < "$NODE_AUTH"
    printf '\n'
  } | curl --fail --silent --show-error --header @- \
    --header 'Content-Type: application/json' \
    --data-binary "$node_body" \
    http://127.0.0.1:12037/api/v1/wallet
}

node_rpc_get /api/v1/status | jq -e '
  .network == "mainnet" and
  .storage_durability == "sync" and
  .undo_retention.prune_history == true and
  .rpc_authentication_required == true and
  .authority.mode == "native" and
  .authority.mainnet_canary_enabled == false and
  .authority.mainnet_canary_active == false and
  .authority.experimental_feature_enabled == false and
  .authority.experimental_bypass_active == false and
  .authority.incomplete_consensus_acknowledged == false and
  .authority.can_authorize_mining_templates == false and
  .authority.can_accept_mining_candidates == false and
  .odoh.requester_enabled == false and
  .hnsr.requester_enabled == false and
  .hnsr.opaque_relay_enabled == false
'
node_rpc_get /api/v1/mining-engine | jq -e '
  .enabled == false and
  .transaction_relay_enabled == false and
  .can_build_templates == false and
  .can_publish_solved_blocks == false
'
node_rpc_get /api/v1/sync | jq -e '.stage != null'
node_rpc_get /api/v1/native-sync | jq -e '.last_error == null'
node_rpc_wallet \
  '{"api_version":1,"request_id":"deployment-capabilities","call":{"method":"capabilities"}}' \
  | jq -e '
    .api_version == 1 and
    .result.api_version == 1 and
    .result.maximum_restore_scripts == 10000 and
    .result.maximum_wire_page_items == 256 and
    .result.maximum_wire_result_bytes == 8388608 and
    .result.maximum_opaque_cursor_bytes == 4096 and
    .result.incoming_transfer_projection_version == 1 and
    .result.incoming_transfer_source_bindings == [
      "retained_body_verified",
      "pruned_trusted_node_projection"
    ] and
    .result.incoming_transfer_cursor_binding ==
      "chain_epoch_exact_tip_and_complete_sorted_unique_script_set" and
    .result.incoming_transfer_cursor_authentication ==
      "none_unkeyed_query_binding_only" and
    .result.incoming_transfer_authority ==
      "candidate_discovery_only_not_balance_name_authority_or_cryptographic_proof" and
    .result.maximum_incoming_transfer_script_examinations == 256 and
    .result.maximum_incoming_transfer_retained_block_decodes == 4
  '
```

These assertions prove mainnet, pruned storage, synchronous durability, native
mode without mining authority, default-feature execution, required RPC
authentication, disabled ODoH/HNSR roles, disabled mining/relay, live sync
diagnostics, and a v1 wallet `result`. The last condition proves the
authenticated wallet route was installed from the first start and advertises
the bounded version-1 incoming-TRANSFER projection.

Bind the running process to the installed artifact:

```bash
NODE_PID=$(systemctl --user show "$NODE_SERVICE" --property MainPID --value)
test "$NODE_PID" -gt 1
test "$(readlink -f "/proc/$NODE_PID/exe")" = "$NODE_DEST"
sha256sum --check --strict "$NODE_DEST.sha256"
```

During synchronization, `/api/v1/sync` must keep advancing. The detailed
`/api/v1/native-sync` projection, not the compact sync projection, owns
`last_error`; check it mechanically while recording logical and physical
growth:

```bash
node_rpc_get /api/v1/native-sync | jq -e '.last_error == null'
df -B1 "$NODE_MOUNT"
du -sx --block-size=1 "$NODE_DATA"
```

Do not assume an unqualified wallet-index disk estimate. Stop and investigate
before free space threatens the filesystem or the preserved archive.

Final synchronization acceptance requires `stage == "Synced"`, identical
nonzero best-header, active, and stored tips, zero pending/inflight/tracked
blocks, at least one ready peer, and no sync error. A synchronized node still
has no mining authority because `--mainnet-canary` is absent.

## Initial send limitation and pruning boundary

This first profile deliberately omits both `--mining-engine` and
`--transaction-relay`. Confirmed restoration, receive history, name evidence,
proofs, and wallet read operations are available while the chain synchronizes.
`broadcast_transaction` fails closed with
`mining_engine-transaction-relay-disabled` until a later, separately reviewed
tranche enables both flags. Transaction relay must never be mistaken for
mainnet mining authority; keep `--mainnet-canary` absent.

Profile-v4 wallet indexes retain compact canonical source-inclusion metadata
for active incoming TRANSFER covenants until the spender rollback horizon
retires. They never retain the raw owner transaction or its witness. Raw owner
transactions older than the 288-block payload horizon can therefore be
unavailable, so the wallet must retain every signed transaction and any raw
owner transactions needed to construct future name actions.

The authenticated `incoming_transfers_page` method exposes the retained compact
state as bounded candidate discovery. After obtaining `chain_epoch` from
`chain_snapshot`, a wallet requests its complete sorted-unique recipient
ScriptId set as follows:

```json
{
  "api_version": 1,
  "request_id": "mainnet-incoming-transfer-1",
  "call": {
    "method": "incoming_transfers_page",
    "params": {
      "script_ids": ["<64 hex characters>"],
      "expected_chain_epoch": 42,
      "cursor": null,
      "limit": 256
    }
  }
}
```

The expected epoch is checked in the immutable snapshot before any recipient
prefix or retained body is read. Each version-1 result row identifies its
sorted `script_index`, covenant `recipient`, `name_hash`, `start_height`, exact
old-owner `transfer_coin`, canonical `inclusion`, `source_output_count`, and
`source_binding`; the page also returns the captured epoch/tip,
`script_examinations`, and `continuation`. The TRANSFER Coin is not part of the
recipient's spendable HNS balance. A row is not current NameState authority, a
cryptographic proof, or permission to finalize a name.

`retained_body_verified` means the same snapshot also verified the retained
block commitments, transaction ordinal/output count, and exact referenced
output. `pruned_trusted_node_projection` means the raw block was proven absent
and the Coin-based result is a trusted-node projection, not a cryptographic
binding of output bytes to txid. Pruning can change this per-row label between
pages without changing the chain epoch. The method always performs the
same-snapshot transaction-index, active-chain/position, block/header status,
evidence-state, and byte-exact active-UTXO checks documented in
`HNS_NODE_WALLET_INDEX.md`.

The request admits at most 10,000 sorted-unique ScriptIds and 256 wire rows. A
call examines at most 256 recipient prefixes total, and therefore at most 256
empty prefixes, and decodes at most four distinct retained block bodies before
returning a continuation. The underlying index page remains bounded to 4,096
rows and 16 MiB; the cursor is a hexadecimal encoding of bounded JSON capped at
4,096 decoded bytes, and the serialized wire result is capped at 8 MiB. The
continuation binds its version, actual epoch, exact tip, complete script-set
digest, and traversal position. That digest is unkeyed: the cursor is opaque
but is not a MAC, authentication token, secret, or capability.

There is no unauthenticated or partial-profile variant. The exact Authorization
header, complete `--wallet-index` profile, canonical native runtime, listener
limits, and collection-read admission used by every wallet method also gate
`incoming_transfers_page`. The exact response schema is in
[`WALLET_RPC_V1.md`](WALLET_RPC_V1.md#incoming-transfer-discovery).

Do not point a profile-v4 binary at this deployment's non-empty, wallet-enabled
profile-v3 data directory. Normal startup deliberately rejects that unsafe
upgrade because pruning may already have removed exact source inclusion data.
Provision a fresh v4 data directory and resynchronize unless a later
version-matched offline migration is separately qualified and reconstructs
every active TRANSFER's canonical transaction ordinal and total output count
from verified archive data.

## Stop before maintenance or builds

Stop cleanly before every later Cargo build/test, binary replacement, storage
maintenance operation, or volume unmount:

If the original shell has ended during the long synchronization, first rerun
the fixed deployment-identity block at the start of this runbook. Then recover
the exact active revision, service, binary, and PID without guessing or using a
mutable symlink:

```bash
mapfile -t NODE_ACTIVE_SERVICES < <(
  systemctl --user list-units --state=active --plain --no-legend \
    'hsrd-mainnet-pruned-wallet@*.service' | awk '{print $1}'
)
test "${#NODE_ACTIVE_SERVICES[@]}" -eq 1
NODE_SERVICE=${NODE_ACTIVE_SERVICES[0]}
if [[ "$NODE_SERVICE" =~ \
  ^hsrd-mainnet-pruned-wallet@([0-9a-f]{40})\.service$ ]]; then
  NODE_REV=${BASH_REMATCH[1]}
else
  printf '%s\n' 'active node unit does not contain one exact source revision' >&2
  exit 1
fi
NODE_DEST="$NODE_BIN_DIR/hsrd-$NODE_REV"
NODE_PID=$(systemctl --user show "$NODE_SERVICE" --property MainPID --value)
test "$NODE_PID" -gt 1
test "$(readlink -f "/proc/$NODE_PID/exe")" = "$NODE_DEST"
```

Now stop and prove both the unit and executable are gone:

```bash
systemctl --user stop "$NODE_SERVICE"
test "$(systemctl --user show "$NODE_SERVICE" \
  --property ActiveState --value)" = inactive
if test -e "/proc/$NODE_PID/exe"; then
  test "$(readlink -f "/proc/$NODE_PID/exe" 2>/dev/null || true)" != \
    "$NODE_DEST"
fi
if node_installed_process_running || pgrep -x hsrd >/dev/null; then
  printf '%s\n' 'an hsrd process survived the clean stop' >&2
  exit 1
fi
```

Never force-unmount or lazy-unmount the encrypted volume while `hsrd` is
running. Restart manually after the build or maintenance work is complete.
