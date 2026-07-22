# Live HSD shadow parity

Live comparison is an external qualification boundary. It reads hsrd's
non-authoritative active state and a separately running pinned HSD node; it
does not feed HSD answers into consensus, change fork choice, or grant a mining
capability.

## Comparison material

API-v8 `/api/v1/status` exposes the active block hash/height and
`active_state_resulting_root`. The latter is the authenticated name-tree root
after applying the active tip. Handshake block `H` commits the root inherited
from `H-1`, so comparison at hsrd height `H` uses:

- HSD's canonical block hash at `H`; and
- the `treeroot` committed by HSD's canonical header at `H+1`.

When hsrd and HSD are at the same live tip, no `H+1` header exists yet. The
runner obtains the root from HSD's next-block template, labels it
`next-template`, and records that it is not yet header-confirmed. A later
sample can confirm the same state through the next canonical header.

The shadow diagnostics also expose an opaque `runtime_instance`. It has no
authority meaning; the evidence runner uses a change in that value to count
observations spanning hsrd restarts.

## Runner

Run hsrd on a diagnostic port distinct from HSD's RPC port, with active-state
connection explicitly acknowledged. Then run:

```bash
scripts/compare-hsrd-hsd-shadow.py \
  --hsrd-url http://127.0.0.1:13037 \
  --hsd-cli /absolute/path/to/hsd/bin/hsd-cli \
  --hsd-source /absolute/path/to/hsd \
  --state-file /absolute/path/to/hsrd-hsd-parity-v1.json \
  --samples 0 --interval-seconds 15
```

Repeat `--hsd-cli-arg=VALUE` for HSD client options such as an alternate
prefix or network. The runner requires an absolute executable inside the
selected HSD source tree, verifies that the tree's tracked files are clean,
and requires its Git revision to equal hsrd's pinned oracle revision. Untracked
files do not change the oracle source check. Binding the running HSD service to
that source/runtime remains an operator deployment responsibility; use the
production HSD preflight for that service-level evidence.

The hsrd URL is restricted to loopback unless
`--allow-remote-hsrd` is supplied. Responses and subprocess output have hard
size limits, calls have bounded timeouts and retries, and the runner rereads
both nodes after gathering comparison material. A tip change during the probe
is retried instead of being reported as a divergence.

## Header-only qualification

A pruned HSD node still exposes the canonical header chain through P2P and
canonical hashes through RPC. Start hsrd with `--shadow-sync-headers-only`, then
compare its durable best header without making any block-body or state claim:

```bash
scripts/compare-hsrd-hsd-shadow.py \
  --headers-only --require-current-tip \
  --hsrd-url http://127.0.0.1:13037 \
  --hsd-cli /absolute/path/to/hsd/bin/hsd-cli \
  --hsd-source /absolute/path/to/hsd
```

The emitted scope covers header linkage, difficulty, timestamps, checkpoints,
chainwork, and canonical ancestry. It does not cover body, script, covenant,
UTXO, name-state, or root parity. Header-only mode refuses the active-state
evidence `--state-file` format rather than mixing those scopes.

## Evidence checkpoint

Each coherent probe emits one canonical JSON line. `--state-file` maintains
a bounded, atomically replaced schema-v1 checkpoint containing counters and
the last complete observation. Observations are BLAKE2b-256 linked to their
predecessor. The loader verifies counter relationships, the complete checkpoint
checksum, and the last observation checksum before extending the checkpoint.

The checkpoint separately counts:

- confirmed next-header matches and provisional next-template matches;
- coherent block-hash or resulting-root divergences;
- reorganizations, including a prior observed height leaving HSD's canonical
  chain; and
- hsrd runtime restarts.

Exit status `0` means every requested sample matched, `1` means a coherent
block/root divergence was recorded, and `2` means the probe or evidence state
was unavailable, incoherent, unsafe, or malformed. `130` is used for an
operator interrupt. A match is evidence for one observed boundary only. Full
mainnet replay, long-duration restart/partition/reorganization campaigns, and
independent review remain release gates.

The offline self-test is part of the source-handoff gate and can be run alone:

```bash
scripts/compare-hsrd-hsd-shadow.py --self-test
```
