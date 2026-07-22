# Bounded control and differential API

Mining does not use this interface. MeshMine and `hsrd` communicate through
native Rust types and bounded channels.

The HTTP/JSON surface is retained only for operator diagnostics, health checks,
and fixture comparison. It binds to loopback by default and reads immutable
snapshots only.

## Currently implemented

- Read-only chain, header, block, transaction, UTXO, name-state, mempool,
  authority, parity, and mining-engine snapshots.
- Truthful network-active and connection-count reporting.
- Live peer and synchronization details on the shadow runtime's bounded REST
  endpoints. `getpeerinfo` fails explicitly until the JSON-RPC compatibility
  response is backed by those live peer snapshots.
- Capability-named REST diagnostics under `/api/v1/status`,
  `/api/v1/authority`, `/api/v1/parity`, and `/api/v1/mining-engine`; the live
  shadow runtime also exposes `/api/v1/peers`, `/api/v1/sync`, and
  `/api/v1/shadow-sync`.
- API-v9 node status reports whether startup name-tree compaction is enabled,
  its height interval, and the last checkpoint's height, tip, retained roots,
  and before/retained/deleted node counts. It also reports whether undo
  retirement is enabled, the exact network `pruneAfterHeight` and `keepBlocks`
  values, and the last checksummed pruning boundary/block/count. Valid
  non-active blocks and durably failed blocks have separate counts. It exposes
  whether the active-state connector is enabled and its bounded per-pass batch
  size without presenting that non-authoritative mode as mining readiness. The
  active tip's post-state authenticated root and the height it results from are
  exposed explicitly for an external HSD comparison; this differs from the
  pre-state root committed inside the active tip's own header.
- Shadow-sync diagnostics distinguish default observation-only retention from
  explicitly enabled non-authoritative active-state connection and report
  committed blocks, reorganizations, contextual-invalid bodies, and an opaque
  process-local runtime instance used to correlate restart evidence.
- Unsupported mutations fail explicitly. No current control endpoint claims to
  authenticate or perform a mutation.

## Target reads

- network, genesis, best hash, height, bits, chainwork, sync/prune status;
- exact header/block lookup needed by differential tests;
- UTXO/name-tree root and deployment commitments needed for parity evidence;
- mempool/template generation and peer/relay health;
- per-lane queue, storage, tip-to-job, and candidate-publication metrics.

## Target mutations

- submit a test/raw block through the same consensus candidate path;
- add/remove an operator-pinned peer;
- initiate graceful shutdown or a bounded diagnostic snapshot.

Wallet, signing, domain actions, DNS, explorer/address queries, public mining
RPC, and broad hsd tooling compatibility are deliberately unsupported.
