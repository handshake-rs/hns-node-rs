# Bounded control and differential API

Native template construction and candidate admission do not use this
interface. The separately built MeshMine Core/operator process uses the
hsrd-specific read-only `getparentauthority` method as its authenticated
runtime parent boundary; in-process mining continues to use native Rust types
and bounded channels.

The HTTP/JSON surface is retained only for operator diagnostics, health checks,
and fixture comparison. It binds to loopback by default and reads immutable
snapshots only.

## Currently implemented

- Read-only chain, header, block, transaction, UTXO, name-state, mempool,
  authority, parity, and mining-engine snapshots.
- `getparentauthority`, which returns the requested canonical header, active
  tip, native authority/readiness, durable validation status, and pending-tip
  state from one immutable snapshot so Core cannot combine claims across a tip
  transition. The native-sync handler uses keyed store reads under the chain
  coordinator lock; periodic Core requalification does not scan the UTXO,
  name-state, header, or block collections.
- Truthful network-active and connection-count reporting.
- Live peer and synchronization details on the native runtime's bounded REST
  endpoints. `getpeerinfo` fails explicitly until the JSON-RPC compatibility
  response is backed by those live peer snapshots.
- Capability-named REST diagnostics under `/api/v1/status`,
  `/api/v1/authority`, `/api/v1/parity`, and `/api/v1/mining-engine`; the live
  native runtime also exposes `/api/v1/peers`, `/api/v1/sync`, and
  `/api/v1/native-sync`. `/api/v1/shadow-sync` is a read-only compatibility
  alias.
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
- Native-sync diagnostics distinguish active-state, observe-only, and
  headers-only operation and report
  committed blocks, reorganizations, contextual-invalid bodies, durable
  address-book load/prune/generation/flush state, and an opaque process-local
  runtime instance used to correlate restart evidence.
- Optional whole-listener Authorization enforcement from
  `--rpc-authorization-header-file`. The absolute nonsymlink file must be
  private and contain one bounded nonempty header value such as `Bearer ...`.
  When configured, every JSON-RPC and diagnostic route rejects missing or
  unequal values with HTTP 401. Secrets are redacted from Debug output.
- Unsupported mutations fail explicitly. No current control endpoint performs
  a mutation.

Core requires authentication to be configured and rejects an otherwise valid
authority snapshot whose `rpc_authentication_required` field is false. A
matching command shape is:

```bash
hsrd --network mainnet --data-dir /path/to/hsrd \
  --rpc-bind 127.0.0.1:14037 \
  --rpc-authorization-header-file /absolute/private/hsrd-authorization-header \
  --authority-mode native --native-sync --p2p-discovery
```

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
