# Bounded control and differential API

Native template construction and candidate admission do not use this
interface. The separately built MeshMine Core/operator process uses the
hsrd-specific read-only `getparentauthority` method as its authenticated
runtime parent boundary; in-process mining continues to use native Rust types
and bounded channels.

The HTTP/JSON surface is retained for operator diagnostics, health checks,
fixture comparison, and one separately versioned noncustodial wallet process
boundary. It binds to loopback by default. Each durable lookup uses one
immutable store snapshot; the live runtime does not materialize the database
into a process-wide RPC snapshot.

## Currently implemented

- Read-only chain, header, block, transaction, UTXO, name-state, mempool,
  authority, parity, and mining-engine snapshots.
- `getparentauthority`, which returns the requested canonical header, active
  tip, native authority/readiness, durable validation status, and pending-tip
  state from one immutable snapshot so Core cannot combine claims across a tip
  transition. The native-sync handler uses keyed store reads under the chain
  coordinator lock; periodic Core requalification does not scan the UTXO,
  name-state, header, or block collections.
- `getdnsresource`, a resolver-specific point read that returns one name's
  canonical resource hex together with the network, active height, best-header
  height, active resulting name-tree root, chain epoch, and synchronized flag
  from the same immutable store snapshot. The separately deployed
  `hns-resolverd` therefore never binds bytes from one tip to status from
  another tip during a block connection or reorganization.
- Native-sync `getblockhash` and `getblockheader` select a complete canonical
  header record from one locked generation of the shared in-memory header
  index. The immutable store snapshot is acquired while that read lock is still
  held. Header import, block connect/disconnect/reorganization, invalid-branch
  publication, and payload pruning hold the matching write lock across the
  durable commit and infallible bounded cache publication. An RPC therefore
  observes either the old index/old store or the new index/new store, including
  the normally dangerous interval after the database commit has returned but
  before publication completes. Cloning the index handle into an RPC read
  context is constant time, and each response clones only its selected record.
- Every JSON-RPC request is classified through the fixed `RpcMethod` registry
  before a node lock, store snapshot, or collection read is attempted. Unknown
  methods, `sendrawtransaction`, and `getpeerinfo` reject immediately.
- `getblockhash`, `getblockheader`, `getblock`, `getrawtransaction`,
  `gettxout`, `getnameinfo`, `getnameresource`, `getdnsresource`, and
  `getnamebyhash` use keyed reads. Confirmed `getrawtransaction` lookup
  requires `--transaction-index`;
  a mempool transaction remains a keyed in-memory read without that option.
  The implementation never falls back to scanning retained blocks.
- `getmempoolinfo` reads exact transaction/claim/airdrop counts, bytes, and
  fees from incrementally maintained `O(1)` aggregates; it never clones the
  transaction collection. `getrawmempool` captures those aggregates plus a
  generation-stable persistent AVL root while briefly holding the node
  coordinator. Capturing a generation is `O(1)`; admission and removal
  path-copy `O(log M)` nodes and share every untouched subtree, even while
  workers retain older generations. The worker releases the coordinator before
  walking the index, formatting hashes, or constructing JSON. If the captured
  transaction count exceeds `--rpc-max-collection-entries`, it returns an
  explicit bounded-result error without cloning or walking the oversized list.
  Dependency-root expiry is also indexed by `(admitted_at, txid)` with an exact
  cached minimum: the steady under-capacity path performs one `O(1)` due check
  and `O(1)` capacity check, while root insert/removal is `O(log M)`. Expiring
  `E` roots visits only due packages and their bounded dependency changes; it
  never scans or sorts all `M` entries merely to discover that none are due.
- `getblockchaininfo` reports the active block height and the best validated
  header height independently, including headers-only and header-ahead sync.
- Truthful network-active and connection-count reporting.
- Live peer and synchronization details on the native runtime's bounded REST
  endpoints. `getpeerinfo` fails explicitly until the JSON-RPC compatibility
  response is backed by those live peer snapshots.
- Capability-named REST diagnostics under `/api/v1/status`,
  `/api/v1/authority`, `/api/v1/parity`, and `/api/v1/mining-engine`; the live
  native runtime also exposes `/api/v1/peers`, `/api/v1/sync`, and
  `/api/v1/native-sync`. The former `/api/v1/shadow-sync` compatibility alias
  was removed in v0.3.0 and is not routed.
- API-v11 node status reports whether startup name-tree compaction is enabled,
  its height interval, and the last checkpoint's height, tip, retained roots,
  and before/retained/deleted node counts. It also reports whether undo
  pruning is enabled, the exact network `pruneAfterHeight` and `keepBlocks`
  values, and independent checksummed raw-block and undo
  boundary/block/count fields. Valid
  non-active blocks and durably failed blocks have separate transition-safe
  O(1) counters rather than a per-refresh block-index scan. Startup computes
  those exact counters with bounded pages while retaining only a fixed 4,096
  block-index record cache; an evicted record remains available by keyed
  durable lookup. It exposes
  whether the active-state connector is enabled and its bounded per-pass batch
  size without presenting that non-authoritative mode as mining readiness. The
  active tip's post-state authenticated root and the height it results from are
  exposed explicitly for an external HSD comparison; this differs from the
  pre-state root committed inside the active tip's own header.
- API-v12 node status adds the canonical Denuo Experimental V1 registry
  identity, wire profile, packet/registry payload limits, and bounded live
  negotiation counts and rejection reasons. Each diagnostics refresh builds
  one `experimental_registry` object from the same per-peer capture for native
  sync and node status; the existing cache markers identify when status is
  serving the last completed capture.
- API-v13 adds a qname-free `hip76` object with the draft wire identity,
  opt-out requester and opt-in provider defaults, live role/phase counts, and
  separate packet-created, queue-admitted, socket-written, failed-write, and
  stale-drop counters. It never exposes request IDs, question names, raw DNS
  bodies, response statuses, or deadlines.
- API-v13's base `NodeService` snapshot initializes `release_stage:
  "pre-authority"`. The native-sync composer replaces it in live RPC with
  `native-sync-live-p2p`, `mining-engine-observe`, or
  `mainnet-canary-gated`, according to configuration. These diagnostic stages
  are intentionally separate from the all-true `consensus_readiness` object
  and from a conditional mainnet-canary permit at a coherent authoritative
  live tip.
- Native status, authority, parity, and mining-engine diagnostics bind before
  startup replay and remain available while the state coordinator is occupied
  by a connect slice or name-tree compaction. HTTP requests always use the last
  sync-loop storage capture rather than recomputing potentially linear
  diagnostic counts under the coordinator lock. Already-bounded live
  peer-count, network-active, registry, HIP-76, and scheduler best-header
  fields are overlaid per request from the diagnostics lock, so ordinary
  network/status RPCs do not freeze at their startup values. Each response reports
  `diagnostic_snapshot_cached: true` and
  `diagnostic_snapshot_captured_at`; that cached response is not mining
  authority.
  `getparentauthority` is deliberately excluded and always reads one coherent
  live state.
- Native-sync diagnostics distinguish active-state, observe-only, and
  headers-only operation and report
  committed blocks, reorganizations, contextual-invalid bodies, durable
  address-book load/prune/generation/flush state, and an opaque process-local
  runtime instance used to correlate restart evidence.
- Optional whole-listener Authorization enforcement from
  `--rpc-authorization-header-file`. The absolute nonsymlink file must be
  private and contain one 1..=4,096-byte visible-ASCII header value such as
  `Bearer ...`, with no leading/trailing whitespace. One terminal LF or CRLF
  is removed; other whitespace/control/Unicode input is not normalized.
  When configured, every JSON-RPC and diagnostic route rejects missing or
  unequal values with HTTP 401. Secrets are redacted from Debug output.
- Authenticated active-state native sync exposes `POST /api/v1/wallet` only
  when both the exact Authorization header and durable `--wallet-index` profile
  are configured. Headers-only/observe-only operation and loopback are not
  sufficient. Its v1 envelope projects the typed
  wallet backend without a Rust sibling dependency: chain/tip reads, global
  confirmed restoration, chain-epoch/restart-bound mempool pages, transaction,
  ordered batch spender, canonical current/proof-name evidence, and exact
  chain/mempool-bound TRANSFER/FINALIZE preparation contexts, fee
  estimation, signed-transaction broadcast, and opaque tracked
  contract evidence. See [`WALLET_RPC_V1.md`](WALLET_RPC_V1.md).
- `broadcast_transaction` is the sole wallet mutation. It accepts only a
  canonical already-signed transaction, enters the same bounded contextual
  mempool admission path as peer transactions, and reports actual inventory
  fanout. Diagnostic-only mode and any listener without explicit
  authentication leave the wallet route unrouted and cannot parse wallet
  requests.

## Dispatch complexity and resource envelope

The durable lookup costs below exclude the bounded cost of decoding the one
record that was selected. `B` is the requested block size, `T(B)` its
transaction count, and `M` the returned mempool size.

The resident header graph keeps the canonical chain proportional to best height
and caps competing or stale headers at exactly 1,000,000. Both the current
alternate count (`records.len() - canonical.len()`) and each admission check are
`O(1)`; bounded batch/reorganization work is checked before durable or cache
mutation, and strict startup reconstruction refuses an over-budget graph.

| Method family | Durable access | Time | Additional space |
| --- | --- | --- | --- |
| chain tip/count/network metadata | fixed metadata keys or cached diagnostics | `O(1)` | `O(1)` |
| `getblockhash`, `getblockheader` | one locked generation of the shared canonical-header index | `O(1)` lookup and selected-record clone | `O(1)` |
| `getblock` | block-index and payload point reads | `O(log N + B)` | `O(B)` |
| confirmed `getrawtransaction` | tx index, canonical index, and one block point read | `O(log N + T(B))` | `O(B)` |
| `gettxout`, name methods | UTXO/name-state point read | `O(log N)` | `O(1)` plus result |
| `getdnsresource` | one name-state read plus fixed chain-generation metadata from one snapshot | `O(log N)` | `O(R)`, with resource `R <= 512` bytes |
| `getmempoolinfo` | exact cached aggregate | `O(1)` | `O(1)` |
| `getrawmempool` | `O(1)` persistent-AVL generation capture, then bounded immutable ID walk after coordinator release | `O(M)` response (`O(log M)` concurrent pool mutation) | `O(M)` response; retained generations share untouched subtrees |
| `getparentauthority` | fixed metadata/header keys under one coordinator epoch | `O(log N)` | `O(1)` |
| wallet confirmed/script/contract pages | chain-epoch/query-bound wallet indexes under stricter wire limits | bounded by 256 script-prefix examinations or 256 returned rows | at most 8 MiB projected JSON plus opaque cursor |
| wallet mempool pages/fee estimate | immutable chain-epoch/tip plus process-instance/generation capture | at most 1,024 inspected transactions per wire page; fee sample remains 4,096 | at most 8 MiB projected JSON |
| wallet point/batch evidence | fixed metadata/index keys, at most one retained block transaction lookup, or up to 256 ordered spend-index reads | point/collection reads plus selected payload | selected bounded result under one chain epoch/tip |
| wallet name-action context | fixed network/genesis/name params, current name/UTXO/owner and renewal-height point reads plus immutable mempool spender index | point reads plus O(log M) exact owner-spender lookup; fixed at most nine eligibility reasons | one selected owner transaction under the 8 MiB result ceiling |

Both standalone and native-sync listeners enforce the same fail-closed limits:

- `--rpc-max-request-bytes`, default 65,536 and hard maximum 1,048,576.
  Axum rejects a larger decoded body with HTTP 413 before JSON parsing.
- `--rpc-max-concurrent-requests`, default 32 and hard maximum 256. Excess
  work receives HTTP 429 rather than waiting in an unbounded queue.
- `--rpc-execution-timeout-ms`, default 5,000 and hard maximum 30,000. An
  expired request receives HTTP 504.
- `--rpc-max-collection-entries`, default 50,000 and hard maximum 250,000.

Durable point reads and material collection/encoding work run on the bounded
blocking pool rather than a Tokio executor thread. Point reads and collection
walks have distinct owned capacity permits, each bounded by the configured
request concurrency. The permit stays inside the worker through response
construction, so an HTTP timeout cannot release point-read or collection
capacity while its non-cancellable work is still finishing. Authorization
middleware remains outside these resource layers, so an unauthenticated client
is rejected before it can occupy RPC execution capacity.

The wallet route strengthens that general policy: it is installed only when an
Authorization header file was explicitly configured, even when the listener is
loopback-only. It also requires the complete wallet profile and native runtime.
Its opaque cursors and backend calls retain their additional script, page,
prefix-examination, result, and process-generation bounds. Opaque cursors are
behaviorally hidden/query-bound traversal hints, not secrets or authenticated
capabilities. Every JSON result is encoded and measured before publication and
fails with a stable error above the 8 MiB transport budget.

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

- submit one already-signed wallet transaction through canonical contextual
  admission and live peer fanout (implemented only in authenticated wallet
  RPC v1);
- submit a test/raw block through the same consensus candidate path;
- add/remove an operator-pinned peer;
- initiate graceful shutdown or a bounded diagnostic snapshot.

Wallet signing/custody, execution of domain actions, contract registration through the wire,
an embedded DNS listener, explorer/address queries, public mining RPC, and
broad hsd tooling compatibility are deliberately unsupported. The narrow
`getdnsresource` read exists only for the separate resolver boundary; wallet
RPC v1 is a distinct authenticated API rather than hsd JSON-RPC compatibility.
