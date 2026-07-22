# P2P and synchronization

## Scope

The shadow-sync runtime gives `hsrd` a live, bounded Handshake network path while
preserving its pre-authority status. The runtime can discover chain progress
from explicit peers, validate and retain headers and block bodies, serve
retained data, and resume from a durable checkpoint after restart.

The default remains an **observation-only shadow path**. A
`--shadow-sync-headers-only` qualification mode validates and durably indexes
canonical headers without scheduling block bodies, which is useful with a
pruned HSD reference or when proving checkpoint/deployment ancestry. An
explicit `--shadow-sync-active-state --acknowledge-incomplete-consensus` mode
additionally connects stored bodies to active UTXO/name state in bounded atomic
batches. All modes are non-authoritative: shadow state cannot authorize mining
templates, publish ASIC jobs, or mint the private mining capability.

## Runtime flow

```text
explicit outbound peers / optional listener
                    |
                    v
        bounded plaintext HNS peer sessions
                    |
          VERSION / VERACK / SENDHEADERS
                    |
                    v
          headers-first synchronization
                    |
          durable best-header selection
                    |
                    v
       bounded block-body download scheduler
                    |
                    v
   spawn_blocking stateless body-validation workers
                    |
         ordered validation-result sequencer
                    |
                    v
  authenticated invalid / invalid-child classification
                    |
                    v
       durable non-active shadow block storage
                    |
                    v
 optional bounded contextual state connector
                    |
                    v
        restartable sync checkpoint + diagnostics
```

Socket tasks decode bounded packets and emit peer events. They do not validate
consensus or write databases. CPU-heavy block-body checks execute in dedicated
blocking workers. The node coordinator alone imports headers and stores
validated bodies.

## Wire compatibility

`hns-p2p` implements the HSD frame format:

```text
u32le magic
u8    packet type
u32le payload length
bytes payload
```

The maximum payload is eight million bytes and is checked before allocation.
Packet and collection limits are explicit. The codec covers the
sync-relevant HNS packet set, including VERSION, VERACK, PING/PONG, ADDR,
INV/GETDATA/NOTFOUND, GETBLOCKS/GETHEADERS/HEADERS, BLOCK, TX, REJECT,
SENDHEADERS, MEMPOOL, and the bounded opaque forms required to reject or ignore
unsupported traffic safely.

The HSD fixture generator verifies subtle compatibility behavior:

- low service bits and reserved high service words;
- unsupported address-kind normalization;
- HSD `noRelay` interpretation;
- HSD ASCII high-bit clearing;
- locator, inventory, header, block, and reject encodings;
- exact 9-byte frame headers and network magic.

The runtime currently uses plaintext TCP only. Brontide is not implemented.

## Peer lifecycle

Each live peer has:

- direction and socket address;
- handshake state;
- advertised protocol, services, height, agent, and relay preference;
- bounded critical, control, and normal queues;
- byte counters and ping latency;
- a local misbehavior score;
- handshake, idle, ping, and pong timeouts.

The in-progress frame read is retained when ping, idle, or shutdown maintenance
runs. Tokio's exact-read future is not cancellation safe after consuming a
partial header or payload, so dropping and recreating that future would lose
stream bytes and eventually report a false network-magic mismatch.

Outbound peers must advertise `SERVICE_NETWORK`. Duplicate socket addresses are
rejected. One unpredictable process-local nonce is shared by local sessions, so
an outbound connection that reaches the node's own listener observes the same
nonce and fails the VERSION self-connection check. Peer limits are checked both
before a connection attempt and under the registration lock after connection.

A score of 100 disconnects the peer. The current score is process-local; durable
bans and a persistent peer database are future work.

## Queue and resource bounds

The shadow-sync runtime rejects configurations outside hard ceilings:

| Resource | Hard ceiling |
|---|---:|
| Total inbound + outbound peer slots | 256 |
| Stateless validation workers | 128 |
| Validation input/results queue | 8,192 |
| Retained orphan blocks | 8,192 |
| Retained orphan bytes | 1 GiB |
| Active-state blocks per atomic batch | 1,024 |
| Polling interval | at least 10 ms |

Default operational bounds are intentionally lower. Each peer also has
separate outbound queue capacities, while synchronization limits pending,
inflight, and per-peer block requests.

The critical lane is reserved for future solved-block publication and supports a
bounded waiting send. Ordinary body serving uses the normal lane and cannot
consume critical-lane slots.

## Header synchronization

The scheduler selects ready network-service peers and sends GETHEADERS using an
exponential block locator. Header batches are limited to the HNS protocol
maximum. Every unknown header is checked for:

- parent availability;
- expected height;
- expected difficulty bits;
- median-time-past and future-time constraints;
- proof of work;
- unsigned cumulative chainwork.

Valid headers are persisted in atomic protocol batches of at most 2,000. Every
batch is contextually validated against one stable resident header-index view
plus its earlier staged predecessors; one RocksDB batch then commits all
records and the final best-header binding before the compact in-memory delta is
published. A late invalid header or failed commit therefore accepts none of
that batch. The runtime yields to the supervisor between protocol batches, so
shutdown may cancel only a later batch and restart resumes from the last
complete batch. The durable best header may advance ahead of block-body
availability. Equal-work branches preserve first-seen selection according to
the existing chain-index rules.

Headers-only mode is mutually exclusive with active-state connection. Its
diagnostic flag makes the reduced qualification scope explicit; it proves the
header, difficulty, timestamp, checkpoint, chainwork, and canonical ancestry
path, not block-body or state parity. Its scheduler reports `Synced` when the
best header reaches the peer target without pretending that stored-body or
active-state tips advanced.

`GET /api/v1/header-deployments` independently walks the canonical header
ancestry and replays every HSD BIP9 window. It reports threshold states,
deployment parameters, mandatory script and lock flags, deployment-derived
name/airdrop effects, the next-block version, and whether the exact final
checkpoint anchors HSD's historical script assumption. The derivation does not
consult the active-state deployment cache, so it remains useful as independent
qualification evidence in headers-only mode.

## Block-body synchronization

Canonical headers without stored bodies enter a bounded pending queue. Requests
are limited globally and per peer. All hashes selected for one peer in a poll
are encoded in one bounded HSD-shaped `GETDATA` inventory. Polling reserves the
individual hashes before transport admission; if that single packet cannot
enter the outbound queue, the exact batch is atomically restored without
consuming an attempt. A missing transport peer is removed from scheduler state
immediately, while queue saturation retains the live peer for a later retry.
Header-request admission is rolled back under the same rule.

HSD uses a 60-second response deadline for `GETHEADERS` and a 120-second block
deadline. The scheduler uses those defaults. A timed-out body batch requeues its
per-block work and emits only one disconnect for the peer, matching HSD's
connection-level stall handling instead of multiplying a score by the number
of hashes in the packet. Retry exhaustion remains tracked per block across
peer assignments.

The current scheduler keeps one in-flight request per block. A future latency
optimization may use bounded, staggered hedged requests: ask the preferred peer
first, admit at most one backup after a delay, accept the first fully valid
response, and cancel or ignore the loser without double-counting retries or
peer scores. Immediate unbounded request racing is intentionally excluded
because it would amplify bandwidth and blur timeout and unsolicited-response
accounting.

An unsolicited block is accepted only when it was already pending and the
sender was an eligible announcer. A body with no known header context is dropped
after requesting headers and applying a small protocol penalty; arbitrary
unvalidated bodies are never retained. When the block is on the durable
canonical header path, strict import validation rechecks that binding and may
atomically store its body and non-active index before its parent body arrives.
Ordinary block acceptance, active-state connection, and reorganization still
require the complete parent body/index chain. The contiguous stored tip stops at
the first gap and advances across already stored successors when the missing
body arrives, including after restart. A non-canonical descendant without its
parent body instead enters the bounded, oldest-first in-memory orphan pool after
stateless validation.

One bounded reservation follows each body across pending, network inflight,
validation, durable canonical retention, or orphan retention, preventing
duplicate downloads and preserving retry capacity while those states overlap.
Canonical acquisition is limited to the configured orphan-count horizon beyond
the contiguous stored-body tip; the window slides only as that tip advances, so
the canonical downloader alone cannot create an unbounded durable future-body
range.

A requested block `notfound` response is availability evidence, not proof of a
bad block or peer. The scheduler accepts it only from the peer that owns the
inflight request, records it separately, excludes that peer for the hash for
the rest of that peer connection, and immediately permits another peer without
consuming the transport or validation retry budget. An unsolicited or
cross-peer `notfound` cannot cancel another peer's request.
An already in-transit response for a bounded pending hash remains admissible and
fully validated if it reaches the scheduler before the timeout's peer
disconnect is applied.

The stateless validation worker first authenticates both body roots against the
known header. Above the final checkpoint it then verifies full block-body
syntax. At HSD historical heights it instead retains the always-on transaction
start, name DoS limits, and coinbase-height checks while deferring body sanity;
the worker has height but not sufficient branch evidence to make a durable
checkpoint decision. A body is then revalidated through the node's strict
import path, where exact final-checkpoint ancestry selects the historical route
or fails closed to full validation, and is stored as a non-active block/index
record. The shadow-sync path explicitly clears UTXO, name-state, tree-root,
undo, and active-chain status bits. Retaining an orphan completes the temporary
validation stage without advancing the contiguous stored-body tip.

A body that does not match its header is a retryable bad peer response, not
proof that the header branch is invalid. A worker crash is also retryable and
is requeued without changing peer-failure accounting. Only a body whose merkle
and witness roots match the header but still fails deterministic validation is
permanent: its durable header/block status and every known descendant are
marked failed in the same batch as best-header fallback. The scheduler removes
queued work for every affected descendant, the failed branch remains excluded
after restart, its orphan descendants are discarded, and the remote peer earns
a score of 100. Local orphan re-submission is never penalized as a network peer.

## Optional active-state connector

The active-state mode is opt-in while historical and live parity gates remain
open. It requires the explicit incomplete-consensus acknowledgement and is
bounded to 288 connected blocks per atomic reorganization by default, matching
mainnet's retained reorganization window (hard maximum 1,024). Straight-line
IBD progress is additionally limited to eight connected blocks per supervisor
slice so RPC, peer work, and shutdown are polled between small atomic commits.
Each batch uses the node's existing deployment, script, sequence-lock,
claim/airdrop, covenant, UTXO, name-state, Urkel-root, undo, and reorganization
pipeline; no second consensus implementation exists in the sync runtime. The
connector carries the one HSD historical/full route chosen by strict import.
The historical route is available only after the candidate and exact final
checkpoint are bound to the same best validated header path; otherwise every
stage runs on the full path.

```bash
cargo run --locked -p hns-node -- \
  --shadow-sync --connect 127.0.0.1:12038 \
  --shadow-sync-active-state --acknowledge-incomplete-consensus \
  --active-state-connect-batch 288
```

On restart and every supervisor tick, the connector compares the active tip
with the highest contiguous stored canonical body. Direct progress advances in
at-most-eight-block atomic slices even when the configured bound is larger. A
best-work fork is disconnected and connected atomically once its bounded
replacement prefix exceeds active chainwork; it may use the full configured
bound because yielding partway through a reorganization would violate the
single-commit invariant. Shutdown therefore returns between direct slices but
waits for an already staged reorganization commit. Deep replacements that
cannot exceed the active tip within the configured batch fail closed and
require an operator-selected larger bound.

Candidate-derived contextual failures carry the exact failing block back out of
the staged reorganization. That root and every known descendant are durably
failed before best-header fallback. Storage, authenticated-tree, verifier
backend, chain-view, and undo failures are local faults: they terminate active
sync without marking any peer branch invalid. Because an older stored block may
be identified only when a later tip triggers reorganization, the connector does
not guess a peer attribution for delayed contextual failures.

## Restart and checkpoint semantics

A versioned sync checkpoint (retained by the current schema 14/profile `hsrd-mining-v10`) contains:

- monotonically increasing sequence;
- stage;
- best header;
- active tip;
- contiguous stored-body tip;
- target peer height;
- update time.

Startup never trusts the checkpoint blindly. It reloads durable chain state,
verifies canonical body continuity, and recomputes the stored-body tip. Missing
canonical bodies are requeued. A `Validating` checkpoint resumes as `Blocks`
because in-memory validation jobs are not durable.

When active-state mode is enabled, stored-but-unconnected canonical bodies are
also resumed through the bounded connector before normal polling. The active tip
and advertised local height advance only after the complete state batch commits.

The supervisor writes clean-shutdown metadata only if shutdown was requested
normally and both the RPC server and optional P2P listener terminate
successfully. Unexpected channel or task termination leaves the store marked
unclean.

## Serving behavior

Ready peers may request:

- headers following a locator;
- block inventory following a locator;
- retained block bodies;
- an empty address response;
- bounded transaction inventory and accepted mempool transactions when the mining engine
  is enabled.

Serving is read-only. Mining-engine peer transaction admission remains fail closed
until the complete contextual verifier is composed; unsupported relay behavior
is not silently emulated. Requests are bounded below the wire protocol maxima
to limit local work and queue occupation. Ordinary serving uses noncritical
lanes and cannot consume solved-block publication capacity.

## Diagnostics

The shadow-sync API exposes:

```text
GET /api/v1/status
GET /api/v1/authority
GET /api/v1/parity
GET /api/v1/peers
GET /api/v1/sync
GET /api/v1/shadow-sync
GET /api/v1/header-deployments
```

Diagnostics include configured endpoints, reconnect attempts, live peer
snapshots, synchronization stage, best/active/stored tips, queue depths, orphan
usage, received/served counts, durably failed-body count, checkpoint sequence,
active-state connection/reorganization counts, contextual-failure count, and
the last supervisor error. API-v9 node status separately counts valid non-active
blocks and durably failed blocks and exposes the active tip's resulting
authenticated root/height. The shadow endpoint includes an opaque runtime
instance so external evidence can distinguish observations across restarts.

`observation_only` is true in the default retention mode and false only when the
explicit active-state connector is enabled. `active_state` reports that choice.
`headers_only` reports the narrower no-body qualification mode. None of these
values changes the authority mode or claims a live HSD oracle.

`scripts/compare-hsrd-hsd-shadow.py` consumes those diagnostics and a pinned
operator-selected `hsd-cli`. It compares the canonical block at height `H` and
the post-`H` hsrd root against HSD's header at `H+1`; at the live tip it labels
HSD's next-template root provisional until a later header confirms it. The
runner rereads both tips around every bounded probe, records coherent
divergence separately from unavailable/racing observations, and can maintain a
checksummed bounded restart/reorganization evidence checkpoint. See
[`live-shadow-parity.md`](live-shadow-parity.md).

With `--headers-only`, the same runner instead compares the durable hsrd
best-header height/hash with `getblockhash` from a coherent pinned HSD RPC
snapshot. At the current tip it also compares the header-derived deployment
states and script-policy effects with HSD's softfork view.
`--require-current-tip` fails unless both heights and both deployment views
match. This mode deliberately rejects `--state-file`, whose schema records
active block/root evidence rather than header-only evidence.

## Known limitations

The shadow-sync runtime does not yet provide:

- Brontide transport;
- DNS seed or address-manager discovery;
- durable peer scoring or bans;
- transaction and mempool relay;
- compact-block reconstruction;
- historical mainnet block-body and active-state replay qualification;
- persistent pruning-horizon discovery plus full pruning and
  sustained-reorganization IBD qualification;
- solved-block fan-out;
- mining authority.

Those omissions are reported rather than hidden. The comparison runner supplies
the live observation mechanism, not the full-mainnet duration, pruning, or
reorganization coverage required for sustained HSD shadow agreement.
