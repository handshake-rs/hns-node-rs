# P2P and synchronization

## Scope

The native-sync runtime gives `hsrd` a live, bounded Handshake network path with
no HSD runtime dependency. It discovers chain progress from authenticated
peers, validates and retains headers and block bodies, connects active UTXO and
name state, serves retained data, and resumes from a durable checkpoint.

`--native-sync` downloads bodies and connects active state by default.
`--native-sync-headers-only` narrows operation to canonical headers, while
`--native-sync-observe-only` downloads bodies without connecting them. Native
operation does not by itself grant mining authority: the separate readiness
gate and the durable tip's complete consensus-authoritative status remain
mandatory.

## Runtime flow

```text
explicit outbound peers / optional listener
                    |
                    v
 authenticated Brontide HNS peer sessions
                    |
     VERSION / VERACK / SENDHEADERS / SENDCMPCT
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
        durable validated block storage
                    |
                    v
   bounded contextual active-state connector
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
SENDHEADERS, MEMPOOL, SENDCMPCT, CMPCTBLOCK, GETBLOCKTXN, and BLOCKTXN.
Remaining bounded opaque forms are retained only where safe rejection or ignore
behavior is intentional.

The HSD fixture generator verifies subtle compatibility behavior:

- low service bits and reserved high service words;
- unsupported address-kind normalization;
- HSD `noRelay` interpretation;
- HSD ASCII high-bit clearing;
- locator, inventory, header, block, and reject encodings;
- compact-block negotiation, 48-bit short IDs, differential indexes, and
  prefilled/missing transaction encodings;
- exact 9-byte frame headers and network magic.

Mainnet and testnet wrap each complete nine-byte HNS frame plus payload in HSD's
Brontide stream records. The implementation is pinned to Noise XK over
secp256k1, HSD's Elligator-Squared encoding, SHA256/HKDF,
ChaCha20-Poly1305, four-byte little-endian stream lengths, and key rotation
after 1,000 AEAD records. Regtest and simnet retain plaintext TCP for local
development. The fixture generator checks HSD's exact cipher, split-key,
traffic, rotation, and fixed-seed vectors.

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

Misbehavior score is connection-local, matching HSD. Crossing score 100 creates
a 24-hour ban for the normalized IP address, disconnects every live session
from that IP, and rejects both outbound sockets and inbound registration before
the VERSION handshake. An explicit `--connect` target does not bypass a ban.
The HSD expiry boundary is preserved: the address remains banned while the
current Unix second is equal to `ban_until` and becomes eligible after it.

With `--data-dir`, the bounded 16,384-entry IP ban list is written immediately,
retried with the peer-state flush cadence after a storage failure, compacted as
entries expire, and flushed again at shutdown. Its record is checksummed,
versioned, and network-bound. Corrupt record bytes are reported and replaced;
a store read failure aborts startup. Subthreshold scores deliberately remain
connection-local rather than becoming invented long-lived reputation.

## Queue and resource bounds

The native-sync runtime rejects configurations outside hard ceilings:

| Resource | Hard ceiling |
|---|---:|
| Total inbound + outbound peer slots | 256 |
| Stateless validation workers | 128 |
| Validation input/results queue | 8,192 |
| Retained orphan blocks | 8,192 |
| Retained orphan bytes | 1 GiB |
| Pending compact blocks per peer | 15 |
| Pending compact blocks globally | 128 |
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

HSD uses a 60-second response deadline for `GETHEADERS` and a conservative
120-second block deadline. Native IBD retains the header deadline but fails a
stalled block connection over after 15 seconds of body inactivity so one slow
peer cannot pin the contiguous state frontier for two minutes. Each eligible
block response advances that peer's progress timestamp; an absolute per-item
deadline therefore cannot disconnect a peer that is still draining its bounded
batch. A timed-out body batch requeues its
per-block work and emits only one disconnect for the peer, preserving HSD's
connection-level stall accounting instead of multiplying a score by the number
of hashes in the packet. Retry exhaustion remains tracked per block across
peer assignments. A new connection receives only one body probe until it
delivers an eligible block. That proof expands its window to the configured
32 requests; silent or non-archival peers therefore cannot reserve most of the
128-request global limit merely by completing the transport handshake.

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
import path, where ancestry to the nearest configured checkpoint at or above
the candidate selects the historical route or fails closed to full validation,
and is stored as a non-active block/index
record. Pre-connection body storage explicitly clears UTXO, name-state,
tree-root, undo, and active-chain status bits; the native connector sets them
only after contextual state validation commits. Retaining an orphan completes the temporary
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

### Compact-block relay

On Ready, the runtime advertises compact-block version 1 in request-only mode.
A peer becomes compact-capable only after sending a valid version-1-or-earlier
`SENDCMPCT`; unsupported versions are ignored. Body dispatch then requests the
compact inventory kind from capable peers and retains full-block requests for
all other peers.

Incoming compact blocks derive the BIP152 SipHash key from the encoded HNS
header and the peer's eight-byte nonce, then resolve 48-bit short IDs from the
mining engine's bounded mempool snapshot. Complete reconstructions enter the
normal stateless validation and ordered import path. Otherwise the runtime
sends one exact differential-index `GETBLOCKTXN` and fills the missing slots
from the owning peer's `BLOCKTXN` response. Pending reconstructions are bounded
to 15 per peer and 128 globally, use HSD's 30-second block-transaction response
deadline, and are removed on disconnect.

Malformed layouts and unavailable requested blocks use HSD's score-100 path.
Duplicate compact short IDs, mismatched responses, and other recoverable
reconstruction failures earn 10 points and fall back to the already reserved
full-block request without widening scheduler admission. A different peer
cannot complete or cancel another peer's pending reconstruction.

For negotiated peers, compact `GETDATA` requests are served with a fresh random
nonce and the coinbase prefilled. `GETBLOCKTXN` is answered only for retained
blocks within HSD's recent 15-block window and never returns more transactions
than the 16,662-transaction compact-block protocol bound. Non-capable peers and
headers-only operation retain full-block behavior.

## Native active-state connector

Active-state connection is the native-sync default and is bounded to 288
connected blocks per atomic reorganization by default, matching
mainnet's retained reorganization window (hard maximum 1,024). Straight-line
IBD progress is limited to eight connected blocks per state transaction so
RPC, peer work, and shutdown are polled between small atomic commits. A valid
body completion is durably sequenced without recursively entering the state
writer. Network maintenance retains its configured polling cadence. A separate
10 ms minimum activation cadence connects exactly one slice per scheduler turn
and delays its next tick after an overrun, leaving an inter-slice opportunity
for peer events, validation results, and shutdown. This prevents a full stored
buffer from monopolizing the supervisor without making the general polling
interval a replay throughput ceiling.
Each batch uses the node's existing deployment, script, sequence-lock,
claim/airdrop, covenant, UTXO, name-state, Urkel-root, undo, and reorganization
pipeline; no second consensus implementation exists in the sync runtime. The
connector carries the one HSD historical/full route chosen by strict import.
The historical route is available only after the candidate and exact final
checkpoint are bound to the same best validated header path; otherwise every
stage runs on the full path.

```bash
cargo run --locked -p hns-node -- \
  --network mainnet --authority-mode native \
  --rpc-authorization-header-file /absolute/private/hsrd-authorization-header \
  --native-sync --p2p-discovery \
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

A versioned sync checkpoint (retained by schema 19/profile
`hsrd-mining-v15`) contains:

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
successfully. The clean marker and exact startup-audit commitment are one atomic
store batch. On entry the next process marks the store unclean before beginning
recovery validation, so a crash during a long audit cannot preserve the prior
clean state. Unexpected channel or task termination leaves the store marked
unclean and forces the exhaustive recovery path. A matching clean checkpoint
uses keyed canonical reads to audit the complete network reorganization/undo
horizon rather than scanning all historical bodies. Unclean and stale
checkpoints still force the full materialized-state, retained-tree, active-chain,
deployment, and undo audit.

## Serving behavior

Ready peers may request:

- headers following a locator;
- block inventory following a locator;
- retained full or compact block bodies and recent missing block transactions;
- an empty address response;
- bounded ordinary/claim/airdrop inventory and accepted mempool transactions,
  DNSSEC claims, or airdrop proofs when the mining engine is enabled.

Serving is read-only. When explicitly enabled, ordinary peer transactions are
admitted against one immutable active-chain UTXO/deployment/name snapshot with
the native script verifier, HSD's minimum relay fee, deterministic name-overlay
replay, and bounded orphan promotion. Typed HSD airdrop packets are admitted
against next-block airstop/hardening/GooSig flags, native proof verification,
the durable spent-allocation field, and an unconfirmed position index; accepted
inventory is served back through GETDATA. The compatibility admission API
remains fail closed. Typed HSD claim packets use their exact length-prefixed
ownership-proof envelope; admission verifies native DNSSEC, proof time against
the active parent header, deployment flags, reserved-name lifecycle, canonical
commit ancestry, replacement value/frequency, and shared mempool name
exclusivity before relaying the claim inventory hash.
Requests are bounded below the wire protocol maxima to limit local work and
queue occupation. Mempool serving uses noncritical lanes and cannot consume
solved-block publication capacity.

## Diagnostics

The native-sync API exposes:

```text
GET /api/v1/status
GET /api/v1/authority
GET /api/v1/parity
GET /api/v1/peers
GET /api/v1/sync
GET /api/v1/native-sync
GET /api/v1/header-deployments
```

Diagnostics include configured endpoints, reconnect attempts, live peer
snapshots, synchronization stage, best/active/stored tips, queue depths, orphan
usage, compact-capable peers, pending/received/reconstructed/fallback compact
blocks, served compact blocks and block transactions, ordinary received/served
counts, durably failed-body count, checkpoint sequence,
active-state connection/reorganization counts, contextual-failure count, and
monotonic process-lifetime sent/received byte totals. Active-state diagnostics
also report slice count, blocks, total duration, planning/state-commit/post-commit
phase durations, and peer-event/validation-result channel backlogs. Final peer counters move
atomically into retired-session totals before peer removal, so rotation cannot
make traffic evidence regress. Each scheduler peer also exposes
`body_available`, distinguishing a transport-ready peer from one that has
actually delivered an eligible body. The diagnostics also expose the last
terminal/internal supervisor error. Expected peer churn, stale
alternate-peer deliveries, invalid peer data, and transient relay races are
logged as warnings and reflected by their dedicated peer/rejection counters;
they do not poison `last_error` after healthy synchronization continues.
Discovery diagnostics additionally expose durable
address-book availability, loaded/pruned counts, generation, dirty state,
successful/failed flushes, decode failures, the last flush time, and its last
storage error. API-v10 node status separately counts valid non-active blocks and
durably failed blocks and exposes the active tip's resulting authenticated
root/height. The native endpoint includes an opaque runtime instance so external
evidence can distinguish observations across restarts.

Authenticated status, authority, parity, and mining-engine diagnostics remain
available during serialized replay and name-tree compaction. They return a
constant-payload snapshot captured after the last committed active-state slice;
`diagnostic_snapshot_cached` identifies a lock-busy response and
`diagnostic_snapshot_captured_at` gives its Unix capture time. RPC binds before
startup replay so startup compaction is observable. This cache is diagnostic
only: `getparentauthority` and every authority-bearing mining decision require
the coherent live node lock and are never served from it.

`observation_only` is false for the native default and true only under
`--native-sync-observe-only` or `--native-sync-headers-only`. `active_state`
reports that choice, while `headers_only` reports the narrower no-body mode.
None of these values changes the authority mode or claims a live HSD oracle.

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

## Peer discovery

`--p2p-discovery` opts into the key-bearing fixed-seed tables pinned from HSD,
then uses GETADDR/ADDR for additional records. Mainnet starts with ten
authenticated endpoints on port 44806; testnet starts with four on port 45806.
Regtest and simnet have no fixed seeds, so discovery alone is rejected there.

The address book has an operator-configured bound (4,096 by default,
16,384 hard maximum). Public networks accept only compressed-key-bearing IP
addresses advertising the network service, rejects unroutable ranges and the configured
listener, and normalizes missing or future timestamps with HSD's five-day
fallback. Explicit `--connect` addresses are protected reconnect targets.
On mainnet/testnet they use `KEYHEX@IP:PORT` so the remote Brontide static key
is authenticated before VERSION; keyless public-network endpoints fail
configuration. Regtest/simnet continue to accept plain `IP:PORT` targets.
Discovered targets fill only unused outbound slots and rotate after three
consecutive connection failures; they cannot displace explicit targets.
Selection matches HSD's canonical network groups: IPv4 and embedded IPv4
transition addresses use `/16`, ordinary IPv6 uses `/32`, Hurricane Electric
tunnels use `/36`, and Teredo uses its decoded client prefix. Discovery slots
and simultaneous socket attempts are unique by group. Explicit `--connect`
targets bypass the collision check to preserve operator intent, but an active
or immediately due explicit attempt reserves its group against discovered
targets. The API reports the number of groups represented by connected and
connecting outbound peers.
Active bans exclude every port on the IP from ADDR admission, selection, socket
attempts, and GETADDR replies. Learned endpoints for a newly banned IP are
removed; explicit endpoints remain configured but dormant until expiry and do
not consume a discovery slot while banned.
Ready protocol-v3-or-newer outbound peers receive one `GETADDR`. A peer's first
inbound `GETADDR` is answered with at most HSRD's 1,000-address wire bound;
outbound or repeated requests are ignored, matching HSD's anti-scraping rule.
The pinned HSD pool deliberately advertises only unkeyed plaintext addresses
and ignores keyed `ADDR` entries. Public-network hsrd remains Brontide-only, so
those unkeyed entries are rejected and counted rather than silently opening a
plaintext fallback. Key-bearing DNS seeds and explicit keyed `--connect`
targets are consequently the only public-network bootstrap sources.
Eligible discovery slots are refilled on every poll, and due sockets start
before potentially expensive historical active-state or body-queue scans.
Only a completed Ready handshake resets a target's connection-failure history.

For example, mainnet can bootstrap without hard-coded socket addresses:

```bash
hsrd --network mainnet --data-dir /path/to/hsrd \
  --authority-mode native --native-sync --p2p-discovery
```

When `--data-dir` is configured, the permission-checked Brontide static identity
is restart-durable. Discovered addresses, static keys, services, timestamps,
attempt counts, last success, and last attempt are stored in the `peers` column
family as one checksummed, versioned, network-bound snapshot. Explicit peers
remain configuration and are never written into the cache. The runtime flushes
dirty state every 120 seconds and on shutdown. Restore re-applies bounded
cooldowns and HSD's recent-attempt, 30-day horizon, three-attempt
never-successful, and ten-failure/seven-day stale rules. A malformed record is
reported and replaced from fresh discovery; a store read failure aborts
startup. Without `--data-dir`, discovery remains deliberately process-local and
performs no meaningless memory-store flushes.

The API reports address- and ban-persistence availability, loaded, pruned, and
expired counts, generations, dirty/flush state and errors, active banned IPs,
ban events, known/received/accepted/rejected/served addresses, resolved DNS
addresses, DNS failures, and discovered connection failures. Connection-local
subthreshold scores are not persisted.

## Known limitations

The native-sync runtime does not yet provide:

- long-lived subthreshold peer reputation;
- sustained adversarial qualification of its bounded ordinary,
  claim/airdrop, and solved-block relay paths;
- historical mainnet block-body and active-state replay qualification;
- persistent pruning-horizon discovery plus full pruning and
  sustained-reorganization IBD qualification;
- production mining authority before every readiness gate passes.

Those omissions are reported rather than hidden. The optional comparison runner
supplies external qualification evidence; it is not in the native sync runtime
or its consensus authority path.
