# P2P and synchronization

## Scope

The shadow-sync runtime gives `hsrd` a live, bounded Handshake network path while preserving
its pre-authority status. The runtime can discover chain progress from explicit
peers, validate and retain headers and block bodies, serve retained data, and
resume from a durable checkpoint after restart.

It is an **observation-only shadow path**. It does not connect downloaded blocks
to active UTXO/name state, authorize mining templates, or publish ASIC jobs.
That separation is deliberate: network availability evidence must not bypass
unfinished consensus and historical-parity gates.

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
       durable non-active shadow block storage
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

Valid headers are persisted individually. The next in-memory header-index view
is published only after its matching durable batch commits. If a later header
in one peer batch is invalid, any valid durable prefix remains accepted, the
scheduler refreshes from durable state, and the sender is disconnected. The
durable best header may advance ahead of block-body availability. Equal-work
branches preserve first-seen selection according to the existing chain-index
rules.

## Block-body synchronization

Canonical headers without stored bodies enter a bounded pending queue. Requests
are limited globally and per peer. Timeouts increase peer failures, requeue work
onto other eligible peers, and eventually disconnect a peer after the retry
budget is exhausted.

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
unvalidated bodies are never retained. If the block's own header is known but
its parent body is not yet available, the body is statelessly validated before
entering the bounded orphan pool. Orphans are evicted oldest-first when limits
are reached.

The stateless validation worker verifies block-body syntax and commitments. A
valid body is then revalidated through the node's strict import path and stored
as a non-active block/index record. The shadow-sync path explicitly clears UTXO,
name-state, tree-root, undo, and active-chain status bits. Retaining an orphan
completes the temporary validation stage without advancing the contiguous stored
body tip.

A permanently invalid body earns a score of 100 and disconnects the remote
peer. Local orphan re-submission uses a synthetic local peer identifier and is
never penalized as a network peer.

## Restart and checkpoint semantics

A versioned sync checkpoint (retained by the current schema 13/profile `hsrd-mining-v9`) contains:

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
```

Diagnostics include configured endpoints, reconnect attempts, live peer
snapshots, synchronization stage, best/active/stored tips, queue depths, orphan
usage, received/served counts, checkpoint sequence, and the last supervisor
error.

`observation_only` is always true. The parity state explicitly says that no live
HSD oracle is configured.

## Known limitations

The shadow-sync runtime does not yet provide:

- Brontide transport;
- DNS seed or address-manager discovery;
- durable peer scoring or bans;
- transaction and mempool relay;
- compact-block reconstruction;
- active-state ordered block connection;
- historical mainnet replay qualification;
- a live HSD state/root comparison feed;
- pruning-aware IBD;
- solved-block fan-out;
- mining authority.

Those omissions are reported rather than hidden. The next authority-relevant
step is not merely more networking: it is complete consensus connection and
sustained HSD shadow agreement over the downloaded chain.
