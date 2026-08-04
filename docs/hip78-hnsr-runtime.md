# HIP-78 HNSR requester and opaque relay

The native P2P runtime enables the HNSR requester and opaque circuit-relay
policies by default. Operators can independently opt out with
`--no-hnsr-requester` and `--no-hnsr-relay`, explicitly reverse saved choices
with `--hnsr-requester` and `--hnsr-relay`, or use no policy flag to preserve
the durable selections. The CLI keeps the node-supported capability ceilings
available so a live or later-start re-enable remains possible. Embedded callers
use the public `hns-p2p` coordinator and live-manager APIs.
Endpoint/output-node and rendezvous roles are unavailable, and plaintext peers
are never eligible.

Policy enablement is not provider availability. A local relay service is
created and advertises `HNSR_RELAY_SERVICE` only when the operator supplies
`--hnsr-relay-address`, the address passes the network's public/private policy,
and a durable Brontide identity is available. Withdrawing the role changes the
service mask for future VERSION handshakes and retires the bounded live peer
set so reconnects cannot retain a stale advertisement.

Relay tickets are signed by that durable Brontide identity. Canonical requester
admission requires the ticket relay key to equal the authenticated outer
Brontide static key; an independent relay scalar would break that binding and
is therefore neither configured nor persisted.

Every circuit path is bound to the exact Brontide-authenticated connection,
canonical Denuo V1 registry fingerprint/version/protocol tuple, matching
network and genesis, nonzero negotiated limits, and one explicit canonical
profile. Native nodes default to `HNS_NODE_V1`; embedded browser adapters set
`HNS_WEB_V1`. The selected profile is bound into requester admission, relay
support, status, and durable configuration identity.
Requester selection additionally requires the remote HNSR relay service bit.
Incoming requesters and endpoints need Denuo admission but do not impersonate
a provider by advertising that bit. Connection IDs, not socket addresses, own
reservations and circuits.

Packet `0xf3` is bounded before allocation and decoded strictly by the pinned
`hns-hnsr-protocol` crate. Context ownership selects exactly one requester or
relay state machine; ambiguous DATA/WINDOW/CLOSE/ERROR packets are rejected.
Opaque relay routes remain charged until the destination writer acknowledges
the actual socket write. A failed or timed-out critical write retires the exact
connection and revokes affected circuits. Disconnect, Denuo loss, reservation
removal, expiry, and policy replacement clear connection-bound authority.

Only policy, counters, generation floors, configuration identity, and trusted
time cross restart. Checksummed `hnsr-runtime-state/v1` and
`hnsr-durable-floor/v1` records commit in one atomic batch and must appear as a
matching pair. Restore uses a fresh process session, advances upstream
requester and relay generations, counts formerly live work as revoked, and
rejects corruption, wrong network/configuration, generation rollback, or clock
regression. Reservations, circuit IDs, queued opaque bytes, action tokens, and
authenticated peer authority are never restored.
Explicit startup overrides advance the restored coordinator generation and are
flushed before peer networking. Absent overrides preserve the saved requester
and opaque-relay bits. Live replacements remain clamped by the immutable
embedding capability ceilings and cannot activate endpoint or rendezvous
roles.

The public authenticated experimental-evidence getter exposes the exact
upstream `ExperimentalPeerState` and `NegotiatedRegistry` keyed by Brontide
static key. The raw bounded exchange seam provides exact peer/packet-type
correlation for other browser and mobile extension profiles. It rejects packet
types owned by the built-in Denuo, HIP-76, ODoH, and HNSR runtimes, preserving
exactly one state owner for each protocol. Public key-bearing HSD fixed seeds
support authenticated bootstrap. Standalone `hns-p2p` uses RustCrypto
ChaCha20-Poly1305 and disables the full node's optional OpenSSL
consensus-verifier feature.
