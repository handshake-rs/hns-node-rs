# Bounded Shakescape marketplace relay

`hns-shakescape-market-relay` is an isolated, noncustodial cache and abuse-policy
core for five independently enabled roles:

1. Handshake name-market listings/cancellations;
2. cross-chain market intents;
3. price observations and verified price rounds;
4. fill-grant/match rendezvous;
5. bounded swap-session status.

The default `NodeConfig` role mask is empty. An embedded native adapter must
explicitly enable roles and obtains the shared service through
`NodeRuntime::shakescape_relay`.

## Admission model

The relay is hash-first. A peer announces the exact kind, hash, signer,
sequence, creation/expiry bounds, and payload length. The store returns a
bounded fetch deadline only when the hash is absent. A payload is accepted only
for that live request and only when its metadata, length, and domain-separated
content hash match.

The core enforces:

- a 512 KiB default per-object ceiling;
- independent per-role object caps and one aggregate byte cap;
- hard caps for tracked peer identities, admitted-payload signer identities,
  and explicit signer-policy records, with bounded inactive-accounting
  eviction; pending-only signer identities are separately bounded by the
  pending-fetch cap and do not consume rate/sequence slots until payload
  admission;
- exclusive expiry and a maximum lifetime;
- duplicate suppression and per-signer sequence high-water while the bounded
  in-memory signer accounting is retained;
- fixed-window rates for every peer announcement/payload attempt and for
  admitted signer objects;
- per-signer role/object policy;
- pending-request timeouts;
- peer scoring, malformed strikes, and exponential bounded bans;
- hash-only fetch rather than automatic board enumeration.

Peer rate admission occurs before expiry work, shape validation, duplicate
classification, sequence checks, or payload matching. Invalid, stale,
duplicate, unsolicited, and mismatched attempts therefore consume the same
bounded peer budget as successful attempts. Shape, sequence, request, metadata,
length, and hash failures automatically add a malformed strike and lower the
bounded peer score; the strike threshold or minimum score triggers the same
progressive ban path. Successful payload storage raises the score within its
configured ceiling, so the score is enforced state rather than a diagnostic
claim.

Pending deadlines and retained-object expirations use ordered indexes. Peer
and signer admission also maintains ordered, eligibility-only eviction indexes
plus exact pending/active counts; identity churn therefore does not search the
peer-by-pending or signer-by-object Cartesian product while holding the relay
lock. Per-role pressure removes that role's oldest object, while aggregate-byte
pressure removes the deterministic global oldest across roles rather than
favoring an enum role. One operation removes only entries whose deadline has
passed, and each object is also removed from its ordered insertion index in
logarithmic time; admission does not perform a full pending/object expiry scan
on each attempt.

Brontide peer identity is used only for transport abuse accounting. It does not
make a listing, signer claim, price, fill grant, or swap status true.

The relay cache, pending requests, scores, bans, and sequence high-water marks
are process-local. Inactive signer-accounting eviction or restart can forget a
previous sequence. Sequence checks therefore suppress replays only within the
retained cache lifetime; they are not durable cancellation truth. Typed
adapters must reverify every object, and wallets must reconcile listings,
intents, grants, and sessions from signed objects plus current chain/local
state rather than deriving safety from this cache.

## Authority boundary

Canonical marketplace parsing and signature/semantic verification belong in
the pinned `hns-rs` protocol crate. An adapter must perform that verification
before passing exact canonical bytes to `ShakescapeRelayHandle::put`. The node core:

- does not sign messages or transactions;
- does not choose matches;
- does not calculate an authoritative price;
- does not hold keys, seeds, liquidity, or funds;
- does not automatically accept or execute swaps.

The active node transport and peer admission negotiate the exact Shakescape V1
registry and fingerprint. Native typed adapters are installed for both the
name market and the direct HNS/BTC market. They decode the canonical protocol,
verify signed listings, cancellations, takes, and session messages, serve
bounded inventory/get exchanges, and route funding, redeem, refund, and watch
status only after the corresponding signed session has been established. The
generic price-observation cache role still has no native peer-wire adapter;
enabling that role bit alone does not advertise an application protocol.

## Mobile rendezvous gateway profile

`--shakescape-mobile-rendezvous` is the fail-closed deployment profile for a
shared, always-on mobile board peer. It composes only implemented services:

- the typed name-market and direct HNS/BTC board relays;
- signed direct-offer cancellation, take, bilateral-session, and swap-status
  routing;
- an inbound Handshake/Brontide listener advertising the ordinary `NETWORK`
  service together with the Shakescape extension service;
- the bounded opaque HNSR relay, including the canonical Shakescape swap
  circuit profile.

The mode requires an absolute persistent `--data-dir`, `--p2p-listen`, and a
network-valid public `--hnsr-relay-address`. By default that public socket is
also the `--p2p-advertise` socket. It explicitly re-enables the durable HNSR
relay policy if an earlier run saved an opt-out. A private, unspecified,
zero-port, or otherwise unroutable mainnet/testnet advertised or relay address
is rejected by `--check-config` before storage or networking starts.

On each advertisement epoch the node sends one ordinary `ADDR` record to at
most eight ready outbound peers. The record contains the current timestamp,
`NETWORK | SHAKESCAPE`, the verified public IP and port, and a zero key. It
refreshes every 30 minutes. Stock HSD rejects keyed `ADDR` entries, so the
public listener accepts standard keyless Handshake framing as well as
Brontide. It remains legitimate because the endpoint really speaks
the Handshake protocol and includes the required `NETWORK` service. Exact
ShakeScape registry/network/genesis negotiation and signed board-message
validation gate board use above that transport. A TLS/HTTP reverse proxy is
not compatible; a forwarding service must preserve the raw TCP byte stream end
to end.

The mobile rendezvous profile keeps the default 32 total inbound slots but
reserves eight for keyless ShakeScape sessions. Brontide peers may occupy the
other 24. Keyless peers must complete ShakeScape registry negotiation within
the bounded Handshake and registry deadlines or release their reserved slot.
`--p2p-reserved-shakescape-inbound N` changes the reservation without raising
`--maximum-inbound`; `N=0` restores the shared inbound pool. A public relay
that has already filled all 32 slots needs one graceful restart after enabling
the reservation to establish the new split.

This profile is rendezvous in the product sense that separately connected
phones share one continuously reachable board and relay. It does not claim an
HNSR endpoint-directory role, does not publish wallet endpoint records, and
does not make the unused generic `Rendezvous` cache role functional. Until a
wallet endpoint/ticket exchange is installed, opaque circuit capability is
available at the node boundary but is not itself peer discovery.

Example:

```bash
hsrd \
  --network mainnet \
  --data-dir /absolute/path/on/persistent-volume/hsrd \
  --p2p-listen 0.0.0.0:12038 \
  --p2p-advertise "$PUBLIC_IP:12038" \
  --hnsr-relay-address "$PUBLIC_IP:12038" \
  --shakescape-mobile-rendezvous \
  --check-config
```

Set `PUBLIC_IP` to the actual public IPv4 address routed to the listener (or
pass a bracketed public IPv6 socket directly). The advertised address is never
inferred from the bind wildcard.

## Read-only offer-board HTTP snapshots

`--shakescape-board-http-bind 127.0.0.1:12039` optionally starts a separate
loopback-only listener with two routes:

```text
GET /api/v1/shakescape/direct-offers
GET /api/v1/shakescape/name-offers
```

The flag requires native sync and the cross-chain relay role. It rejects a
non-loopback or zero port and cannot share the broad RPC listener's address.
The listener defaults off. It does not mount JSON-RPC, wallet RPC, offer
publication, acceptance, or swap-session routes. Its bounded v1 JSON response
contains at most 100 currently reachable, unexpired, uncancelled signed HNS/BTC
direct offers, their exact base-unit amounts, a network name, a revision digest,
and a 20-second feed horizon. Its `Cache-Control` is `no-store`; clients must
check both the feed and each offer expiry. After a relay restart or owner
disconnect, an offer does not reappear until an owner re-proves it. The wallet
still re-fetches the exact signed offer before any acceptance.

The name route returns at most 100 unexpired, uncancelled, signed fixed-price
name listings from the existing name-market adapter, with listing ID, seller
key, canonical name, HNS price and marketplace fee in base units, and creation
and expiry times. It does not read a wallet index or expose the broad RPC.
The snapshot is an advertisement; a buyer wallet must verify the current
locked name coin against the signed HIP-0001 proof before purchase. It uses
the same 20-second feed horizon and `no-store` response policy. An exact-path
HTTPS proxy may expose both routes when the site runs on another host.

For a same-machine site preview, point its server-side reader to
`http://127.0.0.1:12039/api/v1/shakescape/direct-offers`. For a different
host, publish only the required board paths through a bounded HTTPS reverse proxy; keep the
node RPC private. The ordinary ShakeScape P2P listener remains raw TCP and is
not an HTTP upstream.

## Federation between rendezvous nodes

With `--shakescape-mobile-rendezvous` or all four typed relay flags
(`--shakescape-name-market-relay`, `--shakescape-cross-chain-relay`,
`--shakescape-rendezvous-relay`, and `--shakescape-swap-status-relay`), federation
is on automatically when P2P discovery is enabled. The individually configured
relay profile does not need to enable HNSR. The address book accepts public
`NETWORK | SHAKESCAPE` gossip, including the keyless form that stock HSD
relays. The node reserves up to two of its outbound slots for these candidates,
connects to their compatible raw-TCP listener, and federates only after the
ShakeScape V1 registry and network have negotiated. Keyless discovery is a
capability claim rather than an authenticated operator identity; signed offer,
cancellation, and swap messages still undergo their normal verification and
the shared board limits remain in force. Up to eight live peers participate in
federation at once. `--no-p2p-discovery` disables automatic federation.

Operators may also pin a known node with
`--shakescape-federation-peer KEYHEX@IP:PORT` (repeat the flag for each node).
This uses an authenticated Brontide link and takes priority within the eight
federation slots. It is useful when gossip is slow or an operator wants a
specific route; no manual peer list is needed for the default profile.

Federated nodes exchange active signed name listings, HNS/BTC direct offers,
and signed cancellations. A fresh link synchronizes both boards; a five-minute
reconciliation repairs missed announcements. The name board replays the
original signed listing with each retained cancellation so a newly joined
node can verify the tombstone. The direct-offer board fetches exact missing
offers and forwards only cancellations verified against their offers. A node
that receives an acceptance routes the signed swap proposal, hello, and
subsequent signed status messages through the link that supplied the offer,
back to its owner. Recovery proposals can also traverse federation links.

Gossip discovers ShakeScape-capable full nodes, not a formally attested relay
operator role. Offer and session authority remains with the wallet signatures.
Board and session routes remain
process-local: after restart or disconnection, peers must reconnect and
reconcile before a live offer can be taken through that node. Wallets should
retain and replay their own signed offer and swap state until settlement.

The independently enabled HIP-78 opaque relay advertises the canonical
Shakescape swap circuit profile (`0x0004`) alongside Node, Web, and Chat. That
profile permits two authenticated endpoints to carry bounded encrypted swap
bytes through an ordinary relay. The opaque relay does not decode the payload,
invoke the marketplace cache, validate an offer, or acquire endpoint or
settlement authority. This is separate from the installed typed direct
HNS/BTC board adapter above: the typed adapter handles signed discovery and
session/status routing, while profile `0x0004` transports already-addressed
private session bytes.

The node now has descriptor-bound, restart-durable confirmed Shakedex-v2 and
HNS-HTLC-v1 funding/spend/preimage tracking plus bounded mempool reconciliation.
That local tracking profile is derivative source implementation, not Shakescape or
swap protocol authority: its frozen vectors cannot replace the published
canonical `hns-swap` artifact and a qualified node adapter.
It still does not construct or sign transactions, own swap workflow state,
choose matches, store unrevealed preimages, or automatically execute a swap.
`SwapStatus` remains an authenticated-adapter-supplied bounded relay role, not
a chain-authoritative swap engine.
