# Bounded Denuo marketplace relay

`hns-denuo-market-relay` is an isolated, noncustodial cache and abuse-policy
core for five independently enabled roles:

1. Handshake name-market listings/cancellations;
2. cross-chain market intents;
3. price observations and verified price rounds;
4. fill-grant/match rendezvous;
5. bounded swap-session status.

The default `NodeConfig` role mask is empty. An embedded native adapter must
explicitly enable roles and obtains the shared service through
`NodeRuntime::denuo_relay`.

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
before passing exact canonical bytes to `DenuoRelayHandle::put`. The node core:

- does not sign messages or transactions;
- does not choose matches;
- does not calculate an authoritative price;
- does not hold keys, seeds, liquidity, or funds;
- does not automatically accept or execute swaps.

The workspace now pins exact reachable `hns-rs` 0.3 source at
`88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e`, which contains the canonical
Denuo V2 registry, generated fingerprint, typed marketplace envelopes, and the
new HRM-backed authority contracts. The prior 0.2 package cohort is published
and provenance-verified, while 0.3 remains an unpublished exact Git source.
The active node transport and peer admission deliberately negotiate Denuo V1
and expose no marketplace subprotocol. No typed marketplace adapter or live
advertisement is installed. Live marketplace wire advertisement must therefore
remain disabled until the exact 0.3 archives are published and
provenance-verified, transport admission adopts the exact Denuo V2 registry and
fingerprint, and the joined adapter is qualified. No sibling-path dependency or
unassigned production message ID is used as a workaround. Enabling a local role
creates only the bounded service for an installed native adapter; it does not
make this revision advertise a marketplace protocol.

The node now has descriptor-bound, restart-durable confirmed Shakedex-v2 and
HNS-HTLC-v1 funding/spend/preimage tracking plus bounded mempool reconciliation.
That local tracking profile is derivative source implementation, not Denuo or
swap protocol authority: its frozen vectors cannot replace a published,
revision-pinned canonical `hns-swap` commit and qualified node adapter.
It still does not construct or sign transactions, own swap workflow state,
choose matches, store unrevealed preimages, or automatically execute a swap.
`SwapStatus` remains an authenticated-adapter-supplied bounded relay role, not
a chain-authoritative swap engine.
