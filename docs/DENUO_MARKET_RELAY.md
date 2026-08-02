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

The current `hns-node-rs` dependency pin still exposes the Denuo V1 registry
without marketplace subprotocol assignments. Consequently the cache/role
service and tests are implemented, while live marketplace wire advertisement
must remain disabled until the repository pins the generated Denuo V2 registry
from `hns-rs` (registry version 2, protocol/message assignments, and generated
fingerprint) and adds its typed envelope adapter. No sibling-path dependency or
unassigned production message ID is used as a workaround. Enabling a local
role creates only the bounded service for an installed native adapter; it does
not make this revision advertise a marketplace protocol on its own.

This revision also does not implement Shakedex order interpretation, HTLC
construction/monitoring, secret-preimage storage or extraction, swap wallet
state, or automatic execution. `SwapStatus` is only an authenticated-adapter
supplied bounded relay role, not a live swap engine.
