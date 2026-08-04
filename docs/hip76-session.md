# HIP-76 live-session boundary

`hns-p2p` carries draft HIP-76 DNS relay packets as a bounded, role-safe
per-peer session. This is transport and admission plumbing. It is not a claim
that `hsrd` currently provides a production recursive resolver, authenticates
the returned DNS data, or enables a public output service by default.

## Consent and advertisement

- The requester policy defaults to `Auto`. A node may request through a peer
  that advertises the HIP-76 DNS output service after the Denuo registry
  agreement becomes active. `--no-hip76-requester` records a process-wide
  opt-out, `--hip76-requester` explicitly restores `Auto`, and using neither
  flag preserves the durable selection.
- The provider/output policy defaults to disabled. The HIP-76 service bit is
  stripped from the configured VERSION mask and restored only when the
  operator explicitly opts in and declares the provider backend ready.
- Changing a connected peer's provider advertisement requires reconnecting
  because VERSION service bits are immutable for that connection.
- Mainnet and testnet reject plaintext peer configuration; HIP-76 provenance
  on public networks is therefore bound to the authenticated Brontide remote
  static key. Plaintext remains available for regtest and simnet development.

The live manager owns one monotonic requester-policy generation for the whole
process. A compare-and-replace update is serialized with peer registration,
revokes prior-generation requester work on every live peer, disconnects a peer
whose update channel has failed, and is inherited by every future peer.
Per-peer provider consent is deliberately outside this record and remains off
unless separately configured.

## Requester policy and restart

Persistent native nodes commit checksummed, network-bound
`hip76-requester-policy/v1` and `hip76-requester-policy-floor/v1` records in one
storage batch. Startup accepts both or neither and rejects corruption, wrong
network binding, a zero generation, or rollback below the independent floor.
An explicit startup enable or disable advances the restored generation and is
flushed before peer networking starts; policy changes are retried at the
bounded peer-state interval and at orderly shutdown. Request IDs, peer
sessions, queries, responses, provider consent, and backend readiness never
cross restart.

## Admission and completion

Every request has a policy generation, a deadline, and a unique opaque write
receipt. Requester admission returns a non-cloneable pending outcome rather
than publishing a shared response event. Provider admission returns a
non-cloneable work capability; preparing a response does not consume it, while
committing the response after bounded writer-queue admission does.

Diagnostics distinguish packet creation, writer-queue admission, completed
socket writes, failed socket writes, and stale queue drops. Revocation,
expiration, disconnect, or a generation change completes affected waiters
fail-closed. A stale provider capability or writer receipt cannot complete
later work that reuses the same peer-supplied request ID.

HIP-76 `f0` and `f1` frames are intercepted before generic packet delivery.
Their packet-specific limits are enforced before large plaintext allocation;
Brontide records are authenticated and decrypted before the same typed limit
is applied. A scoped oversized HIP-76 frame disables that experimental session
without desynchronizing or automatically terminating the ordinary peer
session.

## DNS boundary

The provider accepts only canonical, strict, non-recursive DNS queries with a
single question and DNSSEC requested. Locally unavailable, busy, or invalid
provider work receives a correlated protocol status when possible. A
successful response must be a complete, correlated DNS response, but its bytes
are exposed as `Hip76UntrustedDnsResponse`. DNSSEC authentication, namespace
selection, caching, and application policy belong to the consuming resolver.

RPC/native diagnostics aggregate only qname-free session state and counters.
They never include request IDs, question names, raw queries, response bodies,
statuses, or deadlines.
