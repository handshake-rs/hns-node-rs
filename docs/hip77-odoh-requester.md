# HIP-77 ODoH requester boundary

`hns-p2p` provides a process-wide HIP-77 requester over live HNS peers. The
requester policy is enabled by default on every network and can be disabled or
revoked with a monotonic policy generation. Standalone operators can start with
`--no-odoh-requester`; embedded users set `NativeSyncConfig::odoh_requester`.
This does not enable a local ODoH
proxy, target, DNS resolver, or plaintext output role, and the node does not
advertise the ODoH provider service bit on their behalf.

## Admission and routing

A request can use a peer only after ordinary VERSION/VERACK readiness and an
exact Denuo V1 registry negotiation. Admission retains the upstream
`ExperimentalWireProfile::DenuoV1` and `NegotiatedRegistry` values rather than
reconstructing authority from diagnostics. The fingerprint, registry and
negotiation protocol versions, network, genesis hash, send bound, and live-work
bound must all match the local connection. Both the Denuo extension and ODoH
service bits must be present. Every ODoH path requires the exact
remote static key authenticated by that connection's Brontide handshake; the
default plaintext regtest/simnet transport therefore remains awaiting an
eligible proxy unless an embedded deployment supplies authenticated transport.
The manager prefers outbound peers deterministically, excludes faulted peers, and
requires the selected proxy key to differ from the target-signed locator key.

Packet `0xf2` is bounded before allocation and is consumed by the typed ODoH
runtime before generic unknown-packet delivery. Each outstanding request binds
its nonzero ID, policy generation, absolute deadline, connection ID, proxy
address, direction, transport, authenticated proxy key, and target key.
Responses from another connection or key do not complete the request. A
disconnect, registry failure, scoped oversize packet, policy replacement,
revocation, or deadline expiration clears affected work.

The manager holds requester state through bounded critical socket-write
acknowledgement. A queued write is therefore not reported as sent, and a policy
change cannot race a stale request into the writer. Negotiated send-size and
live-request limits are intersected with local limits.

## Target cache and restart

Callers install target-signed configuration records directly or obtain them
through a correlated `GETCONFIG` exchange. Verification binds the target
locator, Handshake network magic, signature, validity interval, supported HPKE
configuration, and per-locator monotonic sequence. Equal-sequence conflicts and
rollbacks are rejected.

The durable cache is canonical, bounded to 16 target locators, checksummed, and
bound to the network and private-address policy. Startup reverifies every live
signed record at the current trusted time. Expired records are removed without
moving verification time backwards, while their sequence high-water mark is
retained. A checksummed `odoh-durable-floor/v1` record carries the minimum cache
generation, policy generation, and trusted-time high-water. Native sync commits
that floor atomically with `odoh-target-cache/v1`; startup requires either both
records or neither and rejects older generations or a clock below the durable
high-water. Advancing time or pruning on restore makes the cache dirty so the
new floor is persisted. The explicit requester opt-out and revocation state are
part of the versioned snapshot, so restart cannot silently re-enable them.
Persistent native-sync nodes flush this state at the bounded peer-state interval
and once more during orderly shutdown. Corrupt, incomplete, rolled-back, or
policy-mismatched state rejects requester initialization.

Only signed public target records, selected configuration indexes, expiration
times, sequence high-water marks, requester policy, and the durable rollback
floors persist. Proxy connections, request IDs,
pending work, HPKE sender contexts, plaintext queries, and decrypted responses
never cross restart.

## Output trust

A successful HPKE open yields `OdohUntrustedDnsResponse`. It is deliberately
not a resolver answer. The consumer remains responsible for strict DNS parsing,
exact question correlation, response limits, and DNSSEC validation before the
bytes influence any browser, wallet, or policy decision.
