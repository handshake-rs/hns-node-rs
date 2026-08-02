# Native Handshake DNS resolver

`hns-resolverd` is a companion service for `hsrd`. It exposes ordinary DNS over
UDP and TCP, so applications that already accept a resolver address do not need
an `hsd` process or a Handshake-specific library.

This is intentionally a separate binary rather than a listener embedded in the
consensus node. `hsrd` remains responsible for consensus, authenticated state,
and synchronization. The resolver owns untrusted DNS packet parsing, recursive
network traffic, caches, and DNS-facing resource limits. A fault or future
privilege sandbox in either service therefore does not expand the other
service's authority.

## Current capability boundary

The initial native implementation provides:

- loopback-first UDP and TCP DNS on port 5350;
- atomic Handshake resource reads from one immutable `hsrd` state snapshot;
- HSD-compatible DS, NS, GLUE4, GLUE6, SYNTH4, SYNTH6, and binary TXT
  projection;
- Handshake root DNSKEY publication, P-256 KSK/ZSK signing, signed NSEC
  denial, and recursive validation from the fixed Handshake KSK;
- DNSSEC-validated dynamic fallback for eligible ICANN root names only when no
  Handshake resource exists, using a separate IANA trust-anchor set and direct
  iterative resolution seeded only by the configured ICANN root hints;
- Handshake-wins precedence for registered eligible ICANN names, plus HSD's
  decentralized-name collision blacklist, so fallback cannot override chain
  state or claim names assigned to other decentralized systems;
- iterative recursion through delegated authoritative name servers;
- bounded record and name-server caches, recursion depth, DNS concurrency,
  `hsrd` concurrency, RPC time, and TCP request time;
- duplicate NS removal and bailiwick filtering for glue;
- default rejection of loopback, private, link-local, documentation, and
  reserved delegated name-server addresses;
- fail-closed answers while the active state is behind the best validated
  header, unless the operator explicitly opts out;
- one-second chain-state polling by default, with fail-closed admission and
  whole-cache generation replacement after a block connection or reorganization;
- shorter local cache ceilings than the six-hour resource TTL: 30 minutes for
  positive data and five minutes for NXDOMAIN by default.

The following are not complete yet and must not be inferred from the presence
of a DNS listener:

- DNS over HTTPS, DNS over TLS, or DNS over QUIC;
- a public-recursive-resolver deployment profile.

The raw listener remains a private sidecar/local-resolver interface. Do not
publish it as an open resolver. DNSSEC validation and dual-root fallback are
enabled by default, but release qualification still requires live HSD/hnsd
differential fixtures before treating this implementation as an independently
audited DANE or certificate-pinning authority.

## Build and run

Build both processes:

```bash
cargo build --locked --release -p hns-node --bin hsrd
cargo build --locked --release -p hns-resolver --bin hns-resolverd
```

Start and synchronize `hsrd` first. Its existing JSON diagnostics expose sync
progress; there is no HTML status page:

```bash
curl --fail --silent --show-error http://127.0.0.1:12037/api/v1/status
curl --fail --silent --show-error http://127.0.0.1:12037/api/v1/sync
```

Then start the resolver:

```bash
./target/release/hns-resolverd \
  --listen 127.0.0.1:5350 \
  --hsrd-rpc-url http://127.0.0.1:12037/
```

If `hsrd` uses `--rpc-authorization-header-file`, mount the same private,
absolute, mode-0600 file into the resolver and pass:

```bash
--hsrd-authorization-header-file /absolute/private/hsrd-authorization-header
```

The authorization header grants access to the entire authenticated RPC
listener, not just resolver methods. Do not give that credential to the
resolver when the same listener exposes a wallet-enabled profile unless the
resolver is intentionally trusted as a full RPC principal, including wallet
broadcast authority. Prefer an hsrd instance and listener whose enabled profile
excludes wallet RPC routes for the resolver boundary.

The current RPC transport accepts `http://` only and deliberately ignores
ambient HTTP proxies and redirects. Keep it on loopback or an isolated sidecar
network; TLS support must arrive as an explicit, tested transport feature.

Test the normal DNS interface with:

```bash
dig @127.0.0.1 -p 5350 example. A
dig @127.0.0.1 -p 5350 example. TXT
```

Run `hns-resolverd --help` for cache and concurrency controls.
`--hsrd-chain-state-poll-ms` controls the synchronization detection and cache
generation interval; it does not change Handshake consensus behavior. ICANN
fallback uses the 13 compiled InterNIC root-hint IPv4 addresses, Hickory's IANA
KSK-2017/KSK-2024 anchors, a three-second timeout, 16 permits, and a 4,096-entry
cache by default. `--icann-root-server` replaces the root-hint list when
repeated; `--disable-icann-fallback` produces an HNS-only resolver.

The compiled addresses come from InterNIC's
[`named.root`](https://www.internic.net/domain/named.root), and the validation
keys come from IANA's [DNSSEC trust-anchor publication](https://www.iana.org/dnssec/files).
Release qualification must recheck both sources. Hickory 0.26.1 includes the
active KSK-2017 and pre-published KSK-2024; IANA currently schedules the active
rollover for October 11, 2026, so anchor rollover remains an explicit operator
and dependency-update obligation rather than an assumption.

## Docker and Pinner

The release publishes the resolver separately from the node:

```bash
docker pull ghcr.io/handshake-rs/hns-resolverd:canary-v0.3.4
```

The checked-in Compose stack is the preferred deployment. It shares the node's
network namespace with the resolver, keeping hsrd RPC on loopback, and publishes
DNS only on host loopback:

```bash
docker compose up --detach
dig @127.0.0.1 -p 5350 example. A
```

Use `hns_resolver=127.0.0.1:5350` when Pinner runs on the host. When Pinner is a
container, attach it to the `hns-node-rs_default` network and use:

```text
hns_resolver=hns-resolverd:5350
```

For an independently managed, ACL-controlled sidecar network, override the
image's default RPC URL and bind the resolver to its container interface:

```bash
hns-resolverd \
  --listen 0.0.0.0:5350 \
  --allow-non-loopback-listen \
  --hsrd-rpc-url http://hsrd:12037/
```

Then configure Pinner with:

```text
hns_resolver=hns-resolverd:5350
```

Do not publish port 5350 to the Internet. The flag is an acknowledgement, not
an access-control mechanism; use a container network policy or firewall. A
separate bridge also requires hsrd RPC to bind outside loopback; authenticate
that listener and ensure only the resolver can reach it. Do not reuse a
wallet-enabled listener credential unless the resolver is intentionally trusted
with every route on that listener. The checked-in Compose topology avoids that
additional RPC exposure.

## State and request flow

```text
Pinner / browser adapter / local forwarder
                  |
             DNS UDP/TCP
                  |
                hns-resolverd
            /         |          \
 getdnsresource  iterative DNS   validating ICANN recursion
   (loopback)     (delegated NS)   (ICANN fallback)
       |               |                |
      hsrd     authoritative servers  ICANN roots
             |
  immutable active-state snapshot
```

The resolver does not compose `gethsrdstatus` and `getnameinfo`. A block
connection or reorganization between those two calls could bind resource bytes
to the wrong synchronization claim. The resolver-specific `getdnsresource`
method returns the canonical resource bytes together with network, active
height, best-header height, active name-tree root, chain epoch, and synchronized
state from one database snapshot.

## Baseline and engineering changes

Pinned HSD behavior is the compatibility oracle for record projection and DNS
response semantics. Its JavaScript object graph is not copied as the Rust
architecture. The native design changes the boundary in several ways:

- typed resource decoding lives in `hns-primitives` and preserves binary TXT;
- the consensus process exposes one narrow atomic read instead of embedding a
  recursive server;
- the DNS service is reusable as a library and independently deployable as a
  daemon;
- overload is rejected immediately by hard semaphores rather than creating an
  unbounded wait queue;
- caches are count-bounded and have explicit local TTL ceilings;
- positive and negative caches are replaced atomically whenever the active
  height, name-tree root, network, or chain epoch changes;
- recursion and name-server discovery have separate depth bounds;
- outbound delegated servers are filtered before connection;
- Handshake and ICANN validation use disjoint trust-anchor sets; ICANN NS data,
  parent DS or authenticated denial, and name-server addresses are resolved in
  the IANA trust domain before the delegation is re-signed into the Handshake
  root view;
- fallback is derived from the vendored reserved-name provenance bit, runs
  only after an atomic chain lookup proves the Handshake resource absent, and
  fails closed on timeout, overload, malformed referrals, bogus DS, or missing
  authenticated denial of DS;
- the internal root adapter retains an exact ephemeral transport and never
  requires a privileged port 53;
- authentication secrets are read only from bounded, nonsymlink, mode-0600
  regular files and are redacted from debug output;
- `hsrd` HTTP bodies are consumed incrementally and rejected above 16 KiB,
  including chunked responses without a trustworthy content length.
- JSON-RPC protocol version, request ID, and returned name are checked before a
  resource can enter DNS projection.
- the hsrd client neither follows redirects nor consults ambient proxies, so an
  authorization header cannot be forwarded outside the configured endpoint.

## Complexity and bounds

Let `R` be a resource's encoded size, `K` its record count, and `D` the bounded
recursive lookup depth.

| Operation | Time | Additional space | Hard/default bound |
| --- | ---: | ---: | --- |
| Typed resource decode | `O(R)` | `O(R)` | `R <= 512` bytes |
| DNS-name pointer detection | `O(R)` | `O(512)` fixed table | backward pointers only |
| Record projection | expected `O(K)` | `O(K)` | `K` is bounded by `R` |
| Cache lookup/insert | expected `O(1)` | bounded LRU entries | 1,024 NS / 32,768 records |
| Iterative resolution | network-dependent `O(D)` rounds | bounded caches/tasks | depth 12, NS depth 16 |
| Concurrent public work | `O(1)` admission | fixed permits | 256 queries |
| Concurrent `hsrd` work | `O(1)` admission | fixed permits | 32 requests, 2 s timeout, 16 KiB body |
| ICANN fallback referral | network-dependent `O(D + N)` rounds | bounded LRU/tasks/records | 13 roots, 32 NS, 16 permits, 3 s, 256 records |
| DNSSEC signing | `O(K log K)` canonical RRset encoding | `O(K)` response-local | `K` bounded by resource/referral limits |
| Chain-state check | `O(1)` RPC point read | one active generation | every 1 s |
| Reorg/block invalidation | `O(1)` cache swap | old generation drains via `Arc` | every identity change |

DNS labels, compressed pointers, resource bytes, RPC response size, recursion,
cache entries, and concurrent work are all bounded independently. The fixed
pointer table avoids a quadratic visited-offset scan and cannot grow with
attacker input.

## Next production milestones

The next resolver work should be completed in this order:

1. Add live HSD/hnsd differential fixtures for every resource type, negative
   proof, delegation form, CNAME chain, truncation/TCP retry, and reorganization.
2. Add an optional authenticated local DoH frontend after the DNSSEC boundary
   is complete; keep the raw DNS listener private by default.
