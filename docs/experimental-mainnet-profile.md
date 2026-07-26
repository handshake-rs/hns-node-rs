# Experimental mainnet profile

`hsrd` uses **Denuo Experimental V1 — Not an official Handshake protocol
assignment** for private extension negotiation on mainnet, testnet, regtest,
and simnet.

The canonical authority is the exact `handshake-rs/hns-rs`
`hns-p2p-experimental` revision pinned by this repository. The live node never
copies a registry digest or private Hello/Ack message number.

## Canonical identity

- Registry: `Denuo Experimental Handshake P2P Registry`
- Registry version: `1`
- Registry protocol: `0x0000`, version `1`
- Wire profile: `denuo-v1`
- Fingerprint:
  `95774db08c569b36fa7b7e4a071930f563b7251fc30934ba986732379a6e542d`
- Extension service bit: `0x10000000`
- Extension packet: `0xf4`
- Maximum complete `DENUO_EXT` payload: 1,048,576 bytes
- Maximum nested envelope payload: 1,048,550 bytes
- Maximum registry-negotiation payload: 16,384 bytes

These values are stable only within Denuo Experimental Registry v1. They are
not official global Handshake assignments.

## Connection behavior

The node advertises the ordinary network service and the Denuo extension
service. It does not advertise DNS relay, ODoH, HNSR, marketplace, or any
provider/output role until the corresponding runtime and consent boundary
exist.

Ordinary VERSION/VERACK completes first. An outbound peer then initiates the
first `DENUO_EXT` exchange only if the remote VERSION advertised the extension
service. The correlated Hello/HelloAck exchange binds:

- the canonical registry fingerprint and supported versions;
- protocol `0x0000` version 1;
- bounded receive size and live-request limits;
- exact Handshake network and genesis hash; and
- negotiated feature flags.

The negotiation deadline starts when the bounded control queue admits the
outbound Hello. An already admitted socket write is not presented as
cancelled; any Ack observed after the deadline is rejected and Denuo remains
disabled for that connection.

A peer without the extension service receives no private packet. A registry,
network, genesis, version, correlation, replay, or parsing failure disables
experimental traffic for that connection. It does not by itself ban or
disconnect the peer, and ordinary headers, blocks, transactions, compact-block
negotiation, address exchange, and ping/pong remain available.

Only packet `0xf4` enters this coordinator. Every other unknown packet remains
opaque to the ordinary P2P event consumer. Unknown Denuo subprotocols are
bounded and rejected without being assigned new semantics.

## Diagnostics

`gethsrdstatus`, `/api/v1/status`, and `/api/v1/native-sync` report the
canonical identity and wire profile, advertised state, peer negotiation
counts, bounded message totals, and a closed set of rejection reasons.
Per-peer native diagnostics report the connection's negotiation phase,
disable reason, and negotiated limits.

Outbound message totals count bounded queue admission, not socket-write
completion. Inbound totals count decoded messages received from the wire, and
agreement totals count compatible registry computations. Peer byte counters
remain the transport-level evidence of completed writes.

The status is evidence of compatible private-wire negotiation only. It is not
evidence that a draft HIP is official, that a provider role is enabled, or
that relayed DNS or marketplace data is trusted.
