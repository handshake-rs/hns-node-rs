# hsrd

`hsrd` is the lean Handshake mining full node built for MeshMine. It owns the
minimum complete consensus, state, synchronization, template, and relay path
needed to mine valid HNS blocks with predictable latency.

It is deliberately not a wallet, desktop application, domain manager, DNS
server, explorer, or general `hsd` compatibility distribution. MeshMine uses
native in-process Rust interfaces for mining; the bounded HTTP control surface
exists only for diagnostics, operations, and differential testing.

`hsd` remains a behavioral oracle while `hsrd` is incomplete. It may be
removed from production only after full historical replay, invalid-corpus,
reorganization, and live shadow-node parity gates pass. See
[`docs/mining-node-scope.md`](docs/mining-node-scope.md). The source-level
`hsd` keep/adapt/remove map is in
[`docs/hsd-decomposition.md`](docs/hsd-decomposition.md).
