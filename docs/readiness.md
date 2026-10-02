# Node release readiness

`hsrd` is the standalone Handshake consensus, state, synchronization, mining,
and relay authority. MeshMine consumes its bounded native interfaces; the
process does not embed wallet UI, domain management, or MeshMine workers.

A process may acquire authority only from complete current consensus readiness,
validated active-state/header agreement, persistent storage integrity, and its
selected operational profile. RPC mode labels do not grant authority. The
mainnet canary additionally requires authenticated loopback control, current
peers, a fresh parent, and the configured durable rollback horizon.

Before release, run [the standalone gate](testing.md) and the applicable
[production assurance tiers](production-assurance.md). Validate canonical HSD
fixtures, independent invalid cases, full-state replay and semantic parity,
disconnect/reconnect, restart, storage failures, synchronization, mempool,
templates, solved-block publication, and the configured mining boundary.

Wallet indexes require explicit profile selection and authenticated readiness.
Account-local clients can use the canonical block feed without enabling the
global wallet index. Index completeness, pruning, recovery, and current chain
identity must be verified before relying on indexed results.

Production acceptance includes sustained multi-peer operation, fault injection,
WAN and load latency, production-scale pruning, complete archive/reorganization
qualification, and physical gateway/ASIC behavior where applicable. Run the
matching executable gates against the exact source and configuration selected
for deployment. A library test or source archive does not establish live
production readiness.

See [architecture](architecture.md), [native synchronization](p2p-sync.md),
[storage rollout](storage-rollout.md), [wallet indexes](HNS_NODE_WALLET_INDEX.md),
and [mainnet canary](mainnet-canary.md) for current operational contracts.
