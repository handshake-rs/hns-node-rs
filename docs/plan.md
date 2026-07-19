# Mining full-node implementation plan

## Goal

Replace MeshMine's `hsd` process/RPC boundary with a lean native Rust HNS node
that performs complete consensus validation, maintains the chain and name
state, builds mining templates, and relays solved blocks with reserved capacity.

## Design rules

- Complete HNS consensus is mandatory; unrelated product surfaces are not.
- The committed tip has one deterministic authority and immutable generation.
- Mining uses native Rust data and bounded channels, never JSON-RPC.
- Solved-block and tip/job work have reserved CPU, queue, storage, and P2P
  capacity.
- Async socket tasks do no consensus validation or database writes inline.
- Parser inputs, peer inventories, orphan pools, mempool indexes, templates,
  and diagnostics are bounded and fuzzed.
- Every state mutation has undo/restart evidence.
- `hsd` is retained only as an oracle until the removal gates pass.

## Deliverables

- Exact primitives and consensus kernel with hsd-derived positive/negative
  fixtures.
- Atomic chain/UTXO/name-tree/undo state and reorganization engine.
- Bounded P2P and pipelined synchronization.
- Minimal template-oriented mempool and incremental template engine.
- Native staged events, immutable snapshots, prepared jobs, and candidate API.
- Priority, multi-peer solved-block broadcast with durable per-target outcomes.
- Shadow replay/comparison harness, fuzz corpus, metrics, and release evidence.

Implementation follows the source boundary and extraction order in
`hsd-decomposition.md`; excluded product modules are not allowed to re-enter
the node merely for broad `hsd` API compatibility.

## Implemented native mining foundation

- Durable monotonic mining generation tied atomically to each canonical
  connect/disconnect batch.
- Immutable restart-recoverable tip snapshots plus bounded staged events with
  authoritative lag recovery.
- Reorg start/abort fencing and one final published tip rather than transient
  disconnect/connect activation.
- Canonically length-delimited prepared-job identity, exact generation/parent
  activation, mask-hash binding, and reconstructed-candidate checks.

The current code remains pre-authority: primitive fixtures and limited
in-memory/store behavior do not constitute consensus completeness. In
particular, contextual consensus, scripts/covenants/name transitions, Urkel
parity, live P2P, atomic multi-block reorgs, incremental templates, candidate
priority relay, and historical/shadow evidence remain production gates.
