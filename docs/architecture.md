# Architecture

`hsrd` is a purpose-built HNS mining full node for MeshMine. Its architecture
optimizes tail latency and isolation while preserving complete Handshake
consensus behavior.

```text
hns-node
  -> bounded diagnostics/control and supervision
  -> hns-mining native events, snapshots, templates, candidate publication
  -> hns-sync / hns-p2p / hns-mempool
  -> hns-chain / hns-state / hns-consensus / hns-urkel
  -> hns-store
  -> hns-primitives
```

The native mining interface is primary. HTTP/JSON is never used between
MeshMine and the node.

## Execution lanes

1. solved block validation, durable publication intent, and reserved relay;
2. committed tip notification and clean ASIC-job activation;
3. ordinary ASIC-share support reads;
4. live P2P validation and ordered state commit;
5. mempool reconciliation and replacement-template refinement;
6. historical synchronization, diagnostics, metrics, and compaction.

Lower lanes may not consume every queue slot, CPU worker, disk permit, peer
send permit, or runtime thread required by a higher lane. Consensus state is
committed in order; stateless parsing, hashing, and verification may be
parallelized against immutable inputs.

## Staged chain events

- `CandidateTipSeen`: bounded header/parent evidence arrived; useful only to
  stop obviously obsolete work, never to authorize a new job.
- `BlockValidated`: the complete block passed stateless/contextual checks.
- `TipCommitted`: UTXO/name-tree/index/undo state committed atomically; this is
  the sole event that can activate a new parent-bound job.
- `TipCleared`: the durable chain has no connected tip; all prepared work must
  stop until a later committed snapshot.
- `ReorgStarted`: consumers enter a no-activation state while the replacement
  branch is applied. Intermediate disconnect/connect generations are never
  published as mining tips.
- `ReorgAborted`: consumers resynchronize from the authoritative snapshot after
  a failed application attempt.
- `MempoolReconciled`: a replacement template can incorporate the post-connect
  mempool delta without delaying the clean job.

Events carry immutable summaries and monotonically ordered local generations.
Restart reconstructs the last committed generation before events resume.

The current implementation durably advances `BestBlockHash` and
`MiningGeneration` in the same connect/disconnect batch and publishes only
after that commit. Multi-block reorganization storage is not atomic yet;
`ReorgStarted` prevents activation of its intermediate tips, but an atomic
overlay/batch reorg engine remains a production gate.

## State and storage

`hns-state` is the only consensus-state writer. Connect/disconnect commits the
block index, canonical height, UTXO changes, name-tree changes, and undo data
atomically. Readers use immutable snapshots so a mining template never holds a
state-writer lock. Compaction and pruning are bounded background work with no
permission to take the mining lane's reserved storage budget.

## Compatibility boundary

`hns-consensus` is deterministic, synchronous, and independent of networking,
storage, RPC, MeshMine, and wall clocks. `hsd`, historical mainnet, hnsd, and
Urkel/liburkel are comparison oracles, not architectural dependencies. The
production authority transition is governed by `mining-node-scope.md`.
