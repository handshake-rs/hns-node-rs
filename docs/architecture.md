# Architecture

`hsrd` is a purpose-built HNS mining full node for MeshMine. Its architecture
optimizes tail latency and isolation while preserving the requirement for exact
Handshake consensus behavior.

```text
hns-node
  -> bounded diagnostics/control and supervision
  -> hns-mining native events, snapshots, jobs, candidate publication
  -> hns-sync / hns-p2p / hns-mempool
  -> hns-chain / hns-state / hns-consensus / hns-urkel
  -> hns-store
  -> hns-primitives
```

The native mining interface is primary. HTTP/JSON is never used between
MeshMine and the node.

## Execution lanes

1. solved-block validation, durable publication intent, and reserved relay;
2. committed tip notification and clean ASIC-job activation;
3. ordinary ASIC-share support reads;
4. live P2P validation and ordered state commit;
5. mempool reconciliation and replacement-template refinement;
6. historical synchronization, diagnostics, metrics, and compaction.

Lower lanes may not consume every queue slot, CPU worker, disk permit, peer send
permit, or runtime thread required by a higher lane. Consensus state is
committed in order; stateless parsing, hashing, and verification may be
parallelized against immutable inputs.

## Validation stages

Durable `BlockStatus` uses independent stages rather than broad validity labels:

```text
header context
checkpoint
activation/deployment state
body presence
body syntax and commitments
absolute finality
relative sequence locks
scripts/witness authorization
covenant input/output linkage
contextual covenant/name rules
claims and airdrops
UTXO connection
name-state connection
Urkel tree-root agreement
undo durability
active-chain membership
```

`covenant_links_valid` means only the deterministic non-coinbase linkage pass
has succeeded. It must never be interpreted as contextual name-state validity.
The authoritative mining snapshot requires every consensus and state stage;
the pre-authority staged snapshot is separate and diagnostic only.

## Staged chain events

- `CandidateTipSeen`: bounded header/parent evidence arrived; useful only to stop
  obviously obsolete work, never to authorize a new job.
- `BlockSyntaxValidated`: bounded body syntax and commitments passed. It does not
  claim scripts, covenants, name state, or complete consensus.
- `TipStaged`: the current pre-authority state subset committed durably, but the
  generation is excluded from the authoritative mining snapshot channel.
- `TipCommitted`: every release-gated consensus and state condition passed; this
  is the sole event that can authorize a native mining parent.
- `TipCleared`: the durable chain has no connected tip.
- `ReorgStarted`: consumers enter a no-activation state while a replacement
  branch is staged.
- `ReorgAborted`: the staged operation failed and no durable reorganization was
  committed.
- `MempoolReconciled`: a later replacement template may include post-connect
  mempool changes without delaying the clean job.

Events carry immutable summaries and monotonically ordered local generations.
Restart reconstructs the last durable generation before event publication.

## Atomic chain mutation

Single-block connects/disconnects and multi-block reorganizations use one store
batch. A reorganization is evaluated against one immutable base snapshot plus a
read-your-writes overlay:

```text
immutable base snapshot
       +
staged disconnect/connect overlay
       -> validate complete replacement branch
       -> verify final best-work tip
       -> commit one underlying database batch
       -> refresh indexes
       -> publish one final generation
```

No intermediate disconnect or connect is visible in durable state. On any
error, the underlying batch is dropped and the original chain remains intact.
This solves database atomicity; complete historical reorganization consensus
parity remains a separate qualification gate.

## State and storage

`hns-state` is the only UTXO/name-state writer. It resolves and authorizes all
transaction inputs before staging spends, verifies Phase 3 covenant linkage,
then stages value changes and undo data. Claim/airdrop and complete name-state
work remain fail-closed.

Memory-store snapshots are cloned immutable maps. RocksDB snapshots retain a
sequence-consistent `rocksdb::Snapshot`, so related reads cannot cross a commit
boundary. Compaction and pruning remain bounded background work without access
to the mining lane's reserved storage budget.

## Compatibility boundary

`hns-consensus` is deterministic, synchronous, and independent of networking,
storage, RPC, MeshMine, and wall clocks. `hsd`, historical mainnet, `hnsd`, and
Urkel/liburkel are comparison oracles, not runtime architectural dependencies.
The production authority transition is governed by
[`mining-node-scope.md`](mining-node-scope.md).
