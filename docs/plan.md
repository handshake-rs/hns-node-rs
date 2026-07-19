# Mining full-node implementation plan

## Goal

Replace MeshMine's `hsd` process/RPC boundary with a lean native Rust HNS node
that performs complete consensus validation, maintains chain and name state,
builds competitive mining templates, and relays solved blocks with reserved
capacity.

## Design rules

- Complete HNS consensus is mandatory; unrelated product surfaces are not.
- One committed tip and monotonically ordered generation are authoritative.
- Mining uses native Rust data and bounded channels, never JSON-RPC.
- Solved-block and tip/job work have reserved CPU, queue, storage, and P2P
  capacity.
- Async socket tasks do not validate consensus or write databases inline.
- Inputs, inventories, orphan pools, mempools, templates, and diagnostics are
  bounded and fuzzed.
- Every state mutation has undo, restart, and atomicity evidence.
- Validation stages remain granular; partial work is never relabeled as full
  consensus.
- HSD remains the pinned oracle until historical, invalid-corpus, reorganization,
  and live shadow gates pass.

## Completed Phase 1–3 foundation

### Authority and storage safety

- Nested workspace CI and separate RustSec audit.
- Explicit authority modes and fail-closed readiness diagnostics.
- Granular durable status and separate staged/authoritative mining channels.
- Test-only fixture bypasses.
- Sequence-consistent RocksDB snapshots.
- One-batch read-your-writes multi-block reorganization application.
- Schema version 5 with explicit reindex behavior.

### Transaction authorization foundation

- HSD signature hashing and signature-type validation.
- Relative sequence locks and CLTV/CSV predicates.
- Bounded version-zero witness/script foundation with pluggable signature
  verification.
- Default rejection when the signature backend is unavailable.

### Covenant linkage foundation

- Exact HSD non-coinbase input/output linkage and local commitment checks.
- Linkage completes before UTXO mutation.
- 33 reproducible HSD oracle cases and fixture digests.
- Contextual covenant/name state remains an independent unfinished stage.

## Next implementation order

1. **Compile/CI reconciliation**: run every Phase 1–3 Cargo gate, resolve
   formatting/Clippy/API issues, and retain generated fixtures unchanged.
2. **Signature authority**: select and audit a secp256k1 backend, implement exact
   witness-program dispatch/flags, and expand negative HSD vectors.
3. **Contextual covenants**: port rollout, reserved names, auction phases,
   ownership, renewal, expiration, transfer/finalize, and resource rules.
4. **Claims and airdrops**: verify proof codecs, historical datasets,
   deflation-era accounting, and conjured value.
5. **Urkel/name state**: exact mutation, persistence, undo, proof, snapshot, and
   root parity.
6. **Chain qualification**: side chains, checkpoints, historical exceptions,
   pruning, crash recovery, and full reorganization parity.
7. **Live P2P/sync**: bounded peer manager, headers-first download, ordered
   commits, serving, and reserved block publication.
8. **Mempool/templates**: consensus admission, package indexes, incremental
   future jobs, and complete candidate validation.
9. **Historical and live shadow qualification**: mainnet replay, invalid corpus,
   state-root comparisons, live restarts/partitions/reorgs.
10. **Controlled authority transition**: HSD cross-check/fallback first; removal
    only after reviewed reproducible evidence.

Implementation follows `hsd-decomposition.md`. Excluded wallet, DNS, UI, and
broad RPC modules must not re-enter the node merely for convenience.
