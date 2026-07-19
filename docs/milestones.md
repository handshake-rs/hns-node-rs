# Milestones

Status labels describe the current source tree, not production readiness.

## 1. Scope and primitive freeze — foundation present

- Lean mining-node boundary documented; unrelated product surfaces excluded.
- Bounded primitive codecs and initial HSD-derived vectors present.
- Fixture manifest is versioned, pinned, path-safe, and digest-verified.

Remaining: broaden positive/negative vectors and fuzz every parser family.

## 2. Consensus kernel — partial

Implemented:

- Header PoW/difficulty/time context and body commitment/syntax foundations.
- HSD-compatible sighash, sequence-lock, CLTV, and CSV primitives.
- Bounded version-zero witness/script interpreter foundation.
- Exact non-coinbase covenant input/output linkage with HSD oracle parity.

Remaining:

- audited secp256k1 backend and complete script/opcode/flag/historical parity;
- deployments/checkpoints/historical exceptions;
- claim and airdrop validation/accounting;
- complete contextual covenant/name rules.

## 3. State and reorganization engine — partial

Implemented:

- UTXO connect/disconnect and undo;
- spent output address persistence;
- authorization and covenant linkage before spend mutation;
- true store snapshots;
- one-batch multi-block reorganization staging;
- validated non-active block/header/body retention;
- separate best-header and active-best-block bindings;
- strict greater-work fork choice with equal-work first-seen preservation;
- active-to-candidate reorganization planning and pre-commit shape/work checks;
- gated restart recovery of fully stored better branches;
- granular durable validation status;
- schema/network/genesis/profile/chain-epoch bindings.

Remaining:

- complete name-state and Urkel mutation/undo/root parity;
- orphan inventory, header-first acquisition, and all historical HSD
  reorganization/checkpoint/deployment semantics;
- pruning and crash-recovery qualification under RocksDB fault injection.

## 4. Live P2P and synchronization — not complete

Implement bounded peers, serving, inventory, download queues, orphan/stall
handling, parallel stateless work, ordered commits, restartable IBD, and
priority solved-block relay.

## 5. Mining engine — foundation present

Implemented:

- durable mining generations and immutable snapshots;
- staged versus authoritative event channels;
- prepared-job identity and parent/generation checks;
- mask-bound reconstructed candidate checks;
- diagnostic status/readiness/parity surfaces.

Remaining:

- consensus-complete mempool admission and package indexes;
- incremental/future templates;
- complete candidate validation and reserved multi-peer relay.

## 6. MeshMine composition — partial

The native node/gateway handoff types exist. Complete live composition,
failover, publication fan-out, operational safe modes, and latency evidence
remain.

## 7. Differential and shadow qualification — early

- Phase 2 and Phase 3 deterministic HSD fixture generators are committed.
- Nested-workspace CI and static authority/fixture gates are defined.

Remaining: replay mainnet and invalid corpora at every state boundary, then run
live shadow nodes through restarts, partitions, and reorganizations.

## 8. Authority and HSD removal — blocked by design

- Default mode is `shadow`.
- Incomplete states cannot enter the authoritative snapshot channel.
- Native experimental authority is explicitly gated and non-production.

Promote `hsrd` only after every gate in `mining-node-scope.md` is reproducibly
satisfied and reviewed.

## 9. Production hardening — future

Fuzz, audit, profile P50/P95/P99/max latency, tune storage/P2P isolation, run WAN
and real-hardware trials, publish recovery procedures, and produce reproducible
signed releases.
