# Milestones

## 1. Scope and primitive freeze

- Freeze the lean mining-node boundary and remove unrelated product crates.
- Expand hsd-generated serialization/hash fixtures and parser fuzzing.

## 2. Consensus kernel

- Implement exact headers, transactions, scripts, covenants, claims, airdrops,
  subsidy, commitments, deployments, difficulty, and historical exceptions.
- Add positive and negative hsd-derived fixtures for every rule family.

## 3. State and reorganization engine

- Implement UTXO/name-tree/Urkel state, undo, atomic connect/disconnect, side
  chains, reorgs, checkpoints, pruning, and crash recovery.

## 4. Live P2P and sync

- Implement bounded peers, serving, inventory, download queues, orphan/stall
  handling, parallel stateless work, ordered commits, and restartable IBD.

## 5. Mining engine

- Implement the minimal package/fee/covenant mempool indexes, incremental
  templates, immutable snapshots, staged events, and prepared clean jobs.
- Implement direct solved-candidate validation and reserved multi-peer relay.

## 6. MeshMine composition

- Bind the native node to MeshMine gateway assignments, winner reconstruction,
  publication fan-out, safe modes, and latency metrics.

## 7. Differential and shadow qualification

- Replay mainnet and invalid corpora against hsd at every state boundary.
- Run live shadow nodes through restarts, partitions, and reorganizations.

## 8. Authority and hsd removal

- Promote `hsrd` to mining authority while hsd independently cross-checks and
  can broadcast.
- Remove hsd only after every gate in `mining-node-scope.md` is reviewed and
  reproducibly satisfied.

## 9. Production hardening

- Fuzz, audit, profile P50/P95/P99/max latency, tune storage/P2P isolation, run
  WAN and hardware trials, and publish operational recovery procedures.
