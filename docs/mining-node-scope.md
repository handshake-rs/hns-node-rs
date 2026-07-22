# Mining node scope

## Product invariant

`hsrd` exists to make one latency-sensitive pipeline native and dependable:

```text
HNS peer input
  -> complete consensus validation and state commit
  -> immutable tip/mempool snapshot
  -> incremental mining template
  -> direct MeshMine job activation
  -> solved-candidate validation
  -> reserved multi-peer block relay
```

No JSON-RPC, child process, JavaScript heap, wallet service, or settlement task
may sit on that path.

## Included

- Every historical and current HNS consensus rule.
- Header, transaction, script, covenant, claim, airdrop, subsidy, difficulty,
  deployment, and block validation.
- Complete UTXO and Handshake name-tree/Urkel transitions plus undo data.
- Best-chain selection, side chains, reorganization planning, and checkpoints.
- Bounded P2P handshake, peer management, headers/block synchronization,
  transaction relay, block serving, and solved-block priority relay.
- A minimal mempool with only the dependency, fee, weight, covenant, claim,
  and airdrop indexes needed to build correct competitive templates.
- Incremental templates, immutable chain/mempool snapshots, staged tip events,
  prepared jobs, candidate validation, and direct MeshMine APIs.
- Pruned operation, bounded diagnostics/control, metrics, differential fixture
  generation, fuzzing, and crash/restart evidence.

## Excluded

- Wallets, seed phrases, signing, keyrings, address books, and coin selection.
- Desktop/mobile/web UI and domain lifecycle management.
- DNS, DNSSEC, DANE, recursive/authoritative serving, browser resolution, and
  resource presentation beyond bytes required by consensus.
- Explorer/address indexes and broad convenience transaction indexes.
- Mining through public JSON-RPC; broad `hsd` RPC compatibility.
- Settlement, share DAG, mask MPC/VSS, and body-availability logic, which stay
  in MeshMine and consume native node snapshots/events.

## What cannot be trimmed

Mining does not permit a partial consensus node. A transaction that appears
unrelated to mining can change the UTXO set, a covenant can change the name
tree, and either can change the next valid header commitment. Consequently the
full consensus transition engine is mandatory even when wallet, DNS, and
general RPC product surfaces are absent.

## Native MeshMine handoff

The Core-side bridge consumes only `TipCommitted` snapshots. It derives a
prepared body and signed gateway assignment bound to the exact mining
generation, parent, header roots, transaction bytes, mask commitment, target,
time window, and worker search range. The gateway captures submissions only
under that authenticated assignment. A winning reconstruction returns through
a reserved candidate-validation and multi-target publication lane; DAG and
settlement reconciliation never gate job activation or block broadcast.

The native bridge now acquires only the authority-permitted event stream,
persists exact generation/job bindings in the gateway store, activates signed
assignments through the gateway, retires work on tip loss/change, and rechecks
authority before publication. Production authority still does not move until
the consensus/removal gates below are complete.

## hsd removal gate

`hsrd` progresses through fixture, historical replay, native synchronization,
and authority stages. HSD remains only a pinned offline oracle when
independently reproducible evidence shows:

1. identical accept/reject results for every historical mainnet block and the
   invalid/mutated corpus;
2. identical block hash, height, chainwork, UTXO outcome, name-tree root,
   deployment state, and undo/reorg result at every boundary;
3. stable multi-peer native operation through restarts, partitions, and
   reorganizations, with bounded offline differential audits of retained data;
4. successful candidate construction/validation and multi-path publication;
5. a reviewed migration and fallback plan that does not create ambiguous fork
   choice.
