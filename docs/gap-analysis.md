# Gap analysis

## Existing local evidence

- Bounded header/transaction/block/covenant/resource parsers and seven
  hsd-derived primitive fixture tests.
- Header/block index records, canonical-height concepts, raw block/tx indexes,
  memory/RocksDB store boundary, and atomic batch primitives.
- Body commitment and non-contextual covenant-shape/count checks, UTXO
  connect/disconnect with missing/double-spend, value-conservation, coinbase
  maturity and unspent-collision checks, ordinary coinbase subsidy-plus-fee
  accounting, absolute height/time locktime finality, undo codec, minimal
  mempool behavior, bounded frame codec, and diagnostic RPC snapshot.
- A lean daemon workspace with the first durable native-mining event and
  prepared-job foundation, exact unsigned 256-bit target-work derivation, HNS
  suitable-median difficulty and timestamp admission, direct solved-candidate
  admission, and a fail-closed durable MeshMine assignment binding. Test counts
  are reported from current verification, not frozen here as a readiness proxy.

These are building blocks, not a production full node.

## Mandatory missing work

- Exact sighashes and complete script verification.
- All remaining transaction contextual rules: relative sequence locks,
  verified claim/airdrop issuance and conjured-value accounting, deployments,
  and historical exceptions. Claim/airdrop coinbases currently fail closed;
  they are not accepted on structural checks alone.
- Complete covenant validation and OPEN through REVOKE state transitions,
  rollout/auction timing, reserved names, renewal/expiration, transfer/finalize,
  and name-tree root agreement.
- Production Urkel mutation, proof generation/verification, snapshots, and undo.
- Atomic complete connect/disconnect and side-chain/reorg behavior.
- Live connection manager, inventory/getdata/block/tx serving, peer scoring,
  orphan handling, stall detection, backpressure, and reserved block relay.
- Headers-first parallel block download with ordered commit and pruning.
- Template-oriented mempool indexes and incremental template construction.
- Incremental template production, complete state-context validation behind the
  direct solved-candidate admission boundary, priority relay, and atomic live
  activation orchestration around the implemented durable native
  snapshot/prepared-job/MeshMine gateway bridge.
- Full historical/invalid-corpus differential execution and sustained shadow
  mainnet evidence.

## Explicitly removed work

Wallet, desktop, keyring, domain-manager, DNS/resolver, explorer indexes, and
broad RPC compatibility are outside this repository's product scope. Consensus
parsing of name/resource bytes remains only where block validity requires it.
