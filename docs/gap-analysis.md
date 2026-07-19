# Gap analysis

## Implemented evidence

### Primitive, chain, and storage foundation

- Bounded header, transaction, block, covenant, address, resource, and witness
  codecs with HSD-derived primitive fixtures.
- Header/block index records, canonical-height indexes, raw block and
  transaction indexes, exact unsigned 256-bit chainwork, and durable mining
  generations.
- Memory and RocksDB stores behind typed traits, atomic write batches,
  sequence-consistent RocksDB read snapshots, and a read-your-writes staging
  overlay for one-commit multi-block reorganizations.
- Persistent network, genesis, storage-profile, schema, and chain-epoch
  bindings. Schema version 5 is a mandatory reindex boundary.
- Validated non-active block/header/body storage, strict greater-work best-header
  promotion, equal-work first-seen preservation, explicit active-to-candidate
  reorganization plans, and one-batch activation after ancestry/body/status/work
  checks. Best known header and active best block remain separate bindings.

### Validation and state foundation

- Header proof-of-work, parent linkage, HNS difficulty transitions,
  median/future timestamp admission, block commitments, bounded block syntax,
  ordinary subsidy-plus-fee accounting, absolute locktime finality, UTXO
  connect/disconnect, undo, coinbase maturity, duplicate/missing spend checks,
  value conservation, and unspent-output collision checks.
- Explicit durable validation stages distinguish syntax, scripts, covenant
  linkage, contextual covenants, claims/airdrops, UTXO state, name state, tree
  root, undo, and active-chain membership.
- HSD-compatible signature hashing, relative sequence-lock calculations, and
  CLTV/CSV predicates.
- A bounded version-zero witness/script execution foundation with pluggable
  signature verification. The production default rejects all non-coinbase
  spends until a complete verifier is installed.
- Exact non-coinbase covenant input/output linkage from HSD
  `verifyCovenants`, checked before UTXO mutation. A deterministic pinned oracle
  corpus covers 33 linkage cases.
- Claim/airdrop coinbase issuance fails closed; it is not accepted on structural
  checks alone.

### Mining and operational foundation

- Native immutable mining snapshots, durable generation ordering, prepared-job
  identity, exact parent/generation activation, mask-hash binding, reconstructed
  candidate admission, and a fail-closed MeshMine assignment boundary.
- Bounded staged events distinguish candidate observation, syntax validation,
  staged non-authoritative tips, authoritative committed tips, reorg fencing,
  and mempool reconciliation.
- Explicit authority modes, readiness blockers, parity status, and read-only
  diagnostics. `shadow` is the default and incomplete states are never exposed
  through the authoritative snapshot channel.
- Full nested-workspace CI definition plus static metadata, fixture-integrity,
  oracle-pin, schema, and authority-invariant checks.

These are substantial foundations, not a production full node.

## Mandatory missing work

### Consensus

- Audited secp256k1 verification and complete HSD script/opcode/flag/historical
  parity. The current script engine is a foundation, not a release claim.
- Deployment and checkpoint parity and all historical exceptions.
- Verified DNSSEC claim and airdrop proofs, historical datasets, deflation-era
  accounting, and exact conjured-value rules.
- Full contextual covenant validation: rollout, reserved names, auction phase,
  winner/second-price selection, ownership, renewal, expiration,
  transfer/finalize timing, revocation, and resource rules.
- Complete name-state transition derivation and agreement with the header
  `tree_root`.
- Production Urkel mutation, persistence, undo, membership/non-membership
  proofs, snapshots, and exact root parity.

### Chain, network, and mining authority

- Full alternate-chain inventory, orphan handling, best-chain selection, deep
  historical reorganization parity, pruning interactions, and crash recovery
  evidence. Atomic database application now exists, but complete consensus
  behavior around every reorganization does not.
- Live HNS connection management, encrypted/plain peer negotiation as required,
  inventory/getdata/block/tx serving, peer scoring, stall detection,
  backpressure, and reserved solved-block relay.
- Headers-first parallel download, ordered block commit, restartable IBD, and
  pruning.
- Consensus-complete mempool admission, package/dependency indexes, incremental
  templates, fee/covenant/claim selection, and future-job activation.
- End-to-end candidate validation and multi-target publication after every
  authority gate is complete.

### Qualification

- Complete historical mainnet replay against the pinned HSD oracle.
- Positive and negative invalid corpora for every consensus rule family.
- Byte-for-byte state, UTXO, name-tree, deployment, undo, and reorganization
  parity.
- Sustained live shadow-node agreement through restarts, partitions, tip races,
  and real reorganizations.
- Reproducible release builds, external review, fuzzing, and published latency
  and recovery evidence.

## Explicitly excluded product work

Wallets, seed/key management, desktop/mobile UI, domain management, DNS
resolution/serving, explorer indexes, and broad convenience RPC compatibility
remain outside `hsrd`. Consensus parsing of name/resource bytes remains only
where block validity requires it.
