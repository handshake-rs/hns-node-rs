# Mining engine

The bounded, fail-closed mining engine builds on the durable chain snapshots.
It does not change the authority
boundary: native synchronization may inspect the mempool and prepare future
templates, but it cannot publish authoritative jobs or accept solved candidates
without the private `MiningAuthorityPermit` issued by `hns-node`.

## Data flow

```text
peer or local transaction
        |
        v
bounded admission pipeline
        |
        +-- unresolved input -> bounded orphan pool
        |
        +-- accepted -> immutable mempool generation
                              |
                              v
                    package-aware template builder
                              |
                              v
                    bounded future-template set
                              |
                       exact generation activation
                              |
                              v
                     prepared MeshMine mining job
```

Solved blocks use a separate critical path:

```text
solved candidate
        |
        v
private authority capability check
        |
        v
checksummed durable publication intent
        |
        v
full local candidate admission and state connection
        |
        v
parallel critical fan-out to ready HNS peers
        |
        +-- at least one peer write completed -> delete intent
        |
        +-- no peer write completed -> retain intent for safe retry
```

A persisted intent is never retried unless the corresponding block is already a
locally accepted active block. This prevents an intent written before a failed
local connection from becoming a network publication source.

## Mempool

`hns-mempool` provides:

- explicit transaction, byte, orphan, ancestor, and descendant bounds;
- immutable snapshots identified by a monotonically increasing generation;
- parent/child and spent-outpoint indexes;
- package construction in dependency order;
- ancestor fee and weight accounting;
- bounded orphan retention and deterministic oldest-first eviction;
- HSD exclusive-name admission and deterministic accepted-name overlay replay;
- HSD 72-hour dependency-root expiry and descendant-aware fee eviction to the
  90% trim target;
- HSD confirmed-coin free priority and exponentially decaying low-fee relay
  limiting;
- atomic active-chain reconciliation with complete retained-pool revalidation
  and contextual ordinary-transaction re-admission after disconnects;
- native HSD airdrop/faucet proof admission against deployment flags and the
  durable allocation field, with hash/position indexes and unified size trim;
- native HSD DNSSEC claim admission against the exact parent time, deployment
  flags, active name state, and canonical commit ancestry, with hash/name
  indexes, ordinary-name exclusivity, replacement rules, and unified size trim;
- explicit verifier-completeness gates.

The compatibility `Mempool::submit` entrypoint rejects with
`verified-mempool-context-required`. Production admission must use
`submit_with_context` with complete input and contextual verifiers. The
mining-engine peer boundary now does so for ordinary transactions using one
immutable active-chain snapshot, deployment-derived name flags, HSD's 1,000
minimum relay rate, the native script backend, and the live accepted-name
overlay. Typed claim and airdrop packets use dedicated proof-capable admission
paths and are relayed by their HSD inventory hashes.
Mainnet transaction/output and witness
standardness, standard script flags, dust, and absurd-fee checks are active.
Every direct active extension atomically rebuilds retained transactions and
orphans through the same complete context, promoting newly resolvable inputs
and advancing the generation once only when membership changes. Disconnects
and reorganizations additionally consider ordinary transactions and special
coinbase proofs from disconnected blocks before the retained pool, preserving
HSD's older-name-update priority while the final replacement-chain view rejects
conflicts. The pinned
height-62,517 case and the 39,086-39,101 -> 76,722 replacement history establish
exact proof/accounting, parent-header-time, retained-value, and commit-advance
behavior for bounded real mainnet claims, but they are not full-chain
qualification. A separate 28-case pinned-HSD corpus now covers every non-claim
contextual transition family with exact accepted post-states and targeted
rejections; it is deterministic regtest evidence, not mainnet replay.

## Template construction

`TemplateAssembler` consumes exactly one immutable chain snapshot and one
immutable mempool snapshot. The resulting template commits to:

- network identifier;
- active mining generation;
- mempool generation;
- parent block;
- next authenticated name-tree root;
- reserved root;
- version, target, and minimum time;
- public mask commitment;
- exact transaction count and bytes.

Packages are selected deterministically by ancestor-inclusive fee rate using
HSD's sigop-adjusted virtual size, then by oldest sequence and transaction
identifiers. Actual transaction weight remains separate and controls the block
weight bound. Selection also enforces explicit sigops, OPEN, UPDATE, RENEW,
transaction-count, and exclusive-name bounds. Coinbase, subsidy, mempool sigop
policy, and adjusted-size boundaries are checked against fixtures generated by
the pinned HSD revision. Claims are fee-rate ranked before airdrops and ordinary
packages, bounded to ten, charged against UPDATE and weight limits, and rendered
into their exact same-index coinbase inputs/outputs. Only an initial
`commitHeight == 1` claim fee increases the miner payout, matching HSD.

The base header version, target, and timestamp floor are not unconstrained
variant fields. Each durable mining snapshot carries the median timestamp of
the active tip and up to ten ancestors. Before template assembly, the node
re-reads the canonical tip and exact header context, verifies that cached MTP,
advances the parent-derived deployment cache for the next height, computes
HSD's exact `computeBlockVersion` result, and computes HSD's next target for the
requested minimum time. A time at or below parent MTP, a time beyond the
consensus future limit, or any caller-supplied version/target mismatch rejects
the entire atomic rebuild without replacing the prior template set. The
prepared job also carries the last timestamp for which non-reset testnet target
bits remain valid and rejects reconstruction beyond HSD's
`parent.time + 2 * targetSpacing` reset boundary, forcing a template refresh.
The canonical 168-period mainnet history pins the deployment calculation
against HSD through height 338,688; the shared import/template target path is
covered by the pinned difficulty vectors and native composition tests.

`TemplateCoordinator` atomically replaces a bounded set of variants for one
chain/mempool generation. If any variant fails, the previous set remains intact.
Activation rechecks the durable chain generation, parent, and next tree root.
Every active-chain generation change clears the derivative cache.

## Publication durability

`SolvedBlockPublicationIntent` is versioned, checksummed, and stored under the
`Snapshots` column family using the `publication/v1/` prefix. It commits to the
mining generation, job ID, block hash, creation time, and exact encoded block.

The publication sequence is intentionally local-first:

1. Validate the candidate against the current authority capability.
2. Persist the intent.
3. Connect the candidate through the ordinary local block-admission path.
4. Fan the accepted block out through every ready peer's reserved critical
   writer concurrently and await socket-write completion independently.
5. Remove the intent after at least one peer writer completes the socket write.

If step 3 returns an error, the service re-reads the canonical block record
before treating the candidate as failed. This distinguishes a pre-commit
validation failure from a post-commit operational notification failure. A
confirmed post-commit condition continues publication and is returned as a
warning. If a crash interrupts the sequence, retry first verifies that the
block is a locally accepted active record. A zero-peer or zero-completed-write
fan-out is returned as `publication_pending`, not as a false local-connection
failure.

## Mempool and chain transitions

A direct active-chain extension removes included/conflicting transactions,
mined claim names, and mined airdrop positions from the mempool. A disconnect
or reorganization atomically rebuilds the retained pool against the final chain
snapshot and re-admits eligible ordinary transactions from disconnected blocks
in oldest-block order, then re-admits valid claims and airdrop proofs from
disconnected coinbases after name state and the allocation bitfield have been
rewound. Retained claims are revalidated first so an expired claim cannot block
a valid ordinary name transaction. Internal view failures still clear the pool
fail closed.
Mining-template caches are cleared whenever the durable chain generation
advances or an accepted mempool generation changes.

## Diagnostics and operation

`getminingengineinfo` and `/api/v1/mining-engine` report:

- whether the mining engine is enabled;
- observation-only status;
- transaction-relay status;
- accepted/orphan counts, bytes, fees, and generation;
- configured and cached template variants;
- pending publication intents;
- retry interval and queue capacity;
- shadow-template readiness;
- solved-block publication readiness and blockers.

The command-line controls are bounded by hard maximums and include mempool,
template-variant, pending-publication, and retry parameters.

## Deliberate release boundary

The mining engine is a foundation, not production HNS mining authority. The following
remain release-blocking:

- historical replay qualification;
- independent script fuzz/invalid evidence beyond the pinned HSD corpus;
- current/live claim-proof evidence and complete historical replay beyond the
  pinned initial/replacement histories for the active deployment-composed
  proof/accounting service;
- complete contextual name-state parity;
- deployment-scale Urkel compaction performance/priority qualification and
  RocksDB mid-commit process-crash/fault injection;
- qualified full-mainnet active-state IBD and live HSD state comparison;
- measured production template and solved-block latency;
- native mainnet authority qualification.
