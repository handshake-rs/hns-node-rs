# Mining engine

The bounded, fail-closed mining engine builds on the durable chain snapshots.
It does not change the authority
boundary: shadow mode may inspect the mempool and build future templates, but it
cannot publish authoritative jobs or accept solved candidates without the
private `MiningAuthorityPermit` issued by `hns-node`.

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
- block-confirmation reconciliation;
- fail-closed clearing on reorganizations until disconnected transactions can
  be contextually re-admitted;
- explicit verifier-completeness gates.

The compatibility `Mempool::submit` entrypoint rejects with
`verified-mempool-context-required`. Production admission must use
`submit_with_context` with complete input and contextual verifiers. Mining-engine
peer relay therefore remains deliberately fail closed while the documented
broader claim-history and historical-qualification gaps remain. The pinned
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

Packages are selected deterministically by ancestor-inclusive fee rate, then by
oldest sequence and transaction identifiers. Selection enforces explicit
weight, sigops, OPEN, UPDATE, RENEW, transaction-count, and exclusive-name
bounds. The coinbase and subsidy boundary are checked against fixtures generated
by the pinned HSD revision.

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

A direct active-chain extension removes included and conflicting transactions
from the mempool and advances the mempool generation at most once. A disconnect
or reorganization clears the mempool conservatively because contextual
re-admission of disconnected transactions is not yet consensus complete.
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
- production Urkel compaction scheduling/scale qualification and RocksDB
  process-crash/fault qualification;
- active-state IBD and live HSD state comparison;
- contextually complete peer transaction admission;
- measured production template and solved-block latency;
- native mainnet authority qualification.
