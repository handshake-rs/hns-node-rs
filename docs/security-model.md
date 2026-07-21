# Security model

`hsrd` verifies consensus locally. Peers, snapshots, control clients, MeshMine
inputs, caches, fixtures, synchronization checkpoints, and local databases are
untrusted until promoted by an explicit validation stage. Until every parity
gate passes, the pinned `hsd` revision remains the production oracle and
`hsrd` has no native mainnet authority.

## Current trust boundary

The current foundation verifies or records evidence for:

- network/genesis/schema/storage-profile identity;
- durable name-tree-root binding to materialized name state;
- proof-of-work, unsigned 256-bit chainwork, difficulty transitions, and
  timestamp bounds;
- bounded primitive encoding and block syntax/commitments;
- ordinary subsidy-plus-fee limits, absolute and relative locks, UTXO/undo
  invariants, and value conservation;
- HSD-compatible signature hashes and a native pinned secp256k1 verification
  backend;
- bounded witness/script execution for the implemented operation set;
- exact non-coinbase covenant linkage;
- contextual non-claim name-transition foundations;
- correctness-first exact Urkel roots;
- atomic single- and multi-block database mutations;
- sequence-consistent snapshots;
- bounded HNS framing, peer lifecycle, header synchronization, body scheduling,
  stateless validation, non-active body retention, and restart checkpoints;
- bounded in-memory mempool/orphan storage, immutable generations, dependency
  packages, deterministic future templates, and HSD-derived coinbase behavior;
- versioned checksummed solved-block publication intents, local candidate
  admission before fan-out, and parallel reserved critical publication queues;
- granular validation, authority, readiness, parity, peer, synchronization, and
  mining-engine diagnostics.

The default input verifier rejects non-coinbase spends. Native script
verification must be selected explicitly. Successful configured script/name
checks do not imply global mainnet authority; historical and live evidence
remain separate gates.

Shadow-network input is observation-only. Downloaded bodies remain non-active,
do not mutate UTXO/name state, and cannot produce a mining authority capability.
The mining engine may build diagnostic future templates from a durable active snapshot,
but peer transaction admission remains fail closed and solved-block staging,
connection, and publication require the same private authority capability as
the existing authoritative mining boundary.

The following remain untrusted and release-blocking:

- complete script/deployment/checkpoint/historical behavior;
- claim and airdrop proofs/accounting;
- complete contextual name consensus over all historical cases;
- persistent production Urkel nodes and HSD proof-wire parity;
- active-state IBD, pruning, and complete alternate-chain/reorganization parity;
- Brontide, durable peer reputation, discovery, compact blocks, and
  production-complete contextual transaction relay;
- disconnected-transaction re-admission, production template qualification,
  continuously supervised publication retry, and measured publication latency;
- complete mainnet replay, invalid corpus, and sustained live HSD shadow
  agreement.

## Authority policy

- `disabled`: no mining authority.
- `shadow`: default; staged state and comparisons are diagnostic only.
- `hsd-verified`: reserved until the independent HSD verifier boundary exists;
  configuration currently fails closed.
- `native-experimental`: requires the `experimental-authority` Cargo feature,
  explicit incomplete-consensus acknowledgement, and regtest/simnet.

Live networking is accepted only in `disabled` or `shadow` mode.
The mining engine cannot manufacture the private authority capability through its
configuration, template cache, mempool, diagnostics, or durable intent queue.

A private `MiningAuthorityPermit` is required by authoritative mining
subscriptions and candidate admission. Normal modes do not receive it. Future
mainnet modes must issue the same capability only after complete readiness and
an authoritative durable tip.

## Network-input policy

- Frame magic and payload length are checked before allocation.
- Packet collections and all runtime queues have explicit limits.
- Socket tasks decode/encode and emit events; they do not validate consensus or
  write the database.
- CPU-heavy block-body checks run outside async socket workers.
- One process-local unpredictable nonce is shared across local sessions so a
  connection to the node's own listener is rejected as self-connection.
- Duplicate socket addresses and over-capacity registrations fail under the
  peer-manager registration lock.
- Invalid header batches consume the outstanding request and disconnect the
  sender at the current score threshold. Any valid durable prefix remains
  tracked by the scheduler.
- A body without known header context is dropped after requesting headers; it
  is not retained as an unvalidated orphan.
- A body with known header context but unavailable parent body is retained only
  after stateless validation and within count/byte bounds.
- Peer scores, reconnect timers, inflight requests, and orphan bodies are
  currently process-local and are not trusted after restart.
- The synchronization checkpoint is checksummed and reconciled with durable
  chain/body state rather than trusted as consensus.

## Mining-engine and publication policy

- Every mempool, orphan, package, template, and publication collection has a
  configured bound and a compiled hard ceiling.
- The compatibility mempool entrypoint and peer relay reject until complete
  contextual input and transaction verifiers are composed.
- A template consumes one immutable durable chain snapshot and one immutable
  mempool snapshot and records both generations.
- Cached activation rechecks generation, parent, and next authenticated tree
  root; cache entries are derivative state and are cleared on relevant chain or
  mempool transitions.
- A publication intent is durable recovery evidence, not proof that a block is
  valid or permission to send it.
- Solved-block network fan-out occurs only after the ordinary local candidate
  admission path accepts the block as active. A returned local error is not
  classified as pre-commit failure until the canonical active record is
  re-read.
- Restart retry rechecks that the intent's block is a locally accepted active
  record before any peer writer receives it for socket transmission.
- A zero-peer fan-out keeps the intent pending; it does not roll back or
  misreport the successful local chain connection.
- Ordinary block and transaction serving cannot consume the reserved critical
  publication lane.

## Name-tree invariants

- The durable root must equal a rebuild from all non-null materialized
  `NameState` records.
- A block header must equal the inherited pre-state root.
- The current block's transitions produce the next root.
- Connect and disconnect record previous/resulting roots in undo.
- Disconnect must begin at the undo's resulting root and end at its previous
  root.
- Name-state and root changes share the same atomic batch.
- Null states are deleted, never authenticated as values.

## Fixture and oracle policy

- HSD fixtures are pinned to an exact 40-character revision.
- Every manifest entry has a BLAKE2b-256 digest.
- Loaders reject missing, altered, duplicate, or path-escaping entries.
- Fixture chainwork overrides compile only for tests.
- Generators support reproducibility checks and fail on drift.

Fixtures are evidence, not authority.

## Failure policy

- Unsupported consensus data fails closed.
- Malformed parser input returns bounded errors rather than panicking.
- Missing signature verification rejects spends.
- Claim/airdrop issuance rejects until proof validation exists.
- Missing deployment-derived name flags reject contextual name transitions.
- A failed staged reorganization commits no durable operation.
- Root, schema, network, genesis, or profile mismatch requires explicit operator
  action/reindex.
- Unexpected shadow-network supervisor/channel/task failure leaves the store marked
  unclean.
- A corrupt or over-capacity publication queue fails diagnostics/recovery rather
  than silently dropping solved-block evidence.
- Diagnostic APIs do not label staged or shadow state as authoritative.
- Trusted snapshot mode remains disabled until explicitly implemented.

## Review checklist

- Parser lengths and collection counts are bounded and fuzzed.
- P2P payloads reject wrong magic and oversized messages.
- Async socket tasks do not perform consensus validation or database writes.
- Raw body presence never implies full block validity.
- Scripts, covenant linkage, contextual covenants, claims/airdrops, name state,
  and root validity remain separately observable.
- Authorization and covenant/name checks finish before spend staging.
- Reorganization undo and replacement state share one batch.
- Root metadata and materialized name state are checked before state mutation.
- Peer inventories, orphans, queues, templates, publication attempts, and
  control requests have explicit bounds.
- Shadow-network input cannot issue or bypass a mining authority permit.
- Template, mempool, intent, retry, and fan-out paths cannot issue or
  bypass a mining authority permit.
- Local solved-block admission precedes every peer publication attempt.
- No wallet, key-management, DNS, domain-action, or SQLite consensus surface is
  linked into the node.
