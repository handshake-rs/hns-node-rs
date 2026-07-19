# Security model

`hsrd` verifies consensus locally. Peers, snapshots, control clients, MeshMine
inputs, caches, fixtures, and local databases are untrusted until promoted by
an explicit validation stage. Until all parity gates pass, `hsd` remains the
production oracle and `hsrd` has no native mainnet authority.

## Current trust boundary

The current foundation verifies or records evidence for:

- exact network/genesis/storage-profile identity;
- proof-of-work, unsigned 256-bit chainwork, HNS difficulty transitions, and
  median/future timestamp bounds;
- bounded primitive encoding and block body commitments/syntax;
- ordinary subsidy-plus-fee limits, absolute locktime finality, and UTXO/undo
  invariants for missing, duplicate, immature, inflationary, and colliding
  spends;
- HSD-compatible signature-hash and relative-lock primitives;
- a bounded witness/script foundation behind a pluggable signature verifier;
- exact non-coinbase covenant input/output linkage and local commitments;
- atomic single- and multi-block database mutations;
- sequence-consistent database snapshots;
- durable validation-stage, authority-mode, readiness, and parity diagnostics.

The production default input verifier rejects every non-coinbase spend. This is
intentional: an unavailable or incomplete signature backend is not treated as
successful authorization.

The following remain untrusted and release-blocking:

- complete script/opcode/flag/historical behavior and audited secp256k1 checks;
- deployments, checkpoints, and historical exceptions;
- claim and airdrop proofs/accounting;
- contextual covenant, auction, ownership, renewal, transfer, and expiration
  rules;
- name-state mutation and Urkel root agreement;
- complete alternate-chain/reorganization parity;
- live P2P, synchronization, mempool, template, and solved-block relay;
- historical replay, invalid-corpus, and live shadow evidence.

## Authority policy

- `disabled`: no mining authority.
- `shadow`: default; staged state and comparisons are diagnostic only.
- `hsd-verified`: reserved until a composed HSD verification path exists; it
  fails configuration validation today.
- `native-experimental`: requires the `experimental-authority` Cargo feature,
  an explicit incomplete-consensus acknowledgement, and a non-production
  network. It is not a mainnet release mode.

An authoritative mining tip requires complete consensus validity, UTXO and name
state connection, tree-root agreement, undo durability, and active-chain
membership. A merely staged tip is never placed on the authoritative snapshot
channel.

## Fixture and oracle policy

- HSD fixtures are pinned to an exact 40-character commit ID.
- Every fixture manifest entry contains a BLAKE2b-256 digest of its exact bytes.
- The loader and static validator reject missing, altered, duplicate, or
  path-escaping fixture entries.
- Fixture-only chainwork overrides are private and compiled only for tests.
- Oracle generators support reproducibility checking and fail when committed
  outputs drift.

Fixtures are evidence, not authority. Historical replay and independently
reviewed behavior remain mandatory.

## Failure policy

- Invalid or unsupported consensus data fails closed.
- Malformed parser input returns bounded errors rather than panicking.
- Signature-verifier absence rejects spends.
- Coinbase claim/airdrop issuance rejects until proof verification exists.
- A failed staged reorganization commits no durable operation.
- Snapshot mismatch rejects before state import.
- Schema, network, genesis, or storage-profile mismatch requires explicit
  reindex/operator action.
- The control API never labels staged data as authoritative or confirmed.
- Trusted snapshot mode remains disabled unless explicitly implemented and
  configured.

## Review checklist

- Parser lengths and collection counts are bounded and fuzzed.
- P2P payloads reject wrong network magic and oversize messages.
- Async socket tasks do not run consensus validation or database writes inline.
- Header sync validates difficulty and PoW before promotion.
- Raw block storage never implies complete block validity.
- Script, covenant linkage, contextual covenants, name state, and tree-root
  validation remain separately observable.
- Transaction authorization and covenant linkage finish before spends are
  staged.
- Reorganization undo and replacement state share one atomic batch.
- Name-state updates are derived from validated covenants and block order, not
  peer assertions.
- Peer inventories, orphans, queues, templates, publication attempts, and
  control requests have explicit bounds.
- Snapshot chunks and manifests are hash-checked.
- Assume-valid or snapshot modes, when implemented, are visible in diagnostics.
- Control mutations require authentication and bind to loopback by default.
- No wallet, key-management, DNS, or domain-action surface is linked into the
  node.
- No SQLite path exists for consensus-critical state.
