# hsrd

`hsrd` is the lean Handshake mining full node being built for MeshMine. Its
product boundary is the minimum complete consensus, state, synchronization,
template, and relay path required to mine valid HNS blocks with predictable
latency.

It is deliberately not a wallet, desktop application, domain manager, DNS
server, explorer, or general `hsd` compatibility distribution. MeshMine uses
native in-process Rust interfaces for mining; the bounded HTTP control surface
exists only for diagnostics, operations, and differential testing.

## Current release stage

`hsrd` remains **pre-authority**. `hsd` is still the behavioral and production
oracle. The default authority mode is `shadow`, and a native experimental mode
requires an explicit Cargo feature, an explicit runtime acknowledgement, and a
non-production network. No incomplete validation stage is represented as full
Handshake consensus validity.

The current tree contains three coordinated implementation phases:

### Phase 1 — authority safety and verification

- The complete nested `hsrd` workspace is included in CI formatting, Clippy,
  test, feature-matrix, release-build, and RustSec jobs.
- Durable block status is split into explicit validation and state stages rather
  than coarse `tx_valid` or `state_connected` booleans.
- Authority modes, readiness blockers, parity diagnostics, and read-only status
  endpoints fail closed.
- Multi-block reorganizations are staged against one immutable snapshot and
  committed as one database batch.
- RocksDB reads use a real sequence-consistent snapshot.
- Fixture imports and caller-supplied chainwork are test-only.
- Persistent schema version 5 is an intentional reindex boundary.

### Phase 2 — transaction authorization foundation

- HSD-compatible Handshake signature hashing is implemented for all defined
  base modes and NOINPUT/ANYONECANPAY modifiers.
- Relative sequence-lock calculation plus CLTV/CSV predicates are implemented.
- A bounded version-zero witness-program/script interpreter foundation exists,
  with Handshake BLAKE160/BLAKE256/SHA3/Keccak operations.
- Spent coins persist their address, which is required for witness validation.
- Non-coinbase state connection is fail-closed unless a transaction-input
  verifier is explicitly installed. The current default does not silently
  authorize spends.
- Deterministic Phase 2 fixtures are reproduced from the pinned HSD revision.

The Phase 2 script path is not yet consensus-complete: an audited secp256k1
signature backend, full historical flag selection, complete opcode parity, and
historical replay remain release gates.

### Phase 3 — covenant linkage and durable best-chain activation

The phase is deliberately split into two independent foundations. Neither is
promoted to full Handshake consensus authority.

**Covenant linkage**

- The non-coinbase linkage portion of
  `hsd/lib/covenants/rules.js::verifyCovenants` is implemented as a deterministic
  storage-independent consensus function.
- BID/REVEAL blind commitments, linked output indexes, name/start commitments,
  locked values, addresses, TRANSFER destinations, REVOKE burns, and unknown
  covenant restrictions are checked before UTXO mutation.
- A pinned HSD oracle corpus currently covers 33 accepted and rejected linkage
  cases, including multi-input index alignment.
- `covenant_links_valid` is deliberately separate from
  `covenants_context_valid`: Phase 3 does not claim auction-phase, ownership,
  rollout, renewal, expiration, name-state, or Urkel validation.

**Best-chain activation**

- Validated non-active headers, block indexes, and raw block bodies are retained
  by hash without rewriting the active `height_index`.
- The persisted best-header binding advances only for strictly greater
  chainwork; equal-work branches preserve the existing first-seen tip.
- Reorganization plans are derived between the active block tip and a stored
  candidate, then checked for ancestry, contiguous heights, canonical
  disconnects, body availability, status prerequisites, and increasing work.
- A complete disconnect/connect replacement is applied through one
  read-your-writes staging overlay and one durable batch. Intermediate tips are
  never committed.
- Startup recovery of a fully stored higher-work branch is restricted to the
  explicitly gated regtest/simnet native-experimental path. Shadow mode remains
  observation-only.
- Diagnostics distinguish the best known header from the active best block and
  expose pending activation, alternate-block count, chain epoch, storage
  profile, and durability policy.

This is a side-chain and atomic-activation foundation, not a claim of complete
historical fork-choice parity. Orphan inventory, header-first synchronization,
checkpoints/deployments, scripts, contextual name rules, Urkel roots, pruning,
and mainnet reorganization replay remain release gates.

## Remaining authority gates

At minimum, native authority still requires:

- an audited signature-verification backend and complete script parity;
- deployment and checkpoint parity;
- claim and airdrop proof/accounting validation;
- complete contextual covenant and name-state transitions;
- production Urkel mutation, undo, proof, snapshot, and root parity;
- full side-chain, historical reorganization, and historical exception parity;
- live HNS P2P, synchronization, mempool/template construction, and priority
  solved-block relay;
- complete mainnet replay, invalid-corpus differential tests, and sustained live
  shadow agreement.

See [`docs/mining-node-scope.md`](docs/mining-node-scope.md),
[`docs/gap-analysis.md`](docs/gap-analysis.md), and
[`docs/phase-1-3-change-report.md`](docs/phase-1-3-change-report.md).
The source-level `hsd` keep/adapt/remove map is in
[`docs/hsd-decomposition.md`](docs/hsd-decomposition.md).

## Verification

The intended verification sequence is:

```bash
python3 scripts/validate-hsrd-static.py
npm ci --prefix hsd-oracle --ignore-scripts
npm run hsrd-phase2-fixtures --prefix hsd-oracle
npm run hsrd-phase3-fixtures --prefix hsd-oracle
cargo fmt --manifest-path hsrd/Cargo.toml --all --check
cargo clippy --locked --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --all-features
cargo test --locked --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --no-default-features
cargo build --locked --release --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --all-features
```

The static and HSD fixture checks can run without a Rust toolchain. They are not
a substitute for the Cargo gates.

## Storage migration

Schema version 5 changes durable block-status bit assignments and the UTXO coin
codec. Existing pre-authority databases must be reindexed; no implicit migration
is attempted.
