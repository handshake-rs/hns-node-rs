# Testing strategy

## Fast static gate

`python3 scripts/validate-hsrd-static.py` runs without a Rust toolchain and
checks:

- every repository `Cargo.toml` and JSON file parses;
- fixture manifest schema, unique IDs, safe relative paths, exact oracle pin,
  file presence, and BLAKE2b-256 digests;
- HSD package and lockfile revision pinning;
- schema version and granular block-status coordination;
- fixture-only chainwork restrictions;
- authority-mode safety tokens and absence of premature production-stage flags;
- Phase 2/3 module boundaries and the ordering of authorization/linkage before
  UTXO mutation.

This is a fail-fast integrity gate, not a compiler or consensus proof.

## Pinned HSD fixtures

The oracle is pinned to HSD commit
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.
Committed generators support `--check` reproducibility mode:

```bash
npm run hsrd-phase2-fixtures --prefix hsd-oracle
npm run hsrd-phase3-fixtures --prefix hsd-oracle
```

Current generated evidence includes:

- signature-hash vectors covering every defined base mode and modifier
  combination across multiple inputs;
- signature-type encoding validity;
- relative sequence-lock cases;
- 33 accepted/rejected non-coinbase covenant-linkage cases, including blind bid
  checks, linked output indexes, transfer commitments, revoked coins, unknown
  covenants, and multi-input alignment.

The Rust fixture loader independently validates every committed digest before
returning the manifest.

## Cargo gates

The nested `hsrd` workspace is independently exercised in CI:

```bash
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

The root and nested lockfiles are audited separately with pinned `cargo-audit`.

## Consensus fixture expansion

Further fixtures are mandatory for valid and invalid scripts, signature
backends, deployments, checkpoints, claims, airdrops, contextual covenants,
name transitions, Urkel roots, undo, difficulty boundaries, historical
exceptions, and reorganizations. Every fixture records network and exact oracle
revision; unexplained compatibility exceptions are forbidden.

## Differential replay

For every mainnet block and mutation-corpus case, compare:

- accept/reject and normalized reason;
- best hash, height, bits, and chainwork;
- UTXO additions/removals;
- name-state transition and Urkel root;
- deployment state;
- undo, disconnect, and reconnect result;
- candidate/template commitments where applicable.

A mismatch fails closed and cannot be converted into a silent exception.

## Integration and fault tests

- Multiple peers, parallel download, malicious/stalled peer replacement,
  serving, orphan bounds, and reconnect.
- Restart/crash at raw-block, validation, undo, state-batch, tip-promotion,
  template, and publication-intent boundaries.
- Reorganizations across scripts, deployments, covenants, claims/airdrops,
  name state, and pruning.
- A failed multi-step reorganization must preserve every durable key and mining
  generation.
- Mempool conflicts, dependencies, eviction, and template replacement.
- Tip commit to job activation and candidate receipt to first accepted relay.
- Priority isolation while sync, compaction, diagnostics, and slow peers
  saturate lower lanes.

## Fuzzing

Fuzz P2P, header, transaction, block, witness/script, covenant, resource,
Urkel, snapshot, diagnostic, and native MeshMine-boundary parsers. Allocation
bounds are part of the fuzz assertions.

## Performance evidence

Report count, P50, P95, P99, maximum, failure count, and unavailable evidence
for header/block validation, ordered state mutation, reorganization commit,
storage, IBD, tip-to-job, candidate validation, and each publication target.
Mean throughput alone is not a release gate.
