# Testing strategy

## Fast static gate

`python3 scripts/validate-hsrd-static.py` runs without a Rust toolchain and
checks:

- every repository `Cargo.toml` and JSON file parses;
- fixture manifest schema, unique IDs, safe relative paths, exact oracle pin,
  file presence, and BLAKE2b-256 digests;
- HSD package/lock revision pinning;
- schema version, profile, root marker, sync checkpoint, and block-status
  coordination;
- fixture-only chainwork restrictions;
- authority-mode safety tokens;
- authorization, covenant, name-transition, and spend-staging order;
- correct pre-state root validation before transaction mutation;
- null-state deletion and durable root binding;
- observation-only network wiring, resource ceilings, frame limits, peer/sync
  modules, and CLI configuration;
- mempool/template/publication bounds, fixture wiring, local-first
  publication ordering, authority checks, and schema/profile coordination.

This is a fail-fast integrity gate, not a compiler or consensus proof.

## Complete offline source-handoff gate

```bash
scripts/verify-hsrd-source-handoff.sh
```

This reproducible wrapper runs the static authority/schema validator, direct
Cargo-lock/path-dependency coverage, Rust lexical-balance checks, every pinned
HSD fixture generator in check mode, baseline MeshMine/HSD body and payout
oracles, the vendored secp256k1 C smoke test, source-language syntax checks,
Git whitespace checks, and merge-conflict-marker detection. It is suitable for
source handoffs on machines that do not have Rust installed. The wrapper gives
the npm advisory service a bounded timeout and reports an unavailable service
without disguising that audit as successful. CI separately runs strict
`npm run audit`. The offline wrapper does not replace that strict audit or the
Cargo gates below.

## Pinned HSD fixtures

The oracle is pinned to HSD commit
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.
Generators support `--check` reproducibility mode:

```bash
npm run hsrd-script-fixtures --prefix hsd-oracle
npm run hsrd-covenant-fixtures --prefix hsd-oracle
npm run hsrd-name-state-codec-fixtures --prefix hsd-oracle
npm run hsrd-name-state-urkel-fixtures --prefix hsd-oracle
npm run hsrd-name-policy-fixtures --prefix hsd-oracle
npm run hsrd-p2p-wire-fixtures --prefix hsd-oracle
npm run hsrd-mining-template-fixtures --prefix hsd-oracle
```

Current evidence includes:

- signature-hash vectors for every defined base mode/modifier combination;
- signature-type encoding validity;
- relative sequence-lock cases;
- 56 HSD-executed witness-program cases spanning control flow, stack and
  numeric operations, hashes, native `CHECKSIG`/`CHECKMULTISIG`, CLTV/CSV,
  disabled/unknown opcodes, and policy flags with normalized HSD rejection
  codes;
- 33 covenant-linkage accepted/rejected cases;
- exact HSD `NameState` encoding vectors;
- incremental HSD Urkel roots with explicit header/pre-state and
  resulting/post-state roots;
- reserved-name and lockup dataset checks;
- renewal-commitment maturity/period boundary checks;
- exact HNS frames, version packets, addresses, service normalization,
  `noRelay`, ASCII handling, inventory, locators, headers, blocks, and rejects;
- HSD subsidy boundaries and deterministic mining-template coinbase bytes.

## Native secp256k1 smoke gate

```bash
scripts/verify-hsrd-secp256k1.sh
```

This independently compiles the vendored C source with the same configuration
as `hns-secp256k1`, then verifies the deterministic low-S signature fixture and
rejects an altered message. It checks the pinned native dependency and ABI
surface without depending on Cargo.

## Cargo gates

The nested workspace is independently exercised:

```bash
cargo metadata --locked --manifest-path hsrd/Cargo.toml --format-version 1
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

Root and nested lockfiles are audited separately with pinned `cargo-audit`.

## State and storage invariants

Tests must cover:

- empty-schema initialization with a zero root;
- missing/malformed schema/profile/root/checkpoint markers;
- markerless nonempty databases;
- root versus materialized-state corruption;
- pre-state block-header root timing;
- atomic connect/disconnect root transitions;
- multi-block staged root transitions;
- equal-work branch stability and greater-work activation;
- header-index memory publication only after durable commit;
- failure before commit leaving every durable key unchanged;
- true snapshot consistency during concurrent writes;
- WAL/sync restart points and fault-injected batch failure.

## Network and synchronization tests

Tests and fault harnesses should cover:

- exact frame boundary handling, wrong magic, unknown packet types, truncation,
  oversized payloads, and oversized collection counts;
- inbound/outbound capacity races and duplicate-address registration;
- process-local self-connection detection through the node's own listener;
- handshake, idle, ping, pong, request, and reconnect timeouts;
- priority-lane isolation and queue saturation;
- invalid header batches with a durable valid prefix;
- known and unknown header/body ordering;
- bounded pending/inflight/per-peer body requests and reassignment;
- stateless validation result ordering despite out-of-order worker completion;
- orphan count/byte eviction and local resubmission;
- checkpoint corruption, stale checkpoint recovery, and `Validating` restart;
- read-only bounded serving and slow-peer backpressure;
- abnormal supervisor/channel/task termination leaving the database unclean;
- proof that no shadow-network path can issue a `MiningAuthorityPermit`.

## Mempool, template, and publication tests

Tests and fault harnesses should cover:

- hard accepted-transaction, byte, orphan, ancestor, descendant, package,
  template-variant, and publication-intent bounds;
- duplicate/conflict rejection, dependency indexes, deterministic package
  order, orphan promotion, and oldest-first bounded orphan eviction;
- explicit rejection when input or contextual verification is incomplete;
- one-generation advancement for a block reconciliation and conservative
  clearing on disconnect/reorganization;
- deterministic package ranking and selection under HNS weight, sigops, OPEN,
  UPDATE, RENEW, transaction-count, and exclusive-name limits;
- atomic template-set replacement: any failed variant preserves the previous
  complete cache;
- activation rejection for stale chain generation, mempool generation, parent,
  or next tree root;
- publication-intent checksum, key/hash binding, capacity, idempotence, and
  corrupted-record rejection;
- proof that local candidate admission precedes every solved-block network
  broadcast;
- retry rejection for intents whose block is not a locally accepted active
  record;
- zero-peer publication remaining durable and pending after successful local
  connection;
- parallel critical fan-out isolation from ordinary block/transaction serving;
- crash/restart points before intent commit, after intent commit, after local
  connection, after the first completed peer socket write, and before intent deletion;
- proof that shadow templates and peer transactions cannot issue or bypass a
  `MiningAuthorityPermit`.

## Differential replay

An exact pinned HSD checkout can export its complete upstream script corpus for
the Rust differential verifier without adding machine-specific source paths to
the committed fixture set:

```bash
NODE_BACKEND=js node hsd-oracle/generate-hsrd-script-fixtures.js \
  --hsd-source /path/to/hsd \
  --full-script-output /tmp/hsrd-hsd-script-corpus.json
cargo run --locked --manifest-path hsrd/Cargo.toml -p hns-consensus \
  --example verify_hsd_script_corpus -- /tmp/hsrd-hsd-script-corpus.json
```

The exporter requires the exact pinned Git revision, reruns every declared HSD
case through that checkout's script engine, and refuses source/result drift.
The Rust verifier compares all normalized success and rejection codes and exits
nonzero on any mismatch.

The committed deployment/checkpoint fixture is generated through HSD's own
`Chain.getState`, `getDeployments`, `computeBlockVersion`, and historical
boundary methods:

```bash
NODE_BACKEND=js npm run hsrd-deployment-fixtures --prefix hsd-oracle
```

It pins all network deployment parameters and mainnet checkpoint hashes, then
checks compact synthetic histories across DEFINED, STARTED, LOCKED_IN, ACTIVE,
FAILED, timeout, partial-period, and per-deployment window/threshold behavior.

For every mainnet block and mutation-corpus case, compare:

- accept/reject and normalized reason;
- best hash, height, bits, and chainwork;
- UTXO additions/removals;
- name transition and both inherited/resulting roots;
- deployment state;
- undo, disconnect, reconnect, and reorganization result;
- candidate/template commitments where applicable.

A mismatch fails closed and cannot become a silent compatibility exception.

## Integration and fault tests

- Multiple peers, parallel download, malicious/stalled peer replacement,
  serving, orphan bounds, and reconnect.
- Restart/crash at raw-block, validation, undo, state-batch, root-binding,
  tip-promotion, sync-checkpoint, template, and publication boundaries.
- Reorganizations across scripts, deployments, covenants, claims/airdrops,
  name state, roots, and pruning.
- A failed multi-step reorganization preserves every durable key, root, epoch,
  and mining generation.
- Mempool conflicts, dependencies, eviction, and template replacement.
- Tip commit to job activation and candidate receipt to first accepted relay.
- Priority isolation under sync, compaction, diagnostics, and slow-peer load.

## Fuzzing

Fuzz P2P, header, transaction, block, witness/script, covenant, resource,
`NameState`, Urkel, snapshot, checkpoint, diagnostics, and native
MeshMine-boundary parsers. Allocation and execution bounds are part of the
assertions.

## Performance evidence

Report count, P50, P95, P99, maximum, failure count, and unavailable evidence
for header/block validation, state/root mutation, reorganization commit,
storage, peer handshake, IBD, tip-to-job, candidate validation, and each
publication target. Mean throughput alone is not a release gate.
