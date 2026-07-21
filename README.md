# hsrd

`hsrd` is the lean Handshake mining full node being built for MeshMine. Its
product boundary is the smallest complete consensus, state, synchronization,
template, and relay path required to mine valid HNS blocks with predictable
latency.

It is deliberately not a wallet, desktop application, domain manager, DNS
server, explorer, or general `hsd` compatibility distribution. MeshMine uses
native in-process Rust interfaces for mining; the bounded HTTP control surface
exists for diagnostics, operations, and differential testing.

## Current release stage

`hsrd` remains **pre-authority**. The pinned `hsd` revision is still the
behavioral oracle and production authority. The default mode is `shadow`.
`native-experimental` requires an explicit Cargo feature, an explicit runtime
acknowledgement, and regtest or simnet. No incomplete validation or
synchronization stage is presented as complete Handshake consensus.

The current tree contains hardened authority, storage, transaction, covenant,
and name-state foundations, a live P2P/shadow-synchronization foundation, and a
bounded mempool, future-template, and durable solved-block publication
foundation. Network data remains observation-only, and the mining engine cannot authorize jobs or
publish solved blocks without the private authority capability.

## Authority, storage, and reorganization safety

Implemented:

- Separate nested-workspace CI for formatting, Clippy, feature matrices, tests,
  release builds, and RustSec checks.
- Explicit validation-stage bits rather than coarse `tx_valid` or
  `state_connected` labels.
- `disabled`, `shadow`, reserved `hsd-verified`, and explicitly gated
  `native-experimental` authority modes.
- A private authority capability required by authoritative mining-template and
  candidate-admission boundaries.
- Test-only fixture imports and caller-supplied chainwork.
- Sequence-consistent RocksDB read snapshots.
- One-snapshot, read-your-writes, one-batch multi-block reorganizations.
- Separate durable best-header and active-best-block bindings.
- Strict greater-work activation; equal-work branches preserve the existing
  first-seen tip.
- Schema version **9**, storage profile **`hsrd-mining-v5`**, explicit clean
  reindex behavior, a durable 32-byte name-tree-root binding, and a checksummed
  synchronization checkpoint.
- Startup checks that compare durable name-tree-root metadata against the
  materialized name-state column family.

## Transaction authorization foundation

Implemented:

- HSD-compatible signature hashing for all defined base modes and
  `NOINPUT`/`ANYONECANPAY` combinations.
- Relative sequence-lock calculation and CLTV/CSV predicates.
- A bounded version-zero witness/script interpreter covering the principal
  stack, numeric, control, hash, signature, multisignature, CLTV, and CSV
  operation families.
- Handshake BLAKE160, BLAKE256, SHA3, and Keccak script operations.
- A verification-only safe Rust wrapper over the exact vendored
  `libsecp256k1` source used by the pinned HSD dependency.
- Compact-signature parsing, low-S enforcement, compressed public-key parsing,
  and ECDSA verification.
- Spent-output address persistence in the UTXO coin codec.
- Input authorization and relative-lock checks before any spend is staged.
- Fail-closed verification when a complete authorization backend is not
  explicitly installed.
- Reproducible HSD signature-hash and sequence-lock fixtures.

Still release-blocking:

- complete HSD opcode/flag/deployment/historical parity;
- broader positive and negative script corpora;
- complete mainnet replay and independent review of the Rust wrapper and script
  integration.

## Covenant, name-state, Urkel-root, and best-chain foundations

Implemented:

- Exact non-coinbase covenant input/output linkage from HSD
  `verifyCovenants`, including BID/REVEAL commitments, linked indexes, locked
  values, address preservation, transfer destinations, revocation burns, and
  unknown-covenant restrictions.
- A contextual non-claim name-transition foundation covering OPEN, BID,
  REVEAL, REDEEM, REGISTER, UPDATE, RENEW, TRANSFER, FINALIZE, and REVOKE.
- Exact pinned reserved-name and lockup datasets.
- HSD-derived renewal-commitment boundary fixtures.
- Exact HSD `NameState` value encoding and undo records.
- A correctness-first in-memory compressed Urkel implementation with exact
  HSD-derived roots and internal inclusion/non-inclusion proof checks.
- Correct Handshake root timing: block `H` commits to the inherited pre-state
  root; applying block `H` produces the root that block `H+1` must commit to.
- Durable previous/resulting roots in block undo records.
- Atomic name-state and durable-root writes on connect, disconnect, and
  multi-block reorganization.
- Stored-root versus materialized-state corruption detection.
- Durable non-active header/index/body storage and validated atomic activation
  of a strictly greater-work replacement branch.

Still release-blocking:

- DNSSEC claim and airdrop proof/accounting validation;
- complete deployment/checkpoint and historical-exception parity;
- full contextual covenant parity across mainnet history;
- a production persistent incremental Urkel node store and exact HSD proof-wire
  codec;
- complete historical root, undo, and reorganization replay.

## Live P2P and restartable shadow synchronization

Implemented:

- Exact bounded HNS frame and sync-relevant packet codecs with pinned HSD wire
  fixtures.
- Live inbound and explicit outbound plaintext TCP sessions with VERSION,
  VERACK, SENDHEADERS, PING/PONG, self-connection rejection, handshake/idle
  timeouts, and byte counters.
- Bounded critical, control, and normal outbound queues.
- A bounded peer manager with connection limits, duplicate-address rejection,
  process-local scoring, disconnect thresholds, snapshots, and exponential
  outbound reconnect backoff.
- Headers-first synchronization with bounded pending, global inflight, and
  per-peer block requests; timeout, retry, penalty, and reassignment behavior.
- Bounded oldest-first orphan retention only after the block's header context is
  known and the body passes stateless validation. Bodies with no known header
  context are dropped after requesting headers.
- CPU-heavy stateless body validation through blocking workers and ordered
  result delivery.
- Durable best-header and contiguous stored-body progress plus a versioned,
  checksummed restart checkpoint that is cross-checked against durable state.
- Read-only bounded serving of headers, block inventory, retained bodies, empty
  address responses, and empty mempool inventory responses.
- Read-only peer and synchronization diagnostics.
- Observation-only storage: downloaded bodies remain non-active records and do
  not connect UTXO/name state or authorize mining work.

Still release-blocking:

- Brontide transport, DNS seed/address-manager discovery, durable bans, and
  long-lived peer reputation;
- contextually complete transaction admission and compact-block reconstruction;
- complete contextual active-state block connection during IBD;
- pruning-aware synchronization and production persistent Urkel storage;
- live HSD state/root comparison and sustained shadow agreement;
- active-state IBD, live HSD comparison, and native mainnet mining authority.

## Bounded mempool, templates, and solved-block publication

Implemented:

- Explicit hard bounds for accepted transactions, bytes, orphans, ancestor and
  descendant graphs, template variants, and pending publication intents.
- Immutable mempool generations, dependency indexes, deterministic package
  construction, orphan promotion, confirmed-transaction reconciliation, and
  fail-closed clearing on reorganizations.
- Structural, finality, sequence-lock, maturity, authorization, covenant-link,
  contextual, fee, and resource admission stages with explicit verifier
  completeness gates.
- Deterministic ancestor-inclusive template selection with HNS weight, sigops,
  OPEN, UPDATE, RENEW, transaction-count, and exclusive-name limits.
- HSD-derived subsidy and deterministic coinbase fixtures.
- Atomic bounded future-template variant replacement and exact chain/mempool
  generation activation.
- Versioned checksummed solved-block publication intents.
- Full local candidate admission before parallel critical peer fan-out.
- Publication retry only for blocks already accepted on the local active chain.
- Mempool/template invalidation on direct connections, disconnects,
  reorganizations, and accepted mempool generations.
- `getminingengineinfo` and `/api/v1/mining-engine` diagnostics.

Still release-blocking:

- production-complete contextual peer transaction admission;
- disconnected-transaction re-admission after reorganizations;
- active-state IBD and production persistent Urkel;
- live HSD state/root comparison and sustained shadow agreement;
- measured template/job and solved-block publication latency;
- native mainnet authority.

See [`docs/mining-engine.md`](docs/mining-engine.md).

## Authority gates

Native mainnet authority remains disabled until all readiness fields report
complete and historical/live evidence is independently reviewed. The live
network path is available only in `disabled` or `shadow` authority modes.
Downloaded network data cannot produce a `MiningAuthorityPermit`.

See:

- [`docs/mining-node-scope.md`](docs/mining-node-scope.md)
- [`docs/readiness.md`](docs/readiness.md)
- [`docs/gap-analysis.md`](docs/gap-analysis.md)
- [`docs/p2p-sync.md`](docs/p2p-sync.md)
- [`docs/mining-engine.md`](docs/mining-engine.md)
- [`docs/storage-schema.md`](docs/storage-schema.md)
- [`docs/hsd-decomposition.md`](docs/hsd-decomposition.md)

## Verification

Checks that do not require a Rust toolchain can be run as one source-handoff
gate:

```bash
scripts/verify-hsrd-source-handoff.sh
```

The individual fixture and native-dependency checks include:

```bash
python3 scripts/validate-hsrd-static.py
python3 scripts/validate-hsrd-source-handoff.py
npm run hsrd-script-fixtures --prefix hsd-oracle
npm run hsrd-covenant-fixtures --prefix hsd-oracle
npm run hsrd-name-state-codec-fixtures --prefix hsd-oracle
npm run hsrd-name-state-urkel-fixtures --prefix hsd-oracle
npm run hsrd-name-policy-fixtures --prefix hsd-oracle
npm run hsrd-p2p-wire-fixtures --prefix hsd-oracle
npm run hsrd-mining-template-fixtures --prefix hsd-oracle
scripts/verify-hsrd-secp256k1.sh
```

Compiler gates:

```bash
cargo metadata --locked --manifest-path hsrd/Cargo.toml --format-version 1
cargo metadata --locked --manifest-path hsrd/fuzz/Cargo.toml --format-version 1
cargo fmt --manifest-path hsrd/Cargo.toml --all --check
cargo fmt --manifest-path hsrd/fuzz/Cargo.toml --all --check
cargo check --locked --manifest-path hsrd/fuzz/Cargo.toml --all-targets
cargo clippy --locked --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --all-features
cargo test --locked --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --no-default-features
cargo build --locked --release --manifest-path hsrd/Cargo.toml \
  --workspace --all-targets --all-features
```

The offline wrapper attempts the npm advisory audit with a bounded timeout. If
the advisory service is unavailable, it reports that fact and continues the
offline handoff checks; CI still runs the strict `npm run audit` command and
fails when the audit cannot be completed.

The static, fixture, and C-level secp256k1 checks are valuable fail-fast gates.
They are not substitutes for the strict dependency audit or Cargo gates.

## Storage migration

Schema version 9 and storage profile `hsrd-mining-v5` add the mining
release identity and durable solved-block publication namespace beyond the
shadow-synchronization schema. Existing pre-authority databases must be
reindexed. No implicit in-place migration is attempted.
