# Phase 1–3 implementation report

This report describes the source updates delivered in the Phase 1–3 archive.
It distinguishes implemented behavior from unverified or incomplete work.

## Scope

### Phase 1: authority safety and verification

Implemented:

- independent CI for every crate and target in the nested `hsrd` workspace;
- all-features and no-default-features test configurations;
- nested lockfile RustSec auditing;
- static TOML/JSON, fixture-integrity, oracle-pin, schema, and authority checks;
- granular durable block-validation and state flags;
- separate staged and authoritative mining-tip semantics;
- `disabled`, `shadow`, `hsd-verified`, and explicitly gated
  `native-experimental` authority modes;
- private test-only fixture chainwork overrides;
- one-batch multi-block reorganization staging with read-your-writes views;
- real sequence-consistent RocksDB snapshots;
- explicit WAL/sync durability configuration;
- read-only status, authority, and parity diagnostics;
- schema version 5 with fail-closed reindex behavior.

### Phase 2: transaction authorization foundation

Implemented:

- HSD-compatible Handshake signature hashing for ALL, NONE, SINGLE,
  SINGLEREVERSE, NOINPUT, and ANYONECANPAY combinations;
- signature-hash type validation;
- relative sequence-lock calculation and lock predicates;
- CLTV and CSV predicate helpers;
- bounded version-zero witness-program/script interpreter foundation;
- Handshake BLAKE160, BLAKE256, SHA3, and Keccak script hash operations;
- pluggable signature-verification and witness-program boundaries;
- fail-closed production default for every non-coinbase spend;
- spent output address persistence in the UTXO coin codec;
- input authorization before any spend is staged;
- reproducible HSD signature-hash and sequence-lock fixtures.

Not claimed:

- an audited secp256k1 backend;
- complete HSD script/opcode/flag/historical parity;
- block-connect integration of every relative-lock rule;
- mainnet authorization readiness.

### Phase 3: covenant input/output linkage

Implemented:

- deterministic port of the non-coinbase branch of
  `hsd/lib/covenants/rules.js::verifyCovenants`;
- exact input-index/output-index linkage;
- BID to REVEAL name, height, blind commitment, and locked-value checks;
- CLAIM/REVEAL to REGISTER/REDEEM restrictions;
- REGISTER/UPDATE/RENEW/FINALIZE locked value, address, name, and start checks;
- TRANSFER destination commitment and fallback-owner checks;
- REVOKE permanent burn behavior;
- unknown covenant restriction against creating name covenants;
- linkage completion before UTXO mutation;
- 33 reproducible HSD accepted/rejected cases, including multi-input alignment;
- an independently durable `covenant_links_valid` stage.

Not claimed:

- auction or rollout phase validity;
- reserved-name behavior;
- winner, second-price, ownership, renewal, expiration, transfer timing, or
  resource validity;
- claim/airdrop issuance;
- name-state mutation or Urkel root agreement.

### Phase 3 hardening: durable best-chain activation

Implemented:

- durable storage of validated non-active header, block-index, and raw-body
  records without mutating the active height index;
- separate durable `BestHeaderHash` and `BestBlockHash` bindings;
- strict greater-work promotion, preserving the existing first-seen tip on
  equal work;
- reorganization planning between an explicit active tip and candidate tip;
- validation of common ancestry, canonical disconnect order, contiguous connect
  order, raw-body availability, status prerequisites, and monotonic chainwork;
- reconstruction of stored blocks into activation imports, with fixture
  chainwork bypasses remaining test-only;
- one-snapshot, one-overlay, one-batch disconnect/connect application;
- a final replacement-work check before commit;
- startup recovery of a fully stored better branch only on the explicitly
  gated native-experimental regtest/simnet path;
- startup durable-chain invariant checks over the active height index, block
  indexes, bodies, parent continuity, work continuity, and metadata bindings;
- diagnostic separation of best header and best active block, including pending
  activation and alternate-block counters;
- tests covering equal-work preservation, higher-work activation, multi-block
  branch activation, restart recovery, lower-work rejection, profile drift, and
  atomic failure behavior.

Not claimed:

- a complete orphan/header-download subsystem;
- production mainnet recovery or authority;
- all HSD historical fork-choice exceptions, checkpoints, deployment states,
  pruning interactions, or invalid-branch behavior;
- activation of branches containing spends until the Phase 2 signature backend
  and complete script/covenant/name/Urkel validation exist;
- crash-tested RocksDB reorganization parity in this delivery environment.

## Principal files

- `.github/workflows/ci.yml`
- `scripts/validate-hsrd-static.py`
- `hsd-oracle/generate-hsrd-phase2-fixtures.js`
- `hsd-oracle/generate-hsrd-phase3-fixtures.js`
- `hsrd/fixtures/hsd/manifest-v1.json`
- `hsrd/fixtures/hsd/scripts/*`
- `hsrd/fixtures/hsd/covenants/linkage-v1.json`
- `hsrd/crates/hns-primitives/src/lib.rs`
- `hsrd/crates/hns-consensus/src/{sighash,locks,script,covenant}.rs`
- `hsrd/crates/hns-state/src/lib.rs`
- `hsrd/crates/hns-chain/src/lib.rs`
- `hsrd/crates/hns-store/src/lib.rs`
- `hsrd/crates/hns-mining/src/lib.rs`
- `hsrd/crates/hns-node/src/{lib,main}.rs`
- `hsrd/crates/hns-rpc/src/lib.rs`
- `hsrd/crates/hns-testkit/src/lib.rs`

## Safety invariants

The update is designed around these invariants:

1. Partial validation is never named or encoded as complete consensus.
2. Production code cannot call the fixture chainwork bypass.
3. Shadow mode is the default.
4. Native experimental authority is limited to regtest/simnet and requires two
   explicit opt-ins.
5. Missing signature verification rejects spends.
6. Claim/airdrop coinbase issuance rejects until verified.
7. All transaction inputs are resolved and authorized before UTXO deletion.
8. Covenant linkage finishes before spend staging.
9. A failed reorganization commits no durable key.
10. Related RocksDB reads share one sequence-consistent snapshot.
11. Equal-work branches do not displace the persisted first-seen best tip.
12. Non-active block storage cannot rewrite the active height index.
13. A replacement chain must have strictly greater final chainwork before commit.
14. Fixture bytes are pinned by BLAKE2b-256 and exact HSD commit metadata.
15. Schema incompatibility requires an explicit reindex.

## Verification performed in the delivery environment

Completed:

```text
python3 scripts/validate-hsrd-static.py
npm run hsrd-phase2-fixtures --prefix hsd-oracle
npm run hsrd-phase3-fixtures --prefix hsd-oracle
```

The Phase 3 generator reproduced 33 cases against the pinned HSD checkout.
Repository JSON and TOML parsing, fixture hashes, package/lockfile pins, status
schema, authority tokens, and Phase 2/3 ordering invariants passed the static
validator.

Additional JavaScript oracle checks and archive checks are recorded in the root
`PHASE1_3_IMPLEMENTATION_REPORT.md` generated for this delivery.

## Verification not performed locally

The delivery environment did not contain `cargo`, `rustc`, or `rustfmt`.
Accordingly, this source archive is not represented as locally compiled. The CI
workflow contains the required formatting, Clippy, all-target/all-feature,
no-default-feature, release-build, and RustSec gates. The next developer should
run those commands first and resolve any compiler/API/formatting issues without
weakening the fail-closed boundaries.

## Required next work

1. Run and repair all Cargo gates.
2. Select, integrate, and review a secp256k1 backend.
3. Expand exact script fixtures and full script parity.
4. Implement contextual covenant/name-state transitions.
5. Implement claim/airdrop verification and accounting.
6. Implement production Urkel state/root/undo parity.
7. Complete P2P, synchronization, mempool, templates, and solved-block relay.
8. Run full historical and invalid-corpus differential replay.
9. Accumulate sustained live shadow evidence before authority promotion.
