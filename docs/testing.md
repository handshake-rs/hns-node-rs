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
- sigop-limit, authorization, covenant, name-transition, and spend-staging
  order;
- correct pre-state root validation before transaction mutation;
- null-state deletion and durable root binding;
- non-authoritative network wiring, active-state acknowledgement/batch bounds,
  resource ceilings, frame limits, peer/sync modules, and CLI configuration;
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
npm run hsrd-deployment-fixtures --prefix hsd-oracle
npm run hsrd-airdrop-fixtures --prefix hsd-oracle
npm run hsrd-claim-fixtures --prefix hsd-oracle
npm run hsrd-mainnet-claim-history --prefix hsd-oracle
npm run hsrd-mainnet-claim-replacements --prefix hsd-oracle
npm run hsrd-covenant-fixtures --prefix hsd-oracle
npm run hsrd-name-state-codec-fixtures --prefix hsd-oracle
npm run hsrd-name-transition-fixtures --prefix hsd-oracle
npm run hsrd-name-state-urkel-fixtures --prefix hsd-oracle
npm run hsrd-name-policy-fixtures --prefix hsd-oracle
npm run hsrd-p2p-wire-fixtures --prefix hsd-oracle
npm run hsrd-mining-template-fixtures --prefix hsd-oracle
```

Current evidence includes:

- signature-hash vectors for every defined base mode/modifier combination;
- all five HSD airdrop-key codecs, proof hashes and signature preimages,
  allocation-root checks, strict decode failures, HSD-generated valid and
  mutated RSA/P-256/Ed25519/GooSig signature cases, a complete valid faucet
  proof, and an upstream production-root GooSig proof exercised through native
  consensus and active-node state;
- HSD Claim envelope encoding and blob-only hashes, strict length/trailing
  failures, checksummed ownership TXT payloads for every network prefix, all
  four upstream signed DNSKEY/DS/TXT/RRSIG proofs, their exact codec/sanity/
  window/weak outputs, SHA-256 and legacy GOST94 historical-anchor results,
  and direct GOST94 boundary/multiblock vectors;
- checkpoint-linked canonical mainnet block 62,517 with two real DNSSEC claim
  witnesses, full raw body metrics, exact parent-header-time context, native
  proof mutation/hardening rejection, and claim coinbase connect/disconnect;
- checkpoint-linked mainnet replacement history spanning seven predecessor
  blocks at heights 39,086-39,101 and the ten-claim replacement block 76,722,
  with exact value preservation, commit advancement, native state replay, and
  reverse disconnect;
- checkpoint-linked `mylinksfree` claim-height 1→2→3 replay at blocks 55,798,
  177,097, and 178,235, terminal `vcel` acceptance at 210,237, and exact
  claim-period rejection at the canonical height-210,240 boundary;
- build-checked libFuzzer targets for bounded Claim/TXT/ownership-proof and
  airdrop key/proof decoding plus their derived hash, sanity, and Merkle paths;
- signature-type encoding validity;
- relative sequence-lock cases;
- 56 HSD-executed witness-program cases spanning control flow, stack and
  numeric operations, hashes, native `CHECKSIG`/`CHECKMULTISIG`, CLTV/CSV,
  disabled/unknown opcodes, and policy flags with normalized HSD rejection
  codes plus exact per-program sigop counts;
- an HSD-executed full/historical validation-route matrix proving that
  transaction start and candidate coinbase height remain checked under
  checkpoints while contextual block sigops follow the full-input route, with
  HSD-driven pre-start/boundary block-shape cases, native block-1 evidence, and
  an atomic 80,020-sigop rejection;
- 33 covenant-linkage accepted/rejected cases;
- exact HSD `NameState` encoding vectors;
- 28 exact HSD contextual name-transition cases: 15 accepted lifecycle,
  historical-bypass, expiration, and hardening paths plus 13 targeted
  rejections, with native linkage and byte-for-byte post-state checks;
- incremental HSD Urkel roots with explicit header/pre-state and
  resulting/post-state roots;
- canonical HSD Urkel inclusion and non-inclusion proof bytes across dead-end,
  short, collision, and exists terminals, plus malformed, wrong-root,
  wrong-key, and trailing-byte cases;
- materialized durable name-tree proof snapshots that remain root-pinned across
  later commits, reproduce proof bytes after state-engine restart, and reject
  corrupt durable root bindings;
- content-addressed node-record parity against every pinned HSD proof, path-local
  durable inclusion/non-inclusion reads, memory/RocksDB reopen stability, and
  fail-closed missing/corrupt-node handling at proof, transition, and startup;
- path-local immutable insert/replace/remove parity against pinned HSD
  incremental roots and a 1,000-step deterministic mixed-mutation rebuild
  oracle, plus retained historical proofs and read-your-writes multi-step
  connect/disconnect;
- network-interval snapshot-pin codec/connect/disconnect/restart invariants and
  retained-root compaction that preserves current, undo, and pinned proof bytes
  while deleting only unreachable records;
- malformed-pin and failed-compaction-commit cases that leave the complete node
  set unchanged, followed by an idempotent successful retry;
- startup compaction due/not-due scheduling, nonzero interval validation,
  forced coordinator maintenance, checksummed checkpoint rejection, API-v9
  status, and unclean RocksDB reopen with exact checkpoint/node-set agreement;
- exact HSD undo-retention constants, steady/startup retirement, protected and
  retained windows, non-empty pinned-root compaction after undo expiry,
  checksummed checkpoint rejection, deep-reorg rejection, and unclean RocksDB
  reopen;
- reserved-name and lockup dataset checks;
- renewal-commitment maturity/period boundary checks;
- exact HNS frames, version packets, addresses, service normalization,
  `noRelay`, ASCII handling, inventory, locators, headers, blocks, and rejects;
- maximum-size 2,000-header atomic protocol-batch import, including
  late-invalid and failed-commit rollback;
- canonical-header derivation of BIP9 threshold states, next-block signaling,
  mandatory script/lock/name effects, and final-checkpoint historical policy;
- durable invalid/invalid-child propagation, best-header fallback across
  restart, body/header mismatch retry, and non-attribution of validator-worker
  failures;
- pruning-aware `notfound` failover without peer/block blame, rejection of
  cross-peer `notfound` cancellation, and capacity reservations that survive
  pending/inflight/validation transitions without duplicate work, plus an
  orphan-horizon canonical queue bound and acceptance of an already-in-transit
  response during post-timeout reassignment backoff;
- bounded active-state restart resumption, eight-block cooperative direct
  slices, full-bound atomic fork connection, contextual-invalid ancestor
  persistence, and proof that local state faults do not poison stored branches
  or grant shadow mining authority;
- API-v9 next-header committed-root material, opaque runtime-instance exposure, and the
  external HSD comparison self-test covering confirmed/provisional roots,
  header-derived deployment/script-policy comparison, divergence,
  restart/reorganization counters, hash normalization, and checksummed evidence
  chaining;
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
- interval-pin lifecycle and startup validation;
- compaction reachability, malformed metadata, idempotence, and atomic commit
  failure;
- scheduled and forced compaction checkpoint agreement across unclean RocksDB
  reopen;
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
- late-invalid header batches with full current-batch rollback;
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
- exact HSD native sigop derivation from resolved coins, 16,001-sigop policy
  rejection, and sigop-adjusted minimum-fee accounting;
- one-generation advancement for a block reconciliation and conservative
  clearing on disconnect/reorganization;
- deterministic package ranking by HSD sigop-adjusted policy size while actual
  HNS weight independently controls block fit, plus sigops, OPEN, UPDATE,
  RENEW, transaction-count, and exclusive-name limits;
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

The committed canonical-mainnet fixture adds every completed 2,016-block
deployment period through height 338,688. Its offline check replays each real
median time and signal count through the pinned HSD `Chain` methods; the Rust
test independently advances the same cached states and compares deployment
effects, next-block versions, and the checkpoint-backed historical decision.
It also carries canonical mainnet block 1 as an absolute-finality regression:
HSD reports its only transaction as individually non-final because the
coinbase uses locktime 1 and a non-final sequence, while contextual block
validation accepts it because HSD applies transaction finality only after the
coinbase. Rust decodes the same raw block and verifies both decisions.
The compact deployment fixture also executes HSD's full-body versus
commitments-only and verified-input versus historical-input routes, pinning the
exact validation-stage plan on both sides of checkpoint height 258,026:

```bash
NODE_BACKEND=js npm run hsrd-mainnet-deployment-history --prefix hsd-oracle
```

Node regressions decode HSD's real height-258,026 header and require both the
candidate and that exact final checkpoint to occupy the same best validated
header path before selecting the historical plan. Consensus regressions split
full body sanity from the historical commitment/name-limit stages and prove a
malformed exclusive covenant returns an error rather than panicking. State
regressions prove the BID/REDEEM NameState exception; coordinated maturity,
sequence-lock, sigop, script, value, covenant-link, and reward assumptions; and
the retained HSD special-proof sanity path, including a sane but
cryptographically invalid airdrop, HSD's malformed-key hardening behavior, and
a canonical ownership proof whose altered DNSSEC signature still passes the
retained parent-time check. An altered partial plan is rejected. Missing,
unverified, alternate-branch, post-checkpoint, and checkpoint-free-network cases
all remain fail-closed.

An operator with a synchronized mainnet HSD node can reproduce the compact
fixture without embedding an API key or machine path:

```bash
NODE_BACKEND=js npm run refresh-hsrd-mainnet-deployment-history \
  --prefix hsd-oracle -- --hsd-prefix /path/to/hsd-prefix
```

This is deployment, historical-policy, and one exact historical finality-route
case; it is not complete transaction, UTXO, covenant, name-root, or
block-validity replay.

The claim fixture is generated through HSD's `Claim` and `ownership` codecs:

```bash
NODE_BACKEND=js npm run hsrd-claim-fixtures --prefix hsd-oracle
```

It pins the bounded Claim envelope, blob-only identifier hash, all four network
TXT prefixes, binary address/fee/commit fields, checksum behavior, strict
decode failures, and HSD's complete four-file upstream ownership-proof corpus.
Rust tests cover compression-free proof parsing, HSD sanity/window/weak
classification, reserved-target lookup, current ICANN-anchor rejection, all
five DS digest types, and successful end-to-end chain verification under both
SHA-256 and legacy GOST94/CryptoPro historical anchors. State tests separately
cover authenticated claim connect and disconnect semantics.

The canonical mainnet claim-history fixture is checked offline through the
pinned HSD implementation:

```bash
NODE_BACKEND=js npm run hsrd-mainnet-claim-history --prefix hsd-oracle
```

It pins block 62,517, its two real claims, the height-1 commit header, and the
eleven headers needed for parent-time/MTP context. The native consensus test
round-trips and validates the full block and both proofs, while the state test
connects and disconnects the exact historical coinbase. A deliberately
negative assertion proves that using MTP instead of HSD's exact parent block
timestamp rejects both otherwise canonical proofs.

An operator can refresh this fixture using a synchronized local mainnet HSD
node. Refresh obtains the historical block bytes from the bounded archival
endpoint recorded in the fixture, then requires a continuous locally queried
header chain from HSD checkpoint 61,043 through the block before writing:

```bash
NODE_BACKEND=js npm run refresh-hsrd-mainnet-claim-history \
  --prefix hsd-oracle -- --hsd-prefix /path/to/hsd-prefix
```

The bounded replacement history is checked independently:

```bash
NODE_BACKEND=js npm run hsrd-mainnet-claim-replacements --prefix hsd-oracle
```

It pins 12 full raw claim blocks, the compact canonical boundary
header/coinbase, checkpoint-linked parent-time contexts, commit headers 1/2/3,
the existing 66 initial and ten replacement claims, the complete `mylinksfree`
1→2→3 lineage, and terminal `vcel`. Native replay connects the seven original
predecessor coinbases, verifies every replacement against its prior coin and
`NameState`, replays and reverses both later `mylinksfree` generations, and
proves the height-210,240 boundary rejects a mutated terminal proof. The
mixed-size `.zone` DNSKEY RRset is a regression for RFC 4034/HSD canonical
RDATA ordering.

Refresh uses the same synchronized local HSD/header-chain requirement and
bounded archival endpoint:

```bash
NODE_BACKEND=js npm run refresh-hsrd-mainnet-claim-replacements \
  --prefix hsd-oracle -- --hsd-prefix /path/to/hsd-prefix
```

These are bounded canonical initial, multi-generation, and terminal histories,
not complete historical claim, UTXO, covenant, name-root, or reorganization
replay.

The contextual name-transition fixture is generated directly through the
pinned HSD `Chain.verifyCovenants` implementation. Each case records the exact
pre-state, raw transaction, resolved input covenant, active-chain renewal
lookups, deployment-derived name flags, accept/reject result, and accepted
post-state bytes:

```bash
NODE_BACKEND=js npm run hsrd-name-transition-fixtures --prefix hsd-oracle
```

It covers every non-claim covenant family and important negative boundaries,
but remains deterministic regtest evidence rather than complete mainnet
historical replay.

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
