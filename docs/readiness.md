# Readiness status

Status labels describe source maturity, not production authority. At the
current source revision every `RpcConsensusReadiness` field is true, including
historical replay and invalid-corpus readiness. Runtime authority remains
conditional on the explicit mainnet canary, exact synchronization, and a
coherent durable authoritative tip. API-v15 initializes the base
`release_stage` as `pre-authority`, then the live native RPC composer replaces
it with a configuration-specific diagnostic stage.

## Scope and primitives — foundation present

Implemented:

- Lean mining-node boundary.
- Bounded primitive codecs.
- Pinned, digest-verified HSD fixture manifest.
- Complete canonical HSD genesis-block fixtures for all four networks with
  strict import, durable state restart, and mainnet block-1 continuation.

Further hardening: broaden valid/invalid vectors and sustain fuzzing across
every parser family.

## Consensus kernel — source readiness complete

Implemented:

- Header PoW/difficulty/time and block syntax/commitment foundations.
- HSD sighash, sequence-lock, CLTV, and CSV behavior.
- Broad bounded version-zero witness/script interpreter.
- Exact results for all 876 cases in HSD's pinned upstream script corpus.
- Exact HSD witness-program sigop counting and atomic contextual enforcement of
  the 80,000-sigop block maximum from resolved active-state coins.
- Exact HSD deployment/checkpoint constants, BIP9 transitions, block-version
  signaling, deployment effects, cached next-block versions, and a
  checkpoint-backed historical validation-stage plan carried from block import
  through active state. It distinguishes retained commitments, name limits,
  deployment/finality/height, special-proof sanity, allocation/UTXO, and
  mutating covenant checks from HSD's coordinated checkpoint assumptions for
  body sanity, proof cryptography/binding, maturity/value/reward, sequence
  locks, block sigops, covenant links, scripts, and BID/REDEEM context.
- Branch-specific final-checkpoint header evidence is mandatory for that route;
  missing, mismatched, failed, alternate-branch, post-checkpoint, or
  checkpoint-free evidence selects full validation.
- Exact per-network HSD `txStart` values and strict mainnet enforcement before
  height 2,016: only the coinbase, exactly one output, and no covenant.
- Canonical mainnet block-1 finality parity: ordinary transaction finality
  excludes the coinbase, including HSD's accepted non-final-looking historical
  coinbase vector, while the independent coinbase-height commitment remains
  enforced.
- Active-chain deployment caches and parent-derived contextual name,
  DNSSEC-claim, and full airdrop validation across connect/reorg/restart.
- Strict header checkpoint enforcement in native peer and candidate imports.
- Pinned vendored native secp256k1 verification.
- Exact non-coinbase covenant linkage.
- Contextual name-transition foundation, including authenticated CLAIM
  connect/disconnect at the proof-capable state-service boundary.
- Exact HSD contextual transition replay across all non-claim families: 15
  accepted and 13 rejected cases with linkage, renewal-chain context,
  deployment flags, and byte-for-byte `NameState` post-images.
- Exact HSD ownership-proof codecs, sanity/time/weak rules, ICANN-rooted DNSSEC
  verification, all five HSD DS digests including legacy GOST94/CryptoPro,
  complete upstream historical-proof corpus replay, and claim output/commit/
  deflation accounting.
- Checkpoint-linked canonical mainnet block 62,517 with two real claims,
  complete raw body/proof verification, exact parent-header-time parity, and
  native claim coinbase connect/disconnect evidence.
- Checkpoint-linked canonical replacement history from seven initial-claim
  blocks at 39,086-39,101 through all ten replacements in block 76,722, with
  retained-value/commit advancement checks and full connect/disconnect replay.
- Checkpoint-linked three-generation `mylinksfree` replay at heights 55,798,
  177,097, and 178,235 with exact commit-height 1→2→3 advancement, value/
  frequency enforcement, and predecessor restoration, plus the final accepted
  `vcel` claim at 210,237 and exact height-210,240 claim-period rejection.
- Native RSA/SHA-256, compact P-256, Ed25519, direct-address, and pinned
  Goosig 0.11.0 airdrop verification, including an upstream production-root
  GooSig proof through active block connection and durable duplicate rejection.

Further hardening (not false readiness bits):

- broader full-history auditing of the composed historical route and broader
  contextual invalid/fuzz corpora beyond the independently generated
  non-contextual and core UTXO/lock/script state-boundary block corpora;
- independently sourced live DNSSEC-proof evidence for historical-policy
  qualification and complete historical claim replay beyond the pinned
  initial, multi-generation, and terminal histories; mainnet's claim period
  ended at height 210,240;
- mainnet historical contextual replay and positive/negative invalid coverage
  for every remaining claim, airdrop, name, deployment, and reorganization
  rule family.

## State and reorganization engine — qualified foundation

Implemented:

- UTXO connect/disconnect and undo.
- Relative locks, contextual sigop limits, authorization, covenant linkage, and
  contextual name checks before spend mutation.
- Exact HSD `NameState` encoding.
- Correctness-first exact Urkel roots plus canonical bounded HSD proof
  encoding, decoding, and native inclusion/non-inclusion verification.
- Root-checked immutable proof views rebuilt from sequence-consistent durable
  name-state snapshots and stable across later commits and engine restart.
- Durable content-addressed authenticated nodes, path-local exact proof reads,
  startup/transition validation, and RocksDB reopen evidence.
- Path-local immutable mutation with HSD incremental-root parity, independent
  rebuild checks, retained historical proofs, and multi-step overlay undo.
- Checksummed network-interval root pins validated across connect, disconnect,
  restart, and corruption cases.
- Validated mark-and-sweep compaction retaining the current, undo, and pinned
  root union, including idempotence and failed-commit atomicity evidence.
- Opt-in interval-gated startup scheduling, forced serialized maintenance, an
  atomic checksummed last-run checkpoint, compaction diagnostics introduced in
  API-v10 and retained in current API-v15, and unclean
  RocksDB reopen evidence.
- Matching clean checkpoints audit the complete network reorganization/undo
  suffix with keyed reads; unclean or stale checkpoints retain exhaustive
  historical state, tree, block, deployment, and undo validation.
- Exact HSD undo-retention horizons with opt-in atomic retirement, bounded
  startup catch-up, pruning-aware pin/compaction validation, and deep-reorg
  rejection across retired history.
- Correct pre-state root validation and durable post-state root binding.
- Previous/resulting roots in undo and atomic root restoration.
- True store snapshots and one-batch multi-block reorganizations.
- Durable non-active branches, separate best-header/active-block bindings,
  strict greater-work fork choice, and restart recovery gates.
- Schema/network/genesis/profile/epoch/root identity checks.

Further hardening:

- deployment-scale compaction performance/priority qualification and broader
  RocksDB mid-commit process-crash/fault injection;
- broader full-history auditing of historical contextual claim/airdrop behavior;
- production-scale pruning and RocksDB crash/fault qualification;
- sustained live mainnet reorganization/root campaigns.

## Noncustodial wallet and contract indexes — production qualification pending

Implemented in source:

- optional transaction, script-history, spender, and restoration UTXO indexes;
- chain-epoch- and script-set-bound global confirmed restoration pages across
  history and UTXOs, rejecting continuations after a reorganization, with
  collection-read admission, a 256-prefix-examination work bound, and resumable
  empty progress;
- bounded one-pass reconciliation of up to 10,000 sorted-unique wallet scripts
  against chain-epoch-, process-instance-, and generation-bound immutable
  mempool pages, with exact admission times and
  fallible OS-random nonzero instance initialization and result indexes
  explicitly defined against sorted request order for adapter reverse mapping;
- chain-bound active-height block hash reads, tree-root-bearing tips, ordered
  immutable outpoint-spend batches, combined generation-stable transaction
  evidence with optional exact retained-block position, optional canonical
  confirmed block times, and tip/root-bound current-versus-authenticated name
  evidence with complete canonical encoded state bytes;
- versioned TRANSFER/FINALIZE name-action contexts requiring exact chain epoch
  and mempool process-generation bindings, echoing stable network/genesis/name
  consensus profile identity, tip-plus-one candidate inclusion, active
  NameState/owner/UTXO consistency, canonical transfer maturity, HSD-selected
  active-chain renewal block, and exact immutable-mempool owner-spender evidence
  under a fixed nine-reason fail-closed eligibility bound;
- immutable public Shakedex-v2 and HNS-HTLC-v1 registrations with pinned
  secp256k1 key parsing, canonical scripts, exact signature-hash profiles, and
  an explicit versioned canonical-binary descriptor identity plus bounded
  one-to-many address candidate sets for terms not committed by the script;
- checksummed, key-bound active funding and confirmed fulfillment, recovery,
  redemption, refund, and revealed-preimage events committed and disconnected
  in the canonical chain batch, with consensus-valid out-of-profile spends
  preserved as `Unrecognized` rather than rejected; Shakedex fulfillment and
  recovery are the exact seller-signed TRANSFER shapes (`0x84`/`0x83`), and
  public serde redacts rather than exports persisted raw preimages;
- bounded startup topology validation, query pagination, typed
  disabled/corrupt/pruned failures, and explicit preimage redaction.
- authenticated wallet RPC v1 on the active-state native-sync process
  boundary, requiring both explicit listener Authorization and the durable
  complete wallet profile,
  with canonical hex payloads, bounded opaque cursors, stable redacted errors,
  exact encoded current/proof name views, snapshot-bound block/spender/mempool
  evidence, candidate-specific TRANSFER/FINALIZE preparation evidence,
  signed-transaction contextual admission, and transaction-bound
  fee quotes that resolve input coins and derive exact HSD policy size/minimum
  fee plus checked actual-fee/shortfall evidence from one caller-bound
  chain/mempool capture,
  stricter 256-row/1,024-scan wire limits, an 8 MiB measured JSON-result
  ceiling, and node-local tracked-contract evidence that keeps descriptor
  registration and raw preimages unavailable.

The code-bearing 0.3.5 candidate at
`2b267ffe7fc6f9929063a18986a83b566d02ae6d` passed the exact-revision CI,
container, and CodeQL workflows. A cross-repository `hns-wallet-rs` transport
adapter and fail-closed Android/iOS read projections are also implemented in
source. This implementation is nevertheless not release- or
production-qualified until it has a published and pinned canonical `hns-swap`
commit plus a joined backend/authentication, restart/reorg, lifecycle,
adversarial, storage-fault, and deployment-scale qualification pass on the
selected final revisions. Local script
duplication and frozen vectors are cross-boundary qualification checks, not
protocol authority. It stores no wallet key or unrevealed preimage and remains
disabled by default. Exact never-confirmed registrations now have a monotonic,
revision- and restart/reorg-safe in-process retirement path that reclaims active
global and per-address slots under an exact chain/current-mempool generation.
It requires zero retained transaction orphans and scans accepted ordinary
transactions and airdrop outputs. The caller must durably abandon prior
broadcasts; the node cannot prove an evicted transaction will never return.
Completed lifecycles now have a source-complete typed tombstone transition,
but only after their bounded exact event history lies below the irreversible
undo frontier and the caller permanently abandons descriptor reuse. The
tombstone retains terminal/preimage evidence and a commitment over deleted
rows while reclaiming active slots. Legacy-unknown records remain
non-retirable. The completed path passed four focused wallet-index tests at
exact local revision `fd0c9b00114e3fa0a293972de7d4538dcd959ce0`, but has not
run a RocksDB reopen, live restart/reorg, adversarial topology, performance
measurement, or the full qualification gate. Its immutable tombstone registry
has a finite 65,536-entry lifetime cap, and later matching outputs are
deliberately untracked; untrusted registration therefore remains unavailable
and production availability remains blocked.
Live marketplace wire
advertisement separately awaits the
published, revision-pinned canonical `hns-rs` 0.2 Denuo V2 dependency and
adapter gate.

The focused local evidence is intentionally narrow: the NVMe `hns-consensus`
`wallet_name_action` filter passed 2 tests with 0 failures and 75 filtered. At
exact local revision `fd0c9b00114e3fa0a293972de7d4538dcd959ce0`, the separate
`production_next_` filter passed all four matching completed-retirement/profile
wallet-index tests with zero failures and 15 filtered; no `hns-node` test
matched the filter. No RocksDB reopen, full gate, network, live restart/reorg,
adversarial topology, performance, or resource qualification ran for this
tranche. The later exact-revision remote repository gates above cover the
current code-bearing candidate, but they do not add the live qualification
campaigns listed here.

Fee-quote source tests and documentation are present but were not executed in
the source-only tranche that introduced the method. A quote is exact only for
the supplied serialized witness bytes; production wallet qualification must
demonstrate a final-signed-artifact requote and rebuild-on-underpayment loop
before broadcast. Existing readiness or parity evidence does not qualify this
new method by inheritance.

## Live P2P and synchronization — native path implemented and qualified

Implemented:

- exact bounded HNS frames and sync-relevant packets with HSD oracle fixtures;
- inbound/outbound plaintext sessions and VERSION/VERACK negotiation;
- post-VERSION canonical Denuo Experimental V1 registry negotiation with exact
  fingerprint agreement, plus a live role-safe HIP-76 requester/provider
  session whose requester can opt out and whose provider remains explicit
  opt-in with a ready backend;
- process-local self-connection detection, service checks, timeouts, ping/pong,
  priority outbound lanes, and cancellation-safe partial frame reads across
  timer maintenance;
- bounded peer registration, scoring, disconnect, diagnostics, and reconnect;
- opt-in HSD DNS-seed bootstrap plus bounded GETADDR/ADDR learning, routability
  and service filtering, HSD timestamp normalization, protected explicit peers,
  failed discovered-target rotation, and a checksummed, network-bound durable
  address book with HSD attempt/success metadata and stale-entry horizons;
- HSD-aligned connection-local scoring with a score-100 normalized-IP ban for
  24 hours, IP-wide disconnect and pre-handshake admission enforcement, bounded
  checksummed/network-bound persistence, expiry compaction, and restart restore;
- exact HSD IPv4 `/16`, IPv6 `/32`, HE `/36`, and transition-address outbound
  groups, with unique discovered targets/attempts, explicit-peer priority, and
  active-group diagnostics;
- headers-first acquisition, 2,000-header atomic durable protocol batches,
  best-work retention, and independent canonical-header derivation of BIP9
  states plus mandatory script/lock/name policy;
- bounded cross-stage body reservations with per-peer requests, retry/timeout,
  an orphan-horizon canonical window, and pruning-aware `notfound` failover
  that does not fabricate failures or let canonical acquisition alone overrun
  the configured count bound;
- HSD-shaped per-peer `GETDATA` inventories with atomic failed-admission
  rollback, HSD's 60/120-second header/block deadlines, and one disconnect per
  expired peer batch rather than per-hash score multiplication;
- HSD version-1 compact-block negotiation, exact witness short IDs and
  differential indexes, bounded mempool-assisted reconstruction with
  `GETBLOCKTXN`/`BLOCKTXN` completion and full-block fallback, plus bounded
  recent-block compact serving;
- restart-durable out-of-parent-order canonical-body retention after a strict
  best-header-path recheck, with the contiguous and active tips pinned at the
  first gap while ordinary imports and reorgs retain the parent-body invariant;
- bounded known-header orphan handling for non-canonical descendants;
- parallel stateless body validation with ordered results;
- durable permanent-invalid and invalid-child status, atomic best-header
  fallback, restart recovery, and separate retry paths for uncommitted body
  mismatches and validator-worker failures;
- durable non-active body retention and restartable sync checkpoints;
- explicitly acknowledged bounded active-state batches through the single
  contextual state/reorganization pipeline, including restart resumption,
  eight-block shutdown-responsive direct slices, full-bound atomic
  reorganizations, exact contextual-invalid ancestry, and fail-closed
  local-fault separation;
- next-header committed-root material introduced in API-v10 and retained in
  current API-v15, plus a pinned-source, race-safe external HSD block/root
  comparator with checksummed bounded evidence and explicit
  restart/reorganization accounting;
- complete native mainnet active-state replay through height 339,660, a
  passing stopped-state comparison of physical UTXOs, HSD-compatible name
  state, pending/committed Urkel roots, deployments, and checkpoint ancestry,
  plus exact normalized disconnect/reconnect parity over the complete
  288-block retained horizon;
- bounded read-only header, inventory, block, and transaction serving;
- reserved critical-lane parallel fan-out used by the mining publication path.

Further network hardening:

- long-lived subthreshold reputation, broader peer-diversity controls, and
  adversarial network qualification;
- production-complete contextual transaction admission and relay;
- sustained native multi-peer campaigns across restarts, partitions, and real
  reorganizations, with offline differential audits of retained history.

This networking path grants no authority by itself. Active-state mode mutates
validated state only after an atomic batch commits; the explicit mainnet canary
still requires exact synchronization, durable authoritative status, and every
consensus readiness bit.

## Mining engine — bounded authority path implemented

Implemented:

- durable generations and immutable chain/mempool snapshots;
- bounded accepted-transaction and orphan storage;
- dependency, ancestor, descendant, spent-outpoint, and exclusive-name indexes;
- deterministic dependency-ordered package construction;
- explicit contextual-verifier completeness gates and fail-closed peer relay;
- native resolved-coin HSD sigop accounting, the 16,000-sigop transaction
  policy maximum, and exact sigop-adjusted fee/package sizing;
- HNS-aware future-template construction with deterministic package selection
  that retains actual weight for consensus block-fit accounting;
- durable canonical-tip and parent-MTP binding with HSD-derived deployment
  version, time-dependent target, timestamp-floor validation, and testnet
  target-reset job expiry;
- bounded atomic template-variant replacement and exact generation activation;
- HSD-derived subsidy, deterministic coinbase, and sigop-policy fixtures;
- versioned, checksummed, bounded solved-block publication intents;
- authority-gated local candidate admission before parallel critical fan-out with writer-completion acknowledgment;
- crash-safe retry restricted to locally accepted active blocks;
- mempool/template reconciliation on active-chain transitions;
- atomic complete-context revalidation of retained transactions and orphans
  after direct active-chain connections;
- contextual ordinary-transaction re-admission after disconnects and
  reorganizations, with older disconnected name updates taking priority;
- HSD mainnet standardness, all-network standard script flags, dust and
  absurd-fee policy pinned to the deterministic HSD oracle;
- HSD 72-hour root-package expiry and descendant-aware fee eviction to its 90%
  trim target;
- HSD confirmed-coin free priority and the default decaying low-fee relay
  limiter;
- typed HSD airdrop wire/inventory/GETDATA relay, deployment- and bitfield-aware
  native admission, reorg reconciliation, and fee-ranked coinbase assembly;
- typed HSD DNSSEC claim wire/inventory/GETDATA relay, native contextual
  admission and replacement policy, reorg reconciliation, and fee-ranked
  pre-airdrop coinbase assembly;
- mining-engine readiness and queue diagnostics.

Further mining-path hardening:

- measured tip-to-job and candidate-to-peer latency under WAN and load;
- physical gateway/ASIC campaigns and longer-duration canary operation. The
  conditional native permit path and retained-horizon disconnect/reconnect
  qualification are implemented; no release-stage diagnostic is itself an
  authority grant.

## MeshMine composition — operator foundation implemented

Implemented:

- continuous loopback HandyStratum service with concurrent bounded sessions;
- shared gateway locking only around one request or job snapshot;
- replacement-job push and connection-epoch rotation after prefix changes;
- deterministic bootstrapping/mining/degraded/fallback/draining/stopped modes;
- fallback and recovery hysteresis with explicit hard and soft backlog limits;
- process-wide authorization failure accounting;
- authenticated private Core assignment/job streaming with sole native-hsrd
  parent qualification and no runtime HSD dependency;
- exact signed assignment binding at the gateway plus durable capture envelopes,
  Core-side `ShareV2` construction/admission, and terminal receipt reconciliation;
- network- and pinned-key-bound signed `CoreCaptureReceiptV1` plus ACK-only reconciliation;
- schema-v2 network/Core-key trust-bound service database and bounded aggregated event journal;
- real listener/credential health, counters, read-only status API, and embedded dashboard;
- strict pre-production configuration and loopback-only listeners.

Remaining:

- full `meshmine-work` backend registration and native/external worker process
  composition inside one daemon;
- physical ASIC job-switch/fallback evidence and device telemetry;
- continuous mask/session/settlement supervision and solved-block publication
  recovery in one release process;
- measured P50/P95/P99/max end-to-end latency under real hardware and WAN load.

## Differential and native qualification — fixtures expanded

Implemented:

- HSD generators for sighash, locks, a 56-case focused script execution/error
  corpus, and pinned-source native replay of all 876 upstream execution/error
  outcomes and sigop counts; deployments/checkpoints/historical
  boundaries and validation routes, all 168 canonical mainnet deployment
  periods through height 338,688 with next-block versions, airdrop proofs,
  Claim/TXT/DNSSEC ownership-proof codecs and all four
  upstream signed proof chains under SHA-256/GOST94 historical anchors,
  terminal mainnet claim-period behavior and a complete three-generation claim
  lineage,
  covenant linkage, all-family contextual name transitions with 15 accepted
  and 13 rejected exact state cases, name-state codec,
  reserved/lockup/renewal policy, incremental Urkel roots, P2P wire bytes,
  subsidy, and deterministic coinbase behavior;
- static integrity checks, native secp256k1 smoke verification, and exact
  vendored-Goosig source comparison against HSD's pinned dependency;
- reproducible independently generated invalid-corpus qualification against
  pinned HSD: 24 noncontextual transaction/block cases and 12 contextual
  state-boundary cases, with 30 invalid mutations, six valid controls, semantic
  failure-class agreement, and atomic state rejection;
- a self-tested live comparison runner that verifies an operator-selected clean
  HSD source revision, canonical block identity, and post-tip authenticated
  root while keeping HSD outside hsrd's consensus/authority path.
- a passing height-339,654 stopped-state comparison against pinned HSD for all
  23,728,438 physical UTXOs, all 12,853,528 name states, both Urkel roots, and
  the same-tip deployment/checkpoint view, with checksummed retained evidence.
- a passing read-only normalized comparison of all 288 retained mainnet
  disconnect/reconnect transitions through height 339,660, anchored to that
  full-state pass and covering raw blocks, coins, full name states, committed
  roots, and the complete airdrop field.

Remaining:

- long-duration native multi-peer evidence through restarts, partitions, and
  reorganizations, plus offline differential audits;
- production mempool/template/publication differential and latency evidence.

## Authority and HSD removal

- Default mode is `native`; HSD is not a runtime dependency.
- Native networking connects downloaded bodies through authoritative state;
  a mining permit is available only for the synchronized, fully qualified
  durable tip.
- Mainnet additionally requires the explicit hardened canary profile, exact
  header/active-state synchronization, durable authority, and every readiness
  bit.
- Native experimental authority remains feature-gated, explicitly
  acknowledged, and restricted to regtest/simnet.

The historical replay, stopped-state, retained rollback, and invalid-corpus
readiness gates have reproducible retained evidence. Longer operational
campaigns remain hardening work rather than hidden consensus-readiness flags.

## Production assurance — executable gates, external evidence open

Implemented harness and verification surfaces:

- `scripts/check.sh` and the development `smoke` tier select the performance
  binary's default in-memory scenario: ten unmeasured warm-up blocks followed
  by 100 measured native regtest blocks with explicit P99 limits. The assurance
  tier retains the schema-v2 report, but this fast regression does not exercise
  RocksDB, synchronous durability, or saturated block-index-cache occupancy;
- scheduled and release software qualification instead select
  `persistent-rocksdb-sync`: RocksDB with `Sync` durability, exactly 4,096
  unmeasured setup blocks, cache capacity and occupancy fixed at 4,096, and 100
  measured blocks. Their schema-v2 evidence must pass the backend, durability,
  workload, cache, availability, and latency checks, and the automatically
  created marked data root must be closed, verified, and removed;
- `scripts/run-sustained-fuzz.sh` runs every current fuzz target under a pinned
  nightly/cargo-fuzz toolchain and retains source/tool/configuration identities,
  logs, crash artifacts, and SHA-256s;
- scheduled and manually dispatched CI run a bounded three-minute-per-target
  sanitizer campaign and retain the software evidence;
- `scripts/run-production-assurance.sh` separates development smoke, scheduled
  software qualification, external evidence verification, and the conjunctive
  release decision. Scheduled/release runs require a fully clean worktree and
  the exact stable/nightly toolchains, and reject tracked or non-ignored
  untracked changes during execution;
- both performance scenarios are deterministic local regtest gates. Neither is
  full-mainnet initial synchronization, production pruning, RocksDB fault
  injection, sustained reorganization/partition, WAN/load, physical
  gateway/ASIC, long-duration multi-peer, or production
  mempool/template/publication differential evidence;
- the external verifier fails closed on absent, failed, wrong-source, malformed,
  unreviewed, under-threshold, missing-artifact, or digest-mismatched records
  for production-scale pruning, RocksDB fault injection, sustained
  reorganization/partition, WAN/load latency, physical gateway/ASIC,
  long-duration multi-peer operation, and mempool/template/publication
  differential testing. Production pruning additionally requires the actual
  typed `hsrd` binary and a hashed build manifest bound to the release source
  tree, and recomputes the binary digest before accepting the configured
  identity.

Not yet completed evidence:

- no reviewed deployment custody record proves exclusive `hsrd`/trusted
  maintenance write access to the data root and external page/segment paths,
  with owners, modes, ACLs, mount controls, privileged writers, and maintenance
  identities retained; automated checksums do not authenticate a hostile local
  database writer;
- no passing exact-release production-scale pruning and process-fault campaign
  is retained, including the required full non-pruned mainnet baseline within
  the 150,000,000,000-byte disk envelope, separately preserved
  10,000,000,000-byte free-filesystem reserve, and measured pruned comparison;
  90,000,000,000 bytes is only an optional informational comparison and is not
  a qualification or release criterion;
- no passing six-hour real reorganization/partition campaign is retained;
- no passing WAN/load, four-hour physical gateway/ASIC, or 24-hour eight-peer
  soak record is retained;
- no passing production mempool/template/publication differential record is
  retained;
- a scheduled fuzz artifact demonstrates bounded software exercise, not
  exhaustive hostile-input coverage or a substitute for the external gates.

The assurance harness does not delete HSD blocks. Any later removal remains a
separate operator-approved procedure contingent on independently verified hsrd
chain completeness, tested wallet backup/restore, and an explicit
rollback/retention plan.

The schema, minimum acceptance criteria, collection requirements, and release
command are in [`production-assurance.md`](production-assurance.md). Until the
exact release has a complete passing evidence bundle, production hardening
remains open and mainnet operation remains canary-only.
