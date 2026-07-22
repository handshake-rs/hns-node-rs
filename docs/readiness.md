# Readiness status

Status labels describe source maturity, not production authority.

## Scope and primitives — foundation present

Implemented:

- Lean mining-node boundary.
- Bounded primitive codecs.
- Pinned, digest-verified HSD fixture manifest.
- Complete canonical HSD genesis-block fixtures for all four networks with
  strict import, durable state restart, and mainnet block-1 continuation.

Remaining: broaden valid/invalid vectors and fuzz every parser family.

## Consensus kernel — substantial foundation, not complete

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

Remaining:

- full-mainnet qualification of the composed historical route and broader
  independent invalid/fuzz corpora;
- independently sourced live DNSSEC-proof evidence for historical-policy
  qualification and complete historical claim replay beyond the pinned
  initial, multi-generation, and terminal histories; mainnet's claim period
  ended at height 210,240;
- mainnet historical contextual replay and broader invalid corpus.

## State and reorganization engine — hardened foundation

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
  atomic checksummed last-run checkpoint, API-v9 diagnostics, and unclean
  RocksDB reopen evidence.
- Exact HSD undo-retention horizons with opt-in atomic retirement, bounded
  startup catch-up, pruning-aware pin/compaction validation, and deep-reorg
  rejection across retired history.
- Correct pre-state root validation and durable post-state root binding.
- Previous/resulting roots in undo and atomic root restoration.
- True store snapshots and one-batch multi-block reorganizations.
- Durable non-active branches, separate best-header/active-block bindings,
  strict greater-work fork choice, and restart recovery gates.
- Schema/network/genesis/profile/epoch/root identity checks.

Remaining:

- deployment-scale compaction performance/priority qualification and RocksDB
  mid-commit process-crash/fault injection;
- full-mainnet qualification of historical contextual claim/airdrop behavior;
- pruning and RocksDB crash/fault qualification;
- complete mainnet reorganization/root replay.

## Live P2P and synchronization — shadow foundation implemented

Implemented:

- exact bounded HNS frames and sync-relevant packets with HSD oracle fixtures;
- inbound/outbound plaintext sessions and VERSION/VERACK negotiation;
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
- API-v9 next-header committed-root material plus a pinned-source, race-safe external HSD
  block/root comparator with checksummed bounded evidence and explicit
  restart/reorganization accounting;
- bounded read-only header, inventory, block, and transaction serving;
- reserved critical-lane parallel fan-out used by the mining publication path.

Remaining:

- Brontide transport;
- long-lived subthreshold reputation, broader peer-diversity controls, and
  adversarial network qualification;
- full-mainnet replay and pruning-aware qualification of active-state IBD;
- production-complete contextual transaction admission and relay;
- sustained live HSD comparison campaigns across restarts, partitions, and
  real reorganizations.

This networking path remains non-authoritative. Active-state mode mutates the
validated state only after an atomic batch commits and still cannot grant mining
authority.

## Mining engine — bounded foundation implemented

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
- mining-engine readiness and queue diagnostics.

Remaining:

- special HSD claim/airdrop relay, including replacement claims;
- full-mainnet active-state IBD and live HSD state/root qualification;
- measured tip-to-job and candidate-to-peer latency under WAN and load;
- native mainnet authority qualification.

## MeshMine composition — operator foundation implemented

Implemented:

- continuous loopback HandyStratum service with concurrent bounded sessions;
- shared gateway locking only around one request or job snapshot;
- replacement-job push and connection-epoch rotation after prefix changes;
- deterministic bootstrapping/mining/degraded/fallback/draining/stopped modes;
- fallback and recovery hysteresis with explicit hard and soft backlog limits;
- process-wide authorization failure accounting;
- authenticated private Core assignment/job streaming with live HSD parent
  qualification and optional HSRD shadow agreement;
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

## Differential and shadow qualification — fixtures expanded

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
- a self-tested live comparison runner that verifies an operator-selected clean
  HSD source revision, canonical block identity, and post-tip authenticated
  root while keeping HSD outside hsrd's consensus/authority path.

Remaining:

- complete mainnet replay and invalid corpora at every state boundary;
- long-duration live shadow comparison evidence through restarts, partitions,
  and reorganizations;
- production mempool/template/publication differential and latency evidence.

## Authority and HSD removal — blocked by design

- Default mode is `shadow`.
- Live networking is allowed only in `disabled` or `shadow` mode.
- Downloaded bodies remain non-active and cannot create authoritative jobs.
- Shadow templates do not bypass the private authority capability.
- Native experimental authority is feature-gated, explicitly acknowledged, and
  restricted to regtest/simnet.

Promote `hsrd` only after every readiness gate is reproducibly satisfied and
reviewed.

## Production hardening — future

Fuzz, audit, profile P50/P95/P99/max latency, tune storage/P2P isolation, run WAN
and real-hardware trials, publish recovery procedures, and produce reproducible
signed releases.
