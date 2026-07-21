# Readiness status

Status labels describe source maturity, not production authority.

## Scope and primitives — foundation present

Implemented:

- Lean mining-node boundary.
- Bounded primitive codecs.
- Pinned, digest-verified HSD fixture manifest.

Remaining: broaden valid/invalid vectors and fuzz every parser family.

## Consensus kernel — substantial foundation, not complete

Implemented:

- Header PoW/difficulty/time and block syntax/commitment foundations.
- HSD sighash, sequence-lock, CLTV, and CSV behavior.
- Broad bounded version-zero witness/script interpreter.
- Exact results for all 876 cases in HSD's pinned upstream script corpus.
- Exact HSD deployment/checkpoint constants, BIP9 transitions, block-version
  signaling, deployment effects, and checkpoint/historical-script policy.
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
- Native RSA/SHA-256, compact P-256, Ed25519, direct-address, and pinned
  Goosig 0.11.0 airdrop verification, including an upstream production-root
  GooSig proof through active block connection and durable duplicate rejection.

Remaining:

- historical replay qualification;
- non-script historical exceptions and broader independent invalid/fuzz
  corpora;
- current/live claim-proof evidence and complete historical claim replay beyond
  the pinned initial/replacement histories;
- mainnet historical contextual replay and broader invalid corpus.

## State and reorganization engine — hardened foundation

Implemented:

- UTXO connect/disconnect and undo.
- Authorization, relative locks, covenant linkage, and contextual name checks
  before spend mutation.
- Exact HSD `NameState` encoding.
- Correctness-first exact Urkel roots plus canonical bounded HSD proof
  encoding, decoding, and native inclusion/non-inclusion verification.
- Root-checked immutable proof views rebuilt from sequence-consistent durable
  name-state snapshots and stable across later commits and engine restart.
- Correct pre-state root validation and durable post-state root binding.
- Previous/resulting roots in undo and atomic root restoration.
- True store snapshots and one-batch multi-block reorganizations.
- Durable non-active branches, separate best-header/active-block bindings,
  strict greater-work fork choice, and restart recovery gates.
- Schema/network/genesis/profile/epoch/root identity checks.

Remaining:

- production persistent incremental Urkel storage, incremental proof serving,
  interval snapshots, compaction, undo, and crash recovery;
- complete historical contextual claim/airdrop behavior;
- pruning and RocksDB crash/fault qualification;
- complete mainnet reorganization/root replay.

## Live P2P and synchronization — shadow foundation implemented

Implemented:

- exact bounded HNS frames and sync-relevant packets with HSD oracle fixtures;
- inbound/outbound plaintext sessions and VERSION/VERACK negotiation;
- process-local self-connection detection, service checks, timeouts, ping/pong,
  and priority outbound lanes;
- bounded peer registration, scoring, disconnect, diagnostics, and reconnect;
- headers-first acquisition and best-work header retention;
- bounded pending/inflight/per-peer block scheduling with retry and timeout;
- bounded known-header orphan handling;
- parallel stateless body validation with ordered results;
- durable non-active body retention and restartable sync checkpoints;
- bounded read-only header, inventory, block, and transaction serving;
- reserved critical-lane parallel fan-out used by the mining publication path.

Remaining:

- Brontide and address-manager/DNS-seed discovery;
- durable bans/reputation and broader adversarial network qualification;
- active-state ordered block connection and pruning-aware IBD;
- compact blocks and production-complete contextual transaction relay;
- live HSD state/root comparison and sustained shadow agreement.

This networking path remains observation-only and cannot grant mining authority.

## Mining engine — bounded foundation implemented

Implemented:

- durable generations and immutable chain/mempool snapshots;
- bounded accepted-transaction and orphan storage;
- dependency, ancestor, descendant, spent-outpoint, and exclusive-name indexes;
- deterministic dependency-ordered package construction;
- explicit contextual-verifier completeness gates and fail-closed peer relay;
- HNS-aware future-template construction with deterministic package selection;
- bounded atomic template-variant replacement and exact generation activation;
- HSD-derived subsidy and deterministic coinbase fixtures;
- versioned, checksummed, bounded solved-block publication intents;
- authority-gated local candidate admission before parallel critical fan-out with writer-completion acknowledgment;
- crash-safe retry restricted to locally accepted active blocks;
- mempool/template reconciliation on active-chain transitions;
- mining-engine readiness and queue diagnostics.

Remaining:

- production-complete contextual mempool admission and peer transaction relay;
- disconnected-transaction re-admission after reorganizations;
- active-state IBD and live HSD state/root qualification;
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
  corpus, all 876 upstream script cases, deployments/checkpoints/historical
  boundaries, all 167 canonical mainnet deployment periods through height
  336,672, airdrop proofs, Claim/TXT/DNSSEC ownership-proof codecs and all four
  upstream signed proof chains under SHA-256/GOST94 historical anchors,
  covenant linkage, all-family contextual name transitions with 15 accepted
  and 13 rejected exact state cases, name-state codec,
  reserved/lockup/renewal policy, incremental Urkel roots, P2P wire bytes,
  subsidy, and deterministic coinbase behavior;
- static integrity checks, native secp256k1 smoke verification, and exact
  vendored-Goosig source comparison against HSD's pinned dependency.

Remaining:

- complete mainnet replay and invalid corpora at every state boundary;
- live shadow comparison through restarts, partitions, and reorganizations;
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
