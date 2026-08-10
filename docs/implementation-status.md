# Implementation status

This document contains the detailed capability and release-hardening ledger for
[`hns-node-rs`](../README.md). Run all commands below from the repository root.

This is the canonical source repository for `hsrd`, the lean Handshake mining
full node being built for MeshMine. Its
product boundary is the smallest complete consensus, state, synchronization,
template, and relay path required to mine valid HNS blocks with predictable
latency.

The `hsrd` process is deliberately not a wallet, desktop application, domain
manager, DNS server, explorer, or general `hsd` compatibility distribution.
The separately deployed [native resolver companion](hns-resolverd.md) consumes
one narrow atomic state read without expanding `hsrd`'s authority. It now signs
the Handshake root with the canonical HSD KSK/ZSK, validates recursive DNSSEC,
and imports eligible absent ICANN TLD referrals through an independently
validated IANA trust domain. MeshMine
uses native in-process Rust interfaces for mining; the bounded HTTP control
surface exists for diagnostics, operations, and differential testing.

## Standalone extraction

This repository preserves the history of MeshMine's former `hsrd/` subtree.
See [the extraction provenance](extraction-provenance.md) for the exact
source and split commits, the standalone boundary, and the post-extraction
release qualification.

## Current release stage

The current source has complete functional consensus readiness: every
`RpcConsensusReadiness` field is true, including historical replay and the
independent invalid corpus. The retained stopped-state and 288-block rollback
qualifications are recorded under `qualification/`. This source qualification
does not by itself make an arbitrary process or deployment authoritative.
`NodeService` initializes a base snapshot with `release_stage:
"pre-authority"`; the live native-sync RPC composer replaces that field with
`native-sync-live-p2p`, `mining-engine-observe`, or
`mainnet-canary-gated` according to the active configuration. Those are
diagnostic mode labels, not readiness or authority grants.

The pinned `hsd` revision remains the offline behavioral oracle; it is not a
runtime parent or production authority. The default mode is `native`.
`native-experimental` requires an explicit Cargo feature, an explicit runtime
acknowledgement, and regtest or simnet. No incomplete validation or
synchronization stage is presented as complete Handshake consensus.

The Core/operator integration has no runtime HSD dependency. It consumes the
hsrd-specific atomic `getparentauthority` snapshot, and it will accept that
snapshot only when the RPC listener is protected with
`--rpc-authorization-header-file` and every native authority/readiness and
durable-tip gate passes. A current build can issue the private mining permit
only for that coherent synchronized tip; a stale, staged, unauthenticated, or
otherwise incomplete snapshot remains fail closed.

Native mainnet operation has a second explicit lock: `--mainnet-canary`. The
flag is accepted only with the hardened native-sync/mining configuration and it
cannot bypass synchronization, durable tip authority, or any consensus
readiness bit. See [Native mainnet mining canary](mainnet-canary.md) for
the runnable sync command and exact runtime qualification boundary.

Live peers also negotiate the collision-detectable
[Denuo Experimental V1 profile](experimental-mainnet-profile.md) after
ordinary Handshake readiness. Its service bit advertises only the extension
envelope; it neither represents nor changes requester, opaque-relayer, output,
HNSR, or market-role consent.

The bounded [HIP-76 session boundary](hip76-session.md) is now wired
through live peers. Requesting is available by default and can be disabled
(opt-out); its process-wide policy/floor pair is persisted atomically and an
explicit enable reverses a saved opt-out. Serving DNS output remains disabled
until an operator explicitly opts in and marks a backend ready. The session
validates framing, DNS message shape, correlation, policy generations,
deadlines, queue admission, and socket completion. A received DNS answer
remains untrusted input for a separate resolver/DNSSEC validation boundary.

The bounded HIP-77 ODoH requester is likewise wired through live peers and is
enabled by default with durable opt-out and explicit re-enable. It requires
exact Brontide proxy authentication, both Denuo and ODoH service advertisements,
exact Denuo V1 profile/registry/network/genesis evidence, and a proxy key
distinct from the target-signed locator. Request correlation,
deadlines, negotiated bounds, disconnect cleanup, policy revocation, and
socket-write acknowledgement are enforced in the live runtime. Only verified
public target records, anti-rollback sequence high-water marks, policy state,
and cache/policy/trusted-time generation floors are durable atomically;
live sessions and HPKE context are not. Local proxy, target, and output roles
remain unavailable, and decrypted response bytes remain untrusted until the
higher resolver boundary parses, correlates, and DNSSEC-validates them.

HIP-78 requester and opaque circuit relay are wired through live authenticated
peers and default on with independent durable opt-outs and explicit re-enable.
The runtime admits only HNS
Node v1 over exact Brontide and canonical Denuo V1 evidence, acknowledges real
destination writes, revokes connection-owned state on lifecycle failure, and
persists only checksummed policy/counter/generation/time state. Relay service
advertisement remains unavailable until an explicit valid advertise address
and durable Brontide identity are configured. Endpoint, rendezvous, and
plaintext provider roles are unavailable.

The current tree contains hardened authority, storage, transaction, covenant,
and name-state foundations, a live native P2P/synchronization foundation, and a
bounded mempool, future-template, and durable solved-block publication
foundation. Native synchronization can produce fully validated durable block
status, but the mining engine cannot authorize jobs or publish solved blocks
without the private authority capability and a currently authoritative durable
tip. API-v15
exposes the exact next-header interval-committed root, and the external comparison
runner can check it against a pinned live HSD node without feeding oracle data
back into consensus.

## Authority, storage, and reorganization safety

Implemented:

- Independent root and fuzz-workspace CI for locked metadata and dependency
  policy, formatting, Clippy, feature matrices, tests, release builds, and
  RustSec checks, followed by a two-node regtest P2P/Denuo qualification.
- Explicit validation-stage bits rather than coarse `tx_valid` or
  `state_connected` labels.
- `disabled`, legacy `shadow`, fail-closed `native`, reserved `hsd-verified`, and explicitly gated
  `native-experimental` authority modes.
- A private authority capability required by authoritative mining-template and
  candidate-admission boundaries.
- Test-only fixture imports and caller-supplied chainwork.
- Sequence-consistent RocksDB read snapshots.
- One-snapshot, read-your-writes, one-batch multi-block reorganizations.
- Separate durable best-header and active-best-block bindings.
- Strict greater-work activation; equal-work branches preserve the existing
  first-seen tip.
- Schema version **19**, storage profile **`hsrd-mining-v15`**, a reversible
  36-block name accumulator, one-pass Patricia mutation frontiers, append-only
  64 KiB name pages with authenticated 4 KiB indexes/record subpages, monotonic
  360-height physical page seals, and checksummed append-only block/undo
  segments whose compact locators publish atomically with chain state. Schema
  16, 17, and 18 stores migrate in place and fail closed on ambiguous profile
  combinations.
- Startup checks that compare the interval accumulator and materialized
  name-state column, validate every retained committed root, truncate
  unpublished page/frame tails, and reject locator/manifest disagreement.
- Optional `--transaction-index` historical lookup. The mining profile omits
  the redundant per-transaction LSM write by default.
- Optional `--script-history-index`, `--spender-index`, and combined
  `--wallet-index` active-chain profiles, staged atomically with UTXO/name
  state and exactly reversed on disconnect/reorganization. The typed
  noncustodial backend, bounded fee estimator, current name proof/owner lookup,
  contextual transaction admission/P2P fanout, one-pass bounded multi-script
  mempool reconciliation, chain-epoch-bound global confirmed history/UTXO
  restoration, active-height hash reads, atomically bundled transaction/name
  evidence, immutable ordered outpoint-spend batches,
  collection-admitted/256-examination confirmed pagination, and chain-epoch-,
  process-instance-, plus generation-bound mempool pagination are implemented in
  source; all remain disabled by default. Native sync now projects the safe
  subset through wallet RPC v1 without a sibling dependency. That route is
  absent outside active-state native sync and fails closed unless both explicit
  listener Authorization and the durable complete wallet profile are
  configured; it preserves opaque chain/query cursors,
  explicit chain/tip and mempool instance nonce/generation, optional exact
  transaction position and block time without zero sentinels, canonical encoded
  current/proof NameState bytes and separate owner views, and versioned
  TRANSFER/FINALIZE name-action contexts bound to the exact chain epoch and
  mempool process generation. Each name-action context echoes stable
  network/genesis/`hns-consensus/name-policy-v1` identity, candidate tip-plus-one
  height, the exact active owner and any immutable-mempool owner spender,
  canonical lockup/maturity evidence, and HSD-selected active-chain renewal
  block under a fixed nine-reason fail-closed eligibility bound. Contextual
  signed-transaction broadcast, transaction-bound HSD policy fee quotes, and
  stable redacted errors under the existing HTTP/backend resource bounds plus stricter
  256-row/1,024-scan wire limits and an 8 MiB measured JSON-result ceiling.
  Each fee quote requires an exact chain epoch and mempool instance/generation,
  resolves input coins from that stable capture, and reports same-generation
  rate evidence, transaction weight, input-aware sigops, sigop-adjusted policy
  virtual bytes, minimum fee, and checked actual-fee/shortfall evidence in
  explicit atomic units. It accepts no
  caller-derived coin or sizing evidence and neither signs nor broadcasts. The
  result is exact only for the supplied serialized witness bytes, requiring a
  final-signed-artifact requote before broadcast.
  Contract registration,
  canonical name/resource interpretation, and raw revealed-preimage transport
  remain unavailable across this wire boundary. Immutable public Shakedex-v2 and
  HNS-HTLC-v1 registrations drive restart-durable funding, seller-signed
  TRANSFER fulfillment (`0x84`) and recovery (`0x83`), redemption, refund, and
  internally raw/publicly redacted revealed-preimage events in the canonical
  block/reorg batch. Consensus-valid spends outside the pinned wallet profile
  are recorded as `Unrecognized` rather than rejected. Contract IDs use an
  explicit versioned canonical binary encoding, while bounded one-to-many
  address candidates preserve valid key reuse and match exact output terms.
  Contract pages bind their contract and chain epoch. Connect indexing reads the
  authenticated pre-current-block UTXO view plus the complete same-block output
  map before state-overlay mutation. A checksummed monotonic confirmation row and lifecycle revision are
  written with every new registration and set permanently on first matching
  canonical funding. The typed backend can retire only exact never-confirmed
  registrations after binding the caller's revision, requiring no retained
  transaction orphans, and applying an exact current accepted ordinary/airdrop
  scan plus canonical-writer guard,
  atomically reclaiming active global and per-address slots. A separate typed
  completed transition reclaims the same active slots only for an exactly
  paired, fully spent event history below the durable undo-pruned frontier.
  Its immutable tombstone preserves exact descriptor/lifecycle identity,
  terminal and revealed-preimage evidence, min/max heights, and a commitment
  over all ordered deleted rows; startup checks current pruning and canonical
  block authority. Retired IDs cannot be reused. Legacy-unknown records remain
  non-retirable. The finite tombstone/event limits and permanent-abandonment
  semantics remain a narrower production-availability blocker and untrusted
  registration remains absent. A concrete adapter boundary now exists in
  `hns-wallet-rs`; this implementation is awaiting the repository's full gate,
  product integration, a published and pinned canonical `hns-swap` release,
  and cross-repository adapter qualification. Local script duplication and
  frozen vectors are not protocol
  authority and no release-readiness claim is made by this source status
  update. The focused NVMe command
  `cargo test --locked -p hns-consensus wallet_name_action -- --test-threads=1`
  passed 2 tests with 0 failures and 75 filtered. It covers only the canonical
  action-height/source helpers; wallet-backend/RPC, restart/reorg/adversarial,
  RocksDB, and the repository's full qualification gate remain unexecuted for
  that prior tranche and inherit no result from an earlier commit. At exact
  local revision `fd0c9b00114e3fa0a293972de7d4538dcd959ce0`, the one focused
  `production_next_` command compiled hns-node and passed all four matching
  wallet-index retirement/profile tests with zero failures and 15 filtered,
  using the existing prebuilt RocksDB archive under `ROCKSDB_COMPILE=0`. It was
  not a RocksDB reopen, live restart/reorg, adversarial, or full-gate run.
- A bounded hash-first Denuo marketplace relay/cache core with five separate
  roles is implemented with pre-validation peer charging, automatic malformed
  strikes, consequential bounded scores/bans, and indexed expiry. Live
  marketplace wire advertisement remains disabled until the currently
  unpublished canonical `hns-rs` 0.2 Denuo V2 registry/envelope release is
  pinned by revision and its adapter is qualified; no live swap engine is
  claimed.
- Opt-in `--prune-undo-history` retirement at HSD's exact per-network
  `pruneAfterHeight`/`keepBlocks` horizon. Each atomic retirement clears the
  block/header undo status and advances a checksummed checkpoint; startup
  catches up missed heights, retires the matching interval pin in the same
  batch, and a reorganization that reaches retired undo fails before mutation.
  Pruned mode compacts unreachable name-tree nodes every configured maintenance
  interval. Once a store has retired undo, the option cannot be disabled for
  that store.

## Transaction authorization foundation

Implemented:

- HSD-compatible signature hashing for all defined base modes and
  `NOINPUT`/`ANYONECANPAY` combinations.
- Relative sequence-lock calculation and CLTV/CSV predicates.
- A bounded version-zero witness/script interpreter matching every case in the
  pinned HSD 876-case upstream script corpus, including normalized rejection
  codes and historical BIP66-derived ordering cases.
- Handshake BLAKE160, BLAKE256, SHA3, and Keccak script operations.
- A verification-only safe Rust wrapper over the exact vendored
  `libsecp256k1` source used by the pinned HSD dependency.
- Compact-signature parsing, low-S enforcement, compressed public-key parsing,
  and ECDSA verification.
- Spent-output address persistence in the UTXO coin codec.
- Input authorization and relative-lock checks before any spend is staged.
- Fail-closed verification when a complete authorization backend is not
  explicitly installed.
- Reproducible HSD signature-hash, sequence-lock, and 56-case focused script
  execution/error fixtures, plus a pinned-source full-corpus verifier covering
  all 876 upstream execution outcomes and sigop counts, including
  flag-sensitive numeric-depth behavior.
- Reproducible complete canonical genesis blocks for all four HSD networks,
  with strict peer-style import, UTXO/undo connection, durable restart, and a
  canonical mainnet block-1 continuation through the ordinary validation path.
- Exact HSD BIP9 threshold transitions, block-version signaling, deployment
  effects, mandatory/standard script flags, all four networks' deployment
  parameters, and all 15 mainnet checkpoint hashes.
- Compact canonical-mainnet evidence for all 168 completed deployment periods
  through height 338,688, replaying real signal counts, median times, threshold
  states, deployment effects, next-block versions, and the checkpoint-backed
  historical boundary through both pinned HSD and Rust.
- Parent-derived active-chain deployment state with HSD period-boundary
  caching, atomic reorganization/restart persistence, and fail-closed cache
  validation before contextual name and claim/airdrop checks. Native template
  assembly revalidates the canonical tip and durable parent MTP, derives HSD's
  next-block version and time-dependent target from that exact context, and
  rejects caller-selected mismatches or consensus-invalid time floors.
- Strict header checkpoint enforcement and a fail-closed historical-script
  policy that requires verified checkpoint ancestry before allowing HSD's
  optional historical validation shortcut.
- Block import carries one HSD-exact historical/full plan through active-state
  connection only when the candidate and final configured checkpoint are bound
  to the same best validated header path. A strictly validated final-checkpoint
  block supplies its own binding; missing, mismatched, failed, alternate-branch,
  post-checkpoint, or checkpoint-free evidence selects the full route.
- An HSD-executed historical validation-plan matrix pins which body, header,
  deployment, finality, transaction-start, claim/airdrop, input, covenant,
  reward, and script stages are checked or assumed at the checkpoint boundary.
  HSD's always-on mainnet pre-height-2,016 restriction permits only one
  ordinary coinbase output and is enforced before any historical shortcut. The
  historical route retains body commitments, name DoS limits, header and
  deployment context, absolute finality, transaction start, coinbase height,
  special-proof format/time/deployment checks, allocation-bit spending, UTXO
  existence, and mutating name-covenant context. It applies HSD's coordinated
  checkpoint assumptions for body sanity, proof cryptography/output binding,
  maturity/value/reward checks, sequence locks, contextual sigops, covenant
  links, scripts, and BID/REDEEM NameState reads. The runtime records the exact
  route in each state result. Broader full-history replay remains an independent
  audit and hardening campaign, not a false consensus-readiness bit.
- Exact bounded HSD Claim envelope encoding, blob-only Claim hashes, and the
  checksummed ownership TXT payload codec for all four network prefixes.
- Compression-free DNSKEY/DS/TXT/RRSIG ownership-proof parsing, exact HSD
  sanity/window/weak-key behavior, the pinned ICANN 2017 root anchor, canonical
  DNSSEC signature-chain verification for HSD's supported algorithms, all five
  DS digests including legacy GOST94/CryptoPro, and reserved-target/output/
  commit/deflation accounting checks. The complete four-proof HSD upstream
  ownership corpus is replayed under SHA-256 and GOST94 historical anchors.
- Checkpoint-linked canonical-mainnet evidence from block 62,517, including its
  two real CLAIM witnesses, exact parent-header timestamp semantics, full raw
  block/body validation, and native claim coinbase connect/disconnect. The
  fixture demonstrates why HSD's claim RRSIG clock is the exact parent block
  time rather than median-time-past.
- A second checkpoint-linked history replays seven initial-claim coinbases at
  heights 39,086-39,101 and all ten canonical replacement claims at height
  76,722. It exercises height-1 to height-2 commit advancement, exact retained
  output values, post-deflation accounting, claim-frequency eligibility,
  authenticated name-state replacement, and reverse disconnect. The mixed-size
  `.zone` DNSKEY RRset also pins HSD's canonical RDATA sort order.
- Native verification for all five HSD airdrop key types: direct address
  allocations, RSA/SHA-256, compact P-256 ECDSA, Ed25519, and the exact pinned
  Goosig 0.11.0 verifier. HSD-generated vectors cover valid and mutated
  signatures, plus an upstream production-root GooSig allocation through the
  active node's durable duplicate-prevention path.

Remaining release hardening:

- broader independently generated script fuzz and invalid corpora beyond HSD's
  upstream suite;
- broader historical replay and independent review of the Rust wrapper and
  script integration beyond the retained qualification used for source
  readiness.

## Covenant, name-state, Urkel-root, and best-chain foundations

Implemented:

- Exact non-coinbase covenant input/output linkage from HSD
  `verifyCovenants`, including BID/REVEAL commitments, linked indexes, locked
  values, address preservation, transfer destinations, revocation burns, and
  unknown-covenant restrictions.
- A contextual non-claim name-transition foundation covering OPEN, BID,
  REVEAL, REDEEM, REGISTER, UPDATE, RENEW, TRANSFER, FINALIZE, and REVOKE.
- A pinned HSD contextual corpus with 15 accepted and 13 rejected transitions,
  including the full auction/ownership lifecycle, exact `NameState` post-images,
  historical BID/REDEEM bypasses, expiration/reopen, renewal ancestry, and
  hardened weak-claim registration.
- Exact pinned reserved-name and lockup datasets.
- HSD-derived renewal-commitment boundary fixtures.
- Exact HSD `NameState` value encoding and undo records.
- A correctness-first in-memory compressed Urkel implementation with exact
  HSD-derived roots, canonical bounded HSD proof encoding/decoding, and native
  inclusion/non-inclusion verification across all four terminal forms.
- A pinned byte-for-byte Urkel proof corpus with inclusion, dead-end, short,
  collision, trailing-byte, malformed-length, wrong-root, and wrong-key cases.
- Canonical content-addressed node records keyed by their exact HSD/Urkel node
  hash, staged atomically with each name-state/root transition and retained
  across later roots.
- Immutable path-local inserts, replacements, and removals that construct only
  changed ancestors, read freshly staged nodes across one-batch reorganizations,
  and match the independent rebuild oracle and pinned HSD incremental roots.
- Path-local durable inclusion/non-inclusion proof reads that rehash every
  loaded record and reproduce the pinned HSD proof bytes after engine and
  RocksDB restart.
- Root-checked immutable proof views rebuilt from sequence-consistent durable
  name-state snapshots; views stay pinned across later commits and reproduce
  exact proof bytes after state-engine restart.
- Correct Handshake root timing: block `H` commits to the inherited pre-state
  root; applying block `H` produces the root that block `H+1` must commit to.
- Durable previous/resulting roots in block undo records.
- Versioned, checksummed root pins written at each network `treeInterval`,
  removed with their active block on disconnect, and exhaustively checked at
  startup against active indexes, undo, and reachable authenticated records.
- Explicit mark-and-sweep node compaction that validates the union reachable
  from the current root, every retained undo root, and every interval pin
  before atomically deleting anything else; malformed metadata and failed
  commits leave all records unchanged.
- HSD-shaped opt-in startup scheduling with a nonzero block-height interval
  (10,000 by default), a checksummed last-run checkpoint committed in the same
  batch as deletions, manual serialized maintenance, and current API-v15 status
  counts (introduced with the API-v9 compaction diagnostics).
- Optional HSD-shaped undo retirement preserves heights through
  `pruneAfterHeight` and the newest `keepBlocks`, advances a checksummed
  checkpoint in the same batch as each status/undo deletion, preserves
  interval-pinned roots after their undo expires, and rejects deeper reorgs.
- Atomic name-state and durable-root writes on connect, disconnect, and
  multi-block reorganization.
- Authenticated CLAIM name-state creation/replacement with active-chain commit,
  hardening, frequency/value, and atomic disconnect/undo checks at the state
  service boundary.
- Checkpoint-linked `mylinksfree` replay across its complete claim-height
  1→2→3 lineage at blocks 55,798, 177,097, and 178,235, including two
  post-deflation replacements with identical retained value and reverse
  authenticated-state restoration. Block 210,237 pins `vcel`, the final
  accepted mainnet claim, while the canonical height-210,240 header/coinbase
  and a mutated terminal proof pin the exact claim-period rejection boundary.
- Stored-root versus materialized-state corruption detection.
- Durable non-active header/index/body storage and validated atomic activation
  of a strictly greater-work replacement branch.

Remaining release hardening:

- independently sourced live DNSSEC-proof evidence for historical-policy
  qualification and complete claim replay beyond the pinned initial,
  multi-generation, and terminal histories (new on-chain claims are impossible
  after mainnet's height-210,240 claim-period boundary);
- full contextual covenant parity across mainnet history;
- deployment-scale compaction performance/priority qualification and RocksDB
  mid-commit process-crash/fault injection for the incremental Urkel lifecycle;
- broader historical root, undo, and reorganization campaigns beyond the
  qualified retained rollback horizon.

## Live native P2P and restartable synchronization

Implemented:

- Exact bounded HNS frame and sync-relevant packet codecs with pinned HSD wire
  fixtures.
- Live inbound, explicit outbound, and opt-in discovered TCP sessions with
  VERSION, VERACK, SENDHEADERS, PING/PONG, self-connection rejection,
  handshake/idle timeouts, and byte counters. Mainnet and testnet use HSD's
  authenticated Brontide transport (Noise XK, Elligator-Squared,
  ChaCha20-Poly1305, exact transcript rules, and 1,000-record key rotation);
  plaintext remains limited to regtest/simnet development. Pinned HSD cipher,
  split-key, packet, and rotation vectors plus a full encrypted manager test
  cover the transport boundary. Partial frame reads remain pinned across timer
  maintenance so a ping tick cannot desynchronize a large block payload.
- Bounded critical, control, and normal outbound queues.
- A bounded peer manager with connection limits, duplicate-address rejection,
  connection-local scoring, HSD's score-100/24-hour normalized-IP ban policy,
  pre-handshake inbound/outbound enforcement, snapshots, and exponential
  outbound reconnect backoff. Ban records are restart-durable when a data
  directory is configured.
- Opt-in bootstrap from HSD's pinned key-bearing Brontide seed table and
  GETADDR/ADDR learning through a bounded, restart-durable address book.
  Discovery accepts only key-bearing, network-service, routable addresses with
  HSD-normalized timestamps; public keys survive restart and newer address
  records can rotate them. Repeatedly failing
  discovered targets rotate without displacing explicit reconnect peers.
  Discovered outbound targets and simultaneous attempts enforce HSD's exact
  IPv4 `/16`, IPv6 `/32`, HE `/36`, and transition-address group keys.
  Explicit peers retain operator-selected priority while their live attempts
  still reserve groups against discovery.
- Headers-first synchronization with 2,000-header atomic protocol batches and an
  explicit headers-only checkpoint/deployment-ancestry qualification mode. A
  read-only diagnostic independently replays every canonical BIP9 window and
  reports current threshold states, next-block version, mandatory script/lock/
  name effects, and the final-checkpoint historical-script binding. Bounded
  body-work reservations span pending, inflight, validator, and orphan states.
  The canonical download window never exceeds the configured orphan-count
  horizon, so that downloader alone cannot create an unbounded durable
  future-body range when a low body is delayed. A strictly validated canonical
  body is stored as non-active before its parent body arrives; the contiguous
  and active tips remain pinned at the first gap. Non-canonical descendants
  continue to use bounded in-memory orphan retention.
  Selected hashes are coalesced into one bounded HSD-shaped `GETDATA` inventory
  per peer. Failed queue admission atomically restores the exact scheduler
  reservations without consuming a retry; transport-stale peers are removed
  immediately, while queue pressure retains the live peer for a clean retry.
  Honest `notfound` responses exclude that peer only for the unavailable hash,
  fail over without consuming validation/transport retries, and remain distinct
  from invalid-block evidence. Header and block deadlines match HSD's 60- and
  120-second behavior; one expired block batch disconnects its peer once while
  retaining per-block retry accounting. A valid response already in transit
  remains admissible if it wins the timeout/disconnect race.
- HSD-compatible `SENDCMPCT` negotiation and BIP152 `CMPCTBLOCK`,
  `GETBLOCKTXN`, and `BLOCKTXN` codecs. Negotiated peers use witness-hash
  short IDs, bounded mempool-assisted reconstruction, exact missing-transaction
  requests, collision fallback, and recent-block compact serving.
- Bounded oldest-first orphan retention for non-canonical descendants only
  after the block's header context is known and the body passes stateless
  validation. Bodies with no known header context are dropped after requesting
  headers.
- CPU-heavy stateless body validation through blocking workers and ordered
  result delivery.
- Header-committed permanent invalidity is atomically retained in durable
  header/block status, propagated to known descendants, and excluded from
  best-header selection across restart. Body/header mismatches remain retryable
  peer failures, while validator-worker failures are immediately requeued and
  neither poison branches nor affect peer-failure accounting.
- Durable best-header and contiguous stored-body progress plus a versioned,
  checksummed restart checkpoint that is cross-checked against durable state.
- Bounded native active-state batches that resume stored work
  after restart and use the same contextual state/reorganization pipeline as
  local blocks. Contextual-invalid roots and known descendants are durably
  failed with atomic header fallback; local storage/backend faults stop sync
  without poisoning the branch.
- Read-only bounded serving of headers, block inventory, retained full or
  compact bodies, requested block transactions, learned routable addresses,
  and accepted ordinary/claim/airdrop mempool inventory and payloads.
- Read-only peer and synchronization diagnostics.
- Constant-payload live status snapshots: diagnostic routes use point-read
  metadata plus post-commit in-memory block-status counts instead of decoding
  every historical block, transaction, UTXO, and name record.
- Native mainnet body and active-state synchronization by default, plus explicit
  headers-only and observe-only reductions. Synchronization alone cannot mint
  the private mining authority capability.
- A fail-closed external live HSD comparison runner for canonical block hashes
  and post-tip authenticated roots, with race retries, pinned-source checks,
  provisional-versus-confirmed root labeling, and a checksummed bounded
  restart/reorganization evidence checkpoint.

Remaining network and operational hardening:

- Long-lived subthreshold peer reputation and broader adversarial network
  qualification;
- sustained adversarial qualification of the implemented ordinary,
  claim/airdrop, and solved-block relay paths;
- long-duration production-scale contextual active-state IBD and sustained
  reorganization campaigns beyond the stopped-state and retained-horizon
  qualifications;
- pruning-aware synchronization, invalid-branch pruning policy, and production
  Urkel lifecycle qualification;
- sustained live HSD state/root agreement campaigns using the comparison
  runner across restarts, partitions, and real reorganizations;
- continued live HSD comparison across changing mainnet conditions. The
  conditional mainnet canary permit path is implemented but remains dependent
  on the explicit synchronized canary and durable runtime gates; no base or
  live release-stage diagnostic bypasses those gates.

## Bounded mempool, templates, and solved-block publication

Implemented:

- Explicit hard bounds for accepted transactions, bytes, orphans, ancestor and
  descendant graphs, template variants, and pending publication intents.
- Immutable mempool generations, dependency indexes, deterministic package
  construction, orphan promotion, and atomic active-chain reconciliation.
- Structural, finality, sequence-lock, maturity, authorization, covenant-link,
  contextual, fee, and resource admission stages with explicit verifier
  completeness gates.
- Ordinary peer transactions admitted against one immutable active-chain UTXO,
  median-time, deployment, and name-state snapshot, including deterministic
  mempool name-overlay replay, exclusive-name conflicts, and orphan promotion.
- HSD mainnet transaction/output standardness, contextual witness-shape limits,
  standard script flags on every network, dust thresholds, and absurd-fee
  protection, pinned to the HSD policy oracle.
- HSD 72-hour root-package expiry and descendant-aware fee eviction to the
  90% trim target, with deterministic oldest-first equal-rate ordering.
- HSD confirmed-coin free-relay priority and the default exponentially decaying
  low-fee rate limiter, including exact strict-threshold behavior.
- Atomic post-connect revalidation of every retained transaction and orphan
  against the new active context, with one monotonic generation update and
  fail-closed clearing on internal view failure.
- Contextual ordinary-transaction re-admission after disconnects and
  reorganizations, with older disconnected name updates considered before the
  retained pool and replacement-branch conflicts removed transitively.
- Typed HSD airdrop wire/inventory/GETDATA relay, native deployment- and
  allocation-field-aware admission, reorg reconciliation, and fee-ranked
  ten-proof coinbase assembly.
- Typed HSD DNSSEC claim wire/inventory/GETDATA relay, native proof and exact
  active-name/commit-ancestry admission, shared name-conflict replacement,
  connected/disconnected reconciliation, and HSD-ordered ten-claim coinbase
  assembly before airdrops.
- Deterministic ancestor-inclusive template selection with HNS weight, sigops,
  OPEN, UPDATE, RENEW, transaction-count, and exclusive-name limits.
- HSD-derived subsidy and deterministic coinbase fixtures.
- Durable canonical-tip/MTP binding plus HSD-derived deployment version,
  time-dependent target, consensus timestamp-floor validation, and testnet
  target-reset job expiry.
- Atomic bounded future-template variant replacement and exact chain/mempool
  generation activation.
- Versioned checksummed solved-block publication intents.
- Full local candidate admission before parallel critical peer fan-out.
- Publication retry only for blocks already accepted on the local active chain.
- Mempool/template invalidation on direct connections, disconnects,
  reorganizations, and accepted mempool generations.
- `getminingengineinfo` and `/api/v1/mining-engine` diagnostics.

Remaining mining-path hardening:

- long-duration full-history active-state and incremental production Urkel
  lifecycle campaigns;
- sustained live HSD comparison evidence across restarts, partitions, and real
  reorganizations;
- measured template/job and solved-block publication latency;
- physical deployment qualification. The mainnet canary can issue a permit
  only at a synchronized authoritative tip; its `mainnet-canary-gated` live
  release-stage label describes that mode rather than proving the tip is
  currently authorized.

See [`mining-engine.md`](mining-engine.md).

Release IBD and native mining-path measurement commands, current bounded
results, and their qualification limits are in
[`performance.md`](performance.md).

## Authority gates

Every functional readiness field currently reports complete. The base snapshot
uses `release_stage: "pre-authority"` and live native RPC replaces it with a
configuration-specific stage. A native mainnet permit is nevertheless fail
closed unless `--mainnet-canary` passes its
hardened configuration checks and the live best header, active state, chainwork,
durable status, and pending-chain view form one coherent authoritative tip. The
live network path is available in `disabled`, legacy `shadow`, or `native`
authority modes; only the qualified `native` path can receive a
`MiningAuthorityPermit`. Independent review and longer operational campaigns
remain release-hardening work rather than hidden readiness overrides.

See:

- [`mining-node-scope.md`](mining-node-scope.md)
- [`readiness.md`](readiness.md)
- [`gap-analysis.md`](gap-analysis.md)
- [`p2p-sync.md`](p2p-sync.md)
- [`live-shadow-parity.md`](live-shadow-parity.md)
- [`mining-engine.md`](mining-engine.md)
- [`storage-schema.md`](storage-schema.md)
- [`hsd-decomposition.md`](hsd-decomposition.md)

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
scripts/compare-hsrd-hsd-shadow.py --self-test
npm run hsrd-script-fixtures --prefix hsd-oracle
npm run hsrd-deployment-fixtures --prefix hsd-oracle
npm run hsrd-genesis-fixtures --prefix hsd-oracle
npm run hsrd-mainnet-deployment-history --prefix hsd-oracle
npm run hsrd-mainnet-claim-history --prefix hsd-oracle
npm run hsrd-mainnet-claim-replacements --prefix hsd-oracle
npm run hsrd-covenant-fixtures --prefix hsd-oracle
npm run hsrd-name-state-codec-fixtures --prefix hsd-oracle
npm run hsrd-name-transition-fixtures --prefix hsd-oracle
npm run hsrd-name-state-urkel-fixtures --prefix hsd-oracle
npm run hsrd-urkel-proof-fixtures --prefix hsd-oracle
npm run hsrd-name-policy-fixtures --prefix hsd-oracle
npm run hsrd-p2p-wire-fixtures --prefix hsd-oracle
npm run hsrd-mining-template-fixtures --prefix hsd-oracle
scripts/verify-hsrd-secp256k1.sh
```

Those source-handoff, oracle-generation, and comparison commands still live in
the source MeshMine repository and were not part of the history-preserving
`hsrd/` prefix extraction. The committed Rust fixtures remain in this
repository. Until the independent tooling is ported, run those checks against
the source commit recorded in
[the extraction provenance](extraction-provenance.md).

Compiler gates:

```bash
./scripts/check.sh

# Equivalent individual commands:
cargo metadata --locked --manifest-path Cargo.toml --format-version 1
cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1
cargo fmt --manifest-path Cargo.toml --all --check
cargo fmt --manifest-path fuzz/Cargo.toml --all --check
cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets
cargo clippy --locked --manifest-path Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path Cargo.toml \
  --workspace --all-targets --all-features
cargo test --locked --manifest-path Cargo.toml \
  --workspace --all-targets --no-default-features
cargo build --locked --release --manifest-path Cargo.toml \
  --workspace --all-targets --all-features
```

The complete gate ends by launching two isolated regtest `hsrd` processes,
waiting for both standard Handshake peers to remain ready after canonical
Denuo registry negotiation, and checking their matching fingerprints and
bidirectional traffic through qname-free local diagnostics. Ports may be
overridden with `HNS_NODE_RPC_A`, `HNS_NODE_RPC_B`, `HNS_NODE_P2P_A`, and
`HNS_NODE_P2P_B`.

The offline wrapper attempts the npm advisory audit with a bounded timeout. If
the advisory service is unavailable, it reports that fact and continues the
offline handoff checks; CI still runs the strict `npm run audit` command and
fails when the audit cannot be completed.

The static, fixture, and C-level secp256k1 checks are valuable fail-fast gates.
They are not substitutes for the strict dependency audit or Cargo gates.

## Storage migration

Schema 19/profile `hsrd-mining-v15` accepts schema-17 and schema-18 interval
state through an atomic marker cutover and converts schema-16 working-tree
state with the resumable, backup-first undo migration. New name records use
authenticated 4 KiB subpages while every schema-18 64 KiB page remains
readable in place. On first open without page state it packs the current
committed name tree and initializes block/undo segment manifests; legacy
RocksDB payloads remain readable while every new payload is stored only as a
locator plus an append-only frame. Interrupted rollout is restart-safe.

Block undo version 7 carries the prior accumulator and boundary state needed to
reverse pending intervals. The optional undo-retirement checkpoint uses the
existing snapshots namespace; once present, `--prune-undo-history` is required
on subsequent opens. Schema/profile combinations older than 16 or otherwise
ambiguous still fail closed and require an explicit reindex.

The reviewed offline backup, bounded inline-payload conversion, verification,
and non-destructive fallback procedure is
[`storage-rollout.md`](storage-rollout.md). The maintenance marker
blocks normal node startup, and the maintenance tool requires both RocksDB
exclusivity and an explicit clean-shutdown record.
