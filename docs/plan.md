# Mining full-node implementation plan

## Goal

Replace MeshMine's `hsd` process/RPC boundary with a lean native Rust HNS node
that performs complete consensus validation, maintains UTXO and authenticated
name state, builds competitive templates, and relays solved blocks through
reserved low-latency paths.

## Design rules

- Complete HNS consensus is mandatory; unrelated product surfaces are excluded.
- One committed active tip and monotonically ordered mining generation are
  authoritative.
- Mining uses native Rust data and bounded channels, never JSON-RPC.
- Solved-block and tip/job work receive reserved CPU, queue, storage, and P2P
  capacity.
- Async socket tasks do not validate consensus or write databases inline.
- Every collection, queue, parser, orphan pool, mempool, template set,
  publication queue, and diagnostic surface has an explicit bound.
- Every state mutation has undo, restart, and atomicity evidence.
- Validation stages remain granular; partial work is never renamed as full
  consensus validity.
- The pinned HSD revision remains the oracle until historical, invalid-corpus,
  reorganization, and live-shadow gates pass.
- Correctness-first implementations are replaced by optimized implementations
  only after differential equality is demonstrated.
- A persisted publication intent is evidence of work awaiting delivery, not
  permission to broadcast an unaccepted block.

## Implemented foundation

### Authority and storage

- Explicit fail-closed authority modes and readiness diagnostics.
- Private authority capability at authoritative mining boundaries.
- Sequence-consistent RocksDB snapshots.
- Atomic read-your-writes multi-block reorganizations.
- Separate best-header and active-block bindings.
- Schema 13/profile `hsrd-mining-v9`, durable name-tree-root,
  content-addressed authenticated nodes, and HSD airdrop-field bindings,
  checksummed network-interval root pins, hash-keyed deployment-state caches, a
  checksummed synchronization checkpoint, and a versioned solved-block
  publication namespace.
- Root/materialized-state verification at connect, disconnect, reorganization,
  and startup.

### Transaction authorization

- HSD signature hashing and relative locks.
- Complete pinned-HSD interpreter parity across all 876 upstream script cases.
- Exact HSD BIP9 deployment selection, checkpoint tables/enforcement, and a
  fail-closed checkpoint-backed historical policy plus a stage-by-stage HSD
  validation-route plan. Broader non-script assumptions remain disabled in the
  native runtime pending historical replay qualification.
- Exact vendored native secp256k1 verification backend.
- Authorization and lock checks before state mutation.

### Covenant and name state

- Exact non-coinbase covenant linkage.
- Contextual non-claim name-state transitions plus authenticated CLAIM
  connect/disconnect under active parent-derived deployment state.
- Pinned HSD replay of 28 contextual transition cases spanning every non-claim
  family, historical BID/REDEEM shortcuts, renewal ancestry, expiration,
  hardening, exact accepted post-states, and targeted rejections.
- A checkpoint-linked canonical mainnet claim case at height 62,517: full raw
  block/body validation, both real DNSSEC witnesses, HSD's exact parent-header
  timestamp rule, and exact coinbase connect/disconnect through native state.
- A checkpoint-linked replacement history covering seven canonical initial
  coinbases and all ten replacements at height 76,722, including exact
  predecessor coin values, height-1/height-2 commit ancestry, post-deflation
  accounting, authenticated state replacement, and reverse disconnect.
- Reserved/lockup datasets and renewal-policy fixtures.
- Exact `NameState` encoding and undo.
- Correctness-first exact Urkel roots plus byte-for-byte canonical HSD
  inclusion/non-inclusion proof encoding, decoding, and verification.
- Root-checked immutable proof views materialized from sequence-consistent
  durable name-state snapshots, stable across later commits and engine restart.
- Canonical content-addressed authenticated nodes staged atomically with state,
  path-local exact proof reads, startup/transition validation, and RocksDB
  restart evidence.
- Path-local immutable insert/replace/remove with HSD incremental-root parity,
  independent rebuild checks, retained historical proofs, and read-your-writes
  multi-step reorganization coverage.
- Validated retained-root compaction over the current root, every undo root,
  and network-interval pins, with restart, malformed-pin, idempotence, and
  failed-commit atomicity coverage.
- Opt-in HSD-shaped startup compaction scheduling, a checksummed atomic
  last-run checkpoint, forced coordinator maintenance, API-v5 diagnostics, and
  unclean RocksDB reopen evidence.
- Opt-in HSD-horizon undo retirement with atomic checkpoints, bounded startup
  catch-up, pruning-aware pinned roots, and fail-closed deep-reorg handling.
- Correct pre-state header commitment and durable resulting-root semantics.

### Live shadow networking

- Exact bounded HNS wire codecs and pinned HSD wire fixtures.
- Bounded inbound/outbound peers, handshake/timeouts, scoring, and reconnect.
- Headers-first download scheduling and bounded body queues.
- Parallel stateless validation with ordered delivery.
- Durable non-active shadow bodies and restartable checkpoints.
- Bounded read-only header/body/transaction serving and diagnostics.
- Reserved critical outbound queues and parallel fan-out.

### Mempool, templates, and publication

- Bounded mempool and orphan storage with dependency and spend indexes.
- Immutable mempool generations and deterministic package construction.
- Explicit verifier-completeness gates; compatibility and peer relay fail
  closed until contextual consensus admission is complete.
- Deterministic ancestor-inclusive templates with HNS operation limits.
- Atomic bounded future-template variants tied to exact chain and mempool
  generations.
- HSD-derived subsidy and deterministic coinbase fixtures.
- Versioned and checksummed durable publication intents.
- Local candidate admission before network publication.
- Parallel critical fan-out with writer-completion acknowledgment and retry only for locally accepted active blocks.
- Conservative mempool clearing on disconnect/reorganization.

## Remaining implementation order

1. **Claim and airdrop validation** — capture current/live valid claim evidence
   and replay the proof-capable active-node service across the rest of mainnet
   history. Heights 62,517 and 39,086-39,101 -> 76,722 now supply bounded
   checkpoint-linked initial and replacement cases with exact parent-time and
   coinbase state replay. Exact Claim/DNSSEC/TXT
   codecs, all HSD DS digests including GOST94, the complete upstream
   historical ownership-proof corpus, ICANN-rooted signature verification,
   parent-derived deployment composition, claim deflation and name-state
   rules, all five airdrop key types (including pinned GooSig), faucet and
   production-root proof verification, conjured accounting, and durable
   duplicate prevention/undo are implemented.
2. **Contextual covenant closure** — extend the complete deterministic HSD
   transition-family corpus into mainnet history and historical exceptions.
3. **Persistent Urkel closure** — scale and priority-qualify the scheduled
   interval-pin/retained-root compactor and complete RocksDB mid-commit
   process-crash/fault qualification while preserving qualified incremental
   roots, historical reachability, and exact proof bytes.
4. **Active-state IBD** — connect downloaded bodies through the one consensus
   pipeline, persist invalid branches, recover from restart, and qualify
   pruning/reorganizations without changing the authority boundary.
5. **Network hardening** — Brontide, address management/discovery, durable
   bans/reputation, peer diversity, compact blocks, and adversarial WAN tests.
6. **Mempool admission closure** — compose complete active-chain views,
   scripts/deployments/claims/name context, disconnected-transaction
   re-admission, policy replacement, and differential corpora.
7. **Mining composition** — continuously rebuild bounded future variants,
   activate jobs on committed tips, supervise publication retries, and bind the
   ASIC gateway without allowing shadow state to authorize work.
8. **Historical/live qualification** — full mainnet replay, invalid corpus,
    state/root comparison, restart/partition/reorganization shadow tests, and
    P50/P95/P99/max mining-lane measurements.
9. **Controlled authority transition** — HSD cross-check and fallback first;
    remove HSD only after reviewed reproducible evidence.

Implementation follows `hsd-decomposition.md`. Wallet, DNS, UI, domain manager,
and broad compatibility modules must not re-enter the node merely for
convenience.
