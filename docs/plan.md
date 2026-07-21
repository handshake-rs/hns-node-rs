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
- Schema 11/profile `hsrd-mining-v7`, durable name-tree-root and HSD
  airdrop-field bindings, hash-keyed deployment-state caches, a checksummed
  synchronization checkpoint, and a versioned solved-block publication
  namespace.
- Root/materialized-state verification at connect, disconnect, reorganization,
  and startup.

### Transaction authorization

- HSD signature hashing and relative locks.
- Complete pinned-HSD interpreter parity across all 876 upstream script cases.
- Exact HSD BIP9 deployment selection, checkpoint tables/enforcement, and a
  fail-closed checkpoint-backed historical script policy.
- Exact vendored native secp256k1 verification backend.
- Authorization and lock checks before state mutation.

### Covenant and name state

- Exact non-coinbase covenant linkage.
- Contextual non-claim name-state transitions plus authenticated CLAIM
  connect/disconnect under active parent-derived deployment state.
- Reserved/lockup datasets and renewal-policy fixtures.
- Exact `NameState` encoding and undo.
- Correctness-first exact Urkel roots and internal proofs.
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
   and replay the proof-capable active-node service across mainnet history.
   Exact Claim/DNSSEC/TXT codecs, all HSD DS digests including GOST94, the
   complete upstream historical ownership-proof corpus, ICANN-rooted signature
   verification, parent-derived deployment composition, claim deflation and
   name-state rules, all five airdrop key types (including pinned GooSig),
   faucet and production-root proof verification, conjured accounting, and
   durable duplicate prevention/undo are implemented.
2. **Contextual covenant closure** — replay all mainnet transition families and
   historical exceptions against HSD.
3. **Persistent Urkel** — incremental nodes, exact proof wire format,
   snapshots, undo, compaction, and crash qualification while preserving exact
   correctness-first roots.
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
