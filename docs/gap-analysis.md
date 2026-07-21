# Gap analysis

## Implemented evidence

### Primitive, chain, and storage foundation

- Bounded header, transaction, block, covenant, address, resource, witness, and
  sync-relevant P2P codecs with HSD-derived fixtures.
- Exact unsigned 256-bit chainwork and durable header/block/raw-body indexes.
- Memory and RocksDB stores behind typed traits, atomic batches, true RocksDB
  snapshots, and a read-your-writes reorganization overlay.
- Schema version 11, profile `hsrd-mining-v7`, network, genesis, epoch,
  mandatory name-tree-root and HSD airdrop-field bindings, hash-keyed
  deployment-state caches, checksummed sync checkpoint, and a bounded
  checksummed solved-block publication namespace.
- Durable alternate branches, separate best-header and active-block bindings,
  equal-work stability, strict greater-work activation, and one-batch
  replacement after ancestry/body/status/work/root checks.

### Validation and state foundation

- Header PoW, parent linkage, HNS difficulty, timestamp bounds, block syntax and
  commitments, ordinary subsidy-plus-fee accounting, absolute finality, UTXO
  connect/disconnect, coinbase maturity, duplicate/missing spend checks, value
  conservation, and output-collision checks.
- HSD signature hashing, relative locks, CLTV, and CSV.
- Bounded witness/script interpreter matching all 876 pinned upstream HSD
  execution cases, plus 56 committed focused execution/error vectors.
- Exact HSD BIP9 transitions, block-version selection, deployment effects,
  network checkpoint tables, strict header checkpoint enforcement, and a
  checkpoint-ancestry-gated historical script policy.
- Canonical-mainnet replay of all 167 completed deployment periods through
  height 336,672, including real median times, signal counts, threshold states,
  deployment effects, and the historical-script boundary.
- Active blocks derive name and issuance flags from their parent, cache all
  four threshold states atomically, retain branch caches across reorganization,
  and fail startup on missing or inconsistent active-chain cache entries.
- Verification-only wrapper around the exact vendored HSD secp256k1 source,
  including compact low-S ECDSA and compressed keys.
- Exact non-coinbase covenant linkage before UTXO mutation.
- Contextual non-claim name-state transition foundation.
- Exact reserved-name/lockup datasets and renewal boundary evidence.
- Exact HSD `NameState` codec and name undo.
- Correctness-first exact Urkel roots and internal memory proof checks.
- Correct Handshake pre-state header-root timing and durable resulting-root
  binding.
- Exact HSD airdrop key/proof codecs, hashes, Merkle/output/accounting checks,
  valid faucet proof handling, and atomic duplicate-position connect/undo;
  the active node composes faucet verification from parent deployment state,
  while non-address signature backends remain fail-closed.
- Exact HSD Claim envelope encoding and blob-only hashes plus checksummed
  ownership TXT payloads for all four networks.
- Exact compression-free ownership-proof DNS codecs and HSD sanity/time/weak
  behavior, ICANN-rooted DS/RRSIG authentication through RSA, P-256/P-384,
  Ed25519, and Ed448, reserved allocation/output/commit/deflation accounting,
  and atomic contextual claimed-name connect/disconnect at the service
  boundary.

### Network and synchronization foundation

- Exact bounded HNS framing and sync packet behavior with pinned HSD wire
  fixtures.
- Live inbound/outbound plaintext peers with handshake, service, self-connect,
  timeout, ping/pong, and priority-queue controls.
- Bounded peer manager, scoring, disconnect, snapshots, and reconnect backoff.
- Headers-first synchronization with bounded pending/inflight/per-peer body
  requests, retry, timeout, and reassignment.
- Bounded orphan retention only for statelessly valid bodies with known header
  context; unknown-context bodies are dropped after requesting headers.
- Blocking validation workers with ordered result delivery.
- Durable non-active body retention, contiguous-body recovery, restart
  checkpointing, and bounded read-only serving.
- Observation-only diagnostics; network data cannot grant authority.

### Mempool, template, and publication foundation

- Explicit hard bounds for accepted transactions, bytes, orphans, dependency
  graphs, package members, template variants, and pending publication intents.
- Immutable mempool generations, parent/child/spent-outpoint indexes,
  deterministic dependency-ordered packages, and bounded orphan promotion.
- Admission stages for syntax, finality, conflicts, coin resolution, maturity,
  relative locks, input authorization, covenant linkage, contextual checks,
  value, fees, and resource limits.
- Explicit verifier-completeness gates; compatibility and peer transaction
  entrypoints fail closed until complete contextual consensus is composed.
- Deterministic ancestor-inclusive future templates with HNS weight, sigops,
  OPEN, UPDATE, RENEW, transaction-count, and exclusive-name limits.
- HSD-derived subsidy boundaries and deterministic coinbase bytes.
- Atomic bounded template-variant replacement tied to exact chain and mempool
  generations, parent, and next authenticated tree root.
- Versioned checksummed publication intents and bounded durable recovery.
- Full local candidate admission before parallel reserved critical peer fan-out.
- Retry only for blocks already accepted on the local active chain.
- Conservative mempool clearing on disconnect/reorganization and cache
  invalidation on relevant chain/mempool changes.
- Mining-engine readiness, queue, mempool, and template diagnostics.

### Authority and operational foundation

- Native immutable mining snapshots, durable generation ordering, prepared-job
  identity, exact parent/generation activation, mask binding, and candidate
  admission boundaries.
- Staged versus authoritative event channels.
- Explicit authority modes, capability-gated authoritative paths, readiness
  blockers, parity status, and read-only diagnostics.
- Nested-workspace CI definition, static fixture/schema/authority checks, and a
  C-level vendored secp256k1 smoke test.

These are substantial foundations, not a production full node.

## Mandatory missing work

### Consensus and authenticated state

- Historical checkpoint-fast-path replay qualification and non-script
  historical exceptions.
- Independently generated script fuzz/invalid corpora beyond the complete
  pinned HSD upstream suite.
- Non-address airdrop signatures, legacy GOST94 DS compatibility, broader
  current/historical valid claim-proof corpora, remaining historical datasets,
  and complete replay evidence. Claim deflation accounting, active-node
  deployment composition, and airdrop duplicate/conjured-value accounting are
  implemented.
- Complete contextual covenant/name behavior across mainnet history.
- Production persistent incremental Urkel storage, exact HSD proof wire format,
  snapshots, compaction, and crash recovery.

### Chain and network qualification

- Active-state ordered connection of downloaded blocks and full restartable IBD.
- Invalid-branch persistence policy, pruning interactions, historical
  reorganizations, and RocksDB fault evidence.
- Brontide, address-manager/DNS-seed discovery, durable bans/reputation, and
  broader peer-diversity controls.
- Compact-block reconstruction and pruning-aware synchronization.
- Production-complete contextual peer transaction admission and relay.
- Sustained multipath publication and reconnect/retry supervision under WAN
  partitions and queue saturation.

### Mining authority

- Contextually complete mempool admission, replacement/policy parity, and
  disconnected-transaction re-admission.
- Continuous future-template lifecycle tied to live committed tips and the ASIC
  gateway.
- End-to-end candidate validation against a historically qualified active state.
- Complete historical mainnet replay against the pinned HSD oracle.
- Positive and negative invalid corpora for every rule family.
- Byte-for-byte UTXO, name-state, Urkel-root, deployment, undo, and
  reorganization parity.
- Sustained live HSD shadow agreement through restarts, partitions, tip races,
  and real reorganizations.
- Measured P50/P95/P99/maximum tip-to-job, candidate-validation, local-connect,
  and first-peer-acceptance latency.
- Reproducible builds, external review, fuzzing, and published latency/recovery
  evidence.

## Explicitly excluded product work

Wallets, seed/key management, desktop/mobile UI, domain management, DNS
resolution/serving, explorer indexes, and broad convenience RPC compatibility
remain outside `hsrd`. Consensus parsing of name/resource bytes remains only
where block validity requires it.
