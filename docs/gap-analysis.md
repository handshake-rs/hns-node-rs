# Gap analysis

## Implemented evidence

### Primitive, chain, and storage foundation

- Bounded header, transaction, block, covenant, address, resource, witness, and
  sync-relevant P2P codecs with HSD-derived fixtures.
- Exact unsigned 256-bit chainwork and durable header/block/raw-body indexes.
- Memory and RocksDB stores behind typed traits, atomic batches, true RocksDB
  snapshots, and a read-your-writes reorganization overlay.
- Schema version 13, profile `hsrd-mining-v9`, network, genesis, epoch,
  mandatory name-tree-root/content-addressed-node and HSD airdrop-field
  bindings, checksummed network-interval root pins, hash-keyed deployment-state
  caches, checksummed sync checkpoint, and a bounded checksummed solved-block
  publication namespace.
- Durable alternate branches, separate best-header and active-block bindings,
  equal-work stability, strict greater-work activation, and one-batch
  replacement after ancestry/body/status/work/root checks.

### Validation and state foundation

- Header PoW, parent linkage, HNS difficulty, timestamp bounds, block syntax and
  commitments, candidate coinbase-height binding, HSD's mainnet
  pre-height-2,016 transaction/coinbase restriction, ordinary subsidy-plus-fee
  accounting, absolute finality, contextual 80,000-sigop enforcement, UTXO
  connect/disconnect, coinbase maturity, duplicate/missing spend checks, value
  conservation, and output-collision checks.
- HSD signature hashing, relative locks, CLTV, and CSV.
- Bounded witness/script interpreter matching all 876 pinned upstream HSD
  execution cases, plus 56 committed focused execution/error vectors with
  exact HSD sigop counts.
- Exact HSD BIP9 transitions, block-version selection, deployment effects,
  network checkpoint tables, strict header checkpoint enforcement, and a
  checkpoint-ancestry-gated historical validation policy with an HSD-executed
  stage-by-stage full/historical route matrix, including always-on transaction
  start and coinbase height plus checkpoint-skipped contextual sigops.
- Block import selects one coordinated HSD historical/full route only for
  candidates on the best validated header path through the exact final
  configured checkpoint and carries it through active state. The historical
  route retains commitments, name/deployment/finality/height checks, special
  proof sanity/allocation spending, UTXO existence, and mutating covenant
  context while applying the exact HSD checkpoint assumptions to the remaining
  stages. Missing or branch-mismatched evidence keeps full validation, and the
  selected route is returned as explicit state-transition evidence.
- Canonical-mainnet replay of all 168 completed deployment periods through
  height 338,688, including real median times, signal counts, threshold states,
  deployment effects, next-block versions, the historical boundary, and the
  exact accepted block-1 coinbase-finality exception with its separate valid
  height commitment.
- Active blocks derive name and issuance flags from their parent, cache all
  four threshold states atomically, retain branch caches across reorganization,
  and fail startup on missing or inconsistent active-chain cache entries.
- Verification-only wrapper around the exact vendored HSD secp256k1 source,
  including compact low-S ECDSA and compressed keys.
- Exact non-coinbase covenant linkage before UTXO mutation.
- Contextual non-claim name-state transition foundation plus 28 exact HSD
  accepted/rejected cases covering every transition family, historical
  BID/REDEEM bypasses, renewal context, hardening, and post-state bytes.
- Exact reserved-name/lockup datasets and renewal boundary evidence.
- Exact HSD `NameState` codec and name undo.
- Correctness-first exact Urkel roots and byte-for-byte canonical HSD
  inclusion/non-inclusion proof generation, decoding, and native verification.
- Root-checked immutable proof views rebuilt from sequence-consistent durable
  name-state snapshots and stable across later commits and state-engine restart.
- Canonical content-addressed nodes written atomically with authenticated state,
  path-local proofs that rehash loaded records, and restart/corruption evidence
  for both memory and RocksDB stores.
- Path-local immutable insert/replace/remove, exact HSD incremental-root parity,
  independent materialized rebuild checks, retained historical proofs, and
  read-your-writes multi-block undo coverage.
- Network-parameter interval root pins with connect/disconnect and startup
  validation, plus validated mark-and-sweep compaction over the current, undo,
  and pinned-root reachable union. Malformed pins and failed commits preserve
  every node.
- Opt-in height-gated startup scheduling and forced serialized maintenance with
  an atomic checksummed last-run checkpoint, API-v8 status, and unclean RocksDB
  reopen evidence.
- Exact HSD `pruneAfterHeight`/`keepBlocks` constants and opt-in atomic undo
  retirement, including startup catch-up, pruning-aware pinned-root compaction,
  deep-reorg rejection, checksummed checkpoints, and unclean RocksDB reopen.
- Correct Handshake pre-state header-root timing and durable resulting-root
  binding.
- Exact HSD airdrop key/proof codecs, hashes, Merkle/output/accounting checks,
  native RSA/P-256/Ed25519/GooSig verification, valid faucet and upstream
  production-root GooSig proofs, and atomic duplicate-position connect/undo;
  the active node composes the complete verifier from parent deployment state.
- Exact HSD Claim envelope encoding and blob-only hashes plus checksummed
  ownership TXT payloads for all four networks.
- Exact compression-free ownership-proof DNS codecs and HSD sanity/time/weak
  behavior, ICANN-rooted DS/RRSIG authentication through RSA, P-256/P-384,
  Ed25519, and Ed448, SHA-1/SHA-256/GOST94/SHA-384/SHA-512 DS digests,
  reserved allocation/output/commit/deflation accounting, and atomic
  contextual claimed-name connect/disconnect at the service boundary. All four
  upstream HSD ownership proofs replay under both SHA-256 and legacy GOST94
  historical anchors.
- Canonical mainnet block 62,517 is pinned with a checkpoint-linked header
  context and two real CLAIM witnesses (`jinronghd` and `namecheap`). Native
  tests validate the complete raw body and both proofs, reject median-time-past
  in place of HSD's exact parent-header time, and connect/disconnect the exact
  claim coinbase through the proof-capable state service.
- Seven canonical initial-claim blocks at heights 39,086-39,101 and the full
  ten-claim replacement block 76,722 are pinned with checkpoint-linked parent
  contexts. Native replay preserves predecessor values, advances commit height
  1 to 2, applies post-deflation replacement accounting, and reverses all state.
- A complete three-generation `mylinksfree` lineage at heights 55,798,
  177,097, and 178,235 advances commit height 1→2→3, preserves exact
  post-deflation value and claim-frequency rules, and disconnects through both
  predecessors. The final accepted claim (`vcel`, height 210,237), canonical
  claim-period header/coinbase at 210,240, and a boundary mutation pin HSD's
  terminal accept/reject behavior through native consensus and state services.

### Network and synchronization foundation

- Exact bounded HNS framing and sync packet behavior with pinned HSD wire
  fixtures.
- Live inbound/outbound plaintext peers with handshake, service, self-connect,
  timeout, ping/pong, and priority-queue controls.
- Bounded peer manager, scoring, disconnect, snapshots, and reconnect backoff.
- Headers-first synchronization with 2,000-header atomic protocol batches plus
  canonical-header BIP9/script-policy derivation and bounded
  pending/inflight/per-peer body requests, retry, timeout, and reassignment.
- Bounded orphan retention only for statelessly valid bodies with known header
  context; unknown-context bodies are dropped after requesting headers.
- Blocking validation workers with ordered result delivery.
- Durable non-active body retention, contiguous-body recovery, restart
  checkpointing, and bounded read-only serving.
- Durable failed-body and failed-child propagation with atomic best-header
  fallback and restart recovery. Uncommitted body/header mismatches are retried,
  and validator-worker failure is not attributed to a peer or branch.
- Explicitly acknowledged bounded active-state connection through the single
  contextual state/reorg pipeline, with restart resumption, exact failed-root
  attribution, local-fault separation, shutdown-responsive eight-block direct
  slices, and full-configured-bound atomic reorganizations.
- API-v8 post-tip root diagnostics and a pinned-source external HSD comparator
  with coherent-tip retries, provisional/confirmed root labels, and bounded
  checksummed restart/reorganization evidence.
- Non-authoritative diagnostics; network data cannot grant mining authority.

### Mempool, template, and publication foundation

- Explicit hard bounds for accepted transactions, bytes, orphans, dependency
  graphs, package members, template variants, and pending publication intents.
- Immutable mempool generations, parent/child/spent-outpoint indexes,
  deterministic dependency-ordered packages, and bounded orphan promotion.
- Admission stages for syntax, finality, conflicts, coin resolution, maturity,
  relative locks, native resolved-coin sigop accounting and the HSD 16,000
  transaction-policy ceiling, input authorization, covenant linkage,
  contextual checks, value, fees, and resource limits.
- Explicit verifier-completeness gates; compatibility and peer transaction
  entrypoints fail closed until complete contextual consensus is composed.
- Deterministic ancestor-inclusive future templates with actual HNS block
  weight kept separate from HSD sigop-adjusted policy size, plus sigops, OPEN,
  UPDATE, RENEW, transaction-count, and exclusive-name limits.
- HSD-derived subsidy boundaries, deterministic coinbase bytes, transaction
  sigop policy constants, and exact policy-size vectors.
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

- Full-mainnet replay and independent invalid-corpus qualification of the now
  composed checkpoint fast path.
- Independently generated script fuzz/invalid corpora beyond the complete
  pinned HSD upstream suite.
- Independently sourced live DNSSEC-proof evidence for historical-policy
  qualification, remaining historical datasets, and complete replay beyond the
  pinned initial, multi-generation, and terminal claim histories. Mainnet no
  longer accepts new claims after height 210,240. Claim DNSSEC algorithms and
  DS digests, the full upstream historical proof corpus, deflation accounting,
  complete airdrop-key verification, active-node deployment composition, and
  airdrop duplicate/conjured-value accounting are implemented.
- Complete contextual covenant/name behavior across mainnet history; all
  non-claim families now have deterministic HSD differential coverage.
- Deployment-scale Urkel compaction performance/priority qualification and
  RocksDB mid-commit process-crash/fault injection.

### Chain and network qualification

- Full-mainnet replay, sustained fork, and pruning qualification of the bounded
  restartable active-state connector.
- Failed-branch pruning/retention policy, historical reorganizations, and
  RocksDB fault evidence.
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
- Sustained live HSD shadow agreement evidence through restarts, partitions,
  tip races, and real reorganizations; the comparison mechanism exists, but
  the production-duration campaign does not.
- Measured P50/P95/P99/maximum tip-to-job, candidate-validation, local-connect,
  and first-peer-acceptance latency.
- Reproducible builds, external review, fuzzing, and published latency/recovery
  evidence.

## Explicitly excluded product work

Wallets, seed/key management, desktop/mobile UI, domain management, DNS
resolution/serving, explorer indexes, and broad convenience RPC compatibility
remain outside `hsrd`. Consensus parsing of name/resource bytes remains only
where block validity requires it.
