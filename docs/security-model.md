# Security model

`hsrd` verifies consensus locally. Peers, imported snapshots, control clients,
MeshMine inputs, caches, fixtures, and synchronization checkpoints are
untrusted until an explicit validation stage accepts their use. The source
consensus-readiness matrix is complete, but authority is still a runtime
capability: only the explicit synchronized mainnet canary with a coherent
durable authoritative tip may receive it. The pinned `hsd` revision remains an
offline comparison oracle, not a runtime or production authority. API-v13's
base snapshot initializes `release_stage: "pre-authority"`; live native RPC
replaces it with a configuration-specific diagnostic stage that does not grant
authority.

Local durable state has a narrower production trust boundary. The data root and
its external page/segment files must remain in exclusive custody: only the
dedicated `hsrd` service identity and trusted, audited offline maintenance may
write them. OS, root, storage-administrator, backup-restore, and hypervisor
principals that can modify those bytes are part of the trusted computing base.
The node decodes and revalidates durable records where described below, but it
does not authenticate the complete logical database against a hostile local
writer.

The clean-shutdown marker and `startup-audit/v1` record use unkeyed checksums as
crash-recovery and cache-coherency evidence. RocksDB checksums, atomic batches,
synced archive frames, and manifest reconciliation are designed to expose torn,
partial, or random physical corruption and ambiguous writes. None is a MAC or
signature from a separately protected authority. In particular, the startup
audit does not commit to every UTXO key/value pair or every logical database
record. A writer with offline database access can inject a well-formed UTXO or
coordinately alter records and preserve or recompute the unkeyed markers; a
successful startup audit therefore does not prove state provenance.

Arbitrary offline logical database mutation is outside the production threat
model. Suspected loss of custody requires stopping the node, withholding mining
authority, preserving the affected store as evidence, and rebuilding consensus
state through a full trusted replay. A separately protected keyed or otherwise
trusted commitment covering the complete logical state could provide another
recovery basis only after that mechanism is implemented and qualified; the
current implementation has no such commitment.

## Current trust boundary

The current foundation verifies or records evidence for:

- network/genesis/schema/storage-profile identity;
- durable name-tree-root binding to materialized name state;
- proof-of-work, unsigned 256-bit chainwork, difficulty transitions, and
  timestamp bounds;
- bounded primitive encoding and block syntax/commitments;
- ordinary subsidy-plus-fee limits, absolute and relative locks, UTXO/undo
  invariants, and value conservation;
- HSD-compatible signature hashes and a native pinned secp256k1 verification
  backend;
- bounded witness/script execution for the implemented operation set;
- exact non-coinbase covenant linkage;
- contextual non-claim name transitions plus authenticated CLAIM
  connect/disconnect at an explicit proof-capable service boundary;
- exact pinned-HSD contextual results and accepted post-state bytes for all
  non-claim transition families, including historical shortcuts and hardening;
- parent-derived deployment-state caches composed into active node name,
  DNSSEC-claim, and faucet checks with restart/reorg validation;
- a single branch-evidenced HSD historical validation plan carried from body
  import through state connection, retaining commitments, name limits,
  deployment/finality/height, proof-sanity/allocation, UTXO, and mutating-name
  checks while making only HSD's coordinated checkpoint assumptions;
- ICANN-rooted DNSSEC claim verification and HSD claim output/commit/deflation
  accounting;
- checkpoint-linked block 62,517 claim evidence validating two real mainnet
  proofs and their state transition against HSD's exact parent-header-time
  rule;
- checkpoint-linked predecessor/replacement evidence spanning seven initial
  coinbases and all ten replacements in block 76,722, including retained-value,
  commit-advance, and reverse-disconnect behavior;
- correctness-first exact Urkel roots and canonical bounded HSD
  inclusion/non-inclusion proof bytes with native verification;
- root-checked immutable proof views rebuilt from sequence-consistent durable
  name-state snapshots, with corruption rejected before proof exposure;
- content-addressed authenticated nodes committed with state, path-local proof
  reads that rehash each record, bound-root/touched-path validation at
  transition boundaries, bounded clean-start root/reorganization-horizon
  validation, and full reachable-tree validation after unclean startup;
- immutable path-local mutation that verifies every touched record, retains old
  roots, and uses the materialized O(N) rebuild as an independent startup and
  differential-test oracle;
- checksummed network-interval root pins bound to active block/undo history,
  plus startup validation of every pinned reachable tree;
- explicit mark-and-sweep compaction that validates the complete retained-root
  union before staging deletions and commits the deletion batch atomically;
- opt-in height-gated startup scheduling under the mutable node coordinator,
  with a checksummed last-run checkpoint in the deletion batch and unclean
  RocksDB reopen validation;
- atomic single- and multi-block database mutations;
- sequence-consistent snapshots;
- bounded HNS framing, peer lifecycle, header synchronization, body scheduling,
  stateless validation, non-active body retention, and restart checkpoints;
- bounded in-memory mempool/orphan storage, immutable generations, dependency
  packages, deterministic future templates, and HSD-derived coinbase behavior;
- versioned checksummed solved-block publication intents, local candidate
  admission before fan-out, and parallel reserved critical publication queues;
- granular validation, authority, readiness, parity, peer, synchronization, and
  mining-engine diagnostics.

The default input verifier rejects non-coinbase spends. Native script
verification must be selected explicitly. Successful configured script/name
checks do not imply global mainnet authority; historical and live evidence
remain separate assurance work.

Shadow-network input is non-authoritative. Downloaded bodies remain non-active
in observe-only mode. Native active-state mode may connect them to UTXO/name
state through bounded atomic consensus batches and may receive a mining
authority capability only when every canary, readiness, synchronization, and
durable-tip gate passes. Candidate-derived contextual failures
may poison the exact durable branch; local store/tree/backend/chain-view faults
instead stop synchronization without changing branch validity. The mining
engine may build diagnostic future templates from a durable active snapshot,
and explicitly enabled ordinary peer transaction relay admits only through a
complete native script verifier and one immutable active UTXO/deployment/name
snapshot. Airdrop relay separately requires native proof verification,
next-block deployment flags, and the immutable durable allocation field. Relay
does not grant authority. Solved-block staging, connection, and
publication require the same private authority capability as the existing
authoritative mining boundary.

Current API-v13 retains the next-header interval-committed root introduced in
API-v10 for external qualification. `compare-hsrd-hsd-shadow.py` reads that
material and a pinned
HSD node, but its observations and evidence checkpoint never enter the store,
fork-choice logic, validation services, mining event hub, or authority permit.
A match is evidence for an observed boundary, not a consensus input. Remote
diagnostic reads require an explicit acknowledgement, and HSD/hsrd tip changes
during a probe are retried rather than classified as divergence.

The following remain hardening or assurance work; none is represented as a
false source-readiness bit:

- broader full-history replay beyond the qualified stopped state and retained
  rollback horizon;
- independent script fuzz/invalid evidence beyond the complete pinned HSD
  upstream corpus;
- current/live claim-proof evidence and complete historical claim replay beyond
  the pinned initial/replacement histories;
- complete contextual name consensus over mainnet historical cases beyond the
  deterministic all-family transition corpus;
- deployment-scale compaction performance/priority qualification and RocksDB
  mid-commit process-crash/fault injection;
- long-duration full-history active-state IBD, pruning, and sustained
  alternate-chain/reorganization campaigns;
- long-lived subthreshold peer reputation and sustained adversarial Brontide
  qualification;
- production template qualification, continuously supervised publication
  retry, and measured publication latency;
- sustained native multi-peer qualification and offline differential audits.

## Authority policy

- `disabled`: no mining authority.
- `shadow`: legacy diagnostic mode; staged state never grants authority.
- `hsd-verified`: reserved until the independent HSD verifier boundary exists;
  configuration currently fails closed.
- `native`: the default mainnet synchronization mode; mining remains fail
  closed until every readiness bit and the durable tip's authoritative status
  pass. Those readiness bits are complete in current source, but the live-tip
  requirements are evaluated continuously.
- `native-experimental`: requires the `experimental-authority` Cargo feature,
  explicit incomplete-consensus acknowledgement, and regtest/simnet.

Live networking is accepted in `disabled`, `shadow`, or `native` mode.
The mining engine cannot manufacture the private authority capability through its
configuration, template cache, mempool, diagnostics, or durable intent queue.

A private `MiningAuthorityPermit` is required by authoritative mining
subscriptions and candidate admission. `disabled`, `shadow`, observe-only, and
incomplete native states do not receive it. The explicit native mainnet canary
issues the same capability only after complete readiness and an authoritative
durable tip.

Production authority additionally requires a reviewed custody record for the
exact deployment. It identifies the numeric owner/group, modes and ACLs of the
data root and every external page/segment path, the parent-directory and mount
controls, every privileged principal able to write them, and the exact trusted
maintenance binaries and window. Shared or unaccounted write access blocks
release. Any custody breach invalidates evidence derived from that store; a
clean marker or matching startup checkpoint cannot restore authority.

## Network-input policy

- Frame magic and payload length are checked before allocation.
- Packet collections and all runtime queues have explicit limits.
- Socket tasks decode/encode and emit events; they do not validate consensus or
  write the database.
- CPU-heavy block-body checks run outside async socket workers.
- One process-local unpredictable nonce is shared across local sessions so a
  connection to the node's own listener is rejected as self-connection.
- Duplicate socket addresses and over-capacity registrations fail under the
  peer-manager registration lock.
- Invalid header batches consume the outstanding request and disconnect the
  sender at the current score threshold. The current atomic protocol batch is
  rejected in full; earlier complete batches remain tracked by the scheduler.
- A body without known header context is dropped after requesting headers; it
  is not retained as an unvalidated orphan.
- A body with known header context but unavailable parent body is retained only
  after stateless validation and within count/byte bounds.
- Discovered peer addresses and their attempt/success history use a bounded,
  checksummed, network-bound cache; it is selection input, never consensus
  input. Score 100 creates a bounded, checksummed, network-bound 24-hour IP-ban
  record and is enforced before inbound or outbound handshake work; neither
  addresses nor bans can authorize chain state. Subthreshold connection scores,
  live reconnect timers, inflight requests, and orphan bodies remain
  process-local and are not trusted after restart.
- The synchronization checkpoint is checksummed and reconciled with durable
  chain/body state rather than trusted as consensus.
- A block `notfound` is accepted only from its assigned request peer and is
  tracked as bounded per-hash availability evidence. It cannot mark a block
  invalid, blame the peer, consume the validation retry budget, or cancel a
  request owned by another peer.
- Header-derived deployment diagnostics walk only the validated canonical
  ancestry and bind any historical-script assumption to the exact final
  configured checkpoint; they do not confer body, state, or mining authority.
- Denuo registry agreement and HIP-76 role/session state are connection-local
  experimental transport capabilities. Requester operation can be disabled;
  provider advertisement requires explicit opt-in and a ready backend. Neither
  DNS relay negotiation nor received DNS bytes grant consensus or mining
  authority.

## Mining-engine and publication policy

- Every mempool, orphan, package, template, and publication collection has a
  configured bound and a compiled hard ceiling.
- The compatibility mempool entrypoint and peer relay reject until complete
  contextual input and transaction verifiers are composed.
- A template consumes one immutable durable chain snapshot and one immutable
  mempool snapshot and records both generations.
- Cached activation rechecks generation, parent, and next authenticated tree
  root; cache entries are derivative state and are cleared on relevant chain or
  mempool transitions.
- A publication intent is durable recovery evidence, not proof that a block is
  valid or permission to send it.
- Solved-block network fan-out occurs only after the ordinary local candidate
  admission path accepts the block as active. A returned local error is not
  classified as pre-commit failure until the canonical active record is
  re-read.
- Restart retry rechecks that the intent's block is a locally accepted active
  record before any peer writer receives it for socket transmission.
- A zero-peer fan-out keeps the intent pending; it does not roll back or
  misreport the successful local chain connection.
- Ordinary block and transaction serving cannot consume the reserved critical
  publication lane.

## Name-tree invariants

- The durable root must equal a rebuild from all non-null materialized
  `NameState` records.
- A block header must equal the inherited pre-state root.
- The current block's transitions produce the next root.
- Connect and disconnect record previous/resulting roots in undo.
- Disconnect must begin at the undo's resulting root and end at its previous
  root.
- Name-state and root changes share the same atomic batch.
- Null states are deleted, never authenticated as values.

## Fixture and oracle policy

- HSD fixtures are pinned to an exact 40-character revision.
- Every manifest entry has a BLAKE2b-256 digest.
- Loaders reject missing, altered, duplicate, or path-escaping entries.
- Fixture chainwork overrides compile only for tests.
- Generators support reproducibility checks and fail on drift.

Fixtures are evidence, not authority.

## Failure policy

- Unsupported consensus data fails closed.
- Malformed parser input returns bounded errors rather than panicking.
- Missing signature verification rejects spends.
- Claim/airdrop issuance rejects unless its implemented native proof validation,
  allocation, deployment, and duplicate-prevention checks pass.
- Missing deployment-derived name flags reject contextual name transitions.
- A failed staged reorganization commits no durable operation.
- Root, schema, network, genesis, or profile mismatch requires explicit operator
  action/reindex.
- Suspected unauthorized local database access revokes production authority and
  requires a full trusted replay or a qualified separately protected commitment;
  a clean startup or successful checksum verification is insufficient.
- Unexpected shadow-network supervisor/channel/task failure leaves the store marked
  unclean.
- A corrupt or over-capacity publication queue fails diagnostics/recovery rather
  than silently dropping solved-block evidence.
- Diagnostic APIs do not label staged or shadow state as authoritative.
- Trusted snapshot mode remains disabled until explicitly implemented.

## Review checklist

- Parser lengths and collection counts are bounded and fuzzed.
- P2P payloads reject wrong magic and oversized messages.
- Async socket tasks do not perform consensus validation or database writes.
- Raw body presence never implies full block validity.
- Scripts, covenant linkage, contextual covenants, claims/airdrops, name state,
  and root validity remain separately observable.
- Authorization and covenant/name checks finish before spend staging.
- Reorganization undo and replacement state share one batch.
- Root metadata and materialized name state are checked before state mutation.
- Production data-root custody, owners, permissions, ACLs, mounts, privileged
  writers, and offline-maintenance access are reviewed and retained as release
  evidence.
- Startup and RocksDB checksums are treated as crash/corruption evidence, not
  hostile-writer authentication or proof of complete UTXO provenance.
- Peer inventories, orphans, queues, templates, publication attempts, and
  control requests have explicit bounds.
- Shadow-network input cannot issue or bypass a mining authority permit.
- Template, mempool, intent, retry, and fan-out paths cannot issue or
  bypass a mining authority permit.
- Local solved-block admission precedes every peer publication attempt.
- No wallet, key-management, DNS, domain-action, or SQLite consensus surface is
  linked into the node.
