# Architecture

`hsrd` is a purpose-built HNS mining full node for MeshMine. Its architecture
optimizes tail latency and isolation while preserving the requirement for exact
Handshake consensus behavior.

```text
hns-node
  -> bounded diagnostics/control and supervision
  -> hns-mining native events, snapshots, jobs, candidate publication
  -> hns-sync / hns-p2p / hns-mempool
  -> hns-chain / hns-state / hns-consensus / hns-urkel
  -> hns-store
  -> hns-primitives
```

The native mining interface is primary. HTTP/JSON is never used between
MeshMine and the node.

## Execution lanes

1. solved-block validation, durable publication intent, and reserved relay;
2. committed tip notification and clean ASIC-job activation;
3. ordinary ASIC-share support reads;
4. live P2P validation and ordered state commit;
5. mempool reconciliation and replacement-template refinement;
6. historical synchronization, diagnostics, metrics, and compaction.

Lower lanes may not consume every queue slot, CPU worker, disk permit, peer send
permit, or runtime thread required by a higher lane. Consensus state is
committed in order; stateless parsing, hashing, and verification may be
parallelized against immutable inputs.

## Validation stages

Durable `BlockStatus` uses independent stages rather than broad validity labels:

```text
header context
checkpoint
activation/deployment state
body presence
body-stage satisfaction and commitments
absolute finality
relative sequence locks
scripts/witness authorization
covenant input/output linkage
contextual covenant/name rules
claims and airdrops
UTXO connection
name-state connection
Urkel tree-root agreement
undo durability
active-chain membership
```

`covenant_links_valid` means only the deterministic non-coinbase linkage pass
has succeeded. It must never be interpreted as contextual name-state validity.
The authoritative mining snapshot requires every consensus and state stage;
the pre-authority staged snapshot is separate and diagnostic only.
For exact hardcoded-checkpoint ancestry, a durable stage may be satisfied by
HSD's historical assumption rather than local execution. Checkpoint status,
height/hash, and canonical header ancestry are the provenance; arbitrary or
partial historical plans are rejected.

## Staged chain events

- `CandidateTipSeen`: bounded header/parent evidence arrived; useful only to stop
  obviously obsolete work, never to authorize a new job.
- `BlockSyntaxValidated`: the bounded full body stage, or the retained
  historical commitment/name-limit subset, passed preflight. It does not claim
  scripts, covenants, name state, or complete consensus.
- `TipStaged`: the current pre-authority state subset committed durably, but the
  generation is excluded from the authoritative mining snapshot channel.
- `TipCommitted`: every release-gated consensus and state condition passed; this
  is the sole event that can authorize a native mining parent.
- `TipCleared`: the durable chain has no connected tip.
- `ReorgStarted`: consumers enter a no-activation state while a replacement
  branch is staged.
- `ReorgAborted`: the staged operation failed and no durable reorganization was
  committed.
- `MempoolReconciled`: a later replacement template may include post-connect
  mempool changes without delaying the clean job.

Events carry immutable summaries and monotonically ordered local generations.
Restart reconstructs the last durable generation before event publication.

## Atomic chain mutation

Single-block connects/disconnects and multi-block reorganizations use one store
batch. A reorganization is evaluated against one immutable base snapshot plus a
read-your-writes overlay:

```text
immutable base snapshot
       +
staged disconnect/connect overlay
       -> validate complete replacement branch
       -> verify final best-work tip
       -> commit one underlying database batch
       -> refresh indexes
       -> publish one final generation
```

No intermediate disconnect or connect is visible in durable state. On any
error, the underlying batch is dropped and the original chain remains intact.
Database atomicity, the qualified stopped state, and the complete retained
rollback horizon satisfy the source readiness gate. Broader historical and
long-running reorganization campaigns remain assurance work.

## State and storage

`hns-state` is the only UTXO/name-state writer. It resolves and authorizes all
transaction inputs before staging spends, verifies contextual covenant linkage,
then stages value changes and undo data. Claims, airdrops, and name-state
transitions use their implemented native validators and remain fail closed on
missing proof, deployment, allocation, or authenticated-state context.

Memory-store snapshots are cloned immutable maps. RocksDB snapshots retain a
sequence-consistent `rocksdb::Snapshot`, so related reads cannot cross a commit
boundary. Compaction and pruning remain bounded background work without access
to the mining lane's reserved storage budget.

## Noncustodial wallet boundary

The optional wallet profile adds only derivative public indexes. The typed
backend exposes active-height hashes and tree-root-bearing tips, combines
transaction status/inclusion/payload with one chain epoch and mempool
instance/generation, and
bundles current versus interval-root-authenticated name state, proof, and owner
evidence in one snapshot. Confirmed history/UTXO restoration uses a global
script-set- and chain-epoch-bound cursor so a reorganization cannot tear a
multi-page scan. Collection admission and a 256-script-prefix-page work bound
permit resumable empty progress without monopolizing the point-read lane.
Mempool continuations additionally bind a fallibly initialized, random,
nonzero, process-local instance nonce and the durable chain epoch, so neither a
restart nor a confirmed-chain transition can reuse generation numbers as
cursor authority. Mempool pages carry the complete chain tip and exact
admission time. Multi-script result positions refer to the sorted
request, so the wallet adapter owns the reverse map to derivation order.

Before any script-set read, the backend can capture the durable chain epoch and
complete tip together in one immutable point read. This script-free snapshot,
followed by a height-zero hash read under the same epoch, lets an external wallet
validate its selected network without first disclosing derived script
identities. The older tip-only read remains an unchanged compatibility surface.

Active-height hash lookup and ordered, bounded outpoint-spend batches carry one
immutable chain epoch/tip binding. Confirmed history carries optional canonical
header time. Transaction position is exact when retained block bytes allow the
node to enumerate it and explicitly unavailable after pruning; zero is never a
sentinel. This avoids extending the durable transaction-index schema inside a
transport change.

The native-sync process exposes that backend through authenticated wallet RPC
v1 at `POST /api/v1/wallet`. The transport is a projection layer, not a second
chain implementation: native runtime reads, canonical writer admission, index
page bounds, and peer fanout remain behind the existing typed backend. It is
constructed only for a canonical active-state native runtime, an explicitly
authenticated listener, and the durable complete wallet profile. Headers-only,
observe-only, diagnostic-only, narrower-profile, or unauthenticated listeners
do not install the route. The listener's body, concurrency, and
timeout middleware remains outside the handler, and the
backend's separate point/collection admission remains inside it.

The transaction-bound fee-quote read is also a projection of canonical node
policy. One stable active-state snapshot plus one immutable mempool generation
resolve every input coin and supply the bounded rate sample. Node internals then
derive transaction weight, input-aware sigops, HSD sigop-adjusted policy virtual
bytes, the minimum fee in atomic units per 1,000 policy virtual bytes, and the
actual node-resolved fee/shortfall comparison. The
request must bind the exact chain epoch and mempool instance/generation and can
supply only canonical raw transaction bytes, never coins or derived policy
values. The result is exact for those serialized witness bytes only, so the
wallet must requote the final signed artifact before broadcast; this read does
not sign, relay, or promise admission.

TRANSFER/FINALIZE preparation uses a separate versioned name-action read over
that same stable chain/mempool capture. It binds the configured network,
genesis, and `hns-consensus/name-policy-v1` identity; verifies the current owner
against its active UTXO; selects the HSD renewal block from the active chain;
derives tip-plus-one transfer maturity; and performs an O(log N) immutable
mempool lookup for an exact owner spender. The response has a fixed nine-reason
eligibility bound. It supplies public evidence only: the wallet still owns
approval, signing, durable workflow state, final fee requote, broadcast, and
restart/reorg reconciliation.

The frozen v1 response retains the confirmed owner transaction. Additive
`name_action_context_v2` preserves the same binding and policy fields but uses
the current NameState plus byte-exact active UTXO Coin and canonical
transaction-index inclusion instead. It never reads a raw block, so its
transaction position is explicitly unavailable and a valid pruned owner does
not fail with `PayloadPruned`. This trusted-node projection is neither a
Coin-to-txid proof nor wallet-ownership, signing, relay, or value authority.

Wire continuations encode typed cursors as bounded behaviorally opaque tokens,
not secrets or authenticated capabilities. Binary identities and payloads are
canonical hexadecimal strings, so an independent wallet process need not link
this workspace. Wire pages/scans are stricter than internal index bounds, and
each JSON result is encoded and measured against an 8 MiB ceiling before
publication. The response preserves explicit
chain epoch/tip and mempool instance nonce/generation boundaries. Name current
state and proof-root state, plus both owner views, remain separate. Complete
canonical NameState values are transported as explicit encoded hex; projected
resource data remains a non-authoritative hint. Name data,
tracked-contract descriptors, and revealed-preimage settlement semantics stay
opaque pending published canonical protocol dependencies; the transport never
becomes their semantic authority.

Public Shakedex/HTLC registrations and confirmed events share the canonical
block/reorg batch, but never participate in consensus validity. Connect staging
reads the authenticated pre-current-block UTXO view before the state connector
mutates any live/reorg overlay, plus a complete same-block output map. An
accepted spend outside the pinned wallet profile becomes `Unrecognized`; it
cannot make the optional index reject a block. Shakedex fulfillment and recovery
are the seller-signed TRANSFER shapes with exact `0x84` and `0x83` hash types;
an invented direct FINALIZE shape is not recognized. Bounded address candidate
sets preserve descriptors that share a script while matching their exact output
terms; key uniqueness is not a protocol assumption. Revealed preimages remain
raw only in internal durable events; public debug/serde surfaces redact them and
raw access is explicit.

New registrations carry a checksummed monotonic confirmation record and a
retained lifecycle revision that changes on serialized exact re-registration.
The first matching canonical funding marks it confirmed
atomically and reorg disconnects never clear that fact. The typed backend may
retire only exact never-confirmed registrations after binding the caller's
lifecycle revision, requiring zero retained transaction orphans, scanning the
current immutable accepted ordinary/airdrop pool, and exact canonical-writer
compare-and-commit. This reclaims active global and per-address slots without
removing any descriptor needed by disconnect. Legacy-unknown and ever-confirmed
registrations fail closed on that path. The distinct completed transition
requires a fully paired, fully spent bounded event history below the durable
undo-pruned frontier and the same exact chain/tip/mempool authority. It replaces
the live descriptor with an immutable, separately bounded tombstone containing
the exact public identity, terminal and revealed-preimage evidence, min/max
heights, pruning checkpoint, and commitment over all ordered deleted rows.
Startup rechecks the current frontier and canonical proof hashes; the retired
ID can never be reused. Active slots are reclaimed, but the finite tombstone
quota and explicit decision to leave any later matching output untracked keep
untrusted registration a production-availability blocker.
The caller must separately and durably abandon prior broadcasts because an
evicted transaction can be rebroadcast after the current-mempool proof.
Local profile duplication and frozen vectors are not protocol authority.
Release qualification also requires a published and pinned canonical
`hns-swap` commit and a qualified adapter. Wallet secrets, signing, workflow
decisions, and unrevealed preimages remain outside the node.

## Compatibility boundary

`hns-consensus` is deterministic, synchronous, and independent of networking,
storage, RPC, MeshMine, and wall clocks. `hsd`, historical mainnet, `hnsd`, and
Urkel/liburkel are comparison oracles, not runtime architectural dependencies.
Ordinary VERSION/VERACK precedes the connection-local Denuo Experimental V1
registry exchange; typed HIP-76 `f0`/`f1` traffic is admitted only after that
agreement and under separate requester/provider role policy. These extensions
do not enter consensus or authority. The workspace now pins exact crates.io
`hns-rs` `=0.3.0` artifacts from the published, non-yanked,
provenance-verified 19-package cohort, while the active transport deliberately
remains Denuo V1.
Marketplace roles stay locally bounded and wire-disabled until Denuo V2
transport/admission and a typed adapter are joined and the result is qualified;
a sibling path is
not an acceptable dependency substitute.

The authority and production-hardening boundary is governed by
[`mining-node-scope.md`](mining-node-scope.md).
