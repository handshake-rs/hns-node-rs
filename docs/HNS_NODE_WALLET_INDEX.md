# Handshake wallet indexes and typed backend

`hsrd` can act as a noncustodial first-party chain backend for a separate
wallet. It never stores wallet seeds or private keys and it cannot construct or
sign wallet transactions. The wallet submits already signed Handshake
transactions to the same contextual mempool path used for peer transactions.

## Profiles

All wallet indexes are optional and are not consensus or mining inputs.

| Option | Durable data | Implied data |
| --- | --- | --- |
| `--transaction-index` | active-chain `txid -> block/height/offset` | none |
| `--script-history-index` | confirmed transaction history by canonical output-address script | none |
| `--spender-index` | active-chain `outpoint -> spending tx/input/block` | none |
| `--wallet-index` | script UTXOs plus registered Shakedex/HTLC funding and event state | transaction, script-history, and spender indexes |

`--wallet-index` is the recommended first-party wallet profile. A narrower
service may enable the independent flags to control disk amplification.
`WalletIndexProfile` is also available to embedded callers.

The script identity is BLAKE2b-256 over the canonical Handshake output address
encoding. This is an exact transaction-script descriptor, not a human address
string and not an explorer heuristic.

## Atomicity and reorganization behavior

`hns-wallet-index` stages its writes in the same store batch used for active
UTXO/name-state connection. Connect staging runs before that block's state
connector mutates a live or reorganization overlay, so every derivative input
lookup sees the authenticated state immediately before the current block:

1. resolve every non-coinbase input against the immutable pre-connect UTXO
   snapshot or the complete block-local map of spendable outputs;
2. add consolidated received/spent history rows;
3. add spender mappings and script UTXOs;
4. run the authoritative state connector, which still enforces transaction
   ordering and every consensus rule; and
5. commit the shared batch atomically with canonical height, best block, UTXO,
   name state, undo, and transaction-index changes.

Any authoritative connection failure discards the derivative writes with the
batch. The full block-local map prevents an ordinary same-block child from
making the optional tracker reject an otherwise valid block; it does not make
the tracker an admission authority.

Disconnect uses the already validated `BlockUndo`. It deletes rows created by
the disconnected block, removes its spender mappings, and restores prior
script UTXOs from `spent_coins` in that same batch. Multi-block activation and
reorganization use the existing staging overlay, so later blocks see the
earlier staged UTXO/index state and the complete reorg has one publication
boundary. Unit coverage exercises connect, disconnect, reconnect, and
within-block spends.

Registered contract funding and spend events use the same publication boundary.
A disconnect removes events from the disconnected block and restores the exact
prior funding record carried by the checksummed spend event. Funding created and
spent within one block is restored first and then removed, producing the exact
pre-block state. Multi-block reorganizations use the staging overlay, so no
consumer can observe a half-reversed swap history.

## Startup profile checks and migrations

The checksummed `wallet-index-profile/v1` record in `snapshots` binds the data
directory to its built components. Startup fails closed when:

- a requested component was not built for existing active-chain history;
- wallet-index keys exist without a profile record;
- a checksummed profile is corrupt;
- `--wallet-index` would implicitly enable a transaction index after unindexed
  history already exists.

Disabling a component is allowed and stops future writes. Its old keys are not
silently treated as current. Re-enabling it after the chain advances fails and
requires an offline reindex. This prevents a partially indexed history from
appearing complete.

There is no in-place backfill during normal startup. For an existing data
directory, use one of these explicit procedures:

1. create a new data directory with the final profile and resynchronize; or
2. use a version-matched offline reindex tool once that tool is qualified for
   the exact `hsrd` storage schema.

Do not copy `tx_index` keys between data directories. The active-chain binding,
network identity, store schema, and profile record must move as one qualified
backup. At this revision no online profile migration or resume checkpoint is
claimed.

Contract tracking does not require an index-profile migration for a store that
already has `--wallet-index`: it adds versioned derivative keys under that
existing profile. Registrations are immutable and must be committed through
`register_tracked_contract` before funding is broadcast. Registration after a
funding confirmation does not pretend to backfill history; rescan/reindex or a
new funding outpoint is required.

## Disk and indexing cost

Every active transaction adds one history row for each distinct touched
script. Every spent input adds one fixed spender row. The complete wallet
profile additionally keeps one encoded `Coin` row for each active script UTXO.
Exact disk use therefore depends on transaction fan-out, address reuse,
covenant size, RocksDB compression, and reorganization history. Operators must
measure their own chain snapshot; no mainnet byte estimate has been qualified
for this revision.

Index construction is linear in connected transaction inputs and outputs, with
point reads for pre-block input coins. Intra-block outputs use a bounded
block-local map. Query pages are capped at 4,096 entries and 16 MiB of combined
key/value data.

The active public contract registry is capped at 16,384 entries. Each funding output
and input adds constant-count address/registration/funding point reads; block
connection never scans the registry. Contract funding and event pages share the
4,096-entry/16-MiB limits. Startup walks the bounded registration and address
topology, verifies the checksummed count and every reverse binding, and fails
closed on missing, duplicate, or malformed state.

Completed retirements use a separate immutable registry capped at 65,536
tombstones. One transition may consume at most 4,096 confirmed event rows. The
finite limits bound atomic write size and startup validation; they do not claim
lifetime-unbounded admission for an untrusted registrar.

Each new registration atomically creates a checksummed monotonic confirmation
record with a retained lifecycle revision that changes on exact re-registration
through the serialized node writer. The first matching confirmed funding marks it confirmed in the same
canonical block batch, including a funding spent later in that block; disconnect
never clears the mark. `retire_never_confirmed_tracked_contract` can therefore remove an
exact `NeverConfirmed` registration, its address membership, confirmation row, and
active count in one batch. It also requires the caller-observed lifecycle
revision and empty funding/event prefixes. The
typed backend requires the bound publication to retain no transaction orphans,
scans its exact immutable accepted ordinary transactions and airdrop outputs for
matching funding, and commits through the exact canonical-writer epoch. A
target-lifecycle, chain, or current-mempool change after the caller context
rejects the request; any canonical-writer mutation after the internal stable
proof rejects the compare-and-commit. This safely reclaims both the 16,384-entry
active cap and the 256-active-descriptors-per-address cap for mistaken or
abandoned registrations.

The mempool proof establishes only that the currently bound accepted ordinary
and airdrop generation has no matching funding and retains no transaction
orphans. It cannot prove that an earlier evicted transaction was never broadcast
or will never be rebroadcast. Calling retirement is therefore an explicit
abandonment decision: the wallet must durably cancel every related broadcast/
rebroadcast intent and accept that a later matching confirmation will not be
tracked under the removed descriptor.

Existing registrations that predate the monotonic record are marked
`LegacyUnknown` on an idempotent registration write and fail closed for this
retirement. A distinct typed completed-retirement operation handles only a
currently fully spent `Confirmed` lifecycle. It walks the complete bounded,
ordered event history, rejects duplicate funding outpoints, proves every
funding has one exact spend, requires no active funding, and refuses any event
above the durable undo-pruning checkpoint. The same chain/tip/mempool binding,
zero-orphan rule, accepted ordinary/airdrop funding scan, and exact writer
compare-and-commit apply. The caller must explicitly acknowledge permanent
descriptor abandonment.

The atomic mutation replaces the active registration/observation/history with
a checksummed tombstone containing the exact descriptor and lifecycle,
terminal spend, every revealed-preimage settlement binding, event count,
minimum/maximum height, undo-frontier height/hash, and SHA-256 commitment to
the exact ordered deleted event keys and stored bytes. It removes active
address membership and reclaims global/per-address capacity. Startup validates
the bounded tombstone topology, current frontier, and canonical checkpoint and
terminal hashes. Re-registration of that content-derived ID is permanently
rejected. A later consensus-valid matching output is deliberately untracked,
which is why abandonment is explicit and this operation is not automatic.
Manual key deletion remains corruption, not reclamation.

## Pruning

Wallet index rows are active-chain metadata and are not automatically deleted
by raw block/undo pruning. The only coupling is explicit completed retirement,
which may replace a fully spent contract history with its immutable tombstone
after the corresponding undo is already gone. Therefore:

- transaction inclusion, confirmation, script history, script UTXOs, spender
  lookup, name state, and current name proof continue to work;
- raw confirmed transaction and current owner-transaction retrieval require
  the containing raw block and return `PayloadPruned` when it is gone;
- the archive storage profile is required for guaranteed historical raw
  transaction and owner-transaction retrieval;
- reorganization remains limited by the node's retained undo horizon, exactly
  as active-state reorganization is.

Pruning never converts an unavailable payload into a fabricated transaction.

## Corruption handling

Profile records, history values, spender values, and wallet-index UTXO
envelopes carry versions and checksums. Every history, spender, and UTXO
checksum includes its full versioned database key. UTXO decoding additionally
reconstructs the key from the decoded outpoint and verifies that the encoded
address hashes to the requested script identity. Copying an otherwise valid
history, UTXO, or spender value to another key, or changing a checksummed value
in place, therefore fails closed. Keys are versioned and length checked. Input
resolution during block connection fails the whole atomic mutation if a
required coin is missing. The indexes are derivative: repair means rebuilding
them from canonical block/state data, never modifying consensus state to agree
with a secondary index.

Contract registrations, address bindings, active fundings, confirmed events,
active/retirement counts, and completed tombstones are independently versioned,
checksummed, and bound to their complete database keys. Descriptor identities are BLAKE2b-256 over the
fixed `hns-wallet-index/contract-id` domain, encoding version byte, contract
tag, fixed descriptor fields, and fixed-width big-endian integer fields. They
do not depend on JSON, serde, field order, or a node network. This intentional
network-independent identity names identical public script terms on every
Handshake network; funding and event records remain local to the store's
separately validated network/genesis binding.
Startup validates the complete bounded registry topology; point and page reads
also validate value/key identity. Script addresses map to a sorted, checksummed
candidate set rather than one descriptor: Shakedex name/value terms and HTLC
funding value are not all committed by the address. Up to 256 descriptors may
share one address under the 16,384-registration global cap. Connect,
disconnect, and mempool reads select a candidate only when the complete output
terms match; ambiguous matches fail as derivative-index corruption. This does
not impose unique key or address reuse as a protocol rule.

The typed backend preserves disabled-component and corruption classifications
instead of flattening them into a generic node error, so a wallet can stop the
affected read path and direct the operator to the explicit rebuild procedure.

## Typed backend

`NodeRuntime::wallet_backend` binds immutable reads, canonical writer admission,
and the live peer manager. It implements:

- `get_chain_tip`
- `get_block_hash`
- `get_block_hash_evidence`
- `get_raw_transaction`
- `get_transaction_evidence`
- `get_transaction_status`
- `get_transaction_inclusion`
- `get_script_history`
- `get_script_utxos`
- `get_confirmed_scripts_page`
- `get_spending_transaction`
- `get_outpoint_spending_evidence`
- `register_tracked_contract`
- `get_tracked_contract_retirement_context`
- `retire_never_confirmed_tracked_contract`
- `get_completed_tracked_contract_retirement_context`
- `retire_completed_tracked_contract`
- `get_completed_tracked_contract_retirement`
- `get_tracked_contract`
- `get_tracked_contract_fundings`
- `get_tracked_contract_events`
- `get_mempool_script_activity`
- `get_mempool_scripts_activity`
- `get_mempool_tracked_contract_activity`
- `broadcast_transaction`
- `estimate_fee_rate`
- `get_name_state`
- `get_name_proof`
- `get_name_evidence`
- `get_name_action_context`
- `get_name_owner_transaction`

`WalletChainTip` contains the active hash, height, HSD-compatible
median-time-past computed over the tip and up to ten ancestors, and the exact
authenticated name-tree root used for current persisted proofs.
`get_transaction_evidence`
captures status, inclusion, retained-or-pruned payload state, active tip,
durable chain epoch, and immutable mempool instance/generation together, then rejects
the result if publication changes during the read. The compatibility status,
inclusion, and raw-transaction calls are projections of that combined read;
wallet adapters should consume the combined result when several fields must
agree across a reorganization.

Block-hash evidence and ordered outpoint-spend evidence return the durable
chain epoch and complete tip from the same immutable snapshot. The spending
batch contains exactly one result per requested outpoint in request order and
is capped at 4,096 entries internally (256 on wallet RPC). Confirmed inclusion
contains an exact optional transaction position: retained block bytes make the
position derivable, while pruned legacy transaction-index rows retain valid
inclusion without an ordinal. No layer substitutes zero.

`get_name_evidence` returns one durable chain epoch containing the active tip,
current NameState, interval-root-authenticated NameState, proof, and both
corresponding owner transactions. Pending interval changes can make the
current and proof states differ; the API labels both instead of implying that
the persisted proof authenticates pending state. Owner output and transaction
inclusion are resolved in the same store snapshot. `get_name_proof` also
returns its atomically captured tip.

`get_name_action_context` is the candidate-specific source for TRANSFER and
FINALIZE preparation. It requires the caller's exact chain epoch and mempool
instance/generation, then captures the selected network/genesis and stable
`hns-consensus/name-policy-v1` identity, tip-plus-one candidate height, canonical
current state, confirmed owner transaction, matching active UTXO, transfer
lockup/maturity, and HSD-selected active-chain renewal height/hash together. The
immutable mempool snapshot carries a persistent owner-outpoint spender index,
so the exact concurrent spender is an O(log N) lookup rather than a pool scan.
Eligibility has a fixed maximum of nine reasons and any current spender is a
fail-closed ineligibility. This evidence does not construct or sign the action,
and a later chain or mempool generation requires a fresh context.

Authority-bearing durable reads capture the published canonical epoch, prove
that the store snapshot has the same durable chain epoch and tip, and recheck
the publication after decoding. An in-flight writer or any overlapping
chain-changing publication returns the explicit retryable
`StaleCanonicalRead`; a completed mempool-only publication does not invalidate
an otherwise stable durable-chain read. A final page cannot silently complete
from a tip that ceased to be current during the call.

The backend's tracked-contract funding and event pages wrap the lower-level
index cursor in opaque cursors bound to the contract ID and durable chain epoch,
and return the captured tip. `StaleChainEpoch` forces a restart after reorg;
contract substitution returns an invalid-cursor error. Consumers must use this
backend surface rather than directly combining raw `hns-wallet-index` pages.

Broadcast is not an always-success shim. It requires the mining-engine
transaction-relay policy, performs full active-chain contextual admission, and
announces inventory to live peers only after acceptance (or for an already
admitted idempotent retry). Rejected and orphan transactions are typed failures.
Fee estimation samples at most 4,096 immutable mempool entries and falls back
to the pinned minimum relay rate when the sample is empty; it is a bounded
policy estimate, not a confirmation guarantee.

The API exposes no signing operation, seed storage, arbitrary key access, or
wallet database.

## Authenticated process boundary

The native-sync listener projects the safe subset above through versioned
`POST /api/v1/wallet`. This is the consumable boundary for an independently
built `hns-wallet-rs` adapter; it does not require a path or sibling Cargo
dependency. The route is instantiated only when native sync owns the canonical
active-state runtime and peer manager (not headers-only/observe-only), the
durable complete `--wallet-index` profile is
active, and an exact `--rpc-authorization-header-file` value was explicitly
configured. Loopback alone never enables it. Diagnostic-only mode, a narrower
index profile, or missing listener authentication leaves the route unrouted;
no wallet request is parsed and no wallet read or write begins.

The v1 request/response envelope uses canonical hexadecimal identities and raw
transactions. Continuations are bounded behaviorally opaque hexadecimal
tokens, not secrets or authenticated capabilities. Confirmed responses
preserve chain epoch, tip, and script-set binding; mempool responses preserve
the chain epoch/tip plus explicit process instance nonce, generation, and query
binding. Mempool requests supply their confirmed restore epoch, and mempool
cursors bind that epoch as well as the process-local generation.
Transaction/raw point requests also require that chain epoch and optionally
require the exact nonce/generation learned from a prior mempool page; omission
means an explicitly independent current mempool capture.
Block-hash, name, spender, and confirmed contract reads require the learned
chain epoch as well. Their full returned tips remain available for exact adapter
comparison.
The listener's body limit, concurrency admission, timeout, Authorization
middleware, backend collection permits, and canonical-writer queue all remain
in force. Stable wire errors redact node/store internals and distinguish stale
retry, unavailable index, invalid cursor/bound, pruned payload, rejected/orphan
transaction, and inconsistent derivative evidence.
Wire pages are capped at 256 rows, mempool scans at 1,024 transaction IDs, and
every projected JSON result is encoded and measured against an 8 MiB ceiling
before response publication. These limits are stricter than the typed index
page envelope so hexadecimal and covenant expansion stays bounded.

`name_evidence` carries separate current/proof states and owners plus complete
canonical `encode_name_state` byte strings for both views. Projected
`data_hex` is only the resource field and remains semantically opaque; an
adapter never reconstructs consensus bytes from projected fields. The wire exposes existing tracked-contract
funding/spend classifications by opaque content ID only: it does not expose
descriptor registration or raw revealed-preimage transport while the canonical
`hns-rs` 0.2 protocol boundary is unpublished. The exact wire contract is in
[`WALLET_RPC_V1.md`](WALLET_RPC_V1.md).

## Confirmed restoration snapshot

The one-script history and UTXO methods are point-query conveniences; looping
over them does not make a multi-script restoration atomic. Production restore
uses `get_confirmed_scripts_page` with the complete sorted-unique set of up to
10,000 script identities. A global opaque cursor traverses confirmed history
and then active UTXOs, returns every row with its sorted request position, and
binds the script-set digest plus the durable chain epoch. A reorganization
returns `StaleChainEpoch`; the wallet discards the partial accumulation and
restarts from the first page. An overlap during the current page returns
`StaleCanonicalRead`, including on the terminal page.

Each response contains at most 4,096 rows from one underlying key-bound page
and inherits the 16 MiB index-page envelope. Confirmed restore is admitted
through the collection-read lane and examines at most 256 underlying
script-prefix pages per call. It can therefore return an empty result with a
nonterminal continuation; `script_examinations` reports the work consumed and
the caller must resume it. The page includes the active tip captured in the same
store snapshot. Confirmed history includes optional canonical header
`block_time`, cached by block hash within that snapshot, and never fabricates a
timestamp when unavailable. As with mempool results, the adapter must preserve a reverse
mapping from sorted request position to wallet derivation order.

## Mempool reconciliation

`get_mempool_scripts_activity` accepts one sorted-unique restoration set of up
to 10,000 script identities. It scans at most 4,096 global mempool transaction
IDs per page and reports each received/spent match with the caller's script
index in that sorted request, not the wallet's derivation-order index. An
adapter must retain a reverse mapping from each sorted request position to the
original derivation path/address record before applying results. This avoids
an address-by-address rescan without silently reassigning activity.
Continuations bind the durable chain epoch, exact published mempool generation,
query identity, and a cryptographically random, nonzero, non-persisted
mempool-instance nonce. Pages return the same chain epoch and tip and each
relevant activity carries the exact mempool `admitted_at` value. Initialization obtains
that nonce through the fallible operating-system RNG and fails startup on RNG
failure or the reserved zero value. Clear and in-process revalidation preserve
the nonce; process restart creates a new one. A generation change returns
`StaleMempoolGeneration`, while a restart/instance mismatch returns
`StaleMempoolInstance`; either result makes the wallet restart reconciliation
from the first page. Pages expose the nonce and generation and return at most
4,096 relevant inputs/outputs.

`get_mempool_tracked_contract_activity` applies the same cursor and scan bounds
to one registered contract. It recognizes exact unconfirmed funding terms,
confirmed tracked fundings, and mempool-parent fundings, then classifies the
spend against the registered public descriptor. Mempool cursors bind the
script-set digest or exact contract identity as well as the instance nonce and
generation, so a continuation cannot be reused across a query or restart.
Mempool overlays are not durable truth: after restart, the wallet reconciles its
persisted workflow and rebroadcast journal against the node's newly admitted
mempool and durable confirmed events.

Never-confirmed registration retirement is intentionally an in-process typed-
backend operation, not a wallet RPC v1 method. A preparation read returns the
complete public registration, exact lifecycle revision, chain epoch,
authenticated tip, mempool-instance nonce, and generation. The backend scans the complete hard-bounded accepted
mempool once on a collection worker, fails on the first matching funding, and
uses the internally captured exact writer sequence for compare-and-commit.

## Shakedex and HNS HTLC tracking

Supported immutable registrations are deliberately narrow:

- Shakedex v2: exact HIP-0001 seller key, name hash, funding value, canonical
  44-byte lock script, FINALIZE funding coin, seller-authorized TRANSFER
  fulfillment witness using hash type `0x84`, and seller-signed TRANSFER
  recovery witness using hash type `0x83`; the later spend that FINALIZEs the
  resulting TRANSFER coin is not a direct spend of the registered lock;
- HNS HTLC v1: exact value, SHA-256 hashlock, distinct receiver/refund public
  keys, absolute CLTV locktime, canonical script, canonical redeem/refund
  witness layouts, and `SIGHASH_ALL`.

Public keys are parsed by the pinned HSD/libsecp256k1 verifier. Marketplace
signatures must be valid compact low-S encodings and use the exact profile hash
type (`0x84` for Shakedex fulfillment, `0x83` for Shakedex recovery, and `0x01`
for HNS HTLC branches). Consensus admission authenticates the signature; the
tracker additionally requires the exact hash type, witness script, and TRANSFER
output shape. The previously invented direct FINALIZE/one-script shape is
`Unrecognized`.
If consensus accepts a spend outside those pinned wallet shapes, the optional
index records `Unrecognized` and removes the funding normally; it never rejects
the canonical block or exposes a guessed preimage. This keeps the derivative
index from strengthening consensus.

Frozen script, script-hash, canonical-binary descriptor-identity, and branch
vectors are cross-boundary qualification evidence against the current `hns-rs`
implementation. Local duplicated script/profile logic is not protocol
authority and is not a substitute for a published canonical `hns-swap` commit.
This tracker cannot be release-qualified until the node pins that canonical
commit and qualifies an adapter against it.

The index stores no private key, seed, password, capability token, or unrevealed
preimage. A preimage is persisted only after it appears in a consensus-confirmed
canonical HTLC redeem witness and matches the registered SHA-256 hashlock. Its
Rust `Debug` and public serde serialization are redacted, and public serde
deserialization refuses to reconstruct a preimage. Internal checksummed event
persistence retains the raw 32 bytes so restart and disconnect remain exact;
callers can obtain them only through the explicit `expose_for_settlement`
accessor. The chain value is already public at that point; wallet code must
still keep it out of logs. Completed retirement carries every such value into
the tombstone with its funding-outpoint and spending-transaction binding; it
never drops an internally retained revealed preimage.

## Remaining integration work

This source implementation now has a bounded authenticated process transport,
but still needs the repository's full qualification gate and an independent
cross-repository wallet adapter implementation/qualification, including the
canonical `hns-swap` pin described above, before it is release-qualified.
Completed-contract active-slot reclamation is implemented in source but has
not run its focused, restart/reorg, RocksDB, adversarial, or full qualification
gates in this tranche. Its finite 65,536 tombstone quota and permanent-
abandonment semantics are still production-availability constraints, so
untrusted registration remains unavailable. Live subscription delivery remains outside
this typed pull API. Durable encrypted workflow state, rebroadcast journals,
matching decisions, transaction construction/signing, and secret preimages
remain wallet responsibilities.

The separate Denuo cache remains wire-disabled. Live marketplace advertisement
requires a canonical dependency re-pin to the currently unpublished `hns-rs`
0.2 release containing generated Denuo V2 registry assignments and typed
envelopes; no sibling path or unassigned message ID is permitted.
