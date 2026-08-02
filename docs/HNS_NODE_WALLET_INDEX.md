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
UTXO/name-state connection:

1. resolve every non-coinbase input against the immutable pre-connect UTXO
   snapshot or an earlier output in the same block;
2. add consolidated received/spent history rows;
3. add spender mappings and script UTXOs;
4. commit those writes atomically with canonical height, best block, UTXO,
   name state, undo, and transaction-index changes.

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

The public contract registry is capped at 16,384 entries. Each funding output
and input adds constant-count address/registration/funding point reads; block
connection never scans the registry. Contract funding and event pages share the
4,096-entry/16-MiB limits. Startup walks the bounded registration and address
topology, verifies the checksummed count and every reverse binding, and fails
closed on missing, duplicate, or malformed state.

## Pruning

Wallet index rows are active-chain metadata and are not deleted by raw
block/undo pruning. Therefore:

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
and the registry count are independently versioned, checksummed, and bound to
their complete database keys. Descriptor identities are BLAKE2b-256 over the
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
- `get_raw_transaction`
- `get_transaction_evidence`
- `get_transaction_status`
- `get_transaction_inclusion`
- `get_script_history`
- `get_script_utxos`
- `get_confirmed_scripts_page`
- `get_spending_transaction`
- `register_tracked_contract`
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
- `get_name_owner_transaction`

`WalletChainTip` contains the active hash, height, and the exact authenticated
name-tree root used for current persisted proofs. `get_transaction_evidence`
captures status, inclusion, retained-or-pruned payload state, active tip,
durable chain epoch, and immutable mempool generation together, then rejects
the result if publication changes during the read. The compatibility status,
inclusion, and raw-transaction calls are projections of that combined read;
wallet adapters should consume the combined result when several fields must
agree across a reorganization.

`get_name_evidence` returns one durable chain epoch containing the active tip,
current NameState, interval-root-authenticated NameState, proof, and both
corresponding owner transactions. Pending interval changes can make the
current and proof states differ; the API labels both instead of implying that
the persisted proof authenticates pending state. Owner output and transaction
inclusion are resolved in the same store snapshot. `get_name_proof` also
returns its atomically captured tip.

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
and inherits the 16 MiB index-page envelope. Empty scripts are skipped within
the bounded 10,000-script request. The page includes the active tip captured in
the same store snapshot. As with mempool results, the adapter must preserve a
reverse mapping from sorted request position to wallet derivation order.

## Mempool reconciliation

`get_mempool_scripts_activity` accepts one sorted-unique restoration set of up
to 10,000 script identities. It scans at most 4,096 global mempool transaction
IDs per page and reports each received/spent match with the caller's script
index in that sorted request, not the wallet's derivation-order index. An
adapter must retain a reverse mapping from each sorted request position to the
original derivation path/address record before applying results. This avoids
an address-by-address rescan without silently reassigning activity.
Continuations bind the exact
published mempool generation; a generation change returns
`StaleMempoolGeneration` and the wallet restarts reconciliation from the first
page. A page returns at most 4,096 relevant inputs/outputs.

`get_mempool_tracked_contract_activity` applies the same cursor and scan bounds
to one registered contract. It recognizes exact unconfirmed funding terms,
confirmed tracked fundings, and mempool-parent fundings, then classifies the
spend against the registered public descriptor. Mempool cursors bind the
script-set digest or exact contract identity as well as the generation, so a
continuation cannot be reused to skip another query. Mempool overlays are not
durable truth: after restart, the wallet reconciles its persisted workflow and
rebroadcast journal against the node's newly admitted mempool and durable
confirmed events.

## Shakedex and HNS HTLC tracking

Supported immutable registrations are deliberately narrow:

- Shakedex v2: exact HIP-0001 seller key, name hash, funding value, canonical
  44-byte lock script, FINALIZE funding coin, seller-authorized TRANSFER
  fulfillment branch, and FINALIZE recovery branch;
- HNS HTLC v1: exact value, SHA-256 hashlock, distinct receiver/refund public
  keys, absolute CLTV locktime, canonical script, canonical redeem/refund
  witness layouts, and `SIGHASH_ALL`.

Public keys are parsed by the pinned HSD/libsecp256k1 verifier. Marketplace
signatures must be valid compact low-S encodings and use the exact profile hash
type (`0x84` for the Shakedex seller branch and `0x01` for HNS HTLC branches).
If consensus accepts a spend outside those pinned wallet shapes, the optional
index records `Unrecognized` and removes the funding normally; it never rejects
the canonical block or exposes a guessed preimage. This keeps the derivative
index from strengthening consensus.

Frozen script, script-hash, canonical-binary descriptor-identity, and branch
vectors are a temporary cross-boundary check against the current `hns-rs`
implementation. Local duplicated script/profile logic is not protocol
authority and is not a substitute for a published canonical `hns-swap` commit.
This tracker cannot be release-qualified until the node pins that canonical
commit and qualifies an adapter against it.

The index stores no private key, seed, password, capability token, or unrevealed
preimage. A preimage is persisted only after it appears in a consensus-confirmed
canonical HTLC redeem witness and matches the registered SHA-256 hashlock. Its
Rust `Debug` representation is redacted and bytes require the explicit
`expose_for_settlement` accessor. The chain value is already public at that
point; wallet code must still keep it out of logs.

## Remaining integration work

This source tranche still needs the repository's full qualification gate and
cross-repository wallet adapter qualification, including the canonical
`hns-swap` pin described above, before its status can move from
implemented-in-source to release-qualified. Live subscription delivery remains
outside this typed pull API. Durable encrypted workflow state, rebroadcast
journals, matching decisions, transaction construction/signing, and secret
preimages remain wallet responsibilities.

The separate Denuo cache remains wire-disabled. Live marketplace advertisement
requires a canonical dependency re-pin to the currently unpublished `hns-rs`
0.2 release containing generated Denuo V2 registry assignments and typed
envelopes; no sibling path or unassigned message ID is permitted.
