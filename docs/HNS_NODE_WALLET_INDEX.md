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
| `--wallet-index` | script UTXOs for restoration | transaction, script-history, and spender indexes |

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

The typed backend preserves disabled-component and corruption classifications
instead of flattening them into a generic node error, so a wallet can stop the
affected read path and direct the operator to the explicit rebuild procedure.

## Typed backend

`NodeRuntime::wallet_backend` binds immutable reads, canonical writer admission,
and the live peer manager. It implements:

- `get_chain_tip`
- `get_raw_transaction`
- `get_transaction_status`
- `get_transaction_inclusion`
- `get_script_history`
- `get_script_utxos`
- `get_spending_transaction`
- `broadcast_transaction`
- `estimate_fee_rate`
- `get_name_state`
- `get_name_proof`
- `get_name_owner_transaction`

Broadcast is not an always-success shim. It requires the mining-engine
transaction-relay policy, performs full active-chain contextual admission, and
announces inventory to live peers only after acceptance (or for an already
admitted idempotent retry). Rejected and orphan transactions are typed failures.
Fee estimation samples at most 4,096 immutable mempool entries and falls back
to the pinned minimum relay rate when the sample is empty; it is a bounded
policy estimate, not a confirmation guarantee.

The API exposes no signing operation, seed storage, arbitrary key access, or
wallet database.

## Current scope gaps

The index is confirmed-active-chain state only. It does not enumerate
wallet-relevant mempool transactions, merge unconfirmed spends into history or
UTXO pages, persist a wallet mempool restoration journal, or provide a live
wallet subscription stream. `broadcast_transaction` does use the node's real
contextual mempool and P2P path, but acceptance does not make the confirmed
index report the transaction before mining.

No Shakedex order index, HTLC tracker, swap-session wallet state, or secret
preimage store/extractor is implemented here. The separate Denuo cache remains
wire-disabled pending the pinned generated V2 registry and does not fill those
wallet responsibilities.
