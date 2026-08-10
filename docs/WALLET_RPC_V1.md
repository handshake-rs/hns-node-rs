# Authenticated wallet RPC v1

`POST /api/v1/wallet` is the versioned process boundary for a separate
noncustodial wallet. It is a source-complete transport projection of the typed
`WalletBackend`; it is not an hsd compatibility RPC and is not a production
qualification claim.

The route is available only when all of these conditions hold:

- native sync owns the canonical active-state `NodeRuntime` and live peer
  manager (not headers-only or observe-only sync);
- the node was started with the durable `--wallet-index` profile; and
- `--rpc-authorization-header-file` configured an exact bounded Authorization
value.

The configured value is 1..=4,096 visible ASCII bytes. Internal spaces such as
the separator in `Bearer token` are preserved, while leading/trailing
space or tab, other controls, and non-ASCII bytes are rejected. The private
file may end in one LF or CRLF for editor ergonomics; only that single line
terminator is removed, and no other trimming or normalization occurs.

Loopback binding alone is not authorization. Without explicit Authorization,
the wallet profile, and the canonical native runtime the route is not installed
and therefore cannot parse a request or read node state. Once installed, the
outer listener middleware returns HTTP 401 for a missing or unequal header.
The existing diagnostic/compatibility routes retain their documented listener
policy.

## Envelope

Requests use an exact v1 envelope:

```json
{
  "api_version": 1,
  "request_id": "wallet-local-correlation-id",
  "call": {
    "method": "chain_snapshot"
  }
}
```

Methods with parameters put them under `params`:

```json
{
  "api_version": 1,
  "request_id": "restore-17",
  "call": {
    "method": "confirmed_scripts_page",
    "params": {
      "script_ids": ["<64 lowercase or uppercase hex characters>"],
      "cursor": null,
      "limit": 256
    }
  }
}
```

`request_id` is optional and capped at 128 UTF-8 bytes. Unknown envelope,
method, or parameter fields are rejected. All binary identities, hashes, raw
transactions, output-address hashes, covenant items, name bytes, name-state
data, and proofs use hexadecimal strings. Integers are JSON numbers.

A successful response has one `result`; a failed response has one stable error:

```json
{
  "api_version": 1,
  "request_id": "restore-17",
  "error": {
    "code": "stale_snapshot",
    "message": "the bound chain or mempool generation changed; restart this reconciliation",
    "retryable": true
  }
}
```

Internal node/store error strings and filesystem paths are not copied to the
wire. Transaction policy rejection text is bounded to 256 characters.

## Methods

| Method | Parameters | Result and binding |
| --- | --- | --- |
| `capabilities` | none | Hard bounds and explicit unavailable protocol surfaces. |
| `chain_tip` | none | Frozen tip-only projection: active hash, height, HSD-compatible median-time-past, and exact proof tree root. It carries no chain epoch. |
| `chain_snapshot` | none | Durable chain epoch and the exact active tip from one immutable read, without accepting script identities. |
| `block_hash` | `height`, required `expected_chain_epoch` | Requested height and active-chain hash or `null`, bound to the chain epoch and full tip captured in the same immutable read. |
| `confirmed_scripts_page` | sorted-unique `script_ids`, opaque `cursor`, `limit` (1..=256) | Combined history (including canonical block time when retained in the header index) then UTXOs, chain epoch, tip, work count, continuation. |
| `mempool_scripts_page` | same script set, required `expected_chain_epoch`, opaque `cursor`, `scan_limit` (1..=1,024) | Relevant transactions with exact admission times, chain epoch/tip, process `instance_nonce`, and immutable `generation`. A mismatched expected epoch fails stale. |
| `raw_transaction` | `txid`, required `expected_chain_epoch`, optional `expected_mempool` | Canonical retained transaction hex or `null` plus chain tip/epoch and mempool instance/generation; pruned payloads are explicit errors. |
| `transaction_evidence` | `txid`, required `expected_chain_epoch`, optional `expected_mempool` | Status, inclusion, payload availability, optional raw hex, chain epoch, tip, and mempool instance/generation from one stable capture. Inclusion carries the exact `transaction_index` when derivable. |
| `spending_transaction` | `txid`, `output_index`, required `expected_chain_epoch` | One-entry ordered active-chain spender evidence bound to one chain epoch/tip. |
| `spending_transactions` | `outpoints` (1..=256 ordered `{txid, output_index}` values), required `expected_chain_epoch` | Exactly one optional spender entry per requested outpoint, in request order, from one immutable chain snapshot with one epoch/tip binding. |
| `name_evidence` | `name_hash`, required `expected_chain_epoch` | Canonical encoded current/proof state bytes, separate projected hints and owners, tip/root, and canonical proof hex from one chain snapshot. |
| `name_action_context` | `action` (`transfer` or `finalize`), `name_hash`, required `expected_chain_epoch`, required exact `expected_mempool` | Versioned candidate-height context containing stable chain identity, canonical current state and owner, exact owner-mempool-spender evidence, transfer maturity, HSD-selected active-chain renewal block, and a fixed bounded eligibility decision from one chain/mempool generation. |
| `broadcast_transaction` | `transaction_hex` | Canonical contextual admission followed by actual live-peer inventory fanout counts. The node never signs. |
| `estimate_fee_rate` | `target_blocks` | Bounded deterministic estimate and its sample/source evidence. |
| `quote_transaction_fee` | bounded canonical `transaction_hex`, `target_blocks`, required `expected_chain_epoch`, required exact `expected_mempool` | Transaction ID, complete chain/mempool bindings, sampled rate evidence, exact transaction weight and node-resolved sigops, HSD sigop-adjusted policy virtual bytes, minimum and actual fees, shortfall, and a meets-minimum boolean in explicit atomic units. The method never signs or broadcasts. |
| `tracked_contract_known` | `contract_id` | Whether an immutable node-local registration exists; descriptor semantics remain opaque. |
| `tracked_contract_fundings` | `contract_id`, required `expected_chain_epoch`, opaque `cursor`, `limit` (1..=256) | Active confirmed funding evidence bound to contract and chain epoch. |
| `tracked_contract_events` | same | Confirmed funding/spend classifications bound to contract and chain epoch. |
| `mempool_tracked_contract` | `contract_id`, required `expected_chain_epoch`, opaque `cursor`, `scan_limit` (1..=1,024) | Unconfirmed funding/spend evidence with exact admission time, chain epoch/tip, and explicit mempool instance nonce/generation. |

An initialized wallet should begin with `chain_snapshot`, which returns exactly
`{"chain_epoch":N,"tip":{...}}`. `tip` is `null` only while the active chain is
uninitialized and cannot form a wallet snapshot binding. The wallet can next
request `block_hash` at height zero under that epoch and compare the returned
full binding and genesis hash with its selected network. Both requests are
script-free, so network identity can be established before any derived ScriptId
is disclosed. A chain change between them produces `stale_snapshot`; the wallet
restarts the two-step capture. `chain_tip` retains its existing nullable tip-only
result for compatibility and is not a substitute for this initial binding.

Script IDs are BLAKE2b-256 identities of canonical Handshake output-address
encodings. Clients must preserve their own reverse map from each sorted request
position to the derivation record. A confirmed page can be empty while
`continuation` advances because each call examines at most 256 script-prefix
pages. A client must discard all partial confirmed results and restart when the
chain epoch changes.

Mempool cursors bind the chain epoch, query, immutable generation, and a random
nonzero process-local instance nonce. The first request supplies the confirmed
restore's expected chain epoch; every response also carries the exact chain tip
so the adapter can compare the complete snapshot binding. The nonce changes at
process restart even if the numeric generation repeats. A client must discard
all partial mempool results when any binding changes. Continuations are
hexadecimal encodings of bounded
opaque transport state; clients echo them exactly and must not infer their JSON
payload or construct them. “Opaque” is behavioral, not cryptographic: tokens
are neither secret nor an authentication code. Typed backend validation binds
them to the exact query/generation and rejects malformed, cross-query, stale,
or impossible traversal state; a client-supplied cursor never grants chain or
index authority.

Transaction and raw-transaction point reads require the confirmed
`expected_chain_epoch`. They optionally accept
`expected_mempool: {"instance_nonce":"<64 hex>","generation":N}`. When the
caller is combining the point read with a prior mempool page it supplies that
pair and any restart or generation change fails with `stale_snapshot`. Omitting
`expected_mempool` explicitly requests an independently stable current mempool
capture; the response still returns its actual nonce and generation.

After `chain_snapshot` establishes the durable epoch, `block_hash`, name
evidence, spender evidence, and confirmed tracked-contract pages require
`expected_chain_epoch`. A mismatch is rejected before wire projection. Every
response retains the complete captured tip so the adapter can also require exact
tip equality. Confirmed restoration still returns the same binding on every
page and rejects a pre-scan reorganization; it no longer needs to be the first
request that reveals the epoch.

Every non-null `tip` object contains `hash`, `height`, `median_time_past`, and
`tree_root`. `median_time_past` is the median timestamp of the active tip and up
to ten ancestors, matching the HSD consensus window. The node loads that header
ancestry from the same immutable snapshot as the tip and proof root; missing or
inconsistent ancestry fails closed instead of projecting a partial time value.

## Transaction-bound fee quotes

`quote_transaction_fee` requires the complete binding established by a prior
chain/mempool reconciliation. The request shape is:

```json
{
  "api_version": 1,
  "request_id": "quote-final-signed-17",
  "call": {
    "method": "quote_transaction_fee",
    "params": {
      "transaction_hex": "<canonical raw Handshake transaction>",
      "target_blocks": 6,
      "expected_chain_epoch": 42,
      "expected_mempool": {
        "instance_nonce": "<64 hex characters>",
        "generation": 17
      }
    }
  }
}
```

The node captures one stable active-chain snapshot and one immutable mempool
generation. It rejects a mismatched expected epoch, process nonce, or generation
before quoting. For every non-null input it resolves the coin itself, preferring
an exact parent output in that mempool generation and otherwise reading the
active UTXO set. The method resolves at most 4,096 inputs. Caller-supplied coins,
weights, sigop counts, policy sizes, and rates do not exist on this method. A
missing parent/output or active coin is a
retryable `fee_quote_input_unavailable`; a malformed ordinary transaction or a
coinbase transaction is `invalid_fee_quote_transaction`; a stored coin whose
payload names another outpoint is backend corruption. Spending a legitimate
coinbase-created UTXO is not itself rejected by the quote boundary.

The same captured mempool generation supplies the bounded rate sample. The
response names the rate as
`rate_atomic_units_per_1000_policy_vbytes`, reports its source and sample count,
and returns `transaction_weight`, `transaction_sigops`,
`sigop_adjusted_policy_vbytes`, `minimum_policy_fee_atomic_units`,
`actual_fee_atomic_units`, `minimum_policy_fee_shortfall_atomic_units`, and
`meets_minimum_policy_fee`. Actual fee is the checked sum of node-resolved input
values minus the checked output sum; overflow or output value above input value
is an invalid quote transaction. Its txid, chain epoch/tip, and mempool
instance/generation identify the exact evidence capture.

The quote is exact only for the serialized transaction and witness bytes in
`transaction_hex`. An unsigned transaction, placeholder witness, or later
signature can change weight and, for script-hash inputs, sigop accounting. A
wallet may use an earlier quote while constructing change, but it must quote
the final signed artifact against a current exact binding before broadcast and
rebuild rather than broadcast when the paid fee is below that final minimum.
The quote does not predict a future signed size and is not an admission result.

## Name evidence

Handshake can have pending current NameState changes while the authenticated
Urkel root still represents the preceding interval state. The response never
conflates these views:

- `current_state` and `current_owner` come from the latest active column;
- `proof_state` and `proof_owner` are selected by the value authenticated by
  `proof.root`; and
- `tip.tree_root` and `proof.root` are returned separately and agree for a
  nonempty active tip.

`current_state_hex` and `proof_state_hex` are the complete canonical
`hns_state::encode_name_state` values. They are the bytes an adapter compares
against strict Urkel proof output and later supplies to a canonical decoder;
the adapter must never reconstruct them from projected JSON fields.
`current_state` and `proof_state` remain separate decoded hints. Within those
hints, `name_hex` is the name and `data_hex` is only the resource-data field,
not an encoded NameState. Resource semantics remain opaque until a published
canonical decoder is available.

## Name-action context

`name_action_context` supplies public construction evidence for exactly one
TRANSFER or FINALIZE candidate. It does not construct, approve, sign, or
broadcast a transaction. The request must bind the exact chain and mempool
generation already held by the wallet:

```json
{
  "api_version": 1,
  "request_id": "finalize-alpha-1",
  "call": {
    "method": "name_action_context",
    "params": {
      "action": "finalize",
      "name_hash": "<64 hex characters>",
      "expected_chain_epoch": 42,
      "expected_mempool": {
        "instance_nonce": "<64 hex characters>",
        "generation": 17
      }
    }
  }
}
```

The result schema is:

```json
{
  "context_version": 1,
  "action": "finalize",
  "chain_identity": {
    "network": "mainnet|testnet|regtest|simnet",
    "network_id": 0,
    "genesis_hash": "<64 hex characters>",
    "consensus_profile": "hns-consensus/name-policy-v1"
  },
  "chain_epoch": 42,
  "tip": {
    "hash": "<64 hex characters>",
    "height": 100000,
    "median_time_past": 1700000123,
    "tree_root": "<64 hex characters>"
  },
  "candidate_inclusion_height": 100001,
  "mempool": {
    "instance_nonce": "<64 hex characters>",
    "generation": 17,
    "owner_spender_txid": null
  },
  "name_hash": "<64 hex characters>",
  "current_state_hex": "<canonical encoded NameState hex>",
  "current_state": {
    "name_hash": "<64 hex characters>",
    "name_hex": "<hex>",
    "height": 1,
    "renewal": 90000,
    "owner": {"txid": "<64 hex characters>", "index": 0},
    "value": 0,
    "highest": 0,
    "data_hex": "<hex>",
    "transfer": 99713,
    "revoked": 0,
    "claimed": 0,
    "renewals": 0,
    "registered": true,
    "expired": false,
    "weak": false
  },
  "owner": {
    "name_state": {
      "name_hash": "<64 hex characters>",
      "name_hex": "<hex>",
      "height": 1,
      "renewal": 90000,
      "owner": {"txid": "<64 hex characters>", "index": 0},
      "value": 0,
      "highest": 0,
      "data_hex": "<hex>",
      "transfer": 99713,
      "revoked": 0,
      "claimed": 0,
      "renewals": 0,
      "registered": true,
      "expired": false,
      "weak": false
    },
    "owner": {"txid": "<64 hex characters>", "index": 0},
    "transaction_hex": "<canonical raw transaction hex>",
    "owner_output": {
      "value": 0,
      "address": {"version": 0, "hash": "<hex>"},
      "covenant": {"kind": 9, "items": ["<hex>"]}
    },
    "inclusion": {
      "block_hash": "<64 hex characters>",
      "height": 99713,
      "transaction_index": 1,
      "confirmations": 288
    }
  },
  "lifecycle": "closed",
  "transfer": {
    "lockup_blocks": 288,
    "current_transfer_height": 99713,
    "finalize_maturity_height": 100001,
    "finalize_eligible_at_candidate": true
  },
  "renewal": {
    "maturity_blocks": 4320,
    "period_blocks": 26208,
    "hsd_selected_height": 91360,
    "hsd_selected_hash": "<64 hex characters>",
    "valid_at_candidate": true
  },
  "eligibility": {"eligible": true, "reasons": []}
}
```

`candidate_inclusion_height` is the captured tip plus one. Network ID, genesis,
name parameters, transfer maturity, and renewal-window checks come from the
selected `hns-consensus` network profile. The HSD wallet selection is
`tip.height - 2 * renewal.maturity_blocks`, clamped to genesis; the returned
hash is looked up on the active chain in the same immutable snapshot. The
current owner is also checked against the active UTXO set and its canonical
name-hash/start-height commitments, plus the registered locked value when the
state is registered, before projection.

The immutable mempool snapshot provides an O(log N) owner-outpoint spender
lookup. `owner_spender_txid` is `null` only when that exact generation has no
accepted spender. A non-null value always adds `owner_spent_in_mempool` and the
wallet must reject preparation rather than race or replace the existing name
spend. Any chain epoch, process nonce, or generation mismatch is
`stale_snapshot`.

`eligibility.reasons` contains at most nine values in this fixed order and
vocabulary: `name_not_registered`, `name_expired_at_candidate`,
`lifecycle_not_closed`, `transfer_already_pending`, `transfer_not_pending`,
`transfer_not_mature`, `owner_covenant_invalid_for_action`,
`renewal_commitment_invalid`, and `owner_spent_in_mempool`. The response order
is deterministic according to the backend evaluation; clients must understand
every returned reason and must not treat an unknown future value as eligible.
The method returns evidence for an ineligible well-formed state rather than
turning that decision into transport success. Missing state/owner, malformed or
inconsistent owner evidence, stale bindings, and unavailable pruned owner bytes
remain explicit fail-closed errors.

## Time and transaction order

Mempool history carries exact `admitted_at` values from contextual admission.
Confirmed history carries optional `block_time` read from the canonical header
record in the same snapshot and cached by block hash within a page. The wire
never substitutes zero for unavailable time.

Confirmed transaction inclusion carries `transaction_index` as a nullable
exact value. The current durable transaction index stores byte offset and
length, not the transaction ordinal. The node derives the ordinal by enumerating
retained block transactions; consequently owner evidence always carries it,
while a pruned transaction remains valid confirmed evidence with
`transaction_index: null`. A client must preserve that unavailable state and
must not invent zero. Adding a durable ordinal requires a separately designed
storage migration, not a wire shortcut.

## Tracked contracts

The v1 boundary intentionally does not accept Shakedex or HNS-HTLC descriptor
registrations. Those profiles are duplicated locally for derivative tracking.
The workspace now pins the canonical `hns-rs` 0.2 source, but its packages are
not yet published and the trusted registration adapter is not installed or
qualified. The API exposes only evidence for registrations already admitted
through a trusted in-process boundary and labels it
`node_local_profile_only_not_protocol_authority`.

Confirmed or mempool HTLC redemption is classified, but the revealed preimage
is not transported. The public wire returns
`hns_htlc_redemption_preimage_opaque`; raw bytes remain available only through
the deliberately named in-process settlement accessor. Adding protocol
registration or preimage transport requires a published canonical protocol
revision, an explicit wire-version change, threat review, and cross-repository
qualification.

Wallet RPC v1 exposes neither registration nor retirement. The in-process typed
backend can reclaim the 16,384-active-entry and 256-active-descriptors-per-address
capacity for exact never-confirmed abandonments and for fully spent completed
lifecycles below the irreversible undo frontier. Both paths bind exact
lifecycle/chain/mempool authority, require no retained transaction orphans,
and scan the current accepted ordinary/airdrop generation. Completed retirement
is an irreversible, separately bounded tombstone transition with explicit
permanent-abandonment semantics; later matching outputs are deliberately
untracked. Legacy-unknown registrations remain non-retirable, and the finite
tombstone quota keeps capacity exhaustion a production-availability blocker.
Untrusted registration and every retirement mutation remain absent from this
endpoint.

## Resource and authority boundaries

The route remains under the listener's `DefaultBodyLimit`, global concurrent
request admission, execution timeout, and exact Authorization middleware.
Wallet backend reads additionally use the node's bounded point/collection
permits; broadcasts enter the bounded canonical writer queue and existing
contextual mempool admission before peer fanout. Opaque cursors are capped at
4,096 decoded bytes, transactions at the consensus transaction bound, restore
sets at 10,000 sorted-unique script IDs, wire pages at 256 rows, and wire
mempool scans at 1,024 transaction IDs. Fee quotes resolve at most 4,096 input
coins. Ordered outpoint-spend batches are
capped at 256 on the wire (4,096 in the typed backend). Every projected JSON `result` is
serialized and accounted before response publication and is rejected with the
stable `response_projection_limit` error above 8 MiB. This wire ceiling is
stricter than the internal 4,096-row/16-MiB index envelope and prevents
hex/covenant expansion from producing a disproportionate response. Raw and
name-owner transactions are also subject to this projection budget and to the
configured request-body limit when submitted.
Name-action eligibility is a fixed nine-reason maximum, and its owner-spender
lookup is one immutable O(log N) mempool-index read rather than a pool scan.

Wallet-index failure cannot authorize or invalidate consensus. Index writes
remain derivative members of the canonical batch; a valid block is not rejected
solely because an optional tracker cannot classify its spend. The endpoint
contains no key, seed, passphrase, workflow, signing, matching, or unrevealed
preimage service.

This source boundary still requires an independently implemented wallet
adapter, restart/reorg/adversarial transport qualification, deployment evidence,
and the repository's full release gate. It must not be labeled production-ready
from source inspection alone.
