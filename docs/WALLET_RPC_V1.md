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
    "method": "chain_tip"
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
| `chain_tip` | none | Active hash, height, and exact proof tree root. |
| `block_hash` | `height`, required `expected_chain_epoch` | Requested height and active-chain hash or `null`, bound to the chain epoch and full tip captured in the same immutable read. |
| `confirmed_scripts_page` | sorted-unique `script_ids`, opaque `cursor`, `limit` (1..=256) | Combined history (including canonical block time when retained in the header index) then UTXOs, chain epoch, tip, work count, continuation. |
| `mempool_scripts_page` | same script set, required `expected_chain_epoch`, opaque `cursor`, `scan_limit` (1..=1,024) | Relevant transactions with exact admission times, chain epoch/tip, process `instance_nonce`, and immutable `generation`. A mismatched expected epoch fails stale. |
| `raw_transaction` | `txid`, required `expected_chain_epoch`, optional `expected_mempool` | Canonical retained transaction hex or `null` plus chain tip/epoch and mempool instance/generation; pruned payloads are explicit errors. |
| `transaction_evidence` | `txid`, required `expected_chain_epoch`, optional `expected_mempool` | Status, inclusion, payload availability, optional raw hex, chain epoch, tip, and mempool instance/generation from one stable capture. Inclusion carries the exact `transaction_index` when derivable. |
| `spending_transaction` | `txid`, `output_index`, required `expected_chain_epoch` | One-entry ordered active-chain spender evidence bound to one chain epoch/tip. |
| `spending_transactions` | `outpoints` (1..=256 ordered `{txid, output_index}` values), required `expected_chain_epoch` | Exactly one optional spender entry per requested outpoint, in request order, from one immutable chain snapshot with one epoch/tip binding. |
| `name_evidence` | `name_hash`, required `expected_chain_epoch` | Canonical encoded current/proof state bytes, separate projected hints and owners, tip/root, and canonical proof hex from one chain snapshot. |
| `broadcast_transaction` | `transaction_hex` | Canonical contextual admission followed by actual live-peer inventory fanout counts. The node never signs. |
| `estimate_fee_rate` | `target_blocks` | Bounded deterministic estimate and its sample/source evidence. |
| `tracked_contract_known` | `contract_id` | Whether an immutable node-local registration exists; descriptor semantics remain opaque. |
| `tracked_contract_fundings` | `contract_id`, required `expected_chain_epoch`, opaque `cursor`, `limit` (1..=256) | Active confirmed funding evidence bound to contract and chain epoch. |
| `tracked_contract_events` | same | Confirmed funding/spend classifications bound to contract and chain epoch. |
| `mempool_tracked_contract` | `contract_id`, required `expected_chain_epoch`, opaque `cursor`, `scan_limit` (1..=1,024) | Unconfirmed funding/spend evidence with exact admission time, chain epoch/tip, and explicit mempool instance nonce/generation. |

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

After the first confirmed restoration page establishes the durable epoch,
`block_hash`, name evidence, spender evidence, and confirmed tracked-contract
pages also require `expected_chain_epoch`. A mismatch is rejected before wire
projection. Every response retains the complete captured tip so the adapter can
also require exact tip equality.

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
registrations. Those profiles are duplicated locally for derivative tracking
and the canonical `hns-rs` 0.2 protocol types are not yet a published, pinned
dependency. The API exposes only evidence for registrations already admitted
through a trusted in-process boundary and labels it
`node_local_profile_only_not_protocol_authority`.

Confirmed or mempool HTLC redemption is classified, but the revealed preimage
is not transported. The public wire returns
`hns_htlc_redemption_preimage_opaque`; raw bytes remain available only through
the deliberately named in-process settlement accessor. Adding protocol
registration or preimage transport requires a published canonical protocol
revision, an explicit wire-version change, threat review, and cross-repository
qualification.

The append-only 16,384-entry registry and 256-descriptors-per-address cap have
no authenticated retirement/reclamation lifecycle. Capacity exhaustion remains
a production-availability blocker even though untrusted registration is absent
from this endpoint.

## Resource and authority boundaries

The route remains under the listener's `DefaultBodyLimit`, global concurrent
request admission, execution timeout, and exact Authorization middleware.
Wallet backend reads additionally use the node's bounded point/collection
permits; broadcasts enter the bounded canonical writer queue and existing
contextual mempool admission before peer fanout. Opaque cursors are capped at
4,096 decoded bytes, transactions at the consensus transaction bound, restore
sets at 10,000 sorted-unique script IDs, wire pages at 256 rows, and wire
mempool scans at 1,024 transaction IDs. Ordered outpoint-spend batches are
capped at 256 on the wire (4,096 in the typed backend). Every projected JSON `result` is
serialized and accounted before response publication and is rejected with the
stable `response_projection_limit` error above 8 MiB. This wire ceiling is
stricter than the internal 4,096-row/16-MiB index envelope and prevents
hex/covenant expansion from producing a disproportionate response. Raw and
name-owner transactions are also subject to this projection budget and to the
configured request-body limit when submitted.

Wallet-index failure cannot authorize or invalidate consensus. Index writes
remain derivative members of the canonical batch; a valid block is not rejected
solely because an optional tracker cannot classify its spend. The endpoint
contains no key, seed, passphrase, workflow, signing, matching, or unrevealed
preimage service.

This source boundary still requires an independently implemented wallet
adapter, restart/reorg/adversarial transport qualification, deployment evidence,
and the repository's full release gate. It must not be labeled production-ready
from source inspection alone.
