# Semantic state parity

The full-state comparison is a qualification boundary, not an HSD storage
compatibility layer. It compares the state that can affect independent mining
and consensus while leaving producer-specific indexes and archival fields out
of hsrd.

## Compared state

| Component | Canonical comparison |
| --- | --- |
| Active chain | network, height, active block hash, and genesis hash |
| UTXO set | ordered digest and count over outpoint, value, creation height, coinbase flag, address, and covenant; total unspent value is checked separately |
| Name state | ordered digest and count over the exact 32-byte name hash and HSD-compatible encoded `NameState` value |
| Urkel state | current working root and interval-committed root |
| Deployments | pinned live HSD comparison at the same active parent |
| Undo | operational rollback campaign across the retained reorganization horizon |

HSD's `CoinEntry.version` records the originating transaction version. The
pinned HSD source carries it into coin JSON/RPC output, but its script,
covenant, maturity, fee, and spend-validation paths do not consume it. The
canonical UTXO projection therefore declares
`origin_transaction_version` as excluded archival metadata. hsrd must not grow
a consensus-state field merely to mirror an HSD database object.

Output admission is different: HSD's `Output.isUnspendable()` omits both
version-31 null-data addresses and `REVOKE` covenants from `Coins.fromTX`.
Their value and covenant effects still participate in validation and name
state, but the outputs never become UTXOs or undo-created coins. hsrd applies
that same rule because it changes the state a miner validates, not because it
copies HSD's storage shape.

This rule is general: a field belongs in mining authority when it can affect
admission, state transition, authenticated roots, rollback, template
construction, candidate validation, or publication. Optional wallet indexes
are a separately required compatibility backend: they share atomic batches but
are never read by consensus, mining, or authenticated state. Seed/key storage,
convenience RPC fields, and redundant archival metadata remain outside mining
authority.

## Offline manifests

`hsrd-state-manifest` streams RocksDB snapshot ranges with bounded memory and
emits domain-separated BLAKE2b-256 digests. It canonicalizes outpoint indexes as
big-endian for ordering, buffering only one transaction's outputs.

The exporter accepts an offline chain directory containing the exact marker
`.hsrd-state-audit-copy` with the contents `hsrd-state-audit-copy-v1\n`.
Use a consistent stopped-state copy or checkpoint. Never open a running
production database with a second process or place this marker on live state.

After building the current binaries using the workspace build prerequisites:

```sh
hsrd-state-manifest \
  --data-dir /absolute/offline/hsrd-chain \
  > /absolute/qualification/hsrd-state-manifest.json
```

Compare independently exported HSD state at the same network, genesis, height,
and canonical block hash. Require the same semantic projection, digest domains,
ordering, counts, total UTXO value, and working/committed roots. A hash/height
match alone does not establish full-state equality. Pin and qualify the HSD
exporter used for that comparison independently.

## Retained-horizon rollback qualification

`hsrd-rollback-manifest` expands retained undo into a read-only transition
transcript. Every active block is bound by its raw-block digest and normalized
spent/resurrected coins, surviving created outputs, airdrop bit operations,
changed names, and previous/resulting committed roots. Its validation checks
undo against the raw block before export.

Stop the node, then export from its data root:

```sh
hsrd-rollback-manifest \
  --data-dir /absolute/stopped/hsrd-data \
  --output /absolute/qualification/hsrd-rollback-manifest.json
```

Compare the complete retained horizon with an independent producer using the
same normalized transition schema. Exclude outputs created and spent within
one block and name entries whose encoded before/after states are equal. Require
a passing full-state comparison at an anchor inside both transcripts. Equality
at that anchor and every transition establishes disconnect/reconnect equality.

Deployment state must also match at the same parent because it is derived
from headers rather than a portable database record. Qualification requires
full-state equality, deployment equality, and complete anchored rollback
transcripts. Keep the exact source and configuration identities with the
current qualification outputs as required by
[production assurance](production-assurance.md).
