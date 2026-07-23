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

This rule is general: a field belongs in hsrd when it can affect admission,
state transition, authenticated roots, rollback, template construction,
candidate validation, or publication. Wallet indexes, convenience RPC fields,
and redundant archival metadata do not belong in the mining authority unless a
separate compatibility requirement explicitly adds them.

## Constant-space manifests

`hsrd-state-manifest` streams RocksDB snapshot ranges with bounded memory.
`export-hsd-state-manifest.js` streams HSD LevelDB and the recovered current
Urkel transaction. Both use the same domain-separated BLAKE2b-256 transcript.
They canonicalize an outpoint index as big-endian for ordering even though
hsrd's durable protocol key stores it little-endian. Only the outputs of one
transaction are buffered to perform that numeric ordering.

The Rust exporter refuses a directory without this exact marker:

```text
.hsrd-state-audit-copy = "hsrd-state-audit-copy-v1\n"
```

The HSD exporter similarly requires:

```text
.hsd-state-audit-copy = "hsd-state-audit-copy-v1\n"
```

These markers prevent an accidental attempt to open a running production
database. An operator may use an actual consistent copy/checkpoint, or may
place the marker only while both user services are stopped and remove it before
restart. Opening two processes against either live database is forbidden.

At an identical stopped block hash:

```sh
cargo run --release --manifest-path hsrd/Cargo.toml \
  -p hns-node --bin hsrd-state-manifest -- \
  --data-dir /absolute/offline/hsrd-chain \
  > hsrd-state-manifest.json

node hsd-oracle/export-hsd-state-manifest.js \
  --hsd-source /absolute/pinned/hsd \
  --prefix /absolute/offline/hsd-prefix \
  --network main \
  --prune \
  > hsd-state-manifest.json

python3 scripts/compare-hsrd-hsd-state-manifests.py \
  --hsrd-manifest hsrd-state-manifest.json \
  --hsd-manifest hsd-state-manifest.json
```

The HSD exporter requires the clean tracked revision
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4`. It checks HSD's scanned UTXO count
and total against HSD's own chain-state aggregates before emitting a manifest.
The two implementations share a fixed cross-language digest vector, and HSD's
integration self-test opens a real pinned regtest Chain/BlockStore:

```sh
node hsd-oracle/export-hsd-state-manifest.js --self-test
node hsd-oracle/export-hsd-state-manifest.js \
  --integration-self-test \
  --hsd-source /absolute/pinned/hsd
python3 scripts/compare-hsrd-hsd-state-manifests.py --self-test
```

## What a manifest pass does not prove

A manifest pass proves equality of the listed chain, UTXO, name, and root
projections at one block hash. It does not prove that the producer-native undo
bytes are structurally identical. HSD separates spent-coin undo, name deltas,
and its airdrop bitfield, whereas hsrd records a composed block undo. The
correct cross-implementation test is to disconnect the same retained suffix in
copies, compare the normalized state after every disconnect, reconnect it, and
compare again.

Likewise, deployments remain in the pinned live comparison because their state
is derived from historical headers and the candidate parent rather than being
one portable database record. Final mainnet evidence must contain all three:

1. a passing state-manifest comparison;
2. a passing pinned deployment comparison at that same block hash; and
3. a passing disconnect/reconnect rollback campaign for the retained horizon.
