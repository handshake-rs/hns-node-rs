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
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4`. Its canonical UTXO component is
the physical LevelDB scan. HSD's `ChainState.coin`, `value`, and `burned`
fields are emitted separately as diagnostics, not asserted as physical-set
aggregates: REGISTER through REVOKE deliberately has no chain-accounting
effect after the initial burn, while REVOKE has no physical UTXO, and claim
replacement has separate accounting rules. The two implementations share a
fixed cross-language digest vector, and HSD's integration self-test opens a
real pinned regtest Chain/BlockStore:

```sh
node hsd-oracle/export-hsd-state-manifest.js --self-test
node hsd-oracle/export-hsd-state-manifest.js \
  --integration-self-test \
  --hsd-source /absolute/pinned/hsd
python3 scripts/compare-hsrd-hsd-state-manifests.py --self-test
```

## Retained-horizon rollback qualification

A manifest pass proves equality of the listed chain, UTXO, name, and root
projections at one block hash. It does not prove that the producer-native undo
bytes are structurally identical. HSD separates spent-coin undo, name deltas,
and its airdrop bitfield, whereas hsrd records a composed block undo.

`hsrd-rollback-manifest` and `export-hsd-rollback-manifest.js` instead expand
both representations into the same read-only transition transcript. Each
retained active block is bound by its raw-block digest and exact normalized:

- spent outpoint plus resurrected coin;
- surviving created outpoint plus coin;
- airdrop positions, with a full current-field digest and simulated
  disconnect/reconnect bit operations;
- changed name hash plus full prior and resulting HSD-compatible `NameState`;
- previous and resulting interval-committed roots.

Each exporter first validates its own undo against the raw block. Outputs
created and spent within one block are removed from the net transition.
Producer-only name undo entries whose full before/after bytes are equal are
removed as semantic no-ops. HSD's originating transaction version remains
excluded for the same reason as in the full-state manifest. The comparator
requires a previously passing full-state qualification whose height and hash
occur inside both complete retained transcripts. Equality at that anchor plus
equality of every transition proves each disconnected and reconnected state by
induction. No database copy and no state-mutating disconnect are required, but
both services must be stopped so each producer can obtain its database lock.

```sh
cargo run --release --manifest-path hsrd/Cargo.toml \
  -p hns-node --bin hsrd-rollback-manifest -- \
  --data-dir /absolute/stopped/hsrd-data \
  --output /local/temp/hsrd-rollback-manifest.json

NODE_BACKEND=js node hsd-oracle/export-hsd-rollback-manifest.js \
  --hsd-source /absolute/pinned/hsd \
  --prefix /absolute/stopped/hsd-prefix \
  --network main \
  --prune \
  --output /local/temp/hsd-rollback-manifest.json

python3 scripts/compare-hsrd-hsd-rollback-manifests.py \
  --hsrd-manifest /local/temp/hsrd-rollback-manifest.json \
  --hsd-manifest /local/temp/hsd-rollback-manifest.json \
  --anchor-qualification \
    hsrd/qualification/mainnet-339654/qualification-result.json \
  --output /local/temp/rollback-comparison.json
```

Likewise, deployments remain in the pinned comparison because their state is
derived from historical headers and the candidate parent rather than being one
portable database record. Mainnet qualification evidence contains all three:

1. a passing state-manifest comparison;
2. a passing pinned deployment comparison at the full-state anchor; and
3. a passing anchored disconnect/reconnect transcript for the complete
   retained horizon.

The retained mainnet result through height 339,660 is recorded in
[`../qualification/mainnet-339660/`](../qualification/mainnet-339660/).
