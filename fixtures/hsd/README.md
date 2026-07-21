# hsd Fixtures

These pinned HSD-derived vectors are grouped by protocol surface so additional
golden cases can be added without changing testkit paths.

- `headers`: serialized headers and expected metadata.
- `blocks`: serialized blocks.
- `airdrops`: HSD key/proof codecs, hash preimages, allocation roots, and a
  complete valid faucet proof from the pinned upstream corpus.
- `claims`: HSD Claim envelope/hash vectors, checksummed ownership TXT payloads
  for all four network prefixes, and a complete upstream DNSKEY/DS/TXT/RRSIG
  proof with exact sanity/window/weak and trust-policy results.
- `transactions`: serialized transactions.
- `scripts`: signature hashes, sequence locks, and HSD execution/error vectors.
- `covenants`: covenant cases and name-operation vectors.
- `resources`: DNS/resource-value encodings.
- `rpc`: hsd JSON-RPC golden responses.
- `name-states`: expected name-state records.
- `chains`: HSD deployment/checkpoint/historical-boundary vectors, compact
  canonical-mainnet deployment-period history, and generated regtest/simnet
  chain scenarios.
- `network`: P2P peer and packet fixtures.
- `snapshots`: snapshot manifest and chunk fixtures.
