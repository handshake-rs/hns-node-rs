# hsd Fixtures

These pinned HSD-derived vectors are grouped by protocol surface so additional
golden cases can be added without changing testkit paths.

- `headers`: serialized headers and expected metadata.
- `blocks`: serialized blocks.
- `airdrops`: HSD key/proof codecs, hash preimages, allocation roots, and a
  complete valid faucet proof from the pinned upstream corpus.
- `claims`: HSD Claim envelope/hash vectors, checksummed ownership TXT payloads
  for all four network prefixes, the complete four-proof upstream historical
  DNSKEY/DS/TXT/RRSIG corpus, and a canonical mainnet block containing two real
  CLAIM outputs with checkpoint-linked header/time context.
- `transactions`: serialized transactions.
- `scripts`: signature hashes, sequence locks, and HSD execution/error vectors.
- `covenants`: covenant cases and name-operation vectors.
- `resources`: DNS/resource-value encodings.
- `rpc`: hsd JSON-RPC golden responses.
- `name-states`: expected name-state records.
- `chains`: HSD deployment/checkpoint/historical-boundary and validation-route
  vectors, compact canonical-mainnet deployment-period/next-version history,
  and generated regtest/simnet chain scenarios.
- `network`: P2P peer and packet fixtures.
- `snapshots`: snapshot manifest and chunk fixtures.
