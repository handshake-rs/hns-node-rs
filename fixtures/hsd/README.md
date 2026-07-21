# hsd Fixtures

These pinned HSD-derived vectors are grouped by protocol surface so additional
golden cases can be added without changing testkit paths.

- `headers`: serialized headers and expected metadata.
- `blocks`: serialized blocks.
- `transactions`: serialized transactions.
- `scripts`: signature hashes, sequence locks, and HSD execution/error vectors.
- `covenants`: covenant cases and name-operation vectors.
- `resources`: DNS/resource-value encodings.
- `rpc`: hsd JSON-RPC golden responses.
- `name-states`: expected name-state records.
- `chains`: HSD deployment/checkpoint/historical-boundary vectors and generated
  regtest/simnet chain scenarios.
- `network`: P2P peer and packet fixtures.
- `snapshots`: snapshot manifest and chunk fixtures.
