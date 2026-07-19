# hsd Fixtures

This directory is reserved for hsd-derived fixture data. The scaffold keeps the layout explicit so later milestones can add golden vectors without changing testkit paths.

- `headers`: serialized headers and expected metadata.
- `blocks`: serialized blocks.
- `transactions`: serialized transactions.
- `covenants`: covenant cases and name-operation vectors.
- `resources`: DNS/resource-value encodings.
- `rpc`: hsd JSON-RPC golden responses.
- `name-states`: expected name-state records.
- `chains`: generated regtest/simnet chain scenarios.
- `network`: P2P peer and packet fixtures.
- `snapshots`: snapshot manifest and chunk fixtures.
