# hsd Fixtures

These pinned HSD-derived vectors are grouped by protocol surface so additional
golden cases can be added without changing testkit paths.

- `headers`: serialized headers and expected metadata.
- `blocks`: serialized blocks.
- `airdrops`: HSD key/proof codecs, hash preimages, allocation roots, and a
  complete valid faucet proof from the pinned upstream corpus.
- `claims`: HSD Claim envelope/hash vectors, checksummed ownership TXT payloads
  for all four network prefixes, the complete four-proof upstream historical
  DNSKEY/DS/TXT/RRSIG corpus, checkpoint-linked canonical mainnet claim blocks,
  a complete commit-height 1→2→3 replacement lineage, the final accepted claim
  at height 210,237, and the height-210,240 claim-period boundary.
- `transactions`: serialized transactions.
- `scripts`: signature hashes, sequence locks, and HSD execution/error vectors.
- `covenants`: covenant cases and name-operation vectors.
- `resources`: DNS/resource-value encodings.
- `rpc`: hsd JSON-RPC golden responses.
- `name-states`: expected name-state records.
- `chains`: HSD deployment/checkpoint/historical-boundary and validation-route
  vectors, compact canonical-mainnet deployment-period/next-version history,
  canonical block-1 coinbase-finality evidence, and generated regtest/simnet
  chain scenarios.
- `p2p`: P2P peer/packet fixtures plus HSD Brontide cipher, handshake,
  key-rotation, traffic, and key-bearing fixed-seed vectors.
- `network`: reserved live-network evidence fixtures.
- `snapshots`: snapshot manifest and chunk fixtures.
