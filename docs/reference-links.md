# Reference index

## Precedence

1. Existing Handshake mainnet consensus and serialized chain history.
2. Handshake protocol documentation.
3. Pinned hsd/hnsd and Urkel/liburkel behavior as differential oracles.
4. Local Rust architecture decisions.

## Handshake compatibility

- [Handshake protocol summary](https://hsd-dev.org/protocol/summary.html)
- [handshake-org/hsd](https://github.com/handshake-org/hsd)
- [handshake-org/hnsd](https://github.com/handshake-org/hnsd)
- [Handshake whitepaper](https://handshake.org/files/handshake.txt)
- [Urkel](https://github.com/handshake-org/urkel)
- [Liburkel](https://github.com/chjj/liburkel)
- [Pinned HSD network constants](https://github.com/handshake-org/hsd/blob/698e252ebc7b5c1dd0a9587e342fdd153d020ae4/lib/protocol/networks.js)
- [Pinned HSD consensus constants](https://github.com/handshake-org/hsd/blob/698e252ebc7b5c1dd0a9587e342fdd153d020ae4/lib/protocol/consensus.js)
- [Pinned HSD primitives](https://github.com/handshake-org/hsd/tree/698e252ebc7b5c1dd0a9587e342fdd153d020ae4/lib/primitives)
- [Pinned HSD covenant rules](https://github.com/handshake-org/hsd/blob/698e252ebc7b5c1dd0a9587e342fdd153d020ae4/lib/covenants/rules.js)
- [Pinned HSD name state](https://github.com/handshake-org/hsd/blob/698e252ebc7b5c1dd0a9587e342fdd153d020ae4/lib/covenants/namestate.js)

## Runtime, storage, and assurance

- [Tokio](https://docs.rs/tokio)
- [RocksDB](https://rocksdb.org/)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [RustSec](https://rustsec.org/)

Handshake P2P wire behavior is fixture-tested against hsd/hnsd. No DNS, UI,
wallet, or broad web/RPC standards are product requirements for this mining
node.
