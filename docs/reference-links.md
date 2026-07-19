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
- [HSD network constants](https://github.com/handshake-org/hsd/blob/master/lib/protocol/networks.js)
- [HSD consensus constants](https://github.com/handshake-org/hsd/blob/master/lib/protocol/consensus.js)
- [HSD primitives](https://github.com/handshake-org/hsd/tree/master/lib/primitives)
- [HSD covenant rules](https://github.com/handshake-org/hsd/blob/master/lib/covenants/rules.js)
- [HSD name state](https://github.com/handshake-org/hsd/blob/master/lib/covenants/namestate.js)

## Runtime, storage, and assurance

- [Tokio](https://docs.rs/tokio)
- [RocksDB](https://rocksdb.org/)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [RustSec](https://rustsec.org/)

Handshake P2P wire behavior is fixture-tested against hsd/hnsd. No DNS, UI,
wallet, or broad web/RPC standards are product requirements for this mining
node.
