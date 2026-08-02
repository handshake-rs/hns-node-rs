# hns-node-rs (`hsrd`)

`hsrd` is a lean Handshake full node written in Rust. It implements Handshake
consensus, authenticated chain state, native P2P synchronization, a bounded
mempool, mining templates, and block relay without an `hsd` runtime dependency.

The `hsrd` process is intentionally focused on the node and mining path. It is
not a custodial wallet, desktop application, domain manager, DNS server, or
explorer. Optional indexes and a typed noncustodial chain backend support a
separate self-custodial wallet without storing or signing with wallet keys. The
repository also contains the separately deployed, bounded
[`hns-resolverd`](docs/hns-resolverd.md) companion for applications that need
ordinary HNS DNS without an `hsd` runtime.

> [!IMPORTANT]
> Functional consensus readiness is complete, but production hardening is
> ongoing. Ordinary mainnet synchronization does not grant mining authority.
> Mainnet mining is restricted to the explicit, fail-closed
> [canary profile](docs/mainnet-canary.md).

## Requirements

The repository pins Rust 1.97.1 in `rust-toolchain.toml`. With
[rustup](https://rustup.rs/) installed, Cargo selects it automatically.

The default build includes RocksDB and requires a C/C++ toolchain and Clang. On
Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install --yes build-essential clang libclang-dev
```

## Build

```bash
git clone https://github.com/handshake-rs/hns-node-rs.git
cd hns-node-rs
cargo build --locked --release -p hns-node --bin hsrd
```

The binary is written to `target/release/hsrd`.
The first release build compiles RocksDB and can take several minutes.

## Run a mainnet node

The following starts an outbound mainnet node, discovers Handshake peers, and
synchronizes active chain state. Storage is pruned by default.

```bash
mkdir -p "$PWD/data/mainnet"

./target/release/hsrd \
  --network mainnet \
  --data-dir "$PWD/data/mainnet" \
  --rpc-bind 127.0.0.1:12037 \
  --native-sync \
  --p2p-discovery
```

Press `Ctrl-C` for a clean shutdown.

In another terminal, inspect node and synchronization status:

```bash
curl --fail --silent --show-error \
  http://127.0.0.1:12037/api/v1/status

curl --fail --silent --show-error \
  http://127.0.0.1:12037/api/v1/sync
```

The RPC listener is loopback-only by default. Do not expose an unauthenticated
RPC listener to another host. See the
[control API documentation](docs/rpc-compat.md) for optional whole-listener
authorization and the complete diagnostic surface.

## Check a configuration

Add `--check-config` to any `hsrd` command to validate its arguments and exit
without opening the node:

```bash
./target/release/hsrd \
  --network mainnet \
  --data-dir "$PWD/data/mainnet" \
  --native-sync \
  --p2p-discovery \
  --check-config
```

Run `./target/release/hsrd --help` for all options.

## Local two-node smoke test

After building the release binary, run two temporary regtest nodes and verify
their P2P and Denuo negotiation:

```bash
./scripts/qualify-two-node-regtest.sh
```

The script stops both nodes and removes their temporary data when it finishes.

## Storage profiles

The default `pruned` profile retains the rollback horizon required by the
network while removing older raw block and undo payloads. To retain complete
block history, start a new data directory with:

```bash
./target/release/hsrd \
  --network mainnet \
  --data-dir "$PWD/data/mainnet-archive" \
  --native-sync \
  --p2p-discovery \
  --storage-mode archive
```

A data directory that has pruned history cannot later be changed to the archive
profile. Storage layout, migration, backup, and recovery procedures are
documented in [Storage rollout](docs/storage-rollout.md).

## Documentation

- [Architecture](docs/architecture.md)
- [P2P and synchronization](docs/p2p-sync.md)
- [Control and diagnostic API](docs/rpc-compat.md)
- [Native Handshake DNS resolver](docs/hns-resolverd.md)
- [Mining engine](docs/mining-engine.md)
- [Security model](docs/security-model.md)
- [Readiness status](docs/readiness.md)
- [Detailed implementation status](docs/implementation-status.md)
- [Testing and qualification](docs/testing.md)
- [Production assurance and external evidence](docs/production-assurance.md)
- [Storage schema and complexity](docs/storage-schema.md)
- [Wallet indexes and typed backend](docs/HNS_NODE_WALLET_INDEX.md)
- [Bounded Denuo marketplace relay](docs/DENUO_MARKET_RELAY.md)
- [Docker and GHCR](docs/docker.md)
- [Native mainnet mining canary](docs/mainnet-canary.md)
- [Extraction provenance](docs/extraction-provenance.md)

The full development and release qualification gate is:

```bash
./scripts/check.sh
```

It requires the additional tools described in
[Testing and qualification](docs/testing.md).

## License

Project-authored source is available under the
[ISC License](LICENSE-ISC). Separately licensed bundled and third-party material
remains under its original terms; see [Third-party notices](THIRD_PARTY_NOTICES.md).
