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

The wallet-index source implementation includes bounded chain-epoch-bound
confirmed restoration, chain-epoch/process-instance/generation-bound mempool
reconciliation, ordered snapshot-bound outpoint-spend evidence, canonical
encoded current/proof name state, atomic transaction/name evidence,
active-chain height/root reads, exact-generation TRANSFER/FINALIZE preparation
context with owner-spender and canonical maturity/renewal evidence, and restart/reorg-durable public
Shakedex-v2/HNS-HTLC-v1 event tracking.
Authenticated wallet RPC v1 now projects the safe subset through the native
node process boundary without a sibling dependency. It requires explicit
listener Authorization and `--wallet-index`; loopback alone never enables it.
The subsystem is disabled by default and is not production-qualified. The
code-bearing 0.3.5 candidate at
`2b267ffe7fc6f9929063a18986a83b566d02ae6d` passed the repository CI,
container, and CodeQL workflows on that exact revision, but those source and
build gates do not replace live restart/reorganization, storage-fault,
adversarial-topology, or deployment-scale qualification. The typed in-process
backend can reclaim registrations that authoritative durable
state proves were never confirmed, provided the caller permanently abandons
every prior funding broadcast, the exact current accepted ordinary/airdrop pool
has no matching funding, and the bound pool retains no transaction orphans.
It also contains a source-complete, typed completed-contract retirement path:
an exact fully spent lifecycle can become an immutable tombstone only after
every confirmed event is below the store's irreversible undo-pruning frontier.
The tombstone retains the complete descriptor, terminal spend and revealed
preimages, min/max heights, and an ordered event commitment while reclaiming
active global/per-address slots. At exact local revision
`fd0c9b00114e3fa0a293972de7d4538dcd959ce0`, this path passed all four matching
focused `production_next_` wallet-index tests with zero failures. That narrow
historical test record has not run a RocksDB reopen, live restart/reorg,
adversarial topology, or performance measurement. Tombstones have a separate
finite lifetime cap; later matching funding is deliberately untracked after
explicit permanent abandonment, and registration remains absent from
untrusted wallet RPC. `hns-wallet-rs` now contains a concrete node-RPC adapter
boundary and the mobile repository contains fail-closed Android and iOS read
projections. What
remains is joined backend/authentication and lifecycle qualification, explicit
product enablement, and a released canonical `hns-swap` dependency rather than
initial adapter implementation. See the
[wallet-index status](docs/HNS_NODE_WALLET_INDEX.md) and
[wire contract](docs/WALLET_RPC_V1.md).

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

To run both the node and ordinary DNS resolver from published containers, use:

```bash
docker compose up --detach
dig @127.0.0.1 -p 5350 example. A
```

See [Docker and GHCR](docs/docker.md) for Pinner and container-network wiring.

## Run a mainnet node

The following starts an outbound mainnet node, discovers Handshake peers, and
synchronizes active chain state. Storage is pruned by default.

```bash
mkdir -p "$PWD/data/mainnet"

./target/release/hsrd \
  --network mainnet \
  --data-dir "$PWD/data/mainnet" \
  --rpc-bind 127.0.0.1:12037
```

Outbound native P2P, fixed-seed discovery, and active-state synchronization are
enabled by default. `--no-native-sync` creates an RPC-only process, while
`--no-p2p-discovery` requires an explicit `--connect` peer or inbound listener.
The former positive flags remain accepted for deployment compatibility. Press
`Ctrl-C` for a clean shutdown.

HIP-76, ODoH, and HNSR requester policies also default on (`Auto` for HIP-76).
With a persistent data directory, the `--no-hip76-requester`,
`--no-odoh-requester`, `--no-hnsr-requester`, and `--no-hnsr-relay` choices
persist across restart. Their matching positive flags explicitly reverse a
saved opt-out; omitting both forms preserves the durable choice. These
requester controls do not opt into HIP-76 or ODoH DNS-output provider roles.

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
  --storage-mode archive
```

A data directory that has pruned history cannot later be changed to the archive
profile. Storage layout, migration, backup, and recovery procedures are
documented in [Storage rollout](docs/storage-rollout.md).

## Documentation

- [Architecture](docs/architecture.md)
- [P2P and synchronization](docs/p2p-sync.md)
- [HIP-77 ODoH requester boundary](docs/hip77-odoh-requester.md)
- [HIP-78 HNSR requester and opaque relay](docs/hip78-hnsr-runtime.md)
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
- [Authenticated wallet RPC v1](docs/WALLET_RPC_V1.md)
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
