# hns-node-rs (`hsrd`)

`hsrd` is a native Rust Handshake full node. It validates Handshake consensus,
maintains authenticated chain state, synchronizes and serves peers, relays
blocks and transactions, builds mining templates, and can provide a bounded
noncustodial ShakeScape rendezvous service without an `hsd` runtime.

The process is a node, not a custodial wallet. It never stores wallet seeds or
signs wallet transactions. Optional indexes and authenticated read APIs can
serve a separate self-custodial wallet, but those facilities are disabled by
default.

> [!IMPORTANT]
> Consensus synchronization is implemented, but production hardening and
> deployment qualification remain ongoing. Mainnet mining requires the
> explicit fail-closed [canary profile](docs/mainnet-canary.md).

## Current compatibility

- Node source line: `0.3.5`
- Rust toolchain: `1.97.1`
- Handshake protocol crates: exact `hns-rs 0.4.1`
- ShakeScape Experimental V1 registry fingerprint:
  `04fce3f12b717c4254bb66ac07474a6c9f61bd2916efc18ebfc79df82a89a66b`
- Ordinary public mainnet listener and rendezvous port: TCP `12038`

Port `44806` belongs to HSD's key-bearing fixed-seed/Brontide bootstrap
endpoints. A normal public `hsrd` or LearnHNS rendezvous deployment should use
TCP `12038` unless its operator deliberately configures a different reachable
Handshake listener.

## Build

The default build includes RocksDB and requires a C/C++ toolchain and Clang.
On Ubuntu or Debian:

```sh
sudo apt-get update
sudo apt-get install --yes build-essential clang libclang-dev

git clone https://github.com/handshake-rs/hns-node-rs.git
cd hns-node-rs
cargo build --locked --release -p hns-node --bin hsrd
```

The binary is written to `target/release/hsrd`.

## Run a mainnet node

The default storage profile is pruned. Outbound P2P, fixed-seed bootstrap,
learned-peer discovery, header synchronization, block acquisition, and active
state validation are enabled by default.

```sh
mkdir -p "$PWD/data/mainnet"

./target/release/hsrd \
  --network mainnet \
  --data-dir "$PWD/data/mainnet" \
  --rpc-bind 127.0.0.1:12037
```

Inspect status from the same host:

```sh
curl --fail --silent --show-error http://127.0.0.1:12037/api/v1/status
curl --fail --silent --show-error http://127.0.0.1:12037/api/v1/sync
```

The RPC listener is loopback-only by default. Do not expose an unauthenticated
RPC listener to another host. See [`docs/rpc-compat.md`](docs/rpc-compat.md)
for listener authentication and the complete diagnostic API.

## Deploy a public mobile rendezvous

The mobile-rendezvous profile makes one always-on `hsrd` reachable by multiple
phones. It provides:

- a legitimate inbound Handshake listener advertising
  `NETWORK | SHAKESCAPE`;
- ordinary stock-HSD-compatible `ADDR` gossip for that reachable listener;
- exact ShakeScape network, genesis, registry, and version negotiation;
- typed signed Handshake name-sale board messages;
- typed direct HNS/BTC offer discovery, cancellation, take, bilateral-session,
  and swap-status routing;
- an opaque HNSR relay supporting ShakeScape profile `0x0004` for
  already-addressed encrypted swap-session bytes.

It does not hold funds, choose trades, sign transactions, learn opaque HNSR
payloads, or make a signed marketplace object trustworthy merely because it
was relayed.

Use an absolute persistent data directory and a public IPv4 or IPv6 address
that routes raw TCP to the listener:

```sh
./target/release/hsrd \
  --network mainnet \
  --data-dir /var/lib/hsrd/mainnet \
  --rpc-bind 127.0.0.1:12037 \
  --p2p-listen 0.0.0.0:12038 \
  --p2p-advertise "$PUBLIC_IP:12038" \
  --hnsr-relay-address "$PUBLIC_IP:12038" \
  --shakescape-mobile-rendezvous
```

Before starting it, append `--check-config` to validate the deployment without
opening storage or sockets. Open inbound TCP `12038` in the host and cloud
firewalls. Do not place an HTTP/TLS reverse proxy in front of it: the forwarding
path must preserve the raw TCP byte stream.

The same listener accepts standard keyless Handshake framing and authenticated
Brontide. Its stock-compatible `ADDR` entry uses a current timestamp, the
public host/port, `NETWORK | SHAKESCAPE`, and the zero key required by stock
HSD's ordinary address path. Application use still requires exact ShakeScape
negotiation and signed-message validation.

### Rendezvous data flow

```text
Mobile A ──authenticated Handshake/ShakeScape──┐
                                               │
                                      public hsrd:12038
                                               │
Mobile B ──authenticated Handshake/ShakeScape──┘

signed board inventory and session routing: A ↔ hsrd ↔ B
opaque profile 0x0004 session bytes:          A ↔ hsrd ↔ B
settlement transactions:                      each wallet ↔ its native chain
```

The typed marketplace adapter and the opaque HNSR relay are complementary.
The former discovers and validates signed message structure and correlates
sessions; the latter transports bounded encrypted bytes without parsing them.

See [`docs/SHAKESCAPE_MARKET_RELAY.md`](docs/SHAKESCAPE_MARKET_RELAY.md) and
[`docs/hip78-hnsr-runtime.md`](docs/hip78-hnsr-runtime.md) for the exact role
and trust boundaries.

## HNSR profile `0x0004` fixture

The repository includes an isolated requester → opaque relay → endpoint test
for the canonical ShakeScape swap profile. It reserves an endpoint, opens a
circuit, sends fixed binary data in both directions, and asserts byte-exact
delivery without marketplace parsing.

```sh
cargo test --locked -p hns-p2p \
  mobile_swap_profile_routes_opaque_fixture_end_to_end
```

This protocol fixture is deterministic and does not require a blockchain,
public IP, or real funds. It complements rather than replaces a public
Brontide/two-phone canary.

## Local two-node qualification

Build the release binary, then run:

```sh
./scripts/qualify-two-node-regtest.sh
```

The harness verifies ready peers and exact ShakeScape V1 negotiation using the
current registry fingerprint. Regtest intentionally uses plaintext local P2P;
it is a node/registry qualification test, not evidence for public Brontide or
HNSR deployment.

## Storage profiles

The default `pruned` profile retains consensus state and the rollback horizon
while removing older raw block and undo payloads. It can synchronize and serve
current peers without maintaining a global wallet history index.

To retain the complete blockchain for historical peer serving, start a new
data directory in archive mode:

```sh
./target/release/hsrd \
  --network mainnet \
  --data-dir "$PWD/data/mainnet-archive" \
  --storage-mode archive
```

A directory that has already pruned history cannot later become a complete
archive. See [`docs/storage-rollout.md`](docs/storage-rollout.md).

The node checks the predicted bytes required by individual storage operations.
It does not impose an unrelated fixed 10 GB free-space cushion at ordinary
startup or compaction. Operators and deployment tooling may impose their own
reserve independently.

## Optional indexes and wallet RPC

`--wallet-index` enables the global transaction, script-history, spender,
UTXO, name-state, and swap-evidence rows required by the authenticated wallet
backend. It is not needed for a rendezvous-only node and remains disabled by
default. Enabling it does not import or custody a wallet.

Wallet RPC requires explicit listener authorization in addition to
`--wallet-index`; loopback binding alone does not enable it. See:

- [`docs/HNS_NODE_WALLET_INDEX.md`](docs/HNS_NODE_WALLET_INDEX.md)
- [`docs/WALLET_RPC_V1.md`](docs/WALLET_RPC_V1.md)
- [`docs/mainnet-pruned-wallet-node.md`](docs/mainnet-pruned-wallet-node.md)

## Other components

The repository also contains `hns-resolverd`, a separately deployed bounded
Handshake DNS resolver. It is not automatically exposed by `hsrd`:

```sh
docker compose up --detach
dig @127.0.0.1 -p 5350 example. A
```

See [`docs/hns-resolverd.md`](docs/hns-resolverd.md) and
[`docs/docker.md`](docs/docker.md).

## Validation

```sh
cargo fmt --all -- --check
cargo test --locked
./scripts/check.sh
```

The complete gate and external-tool requirements are documented in
[`docs/testing.md`](docs/testing.md).

## Documentation

- [Architecture](docs/architecture.md)
- [P2P and synchronization](docs/p2p-sync.md)
- [HNSR requester and opaque relay](docs/hip78-hnsr-runtime.md)
- [ShakeScape marketplace relay](docs/SHAKESCAPE_MARKET_RELAY.md)
- [Storage schema and complexity](docs/storage-schema.md)
- [Security model](docs/security-model.md)
- [Readiness status](docs/readiness.md)
- [Mining engine](docs/mining-engine.md)
- [Mainnet mining canary](docs/mainnet-canary.md)
- [Production assurance](docs/production-assurance.md)

## License

Project-authored source is available under the [ISC License](LICENSE-ISC).
Separately licensed bundled and third-party material remains under its original
terms; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
