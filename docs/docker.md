# Docker and GHCR

Each release publishes two multi-platform OCI images for `linux/amd64`
(x86_64) and `linux/arm64` (AArch64):

```sh
docker pull ghcr.io/handshake-rs/hns-node-rs:canary-v0.3.4
docker pull ghcr.io/handshake-rs/hns-resolverd:canary-v0.3.4
```

The first image runs the `hsrd` consensus node. The second runs the ordinary
UDP/TCP DNS companion backed by that node. Docker selects the matching platform
automatically. The v0.3.4 prerelease publishes only each exact
`canary-v0.3.4` tag. Stable releases publish the exact version, minor-version,
and `latest` tags. Production deployments should pin both manifest digests
recorded by the release workflow:

```yaml
HSRD_IMAGE: ghcr.io/handshake-rs/hns-node-rs@sha256:NODE_MANIFEST_DIGEST
HNS_RESOLVERD_IMAGE: ghcr.io/handshake-rs/hns-resolverd@sha256:RESOLVER_MANIFEST_DIGEST
```

The same image runs ordinary nodes and the explicitly gated mainnet mining
canary. The image defaults to an outbound-only, pruned mainnet node. It does
not enable mining, publish RPC, or accept inbound P2P connections by default.

## Run with Compose

Start the default node and DNS sidecar with durable named-volume storage:

```sh
docker compose up --detach
docker compose logs --follow hsrd hns-resolverd
```

The checked-in Compose configuration defaults to the two v0.3.4 canary images.
Override `HSRD_IMAGE` and `HNS_RESOLVERD_IMAGE` with immutable manifest digests
for a pinned deployment.

Both services run as UID/GID 10001, drop every Linux capability, and use a
read-only root filesystem. The resolver shares only the node's network
namespace and reaches RPC at `127.0.0.1:12037`; Compose never publishes the
RPC port or binds it to the bridge. The node receives two minutes to checkpoint
RocksDB after SIGTERM. Its health check reports local RPC availability; it does
not mean synchronization is complete. Inspect synchronization without
publishing RPC:

```sh
docker compose exec hsrd \
  curl --fail --silent --show-error http://127.0.0.1:12037/api/v1/sync
```

Back up or inspect the `hns-node-rs_hsrd-mainnet` volume with the node stopped.
Never attach two node processes to the same data volume.

The DNS listener is published only on host loopback as UDP and TCP port 5350.
A host-native Pinner instance should use:

```text
hns_resolver=127.0.0.1:5350
```

A containerized Pinner instance can join the `hns-node-rs_default` Compose
network and use the `hns-resolverd:5350` alias. That alias reaches port 5350 in
the shared node/resolver network namespace without making hsrd RPC reachable
on the bridge. The resolver remains fail closed until hsrd is synchronized.

Do not change the loopback publication to `0.0.0.0:5350` on an Internet-facing
host. This image is a private application sidecar, not a public open resolver.
Set `HNS_RESOLVER_PORT` only when another local service already owns port 5350.

To use immutable images, set both variables before starting Compose:

```sh
HSRD_IMAGE='ghcr.io/handshake-rs/hns-node-rs@sha256:MANIFEST_DIGEST' \
HNS_RESOLVERD_IMAGE='ghcr.io/handshake-rs/hns-resolverd@sha256:MANIFEST_DIGEST' \
  docker compose up --detach
```

## Optional inbound P2P

The default remains outbound-only. To accept inbound mainnet peers, add
`--p2p-listen 0.0.0.0:12038` to the command and publish TCP port 12038 in a
local Compose override. Make the port reachable through the host firewall and
NAT only when inbound service is intentional.

Do not publish the unauthenticated RPC listener. If an ordinary deployment
must make RPC reachable outside the container namespace, configure
`--rpc-authorization-header-file`, bind the container listener explicitly, and
publish it only to a trusted interface.

## Mainnet mining canary

The canary remains opt-in and uses the same image. It must retain the exact
fail-closed configuration documented in [Native mainnet mining canary](mainnet-canary.md),
including authenticated loopback RPC. A conventional bridge-network port
publication requires a non-loopback container bind and therefore does not
satisfy that profile.

Mount the authorization value as a nonsymlink, mode-0600 regular file readable
by UID 10001. Keep the canary RPC on `127.0.0.1`; a colocated gateway that must
consume it should share the node's network namespace. Do not put the
authorization value in the image, Compose file, environment, command line, or
image build arguments.

## Build locally

Build the native architecture:

```sh
docker build --tag hsrd:local .
docker build --target hns-resolverd-runtime --tag hns-resolverd:local .
docker run --rm hsrd:local --version
docker run --rm hns-resolverd:local --version
```

Build both release architectures into an OCI layout with Buildx:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=hsrd.oci.tar \
  --target hsrd-runtime \
  .

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=hns-resolverd.oci.tar \
  --target hns-resolverd-runtime \
  .
```

The build uses the locked Cargo dependency graph, the repository's Rust 1.97.1
toolchain, architecture-scoped compiler caches, and digest-pinned Debian base
indexes. The runtime image contains neither Cargo nor the native build
toolchain.

## Exact-commit recovery candidate

The manual **hsrd arm64 recovery candidate** workflow exports the exact current
`main` source as a `linux/arm64` OCI archive for the narrowly guarded legacy
interval-accumulator recovery. It fails closed if the requested full commit,
checked-out `HEAD`, workflow definition, and current canonical `origin/main`
are not identical. The seven-day GitHub Actions artifact also contains
checksums and provenance binding the full source tree and imported image ID.

This workflow never publishes an image, tag, GitHub Release, or GHCR package;
it is not a substitute for release qualification. The archive requires an
explicit local `skopeo` import. Follow the complete stop, whole-root cold
backup, one-shot start, success, and rollback procedure in
[Legacy interval-accumulator recovery](interval-accumulator-recovery.md).

## Release publication

Pull requests and `main` changes build and execute both images independently on
native amd64 and arm64 GitHub-hosted runners. Publishing occurs only for a
published GitHub Release whose tag is valid semantic versioning. Before the
GHCR release event proceeds, it verifies the uploaded hsrd binary archive,
separate relinking/source archive, `SHA256SUMS`, and `BUILD-PROVENANCE.json`.
Each native runner pushes an untagged platform image by digest; the final jobs
create separate multi-platform node and resolver manifests and apply only the
prerelease canary tag, or the stable version, minor-version, and `latest` tags,
after all four platform builds pass.

The release workflow publishes BuildKit SBOM/provenance attestations and a
GitHub artifact attestation for the final manifest. Verify the latter with:

```sh
gh attestation verify \
  oci://ghcr.io/handshake-rs/hns-node-rs:canary-v0.3.4 \
  --repo handshake-rs/hns-node-rs

gh attestation verify \
  oci://ghcr.io/handshake-rs/hns-resolverd:canary-v0.3.4 \
  --repo handshake-rs/hns-node-rs
```

GHCR package visibility is separate from repository visibility. An
organization administrator must make each package public after its first
publication. Both images' OCI source labels link them to this repository so
they can inherit repository access.
