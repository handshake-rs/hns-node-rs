# Docker and GHCR

The release image is published as a multi-platform OCI image for
`linux/amd64` (x86_64) and `linux/arm64` (AArch64):

```sh
docker pull ghcr.io/handshake-rs/hns-node-rs:canary-v0.3.3
```

Docker selects the matching platform automatically. The v0.3.3 prerelease
publishes only the exact `canary-v0.3.3` tag. Stable releases publish the exact
version, minor-version, and `latest` tags. Production deployments should pin
the manifest digest recorded by the release workflow:

```yaml
image: ghcr.io/handshake-rs/hns-node-rs@sha256:MANIFEST_DIGEST
```

The same image runs ordinary nodes and the explicitly gated mainnet mining
canary. The image defaults to an outbound-only, pruned mainnet node. It does
not enable mining, publish RPC, or accept inbound P2P connections by default.

## Run with Compose

Start the default node with durable named-volume storage:

```sh
docker compose up --detach
docker compose logs --follow hsrd
```

The checked-in Compose configuration defaults to
`ghcr.io/handshake-rs/hns-node-rs:canary-v0.3.3` for this prerelease. Override
`HSRD_IMAGE` with an immutable manifest digest for a pinned deployment.

The Compose service runs as UID/GID 10001, drops every Linux capability, uses
a read-only root filesystem, and gives RocksDB two minutes to checkpoint after
SIGTERM. The health check reports local RPC availability; it does not mean the
node has finished synchronizing. Inspect synchronization without publishing
RPC to the host:

```sh
docker compose exec hsrd \
  curl --fail --silent --show-error http://127.0.0.1:12037/api/v1/sync
```

Back up or inspect the `hns-node-rs_hsrd-mainnet` volume with the node stopped.
Never attach two node processes to the same data volume.

To use an immutable image, set `HSRD_IMAGE` to the release digest before
starting Compose:

```sh
HSRD_IMAGE='ghcr.io/handshake-rs/hns-node-rs@sha256:MANIFEST_DIGEST' \
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
docker run --rm hsrd:local --version
```

Build both release architectures into an OCI layout with Buildx:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=hsrd.oci.tar \
  .
```

The build uses the locked Cargo dependency graph, the repository's Rust 1.97.1
toolchain, architecture-scoped compiler caches, and digest-pinned Debian base
indexes. The runtime image contains neither Cargo nor the native build
toolchain.

## Release publication

Pull requests and `main` changes build and execute the image independently on
native amd64 and arm64 GitHub-hosted runners. Publishing occurs only for a
published GitHub Release whose tag is valid semantic versioning. Before the
GHCR release event proceeds, it verifies the uploaded binary archive, separate
relinking/source archive, `SHA256SUMS`, and `BUILD-PROVENANCE.json`. Each native
runner pushes an untagged platform image by digest; the final job creates one
multi-platform GHCR manifest and applies only the prerelease canary tag, or the
stable version, minor-version, and `latest` tags, after both platform checks
pass.

The release workflow publishes BuildKit SBOM/provenance attestations and a
GitHub artifact attestation for the final manifest. Verify the latter with:

```sh
gh attestation verify \
  oci://ghcr.io/handshake-rs/hns-node-rs:canary-v0.3.3 \
  --repo handshake-rs/hns-node-rs
```

GHCR package visibility is separate from repository visibility. An
organization administrator must make the package public after its first
publication. The image's OCI source label links it to this repository so it
can inherit repository access.
