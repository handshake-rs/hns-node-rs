# syntax=docker/dockerfile:1.7

# Keep the compiler and runtime distributions on the same glibc generation.
# Both references pin multi-platform OCI indexes that contain amd64 and arm64.
FROM rust:1.97.1-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# Use the compiler already installed in the builder image. This override keeps
# rustup from installing the repository's lint-only components in this stage.
ENV RUSTUP_TOOLCHAIN=1.97.1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        clang \
        libclang-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

ARG TARGETARCH
RUN --mount=type=cache,id=hsrd-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=hsrd-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=hsrd-target-${TARGETARCH},target=/workspace/target,sharing=locked \
    cargo build --locked --release --package hns-node --bin hsrd \
    && install -D --mode=0755 target/release/hsrd /out/hsrd

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="hns-node-rs" \
      org.opencontainers.image.description="Lean Handshake full node written in Rust" \
      org.opencontainers.image.source="https://github.com/handshake-rs/hns-node-rs" \
      org.opencontainers.image.url="https://github.com/handshake-rs/hns-node-rs" \
      org.opencontainers.image.documentation="https://github.com/handshake-rs/hns-node-rs/blob/main/docs/docker.md" \
      org.opencontainers.image.licenses="ISC" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        libssl3 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hsrd \
    && useradd --uid 10001 --gid hsrd --no-create-home --home-dir /var/lib/hsrd \
        --shell /usr/sbin/nologin hsrd \
    && install -d --mode=0700 --owner=hsrd --group=hsrd /var/lib/hsrd

COPY --from=builder /out/hsrd /usr/local/bin/hsrd
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/hsrd-container-entrypoint

USER 10001:10001
WORKDIR /var/lib/hsrd

VOLUME ["/var/lib/hsrd"]
EXPOSE 12037 12038
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/hsrd-container-entrypoint"]
CMD ["--network", "mainnet", "--data-dir", "/var/lib/hsrd", "--rpc-bind", "127.0.0.1:12037", "--native-sync", "--p2p-discovery"]
