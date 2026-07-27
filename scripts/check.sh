#!/usr/bin/env sh
set -eu

repo_root=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
cargo_target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}

cargo +"$rust_toolchain" metadata --locked --manifest-path Cargo.toml --format-version 1 >/dev/null
cargo +"$rust_toolchain" metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null
cargo +"$rust_toolchain" deny --locked check
cargo +"$rust_toolchain" deny --locked --manifest-path fuzz/Cargo.toml check
cargo +"$rust_toolchain" fmt --manifest-path Cargo.toml --all -- --check
cargo +"$rust_toolchain" fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo +"$rust_toolchain" check --locked --manifest-path fuzz/Cargo.toml --all-targets
cargo +"$rust_toolchain" clippy --locked --manifest-path Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo +"$rust_toolchain" test --locked --manifest-path Cargo.toml \
  --workspace --all-targets --all-features
cargo +"$rust_toolchain" test --locked --manifest-path Cargo.toml \
  --workspace --all-targets --no-default-features
cargo +"$rust_toolchain" build --locked --release --manifest-path Cargo.toml \
  --workspace --all-targets --all-features
./scripts/qualify-two-node-regtest.sh "$cargo_target_dir/release/hsrd"
