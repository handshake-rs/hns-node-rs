# Extraction provenance

This repository was extracted from the `hsrd/` prefix of MeshMine without
squashing its source history.

## Source identity

- Source repository: `https://github.com/denuoweb/MeshMine.git`
- Source branch at extraction: `codex/external-rust-node-and-experimental-p2p`
- Source commit: `67a11290d410dc88113c4c3516ce9d22e8640a49`
- Extracted prefix: `hsrd`
- Command: `git subtree split --prefix=hsrd`
- Split commit: `a99f58ca66fc0288526a3af7aae448e7af9bfbd1`
- Source-prefix and split-root tree:
  `cf8a5fb2f133bbfac1df038dc4598c7015fd8fa3`
- Preserved split history: 126 commits
- Extraction date: 2026-07-25

The split commit is the unmodified subtree result. The following standalone
normalization commit removes the MeshMine-only binary and service that cannot
belong to the independent workspace, adjusts commands and deployment paths for
the new repository root, and records this boundary. It does not rewrite the
extracted history or alter consensus, state, or storage code.

## Standalone boundary

`meshmine-minerd` combined the node with MeshMine's CPU, Vulkan, and
HandyStratum worker stack. Its manifest depended on MeshMine crates outside the
extracted prefix, so the raw split could not resolve Cargo metadata by itself.
The standalone normalization removes that crate and its MeshMine-specific
service unit from this repository. The original remains at
`hsrd/crates/meshmine-minerd` in the source commit above.

MeshMine's `meshmine-hsrd-bridge`, unified miner, CI job, HSD-oracle
generators, and source-handoff/comparison scripts were outside `hsrd/` and are
not included here. MeshMine has deliberately not yet been rewired to consume
this repository. Committed Rust fixtures, qualification artifacts, vendored
cryptographic sources, and the independent fuzz workspace were inside the
prefix and are preserved.

Documentation retains the source-only oracle and comparison procedures because
they describe how the committed evidence was produced. Run those commands from
the source MeshMine commit above; run Cargo and installed-binary commands from
this standalone repository as documented.

## Readiness documentation caveat

The extracted source contains a known release-status inconsistency that this
mechanical extraction does not resolve:

- `crates/hns-node/src/lib.rs` reports every `RpcConsensusReadiness` field as
  true, including historical replay and invalid-corpus readiness.
- `qualification/mainnet-339654/`,
  `qualification/mainnet-339660/`, and later sections of
  `docs/mainnet-canary.md` and `docs/readiness.md` record the stopped-state,
  retained rollback, and invalid-corpus promotions.
- Earlier text in `README.md`, `docs/readiness.md`, and
  `docs/gap-analysis.md` still describes the node as pre-authority or lists
  some promoted gates as incomplete.

Until those claims receive a dedicated evidence review and one consistent
documentation update, treat the strict mainnet canary as an implementation and
qualification mechanism, not as independent production endorsement.

## Storage compatibility

The extraction normalization does not change consensus or persistent-state
behavior. A follow-up qualification cleanup only names existing compound return
types, groups an internal root/height argument pair, scopes test borrows
lexically, and writes one boolean equivalence in its minimal form. In
particular, schema version 19, storage profile `hsrd-mining-v15`, append-only
authenticated name pages, block/undo segment locators, RocksDB snapshot and
multi-get paths, pruning checkpoints, and one-batch reorganization semantics
are unchanged from the source-prefix tree.

## Extraction qualification

The standalone normalization was checked on 2026-07-25 with the repository's
pinned Rust 1.89.0 toolchain:

- root and fuzz-workspace locked metadata resolve independently;
- both workspaces pass `cargo fmt --all -- --check`;
- the root workspace passes strict Clippy across all targets and all features;
- the complete no-default-features workspace test matrix passes, including its
  loopback network tests when run with local socket permission; and
- every fuzz target passes locked offline `cargo check`.

The all-features test command started compiling the Rust workspace but did not
reach test execution on this ARM host: building and archiving bundled RocksDB
remained I/O-bound on the external work disk for more than one hour, so the
attempt was interrupted rather than repeatedly rebuilt. The strict all-features
Clippy gate did finish that native dependency and pass, but it is not
represented as a substitute for the incomplete all-features test or
release-build gates.
