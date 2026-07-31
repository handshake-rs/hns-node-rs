# Fuzz Targets

Parser and hostile-input fuzz targets live here. They exercise the bounded HNS
primitive decoders, P2P frame and packet decoder, JSON-RPC request decoder, and
fixture-manifest validation boundary.

The current targets are `airdrop_proof_parser`, `block_parser`, `claim_parser`,
`covenant_parser`, `fixture_manifest_parser`, `header_parser`,
`p2p_frame_parser`, `resource_value_parser`, `rpc_request_parser`, and
`transaction_parser`.

Every target is formatting- and compile-checked by the normal gate. Scheduled
and manually dispatched CI also runs every target with exactly
`nightly-2025-08-07` and `cargo-fuzz 0.13.2`; another cargo-fuzz version fails
before target execution.

Run an evidence-producing local campaign from the repository root:

```bash
scripts/run-sustained-fuzz.sh \
  --duration-seconds 1800 \
  --output-dir /new/path/hsrd-fuzz-evidence
```

The output path must not exist. The runner retains per-target corpora, logs,
crash artifacts, exact tool/configuration/source identities, start/completion
corpus inventories, and SHA-256 digests in `summary.json`. A target crash,
timeout, build failure, missing tool, source/worktree change during the
campaign, target skipped after an earlier failure, or successful process exit
before the configured per-target duration makes the summary and command fail.
The worktree digest includes non-ignored untracked files, so keep output and
corpora outside the repository. Corpus inventories reject symbolic links and
bind relative names, modes, sizes, and streamed contents. Use `--corpus-root`
for a persistent corpus and repeated `--target` arguments only for focused
triage; release qualification runs all targets.
The scheduled orchestrator requires at least three minutes per target and the
release orchestrator requires at least 30 minutes per target.

The weekly three-minute-per-target CI campaign is a bounded sustained software
gate, not proof that all hostile inputs have been exhausted. Longer release
campaigns and evidence retention are specified in
[`../docs/production-assurance.md`](../docs/production-assurance.md).
