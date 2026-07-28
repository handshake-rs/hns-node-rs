# Fuzz Targets

Parser and hostile-input fuzz targets live here. They exercise the bounded HNS
primitive decoders, P2P frame and packet decoder, JSON-RPC request decoder, and
fixture-manifest validation boundary.

The current targets are `airdrop_proof_parser`, `block_parser`, `claim_parser`,
`covenant_parser`, `fixture_manifest_parser`, `header_parser`,
`p2p_frame_parser`, `resource_value_parser`, `rpc_request_parser`, and
`transaction_parser`.

Run targets with `cargo fuzz run <target>` after installing `cargo-fuzz`.
Every target is formatting- and compile-checked in CI before fuzzing campaigns
are run separately. From the repository root, `./scripts/check.sh` performs the
locked compile check as part of the complete standalone gate.
