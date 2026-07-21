# Fuzz Targets

Parser and hostile-input fuzz targets live here. They exercise the bounded HNS
primitive decoders, P2P frame and packet decoder, JSON-RPC request decoder, and
fixture-manifest validation boundary.

Run targets with `cargo fuzz run <target>` after installing `cargo-fuzz`.
Every target is formatting- and compile-checked in CI before fuzzing campaigns
are run separately.
