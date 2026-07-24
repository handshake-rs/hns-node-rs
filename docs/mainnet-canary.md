# Native mainnet mining canary

The mainnet canary is an explicit fail-closed authority profile. It uses native
Brontide peers, native active-state synchronization, native templates, and the
native MeshMine gateway bridge. HSD is not started or queried at runtime; its
pinned source and fixtures remain offline development evidence only.

`--mainnet-canary` is necessary but not sufficient to authorize work. Startup
rejects the flag unless all of these operational constraints are present:

- network `mainnet` and authority mode `native`;
- a persistent data directory and sync WAL durability;
- a mandatory authenticated loopback RPC listener;
- full native block-body and active-state sync, not headers-only or observe-only;
- at least four outbound slots and either key-bearing discovery or two pinned
  Brontide peers;
- the mining engine and transaction relay;
- either full undo history or opt-in pruning at HSD's exact mainnet
  `pruneAfterHeight`/`keepBlocks` rollback horizon; and
- no incomplete-consensus acknowledgement or experimental feature bypass.

Even after startup, the private mining permit remains unavailable until the
best header exactly equals the active-state tip by hash, height, and chainwork,
the tip has every durable validation/state/undo bit, no better chain is pending,
and every native consensus readiness bit reports complete. Core independently
requires the same atomic `getparentauthority` result. On mainnet it additionally
requires `mainnet_canary_enabled=true`, `mainnet_canary_active=true`, exact
header/block synchronization, a parent no older than 30 minutes, and at most a
one-second qualification cache.

The native script, contextual covenant, claim/airdrop, name-state, Urkel, and
invalid-corpus engines report functional readiness from their pinned
differential suites. The invalid qualification is reproduced from 24
independently generated noncontextual transaction/block cases and 12 contextual
state-boundary cases, including valid controls and atomic rejection checks.
Historical full-mainnet replay and offline state/root qualification remain
incomplete. Therefore the command below can run a native mainnet node and
accumulate that final qualification evidence, but it cannot yet activate a
mining job.

Create a private file containing one complete Authorization value, such as
`Bearer <random-secret>`, then check the operational configuration:

```sh
cargo run --locked --release --manifest-path hsrd/Cargo.toml \
  -p hns-node --bin hsrd -- \
  --network mainnet \
  --data-dir /absolute/path/hsrd-mainnet \
  --rpc-bind 127.0.0.1:12037 \
  --rpc-authorization-header-file /absolute/path/hsrd-authorization-header \
  --authority-mode native \
  --mainnet-canary \
  --native-sync --p2p-discovery --maximum-outbound 8 \
  --mining-engine --transaction-relay \
  --prune-undo-history --compact-name-tree-on-startup \
  --name-tree-compaction-interval 10000 \
  --check-config
```

Remove `--check-config` to start synchronization. Never add
`--acknowledge-incomplete-consensus`; mainnet canary validation rejects it.
The deployed mining-only profile enables undo pruning: it preserves the newest
288 mainnet blocks exactly as HSD specifies, rejects deeper reorganizations
before mutation, retires matching historical root pins atomically, and runs
name-tree reclamation on the configured height interval.
Keep the Authorization value out of command-line arguments, logs, and shell
history. An authenticated local client may inspect `getauthorityinfo` or the
atomic `getparentauthority` response. ASIC service must be started only through
`AuthoritativeHsrdMiningStream` and `HsrdGatewayActivationRequest`; the
observed/staged stream cannot construct that capability.

For restart-surviving operation, build the release binary and install the
provided user-service unit:

```sh
cargo build --locked --release --manifest-path hsrd/Cargo.toml \
  -p hns-node --bin hsrd
install -d -m 700 "$HOME/.config/systemd/user" \
  "$HOME/.config/hsrd" "$HOME/.local/share/hsrd/mainnet-canary"
install -m 600 hsrd/deploy/meshmine-hsrd-mainnet-canary.service \
  "$HOME/.config/systemd/user/meshmine-hsrd-mainnet-canary.service"
systemctl --user daemon-reload
systemctl --user enable --now meshmine-hsrd-mainnet-canary.service
```

Create the mode-0600 Authorization-value file before starting the unit. The
service has no HSD argument or dependency, is restricted to its state and auth
paths, restarts on failure, and delivers SIGTERM for a clean checkpoint and
shutdown marker. Review the `%h/Documents/MeshMine` paths if the checkout lives
elsewhere.

This profile is a bounded canary mechanism, not production eligibility,
independent review, or permission to turn incomplete readiness flags on.
