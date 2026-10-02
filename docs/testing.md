# Node qualification

Run gates from this repository against the exact source and build configuration.
For builds on the workspace ARM host, first verify the prebuilt
`/home/den/.cache/codex/rocksdb-10.4.2-aarch64/lib/librocksdb.a` exists. Use the
local `.cargo/config.toml` with target directory
`/home/den/.cache/codex/hns-node-rs-audit/target`,
`TMPDIR=/home/den/.cache/codex/hns-node-rs-audit/tmp`,
`ROCKSDB_COMPILE=0`, `ROCKSDB_LIB_DIR` pointing to that prebuilt library, and
`ROCKSDB_STATIC=1`. Do not compile bundled RocksDB on this host.

## Standalone gate

```bash
./scripts/check.sh
```

The gate uses Rust 1.97.1 by default and verifies the locked root and fuzz
metadata, released protocol source policy, full-sync qualification self-tests,
production-assurance verifier regressions, both dependency policies, formatting,
fuzz compilation, strict all-feature Clippy, all-feature and no-default-feature
tests, and an optimized all-target release build. It then runs the mining-path
performance gate and the independent two-node regtest harness.

The two-node harness requires ordinary P2P readiness, exact Shakescape registry
negotiation, and bidirectional traffic. Plaintext local regtest is separate from
public Brontide, HIP-76, and HNSR qualification.

For a read-only source-policy check without compilation:

```bash
python3 scripts/test-verify-hns-rs-source.py
python3 scripts/verify-hns-rs-source.py
scripts/run-full-sync-qualification.sh self-test
scripts/run-production-assurance.sh self-test
```

## Consensus and state

Use the pinned HSD fixture corpus and independently mutated invalid cases.
Require byte-exact wire, hashes, genesis, network constants, script outcomes,
sigops, claims, airdrops, covenants, name transitions, and committed roots.
Compare canonical blocks at the same parent with the exact deployment and
checkpoint context. Header-only agreement does not establish body or state
agreement.

Qualify atomic connect, disconnect, and reorganizations; spend staging;
read-your-writes behavior; interval-committed versus working name roots;
undo completeness; and crash/reopen behavior. Full-state and retained-horizon
comparisons must satisfy [the semantic parity contract](state-parity.md).
Optional wallet indexes must remain derivative and must not change consensus.

## Storage and wallet indexes

Exercise synchronous durability, bounded snapshot scans, segment checksum
failures, incomplete generation publication, pruning/reopen, rollback retention,
compaction, and persistent authority fences. A read error must fail closed.

Wallet-index qualification includes source inclusion, chain-epoch binding,
confirmed restoration pagination, mempool snapshot invalidation, typed contract
funding/spend detection, retirement fences, and tracked-state recovery. Check
both pruned and archive profiles and reject unsupported profile combinations.
The exact contract is in [wallet indexes](HNS_NODE_WALLET_INDEX.md).

## Synchronization, relay, and mining

Test bounded framing, Brontide authentication, peer discovery, stalled or closed
connections, ban thresholds, request timeouts, orphan limits, best-work branch
selection, ordered body/state activation, and restart recovery. Revocation must
fence queued and active work for HIP-76, ODoH, HNSR, and Shakescape roles.

Qualify mempool admission and reconciliation, replacement policy, deterministic
templates, package ordering, coinbase/claim/airdrop assembly, target/version/time,
resource limits, and local solved-block validation. Persistent publication
intents must survive interruption and clear only after successful peer-write
completion. Diagnostics and observed templates cannot grant mining authority.

## Performance and production assurance

```bash
scripts/run-production-assurance.sh smoke \
  --evidence-dir /new/path/smoke-evidence
scripts/run-production-assurance.sh scheduled \
  --evidence-dir /new/path/scheduled-evidence
scripts/run-production-assurance.sh verify-external \
  --evidence-dir /path/to/external-evidence
scripts/run-production-assurance.sh release \
  --evidence-dir /path/to/complete-release-evidence
```

Smoke uses an in-memory regtest scenario; scheduled qualification uses persistent
RocksDB with synchronous durability and saturated cache occupancy. Scheduled
and release runs require a fully clean source tree and the pinned fuzz toolchain.
Compare the exact configured workloads and thresholds described in
[performance](performance.md) and [production assurance](production-assurance.md).

Production release additionally requires complete mainnet synchronization,
production-scale pruning, RocksDB fault injection, sustained reorganization and
partition tests, WAN/load latency, physical gateway/ASIC testing where applicable,
long-duration multi-peer operation, and mempool/template/publication differential
qualification. Keep binary, configuration, and source identities consistent
across the required qualification outputs. A passing local fixture or a callable
harness does not establish production readiness.
