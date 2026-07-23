# Native synchronization and mining-path performance

Performance qualification uses release builds and never requires a running HSD
process. HSD remains only the pinned offline behavioral oracle for fixtures.

## Reproducible commands

Measure an already-running native mainnet node:

```bash
python3 scripts/measure-hsrd-native-sync.py \
  --hsrd-url http://127.0.0.1:12037 \
  --authorization-header-file /absolute/path/hsrd-authorization-header \
  --duration-seconds 60 --interval-seconds 2 \
  --output /path/to/native-sync-measurement.json
```

The sampler accepts only a literal loopback HTTP origin unless the operator
explicitly opts into a remote endpoint. Its optional Authorization value is
read from an absolute, non-symlink, mode-0600 regular file and is never placed
in arguments, output, or logs. It requires active-state native sync,
binds every sample to one runtime instance, rejects counter regression and any
reported runtime error, bounds response size and request time, and records:

- overall and interval P50/P95/P99/maximum header, body, state, and byte rates;
- active-state stalls, starting/ending/minimum ready peers, zero-peer samples,
  peer failures, failed blocks, and unavailable evidence;
- starting, ending, and raw samples so derived claims can be audited.

Network-byte rates use the runtime-lifetime traffic total. A peer's final
snapshot is atomically transferred into retired-session counters before it is
removed, so rotation and reconnects cannot make the sampled counter regress.

Measure the local mining critical path:

```bash
cargo run --locked --release -p hns-node --bin hsrd-performance-gate
```

The gate strictly imports canonical HSD regtest genesis, warms ten blocks, then
builds and connects 100 consecutive native blocks. It reports count,
P50/P95/P99/maximum, failure count, and unavailable evidence for template
assembly, cached job preparation, combined tip-to-job work, solved-candidate
validation, and local consensus connection. Its intentionally conservative
development-host P99 gates are 25 ms tip-to-job, 5 ms candidate validation, and
50 ms in-memory local connection.

## 2026-07-22 development-host evidence

Host: four Cortex-A76 cores at up to 2.8 GHz, aarch64. The bounded native IBD
samples used a tmpfs datastore, eight configured outbound slots, seven Ready
Brontide peers, four stateless validation workers, a 1,024-entry validation
queue, synchronous durability, and the 250 ms default supervisor poll.

Before the IBD scheduler change, a 68-second startup smoke reached header
50,000, stored height 2,523, and active height 1,942: 28.6 connected blocks/s
from process start. Active replay was visibly capped by the eight-block periodic
slice.

After immediate full-slice activation, a 15-second stalled-body failover, and a
32-request per-peer limit within the unchanged 128-request global bound, the
versioned sampler measured this uninterrupted 60-second window:

| Metric | Result |
|---|---:|
| Best-header overall rate | 833.332 headers/s |
| Received-body overall rate | 46.767 blocks/s |
| Stored-body overall rate | 43.967 blocks/s |
| Contiguous stored-height rate | 48.133 blocks/s |
| Active-height / connected-block rate | 47.667 blocks/s |
| Active interval P50 / P95 / P99 / max | 27.000 / 166.498 / 169.994 / 169.994 blocks/s |
| Received network bytes | 1,270,006.807 bytes/s |
| Active stall intervals | 2 of 30 |
| Ready peers | 7 |
| Block / peer failures / unavailable | 0 / 0 / 0 |

The comparable startup rate improved by about 67%, while active and stored
frontiers remained within 28 blocks at the end of the measured window. This is
bounded early-chain WAN evidence, not a full-mainnet IBD completion claim;
later blocks, name-state growth, RocksDB on persistent media, pruning, and
compaction require a longer campaign.

The same host produced:

| Mining-path stage (100 blocks) | P50 | P95 | P99 | Max |
|---|---:|---:|---:|---:|
| Template build | 188 us | 704 us | 2,715 us | 3,320 us |
| Cached job preparation | 98 us | 392 us | 638 us | 757 us |
| Tip to prepared job | 286 us | 1,179 us | 3,015 us | 4,078 us |
| Solved-candidate validation | 9 us | 12 us | 13 us | 14 us |
| Local consensus connection | 642 us | 2,427 us | 4,283 us | 4,752 us |

All 100 samples passed with zero failure or unavailable evidence. These are
local empty-mempool regtest critical-path measurements using the in-memory
store. They establish a regression gate, not ASIC, mainnet-state, persistent
storage, or first-peer-acceptance qualification.

## Persistent mainnet canary evidence

The release canary's exhaustive RocksDB startup audit reached its authenticated
RPC in 20.228 seconds at active height 9,396, 21.624 seconds at height 9,622,
and 27.519 seconds at height 10,952. Before the retained-root union traversal,
the same audit took roughly 70 seconds at height 8,328. Every restart preserved
the exact active/stored tip and reopened with zero failed blocks, bans,
rejections, contextual failures, or terminal error. These are bounded restart
observations, not deployment-scale crash-recovery qualification.

A 60-second persistent-store window beginning at height 9,622 connected 624
historical blocks (10.4 blocks/s) and advanced the contiguous stored frontier
916 blocks (15.267 blocks/s), with zero failed or unavailable blocks. The same
window fell from seven ready peers to zero, so it is explicitly not sustained
multi-peer evidence. Debug qualification subsequently showed six authenticated
public peers timing out without serving an assigned historical body while a
peer making body progress remained connected under the inactivity deadline.
This distinguishes archival-body availability from consensus or Brontide
failure; discovery breadth and sustained multi-archival-peer IBD remain open.

After adding the one-body availability probe, live diagnostics first showed
seven transport-ready peers capped at one request each. Ten seconds later six
had delivered an eligible body, four proven peers held 30--32 requests, and the
global 128-request window was full. A following 60-second window connected 584
historical blocks (9.733 blocks/s) and advanced the stored frontier 530 blocks
(8.833 blocks/s), again with zero failed or unavailable blocks. It began with
four ready peers but ended with zero and contained 12 zero-peer samples, so the
probe improves scarce-body-source allocation but does not satisfy sustained
multi-peer qualification.

## Optimization and safety boundary

Native IBD now connects a newly available full eight-block state slice directly
from the ordered validation completion path; periodic polling flushes partial
tails and provides recovery. It does not enlarge the atomic state transaction
or the global 128-body inflight limit. Body requests remain single-flight and
all reassigned responses pass the same strict validation. The shorter timeout
is an inactivity deadline: each eligible response extends the bounded batch,
while a peer that stops delivering still fails over after 15 seconds. This
changes availability failover only; it does not accept alternate consensus
data, weaken scoring, or alter authority readiness.

Each new connection starts with one body probe. Only an eligible block response
sets its diagnostic `body_available` flag and expands it to the 32-request
window. The probe is connection-local and changes scheduling capacity only;
the returned block still passes the same stateless and contextual validation.

Ordered worker-validated bodies are drained in groups of at most 32 and written
with one synchronous atomic RocksDB commit. Scheduler completion occurs only
after that transaction succeeds. The worker result is bound to the exact block
hash and height; it may skip duplicate coordinator body work only when it
covers the branch's checkpoint-derived historical validation plan. Header,
difficulty, finality, branch, contextual state, scripts, covenants, claims,
airdrops, name state, tree-root, and undo validation remain on their existing
authoritative paths. A malformed member rejects the complete pre-commit group.

Unclean startup, first startup after upgrade, and any stale or corrupt audit
checkpoint perform the exhaustive materialized-name rebuild and the
depth-sensitive reachable-union traversal of current, committed, and
interval-pinned Urkel roots. A clean shutdown now atomically binds a checksummed
audit checkpoint to the exact durable identity. When it matches, startup checks
the canonical encoding and content hash of every retained root record without
walking shared descendants or rebuilding the materialized name tree. The active
height, block/header/body, deployment, undo, root-continuity, and
snapshot-pin-to-chain audit remains exhaustive in both routes. The process
marks the database unclean before either audit starts, preventing a crash during
startup from preserving an older clean marker.

Production qualification still needs full mainnet IBD on persistent NVMe,
P50/P95/P99/max storage and compaction latency, loaded-mempool templates,
candidate-to-first-peer acceptance under WAN load, restart/reorganization
campaigns, and physical ASIC job-switch measurements.
