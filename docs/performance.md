# Native synchronization and mining-path performance

Performance qualification uses release builds and never requires a running HSD
process. HSD remains only the pinned offline behavioral oracle for fixtures.

## Reproducible commands

Measure an already-running native mainnet node:

```bash
python3 scripts/measure-hsrd-native-sync.py \
  --hsrd-url http://127.0.0.1:12037 \
  --duration-seconds 60 --interval-seconds 2 \
  --output /path/to/native-sync-measurement.json
```

The sampler accepts only a literal loopback HTTP origin unless the operator
explicitly opts into a remote endpoint. It requires active-state native sync,
binds every sample to one runtime instance, rejects counter regression and any
reported runtime error, bounds response size and request time, and records:

- overall and interval P50/P95/P99/maximum header, body, state, and byte rates;
- active-state stalls, peer count/failures, failed blocks, and unavailable
  evidence;
- starting, ending, and raw samples so derived claims can be audited.

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

## Optimization and safety boundary

Native IBD now connects a newly available full eight-block state slice directly
from the ordered validation completion path; periodic polling flushes partial
tails and provides recovery. It does not enlarge the atomic state transaction
or the global 128-body inflight limit. Body requests remain single-flight and
all reassigned responses pass the same strict validation. The shorter timeout
changes availability failover only: it does not accept alternate consensus
data, weaken scoring, or alter authority readiness.

Production qualification still needs full mainnet IBD on persistent NVMe,
P50/P95/P99/max storage and compaction latency, loaded-mempool templates,
candidate-to-first-peer acceptance under WAN load, restart/reorganization
campaigns, and physical ASIC job-switch measurements.
