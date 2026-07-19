# Fast Sync

Sync is headers-first, block-parallel, and state-ordered. The node should maximize network and disk throughput while preserving hsd-compatible validation behavior.

## Header Phase

- Maintain many outbound peers with address-group diversity.
- Start with static seeds, DNS seeds, persisted peers, and optional operator peers.
- Handshake with version/verack, record advertised height, and request `sendheaders` when supported.
- Request headers using a locator generated from the best validated header chain.
- Validate every received header for length, hash, previous link, PoW, mainnet difficulty, checkpoint ancestry, timestamp policy, and duplicate behavior.
- Compare tips across peers. Do not trust a single peer for chain tip, snapshots, proofs, or block data.
- Persist headers in batches and promote the best header chain by chainwork.

## Block Download

- Create a download frontier from validated headers whose bodies are missing.
- Assign blocks to peers with bounded in-flight windows by peer quality, recent throughput, stall history, and inventory evidence.
- Request blocks using `getdata`; support `inv`, `notfound`, and direct block responses.
- Prefer diverse peers for high-value ranges and re-request stalled blocks from another peer.
- Keep orphan blocks bounded by count, bytes, and age.
- Store raw blocks before validation so a restart can resume without re-downloading.

## Validation Pipeline

```text
network tasks -> raw block queue -> parse/cheap checks -> script workers -> ordered state connector -> batched store flush
```

- Network tasks never validate or write state inline.
- Parse and cheap block checks can run in parallel.
- Script checks can run in parallel when inputs are available or under a validation cache.
- Final UTXO and name-state mutation is ordered by active-chain height.
- Reorg handling pauses the ordered connector, disconnects to the fork point, then connects the stronger branch.

## Database Batching

- Batch block index, UTXO, name-state, undo, and tx-index writes.
- Flush by maximum batch bytes, block count, validation latency, or shutdown.
- Keep undo data before promoting the active tip.
- Track DB write latency and compaction stalls as first-class sync metrics.

## Peer Scoring

- Reward peers that serve valid data quickly.
- Penalize stale tips, timeouts, duplicate-only header pages, malformed frames, invalid headers, invalid blocks, wrong inventory, and repeated stalls.
- Ban or cooldown peers for malformed consensus data.
- Keep transient failures from permanently exhausting the peer table.

## Snapshots And Assume-Valid

- Default mode validates from genesis.
- Assume-valid mode may defer expensive script checks for ancestors of a configured hsd-matched hash, but consensus data is eventually verified in the background.
- Checkpointed snapshot mode imports UTXO and name state at a signed height, verifies the header chain and manifest, then validates blocks forward from the snapshot.
- Trusted snapshot mode skips eventual replay only when explicitly configured by the operator.
- Snapshot chunks must be hash-checked and fetched from more than one source when available.

## Metrics

Expose at least:

- headers per second;
- blocks per second;
- bytes per second;
- validation queue depth;
- script worker queue depth;
- state connector height;
- DB write latency;
- cache hit/miss and dirty bytes;
- peer stalls, bans, and re-requests;
- snapshot import progress;
- background verification progress.
