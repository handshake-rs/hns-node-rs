# Testing strategy

## Consensus fixtures

Generate versioned fixtures from the pinned `hsd` oracle for valid and invalid
headers, transactions, scripts, covenants, claims, airdrops, blocks, name-state
transitions, Urkel roots, undo records, deployments, difficulty boundaries, and
reorganizations. Every fixture records the oracle revision and network.

## Differential replay

For every mainnet block and mutation corpus entry compare accept/reject result,
best hash, height, bits, chainwork, UTXO outcome, name-tree root, deployment
state, undo/disconnect result, and reconnect result. A mismatch fails closed and
never becomes an undocumented compatibility exception.

## Integration and fault tests

- Multiple fixture peers, parallel download, stalled/malicious peer replacement,
  orphan bounds, serving, and reconnect.
- Restart/crash at raw-block, validation, undo, state-batch, tip-promotion,
  template, and publication-intent boundaries.
- Reorganizations across covenants, deployments, claims/airdrops, and pruning.
- Mempool conflicts/dependencies/eviction plus template replacement.
- Tip commit to job activation and candidate receipt to first accepted relay.
- Priority isolation while sync, compaction, diagnostics, and slow peers saturate.

## Fuzzing

Fuzz all P2P, header, transaction, block, script, covenant, resource, Urkel,
snapshot, control-message, and native MeshMine-boundary parsers. Corpus inputs
must remain bounded before allocation.

## Performance evidence

Report count, P50, P95, P99, maximum, failures, and unavailable evidence for
header/block validation, ordered connect/disconnect, storage commits, IBD,
tip-to-job, candidate validation, and per-target publication. Mean throughput
alone is not a release gate.
