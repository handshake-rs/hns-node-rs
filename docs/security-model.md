# Security Model

`hsrd` is designed to verify consensus locally. Peers, snapshots, control clients, MeshMine inputs, and local caches are untrusted unless explicitly promoted by validation. Until the parity gates pass, `hsd` remains the production oracle and `hsrd` has no authority.

## Trust

The current foundation verifies exact network/genesis identity, proof-of-work,
derived unsigned 256-bit header chainwork, HNS difficulty transitions,
median/future timestamp bounds, block commitments, bounded primitive encoding,
non-contextual covenant shapes/counts, and a UTXO/undo path that rejects
missing/double/immature/inflationary spends and unspent-output collisions. The
path also enforces the ordinary coinbase subsidy-plus-fee ceiling and absolute
height/time locktime finality. Claim/airdrop issuance fails closed until its
proofs and historical datasets are verified. Production authority additionally
requires checkpoints and deployments, exact claim/airdrop accounting, relative
sequence locks, complete script rules, covenant/name-state transitions, Urkel
roots, historical exceptions, atomic reorgs, and snapshot manifests. Those
unfinished checks are release blockers, not trusted inputs.

The node does not trust one peer for headers, blocks, proofs, snapshots, mempool data, or chain tips. It does not trust cached UTXO or name state after a crash until recovery checks complete.

## Failure Policy

- Invalid consensus data fails closed and marks the source peer.
- Malformed parser input fails closed without panics.
- Snapshot mismatch fails closed before state import.
- Database recovery mismatch fails closed and requires reindex or operator action.
- The control API never labels data confirmed unless the active chain state has validated it.
- Trusted snapshot mode is disabled unless explicitly configured.

## Review Checklist

- Parser lengths are bounded and fuzzed.
- P2P payloads reject wrong network magic and oversize messages.
- Async socket tasks do not run validation or database writes inline.
- Header sync validates difficulty and PoW before storage.
- Block sync stores raw bytes but does not promote a block before validation.
- Reorg code writes undo data before active-tip promotion.
- Name-state updates are derived from covenants and block order, not from peer proofs.
- Peer addresses are advisory, service-filtered, deduplicated, and scored.
- Peer bans distinguish malformed consensus data from transient network failure.
- Snapshot chunks are hash-checked and manifest-checked.
- Assume-valid and snapshot modes are visible in diagnostics and metrics.
- Control API mutations require authentication and bind to loopback by default.
- Control and native MeshMine inputs and outputs are bounded.
- No wallet, key-management, DNS, or domain-action surface is linked into the node.
- No unbounded memory growth from orphan blocks, orphan transactions, peer inventory, templates, publication attempts, or control requests.
- No SQLite state path for consensus-critical data.
