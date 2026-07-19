# Bounded control and differential API

Mining does not use this interface. MeshMine and `hsrd` communicate through
native Rust types and bounded channels.

The HTTP/JSON surface is retained only for operator diagnostics, health checks,
fixture comparison, and emergency control. It binds to loopback by default,
has bounded requests/responses and timeouts, authenticates mutations, and may
read immutable snapshots only.

## Required reads

- network, genesis, best hash, height, bits, chainwork, sync/prune status;
- exact header/block lookup needed by differential tests;
- UTXO/name-tree root and deployment commitments needed for parity evidence;
- mempool/template generation and peer/relay health;
- per-lane queue, storage, tip-to-job, and candidate-publication metrics.

## Required mutations

- submit a test/raw block through the same consensus candidate path;
- add/remove an operator-pinned peer;
- initiate graceful shutdown or a bounded diagnostic snapshot.

Wallet, signing, domain actions, DNS, explorer/address queries, public mining
RPC, and broad hsd tooling compatibility are deliberately unsupported.
