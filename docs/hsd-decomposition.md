# hsd decomposition for a mining full node

This is the source-level boundary for replacing `hsd` without cloning its
product surface. It was derived from the pinned production/oracle checkout at
commit `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.

## Port exactly or reproduce with differential evidence

| hsd source | hsrd owner | Why mining needs it |
|---|---|---|
| `lib/protocol/consensus.js`, `network.js`, `networks.js`, `genesis.js`, `policy.js` | `hns-consensus`, `hns-primitives` | Network constants, genesis, subsidy, limits, deployments, targets, and standard relay/template policy. |
| `lib/primitives/{abstractblock,block,headers,tx,input,output,outpoint,coin,covenant,claim,airdropkey,airdropproof,invitem}.js` | `hns-primitives` | Exact wire/hash/sighash subjects and every block-contained object. |
| `lib/script/*` | `hns-consensus` | Complete input verification is consensus-critical even though `hsrd` owns no keys. |
| `goosig@0.11.0/src/goo/*` (HSD dependency) | `hns-goosig`, `hns-consensus` | Historical airdrop allocations use GooSig; the exact pinned C verifier is wrapped behind a verification-only Rust API. |
| `bns/lib/{ownership,dnssec}.js`, `bcrypto/lib/gost94.js` (HSD dependencies) | `hns-primitives`, `hns-consensus` | CLAIM trust-chain parsing, signing policy, all DS digests, and legacy GOST94/CryptoPro are consensus-critical. |
| `lib/covenants/{rules,namestate,namedelta,undo,view,ownership,reserved,locked,bitfield}.js` plus the committed name/lockup data | `hns-consensus`, `hns-state`, `hns-urkel` | Claims, airdrops, auctions, renewals, transfers, revocations, reserved names, historical lockups, and name-tree transitions determine block validity and the next header root. |
| `lib/coins/{coins,coinentry,coinview,compress,undocoins}.js` | `hns-state`, `hns-store` | UTXO lookup, mutation, compression, and disconnect evidence. |
| `lib/blockchain/{chain,chaindb,chainentry,common,records,layout}.js` | `hns-chain`, `hns-state`, `hns-store`, `hns-urkel` | Contextual validation, chainwork, MTP/difficulty, deployments, side chains, reorgs, UTXO/name commits, pruning, and crash recovery. |
| `lib/blockstore/*` | `hns-store` | Bounded raw-block retention and pruning. The JavaScript/LevelDB layout need not be copied, but its recovery semantics do. |
| `lib/net/{framer,parser,packets,netaddress,peer,pool,hostlist,lookup,brontide,slidingwindow}.js` | `hns-p2p`, `hns-sync` | Exact HNS framing, peer handshake, inventory/data flow, sync, serving, scoring, stall/orphan bounds, and relay. |
| `lib/mining/{miner,template,common}.js` | `hns-mining` | Version, MTP, next target, live Urkel root, coinbase/claim/airdrop construction, package ordering, weight/sigops/update limits, and exact header/body assembly. |

The crucial observation is that `lib/blockchain/chain.js` directly imports
scripts, covenant rules, name state, ownership proofs, airdrop proofs, and coin
views. Those are mining dependencies, not domain-product features. Removing
them would allow an invalid state root or transaction into a template.

Likewise, `lib/mining/miner.js` obtains version, MTP, deployments, next target,
and the live Urkel root from the chain before assembling claims, airdrops, and
ordinary transactions. A fast template engine may cache and incrementally
update those values, but it may not approximate or omit them.

## Retain a smaller mining-specific form

| hsd source | Lean treatment |
|---|---|
| `lib/mempool/mempool.js`, entry types, contract state | Retain validation, conflicts, ancestors/descendants, claims, airdrops, covenant/update limits, fee/weight ordering, connect/disconnect/reorg reconciliation, and bounded orphans. Remove wallet/address indexes and broad query conveniences. |
| `lib/mempool/fees.js` | Historical fee estimation is optional. Exact entry fees and package rates used by template ordering are mandatory. |
| `lib/net/bip152.js` | Compact-block support is a later propagation optimization, not a prerequisite for initial correctness. Full block relay remains mandatory. |
| `lib/workers/*` | Preserve bounded parallel stateless verification, but use native Rust worker pools and immutable inputs rather than porting the child-process protocol. |
| `lib/blockchain/migrations.js`, `lib/migrations/*` | Implement explicit `hsrd` schema migrations and import tools. Do not inherit unrelated `hsd` product schema merely for compatibility. |
| `lib/node/fullnode.js` | Recompose only chain, store, minimal mempool, P2P/sync, mining, metrics, and bounded control. Its DNS, HTTP, and broad RPC components are separable constructors and are not mining dependencies. |
| `lib/node/rpc.js`, `http.js` | Keep a small authenticated/local diagnostics, differential, and operator-control surface. Mining never traverses it. |

## Exclude from the production binary

- `lib/wallet/*`, `lib/client/wallet.js`, `lib/hd/*`,
  `lib/primitives/keyring.js`, and `lib/utils/coinselector.js`.
- `lib/dns/*` servers, DNSSEC/DANE presentation, and recursive resolution.
  Consensus retains only the name/resource bytes and commitments it actually
  validates.
- `lib/ui/*`, browser entrypoints, desktop/mobile/web product code, and URI UX.
- Address/explorer indexes, wallet RPCs, broad public RPC compatibility, SPV
  node, seeder daemon, and bloom-filter serving.
- The CPU miner loop as a production data path. Its template/job semantics are
  useful differential references; ASIC jobs use the native prepared-job API.

## Differential extraction order

1. Freeze every primitive, hash, target, genesis, and network constant.
2. Port header/transaction/script checks and generate positive and mutated
   negative fixtures from the exact `chain.js` rejection sites.
3. Port claims, airdrops, covenant/name state, historical exception databases,
   UTXO/name undo, and Urkel roots.
4. Replay connect/disconnect/reorg sequences and compare accept/reject,
   chainwork, UTXO outcome, name-tree root, and undo behavior at each step.
5. Port peer/sync behavior and run a live shadow node without authority.
6. Port template assembly and compare coinbase, ordered transactions, roots,
   weight, sigops, target, version, and minimum time byte-for-byte.
7. Enable the native MeshMine bridge only on a shadow-agreeing committed tip;
   promote authority only after the removal gates pass.

This is a semantic reimplementation, not a line-for-line translation. Rust may
replace JavaScript locks, caches, workers, databases, and event emitters, but
every consensus-visible outcome and HNS wire byte must remain identical.
