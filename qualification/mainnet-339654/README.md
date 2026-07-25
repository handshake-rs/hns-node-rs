# Mainnet replay stopped-state qualification at 339654

Both services were stopped at the same active block:

- height: `339654`
- hash: `0000000000000012200f131c1c6cb5d51f5977564da70c4bd2857461a4a6772c`
- pinned HSD revision: `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`

The state-manifest comparison passed every component in its declared scope:
active-chain identity, the ordered physical UTXO projection, total UTXO value,
the ordered HSD-compatible `NameState` projection, the pending working Urkel
root, and the interval-committed Urkel root. The pinned live comparison at the
same block also passed all deployment and checkpoint checks.

HSD's `ChainState.coin`, `value`, and `burned` diagnostics are economic
accounting fields, not physical UTXO aggregates. In particular, a REGISTER
lineage remains burned in those counters when REVOKE removes its physical
output. The comparison therefore uses the independently scanned physical
LevelDB set. Its count, value, and digest match hsrd exactly.

This record does not promote the `historical_replay` readiness bit. The
producer-native undo encodings are intentionally different, and a normalized
retained-horizon disconnect/reconnect comparison remains required. The next
tool should derive those transitions read-only from blocks and undo records,
avoiding a second database copy and avoiding mutation of either qualified
store.
