# Mainnet retained-horizon rollback qualification at 339660

The read-only normalized rollback comparison passed over HSD mainnet's complete
288-block retained reorganization horizon:

- horizon: `339373..=339660`
- tip: `000000000000001c2384d1b48e185a0e43696385156355862e5fc29914ca7200`
- full-state anchor: height `339654`
- pinned HSD revision: `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`

Both exporters independently validated their producer-native undo against the
same raw blocks, then emitted exact net transitions for coins, full name
states, committed roots, and airdrop positions. The complete current airdrop
field also matched and round-tripped through all retained disconnects and
reconnects. Equality at the previously qualified full-state anchor plus every
bidirectional transition proves state equality throughout the retained
horizon without copying or mutating either database.

After promotion, the installed MeshMine miner reported synchronized consensus
readiness with no blockers, template and candidate authority enabled, solved
block publication enabled, observation mode disabled, and live shadowing
disabled.
