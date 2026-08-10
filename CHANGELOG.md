# Changelog

All notable changes to the standalone node are recorded here. Release entries
describe source identity; they do not by themselves establish production
qualification or authorize deployment.

## 0.3.5 - unreleased

- Enable outbound standard Handshake P2P, active-state synchronization, and
  fixed-seed/GETADDR discovery in the standalone process by default, with
  explicit `--no-native-sync` and `--no-p2p-discovery` opt-outs. HIP-76
  requester policy remains `Auto`; its plaintext output role remains off.
  The process-wide requester selection now has checksummed, network-bound,
  atomic policy/floor persistence. `--no-hip76-requester` records a durable
  opt-out, `--hip76-requester` explicitly restores `Auto`, and an absent flag
  preserves the saved choice while every live and future peer inherits it.
- Enable the HIP-77 ODoH requester policy by default. Requests use only ready,
  exact-Denuo-V1-negotiated, Brontide-authenticated peers advertising both the
  Denuo and ODoH services with matching network and genesis evidence,
  reject proxy/target identity collisions, and carry bounded correlation and
  deadlines through socket-write acknowledgement. Target-signed public
  configuration records use a checksummed, network-bound, anti-rollback cache
  with atomic cache/policy generation and trusted-time floors. Opt-out and
  revocation policy survive restart;
  live request IDs and HPKE state are never persisted. Proxy, target, and DNS
  output provider roles remain unavailable. `--no-odoh-requester` is the
  explicit requester opt-out, `--odoh-requester` explicitly reverses a saved
  opt-out, and an absent flag preserves the durable choice.
- Enable HIP-78 HNSR requester and opaque-relay policy by default with
  independent `--no-hnsr-requester` and `--no-hnsr-relay` opt-outs. Exact
  Brontide/Denuo/network/genesis admission, explicit `HNS_NODE_V1` or
  `HNS_WEB_V1` circuit profiles, actual socket-write acknowledgements,
  connection-bound cleanup, and atomic
  checksummed state/floor persistence fail closed. Relay service advertisement
  additionally requires `--hnsr-relay-address`; endpoint, rendezvous, and
  plaintext roles remain unavailable. Symmetric `--hnsr-requester` and
  `--hnsr-relay` flags explicitly reverse saved opt-outs; absent flags preserve
  the durable selections without lowering the node's live capability ceiling.
- Publish key-bearing HSD fixed seeds, canonical negotiated-peer evidence, and
  a bounded raw authenticated extension exchange from `hns-p2p` for browser
  and mobile adapters. Brontide now uses portable RustCrypto
  ChaCha20-Poly1305; standalone `hns-p2p` no longer enables OpenSSL consensus
  verifiers.
- Bind wallet snapshots and name-action contexts to consensus median time past.
- Add a script-free authenticated wallet `chain_snapshot` read that atomically
  returns the durable chain epoch and exact tip, allowing a bound genesis check
  before any derived script identity is disclosed. The existing `chain_tip`
  result is unchanged.
- Record that the code-bearing 0.3.5 candidate at
  `2b267ffe7fc6f9929063a18986a83b566d02ae6d` passed its exact-revision CI,
  container, and CodeQL workflows. Release and production availability remain
  blocked on the documented live storage/reorganization, adversarial,
  deployment-scale, joined-wallet, and canonical dependency gates.
- Reclaim never-confirmed contract capacity and safely retire completed tracked
  contracts only after canonical evidence is validated.
- Consume canonical HNS resource parsing from the exact `hns-rs` source rather
  than retaining a second resolver-local codec. Advance that coherent source
  to the dated 0.2.0 publication-source commit
  `b24b66c382de53330ec21dd3137e056a2bea3e2d`, including the HNSA/HNSR
  selection/admission correction and linked-covenant output validation. The
  source passed its consolidated CI, CodeQL, and 17-crate publication
  preflight; its crates and release tag remain unpublished. Endpoint and
  rendezvous roles remain unavailable; a newer protocol pin does not enable
  either role.
- Commit single-block native replay atomically.
- Streamline bounded active-state persistence across the store, name-page,
  state, and Urkel layers. Only committed blocks contribute workload and
  mempool effects, and a staged-effect truncation feeds its accepted direct-
  extension prefix back to the native-sync slice tuner instead of retrying a
  known-excessive span. This is a persistence/performance change, not a change
  to consensus rules or release status.
- Defer routine full name-page generation rewrites while native sync is
  catching up. Synchronized nodes retain the sixteen-segment reclamation
  cadence, while IBD and native-sync startup use a 128-segment emergency bound
  instead of repeatedly pausing replay every 5,760 blocks.
- Keep an active-state batch limit stable for sixteen full successful slices
  after an atomic-effect-budget retry, avoiding the one-block/two-block
  oscillation that repeatedly discarded expensive replay work.
- Record only net `NameState` changes in new block undo and the pending
  interval accumulator. Older 0.3.5 candidate builds could record valid
  no-op `BID`/`REDEEM` touches in undo without counting them in the
  accumulator, causing a later restart audit to fail. Startup now recognizes
  only the strictly validated accumulator-subset form of that mismatch,
  reconstructs the canonical raw-undo counts under the existing resource
  limits, verifies the committed boundary root, and atomically replaces only
  the accumulator key so legacy disconnect remains exact. It does not rewrite
  undo, `NameState`, authenticated-tree, or chain-index records.
- Retain the v0.3.4 resolver release-CI port correction.

The current source remains a release candidate until its consolidated current-
head gate and production-assurance evidence pass. Existing v0.3.4 container
examples and tags remain historical and are not relabeled as v0.3.5 artifacts.

## 0.3.4 - 2026-08-02

- Published the private loopback resolver-sidecar/container release source at
  tag `v0.3.4`.
