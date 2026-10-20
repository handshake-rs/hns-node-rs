# Changelog

All notable changes to the standalone node are recorded here. Release entries
describe source identity; they do not by themselves establish production
qualification or authorize deployment.

## 0.3.13 - 2026-10-19

- Publish Linux release binaries and container images with source-bound OCI
  version and revision labels. Node consensus and ShakeScape behavior remain
  the same as 0.3.12.

## 0.3.12 - 2026-10-19

- Accept a validated replay of a canonical active block whose raw body was
  intentionally pruned, while still rejecting missing raw bodies for retained
  blocks or records that do not match the canonical header and pruning checkpoint.

## 0.3.11 - 2026-10-19

- Add an optional loopback-only, read-only HTTP snapshot of reachable signed
  ShakeScape direct HNS/BTC offers for a separately hosted offer board. Keep
  the existing node RPC listener and swap routing separate from this feed.
- Continue accepting competing direct-offer responses until the publisher
  countersigns a session, so a stalled first responder cannot reserve an offer.
- Refresh the locked Tokio and serde_json dependencies used by the board HTTP
  endpoint within their existing compatible version ranges.
- Update the locked Hickory resolver family to `0.26.3`, addressing the
  published resolver advisories affecting the separate `hns-resolverd` binary.

## 0.3.10 - 2026-10-11

- Open Windows storage directories with the directory-handle flag so native
  `hsrd` can validate and recover persisted segment and name-page state. Reject
  missing capacity-check paths on Windows before querying their volume.

## 0.3.9 - 2026-10-10

- Federate signed ShakeScape name listings, direct HNS/BTC offers, cancellations,
  and swap-session routing among rendezvous nodes. Board and session messages
  retain their original signatures and expiry checks across federation links.
- Discover and connect to other ShakeScape rendezvous nodes automatically from
  `NETWORK | SHAKESCAPE` address gossip when the complete ShakeScape relay
  roles are enabled, including the existing individually configured relay
  profile. Reserve outbound capacity for those links while keeping optional
  explicitly configured federation peers.

## 0.3.8 - 2026-09-28 (prerelease)

- Consume the coherent `hns-rs 0.5.0` protocol graph. Route signed direct-offer
  acceptances from the responding swap maker to the offer setter, then route
  the maker's proposal and the setter's countersigned session under the new
  HNS/BTC role model.
- Expose the authenticated canonical-block wallet-chain feed without the
  chain-wide `--wallet-index`; account-local clients validate the returned
  block bytes and maintain their own durable scan cursor.
