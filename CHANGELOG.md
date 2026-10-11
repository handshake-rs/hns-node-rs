# Changelog

All notable changes to the standalone node are recorded here. Release entries
describe source identity; they do not by themselves establish production
qualification or authorize deployment.

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
