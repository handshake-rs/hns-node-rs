# Changelog

All notable changes to the standalone node are recorded here. Release entries
describe source identity; they do not by themselves establish production
qualification or authorize deployment.

## 0.3.8 - 2026-09-28 (prerelease)

- Consume the coherent `hns-rs 0.5.0` protocol graph. Route signed direct-offer
  acceptances from the responding swap maker to the offer setter, then route
  the maker's proposal and the setter's countersigned session under the new
  HNS/BTC role model.
- Expose the authenticated canonical-block wallet-chain feed without the
  chain-wide `--wallet-index`; account-local clients validate the returned
  block bytes and maintain their own durable scan cursor.
