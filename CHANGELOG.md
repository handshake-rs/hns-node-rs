# Changelog

All notable changes to the standalone node are recorded here. Release entries
describe source identity; they do not by themselves establish production
qualification or authorize deployment.

## 0.3.5 - unreleased

- Bind wallet snapshots and name-action contexts to consensus median time past.
- Reclaim never-confirmed contract capacity and safely retire completed tracked
  contracts only after canonical evidence is validated.
- Commit single-block native replay atomically.
- Retain the v0.3.4 resolver release-CI port correction.

The current source remains a release candidate until its consolidated current-
head gate and production-assurance evidence pass. Existing v0.3.4 container
examples and tags remain historical and are not relabeled as v0.3.5 artifacts.

## 0.3.4 - 2026-08-02

- Published the private loopback resolver-sidecar/container release source at
  tag `v0.3.4`.
