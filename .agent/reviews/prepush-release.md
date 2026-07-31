# Pre-push release and fresh-mainnet-sync audit

Audit captured at `2026-07-31T12:22:36Z`. This was a read-only operational
review except for this assigned report. No release command, Git mutation,
publication, target cleanup, or sync launch was performed by this reviewer.

Host-path placeholders used below are intentionally non-identifying:
`<SHARED_AUDIT_TARGET>` is the exact shared Cargo target audited on the host;
`<QUALIFICATION_FILESYSTEM>` is the filesystem selected for the campaign;
`<FULL_SYNC_DATA_ROOT>` and `<FULL_SYNC_EVIDENCE_ROOT>` are the two intended
fresh campaign roots; and `<WALLET_BACKUP_ROOT>` is the private wallet-backup
directory.

## Verdict

**Not release-ready and not production-complete.** The 0.2.0 workspace and both
lockfiles are internally coherent, CI and the assurance/full-sync runners are
substantive and fail closed, and the intended Git publication scope is clear.
However, the required historical commit/push-before-release-profile ordering
has already been violated by an earlier release-profile compilation attempt.
The current candidate is also uncommitted/unpushed, the host currently fails
the 160,000,000,000-byte full-sync launch gate, no fresh mainnet campaign has
started, no external production record exists, and local-state custody plus a
tested wallet restore remain unproved.

These are operational/evidence blockers; they do not negate the software work.
They do prohibit a tag, hosted release, crate publication, or statement that
production hardening is complete.

## Blocking findings

### R0 — Historical release-order exception: release profile was entered before commit/push

The active branch is `agent/production-hardening-0.2.0`, but `HEAD` remains the
unchanged base commit `1216ecc267dabdbc02eb809748376e68fc51d564`, the branch has
no upstream, and the complete candidate is still a large dirty/untracked
worktree. The 0.2.0 workspace edit was timestamped later than an existing
release-profile compilation:

- `<SHARED_AUDIT_TARGET>/release` contains 232
  files timestamped from `2026-07-31T01:43:52.612473426` through
  `2026-07-31T01:44:29.192650109`;
- those files include
  `release/.fingerprint/hns-primitives-151d67d41f7fe386/invoked.timestamp`, a
  release-profile `hns-primitives` fingerprint, and release `.rmeta` output;
- `Cargo.toml`, which now carries 0.2.0, was modified at
  `2026-07-31T04:06:38.538664155-07:00`;
- there is no completed `release/hsrd` executable in that stale profile.

This proves at least one release-profile compilation was attempted before the
required candidate commit and push. The coordination history also records
earlier release checks/Clippy at `.agent/coordination.json:70` and
`.agent/coordination.json:244`. It is therefore impossible to claim that the
strict historical boundary was perfectly observed.

Required recovery/representation:

1. Disclose this as a process exception; do not describe the old artifacts as
   release qualification.
2. Do not reuse any file in that stale release profile.
3. Finish all debug/static checks, commit every intended file, push the exact
   candidate, and create the draft PR before another release-profile command.
4. Run post-push release work in a fresh commit-specific target. If a fix is
   needed, make and debug-test the fix, commit and push it, discard that failed
   target, and begin release qualification again for the new pushed commit.

The assurance script's clean-tree guard supports the corrected process:
`scripts/run-production-assurance.sh:140-164` captures source identity and
rejects a dirty scheduled/release run; lines 1716-1730 reject source changes
during the software gates.

### R1 — Current candidate has not crossed the required Git boundary

At audit time, `git status -sb` showed the branch with all production changes
modified or untracked, including `.agent/`; `git branch -vv` showed no upstream.
The local `HEAD` and `origin/main` were both the base commit above. Thus 0.2.0
exists only in the worktree, not in a pushed candidate commit.

No local release test may start in this state. The required first publication
is the intentionally scoped branch commit and push plus a draft PR. The CI
workflow runs the main qualification job for `pull_request`
(`.github/workflows/ci.yml:3-9,18-39`), so opening the draft PR naturally causes
the first hosted release-profile qualification only after the push. Every
release-discovered fix must be a new pushed commit before its release rerun.

### R2 — The host currently fails the full-sync disk launch gate

At `2026-07-31T12:22:36Z`:

- `<QUALIFICATION_FILESYSTEM>` had **140,671,668,224 bytes available**;
- the exact shared target occupied **24,368,238,592 allocated bytes**;
- their arithmetic sum is **165,039,906,816 bytes**, only
  **5,039,906,816 bytes** above the 160,000,000,000-byte launch requirement.

The projection is not a guarantee because tests and a new release build can
consume more space. The full-sync preflight correctly requires
`limit_bytes + filesystem_reserve_bytes` available at launch
(`scripts/run-full-sync-qualification.sh:940-946`), so it will currently refuse
the default 150,000,000,000 + 10,000,000,000 profile.

The target was actively in use at audit time by a debug `cargo test` process
and its `rustc` children writing the target's `debug/` subtree. It must not be
removed while any such process is live.

Safe recovery requirements:

- wait for every process using the target to exit and retain its test result;
- build post-push in a fresh, explicit commit-specific release target;
- copy the final `hsrd` executable to a private, nonsymlink, non-target artifact
  path and fingerprint that copy before cleaning either target;
- verify each deletion target by exact `realpath`, type, owner, device/mount,
  lack of symlinks/mount nesting, and lack of live users; delete only the two
  explicit build-target paths, never a home or cache root, `$HOME`, `~`, or an
  unresolved variable/glob;
- re-run `df -B1` after cleanup and require an observed value of at least
  **160,000,000,000 bytes** immediately before launch. If it is lower, do not
  start.

Deleting only the old shared target may be insufficient after a new release
build. The fresh build target must also be removed after the external binary
copy is verified.

### R3 — The selected release executable must survive target cleanup

The documented example passes
`/ABS/checkout/target/release/hsrd` directly to the long-running supervisor
(`docs/production-assurance.md:168-188`). That path would disappear when this
host performs its required build-target cleanup. The runner deliberately binds
the executable's path, file identity, and SHA-256 at preflight and resume
(`scripts/run-full-sync-qualification.sh:448-459,1239-1311`) and revalidates the
running image and selected file at every sample
(`scripts/run-full-sync-qualification.sh:2258-2280`). It cannot resume if its
selected executable has been removed or copied later.

For this campaign, the post-push sequence must therefore be:

1. build in a fresh release target;
2. copy `hsrd` outside all build targets into a private artifact location;
3. verify the copied bytes against the build output and record SHA-256, size,
   mode, source commit/tree, Rust/Cargo versions, and exact build command;
4. use the copied path as `--binary` for the first launch and every resume;
5. only then remove the exact build targets and remeasure free space.

The full-sync runner records the selected copy in `build-provenance.json`, but
truthfully labels this binding as not proving reproducibility
(`scripts/run-full-sync-qualification.sh:1018-1064`). Production evidence also
needs the separate typed `hsrd_build_manifest` specified at
`docs/production-assurance.md:352-392` and checked at
`scripts/run-production-assurance.sh:441-570`.

### R4 — A fresh non-pruned mainnet campaign has not started

Both intended fresh roots were absent at audit time:

- `<FULL_SYNC_DATA_ROOT>`;
- `<FULL_SYNC_EVIDENCE_ROOT>`.

Port 12037 had no listener. The HSD user service was disabled and in failed/not
running state, so it was not repopulating the freed chain data. No private RPC
authorization file has yet been selected and bound to a campaign.

The supervisor implements the requested run correctly:

- defaults are a 150,000,000,000-byte cutoff and a separate
  10,000,000,000-byte reserve (`scripts/run-full-sync-qualification.sh:10-16`);
- `run` accepts only canonical empty nonsymlink data/evidence roots, outside and
  disjoint from the repository (`:335-412,926-980`);
- the fixed node profile is mainnet, native authority/sync, `Sync` durability,
  and archive storage (`:826-851`), and the recorded schema declares
  `full_non_pruned`, `archive`, and `pruning_enabled: false` (`:1138-1163`);
- completion requires five consecutive genuinely synchronized samples by
  default and a graceful zero-status exit (`:1516-1535,2326-2438,2729-2740`);
- periodic/final storage uses the maximum of apparent bytes, allocated bytes,
  and positive filesystem-used delta, while the reserve is checked separately
  (`:2290-2348,2950-2960`);
- the runner accurately states that sampling is not a kernel quota or proof of
  unobserved transient peaks (`:1187-1205,3099-3110`).

The auth design keeps the value out of argv: only the authorization-file path
is passed (`:826-851`), RPC calls pipe the header to curl (`:1475-1491`), the
file must be private/owned/single-link (`:499-530`), and a boundary-aware,
bounded rotating log scanner redacts disclosure and fails closed on mutation or
scanner failure (`:1537-1937,2673-2699`). Use a dedicated 0700 directory and an
exact 0600, one-line printable-ASCII file; never print or record the value.

Resume is appropriately identity-bound and rejects live old processes,
mismatched binary/auth/configuration, terminal integrity classifications,
symlinks, sample-chain mismatch, exhausted disk headroom, or more than 32
attempts (`:1239-1437`). `status` is read-only and process-aware
(`:3184-3209`); `stop` signals only a strongly matched runner/child
(`:3211-3239`). These controls are ready, but their availability is not a
completed sync.

### R5 — All seven external production gates and custody evidence remain open

A bounded search under the operator home directory found no
`release-summary.json` and none of the seven required external record
filenames. The verifier requires exactly:

- production-scale pruning;
- RocksDB process fault injection;
- sustained reorganization/partition;
- WAN/load latency;
- physical gateway/ASIC;
- long-duration multi-peer operation;
- mempool/template/publication differential.

Their exact filenames are enumerated in
`scripts/run-production-assurance.sh:197-206`; missing records fail at
`:308-327`. Every record must match the exact candidate commit/tree, share one
actual typed `hsrd` binary and build manifest, hash typed campaign inputs, have
independent operator/reviewer identities, and satisfy its minimums
(`:328-570,628-901`). The source docs accurately retain the scale/duration
minimums at `docs/production-assurance.md:433-580`.

The release tier is deliberately conjunctive: it first requires a clean tree,
creates fresh software evidence, verifies all external records, and writes
`release-summary.json` only on complete success
(`scripts/run-production-assurance.sh:1690-1814,1816-1885`). With the external
records absent, that command cannot truthfully pass. Run `verify-external`
before committing hours to the full release tier when evidence collection is
eventually complete.

There is also no reviewed exclusive-custody record for the live data root,
external page/segment paths, privileged writers, maintenance identities, and
evidence reviewer boundary. This remains an independent production blocker as
documented at `docs/production-assurance.md:145-164,595-599`.

Even a successful fresh archive sync remains provisional: the runner labels a
clean completion `completed_provisional_unverified_reproducible_build_binding`
(`scripts/run-full-sync-qualification.sh:2962-2971`) and explicitly excludes a
pruned comparison and reproducible-build proof (`:3131-3144`). The pruning
campaign must additionally supply reviewed peak accounting because periodic
sampling can miss transient allocation (`docs/production-assurance.md:232-240`).

### R6 — HSD deletion is backed up and byte-verified, but restore is untested

`<WALLET_BACKUP_ROOT>/BACKUP_MANIFEST.txt` records a stopped
copy of 15 wallet files totaling 13,814,350 bytes and normalized content digest
`1bab303e4a32184f241d9fac6deef1d15f2d783302b1e9cb245dad8a535d2e26`.
At audit time the source and backup each still contained 15 files/13,814,350
bytes and `diff -qr --no-dereference` returned zero. The backup parent is mode
0700, so its more permissive nested modes are not traversable by other users.

The HSD `blocks`, `chain`, and `tree` directories and the previous hsrd data root
are already absent, matching the operator-approved space reclamation. However,
the manifest records copy/digest verification, not a tested wallet restore.
The repository correctly warns that a wallet copy alone does not prove
recoverability (`docs/production-assurance.md:242-246,471-476`). Preserve both
source wallet and backup; do not perform further HSD deletion or overwrite until
a restore test and rollback/retention record exist. This blocks a claim of a
fully qualified destructive rollback plan, though it does not block starting
the separately scoped fresh hsrd archive after the disk gate passes.

## Controls that passed this audit

### Version and lock coherence

- `Cargo.toml:22-26` sets workspace version `0.2.0` and `publish = false`.
- All 15 local workspace packages use `version.workspace = true` and
  `publish.workspace = true`; locked `cargo metadata --no-deps` resolved all 15
  to exactly 0.2.0 with `publish: []`.
- `fuzz/Cargo.toml:1-9` remains intentionally private at 0.0.0.
- Locked root and fuzz metadata both resolved successfully under Rust 1.89.0.
  Local packages in both locks resolve to 0.2.0; remaining `hns-*` 0.1.0 entries
  are pinned external `hns-rs` Git dependencies, not stale local packages.
- SHA-256 identities at audit time were:
  `Cargo.toml` `a2b860d59ee213a3b704556286127157e52a9cf73a2b6b6e46f25e969e53746e`,
  `Cargo.lock` `442efd764a6c7e7bc3b3b1dea560a9c6c4f26ca00964c9092364f6a21e5e8935`,
  and `fuzz/Cargo.lock`
  `85226d0e88f3e7048ba01a9b08b7f44c3b97e52c6b9940aabf0671c66b97881c`.
- Runtime version surfaces derive from `CARGO_PKG_VERSION` at
  `crates/hns-p2p/src/constants.rs:11`, `crates/hns-rpc/src/lib.rs:10,633`, and
  `crates/hns-node/src/main.rs:428-431`.

### CI and software-assurance coverage

- The normal CI job installs pinned Rust 1.89.0 and cargo-deny, then runs
  `scripts/check.sh` (`.github/workflows/ci.yml:18-39`). RustSec audits both
  lockfiles independently (`:41-61`).
- `scripts/check.sh:10-27` checks both locked graphs, verifier self-test,
  dependency policy, formatting, every fuzz target's debug build, strict
  all-feature Clippy, all-feature/no-default tests, optimized all-target build,
  deterministic performance, and live two-node regtest.
- Scheduled/manual assurance installs pinned stable/nightly and cargo-fuzz
  0.13.2, runs three minutes per each of ten targets plus persistent
  RocksDB/Sync performance, and retains evidence for 30 days
  (`.github/workflows/ci.yml:63-98`). It is correctly excluded from ordinary PR
  runs and is software evidence only.
- Release assurance refuses less than 1,800 fuzz seconds per target
  (`scripts/run-production-assurance.sh:66-87`) and uses the persistent
  4,096-setup/100-measured RocksDB/Sync scenario
  (`:911-939,941-1084,1690-1713`).
- The sustained-fuzz runner pins ten explicit targets and cargo-fuzz 0.13.2,
  checks actual wall-clock duration, records not-run targets, hashes logs/crash
  artifacts/corpora, and fails on tool drift or source changes
  (`scripts/run-sustained-fuzz.sh:5-25,245-355,406-524`).
- All four reviewed shell entrypoints passed `bash -n`; `scripts/check.sh` also
  passed POSIX `sh -n`. `git diff --check` passed at the audit snapshot.

### Publication scope

Every workspace crate is non-publishable through Cargo, so `cargo publish` is
neither needed nor authorized for 0.2.0. With all external production gates
open, no Git tag or GitHub Release is justified. The correct publication now is
only the pushed candidate branch plus a draft PR. A later hosted release must
remain withheld until the exact pushed commit has a passing release bundle and
reviewed custody record.

## Required coordinator run order

1. Let the active debug test finish; collect its result. Re-run final static
   checks after any documentation/review integration. Do not run release
   profile in the dirty worktree.
2. Stage only the reviewed candidate (including the requested `.agent`
   coordination/audit files), inspect the staged diff, commit 0.2.0, push the
   branch, create a draft PR, and verify the remote branch SHA equals local
   `HEAD`.
3. Set a fresh commit-specific `CARGO_TARGET_DIR` and run post-push release
   qualification. Treat hosted PR CI and local evidence as tied to that SHA.
   If a fix is required, return to debug/static checks, commit and push the fix,
   then use another fresh target for the release rerun.
4. After the last passing release run, copy `hsrd` outside every build target.
   Verify source/copy SHA-256 equality and capture the exact commit, tree,
   command, Rust/Cargo versions, size, mode, and typed build manifest. Never use
   the stale pre-push release artifacts.
5. After confirming no process uses them, remove only the canonical old shared
   target and the fresh release target. Re-measure actual available bytes and
   require at least 160,000,000,000; do not rely on the projection in this
   report.
6. Create a secret outside the repository in a 0700 directory and exact 0600
   regular file without printing it. Reconfirm the copied binary and the chosen
   data/evidence roots are canonical, nonsymlink, disjoint, private, and absent
   or empty. Reconfirm port 12037 is free.
7. Launch `scripts/run-full-sync-qualification.sh run` in the foreground with
   the copied binary, the two fresh roots, explicit
   `--limit-bytes 150000000000`, and explicit
   `--filesystem-reserve-bytes 10000000000`. Monitor with `status`; use `resume`
   only for a verified interrupted campaign and `stop` for a graceful operator
   stop. Never hand-edit evidence or reuse another data root.
8. Report the full sync as provisional baseline evidence only. Do not claim
   production completion or create a release until all seven external
   campaigns, reviewed custody, tested rollback/restore, and the exact
   `run-production-assurance.sh release` decision pass for the same pushed
   commit, tree, binary, and build manifest.
