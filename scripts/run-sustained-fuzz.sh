#!/usr/bin/env bash
set -euo pipefail

repo_root=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
rust_toolchain=${FUZZ_RUST_TOOLCHAIN:-nightly-2025-08-07}
readonly expected_cargo_fuzz_version="cargo-fuzz 0.13.2"
duration_seconds=${FUZZ_DURATION_SECONDS:-300}
case_timeout_seconds=${FUZZ_CASE_TIMEOUT_SECONDS:-10}
rss_limit_mb=${FUZZ_RSS_LIMIT_MB:-4096}
seed=${FUZZ_SEED:-24301}
output_dir=
corpus_root=
declare -a selected_targets=()
readonly all_targets=(
  airdrop_proof_parser
  block_parser
  claim_parser
  covenant_parser
  fixture_manifest_parser
  header_parser
  p2p_frame_parser
  resource_value_parser
  rpc_request_parser
  transaction_parser
)

worktree_digest() {
  python3 - "$repo_root" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

root = Path(sys.argv[1])
digest = hashlib.sha256()
digest.update(
    subprocess.check_output(
        ["git", "-C", str(root), "diff", "--binary", "HEAD", "--"]
    )
)
untracked = subprocess.check_output(
    [
        "git",
        "-C",
        str(root),
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    ]
).split(b"\0")
for encoded in sorted(item for item in untracked if item):
    path = root / os.fsdecode(encoded)
    metadata = path.lstat()
    digest.update(b"\0untracked\0")
    digest.update(encoded)
    digest.update(b"\0mode\0")
    digest.update(f"{stat.S_IMODE(metadata.st_mode):o}".encode())
    if path.is_symlink():
        digest.update(b"\0symlink\0")
        digest.update(os.fsencode(os.readlink(path)))
    elif path.is_file():
        digest.update(b"\0file\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    else:
        digest.update(b"\0other\0")
print(digest.hexdigest())
PY
}

monotonic_nanoseconds() {
  python3 - <<'PY'
import time

print(time.monotonic_ns())
PY
}

corpus_inventory() {
  python3 - "$1" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
digest = hashlib.sha256()
files = 0
total_bytes = 0
for path in sorted(root.rglob("*"), key=lambda item: os.fsencode(str(item.relative_to(root)))):
    relative = os.fsencode(str(path.relative_to(root)))
    metadata = path.lstat()
    if path.is_symlink():
        print(f"corpus contains a symbolic link: {path}", file=sys.stderr)
        raise SystemExit(1)
    if path.is_dir():
        continue
    if not path.is_file():
        print(f"corpus contains a non-regular entry: {path}", file=sys.stderr)
        raise SystemExit(1)
    digest.update(b"\0file\0")
    digest.update(relative)
    digest.update(b"\0mode\0")
    digest.update(f"{stat.S_IMODE(metadata.st_mode):o}".encode())
    digest.update(b"\0bytes\0")
    digest.update(str(metadata.st_size).encode())
    digest.update(b"\0content\0")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    files += 1
    total_bytes += metadata.st_size
print(f"{digest.hexdigest()}\t{files}\t{total_bytes}")
PY
}

usage() {
  cat <<'EOF'
Usage: scripts/run-sustained-fuzz.sh --output-dir DIR [options]

Options:
  --duration-seconds N     Per-target wall-clock budget (default: 300).
  --case-timeout-seconds N Per-input timeout (default: 10).
  --rss-limit-mb N         Per-process libFuzzer RSS limit (default: 4096).
  --seed N                 Reproducible starting seed (default: 24301).
  --corpus-root DIR        Reuse corpora outside the immutable output directory.
  --target NAME            Run one target; repeat to select several.
  --help                   Show this help.

The output directory must not already exist. A summary.json is written even
when a target finds a crash or times out, and the command exits nonzero.
EOF
}

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_known_target() {
  local candidate=$1
  local known
  for known in "${all_targets[@]}"; do
    if [[ "$candidate" == "$known" ]]; then
      return 0
    fi
  done
  return 1
}

while (($#)); do
  case "$1" in
    --output-dir)
      output_dir=${2:?missing value for --output-dir}
      shift 2
      ;;
    --duration-seconds)
      duration_seconds=${2:?missing value for --duration-seconds}
      shift 2
      ;;
    --case-timeout-seconds)
      case_timeout_seconds=${2:?missing value for --case-timeout-seconds}
      shift 2
      ;;
    --rss-limit-mb)
      rss_limit_mb=${2:?missing value for --rss-limit-mb}
      shift 2
      ;;
    --seed)
      seed=${2:?missing value for --seed}
      shift 2
      ;;
    --corpus-root)
      corpus_root=${2:?missing value for --corpus-root}
      shift 2
      ;;
    --target)
      selected_targets+=("${2:?missing value for --target}")
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$output_dir" ]]; then
  echo "--output-dir is required" >&2
  exit 2
fi
for value in "$duration_seconds" "$case_timeout_seconds" "$rss_limit_mb" "$seed"; do
  if ! is_positive_integer "$value"; then
    echo "numeric fuzz settings must be positive integers: $value" >&2
    exit 2
  fi
done
if ((${#selected_targets[@]} == 0)); then
  selected_targets=("${all_targets[@]}")
fi
for target in "${selected_targets[@]}"; do
  if ! is_known_target "$target"; then
    echo "unknown fuzz target: $target" >&2
    exit 2
  fi
done
if [[ -e "$output_dir" || -L "$output_dir" ]]; then
  echo "refusing to reuse fuzz evidence directory: $output_dir" >&2
  exit 2
fi

mkdir -p "$output_dir/logs" "$output_dir/artifacts"
output_dir=$(cd "$output_dir" && pwd)
if [[ -z "$corpus_root" ]]; then
  corpus_root="$output_dir/corpus"
fi
mkdir -p "$corpus_root"
corpus_root=$(cd "$corpus_root" && pwd)
if [[ "$corpus_root" == "$output_dir/corpus" ]]; then
  corpus_root_mode=evidence_output
else
  corpus_root_mode=external
fi

results_file="$output_dir/results.tsv"
: >"$results_file"
campaign_started=$(date -u +%s)
campaign_status=pass
source_revision_started=$(git -C "$repo_root" rev-parse HEAD)
source_tree_started=$(git -C "$repo_root" rev-parse 'HEAD^{tree}')
source_worktree_started=$(worktree_digest)
if [[ -n "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]]; then
  source_dirty_started=true
else
  source_dirty_started=false
fi

cd "$repo_root"
set +e
rustc_version=$(rustc +"$rust_toolchain" --version 2>&1)
rustc_status=$?
cargo_fuzz_version=$(cargo +"$rust_toolchain" fuzz --version 2>&1)
cargo_fuzz_status=$?
set -e
tool_preflight_passed=true
if ((rustc_status != 0)); then
  rustc_version="unavailable (exit $rustc_status): $rustc_version"
  tool_preflight_passed=false
  campaign_status=fail
fi
if ((cargo_fuzz_status != 0)); then
  cargo_fuzz_version="unavailable (exit $cargo_fuzz_status): $cargo_fuzz_version"
  tool_preflight_passed=false
  campaign_status=fail
elif [[ "$cargo_fuzz_version" != "$expected_cargo_fuzz_version" ]]; then
  tool_preflight_passed=false
  campaign_status=fail
fi

if [[ "$tool_preflight_passed" == true ]]; then
  for target in "${selected_targets[@]}"; do
    target_corpus="$corpus_root/$target"
    target_artifacts="$output_dir/artifacts/$target"
    target_log="$output_dir/logs/$target.log"
    mkdir -p "$target_corpus" "$target_artifacts"
    IFS=$'\t' read -r \
      corpus_started_sha256 corpus_started_files corpus_started_bytes \
      < <(corpus_inventory "$target_corpus")
    target_started=$(date -u +%s)
    target_monotonic_started=$(monotonic_nanoseconds)
    set +e
    cargo +"$rust_toolchain" fuzz run \
      --fuzz-dir "$repo_root/fuzz" \
      "$target" "$target_corpus" -- \
      "-max_total_time=$duration_seconds" \
      "-timeout=$case_timeout_seconds" \
      "-rss_limit_mb=$rss_limit_mb" \
      "-seed=$seed" \
      "-print_final_stats=1" \
      "-artifact_prefix=$target_artifacts/" \
      >"$target_log" 2>&1
    target_status=$?
    set -e
    target_monotonic_completed=$(monotonic_nanoseconds)
    target_completed=$(date -u +%s)
    target_elapsed_nanoseconds=$((target_monotonic_completed - target_monotonic_started))
    target_minimum_nanoseconds=$((duration_seconds * 1000000000))
    if ((target_elapsed_nanoseconds >= target_minimum_nanoseconds)); then
      target_duration_satisfied=true
    else
      target_duration_satisfied=false
      campaign_status=fail
    fi
    IFS=$'\t' read -r \
      corpus_completed_sha256 corpus_completed_files corpus_completed_bytes \
      < <(corpus_inventory "$target_corpus")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$target" "$target_status" "$target_started" "$target_completed" \
      "$target_elapsed_nanoseconds" "$target_duration_satisfied" \
      "$corpus_started_sha256" "$corpus_started_files" "$corpus_started_bytes" \
      "$corpus_completed_sha256" "$corpus_completed_files" "$corpus_completed_bytes" \
      >>"$results_file"
    if ((target_status != 0)) || [[ "$target_duration_satisfied" != true ]]; then
      campaign_status=fail
      break
    fi
  done
fi

campaign_completed=$(date -u +%s)
source_revision_completed=$(git rev-parse HEAD)
source_tree_completed=$(git rev-parse 'HEAD^{tree}')
source_worktree_completed=$(worktree_digest)
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  source_dirty_completed=true
else
  source_dirty_completed=false
fi
if [[ "$source_revision_started" != "$source_revision_completed" ||
  "$source_tree_started" != "$source_tree_completed" ||
  "$source_worktree_started" != "$source_worktree_completed" ]]; then
  source_changed_during_campaign=true
  campaign_status=fail
else
  source_changed_during_campaign=false
fi
set +e
rustc_version_completed=$(rustc +"$rust_toolchain" --version 2>&1)
rustc_completed_status=$?
cargo_fuzz_version_completed=$(cargo +"$rust_toolchain" fuzz --version 2>&1)
cargo_fuzz_completed_status=$?
set -e
if ((rustc_completed_status != 0)); then
  rustc_version_completed="unavailable (exit $rustc_completed_status): $rustc_version_completed"
  campaign_status=fail
fi
if ((cargo_fuzz_completed_status != 0)); then
  cargo_fuzz_version_completed="unavailable (exit $cargo_fuzz_completed_status): $cargo_fuzz_version_completed"
  campaign_status=fail
elif [[ "$cargo_fuzz_version_completed" != "$expected_cargo_fuzz_version" ]]; then
  campaign_status=fail
fi
if [[ "$rustc_version" != "$rustc_version_completed" ||
  "$cargo_fuzz_version" != "$cargo_fuzz_version_completed" ]]; then
  campaign_status=fail
fi

python3 - \
  "$output_dir" "$results_file" \
  "$source_revision_started" "$source_tree_started" \
  "$source_dirty_started" "$source_worktree_started" \
  "$source_revision_completed" "$source_tree_completed" \
  "$source_dirty_completed" "$source_worktree_completed" \
  "$source_changed_during_campaign" \
  "$rust_toolchain" "$rustc_version" "$cargo_fuzz_version" \
  "$rustc_version_completed" "$cargo_fuzz_version_completed" \
  "$expected_cargo_fuzz_version" \
  "$duration_seconds" "$case_timeout_seconds" "$rss_limit_mb" "$seed" \
  "$corpus_root_mode" \
  "$campaign_started" "$campaign_completed" "$campaign_status" \
  "${selected_targets[@]}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

(
    output_raw,
    results_raw,
    source_revision_started,
    source_tree_started,
    source_dirty_started,
    source_worktree_started,
    source_revision_completed,
    source_tree_completed,
    source_dirty_completed,
    source_worktree_completed,
    source_changed_during_campaign,
    rust_toolchain,
    rustc_version,
    cargo_fuzz_version,
    rustc_version_completed,
    cargo_fuzz_version_completed,
    expected_cargo_fuzz_version,
    duration_seconds,
    case_timeout_seconds,
    rss_limit_mb,
    seed,
    corpus_root_mode,
    campaign_started,
    campaign_completed,
    campaign_status,
    *selected_targets,
) = sys.argv[1:]
output = Path(output_raw)

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

executed = {}
for line in Path(results_raw).read_text(encoding="utf-8").splitlines():
    (
        target,
        status,
        started,
        completed,
        elapsed_nanoseconds,
        duration_satisfied,
        corpus_started_sha256,
        corpus_started_files,
        corpus_started_bytes,
        corpus_completed_sha256,
        corpus_completed_files,
        corpus_completed_bytes,
    ) = line.split("\t")
    executed[target] = {
        "status": (
            "pass"
            if int(status) == 0 and duration_satisfied == "true"
            else "fail"
        ),
        "exit_code": int(status),
        "started_unix_seconds": int(started),
        "completed_unix_seconds": int(completed),
        "elapsed_nanoseconds": int(elapsed_nanoseconds),
        "duration_satisfied": duration_satisfied == "true",
        "corpus": {
            "at_start": {
                "sha256": corpus_started_sha256,
                "files": int(corpus_started_files),
                "bytes": int(corpus_started_bytes),
            },
            "at_completion": {
                "sha256": corpus_completed_sha256,
                "files": int(corpus_completed_files),
                "bytes": int(corpus_completed_bytes),
            },
        },
    }

targets = []
for target in selected_targets:
    record = executed.get(target, {"status": "not_run", "exit_code": None})
    log_path = output / "logs" / f"{target}.log"
    artifacts_dir = output / "artifacts" / target
    if log_path.is_file():
        record["log"] = {
            "path": str(log_path.relative_to(output)),
            "sha256": sha256_file(log_path),
        }
    artifacts = []
    if artifacts_dir.is_dir():
        for path in sorted(item for item in artifacts_dir.rglob("*") if item.is_file()):
            artifacts.append(
                {
                    "path": str(path.relative_to(output)),
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                }
            )
    record["artifacts"] = artifacts
    record["target"] = target
    targets.append(record)

summary = {
    "schema_version": 1,
    "gate": "sustained_fuzz",
    "status": campaign_status,
    "source_revision": source_revision_started,
    "source_tree": source_tree_started,
    "source_dirty": source_dirty_started == "true",
    "source_worktree_sha256": source_worktree_started,
    "source_at_completion": {
        "revision": source_revision_completed,
        "tree": source_tree_completed,
        "dirty": source_dirty_completed == "true",
        "worktree_sha256": source_worktree_completed,
    },
    "source_changed_during_campaign": source_changed_during_campaign == "true",
    "tool": {
        "rust_toolchain": rust_toolchain,
        "rustc_version": rustc_version,
        "cargo_fuzz_version": cargo_fuzz_version,
        "expected_cargo_fuzz_version": expected_cargo_fuzz_version,
        "at_completion": {
            "rustc_version": rustc_version_completed,
            "cargo_fuzz_version": cargo_fuzz_version_completed,
        },
    },
    "configuration": {
        "duration_seconds_per_target": int(duration_seconds),
        "case_timeout_seconds": int(case_timeout_seconds),
        "rss_limit_mb": int(rss_limit_mb),
        "seed": int(seed),
        "corpus_root_mode": corpus_root_mode,
        "selected_targets": selected_targets,
    },
    "started_unix_seconds": int(campaign_started),
    "completed_unix_seconds": int(campaign_completed),
    "targets": targets,
}
(output / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

echo "sustained fuzz evidence: $output_dir/summary.json"
if [[ "$campaign_status" != pass ]]; then
  echo "sustained fuzz campaign failed; inspect retained logs and artifacts" >&2
  exit 1
fi
