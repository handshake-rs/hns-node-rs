#!/usr/bin/env bash
set -euo pipefail

repo_root=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
fuzz_rust_toolchain=${FUZZ_RUST_TOOLCHAIN:-nightly-2025-08-07}
cargo_target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
tier=${1:-}
if (($#)); then
  shift
fi
evidence_dir=
fuzz_duration_seconds=${FUZZ_DURATION_SECONDS:-}

usage() {
  cat <<'EOF'
Usage:
  scripts/run-production-assurance.sh smoke --evidence-dir NEW_DIR
  scripts/run-production-assurance.sh scheduled --evidence-dir NEW_DIR [--fuzz-duration-seconds N]
  scripts/run-production-assurance.sh verify-external --evidence-dir EXISTING_DIR
  scripts/run-production-assurance.sh release --evidence-dir EXISTING_DIR [--fuzz-duration-seconds N]
  scripts/run-production-assurance.sh self-test

smoke runs the fast in-memory performance and two-node gates. scheduled adds
the persistent RocksDB/sync performance scenario and all sustained fuzz targets.
verify-external validates independently collected production evidence. release
runs scheduled software gates and then requires all external evidence; it fails
closed when any record or artifact is absent.
EOF
}

if [[ "$tier" == --help || "$tier" == -h ]]; then
  usage
  exit 0
fi

while (($#)); do
  case "$1" in
    --evidence-dir)
      evidence_dir=${2:?missing value for --evidence-dir}
      shift 2
      ;;
    --fuzz-duration-seconds)
      fuzz_duration_seconds=${2:?missing value for --fuzz-duration-seconds}
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

case "$tier" in
  smoke|scheduled|verify-external|release|self-test) ;;
  *)
    usage >&2
    exit 2
    ;;
esac
if [[ -z "$fuzz_duration_seconds" ]]; then
  if [[ "$tier" == release ]]; then
    fuzz_duration_seconds=1800
  else
    fuzz_duration_seconds=180
  fi
fi
if [[ "$tier" != self-test && -z "$evidence_dir" ]]; then
  echo "--evidence-dir is required" >&2
  exit 2
fi
if [[ ! "$fuzz_duration_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "--fuzz-duration-seconds must be a positive integer" >&2
  exit 2
fi
if [[ "$tier" == scheduled && "$fuzz_duration_seconds" -lt 180 ]]; then
  echo "scheduled assurance requires at least 180 fuzz seconds per target" >&2
  exit 2
fi
if [[ "$tier" == release && "$fuzz_duration_seconds" -lt 1800 ]]; then
  echo "release assurance requires at least 1800 fuzz seconds per target" >&2
  exit 2
fi

cd "$repo_root"

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

source_revision=$(git rev-parse HEAD)
source_tree=$(git rev-parse 'HEAD^{tree}')
source_worktree=$(worktree_digest)
if [[ -z "$(git status --porcelain --untracked-files=all)" ]]; then
  source_dirty_started=false
else
  source_dirty_started=true
fi

require_clean_worktree() {
  local checked_rust_toolchain=${1:-$rust_toolchain}
  local checked_fuzz_toolchain=${2:-$fuzz_rust_toolchain}
  if [[ "$checked_rust_toolchain" != 1.89.0 ]]; then
    echo "$tier assurance requires RUST_TOOLCHAIN=1.89.0" >&2
    return 1
  fi
  if [[ "$checked_fuzz_toolchain" != nightly-2025-08-07 ]]; then
    echo "$tier assurance requires FUZZ_RUST_TOOLCHAIN=nightly-2025-08-07" >&2
    return 1
  fi
  if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "$tier assurance requires a fully clean worktree" >&2
    return 1
  fi
}

require_external_evidence_path() {
  python3 - "$repo_root" "$1" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
evidence = Path(sys.argv[2]).resolve()
if evidence == root or root in evidence.parents:
    print("scheduled/release evidence must be outside the repository", file=sys.stderr)
    raise SystemExit(1)
PY
}

verify_external_evidence() {
  local root=$1
  if [[ ! -d "$root" || -L "$root" ]]; then
    echo "external evidence directory is missing or unsafe: $root" >&2
    return 1
  fi
  python3 - "$root" "$source_revision" "$source_tree" <<'PY'
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()
expected_revision = sys.argv[2]
expected_tree = sys.argv[3]
external = root / "external"
gates = {
    "production_scale_pruning": "production-scale-pruning.json",
    "rocksdb_fault_injection": "rocksdb-fault-injection.json",
    "sustained_reorg_partition": "sustained-reorg-partition.json",
    "wan_load_latency": "wan-load-latency.json",
    "physical_gateway_asic": "physical-gateway-asic.json",
    "long_duration_multi_peer": "long-duration-multi-peer.json",
    "mempool_template_differential": "mempool-template-differential.json",
}
errors = []
shared_binary_identity = None
shared_manifest_identity = None
if external.is_symlink():
    errors.append("external evidence directory must not be a symlink")

digest_cache = {}

def sha256_file(path):
    if path in digest_cache:
        return digest_cache[path]
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    value = digest.hexdigest()
    digest_cache[path] = value
    return value

def number(metrics, name, minimum=0, maximum=None):
    value = metrics.get(name)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        errors.append(f"{current}: metrics.{name} must be numeric")
        return
    if minimum is not None and value < minimum:
        errors.append(f"{current}: metrics.{name}={value} is below {minimum}")
    if maximum is not None and value > maximum:
        errors.append(f"{current}: metrics.{name}={value} exceeds {maximum}")

def exact(values, name, expected, namespace="metrics"):
    if values.get(name) != expected:
        errors.append(
            f"{current}: {namespace}.{name}={values.get(name)!r}, expected {expected!r}"
        )

def required_string(values, name, namespace="configuration"):
    value = values.get(name)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{current}: {namespace}.{name} is required")
        return None
    return value

def required_sha256(values, name, namespace="configuration"):
    value = values.get(name)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        errors.append(f"{current}: {namespace}.{name} must be lowercase SHA-256")
        return None
    return value

def single_typed_artifact(artifacts, artifact_type):
    matches = [
        artifact for artifact in artifacts if artifact["type"] == artifact_type
    ]
    if len(matches) != 1:
        errors.append(
            f"{current}: exactly one verified artifact of type "
            f"{artifact_type!r} is required"
        )
        return None
    return matches[0]

def bind_typed_digest(config, artifacts, field, artifact_type):
    digest = required_sha256(config, field)
    artifact = single_typed_artifact(artifacts, artifact_type)
    if digest is not None and artifact is not None and digest != artifact["sha256"]:
        errors.append(
            f"{current}: configuration.{field} does not match the verified "
            f"{artifact_type} artifact"
        )
    return artifact

def required_identity_list(config, field, minimum):
    value = config.get(field)
    if (
        not isinstance(value, list)
        or len(value) < minimum
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(set(value)) != len(value)
    ):
        errors.append(
            f"{current}: configuration.{field} must contain at least {minimum} "
            "distinct nonempty identities"
        )
        return None
    return value

def bind_list_count(config, metrics, field, metric, minimum):
    identities = required_identity_list(config, field, minimum)
    count = metrics.get(metric)
    if isinstance(count, bool) or not isinstance(count, int):
        errors.append(f"{current}: metrics.{metric} must be an integer")
    elif identities is not None and len(identities) != count:
        errors.append(
            f"{current}: configuration.{field} contains {len(identities)} "
            f"identities but metrics.{metric} is {count}"
        )

for gate, filename in gates.items():
    current = filename
    path = external / filename
    if path.is_symlink() or not path.is_file():
        errors.append(f"missing external evidence record: external/{filename}")
        continue
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{current}: invalid JSON: {error}")
        continue
    if not isinstance(record, dict):
        errors.append(f"{current}: record must be a JSON object")
        continue
    if record.get("schema_version") != 2:
        errors.append(f"{current}: schema_version must be 2")
    if record.get("gate") != gate:
        errors.append(f"{current}: gate must be {gate!r}")
    if record.get("status") != "pass":
        errors.append(f"{current}: status must be 'pass'")
    if record.get("source_revision") != expected_revision:
        errors.append(f"{current}: source_revision does not match {expected_revision}")
    if record.get("source_tree") != expected_tree:
        errors.append(f"{current}: source_tree does not match {expected_tree}")
    for object_name in ("tool", "configuration", "metrics"):
        value = record.get(object_name)
        if not isinstance(value, dict) or not value:
            errors.append(f"{current}: {object_name} must be a nonempty object")
    tool = record.get("tool")
    if not isinstance(tool, dict):
        tool = {}
    for field in ("name", "version"):
        if not isinstance(tool.get(field), str) or not tool[field].strip():
            errors.append(f"{current}: tool.{field} is required")
    operator = record.get("operator")
    reviewer = record.get("reviewer")
    if not isinstance(operator, str) or not operator.strip():
        errors.append(f"{current}: operator is required")
    if not isinstance(reviewer, str) or not reviewer.strip():
        errors.append(f"{current}: reviewer is required")
    if operator == reviewer:
        errors.append(f"{current}: reviewer must be independent of operator")
    try:
        started = datetime.fromisoformat(record["started_at"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(record["completed_at"].replace("Z", "+00:00"))
        if started.utcoffset() is None or completed.utcoffset() is None:
            errors.append(f"{current}: timestamps must include a UTC offset")
        if completed <= started:
            errors.append(f"{current}: completed_at must be after started_at")
        declared_metrics = record.get("metrics")
        declared_duration = (
            declared_metrics.get("duration_seconds")
            if isinstance(declared_metrics, dict)
            else None
        )
        if (
            isinstance(declared_duration, (int, float))
            and not isinstance(declared_duration, bool)
            and declared_duration > (completed - started).total_seconds() + 1
        ):
            errors.append(f"{current}: duration_seconds exceeds the timestamp interval")
    except (KeyError, TypeError, ValueError) as error:
        errors.append(f"{current}: invalid started_at/completed_at: {error}")

    artifacts = record.get("artifacts")
    verified_artifacts = []
    seen_artifact_paths = set()
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"{current}: at least one hashed artifact is required")
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"{current}: artifacts[{index}] must be an object")
                continue
            relative = artifact.get("path")
            digest = artifact.get("sha256")
            artifact_type = artifact.get("type")
            if artifact_type is not None and (
                not isinstance(artifact_type, str) or not artifact_type.strip()
            ):
                errors.append(f"{current}: artifacts[{index}].type must be a nonempty string")
                continue
            if (
                not isinstance(relative, str)
                or Path(relative).is_absolute()
                or ".." in Path(relative).parts
            ):
                errors.append(f"{current}: artifacts[{index}].path must be safe and relative")
                continue
            if relative in seen_artifact_paths:
                errors.append(
                    f"{current}: artifact path is listed more than once: {relative}"
                )
                continue
            seen_artifact_paths.add(relative)
            artifact_candidate = root / relative
            cursor = root
            has_symlink = False
            for part in Path(relative).parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    has_symlink = True
                    break
            if has_symlink:
                errors.append(f"{current}: artifact path contains a symlink: {relative}")
                continue
            artifact_path = artifact_candidate.resolve()
            if root not in artifact_path.parents or not artifact_path.is_file():
                errors.append(f"{current}: artifact is missing: {relative}")
                continue
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                errors.append(f"{current}: artifact digest is not lowercase SHA-256: {relative}")
                continue
            actual = sha256_file(artifact_path)
            if actual != digest:
                errors.append(f"{current}: artifact digest mismatch: {relative}")
                continue
            verified_artifacts.append(
                {
                    "type": artifact_type,
                    "path": relative,
                    "sha256": actual,
                    "resolved": artifact_path,
                }
            )

    metrics = record.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}
    config = record.get("configuration")
    if not isinstance(config, dict):
        config = {}

    exact(config, "network", "mainnet", "configuration")
    binary_digest = required_sha256(config, "binary_sha256")
    binary_artifact = single_typed_artifact(verified_artifacts, "hsrd_binary")
    manifest_artifact = single_typed_artifact(
        verified_artifacts, "hsrd_build_manifest"
    )
    campaign_artifact = single_typed_artifact(
        verified_artifacts, "hsrd_campaign_configuration"
    )
    if binary_artifact is not None and binary_digest is not None:
        if binary_digest != binary_artifact["sha256"]:
            errors.append(
                f"{current}: configuration.binary_sha256 does not match the "
                "actual hsrd_binary artifact"
            )
        binary_identity = (binary_artifact["path"], binary_artifact["sha256"])
        if shared_binary_identity is None:
            shared_binary_identity = binary_identity
        elif binary_identity != shared_binary_identity:
            errors.append(
                f"{current}: hsrd_binary identity differs from the other "
                "external gates"
            )

    if manifest_artifact is not None:
        manifest_identity = (manifest_artifact["path"], manifest_artifact["sha256"])
        if shared_manifest_identity is None:
            shared_manifest_identity = manifest_identity
        elif manifest_identity != shared_manifest_identity:
            errors.append(
                f"{current}: hsrd_build_manifest identity differs from the other "
                "external gates"
            )
        if config.get("binary_manifest_path") != manifest_artifact["path"]:
            errors.append(
                f"{current}: configuration.binary_manifest_path must identify the "
                "verified hsrd_build_manifest artifact"
            )
        try:
            build_manifest = json.loads(
                manifest_artifact["resolved"].read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            errors.append(f"{current}: invalid hsrd build manifest: {error}")
            build_manifest = {}
        if not isinstance(build_manifest, dict):
            errors.append(f"{current}: hsrd build manifest must be a JSON object")
            build_manifest = {}
        if build_manifest.get("schema_version") != 1:
            errors.append(f"{current}: hsrd build manifest schema_version must be 1")
        if build_manifest.get("artifact_type") != "hsrd_build_manifest":
            errors.append(
                f"{current}: hsrd build manifest artifact_type must be "
                "'hsrd_build_manifest'"
            )
        if build_manifest.get("source_revision") != expected_revision:
            errors.append(
                f"{current}: hsrd build manifest source_revision does not match "
                f"{expected_revision}"
            )
        if build_manifest.get("source_tree") != expected_tree:
            errors.append(
                f"{current}: hsrd build manifest source_tree does not match "
                f"{expected_tree}"
            )
        build = build_manifest.get("build")
        if not isinstance(build, dict):
            errors.append(f"{current}: hsrd build manifest build must be an object")
        else:
            exact(
                build,
                "command",
                "cargo +1.89.0 build --locked --release -p hns-node --bin hsrd",
                "hsrd build manifest build",
            )
            exact(
                build,
                "rust_toolchain",
                "1.89.0",
                "hsrd build manifest build",
            )
            rustc_version = required_string(
                build, "rustc_version", "hsrd build manifest build"
            )
            if rustc_version is not None and not re.match(
                r"^rustc 1[.]89[.]0(?: |$)", rustc_version
            ):
                errors.append(
                    f"{current}: hsrd build manifest build.rustc_version must "
                    "identify rustc 1.89.0"
                )
            cargo_version = required_string(
                build, "cargo_version", "hsrd build manifest build"
            )
            if cargo_version is not None and not re.match(
                r"^cargo 1[.]89[.]0(?: |$)", cargo_version
            ):
                errors.append(
                    f"{current}: hsrd build manifest build.cargo_version must "
                    "identify cargo 1.89.0"
                )
        manifest_binary = build_manifest.get("binary")
        if not isinstance(manifest_binary, dict):
            errors.append(f"{current}: hsrd build manifest binary must be an object")
        else:
            if manifest_binary.get("type") != "hsrd_binary":
                errors.append(
                    f"{current}: hsrd build manifest binary.type must be "
                    "'hsrd_binary'"
                )
            if manifest_binary.get("name") != "hsrd":
                errors.append(
                    f"{current}: hsrd build manifest binary.name must be 'hsrd'"
                )
            if (
                binary_artifact is not None
                and manifest_binary.get("path") != binary_artifact["path"]
            ):
                errors.append(
                    f"{current}: hsrd build manifest binary.path does not match "
                    "the verified hsrd_binary artifact"
                )
            if (
                binary_artifact is not None
                and manifest_binary.get("sha256") != binary_artifact["sha256"]
            ):
                errors.append(
                    f"{current}: hsrd build manifest binary.sha256 does not match "
                    "the actual hsrd_binary artifact"
                )

    campaign_digest = required_sha256(config, "campaign_config_sha256")
    if campaign_artifact is not None:
        if config.get("campaign_config_path") != campaign_artifact["path"]:
            errors.append(
                f"{current}: configuration.campaign_config_path must identify the "
                "verified hsrd_campaign_configuration artifact"
            )
        if (
            campaign_digest is not None
            and campaign_digest != campaign_artifact["sha256"]
        ):
            errors.append(
                f"{current}: configuration.campaign_config_sha256 does not match "
                "the actual campaign-configuration artifact"
            )
        try:
            campaign_manifest = json.loads(
                campaign_artifact["resolved"].read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            errors.append(f"{current}: invalid campaign configuration: {error}")
            campaign_manifest = {}
        if not isinstance(campaign_manifest, dict):
            errors.append(f"{current}: campaign configuration must be a JSON object")
            campaign_manifest = {}
        if campaign_manifest.get("schema_version") != 1:
            errors.append(f"{current}: campaign configuration schema_version must be 1")
        if (
            campaign_manifest.get("artifact_type")
            != "hsrd_campaign_configuration"
        ):
            errors.append(
                f"{current}: campaign configuration artifact_type must be "
                "'hsrd_campaign_configuration'"
            )
        if campaign_manifest.get("gate") != gate:
            errors.append(f"{current}: campaign configuration gate must be {gate!r}")
        if campaign_manifest.get("source_revision") != expected_revision:
            errors.append(
                f"{current}: campaign configuration source_revision does not match "
                f"{expected_revision}"
            )
        if campaign_manifest.get("source_tree") != expected_tree:
            errors.append(
                f"{current}: campaign configuration source_tree does not match "
                f"{expected_tree}"
            )
        bound_configuration = dict(config)
        bound_configuration.pop("campaign_config_path", None)
        bound_configuration.pop("campaign_config_sha256", None)
        if campaign_manifest.get("configuration") != bound_configuration:
            errors.append(
                f"{current}: record configuration does not match its hashed "
                "campaign configuration"
            )

    if gate == "production_scale_pruning":
        exact(config, "baseline_mode", "full_non_pruned", "configuration")
        exact(config, "pruned_mode", "prune_history", "configuration")
        exact(config, "rollback_horizon_blocks", 288, "configuration")
        if isinstance(config.get("rollback_horizon_blocks"), bool) or not isinstance(
            config.get("rollback_horizon_blocks"), int
        ):
            errors.append(
                f"{current}: configuration.rollback_horizon_blocks must be an integer"
            )
        for field in ("host_id", "filesystem", "measurement_scope"):
            required_string(config, field)
        bind_typed_digest(
            config, verified_artifacts, "dataset_manifest_sha256", "dataset_manifest"
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "baseline_config_sha256",
            "baseline_configuration",
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "pruned_config_sha256",
            "pruned_configuration",
        )
        if not isinstance(config.get("dataset_height"), int) or isinstance(
            config.get("dataset_height"), bool
        ):
            errors.append(f"{current}: configuration.dataset_height must be an integer")
        elif config["dataset_height"] < 300_000:
            errors.append(
                f"{current}: configuration.dataset_height is below production scale"
            )
        number(metrics, "block_records", 300_000)
        number(metrics, "utxo_records", 20_000_000)
        number(metrics, "name_records", 10_000_000)
        number(metrics, "rollback_horizon_blocks", 288)
        if isinstance(metrics.get("rollback_horizon_blocks"), bool) or not isinstance(
            metrics.get("rollback_horizon_blocks"), int
        ):
            errors.append(
                f"{current}: metrics.rollback_horizon_blocks must be an integer"
            )
        if metrics.get("rollback_horizon_blocks") != config.get(
            "rollback_horizon_blocks"
        ):
            errors.append(
                f"{current}: metrics.rollback_horizon_blocks must match "
                "configuration.rollback_horizon_blocks"
            )
        number(metrics, "reclaimed_bytes", 1)
        number(metrics, "duration_seconds", 1)
        number(metrics, "peak_rss_bytes", 1)
        number(metrics, "peak_disk_bytes", 1, 150_000_000_000)
        number(metrics, "final_disk_bytes", 1, 150_000_000_000)
        number(metrics, "pruned_final_disk_bytes", 1)
        number(metrics, "rocksdb_background_errors", maximum=0)
        exact(metrics, "resource_limits_respected", True)
        exact(metrics, "hsd_blocks_deleted", False)
        exact(metrics, "comparison_scope_identical", True)
        peak_disk = metrics.get("peak_disk_bytes")
        final_disk = metrics.get("final_disk_bytes")
        pruned_disk = metrics.get("pruned_final_disk_bytes")
        if (
            isinstance(final_disk, (int, float))
            and not isinstance(final_disk, bool)
            and isinstance(pruned_disk, (int, float))
            and not isinstance(pruned_disk, bool)
            and pruned_disk >= final_disk
        ):
            errors.append(
                f"{current}: pruned_final_disk_bytes must be below final_disk_bytes"
            )
        if (
            isinstance(peak_disk, (int, float))
            and not isinstance(peak_disk, bool)
            and isinstance(final_disk, (int, float))
            and not isinstance(final_disk, bool)
            and peak_disk < final_disk
        ):
            errors.append(f"{current}: peak_disk_bytes must cover final_disk_bytes")
        exact(metrics, "pre_inventory_valid", True)
        exact(metrics, "post_inventory_valid", True)
        exact(metrics, "restart_tip_match", True)
        exact(metrics, "fallback_restore_verified", True)
    elif gate == "rocksdb_fault_injection":
        exact(config, "storage_backend", "rocksdb", "configuration")
        for field in ("host_id", "filesystem"):
            required_string(config, field)
        bind_typed_digest(
            config, verified_artifacts, "dataset_manifest_sha256", "dataset_manifest"
        )
        bind_typed_digest(
            config, verified_artifacts, "fault_schedule_sha256", "fault_schedule"
        )
        bind_typed_digest(
            config, verified_artifacts, "seed_manifest_sha256", "seed_manifest"
        )
        number(metrics, "injection_points", 8)
        number(metrics, "iterations_per_point", 100)
        number(metrics, "iterations", 800)
        for field in ("injection_points", "iterations_per_point", "iterations"):
            if isinstance(metrics.get(field), bool) or not isinstance(
                metrics.get(field), int
            ):
                errors.append(f"{current}: metrics.{field} must be an integer")
        points = metrics.get("injection_points")
        per_point = metrics.get("iterations_per_point")
        iterations = metrics.get("iterations")
        if (
            isinstance(points, int)
            and not isinstance(points, bool)
            and isinstance(per_point, int)
            and not isinstance(per_point, bool)
            and isinstance(iterations, int)
            and not isinstance(iterations, bool)
            and iterations < points * per_point
        ):
            errors.append(
                f"{current}: metrics.iterations must cover every injection point"
            )
        bind_list_count(
            config,
            metrics,
            "injection_point_ids",
            "injection_points",
            8,
        )
        number(metrics, "reopen_failures", maximum=0)
        number(metrics, "tip_mismatches", maximum=0)
        number(metrics, "root_mismatches", maximum=0)
        number(metrics, "unexpected_authority_grants", maximum=0)
    elif gate == "sustained_reorg_partition":
        required_string(config, "topology_id")
        required_string(config, "state_oracle_revision")
        bind_typed_digest(
            config,
            verified_artifacts,
            "partition_schedule_sha256",
            "partition_schedule",
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "competing_chain_manifest_sha256",
            "competing_chain_manifest",
        )
        number(metrics, "duration_seconds", 21_600)
        number(metrics, "peer_count", 3)
        number(metrics, "partition_cycles", 3)
        number(metrics, "real_reorganizations", 1)
        bind_list_count(config, metrics, "peer_ids", "peer_count", 3)
        bind_list_count(
            config,
            metrics,
            "partition_cycle_ids",
            "partition_cycles",
            3,
        )
        number(metrics, "state_parity_mismatches", maximum=0)
        number(metrics, "unexpected_authority_grants", maximum=0)
    elif gate == "wan_load_latency":
        required_string(config, "topology_id")
        required_string(config, "clock_sync_profile")
        bind_typed_digest(
            config, verified_artifacts, "load_profile_sha256", "load_profile"
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "network_profile_sha256",
            "network_profile",
        )
        number(metrics, "duration_seconds", 3_600)
        number(metrics, "site_count", 2)
        number(metrics, "samples", 1_000)
        bind_list_count(config, metrics, "site_ids", "site_count", 2)
        number(metrics, "job_delivery_p99_millis", maximum=250)
        number(metrics, "candidate_to_first_peer_p99_millis", maximum=500)
        number(metrics, "failed_samples", maximum=0)
        number(metrics, "unavailable_samples", maximum=0)
    elif gate == "physical_gateway_asic":
        exact(config, "device_kind", "physical_asic", "configuration")
        for field in (
            "device_id",
            "device_model",
            "firmware_version",
            "gateway_version",
        ):
            required_string(config, field)
        bind_typed_digest(
            config,
            verified_artifacts,
            "gateway_binary_sha256",
            "gateway_binary",
        )
        bind_typed_digest(
            config, verified_artifacts, "fallback_plan_sha256", "fallback_plan"
        )
        number(metrics, "duration_seconds", 14_400)
        number(metrics, "jobs_observed", 1_000)
        number(metrics, "valid_shares", 1)
        number(metrics, "valid_block_candidates", 1)
        number(metrics, "fallback_recovery_cycles", 3)
        bind_list_count(
            config,
            metrics,
            "fallback_cycle_ids",
            "fallback_recovery_cycles",
            3,
        )
        number(metrics, "job_switch_p99_millis", maximum=250)
        number(metrics, "invalid_jobs", maximum=0)
        number(metrics, "unreconciled_receipts", maximum=0)
    elif gate == "long_duration_multi_peer":
        required_string(config, "topology_id")
        bind_typed_digest(
            config, verified_artifacts, "peer_set_sha256", "peer_set_manifest"
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "restart_schedule_sha256",
            "restart_schedule",
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "authority_policy_sha256",
            "authority_policy",
        )
        number(metrics, "duration_seconds", 86_400)
        number(metrics, "peer_count", 8)
        number(metrics, "controlled_restarts", 3)
        bind_list_count(config, metrics, "peer_ids", "peer_count", 8)
        bind_list_count(
            config,
            metrics,
            "restart_ids",
            "controlled_restarts",
            3,
        )
        number(metrics, "tip_divergences", maximum=0)
        number(metrics, "database_recovery_failures", maximum=0)
        number(metrics, "unexpected_authority_grants", maximum=0)
    elif gate == "mempool_template_differential":
        for field in ("oracle_name", "oracle_revision", "normalization_revision"):
            required_string(config, field)
        bind_typed_digest(
            config,
            verified_artifacts,
            "oracle_binary_sha256",
            "oracle_binary",
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "corpus_manifest_sha256",
            "corpus_manifest",
        )
        bind_typed_digest(
            config,
            verified_artifacts,
            "mempool_policy_sha256",
            "mempool_policy",
        )
        number(metrics, "transaction_cases", 10_000)
        number(metrics, "template_cases", 1_000)
        number(metrics, "reorg_reconciliation_cases", 100)
        number(metrics, "mempool_mismatches", maximum=0)
        number(metrics, "template_mismatches", maximum=0)
        number(metrics, "publication_mismatches", maximum=0)

if errors:
    for error in errors:
        print(f"production-assurance: {error}", file=sys.stderr)
    raise SystemExit(1)
print(f"verified {len(gates)} production evidence records for {expected_revision}")
PY
}

performance_scenario_for_tier() {
  case "$1" in
    smoke)
      printf '%s\n' smoke
      ;;
    scheduled|release)
      printf '%s\n' persistent-rocksdb-sync
      ;;
    *)
      echo "tier $1 has no software performance scenario" >&2
      return 1
      ;;
  esac
}

invoke_performance_gate() {
  local gate_tier=$1
  local binary=$2
  local report=$3
  local scenario
  scenario=$(performance_scenario_for_tier "$gate_tier") || return 1
  if [[ "$scenario" == smoke ]]; then
    "$binary" --json-output "$report"
  else
    "$binary" \
      --scenario "$scenario" \
      --json-output "$report"
  fi
}

verify_performance_gate_report() {
  local report=$1
  local expected_scenario=$2
  if [[ ! -f "$report" || -L "$report" ]]; then
    echo "performance evidence is missing or unsafe: $report" >&2
    return 1
  fi
  python3 - "$report" "$expected_scenario" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
expected_scenario = sys.argv[2]
try:
    record = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid performance evidence {path}: {error}")

def exact(container, key, expected, context):
    actual = container.get(key)
    if type(actual) is not type(expected) or actual != expected:
        raise SystemExit(
            f"performance evidence {context}.{key} must be {expected!r}, got {actual!r}"
        )

def nonnegative_integer(container, key, context):
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(
            f"performance evidence {context}.{key} must be a nonnegative integer"
        )
    return value

exact(record, "schema_version", 2, "record")
exact(record, "gate", "deterministic_performance", "record")
exact(record, "scenario", expected_scenario, "record")
exact(record, "status", "pass", "record")
exact(record, "passed", True, "record")
exact(record, "package_name", "hns-node", "record")
version = record.get("package_version")
if not isinstance(version, str) or not version:
    raise SystemExit("performance evidence package_version must be nonempty")
exact(record, "failure_detail", None, "record")

workload = record.get("workload")
thresholds = record.get("thresholds")
metrics = record.get("metrics")
evidence = record.get("evidence")
if not all(isinstance(value, dict) for value in (workload, thresholds, metrics, evidence)):
    raise SystemExit("performance evidence workload/thresholds/metrics/evidence must be objects")
exact(workload, "network", "regtest", "workload")
exact(workload, "measured_blocks", 100, "workload")
exact(workload, "requested_measured_blocks", 100, "workload")
exact(workload, "observed_measured_blocks", 100, "workload")
exact(thresholds, "tip_to_job_p99_target_micros_exclusive", 25_000, "thresholds")
exact(
    thresholds,
    "candidate_validation_p99_target_micros_exclusive",
    5_000,
    "thresholds",
)
exact(thresholds, "local_connect_p99_target_micros_exclusive", 50_000, "thresholds")
exact(metrics, "failure_count", 0, "metrics")
exact(metrics, "unavailable_evidence", 0, "metrics")
for name in (
    "template_build",
    "job_prepare",
    "tip_to_job",
    "candidate_validation",
    "local_connect",
):
    distribution = metrics.get(name)
    if not isinstance(distribution, dict):
        raise SystemExit(f"performance evidence metrics.{name} must be an object")
    exact(distribution, "count", 100, f"metrics.{name}")
    percentiles = [
        nonnegative_integer(distribution, field, f"metrics.{name}")
        for field in ("p50_micros", "p95_micros", "p99_micros", "max_micros")
    ]
    if percentiles != sorted(percentiles):
        raise SystemExit(f"performance evidence metrics.{name} is not monotonic")
if metrics["tip_to_job"]["p99_micros"] >= 25_000:
    raise SystemExit("performance evidence tip_to_job p99 misses its exclusive threshold")
if metrics["candidate_validation"]["p99_micros"] >= 5_000:
    raise SystemExit(
        "performance evidence candidate_validation p99 misses its exclusive threshold"
    )
if metrics["local_connect"]["p99_micros"] >= 50_000:
    raise SystemExit("performance evidence local_connect p99 misses its exclusive threshold")
expected_evidence = {
    "backend_matches",
    "durability_matches",
    "preparation_matches",
    "measured_blocks_match",
    "cache_evidence_matches",
    "latency_targets_pass",
}
if set(evidence) != expected_evidence:
    raise SystemExit("performance evidence has missing or unknown evidence checks")
if not evidence or any(value is not True for value in evidence.values()):
    raise SystemExit("performance evidence contains a false or non-boolean evidence check")

if expected_scenario == "smoke":
    exact(record, "backend", "memory", "record")
    exact(record, "requested_backend", "memory", "record")
    exact(record, "durability", "not-applicable", "record")
    exact(record, "requested_durability", "not-applicable", "record")
    exact(record, "data_root", None, "record")
    exact(record, "data_root_policy", "none", "record")
    exact(workload, "warmup_blocks", 10, "workload")
    exact(workload, "observed_warmup_blocks", 10, "workload")
    exact(workload, "setup_blocks", 0, "workload")
    exact(workload, "requested_setup_blocks", 0, "workload")
    exact(workload, "observed_setup_blocks", 0, "workload")
    exact(workload, "requested_cache_occupancy", None, "workload")
elif expected_scenario == "persistent-rocksdb-sync":
    exact(record, "backend", "rocksdb", "record")
    exact(record, "requested_backend", "rocksdb", "record")
    exact(record, "durability", "sync", "record")
    exact(record, "requested_durability", "sync", "record")
    exact(
        record,
        "data_root_policy",
        "automatic-create-new-scoped-cleanup",
        "record",
    )
    data_root = record.get("data_root")
    if not isinstance(data_root, str) or not data_root:
        raise SystemExit("persistent performance evidence data_root must be nonempty")
    if Path(data_root).exists() or Path(data_root).is_symlink():
        raise SystemExit("persistent performance gate left its automatic data root behind")
    exact(workload, "warmup_blocks", 0, "workload")
    exact(workload, "observed_warmup_blocks", 0, "workload")
    exact(workload, "setup_blocks", 4_096, "workload")
    exact(workload, "requested_setup_blocks", 4_096, "workload")
    exact(workload, "observed_setup_blocks", 4_096, "workload")
    exact(workload, "requested_cache_occupancy", 4_096, "workload")
    exact(workload, "observed_cache_occupancy", 4_096, "workload")
    exact(workload, "observed_final_cache_occupancy", 4_096, "workload")
    exact(workload, "observed_cache_capacity", 4_096, "workload")
else:
    raise SystemExit(f"unsupported expected performance scenario {expected_scenario}")
PY
}

run_performance_gate() {
  local gate_tier=$1
  local binary=$2
  local report=$3
  local scenario
  scenario=$(performance_scenario_for_tier "$gate_tier") || return 1
  invoke_performance_gate "$gate_tier" "$binary" "$report" || return 1
  verify_performance_gate_report "$report" "$scenario"
}

run_verifier_self_test() (
  local test_root
  test_root=$(mktemp -d "${TMPDIR:-/tmp}/hsrd-assurance-self-test.XXXXXX")
  trap 'find "$test_root" -depth -delete' EXIT

  record_performance_arguments() {
    printf '%s\n' "$@"
  }

  local smoke_report
  local scheduled_report
  local release_report
  local smoke_arguments
  local scheduled_arguments
  local release_arguments
  local expected_arguments
  smoke_report="$test_root/smoke-performance.json"
  scheduled_report="$test_root/scheduled-performance.json"
  release_report="$test_root/release-performance.json"

  smoke_arguments=$(
    invoke_performance_gate smoke record_performance_arguments "$smoke_report"
  )
  expected_arguments=$(printf '%s\n' --json-output "$smoke_report")
  if [[ "$smoke_arguments" != "$expected_arguments" ]]; then
    echo "smoke tier did not use the performance gate's default scenario" >&2
    return 1
  fi

  scheduled_arguments=$(
    invoke_performance_gate \
      scheduled record_performance_arguments "$scheduled_report"
  )
  expected_arguments=$(printf '%s\n' \
    --scenario persistent-rocksdb-sync --json-output "$scheduled_report")
  if [[ "$scheduled_arguments" != "$expected_arguments" ]]; then
    echo "scheduled tier did not select automatic-root persistent performance" >&2
    return 1
  fi

  release_arguments=$(
    invoke_performance_gate release record_performance_arguments "$release_report"
  )
  expected_arguments=$(printf '%s\n' \
    --scenario persistent-rocksdb-sync --json-output "$release_report")
  if [[ "$release_arguments" != "$expected_arguments" ]]; then
    echo "release tier did not select automatic-root persistent performance" >&2
    return 1
  fi

  if invoke_performance_gate \
    verify-external record_performance_arguments "$test_root/invalid.json" \
    >/dev/null 2>&1; then
    echo "performance routing accepted an unsupported assurance tier" >&2
    return 1
  fi

  python3 - "$test_root" "$source_revision" "$source_tree" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
revision, tree = sys.argv[2:]
external = root / "external"
raw = external / "raw"
raw.mkdir(parents=True)
hsrd_binary = raw / "hsrd"
hsrd_binary.write_bytes(b"production-assurance self-test hsrd executable\n")
hsrd_binary.chmod(0o755)
hsrd_binary_sha256 = hashlib.sha256(hsrd_binary.read_bytes()).hexdigest()
hsrd_build_manifest = raw / "hsrd-build-manifest.json"
hsrd_build_manifest.write_text(
    json.dumps(
        {
            "schema_version": 1,
            "artifact_type": "hsrd_build_manifest",
            "source_revision": revision,
            "source_tree": tree,
            "build": {
                "command": "cargo +1.89.0 build --locked --release -p hns-node --bin hsrd",
                "rust_toolchain": "1.89.0",
                "rustc_version": "rustc 1.89.0 (self-test)",
                "cargo_version": "cargo 1.89.0 (self-test)",
            },
            "binary": {
                "type": "hsrd_binary",
                "name": "hsrd",
                "path": str(hsrd_binary.relative_to(root)),
                "sha256": hsrd_binary_sha256,
            },
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
def artifact_entry(path, artifact_type=None):
    entry = {
        "path": str(path.relative_to(root)),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    if artifact_type is not None:
        entry["type"] = artifact_type
    return entry

def typed_artifact(gate, artifact_type):
    path = raw / f"{gate}-{artifact_type}.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_type": artifact_type,
                "gate": gate,
                "identity": f"self-test-{gate}-{artifact_type}",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return artifact_entry(path, artifact_type)

records = {
    "production-scale-pruning.json": (
        "production_scale_pruning",
        {
            "baseline_mode": "full_non_pruned",
            "pruned_mode": "prune_history",
            "rollback_horizon_blocks": 288,
            "dataset_height": 339_660,
            "host_id": "self-test-host",
            "filesystem": "self-test-filesystem",
            "measurement_scope": "same-data-root-byte-accounting",
        },
        {
            "block_records": 300_000,
            "utxo_records": 20_000_000,
            "name_records": 10_000_000,
            "rollback_horizon_blocks": 288,
            "reclaimed_bytes": 1,
            "duration_seconds": 3_600,
            "peak_rss_bytes": 1,
            "peak_disk_bytes": 140_000_000_000,
            "final_disk_bytes": 130_000_000_000,
            "pruned_final_disk_bytes": 120_000_000_000,
            "rocksdb_background_errors": 0,
            "resource_limits_respected": True,
            "hsd_blocks_deleted": False,
            "comparison_scope_identical": True,
            "pre_inventory_valid": True,
            "post_inventory_valid": True,
            "restart_tip_match": True,
            "fallback_restore_verified": True,
        },
    ),
    "rocksdb-fault-injection.json": (
        "rocksdb_fault_injection",
        {
            "storage_backend": "rocksdb",
            "host_id": "self-test-host",
            "filesystem": "self-test-filesystem",
            "injection_point_ids": [f"point-{index}" for index in range(8)],
        },
        {
            "injection_points": 8,
            "iterations_per_point": 100,
            "iterations": 800,
            "reopen_failures": 0,
            "tip_mismatches": 0,
            "root_mismatches": 0,
            "unexpected_authority_grants": 0,
        },
    ),
    "sustained-reorg-partition.json": (
        "sustained_reorg_partition",
        {
            "topology_id": "three-peer-partition",
            "state_oracle_revision": "self-test-state-oracle",
            "peer_ids": ["peer-a", "peer-b", "peer-c"],
            "partition_cycle_ids": ["partition-a", "partition-b", "partition-c"],
        },
        {
            "duration_seconds": 21_600,
            "peer_count": 3,
            "partition_cycles": 3,
            "real_reorganizations": 1,
            "state_parity_mismatches": 0,
            "unexpected_authority_grants": 0,
        },
    ),
    "wan-load-latency.json": (
        "wan_load_latency",
        {
            "topology_id": "two-site-wan",
            "clock_sync_profile": "self-test-ptp-profile",
            "site_ids": ["site-a", "site-b"],
        },
        {
            "duration_seconds": 3_600,
            "site_count": 2,
            "samples": 1_000,
            "job_delivery_p99_millis": 250,
            "candidate_to_first_peer_p99_millis": 500,
            "failed_samples": 0,
            "unavailable_samples": 0,
        },
    ),
    "physical-gateway-asic.json": (
        "physical_gateway_asic",
        {
            "device_kind": "physical_asic",
            "device_id": "self-test-device",
            "device_model": "self-test-model",
            "firmware_version": "self-test-firmware",
            "gateway_version": "self-test-gateway",
            "fallback_cycle_ids": ["fallback-a", "fallback-b", "fallback-c"],
        },
        {
            "duration_seconds": 14_400,
            "jobs_observed": 1_000,
            "valid_shares": 1,
            "valid_block_candidates": 1,
            "fallback_recovery_cycles": 3,
            "job_switch_p99_millis": 250,
            "invalid_jobs": 0,
            "unreconciled_receipts": 0,
        },
    ),
    "long-duration-multi-peer.json": (
        "long_duration_multi_peer",
        {
            "topology_id": "eight-peer-soak",
            "peer_ids": [f"peer-{index}" for index in range(8)],
            "restart_ids": ["restart-a", "restart-b", "restart-c"],
        },
        {
            "duration_seconds": 86_400,
            "peer_count": 8,
            "controlled_restarts": 3,
            "tip_divergences": 0,
            "database_recovery_failures": 0,
            "unexpected_authority_grants": 0,
        },
    ),
    "mempool-template-differential.json": (
        "mempool_template_differential",
        {
            "oracle_name": "self-test-hsd-oracle",
            "oracle_revision": "self-test-oracle-revision",
            "normalization_revision": "self-test-normalization-revision",
        },
        {
            "transaction_cases": 10_000,
            "template_cases": 1_000,
            "reorg_reconciliation_cases": 100,
            "mempool_mismatches": 0,
            "template_mismatches": 0,
            "publication_mismatches": 0,
        },
    ),
}

artifact_bindings = {
    "production_scale_pruning": (
        ("dataset_manifest_sha256", "dataset_manifest"),
        ("baseline_config_sha256", "baseline_configuration"),
        ("pruned_config_sha256", "pruned_configuration"),
    ),
    "rocksdb_fault_injection": (
        ("dataset_manifest_sha256", "dataset_manifest"),
        ("fault_schedule_sha256", "fault_schedule"),
        ("seed_manifest_sha256", "seed_manifest"),
    ),
    "sustained_reorg_partition": (
        ("partition_schedule_sha256", "partition_schedule"),
        ("competing_chain_manifest_sha256", "competing_chain_manifest"),
    ),
    "wan_load_latency": (
        ("load_profile_sha256", "load_profile"),
        ("network_profile_sha256", "network_profile"),
    ),
    "physical_gateway_asic": (
        ("gateway_binary_sha256", "gateway_binary"),
        ("fallback_plan_sha256", "fallback_plan"),
    ),
    "long_duration_multi_peer": (
        ("peer_set_sha256", "peer_set_manifest"),
        ("restart_schedule_sha256", "restart_schedule"),
        ("authority_policy_sha256", "authority_policy"),
    ),
    "mempool_template_differential": (
        ("oracle_binary_sha256", "oracle_binary"),
        ("corpus_manifest_sha256", "corpus_manifest"),
        ("mempool_policy_sha256", "mempool_policy"),
    ),
}

for filename, (gate, configuration, metrics) in records.items():
    configuration = {
        **configuration,
        "network": "mainnet",
        "binary_sha256": hsrd_binary_sha256,
        "binary_manifest_path": str(hsrd_build_manifest.relative_to(root)),
    }
    artifact = raw / f"{gate}.log"
    artifact.write_text(f"self-test artifact for {gate}\n", encoding="utf-8")
    artifacts = [
        artifact_entry(artifact),
        artifact_entry(hsrd_binary, "hsrd_binary"),
        artifact_entry(hsrd_build_manifest, "hsrd_build_manifest"),
    ]
    for field, artifact_type in artifact_bindings[gate]:
        bound_artifact = typed_artifact(gate, artifact_type)
        configuration[field] = bound_artifact["sha256"]
        artifacts.append(bound_artifact)

    campaign_path = raw / f"{gate}-campaign-configuration.json"
    campaign_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_type": "hsrd_campaign_configuration",
                "gate": gate,
                "source_revision": revision,
                "source_tree": tree,
                "configuration": configuration,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    campaign_artifact = artifact_entry(
        campaign_path, "hsrd_campaign_configuration"
    )
    configuration["campaign_config_path"] = campaign_artifact["path"]
    configuration["campaign_config_sha256"] = campaign_artifact["sha256"]
    artifacts.append(campaign_artifact)

    record = {
        "schema_version": 2,
        "gate": gate,
        "status": "pass",
        "source_revision": revision,
        "source_tree": tree,
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-02T00:00:01Z",
        "operator": "self-test-operator",
        "reviewer": "self-test-reviewer",
        "tool": {"name": "self-test", "version": "1"},
        "configuration": configuration,
        "metrics": metrics,
        "artifacts": artifacts,
    }
    (external / filename).write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
PY

  cp -R "$test_root/external" "$test_root/valid-external"

  mutate_self_test_configuration() {
    local filename=$1
    local mode=$2
    local field=$3
    local encoded_value=$4
    python3 - "$test_root" "$filename" "$mode" "$field" "$encoded_value" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
filename, mode, field, encoded_value = sys.argv[2:]
path = root / "external" / filename
record = json.loads(path.read_text(encoding="utf-8"))
campaign_artifact = next(
    artifact
    for artifact in record["artifacts"]
    if artifact.get("type") == "hsrd_campaign_configuration"
)
campaign_path = root / campaign_artifact["path"]
if mode == "replace":
    configuration = json.loads(encoded_value)
elif mode == "set":
    configuration = dict(record["configuration"])
    configuration.pop("campaign_config_path", None)
    configuration.pop("campaign_config_sha256", None)
    configuration[field] = json.loads(encoded_value)
else:
    raise SystemExit(f"unknown self-test mutation mode: {mode}")

campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
campaign["configuration"] = configuration
campaign_path.write_text(
    json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
campaign_digest = hashlib.sha256(campaign_path.read_bytes()).hexdigest()
configuration["campaign_config_path"] = campaign_artifact["path"]
configuration["campaign_config_sha256"] = campaign_digest
record["configuration"] = configuration
campaign_artifact["sha256"] = campaign_digest
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  }

  restore_self_test_gate() {
    local filename=$1
    local gate=$2
    cp "$test_root/valid-external/$filename" "$test_root/external/$filename"
    cp \
      "$test_root/valid-external/raw/${gate}-campaign-configuration.json" \
      "$test_root/external/raw/${gate}-campaign-configuration.json"
  }

  verify_external_evidence "$test_root" >/dev/null
  mutate_self_test_configuration \
    "long-duration-multi-peer.json" set binary_sha256 \
    '"0000000000000000000000000000000000000000000000000000000000000000"'
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a non-pruning binary unrelated to hsrd" >&2
    return 1
  fi
  restore_self_test_gate \
    "long-duration-multi-peer.json" long_duration_multi_peer

  mutate_self_test_configuration \
    "rocksdb-fault-injection.json" replace ignored '{"unrelated":true}'
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted an unrelated fault-campaign configuration" >&2
    return 1
  fi
  restore_self_test_gate \
    "rocksdb-fault-injection.json" rocksdb_fault_injection

  mutate_self_test_configuration \
    "mempool-template-differential.json" set oracle_revision '"   "'
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a blank differential oracle revision" >&2
    return 1
  fi
  restore_self_test_gate \
    "mempool-template-differential.json" mempool_template_differential

  mutate_self_test_configuration \
    "wan-load-latency.json" set load_profile_sha256 \
    '"0000000000000000000000000000000000000000000000000000000000000000"'
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted an unrelated typed configuration artifact" >&2
    return 1
  fi
  restore_self_test_gate "wan-load-latency.json" wan_load_latency

  mutate_self_test_configuration \
    "wan-load-latency.json" set site_ids '["site-a"]'
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a site list inconsistent with site_count" >&2
    return 1
  fi
  restore_self_test_gate "wan-load-latency.json" wan_load_latency

  mutate_self_test_configuration \
    "production-scale-pruning.json" set rollback_horizon_blocks '289'
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a mismatched pruning rollback horizon" >&2
    return 1
  fi
  restore_self_test_gate \
    "production-scale-pruning.json" production_scale_pruning

  python3 - "$test_root/external/production-scale-pruning.json" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["metrics"]["peak_disk_bytes"] = 150_000_000_001
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a full baseline above 150,000,000,000 bytes" >&2
    return 1
  fi
  python3 - "$test_root/external/production-scale-pruning.json" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["metrics"]["peak_disk_bytes"] = 140_000_000_000
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  python3 - "$test_root/external/rocksdb-fault-injection.json" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["metrics"]["iterations_per_point"] = 99
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted fewer than 100 trials per fault point" >&2
    return 1
  fi
  python3 - "$test_root/external/rocksdb-fault-injection.json" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["metrics"]["iterations_per_point"] = 100
path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  printf 'tamper\n' >>"$test_root/external/raw/production_scale_pruning.log"
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a tampered artifact" >&2
    return 1
  fi
  printf 'self-test artifact for production_scale_pruning\n' \
    >"$test_root/external/raw/production_scale_pruning.log"
  rm "$test_root/external/rocksdb-fault-injection.json"
  if verify_external_evidence "$test_root" >/dev/null 2>&1; then
    echo "external verifier accepted a missing evidence record" >&2
    return 1
  fi
  mkdir "$test_root/fake-bin"
  printf '#!/usr/bin/env sh\nprintf "cargo-fuzz 9.9.9\\\\n"\n' \
    >"$test_root/fake-bin/cargo"
  printf '#!/usr/bin/env sh\nprintf "rustc self-test\\\\n"\n' \
    >"$test_root/fake-bin/rustc"
  chmod +x "$test_root/fake-bin/cargo" "$test_root/fake-bin/rustc"
  set +e
  PATH="$test_root/fake-bin:$PATH" \
    FUZZ_RUST_TOOLCHAIN=nightly-2025-08-07 \
    "$repo_root/scripts/run-sustained-fuzz.sh" \
    --duration-seconds 1 \
    --target header_parser \
    --output-dir "$test_root/unpinned-fuzz" \
    >/dev/null 2>&1
  unpinned_status=$?
  set -e
  if ((unpinned_status == 0)); then
    echo "sustained fuzz accepted an unpinned cargo-fuzz version" >&2
    return 1
  fi
  python3 - "$test_root/unpinned-fuzz/summary.json" <<'PY'
import json
from pathlib import Path
import sys

record = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert record["status"] == "fail"
assert record["tool"]["cargo_fuzz_version"] == "cargo-fuzz 9.9.9"
assert record["tool"]["expected_cargo_fuzz_version"] == "cargo-fuzz 0.13.2"
assert record["targets"][0]["status"] == "not_run"
PY
  set +e
  stable_guard=$(require_clean_worktree wrong-stable nightly-2025-08-07 2>&1)
  stable_guard_status=$?
  set -e
  if ((stable_guard_status == 0)) ||
    [[ "$stable_guard" != *"RUST_TOOLCHAIN=1.89.0"* ]]; then
    echo "scheduled/release guard did not enforce Rust 1.89.0" >&2
    return 1
  fi
  set +e
  nightly_guard=$(require_clean_worktree 1.89.0 wrong-nightly 2>&1)
  nightly_guard_status=$?
  set -e
  if ((nightly_guard_status == 0)) ||
    [[ "$nightly_guard" != *"FUZZ_RUST_TOOLCHAIN=nightly-2025-08-07"* ]]; then
    echo "scheduled/release guard did not enforce the pinned nightly" >&2
    return 1
  fi
  if require_external_evidence_path "$repo_root/assurance-self-test" \
    >/dev/null 2>&1; then
    echo "scheduled/release guard accepted an in-repository evidence path" >&2
    return 1
  fi
  require_external_evidence_path "$test_root/outside-evidence"
  echo "production assurance verifier self-test passed"
)

run_software_gates() {
  local output=$1
  local include_fuzz=$2
  if [[ -e "$output" || -L "$output" ]]; then
    echo "refusing to reuse software evidence directory: $output" >&2
    return 1
  fi
  mkdir -p "$output"
  output=$(cd "$output" && pwd)

  cargo +"$rust_toolchain" build --locked --release \
    -p hns-node --bin hsrd --bin hsrd-performance-gate
  run_performance_gate \
    "$tier" \
    "$cargo_target_dir/release/hsrd-performance-gate" \
    "$output/deterministic-performance.json"
  "$repo_root/scripts/qualify-two-node-regtest.sh" \
    "$cargo_target_dir/release/hsrd" >"$output/two-node-regtest.log" 2>&1

  if [[ "$include_fuzz" == true ]]; then
    FUZZ_RUST_TOOLCHAIN="$fuzz_rust_toolchain" \
      "$repo_root/scripts/run-sustained-fuzz.sh" \
      --duration-seconds "$fuzz_duration_seconds" \
      --output-dir "$output/sustained-fuzz"
  fi

  if [[ -z "$(git status --porcelain --untracked-files=all)" ]]; then
    source_dirty_completed=false
  else
    source_dirty_completed=true
  fi
  final_revision=$(git rev-parse HEAD)
  final_tree=$(git rev-parse 'HEAD^{tree}')
  final_worktree=$(worktree_digest)
  if [[ "$source_revision" != "$final_revision" ||
    "$source_tree" != "$final_tree" ||
    "$source_worktree" != "$final_worktree" ]]; then
    source_changed=true
  else
    source_changed=false
  fi
  rustc_version=$(rustc +"$rust_toolchain" --version)
  cargo_version=$(cargo +"$rust_toolchain" --version)
  python3 - \
    "$output" "$source_revision" "$source_tree" "$source_dirty_started" \
    "$source_worktree" "$final_revision" "$final_tree" "$final_worktree" \
    "$source_changed" \
    "$source_dirty_completed" \
    "$rust_toolchain" "$rustc_version" "$cargo_version" \
    "$fuzz_rust_toolchain" "$include_fuzz" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
(
    revision,
    tree,
    source_dirty,
    source_worktree,
    final_revision,
    final_tree,
    final_worktree,
    source_changed,
    source_dirty_completed,
    toolchain,
    rustc_version,
    cargo_version,
    fuzz_toolchain,
    include_fuzz,
) = sys.argv[2:]

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

artifacts = []
for path in sorted(item for item in output.rglob("*") if item.is_file()):
    if path.name == "software-summary.json":
        continue
    artifacts.append(
        {
            "path": str(path.relative_to(output)),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    )
summary = {
    "schema_version": 1,
    "gate": "software_assurance",
    "status": "fail" if source_changed == "true" else "pass",
    "source_revision": revision,
    "source_tree": tree,
    "source_dirty": source_dirty == "true",
    "source_worktree_sha256": source_worktree,
    "source_at_completion": {
        "revision": final_revision,
        "tree": final_tree,
        "dirty": source_dirty_completed == "true",
        "worktree_sha256": final_worktree,
    },
    "source_changed_during_gates": source_changed == "true",
    "tool": {
        "rust_toolchain": toolchain,
        "rustc_version": rustc_version,
        "cargo_version": cargo_version,
        "fuzz_rust_toolchain": fuzz_toolchain,
    },
    "includes_sustained_fuzz": include_fuzz == "true",
    "artifacts": artifacts,
}
(output / "software-summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
  echo "software assurance evidence: $output/software-summary.json"
  if [[ "$source_changed" == true ]]; then
    echo "worktree changed while software assurance was running" >&2
    return 1
  fi
}

write_release_summary() {
  local root=$1
  if [[ -e "$root/release-summary.json" || -L "$root/release-summary.json" ]]; then
    echo "refusing to overwrite release-summary.json" >&2
    return 1
  fi
  python3 - "$root" "$source_revision" "$source_tree" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
revision, tree = sys.argv[2:]

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

artifacts = []
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    if path.name == "release-summary.json":
        continue
    artifacts.append(
        {
            "path": str(path.relative_to(root)),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    )
summary = {
    "schema_version": 1,
    "gate": "production_release_assurance",
    "status": "pass",
    "source_revision": revision,
    "source_tree": tree,
    "artifacts": artifacts,
}
with (root / "release-summary.json").open("x", encoding="utf-8") as handle:
    handle.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
PY
  echo "release assurance evidence: $root/release-summary.json"
}

case "$tier" in
  smoke)
    run_software_gates "$evidence_dir" false
    ;;
  scheduled)
    require_clean_worktree
    require_external_evidence_path "$evidence_dir"
    run_software_gates "$evidence_dir" true
    ;;
  verify-external)
    verify_external_evidence "$evidence_dir"
    ;;
  release)
    require_clean_worktree
    require_external_evidence_path "$evidence_dir"
    if [[ ! -d "$evidence_dir" || -L "$evidence_dir" ]]; then
      echo "release evidence root must already contain external records" >&2
      exit 1
    fi
    run_software_gates "$evidence_dir/software" true
    verify_external_evidence "$evidence_dir"
    write_release_summary "$evidence_dir"
    ;;
  self-test)
    run_verifier_self_test
    ;;
esac
