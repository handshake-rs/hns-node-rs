#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

SCRIPT_PATH=$(realpath -e -- "${BASH_SOURCE[0]}")
readonly SCRIPT_PATH
REPO_ROOT=$(realpath -e -- "$(dirname -- "$SCRIPT_PATH")/..")
readonly REPO_ROOT
readonly SCHEMA_VERSION=1
readonly DEFAULT_LIMIT_BYTES=150000000000
readonly INFORMATIONAL_COMPARISON_BYTES=90000000000
readonly DEFAULT_FILESYSTEM_RESERVE_BYTES=10000000000
readonly DEFAULT_SAMPLE_SECONDS=60
readonly DEFAULT_COMPLETION_SAMPLES=5
readonly DEFAULT_SHUTDOWN_GRACE_SECONDS=120
readonly DEFAULT_MAXIMUM_SAMPLES=250000
readonly LOG_CHUNK_BYTES=67108864
readonly LOG_SLOTS=8
readonly MAX_AUTH_BYTES=4096
readonly LOG_SCANNER_CHILD_EXIT_GRACE_POLLS=50
readonly LOG_SCANNER_CHILD_EXIT_GRACE_SLEEP_SECONDS=0.01

command_name=${1:-}
if (($#)); then
  shift
fi

binary=
data_root=
evidence_dir=
auth_file=
limit_bytes=$DEFAULT_LIMIT_BYTES
filesystem_reserve_bytes=$DEFAULT_FILESYSTEM_RESERVE_BYTES
sample_seconds=$DEFAULT_SAMPLE_SECONDS
completion_samples=$DEFAULT_COMPLETION_SAMPLES
maximum_samples=$DEFAULT_MAXIMUM_SAMPLES
shutdown_grace_seconds=$DEFAULT_SHUTDOWN_GRACE_SECONDS
rpc_port=12037

campaign_id=
campaign_started_epoch=0
campaign_started_at=
attempt=0
sample_sequence=0
baseline_fs_used_bytes=0
baseline_fs_available_bytes=0
data_filesystem_device=
data_filesystem_mount=
config_sha256=
binary_sha256=
binary_file_identity=
auth_identity=
source_revision=
source_tree=
source_worktree_sha256=
source_dirty=true
maximum_observed_vm_hwm_bytes=0
maximum_sampled_apparent_bytes=0
maximum_sampled_allocated_bytes=0
maximum_sampled_filesystem_used_delta_bytes=0
maximum_sampled_storage_bytes=0
minimum_sampled_filesystem_available_bytes=0
consecutive_synced_samples=0
completed_sync_height=
completed_sync_hash=
child_pid=
child_start_ticks=
log_scanner_pid=
log_scanner_start_ticks=
log_scanner_exit=
log_scanner_reaped=false
log_scanner_failure_detail=
log_scanner_clean_exit_child_transition=false
self_test_interpreter_image_allowance=false
child_image_fd=
child_expected_image_path=
child_expected_image_identity=
child_expected_image_sha256=
child_image_verification_count=0
child_launch_image_fd_verified_at_finalization=false
runner_pid=$$
runner_start_ticks=
runtime_fifo=
rpc_response_tmp=
stop_request=
measurement_error=
forced_shutdown=false
authorization_value_emitted=false
authorization_retention_guaranteed=true
run_finalized=false
exit_trap_active=false

usage() {
  cat <<'EOF'
Usage:
  scripts/run-full-sync-qualification.sh run \
    --binary /absolute/path/to/hsrd \
    --data-root /absolute/new/or/empty/hsrd-data \
    --evidence-dir /absolute/new/or/empty/evidence \
    --auth-file /absolute/private/mode-0600/header \
    [--limit-bytes 150000000000] \
    [--filesystem-reserve-bytes 10000000000] \
    [--sample-seconds 60] [--completion-samples 5] \
    [--maximum-samples 250000] \
    [--shutdown-grace-seconds 120] [--rpc-port 12037]

  scripts/run-full-sync-qualification.sh resume \
    --evidence-dir /absolute/existing/evidence

  scripts/run-full-sync-qualification.sh status \
    --evidence-dir /absolute/existing/evidence

  scripts/run-full-sync-qualification.sh stop \
    --evidence-dir /absolute/existing/evidence

  scripts/run-full-sync-qualification.sh self-test

The run command accepts only a genuinely empty, nonsymlink data root and
evidence directory. It checks the exact archive-mode mainnet configuration
before either directory is initialized. Disk use and filesystem reserve are
checked conservatively at each sample and once during finalization. The
150,000,000,000-byte cutoff is the only sampled storage stop threshold. The
separate 10,000,000,000-byte filesystem reserve is also enforced. The
90,000,000,000-byte value is an informational sampled comparison only, not a
qualification criterion, kernel quota, or claim about unobserved transient use.

The runner stays in the foreground. Use status and stop from another terminal.
resume reuses only the exact binary, authorization-file identity, configuration,
data root, and initial filesystem baseline recorded by an interrupted campaign.
EOF
}

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 2
}

require_value() {
  local option=$1
  local count=$2
  ((count >= 2)) || die "missing value for $option"
}

set_once() {
  local name=$1
  local option=$2
  local value=$3
  local current
  current=${!name}
  [[ -z "$current" ]] || die "$option was provided more than once"
  printf -v "$name" '%s' "$value"
}

parse_run_arguments() {
  local limit_set=false
  local reserve_set=false
  local sample_set=false
  local completion_set=false
  local maximum_samples_set=false
  local grace_set=false
  local port_set=false
  local self_test_image_set=false

  while (($#)); do
    case "$1" in
      --binary)
        require_value "$1" "$#"
        set_once binary "$1" "$2"
        shift 2
        ;;
      --data-root)
        require_value "$1" "$#"
        set_once data_root "$1" "$2"
        shift 2
        ;;
      --evidence-dir)
        require_value "$1" "$#"
        set_once evidence_dir "$1" "$2"
        shift 2
        ;;
      --auth-file)
        require_value "$1" "$#"
        set_once auth_file "$1" "$2"
        shift 2
        ;;
      --limit-bytes)
        require_value "$1" "$#"
        [[ "$limit_set" == false ]] || die "$1 was provided more than once"
        limit_set=true
        limit_bytes=$2
        shift 2
        ;;
      --filesystem-reserve-bytes)
        require_value "$1" "$#"
        [[ "$reserve_set" == false ]] || die "$1 was provided more than once"
        reserve_set=true
        filesystem_reserve_bytes=$2
        shift 2
        ;;
      --sample-seconds)
        require_value "$1" "$#"
        [[ "$sample_set" == false ]] || die "$1 was provided more than once"
        sample_set=true
        sample_seconds=$2
        shift 2
        ;;
      --completion-samples)
        require_value "$1" "$#"
        [[ "$completion_set" == false ]] || die "$1 was provided more than once"
        completion_set=true
        completion_samples=$2
        shift 2
        ;;
      --maximum-samples)
        require_value "$1" "$#"
        [[ "$maximum_samples_set" == false ]] || die "$1 was provided more than once"
        maximum_samples_set=true
        maximum_samples=$2
        shift 2
        ;;
      --shutdown-grace-seconds)
        require_value "$1" "$#"
        [[ "$grace_set" == false ]] || die "$1 was provided more than once"
        grace_set=true
        shutdown_grace_seconds=$2
        shift 2
        ;;
      --rpc-port)
        require_value "$1" "$#"
        [[ "$port_set" == false ]] || die "$1 was provided more than once"
        port_set=true
        rpc_port=$2
        shift 2
        ;;
      --self-test-allow-interpreter-image)
        [[ "$self_test_image_set" == false ]] ||
          die "$1 was provided more than once"
        self_test_image_set=true
        self_test_interpreter_image_allowance=true
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown run option: $1"
        ;;
    esac
  done

  [[ -n "$binary" ]] || die "run requires --binary"
  [[ -n "$data_root" ]] || die "run requires --data-root"
  [[ -n "$evidence_dir" ]] || die "run requires --evidence-dir"
  [[ -n "$auth_file" ]] || die "run requires --auth-file"
}

parse_evidence_only_arguments() {
  while (($#)); do
    case "$1" in
      --evidence-dir)
        require_value "$1" "$#"
        set_once evidence_dir "$1" "$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown $command_name option: $1"
        ;;
    esac
  done
  [[ -n "$evidence_dir" ]] || die "$command_name requires --evidence-dir"
}

require_commands() {
  local name
  for name in \
    awk bash basename cargo cat chmod cp curl date dd df dirname du env find findmnt \
    flock git grep head hostname id jq ln mkdir mkfifo mktemp mv ps python3 \
    readlink realpath rm rustc rustup sed sha256sum sleep sort stat timeout tr \
    uname; do
    command -v "$name" >/dev/null 2>&1 || die "required command is unavailable: $name"
  done
}

is_unsigned_integer() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

validate_numeric_options() {
  is_unsigned_integer "$limit_bytes" || die "--limit-bytes must be an unsigned integer"
  is_unsigned_integer "$filesystem_reserve_bytes" ||
    die "--filesystem-reserve-bytes must be an unsigned integer"
  is_unsigned_integer "$sample_seconds" ||
    die "--sample-seconds must be an unsigned integer"
  is_unsigned_integer "$completion_samples" ||
    die "--completion-samples must be an unsigned integer"
  is_unsigned_integer "$maximum_samples" ||
    die "--maximum-samples must be an unsigned integer"
  is_unsigned_integer "$shutdown_grace_seconds" ||
    die "--shutdown-grace-seconds must be an unsigned integer"
  is_unsigned_integer "$rpc_port" || die "--rpc-port must be an unsigned integer"

  ((limit_bytes > 0 && limit_bytes <= 9000000000000000000)) ||
    die "--limit-bytes must be between 1 and 9000000000000000000"
  ((filesystem_reserve_bytes <= 9000000000000000000 - limit_bytes)) ||
    die "limit plus filesystem reserve exceeds the supported integer range"
  ((sample_seconds >= 1 && sample_seconds <= 300)) ||
    die "--sample-seconds must be between 1 and 300"
  ((completion_samples >= 1 && completion_samples <= 60)) ||
    die "--completion-samples must be between 1 and 60"
  ((maximum_samples >= 1 && maximum_samples <= DEFAULT_MAXIMUM_SAMPLES)) ||
    die "--maximum-samples must be between 1 and $DEFAULT_MAXIMUM_SAMPLES"
  ((shutdown_grace_seconds >= 1 && shutdown_grace_seconds <= 600)) ||
    die "--shutdown-grace-seconds must be between 1 and 600"
  ((rpc_port >= 1024 && rpc_port <= 65535)) ||
    die "--rpc-port must be between 1024 and 65535"
}

reject_control_characters() {
  local value=$1
  local label=$2
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] ||
    die "$label contains a control character"
}

normalize_absolute_path() {
  local value=$1
  local label=$2
  local normalized

  reject_control_characters "$value" "$label"
  [[ "$value" == /* ]] || die "$label must be absolute"
  normalized=$(realpath -m -- "$value") ||
    die "could not normalize $label"
  [[ "$normalized" == "$value" ]] ||
    die "$label must be canonical and must not traverse symbolic links: $value"
  [[ "$value" != / ]] || die "$label may not be the filesystem root"
  printf '%s\n' "$normalized"
}

nearest_existing_ancestor() {
  local path=$1
  local probe=$path
  while [[ ! -e "$probe" && ! -L "$probe" ]]; do
    probe=$(dirname -- "$probe")
  done
  [[ -d "$probe" && ! -L "$probe" ]] ||
    die "nearest existing ancestor is not a safe directory: $probe"
  printf '%s\n' "$probe"
}

directory_is_empty() {
  local path=$1
  [[ -z "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]]
}

validate_new_directory_target() {
  local path=$1
  local label=$2
  local ancestor

  if [[ -e "$path" || -L "$path" ]]; then
    [[ -d "$path" && ! -L "$path" ]] ||
      die "$label exists but is not a nonsymlink directory: $path"
    directory_is_empty "$path" ||
      die "$label must be empty: $path"
  else
    ancestor=$(nearest_existing_ancestor "$path")
    [[ "$(realpath -e -- "$ancestor")" == "$ancestor" ]] ||
      die "$label has a symbolic-link ancestor"
  fi
}

validate_existing_private_directory() {
  local path=$1
  local label=$2
  local owner mode

  [[ -d "$path" && ! -L "$path" ]] ||
    die "$label must be an existing nonsymlink directory: $path"
  [[ "$(realpath -e -- "$path")" == "$path" ]] ||
    die "$label must not traverse symbolic links"
  owner=$(stat -Lc '%u' -- "$path")
  mode=$(stat -Lc '%a' -- "$path")
  [[ "$owner" == "$(id -u)" ]] || die "$label must be owned by the current user"
  (( (8#$mode & 8#077) == 0 )) ||
    die "$label must not be accessible by group or other users"
}

paths_overlap() {
  local first=$1
  local second=$2
  [[ "$first" == "$second" || "$first" == "$second/"* || "$second" == "$first/"* ]]
}

validate_campaign_path_scope() {
  paths_overlap "$data_root" "$evidence_dir" &&
    die "data root and evidence directory must be disjoint"
  paths_overlap "$data_root" "$REPO_ROOT" &&
    die "data root must be outside the source repository"
  paths_overlap "$evidence_dir" "$REPO_ROOT" &&
    die "evidence directory must be outside the source repository"
  return 0
}

validate_self_test_interpreter_image_allowance() {
  [[ "$self_test_interpreter_image_allowance" == true ]] || return 0
  local test_root parent_cwd arg candidate
  local found_script=false found_self_test=false

  test_root=$(dirname -- "$binary")
  [[ "$test_root" == "${TMPDIR:-/tmp}/hsrd-full-sync-self-test."* &&
    "$binary" == "$test_root/"* &&
    "$data_root" == "$test_root/"* &&
    "$evidence_dir" == "$test_root/"* &&
    "$auth_file" == "$test_root/"* ]] ||
    die "interpreter-image allowance is restricted to the isolated self-test tree"
  [[ -r "/proc/$PPID/cmdline" ]] ||
    die "could not verify the interpreter-image allowance parent"
  parent_cwd=$(readlink -e -- "/proc/$PPID/cwd") ||
    die "could not verify the interpreter-image allowance parent directory"
  while IFS= read -r -d '' arg; do
    [[ "$arg" == self-test ]] && found_self_test=true
    if [[ "$arg" == "$SCRIPT_PATH" ]]; then
      found_script=true
    elif [[ "$arg" == */* ]]; then
      if [[ "$arg" == /* ]]; then
        candidate=$(realpath -m -- "$arg")
      else
        candidate=$(realpath -m -- "$parent_cwd/$arg")
      fi
      [[ "$candidate" == "$SCRIPT_PATH" ]] && found_script=true
    fi
  done <"/proc/$PPID/cmdline"
  [[ "$found_script" == true && "$found_self_test" == true ]] ||
    die "interpreter-image allowance requires the runner's self-test parent"
}

validate_binary() {
  local owner_mode

  binary=$(normalize_absolute_path "$binary" "binary path")
  [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] ||
    die "binary must be an executable nonsymlink regular file"
  owner_mode=$(stat -Lc '%A' -- "$binary")
  [[ "$owner_mode" == -* ]] || die "binary is not a regular file"
  binary_sha256=$(sha256sum -- "$binary" | awk '{print $1}')
  [[ "$binary_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    die "could not calculate the binary SHA-256"
  binary_file_identity=$(executable_file_identity "$binary")
}

executable_file_identity() {
  local path=$1
  python3 - "$path" <<'PY'
import os
import stat
import sys

metadata = os.stat(sys.argv[1], follow_symlinks=True)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("executable image is not a regular file")
print(
    f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_size}:"
    f"{metadata.st_mtime_ns}:{metadata.st_ctime_ns}:"
    f"{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_uid}:{metadata.st_nlink}"
)
PY
}

auth_file_identity() {
  local path=$1
  python3 - "$path" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
metadata = os.stat(path, follow_symlinks=False)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("authorization path is not a regular file")
print(
    f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_size}:"
    f"{metadata.st_mtime_ns}:{metadata.st_ctime_ns}:"
    f"{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_uid}:{metadata.st_nlink}"
)
PY
}

validate_auth_file() {
  local mode owner size links

  auth_file=$(normalize_absolute_path "$auth_file" "authorization file")
  [[ -f "$auth_file" && ! -L "$auth_file" ]] ||
    die "authorization file must be a nonsymlink regular file"
  mode=$(stat -Lc '%a' -- "$auth_file")
  owner=$(stat -Lc '%u' -- "$auth_file")
  size=$(stat -Lc '%s' -- "$auth_file")
  links=$(stat -Lc '%h' -- "$auth_file")
  [[ "$owner" == "$(id -u)" ]] ||
    die "authorization file must be owned by the current user"
  (( (8#$mode & 8#400) != 0 && (8#$mode & 8#077) == 0 )) ||
    die "authorization file must be owner-readable and inaccessible to group/other"
  ((size >= 1 && size <= MAX_AUTH_BYTES)) ||
    die "authorization file must contain between 1 and $MAX_AUTH_BYTES bytes"
  ((links == 1)) ||
    die "authorization file must have exactly one hard link"
  python3 - "$auth_file" <<'PY' ||
from pathlib import Path
import sys

raw = Path(sys.argv[1]).read_bytes()
if raw.endswith(b"\n"):
    raw = raw[:-1]
if not raw or raw != raw.strip() or b"\n" in raw or b"\r" in raw:
    raise SystemExit(1)
if any(byte < 0x20 or byte > 0x7e for byte in raw):
    raise SystemExit(1)
PY
    die "authorization file must contain one nonempty printable-ASCII header value"
  auth_identity=$(auth_file_identity "$auth_file")
}

filesystem_numbers() {
  local path=$1
  local output
  output=$(df -B1 --output=size,used,avail -- "$path" | awk 'NR == 2 {print $1, $2, $3}')
  [[ "$output" =~ ^[0-9]+\ [0-9]+\ [0-9]+$ ]] ||
    return 1
  printf '%s\n' "$output"
}

filesystem_provenance() {
  local path=$1
  findmnt --json --target "$path" --output SOURCE,TARGET,FSTYPE,OPTIONS,FSROOT
}

worktree_digest() {
  python3 - "$REPO_ROOT" <<'PY'
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

capture_source_provenance() {
  git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    die "runner is not inside a Git worktree"
  source_revision=$(git -C "$REPO_ROOT" rev-parse --verify HEAD)
  source_tree=$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')
  source_worktree_sha256=$(worktree_digest)
  if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]]; then
    source_dirty=false
  else
    source_dirty=true
  fi
}

process_start_ticks() {
  local pid=$1
  [[ -r "/proc/$pid/stat" ]] || return 1
  sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{print $20}'
}

process_state() {
  local pid=$1
  [[ -r "/proc/$pid/stat" ]] || return 1
  sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{print $1}'
}

process_identity_is_live() {
  local pid=$1
  local ticks=$2
  local state
  proc_identity_matches "$pid" "$ticks" || return 1
  state=$(process_state "$pid") || return 1
  [[ "$state" != Z && "$state" != X ]]
}

child_process_is_live() {
  process_identity_is_live "$child_pid" "$child_start_ticks"
}

observe_process_image() {
  local pid=$1
  local observation
  observation=$(python3 - "$pid" 2>/dev/null <<'PY'
import hashlib
import json
import os
import stat
import sys

pid = int(sys.argv[1])
path = f"/proc/{pid}/exe"

def identity(metadata):
    return (
        f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_size}:"
        f"{metadata.st_mtime_ns}:{metadata.st_ctime_ns}:"
        f"{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_uid}:{metadata.st_nlink}"
    )

before = os.readlink(path)
if not before.startswith("/") or before.endswith(" (deleted)"):
    raise SystemExit(1)
descriptor = os.open(path, os.O_RDONLY)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(1)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    after = os.readlink(path)
    current = os.stat(path)
    if before != after or identity(metadata) != identity(current):
        raise SystemExit(1)
finally:
    os.close(descriptor)
print(json.dumps({
    "path": before,
    "file_identity": identity(metadata),
    "sha256": digest.hexdigest(),
}, sort_keys=True, separators=(",", ":")))
PY
) || return 1
  child_observed_image_path=$(jq -er '.path' <<<"$observation") || return 1
  child_observed_image_identity=$(jq -er '.file_identity' <<<"$observation") ||
    return 1
  child_observed_image_sha256=$(jq -er '.sha256' <<<"$observation") || return 1
}

initialize_child_process_image_binding() {
  local shebang='' fd_identity fd_sha256 image_is_expected
  if [[ "$self_test_interpreter_image_allowance" == true ]]; then
    IFS= read -r shebang <"$binary" || return 1
    [[ "$shebang" == '#!/usr/bin/env python3' ]] || return 1
  fi

  for _ in {1..100}; do
    child_process_is_live || return 1
    image_is_expected=false
    if observe_process_image "$child_pid"; then
      if [[ "$self_test_interpreter_image_allowance" == true ]]; then
        [[ "$(basename -- "$child_observed_image_path")" == python3* ]] &&
          image_is_expected=true
      elif [[ "$child_observed_image_path" == "$binary" &&
        "$child_observed_image_identity" == "$binary_file_identity" &&
        "$child_observed_image_sha256" == "$binary_sha256" ]]; then
        image_is_expected=true
      fi
    fi
    if [[ "$image_is_expected" == true ]]; then
      exec {child_image_fd}<"/proc/$child_pid/exe" || return 1
      fd_identity=$(executable_file_identity "/proc/$$/fd/$child_image_fd") ||
        return 1
      fd_sha256=$(sha256sum -- "/proc/$$/fd/$child_image_fd" |
        awk '{print $1}') || return 1
      if [[ "$fd_identity" == "$child_observed_image_identity" &&
        "$fd_sha256" == "$child_observed_image_sha256" ]]; then
        child_expected_image_path=$child_observed_image_path
        child_expected_image_identity=$child_observed_image_identity
        child_expected_image_sha256=$child_observed_image_sha256
        child_image_verification_count=1
        return 0
      fi
      exec {child_image_fd}<&-
      child_image_fd=
    fi
    sleep 0.05
  done
  return 1
}

verify_child_process_image() {
  proc_identity_matches "$child_pid" "$child_start_ticks" || return 1
  observe_process_image "$child_pid" || return 1
  [[ "$child_observed_image_path" == "$child_expected_image_path" &&
    "$child_observed_image_identity" == "$child_expected_image_identity" &&
    "$child_observed_image_sha256" == "$child_expected_image_sha256" ]] ||
    return 1
  child_image_verification_count=$((child_image_verification_count + 1))
}

verify_child_launch_image_fd() {
  local fd_identity fd_sha256
  [[ "$child_image_fd" =~ ^[0-9]+$ ]] || return 1
  fd_identity=$(executable_file_identity "/proc/$$/fd/$child_image_fd") ||
    return 1
  fd_sha256=$(sha256sum -- "/proc/$$/fd/$child_image_fd" | awk '{print $1}') ||
    return 1
  [[ "$fd_identity" == "$child_expected_image_identity" &&
    "$fd_sha256" == "$child_expected_image_sha256" ]]
}

atomic_install() {
  local source=$1
  local target=$2
  python3 - "$source" "$target" <<'PY'
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

source = Path(sys.argv[1])
target = Path(sys.argv[2])
source_metadata = source.lstat()
if source.is_symlink() or not stat.S_ISREG(source_metadata.st_mode):
    raise SystemExit("atomic evidence source must be a nonsymlink regular file")
target_parent = target.parent
parent_metadata = target_parent.lstat()
if target_parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
    raise SystemExit("atomic evidence parent must be a nonsymlink directory")

os.chmod(source, 0o600, follow_symlinks=False)
source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
directory_fd = os.open(
    target_parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
temporary = None
try:
    os.fsync(source_fd)
    if source.parent.resolve() == target_parent.resolve():
        os.close(source_fd)
        source_fd = -1
        os.replace(source, target)
    else:
        temporary_fd, temporary = tempfile.mkstemp(
            prefix=".durable-copy.", dir=str(target_parent)
        )
        try:
            os.fchmod(temporary_fd, 0o600)
            with os.fdopen(temporary_fd, "wb", closefd=True) as output:
                with os.fdopen(os.dup(source_fd), "rb", closefd=True) as input_file:
                    shutil.copyfileobj(input_file, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, target)
            temporary = None
            source.unlink()
        except BaseException:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
            raise
    os.fsync(directory_fd)
finally:
    if source_fd >= 0:
        os.close(source_fd)
    os.close(directory_fd)
    if temporary is not None:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
PY
}

atomic_write_text() {
  local target=$1
  local value=$2
  local target_dir temp
  target_dir=$(dirname -- "$target")
  temp=$(mktemp "$target_dir/.atomic.XXXXXX")
  printf '%s\n' "$value" >"$temp"
  atomic_install "$temp" "$target"
}

node_arguments() {
  NODE_ARGS=(
    --network mainnet
    --data-dir "$data_root"
    --rpc-bind "127.0.0.1:$rpc_port"
    --rpc-authorization-header-file "$auth_file"
    --rpc-max-request-bytes 65536
    --rpc-max-concurrent-requests 32
    --rpc-execution-timeout-ms 5000
    --rpc-max-collection-entries 50000
    --authority-mode native
    --storage-durability sync
    --storage-mode archive
    --native-sync
    --p2p-discovery
    --maximum-known-addresses 4096
    --maximum-inbound 32
    --maximum-outbound 8
    --validation-workers 4
    --validation-queue 128
    --orphan-blocks 1024
    --orphan-bytes 67108864
    --native-sync-poll-ms 250
    --active-state-connect-batch 288
    --log-filter info
  )
}

run_check_config() {
  local output_file=$1
  local before_binary before_binary_identity before_auth after_auth authorization_value
  local result=0 scan_result
  before_binary=$binary_sha256
  before_binary_identity=$binary_file_identity
  before_auth=$auth_identity
  IFS= read -r authorization_value <"$auth_file" || {
    [[ -n "$authorization_value" ]] ||
      return 127
  }

  if (
    ulimit -f 2048
    timeout --signal=TERM --kill-after=5s 30s \
      env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
      HSRD_LOG=info RUST_BACKTRACE=1 \
      "$binary" "${NODE_ARGS[@]}" --check-config
  ) >"$output_file" 2>&1; then
    result=0
  else
    result=$?
  fi

  after_auth=$(auth_file_identity "$auth_file" 2>/dev/null || true)
  if [[ "$after_auth" != "$before_auth" ]]; then
    : >"$output_file"
    printf '%s\n' \
      '[configuration output suppressed: authorization file changed during validation]' \
      >"$output_file"
    return 127
  fi
  if printf '%s' "$authorization_value" |
    python3 -c '
from pathlib import Path
import sys
secret = sys.stdin.buffer.read()
try:
    output = Path(sys.argv[1]).read_bytes()
except OSError:
    raise SystemExit(2)
raise SystemExit(0 if secret and secret in output else 1)
' "$output_file"; then
    scan_result=0
  else
    scan_result=$?
  fi
  if ((scan_result == 0)); then
    : >"$output_file"
    printf '%s\n' '[configuration output suppressed: authorization value was emitted]' \
      >"$output_file"
    return 125
  elif ((scan_result != 1)); then
    : >"$output_file"
    printf '%s\n' \
      '[configuration output suppressed: authorization scan failed closed]' \
      >"$output_file"
    return 124
  fi
  [[ "$(sha256sum -- "$binary" | awk '{print $1}')" == "$before_binary" &&
    "$(executable_file_identity "$binary")" == "$before_binary_identity" ]] ||
    return 126
  return "$result"
}

safe_delete_preflight_directory() {
  local path=$1
  [[ -n "$path" && -d "$path" && ! -L "$path" ]] || return 0
  [[ "$path" == "${TMPDIR:-/tmp}/hsrd-full-sync-preflight."* ]] || return 1
  find "$path" -xdev -depth -delete
}

preflight_new_campaign() {
  local data_probe fs_size required_space
  local preflight_dir check_output check_result

  validate_numeric_options
  validate_binary
  validate_auth_file
  data_root=$(normalize_absolute_path "$data_root" "data root")
  evidence_dir=$(normalize_absolute_path "$evidence_dir" "evidence directory")
  validate_campaign_path_scope
  validate_self_test_interpreter_image_allowance
  validate_new_directory_target "$data_root" "data root"
  validate_new_directory_target "$evidence_dir" "evidence directory"

  data_probe=$(nearest_existing_ancestor "$data_root")
  read -r fs_size baseline_fs_used_bytes baseline_fs_available_bytes \
    <<<"$(filesystem_numbers "$data_probe")" ||
    die "could not read filesystem capacity"
  required_space=$((limit_bytes + filesystem_reserve_bytes))
  ((baseline_fs_available_bytes >= required_space)) ||
    die "qualification filesystem has $baseline_fs_available_bytes available bytes; $required_space are required for the configured cutoff plus reserve"
  data_filesystem_device=$(df --output=source -- "$data_probe" | awk 'NR == 2 {print $1}')
  data_filesystem_mount=$(df --output=target -- "$data_probe" | awk 'NR == 2 {print $1}')
  [[ -n "$data_filesystem_device" && -n "$data_filesystem_mount" ]] ||
    die "could not identify the qualification filesystem"

  capture_source_provenance
  node_arguments

  preflight_dir=$(mktemp -d "${TMPDIR:-/tmp}/hsrd-full-sync-preflight.XXXXXX")
  chmod 700 -- "$preflight_dir"
  check_output="$preflight_dir/check-config.log"
  set +e
  run_check_config "$check_output"
  check_result=$?
  set -e
  if ((check_result != 0)); then
    log "exact hsrd --check-config preflight failed with exit code $check_result"
    sed -n '1,80p' "$check_output" >&2
    safe_delete_preflight_directory "$preflight_dir"
    exit 2
  fi

  validate_new_directory_target "$data_root" "data root"
  validate_new_directory_target "$evidence_dir" "evidence directory"
  mkdir -p -- "$data_root" "$evidence_dir"
  chmod 700 -- "$data_root" "$evidence_dir"
  validate_existing_private_directory "$data_root" "data root"
  validate_existing_private_directory "$evidence_dir" "evidence directory"
  directory_is_empty "$data_root" || die "data root changed during preflight"
  directory_is_empty "$evidence_dir" || die "evidence directory changed during preflight"

  mkdir -m 700 -- "$evidence_dir/logs" "$evidence_dir/samples" "$evidence_dir/attempts"
  atomic_install "$check_output" "$evidence_dir/logs/check-config.log"
  safe_delete_preflight_directory "$preflight_dir"

  campaign_started_epoch=$(date +%s)
  campaign_started_at=$(date -u -d "@$campaign_started_epoch" '+%Y-%m-%dT%H:%M:%SZ')
  campaign_id=$(printf '%s\0%s\0%s\0%s' \
    "$campaign_started_epoch" "$binary_sha256" "$data_root" "$$" |
    sha256sum | awk '{print $1}')
  attempt=1
  sample_sequence=0
  minimum_sampled_filesystem_available_bytes=$baseline_fs_available_bytes
  write_initial_artifacts "$fs_size" "$data_probe"
}

write_initial_artifacts() {
  local fs_size=$1
  local data_probe=$2
  local args_json rustc_version cargo_version active_toolchain cargo_lock_sha
  local binary_size binary_mtime host_name kernel os_release cpu_model mem_total
  local fs_json temp config_path

  args_json=$(jq -cn '$ARGS.positional' --args -- "${NODE_ARGS[@]}")
  rustc_version=$(rustc +1.89.0 -Vv 2>&1 || rustc -Vv 2>&1)
  cargo_version=$(cargo +1.89.0 -V 2>&1 || cargo -V 2>&1)
  active_toolchain=$(rustup show active-toolchain 2>&1 || true)
  if [[ -f "$REPO_ROOT/Cargo.lock" && ! -L "$REPO_ROOT/Cargo.lock" ]]; then
    cargo_lock_sha=$(sha256sum -- "$REPO_ROOT/Cargo.lock" | awk '{print $1}')
  else
    cargo_lock_sha=
  fi
  binary_size=$(stat -Lc '%s' -- "$binary")
  binary_mtime=$(stat -Lc '%y' -- "$binary")
  host_name=$(hostname)
  kernel=$(uname -srm)
  os_release=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -n 1)
  cpu_model=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -n 1)
  mem_total=$(awk '/^MemTotal:/ {print $2 * 1024}' /proc/meminfo)
  fs_json=$(filesystem_provenance "$data_probe")

  temp=$(mktemp "$evidence_dir/.build-provenance.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_build_and_source_provenance \
    --arg binary_path "$binary" \
    --arg binary_sha256 "$binary_sha256" \
    --arg binary_file_identity "$binary_file_identity" \
    --argjson binary_size "$binary_size" \
    --arg binary_mtime "$binary_mtime" \
    --arg repo_root "$REPO_ROOT" \
    --arg source_revision "$source_revision" \
    --arg source_tree "$source_tree" \
    --arg source_worktree_sha256 "$source_worktree_sha256" \
    --argjson source_dirty "$source_dirty" \
    --arg rustc "$rustc_version" \
    --arg cargo "$cargo_version" \
    --arg active_toolchain "$active_toolchain" \
    --arg cargo_lock_sha256 "$cargo_lock_sha" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      binary: {
        path: $binary_path,
        sha256: $binary_sha256,
        file_identity: $binary_file_identity,
        size_bytes: $binary_size,
        mtime: $binary_mtime
      },
      source: {
        repository: $repo_root,
        revision: $source_revision,
        tree: $source_tree,
        worktree_sha256: $source_worktree_sha256,
        dirty: $source_dirty
      },
      build: {
        expected_release_command:
          "cargo +1.89.0 build --locked --release -p hns-node --bin hsrd",
        rustc: $rustc,
        cargo: $cargo,
        active_toolchain: $active_toolchain,
        cargo_lock_sha256: $cargo_lock_sha256,
        binding:
          "operator-supplied binary SHA-256 plus observed source state; reproducible build not proven"
      },
      provisional: $source_dirty
    }' >"$temp"
  atomic_install "$temp" "$evidence_dir/build-provenance.json"

  temp=$(mktemp "$evidence_dir/.host-provenance.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_sync_host_provenance \
    --arg captured_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg hostname "$host_name" \
    --arg kernel "$kernel" \
    --arg os_release "$os_release" \
    --arg cpu_model "$cpu_model" \
    --argjson memory_bytes "$mem_total" \
    --argjson filesystem "$fs_json" \
    --arg filesystem_device "$data_filesystem_device" \
    --arg filesystem_mount "$data_filesystem_mount" \
    --argjson filesystem_size_bytes "$fs_size" \
    --argjson filesystem_used_bytes "$baseline_fs_used_bytes" \
    --argjson filesystem_available_bytes "$baseline_fs_available_bytes" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      captured_at: $captured_at,
      host: {
        hostname: $hostname,
        kernel: $kernel,
        os_release: $os_release,
        cpu_model: $cpu_model,
        memory_bytes: $memory_bytes
      },
      filesystem: {
        findmnt: $filesystem,
        device: $filesystem_device,
        mount: $filesystem_mount,
        size_bytes: $filesystem_size_bytes,
        initial_used_bytes: $filesystem_used_bytes,
        initial_available_bytes: $filesystem_available_bytes
      }
    }' >"$temp"
  atomic_install "$temp" "$evidence_dir/host-provenance.json"

  config_path="$evidence_dir/campaign-config.json"
  temp=$(mktemp "$evidence_dir/.campaign-config.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_non_pruned_mainnet_campaign_configuration \
    --arg campaign_id "$campaign_id" \
    --arg created_at "$campaign_started_at" \
    --arg binary_path "$binary" \
    --arg binary_sha256 "$binary_sha256" \
    --arg binary_file_identity "$binary_file_identity" \
    --arg data_root "$data_root" \
    --arg evidence_dir "$evidence_dir" \
    --arg auth_file "$auth_file" \
    --arg auth_identity "$auth_identity" \
    --argjson rpc_port "$rpc_port" \
    --argjson argv "$args_json" \
    --argjson limit_bytes "$limit_bytes" \
    --argjson informational_comparison "$INFORMATIONAL_COMPARISON_BYTES" \
    --argjson reserve_bytes "$filesystem_reserve_bytes" \
    --argjson sample_seconds "$sample_seconds" \
    --argjson completion_samples "$completion_samples" \
    --argjson maximum_samples "$maximum_samples" \
    --argjson grace_seconds "$shutdown_grace_seconds" \
    --argjson baseline_used "$baseline_fs_used_bytes" \
    --argjson baseline_available "$baseline_fs_available_bytes" \
    --arg filesystem_device "$data_filesystem_device" \
    --arg filesystem_mount "$data_filesystem_mount" \
    --arg source_revision "$source_revision" \
    --arg source_tree "$source_tree" \
    --arg source_worktree_sha256 "$source_worktree_sha256" \
    --argjson source_dirty "$source_dirty" \
    --argjson self_test_interpreter_image_allowance \
      "$self_test_interpreter_image_allowance" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      campaign_id: $campaign_id,
      created_at: $created_at,
      baseline_mode: "full_non_pruned",
      network: "mainnet",
      authority_mode: "native",
      storage_mode: "archive",
      pruning_enabled: false,
      native_sync: {
        enabled: true,
        headers_only: false,
        observe_only: false,
        connect_active_state: true,
        discovery: true,
        maximum_known_addresses: 4096,
        maximum_inbound: 32,
        maximum_outbound: 8,
        validation_workers: 4,
        validation_queue: 128,
        orphan_blocks: 1024,
        orphan_bytes: 67108864,
        poll_interval_ms: 250,
        active_state_connect_batch: 288
      },
      mining_engine: false,
      transaction_relay: false,
      binary: {
        path: $binary_path,
        sha256: $binary_sha256,
        file_identity: $binary_file_identity
      },
      data_root: $data_root,
      evidence_dir: $evidence_dir,
      rpc: {
        bind: ("127.0.0.1:" + ($rpc_port | tostring)),
        maximum_request_bytes: 65536,
        maximum_concurrent_requests: 32,
        execution_timeout_ms: 5000,
        maximum_collection_entries: 50000,
        authorization_file: $auth_file,
        authorization_file_identity: $auth_identity,
        authorization_value_recorded: false
      },
      process_argv_without_secret: $argv,
      self_test: {
        interpreter_image_allowance: $self_test_interpreter_image_allowance
      },
      measurement: {
        sampled_cutoff_bytes: $limit_bytes,
        cutoff_basis:
          "maximum observed at each sample among data-root apparent bytes, data-root allocated bytes, and positive qualification-filesystem used-byte delta",
        sampled_informational_comparison_bytes: $informational_comparison,
        informational_comparison_is_qualification_criterion: false,
        semantics:
          "sampled thresholds only; no kernel quota and no claim about unobserved transient disk peaks",
        filesystem_reserve_bytes: $reserve_bytes,
        filesystem_reserve_semantics:
          "conservatively checked at every sample and final observation",
        sample_seconds: $sample_seconds,
        maximum_samples: $maximum_samples,
        consecutive_synced_samples_required: $completion_samples,
        shutdown_grace_seconds: $grace_seconds,
        initial_filesystem_used_bytes: $baseline_used,
        initial_filesystem_available_bytes: $baseline_available,
        filesystem_device: $filesystem_device,
        filesystem_mount: $filesystem_mount
      },
      source: {
        revision: $source_revision,
        tree: $source_tree,
        worktree_sha256: $source_worktree_sha256,
        dirty: $source_dirty
      },
      release_evidence_status:
        (if $self_test_interpreter_image_allowance then
          "self_test_only_non_qualification"
        elif $source_dirty then
          "provisional_dirty_source"
        else
          "provisional_unverified_reproducible_build_binding"
        end),
      hsd_reference_data_statement:
        "not measured or asserted by this runner"
    }' >"$temp"
  atomic_install "$temp" "$config_path"
  config_sha256=$(sha256sum -- "$config_path" | awk '{print $1}')
  atomic_write_text "$evidence_dir/campaign-config.sha256" "$config_sha256  campaign-config.json"
}

assert_no_authorization_scanner_hard_stop_markers() {
  local marker
  for marker in \
    "$evidence_dir/logs/auth-value-redacted" \
    "$evidence_dir/logs/scanner-failure.json"; do
    [[ ! -e "$marker" && ! -L "$marker" ]] ||
      die "campaign contains a non-resumable authorization scanner hard-stop marker"
  done
}

load_config_for_resume() {
  local config_path expected_digest actual_digest stored_evidence source_repo
  local stored_dirty expected_binary_sha256 expected_binary_identity
  local expected_auth_identity
  local recorded_sample_count recorded_sample_digest
  local recorded_runner_pid recorded_runner_ticks recorded_child_pid recorded_child_ticks
  local recorded_scanner_pid recorded_scanner_ticks

  evidence_dir=$(normalize_absolute_path "$evidence_dir" "evidence directory")
  validate_existing_private_directory "$evidence_dir" "evidence directory"
  config_path="$evidence_dir/campaign-config.json"
  [[ -f "$config_path" && ! -L "$config_path" ]] ||
    die "campaign configuration is missing"
  [[ -f "$evidence_dir/campaign-config.sha256" &&
    ! -L "$evidence_dir/campaign-config.sha256" ]] ||
    die "campaign configuration digest is missing"
  jq -e \
    '.schema_version == 1 and
     .artifact_type == "hsrd_full_non_pruned_mainnet_campaign_configuration" and
     .baseline_mode == "full_non_pruned" and
     .network == "mainnet" and
     .storage_mode == "archive" and
     .pruning_enabled == false and
     .native_sync.connect_active_state == true' \
    "$config_path" >/dev/null ||
    die "campaign configuration is invalid"
  read -r expected_digest _ <"$evidence_dir/campaign-config.sha256"
  actual_digest=$(sha256sum -- "$config_path" | awk '{print $1}')
  [[ "$expected_digest" =~ ^[0-9a-f]{64}$ && "$actual_digest" == "$expected_digest" ]] ||
    die "campaign configuration digest does not match"
  config_sha256=$actual_digest

  campaign_id=$(jq -er '.campaign_id' "$config_path")
  campaign_started_at=$(jq -er '.created_at' "$config_path")
  campaign_started_epoch=$(date -u -d "$campaign_started_at" +%s)
  binary=$(jq -er '.binary.path' "$config_path")
  expected_binary_sha256=$(jq -er '.binary.sha256' "$config_path")
  expected_binary_identity=$(jq -er '.binary.file_identity' "$config_path")
  data_root=$(jq -er '.data_root' "$config_path")
  stored_evidence=$(jq -er '.evidence_dir' "$config_path")
  auth_file=$(jq -er '.rpc.authorization_file' "$config_path")
  expected_auth_identity=$(jq -er '.rpc.authorization_file_identity' "$config_path")
  rpc_port=$(jq -er '.rpc.bind | split(":")[-1] | tonumber' "$config_path")
  limit_bytes=$(jq -er '.measurement.sampled_cutoff_bytes' "$config_path")
  filesystem_reserve_bytes=$(jq -er '.measurement.filesystem_reserve_bytes' "$config_path")
  sample_seconds=$(jq -er '.measurement.sample_seconds' "$config_path")
  completion_samples=$(jq -er '.measurement.consecutive_synced_samples_required' "$config_path")
  maximum_samples=$(jq -er '.measurement.maximum_samples' "$config_path")
  shutdown_grace_seconds=$(jq -er '.measurement.shutdown_grace_seconds' "$config_path")
  baseline_fs_used_bytes=$(jq -er '.measurement.initial_filesystem_used_bytes' "$config_path")
  baseline_fs_available_bytes=$(jq -er '.measurement.initial_filesystem_available_bytes' "$config_path")
  data_filesystem_device=$(jq -er '.measurement.filesystem_device' "$config_path")
  data_filesystem_mount=$(jq -er '.measurement.filesystem_mount' "$config_path")
  source_revision=$(jq -er '.source.revision' "$config_path")
  source_tree=$(jq -er '.source.tree' "$config_path")
  source_worktree_sha256=$(jq -er '.source.worktree_sha256' "$config_path")
  stored_dirty=$(jq -er '.source.dirty' "$config_path")
  source_dirty=$stored_dirty
  self_test_interpreter_image_allowance=$(jq -er \
    '.self_test.interpreter_image_allowance' "$config_path")

  [[ "$stored_evidence" == "$evidence_dir" ]] ||
    die "campaign configuration is bound to a different evidence directory"
  validate_numeric_options
  validate_campaign_path_scope
  validate_binary
  [[ "$binary_sha256" == "$expected_binary_sha256" ]] ||
    die "campaign binary SHA-256 changed"
  [[ "$binary_file_identity" == "$expected_binary_identity" ]] ||
    die "campaign binary file identity changed"
  validate_auth_file
  [[ "$auth_identity" == "$expected_auth_identity" ]] ||
    die "authorization file identity changed"
  data_root=$(normalize_absolute_path "$data_root" "data root")
  validate_self_test_interpreter_image_allowance
  validate_existing_private_directory "$data_root" "data root"
  [[ -z "$(find "$data_root" -xdev -type l -print -quit)" ]] ||
    die "data root contains a symbolic link"
  validate_existing_private_directory "$evidence_dir/logs" "logs directory"
  validate_existing_private_directory "$evidence_dir/samples" "samples directory"
  validate_existing_private_directory "$evidence_dir/attempts" "attempts directory"
  [[ -z "$(find "$evidence_dir" -xdev -type l -print -quit)" ]] ||
    die "evidence directory contains a symbolic link"
  assert_no_authorization_scanner_hard_stop_markers

  source_repo=$(jq -er '.source.repository // empty' "$evidence_dir/build-provenance.json")
  [[ -z "$source_repo" || "$source_repo" == "$REPO_ROOT" ]] ||
    die "campaign was initialized from a different source repository"

  if [[ -f "$evidence_dir/final-summary.json" ]]; then
    case "$(jq -er '.classification' "$evidence_dir/final-summary.json")" in
      sync_completed)
        die "campaign is already complete"
        ;;
      sampled_storage_cutoff_exceeded|\
        sampled_storage_cutoff_and_filesystem_reserve_breached|\
        sampled_filesystem_reserve_breached|\
        sample_limit_exceeded|authorization_value_emission_detected|\
        log_authorization_scanner_failed|\
        authorization_log_retention_guarantee_failed|\
        child_process_image_changed|child_process_identity_changed|\
        sync_completed_child_nonzero|sync_completed_forced_shutdown)
        die "campaign has a non-resumable hard-stop classification"
        ;;
    esac
  fi

  if [[ -f "$evidence_dir/state.json" ]]; then
    [[ ! -L "$evidence_dir/state.json" ]] ||
      die "runtime state must not be a symbolic link"
    recorded_runner_pid=$(jq -r '.runner.pid // empty' "$evidence_dir/state.json")
    recorded_runner_ticks=$(jq -r '.runner.start_ticks // empty' "$evidence_dir/state.json")
    if process_identity_is_live "$recorded_runner_pid" "$recorded_runner_ticks"; then
      die "recorded campaign runner is still live; refusing resume"
    fi
    recorded_child_pid=$(jq -r '.child.pid // empty' "$evidence_dir/state.json")
    recorded_child_ticks=$(jq -r '.child.start_ticks // empty' "$evidence_dir/state.json")
    if process_identity_is_live "$recorded_child_pid" "$recorded_child_ticks"; then
      die "recorded hsrd child is still live; refusing resume"
    fi
    recorded_scanner_pid=$(jq -r '.log_scanner.pid // empty' "$evidence_dir/state.json")
    recorded_scanner_ticks=$(jq -r \
      '.log_scanner.start_ticks // empty' "$evidence_dir/state.json")
    if process_identity_is_live "$recorded_scanner_pid" "$recorded_scanner_ticks"; then
      die "recorded log authorization scanner is still live; refusing resume"
    fi
    attempt=$(jq -er '.attempt' "$evidence_dir/state.json")
    sample_sequence=$(jq -er '.sample_sequence' "$evidence_dir/state.json")
    maximum_observed_vm_hwm_bytes=$(jq -er '.observed_maxima.kernel_process_vm_hwm_bytes' "$evidence_dir/state.json")
    maximum_sampled_apparent_bytes=$(jq -er '.observed_maxima.sampled_data_root_apparent_bytes' "$evidence_dir/state.json")
    maximum_sampled_allocated_bytes=$(jq -er '.observed_maxima.sampled_data_root_allocated_bytes' "$evidence_dir/state.json")
    maximum_sampled_filesystem_used_delta_bytes=$(jq -er '.observed_maxima.sampled_filesystem_used_delta_bytes' "$evidence_dir/state.json")
    maximum_sampled_storage_bytes=$(jq -er '.observed_maxima.sampled_storage_maximum_bytes' "$evidence_dir/state.json")
    minimum_sampled_filesystem_available_bytes=$(jq -er \
      '.minimum_sampled_filesystem_available_bytes' "$evidence_dir/state.json")
  fi
  if ((minimum_sampled_filesystem_available_bytes == 0)); then
    minimum_sampled_filesystem_available_bytes=$baseline_fs_available_bytes
  fi
  read -r recorded_sample_count recorded_sample_digest < <(sample_chain_digest)
  : "$recorded_sample_digest"
  ((recorded_sample_count == sample_sequence)) ||
    die "recorded sample count does not match runtime state"
  attempt=$((attempt + 1))
  ((attempt <= 32)) || die "campaign exceeded the maximum of 32 resume attempts"

  node_arguments
  assert_exact_stored_arguments "$config_path"
}

assert_exact_stored_arguments() {
  local config_path=$1
  local expected actual
  expected=$(jq -c '.process_argv_without_secret' "$config_path")
  actual=$(jq -cn '$ARGS.positional' --args -- "${NODE_ARGS[@]}")
  [[ "$actual" == "$expected" ]] ||
    die "stored process arguments do not match the exact runner profile"
}

resume_preflight() {
  local fs_size current_used current_available resume_log
  local apparent allocated delta current_max remaining required check_tmp check_result

  load_config_for_resume
  read -r fs_size current_used current_available \
    <<<"$(filesystem_numbers "$data_root")" ||
    die "could not read the qualification filesystem"
  [[ "$(df --output=source -- "$data_root" | awk 'NR == 2 {print $1}')" == \
    "$data_filesystem_device" ]] ||
    die "data root is now on a different filesystem"

  read -r apparent allocated < <(measure_data_root) ||
    die "could not measure the existing data root"
  delta=$((current_used - baseline_fs_used_bytes))
  ((delta >= 0)) || delta=0
  current_max=$(maximum_of "$apparent" "$allocated" "$delta")
  ((current_max <= limit_bytes)) ||
    die "existing data already exceeds the configured cutoff"
  remaining=$((limit_bytes - current_max))
  required=$((remaining + filesystem_reserve_bytes))
  ((current_available >= required)) ||
    die "resume filesystem has $current_available available bytes; $required are required for remaining cutoff headroom plus reserve"

  check_tmp=$(mktemp "$evidence_dir/.resume-check-config.XXXXXX")
  set +e
  run_check_config "$check_tmp"
  check_result=$?
  set -e
  if ((check_result != 0)); then
    log "resume hsrd --check-config failed with exit code $check_result"
    sed -n '1,80p' "$check_tmp" >&2
    : >"$check_tmp"
    return 2
  fi
  printf -v resume_log '%s/logs/check-config-resume-%06d.log' "$evidence_dir" "$attempt"
  [[ ! -e "$resume_log" && ! -L "$resume_log" ]] ||
    die "resume check-config log path already exists"
  atomic_install "$check_tmp" "$resume_log"
  : "$fs_size"
}

maximum_of() {
  local maximum=0
  local value
  for value in "$@"; do
    ((value > maximum)) && maximum=$value
  done
  printf '%s\n' "$maximum"
}

measure_data_root() {
  local apparent allocated
  for _ in 1 2 3; do
    if apparent=$(du -x -s -B1 --apparent-size -- "$data_root" 2>/dev/null) &&
      allocated=$(du -x -s -B1 -- "$data_root" 2>/dev/null); then
      apparent=${apparent%%[[:space:]]*}
      allocated=${allocated%%[[:space:]]*}
      if is_unsigned_integer "$apparent" && is_unsigned_integer "$allocated"; then
        printf '%s %s\n' "$apparent" "$allocated"
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

process_vm_hwm_bytes() {
  local pid=$1
  local vm_hwm_kib
  [[ -r "/proc/$pid/status" ]] || return 1
  vm_hwm_kib=$(awk '$1 == "VmHWM:" && $3 == "kB" {print $2}' "/proc/$pid/status")
  is_unsigned_integer "$vm_hwm_kib" || return 1
  printf '%s\n' "$((vm_hwm_kib * 1024))"
}

normalize_sync_status_response() {
  local response=$1

  jq -ce '
    def canonical_block_hash:
      if . == null then
        null
      elif type == "string" then
        if test("^[0-9a-fA-F]{64}$") then
          ascii_downcase
        else
          error("BlockHash string is not exactly 64 hexadecimal characters")
        end
      elif type == "array" then
        if length != 32 then
          error("BlockHash byte array does not contain exactly 32 elements")
        elif all(.[];
          if type == "number" then
            floor == . and . >= 0 and . <= 255
          else
            false
          end) then
          ["0", "1", "2", "3", "4", "5", "6", "7",
           "8", "9", "a", "b", "c", "d", "e", "f"] as $hex |
          map(. as $byte |
            $hex[($byte / 16 | floor)] + $hex[($byte % 16)]) |
          join("")
        else
          error("BlockHash byte array contains a non-byte element")
        end
      else
        error("BlockHash is neither null, a hexadecimal string, nor a byte array")
      end;

    if type != "object" then error("sync response is not an object") else . end |
    {
      stage,
      best_header_height: (.best_header.height // null),
      best_header_hash: (.best_header.hash | canonical_block_hash),
      active_tip_height: (.active_tip.height // null),
      active_tip_hash: (.active_tip.hash | canonical_block_hash),
      stored_tip_height: (.stored_tip.height // null),
      stored_tip_hash: (.stored_tip.hash | canonical_block_hash),
      target_height,
      pending_blocks,
      inflight_blocks,
      tracked_blocks,
      validated_blocks,
      failed_blocks,
      sequence,
      peer_count: (.peers | length),
      ready_peer_count: ([.peers[] | select(.ready == true)] | length)
    }' "$response"
}

read_sync_status() {
  local response=$1
  local url="http://127.0.0.1:$rpc_port/api/v1/sync"

  : >"$response"
  chmod 600 -- "$response"
  if ! python3 - "$auth_file" <<'PY' |
import sys
with open(sys.argv[1], "rb") as handle:
    value = handle.read().strip()
sys.stdout.buffer.write(b"Authorization: " + value + b"\n")
PY
    curl --silent --show-error --fail --noproxy '*' \
      --connect-timeout 2 --max-time 5 --max-filesize 1048576 \
      --header @- --output "$response" "$url" 2>/dev/null; then
    : >"$response"
    return 1
  fi

  normalize_sync_status_response "$response"
}

sync_status_is_complete() {
  local status=$1
  jq -e '
    .stage == "Synced" and
    (.best_header_height | type) == "number" and
    .best_header_height > 0 and
    (.best_header_hash | type) == "string" and
    (.best_header_hash | test("^[0-9a-f]{64}$")) and
    .active_tip_height == .best_header_height and
    .active_tip_hash == .best_header_hash and
    .stored_tip_height == .best_header_height and
    .stored_tip_hash == .best_header_hash and
    (.target_height | type) == "number" and
    .target_height <= .active_tip_height and
    .pending_blocks == 0 and
    .inflight_blocks == 0 and
    .tracked_blocks == 0 and
    .ready_peer_count > 0
  ' <<<"$status" >/dev/null
}

start_log_scanner() {
  local log_dir=$1
  local auth_path=$2
  local expected_auth_identity=$3

  exec python3 -c '
import json
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

log_dir = Path(sys.argv[1])
auth_path = Path(sys.argv[2])
expected_identity = sys.argv[3]
chunk_bytes = int(sys.argv[4])
slots = int(sys.argv[5])
maximum_auth_bytes = int(sys.argv[6])
read_bytes = 65536
replacement = b"[REDACTED RPC AUTHORIZATION VALUE]"
counter_path = log_dir / "log-segment-counter"
partial_path = log_dir / ".hsrd-log-partial"
redaction_marker = log_dir / "auth-value-redacted"
failure_marker = log_dir / "scanner-failure.json"

directory_fd = os.open(
    log_dir,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)

def identity(metadata):
    return (
        f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_size}:"
        f"{metadata.st_mtime_ns}:{metadata.st_ctime_ns}:"
        f"{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_uid}:{metadata.st_nlink}"
    )

def durable_bytes(path, payload):
    descriptor, temporary = tempfile.mkstemp(prefix=".scanner-atomic.", dir=log_dir)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
        os.fsync(directory_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

def durable_json(path, value):
    durable_bytes(
        path,
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )

class AuthorizationChanged(Exception):
    pass

flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
auth_fd = os.open(auth_path, flags)
initial_metadata = os.fstat(auth_fd)
if not stat.S_ISREG(initial_metadata.st_mode):
    raise SystemExit(42)
if identity(initial_metadata) != expected_identity:
    raise SystemExit(42)
initial_auth_bytes = os.pread(auth_fd, maximum_auth_bytes + 1, 0)
if not (1 <= len(initial_auth_bytes) <= maximum_auth_bytes):
    raise SystemExit(42)
secret = initial_auth_bytes.strip()
if not secret:
    raise SystemExit(42)

def validate_authorization():
    try:
        path_metadata = os.stat(auth_path, follow_symlinks=False)
        current = os.pread(auth_fd, maximum_auth_bytes + 1, 0)
    except OSError as error:
        raise AuthorizationChanged from error
    if (
        identity(path_metadata) != expected_identity
        or identity(os.fstat(auth_fd)) != expected_identity
        or current != initial_auth_bytes
    ):
        raise AuthorizationChanged

class RotatingWriter:
    def __init__(self):
        self.output = None
        self.size = 0
        records = self._segment_records()
        inferred_segment = records[-1][0] + 1 if records else 0
        recorded_segment = 0
        if counter_path.exists():
            if counter_path.is_symlink() or not counter_path.is_file():
                raise RuntimeError("unsafe log counter")
            encoded = counter_path.read_text(encoding="ascii").strip()
            if not encoded.isdigit():
                raise RuntimeError("invalid log counter")
            recorded_segment = int(encoded)
            if recorded_segment > 99999999999999999999:
                raise RuntimeError("log counter exceeds monotonic filename range")
        self.segment = max(recorded_segment, inferred_segment)
        self._complete_pending_recovery()
        self._recover_stale_partial()
        records = self._segment_records()
        inferred_segment = records[-1][0] + 1 if records else 0
        self.segment = max(self.segment, inferred_segment)
        if recorded_segment != self.segment:
            durable_json(
                log_dir
                / f"log-counter-reconciliation-{self.segment:020d}.json",
                {
                    "schema_version": 1,
                    "artifact_type": "hsrd_log_counter_reconciliation",
                    "recorded_next_segment": recorded_segment,
                    "inferred_next_segment": inferred_segment,
                    "reconciled_next_segment": self.segment,
                    "monotonic_segment_overwrite_prevented": True,
                },
            )
        durable_bytes(counter_path, f"{self.segment}\n".encode("ascii"))
        self._prune()

    @staticmethod
    def _segment_number(path):
        match = re.fullmatch(r"hsrd-segment-([0-9]{20})\.log", path.name)
        if match is None:
            return None
        return int(match.group(1))

    def _segment_records(self):
        records = []
        for path in log_dir.iterdir():
            segment = self._segment_number(path)
            if segment is None:
                continue
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("unsafe retained log segment")
            if not (1 <= metadata.st_size <= chunk_bytes):
                raise RuntimeError("retained log segment is outside its bound")
            records.append((segment, path))
        records.sort()
        if len({segment for segment, _path in records}) != len(records):
            raise RuntimeError("duplicate retained log segment generation")
        return records

    @staticmethod
    def _scan_recovery_file(path):
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("unsafe stale partial log")
        if not (0 <= metadata.st_size <= chunk_bytes):
            raise RuntimeError("stale partial log is outside its bound")
        digest = hashlib.sha256()
        tail = b""
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                candidate = tail + chunk
                if secret in candidate:
                    raise RuntimeError(
                        "authorization value found in stale partial log"
                    )
                retained = min(len(candidate), max(0, len(secret) - 1))
                tail = candidate[-retained:] if retained else b""
                digest.update(chunk)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        validate_authorization()
        return metadata.st_size, digest.hexdigest()

    @staticmethod
    def _validate_recovered_target(path, size, digest):
        observed_size, observed_digest = RotatingWriter._scan_recovery_file(path)
        if observed_size != size or observed_digest != digest:
            raise RuntimeError("pending recovered segment identity changed")

    def _complete_pending_recovery(self):
        pending = []
        for path in sorted(log_dir.glob("crash-recovery-*.json")):
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("unsafe crash-recovery marker")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("status") == "pending":
                pending.append((path, payload))
        if len(pending) > 1:
            raise RuntimeError("multiple pending crash-recovery records")
        if not pending:
            return
        marker, payload = pending[0]
        generation = payload.get("segment_generation")
        size = payload.get("recovered_bytes")
        digest = payload.get("recovered_sha256")
        if (
            not isinstance(generation, int)
            or generation < 0
            or not isinstance(size, int)
            or not (1 <= size <= chunk_bytes)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or marker.name != f"crash-recovery-{generation:020d}.json"
        ):
            raise RuntimeError("invalid pending crash-recovery record")
        target = log_dir / f"hsrd-segment-{generation:020d}.log"
        if target.exists() or target.is_symlink():
            if partial_path.exists() or partial_path.is_symlink():
                raise RuntimeError("ambiguous pending log recovery")
            self._validate_recovered_target(target, size, digest)
        else:
            observed_size, observed_digest = self._scan_recovery_file(partial_path)
            if observed_size != size or observed_digest != digest:
                raise RuntimeError("pending partial log identity changed")
            os.replace(partial_path, target)
            os.fsync(directory_fd)
        payload["status"] = "completed"
        durable_json(marker, payload)
        self.segment = max(self.segment, generation + 1)

    def _recover_stale_partial(self):
        if not (partial_path.exists() or partial_path.is_symlink()):
            return
        size, digest = self._scan_recovery_file(partial_path)
        if size == 0:
            os.unlink(partial_path)
            os.fsync(directory_fd)
            return
        generation = self.segment
        target = log_dir / f"hsrd-segment-{generation:020d}.log"
        marker = log_dir / f"crash-recovery-{generation:020d}.json"
        if target.exists() or target.is_symlink() or marker.exists() or marker.is_symlink():
            raise RuntimeError("crash-recovery generation collision")
        payload = {
            "schema_version": 1,
            "artifact_type": "hsrd_log_crash_recovery",
            "status": "pending",
            "segment_generation": generation,
            "recovered_bytes": size,
            "recovered_sha256": digest,
            "authorization_value_persisted": False,
            "authorization_identity_revalidated": True,
            "log_stream_contiguous": False,
        }
        durable_json(marker, payload)
        os.replace(partial_path, target)
        os.fsync(directory_fd)
        payload["status"] = "completed"
        durable_json(marker, payload)
        self.segment += 1

    def _prune(self):
        records = self._segment_records()
        removed = False
        for _segment, path in records[:-slots]:
            os.unlink(path)
            removed = True
        if removed:
            os.fsync(directory_fd)

    def _open(self):
        descriptor = os.open(
            partial_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        self.output = os.fdopen(descriptor, "wb", closefd=True)
        self.size = 0

    def _finalize(self):
        if self.output is None:
            return
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.output = None
        target = log_dir / f"hsrd-segment-{self.segment:020d}.log"
        if target.exists() or target.is_symlink():
            raise RuntimeError("log segment generation collision")
        os.replace(partial_path, target)
        os.fsync(directory_fd)
        self.segment += 1
        durable_bytes(counter_path, f"{self.segment}\n".encode("ascii"))
        self._prune()
        self.size = 0

    def write(self, data):
        view = memoryview(data)
        while view:
            if self.output is None:
                self._open()
            available = chunk_bytes - self.size
            piece = view[:available]
            self.output.write(piece)
            written = len(piece)
            self.size += written
            view = view[written:]
            if self.size == chunk_bytes:
                self._finalize()

    def finish(self):
        if self.output is not None:
            if self.size:
                self._finalize()
            else:
                self.output.close()
                self.output = None
                os.unlink(partial_path)
                os.fsync(directory_fd)

    def erase_retained_runtime_logs(self):
        if self.output is not None:
            descriptor = self.output.fileno()
            try:
                self.output.close()
            except OSError:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            self.output = None
            self.size = 0
        paths = [partial_path]
        paths.extend(path for _segment, path in self._segment_records())
        for path in paths:
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError("runtime log erasure target became a directory")
            os.unlink(path)
        durable_bytes(counter_path, b"0\n")
        os.fsync(directory_fd)

writer = RotatingWriter()
pending = b""
redacted = False
failure_reason = None
failure_detail = None
authorization_mutation = False
retained_runtime_logs_erased = False
try:
    while True:
        validate_authorization()
        chunk = sys.stdin.buffer.read(read_bytes)
        if not chunk:
            break
        validate_authorization()
        buffer = pending + chunk
        output = bytearray()
        while True:
            index = buffer.find(secret)
            if index < 0:
                break
            output.extend(buffer[:index])
            output.extend(replacement)
            buffer = buffer[index + len(secret):]
            if not redacted:
                durable_json(
                    redaction_marker,
                    {
                        "schema_version": 1,
                        "artifact_type": "hsrd_log_authorization_redaction",
                        "authorization_value_persisted": False,
                    },
                )
                redacted = True
        retained = min(len(buffer), max(0, len(secret) - 1))
        if retained:
            output.extend(buffer[:-retained])
            pending = buffer[-retained:]
        else:
            output.extend(buffer)
            pending = b""
        writer.write(output)
    validate_authorization()
    if pending:
        if secret in pending:
            raise RuntimeError("scanner invariant failed")
        writer.write(pending)
    writer.finish()
except AuthorizationChanged as error:
    failure_reason = "authorization_identity_or_content_changed"
    failure_detail = type(error).__name__
    authorization_mutation = True
except (OSError, RuntimeError, ValueError) as error:
    failure_reason = "scanner_or_stream_read_error"
    failure_detail = f"{type(error).__name__}:{str(error)[:256]}"
finally:
    try:
        os.close(auth_fd)
    except OSError:
        pass

if failure_reason is not None:
    if authorization_mutation:
        try:
            writer.erase_retained_runtime_logs()
            retained_runtime_logs_erased = True
        except BaseException:
            failure_reason = "authorization_change_runtime_log_erasure_failed"
    else:
        try:
            writer.finish()
        except BaseException:
            pass
    try:
        durable_json(
            failure_marker,
            {
                "schema_version": 1,
                "artifact_type": "hsrd_log_scanner_failure",
                "reason": failure_reason,
                "safe_failure_detail": failure_detail,
                "authorization_mutation_detected": authorization_mutation,
                "retained_runtime_log_slots_erased":
                    retained_runtime_logs_erased,
                "authorization_value_persisted":
                    (False if not authorization_mutation
                     or retained_runtime_logs_erased else None),
            },
        )
    finally:
        os.close(directory_fd)
    raise SystemExit(42)

os.close(directory_fd)
' "$log_dir" "$auth_path" "$expected_auth_identity" \
    "$LOG_CHUNK_BYTES" "$LOG_SLOTS" "$MAX_AUTH_BYTES"
}

capture_log_scanner_exit() {
  local captured_exit
  [[ "$log_scanner_reaped" == false ]] || return 0
  if wait "$log_scanner_pid"; then
    captured_exit=0
  else
    captured_exit=$?
  fi
  log_scanner_exit=$captured_exit
  log_scanner_reaped=true
}

capture_log_scanner_marker_detail() {
  local marker="$evidence_dir/logs/scanner-failure.json"
  local detail
  [[ -f "$marker" && ! -L "$marker" ]] || return 1
  detail=$(jq -r '
    if type != "object" then
      empty
    elif (.safe_failure_detail | type) == "string" and
      (.safe_failure_detail | length) > 0 then
      ((.reason // "scanner_failure") + ":" + .safe_failure_detail)
    elif (.reason | type) == "string" and (.reason | length) > 0 then
      .reason
    else
      empty
    end
  ' "$marker" 2>/dev/null || true)
  if [[ -n "$detail" ]]; then
    log_scanner_failure_detail=$detail
  else
    log_scanner_failure_detail=scanner_failure_marker_invalid
  fi
}

mark_log_scanner_failed() {
  local detail=$1
  [[ -n "$log_scanner_failure_detail" ]] ||
    log_scanner_failure_detail=$detail
  measurement_error=${measurement_error:-log_authorization_scanner_failed}
  stop_request=log_authorization_scanner_failed
  return 1
}

inspect_log_scanner() {
  local poll
  if [[ -f "$evidence_dir/logs/auth-value-redacted" &&
    ! -L "$evidence_dir/logs/auth-value-redacted" ]]; then
    authorization_value_emitted=true
    stop_request=authorization_value_emission_detected
    return 1
  fi
  if [[ -f "$evidence_dir/logs/scanner-failure.json" &&
    ! -L "$evidence_dir/logs/scanner-failure.json" ]]; then
    capture_log_scanner_marker_detail || true
    mark_log_scanner_failed scanner_failure_marker_present
    return 1
  fi
  if [[ -n "$log_scanner_pid" && -n "$log_scanner_start_ticks" ]] &&
    ! process_identity_is_live "$log_scanner_pid" "$log_scanner_start_ticks"; then
    capture_log_scanner_exit
    if [[ -f "$evidence_dir/logs/auth-value-redacted" &&
      ! -L "$evidence_dir/logs/auth-value-redacted" ]]; then
      authorization_value_emitted=true
      stop_request=authorization_value_emission_detected
      return 1
    fi
    if [[ -f "$evidence_dir/logs/scanner-failure.json" &&
      ! -L "$evidence_dir/logs/scanner-failure.json" ]]; then
      capture_log_scanner_marker_detail || true
      mark_log_scanner_failed scanner_failure_marker_present
      return 1
    fi
    if [[ "$log_scanner_exit" != 0 ]]; then
      mark_log_scanner_failed \
        "scanner_exit_nonzero_without_failure_marker:$log_scanner_exit"
      return 1
    fi
    if child_process_is_live; then
      for ((poll = 0;
        poll < LOG_SCANNER_CHILD_EXIT_GRACE_POLLS;
        poll++)); do
        sleep "$LOG_SCANNER_CHILD_EXIT_GRACE_SLEEP_SECONDS"
        if ! child_process_is_live; then
          log_scanner_clean_exit_child_transition=true
          return 0
        fi
      done
      mark_log_scanner_failed \
        "scanner_clean_exit_while_child_remained_live_after_bounded_grace"
      return 1
    fi
    return 0
  fi
  return 0
}

erase_retained_runtime_log_files() {
  python3 - "$evidence_dir/logs" <<'PY'
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

root = Path(sys.argv[1])
directory_fd = os.open(
    root,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    paths = [root / ".hsrd-log-partial"]
    paths.extend(
        path
        for path in root.iterdir()
        if re.fullmatch(r"hsrd-segment-[0-9]{20}\.log", path.name)
        or re.fullmatch(r"hsrd-slot-[0-9]{2}\.log", path.name)
    )
    for path in paths:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("runtime log erasure target became a directory")
        os.unlink(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".counter-reset.", dir=root)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(b"0\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, root / "log-segment-counter")
        temporary = None
        os.fsync(directory_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
finally:
    os.close(directory_fd)
PY
}

write_runtime_state() {
  local status=$1
  local current_vm_hwm=$2
  local current_apparent=$3
  local current_allocated=$4
  local current_delta=$5
  local current_maximum=$6
  local current_available=$7
  local sync_json=$8
  local temp

  temp=$(mktemp "$evidence_dir/.state.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_sync_runtime_state \
    --arg campaign_id "$campaign_id" \
    --arg status "$status" \
    --arg updated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson attempt "$attempt" \
    --argjson sample_sequence "$sample_sequence" \
    --argjson runner_pid "$runner_pid" \
    --arg runner_start_ticks "$runner_start_ticks" \
    --arg child_pid "${child_pid:-}" \
    --arg child_start_ticks "${child_start_ticks:-}" \
    --arg child_image_path "${child_expected_image_path:-}" \
    --arg child_image_identity "${child_expected_image_identity:-}" \
    --arg child_image_sha256 "${child_expected_image_sha256:-}" \
    --argjson child_image_verification_count "$child_image_verification_count" \
    --argjson child_launch_fd_verified \
      "$child_launch_image_fd_verified_at_finalization" \
    --argjson self_test_image_allowance \
      "$self_test_interpreter_image_allowance" \
    --arg scanner_pid "${log_scanner_pid:-}" \
    --arg scanner_start_ticks "${log_scanner_start_ticks:-}" \
    --argjson current_vm_hwm "$current_vm_hwm" \
    --argjson current_apparent "$current_apparent" \
    --argjson current_allocated "$current_allocated" \
    --argjson current_delta "$current_delta" \
    --argjson current_maximum "$current_maximum" \
    --argjson current_available "$current_available" \
    --argjson maximum_vm_hwm "$maximum_observed_vm_hwm_bytes" \
    --argjson maximum_apparent "$maximum_sampled_apparent_bytes" \
    --argjson maximum_allocated "$maximum_sampled_allocated_bytes" \
    --argjson maximum_delta "$maximum_sampled_filesystem_used_delta_bytes" \
    --argjson maximum_storage "$maximum_sampled_storage_bytes" \
    --argjson minimum_available "$minimum_sampled_filesystem_available_bytes" \
    --argjson cutoff "$limit_bytes" \
    --argjson reserve "$filesystem_reserve_bytes" \
    --argjson informational_comparison "$INFORMATIONAL_COMPARISON_BYTES" \
    --argjson consecutive_synced "$consecutive_synced_samples" \
    --argjson sync "$sync_json" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      campaign_id: $campaign_id,
      status: $status,
      updated_at: $updated_at,
      attempt: $attempt,
      sample_sequence: $sample_sequence,
      runner: {
        pid: $runner_pid,
        start_ticks: $runner_start_ticks
      },
      child: {
        pid: (if $child_pid == "" then null else ($child_pid | tonumber) end),
        start_ticks:
          (if $child_start_ticks == "" then null else $child_start_ticks end),
        executable_image_binding: {
          path:
            (if $child_image_path == "" then null else $child_image_path end),
          file_identity:
            (if $child_image_identity == "" then null else $child_image_identity end),
          sha256:
            (if $child_image_sha256 == "" then null else $child_image_sha256 end),
          verification_count: $child_image_verification_count,
          launch_image_fd_verified_at_finalization:
            $child_launch_fd_verified,
          self_test_interpreter_allowance: $self_test_image_allowance
        }
      },
      log_scanner: {
        pid: (if $scanner_pid == "" then null else ($scanner_pid | tonumber) end),
        start_ticks:
          (if $scanner_start_ticks == "" then null else $scanner_start_ticks end)
      },
      current: {
        observed_kernel_vm_hwm_bytes: $current_vm_hwm,
        sampled_data_root_apparent_bytes: $current_apparent,
        sampled_data_root_allocated_bytes: $current_allocated,
        sampled_filesystem_used_delta_bytes: $current_delta,
        sampled_storage_maximum_bytes: $current_maximum,
        sampled_filesystem_available_bytes: $current_available,
        filesystem_reserve_respected: ($current_available >= $reserve)
      },
      observed_maxima: {
        kernel_process_vm_hwm_bytes: $maximum_vm_hwm,
        sampled_data_root_apparent_bytes: $maximum_apparent,
        sampled_data_root_allocated_bytes: $maximum_allocated,
        sampled_filesystem_used_delta_bytes: $maximum_delta,
        sampled_storage_maximum_bytes: $maximum_storage
      },
      minimum_sampled_filesystem_available_bytes: $minimum_available,
      sampled_cutoff_bytes: $cutoff,
      filesystem_reserve_bytes: $reserve,
      filesystem_reserve_currently_respected:
        ($current_available >= $reserve),
      sampled_informational_comparison_bytes: $informational_comparison,
      sampled_informational_comparison_currently_at_or_below:
        ($maximum_storage <= $informational_comparison),
      informational_comparison_is_qualification_criterion: false,
      measurement_semantics:
        "disk values are periodic/final observations, not kernel quotas or true transient peaks",
      consecutive_synced_samples: $consecutive_synced,
      sync: $sync
    }' >"$temp"
  atomic_install "$temp" "$evidence_dir/state.json"
}

take_sample() {
  local timestamp epoch elapsed vm_hwm apparent allocated
  local fs_size fs_used fs_available fs_delta maximum violation reserve_violation
  local observed_binary_sha256 observed_binary_identity observed_auth_identity
  local sync_json=null rpc_reachable=false sync_complete=false
  local temp sample_path

  ((sample_sequence < maximum_samples)) || {
    measurement_error=sample_limit_exceeded
    return 1
  }
  verify_child_process_image || {
    if ! child_process_is_live; then
      measurement_error=child_exited_during_sample
    else
      measurement_error=child_process_image_changed
    fi
    return 1
  }
  observed_binary_sha256=$(sha256sum -- "$binary" | awk '{print $1}') || {
    measurement_error=binary_identity_read_failed
    return 1
  }
  [[ "$observed_binary_sha256" == "$binary_sha256" ]] || {
    measurement_error=binary_identity_changed
    return 1
  }
  observed_binary_identity=$(executable_file_identity "$binary") || {
    measurement_error=binary_identity_read_failed
    return 1
  }
  [[ "$observed_binary_identity" == "$binary_file_identity" ]] || {
    measurement_error=binary_identity_changed
    return 1
  }
  observed_auth_identity=$(auth_file_identity "$auth_file") || {
    measurement_error=authorization_identity_read_failed
    return 1
  }
  [[ "$observed_auth_identity" == "$auth_identity" ]] || {
    measurement_error=authorization_identity_changed
    return 1
  }
  [[ -z "$(find "$data_root" -xdev -type l -print -quit)" ]] || {
    measurement_error=data_root_contains_symlink
    return 1
  }
  read -r apparent allocated < <(measure_data_root) || {
    measurement_error=data_root_measurement_failed
    return 1
  }
  read -r fs_size fs_used fs_available <<<"$(filesystem_numbers "$data_root")" || {
    measurement_error=filesystem_measurement_failed
    return 1
  }
  : "$fs_size"
  fs_delta=$((fs_used - baseline_fs_used_bytes))
  ((fs_delta >= 0)) || fs_delta=0
  vm_hwm=$(process_vm_hwm_bytes "$child_pid") || {
    if ! child_process_is_live; then
      measurement_error=child_exited_during_sample
    else
      measurement_error=vm_hwm_measurement_failed
    fi
    return 1
  }
  maximum=$(maximum_of "$apparent" "$allocated" "$fs_delta")
  ((vm_hwm > maximum_observed_vm_hwm_bytes)) &&
    maximum_observed_vm_hwm_bytes=$vm_hwm
  ((apparent > maximum_sampled_apparent_bytes)) && maximum_sampled_apparent_bytes=$apparent
  ((allocated > maximum_sampled_allocated_bytes)) && maximum_sampled_allocated_bytes=$allocated
  ((fs_delta > maximum_sampled_filesystem_used_delta_bytes)) &&
    maximum_sampled_filesystem_used_delta_bytes=$fs_delta
  ((maximum > maximum_sampled_storage_bytes)) && maximum_sampled_storage_bytes=$maximum
  if ((minimum_sampled_filesystem_available_bytes == 0 ||
    fs_available < minimum_sampled_filesystem_available_bytes)); then
    minimum_sampled_filesystem_available_bytes=$fs_available
  fi

  if sync_json=$(read_sync_status "$rpc_response_tmp"); then
    rpc_reachable=true
    if sync_status_is_complete "$sync_json"; then
      sync_complete=true
      consecutive_synced_samples=$((consecutive_synced_samples + 1))
      completed_sync_height=$(jq -er '.active_tip_height' <<<"$sync_json")
      completed_sync_hash=$(jq -er '.active_tip_hash' <<<"$sync_json")
    else
      consecutive_synced_samples=0
    fi
  else
    sync_json=null
    consecutive_synced_samples=0
  fi

  epoch=$(date +%s)
  timestamp=$(date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ')
  elapsed=$((epoch - campaign_started_epoch))
  sample_sequence=$((sample_sequence + 1))
  violation=false
  ((maximum > limit_bytes)) && violation=true
  reserve_violation=false
  ((fs_available < filesystem_reserve_bytes)) && reserve_violation=true
  printf -v sample_path '%s/samples/%09d.json' "$evidence_dir" "$sample_sequence"
  [[ ! -e "$sample_path" && ! -L "$sample_path" ]] || {
    measurement_error=sample_path_collision
    return 1
  }
  temp=$(mktemp "$evidence_dir/samples/.sample.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_sync_resource_sample \
    --arg campaign_id "$campaign_id" \
    --arg timestamp "$timestamp" \
    --argjson epoch "$epoch" \
    --argjson elapsed "$elapsed" \
    --argjson attempt "$attempt" \
    --argjson sequence "$sample_sequence" \
    --argjson pid "$child_pid" \
    --argjson vm_hwm "$vm_hwm" \
    --arg process_image_path "$child_observed_image_path" \
    --arg process_image_identity "$child_observed_image_identity" \
    --arg process_image_sha256 "$child_observed_image_sha256" \
    --argjson apparent "$apparent" \
    --argjson allocated "$allocated" \
    --argjson fs_used "$fs_used" \
    --argjson fs_available "$fs_available" \
    --argjson fs_delta "$fs_delta" \
    --argjson maximum "$maximum" \
    --argjson cutoff "$limit_bytes" \
    --argjson informational_comparison "$INFORMATIONAL_COMPARISON_BYTES" \
    --argjson violation "$violation" \
    --argjson reserve "$filesystem_reserve_bytes" \
    --argjson reserve_violation "$reserve_violation" \
    --argjson rpc_reachable "$rpc_reachable" \
    --argjson sync_complete "$sync_complete" \
    --argjson consecutive_synced "$consecutive_synced_samples" \
    --argjson sync "$sync_json" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      campaign_id: $campaign_id,
      timestamp: $timestamp,
      epoch_seconds: $epoch,
      elapsed_seconds: $elapsed,
      attempt: $attempt,
      sequence: $sequence,
      process: {
        pid: $pid,
        observed_kernel_vm_hwm_bytes: $vm_hwm,
        executable_image: {
          path: $process_image_path,
          file_identity: $process_image_identity,
          sha256: $process_image_sha256,
          matched_launch_binding: true
        }
      },
      storage: {
        sampled_data_root_apparent_bytes: $apparent,
        sampled_data_root_allocated_bytes: $allocated,
        sampled_filesystem_used_bytes: $fs_used,
        sampled_filesystem_available_bytes: $fs_available,
        sampled_filesystem_used_delta_bytes: $fs_delta,
        sampled_storage_maximum_bytes: $maximum,
        sampled_cutoff_bytes: $cutoff,
        sampled_cutoff_exceeded: $violation,
        filesystem_reserve_bytes: $reserve,
        sampled_filesystem_reserve_breached: $reserve_violation,
        sampled_informational_comparison_bytes: $informational_comparison,
        sampled_informational_comparison_at_or_below:
          ($maximum <= $informational_comparison),
        informational_comparison_is_qualification_criterion: false,
        semantics:
          "sampled disk observation; not a kernel quota or true transient peak"
      },
      rpc_reachable: $rpc_reachable,
      sync_complete_this_sample: $sync_complete,
      consecutive_synced_samples: $consecutive_synced,
      sync: $sync
    }' >"$temp"
  atomic_install "$temp" "$sample_path"
  write_runtime_state running "$vm_hwm" "$apparent" "$allocated" "$fs_delta" \
    "$maximum" "$fs_available" "$sync_json"

  if [[ "$violation" == true && "$reserve_violation" == true ]]; then
    stop_request=sampled_storage_cutoff_and_filesystem_reserve_breached
  elif [[ "$violation" == true ]]; then
    stop_request=sampled_storage_cutoff_exceeded
  elif [[ "$reserve_violation" == true ]]; then
    stop_request=sampled_filesystem_reserve_breached
  elif ((consecutive_synced_samples >= completion_samples)); then
    stop_request=sync_completed
  fi
  return 0
}

request_child_shutdown() {
  local deadline term_deadline
  [[ -n "$child_pid" ]] || return 0
  kill -0 "$child_pid" 2>/dev/null || return 0
  if ! proc_identity_matches "$child_pid" "$child_start_ticks"; then
    measurement_error=${measurement_error:-child_process_identity_changed}
    [[ -n "$stop_request" ]] || stop_request=child_process_identity_changed
    return 0
  fi
  child_process_is_live || return 0

  if ! verify_child_process_image; then
    if child_process_is_live; then
      measurement_error=${measurement_error:-child_process_image_changed}
      stop_request=child_process_image_changed
    else
      return 0
    fi
  fi
  kill -INT "$child_pid" 2>/dev/null || true
  deadline=$(($(date +%s) + shutdown_grace_seconds))
  while child_process_is_live &&
    (($(date +%s) < deadline)); do
    sleep 1
  done
  if child_process_is_live; then
    forced_shutdown=true
    kill -TERM "$child_pid" 2>/dev/null || true
    term_deadline=$(($(date +%s) + 10))
    while child_process_is_live &&
      (($(date +%s) < term_deadline)); do
      sleep 1
    done
  fi
  if child_process_is_live; then
    forced_shutdown=true
    kill -KILL "$child_pid" 2>/dev/null || true
  fi
}

handle_term() {
  [[ -n "$stop_request" ]] || stop_request=operator_stop
}

handle_int() {
  [[ -n "$stop_request" ]] || stop_request=operator_interrupt
}

emergency_exit_cleanup() {
  local original_status=$?
  if [[ "$exit_trap_active" == true && "$run_finalized" == false ]]; then
    request_child_shutdown || true
    if [[ -n "$log_scanner_pid" && -n "$log_scanner_start_ticks" ]] &&
      process_identity_is_live "$log_scanner_pid" "$log_scanner_start_ticks"; then
      kill -TERM "$log_scanner_pid" 2>/dev/null || true
    fi
    if [[ -n "$log_scanner_pid" && "$log_scanner_reaped" == false ]]; then
      capture_log_scanner_exit 2>/dev/null || true
    fi
    if [[ -n "$runtime_fifo" && -p "$runtime_fifo" ]]; then
      rm -f -- "$runtime_fifo"
    fi
    if [[ -n "$rpc_response_tmp" && -f "$rpc_response_tmp" &&
      ! -L "$rpc_response_tmp" ]]; then
      rm -f -- "$rpc_response_tmp"
    fi
  fi
  return "$original_status"
}

start_attempt() {
  local lock_file="$evidence_dir/runner.lock"
  local current_binary current_binary_identity current_auth

  exec 9>"$lock_file"
  flock -n 9 || die "campaign runner is already active"
  runner_start_ticks=$(process_start_ticks "$runner_pid") ||
    die "could not capture runner process identity"
  assert_no_authorization_scanner_hard_stop_markers

  current_binary=$(sha256sum -- "$binary" | awk '{print $1}')
  current_binary_identity=$(executable_file_identity "$binary")
  current_auth=$(auth_file_identity "$auth_file")
  [[ "$current_binary" == "$binary_sha256" &&
    "$current_binary_identity" == "$binary_file_identity" ]] ||
    die "binary changed before launch"
  [[ "$current_auth" == "$auth_identity" ]] ||
    die "authorization file changed before launch"

  runtime_fifo="$evidence_dir/.runtime-log.fifo"
  rpc_response_tmp="$evidence_dir/.sync-response.tmp"
  if [[ -e "$runtime_fifo" || -L "$runtime_fifo" ]]; then
    [[ -p "$runtime_fifo" && ! -L "$runtime_fifo" ]] ||
      die "unsafe stale runtime FIFO path"
    rm -f -- "$runtime_fifo"
  fi
  if [[ -e "$rpc_response_tmp" || -L "$rpc_response_tmp" ]]; then
    [[ -f "$rpc_response_tmp" && ! -L "$rpc_response_tmp" ]] ||
      die "unsafe stale RPC response path"
    rm -f -- "$rpc_response_tmp"
  fi
  mkfifo -m 600 -- "$runtime_fifo"
  : >"$rpc_response_tmp"
  chmod 600 -- "$rpc_response_tmp"

  consecutive_synced_samples=0
  stop_request=
  measurement_error=
  forced_shutdown=false
  authorization_value_emitted=false
  authorization_retention_guaranteed=true
  log_scanner_pid=
  log_scanner_start_ticks=
  log_scanner_exit=
  log_scanner_reaped=false
  log_scanner_failure_detail=
  log_scanner_clean_exit_child_transition=false
  exit_trap_active=true
  trap handle_term TERM
  trap handle_int INT
  trap emergency_exit_cleanup EXIT

  start_log_scanner "$evidence_dir/logs" "$auth_file" "$auth_identity" \
    <"$runtime_fifo" &
  log_scanner_pid=$!
  log_scanner_start_ticks=$(process_start_ticks "$log_scanner_pid") ||
    die "could not capture log scanner process identity"

  env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    HSRD_LOG=info RUST_BACKTRACE=1 \
    "$binary" "${NODE_ARGS[@]}" >"$runtime_fifo" 2>&1 &
  child_pid=$!
  child_start_ticks=$(process_start_ticks "$child_pid") ||
    die "could not capture hsrd process identity"
  initialize_child_process_image_binding ||
    die "launched process image does not match the supplied hsrd binary"
  write_runtime_state starting 0 0 0 0 0 \
    "$baseline_fs_available_bytes" null
  monitor_attempt
}

monitor_attempt() {
  local next_sample now child_exit=0 classification exit_code
  local final_apparent=0 final_allocated=0 final_delta=0 final_maximum=0
  local fs_size final_used final_available=$baseline_fs_available_bytes
  local final_binary_identity_ok=false final_auth_identity_ok=false
  local final_binary_sha final_binary_file_identity final_auth_stat

  next_sample=$(date +%s)
  while child_process_is_live; do
    if ! inspect_log_scanner; then
      request_child_shutdown
      break
    fi
    if [[ -n "$stop_request" ]]; then
      request_child_shutdown
      break
    fi
    now=$(date +%s)
    if ((now >= next_sample)); then
      if ! take_sample; then
        if [[ "$measurement_error" == child_exited_during_sample ]]; then
          measurement_error=
          break
        fi
        case "$measurement_error" in
          sample_limit_exceeded|binary_identity_changed|\
            authorization_identity_changed|binary_identity_read_failed|\
            authorization_identity_read_failed|child_process_image_changed)
            stop_request=$measurement_error
            ;;
          *)
            stop_request=measurement_error
            ;;
        esac
        request_child_shutdown
        break
      fi
      if [[ -n "$stop_request" ]]; then
        request_child_shutdown
        break
      fi
      next_sample=$((now + sample_seconds))
    fi
    sleep 1
  done

  set +e
  wait "$child_pid"
  child_exit=$?
  set -e
  capture_log_scanner_exit
  if verify_child_launch_image_fd; then
    child_launch_image_fd_verified_at_finalization=true
  else
    measurement_error=${measurement_error:-child_process_image_changed}
  fi
  if [[ -p "$runtime_fifo" ]]; then
    rm -f -- "$runtime_fifo"
  fi
  if [[ -f "$rpc_response_tmp" && ! -L "$rpc_response_tmp" ]]; then
    rm -f -- "$rpc_response_tmp"
  fi

  if read -r final_apparent final_allocated < <(measure_data_root) &&
    read -r fs_size final_used final_available <<<"$(filesystem_numbers "$data_root")"; then
    : "$fs_size" "$final_available"
    final_delta=$((final_used - baseline_fs_used_bytes))
    ((final_delta >= 0)) || final_delta=0
    final_maximum=$(maximum_of "$final_apparent" "$final_allocated" "$final_delta")
    ((final_apparent > maximum_sampled_apparent_bytes)) && maximum_sampled_apparent_bytes=$final_apparent
    ((final_allocated > maximum_sampled_allocated_bytes)) && maximum_sampled_allocated_bytes=$final_allocated
    ((final_delta > maximum_sampled_filesystem_used_delta_bytes)) &&
      maximum_sampled_filesystem_used_delta_bytes=$final_delta
    ((final_maximum > maximum_sampled_storage_bytes)) && maximum_sampled_storage_bytes=$final_maximum
    if ((minimum_sampled_filesystem_available_bytes == 0 ||
      final_available < minimum_sampled_filesystem_available_bytes)); then
      minimum_sampled_filesystem_available_bytes=$final_available
    fi
  else
    measurement_error=${measurement_error:-final_measurement_failed}
  fi

  final_binary_sha=$(sha256sum -- "$binary" 2>/dev/null | awk '{print $1}' || true)
  final_binary_file_identity=$(executable_file_identity "$binary" 2>/dev/null || true)
  [[ "$final_binary_sha" == "$binary_sha256" &&
    "$final_binary_file_identity" == "$binary_file_identity" ]] &&
    final_binary_identity_ok=true
  final_auth_stat=$(auth_file_identity "$auth_file" 2>/dev/null || true)
  [[ "$final_auth_stat" == "$auth_identity" ]] &&
    final_auth_identity_ok=true
  if [[ -f "$evidence_dir/logs/scanner-failure.json" &&
    ! -L "$evidence_dir/logs/scanner-failure.json" ]]; then
    capture_log_scanner_marker_detail || true
  elif [[ "$log_scanner_exit" != 0 &&
    -z "$log_scanner_failure_detail" ]]; then
    log_scanner_failure_detail="scanner_exit_nonzero_without_failure_marker:$log_scanner_exit"
  fi
  if [[ "$log_scanner_exit" != 0 ||
    -f "$evidence_dir/logs/scanner-failure.json" ||
    "$final_auth_identity_ok" != true ]]; then
    if ! erase_retained_runtime_log_files; then
      authorization_retention_guaranteed=false
      measurement_error=${measurement_error:-authorization_log_erasure_failed}
    fi
  fi
  if [[ -f "$evidence_dir/logs/auth-value-redacted" &&
    ! -L "$evidence_dir/logs/auth-value-redacted" ]]; then
    authorization_value_emitted=true
  fi
  if [[ "$authorization_retention_guaranteed" != true ]]; then
    stop_request=authorization_log_retention_guarantee_failed
  elif [[ "$authorization_value_emitted" == true ]]; then
    stop_request=authorization_value_emission_detected
  elif [[ "$log_scanner_exit" != 0 ||
    -f "$evidence_dir/logs/scanner-failure.json" ]]; then
    measurement_error=${measurement_error:-log_authorization_scanner_failed}
    stop_request=log_authorization_scanner_failed
  elif [[ "$child_launch_image_fd_verified_at_finalization" != true ||
    "$stop_request" == child_process_image_changed ]]; then
    stop_request=child_process_image_changed
  elif [[ "$stop_request" == sample_limit_exceeded ]]; then
    :
  elif ((final_maximum > limit_bytes &&
    final_available < filesystem_reserve_bytes)); then
    stop_request=sampled_storage_cutoff_and_filesystem_reserve_breached
  elif ((final_maximum > limit_bytes)); then
    stop_request=sampled_storage_cutoff_exceeded
  elif ((final_available < filesystem_reserve_bytes)); then
    stop_request=sampled_filesystem_reserve_breached
  elif [[ "$final_binary_identity_ok" != true ]]; then
    stop_request=binary_identity_changed
  elif [[ "$final_auth_identity_ok" != true ]]; then
    stop_request=authorization_identity_changed
  elif [[ -n "$measurement_error" ]]; then
    case "$stop_request" in
      binary_identity_changed|binary_identity_read_failed|\
        authorization_identity_changed|authorization_identity_read_failed|\
        child_process_identity_changed|sample_limit_exceeded|\
        child_process_image_changed|log_authorization_scanner_failed)
        ;;
      *)
        stop_request=measurement_error
        ;;
    esac
  fi

  case "$stop_request" in
    sync_completed)
      if ((child_exit != 0)); then
        classification=sync_completed_child_nonzero
        exit_code=14
      elif [[ "$forced_shutdown" == true ]]; then
        classification=sync_completed_forced_shutdown
        exit_code=14
      else
        classification=sync_completed
        exit_code=0
      fi
      ;;
    sampled_storage_cutoff_exceeded)
      classification=sampled_storage_cutoff_exceeded
      exit_code=13
      ;;
    sampled_storage_cutoff_and_filesystem_reserve_breached)
      classification=sampled_storage_cutoff_and_filesystem_reserve_breached
      exit_code=16
      ;;
    sampled_filesystem_reserve_breached)
      classification=sampled_filesystem_reserve_breached
      exit_code=15
      ;;
    sample_limit_exceeded)
      classification=sample_limit_exceeded
      exit_code=14
      ;;
    measurement_error)
      classification=measurement_error
      exit_code=14
      ;;
    binary_identity_changed|binary_identity_read_failed)
      classification=$stop_request
      exit_code=14
      ;;
    authorization_identity_changed|authorization_identity_read_failed)
      classification=$stop_request
      exit_code=14
      ;;
    child_process_identity_changed)
      classification=child_process_identity_changed
      exit_code=14
      ;;
    child_process_image_changed)
      classification=child_process_image_changed
      exit_code=14
      ;;
    log_authorization_scanner_failed)
      classification=log_authorization_scanner_failed
      exit_code=14
      ;;
    authorization_value_emission_detected)
      classification=authorization_value_emission_detected
      exit_code=14
      ;;
    authorization_log_retention_guarantee_failed)
      classification=authorization_log_retention_guarantee_failed
      exit_code=14
      ;;
    operator_stop)
      classification=operator_stop
      exit_code=10
      ;;
    operator_interrupt)
      classification=operator_interrupt
      exit_code=130
      ;;
    "")
      if ((child_exit == 0)); then
        classification=node_exit_zero_before_sync
        exit_code=11
      else
        classification=node_exit_nonzero
        exit_code=12
      fi
      ;;
    *)
      classification=internal_runner_error
      exit_code=14
      ;;
  esac
  write_final_summary \
    "$classification" "$child_exit" "$final_apparent" "$final_allocated" \
    "$final_delta" "$final_maximum" "$final_available" \
    "$final_binary_identity_ok" "$final_auth_identity_ok"
  write_runtime_state "$classification" 0 "$final_apparent" "$final_allocated" \
    "$final_delta" "$final_maximum" "$final_available" null
  if [[ "$child_image_fd" =~ ^[0-9]+$ ]]; then
    exec {child_image_fd}<&-
  fi
  run_finalized=true
  exit_trap_active=false
  trap - EXIT TERM INT
  log "full-sync campaign classification: $classification"
  log "final summary: $evidence_dir/final-summary.json"
  return "$exit_code"
}

sample_chain_digest() {
  python3 - "$evidence_dir/samples" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
digest = hashlib.sha256()
count = 0
for path in sorted(root.glob("*.json")):
    raw = path.read_bytes()
    json.loads(raw)
    digest.update(path.name.encode())
    digest.update(b"\0")
    digest.update(raw)
    digest.update(b"\0")
    count += 1
print(f"{count} {digest.hexdigest()}")
PY
}

write_logs_manifest() {
  local output=$1
  python3 - "$evidence_dir/logs" "$output" <<'PY'
import hashlib
import json
from pathlib import Path
import os
import sys
import tempfile

root = Path(sys.argv[1])
output = Path(sys.argv[2])
directory_fd = os.open(
    output.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
records = []
for path in sorted(root.iterdir()):
    if not path.is_file() or path.is_symlink() or path.name.startswith("."):
        continue
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    records.append({
        "path": f"logs/{path.name}",
        "size_bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    })
payload = {
    "schema_version": 1,
    "artifact_type": "hsrd_full_sync_logs_manifest",
    "bounded_rotation": {
        "slots": 8,
        "maximum_bytes_per_slot": 67108864,
        "segment_naming": "monotonic_generation",
        "crash_recovery": "journaled_partial_and_counter_reconciliation",
    },
    "files": records,
}
fd, temporary = tempfile.mkstemp(prefix=".logs-manifest.", dir=str(output.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    temporary = None
    os.fsync(directory_fd)
except BaseException:
    if temporary is not None:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(directory_fd)
PY
}

write_final_summary() {
  local classification=$1
  local child_exit=$2
  local final_apparent=$3
  local final_allocated=$4
  local final_delta=$5
  local final_maximum=$6
  local final_available=$7
  local final_binary_identity_ok=$8
  local final_auth_identity_ok=$9
  local ended_epoch ended_at elapsed sample_count samples_digest
  local final_source_revision final_source_tree final_worktree final_dirty source_changed
  local informational_comparison_at_or_below sampled_cutoff_pass
  local sampled_reserve_pass
  local qualification_status temp attempt_summary attempt_temp

  ended_epoch=$(date +%s)
  ended_at=$(date -u -d "@$ended_epoch" '+%Y-%m-%dT%H:%M:%SZ')
  elapsed=$((ended_epoch - campaign_started_epoch))
  read -r sample_count samples_digest < <(sample_chain_digest)
  write_logs_manifest "$evidence_dir/logs-manifest.json"

  final_source_revision=$(git -C "$REPO_ROOT" rev-parse --verify HEAD)
  final_source_tree=$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')
  final_worktree=$(worktree_digest)
  if [[ -z "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]]; then
    final_dirty=false
  else
    final_dirty=true
  fi
  source_changed=false
  if [[ "$final_source_revision" != "$source_revision" ||
    "$final_source_tree" != "$source_tree" ||
    "$final_worktree" != "$source_worktree_sha256" ]]; then
    source_changed=true
  fi
  sampled_cutoff_pass=false
  ((maximum_sampled_storage_bytes <= limit_bytes && final_maximum <= limit_bytes)) &&
    sampled_cutoff_pass=true
  sampled_reserve_pass=false
  ((minimum_sampled_filesystem_available_bytes >= filesystem_reserve_bytes &&
    final_available >= filesystem_reserve_bytes)) &&
    sampled_reserve_pass=true
  informational_comparison_at_or_below=false
  ((maximum_sampled_storage_bytes <= INFORMATIONAL_COMPARISON_BYTES &&
    final_maximum <= INFORMATIONAL_COMPARISON_BYTES)) &&
    informational_comparison_at_or_below=true

  if [[ "$self_test_interpreter_image_allowance" == true ]]; then
    qualification_status=self_test_only_non_qualification
  elif [[ "$classification" != sync_completed ]]; then
    qualification_status=incomplete
  elif [[ "$source_dirty" == true || "$final_dirty" == true ||
    "$source_changed" == true ]]; then
    qualification_status=completed_provisional_dirty_or_changed_source
  else
    qualification_status=completed_provisional_unverified_reproducible_build_binding
  fi

  temp=$(mktemp "$evidence_dir/.final-summary.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_non_pruned_mainnet_campaign_summary \
    --arg campaign_id "$campaign_id" \
    --arg config_sha256 "$config_sha256" \
    --arg classification "$classification" \
    --arg qualification_status "$qualification_status" \
    --arg started_at "$campaign_started_at" \
    --arg ended_at "$ended_at" \
    --argjson elapsed "$elapsed" \
    --argjson attempt "$attempt" \
    --argjson child_exit "$child_exit" \
    --argjson forced_shutdown "$forced_shutdown" \
    --arg child_image_path "$child_expected_image_path" \
    --arg child_image_identity "$child_expected_image_identity" \
    --arg child_image_sha256 "$child_expected_image_sha256" \
    --argjson child_image_verification_count "$child_image_verification_count" \
    --argjson child_launch_fd_verified \
      "$child_launch_image_fd_verified_at_finalization" \
    --argjson self_test_image_allowance \
      "$self_test_interpreter_image_allowance" \
    --arg measurement_error "$measurement_error" \
    --argjson authorization_value_emitted "$authorization_value_emitted" \
    --argjson authorization_retention_guaranteed \
      "$authorization_retention_guaranteed" \
    --argjson log_scanner_exit "$log_scanner_exit" \
    --arg log_scanner_failure_detail "$log_scanner_failure_detail" \
    --argjson log_scanner_clean_exit_child_transition \
      "$log_scanner_clean_exit_child_transition" \
    --argjson sample_count "$sample_count" \
    --arg samples_digest "$samples_digest" \
    --argjson maximum_vm_hwm "$maximum_observed_vm_hwm_bytes" \
    --argjson maximum_apparent "$maximum_sampled_apparent_bytes" \
    --argjson maximum_allocated "$maximum_sampled_allocated_bytes" \
    --argjson maximum_delta "$maximum_sampled_filesystem_used_delta_bytes" \
    --argjson maximum_storage "$maximum_sampled_storage_bytes" \
    --argjson final_apparent "$final_apparent" \
    --argjson final_allocated "$final_allocated" \
    --argjson final_delta "$final_delta" \
    --argjson final_maximum "$final_maximum" \
    --argjson final_available "$final_available" \
    --argjson minimum_available "$minimum_sampled_filesystem_available_bytes" \
    --argjson cutoff "$limit_bytes" \
    --argjson cutoff_pass "$sampled_cutoff_pass" \
    --argjson reserve "$filesystem_reserve_bytes" \
    --argjson reserve_pass "$sampled_reserve_pass" \
    --argjson informational_comparison "$INFORMATIONAL_COMPARISON_BYTES" \
    --argjson informational_comparison_at_or_below \
      "$informational_comparison_at_or_below" \
    --argjson binary_identity_ok "$final_binary_identity_ok" \
    --argjson auth_identity_ok "$final_auth_identity_ok" \
    --arg sync_height "$completed_sync_height" \
    --arg sync_hash "$completed_sync_hash" \
    --arg source_revision "$source_revision" \
    --arg source_tree "$source_tree" \
    --arg source_worktree "$source_worktree_sha256" \
    --argjson source_dirty "$source_dirty" \
    --arg final_revision "$final_source_revision" \
    --arg final_tree "$final_source_tree" \
    --arg final_worktree "$final_worktree" \
    --argjson final_dirty "$final_dirty" \
    --argjson source_changed "$source_changed" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      campaign_id: $campaign_id,
      campaign_config_sha256: $config_sha256,
      classification: $classification,
      qualification_status: $qualification_status,
      started_at: $started_at,
      ended_at: $ended_at,
      elapsed_seconds: $elapsed,
      final_attempt: $attempt,
      process: {
        exit_code: $child_exit,
        forced_shutdown: $forced_shutdown,
        log_authorization_scanner_exit_code: $log_scanner_exit,
        log_authorization_scanner_failure_detail:
          (if $log_scanner_failure_detail == "" then
            null
          else
            $log_scanner_failure_detail
          end),
        log_authorization_scanner_clean_exit_accepted_during_child_exit_transition:
          $log_scanner_clean_exit_child_transition,
        executable_image_binding: {
          launch_path: $child_image_path,
          launch_file_identity: $child_image_identity,
          launch_sha256: $child_image_sha256,
          verification_count: $child_image_verification_count,
          launch_image_fd_verified_at_finalization: $child_launch_fd_verified,
          self_test_interpreter_allowance: $self_test_image_allowance
        }
      },
      provenance_identity: {
        binary_path_identity_and_sha256_matched_at_finalization:
          $binary_identity_ok,
        authorization_file_identity_matched_at_finalization: $auth_identity_ok
      },
      runner_error:
        (if $measurement_error == "" then null else $measurement_error end),
      authorization: {
        value_emission_detected: $authorization_value_emitted,
        value_persisted_in_retained_logs:
          (if $authorization_retention_guaranteed then false else null end),
        retained_log_absence_guaranteed:
          $authorization_retention_guaranteed,
        scanner_fail_closed: true
      },
      samples: {
        count: $sample_count,
        content_chain_sha256: $samples_digest
      },
      metrics: {
        maximum_observed_kernel_process_vm_hwm_bytes: $maximum_vm_hwm,
        maximum_sampled_data_root_apparent_bytes: $maximum_apparent,
        maximum_sampled_data_root_allocated_bytes: $maximum_allocated,
        maximum_sampled_filesystem_used_delta_bytes: $maximum_delta,
        maximum_sampled_storage_bytes: $maximum_storage,
        final_observed_data_root_apparent_bytes: $final_apparent,
        final_observed_data_root_allocated_bytes: $final_allocated,
        final_observed_filesystem_used_delta_bytes: $final_delta,
        final_observed_filesystem_available_bytes: $final_available,
        minimum_sampled_filesystem_available_bytes: $minimum_available,
        final_observed_storage_maximum_bytes: $final_maximum,
        sampled_cutoff_bytes: $cutoff,
        sampled_cutoff_respected: $cutoff_pass,
        filesystem_reserve_bytes: $reserve,
        sampled_filesystem_reserve_respected: $reserve_pass,
        sampled_operational_thresholds_respected:
          ($cutoff_pass and $reserve_pass),
        sampled_informational_comparison_bytes: $informational_comparison,
        sampled_informational_comparison_at_or_below:
          $informational_comparison_at_or_below,
        informational_comparison_is_qualification_criterion: false,
        semantics:
          "disk values are periodic/final observations; the configured cutoff (150,000,000,000 bytes by default) is the only storage stop threshold, the filesystem reserve is enforced separately, and 90,000,000,000 bytes is an informational sampled comparison only; none is a claim about unobserved transient maxima"
      },
      synchronized_tip: {
        height: (if $sync_height == "" then null else ($sync_height | tonumber) end),
        hash: (if $sync_hash == "" then null else $sync_hash end)
      },
      source: {
        initial: {
          revision: $source_revision,
          tree: $source_tree,
          worktree_sha256: $source_worktree,
          dirty: $source_dirty
        },
        final: {
          revision: $final_revision,
          tree: $final_tree,
          worktree_sha256: $final_worktree,
          dirty: $final_dirty
        },
        changed_during_campaign: $source_changed
      },
      evidence_scope: {
        baseline_mode: "full_non_pruned",
        network: "mainnet",
        storage_mode: "archive",
        hsd_reference_data_statement:
          "not measured or asserted by this runner",
        pruned_comparison_included: false,
        reproducible_build_proven: false,
        self_test_interpreter_image_allowance:
          $self_test_image_allowance,
        log_rotation:
          "newest eight monotonic-generation segments; journaled partial recovery and max-generation counter reconciliation prevent crash-window overwrite",
        evidence_commit_semantics:
          "fsync file, atomic replace, then fsync containing directory"
      }
    }' >"$temp"
  atomic_install "$temp" "$evidence_dir/final-summary.json"
  printf -v attempt_summary '%s/attempts/%06d-summary.json' "$evidence_dir" "$attempt"
  [[ ! -e "$attempt_summary" && ! -L "$attempt_summary" ]] ||
    die "attempt summary path already exists"
  attempt_temp=$(mktemp "$evidence_dir/attempts/.attempt-summary.XXXXXX")
  cp --reflink=auto -- "$evidence_dir/final-summary.json" "$attempt_temp"
  atomic_install "$attempt_temp" "$attempt_summary"
}

proc_identity_matches() {
  local pid=$1
  local ticks=$2
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$ticks" =~ ^[0-9]+$ ]] || return 1
  [[ "$(process_start_ticks "$pid" 2>/dev/null || true)" == "$ticks" ]]
}

proc_cmdline_contains_runner() {
  local pid=$1
  local arg cwd candidate found_script=false found_evidence=false
  [[ -r "/proc/$pid/cmdline" ]] || return 1
  cwd=$(readlink -e -- "/proc/$pid/cwd") || return 1
  while IFS= read -r -d '' arg; do
    if [[ "$arg" == "$SCRIPT_PATH" ]]; then
      found_script=true
    elif [[ "$arg" == */* ]]; then
      if [[ "$arg" == /* ]]; then
        candidate=$(realpath -m -- "$arg")
      else
        candidate=$(realpath -m -- "$cwd/$arg")
      fi
      [[ "$candidate" == "$SCRIPT_PATH" ]] && found_script=true
    fi
    [[ "$arg" == "$evidence_dir" ]] && found_evidence=true
  done <"/proc/$pid/cmdline"
  [[ "$found_script" == true && "$found_evidence" == true ]]
}

status_command() {
  local state runner_alive=false child_alive=false
  evidence_dir=$(normalize_absolute_path "$evidence_dir" "evidence directory")
  validate_existing_private_directory "$evidence_dir" "evidence directory"
  state="$evidence_dir/state.json"
  [[ -f "$state" && ! -L "$state" ]] || die "runtime state is missing"
  jq -e '.artifact_type == "hsrd_full_sync_runtime_state"' "$state" >/dev/null ||
    die "runtime state is invalid"
  if process_identity_is_live \
    "$(jq -r '.runner.pid // empty' "$state")" \
    "$(jq -r '.runner.start_ticks // empty' "$state")"; then
    runner_alive=true
  fi
  if process_identity_is_live \
    "$(jq -r '.child.pid // empty' "$state")" \
    "$(jq -r '.child.start_ticks // empty' "$state")"; then
    child_alive=true
  fi
  jq -c \
    --argjson runner_alive "$runner_alive" \
    --argjson child_alive "$child_alive" \
    '. + {observed_process_state: {
      runner_alive: $runner_alive,
      child_alive: $child_alive
    }}' "$state"
}

stop_command() {
  local state pid ticks child binary_path binary_expected binary_actual child_exe
  evidence_dir=$(normalize_absolute_path "$evidence_dir" "evidence directory")
  validate_existing_private_directory "$evidence_dir" "evidence directory"
  state="$evidence_dir/state.json"
  [[ -f "$state" && ! -L "$state" ]] || die "runtime state is missing"
  pid=$(jq -er '.runner.pid' "$state")
  ticks=$(jq -er '.runner.start_ticks' "$state")
  if process_identity_is_live "$pid" "$ticks" &&
    proc_cmdline_contains_runner "$pid"; then
    kill -TERM "$pid"
    log "requested graceful stop from runner PID $pid"
    return 0
  fi

  child=$(jq -r '.child.pid // empty' "$state")
  ticks=$(jq -r '.child.start_ticks // empty' "$state")
  if process_identity_is_live "$child" "$ticks"; then
    binary_path=$(jq -er '.binary.path' "$evidence_dir/campaign-config.json")
    binary_expected=$(jq -er '.binary.sha256' "$evidence_dir/campaign-config.json")
    binary_actual=$(sha256sum -- "$binary_path" | awk '{print $1}')
    child_exe=$(readlink -e -- "/proc/$child/exe") || die "could not identify orphaned child"
    [[ "$child_exe" == "$binary_path" && "$binary_actual" == "$binary_expected" ]] ||
      die "refusing to signal an orphan whose executable identity does not match"
    kill -INT "$child"
    log "runner was absent; requested graceful stop from verified hsrd PID $child"
    return 0
  fi
  die "no matching live runner or hsrd process was found"
}

self_test_cleanup() {
  local root=$1
  [[ -n "$root" && -d "$root" && ! -L "$root" ]] || return 0
  [[ "$root" == "${TMPDIR:-/tmp}/hsrd-full-sync-self-test."* ]] || return 1
  find "$root" -xdev -depth -delete
}

write_fake_binary() {
  local path=$1
  local behavior=$2
  cat >"$path" <<'FAKE'
#!/usr/bin/env python3
import http.server
import json
import os
from pathlib import Path
import signal
import sys
import time

arguments = sys.argv[1:]

def option(name):
    try:
        return arguments[arguments.index(name) + 1]
    except (ValueError, IndexError):
        return None

if "--check-config" in arguments:
    print("configuration parsed successfully", flush=True)
    raise SystemExit(0)

data_value = option("--data-dir")
auth_value = option("--rpc-authorization-header-file")
rpc_bind = option("--rpc-bind")
if data_value is None:
    raise SystemExit(90)
data = Path(data_value)
if not data.is_dir():
    raise SystemExit(90)
behavior = Path(sys.argv[0]).name

def exit_zero(_signum, _frame):
    raise SystemExit(0)

def run_until_stopped(exit_handler=exit_zero):
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    while True:
        time.sleep(0.1)

def write_allocated(path, size):
    block = b"\0" * (1024 * 1024)
    with path.open("wb") as handle:
        for _ in range(size // len(block)):
            handle.write(block)
        handle.flush()
        os.fsync(handle.fileno())

if "normal" in behavior:
    print("bounded fake node output", flush=True)
    fixture = data / "fixture"
    if not fixture.exists():
        if any(data.iterdir()):
            raise SystemExit(92)
        fixture.write_text("fixture\n", encoding="utf-8")
    time.sleep(2)
    raise SystemExit(0)

if "reserve" in behavior:
    if any(data.iterdir()):
        raise SystemExit(92)
    write_allocated(data / "reserve-pressure", 32 * 1024 * 1024)
    run_until_stopped()

if "limit" in behavior:
    if any(data.iterdir()):
        raise SystemExit(92)
    write_allocated(data / "oversize", 4 * 1024 * 1024)
    run_until_stopped()

if "boundary" in behavior:
    if auth_value is None:
        raise SystemExit(90)
    secret = Path(auth_value).read_bytes().strip()
    split = max(1, len(secret) // 2)
    remaining = 67108864 - split
    block = b"A" * 65536
    while remaining:
        piece = block[:min(remaining, len(block))]
        sys.stdout.buffer.write(piece)
        remaining -= len(piece)
    sys.stdout.buffer.write(secret[:split])
    sys.stdout.buffer.flush()
    time.sleep(0.1)
    sys.stdout.buffer.write(secret[split:])
    sys.stdout.buffer.write(b"B" * 65536)
    sys.stdout.buffer.flush()
    run_until_stopped()

if "auth-change" in behavior:
    signal.signal(signal.SIGINT, exit_zero)
    signal.signal(signal.SIGTERM, exit_zero)
    while True:
        print("auth-change heartbeat", flush=True)
        time.sleep(0.05)

if "exec-change" in behavior:
    time.sleep(2)
    os.execl("/bin/sleep", "sleep", "30")

if "synced-nonzero" in behavior:
    if rpc_bind is None:
        raise SystemExit(90)
    host, port_text = rpc_bind.rsplit(":", 1)
    tip_hash = [0x11] * 32
    payload = json.dumps({
        "stage": "Synced",
        "best_header": {"height": 1, "hash": tip_hash},
        "active_tip": {"height": 1, "hash": tip_hash},
        "stored_tip": {"height": 1, "hash": tip_hash},
        "target_height": 1,
        "pending_blocks": 0,
        "inflight_blocks": 0,
        "tracked_blocks": 0,
        "validated_blocks": 1,
        "failed_blocks": 0,
        "sequence": 1,
        "peers": [{"ready": True}],
    }, separators=(",", ":")).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *_args):
            return

    def exit_seven(_signum, _frame):
        raise SystemExit(7)

    signal.signal(signal.SIGINT, exit_seven)
    signal.signal(signal.SIGTERM, exit_seven)
    server = http.server.ThreadingHTTPServer((host, int(port_text)), Handler)
    server.serve_forever(poll_interval=0.05)

if "long" in behavior:
    sys.stdout.buffer.write(b"L" * 65536)
    sys.stdout.buffer.flush()
    run_until_stopped()

raise SystemExit(91)
FAKE
  chmod 700 -- "$path"
  case "$behavior" in
    normal|limit|reserve|long|boundary|auth-change|exec-change|synced-nonzero)
      ;;
    *)
      return 1
      ;;
  esac
}

self_test_log_scanner_child_exit_race() (
  local fixture_root=$1
  local auth_path=$2
  local expected_identity iteration scanner_stopped release_path
  local release_worker=
  local child_pid=
  local child_start_ticks=
  local log_scanner_pid=
  local log_scanner_start_ticks=
  local log_scanner_exit=
  local log_scanner_reaped=false
  local log_scanner_failure_detail=
  local log_scanner_clean_exit_child_transition=false
  local evidence_dir=
  local runtime_fifo=
  local measurement_error=
  local stop_request=
  local authorization_value_emitted=false

  cleanup_scanner_race_fixture() {
    if [[ -n "$release_worker" ]] &&
      kill -0 "$release_worker" 2>/dev/null; then
      kill -TERM "$release_worker" 2>/dev/null || true
    fi
    [[ -z "$release_worker" ]] || wait "$release_worker" 2>/dev/null || true
    if [[ -n "$child_pid" && -n "$child_start_ticks" ]] &&
      process_identity_is_live "$child_pid" "$child_start_ticks"; then
      kill -TERM "$child_pid" 2>/dev/null || true
    fi
    [[ -z "$child_pid" ]] || wait "$child_pid" 2>/dev/null || true
    if [[ -n "$log_scanner_pid" && -n "$log_scanner_start_ticks" ]] &&
      process_identity_is_live "$log_scanner_pid" "$log_scanner_start_ticks"; then
      kill -TERM "$log_scanner_pid" 2>/dev/null || true
    fi
    if [[ -n "$log_scanner_pid" && "$log_scanner_reaped" == false ]]; then
      capture_log_scanner_exit 2>/dev/null || true
    fi
    if [[ -n "$runtime_fifo" && -p "$runtime_fifo" ]]; then
      rm -f -- "$runtime_fifo"
    fi
  }
  trap cleanup_scanner_race_fixture EXIT

  expected_identity=$(auth_file_identity "$auth_path")
  for iteration in {1..16}; do
    evidence_dir="$fixture_root/scanner-child-exit-race-$iteration"
    mkdir -m 700 -- "$evidence_dir" "$evidence_dir/logs"
    runtime_fifo="$evidence_dir/runtime.fifo"
    mkfifo -m 600 -- "$runtime_fifo"
    release_path="$evidence_dir/release-child"
    child_pid=
    child_start_ticks=
    log_scanner_pid=
    log_scanner_start_ticks=
    log_scanner_exit=
    log_scanner_reaped=false
    log_scanner_failure_detail=
    log_scanner_clean_exit_child_transition=false
    measurement_error=
    stop_request=
    authorization_value_emitted=false

    start_log_scanner "$evidence_dir/logs" "$auth_path" "$expected_identity" \
      <"$runtime_fifo" &
    log_scanner_pid=$!
    log_scanner_start_ticks=$(process_start_ticks "$log_scanner_pid") ||
      die "scanner-race stress could not identify scanner iteration $iteration"
    /bin/sh -c '
      exec 1>&- 2>&-
      while [ ! -f "$1" ]; do
        sleep 0.01
      done
      sleep 0.05
    ' scanner-race-child "$release_path" >"$runtime_fifo" 2>&1 &
    child_pid=$!
    child_start_ticks=$(process_start_ticks "$child_pid") ||
      die "scanner-race stress could not identify child iteration $iteration"

    scanner_stopped=false
    for _ in {1..200}; do
      if ! process_identity_is_live \
        "$log_scanner_pid" "$log_scanner_start_ticks"; then
        scanner_stopped=true
        break
      fi
      sleep 0.01
    done
    [[ "$scanner_stopped" == true ]] ||
      die "scanner-race stress scanner did not cleanly consume EOF"
    child_process_is_live ||
      die "scanner-race stress did not force the child-live/scanner-dead state"

    (
      sleep 0.05
      atomic_write_text "$release_path" release
    ) &
    release_worker=$!
    inspect_log_scanner ||
      die "scanner-race stress misclassified clean EOF iteration $iteration: $log_scanner_failure_detail"
    wait "$release_worker"
    release_worker=
    if wait "$child_pid"; then
      :
    else
      die "scanner-race stress child failed in iteration $iteration"
    fi
    child_pid=
    [[ "$log_scanner_reaped" == true &&
      "$log_scanner_exit" == 0 &&
      "$log_scanner_clean_exit_child_transition" == true &&
      -z "$log_scanner_failure_detail" &&
      -z "$measurement_error" &&
      -z "$stop_request" ]] ||
      die "scanner-race stress lifecycle invariant failed in iteration $iteration"
    rm -f -- "$runtime_fifo"
    runtime_fifo=
  done
  trap - EXIT
)

self_test_sync_hash_normalization() {
  local fixture_root=$1
  local response normalized expected uppercase index
  local -a malformed_labels malformed_values

  response="$fixture_root/sync-hash-response.json"
  expected=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  jq -n '
    [range(0; 32)] as $hash |
    {
      stage: "Synced",
      best_header: {height: 1, hash: $hash},
      active_tip: {height: 1, hash: $hash},
      stored_tip: {height: 1, hash: $hash},
      target_height: 1,
      pending_blocks: 0,
      inflight_blocks: 0,
      tracked_blocks: 0,
      validated_blocks: 1,
      failed_blocks: 0,
      sequence: 1,
      peers: [{ready: true}]
    }' >"$response"
  normalized=$(normalize_sync_status_response "$response") ||
    die "self-test rejected the real byte-array BlockHash RPC shape"
  jq -e --arg expected "$expected" '
    .best_header_hash == $expected and
    .active_tip_hash == $expected and
    .stored_tip_hash == $expected
  ' <<<"$normalized" >/dev/null ||
    die "self-test did not canonically encode byte-array BlockHash values"
  sync_status_is_complete "$normalized" ||
    die "self-test did not recognize a normalized complete sync response"

  uppercase=ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
  jq -n --arg hash "$uppercase" '
    {
      stage: "Synced",
      best_header: {height: 1, hash: $hash},
      active_tip: {height: 1, hash: $hash},
      stored_tip: {height: 1, hash: $hash},
      target_height: 1,
      pending_blocks: 0,
      inflight_blocks: 0,
      tracked_blocks: 0,
      validated_blocks: 1,
      failed_blocks: 0,
      sequence: 1,
      peers: [{ready: true}]
    }' >"$response"
  normalized=$(normalize_sync_status_response "$response") ||
    die "self-test rejected a strictly valid hexadecimal BlockHash"
  jq -e --arg expected "${uppercase,,}" '
    .best_header_hash == $expected and
    .active_tip_hash == $expected and
    .stored_tip_hash == $expected
  ' <<<"$normalized" >/dev/null ||
    die "self-test did not lowercase a compatible hexadecimal BlockHash"

  malformed_labels=(
    short-array
    long-array
    negative-byte
    oversized-byte
    fractional-byte
    non-number-byte
    wrong-container-type
    invalid-string
  )
  malformed_values=(
    "$(jq -cn '[range(0; 31)]')"
    "$(jq -cn '[range(0; 33)]')"
    "$(jq -cn '[range(0; 31)] + [-1]')"
    "$(jq -cn '[range(0; 31)] + [256]')"
    "$(jq -cn '[range(0; 31)] + [1.5]')"
    "$(jq -cn '[range(0; 31)] + ["1"]')"
    "$(jq -cn '{bytes: [range(0; 32)]}')"
    "$(jq -cn '"not-a-block-hash"')"
  )
  for index in "${!malformed_values[@]}"; do
    jq -n --argjson hash "${malformed_values[$index]}" '
      {
        stage: "Synced",
        best_header: {height: 1, hash: $hash},
        active_tip: {height: 1, hash: $hash},
        stored_tip: {height: 1, hash: $hash},
        target_height: 1,
        pending_blocks: 0,
        inflight_blocks: 0,
        tracked_blocks: 0,
        validated_blocks: 1,
        failed_blocks: 0,
        sequence: 1,
        peers: [{ready: true}]
      }' >"$response"
    if normalize_sync_status_response "$response" >/dev/null 2>&1; then
      die "self-test accepted malformed BlockHash: ${malformed_labels[$index]}"
    fi
  done

  jq -n '
    {
      stage: "Headers",
      best_header: null,
      active_tip: null,
      stored_tip: null,
      target_height: 1,
      pending_blocks: 0,
      inflight_blocks: 0,
      tracked_blocks: 0,
      validated_blocks: 0,
      failed_blocks: 0,
      sequence: 1,
      peers: []
    }' >"$response"
  normalized=$(normalize_sync_status_response "$response") ||
    die "self-test rejected absent pre-sync BlockHash values"
  jq -e '
    .best_header_hash == null and
    .active_tip_hash == null and
    .stored_tip_hash == null
  ' <<<"$normalized" >/dev/null ||
    die "self-test changed absent pre-sync BlockHash values"
  if sync_status_is_complete "$normalized"; then
    die "self-test accepted an incomplete null-tip sync response"
  fi
}

self_test() {
  local root auth mutation_auth normal_binary limit_binary reserve_binary
  local long_binary boundary_binary auth_change_binary exec_change_binary
  local synced_nonzero_binary
  local rc output
  local normal_data normal_evidence limit_data limit_evidence
  local reserve_data reserve_evidence reserve_available reserve_bytes
  local refuse_data refuse_evidence symlink_data symlink_evidence
  local stop_data stop_evidence stop_output stop_runner ready
  local orphan_data orphan_evidence orphan_output orphan_runner orphan_child
  local orphan_child_ticks orphan_scanner orphan_scanner_ticks
  local orphan_resume_output orphan_resume_runner recovered_segment recovered_sha
  local recovery_marker stale_counter reconciliation_marker
  local boundary_data boundary_evidence
  local mutation_data mutation_evidence mutation_output mutation_runner
  local exec_change_data exec_change_evidence
  local synced_data synced_evidence sample_limit_data sample_limit_evidence
  local stale_scanner_marker

  root=$(mktemp -d "${TMPDIR:-/tmp}/hsrd-full-sync-self-test.XXXXXX")
  chmod 700 -- "$root"
  trap 'self_test_cleanup "$root"' EXIT
  self_test_sync_hash_normalization "$root"
  auth="$root/auth-header"
  printf '%s\n' 'Bearer self-test-high-entropy-value' >"$auth"
  chmod 600 -- "$auth"
  mutation_auth="$root/mutation-auth-header"
  printf '%s\n' 'Bearer self-test-mutation-original' >"$mutation_auth"
  chmod 600 -- "$mutation_auth"
  normal_binary="$root/fake-normal-hsrd"
  limit_binary="$root/fake-limit-hsrd"
  reserve_binary="$root/fake-reserve-hsrd"
  long_binary="$root/fake-long-hsrd"
  boundary_binary="$root/fake-boundary-hsrd"
  auth_change_binary="$root/fake-auth-change-hsrd"
  exec_change_binary="$root/fake-exec-change-hsrd"
  synced_nonzero_binary="$root/fake-synced-nonzero-hsrd"
  write_fake_binary "$normal_binary" normal
  write_fake_binary "$limit_binary" limit
  write_fake_binary "$reserve_binary" reserve
  write_fake_binary "$long_binary" long
  write_fake_binary "$boundary_binary" boundary
  write_fake_binary "$auth_change_binary" auth-change
  write_fake_binary "$exec_change_binary" exec-change
  write_fake_binary "$synced_nonzero_binary" synced-nonzero
  self_test_log_scanner_child_exit_race "$root" "$auth" ||
    die "self-test clean scanner-exit/child-exit race stress failed"

  normal_data="$root/normal-data"
  normal_evidence="$root/normal-evidence"
  mkdir -m 700 -- "$normal_data" "$normal_evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$normal_data" \
    --evidence-dir "$normal_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19337 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 11 ]] ||
    die "self-test normal-exit fixture returned $rc; expected 11: $output; evidence: $(jq -c '{classification,runner_error,process}' "$normal_evidence/final-summary.json" 2>/dev/null || true)"
  [[ "$(jq -r '.classification' "$normal_evidence/final-summary.json")" == \
    node_exit_zero_before_sync ]] ||
    die "self-test normal-exit classification is wrong"
  jq -e '
    .measurement.sampled_cutoff_bytes == 500000000 and
    .measurement.sampled_informational_comparison_bytes == 90000000000 and
    .measurement.informational_comparison_is_qualification_criterion == false and
    (.measurement | has("sampled_strict_benchmark_bytes") | not)
  ' "$normal_evidence/campaign-config.json" >/dev/null ||
    die "self-test campaign schema confused the informational comparison with the cutoff"
  jq -e '
    .metrics.sampled_cutoff_bytes == 500000000 and
    .metrics.sampled_informational_comparison_bytes == 90000000000 and
    .metrics.informational_comparison_is_qualification_criterion == false and
    (.metrics | has("sampled_strict_benchmark_bytes") | not)
  ' "$normal_evidence/final-summary.json" >/dev/null ||
    die "self-test final schema treated the informational comparison as a criterion"
  [[ -f "$normal_data/fixture" ]] ||
    die "self-test empty-root fixture did not run"
  output=$("$SCRIPT_PATH" status --evidence-dir "$normal_evidence")
  jq -e '
    .status == "node_exit_zero_before_sync" and
    .observed_process_state.runner_alive == false and
    .observed_process_state.child_alive == false
  ' <<<"$output" >/dev/null ||
    die "self-test status did not report the stopped fixture"
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$normal_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 11 ]] ||
    die "self-test resume fixture returned $rc; expected 11: $output; evidence: $(jq -c '{classification,runner_error,process}' "$normal_evidence/final-summary.json" 2>/dev/null || true); scanner: $(jq -c . "$normal_evidence/logs/scanner-failure.json" 2>/dev/null || true)"
  [[ "$(jq -r '.final_attempt' "$normal_evidence/final-summary.json")" == 2 ]] ||
    die "self-test resume did not advance the attempt"
  stale_scanner_marker="$normal_evidence/logs/scanner-failure.json"
  atomic_write_text "$stale_scanner_marker" \
    '{"schema_version":1,"artifact_type":"hsrd_log_scanner_failure","reason":"self_test_stale_marker","safe_failure_detail":"prior_attempt_fixture"}'
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$normal_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"non-resumable authorization scanner hard-stop marker"* &&
    "$(jq -r '.final_attempt' "$normal_evidence/final-summary.json")" == 2 ]] ||
    die "self-test allowed a stale scanner marker to poison a later attempt"
  python3 - "$stale_scanner_marker" <<'PY'
import os
from pathlib import Path
import sys

marker = Path(sys.argv[1])
marker.unlink()
directory_fd = os.open(
    marker.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY

  stop_data="$root/stop-data"
  stop_evidence="$root/stop-evidence"
  stop_output="$root/stop-output"
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$limit_binary" \
    --data-root "$stop_data" \
    --evidence-dir "$stop_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19339 >"$stop_output" 2>&1 &
  stop_runner=$!
  ready=false
  for _ in {1..60}; do
    if [[ -f "$stop_evidence/state.json" ]] &&
      jq -e '.status == "running" or .status == "starting"' \
        "$stop_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$stop_runner" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  [[ "$ready" == true ]] || {
    wait "$stop_runner" || true
    die "self-test stop fixture did not enter running state"
  }
  "$SCRIPT_PATH" stop --evidence-dir "$stop_evidence" >/dev/null
  set +e
  wait "$stop_runner"
  rc=$?
  set -e
  [[ "$rc" == 10 ]] ||
    die "self-test stop fixture returned $rc; expected 10"
  [[ "$(jq -r '.classification' "$stop_evidence/final-summary.json")" == \
    operator_stop ]] ||
    die "self-test graceful stop classification is wrong"

  orphan_data="$root/orphan-data"
  orphan_evidence="$root/orphan-evidence"
  orphan_output="$root/orphan-output"
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$orphan_data" \
    --evidence-dir "$orphan_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 30 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19341 >"$orphan_output" 2>&1 &
  orphan_runner=$!
  ready=false
  for _ in {1..120}; do
    if [[ -f "$orphan_evidence/state.json" ]] &&
      jq -e '.status == "running" or .status == "starting"' \
        "$orphan_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$orphan_runner" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  [[ "$ready" == true ]] || {
    wait "$orphan_runner" || true
    die "self-test live-orphan fixture did not enter running state"
  }
  ready=false
  for _ in {1..120}; do
    if [[ -s "$orphan_evidence/logs/.hsrd-log-partial" ]]; then
      ready=true
      break
    fi
    if ! kill -0 "$orphan_runner" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] || {
    wait "$orphan_runner" || true
    die "self-test crash-recovery fixture did not create a partial log"
  }
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"recorded campaign runner is still live"* ]] ||
    die "self-test resume did not reject the exact live runner"

  orphan_child=$(jq -er '.child.pid' "$orphan_evidence/state.json")
  orphan_child_ticks=$(jq -er '.child.start_ticks' "$orphan_evidence/state.json")
  orphan_scanner=$(jq -er '.log_scanner.pid' "$orphan_evidence/state.json")
  orphan_scanner_ticks=$(jq -er \
    '.log_scanner.start_ticks' "$orphan_evidence/state.json")
  kill -KILL "$orphan_runner"
  set +e
  wait "$orphan_runner"
  rc=$?
  set -e
  [[ "$rc" == 137 ]] ||
    die "self-test could not create an interrupted-runner orphan fixture"
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"recorded hsrd child is still live"* ]] ||
    die "self-test resume did not reject the exact live orphaned child"

  if process_identity_is_live "$orphan_scanner" "$orphan_scanner_ticks"; then
    kill -KILL "$orphan_scanner"
  fi
  for _ in {1..80}; do
    process_identity_is_live "$orphan_scanner" "$orphan_scanner_ticks" || break
    sleep 0.1
  done
  if process_identity_is_live "$orphan_child" "$orphan_child_ticks"; then
    kill -KILL "$orphan_child"
  fi
  for _ in {1..80}; do
    process_identity_is_live "$orphan_child" "$orphan_child_ticks" || break
    sleep 0.1
  done
  process_identity_is_live "$orphan_scanner" "$orphan_scanner_ticks" &&
    die "self-test could not terminate the crashed scanner"
  process_identity_is_live "$orphan_child" "$orphan_child_ticks" &&
    die "self-test could not terminate the crashed child"
  [[ -s "$orphan_evidence/logs/.hsrd-log-partial" ]] ||
    die "self-test all-process loss did not preserve a recoverable partial log"

  orphan_resume_output="$root/orphan-resume-output"
  "$SCRIPT_PATH" resume \
    --evidence-dir "$orphan_evidence" >"$orphan_resume_output" 2>&1 &
  orphan_resume_runner=$!
  ready=false
  for _ in {1..160}; do
    recovery_marker=$(find "$orphan_evidence/logs" -maxdepth 1 -type f \
      -name 'crash-recovery-*.json' -print | sort | tail -n 1)
    if [[ -f "$orphan_evidence/state.json" ]] &&
      jq -e '.attempt == 2 and
        (.status == "running" or .status == "starting")' \
        "$orphan_evidence/state.json" >/dev/null 2>&1 &&
      [[ -n "$recovery_marker" ]] &&
      jq -e '.status == "completed" and
        .authorization_value_persisted == false and
        .log_stream_contiguous == false' \
        "$recovery_marker" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$orphan_resume_runner" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  [[ "$ready" == true ]] || {
    wait "$orphan_resume_runner" || true
    die "self-test did not recover the abrupt-loss partial log"
  }
  "$SCRIPT_PATH" stop --evidence-dir "$orphan_evidence" >/dev/null
  set +e
  wait "$orphan_resume_runner"
  rc=$?
  set -e
  [[ "$rc" == 10 ]] ||
    die "self-test recovered-partial attempt returned $rc; expected 10"

  recovered_segment=$(find "$orphan_evidence/logs" -maxdepth 1 -type f \
    -name 'hsrd-segment-*.log' -print | sort | head -n 1)
  [[ -n "$recovered_segment" ]] ||
    die "self-test recovered partial did not become a monotonic segment"
  recovered_sha=$(sha256sum -- "$recovered_segment" | awk '{print $1}')
  stale_counter=$(basename -- "$recovered_segment")
  stale_counter=${stale_counter#hsrd-segment-}
  stale_counter=${stale_counter%.log}
  stale_counter=$((10#$stale_counter))
  atomic_write_text "$orphan_evidence/logs/log-segment-counter" "$stale_counter"

  "$SCRIPT_PATH" resume \
    --evidence-dir "$orphan_evidence" >"$orphan_resume_output" 2>&1 &
  orphan_resume_runner=$!
  ready=false
  for _ in {1..160}; do
    reconciliation_marker=$(find "$orphan_evidence/logs" -maxdepth 1 -type f \
      -name 'log-counter-reconciliation-*.json' -print | sort | tail -n 1)
    if [[ -f "$orphan_evidence/state.json" &&
      -n "$reconciliation_marker" ]] &&
      jq -e '.attempt == 3 and
        (.status == "running" or .status == "starting")' \
        "$orphan_evidence/state.json" >/dev/null 2>&1 &&
      jq -e '.monotonic_segment_overwrite_prevented == true and
        .recorded_next_segment < .inferred_next_segment and
        .reconciled_next_segment == .inferred_next_segment' \
        "$reconciliation_marker" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$orphan_resume_runner" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  [[ "$ready" == true ]] || {
    wait "$orphan_resume_runner" || true
    die "self-test did not reconcile the rename-before-counter crash window"
  }
  [[ "$(sha256sum -- "$recovered_segment" | awk '{print $1}')" == \
    "$recovered_sha" ]] ||
    die "self-test counter reconciliation overwrote an installed segment"
  "$SCRIPT_PATH" stop --evidence-dir "$orphan_evidence" >/dev/null
  set +e
  wait "$orphan_resume_runner"
  rc=$?
  set -e
  [[ "$rc" == 10 ]] ||
    die "self-test counter-reconciliation attempt returned $rc; expected 10"

  limit_data="$root/limit-data"
  limit_evidence="$root/limit-evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$limit_binary" \
    --data-root "$limit_data" \
    --evidence-dir "$limit_evidence" \
    --auth-file "$auth" \
    --limit-bytes 1000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19338 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 13 ]] ||
    die "self-test size-limit fixture returned $rc; expected 13: $output"
  [[ "$(jq -r '.classification' "$limit_evidence/final-summary.json")" == \
    sampled_storage_cutoff_exceeded ]] ||
    die "self-test size-limit classification is wrong"
  jq -e '
    .metrics.maximum_sampled_storage_bytes >
      .metrics.sampled_cutoff_bytes
  ' \
    "$limit_evidence/final-summary.json" >/dev/null ||
    die "self-test size-limit evidence did not retain the violating measurement"

  reserve_data="$root/reserve-data"
  reserve_evidence="$root/reserve-evidence"
  reserve_available=$(df -B1 --output=avail -- "$root" | awk 'NR == 2 {print $1}')
  reserve_bytes=$((reserve_available - 1000000 - 8388608))
  ((reserve_bytes > 0)) ||
    die "self-test filesystem is too small for reserve coverage"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$reserve_binary" \
    --data-root "$reserve_data" \
    --evidence-dir "$reserve_evidence" \
    --auth-file "$auth" \
    --limit-bytes 1000000 \
    --filesystem-reserve-bytes "$reserve_bytes" \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19340 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 16 ]] ||
    die "self-test combined size/reserve fixture returned $rc; expected 16: $output"
  jq -e '
    .classification ==
      "sampled_storage_cutoff_and_filesystem_reserve_breached" and
    .metrics.sampled_cutoff_respected == false and
    .metrics.sampled_filesystem_reserve_respected == false
  ' "$reserve_evidence/final-summary.json" >/dev/null ||
    die "self-test did not preserve combined size/reserve failure precedence"

  boundary_data="$root/boundary-data"
  boundary_evidence="$root/boundary-evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$boundary_binary" \
    --data-root "$boundary_data" \
    --evidence-dir "$boundary_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19342 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test boundary-redaction fixture returned $rc; expected 14: $output"
  jq -e '
    .classification == "authorization_value_emission_detected" and
    .authorization.value_emission_detected == true and
    .authorization.value_persisted_in_retained_logs == false
  ' "$boundary_evidence/final-summary.json" >/dev/null ||
    die "self-test boundary-spanning authorization emission was not fail-closed"
  jq -e '
    .artifact_type == "hsrd_log_authorization_redaction" and
    .authorization_value_persisted == false
  ' "$boundary_evidence/logs/auth-value-redacted" >/dev/null ||
    die "self-test authorization redaction marker is invalid"
  python3 - "$auth" "$boundary_evidence" <<'PY' ||
import sys
from pathlib import Path

secret = Path(sys.argv[1]).read_bytes().strip()
for path in Path(sys.argv[2]).rglob("*"):
    if path.is_file() and not path.is_symlink() and secret in path.read_bytes():
        raise SystemExit(1)
PY
    die "self-test persisted the boundary-spanning authorization value"
  while IFS= read -r -d '' output; do
    (($(stat -Lc '%s' -- "$output") <= LOG_CHUNK_BYTES)) ||
      die "self-test log rotation exceeded its fixed slot bound"
  done < <(find "$boundary_evidence/logs" -maxdepth 1 -type f \
    -name 'hsrd-segment-*.log' -print0)

  mutation_data="$root/mutation-data"
  mutation_evidence="$root/mutation-evidence"
  mutation_output="$root/mutation-output"
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$auth_change_binary" \
    --data-root "$mutation_data" \
    --evidence-dir "$mutation_evidence" \
    --auth-file "$mutation_auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 30 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19343 >"$mutation_output" 2>&1 &
  mutation_runner=$!
  ready=false
  for _ in {1..120}; do
    if [[ -f "$mutation_evidence/state.json" ]] &&
      jq -e '.status == "running" or .status == "starting"' \
        "$mutation_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$mutation_runner" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  [[ "$ready" == true ]] || {
    wait "$mutation_runner" || true
    die "self-test authorization-mutation fixture did not enter running state"
  }
  printf '%s\n' 'Bearer self-test-mutation-replacement' >"$mutation_auth"
  set +e
  wait "$mutation_runner"
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test authorization-mutation fixture returned $rc; expected 14"
  jq -e '
    .classification == "log_authorization_scanner_failed" and
    .process.log_authorization_scanner_exit_code != 0 and
    .authorization.retained_log_absence_guaranteed == true and
    .authorization.value_persisted_in_retained_logs == false
  ' "$mutation_evidence/final-summary.json" >/dev/null ||
    die "self-test authorization mutation was not fail-closed by the scanner"
  jq -e '
    .reason == "authorization_identity_or_content_changed" and
    .authorization_mutation_detected == true and
    .retained_runtime_log_slots_erased == true and
    .authorization_value_persisted == false
  ' "$mutation_evidence/logs/scanner-failure.json" >/dev/null ||
    die "self-test authorization mutation scanner marker is invalid"
  [[ ! -e "$mutation_evidence/logs/.hsrd-log-partial" &&
    -z "$(find "$mutation_evidence/logs" -maxdepth 1 -type f \
      -name 'hsrd-segment-*.log' -print -quit)" &&
    "$(<"$mutation_evidence/logs/log-segment-counter")" == 0 ]] ||
    die "self-test authorization mutation retained runtime log content"

  exec_change_data="$root/exec-change-data"
  exec_change_evidence="$root/exec-change-evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$exec_change_binary" \
    --data-root "$exec_change_data" \
    --evidence-dir "$exec_change_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19346 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test exec-image-change fixture returned $rc; expected 14: $output"
  jq -e '
    .classification == "child_process_image_changed" and
    .process.executable_image_binding.verification_count >= 2 and
    .process.executable_image_binding.self_test_interpreter_allowance == true
  ' "$exec_change_evidence/final-summary.json" >/dev/null ||
    die "self-test did not detect a post-launch executable-image change"
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$exec_change_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"non-resumable hard-stop classification"* ]] ||
    die "self-test allowed resume after a process-image violation"

  synced_data="$root/synced-nonzero-data"
  synced_evidence="$root/synced-nonzero-evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$synced_nonzero_binary" \
    --data-root "$synced_data" \
    --evidence-dir "$synced_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19344 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test synced-nonzero fixture returned $rc; expected 14: $output"
  jq -e '
    .classification == "sync_completed_child_nonzero" and
    .process.exit_code == 7 and
    .synchronized_tip.height == 1 and
    .synchronized_tip.hash ==
      "1111111111111111111111111111111111111111111111111111111111111111"
  ' "$synced_evidence/final-summary.json" >/dev/null ||
    die "self-test accepted a synchronized child that exited nonzero"
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$synced_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"non-resumable hard-stop classification"* ]] ||
    die "self-test allowed resume after a nonzero synchronized shutdown"

  sample_limit_data="$root/sample-limit-data"
  sample_limit_evidence="$root/sample-limit-evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$sample_limit_data" \
    --evidence-dir "$sample_limit_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --maximum-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19345 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test sample-limit fixture returned $rc; expected 14: $output"
  jq -e '
    .classification == "sample_limit_exceeded" and
    .samples.count == 1 and
    .runner_error == "sample_limit_exceeded"
  ' "$sample_limit_evidence/final-summary.json" >/dev/null ||
    die "self-test did not preserve sample-limit precedence through finalization"

  python3 - "$normal_evidence" <<'PY' ||
import json
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
for path in root.rglob("*"):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(1)
    if path.name.startswith("."):
        raise SystemExit(1)
    if stat.S_ISDIR(metadata.st_mode):
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise SystemExit(1)
    elif stat.S_ISREG(metadata.st_mode):
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SystemExit(1)
    else:
        raise SystemExit(1)
summary = json.loads((root / "final-summary.json").read_text(encoding="utf-8"))
if summary["evidence_scope"]["evidence_commit_semantics"] != (
    "fsync file, atomic replace, then fsync containing directory"
):
    raise SystemExit(1)
PY
    die "self-test durable evidence artifact audit failed"

  set +e
  output=$(bash -c '
"$1" run \
  --self-test-allow-interpreter-image \
  --binary "$2" \
  --data-root "$3" \
  --evidence-dir "$4" \
  --auth-file "$5" \
  --limit-bytes 500000000 \
  --filesystem-reserve-bytes 0
result=$?
:
exit "$result"
' _ "$SCRIPT_PATH" "$normal_binary" \
    "$root/operator-allowance-data" "$root/operator-allowance-evidence" \
    "$auth" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"requires the runner's self-test parent"* ]] ||
    die "self-test interpreter-image allowance was externally reachable"

  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$root/zero-completion-data" \
    --evidence-dir "$root/zero-completion-evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --completion-samples 0 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"between 1 and 60"* ]] ||
    die "self-test did not reject zero completion samples"
  [[ ! -e "$root/zero-completion-data" &&
    ! -e "$root/zero-completion-evidence" ]] ||
    die "self-test initialized a campaign after rejecting zero completion samples"

  refuse_data="$root/refuse-data"
  refuse_evidence="$root/refuse-evidence"
  mkdir -m 700 -- "$refuse_data"
  printf '%s\n' occupied >"$refuse_data/existing"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$refuse_data" \
    --evidence-dir "$refuse_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"data root must be empty"* ]] ||
    die "self-test did not refuse a nonempty data root"
  [[ ! -e "$refuse_evidence" ]] ||
    die "self-test initialized evidence after refusing nonempty data"

  mkdir -m 700 -- "$refuse_evidence"
  printf '%s\n' occupied >"$refuse_evidence/existing"
  find "$refuse_data" -mindepth 1 -maxdepth 1 -delete
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$refuse_data" \
    --evidence-dir "$refuse_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"evidence directory must be empty"* ]] ||
    die "self-test did not refuse a nonempty evidence directory"

  symlink_data="$root/symlink-data"
  symlink_evidence="$root/symlink-evidence"
  mkdir -m 700 -- "$root/real-data" "$root/real-evidence"
  ln -s -- "$root/real-data" "$symlink_data"
  set +e
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$symlink_data" \
    --evidence-dir "$root/symlink-data-evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 >/dev/null 2>&1
  rc=$?
  set -e
  [[ "$rc" == 2 ]] || die "self-test did not refuse a symlink data root"

  ln -s -- "$root/real-evidence" "$symlink_evidence"
  set +e
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$root/symlink-evidence-data" \
    --evidence-dir "$symlink_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 >/dev/null 2>&1
  rc=$?
  set -e
  [[ "$rc" == 2 ]] || die "self-test did not refuse a symlink evidence directory"

  chmod 644 -- "$auth"
  set +e
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$normal_binary" \
    --data-root "$root/public-auth-data" \
    --evidence-dir "$root/public-auth-evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 >/dev/null 2>&1
  rc=$?
  set -e
  [[ "$rc" == 2 ]] || die "self-test did not refuse a public authorization file"

  trap - EXIT
  self_test_cleanup "$root"
  printf '%s\n' \
    'full-sync runner self-test passed: lifecycle, canonical BlockHash normalization and malformed-hash rejection, sixteen forced clean-scanner-exit/child-exit race transitions, stale scanner-marker prelaunch rejection, live-orphan rejection, abrupt-loss partial recovery, monotonic counter reconciliation, terminal failure masking prevention, single operational sampled cutoff plus informational comparison schema, boundary-safe authorization redaction, durable mutation erasure, exact process-image and exec-change detection, isolated interpreter allowance, nonzero synced shutdown, sample-limit precedence, durable evidence, path safety, and private authorization'
}

case "$command_name" in
  run)
    parse_run_arguments "$@"
    require_commands
    preflight_new_campaign
    start_attempt
    ;;
  resume)
    parse_evidence_only_arguments "$@"
    require_commands
    resume_preflight
    start_attempt
    ;;
  status)
    parse_evidence_only_arguments "$@"
    require_commands
    status_command
    ;;
  stop)
    parse_evidence_only_arguments "$@"
    require_commands
    stop_command
    ;;
  self-test)
    (($# == 0)) || die "self-test accepts no arguments"
    require_commands
    self_test
    ;;
  --help|-h|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
