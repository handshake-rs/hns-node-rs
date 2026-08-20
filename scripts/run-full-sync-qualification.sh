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
readonly MAX_SAFE_SHELL_INTEGER=9000000000000000000
readonly MAX_SAFE_VM_HWM_KIB=8789062500000000
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
last_sample_sha256=
last_sample_decision="continue"
sample_journal_record_version=2
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
runner_lock_acquired=false
runtime_fifo=
runtime_fifo_anchor_fd=
rpc_response_tmp=
launch_nonce=
launch_pending_published=false
stop_request=
measurement_error=
forced_shutdown=false
authorization_value_emitted=false
authorization_retention_guaranteed=true
run_finalized=false
exit_trap_active=false
self_test_fault=${HSRD_FULL_SYNC_SELF_TEST_FAULT:-}
sample_commit_ambiguity_unresolved=false

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

is_bounded_unsigned_integer() {
  local value=$1
  local maximum=$2
  local LC_ALL=C

  is_unsigned_integer "$value" && is_unsigned_integer "$maximum" || return 1
  if ((${#value} < ${#maximum})); then
    return 0
  fi
  if ((${#value} > ${#maximum})); then
    return 1
  fi
  [[ "$value" == "$maximum" || "$value" < "$maximum" ]]
}

all_values_are_bounded_unsigned_integers() {
  local maximum=$1
  local value
  shift

  for value in "$@"; do
    is_bounded_unsigned_integer "$value" "$maximum" || return 1
  done
}

validate_numeric_options() {
  is_bounded_unsigned_integer "$limit_bytes" "$MAX_SAFE_SHELL_INTEGER" ||
    die "--limit-bytes must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$filesystem_reserve_bytes" \
    "$MAX_SAFE_SHELL_INTEGER" ||
    die "--filesystem-reserve-bytes must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$sample_seconds" 300 ||
    die "--sample-seconds must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$completion_samples" 60 ||
    die "--completion-samples must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$maximum_samples" "$DEFAULT_MAXIMUM_SAMPLES" ||
    die "--maximum-samples must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$shutdown_grace_seconds" 600 ||
    die "--shutdown-grace-seconds must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$rpc_port" 65535 ||
    die "--rpc-port must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$baseline_fs_used_bytes" \
    "$MAX_SAFE_SHELL_INTEGER" ||
    die "initial filesystem used bytes must be a bounded unsigned integer"
  is_bounded_unsigned_integer "$baseline_fs_available_bytes" \
    "$MAX_SAFE_SHELL_INTEGER" ||
    die "initial filesystem available bytes must be a bounded unsigned integer"

  ((limit_bytes > 0 && limit_bytes <= MAX_SAFE_SHELL_INTEGER)) ||
    die "--limit-bytes must be between 1 and $MAX_SAFE_SHELL_INTEGER"
  ((filesystem_reserve_bytes <= MAX_SAFE_SHELL_INTEGER - limit_bytes)) ||
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
  ((baseline_fs_used_bytes <= MAX_SAFE_SHELL_INTEGER)) ||
    die "initial filesystem used bytes exceed the supported integer range"
  ((baseline_fs_available_bytes <= MAX_SAFE_SHELL_INTEGER)) ||
    die "initial filesystem available bytes exceed the supported integer range"
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

validate_self_test_fault() {
  if [[ -z "$self_test_fault" ]]; then
    return 0
  fi
  [[ "$self_test_interpreter_image_allowance" == true ]] ||
    die "full-sync fault injection is restricted to the isolated self-test"
  case "$self_test_fault" in
    fail_sample_commit_before_install|fail_sample_commit_after_install|\
      fail_state_commit_before_install|fail_state_commit_after_install|\
      fail_final_state_before_install|fail_final_state_after_install|\
      fail_final_attempt_state_before_install|\
      fail_final_attempt_state_after_install|\
      fail_final_summary_before_install|fail_final_summary_after_install|\
      fail_attempt_summary_before_install|fail_attempt_summary_after_install|\
      fail_final_attempt_logs_manifest_before_install|\
      fail_final_attempt_logs_manifest_after_install|\
      fail_final_logs_manifest_before_install|\
      fail_final_logs_manifest_after_install|\
      fail_terminal_commit_before_install|fail_terminal_commit_after_install|\
      pause_after_launch_pending|pause_after_sample_commit|\
      pause_after_state_commit)
      ;;
    *)
      die "unknown isolated full-sync self-test fault: $self_test_fault"
      ;;
  esac
}

trigger_self_test_fault_once() {
  local expected=$1
  local marker
  [[ "$self_test_fault" == "$expected" ]] || return 1
  [[ "$self_test_interpreter_image_allowance" == true ]] ||
    die "full-sync fault injection escaped the isolated self-test"
  marker="$evidence_dir/attempts/.self-test-fault-$expected"
  if [[ -e "$marker" || -L "$marker" ]]; then
    return 1
  fi
  atomic_write_text "$marker" "$expected" ||
    die "could not durably record isolated self-test fault"
}

pause_for_self_test_fault() {
  local expected=$1
  if trigger_self_test_fault_once "$expected"; then
    kill -STOP "$runner_pid"
    measurement_error="self_test_fault_resumed_unexpectedly:$expected"
    return 1
  fi
  return 0
}

validate_binary() {
  local owner_mode

  binary=$(normalize_absolute_path "$binary" "binary path")
  [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] ||
    die "binary must be an executable nonsymlink regular file"
  owner_mode=$(stat -Lc '%A' -- "$binary")
  [[ "$owner_mode" == -* ]] || die "binary is not a regular file"
  python3 - "$binary" <<'PY' ||
import errno
import os
import stat
import sys

path = sys.argv[1]
metadata = os.stat(path, follow_symlinks=False)
if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
    raise SystemExit(1)
try:
    capability = os.getxattr(path, "security.capability", follow_symlinks=False)
except OSError as error:
    if error.errno not in (
        errno.ENODATA,
        getattr(errno, "ENOATTR", errno.ENODATA),
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
    ):
        raise
else:
    if capability:
        raise SystemExit(1)
PY
    die "binary must not use set-ID bits or file capabilities"
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

stable_private_runtime_state_snapshot() {
  local path=$1
  python3 - "$path" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])

def identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_nlink,
    )

descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
    ):
        raise SystemExit("JSON snapshot source is not a private regular file")
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    after = os.fstat(descriptor)
    current = path.lstat()
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise SystemExit("JSON snapshot source changed while read")
finally:
    os.close(descriptor)

raw = b"".join(chunks)
try:
    value = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid JSON snapshot: {error}") from error
if not isinstance(value, dict):
    raise SystemExit("JSON snapshot is not an object")
attempt = value.get("attempt")
status = value.get("status")
if (
    value.get("artifact_type") != "hsrd_full_sync_runtime_state"
    or type(attempt) is not int
    or not (1 <= attempt <= 32)
    or not isinstance(status, str)
    or not status
):
    raise SystemExit("runtime state snapshot identity is invalid")
print(json.dumps({
    "attempt": attempt,
    "sha256": hashlib.sha256(raw).hexdigest(),
    "status": status,
    "value": value,
}, sort_keys=True, separators=(",", ":")))
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
  local output filesystem_size filesystem_used filesystem_available
  output=$(df -B1 --output=size,used,avail -- "$path" | awk 'NR == 2 {print $1, $2, $3}')
  [[ "$output" =~ ^[0-9]+\ [0-9]+\ [0-9]+$ ]] ||
    return 1
  read -r filesystem_size filesystem_used filesystem_available <<<"$output"
  all_values_are_bounded_unsigned_integers "$MAX_SAFE_SHELL_INTEGER" \
    "$filesystem_size" "$filesystem_used" "$filesystem_available" || return 1
  printf '%s %s %s\n' \
    "$filesystem_size" "$filesystem_used" "$filesystem_available"
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

process_holds_open_path() {
  local pid=$1
  local path=$2

  python3 - "$pid" "$path" <<'PY'
import os
from pathlib import Path
import sys

pid = int(sys.argv[1])
target = Path(sys.argv[2]).stat()
for descriptor in Path(f"/proc/{pid}/fd").iterdir():
    try:
        observed = descriptor.stat()
    except (FileNotFoundError, PermissionError):
        continue
    if (observed.st_dev, observed.st_ino) == (target.st_dev, target.st_ino):
        raise SystemExit(0)
raise SystemExit(1)
PY
}

start_runner_lock() {
  local lock_file=$1
  local lock_input_fd lock_output_fd lock_pid lock_status=

  coproc HSRD_RUNNER_LOCK {
    exec python3 -c '
import ctypes
import fcntl
import os
import signal
import stat
import sys

lock_path = sys.argv[1]
expected_parent = int(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
    print("error", flush=True)
    raise SystemExit(74)
if os.getppid() != expected_parent:
    print("error", flush=True)
    raise SystemExit(74)
flags = (
    os.O_RDWR
    | os.O_CREAT
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
try:
    descriptor = os.open(lock_path, flags, 0o600)
    metadata = os.fstat(descriptor)
    current = os.lstat(lock_path)
except OSError:
    print("error", flush=True)
    raise SystemExit(74)

def safe_lock_file(opened, path_metadata):
    return (
        stat.S_ISREG(opened.st_mode)
        and opened.st_uid == os.getuid()
        and stat.S_IMODE(opened.st_mode) == 0o600
        and opened.st_nlink == 1
        and opened.st_dev == path_metadata.st_dev
        and opened.st_ino == path_metadata.st_ino
        and stat.S_ISREG(path_metadata.st_mode)
    )

if not safe_lock_file(metadata, current):
    print("error", flush=True)
    raise SystemExit(74)
try:
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("busy", flush=True)
    raise SystemExit(73)
try:
    after = os.fstat(descriptor)
    current = os.lstat(lock_path)
except OSError:
    print("error", flush=True)
    raise SystemExit(74)
if not safe_lock_file(after, current):
    print("error", flush=True)
    raise SystemExit(74)
print("locked", flush=True)
while True:
    signal.pause()
' "$lock_file" "$runner_pid"
  }
  lock_pid=$HSRD_RUNNER_LOCK_PID
  lock_output_fd=${HSRD_RUNNER_LOCK[0]}
  lock_input_fd=${HSRD_RUNNER_LOCK[1]}
  IFS= read -r lock_status <&"$lock_output_fd" || true
  exec {lock_output_fd}<&-
  exec {lock_input_fd}>&-
  case "$lock_status" in
    locked)
      ;;
    busy)
      wait "$lock_pid" 2>/dev/null || true
      die "campaign runner is already active"
      ;;
    *)
      wait "$lock_pid" 2>/dev/null || true
      die "could not establish the campaign runner lock"
      ;;
  esac
}

acquire_campaign_runner_lock() {
  [[ "$runner_lock_acquired" == false ]] || return 0
  start_runner_lock "$evidence_dir/runner.lock"
  runner_start_ticks=$(process_start_ticks "$runner_pid") ||
    die "could not capture runner process identity"
  runner_lock_acquired=true
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

durably_adopt_exact_file() {
  local target=$1
  local expected_sha256=$2

  python3 - "$target" "$expected_sha256" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import sys

target = Path(sys.argv[1])
expected_sha256 = sys.argv[2]
metadata = target.lstat()
if (
    target.is_symlink()
    or not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != os.getuid()
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_nlink != 1
):
    raise SystemExit("installed terminal artifact is not a private regular file")
descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
directory_descriptor = os.open(
    target.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise SystemExit("installed terminal artifact differs from intended content")
    os.fsync(descriptor)
    os.fsync(directory_descriptor)
finally:
    os.close(descriptor)
    os.close(directory_descriptor)
PY
}

atomic_install_or_adopt_exact() {
  local source=$1
  local target=$2
  local fault_phase=$3
  local expected_sha256 install_result=0

  expected_sha256=$(sha256sum -- "$source" | awk '{print $1}') || return 1
  if trigger_self_test_fault_once "fail_${fault_phase}_before_install"; then
    install_result=1
  elif atomic_install "$source" "$target"; then
    install_result=0
  else
    install_result=$?
  fi
  if ((install_result == 0)) &&
    trigger_self_test_fault_once "fail_${fault_phase}_after_install"; then
    install_result=1
  fi
  if ((install_result != 0)); then
    durably_adopt_exact_file "$target" "$expected_sha256" || return 1
  fi
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

verified_exec_python_source() {
  cat <<'PY'
import ctypes
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys

requested_parent = int(sys.argv[1])
expected_ancestor = int(sys.argv[2])
binary = sys.argv[3]
expected_identity = sys.argv[4]
expected_sha256 = sys.argv[5]
interpreter_allowance = sys.argv[6] == "true"
arguments = [binary, *sys.argv[7:]]

def process_parent(pid):
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    suffix = raw[raw.rfind(") ") + 2:].split()
    return int(suffix[1])

expected_parent = os.getppid() if requested_parent == 0 else requested_parent
if expected_ancestor and process_parent(expected_parent) != expected_ancestor:
    raise SystemExit(74)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    raise SystemExit(74)
if os.getppid() != expected_parent:
    raise SystemExit(74)
if expected_ancestor and process_parent(expected_parent) != expected_ancestor:
    raise SystemExit(74)
descriptor = os.open(
    binary,
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
)
metadata = os.fstat(descriptor)
identity = (
    f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_size}:"
    f"{metadata.st_mtime_ns}:{metadata.st_ctime_ns}:"
    f"{stat.S_IMODE(metadata.st_mode):o}:{metadata.st_uid}:{metadata.st_nlink}"
)
digest = hashlib.sha256()
while True:
    chunk = os.read(descriptor, 1024 * 1024)
    if not chunk:
        break
    digest.update(chunk)
if (
    not stat.S_ISREG(metadata.st_mode)
    or identity != expected_identity
    or digest.hexdigest() != expected_sha256
    or os.execve not in os.supports_fd
):
    raise SystemExit(75)
os.lseek(descriptor, 0, os.SEEK_SET)
if interpreter_allowance:
    os.set_inheritable(descriptor, True)
if os.getppid() != expected_parent:
    raise SystemExit(74)
if expected_ancestor and process_parent(expected_parent) != expected_ancestor:
    raise SystemExit(74)
environment = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "HSRD_LOG": "info",
    "RUST_BACKTRACE": "1",
}
os.execve(descriptor, arguments, environment)
PY
}

start_parent_bound_verified_binary() {
  local expected_parent=$1
  local expected_ancestor=$2
  local launcher_source
  shift 2
  launcher_source=$(verified_exec_python_source) || return 74
  exec env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    python3 -c "$launcher_source" \
    "$expected_parent" "$expected_ancestor" "$binary" \
    "$binary_file_identity" "$binary_sha256" \
    "$self_test_interpreter_image_allowance" "$@"
}

start_parent_bound_check_config() {
  local launcher_source
  launcher_source=$(verified_exec_python_source) || return 74
  exec env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    python3 -c '
import ctypes
import os
import signal
import sys

expected_parent = int(sys.argv[1])
launcher_source = sys.argv[2]
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    raise SystemExit(74)
if os.getppid() != expected_parent:
    raise SystemExit(74)
environment = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}
arguments = [
    "/usr/bin/timeout",
    "--signal=TERM",
    "--kill-after=5s",
    "30s",
    sys.executable,
    "-c",
    launcher_source,
    "0",
    str(expected_parent),
    *sys.argv[3:],
]
if os.getppid() != expected_parent:
    raise SystemExit(74)
os.execve("/usr/bin/timeout", arguments, environment)
' "$runner_pid" "$launcher_source" "$binary" "$binary_file_identity" \
    "$binary_sha256" "$self_test_interpreter_image_allowance" \
    "${NODE_ARGS[@]}" --check-config
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
    start_parent_bound_check_config
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
  validate_self_test_fault
  validate_new_directory_target "$data_root" "data root"
  validate_new_directory_target "$evidence_dir" "evidence directory"

  data_probe=$(nearest_existing_ancestor "$data_root")
  read -r fs_size baseline_fs_used_bytes baseline_fs_available_bytes \
    <<<"$(filesystem_numbers "$data_probe")" ||
    die "could not read filesystem capacity"
  validate_numeric_options
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
  rustc_version=$(rustc +1.97.1 -Vv 2>&1 || rustc -Vv 2>&1)
  cargo_version=$(cargo +1.97.1 -V 2>&1 || cargo -V 2>&1)
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
          "cargo +1.97.1 build --locked --release -p hns-node --bin hsrd",
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
    --argjson journal_record_version "$sample_journal_record_version" \
    --argjson self_test_interpreter_image_allowance \
      "$self_test_interpreter_image_allowance" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      journal_record_version: $journal_record_version,
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

read_required_json_boolean() {
  local key_path=$1
  local input=$2

  jq -er --arg key_path "$key_path" '
    getpath($key_path | split(".")) as $value |
    if ($value | type) == "boolean" then
      $value | tostring
    else
      error($key_path + " must be a boolean")
    end
  ' "$input"
}

read_required_nonempty_json_string() {
  local key_path=$1
  local input=$2

  jq -er --arg key_path "$key_path" '
    getpath($key_path | split(".")) as $value |
    if ($value | type) == "string" and ($value | length) > 0 then
      $value
    else
      error($key_path + " must be a nonempty string")
    end
  ' "$input"
}

read_required_bounded_json_unsigned_integer() {
  local key_path=$1
  local input=$2
  local maximum=$3

  is_unsigned_integer "$maximum" || return 1
  python3 - "$input" "$key_path" "$maximum" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
key_path = sys.argv[2]
maximum = int(sys.argv[3])
try:
    value = json.loads(path.read_bytes())
except (OSError, UnicodeDecodeError, ValueError):
    raise SystemExit(1)
for component in key_path.split("."):
    if not isinstance(value, dict) or component not in value:
        raise SystemExit(1)
    value = value[component]
if type(value) is not int or not (0 <= value <= maximum):
    raise SystemExit(1)
print(value)
PY
}

read_required_rpc_bind_port() {
  local input=$1
  local bind port

  bind=$(read_required_nonempty_json_string rpc.bind "$input") || return 1
  [[ "$bind" =~ ^127\.0\.0\.1:(0|[1-9][0-9]*)$ ]] || return 1
  port=${BASH_REMATCH[1]}
  is_bounded_unsigned_integer "$port" 65535 || return 1
  ((port >= 1024)) || return 1
  printf '%s\n' "$port"
}

resume_classification_is_allowed() {
  case "$1" in
    operator_stop|operator_interrupt|node_exit_zero_before_sync|node_exit_nonzero)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

enforce_terminal_commit_for_resume() {
  local state_status=$1
  local current_attempt=$2
  local summary_path="$evidence_dir/final-summary.json"
  local summary_attempt prior_classification marker_path commit_snapshot
  local attempt_state attempt_summary attempt_logs_manifest

  printf -v marker_path '%s/attempts/%06d-terminal-commit.json' \
    "$evidence_dir" "$current_attempt"
  printf -v attempt_state '%s/attempts/%06d-state.json' \
    "$evidence_dir" "$current_attempt"
  printf -v attempt_summary '%s/attempts/%06d-summary.json' \
    "$evidence_dir" "$current_attempt"
  printf -v attempt_logs_manifest '%s/attempts/%06d-logs-manifest.json' \
    "$evidence_dir" "$current_attempt"

  if [[ -f "$summary_path" && ! -L "$summary_path" ]]; then
    summary_attempt=$(read_required_bounded_json_unsigned_integer final_attempt \
      "$summary_path" 32) ||
      die "campaign final-summary attempt is missing or invalid"
    ((summary_attempt <= current_attempt)) ||
      die "final summary is ahead of the runtime state"
    if ((summary_attempt == current_attempt)); then
      [[ -f "$marker_path" && ! -L "$marker_path" ]] ||
        die "terminal verdict is uncommitted; commit manifest is missing"
      commit_snapshot=$(validated_terminal_commit "$current_attempt") ||
        die "terminal commit manifest or one of its bound artifacts is invalid"
      prior_classification=$(jq -er '
        .classification as $classification |
        if ($classification | type) == "string" and
          ($classification | length) > 0
        then $classification
        else error("classification must be a nonempty string")
        end
      ' <<<"$commit_snapshot") ||
        die "terminal commit classification is missing or invalid"
      [[ "$state_status" == "$prior_classification" ]] ||
        die "terminal commit classification differs from runtime state"
      [[ "$prior_classification" != sync_completed ]] ||
        die "campaign is already complete"
      resume_classification_is_allowed "$prior_classification" ||
        die "campaign has a non-resumable hard-stop classification"
      return 0
    fi
  elif [[ -e "$summary_path" || -L "$summary_path" ]]; then
    die "final summary is not a safe regular file"
  fi

  case "$state_status" in
    launch_pending|starting|running|interrupted_sample_reconciled)
      ;;
    *)
      die "runtime state contains an uncommitted terminal verdict"
      ;;
  esac
  if [[ -e "$marker_path" || -L "$marker_path" ||
    -e "$attempt_state" || -L "$attempt_state" ||
    -e "$attempt_summary" || -L "$attempt_summary" ||
    -e "$attempt_logs_manifest" || -L "$attempt_logs_manifest" ]]; then
    die "campaign contains an incomplete terminal artifact bundle"
  fi
}

state_sample_checkpoint_is_consistent() {
  local snapshot=$1
  local state_path=$2
  local count last_sha last_decision last_attempt
  local maximum_vm maximum_apparent maximum_allocated maximum_delta maximum_storage
  local minimum_available

  count=$(jq -er '.count' <<<"$snapshot")
  maximum_vm=$(jq -er '.observed_maxima.kernel_process_vm_hwm_bytes' <<<"$snapshot")
  maximum_apparent=$(jq -er '.observed_maxima.sampled_data_root_apparent_bytes' <<<"$snapshot")
  maximum_allocated=$(jq -er '.observed_maxima.sampled_data_root_allocated_bytes' <<<"$snapshot")
  maximum_delta=$(jq -er '.observed_maxima.sampled_filesystem_used_delta_bytes' <<<"$snapshot")
  maximum_storage=$(jq -er '.observed_maxima.sampled_storage_maximum_bytes' <<<"$snapshot")
  if ((count == 0)); then
    last_sha=
    last_decision="continue"
    last_attempt=0
    minimum_available=$baseline_fs_available_bytes
  else
    last_sha=$(jq -er '.last.sha256' <<<"$snapshot")
    last_decision=$(jq -er '.last.decision' <<<"$snapshot")
    last_attempt=$(jq -er '.last.attempt' <<<"$snapshot")
    minimum_available=$(jq -er \
      '.minimum_sampled_filesystem_available_bytes' <<<"$snapshot")
  fi

  python3 - \
    "$state_path" "$campaign_id" "$sample_journal_record_version" \
    "$count" "$last_sha" "$last_decision" "$last_attempt" \
    "$maximum_vm" "$maximum_apparent" "$maximum_allocated" \
    "$maximum_delta" "$maximum_storage" "$minimum_available" \
    "$MAX_SAFE_SHELL_INTEGER" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
campaign_id = sys.argv[2]
journal_record_version = int(sys.argv[3])
count = int(sys.argv[4])
last_sha = sys.argv[5]
last_decision = sys.argv[6]
last_attempt = int(sys.argv[7])
expected_maxima = tuple(int(value) for value in sys.argv[8:13])
minimum_available = int(sys.argv[13])
maximum_integer = int(sys.argv[14])
try:
    state = json.loads(path.read_bytes())
except (OSError, UnicodeDecodeError, ValueError):
    raise SystemExit(1)

def bounded(value):
    return type(value) is int and 0 <= value <= maximum_integer

maxima = state.get("observed_maxima")
if not isinstance(state, dict) or not isinstance(maxima, dict):
    raise SystemExit(1)
observed_maxima = (
    maxima.get("kernel_process_vm_hwm_bytes"),
    maxima.get("sampled_data_root_apparent_bytes"),
    maxima.get("sampled_data_root_allocated_bytes"),
    maxima.get("sampled_filesystem_used_delta_bytes"),
    maxima.get("sampled_storage_maximum_bytes"),
)
minimum = state.get("minimum_sampled_filesystem_available_bytes")
if (
    type(state.get("schema_version")) is not int
    or state.get("schema_version") != 1
    or state.get("artifact_type") != "hsrd_full_sync_runtime_state"
    or state.get("campaign_id") != campaign_id
    or not bounded(state.get("sample_sequence"))
    or state.get("sample_sequence") != count
    or not bounded(state.get("attempt"))
    or state.get("attempt") < last_attempt
    or not all(bounded(value) for value in observed_maxima)
    or any(observed < expected for observed, expected in zip(observed_maxima, expected_maxima))
    or not bounded(minimum)
    or minimum > minimum_available
):
    raise SystemExit(1)

if "sample_commit" not in state:
    if journal_record_version != 1:
        raise SystemExit(1)
elif count == 0:
    if state["sample_commit"] is not None:
        raise SystemExit(1)
else:
    commit = state["sample_commit"]
    if (
        not isinstance(commit, dict)
        or not bounded(commit.get("sequence"))
        or commit.get("sequence") != count
        or commit.get("sha256") != last_sha
        or commit.get("decision") != last_decision
        or commit.get("decision_durable_in_sample") is not True
    ):
        raise SystemExit(1)
PY
}

write_sample_recovery_marker() {
  local snapshot=$1
  local prior_sequence=$2
  local marker temp sample_sha decision
  sample_sha=$(jq -er '.last.sha256' <<<"$snapshot")
  decision=$(jq -er '.last.decision' <<<"$snapshot")
  printf -v marker '%s/attempts/%06d-sample-recovery-%09d.json' \
    "$evidence_dir" "$attempt" "$sample_sequence"

  if [[ -e "$marker" || -L "$marker" ]]; then
    [[ -f "$marker" && ! -L "$marker" ]] ||
      die "sample recovery marker is unsafe"
    jq -e \
      --arg campaign_id "$campaign_id" \
      --argjson attempt "$attempt" \
      --argjson prior_sequence "$prior_sequence" \
      --argjson recovered_sequence "$sample_sequence" \
      --arg sample_sha "$sample_sha" \
      --arg decision "$decision" '
        .schema_version == 1 and
        .artifact_type == "hsrd_sample_checkpoint_recovery" and
        .campaign_id == $campaign_id and
        .attempt == $attempt and
        .prior_state_sequence == $prior_sequence and
        .recovered_sample_sequence == $recovered_sequence and
        .recovered_sample_sha256 == $sample_sha and
        .post_sample_decision == $decision and
        .sample_was_deleted == false and
        .recovery_was_fail_closed == true
      ' "$marker" >/dev/null ||
      die "sample recovery marker does not match the durable trailing sample"
    return 0
  fi

  temp=$(mktemp "$evidence_dir/attempts/.sample-recovery.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_sample_checkpoint_recovery \
    --arg campaign_id "$campaign_id" \
    --argjson attempt "$attempt" \
    --argjson prior_sequence "$prior_sequence" \
    --argjson recovered_sequence "$sample_sequence" \
    --arg sample_sha "$sample_sha" \
    --arg decision "$decision" '
      {
        schema_version: $schema_version,
        artifact_type: $artifact_type,
        campaign_id: $campaign_id,
        attempt: $attempt,
        prior_state_sequence: $prior_sequence,
        recovered_sample_sequence: $recovered_sequence,
        recovered_sample_sha256: $sample_sha,
        post_sample_decision: $decision,
        sample_was_deleted: false,
        recovery_was_fail_closed: true
      }
    ' >"$temp"
  atomic_install "$temp" "$marker" ||
    die "could not durably record trailing-sample recovery"
}

persist_reconciled_runtime_state() {
  local snapshot=$1
  local state_path="$evidence_dir/state.json"
  local temp vm_hwm apparent allocated delta maximum available sync_json

  vm_hwm=$(jq -er '.last.vm_hwm' <<<"$snapshot")
  apparent=$(jq -er '.last.apparent' <<<"$snapshot")
  allocated=$(jq -er '.last.allocated' <<<"$snapshot")
  delta=$(jq -er '.last.delta' <<<"$snapshot")
  maximum=$(jq -er '.last.maximum' <<<"$snapshot")
  available=$(jq -er '.last.available' <<<"$snapshot")
  sync_json=$(jq -c '.last.sync' <<<"$snapshot")
  temp=$(mktemp "$evidence_dir/.state-recovery.XXXXXX")
  jq \
    --arg status interrupted_sample_reconciled \
    --arg updated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson sample_sequence "$sample_sequence" \
    --arg sample_sha "$last_sample_sha256" \
    --arg decision "$last_sample_decision" \
    --argjson current_vm_hwm "$vm_hwm" \
    --argjson current_apparent "$apparent" \
    --argjson current_allocated "$allocated" \
    --argjson current_delta "$delta" \
    --argjson current_maximum "$maximum" \
    --argjson current_available "$available" \
    --argjson maximum_vm_hwm "$maximum_observed_vm_hwm_bytes" \
    --argjson maximum_apparent "$maximum_sampled_apparent_bytes" \
    --argjson maximum_allocated "$maximum_sampled_allocated_bytes" \
    --argjson maximum_delta "$maximum_sampled_filesystem_used_delta_bytes" \
    --argjson maximum_storage "$maximum_sampled_storage_bytes" \
    --argjson minimum_available "$minimum_sampled_filesystem_available_bytes" \
    --argjson sync "$sync_json" '
      .status = $status |
      .updated_at = $updated_at |
      .sample_sequence = $sample_sequence |
      .sample_commit = {
        sequence: $sample_sequence,
        sha256: $sample_sha,
        decision: $decision,
        decision_durable_in_sample: true
      } |
      .current.observed_kernel_vm_hwm_bytes = $current_vm_hwm |
      .current.sampled_data_root_apparent_bytes = $current_apparent |
      .current.sampled_data_root_allocated_bytes = $current_allocated |
      .current.sampled_filesystem_used_delta_bytes = $current_delta |
      .current.sampled_storage_maximum_bytes = $current_maximum |
      .current.sampled_filesystem_available_bytes = $current_available |
      .current.filesystem_reserve_respected =
        ($current_available >= .filesystem_reserve_bytes) |
      .observed_maxima.kernel_process_vm_hwm_bytes = $maximum_vm_hwm |
      .observed_maxima.sampled_data_root_apparent_bytes = $maximum_apparent |
      .observed_maxima.sampled_data_root_allocated_bytes = $maximum_allocated |
      .observed_maxima.sampled_filesystem_used_delta_bytes = $maximum_delta |
      .observed_maxima.sampled_storage_maximum_bytes = $maximum_storage |
      .minimum_sampled_filesystem_available_bytes = $minimum_available |
      .filesystem_reserve_currently_respected =
        ($current_available >= .filesystem_reserve_bytes) |
      .sampled_informational_comparison_currently_at_or_below =
        ($maximum_storage <= .sampled_informational_comparison_bytes) |
      .consecutive_synced_samples = 0 |
      .sync = $sync
    ' "$state_path" >"$temp" ||
    die "could not construct a reconciled runtime state"
  atomic_install "$temp" "$state_path" ||
    die "could not durably reconcile runtime state with the trailing sample"
}

enforce_resume_terminal_sample_outcomes() {
  ((maximum_sampled_storage_bytes <= limit_bytes)) ||
    die "campaign contains a non-resumable sampled storage cutoff breach"
  ((minimum_sampled_filesystem_available_bytes >= filesystem_reserve_bytes)) ||
    die "campaign contains a non-resumable sampled filesystem reserve breach"
  ((sample_sequence < maximum_samples)) ||
    die "campaign has reached its non-resumable maximum sample count"
}

load_config_for_resume() {
  local config_path expected_digest actual_digest stored_evidence source_repo
  local stored_dirty expected_binary_sha256 expected_binary_identity
  local expected_auth_identity
  local recorded_sample_count recorded_sample_digest sample_snapshot state_status=missing
  local last_sample_attempt snapshot_maximum_vm snapshot_maximum_apparent
  local snapshot_maximum_allocated snapshot_maximum_delta snapshot_maximum_storage
  local snapshot_minimum_available
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
  if jq -e 'has("journal_record_version")' "$config_path" >/dev/null; then
    sample_journal_record_version=$(read_required_bounded_json_unsigned_integer \
      journal_record_version "$config_path" 2) ||
      die "campaign sample journal record version is missing or invalid"
    ((sample_journal_record_version >= 1)) ||
      die "campaign sample journal record version is unsupported"
  else
    sample_journal_record_version=1
  fi
  campaign_started_at=$(jq -er '.created_at' "$config_path")
  campaign_started_epoch=$(date -u -d "$campaign_started_at" +%s)
  binary=$(jq -er '.binary.path' "$config_path")
  expected_binary_sha256=$(jq -er '.binary.sha256' "$config_path")
  expected_binary_identity=$(jq -er '.binary.file_identity' "$config_path")
  data_root=$(jq -er '.data_root' "$config_path")
  stored_evidence=$(jq -er '.evidence_dir' "$config_path")
  auth_file=$(jq -er '.rpc.authorization_file' "$config_path")
  expected_auth_identity=$(jq -er '.rpc.authorization_file_identity' "$config_path")
  rpc_port=$(read_required_rpc_bind_port "$config_path") ||
    die "campaign RPC bind port is missing or invalid"
  limit_bytes=$(read_required_bounded_json_unsigned_integer \
    measurement.sampled_cutoff_bytes "$config_path" \
    "$MAX_SAFE_SHELL_INTEGER") ||
    die "campaign sampled cutoff is missing or invalid"
  filesystem_reserve_bytes=$(read_required_bounded_json_unsigned_integer \
    measurement.filesystem_reserve_bytes "$config_path" \
    "$MAX_SAFE_SHELL_INTEGER") ||
    die "campaign filesystem reserve is missing or invalid"
  sample_seconds=$(read_required_bounded_json_unsigned_integer \
    measurement.sample_seconds "$config_path" 300) ||
    die "campaign sample interval is missing or invalid"
  completion_samples=$(read_required_bounded_json_unsigned_integer \
    measurement.consecutive_synced_samples_required "$config_path" 60) ||
    die "campaign completion sample count is missing or invalid"
  maximum_samples=$(read_required_bounded_json_unsigned_integer \
    measurement.maximum_samples "$config_path" "$DEFAULT_MAXIMUM_SAMPLES") ||
    die "campaign maximum sample count is missing or invalid"
  shutdown_grace_seconds=$(read_required_bounded_json_unsigned_integer \
    measurement.shutdown_grace_seconds "$config_path" 600) ||
    die "campaign shutdown grace is missing or invalid"
  baseline_fs_used_bytes=$(read_required_bounded_json_unsigned_integer \
    measurement.initial_filesystem_used_bytes "$config_path" \
    "$MAX_SAFE_SHELL_INTEGER") ||
    die "campaign initial filesystem used bytes are missing or invalid"
  baseline_fs_available_bytes=$(read_required_bounded_json_unsigned_integer \
    measurement.initial_filesystem_available_bytes "$config_path" \
    "$MAX_SAFE_SHELL_INTEGER") ||
    die "campaign initial filesystem available bytes are missing or invalid"
  data_filesystem_device=$(jq -er '.measurement.filesystem_device' "$config_path")
  data_filesystem_mount=$(jq -er '.measurement.filesystem_mount' "$config_path")
  source_revision=$(jq -er '.source.revision' "$config_path")
  source_tree=$(jq -er '.source.tree' "$config_path")
  source_worktree_sha256=$(jq -er '.source.worktree_sha256' "$config_path")
  stored_dirty=$(read_required_json_boolean source.dirty "$config_path") ||
    die "campaign source dirty flag is missing or invalid"
  source_dirty=$stored_dirty
  self_test_interpreter_image_allowance=$(read_required_json_boolean \
    self_test.interpreter_image_allowance "$config_path") ||
    die "campaign interpreter-image allowance is missing or invalid"

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
  validate_self_test_fault
  validate_existing_private_directory "$data_root" "data root"
  [[ -z "$(find "$data_root" -xdev -type l -print -quit)" ]] ||
    die "data root contains a symbolic link"
  validate_existing_private_directory "$evidence_dir/logs" "logs directory"
  validate_existing_private_directory "$evidence_dir/samples" "samples directory"
  validate_existing_private_directory "$evidence_dir/attempts" "attempts directory"
  [[ -z "$(find "$evidence_dir" -xdev -type l -print -quit)" ]] ||
    die "evidence directory contains a symbolic link"
  assert_no_authorization_scanner_hard_stop_markers

  source_repo=$(read_required_nonempty_json_string source.repository \
    "$evidence_dir/build-provenance.json") ||
    die "build provenance source repository is missing or invalid"
  [[ "$source_repo" == "$REPO_ROOT" ]] ||
    die "campaign was initialized from a different source repository"

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
    attempt=$(read_required_bounded_json_unsigned_integer attempt \
      "$evidence_dir/state.json" 32) ||
      die "runtime state attempt is missing or invalid"
    ((attempt >= 1)) || die "runtime state attempt is outside its supported range"
    sample_sequence=$(read_required_bounded_json_unsigned_integer sample_sequence \
      "$evidence_dir/state.json" "$maximum_samples") ||
      die "runtime state sample sequence is missing or invalid"
    state_status=$(read_required_nonempty_json_string status \
      "$evidence_dir/state.json") ||
      die "runtime state status is missing or invalid"
    maximum_observed_vm_hwm_bytes=$(read_required_bounded_json_unsigned_integer \
      observed_maxima.kernel_process_vm_hwm_bytes "$evidence_dir/state.json" \
      "$MAX_SAFE_SHELL_INTEGER") ||
      die "runtime state VmHWM maximum is missing or invalid"
    maximum_sampled_apparent_bytes=$(read_required_bounded_json_unsigned_integer \
      observed_maxima.sampled_data_root_apparent_bytes "$evidence_dir/state.json" \
      "$MAX_SAFE_SHELL_INTEGER") ||
      die "runtime state apparent-byte maximum is missing or invalid"
    maximum_sampled_allocated_bytes=$(read_required_bounded_json_unsigned_integer \
      observed_maxima.sampled_data_root_allocated_bytes "$evidence_dir/state.json" \
      "$MAX_SAFE_SHELL_INTEGER") ||
      die "runtime state allocated-byte maximum is missing or invalid"
    maximum_sampled_filesystem_used_delta_bytes=$(
      read_required_bounded_json_unsigned_integer \
        observed_maxima.sampled_filesystem_used_delta_bytes \
        "$evidence_dir/state.json" "$MAX_SAFE_SHELL_INTEGER"
    ) || die "runtime state filesystem-delta maximum is missing or invalid"
    maximum_sampled_storage_bytes=$(read_required_bounded_json_unsigned_integer \
      observed_maxima.sampled_storage_maximum_bytes "$evidence_dir/state.json" \
      "$MAX_SAFE_SHELL_INTEGER") ||
      die "runtime state storage maximum is missing or invalid"
    minimum_sampled_filesystem_available_bytes=$(
      read_required_bounded_json_unsigned_integer \
        minimum_sampled_filesystem_available_bytes \
        "$evidence_dir/state.json" "$MAX_SAFE_SHELL_INTEGER"
    ) || die "runtime state filesystem-available minimum is missing or invalid"
  fi
  if [[ ! -f "$evidence_dir/state.json" ]]; then
    minimum_sampled_filesystem_available_bytes=$baseline_fs_available_bytes
  fi
  if ! sample_snapshot=$(validated_sample_chain); then
    die "sample journal is invalid"
  fi
  recorded_sample_count=$(jq -er '.count' <<<"$sample_snapshot")
  recorded_sample_digest=$(jq -er '.content_chain_sha256' <<<"$sample_snapshot")
  : "$recorded_sample_digest"
  if ((recorded_sample_count == sample_sequence)); then
    if [[ -f "$evidence_dir/state.json" ]]; then
      state_sample_checkpoint_is_consistent \
        "$sample_snapshot" "$evidence_dir/state.json" ||
        die "runtime state sample checkpoint is inconsistent"
    elif ((recorded_sample_count != 0)); then
      die "runtime state is missing for the recorded sample journal"
    fi
    if ((recorded_sample_count == 0)); then
      last_sample_sha256=
      last_sample_decision="continue"
    else
      last_sample_sha256=$(jq -er '.last.sha256' <<<"$sample_snapshot")
      last_sample_decision=$(jq -er '.last.decision' <<<"$sample_snapshot")
    fi
  elif ((recorded_sample_count == sample_sequence + 1)); then
    [[ -f "$evidence_dir/state.json" &&
      ( "$state_status" == starting || "$state_status" == running ) ]] ||
      die "trailing sample cannot follow a terminal or missing runtime state"
    last_sample_attempt=$(jq -er '.last.attempt' <<<"$sample_snapshot")
    ((last_sample_attempt == attempt)) ||
      die "trailing sample belongs to a different campaign attempt"
    state_sample_checkpoint_is_consistent \
      "$(jq -c '.prefix_before_last' <<<"$sample_snapshot")" \
      "$evidence_dir/state.json" ||
      die "runtime state does not match the sample journal prefix"
    last_sample_sha256=$(jq -er '.last.sha256' <<<"$sample_snapshot")
    last_sample_decision=$(jq -er '.last.decision' <<<"$sample_snapshot")
    snapshot_maximum_vm=$(jq -er \
      '.observed_maxima.kernel_process_vm_hwm_bytes' <<<"$sample_snapshot")
    snapshot_maximum_apparent=$(jq -er \
      '.observed_maxima.sampled_data_root_apparent_bytes' <<<"$sample_snapshot")
    snapshot_maximum_allocated=$(jq -er \
      '.observed_maxima.sampled_data_root_allocated_bytes' <<<"$sample_snapshot")
    snapshot_maximum_delta=$(jq -er \
      '.observed_maxima.sampled_filesystem_used_delta_bytes' <<<"$sample_snapshot")
    snapshot_maximum_storage=$(jq -er \
      '.observed_maxima.sampled_storage_maximum_bytes' <<<"$sample_snapshot")
    snapshot_minimum_available=$(jq -er \
      '.minimum_sampled_filesystem_available_bytes' <<<"$sample_snapshot")
    ((snapshot_maximum_vm > maximum_observed_vm_hwm_bytes)) &&
      maximum_observed_vm_hwm_bytes=$snapshot_maximum_vm
    ((snapshot_maximum_apparent > maximum_sampled_apparent_bytes)) &&
      maximum_sampled_apparent_bytes=$snapshot_maximum_apparent
    ((snapshot_maximum_allocated > maximum_sampled_allocated_bytes)) &&
      maximum_sampled_allocated_bytes=$snapshot_maximum_allocated
    ((snapshot_maximum_delta > maximum_sampled_filesystem_used_delta_bytes)) &&
      maximum_sampled_filesystem_used_delta_bytes=$snapshot_maximum_delta
    ((snapshot_maximum_storage > maximum_sampled_storage_bytes)) &&
      maximum_sampled_storage_bytes=$snapshot_maximum_storage
    ((snapshot_minimum_available < minimum_sampled_filesystem_available_bytes)) &&
      minimum_sampled_filesystem_available_bytes=$snapshot_minimum_available
    recorded_sample_count=$((sample_sequence + 1))
    sample_sequence=$recorded_sample_count
    write_sample_recovery_marker "$sample_snapshot" "$((sample_sequence - 1))"
    persist_reconciled_runtime_state "$sample_snapshot"
  else
    die "recorded sample journal differs from runtime state by more than one trailing sample"
  fi
  enforce_terminal_commit_for_resume "$state_status" "$attempt"
  enforce_resume_terminal_sample_outcomes
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

publish_launch_pending() {
  [[ "$launch_pending_published" == false ]] || return 0
  [[ "$runner_lock_acquired" == true && -n "$runner_start_ticks" ]] ||
    die "runner lock and identity are required before launch intent"

  consecutive_synced_samples=0
  stop_request=
  measurement_error=
  forced_shutdown=false
  authorization_value_emitted=false
  authorization_retention_guaranteed=true
  child_pid=
  child_start_ticks=
  child_expected_image_path=
  child_expected_image_identity=
  child_expected_image_sha256=
  child_image_verification_count=0
  child_launch_image_fd_verified_at_finalization=false
  log_scanner_pid=
  log_scanner_start_ticks=
  log_scanner_exit=
  log_scanner_reaped=false
  log_scanner_failure_detail=
  log_scanner_clean_exit_child_transition=false
  launch_nonce=$(dd if=/dev/urandom bs=32 count=1 status=none |
    sha256sum | awk '{print $1}')
  [[ "$launch_nonce" =~ ^[0-9a-f]{64}$ ]] ||
    die "could not generate the attempt launch nonce"
  exit_trap_active=true
  trap handle_term TERM
  trap handle_int INT
  trap emergency_exit_cleanup EXIT

  write_runtime_state launch_pending 0 0 0 0 0 \
    "$baseline_fs_available_bytes" null \
    "$evidence_dir/state.json" launch_pending ||
    die "could not durably publish the new-attempt launch intent"
  launch_pending_published=true
  pause_for_self_test_fault pause_after_launch_pending ||
    die "isolated launch-pending fault resumed unexpectedly"
}

resume_preflight() {
  local fs_size current_used current_available resume_log
  local apparent allocated delta current_max remaining required check_tmp check_result

  evidence_dir=$(normalize_absolute_path "$evidence_dir" "evidence directory")
  validate_existing_private_directory "$evidence_dir" "evidence directory"
  acquire_campaign_runner_lock
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

  publish_launch_pending
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
      if all_values_are_bounded_unsigned_integers \
        "$MAX_SAFE_SHELL_INTEGER" "$apparent" "$allocated"; then
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
  is_bounded_unsigned_integer "$vm_hwm_kib" "$MAX_SAFE_VM_HWM_KIB" || return 1
  printf '%s\n' "$((vm_hwm_kib * 1024))"
}

normalize_sync_status_response() {
  local response=$1

  python3 - "$response" "$MAX_SAFE_SHELL_INTEGER" <<'PY'
import json
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
maximum = int(sys.argv[2])
try:
    value = json.loads(path.read_bytes())
except (OSError, UnicodeDecodeError, ValueError):
    raise SystemExit(1)
if not isinstance(value, dict):
    raise SystemExit("sync response is not an object")

def optional_integer(number, label):
    if number is None:
        return None
    if type(number) is not int or not (0 <= number <= maximum):
        raise SystemExit(f"{label} is not a canonical bounded unsigned integer")
    return number

def block_hash(raw, label):
    if raw is None:
        return None
    if isinstance(raw, str):
        if re.fullmatch(r"[0-9a-fA-F]{64}", raw) is None:
            raise SystemExit(f"{label} is not exactly 64 hexadecimal characters")
        return raw.lower()
    if isinstance(raw, list) and len(raw) == 32 and all(
        type(byte) is int and 0 <= byte <= 255 for byte in raw
    ):
        return bytes(raw).hex()
    raise SystemExit(f"{label} is not a canonical BlockHash")

def header(label):
    raw = value.get(label)
    if raw is None:
        return None, None
    if not isinstance(raw, dict):
        raise SystemExit(f"{label} is not an object or null")
    return (
        optional_integer(raw.get("height"), f"{label} height"),
        block_hash(raw.get("hash"), f"{label} hash"),
    )

stage = value.get("stage")
if not isinstance(stage, str) or not stage:
    raise SystemExit("sync stage is not a nonempty string")
best_height, best_hash = header("best_header")
active_height, active_hash = header("active_tip")
stored_height, stored_hash = header("stored_tip")
peers = value.get("peers")
if not isinstance(peers, list):
    raise SystemExit("sync peers is not an array")
ready_peer_count = 0
for peer in peers:
    if not isinstance(peer, dict):
        raise SystemExit("sync peer is not an object")
    ready = peer.get("ready")
    if type(ready) is not bool:
        raise SystemExit("sync peer readiness is not a boolean")
    if ready:
        ready_peer_count += 1

normalized = {
    "stage": stage,
    "best_header_height": best_height,
    "best_header_hash": best_hash,
    "active_tip_height": active_height,
    "active_tip_hash": active_hash,
    "stored_tip_height": stored_height,
    "stored_tip_hash": stored_hash,
    "target_height": optional_integer(value.get("target_height"), "target height"),
    "pending_blocks": optional_integer(value.get("pending_blocks"), "pending blocks"),
    "inflight_blocks": optional_integer(value.get("inflight_blocks"), "inflight blocks"),
    "tracked_blocks": optional_integer(value.get("tracked_blocks"), "tracked blocks"),
    "validated_blocks": optional_integer(value.get("validated_blocks"), "validated blocks"),
    "failed_blocks": optional_integer(value.get("failed_blocks"), "failed blocks"),
    "sequence": optional_integer(value.get("sequence"), "sync sequence"),
    "peer_count": len(peers),
    "ready_peer_count": ready_peer_count,
}
print(json.dumps(normalized, separators=(",", ":")))
PY
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
  python3 - "$status" "$MAX_SAFE_SHELL_INTEGER" <<'PY'
import json
import re
import sys

try:
    value = json.loads(sys.argv[1])
except (UnicodeDecodeError, ValueError):
    raise SystemExit(1)
maximum = int(sys.argv[2])
if not isinstance(value, dict):
    raise SystemExit(1)

def integer(name):
    number = value.get(name)
    if type(number) is not int or not (0 <= number <= maximum):
        return None
    return number

height = integer("best_header_height")
active_height = integer("active_tip_height")
stored_height = integer("stored_tip_height")
target_height = integer("target_height")
pending = integer("pending_blocks")
inflight = integer("inflight_blocks")
tracked = integer("tracked_blocks")
peer_count = integer("peer_count")
ready_peer_count = integer("ready_peer_count")
block_hash = value.get("best_header_hash")
complete = (
    value.get("stage") == "Synced"
    and height is not None
    and height > 0
    and isinstance(block_hash, str)
    and re.fullmatch(r"[0-9a-f]{64}", block_hash) is not None
    and active_height == height
    and value.get("active_tip_hash") == block_hash
    and stored_height == height
    and value.get("stored_tip_hash") == block_hash
    and target_height is not None
    and target_height <= height
    and pending == 0
    and inflight == 0
    and tracked == 0
    and peer_count is not None
    and ready_peer_count is not None
    and 0 < ready_peer_count <= peer_count
)
raise SystemExit(0 if complete else 1)
PY
}

start_log_scanner() {
  local log_dir=$1
  local auth_path=$2
  local expected_auth_identity=$3
  local expected_parent_pid=${4:-$runner_pid}

  exec python3 -c '
import ctypes
import os
import signal
import sys

expected_parent = int(sys.argv[7])
if expected_parent != 0:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise SystemExit(74)
    if os.getppid() != expected_parent:
        raise SystemExit(74)

import hashlib
import json
from pathlib import Path
import re
import stat
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
    "$LOG_CHUNK_BYTES" "$LOG_SLOTS" "$MAX_AUTH_BYTES" \
    "$expected_parent_pid"
}

start_parent_bound_node() {
  start_parent_bound_verified_binary "$runner_pid" 0 "${NODE_ARGS[@]}"
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
  local target=${9:-$evidence_dir/state.json}
  local fault_phase=${10:-}
  local temp

  temp=$(mktemp "$evidence_dir/.state.XXXXXX") || return 1
  if ! jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_sync_runtime_state \
    --arg campaign_id "$campaign_id" \
    --arg status "$status" \
    --arg updated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --argjson attempt "$attempt" \
    --argjson sample_sequence "$sample_sequence" \
    --arg sample_sha256 "$last_sample_sha256" \
    --arg sample_decision "$last_sample_decision" \
    --argjson runner_pid "$runner_pid" \
    --arg runner_start_ticks "$runner_start_ticks" \
    --arg launch_nonce "$launch_nonce" \
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
      sample_commit:
        (if $sample_sequence == 0 then
          null
        else
          {
            sequence: $sample_sequence,
            sha256: $sample_sha256,
            decision: $sample_decision,
            decision_durable_in_sample: true
          }
        end),
      runner: {
        pid: $runner_pid,
        start_ticks: $runner_start_ticks
      },
      launch: {
        attempt_nonce: $launch_nonce,
        parent_identity_persisted_before_process_start: true,
        child_supervisor_death_signal: "SIGKILL",
        phase:
          (if $status == "launch_pending" then
            "pending"
          elif $status == "starting" or $status == "running" then
            "released"
          else
            "terminal_or_recovered"
          end)
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
    }' >"$temp"; then
    return 1
  fi
  if [[ -n "$fault_phase" ]]; then
    atomic_install_or_adopt_exact "$temp" "$target" "$fault_phase" || return 1
  else
    atomic_install "$temp" "$target" || return 1
  fi
}

adopt_installed_sample_checkpoint() {
  local sample_path=$1
  local snapshot count sequence

  python3 - "$sample_path" <<'PY' || return 1
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
directory_descriptor = os.open(
    path.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("installed sample is not a private single-link regular file")
    os.fsync(descriptor)
    os.fsync(directory_descriptor)
finally:
    os.close(descriptor)
    os.close(directory_descriptor)
PY
  snapshot=$(validated_sample_chain) || return 1
  count=$(jq -er '.count' <<<"$snapshot") || return 1
  sequence=$(jq -er '.last.sequence' <<<"$snapshot") || return 1
  ((count == sample_sequence && sequence == sample_sequence)) || return 1
  last_sample_sha256=$(jq -er '.last.sha256' <<<"$snapshot") || return 1
  last_sample_decision=$(jq -er '.last.decision' <<<"$snapshot") || return 1
}

take_sample() {
  local timestamp epoch elapsed vm_hwm apparent allocated
  local fs_size fs_used fs_available fs_delta maximum violation reserve_violation
  local observed_binary_sha256 observed_binary_identity observed_auth_identity
  local sync_json=null rpc_reachable=false sync_complete=false
  local temp sample_path sample_decision=continue

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
  if ((fs_available < minimum_sampled_filesystem_available_bytes)); then
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
  if [[ "$violation" == true && "$reserve_violation" == true ]]; then
    sample_decision=sampled_storage_cutoff_and_filesystem_reserve_breached
  elif [[ "$violation" == true ]]; then
    sample_decision=sampled_storage_cutoff_exceeded
  elif [[ "$reserve_violation" == true ]]; then
    sample_decision=sampled_filesystem_reserve_breached
  elif ((consecutive_synced_samples >= completion_samples)); then
    sample_decision=sync_completed
  fi
  printf -v sample_path '%s/samples/%09d.json' "$evidence_dir" "$sample_sequence"
  [[ ! -e "$sample_path" && ! -L "$sample_path" ]] || {
    sample_sequence=$((sample_sequence - 1))
    measurement_error=sample_path_collision
    return 1
  }
  if ! temp=$(mktemp "$evidence_dir/samples/.sample.XXXXXX"); then
    sample_sequence=$((sample_sequence - 1))
    measurement_error=sample_evidence_render_failed
    return 1
  fi
  if ! jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_sync_resource_sample \
    --argjson journal_record_version "$sample_journal_record_version" \
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
    --arg post_sample_decision "$sample_decision" \
    '{
      schema_version: $schema_version,
      artifact_type: $artifact_type,
      journal_record_version: $journal_record_version,
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
      sync: $sync,
      post_sample_decision: $post_sample_decision
    }' >"$temp"; then
    sample_sequence=$((sample_sequence - 1))
    measurement_error=sample_evidence_render_failed
    return 1
  fi
  if trigger_self_test_fault_once fail_sample_commit_before_install; then
    sample_sequence=$((sample_sequence - 1))
    measurement_error=sample_evidence_commit_failed
    return 1
  fi
  if ! atomic_install "$temp" "$sample_path"; then
    measurement_error=sample_evidence_commit_failed
    if [[ -f "$sample_path" && ! -L "$sample_path" ]]; then
      if ! adopt_installed_sample_checkpoint "$sample_path"; then
        sample_commit_ambiguity_unresolved=true
      fi
    else
      sample_sequence=$((sample_sequence - 1))
    fi
    return 1
  fi
  if trigger_self_test_fault_once fail_sample_commit_after_install; then
    measurement_error=sample_evidence_commit_failed
    if ! adopt_installed_sample_checkpoint "$sample_path"; then
      sample_commit_ambiguity_unresolved=true
    fi
    return 1
  fi
  if ! last_sample_sha256=$(sha256sum -- "$sample_path" | awk '{print $1}'); then
    measurement_error=sample_evidence_identity_failed
    if ! adopt_installed_sample_checkpoint "$sample_path"; then
      sample_commit_ambiguity_unresolved=true
    fi
    return 1
  fi
  [[ "$last_sample_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    measurement_error=sample_evidence_identity_failed
    if ! adopt_installed_sample_checkpoint "$sample_path"; then
      sample_commit_ambiguity_unresolved=true
    fi
    return 1
  }
  last_sample_decision=$sample_decision
  pause_for_self_test_fault pause_after_sample_commit || return 1
  if trigger_self_test_fault_once fail_state_commit_before_install; then
    measurement_error=runtime_state_commit_failed
    return 1
  fi
  if ! write_runtime_state running "$vm_hwm" "$apparent" "$allocated" \
    "$fs_delta" "$maximum" "$fs_available" "$sync_json"; then
    measurement_error=runtime_state_commit_failed
    return 1
  fi
  if trigger_self_test_fault_once fail_state_commit_after_install; then
    measurement_error=runtime_state_commit_failed
    return 1
  fi
  pause_for_self_test_fault pause_after_state_commit || return 1

  if [[ "$sample_decision" != continue ]]; then
    stop_request=$sample_decision
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

  if [[ -z "$child_expected_image_path" ||
    -z "$child_expected_image_identity" ||
    -z "$child_expected_image_sha256" ]]; then
    forced_shutdown=true
    kill -KILL "$child_pid" 2>/dev/null || true
    return 0
  fi

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
    if [[ "$runtime_fifo_anchor_fd" =~ ^[0-9]+$ ]]; then
      exec {runtime_fifo_anchor_fd}>&-
      runtime_fifo_anchor_fd=
    fi
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
  local current_binary current_binary_identity current_auth

  acquire_campaign_runner_lock
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

  publish_launch_pending
  mkfifo -m 600 -- "$runtime_fifo"
  : >"$rpc_response_tmp"
  chmod 600 -- "$rpc_response_tmp"
  exec {runtime_fifo_anchor_fd}<>"$runtime_fifo"

  (
    exec {runtime_fifo_anchor_fd}>&-
    start_log_scanner "$evidence_dir/logs" "$auth_file" "$auth_identity" \
      <"$runtime_fifo"
  ) &
  log_scanner_pid=$!
  log_scanner_start_ticks=$(process_start_ticks "$log_scanner_pid") ||
    die "could not capture log scanner process identity"

  (
    exec {runtime_fifo_anchor_fd}>&-
    start_parent_bound_node >"$runtime_fifo" 2>&1
  ) &
  child_pid=$!
  child_start_ticks=$(process_start_ticks "$child_pid") ||
    die "could not capture hsrd process identity"
  initialize_child_process_image_binding ||
    die "launched process image does not match the supplied hsrd binary"
  write_runtime_state starting 0 0 0 0 0 \
    "$baseline_fs_available_bytes" null ||
    die "could not durably record the launched runtime state"
  exec {runtime_fifo_anchor_fd}>&-
  runtime_fifo_anchor_fd=
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
    if ((final_available < minimum_sampled_filesystem_available_bytes)); then
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
    "$final_delta" "$final_maximum" "$final_available" null \
    "$evidence_dir/state.json" final_state ||
    die "could not durably record the final runtime state"
  persist_attempt_terminal_state
  write_terminal_commit_manifest "$classification"
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

validated_sample_chain() {
  python3 - \
    "$evidence_dir/samples" \
    "$campaign_id" \
    "$limit_bytes" \
    "$filesystem_reserve_bytes" \
    "$completion_samples" \
    "$maximum_samples" \
    "$INFORMATIONAL_COMPARISON_BYTES" \
    "$baseline_fs_used_bytes" \
    "$sample_journal_record_version" \
    "$MAX_SAFE_SHELL_INTEGER" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

root = Path(sys.argv[1])
campaign_id = sys.argv[2]
cutoff = int(sys.argv[3])
reserve = int(sys.argv[4])
completion_samples = int(sys.argv[5])
maximum_samples = int(sys.argv[6])
informational_comparison = int(sys.argv[7])
baseline_filesystem_used = int(sys.argv[8])
campaign_record_version = int(sys.argv[9])
maximum_integer = int(sys.argv[10])
digest = hashlib.sha256()
sample_pattern = re.compile(r"([0-9]{9})\.json")
temporary_pattern = re.compile(r"\.sample\.[A-Za-z0-9]+")
paths = []
for path in root.iterdir():
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"unsafe sample journal entry: {path.name}")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(f"sample journal entry is not private: {path.name}")
    if metadata.st_nlink != 1:
        raise SystemExit(f"sample journal entry has multiple links: {path.name}")
    if sample_pattern.fullmatch(path.name):
        paths.append(path)
    elif not temporary_pattern.fullmatch(path.name):
        raise SystemExit(f"unexpected sample journal entry: {path.name}")

paths.sort()
if len(paths) > maximum_samples:
    raise SystemExit("sample journal exceeds the configured maximum")

def integer(value, label):
    if type(value) is not int or not (0 <= value <= maximum_integer):
        raise SystemExit(f"{label} must be a bounded unsigned integer")
    return value

def boolean(value, label):
    if type(value) is not bool:
        raise SystemExit(f"{label} must be a boolean")
    return value

def optional_sync_integer(value, label):
    if value is None:
        return None
    if type(value) is not int or not (0 <= value <= maximum_integer):
        raise SystemExit(f"{label} must be a canonical bounded unsigned integer")
    return value

def validate_normalized_sync_status(value):
    if not isinstance(value, dict):
        raise SystemExit("sample sync status must be an object")
    if not isinstance(value.get("stage"), str) or not value.get("stage"):
        raise SystemExit("sample sync stage must be a nonempty string")
    integer_fields = (
        "best_header_height",
        "active_tip_height",
        "stored_tip_height",
        "target_height",
        "pending_blocks",
        "inflight_blocks",
        "tracked_blocks",
        "validated_blocks",
        "failed_blocks",
        "sequence",
    )
    for name in integer_fields:
        optional_sync_integer(value.get(name), f"sample sync {name}")
    for name in ("peer_count", "ready_peer_count"):
        integer(value.get(name), f"sample sync {name}")
    if value["ready_peer_count"] > value["peer_count"]:
        raise SystemExit("sample ready-peer count exceeds peer count")
    for name in ("best_header_hash", "active_tip_hash", "stored_tip_hash"):
        block_hash = value.get(name)
        if block_hash is not None and (
            not isinstance(block_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", block_hash) is None
        ):
            raise SystemExit(f"sample sync {name} is not a canonical BlockHash")

def sync_status_is_complete(value):
    height = value.get("best_header_height")
    block_hash = value.get("best_header_hash")
    target_height = value.get("target_height")
    ready_peer_count = value.get("ready_peer_count")
    return (
        value.get("stage") == "Synced"
        and type(height) is int
        and height > 0
        and isinstance(block_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", block_hash) is not None
        and value.get("active_tip_height") == height
        and value.get("active_tip_hash") == block_hash
        and value.get("stored_tip_height") == height
        and value.get("stored_tip_hash") == block_hash
        and type(value.get("active_tip_height")) is int
        and type(value.get("stored_tip_height")) is int
        and type(target_height) is int
        and target_height <= height
        and type(value.get("pending_blocks")) is int
        and value.get("pending_blocks") == 0
        and type(value.get("inflight_blocks")) is int
        and value.get("inflight_blocks") == 0
        and type(value.get("tracked_blocks")) is int
        and value.get("tracked_blocks") == 0
        and type(ready_peer_count) is int
        and ready_peer_count > 0
    )

def read_regular_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            stat.S_IMODE(value.st_mode),
            value.st_uid,
            value.st_nlink,
        )
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise SystemExit(f"sample journal entry changed while read: {path.name}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)

maximum_vm_hwm = 0
maximum_apparent = 0
maximum_allocated = 0
maximum_delta = 0
maximum_storage = 0
minimum_available = None
last = None
previous_attempt = 0
previous_consecutive = 0
prefix_before_last = None
for expected_sequence, path in enumerate(paths, start=1):
    if path.name != f"{expected_sequence:09d}.json":
        raise SystemExit("sample journal filenames are not contiguous")
    raw = read_regular_file(path)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"invalid sample JSON: {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"sample is not an object: {path.name}")
    if (
        value.get("schema_version") != 1
        or value.get("artifact_type") != "hsrd_full_sync_resource_sample"
        or value.get("campaign_id") != campaign_id
    ):
        raise SystemExit(f"sample identity is invalid: {path.name}")
    if integer(value.get("sequence"), "sample sequence") != expected_sequence:
        raise SystemExit(f"sample sequence does not match filename: {path.name}")
    sample_attempt = integer(value.get("attempt"), "sample attempt")
    if sample_attempt < 1 or sample_attempt < previous_attempt:
        raise SystemExit(f"sample attempts are not monotonic: {path.name}")
    same_attempt = sample_attempt == previous_attempt

    process = value.get("process")
    storage = value.get("storage")
    if not isinstance(process, dict) or not isinstance(storage, dict):
        raise SystemExit(f"sample process or storage record is invalid: {path.name}")
    image = process.get("executable_image")
    if (
        not isinstance(image, dict)
        or image.get("matched_launch_binding") is not True
        or not isinstance(image.get("path"), str)
        or not image.get("path")
        or not isinstance(image.get("file_identity"), str)
        or not image.get("file_identity")
        or not isinstance(image.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", image.get("sha256")) is None
    ):
        raise SystemExit(f"sample process-image binding is invalid: {path.name}")
    vm_hwm = integer(
        process.get("observed_kernel_vm_hwm_bytes"), "sample VmHWM"
    )
    apparent = integer(
        storage.get("sampled_data_root_apparent_bytes"), "sample apparent bytes"
    )
    allocated = integer(
        storage.get("sampled_data_root_allocated_bytes"), "sample allocated bytes"
    )
    filesystem_used = integer(
        storage.get("sampled_filesystem_used_bytes"), "sample filesystem used bytes"
    )
    available = integer(
        storage.get("sampled_filesystem_available_bytes"),
        "sample filesystem available bytes",
    )
    delta = integer(
        storage.get("sampled_filesystem_used_delta_bytes"),
        "sample filesystem delta bytes",
    )
    if delta != max(filesystem_used - baseline_filesystem_used, 0):
        raise SystemExit(f"sample filesystem delta is inconsistent: {path.name}")
    sampled_maximum = integer(
        storage.get("sampled_storage_maximum_bytes"), "sample storage maximum"
    )
    if sampled_maximum != max(apparent, allocated, delta):
        raise SystemExit(f"sample storage maximum is inconsistent: {path.name}")
    if integer(storage.get("sampled_cutoff_bytes"), "sample cutoff") != cutoff:
        raise SystemExit(f"sample cutoff does not match campaign: {path.name}")
    if integer(storage.get("filesystem_reserve_bytes"), "sample reserve") != reserve:
        raise SystemExit(f"sample reserve does not match campaign: {path.name}")
    if integer(
        storage.get("sampled_informational_comparison_bytes"),
        "sample informational comparison",
    ) != informational_comparison:
        raise SystemExit(
            f"sample informational comparison does not match campaign: {path.name}"
        )
    cutoff_exceeded = sampled_maximum > cutoff
    reserve_breached = available < reserve
    if boolean(
        storage.get("sampled_cutoff_exceeded"), "sample cutoff result"
    ) != cutoff_exceeded:
        raise SystemExit(f"sample cutoff result is inconsistent: {path.name}")
    if boolean(
        storage.get("sampled_filesystem_reserve_breached"), "sample reserve result"
    ) != reserve_breached:
        raise SystemExit(f"sample reserve result is inconsistent: {path.name}")
    if boolean(
        storage.get("sampled_informational_comparison_at_or_below"),
        "sample informational result",
    ) != (sampled_maximum <= informational_comparison):
        raise SystemExit(f"sample informational result is inconsistent: {path.name}")
    if storage.get("informational_comparison_is_qualification_criterion") is not False:
        raise SystemExit(f"sample informational semantics are invalid: {path.name}")

    rpc_reachable = boolean(value.get("rpc_reachable"), "sample RPC result")
    sync_complete = boolean(
        value.get("sync_complete_this_sample"), "sample sync result"
    )
    consecutive = integer(
        value.get("consecutive_synced_samples"), "sample consecutive sync count"
    )
    sync = value.get("sync")
    if not rpc_reachable and (sync is not None or sync_complete or consecutive != 0):
        raise SystemExit(f"unreachable RPC sample has sync evidence: {path.name}")
    if rpc_reachable:
        if not isinstance(sync, dict):
            raise SystemExit(f"reachable RPC sample lacks sync evidence: {path.name}")
        validate_normalized_sync_status(sync)
        if sync_complete != sync_status_is_complete(sync):
            raise SystemExit(f"sample sync result is inconsistent: {path.name}")
    expected_consecutive = 0
    if sync_complete:
        expected_consecutive = previous_consecutive + 1 if same_attempt else 1
    if consecutive != expected_consecutive:
        raise SystemExit(f"sample sync counter is inconsistent: {path.name}")
    previous_attempt = sample_attempt
    previous_consecutive = consecutive

    if cutoff_exceeded and reserve_breached:
        decision = "sampled_storage_cutoff_and_filesystem_reserve_breached"
    elif cutoff_exceeded:
        decision = "sampled_storage_cutoff_exceeded"
    elif reserve_breached:
        decision = "sampled_filesystem_reserve_breached"
    elif consecutive >= completion_samples:
        decision = "sync_completed"
    else:
        decision = "continue"
    has_record_version = "journal_record_version" in value
    record_version = value.get("journal_record_version", 1)
    if type(record_version) is not int or record_version not in (1, 2):
        raise SystemExit(f"sample journal record version is invalid: {path.name}")
    if record_version != campaign_record_version:
        raise SystemExit(f"sample journal record version does not match campaign: {path.name}")
    if campaign_record_version == 2 and not has_record_version:
        raise SystemExit(f"sample journal record version is missing: {path.name}")
    if (has_record_version or campaign_record_version == 2) and (
        "post_sample_decision" not in value
    ):
        raise SystemExit(f"sample decision is missing: {path.name}")
    if (
        "post_sample_decision" in value
        and value.get("post_sample_decision") != decision
    ):
        raise SystemExit(f"sample decision is inconsistent: {path.name}")

    if expected_sequence == len(paths):
        prefix_before_last = {
            "count": expected_sequence - 1,
            "content_chain_sha256": digest.hexdigest(),
            "observed_maxima": {
                "kernel_process_vm_hwm_bytes": maximum_vm_hwm,
                "sampled_data_root_apparent_bytes": maximum_apparent,
                "sampled_data_root_allocated_bytes": maximum_allocated,
                "sampled_filesystem_used_delta_bytes": maximum_delta,
                "sampled_storage_maximum_bytes": maximum_storage,
            },
            "minimum_sampled_filesystem_available_bytes": minimum_available,
            "last": last,
        }
    digest.update(path.name.encode())
    digest.update(b"\0")
    digest.update(raw)
    digest.update(b"\0")
    sample_sha256 = hashlib.sha256(raw).hexdigest()
    maximum_vm_hwm = max(maximum_vm_hwm, vm_hwm)
    maximum_apparent = max(maximum_apparent, apparent)
    maximum_allocated = max(maximum_allocated, allocated)
    maximum_delta = max(maximum_delta, delta)
    maximum_storage = max(maximum_storage, sampled_maximum)
    minimum_available = (
        available if minimum_available is None else min(minimum_available, available)
    )
    last = {
        "sequence": expected_sequence,
        "attempt": sample_attempt,
        "sha256": sample_sha256,
        "decision": decision,
        "vm_hwm": vm_hwm,
        "apparent": apparent,
        "allocated": allocated,
        "filesystem_used": filesystem_used,
        "available": available,
        "delta": delta,
        "maximum": sampled_maximum,
        "consecutive_synced_samples": consecutive,
        "sync": sync,
    }

print(json.dumps({
    "count": len(paths),
    "content_chain_sha256": digest.hexdigest(),
    "observed_maxima": {
        "kernel_process_vm_hwm_bytes": maximum_vm_hwm,
        "sampled_data_root_apparent_bytes": maximum_apparent,
        "sampled_data_root_allocated_bytes": maximum_allocated,
        "sampled_filesystem_used_delta_bytes": maximum_delta,
        "sampled_storage_maximum_bytes": maximum_storage,
    },
    "minimum_sampled_filesystem_available_bytes": minimum_available,
    "last": last,
    "prefix_before_last": prefix_before_last,
}, sort_keys=True, separators=(",", ":")))
PY
}

sample_chain_digest() {
  local snapshot
  snapshot=$(validated_sample_chain) || return 1
  jq -er '[.count, .content_chain_sha256] | @tsv' <<<"$snapshot"
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
  local ended_epoch ended_at elapsed sample_count samples_digest sample_snapshot
  local final_source_revision final_source_tree final_worktree final_dirty source_changed
  local informational_comparison_at_or_below sampled_cutoff_pass
  local sampled_reserve_pass
  local qualification_status temp attempt_summary attempt_temp
  local attempt_logs_manifest attempt_logs_temp logs_temp terminal_commit_path

  [[ "$sample_commit_ambiguity_unresolved" == false ]] ||
    die "cannot finalize an ambiguously committed sample journal"

  ended_epoch=$(date +%s)
  ended_at=$(date -u -d "@$ended_epoch" '+%Y-%m-%dT%H:%M:%SZ')
  elapsed=$((ended_epoch - campaign_started_epoch))
  if ! sample_snapshot=$(validated_sample_chain); then
    die "cannot finalize an invalid sample journal"
  fi
  sample_count=$(jq -er '.count' <<<"$sample_snapshot")
  samples_digest=$(jq -er '.content_chain_sha256' <<<"$sample_snapshot")
  ((sample_count == sample_sequence)) ||
    die "cannot finalize a runtime state that disagrees with the sample journal"
  printf -v attempt_logs_manifest '%s/attempts/%06d-logs-manifest.json' \
    "$evidence_dir" "$attempt"
  [[ ! -e "$attempt_logs_manifest" && ! -L "$attempt_logs_manifest" ]] ||
    die "attempt logs manifest path already exists"
  attempt_logs_temp=$(mktemp \
    "$evidence_dir/attempts/.attempt-logs-manifest.XXXXXX")
  write_logs_manifest "$attempt_logs_temp"
  atomic_install_or_adopt_exact "$attempt_logs_temp" \
    "$attempt_logs_manifest" final_attempt_logs_manifest ||
    die "could not durably publish the attempt logs manifest"
  logs_temp=$(mktemp "$evidence_dir/.logs-manifest.XXXXXX")
  cp --reflink=auto -- "$attempt_logs_manifest" "$logs_temp"
  atomic_install_or_adopt_exact "$logs_temp" \
    "$evidence_dir/logs-manifest.json" final_logs_manifest ||
    die "could not durably publish the final logs manifest"

  printf -v terminal_commit_path 'attempts/%06d-terminal-commit.json' "$attempt"

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
  elif [[ "$classification" != sync_completed ||
    "$sampled_cutoff_pass" != true || "$sampled_reserve_pass" != true ]]; then
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
    --arg terminal_commit_path "$terminal_commit_path" \
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
      terminal_verdict_authority: {
        authoritative_only_with_valid_terminal_commit_manifest: true,
        terminal_commit_manifest_path: $terminal_commit_path
      },
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
        sample_journal:
          "strict contiguous validation; at most one exact trailing durable sample is reconciled without deletion, and every recovered or checkpointed operational threshold remains terminal",
        evidence_commit_semantics:
          "fsync file, atomic replace, then fsync containing directory"
      }
    }' >"$temp"
  atomic_install_or_adopt_exact "$temp" "$evidence_dir/final-summary.json" \
    final_summary || die "could not durably publish the final summary"
  printf -v attempt_summary '%s/attempts/%06d-summary.json' "$evidence_dir" "$attempt"
  [[ ! -e "$attempt_summary" && ! -L "$attempt_summary" ]] ||
    die "attempt summary path already exists"
  attempt_temp=$(mktemp "$evidence_dir/attempts/.attempt-summary.XXXXXX")
  cp --reflink=auto -- "$evidence_dir/final-summary.json" "$attempt_temp"
  atomic_install_or_adopt_exact "$attempt_temp" "$attempt_summary" \
    attempt_summary || die "could not durably publish the attempt summary"
}

persist_attempt_terminal_state() {
  local attempt_state state_temp

  printf -v attempt_state '%s/attempts/%06d-state.json' "$evidence_dir" "$attempt"
  [[ ! -e "$attempt_state" && ! -L "$attempt_state" ]] ||
    die "attempt terminal state path already exists"
  state_temp=$(mktemp "$evidence_dir/attempts/.attempt-state.XXXXXX")
  cp --reflink=auto -- "$evidence_dir/state.json" "$state_temp"
  atomic_install_or_adopt_exact "$state_temp" "$attempt_state" \
    final_attempt_state ||
    die "could not durably publish the attempt terminal state"
}

write_terminal_commit_manifest() {
  local classification=$1
  local marker temp sample_snapshot sample_count samples_digest
  local qualification_status build_provenance_sha256
  local state_path final_summary_path logs_manifest_path
  local attempt_state_path attempt_summary_path attempt_logs_manifest_path
  local state_sha256 final_summary_sha256 logs_manifest_sha256
  local attempt_state_sha256 attempt_summary_sha256 attempt_logs_manifest_sha256
  local state_relative final_summary_relative logs_manifest_relative
  local attempt_state_relative attempt_summary_relative attempt_logs_manifest_relative

  state_path="$evidence_dir/state.json"
  final_summary_path="$evidence_dir/final-summary.json"
  logs_manifest_path="$evidence_dir/logs-manifest.json"
  printf -v attempt_state_path '%s/attempts/%06d-state.json' \
    "$evidence_dir" "$attempt"
  printf -v attempt_summary_path '%s/attempts/%06d-summary.json' \
    "$evidence_dir" "$attempt"
  printf -v attempt_logs_manifest_path '%s/attempts/%06d-logs-manifest.json' \
    "$evidence_dir" "$attempt"
  printf -v marker '%s/attempts/%06d-terminal-commit.json' \
    "$evidence_dir" "$attempt"
  [[ ! -e "$marker" && ! -L "$marker" ]] ||
    die "terminal commit manifest path already exists"

  qualification_status=$(read_required_nonempty_json_string \
    qualification_status "$final_summary_path") ||
    die "final summary qualification status is missing or invalid"
  jq -e \
    --arg campaign_id "$campaign_id" \
    --arg classification "$classification" \
    --arg qualification_status "$qualification_status" \
    --argjson attempt "$attempt" \
    --arg config_sha256 "$config_sha256" '
      .schema_version == 1 and
      .artifact_type == "hsrd_full_non_pruned_mainnet_campaign_summary" and
      .campaign_id == $campaign_id and
      .classification == $classification and
      .qualification_status == $qualification_status and
      .final_attempt == $attempt and
      .campaign_config_sha256 == $config_sha256 and
      .terminal_verdict_authority.authoritative_only_with_valid_terminal_commit_manifest == true
    ' "$final_summary_path" >/dev/null ||
    die "final summary is inconsistent with the terminal commit"
  jq -e \
    --arg campaign_id "$campaign_id" \
    --arg classification "$classification" \
    --argjson attempt "$attempt" '
      .schema_version == 1 and
      .artifact_type == "hsrd_full_sync_runtime_state" and
      .campaign_id == $campaign_id and
      .status == $classification and
      .attempt == $attempt
    ' "$state_path" >/dev/null ||
    die "final runtime state is inconsistent with the terminal commit"

  sample_snapshot=$(validated_sample_chain) ||
    die "cannot commit a terminal verdict over an invalid sample journal"
  sample_count=$(jq -er '.count' <<<"$sample_snapshot")
  samples_digest=$(jq -er '.content_chain_sha256' <<<"$sample_snapshot")
  ((sample_count == sample_sequence)) ||
    die "terminal commit sample count differs from runtime state"

  state_sha256=$(sha256sum -- "$state_path" | awk '{print $1}')
  final_summary_sha256=$(sha256sum -- "$final_summary_path" | awk '{print $1}')
  logs_manifest_sha256=$(sha256sum -- "$logs_manifest_path" | awk '{print $1}')
  attempt_state_sha256=$(sha256sum -- "$attempt_state_path" | awk '{print $1}')
  attempt_summary_sha256=$(sha256sum -- "$attempt_summary_path" | awk '{print $1}')
  attempt_logs_manifest_sha256=$(sha256sum -- \
    "$attempt_logs_manifest_path" | awk '{print $1}')
  build_provenance_sha256=$(sha256sum -- \
    "$evidence_dir/build-provenance.json" | awk '{print $1}')
  [[ "$state_sha256" == "$attempt_state_sha256" &&
    "$final_summary_sha256" == "$attempt_summary_sha256" &&
    "$logs_manifest_sha256" == "$attempt_logs_manifest_sha256" ]] ||
    die "canonical and attempt terminal artifacts differ"

  state_relative=state.json
  final_summary_relative=final-summary.json
  logs_manifest_relative=logs-manifest.json
  printf -v attempt_state_relative 'attempts/%06d-state.json' "$attempt"
  printf -v attempt_summary_relative 'attempts/%06d-summary.json' "$attempt"
  printf -v attempt_logs_manifest_relative 'attempts/%06d-logs-manifest.json' \
    "$attempt"

  temp=$(mktemp "$evidence_dir/attempts/.terminal-commit.XXXXXX")
  jq -n \
    --argjson schema_version "$SCHEMA_VERSION" \
    --arg artifact_type hsrd_full_sync_terminal_commit \
    --arg campaign_id "$campaign_id" \
    --argjson attempt "$attempt" \
    --arg classification "$classification" \
    --arg qualification_status "$qualification_status" \
    --arg committed_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg config_sha256 "$config_sha256" \
    --arg build_provenance_sha256 "$build_provenance_sha256" \
    --argjson sample_count "$sample_count" \
    --arg samples_digest "$samples_digest" \
    --arg state_path "$state_relative" \
    --arg state_sha256 "$state_sha256" \
    --arg final_summary_path "$final_summary_relative" \
    --arg final_summary_sha256 "$final_summary_sha256" \
    --arg logs_manifest_path "$logs_manifest_relative" \
    --arg logs_manifest_sha256 "$logs_manifest_sha256" \
    --arg attempt_state_path "$attempt_state_relative" \
    --arg attempt_state_sha256 "$attempt_state_sha256" \
    --arg attempt_summary_path "$attempt_summary_relative" \
    --arg attempt_summary_sha256 "$attempt_summary_sha256" \
    --arg attempt_logs_manifest_path "$attempt_logs_manifest_relative" \
    --arg attempt_logs_manifest_sha256 "$attempt_logs_manifest_sha256" '
      {
        schema_version: $schema_version,
        artifact_type: $artifact_type,
        commit_protocol_version: 1,
        campaign_id: $campaign_id,
        attempt: $attempt,
        classification: $classification,
        qualification_status: $qualification_status,
        committed_at: $committed_at,
        verdict_authoritative: true,
        published_after_all_bound_artifacts: true,
        campaign_config_sha256: $config_sha256,
        build_provenance_sha256: $build_provenance_sha256,
        samples: {
          count: $sample_count,
          content_chain_sha256: $samples_digest
        },
        artifacts: {
          runtime_state: {path: $state_path, sha256: $state_sha256},
          final_summary: {
            path: $final_summary_path,
            sha256: $final_summary_sha256
          },
          logs_manifest: {
            path: $logs_manifest_path,
            sha256: $logs_manifest_sha256
          },
          attempt_state: {
            path: $attempt_state_path,
            sha256: $attempt_state_sha256
          },
          attempt_summary: {
            path: $attempt_summary_path,
            sha256: $attempt_summary_sha256
          },
          attempt_logs_manifest: {
            path: $attempt_logs_manifest_path,
            sha256: $attempt_logs_manifest_sha256
          }
        }
      }
    ' >"$temp" || die "could not construct the terminal commit manifest"
  atomic_install_or_adopt_exact "$temp" "$marker" terminal_commit ||
    die "could not durably publish the terminal commit manifest"
  validated_terminal_commit "$attempt" >/dev/null ||
    die "published terminal commit manifest failed readback validation"
}

validated_terminal_commit() {
  local expected_attempt=$1

  python3 - "$evidence_dir" "$expected_attempt" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

root = Path(sys.argv[1])
expected_attempt = int(sys.argv[2])
if not (1 <= expected_attempt <= 32):
    raise SystemExit("terminal commit attempt is outside its supported range")

def identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_nlink,
    )

def read_private(relative):
    path = root / relative
    if path.parent not in (root, root / "attempts"):
        raise SystemExit(f"terminal artifact escaped its expected directory: {relative}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise SystemExit(f"terminal artifact is not private: {relative}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise SystemExit(f"terminal artifact changed while read: {relative}")
        os.fsync(descriptor)
        return b"".join(chunks)
    finally:
        os.close(descriptor)

def parse_object(raw, label):
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid {label} JSON: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"{label} is not an object")
    return value

def sha256(raw):
    return hashlib.sha256(raw).hexdigest()

attempt_prefix = f"attempts/{expected_attempt:06d}"
expected_paths = {
    "runtime_state": "state.json",
    "final_summary": "final-summary.json",
    "logs_manifest": "logs-manifest.json",
    "attempt_state": f"{attempt_prefix}-state.json",
    "attempt_summary": f"{attempt_prefix}-summary.json",
    "attempt_logs_manifest": f"{attempt_prefix}-logs-manifest.json",
}
marker_relative = f"{attempt_prefix}-terminal-commit.json"
marker_raw = read_private(marker_relative)
marker = parse_object(marker_raw, "terminal commit manifest")
if (
    marker.get("schema_version") != 1
    or marker.get("artifact_type") != "hsrd_full_sync_terminal_commit"
    or marker.get("commit_protocol_version") != 1
    or type(marker.get("attempt")) is not int
    or marker.get("attempt") != expected_attempt
    or not isinstance(marker.get("campaign_id"), str)
    or not marker.get("campaign_id")
    or not isinstance(marker.get("classification"), str)
    or not marker.get("classification")
    or not isinstance(marker.get("qualification_status"), str)
    or not marker.get("qualification_status")
    or not isinstance(marker.get("committed_at"), str)
    or not marker.get("committed_at")
    or marker.get("verdict_authoritative") is not True
    or marker.get("published_after_all_bound_artifacts") is not True
    or not isinstance(marker.get("campaign_config_sha256"), str)
    or re.fullmatch(r"[0-9a-f]{64}", marker.get("campaign_config_sha256", "")) is None
    or not isinstance(marker.get("build_provenance_sha256"), str)
    or re.fullmatch(r"[0-9a-f]{64}", marker.get("build_provenance_sha256", "")) is None
):
    raise SystemExit("terminal commit manifest identity is invalid")

artifacts = marker.get("artifacts")
if not isinstance(artifacts, dict) or set(artifacts) != set(expected_paths):
    raise SystemExit("terminal commit artifact inventory is invalid")
raw_artifacts = {}
for label, relative in expected_paths.items():
    record = artifacts.get(label)
    if (
        not isinstance(record, dict)
        or set(record) != {"path", "sha256"}
        or record.get("path") != relative
        or not isinstance(record.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")) is None
    ):
        raise SystemExit(f"terminal commit binding is invalid: {label}")
    raw = read_private(relative)
    if sha256(raw) != record["sha256"]:
        raise SystemExit(f"terminal commit hash differs: {label}")
    raw_artifacts[label] = raw

if raw_artifacts["runtime_state"] != raw_artifacts["attempt_state"]:
    raise SystemExit("canonical and attempt terminal states differ")
if raw_artifacts["final_summary"] != raw_artifacts["attempt_summary"]:
    raise SystemExit("canonical and attempt final summaries differ")
if raw_artifacts["logs_manifest"] != raw_artifacts["attempt_logs_manifest"]:
    raise SystemExit("canonical and attempt logs manifests differ")

config_raw = read_private("campaign-config.json")
if sha256(config_raw) != marker["campaign_config_sha256"]:
    raise SystemExit("terminal commit campaign configuration differs")
provenance_raw = read_private("build-provenance.json")
if sha256(provenance_raw) != marker["build_provenance_sha256"]:
    raise SystemExit("terminal commit build provenance differs")

sample_dir = root / "samples"
sample_pattern = re.compile(r"([0-9]{9})\.json")
temporary_pattern = re.compile(r"\.sample\.[A-Za-z0-9]+")
sample_paths = []
for path in sample_dir.iterdir():
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"unsafe sample journal entry: {path.name}")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit(f"sample journal entry is not private: {path.name}")
    if metadata.st_nlink != 1:
        raise SystemExit(f"sample journal entry has multiple links: {path.name}")
    if sample_pattern.fullmatch(path.name):
        sample_paths.append(path)
    elif not temporary_pattern.fullmatch(path.name):
        raise SystemExit(f"unexpected sample journal entry: {path.name}")
sample_paths.sort()
sample_digest = hashlib.sha256()
last_sample_sha256 = None
for sequence, path in enumerate(sample_paths, start=1):
    if path.name != f"{sequence:09d}.json":
        raise SystemExit("sample journal filenames are not contiguous")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        raw = b""
        chunks = []
        before = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise SystemExit(f"sample journal entry changed while read: {path.name}")
        os.fsync(descriptor)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    sample_digest.update(path.name.encode())
    sample_digest.update(b"\0")
    sample_digest.update(raw)
    sample_digest.update(b"\0")
    last_sample_sha256 = sha256(raw)
samples = marker.get("samples")
if (
    not isinstance(samples, dict)
    or set(samples) != {"count", "content_chain_sha256"}
    or type(samples.get("count")) is not int
    or samples.get("count") != len(sample_paths)
    or samples.get("content_chain_sha256") != sample_digest.hexdigest()
):
    raise SystemExit("terminal commit sample-chain binding is invalid")

state = parse_object(raw_artifacts["runtime_state"], "terminal runtime state")
summary = parse_object(raw_artifacts["final_summary"], "final summary")
logs_manifest = parse_object(raw_artifacts["logs_manifest"], "logs manifest")
campaign_id = marker["campaign_id"]
classification = marker["classification"]
qualification_status = marker["qualification_status"]
if (
    state.get("schema_version") != 1
    or state.get("artifact_type") != "hsrd_full_sync_runtime_state"
    or state.get("campaign_id") != campaign_id
    or state.get("status") != classification
    or type(state.get("attempt")) is not int
    or state.get("attempt") != expected_attempt
    or type(state.get("sample_sequence")) is not int
    or state.get("sample_sequence") != len(sample_paths)
):
    raise SystemExit("terminal runtime state semantics are invalid")
sample_commit = state.get("sample_commit")
if not sample_paths:
    if sample_commit is not None:
        raise SystemExit("zero-sample terminal state has a sample commit")
elif (
    not isinstance(sample_commit, dict)
    or sample_commit.get("sequence") != len(sample_paths)
    or sample_commit.get("sha256") != last_sample_sha256
    or not isinstance(sample_commit.get("decision"), str)
    or sample_commit.get("decision_durable_in_sample") is not True
):
    raise SystemExit("terminal runtime state sample commit is invalid")

authority = summary.get("terminal_verdict_authority")
if (
    summary.get("schema_version") != 1
    or summary.get("artifact_type")
        != "hsrd_full_non_pruned_mainnet_campaign_summary"
    or summary.get("campaign_id") != campaign_id
    or summary.get("campaign_config_sha256") != marker["campaign_config_sha256"]
    or summary.get("classification") != classification
    or summary.get("qualification_status") != qualification_status
    or type(summary.get("final_attempt")) is not int
    or summary.get("final_attempt") != expected_attempt
    or not isinstance(authority, dict)
    or authority.get("authoritative_only_with_valid_terminal_commit_manifest") is not True
    or authority.get("terminal_commit_manifest_path") != marker_relative
    or not isinstance(summary.get("samples"), dict)
    or summary["samples"].get("count") != len(sample_paths)
    or summary["samples"].get("content_chain_sha256") != sample_digest.hexdigest()
):
    raise SystemExit("final summary terminal semantics are invalid")
if (
    logs_manifest.get("schema_version") != 1
    or logs_manifest.get("artifact_type") != "hsrd_full_sync_logs_manifest"
    or not isinstance(logs_manifest.get("files"), list)
):
    raise SystemExit("terminal logs manifest semantics are invalid")

for directory in (root, root / "attempts", root / "samples"):
    metadata = directory.lstat()
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SystemExit(f"terminal evidence directory is not private: {directory}")
    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

print(json.dumps({
    "attempt": expected_attempt,
    "classification": classification,
    "qualification_status": qualification_status,
    "runtime_state_sha256": sha256(raw_artifacts["runtime_state"]),
    "terminal_commit_manifest_path": marker_relative,
    "verdict_authoritative": True,
}, sort_keys=True, separators=(",", ":")))
PY
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
  local state_snapshot state_json state_sha state_attempt state_status
  local marker_path terminal_verdict terminal_reason verdict_state_sha
  local verdict_attempt verdict_classification
  evidence_dir=$(normalize_absolute_path "$evidence_dir" "evidence directory")
  validate_existing_private_directory "$evidence_dir" "evidence directory"
  state="$evidence_dir/state.json"
  [[ -f "$state" && ! -L "$state" ]] || die "runtime state is missing"
  state_snapshot=$(stable_private_runtime_state_snapshot "$state") ||
    die "runtime state is invalid or changed while read"
  state_json=$(jq -ce '.value' <<<"$state_snapshot") ||
    die "runtime state snapshot is invalid"
  state_sha=$(jq -er '.sha256' <<<"$state_snapshot") ||
    die "runtime state snapshot digest is invalid"
  state_attempt=$(jq -er '.attempt' <<<"$state_snapshot") ||
    die "runtime state snapshot attempt is invalid"
  state_status=$(jq -er '.status' <<<"$state_snapshot") ||
    die "runtime state snapshot status is invalid"

  printf -v marker_path '%s/attempts/%06d-terminal-commit.json' \
    "$evidence_dir" "$state_attempt"
  terminal_reason=no_terminal_commit_for_current_runtime_attempt
  if [[ -f "$marker_path" && ! -L "$marker_path" ]]; then
    if terminal_verdict=$(validated_terminal_commit "$state_attempt" 2>/dev/null); then
      verdict_state_sha=$(jq -er '.runtime_state_sha256' \
        <<<"$terminal_verdict") || verdict_state_sha=
      verdict_attempt=$(jq -er '.attempt' <<<"$terminal_verdict") ||
        verdict_attempt=
      verdict_classification=$(jq -er '.classification' \
        <<<"$terminal_verdict") || verdict_classification=
      if [[ "$verdict_state_sha" == "$state_sha" &&
        "$verdict_attempt" == "$state_attempt" &&
        "$verdict_classification" == "$state_status" ]]; then
        terminal_reason=
      else
        terminal_reason=terminal_bundle_does_not_bind_status_snapshot
      fi
    else
      terminal_reason=current_terminal_bundle_is_uncommitted_or_invalid
    fi
  elif [[ -e "$marker_path" || -L "$marker_path" ]]; then
    terminal_reason=terminal_commit_is_not_a_safe_regular_file
  fi
  if [[ -n "$terminal_reason" ]]; then
    terminal_verdict=$(jq -cn --arg reason "$terminal_reason" '{
      verdict_authoritative: false,
      reason: $reason
    }')
  fi
  if process_identity_is_live \
    "$(jq -r '.runner.pid // empty' <<<"$state_json")" \
    "$(jq -r '.runner.start_ticks // empty' <<<"$state_json")"; then
    runner_alive=true
  fi
  if process_identity_is_live \
    "$(jq -r '.child.pid // empty' <<<"$state_json")" \
    "$(jq -r '.child.start_ticks // empty' <<<"$state_json")"; then
    child_alive=true
  fi
  jq -c \
    --argjson runner_alive "$runner_alive" \
    --argjson child_alive "$child_alive" \
    --argjson terminal_verdict "$terminal_verdict" \
    '. + {observed_process_state: {
      runner_alive: $runner_alive,
      child_alive: $child_alive
    }, terminal_verdict: $terminal_verdict,
    status_semantics: "runtime lifecycle only; qualification verdict authority requires terminal_verdict.verdict_authoritative == true"}' \
    <<<"$state_json"
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
  case "$behavior" in
    normal|limit|reserve|long|boundary|auth-change|exec-change|\
      synced-nonzero|synced-zero)
      ;;
    *)
      return 1
      ;;
  esac
  {
    printf '%s\n' '#!/usr/bin/env python3'
    printf 'SELF_TEST_BEHAVIOR = "%s"\n' "$behavior"
    cat <<'FAKE'
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
behavior = SELF_TEST_BEHAVIOR

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

if "synced-" in behavior:
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

    exit_handler = exit_seven if "synced-nonzero" in behavior else exit_zero
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    server = http.server.ThreadingHTTPServer((host, int(port_text)), Handler)
    server.serve_forever(poll_interval=0.05)

if "long" in behavior:
    sys.stdout.buffer.write(b"L" * 65536)
    sys.stdout.buffer.flush()
    run_until_stopped()

raise SystemExit(91)
FAKE
  } >"$path"
  chmod 700 -- "$path"
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

    start_log_scanner "$evidence_dir/logs" "$auth_path" \
      "$expected_identity" 0 <"$runtime_fifo" &
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
  local response normalized expected uppercase index numeric_token numeric_label
  local byte_token byte_array malformed_status
  local -a malformed_labels malformed_values malformed_numeric_labels
  local -a malformed_numeric_tokens malformed_byte_tokens

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

  malformed_numeric_labels=(
    fractional
    near-integral-fraction
    exponent
    overrange
  )
  malformed_numeric_tokens=(
    1.5
    1.0000000000000000001
    1e0
    9000000000000000001
  )
  for index in "${!malformed_numeric_tokens[@]}"; do
    numeric_label=${malformed_numeric_labels[$index]}
    numeric_token=${malformed_numeric_tokens[$index]}
    printf '{"stage":"Synced","best_header":{"height":%s,"hash":"%s"},"active_tip":{"height":%s,"hash":"%s"},"stored_tip":{"height":%s,"hash":"%s"},"target_height":%s,"pending_blocks":0,"inflight_blocks":0,"tracked_blocks":0,"validated_blocks":1,"failed_blocks":0,"sequence":1,"peers":[{"ready":true}]}\n' \
      "$numeric_token" "$expected" "$numeric_token" "$expected" \
      "$numeric_token" "$expected" "$numeric_token" >"$response"
    if normalize_sync_status_response "$response" >/dev/null 2>&1; then
      die "self-test accepted $numeric_label sync integers"
    fi
  done

  malformed_status=$(printf '{"stage":"Synced","best_header_height":1.0000000000000000001,"best_header_hash":"%s","active_tip_height":1.0000000000000000001,"active_tip_hash":"%s","stored_tip_height":1.0000000000000000001,"stored_tip_hash":"%s","target_height":1.0000000000000000001,"pending_blocks":0,"inflight_blocks":0,"tracked_blocks":0,"peer_count":1,"ready_peer_count":1}' \
    "$expected" "$expected" "$expected")
  if sync_status_is_complete "$malformed_status"; then
    die "self-test completion predicate accepted near-integral sync integers"
  fi

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

  malformed_byte_tokens=(1.0000000000000000001 1e0)
  for byte_token in "${malformed_byte_tokens[@]}"; do
    byte_array="[$byte_token,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]"
    printf '{"stage":"Synced","best_header":{"height":1,"hash":%s},"active_tip":{"height":1,"hash":"%s"},"stored_tip":{"height":1,"hash":"%s"},"target_height":1,"pending_blocks":0,"inflight_blocks":0,"tracked_blocks":0,"validated_blocks":1,"failed_blocks":0,"sequence":1,"peers":[{"ready":true}]}\n' \
      "$byte_array" "$expected" "$expected" >"$response"
    if normalize_sync_status_response "$response" >/dev/null 2>&1; then
      die "self-test accepted noncanonical numeric BlockHash byte $byte_token"
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

self_test_required_json_booleans() {
  local fixture_root=$1
  local response="$fixture_root/required-json-booleans.json"
  local expected key_path label invalid_json value rc
  local -a key_paths=(source.dirty self_test.interpreter_image_allowance)
  local -a invalid_labels=(null missing string number array object)

  for expected in false true; do
    jq -n --argjson value "$expected" '{
      source: {dirty: $value},
      self_test: {interpreter_image_allowance: $value}
    }' >"$response"
    for key_path in "${key_paths[@]}"; do
      value=
      if value=$(read_required_json_boolean "$key_path" "$response" 2>/dev/null); then
        rc=0
      else
        rc=$?
      fi
      [[ "$rc" == 0 && "$value" == "$expected" ]] ||
        die "self-test did not load required boolean $key_path=$expected"
    done
  done

  for key_path in "${key_paths[@]}"; do
    for label in "${invalid_labels[@]}"; do
      case "$label" in
        null)
          invalid_json=null
          ;;
        missing)
          jq -n '{}' >"$response"
          ;;
        string)
          invalid_json='"false"'
          ;;
        number)
          invalid_json=0
          ;;
        array)
          invalid_json='[]'
          ;;
        object)
          invalid_json='{}'
          ;;
      esac
      if [[ "$label" != missing ]]; then
        jq -n --arg key_path "$key_path" --argjson value "$invalid_json" '
          setpath($key_path | split("."); $value)
        ' >"$response"
      fi
      value=
      if value=$(read_required_json_boolean "$key_path" "$response" 2>/dev/null); then
        rc=0
      else
        rc=$?
      fi
      [[ "$rc" != 0 ]] ||
        die "self-test accepted $label for required boolean $key_path"
    done
  done
}

self_test_resume_classification_policy() {
  local fixture_root=$1
  local response="$fixture_root/resume-classification.json"
  local classification label invalid_json value parser_rc policy_rc
  local -a allowed=(
    operator_stop
    operator_interrupt
    node_exit_zero_before_sync
    node_exit_nonzero
  )
  local -a rejected_known=(
    sync_completed
    sync_completed_child_nonzero
    sync_completed_forced_shutdown
    sampled_storage_cutoff_exceeded
    sampled_storage_cutoff_and_filesystem_reserve_breached
    sampled_filesystem_reserve_breached
    sample_limit_exceeded
    measurement_error
    binary_identity_changed
    binary_identity_read_failed
    authorization_identity_changed
    authorization_identity_read_failed
    child_process_identity_changed
    child_process_image_changed
    log_authorization_scanner_failed
    authorization_value_emission_detected
    authorization_log_retention_guarantee_failed
    internal_runner_error
  )
  local -a invalid_labels=(empty null boolean number array object missing malformed)

  for classification in "${allowed[@]}"; do
    jq -n --arg classification "$classification" \
      '{classification: $classification}' >"$response"
    value=
    if value=$(read_required_nonempty_json_string \
      classification "$response" 2>/dev/null); then
      parser_rc=0
    else
      parser_rc=$?
    fi
    if resume_classification_is_allowed "$value"; then
      policy_rc=0
    else
      policy_rc=$?
    fi
    [[ "$parser_rc" == 0 && "$value" == "$classification" &&
      "$policy_rc" == 0 ]] ||
      die "self-test rejected resumable classification $classification"
  done

  for classification in "${rejected_known[@]}" unknown_future_classification; do
    jq -n --arg classification "$classification" \
      '{classification: $classification}' >"$response"
    value=
    if value=$(read_required_nonempty_json_string \
      classification "$response" 2>/dev/null); then
      parser_rc=0
    else
      parser_rc=$?
    fi
    if resume_classification_is_allowed "$value"; then
      policy_rc=0
    else
      policy_rc=$?
    fi
    [[ "$parser_rc" == 0 && "$value" == "$classification" &&
      "$policy_rc" != 0 ]] ||
      die "self-test accepted non-resumable classification $classification"
  done

  for label in "${invalid_labels[@]}"; do
    case "$label" in
      empty)
        invalid_json='""'
        ;;
      null)
        invalid_json=null
        ;;
      boolean)
        invalid_json=false
        ;;
      number)
        invalid_json=0
        ;;
      array)
        invalid_json='[]'
        ;;
      object)
        invalid_json='{}'
        ;;
      missing)
        jq -n '{}' >"$response"
        ;;
      malformed)
        printf '%s\n' '{"classification":' >"$response"
        ;;
    esac
    if [[ "$label" != missing && "$label" != malformed ]]; then
      jq -n --argjson classification "$invalid_json" \
        '{classification: $classification}' >"$response"
    fi
    value=
    if value=$(read_required_nonempty_json_string \
      classification "$response" 2>/dev/null); then
      parser_rc=0
    else
      parser_rc=$?
    fi
    [[ "$parser_rc" != 0 ]] ||
      die "self-test accepted $label final-summary classification"
  done
}

self_test_bounded_numeric_options() {
  local fixture_root=$1
  local response="$fixture_root/bounded-numeric-values.json"
  local output rc value invalid_json invalid_label
  local -a invalid_labels invalid_values

  is_bounded_unsigned_integer 9000000000000000000 \
    "$MAX_SAFE_SHELL_INTEGER" ||
    die "self-test rejected the maximum supported shell integer"
  ! is_bounded_unsigned_integer 9000000000000000001 \
    "$MAX_SAFE_SHELL_INTEGER" ||
    die "self-test accepted an integer above the supported shell range"
  ! is_bounded_unsigned_integer 01 "$MAX_SAFE_SHELL_INTEGER" ||
    die "self-test accepted a noncanonical unsigned integer"
  ! all_values_are_bounded_unsigned_integers "$MAX_SAFE_SHELL_INTEGER" \
    1 9223372036854775808 2 ||
    die "self-test accepted an overflowing filesystem measurement"
  ! is_bounded_unsigned_integer 8789062500000001 "$MAX_SAFE_VM_HWM_KIB" ||
    die "self-test accepted an overflowing VmHWM KiB measurement"

  printf '%s\n' '{"value":9000000000000000000}' >"$response"
  value=$(read_required_bounded_json_unsigned_integer \
    value "$response" "$MAX_SAFE_SHELL_INTEGER") ||
    die "self-test rejected the maximum exact persisted integer"
  [[ "$value" == 9000000000000000000 ]] ||
    die "self-test changed the maximum exact persisted integer"
  invalid_labels=(string fractional exponent overrange)
  invalid_values=(
    '"60"'
    '60.0'
    '6e1'
    '9000000000000000001'
  )
  for invalid_label in "${!invalid_values[@]}"; do
    invalid_json=${invalid_values[$invalid_label]}
    printf '{"value":%s}\n' "$invalid_json" >"$response"
    if read_required_bounded_json_unsigned_integer \
      value "$response" "$MAX_SAFE_SHELL_INTEGER" >/dev/null 2>&1; then
      die "self-test accepted ${invalid_labels[$invalid_label]} persisted integer"
    fi
  done

  printf '%s\n' '{"rpc":{"bind":"127.0.0.1:12037"}}' >"$response"
  value=$(read_required_rpc_bind_port "$response") ||
    die "self-test rejected a canonical RPC bind port"
  [[ "$value" == 12037 ]] || die "self-test changed a canonical RPC bind port"
  for invalid_json in \
    '"127.0.0.1:1e4"' \
    '"127.0.0.1:18446744073709563653"' \
    '12037'; do
    printf '{"rpc":{"bind":%s}}\n' "$invalid_json" >"$response"
    if read_required_rpc_bind_port "$response" >/dev/null 2>&1; then
      die "self-test accepted noncanonical RPC bind value $invalid_json"
    fi
  done

  set +e
  output=$("$SCRIPT_PATH" run \
    --binary /self-test-missing-binary \
    --data-root /self-test-missing-data \
    --evidence-dir /self-test-missing-evidence \
    --auth-file /self-test-missing-auth \
    --limit-bytes 18446744073709551617 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"--limit-bytes must be a bounded"* ]] ||
    die "self-test accepted a wraparound limit: $output"

  set +e
  output=$("$SCRIPT_PATH" run \
    --binary /self-test-missing-binary \
    --data-root /self-test-missing-data \
    --evidence-dir /self-test-missing-evidence \
    --auth-file /self-test-missing-auth \
    --limit-bytes 1 \
    --filesystem-reserve-bytes 18446744073709551616 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"--filesystem-reserve-bytes must be a bounded"* ]] ||
    die "self-test accepted a wraparound filesystem reserve: $output"

  set +e
  output=$("$SCRIPT_PATH" run \
    --binary /self-test-missing-binary \
    --data-root /self-test-missing-data \
    --evidence-dir /self-test-missing-evidence \
    --auth-file /self-test-missing-auth \
    --rpc-port 18446744073709563653 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"--rpc-port must be a bounded"* ]] ||
    die "self-test accepted a wraparound RPC port: $output"
}

self_test() {
  local root auth mutation_auth normal_binary limit_binary reserve_binary
  local long_binary boundary_binary auth_change_binary exec_change_binary
  local synced_nonzero_binary synced_zero_binary
  local rc output
  local normal_data normal_evidence limit_data limit_evidence
  local reserve_data reserve_evidence reserve_available reserve_bytes
  local refuse_data refuse_evidence symlink_data symlink_evidence
  local stop_data stop_evidence stop_output stop_runner ready
  local launch_pending_data launch_pending_evidence launch_pending_output
  local launch_pending_runner launch_pending_marker launch_pending_status
  local launch_pending_lock
  local lock_hardlink_target lock_hardlink_sha
  local lock_attack_target lock_attack_target_sha lock_attack_target_mode
  local lock_attack_state_sha lock_attack_summary_sha
  local orphan_data orphan_evidence orphan_output orphan_runner orphan_child
  local orphan_child_ticks orphan_scanner orphan_scanner_ticks orphan_lock
  local orphan_resume_output orphan_resume_runner recovered_segment recovered_sha
  local orphan_fault_marker orphan_sample orphan_sample_backup orphan_sample_sha
  local orphan_state orphan_state_backup
  local orphan_config orphan_config_backup orphan_config_digest_backup
  local hostile_temp hostile_output extra_sample
  local hostile_index hostile_state_marker hostile_state_payload hostile_state_path
  local -a hostile_sample_filters hostile_sample_labels hostile_state_paths
  local recovery_marker sample_recovery_marker stale_counter reconciliation_marker
  local boundary_data boundary_evidence
  local mutation_data mutation_evidence mutation_output mutation_runner
  local exec_change_data exec_change_evidence
  local synced_data synced_evidence synced_zero_data synced_zero_evidence
  local sample_limit_data sample_limit_evidence
  local stale_scanner_marker
  local terminal_crash_data terminal_crash_evidence terminal_crash_output
  local terminal_crash_runner terminal_child terminal_child_ticks
  local terminal_scanner terminal_scanner_ticks terminal_fault_marker
  local terminal_config terminal_sample terminal_state terminal_sample_sha
  local terminal_baseline_available terminal_recovery_marker
  local sample_commit_failure_data sample_commit_failure_evidence
  local state_commit_failure_data state_commit_failure_evidence
  local sample_precommit_failure_data sample_precommit_failure_evidence
  local state_precommit_failure_data state_precommit_failure_evidence
  local terminal_fault terminal_fault_data terminal_fault_evidence
  local terminal_fault_index terminal_fault_marker terminal_fault_status
  local -a terminal_before_faults terminal_after_faults

  root=$(mktemp -d "${TMPDIR:-/tmp}/hsrd-full-sync-self-test.XXXXXX")
  chmod 700 -- "$root"
  trap 'self_test_cleanup "$root"' EXIT
  self_test_required_json_booleans "$root"
  self_test_resume_classification_policy "$root"
  self_test_bounded_numeric_options "$root"
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
  synced_zero_binary="$root/fake-synced-zero-hsrd"
  write_fake_binary "$normal_binary" normal
  write_fake_binary "$limit_binary" limit
  write_fake_binary "$reserve_binary" reserve
  write_fake_binary "$long_binary" long
  write_fake_binary "$boundary_binary" boundary
  write_fake_binary "$auth_change_binary" auth-change
  write_fake_binary "$exec_change_binary" exec-change
  write_fake_binary "$synced_nonzero_binary" synced-nonzero
  write_fake_binary "$synced_zero_binary" synced-zero
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
    .observed_process_state.child_alive == false and
    .terminal_verdict.verdict_authoritative == true and
    .terminal_verdict.classification == "node_exit_zero_before_sync" and
    .terminal_verdict.terminal_commit_manifest_path ==
      "attempts/000001-terminal-commit.json"
  ' <<<"$output" >/dev/null ||
    die "self-test status did not authenticate the stopped fixture"
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

  launch_pending_data="$root/launch-pending-data"
  launch_pending_evidence="$root/launch-pending-evidence"
  launch_pending_output="$root/launch-pending-output"
  "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$launch_pending_data" \
    --evidence-dir "$launch_pending_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 30 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19356 >"$launch_pending_output" 2>&1 &
  launch_pending_runner=$!
  ready=false
  for _ in {1..120}; do
    if [[ -f "$launch_pending_evidence/state.json" ]] &&
      jq -e '.attempt == 1 and
        (.status == "starting" or .status == "running")' \
        "$launch_pending_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$launch_pending_runner" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] || {
    wait "$launch_pending_runner" || true
    die "self-test launch-pending fixture did not start"
  }
  "$SCRIPT_PATH" stop --evidence-dir "$launch_pending_evidence" >/dev/null
  set +e
  wait "$launch_pending_runner"
  rc=$?
  set -e
  [[ "$rc" == 10 ]] ||
    die "self-test launch-pending baseline returned $rc; expected 10"

  HSRD_FULL_SYNC_SELF_TEST_FAULT=pause_after_launch_pending \
    "$SCRIPT_PATH" resume \
      --evidence-dir "$launch_pending_evidence" \
      >"$launch_pending_output" 2>&1 &
  launch_pending_runner=$!
  launch_pending_marker="$launch_pending_evidence/attempts/.self-test-fault-pause_after_launch_pending"
  ready=false
  for _ in {1..120}; do
    if [[ -f "$launch_pending_marker" &&
      -f "$launch_pending_evidence/state.json" ]] &&
      jq -e '
        .attempt == 2 and
        .status == "launch_pending" and
        .launch.phase == "pending" and
        .launch.parent_identity_persisted_before_process_start == true and
        .child.pid == null and
        .log_scanner.pid == null
      ' "$launch_pending_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$launch_pending_runner" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] || {
    wait "$launch_pending_runner" || true
    die "self-test did not reach the durable launch-pending barrier"
  }
  launch_pending_status=$("$SCRIPT_PATH" status \
    --evidence-dir "$launch_pending_evidence")
  jq -e '
    .attempt == 2 and
    .status == "launch_pending" and
    .observed_process_state.runner_alive == true and
    .observed_process_state.child_alive == false and
    .terminal_verdict.verdict_authoritative == false and
    .terminal_verdict.reason ==
      "no_terminal_commit_for_current_runtime_attempt"
  ' <<<"$launch_pending_status" >/dev/null ||
    die "self-test retained stale terminal authority after launch intent"
  launch_pending_lock="$launch_pending_evidence/runner.lock"
  if flock -n "$launch_pending_lock" true; then
    die "self-test launch-pending runner did not hold the campaign lock"
  fi
  kill -KILL "$launch_pending_runner"
  set +e
  wait "$launch_pending_runner"
  rc=$?
  set -e
  [[ "$rc" == 137 ]] ||
    die "self-test could not interrupt the launch-pending fixture"
  ready=false
  for _ in {1..80}; do
    if flock -n "$launch_pending_lock" true; then
      ready=true
      break
    fi
    sleep 0.05
  done
  [[ "$ready" == true ]] ||
    die "self-test launch-pending lock survived supervisor death"

  "$SCRIPT_PATH" resume --evidence-dir "$launch_pending_evidence" \
    >"$launch_pending_output" 2>&1 &
  launch_pending_runner=$!
  ready=false
  for _ in {1..120}; do
    if jq -e '.attempt == 3 and
      (.status == "starting" or .status == "running")' \
      "$launch_pending_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$launch_pending_runner" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] || {
    wait "$launch_pending_runner" || true
    die "self-test reused rather than consumed a launch-pending attempt"
  }
  "$SCRIPT_PATH" stop --evidence-dir "$launch_pending_evidence" >/dev/null
  set +e
  wait "$launch_pending_runner"
  rc=$?
  set -e
  [[ "$rc" == 10 ]] ||
    die "self-test post-launch-pending recovery returned $rc; expected 10"

  lock_attack_target="$root/runner-lock-symlink-target"
  printf '%s\n' 'self-test lock target must remain unchanged' >"$lock_attack_target"
  chmod 640 -- "$lock_attack_target"
  lock_attack_target_sha=$(sha256sum -- "$lock_attack_target" | awk '{print $1}')
  lock_attack_target_mode=$(stat -c '%a' -- "$lock_attack_target")
  lock_attack_state_sha=$(sha256sum -- \
    "$launch_pending_evidence/state.json" | awk '{print $1}')
  lock_attack_summary_sha=$(sha256sum -- \
    "$launch_pending_evidence/final-summary.json" | awk '{print $1}')
  rm -f -- "$launch_pending_lock"
  lock_hardlink_target="$root/runner-lock-hardlink-target"
  printf '%s\n' 'self-test hard-link target must remain unchanged' \
    >"$lock_hardlink_target"
  chmod 600 -- "$lock_hardlink_target"
  lock_hardlink_sha=$(sha256sum -- "$lock_hardlink_target" | awk '{print $1}')
  ln -- "$lock_hardlink_target" "$launch_pending_lock"
  set +e
  output=$(timeout --signal=KILL 3s \
    "$SCRIPT_PATH" resume --evidence-dir "$launch_pending_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"could not establish the campaign runner lock"* ]] ||
    die "self-test did not reject a hard-linked runner lock without blocking"
  [[ "$(sha256sum -- "$lock_hardlink_target" | awk '{print $1}')" == \
      "$lock_hardlink_sha" &&
    "$(stat -c '%a:%h' -- "$lock_hardlink_target")" == "600:2" ]] ||
    die "self-test hard-linked runner lock changed its target"
  [[ "$(sha256sum -- "$launch_pending_evidence/state.json" | awk '{print $1}')" == \
      "$lock_attack_state_sha" &&
    "$(sha256sum -- "$launch_pending_evidence/final-summary.json" | awk '{print $1}')" == \
      "$lock_attack_summary_sha" ]] ||
    die "self-test hard-linked runner lock changed terminal campaign evidence"
  rm -f -- "$launch_pending_lock"

  ln -s -- "$lock_attack_target" "$launch_pending_lock"
  set +e
  output=$(timeout --signal=KILL 3s \
    "$SCRIPT_PATH" resume --evidence-dir "$launch_pending_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"could not establish the campaign runner lock"* ]] ||
    die "self-test did not reject a symbolic-link runner lock without blocking"
  [[ -L "$launch_pending_lock" &&
    "$(sha256sum -- "$lock_attack_target" | awk '{print $1}')" == \
      "$lock_attack_target_sha" &&
    "$(stat -c '%a' -- "$lock_attack_target")" == "$lock_attack_target_mode" ]] ||
    die "self-test symbolic-link runner lock changed its target"
  [[ "$(sha256sum -- "$launch_pending_evidence/state.json" | awk '{print $1}')" == \
      "$lock_attack_state_sha" &&
    "$(sha256sum -- "$launch_pending_evidence/final-summary.json" | awk '{print $1}')" == \
      "$lock_attack_summary_sha" ]] ||
    die "self-test unsafe runner lock changed terminal campaign evidence"

  rm -f -- "$launch_pending_lock"
  mkfifo -m 600 -- "$launch_pending_lock"
  set +e
  output=$(timeout --signal=KILL 3s \
    "$SCRIPT_PATH" resume --evidence-dir "$launch_pending_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"could not establish the campaign runner lock"* &&
    -p "$launch_pending_lock" ]] ||
    die "self-test did not reject a FIFO runner lock without blocking"
  [[ "$(sha256sum -- "$launch_pending_evidence/state.json" | awk '{print $1}')" == \
      "$lock_attack_state_sha" &&
    "$(sha256sum -- "$launch_pending_evidence/final-summary.json" | awk '{print $1}')" == \
      "$lock_attack_summary_sha" ]] ||
    die "self-test FIFO runner lock changed terminal campaign evidence"
  rm -f -- "$launch_pending_lock"
  : >"$launch_pending_lock"
  chmod 600 -- "$launch_pending_lock"

  terminal_before_faults=(
    fail_final_attempt_logs_manifest_before_install
    fail_final_logs_manifest_before_install
    fail_final_summary_before_install
    fail_attempt_summary_before_install
    fail_final_state_before_install
    fail_final_attempt_state_before_install
    fail_terminal_commit_before_install
  )
  terminal_after_faults=(
    fail_final_attempt_logs_manifest_after_install
    fail_final_logs_manifest_after_install
    fail_final_summary_after_install
    fail_attempt_summary_after_install
    fail_final_state_after_install
    fail_final_attempt_state_after_install
    fail_terminal_commit_after_install
  )
  for terminal_fault_index in "${!terminal_before_faults[@]}"; do
    terminal_fault=${terminal_before_faults[$terminal_fault_index]}
    terminal_fault_data="$root/$terminal_fault-data"
    terminal_fault_evidence="$root/$terminal_fault-evidence"
    set +e
    output=$(HSRD_FULL_SYNC_SELF_TEST_FAULT="$terminal_fault" \
      "$SCRIPT_PATH" run \
        --self-test-allow-interpreter-image \
        --binary "$normal_binary" \
        --data-root "$terminal_fault_data" \
        --evidence-dir "$terminal_fault_evidence" \
        --auth-file "$auth" \
        --limit-bytes 500000000 \
        --filesystem-reserve-bytes 0 \
        --sample-seconds 1 \
        --completion-samples 1 \
        --shutdown-grace-seconds 3 \
        --rpc-port "$((19400 + terminal_fault_index))" 2>&1)
    rc=$?
    set -e
    printf -v terminal_fault_marker \
      '%s/attempts/%06d-terminal-commit.json' "$terminal_fault_evidence" 1
    [[ "$rc" == 2 && ! -e "$terminal_fault_marker" ]] ||
      die "self-test published authority after $terminal_fault: rc=$rc output=$output"
    terminal_fault_status=$(
      "$SCRIPT_PATH" status --evidence-dir "$terminal_fault_evidence"
    )
    jq -e '.terminal_verdict.verdict_authoritative == false' \
      <<<"$terminal_fault_status" >/dev/null ||
      die "self-test status trusted an incomplete terminal bundle after $terminal_fault"
    if [[ "$terminal_fault" == \
      fail_final_attempt_logs_manifest_before_install ]]; then
      set +e
      output=$("$SCRIPT_PATH" resume \
        --evidence-dir "$terminal_fault_evidence" 2>&1)
      rc=$?
      set -e
      [[ "$rc" == 11 &&
        "$(jq -r '.final_attempt' \
          "$terminal_fault_evidence/final-summary.json")" == 2 ]] ||
        die "self-test could not safely recover before the first terminal artifact: $output"
      continue
    fi
    set +e
    output=$(
      "$SCRIPT_PATH" resume --evidence-dir "$terminal_fault_evidence" 2>&1
    )
    rc=$?
    set -e
    [[ "$rc" == 2 &&
      ( "$output" == *"uncommitted"* || "$output" == *"incomplete terminal"* ) ]] ||
      die "self-test resumed an incomplete terminal bundle after $terminal_fault: $output"
  done
  for terminal_fault_index in "${!terminal_after_faults[@]}"; do
    terminal_fault=${terminal_after_faults[$terminal_fault_index]}
    terminal_fault_data="$root/$terminal_fault-data"
    terminal_fault_evidence="$root/$terminal_fault-evidence"
    set +e
    output=$(HSRD_FULL_SYNC_SELF_TEST_FAULT="$terminal_fault" \
      "$SCRIPT_PATH" run \
        --self-test-allow-interpreter-image \
        --binary "$normal_binary" \
        --data-root "$terminal_fault_data" \
        --evidence-dir "$terminal_fault_evidence" \
        --auth-file "$auth" \
        --limit-bytes 500000000 \
        --filesystem-reserve-bytes 0 \
        --sample-seconds 1 \
        --completion-samples 1 \
        --shutdown-grace-seconds 3 \
        --rpc-port "$((19410 + terminal_fault_index))" 2>&1)
    rc=$?
    set -e
    printf -v terminal_fault_marker \
      '%s/attempts/%06d-terminal-commit.json' "$terminal_fault_evidence" 1
    [[ "$rc" == 11 && -f "$terminal_fault_marker" ]] ||
      die "self-test did not adopt exact terminal artifact after $terminal_fault: rc=$rc output=$output"
    terminal_fault_status=$(
      "$SCRIPT_PATH" status --evidence-dir "$terminal_fault_evidence"
    )
    jq -e '
      .terminal_verdict.verdict_authoritative == true and
      .terminal_verdict.classification == "node_exit_zero_before_sync"
    ' <<<"$terminal_fault_status" >/dev/null ||
      die "self-test did not authenticate adopted terminal bundle after $terminal_fault"
  done
  hostile_temp=$(mktemp "$terminal_fault_evidence/.summary-hostile.XXXXXX")
  jq '.qualification_status = "forged-complete"' \
    "$terminal_fault_evidence/final-summary.json" >"$hostile_temp"
  atomic_install "$hostile_temp" "$terminal_fault_evidence/final-summary.json"
  terminal_fault_status=$(
    "$SCRIPT_PATH" status --evidence-dir "$terminal_fault_evidence"
  )
  jq -e '.terminal_verdict.verdict_authoritative == false' \
    <<<"$terminal_fault_status" >/dev/null ||
    die "self-test trusted a terminal summary that differed from its commit manifest"
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir "$terminal_fault_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"bound artifacts is invalid"* ]] ||
    die "self-test resumed a tampered committed terminal bundle: $output"

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
  HSRD_FULL_SYNC_SELF_TEST_FAULT=pause_after_sample_commit \
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
  orphan_fault_marker="$orphan_evidence/attempts/.self-test-fault-pause_after_sample_commit"
  ready=false
  for _ in {1..120}; do
    if [[ -f "$orphan_fault_marker" &&
      -f "$orphan_evidence/state.json" &&
      -f "$orphan_evidence/samples/000000001.json" ]] &&
      jq -e '.status == "starting" and .sample_sequence == 0' \
        "$orphan_evidence/state.json" >/dev/null 2>&1 &&
      jq -e '.sequence == 1 and .post_sample_decision == "continue"' \
        "$orphan_evidence/samples/000000001.json" >/dev/null 2>&1; then
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
    die "self-test did not reach the durable-sample-before-state fault barrier"
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
    ( "$output" == *"campaign runner is already active"* ||
      "$output" == *"recorded campaign runner is still live"* ) ]] ||
    die "self-test resume did not reject the exact live runner"

  orphan_child=$(jq -er '.child.pid' "$orphan_evidence/state.json")
  orphan_child_ticks=$(jq -er '.child.start_ticks' "$orphan_evidence/state.json")
  orphan_scanner=$(jq -er '.log_scanner.pid' "$orphan_evidence/state.json")
  orphan_scanner_ticks=$(jq -er \
    '.log_scanner.start_ticks' "$orphan_evidence/state.json")
  orphan_lock="$orphan_evidence/runner.lock"
  if flock -n "$orphan_lock" true; then
    die "self-test runner lock was not held by the live supervisor"
  fi
  process_holds_open_path "$orphan_child" "$orphan_lock" &&
    die "self-test hsrd child inherited the supervisor lock"
  process_holds_open_path "$orphan_scanner" "$orphan_lock" &&
    die "self-test log scanner inherited the supervisor lock"
  kill -KILL "$orphan_runner"
  set +e
  wait "$orphan_runner"
  rc=$?
  set -e
  [[ "$rc" == 137 ]] ||
    die "self-test could not create an interrupted-runner orphan fixture"
  ready=false
  for _ in {1..80}; do
    if flock -n "$orphan_lock" true; then
      ready=true
      break
    fi
    sleep 0.05
  done
  [[ "$ready" == true ]] ||
    die "self-test supervisor lock survived abrupt runner loss"
  ready=false
  for _ in {1..80}; do
    if ! process_identity_is_live "$orphan_scanner" "$orphan_scanner_ticks" &&
      ! process_identity_is_live "$orphan_child" "$orphan_child_ticks"; then
      ready=true
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] ||
    die "self-test supervisor death did not kill its scanner and hsrd child"
  [[ -s "$orphan_evidence/logs/.hsrd-log-partial" ]] ||
    die "self-test parent-death cascade did not preserve a recoverable partial log"

  orphan_sample="$orphan_evidence/samples/000000001.json"
  orphan_sample_backup="$root/orphan-sample-original.json"
  cp --reflink=auto -- "$orphan_sample" "$orphan_sample_backup"
  chmod 600 -- "$orphan_sample_backup"
  orphan_sample_sha=$(sha256sum -- "$orphan_sample" | awk '{print $1}')
  orphan_state="$orphan_evidence/state.json"
  orphan_state_backup="$root/orphan-state-original.json"
  cp --reflink=auto -- "$orphan_state" "$orphan_state_backup"
  chmod 600 -- "$orphan_state_backup"

  orphan_config="$orphan_evidence/campaign-config.json"
  orphan_config_backup="$root/orphan-config-original.json"
  orphan_config_digest_backup="$root/orphan-config-original.sha256"
  cp --reflink=auto -- "$orphan_config" "$orphan_config_backup"
  cp --reflink=auto -- "$orphan_evidence/campaign-config.sha256" \
    "$orphan_config_digest_backup"
  chmod 600 -- "$orphan_config_backup" "$orphan_config_digest_backup"
  hostile_temp=$(mktemp "$orphan_evidence/.config-hostile.XXXXXX")
  jq '.measurement.initial_filesystem_used_bytes = "0"' \
    "$orphan_config_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_config"
  atomic_write_text "$orphan_evidence/campaign-config.sha256" \
    "$(sha256sum -- "$orphan_config" | awk '{print $1}')  campaign-config.json"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$hostile_output" == *"initial filesystem used bytes are missing or invalid"* ]] ||
    die "self-test accepted a string initial filesystem baseline: $hostile_output"
  hostile_temp=$(mktemp "$orphan_evidence/.config-hostile.XXXXXX")
  cp --reflink=auto -- "$orphan_config_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_config"
  hostile_temp=$(mktemp "$orphan_evidence/.config-digest.XXXXXX")
  cp --reflink=auto -- "$orphan_config_digest_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_evidence/campaign-config.sha256"

  hostile_state_paths=(
    attempt
    sample_sequence
    observed_maxima.kernel_process_vm_hwm_bytes
    observed_maxima.sampled_data_root_apparent_bytes
    observed_maxima.sampled_data_root_allocated_bytes
    observed_maxima.sampled_filesystem_used_delta_bytes
    observed_maxima.sampled_storage_maximum_bytes
    minimum_sampled_filesystem_available_bytes
  )
  for hostile_state_path in "${hostile_state_paths[@]}"; do
    hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
    jq --arg path "$hostile_state_path" '
      setpath($path | split("."); "0")
    ' "$orphan_state_backup" >"$hostile_temp"
    atomic_install "$hostile_temp" "$orphan_state"
    set +e
    hostile_output=$(
      "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
    )
    rc=$?
    set -e
    [[ "$rc" == 2 && "$hostile_output" == *"runtime state"* &&
      "$hostile_output" == *"missing or invalid"* ]] ||
      die "self-test accepted string runtime state field $hostile_state_path: $hostile_output"
  done

  hostile_state_marker="$root/hostile-state-arithmetic-executed"
  hostile_state_payload='BASH_SOURCE[$(touch '"$hostile_state_marker"')0]'
  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  jq --arg payload "$hostile_state_payload" '
    .observed_maxima.sampled_storage_maximum_bytes = $payload
  ' "$orphan_state_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 && ! -e "$hostile_state_marker" ]] ||
    die "self-test evaluated hostile runtime-state arithmetic: $hostile_output"

  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  jq '.observed_maxima.sampled_storage_maximum_bytes = 9000000000000000001' \
    "$orphan_state_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 && "$hostile_output" == *"storage maximum is missing or invalid"* ]] ||
    die "self-test accepted an overflowing runtime-state maximum: $hostile_output"

  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  cp --reflink=auto -- "$orphan_state_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"

  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  jq '.campaign_id = "hostile-other-campaign"' \
    "$orphan_state_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$hostile_output" == *"runtime state does not match the sample journal prefix"* &&
    "$(jq -r '.sample_sequence' "$orphan_state")" == 0 ]] ||
    die "self-test accepted a trailing sample over a mismatched state prefix"
  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  cp --reflink=auto -- "$orphan_state_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"

  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  jq 'del(.sample_commit)' "$orphan_state_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$hostile_output" == *"runtime state does not match the sample journal prefix"* &&
    "$(jq -r '.sample_sequence' "$orphan_state")" == 0 ]] ||
    die "self-test accepted a version-two state without a sample checkpoint"
  hostile_temp=$(mktemp "$orphan_evidence/.state-hostile.XXXXXX")
  cp --reflink=auto -- "$orphan_state_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_state"

  hostile_temp=$(mktemp "$orphan_evidence/samples/.hostile.XXXXXX")
  jq '.campaign_id = "hostile-other-campaign"' \
    "$orphan_sample_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_sample"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 && "$hostile_output" == *"sample journal is invalid"* &&
    "$(jq -r '.sample_sequence' "$orphan_evidence/state.json")" == 0 ]] ||
    die "self-test accepted a trailing sample for another campaign"

  hostile_sample_filters=(
    'del(.post_sample_decision)'
    '.consecutive_synced_samples = 1'
    '.storage.sampled_filesystem_used_delta_bytes += 1'
    '.process.observed_kernel_vm_hwm_bytes = 9000000000000000001'
    '.process.observed_kernel_vm_hwm_bytes = 1.0'
    '.process.observed_kernel_vm_hwm_bytes = 1.0000000000000000001'
  )
  hostile_sample_labels=(
    missing-decision
    inconsistent-sync-counter
    inconsistent-filesystem-delta
    overflowing-integer
    fractional-integer
    near-integral-fraction
  )
  for hostile_index in "${!hostile_sample_filters[@]}"; do
    hostile_temp=$(mktemp "$orphan_evidence/samples/.hostile.XXXXXX")
    jq "${hostile_sample_filters[$hostile_index]}" \
      "$orphan_sample_backup" >"$hostile_temp"
    atomic_install "$hostile_temp" "$orphan_sample"
    set +e
    hostile_output=$(
      "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
    )
    rc=$?
    set -e
    [[ "$rc" == 2 && "$hostile_output" == *"sample journal is invalid"* &&
      "$(jq -r '.sample_sequence' "$orphan_evidence/state.json")" == 0 ]] ||
      die "self-test accepted a trailing sample with ${hostile_sample_labels[$hostile_index]}"
  done

  hostile_temp=$(mktemp "$orphan_evidence/samples/.hostile.XXXXXX")
  cp --reflink=auto -- "$orphan_sample_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_sample"
  hostile_temp=$(mktemp "$orphan_evidence/samples/.hostile.XXXXXX")
  jq '.storage.sampled_cutoff_exceeded = true' \
    "$orphan_sample_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_sample"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 && "$hostile_output" == *"sample journal is invalid"* &&
    "$(jq -r '.sample_sequence' "$orphan_evidence/state.json")" == 0 ]] ||
    die "self-test accepted a trailing sample with forged threshold semantics"

  hostile_temp=$(mktemp "$orphan_evidence/samples/.hostile.XXXXXX")
  cp --reflink=auto -- "$orphan_sample_backup" "$hostile_temp"
  atomic_install "$hostile_temp" "$orphan_sample"
  extra_sample="$orphan_evidence/samples/000000002.json"
  hostile_temp=$(mktemp "$orphan_evidence/samples/.hostile.XXXXXX")
  jq '.sequence = 2' "$orphan_sample_backup" >"$hostile_temp"
  atomic_install "$hostile_temp" "$extra_sample"
  set +e
  hostile_output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$orphan_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$hostile_output" == *"differs from runtime state by more than one"* &&
    "$(jq -r '.sample_sequence' "$orphan_evidence/state.json")" == 0 ]] ||
    die "self-test reconciled more than one trailing durable sample"
  python3 - "$extra_sample" <<'PY'
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.unlink()
descriptor = os.open(
    path.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  [[ "$(sha256sum -- "$orphan_sample" | awk '{print $1}')" == \
    "$orphan_sample_sha" ]] ||
    die "self-test did not restore the canonical trailing sample"

  orphan_resume_output="$root/orphan-resume-output"
  "$SCRIPT_PATH" resume \
    --evidence-dir "$orphan_evidence" >"$orphan_resume_output" 2>&1 &
  orphan_resume_runner=$!
  sample_recovery_marker="$orphan_evidence/attempts/000001-sample-recovery-000000001.json"
  ready=false
  for _ in {1..160}; do
    recovery_marker=$(find "$orphan_evidence/logs" -maxdepth 1 -type f \
      -name 'crash-recovery-*.json' -print | sort | tail -n 1)
    if [[ -f "$orphan_evidence/state.json" ]] &&
      jq -e '.attempt == 2 and
        (.status == "running" or .status == "starting")' \
        "$orphan_evidence/state.json" >/dev/null 2>&1 &&
      [[ -f "$sample_recovery_marker" ]] &&
      jq -e '
        .prior_state_sequence == 0 and
        .recovered_sample_sequence == 1 and
        .post_sample_decision == "continue" and
        .sample_was_deleted == false and
        .recovery_was_fail_closed == true
      ' "$sample_recovery_marker" >/dev/null 2>&1 &&
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
  if [[ "$ready" != true ]]; then
    set +e
    wait "$orphan_resume_runner"
    rc=$?
    set -e
    die "self-test did not recover the abrupt-loss partial log; runner returned $rc: $(sed -n '1,80p' "$orphan_resume_output"); state: $(jq -c '{attempt,status,runner,child,log_scanner}' "$orphan_evidence/state.json" 2>/dev/null || true); summary: $(jq -c '{classification,runner_error,process}' "$orphan_evidence/final-summary.json" 2>/dev/null || true); recovery: $(jq -c . "$recovery_marker" 2>/dev/null || true)"
  fi
  [[ "$(sha256sum -- "$orphan_sample" | awk '{print $1}')" == \
    "$orphan_sample_sha" ]] ||
    die "self-test trailing-sample recovery changed durable sample evidence"
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

  terminal_crash_data="$root/terminal-crash-data"
  terminal_crash_evidence="$root/terminal-crash-evidence"
  terminal_crash_output="$root/terminal-crash-output"
  HSRD_FULL_SYNC_SELF_TEST_FAULT=pause_after_state_commit \
    "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$limit_binary" \
    --data-root "$terminal_crash_data" \
    --evidence-dir "$terminal_crash_evidence" \
    --auth-file "$auth" \
    --limit-bytes 1000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 30 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19348 >"$terminal_crash_output" 2>&1 &
  terminal_crash_runner=$!
  terminal_fault_marker="$terminal_crash_evidence/attempts/.self-test-fault-pause_after_state_commit"
  ready=false
  for _ in {1..160}; do
    if [[ -f "$terminal_fault_marker" &&
      -f "$terminal_crash_evidence/state.json" ]] &&
      jq -e '
        .status == "running" and
        .sample_sequence == 1 and
        .sample_commit.sequence == 1 and
        .sample_commit.decision == "sampled_storage_cutoff_exceeded" and
        .sample_commit.decision_durable_in_sample == true
      ' "$terminal_crash_evidence/state.json" >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$terminal_crash_runner" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] || {
    wait "$terminal_crash_runner" || true
    die "self-test did not reach the state-before-terminal-action fault barrier"
  }
  terminal_child=$(jq -er '.child.pid' "$terminal_crash_evidence/state.json")
  terminal_child_ticks=$(jq -er \
    '.child.start_ticks' "$terminal_crash_evidence/state.json")
  terminal_scanner=$(jq -er \
    '.log_scanner.pid' "$terminal_crash_evidence/state.json")
  terminal_scanner_ticks=$(jq -er \
    '.log_scanner.start_ticks' "$terminal_crash_evidence/state.json")
  kill -KILL "$terminal_crash_runner"
  set +e
  wait "$terminal_crash_runner"
  rc=$?
  set -e
  [[ "$rc" == 137 ]] ||
    die "self-test could not interrupt the post-state terminal fixture"
  ready=false
  for _ in {1..80}; do
    if ! process_identity_is_live "$terminal_scanner" "$terminal_scanner_ticks" &&
      ! process_identity_is_live "$terminal_child" "$terminal_child_ticks"; then
      ready=true
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == true ]] ||
    die "self-test post-state supervisor death left a live child process"
  set +e
  output=$(
    "$SCRIPT_PATH" resume --evidence-dir "$terminal_crash_evidence" 2>&1
  )
  rc=$?
  set -e
  [[ "$rc" == 2 &&
    "$output" == *"non-resumable sampled storage cutoff breach"* &&
    "$(jq -r '.attempt' "$terminal_crash_evidence/state.json")" == 1 &&
    ! -e "$terminal_crash_evidence/logs/check-config-resume-000002.log" ]] ||
    die "self-test resumed after a durably recorded terminal sample decision: $output"

  terminal_config="$terminal_crash_evidence/campaign-config.json"
  terminal_sample="$terminal_crash_evidence/samples/000000001.json"
  terminal_state="$terminal_crash_evidence/state.json"
  terminal_baseline_available=$(jq -er \
    '.measurement.initial_filesystem_available_bytes' "$terminal_config")
  hostile_temp=$(mktemp "$terminal_crash_evidence/.config-hostile.XXXXXX")
  jq '
    .measurement.sampled_cutoff_bytes = 500000000 |
    .measurement.filesystem_reserve_bytes = 1
  ' "$terminal_config" >"$hostile_temp"
  atomic_install "$hostile_temp" "$terminal_config"
  atomic_write_text "$terminal_crash_evidence/campaign-config.sha256" \
    "$(sha256sum -- "$terminal_config" | awk '{print $1}')  campaign-config.json"

  hostile_temp=$(mktemp "$terminal_crash_evidence/samples/.hostile.XXXXXX")
  jq '
    .storage.sampled_filesystem_available_bytes = 0 |
    .storage.sampled_cutoff_bytes = 500000000 |
    .storage.sampled_cutoff_exceeded = false |
    .storage.filesystem_reserve_bytes = 1 |
    .storage.sampled_filesystem_reserve_breached = true |
    .post_sample_decision = "sampled_filesystem_reserve_breached"
  ' "$terminal_sample" >"$hostile_temp"
  atomic_install "$hostile_temp" "$terminal_sample"
  terminal_sample_sha=$(sha256sum -- "$terminal_sample" | awk '{print $1}')

  hostile_temp=$(mktemp "$terminal_crash_evidence/.state-hostile.XXXXXX")
  jq --argjson baseline_available "$terminal_baseline_available" '
    .status = "starting" |
    .sample_sequence = 0 |
    .sample_commit = null |
    .current.observed_kernel_vm_hwm_bytes = 0 |
    .current.sampled_data_root_apparent_bytes = 0 |
    .current.sampled_data_root_allocated_bytes = 0 |
    .current.sampled_filesystem_used_delta_bytes = 0 |
    .current.sampled_storage_maximum_bytes = 0 |
    .current.sampled_filesystem_available_bytes = $baseline_available |
    .current.filesystem_reserve_respected = true |
    .observed_maxima.kernel_process_vm_hwm_bytes = 0 |
    .observed_maxima.sampled_data_root_apparent_bytes = 0 |
    .observed_maxima.sampled_data_root_allocated_bytes = 0 |
    .observed_maxima.sampled_filesystem_used_delta_bytes = 0 |
    .observed_maxima.sampled_storage_maximum_bytes = 0 |
    .minimum_sampled_filesystem_available_bytes = $baseline_available |
    .sampled_cutoff_bytes = 500000000 |
    .filesystem_reserve_bytes = 1 |
    .filesystem_reserve_currently_respected = true |
    .consecutive_synced_samples = 0 |
    .sync = null
  ' "$terminal_state" >"$hostile_temp"
  atomic_install "$hostile_temp" "$terminal_state"
  terminal_recovery_marker="$terminal_crash_evidence/attempts/000001-sample-recovery-000000001.json"
  for _ in 1 2; do
    set +e
    output=$(
      "$SCRIPT_PATH" resume --evidence-dir "$terminal_crash_evidence" 2>&1
    )
    rc=$?
    set -e
    [[ "$rc" == 2 &&
      "$output" == *"non-resumable sampled filesystem reserve breach"* &&
      "$(jq -r '.attempt' "$terminal_state")" == 1 &&
      ! -e "$terminal_crash_evidence/logs/check-config-resume-000002.log" ]] ||
      die "self-test resumed after an exact-zero sampled reserve breach: $output"
    jq -e --arg sample_sha "$terminal_sample_sha" '
      .status == "interrupted_sample_reconciled" and
      .sample_sequence == 1 and
      .minimum_sampled_filesystem_available_bytes == 0 and
      .sample_commit.sha256 == $sample_sha and
      .sample_commit.decision == "sampled_filesystem_reserve_breached"
    ' "$terminal_state" >/dev/null ||
      die "self-test did not preserve the exact-zero recovered reserve checkpoint"
    [[ -f "$terminal_recovery_marker" ]] ||
      die "self-test did not record exact-zero trailing-sample recovery"
  done

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

  sample_precommit_failure_data="$root/sample-precommit-failure-data"
  sample_precommit_failure_evidence="$root/sample-precommit-failure-evidence"
  set +e
  output=$(HSRD_FULL_SYNC_SELF_TEST_FAULT=fail_sample_commit_before_install \
    "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$sample_precommit_failure_data" \
    --evidence-dir "$sample_precommit_failure_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19349 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test pre-install sample failure returned $rc; expected 14: $output"
  if ! jq -e '
    .classification == "measurement_error" and
    .runner_error == "sample_evidence_commit_failed" and
    .samples.count == 0
  ' "$sample_precommit_failure_evidence/final-summary.json" >/dev/null ||
    ! jq -e '
      .sample_sequence == 0 and
      .sample_commit == null
    ' "$sample_precommit_failure_evidence/state.json" >/dev/null; then
    die "self-test masked a pre-install sample evidence failure"
  fi

  sample_commit_failure_data="$root/sample-commit-failure-data"
  sample_commit_failure_evidence="$root/sample-commit-failure-evidence"
  set +e
  output=$(HSRD_FULL_SYNC_SELF_TEST_FAULT=fail_sample_commit_after_install \
    "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$sample_commit_failure_data" \
    --evidence-dir "$sample_commit_failure_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19350 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test sample-commit failure returned $rc; expected 14: $output"
  if ! jq -e '
    .classification == "measurement_error" and
    .runner_error == "sample_evidence_commit_failed" and
    .samples.count == 1
  ' "$sample_commit_failure_evidence/final-summary.json" >/dev/null ||
    ! jq -e '
      .sample_sequence == 1 and
      .sample_commit.sequence == 1 and
      .sample_commit.decision == "continue" and
      .sample_commit.decision_durable_in_sample == true
    ' "$sample_commit_failure_evidence/state.json" >/dev/null; then
    die "self-test did not reconcile an ambiguous sample evidence commit"
  fi

  state_precommit_failure_data="$root/state-precommit-failure-data"
  state_precommit_failure_evidence="$root/state-precommit-failure-evidence"
  set +e
  output=$(HSRD_FULL_SYNC_SELF_TEST_FAULT=fail_state_commit_before_install \
    "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$state_precommit_failure_data" \
    --evidence-dir "$state_precommit_failure_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19351 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test pre-install state failure returned $rc; expected 14: $output"
  if ! jq -e '
    .classification == "measurement_error" and
    .runner_error == "runtime_state_commit_failed" and
    .samples.count == 1
  ' "$state_precommit_failure_evidence/final-summary.json" >/dev/null ||
    ! jq -e '
      .sample_sequence == 1 and
      .sample_commit.sequence == 1 and
      .sample_commit.decision == "continue" and
      .sample_commit.decision_durable_in_sample == true
    ' "$state_precommit_failure_evidence/state.json" >/dev/null; then
    die "self-test masked a pre-install runtime-state evidence failure"
  fi

  state_commit_failure_data="$root/state-commit-failure-data"
  state_commit_failure_evidence="$root/state-commit-failure-evidence"
  set +e
  output=$(HSRD_FULL_SYNC_SELF_TEST_FAULT=fail_state_commit_after_install \
    "$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$long_binary" \
    --data-root "$state_commit_failure_data" \
    --evidence-dir "$state_commit_failure_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19352 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 14 ]] ||
    die "self-test state-commit failure returned $rc; expected 14: $output"
  if ! jq -e '
    .classification == "measurement_error" and
    .runner_error == "runtime_state_commit_failed" and
    .samples.count == 1
  ' "$state_commit_failure_evidence/final-summary.json" >/dev/null ||
    ! jq -e '
      .sample_sequence == 1 and
      .sample_commit.sequence == 1 and
      .sample_commit.decision == "continue" and
      .sample_commit.decision_durable_in_sample == true
    ' "$state_commit_failure_evidence/state.json" >/dev/null; then
    die "self-test masked a failed runtime-state evidence commit"
  fi

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

  synced_zero_data="$root/synced-zero-data"
  synced_zero_evidence="$root/synced-zero-evidence"
  set +e
  output=$("$SCRIPT_PATH" run \
    --self-test-allow-interpreter-image \
    --binary "$synced_zero_binary" \
    --data-root "$synced_zero_data" \
    --evidence-dir "$synced_zero_evidence" \
    --auth-file "$auth" \
    --limit-bytes 500000000 \
    --filesystem-reserve-bytes 0 \
    --sample-seconds 1 \
    --completion-samples 1 \
    --shutdown-grace-seconds 3 \
    --rpc-port 19355 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 0 ]] ||
    die "self-test synced-zero fixture returned $rc; expected 0: $output"
  jq -e '
    .classification == "sync_completed" and
    .qualification_status == "self_test_only_non_qualification" and
    .process.exit_code == 0 and
    .synchronized_tip.height == 1 and
    .synchronized_tip.hash ==
      "1111111111111111111111111111111111111111111111111111111111111111"
  ' "$synced_zero_evidence/final-summary.json" >/dev/null ||
    die "self-test did not publish the successful synchronized summary"
  output=$("$SCRIPT_PATH" status --evidence-dir "$synced_zero_evidence")
  jq -e '
    .status == "sync_completed" and
    .terminal_verdict.verdict_authoritative == true and
    .terminal_verdict.classification == "sync_completed" and
    .terminal_verdict.qualification_status ==
      "self_test_only_non_qualification"
  ' <<<"$output" >/dev/null ||
    die "self-test did not authenticate the successful synchronized verdict"
  set +e
  output=$("$SCRIPT_PATH" resume --evidence-dir \
    "$synced_zero_evidence" 2>&1)
  rc=$?
  set -e
  [[ "$rc" == 2 && "$output" == *"campaign is already complete"* ]] ||
    die "self-test resumed an authoritative successful campaign: $output"

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
if summary["evidence_scope"]["sample_journal"] != (
    "strict contiguous validation; at most one exact trailing durable sample is "
    "reconciled without deletion, and every recovered or checkpointed operational "
    "threshold remains terminal"
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
    'full-sync runner self-test passed: lifecycle, canonical bounded sync-status and BlockHash normalization, sixteen forced clean-scanner-exit/child-exit race transitions, stale scanner-marker prelaunch rejection, serialized durable launch intent, unsafe lock-path rejection without target mutation or blocking, parent-death child containment, descriptor-pinned verified configuration and runtime process launch, exact one-sample crash reconciliation, bounded typed persisted arithmetic and live measurements, hostile sample-journal rejection, durable post-sample terminal decisions, exact-zero reserve persistence, every bound terminal-artifact pre/post-install phase, last-published terminal verdict manifests, snapshot-bound status authority, successful and nonzero synchronized shutdowns, incomplete/tampered terminal-bundle rejection, abrupt-loss partial recovery, monotonic counter reconciliation, terminal failure masking prevention, single operational sampled cutoff plus informational comparison schema, boundary-safe authorization redaction, durable mutation erasure, exact process-image and exec-change detection, isolated interpreter allowance, sample-limit precedence, durable evidence, path safety, and private authorization'
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
