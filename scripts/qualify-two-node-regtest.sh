#!/usr/bin/env sh
set -eu

repo_root=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:-"$repo_root/target/release/hsrd"}
rpc_a=${HNS_NODE_RPC_A:-29337}
rpc_b=${HNS_NODE_RPC_B:-29347}
p2p_a=${HNS_NODE_P2P_A:-29338}
p2p_b=${HNS_NODE_P2P_B:-29348}
expected_fingerprint=95774db08c569b36fa7b7e4a071930f563b7251fc30934ba986732379a6e542d
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/hns-node-two-node.XXXXXX")
node_a_pid=
node_b_pid=

cleanup() {
  if [ -n "$node_b_pid" ]; then
    kill -INT "$node_b_pid" 2>/dev/null || true
    wait "$node_b_pid" 2>/dev/null || true
  fi
  if [ -n "$node_a_pid" ]; then
    kill -INT "$node_a_pid" 2>/dev/null || true
    wait "$node_a_pid" 2>/dev/null || true
  fi
  find "$run_dir" -depth -delete
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ ! -x "$binary" ]; then
  echo "missing executable hsrd binary: $binary" >&2
  exit 1
fi

"$binary" \
  --network regtest \
  --data-dir "$run_dir/node-a" \
  --rpc-bind "127.0.0.1:$rpc_a" \
  --authority-mode native \
  --native-sync \
  --native-sync-headers-only \
  --p2p-listen "127.0.0.1:$p2p_a" \
  --maximum-inbound 4 \
  --maximum-outbound 4 \
  >"$run_dir/node-a.log" 2>&1 &
node_a_pid=$!

attempt=0
while ! curl --fail --silent --show-error \
  "http://127.0.0.1:$rpc_a/api/v1/native-sync" \
  >"$run_dir/node-a.json" 2>/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "node A did not expose diagnostics" >&2
    tail -100 "$run_dir/node-a.log" >&2
    exit 1
  fi
  sleep 1
done

"$binary" \
  --network regtest \
  --data-dir "$run_dir/node-b" \
  --rpc-bind "127.0.0.1:$rpc_b" \
  --authority-mode native \
  --native-sync \
  --native-sync-headers-only \
  --p2p-listen "127.0.0.1:$p2p_b" \
  --connect "127.0.0.1:$p2p_a" \
  --maximum-inbound 4 \
  --maximum-outbound 4 \
  >"$run_dir/node-b.log" 2>&1 &
node_b_pid=$!

attempt=0
while :; do
  curl --fail --silent --show-error \
    "http://127.0.0.1:$rpc_a/api/v1/native-sync" \
    >"$run_dir/node-a.json" 2>/dev/null || true
  curl --fail --silent --show-error \
    "http://127.0.0.1:$rpc_b/api/v1/native-sync" \
    >"$run_dir/node-b.json" 2>/dev/null || true

  if python3 - "$run_dir/node-a.json" "$run_dir/node-b.json" \
    "$expected_fingerprint" <<'PY'
import json
from pathlib import Path
import sys

try:
    nodes = [json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:3]]
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)

expected = sys.argv[3]
for node in nodes:
    peers = node.get("peers", [])
    registry = node.get("experimental_registry", {})
    if (
        len(peers) != 1
        or peers[0].get("state") != "ready"
        or peers[0].get("transport") != "plaintext"
        or peers[0].get("denuo", {}).get("phase") != "negotiated"
        or peers[0].get("denuo", {}).get("negotiated") is None
        or registry.get("fingerprint") != expected
        or registry.get("registry_id") != expected
        or registry.get("negotiated_peers") != 1
        or node.get("bytes_sent", 0) <= 0
        or node.get("bytes_received", 0) <= 0
    ):
        raise SystemExit(1)
PY
  then
    break
  fi

  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "two-node standard/registry negotiation did not become ready" >&2
    tail -100 "$run_dir/node-a.log" >&2
    tail -100 "$run_dir/node-b.log" >&2
    exit 1
  fi
  sleep 1
done

python3 - "$run_dir/node-a.json" "$run_dir/node-b.json" <<'PY'
import json
from pathlib import Path
import sys

summary = {}
for name, path in zip(("node_a", "node_b"), sys.argv[1:]):
    node = json.loads(Path(path).read_text(encoding="utf-8"))
    peer = node["peers"][0]
    registry = node["experimental_registry"]
    summary[name] = {
        "enabled": node["enabled"],
        "headers_only": node["headers_only"],
        "peer_count": len(node["peers"]),
        "peer_state": peer["state"],
        "transport": peer["transport"],
        "denuo_phase": peer["denuo"]["phase"],
        "registry_fingerprint": registry["fingerprint"],
        "registry_negotiated_peers": registry["negotiated_peers"],
        "bytes_sent": node["bytes_sent"],
        "bytes_received": node["bytes_received"],
    }
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "two full-node regtest processes completed standard P2P and matching-registry negotiation"
