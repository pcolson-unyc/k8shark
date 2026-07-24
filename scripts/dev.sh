#!/usr/bin/env bash
# Local dev harness: runs the hub (serving the built UI) plus a demo worker, so
# the whole app is reachable at http://localhost:8898 without a cluster.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=${BIN:-bin/k8shark}
PORT=${PORT:-8898}

if [[ ! -d ui/dist ]]; then
  echo "ui/dist missing — run 'make ui' first" >&2
  exit 1
fi

echo "starting hub on :$PORT (serving ui/dist) + demo worker"
"$BIN" hub --serve-ui ui/dist --port "$PORT" &
HUB=$!
sleep 1
"$BIN" worker --hub "ws://localhost:$PORT/ws/worker" --node dev-node --node-ip 127.0.0.1 --demo --demo-rps 40 &
WK=$!

trap 'kill $HUB $WK 2>/dev/null || true' EXIT INT TERM
echo "→ open http://localhost:$PORT   (Ctrl-C to stop)"
wait
