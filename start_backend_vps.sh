#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-.venv}"
GO_DIR="${GO_DIR:-$SCRIPT_DIR/.go}"
BACKEND_BIN="${BACKEND_BIN:-$SCRIPT_DIR/bin/backendgo}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"

if [ ! -d "$VENV_DIR" ]; then
  echo "[START] Missing $VENV_DIR. Run: bash bootstrap_backend_vps.sh"
  exit 1
fi

if [ ! -f ".env" ]; then
  echo "[START] Missing .env. Run: bash bootstrap_backend_vps.sh"
  exit 1
fi

if [ ! -x "$BACKEND_BIN" ]; then
  echo "[START] Missing backend binary. Run: bash bootstrap_backend_vps.sh"
  exit 1
fi

mkdir -p "$LOG_DIR" "$RUN_DIR"

set -a
# shellcheck disable=SC1091
source ".env"
set +a

SIDECAR_HOST="${BACKEND_PY_SIDECAR_HOST:-127.0.0.1}"
SIDECAR_PORT="${BACKEND_PY_SIDECAR_PORT:-9801}"
SIDECAR_LOG="$LOG_DIR/sidecar.log"

"$VENV_DIR/bin/python" BackendGo/sidecar.py >"$SIDECAR_LOG" 2>&1 &
SIDECAR_PID=$!
echo "$SIDECAR_PID" > "$RUN_DIR/sidecar.pid"

cleanup() {
  kill "$SIDECAR_PID" >/dev/null 2>&1 || true
  rm -f "$RUN_DIR/sidecar.pid"
}

trap cleanup EXIT INT TERM

for _ in $(seq 1 30); do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "http://${SIDECAR_HOST}:${SIDECAR_PORT}/health" >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 1
done

"$BACKEND_BIN"
