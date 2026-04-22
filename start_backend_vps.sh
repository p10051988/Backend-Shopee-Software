#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-.venv}"
GO_DIR="${GO_DIR:-$SCRIPT_DIR/.go}"
BACKEND_BIN="${BACKEND_BIN:-$SCRIPT_DIR/bin/backendgo}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"

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
BACKEND_LOG="$LOG_DIR/backend.log"
SIDECAR_PID_FILE="$RUN_DIR/sidecar.pid"
BACKEND_PID_FILE="$RUN_DIR/backend.pid"

pid_is_running() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

read_pid_file() {
  local file="$1"
  if [ -f "$file" ]; then
    tr -d '[:space:]' < "$file"
  fi
}

cleanup_stale_pid() {
  local file="$1"
  local pid
  pid="$(read_pid_file "$file")"
  if [ -n "$pid" ] && ! pid_is_running "$pid"; then
    rm -f "$file"
  fi
}

cleanup_stale_pid "$SIDECAR_PID_FILE"
cleanup_stale_pid "$BACKEND_PID_FILE"

SIDECAR_PID="$(read_pid_file "$SIDECAR_PID_FILE")"
if [ -n "$SIDECAR_PID" ] && pid_is_running "$SIDECAR_PID"; then
  echo "[START] Sidecar already running with pid $SIDECAR_PID"
else
  "$VENV_DIR/bin/python" BackendGo/sidecar.py >"$SIDECAR_LOG" 2>&1 &
  SIDECAR_PID=$!
  echo "$SIDECAR_PID" > "$SIDECAR_PID_FILE"
fi

for _ in $(seq 1 30); do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "http://${SIDECAR_HOST}:${SIDECAR_PORT}/health" >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 1
done

BACKEND_PID="$(read_pid_file "$BACKEND_PID_FILE")"
if [ -n "$BACKEND_PID" ] && pid_is_running "$BACKEND_PID"; then
  echo "[START] Backend already running with pid $BACKEND_PID"
else
  "$BACKEND_BIN" >"$BACKEND_LOG" 2>&1 &
  BACKEND_PID=$!
  echo "$BACKEND_PID" > "$BACKEND_PID_FILE"
fi

for _ in $(seq 1 30); do
  if ! pid_is_running "$BACKEND_PID"; then
    echo "[START] Backend process exited unexpectedly. Last logs:"
    tail -n 80 "$BACKEND_LOG" 2>/dev/null || true
    exit 1
  fi
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "http://${BACKEND_HOST}:${BACKEND_PORT}/api/public/health" >/dev/null 2>&1; then
      echo "[START] Backend running on http://${BACKEND_HOST}:${BACKEND_PORT} (pid $BACKEND_PID)"
      exit 0
    fi
  else
    sleep 2
    echo "[START] Backend process started with pid $BACKEND_PID"
    exit 0
  fi
  sleep 1
done

echo "[START] Backend process started but health endpoint did not become ready in time."
echo "[START] Check logs:"
echo "  tail -n 80 $SIDECAR_LOG"
echo "  tail -n 80 $BACKEND_LOG"
exit 1
