#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"
RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
PID_FILE="$RUN_DIR/backend-alerts.pid"
LOG_FILE="$LOG_DIR/backend-alerts.log"

mkdir -p "$LOG_DIR" "$RUN_DIR"

PYTHON_BIN="python3"
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif [ -x "$SCRIPT_DIR/.miniforge3/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/.miniforge3/bin/python"
fi

pid_is_running() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

if [ -f "$PID_FILE" ]; then
  PID="$(tr -d '[:space:]' < "$PID_FILE")"
  if [ -n "$PID" ] && pid_is_running "$PID"; then
    echo "[ALERT] Alert watcher already running with pid $PID"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

"$PYTHON_BIN" "$SCRIPT_DIR/backend_alert_watcher.py" >"$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"
echo "[ALERT] Alert watcher started with pid $PID"
