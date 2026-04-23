#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE_PATH="${1:-}"
TARGET_DIR="${TARGET_DIR:-$HOME/Backend-Shopee-Software}"

if [ -z "$ARCHIVE_PATH" ] || [ ! -f "$ARCHIVE_PATH" ]; then
  echo "[RESTORE] Usage: bash restore_backend_vps.sh /abs/path/backend-backup-YYYYMMDD-HHMMSS.tar.gz"
  exit 1
fi

WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

tar -xzf "$ARCHIVE_PATH" -C "$WORK_DIR"

if [ ! -f "$WORK_DIR/repo.tar.gz" ] || [ ! -f "$WORK_DIR/manifest.json" ] || [ ! -f "$WORK_DIR/.env" ]; then
  echo "[RESTORE] Invalid backup archive"
  exit 1
fi

mkdir -p "$TARGET_DIR"
tar -xzf "$WORK_DIR/repo.tar.gz" -C "$TARGET_DIR"
cp "$WORK_DIR/.env" "$TARGET_DIR/.env"

cd "$TARGET_DIR"

bash "$TARGET_DIR/bootstrap_backend_vps.sh"

if [ -f "$TARGET_DIR/run/backend.pid" ]; then
  kill "$(cat "$TARGET_DIR/run/backend.pid")" 2>/dev/null || true
  sleep 2
fi

set -a
# shellcheck disable=SC1091
source "$TARGET_DIR/.env"
set +a

python_bin="python3"
if [ -x "$TARGET_DIR/.venv/bin/python" ]; then
  python_bin="$TARGET_DIR/.venv/bin/python"
elif [ -x "$TARGET_DIR/.miniforge3/bin/python" ]; then
  python_bin="$TARGET_DIR/.miniforge3/bin/python"
fi

db_mode="$(
"$python_bin" - <<PY
import json
from pathlib import Path
payload = json.loads(Path(r"$WORK_DIR/manifest.json").read_text(encoding="utf-8"))
print(payload.get("database_mode", "unknown"))
PY
)"

if [[ "$db_mode" == "postgres" ]]; then
  if ! command -v psql >/dev/null 2>&1; then
    echo "[RESTORE] psql not found. Install PostgreSQL client tools first."
    exit 1
  fi
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$WORK_DIR/postgres.sql"
elif [[ "$db_mode" == "sqlite" ]]; then
  sqlite_path="${DATABASE_URL#sqlite:///}"
  cp "$WORK_DIR/sql_app.db" "$sqlite_path"
else
  echo "[RESTORE] Unsupported database mode: $db_mode"
  exit 1
fi

bash "$TARGET_DIR/start_backend_vps.sh"

echo "[RESTORE] Restore completed into $TARGET_DIR"
