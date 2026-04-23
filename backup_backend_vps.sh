#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f ".env" ]; then
  echo "[BACKUP] Missing .env in $SCRIPT_DIR"
  exit 1
fi

set -a
# shellcheck disable=SC1091
source ".env"
set +a

BACKUP_ROOT="${BACKUP_ROOT:-$SCRIPT_DIR/backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK_DIR="$BACKUP_ROOT/backup-$STAMP"
ARCHIVE_PATH="$BACKUP_ROOT/backend-backup-$STAMP.tar.gz"
MANIFEST_PATH="$WORK_DIR/manifest.json"

mkdir -p "$WORK_DIR"

db_mode="unknown"
db_payload_path=""

if [[ "${DATABASE_URL:-}" == postgresql://* || "${DATABASE_URL:-}" == postgres://* ]]; then
  db_mode="postgres"
  if ! command -v pg_dump >/dev/null 2>&1; then
    echo "[BACKUP] pg_dump not found. Install PostgreSQL client tools first."
    exit 1
  fi
  db_payload_path="$WORK_DIR/postgres.sql"
  pg_dump \
    --dbname="$DATABASE_URL" \
    --no-owner \
    --no-privileges \
    --format=plain \
    --encoding=UTF8 \
    --file="$db_payload_path"
elif [[ "${DATABASE_URL:-}" == sqlite:///* ]]; then
  db_mode="sqlite"
  sqlite_path="${DATABASE_URL#sqlite:///}"
  if [ ! -f "$sqlite_path" ]; then
    echo "[BACKUP] SQLite file not found: $sqlite_path"
    exit 1
  fi
  db_payload_path="$WORK_DIR/sql_app.db"
  cp "$sqlite_path" "$db_payload_path"
else
  echo "[BACKUP] Unsupported DATABASE_URL: ${DATABASE_URL:-}"
  exit 1
fi

cp ".env" "$WORK_DIR/.env"

python_bin="python3"
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  python_bin="$SCRIPT_DIR/.venv/bin/python"
elif [ -x "$SCRIPT_DIR/.miniforge3/bin/python" ]; then
  python_bin="$SCRIPT_DIR/.miniforge3/bin/python"
fi

git_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

"$python_bin" - <<PY
import json
from pathlib import Path

payload = {
    "schema": 1,
    "created_at": "${STAMP}",
    "database_mode": "${db_mode}",
    "database_payload": "$(basename "$db_payload_path")",
    "git_commit": "${git_commit}",
}
Path(r"${MANIFEST_PATH}").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
PY

tar \
  --exclude=".git" \
  --exclude=".venv" \
  --exclude=".go" \
  --exclude="backups" \
  --exclude="logs" \
  --exclude="run" \
  --exclude="BackendGo/cache" \
  -czf "$WORK_DIR/repo.tar.gz" \
  .

tar -czf "$ARCHIVE_PATH" -C "$WORK_DIR" .

echo "[BACKUP] Backup created: $ARCHIVE_PATH"
