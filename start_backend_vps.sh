#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
  echo "[START] Missing .venv. Run: bash bootstrap_backend_vps.sh"
  exit 1
fi

if [ ! -f ".env" ]; then
  echo "[START] Missing .env. Run: bash bootstrap_backend_vps.sh"
  exit 1
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"
export BACKEND_BIND="${BACKEND_BIND:-0.0.0.0:${PORT:-8000}}"
exec gunicorn -c gunicorn.conf.py Backend.main:app
