#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
PORT="${PORT:-8000}"
VENV_DIR="${VENV_DIR:-.venv}"
DATABASE_MODE="${DATABASE_MODE:-sqlite}"
POSTGRES_DB="${POSTGRES_DB:-autoshopee}"
POSTGRES_USER="${POSTGRES_USER:-autoshopee}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
MINIFORGE_DIR="${MINIFORGE_DIR:-$SCRIPT_DIR/.miniforge3}"
MINIFORGE_RELEASE="${MINIFORGE_RELEASE:-25.11.0-1}"

log() {
  echo "[BOOTSTRAP] $*"
}

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return
  fi
  log "Need root/sudo to run: $*"
  return 1
}

apt_install() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 1
  fi
  run_as_root apt-get update -y
  run_as_root apt-get install -y "$@"
}

yum_install() {
  if ! command -v yum >/dev/null 2>&1; then
    return 1
  fi
  run_as_root yum install -y "$@"
}

detect_python_bin() {
  for candidate in "$PYTHON_BIN" python3 python36; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      return 0
    fi
  done
  return 1
}

require_download_tool() {
  if command -v curl >/dev/null 2>&1; then
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt_install curl
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    yum_install curl || yum_install wget
    return 0
  fi
  log "Need curl or wget to download Miniforge."
  exit 1
}

download_file() {
  local url="$1"
  local dest="$2"
  require_download_tool
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
    return 0
  fi
  wget -O "$dest" "$url"
}

ensure_python_runtime() {
  if detect_python_bin; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt_install python3 python3-venv python3-pip
    PYTHON_BIN="python3"
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    yum_install python3 python3-pip || yum_install python36 python36-pip
    detect_python_bin && return 0
  fi
  log "Python runtime not found and could not be installed automatically."
  exit 1
}

python_version_supported() {
  "$PYTHON_BIN" - <<'PY'
import sys
raise SystemExit(0 if (3, 11) <= sys.version_info[:2] < (3, 13) else 1)
PY
}

install_miniforge_python() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      log "Unsupported architecture for Miniforge: $arch"
      exit 1
      ;;
  esac
  local installer="Miniforge3-Linux-${arch}.sh"
  local installer_path="/tmp/${installer}"
  local installer_url="https://github.com/conda-forge/miniforge/releases/download/${MINIFORGE_RELEASE}/${installer}"
  if [ ! -x "$MINIFORGE_DIR/bin/conda" ]; then
    log "System Python is too old. Installing Miniforge ${MINIFORGE_RELEASE}..."
    download_file "$installer_url" "$installer_path"
    bash "$installer_path" -b -p "$MINIFORGE_DIR"
    rm -f "$installer_path"
  fi
  PYTHON_BIN="$MINIFORGE_DIR/bin/python"
}

ensure_modern_python() {
  ensure_python_runtime
  if python_version_supported; then
    return 0
  fi
  install_miniforge_python
  if ! python_version_supported; then
    log "Failed to provision a supported Python runtime."
    exit 1
  fi
}

ensure_virtualenv() {
  if "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    return 0
  fi
  "$PYTHON_BIN" -m pip install virtualenv
  return 0
}

ensure_modern_python

if [ ! -d "$VENV_DIR" ]; then
  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    if command -v apt-get >/dev/null 2>&1; then
      apt_install python3-venv python3-pip
      "$PYTHON_BIN" -m venv "$VENV_DIR" && :
    fi
  fi
  if [ ! -d "$VENV_DIR" ]; then
    ensure_virtualenv
    "$PYTHON_BIN" -m virtualenv "$VENV_DIR"
  fi
fi

if [ ! -d "$VENV_DIR" ]; then
  log "Failed to create virtual environment."
  exit 1
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r Backend/requirements.txt

generate_hex_secret() {
  "$PYTHON_BIN" - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
}

ensure_safe_identifier() {
  local value="$1"
  local label="$2"
  if [[ ! "$value" =~ ^[A-Za-z0-9_]+$ ]]; then
    log "$label chi duoc gom chu, so va dau _"
    exit 1
  fi
}

run_psql_admin() {
  local sql="$1"
  if command -v sudo >/dev/null 2>&1; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc "$sql"
    return
  fi
  if command -v runuser >/dev/null 2>&1; then
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -tAc "$sql"
    return
  fi
  log "Need root/sudo to configure PostgreSQL"
  exit 1
}

prepare_database_url() {
  if [ -n "${DATABASE_URL:-}" ]; then
    return
  fi
  if [ "$DATABASE_MODE" = "postgres" ]; then
    ensure_safe_identifier "$POSTGRES_DB" "POSTGRES_DB"
    ensure_safe_identifier "$POSTGRES_USER" "POSTGRES_USER"
    if ! command -v psql >/dev/null 2>&1; then
      if command -v apt-get >/dev/null 2>&1; then
        apt_install postgresql postgresql-contrib
      else
        log "PostgreSQL client/server missing. Install it or set DATABASE_URL manually."
        exit 1
      fi
    fi
    run_as_root systemctl enable postgresql >/dev/null 2>&1 || true
    run_as_root systemctl start postgresql >/dev/null 2>&1 || true
    if [ -z "$POSTGRES_PASSWORD" ]; then
      POSTGRES_PASSWORD="$(generate_hex_secret)"
    fi
    ROLE_EXISTS="$(run_psql_admin "SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'" || true)"
    if [ -z "$ROLE_EXISTS" ]; then
      run_psql_admin "CREATE ROLE ${POSTGRES_USER} LOGIN PASSWORD '${POSTGRES_PASSWORD}'"
    fi
    DB_EXISTS="$(run_psql_admin "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" || true)"
    if [ -z "$DB_EXISTS" ]; then
      run_psql_admin "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER}"
    fi
    DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
    export DATABASE_URL
    log "Using PostgreSQL database: ${POSTGRES_DB}"
    return
  fi
  DATABASE_URL="sqlite:///$SCRIPT_DIR/Backend/sql_app.db"
  export DATABASE_URL
  log "Using SQLite database for quickstart"
}

prepare_database_url

if [ ! -f ".env" ]; then
  GENERATED_MASTER_KEY="$(python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"
  GENERATED_INTERNAL_SECRET="$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  cat > .env <<EOF
BACKEND_URL=${BACKEND_PUBLIC_URL:-http://127.0.0.1:${PORT}}
BACKEND_BIND=0.0.0.0:${PORT}
BACKEND_WORKERS=2
CUSTOMER_PORTAL_URL=${CUSTOMER_PORTAL_URL:-}
DATABASE_URL=${DATABASE_URL}
INTERNAL_API_SECRET=${INTERNAL_API_SECRET:-$GENERATED_INTERNAL_SECRET}
MASTER_KEY=${MASTER_KEY:-$GENERATED_MASTER_KEY}
RELEASE_SIGNING_PRIVATE_KEY=${RELEASE_SIGNING_PRIVATE_KEY:-}
GUNICORN_PID_FILE=${GUNICORN_PID_FILE:-gunicorn.pid}
WORKER_METRICS_DIR=${WORKER_METRICS_DIR:-Backend/runtime/worker_metrics}
WORKER_METRICS_ENABLED=${WORKER_METRICS_ENABLED:-true}
WORKER_METRICS_FLUSH_SECONDS=${WORKER_METRICS_FLUSH_SECONDS:-2}
DEV_MODE=false
ALLOW_INSECURE_DEFAULTS=false
EOF
  log "Created .env with generated defaults."
fi

if [ -n "${BACKEND_PUBLIC_URL:-}" ]; then
  export BACKEND_URL="$BACKEND_PUBLIC_URL"
fi
export BACKEND_BIND="${BACKEND_BIND:-0.0.0.0:$PORT}"
exec gunicorn -c gunicorn.conf.py Backend.main:app
