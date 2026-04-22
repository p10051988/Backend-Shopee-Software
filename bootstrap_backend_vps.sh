#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-8000}"
VENV_DIR="${VENV_DIR:-.venv}"
GO_DIR="${GO_DIR:-$SCRIPT_DIR/.go}"
GO_VERSION="${GO_VERSION:-1.26.1}"
DATABASE_MODE="${DATABASE_MODE:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-autoshopee}"
POSTGRES_USER="${POSTGRES_USER:-autoshopee}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
MINIFORGE_DIR="${MINIFORGE_DIR:-$SCRIPT_DIR/.miniforge3}"
MINIFORGE_RELEASE="${MINIFORGE_RELEASE:-25.11.0-1}"
BACKEND_BIN="${BACKEND_BIN:-$SCRIPT_DIR/bin/backendgo}"

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

require_download_tool() {
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
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
  log "Need curl or wget."
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
  if [ -x "$MINIFORGE_DIR/bin/python" ]; then
    return 0
  fi
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
  log "Installing Miniforge ${MINIFORGE_RELEASE}..."
  download_file "$installer_url" "$installer_path"
  bash "$installer_path" -b -p "$MINIFORGE_DIR"
  rm -f "$installer_path"
}

ensure_go_runtime() {
  if [ -x "$GO_DIR/bin/go" ]; then
    return 0
  fi
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      log "Unsupported architecture for Go: $arch"
      exit 1
      ;;
  esac
  local archive="go${GO_VERSION}.linux-${arch}.tar.gz"
  local archive_path="/tmp/${archive}"
  local archive_url="https://go.dev/dl/${archive}"
  log "Installing Go ${GO_VERSION}..."
  download_file "$archive_url" "$archive_path"
  rm -rf "$GO_DIR"
  mkdir -p "$GO_DIR"
  tar -xzf "$archive_path" -C "$GO_DIR" --strip-components=1
  rm -f "$archive_path"
}

generate_hex_secret() {
  "$MINIFORGE_DIR/bin/python" - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
}

generate_master_key() {
  "$MINIFORGE_DIR/bin/python" - <<'PY'
import base64
import os
print(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
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

ensure_postgres_runtime() {
  if command -v psql >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt_install postgresql postgresql-contrib
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    yum_install postgresql-server postgresql postgresql-contrib || yum_install postgresql-server postgresql
    return 0
  fi
  log "Cannot install PostgreSQL automatically on this distro."
  exit 1
}

init_postgres_if_needed() {
  if command -v postgresql-setup >/dev/null 2>&1; then
    if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
      run_as_root postgresql-setup initdb || run_as_root postgresql-setup --initdb || true
    fi
  fi
}

try_start_postgres_service() {
  local service_name="$1"
  if [ -z "$service_name" ]; then
    return 1
  fi
  if command -v systemctl >/dev/null 2>&1; then
    run_as_root systemctl enable "$service_name" >/dev/null 2>&1 || true
    run_as_root systemctl start "$service_name" >/dev/null 2>&1 || true
    run_as_root systemctl start "${service_name}.service" >/dev/null 2>&1 || true
  fi
  if command -v service >/dev/null 2>&1; then
    run_as_root service "$service_name" start >/dev/null 2>&1 || true
  fi
}

wait_for_postgres_ready() {
  local attempts="${1:-20}"
  local i
  for ((i=1; i<=attempts; i++)); do
    if command -v pg_isready >/dev/null 2>&1; then
      if pg_isready -h "$POSTGRES_HOST" -p 5432 >/dev/null 2>&1; then
        return 0
      fi
    elif command -v psql >/dev/null 2>&1; then
      if PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p 5432 -U "$POSTGRES_USER" -d postgres -c "SELECT 1" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

ensure_postgres_running() {
  try_start_postgres_service "postgresql"
  try_start_postgres_service "postgresql-16"
  try_start_postgres_service "postgresql-15"
  try_start_postgres_service "postgresql-14"
  try_start_postgres_service "postgresql-13"
  try_start_postgres_service "postgresql-12"
  try_start_postgres_service "postgresql-11"
  try_start_postgres_service "postgresql-10"
  try_start_postgres_service "postgresql-9.6"
  try_start_postgres_service "postgresql-9.5"
  try_start_postgres_service "postgresql-9.4"
  try_start_postgres_service "postgresql-9.3"
  try_start_postgres_service "postgresql-9.2"

  if ! wait_for_postgres_ready 25; then
    log "PostgreSQL service did not become ready on ${POSTGRES_HOST}:5432"
    return 1
  fi
}

prepare_database_url() {
  if [ -n "${DATABASE_URL:-}" ]; then
    export DATABASE_URL
    log "Using provided DATABASE_URL"
    return
  fi

  if [ "$DATABASE_MODE" != "postgres" ]; then
    DATABASE_URL="sqlite:///$SCRIPT_DIR/Backend/sql_app.db"
    export DATABASE_URL
    log "Using SQLite database for local/dev"
    return
  fi

  ensure_safe_identifier "$POSTGRES_DB" "POSTGRES_DB"
  ensure_safe_identifier "$POSTGRES_USER" "POSTGRES_USER"
  ensure_postgres_runtime
  init_postgres_if_needed

  if [ -z "$POSTGRES_PASSWORD" ]; then
    POSTGRES_PASSWORD="$(generate_hex_secret)"
  fi

  ensure_postgres_running

  ROLE_EXISTS="$(run_psql_admin "SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'" || true)"
  if [ -z "$ROLE_EXISTS" ]; then
    run_psql_admin "CREATE ROLE ${POSTGRES_USER} LOGIN PASSWORD '${POSTGRES_PASSWORD}'"
  fi

  DB_EXISTS="$(run_psql_admin "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" || true)"
  if [ -z "$DB_EXISTS" ]; then
    run_psql_admin "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER}"
  fi

  DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:5432/${POSTGRES_DB}?sslmode=disable"
  export DATABASE_URL
  log "Using PostgreSQL database: ${POSTGRES_DB}"
}

ensure_python_runtime
ensure_go_runtime

if [ ! -d "$VENV_DIR" ]; then
  "$MINIFORGE_DIR/bin/python" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r BackendGo/requirements-sidecar.txt

prepare_database_url

mkdir -p "$SCRIPT_DIR/bin" "$SCRIPT_DIR/logs" "$SCRIPT_DIR/run"

if [ ! -f ".env" ]; then
  GENERATED_MASTER_KEY="$(generate_master_key)"
  GENERATED_INTERNAL_SECRET="$(generate_hex_secret)"
  cat > .env <<EOF
BACKEND_URL=${BACKEND_PUBLIC_URL:-http://127.0.0.1:${PORT}}
BACKEND_BIND=0.0.0.0:${PORT}
CUSTOMER_PORTAL_URL=${CUSTOMER_PORTAL_URL:-}
DATABASE_URL=${DATABASE_URL}
INTERNAL_API_SECRET=${INTERNAL_API_SECRET:-$GENERATED_INTERNAL_SECRET}
MASTER_KEY=${MASTER_KEY:-$GENERATED_MASTER_KEY}
RELEASE_PUBLIC_KEY_B64=${RELEASE_PUBLIC_KEY_B64:-IVQiSVHi/lGaURwMPl69hlysa5iL21fwjeFxzUwItf4=}
BACKEND_PY_SIDECAR_HOST=${BACKEND_PY_SIDECAR_HOST:-127.0.0.1}
BACKEND_PY_SIDECAR_PORT=${BACKEND_PY_SIDECAR_PORT:-9801}
BACKEND_PY_SIDECAR_URL=${BACKEND_PY_SIDECAR_URL:-http://127.0.0.1:9801}
DEV_MODE=false
ALLOW_INSECURE_DEFAULTS=false
EOF
  log "Created .env with generated defaults."
fi

export PATH="$GO_DIR/bin:$PATH"
(cd "$SCRIPT_DIR/BackendGo" && "$GO_DIR/bin/go" mod download && "$GO_DIR/bin/go" build -o "$BACKEND_BIN" .)

bash "$SCRIPT_DIR/start_backend_vps.sh"
