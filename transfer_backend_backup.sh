#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ARCHIVE_PATH="${1:-}"
REMOTE_SPEC="${2:-}"
REMOTE_DIR="${3:-}"
TRANSFER_MODE="${TRANSFER_MODE:-scp}"

if [ -z "$ARCHIVE_PATH" ] || [ ! -f "$ARCHIVE_PATH" ]; then
  echo "[TRANSFER] Usage: bash transfer_backend_backup.sh /abs/path/backend-backup-YYYYMMDD-HHMMSS.tar.gz user@host [/remote/dir]"
  exit 1
fi

if [ -z "$REMOTE_SPEC" ]; then
  echo "[TRANSFER] Missing remote target, expected user@host"
  exit 1
fi

if [ -z "$REMOTE_DIR" ]; then
  REMOTE_DIR="~/backend-transfer"
fi

archive_name="$(basename "$ARCHIVE_PATH")"

prepare_remote_dir() {
  if command -v ssh >/dev/null 2>&1; then
    ssh "$REMOTE_SPEC" "mkdir -p '$REMOTE_DIR'"
    return 0
  fi
  echo "[TRANSFER] ssh not found; please create remote dir manually: $REMOTE_DIR"
  return 1
}

transfer_scp() {
  command -v scp >/dev/null 2>&1 || {
    echo "[TRANSFER] scp not found"
    exit 1
  }
  prepare_remote_dir || true
  scp "$ARCHIVE_PATH" "${REMOTE_SPEC}:${REMOTE_DIR}/"
}

transfer_rsync() {
  command -v rsync >/dev/null 2>&1 || {
    echo "[TRANSFER] rsync not found"
    exit 1
  }
  prepare_remote_dir || true
  rsync -av --progress "$ARCHIVE_PATH" "${REMOTE_SPEC}:${REMOTE_DIR}/"
}

transfer_sftp() {
  command -v sftp >/dev/null 2>&1 || {
    echo "[TRANSFER] sftp not found"
    exit 1
  }
  local batch_file
  batch_file="$(mktemp)"
  trap 'rm -f "$batch_file"' EXIT
  cat > "$batch_file" <<EOF
mkdir $REMOTE_DIR
put $ARCHIVE_PATH $REMOTE_DIR/$archive_name
EOF
  sftp -b "$batch_file" "$REMOTE_SPEC"
}

case "$TRANSFER_MODE" in
  scp)
    transfer_scp
    ;;
  rsync)
    transfer_rsync
    ;;
  sftp)
    transfer_sftp
    ;;
  *)
    echo "[TRANSFER] Unsupported TRANSFER_MODE: $TRANSFER_MODE"
    echo "[TRANSFER] Supported: scp, rsync, sftp"
    exit 1
    ;;
esac

echo "[TRANSFER] Uploaded to ${REMOTE_SPEC}:${REMOTE_DIR}/${archive_name}"
