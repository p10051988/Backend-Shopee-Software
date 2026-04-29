#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RUN_DIR="${RUN_DIR:-$SCRIPT_DIR/run}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"
BACKUP_ROOT="${BACKUP_ROOT:-$SCRIPT_DIR/backups}"
BACKEND_PID_FILE="$RUN_DIR/backend.pid"
SIDECAR_PID_FILE="$RUN_DIR/sidecar.pid"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
CRON_BEGIN="# AUTO-SHOPEE BACKEND AUTOBACKUP BEGIN"
CRON_END="# AUTO-SHOPEE BACKEND AUTOBACKUP END"

cyan="\033[96m"
green="\033[92m"
yellow="\033[93m"
red="\033[91m"
blue="\033[94m"
bold="\033[1m"
reset="\033[0m"

pause() {
  echo
  read -r -p "Press Enter to continue..." _
}

pid_is_running() {
  local pid="${1:-}"
  [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
}

read_pid_file() {
  local file="$1"
  if [ -f "$file" ]; then
    tr -d '[:space:]' < "$file"
  fi
}

service_state() {
  local backend_pid sidecar_pid
  backend_pid="$(read_pid_file "$BACKEND_PID_FILE" || true)"
  sidecar_pid="$(read_pid_file "$SIDECAR_PID_FILE" || true)"
  if pid_is_running "$backend_pid"; then
    echo "Active"
  else
    echo "Stopped"
  fi
}

health_state() {
  if command -v curl >/dev/null 2>&1 && curl -fsS "http://${BACKEND_HOST}:${BACKEND_PORT}/api/public/health" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "down"
  fi
}

mem_line() {
  awk '
    /MemTotal/ {total=int($2/1024)}
    /MemAvailable/ {avail=int($2/1024)}
    END {used=total-avail; printf "%d/%d MB", used, total}
  ' /proc/meminfo 2>/dev/null || echo "-/- MB"
}

swap_line() {
  awk '
    /SwapTotal/ {total=int($2/1024)}
    /SwapFree/ {free=int($2/1024)}
    END {used=total-free; printf "%d/%d MB", used, total}
  ' /proc/meminfo 2>/dev/null || echo "-/- MB"
}

cpu_line() {
  if command -v top >/dev/null 2>&1; then
    top -bn1 | awk -F'[, ]+' '/Cpu/ {for (i=1;i<=NF;i++) if ($i=="id") {printf "%.1f%%", 100-$(i-1); exit}}'
  else
    echo "-"
  fi
}

disk_line() {
  df -h / 2>/dev/null | awk 'NR==2 {printf "%s/%s (%s)", $3, $2, $5}' || echo "-/-"
}

load_line() {
  awk '{print $1 ", " $2 ", " $3}' /proc/loadavg 2>/dev/null || echo "-"
}

uptime_line() {
  uptime -p 2>/dev/null || echo "-"
}

public_ip() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 2 https://ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}'
  else
    hostname -I 2>/dev/null | awk '{print $1}'
  fi
}

draw_header() {
  clear 2>/dev/null || true
  local width=116
  printf "${cyan}%*s${reset}\n" "$width" "" | tr ' ' '='
  echo -e "  ${bold}${cyan}AUTO-SHOPEE BACKEND CONTROL${reset}  $(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "  IP: ${blue}$(public_ip)${reset}  |  Host: $(hostname)  |  OS: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")"
  printf "${cyan}%*s${reset}\n" "$width" "" | tr ' ' '='
  local state health color
  state="$(service_state)"
  health="$(health_state)"
  color="$green"
  [ "$state" != "Active" ] && color="$red"
  echo -e "  Backend Status: ${color}${state}${reset}  |  Health: ${health}  |  Base URL: http://${BACKEND_HOST}:${BACKEND_PORT}"
  echo -e "  CPU: $(cpu_line)  |  RAM: $(mem_line)  |  Swap: $(swap_line)  |  Disk: $(disk_line)"
  echo -e "  Load Avg: $(load_line)  |  Uptime: $(uptime_line)"
  printf "${cyan}%*s${reset}\n" "$width" "" | tr ' ' '-'
}

stop_process_from_pid_file() {
  local name="$1"
  local file="$2"
  local pid
  pid="$(read_pid_file "$file" || true)"
  if pid_is_running "$pid"; then
    echo "[CONTROL] Stopping $name pid $pid..."
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 15); do
      if ! pid_is_running "$pid"; then
        break
      fi
      sleep 1
    done
    if pid_is_running "$pid"; then
      echo "[CONTROL] Force stopping $name pid $pid..."
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$file"
}

stop_backend() {
  stop_process_from_pid_file "backend" "$BACKEND_PID_FILE"
  stop_process_from_pid_file "sidecar" "$SIDECAR_PID_FILE"
  pkill -f "$SCRIPT_DIR/bin/backendgo" 2>/dev/null || true
  pkill -f "$SCRIPT_DIR/BackendGo/sidecar.py" 2>/dev/null || true
  echo "[CONTROL] Backend stopped."
}

start_backend() {
  bash "$SCRIPT_DIR/start_backend_vps.sh"
}

restart_backend() {
  stop_backend
  sleep 2
  start_backend
}

update_backend() {
  echo "[CONTROL] Pulling latest code from GitHub..."
  git pull
  echo "[CONTROL] Running bootstrap/build..."
  bash "$SCRIPT_DIR/bootstrap_backend_vps.sh"
  echo "[CONTROL] Restarting backend with latest binary..."
  restart_backend
}

backup_now() {
  bash "$SCRIPT_DIR/backup_backend_vps.sh"
}

backup_with_pause() {
  echo "[CONTROL] Pausing backend before backup..."
  stop_backend
  local backup_status=0
  backup_now || backup_status=$?
  echo "[CONTROL] Starting backend after backup attempt..."
  start_backend || true
  if [ "$backup_status" -ne 0 ]; then
    echo "[CONTROL] Backup failed with status $backup_status. Backend start was attempted."
    return "$backup_status"
  fi
}

latest_backup() {
  find "$BACKUP_ROOT" -maxdepth 1 -type f -name 'backend-backup-*.tar.gz' 2>/dev/null | sort | tail -n 1
}

list_backups() {
  mkdir -p "$BACKUP_ROOT"
  echo "[CONTROL] Backups in $BACKUP_ROOT"
  find "$BACKUP_ROOT" -maxdepth 1 -type f -name 'backend-backup-*.tar.gz' -printf '%TY-%Tm-%Td %TH:%TM  %s bytes  %p\n' 2>/dev/null | sort -r | head -n 20 || true
}

transfer_latest_backup() {
  local archive remote remote_dir mode
  archive="$(latest_backup)"
  if [ -z "$archive" ]; then
    echo "[CONTROL] No backup archive found. Run backup first."
    return 1
  fi
  echo "[CONTROL] Latest backup: $archive"
  read -r -p "Remote target (example root@1.2.3.4): " remote
  if [ -z "$remote" ]; then
    echo "[CONTROL] Missing remote target."
    return 1
  fi
  read -r -p "Remote dir [~/backend-transfer]: " remote_dir
  remote_dir="${remote_dir:-~/backend-transfer}"
  read -r -p "Transfer mode scp/rsync/sftp [scp]: " mode
  mode="${mode:-scp}"
  TRANSFER_MODE="$mode" bash "$SCRIPT_DIR/transfer_backend_backup.sh" "$archive" "$remote" "$remote_dir"
}

install_auto_backup() {
  local runs schedule hours line tmp
  if ! command -v crontab >/dev/null 2>&1; then
    echo "[CONTROL] crontab not found. Install cronie/crontabs first."
    return 1
  fi
  echo "Auto backup frequency:"
  echo "  1. 1 lan/ngay  (03:00)"
  echo "  2. 2 lan/ngay  (03:00, 15:00)"
  echo "  3. 4 lan/ngay  (00:00, 06:00, 12:00, 18:00)"
  echo "  4. Tuy chon moi N gio"
  read -r -p "Chon [1]: " runs
  runs="${runs:-1}"
  case "$runs" in
    1) schedule="0 3 * * *" ;;
    2) schedule="0 3,15 * * *" ;;
    3) schedule="0 0,6,12,18 * * *" ;;
    4)
      read -r -p "Moi bao nhieu gio? [6]: " hours
      hours="${hours:-6}"
      if ! [[ "$hours" =~ ^[0-9]+$ ]] || [ "$hours" -lt 1 ] || [ "$hours" -gt 24 ]; then
        echo "[CONTROL] Invalid hours: $hours"
        return 1
      fi
      schedule="0 */$hours * * *"
      ;;
    *)
      echo "[CONTROL] Invalid choice."
      return 1
      ;;
  esac
  mkdir -p "$LOG_DIR" "$BACKUP_ROOT"
  line="$schedule cd '$SCRIPT_DIR' && BACKUP_ROOT='$BACKUP_ROOT' bash backup_backend_vps.sh >> '$LOG_DIR/auto_backup.log' 2>&1"
  tmp="$(mktemp)"
  (crontab -l 2>/dev/null || true) | awk "/$CRON_BEGIN/{skip=1; next} /$CRON_END/{skip=0; next} !skip{print}" > "$tmp"
  {
    cat "$tmp"
    echo "$CRON_BEGIN"
    echo "$line"
    echo "$CRON_END"
  } | crontab -
  rm -f "$tmp"
  echo "[CONTROL] Auto backup installed:"
  echo "  $line"
}

remove_auto_backup() {
  local tmp
  if ! command -v crontab >/dev/null 2>&1; then
    echo "[CONTROL] crontab not found."
    return 1
  fi
  tmp="$(mktemp)"
  (crontab -l 2>/dev/null || true) | awk "/$CRON_BEGIN/{skip=1; next} /$CRON_END/{skip=0; next} !skip{print}" > "$tmp"
  crontab "$tmp"
  rm -f "$tmp"
  echo "[CONTROL] Auto backup removed."
}

show_auto_backup() {
  if ! command -v crontab >/dev/null 2>&1; then
    echo "[CONTROL] crontab not found."
    return 1
  fi
  crontab -l 2>/dev/null | awk "/$CRON_BEGIN/{show=1} show{print} /$CRON_END/{show=0}" || true
}

show_logs() {
  echo "1. Backend log"
  echo "2. Sidecar log"
  echo "3. Auto backup log"
  read -r -p "Chon log [1]: " choice
  case "${choice:-1}" in
    1) tail -n 120 "$LOG_DIR/backend.log" 2>/dev/null || true ;;
    2) tail -n 120 "$LOG_DIR/sidecar.log" 2>/dev/null || true ;;
    3) tail -n 120 "$LOG_DIR/auto_backup.log" 2>/dev/null || true ;;
    *) echo "[CONTROL] Invalid choice." ;;
  esac
}

open_restore_hint() {
  local archive
  archive="$(latest_backup)"
  echo "[CONTROL] Restore on NEW VPS:"
  echo "  git clone https://github.com/p10051988/Backend-Shopee-Software.git"
  echo "  cd Backend-Shopee-Software"
  echo "  bash restore_backend_vps.sh /abs/path/backend-backup-YYYYMMDD-HHMMSS.tar.gz"
  if [ -n "$archive" ]; then
    echo
    echo "[CONTROL] Latest local archive:"
    echo "  $archive"
  fi
}

menu() {
  while true; do
    draw_header
    echo -e "${bold}MAIN MENU${reset}"
    echo "  1. Update script/backend tu GitHub"
    echo "  2. Start backend"
    echo "  3. Restart backend"
    echo "  4. Stop backend"
    echo "  5. Mo panel backend monitor"
    echo "  6. Reset runtime metrics/panel"
    echo "  7. Backup backend + database ngay"
    echo "  8. Tam dung backend de backup, xong tu start lai"
    echo "  9. Xem danh sach backup"
    echo " 10. Chuyen backup moi nhat sang VPS khac"
    echo " 11. Cau hinh auto backup bang cron"
    echo " 12. Xoa auto backup"
    echo " 13. Xem lich auto backup"
    echo " 14. Huong dan restore tren VPS moi"
    echo " 15. Xem logs"
    echo "  0. Thoat"
    echo
    read -r -p "Chon: " choice
    case "$choice" in
      1) update_backend; pause ;;
      2) start_backend; pause ;;
      3) restart_backend; pause ;;
      4) stop_backend; pause ;;
      5) bash "$SCRIPT_DIR/monitor_backend_vps.sh" ;;
      6) bash "$SCRIPT_DIR/monitor_backend_vps.sh" --reset; pause ;;
      7) backup_now; pause ;;
      8) backup_with_pause; pause ;;
      9) list_backups; pause ;;
      10) transfer_latest_backup; pause ;;
      11) install_auto_backup; pause ;;
      12) remove_auto_backup; pause ;;
      13) show_auto_backup; pause ;;
      14) open_restore_hint; pause ;;
      15) show_logs; pause ;;
      0) exit 0 ;;
      *) echo "[CONTROL] Invalid choice."; pause ;;
    esac
  done
}

case "${1:-}" in
  --update) update_backend ;;
  --start) start_backend ;;
  --restart) restart_backend ;;
  --stop) stop_backend ;;
  --backup) backup_now ;;
  --backup-stopped) backup_with_pause ;;
  --auto-backup-remove) remove_auto_backup ;;
  --status) draw_header ;;
  --restore-hint) open_restore_hint ;;
  *) menu ;;
esac
