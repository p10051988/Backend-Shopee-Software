# Backend-Shopee-Software

Hybrid backend cho Auto-Shopee:
- `BackendGo/`: backend Go chinh cho auth, session, plans, users, subscriptions, devices
- `BackendGo/sidecar.py`: Python sidecar nho cho password hashing va secure module packaging

## One-command VPS bootstrap

```bash
git clone <your-backend-repo> Backend-Shopee-Software && cd Backend-Shopee-Software && bash bootstrap_backend_vps.sh
```

Script se:
- cai Miniforge Python neu can
- cai Go local neu VPS chua co
- setup PostgreSQL local
- tao `.venv` cho sidecar
- build binary Go
- tao `.env` neu chua co
- chay sidecar + backend Go

## Start lai backend sau khi da bootstrap

```bash
bash start_backend_vps.sh
```

## Panel monitor realtime

## Backend control menu

```bash
bash backend_control_vps.sh
```

Menu nay gom update tu GitHub, start/restart/stop backend, monitor panel, backup, transfer backup, auto backup cron va logs.

### Menu chi tiet

- `1. Update script/backend tu GitHub`: git pull, bootstrap/build lai backend, restart backend.
- `2. Start backend`: chay sidecar Python va Go backend nen.
- `3. Restart backend`: stop backend + sidecar, sau do start lai.
- `4. Stop backend`: dung backend + sidecar, khong xoa DB.
- `5. Mo panel backend monitor`: xem user online, session, request, latency, CPU/RAM/swap/disk.
- `6. Reset runtime metrics/panel`: xoa bo dem runtime, khong xoa user/goi/device/subscription/database.
- `7. Backup backend + database ngay`: tao file backup trong `backups/`.
- `8. Tam dung backend de backup, xong tu start lai`: stop backend, backup, roi start lai.
- `9. Xem danh sach backup`: xem cac file backup da tao.
- `10. Chuyen backup moi nhat sang VPS khac`: day backup qua VPS khac bang `scp`, `rsync`, hoac `sftp`.
- `11. Cau hinh auto backup bang cron`: 1 lan/ngay, 2 lan/ngay, 4 lan/ngay, hoac moi N gio.
- `12. Xoa auto backup`: xoa cron auto backup cua Auto-Shopee.
- `13. Xem lich auto backup`: xem cron block hien tai.
- `14. Huong dan restore tren VPS moi`: in lenh restore.
- `15. Xem logs`: backend log, sidecar log, auto backup log.

### Tai backup ve may Windows

File backup nam tren VPS:

```text
/root/Backend-Shopee-Software/backups/backend-backup-YYYYMMDD-HHMMSS.tar.gz
```

Tai ve may Windows:

```powershell
scp root@142.171.57.85:/root/Backend-Shopee-Software/backups/backend-backup-YYYYMMDD-HHMMSS.tar.gz .
```

### Lenh nhanh

```bash
bash backend_control_vps.sh --update
bash backend_control_vps.sh --restart
bash backend_control_vps.sh --backup
bash backend_control_vps.sh --backup-stopped
bash backend_control_vps.sh --status
```

```bash
bash monitor_backend_vps.sh
```

Reset runtime metrics truoc/sau load test:

```bash
bash monitor_backend_vps.sh --reset
```

Panel nay hien thi:

- user online
- session online
- device online
- CPU / RAM / swap / disk
- tong request, success, fail
- avg latency, p95, max
- top routes
- recent sessions

## Alert watcher Telegram

```bash
bash start_backend_alerts.sh
```

Neu `TELEGRAM_BOT_TOKEN` va `TELEGRAM_CHAT_ID` co trong `.env`, watcher se gui canh bao khi backend bi warning/critical.
Neu chua co token/chat id, watcher van co the chay log-only mode.

## Ghi chu

- Public contract giu nguyen cho desktop:
  - `GET /api/public/health`
  - `GET /api/public/plans`
  - `POST /api/public/login`
  - `POST /api/public/access-key-login`
  - `POST /fetch_module`
  - `POST /heartbeat`
  - `POST /puzzle/solve`
- Internal contract chinh van giu:
  - `POST /api/internal/users/upsert`
  - `POST /api/internal/plans/upsert`
  - `POST /api/internal/plans/update-price`
  - `POST /api/internal/subscriptions/grant`
  - `POST /api/internal/devices/authorize`
  - `POST /api/internal/devices/revoke`
