# Auto-Shopee

Desktop tool quản lý shop Shopee với GUI PyQt5, backend FastAPI cho auth/session, và remote module loading cho phần logic nhạy cảm.

## Kiến trúc hiện tại

- `main.py`: entry point cho desktop app.
- `GUI/`: các tab giao diện, flow đăng nhập desktop, quản lý account Shopee.
- `API/`: Shopee API client và helper gọi endpoint Shopee.
- `utils/`: access bootstrap, remote loader, local secret storage, release manifest.
- `Backend/`: FastAPI backend cho account auth, package/device authorization, module delivery.

## Auth flow hiện tại

Project hiện dùng flow production theo `account + package + device`:

1. User mở EXE để lấy `Device ID`.
2. User đăng ký tài khoản / mua gói trên website ngoài.
3. Website gọi internal API để authorize `Device ID`.
4. EXE đăng nhập bằng `username/password` qua `POST /api/public/login`.
5. Backend trả về secure session và `access_key`.
6. Desktop lưu `access_key` local bằng DPAPI.
7. Những lần mở sau, desktop bootstrap lại phiên qua `POST /api/public/access-key-login`.

`POST /verify_license` vẫn còn trong backend để tương thích với legacy key flow, nhưng không còn là bootstrap path chính của desktop hiện tại.

## Security đang có thật trong code

- Public auth/session dùng `session_id + machine_id + sync_token + nonce + timestamp + HMAC`.
- `fetch_module`, `heartbeat`, `puzzle/solve` có signed response và fragment seal theo `session_id + session_epoch`.
- Nonce replay cache ở backend đã được khóa thread-safe.
- `license.json` và `secrets.json` được mã hóa local bằng DPAPI trên Windows.
- Runtime guard có anti-debug probe, timing anomaly detection, risk scoring, degraded/poisoned flow.
- Release build có `release_manifest.json` ký `Ed25519` và runtime verify.
- Với backend production non-local, client yêu cầu `HTTPS` trừ khi đang chạy localhost/dev override.
- Account-bound `access_key` luôn bị re-check lại theo `user + subscription + device` trước khi cấp session mới.

Chi tiết xem tại [SECURITY.md](./SECURITY.md).

## Setup

### Yêu cầu

- Windows 10/11
- Python 3.10 hoặc 3.11
- `pip install -r requirements.txt`
- `pip install -r Backend/requirements.txt`
- Khi dùng VS Code/Pylance, workspace nên chạy bằng Python `3.11`.
- Repo đã có `pyrightconfig.json`, `.vscode/settings.json`, và `typings/PyQt5/` để Pylance hiểu đúng `PyQt5` và giảm cảnh báo nhiễu từ `psutil`.

### Cấu hình

Sao chép `.env.example` thành `.env` và cấu hình:

- `BACKEND_URL`
- `CUSTOMER_PORTAL_URL`
- `DATABASE_URL`
- `INTERNAL_API_SECRET`
- `MASTER_KEY`
- `RELEASE_SIGNING_PRIVATE_KEY`
- `BACKEND_TLS_SPKI_PIN_SHA256`
- `BACKEND_BIND`
- `BACKEND_WORKERS`
- `GUNICORN_PID_FILE`
- `WORKER_METRICS_DIR`
- `WORKER_METRICS_ENABLED`
- `WORKER_METRICS_FLUSH_SECONDS`
- `HEARTBEAT_INTERVAL_SECONDS`
- `HEARTBEAT_JITTER_SECONDS`

### Chạy local

1. Chạy backend:

```bash
run_backend.bat
```

2. Seed dữ liệu backend production:

```bash
python Backend/seed_modules.py
python Backend/seed_license.py
```

3. Chạy desktop app:

```bash
python main.py
```

## Build

```bash
python build_secure_workflow.py
```

Build secure hiện yêu cầu:

- `RELEASE_SIGNING_PRIVATE_KEY`
- `PUBLIC_KEY_B64` trong `release_public_key.py`
- compiler C/C++ tương thích cho Cython

Output hiện tại nằm trong `build-final/` theo versioned layout.

## Export Backend

```bash
python prepare_backend_repo.py
```

Backend export nằm trong `build-final/version x.y.z/Backend-Shopee-Software/`.
Sau khi đưa repo backend này lên VPS, có thể chạy nhanh bằng:

```bash
bash bootstrap_backend_vps.sh
```

Sau khi push repo export len GitHub, co the deploy theo 1 dong:

```bash
git clone <your-backend-repo> Backend-Shopee-Software && cd Backend-Shopee-Software && bash bootstrap_backend_vps.sh
```

## Production backend notes

- Production backend co the chay `SQLite` hoac `PostgreSQL`, nhung muc tieu `300-500 user online` nen dung `PostgreSQL`.
- Deploy production mac dinh nen chay `gunicorn.conf.py` voi `2 workers` tren VPS `2 CPU / 2 GB`.
- Worker runtime scale bang signal chi hoat dong khi backend chay `Gunicorn` tren host POSIX/Linux; local Windows chi nen dung de xem code va smoke test.
- Worker runtime co the xem va scale bang:

```bash
python Backend/manage_workers.py status
python Backend/manage_workers.py add 1 --persist
python Backend/manage_workers.py remove 1 --persist
```

- Migration tu SQLite sang PostgreSQL:

```bash
python Backend/migrate_to_postgres.py --target postgresql://autoshopee:CHANGE_ME@127.0.0.1:5432/autoshopee --truncate
```

- Smoke / load nhe sau khi backend len:

```bash
python Backend/smoke_load.py --base-url http://127.0.0.1:8000 --requests 120 --concurrency 20
python Backend/smoke_load.py --base-url http://127.0.0.1:8000 --include-internal --requests 60 --concurrency 10
```

## Hybrid backend status

- `BackendGo/` la backend production moi theo huong `Go + PostgreSQL`.
- `BackendGo/sidecar.py` giu phan Python-specific: password hashing va secure module packaging cho `/fetch_module`.
- Runtime collector noi bo moi expose `GET /api/internal/runtime/traffic`, luu snapshot theo ngay va auto xoa du lieu qua 90 ngay.
- Repo export backend moi duoc sinh qua `prepare_backend_repo.py` va deploy 1 lenh:

```bash
git clone <your-backend-repo> Backend-Shopee-Software && cd Backend-Shopee-Software && bash bootstrap_backend_vps.sh
```

- Sau khi bootstrap xong, restart backend tren VPS bang:

```bash
cd ~/Backend-Shopee-Software && bash start_backend_vps.sh
```
