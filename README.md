# Backend-Shopee-Software

Backend FastAPI cho Auto-Shopee.

## One-command VPS bootstrap

Sau khi push repo nay len GitHub, co the chay theo kieu 1 dong:

```bash
git clone <your-backend-repo> Backend-Shopee-Software && cd Backend-Shopee-Software && bash bootstrap_backend_vps.sh
```

```bash
bash bootstrap_backend_vps.sh
```

Script se:
- tu cai Python/venv neu VPS la Ubuntu/Debian hoac CentOS/RHEL va dang thieu
- neu Python he thong qua cu (vd 3.6), tu cai Miniforge Python 3.11 trong home
- tao `.venv`
- cai `Backend/requirements.txt`
- tao `.env` neu chua co
- mac dinh dung `SQLite + Gunicorn 2 workers` de len nhanh
- tu sinh `INTERNAL_API_SECRET` va `MASTER_KEY` neu chua cung cap
- chay `gunicorn` voi `2 workers` mac dinh

Neu muon setup `PostgreSQL` local de scale tot hon, dung:

```bash
DATABASE_MODE=postgres bash bootstrap_backend_vps.sh
```

## Bien moi truong co the override truoc khi chay

- `PORT`
- `DATABASE_MODE`
- `BACKEND_BIND`
- `BACKEND_WORKERS`
- `BACKEND_PUBLIC_URL`
- `CUSTOMER_PORTAL_URL`
- `DATABASE_URL`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `INTERNAL_API_SECRET`
- `MASTER_KEY`
- `RELEASE_SIGNING_PRIVATE_KEY`
- `GUNICORN_PID_FILE`
- `WORKER_METRICS_DIR`
- `WORKER_METRICS_ENABLED`
- `WORKER_METRICS_FLUSH_SECONDS`

## Start lai backend sau khi da bootstrap

```bash
bash start_backend_vps.sh
```

## Worker ops tren VPS

```bash
python Backend/manage_workers.py status
python Backend/manage_workers.py add 1 --persist
python Backend/manage_workers.py remove 1 --persist
```

## Smoke / load nhe

```bash
python Backend/smoke_load.py --base-url http://127.0.0.1:8000 --requests 120 --concurrency 20
python Backend/smoke_load.py --base-url http://127.0.0.1:8000 --include-internal --requests 60 --concurrency 10
```

## SQLite -> PostgreSQL migration

```bash
python Backend/migrate_to_postgres.py --target postgresql://autoshopee:CHANGE_ME@127.0.0.1:5432/autoshopee --truncate
```

## Package catalog production

Danh muc mac dinh:
- `trial-7d`
- `plan-1m`
- `plan-3m`
- `plan-6m`
- `plan-12m`

Public endpoint:
- `GET /api/public/plans`
- `POST /api/public/login`

Internal endpoint quan trong:
- `POST /api/internal/plans/seed-defaults`
- `POST /api/internal/plans/update-price`
- `POST /api/internal/subscriptions/grant`
- `POST /api/internal/devices/authorize`
