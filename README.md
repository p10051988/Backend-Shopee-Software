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
