from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
ENV_FILE = ROOT_DIR / ".env"


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


_ENV_VALUES = _parse_env_file(ENV_FILE)


def _get_env(name: str, default: str = "") -> str:
    return os.environ.get(name, _ENV_VALUES.get(name, default))


def _as_bool(value: str, default: bool = False) -> bool:
    if value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str, default: int) -> int:
    if value == "":
        return default
    try:
        return int(value.strip())
    except Exception:
        return default


@dataclass(frozen=True)
class AppSettings:
    root_dir: Path
    backend_url: str
    backend_bind: str
    backend_workers: int
    backend_tls_spki_pin_sha256: str
    database_url: str
    internal_api_secret: str
    master_key: str
    release_signing_private_key: str
    customer_portal_url: str
    gunicorn_pid_file: str
    worker_metrics_dir: str
    worker_metrics_enabled: bool
    worker_metrics_flush_seconds: int
    heartbeat_interval_seconds: int
    heartbeat_jitter_seconds: int
    dev_mode: bool
    allow_insecure_defaults: bool

    @property
    def backend_dir(self) -> Path:
        return self.root_dir / "Backend"

    @property
    def master_key_bytes(self) -> bytes:
        return self.master_key.encode("utf-8")


def load_settings() -> AppSettings:
    default_database = f"sqlite:///{(ROOT_DIR / 'Backend' / 'sql_app.db').resolve().as_posix()}"
    return AppSettings(
        root_dir=ROOT_DIR,
        backend_url=_get_env("BACKEND_URL", "http://127.0.0.1:8000"),
        backend_bind=_get_env("BACKEND_BIND", "0.0.0.0:8000"),
        backend_workers=max(1, _as_int(_get_env("BACKEND_WORKERS"), default=2)),
        backend_tls_spki_pin_sha256=_get_env("BACKEND_TLS_SPKI_PIN_SHA256", ""),
        database_url=_get_env("DATABASE_URL", default_database),
        internal_api_secret=_get_env("INTERNAL_API_SECRET", ""),
        master_key=_get_env("MASTER_KEY", ""),
        release_signing_private_key=_get_env("RELEASE_SIGNING_PRIVATE_KEY", ""),
        customer_portal_url=_get_env("CUSTOMER_PORTAL_URL", ""),
        gunicorn_pid_file=_get_env("GUNICORN_PID_FILE", "gunicorn.pid"),
        worker_metrics_dir=_get_env("WORKER_METRICS_DIR", "Backend/runtime/worker_metrics"),
        worker_metrics_enabled=_as_bool(_get_env("WORKER_METRICS_ENABLED"), default=True),
        worker_metrics_flush_seconds=max(1, _as_int(_get_env("WORKER_METRICS_FLUSH_SECONDS"), default=2)),
        heartbeat_interval_seconds=_as_int(_get_env("HEARTBEAT_INTERVAL_SECONDS"), default=75),
        heartbeat_jitter_seconds=_as_int(_get_env("HEARTBEAT_JITTER_SECONDS"), default=15),
        dev_mode=_as_bool(_get_env("DEV_MODE"), default=False),
        allow_insecure_defaults=_as_bool(_get_env("ALLOW_INSECURE_DEFAULTS"), default=False),
    )


settings = load_settings()
