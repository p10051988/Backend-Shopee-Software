from __future__ import annotations

from app_config import settings


bind = settings.backend_bind
workers = max(1, settings.backend_workers)
worker_class = "uvicorn.workers.UvicornWorker"
pidfile = settings.gunicorn_pid_file
timeout = 60
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
capture_output = True
