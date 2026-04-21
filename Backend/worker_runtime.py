from __future__ import annotations

import atexit
import datetime
import json
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

import psutil

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import ENV_FILE, settings


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow()


def _isoformat(value: datetime.datetime | None) -> str | None:
    if value is None:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"


def _resolve_repo_path(raw_value: str, fallback: Path) -> Path:
    candidate = Path(raw_value) if raw_value else fallback
    if not candidate.is_absolute():
        candidate = (settings.root_dir / candidate).resolve()
    return candidate


def resolve_metrics_dir() -> Path:
    return _resolve_repo_path(
        settings.worker_metrics_dir,
        settings.root_dir / "Backend" / "runtime" / "worker_metrics",
    )


def resolve_pidfile_path() -> Path:
    return _resolve_repo_path(
        settings.gunicorn_pid_file,
        settings.root_dir / "gunicorn.pid",
    )


def _safe_process(pid: int | None) -> psutil.Process | None:
    if not pid:
        return None
    try:
        process = psutil.Process(pid)
        if not process.is_running():
            return None
        return process
    except Exception:
        return None


def _looks_like_gunicorn_master(process: psutil.Process | None) -> bool:
    if process is None:
        return False
    try:
        name = (process.name() or "").lower()
    except Exception:
        name = ""
    try:
        cmdline = " ".join(process.cmdline()).lower()
    except Exception:
        cmdline = ""
    try:
        cwd = str(process.cwd()).lower()
    except Exception:
        cwd = ""

    repo_root = str(settings.root_dir).lower()
    has_gunicorn_marker = "gunicorn" in name or "gunicorn" in cmdline
    points_to_backend = "backend.main:app" in cmdline or repo_root == cwd
    return has_gunicorn_marker and points_to_backend


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)


def _read_master_pid(pidfile_path: Path | None = None) -> int | None:
    pidfile = pidfile_path or resolve_pidfile_path()
    if not pidfile.exists():
        return None
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except Exception:
        return None
    if not _looks_like_gunicorn_master(_safe_process(pid)):
        return None
    return pid


def _load_worker_state(path: Path) -> dict | None:
    payload = _read_json(path)
    if not payload:
        return None
    pid = int(payload.get("pid") or 0)
    process = _safe_process(pid)
    if not process:
        try:
            path.unlink()
        except OSError:
            pass
        return None

    payload["pid"] = pid
    payload["rss_mb"] = round(process.memory_info().rss / (1024 * 1024), 2)
    payload["cpu_percent"] = round(process.cpu_percent(interval=0.0), 2)
    payload["thread_count"] = process.num_threads()
    inflight = int(payload.get("inflight_requests") or 0)
    payload["status"] = "busy" if inflight > 0 else "idle"
    return payload


def _placeholder_worker_state(process: psutil.Process) -> dict:
    return {
        "pid": process.pid,
        "hostname": socket.gethostname(),
        "process_started_at": _isoformat(datetime.datetime.utcfromtimestamp(process.create_time())),
        "updated_at": _isoformat(utcnow()),
        "last_request_at": None,
        "last_request_path": "",
        "last_request_method": "",
        "last_response_status": 0,
        "inflight_requests": 0,
        "handled_requests": 0,
        "rss_mb": round(process.memory_info().rss / (1024 * 1024), 2),
        "cpu_percent": round(process.cpu_percent(interval=0.0), 2),
        "thread_count": process.num_threads(),
        "status": "idle",
    }


def _load_all_worker_states(metrics_dir: Path | None = None) -> dict[int, dict]:
    directory = metrics_dir or resolve_metrics_dir()
    if not directory.exists():
        return {}
    states: dict[int, dict] = {}
    for path in directory.glob("worker-*.json"):
        state = _load_worker_state(path)
        if state:
            states[int(state["pid"])] = state
    return states


def _list_child_workers(master_pid: int | None) -> list[psutil.Process]:
    master_process = _safe_process(master_pid)
    if not master_process:
        return []
    try:
        return [child for child in master_process.children(recursive=False) if child.is_running()]
    except Exception:
        return []


def _update_worker_target(target_workers: int, env_path: Path | None = None) -> None:
    env_path = env_path or ENV_FILE
    lines = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    updated = False
    for index, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if stripped.startswith("BACKEND_WORKERS="):
            lines[index] = f"BACKEND_WORKERS={target_workers}"
            updated = True
            break
    if not updated:
        lines.append(f"BACKEND_WORKERS={target_workers}")
    env_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


class RuntimeWorkerMonitor:
    def __init__(self):
        self.enabled = settings.worker_metrics_enabled
        self.flush_interval_seconds = max(1, settings.worker_metrics_flush_seconds)
        self.metrics_dir = resolve_metrics_dir()
        self.pid = os.getpid()
        self.hostname = socket.gethostname()
        self.process_started_at = utcnow()
        self._inflight_requests = 0
        self._handled_requests = 0
        self._last_request_at: datetime.datetime | None = None
        self._last_request_path = ""
        self._last_request_method = ""
        self._last_response_status = 0
        self._last_flushed_at = 0.0
        self._lock = threading.Lock()
        self._state_path = self.metrics_dir / f"worker-{self.pid}.json"
        atexit.register(self._cleanup_state_file)
        self._write_state(force=True)

    def _payload_locked(self) -> dict:
        process = _safe_process(self.pid)
        rss_mb = 0.0
        cpu_percent = 0.0
        thread_count = 0
        if process:
            rss_mb = round(process.memory_info().rss / (1024 * 1024), 2)
            cpu_percent = round(process.cpu_percent(interval=0.0), 2)
            thread_count = process.num_threads()
        return {
            "pid": self.pid,
            "hostname": self.hostname,
            "process_started_at": _isoformat(self.process_started_at),
            "updated_at": _isoformat(utcnow()),
            "last_request_at": _isoformat(self._last_request_at),
            "last_request_path": self._last_request_path,
            "last_request_method": self._last_request_method,
            "last_response_status": self._last_response_status,
            "inflight_requests": self._inflight_requests,
            "handled_requests": self._handled_requests,
            "rss_mb": rss_mb,
            "cpu_percent": cpu_percent,
            "thread_count": thread_count,
            "status": "busy" if self._inflight_requests > 0 else "idle",
        }

    def _write_state(self, *, force: bool = False) -> None:
        if not self.enabled:
            return
        with self._lock:
            now = time.monotonic()
            if not force and (now - self._last_flushed_at) < self.flush_interval_seconds:
                return
            _write_json_atomic(self._state_path, self._payload_locked())
            self._last_flushed_at = now

    def request_started(self, path: str, method: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            was_idle = self._inflight_requests == 0
            self._inflight_requests += 1
            self._last_request_at = utcnow()
            self._last_request_path = path
            self._last_request_method = method
            now = time.monotonic()
            if was_idle or (now - self._last_flushed_at) >= self.flush_interval_seconds:
                _write_json_atomic(self._state_path, self._payload_locked())
                self._last_flushed_at = now

    def request_finished(self, status_code: int = 0) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._handled_requests += 1
            self._inflight_requests = max(0, self._inflight_requests - 1)
            self._last_response_status = int(status_code or 0)
            now = time.monotonic()
            if self._inflight_requests == 0 or (now - self._last_flushed_at) >= self.flush_interval_seconds:
                _write_json_atomic(self._state_path, self._payload_locked())
                self._last_flushed_at = now

    def snapshot(self) -> dict:
        with self._lock:
            return self._payload_locked()

    def _cleanup_state_file(self) -> None:
        try:
            if self._state_path.exists():
                self._state_path.unlink()
        except OSError:
            pass


def get_runtime_worker_status() -> dict:
    metrics_dir = resolve_metrics_dir()
    states = _load_all_worker_states(metrics_dir)
    master_pid = _read_master_pid()
    child_workers = _list_child_workers(master_pid)
    child_worker_map = {process.pid: process for process in child_workers}

    if master_pid and child_worker_map:
        known_pids = set(child_worker_map.keys())
    else:
        known_pids = set(states.keys())
        if not known_pids:
            current_process = _safe_process(os.getpid())
            if current_process:
                known_pids.add(current_process.pid)

    workers = []
    for pid in sorted(known_pids):
        state = states.get(pid)
        if not state:
            process = child_worker_map.get(pid) or _safe_process(pid)
            if not process:
                continue
            state = _placeholder_worker_state(process)
        workers.append(state)

    busy_workers = sum(1 for worker in workers if int(worker.get("inflight_requests") or 0) > 0)
    idle_workers = max(0, len(workers) - busy_workers)
    total_inflight_requests = sum(int(worker.get("inflight_requests") or 0) for worker in workers)
    total_handled_requests = sum(int(worker.get("handled_requests") or 0) for worker in workers)

    return {
        "manager": {
            "mode": "gunicorn" if master_pid else "standalone",
            "master_pid": master_pid,
            "pidfile": str(resolve_pidfile_path()),
            "metrics_dir": str(metrics_dir),
            "configured_workers": settings.backend_workers,
            "can_scale": bool(master_pid and hasattr(signal, "SIGTTIN") and hasattr(signal, "SIGTTOU")),
        },
        "summary": {
            "configured_workers": settings.backend_workers,
            "active_workers": len(workers),
            "idle_workers": idle_workers,
            "busy_workers": busy_workers,
            "available_workers": idle_workers,
            "total_inflight_requests": total_inflight_requests,
            "total_handled_requests": total_handled_requests,
        },
        "workers": workers,
    }


def scale_runtime_workers(*, action: str, count: int = 1, persist: bool = False) -> dict:
    normalized_action = (action or "").strip().lower()
    if normalized_action not in {"add", "remove"}:
        raise RuntimeError("action must be 'add' or 'remove'")

    count = max(1, int(count or 1))
    status = get_runtime_worker_status()
    master_pid = status["manager"].get("master_pid")
    if not master_pid:
        raise RuntimeError("Dynamic worker scaling only works when backend runs under Gunicorn")
    if not hasattr(signal, "SIGTTIN") or not hasattr(signal, "SIGTTOU"):
        raise RuntimeError("Dynamic worker scaling is only available on POSIX-compatible hosts")

    active_workers = int(status["summary"].get("active_workers") or 0)
    if normalized_action == "remove" and active_workers - count < 1:
        raise RuntimeError("Cannot scale below 1 active worker")

    scale_signal = signal.SIGTTIN if normalized_action == "add" else signal.SIGTTOU
    for _ in range(count):
        os.kill(master_pid, scale_signal)
        time.sleep(0.25)

    time.sleep(1.0)
    updated_status = get_runtime_worker_status()
    if persist:
        updated_active_workers = int(updated_status["summary"].get("active_workers") or 1)
        _update_worker_target(max(1, updated_active_workers))
        updated_status["manager"]["configured_workers"] = max(1, updated_active_workers)
        updated_status["summary"]["configured_workers"] = max(1, updated_active_workers)
    updated_status["last_scale_action"] = {
        "action": normalized_action,
        "count": count,
        "persist": bool(persist),
    }
    return updated_status
