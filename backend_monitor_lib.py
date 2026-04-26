#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT_CANDIDATES = [SCRIPT_DIR, SCRIPT_DIR.parent]
for candidate in REPO_ROOT_CANDIDATES:
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from app_security import current_timestamp, new_nonce, sign_internal_request  # noqa: E402


@dataclass
class MonitorConfig:
    base_url: str
    internal_api_secret: str
    timeout_seconds: int
    alert_poll_seconds: int
    alert_cooldown_seconds: int
    alert_error_rate_percent: float
    alert_p95_ms: float
    alert_avg_ms: float
    alert_cpu_percent: float
    alert_mem_available_mb: int
    alert_disk_percent: float
    telegram_bot_token: str
    telegram_chat_id: str


def load_env(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_path.exists():
        return values
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def merged_env() -> dict[str, str]:
    env = load_env(SCRIPT_DIR / ".env")
    env.update({k: v for k, v in os.environ.items() if v is not None})
    return env


def infer_local_base_url(env: dict[str, str]) -> str:
    explicit = (env.get("BACKEND_MONITOR_BASE_URL") or "").strip()
    if explicit:
        return explicit.rstrip("/")
    bind = (env.get("BACKEND_BIND") or "0.0.0.0:8000").strip()
    host = "127.0.0.1"
    port = "8000"
    if ":" in bind:
        _, port = bind.rsplit(":", 1)
    return f"http://{host}:{port}".rstrip("/")


def load_config() -> MonitorConfig:
    env = merged_env()
    return MonitorConfig(
        base_url=infer_local_base_url(env),
        internal_api_secret=(env.get("INTERNAL_API_SECRET") or "").strip(),
        timeout_seconds=max(int(env.get("BACKEND_MONITOR_TIMEOUT_SECONDS", "10") or 10), 3),
        alert_poll_seconds=max(int(env.get("BACKEND_ALERT_POLL_SECONDS", "60") or 60), 15),
        alert_cooldown_seconds=max(int(env.get("BACKEND_ALERT_COOLDOWN_SECONDS", "900") or 900), 60),
        alert_error_rate_percent=float(env.get("BACKEND_ALERT_ERROR_RATE_PERCENT", "5") or 5),
        alert_p95_ms=float(env.get("BACKEND_ALERT_P95_MS", "1500") or 1500),
        alert_avg_ms=float(env.get("BACKEND_ALERT_AVG_MS", "700") or 700),
        alert_cpu_percent=float(env.get("BACKEND_ALERT_CPU_PERCENT", "85") or 85),
        alert_mem_available_mb=int(env.get("BACKEND_ALERT_MEM_AVAILABLE_MB", "200") or 200),
        alert_disk_percent=float(env.get("BACKEND_ALERT_DISK_PERCENT", "90") or 90),
        telegram_bot_token=(env.get("TELEGRAM_BOT_TOKEN") or "").strip(),
        telegram_chat_id=(env.get("TELEGRAM_CHAT_ID") or "").strip(),
    )


def _decode_json_response(resp: urllib.response.addinfourl) -> dict[str, Any]:
    raw = resp.read().decode("utf-8")
    if not raw.strip():
        return {}
    return json.loads(raw)


def internal_get(config: MonitorConfig, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    if not config.internal_api_secret:
        raise RuntimeError("INTERNAL_API_SECRET is missing in .env")
    ts = str(current_timestamp())
    nonce = new_nonce()
    query = ""
    if params:
        query = "?" + urllib.parse.urlencode(params)
    url = config.base_url + path + query
    headers = {
        "X-Internal-Key": "autoshopee-internal",
        "X-Internal-Timestamp": ts,
        "X-Internal-Nonce": nonce,
        "X-Internal-Signature": sign_internal_request(config.internal_api_secret, "GET", path, ts, nonce, None),
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=config.timeout_seconds) as resp:
        return _decode_json_response(resp)


def public_get(config: MonitorConfig, path: str) -> dict[str, Any]:
    req = urllib.request.Request(config.base_url + path, method="GET")
    with urllib.request.urlopen(req, timeout=config.timeout_seconds) as resp:
        return _decode_json_response(resp)


def read_pid(pid_path: Path) -> tuple[int | None, bool]:
    if not pid_path.exists():
        return None, False
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except Exception:
        return None, False
    try:
        os.kill(pid, 0)
        return pid, True
    except OSError:
        return pid, False


def read_os_name() -> str:
    os_release = Path("/etc/os-release")
    if os_release.exists():
        data = load_env(os_release)
        pretty = data.get("PRETTY_NAME") or data.get("NAME")
        if pretty:
            return pretty
    try:
        return " ".join(os.uname())
    except Exception:
        return "Linux"


def read_uptime_seconds() -> int:
    try:
        proc_path = Path("/proc/uptime")
        if not proc_path.exists():
            return 0
        return int(float(proc_path.read_text(encoding="utf-8").split()[0]))
    except Exception:
        return 0


def format_duration(seconds: int) -> str:
    days, rem = divmod(max(seconds, 0), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, sec = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if days or hours:
        parts.append(f"{hours}h")
    if days or hours or minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{sec}s")
    return " ".join(parts)


def sample_cpu_percent(sample_seconds: float = 0.25) -> float:
    def read_cpu() -> tuple[int, int]:
        proc_path = Path("/proc/stat")
        if not proc_path.exists():
            return 0, 0
        fields = proc_path.read_text(encoding="utf-8").splitlines()[0].split()[1:]
        numbers = [int(item) for item in fields]
        idle = numbers[3] + numbers[4]
        total = sum(numbers)
        return idle, total

    idle1, total1 = read_cpu()
    time.sleep(sample_seconds)
    idle2, total2 = read_cpu()
    idle_delta = idle2 - idle1
    total_delta = total2 - total1
    if total_delta <= 0:
        return 0.0
    return round((1 - (idle_delta / total_delta)) * 100, 2)


def read_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    proc_path = Path("/proc/meminfo")
    if not proc_path.exists():
        return values
    for line in proc_path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        parts = raw_value.strip().split()
        if not parts:
            continue
        values[key] = int(parts[0])
    return values


def read_system_stats() -> dict[str, Any]:
    mem = read_meminfo()
    mem_total_mb = mem.get("MemTotal", 0) // 1024
    mem_available_mb = mem.get("MemAvailable", 0) // 1024
    mem_used_mb = max(mem_total_mb - mem_available_mb, 0)
    swap_total_mb = mem.get("SwapTotal", 0) // 1024
    swap_free_mb = mem.get("SwapFree", 0) // 1024
    swap_used_mb = max(swap_total_mb - swap_free_mb, 0)
    disk = shutil.disk_usage("/")
    disk_total_gb = round(disk.total / (1024**3), 1)
    disk_used_gb = round((disk.total - disk.free) / (1024**3), 1)
    disk_percent = round(((disk.total - disk.free) / disk.total) * 100, 1) if disk.total else 0.0
    return {
        "hostname": socket.gethostname(),
        "os_name": read_os_name(),
        "cpu_percent": sample_cpu_percent(),
        "mem_total_mb": mem_total_mb,
        "mem_used_mb": mem_used_mb,
        "mem_available_mb": mem_available_mb,
        "swap_total_mb": swap_total_mb,
        "swap_used_mb": swap_used_mb,
        "disk_total_gb": disk_total_gb,
        "disk_used_gb": disk_used_gb,
        "disk_percent": disk_percent,
        "load_average": os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0),
        "uptime_seconds": read_uptime_seconds(),
    }


def safe_fetch(config: MonitorConfig) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "base_url": config.base_url,
        "health": None,
        "stats": None,
        "connections": None,
        "traffic": None,
        "system": read_system_stats(),
        "errors": [],
    }
    for label, fn in (
        ("health", lambda: public_get(config, "/api/public/health")),
        ("stats", lambda: internal_get(config, "/api/internal/stats")),
        ("connections", lambda: internal_get(config, "/api/internal/runtime/connections", {"include_sessions": "true"})),
        ("traffic", lambda: internal_get(config, "/api/internal/runtime/traffic", {"days": 1})),
    ):
        try:
            payload[label] = fn()
        except urllib.error.HTTPError as exc:
            payload["errors"].append(f"{label}: HTTP {exc.code}")
        except Exception as exc:
            payload["errors"].append(f"{label}: {exc}")
    backend_pid, backend_running = read_pid(SCRIPT_DIR / "run" / "backend.pid")
    sidecar_pid, sidecar_running = read_pid(SCRIPT_DIR / "run" / "sidecar.pid")
    payload["process"] = {
        "backend_pid": backend_pid,
        "backend_running": backend_running,
        "sidecar_pid": sidecar_pid,
        "sidecar_running": sidecar_running,
    }
    return payload


def classify_state(snapshot: dict[str, Any], config: MonitorConfig) -> tuple[str, list[str]]:
    reasons: list[str] = []
    health = snapshot.get("health") or {}
    traffic = snapshot.get("traffic") or {}
    system = snapshot.get("system") or {}
    if not health or health.get("status") != "ok":
        reasons.append("backend health is not ok")
    if float(traffic.get("error_rate_percent") or 0) >= config.alert_error_rate_percent:
        reasons.append(f"error rate >= {config.alert_error_rate_percent}%")
    if float(traffic.get("p95_latency_ms") or 0) >= config.alert_p95_ms:
        reasons.append(f"p95 latency >= {int(config.alert_p95_ms)}ms")
    if float(traffic.get("avg_latency_ms") or 0) >= config.alert_avg_ms:
        reasons.append(f"avg latency >= {int(config.alert_avg_ms)}ms")
    if float(system.get("cpu_percent") or 0) >= config.alert_cpu_percent:
        reasons.append(f"cpu >= {int(config.alert_cpu_percent)}%")
    if int(system.get("mem_available_mb") or 0) <= config.alert_mem_available_mb:
        reasons.append(f"available mem <= {config.alert_mem_available_mb} MB")
    if float(system.get("disk_percent") or 0) >= config.alert_disk_percent:
        reasons.append(f"disk >= {int(config.alert_disk_percent)}%")
    if reasons:
        severe = any("backend health" in reason or "p95 latency" in reason or "available mem" in reason for reason in reasons)
        return ("CRITICAL" if severe else "WARNING"), reasons
    return "HEALTHY", []


def send_telegram(config: MonitorConfig, text: str) -> None:
    if not config.telegram_bot_token or not config.telegram_chat_id:
        return
    payload = urllib.parse.urlencode(
        {
            "chat_id": config.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        _decode_json_response(resp)


def load_state_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state_file(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_alert_message(snapshot: dict[str, Any], status: str, reasons: list[str]) -> str:
    traffic = snapshot.get("traffic") or {}
    connections = snapshot.get("connections") or {}
    system = snapshot.get("system") or {}
    lines = [
        f"<b>Auto-Shopee Backend Alert</b>",
        f"Status: <b>{status}</b>",
        f"Reasons: {', '.join(reasons) if reasons else 'none'}",
        "",
        f"Online users: {connections.get('authoritative_online_users', 0)}",
        f"Online sessions: {connections.get('authoritative_online_sessions', 0)}",
        f"Error rate: {traffic.get('error_rate_percent', 0)}%",
        f"Latency avg/p95/max: {traffic.get('avg_latency_ms', 0)} / {traffic.get('p95_latency_ms', 0)} / {traffic.get('max_latency_ms', 0)} ms",
        f"Requests ok/err: {traffic.get('total_ok', 0)} / {traffic.get('total_errors', 0)}",
        f"CPU: {system.get('cpu_percent', 0)}% | Mem avail: {system.get('mem_available_mb', 0)} MB | Disk: {system.get('disk_percent', 0)}%",
    ]
    return "\n".join(lines)
