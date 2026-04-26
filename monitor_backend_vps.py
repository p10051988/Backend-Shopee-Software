#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime

from backend_monitor_lib import classify_state, format_duration, load_config, safe_fetch


RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
DIM = "\033[2m"
BOLD = "\033[1m"


def color_for_status(status: str) -> str:
    return {"HEALTHY": GREEN, "WARNING": YELLOW, "CRITICAL": RED}.get(status, CYAN)


def draw_line(width: int, char: str = "=") -> str:
    return CYAN + (char * max(width, 40)) + RESET


def fmt_mb(used: int, total: int) -> str:
    return f"{used}/{total} MB"


def fmt_swap(used: int, total: int) -> str:
    return f"{used}/{total} MB"


def fmt_disk(used: float, total: float, percent: float) -> str:
    return f"{used:.1f}/{total:.1f} GB ({percent:.1f}%)"


def render(snapshot: dict, status: str, reasons: list[str]) -> str:
    size = shutil.get_terminal_size((120, 40))
    width = size.columns
    system = snapshot.get("system") or {}
    process = snapshot.get("process") or {}
    traffic = snapshot.get("app_traffic") or {}
    raw_traffic = snapshot.get("traffic") or {}
    connections = snapshot.get("connections") or {}
    health = snapshot.get("health") or {}
    stats = snapshot.get("stats") or {}
    routes = list((traffic.get("routes") or []))[:6]
    sessions = list((connections.get("sessions") or []))[:6]
    status_color = color_for_status(status)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines: list[str] = []
    lines.append(draw_line(width))
    lines.append(f"{BOLD}{CYAN} AUTO-SHOPEE BACKEND MONITOR {RESET}  {DIM}{now_str}{RESET}")
    lines.append(f" Host: {BLUE}{system.get('hostname', '-')}{RESET}  |  OS: {system.get('os_name', '-')}")
    lines.append(f" Base URL: {snapshot.get('base_url', '-')}")
    lines.append(draw_line(width))
    lines.append(
        f" Status: {status_color}{status}{RESET}"
        f"  |  Health: {GREEN if health.get('status') == 'ok' else RED}{health.get('status', 'down')}{RESET}"
        f"  |  Backend PID: {process.get('backend_pid') or '-'}"
        f"  |  Sidecar PID: {process.get('sidecar_pid') or '-'}"
    )
    if reasons:
        lines.append(f" Reasons: {status_color}{'; '.join(reasons)}{RESET}")
    lines.append(
        f" CPU: {system.get('cpu_percent', 0)}%  |  RAM: {fmt_mb(system.get('mem_used_mb', 0), system.get('mem_total_mb', 0))}"
        f"  |  Swap: {fmt_swap(system.get('swap_used_mb', 0), system.get('swap_total_mb', 0))}"
        f"  |  Disk: {fmt_disk(system.get('disk_used_gb', 0), system.get('disk_total_gb', 0), system.get('disk_percent', 0))}"
    )
    load_avg = system.get("load_average") or (0.0, 0.0, 0.0)
    lines.append(
        f" Uptime: {format_duration(int(system.get('uptime_seconds', 0)))}"
        f"  |  Load Avg: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}"
        f"  |  Backend uptime: {format_duration(int(raw_traffic.get('server_uptime_seconds', 0)))}"
    )
    lines.append(draw_line(width, "-"))
    lines.append(
        f" Online Users: {BOLD}{connections.get('authoritative_online_users', 0)}{RESET}"
        f"  |  Sessions: {BOLD}{connections.get('authoritative_online_sessions', 0)}{RESET}"
        f"  |  Devices: {BOLD}{connections.get('authoritative_online_devices', 0)}{RESET}"
        f"  |  Window: {connections.get('online_window_seconds', 0)}s"
    )
    lines.append(
        f" DB Live Sessions: {stats.get('live_sessions_db', 0)}"
        f"  |  Active Sessions(DB any): {stats.get('active_sessions', 0)}"
        f"  |  Inflight: {raw_traffic.get('inflight_requests', 0)}"
        f"  |  Handled Since Boot: {raw_traffic.get('handled_requests_since_boot', 0)}"
    )
    lines.append(draw_line(width, "-"))
    lines.append(
        f" App Requests: {traffic.get('total_requests', 0)}"
        f"  |  Success: {traffic.get('total_ok', 0)}"
        f"  |  Fail: {traffic.get('total_errors', 0)}"
        f"  |  Error Rate: {traffic.get('error_rate_percent', 0)}%"
    )
    lines.append(f" Monitor/Admin Requests Hidden: {traffic.get('monitor_requests_hidden', 0)}")
    lines.append(
        f" Latency Avg: {traffic.get('avg_latency_ms', 0)} ms"
        f"  |  P95: {traffic.get('p95_latency_ms', 0)} ms"
        f"  |  Max: {traffic.get('max_latency_ms', 0)} ms"
    )
    lines.append(draw_line(width, "-"))
    lines.append(f"{BOLD} Top Routes (last window report){RESET}")
    if routes:
        for item in routes:
            route = (item.get("route") or "-")[:44]
            lines.append(
                f" - {route:<44} req={item.get('requests', 0):>6} ok={item.get('ok', 0):>6}"
                f" err={item.get('errors', 0):>5} avg={item.get('avg_latency_ms', 0):>7}ms"
                f" p95={item.get('p95_latency_ms', 0):>7}ms"
            )
    else:
        lines.append(" - no route data yet")
    lines.append(draw_line(width, "-"))
    lines.append(f"{BOLD} Recent Online Sessions{RESET}")
    if sessions:
        for item in sessions:
            account = (item.get("account_username") or "-")[:18]
            machine = (item.get("machine_id") or "-")[:18]
            last_route = (item.get("last_route") or "-")[:24]
            last_seen = item.get("last_seen_at") or "-"
            lines.append(f" - {account:<18} | {machine:<18} | {last_route:<24} | {last_seen}")
    else:
        lines.append(" - no active sessions in memory")
    if snapshot.get("errors"):
        lines.append(draw_line(width, "-"))
        lines.append(f"{RED}{BOLD} Fetch Errors{RESET}")
        for item in snapshot["errors"]:
            lines.append(f" - {item}")
    lines.append(draw_line(width))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Print once and exit")
    parser.add_argument("--interval", type=int, default=2, help="Refresh interval in seconds")
    parser.add_argument("--json", action="store_true", help="Output raw JSON snapshot once")
    args = parser.parse_args()

    config = load_config()
    while True:
        snapshot = safe_fetch(config)
        status, reasons = classify_state(snapshot, config)
        if args.json:
            print(json.dumps(snapshot, ensure_ascii=False, indent=2, default=str))
            return 0
        if not args.once:
            os.system("clear")
        print(render(snapshot, status, reasons))
        if args.once:
            return 0
        time.sleep(max(args.interval, 1))


if __name__ == "__main__":
    raise SystemExit(main())
