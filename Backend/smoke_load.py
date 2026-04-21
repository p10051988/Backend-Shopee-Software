from __future__ import annotations

import argparse
import concurrent.futures
import json
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings
from app_security import current_timestamp, new_nonce, sign_internal_request


@dataclass
class Scenario:
    name: str
    method: str
    path: str
    body: dict | None = None
    internal: bool = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lightweight smoke/load checker for Auto-Shopee backend")
    parser.add_argument("--base-url", default=settings.backend_url or "http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=60, help="Requests per scenario")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent workers per scenario")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds")
    parser.add_argument("--path", default="", help="Optional custom path to test instead of built-in scenarios")
    parser.add_argument("--method", default="GET", help="HTTP method for --path")
    parser.add_argument("--body", default="", help="JSON body string for --path")
    parser.add_argument("--include-internal", action="store_true", help="Also test internal worker-status route")
    return parser.parse_args()


def build_scenarios(args: argparse.Namespace) -> list[Scenario]:
    if args.path:
        body = json.loads(args.body) if args.body else None
        return [Scenario(name="custom", method=args.method.upper(), path=args.path, body=body, internal=False)]

    scenarios = [
        Scenario(name="health", method="GET", path="/api/public/health"),
        Scenario(name="plans", method="GET", path="/api/public/plans"),
    ]
    if args.include_internal and settings.internal_api_secret:
        scenarios.append(
            Scenario(
                name="runtime-workers",
                method="GET",
                path="/api/internal/runtime/workers",
                internal=True,
            )
        )
    return scenarios


def make_request(base_url: str, scenario: Scenario, timeout: float) -> tuple[int, float, str]:
    body_bytes = None
    headers = {}
    if scenario.body is not None:
        body_bytes = json.dumps(scenario.body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if scenario.internal:
        timestamp = str(current_timestamp())
        nonce = new_nonce()
        signature = sign_internal_request(
            settings.internal_api_secret,
            scenario.method,
            scenario.path,
            timestamp,
            nonce,
            scenario.body,
        )
        headers["X-Internal-Key"] = "autoshopee-internal"
        headers["X-Internal-Timestamp"] = timestamp
        headers["X-Internal-Nonce"] = nonce
        headers["X-Internal-Signature"] = signature

    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", scenario.path.lstrip("/"))
    request = urllib.request.Request(url=url, method=scenario.method, data=body_bytes, headers=headers)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(64)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return int(response.status), elapsed_ms, ""
    except urllib.error.HTTPError as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return int(exc.code), elapsed_ms, f"http:{exc.code}"
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, elapsed_ms, type(exc).__name__


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * ratio))))
    return ordered[index]


def run_scenario(base_url: str, scenario: Scenario, total_requests: int, concurrency: int, timeout: float) -> dict:
    started = time.perf_counter()
    durations = []
    ok_count = 0
    errors: dict[str, int] = {}
    status_buckets: dict[int, int] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = [executor.submit(make_request, base_url, scenario, timeout) for _ in range(total_requests)]
        for future in concurrent.futures.as_completed(futures):
            status_code, elapsed_ms, error_key = future.result()
            durations.append(elapsed_ms)
            status_buckets[status_code] = status_buckets.get(status_code, 0) + 1
            if 200 <= status_code < 400:
                ok_count += 1
            elif error_key:
                errors[error_key] = errors.get(error_key, 0) + 1

    elapsed_total = max(time.perf_counter() - started, 0.001)
    return {
        "scenario": scenario.name,
        "path": scenario.path,
        "requests": total_requests,
        "concurrency": concurrency,
        "ok": ok_count,
        "errors": total_requests - ok_count,
        "status_buckets": status_buckets,
        "error_buckets": errors,
        "rps": round(total_requests / elapsed_total, 2),
        "avg_ms": round(statistics.mean(durations) if durations else 0.0, 2),
        "p50_ms": round(percentile(durations, 0.50), 2),
        "p95_ms": round(percentile(durations, 0.95), 2),
        "max_ms": round(max(durations) if durations else 0.0, 2),
    }


def main() -> None:
    args = parse_args()
    scenarios = build_scenarios(args)
    results = [
        run_scenario(
            base_url=args.base_url,
            scenario=scenario,
            total_requests=max(1, int(args.requests or 1)),
            concurrency=max(1, int(args.concurrency or 1)),
            timeout=max(1.0, float(args.timeout or 1.0)),
        )
        for scenario in scenarios
    ]
    print(json.dumps({"base_url": args.base_url, "results": results}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
