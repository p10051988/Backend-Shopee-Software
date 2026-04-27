from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import re
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings
from app_security import (
    current_timestamp,
    new_nonce,
    sign_hmac,
    sign_internal_request,
    sign_session_payload,
    verify_fragment_seal,
    verify_server_response,
)

try:
    from cryptography.fernet import Fernet
except Exception:  # pragma: no cover - optional dependency for module decrypt verification
    Fernet = None


DEFAULT_MODULES = [
    "_get_headers",
    "_ensure_fe_session",
    "_safe_json",
    "login_webchat",
    "get_conversation_list",
    "get_chat_messages",
    "send_message",
    "create_product_complete",
    "get_product_list",
    "update_product",
    "get_shop_rating_list",
    "reply_rating",
    "get_order_list_impl",
]


@dataclass
class VirtualUser:
    username: str
    password: str
    machine_id: str
    device_name: str
    access_key: str = ""
    session_key: str = ""
    session_id: str = ""
    sync_token: str = ""
    sync_token_ttl_seconds: int = 240
    session_epoch: int = 0
    session_expiration: str = ""


class ResultBook:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._durations: dict[str, list[float]] = {}
        self._status_buckets: dict[str, dict[int, int]] = {}
        self._error_buckets: dict[str, dict[str, int]] = {}
        self._success: dict[str, int] = {}
        self._total: dict[str, int] = {}

    def record(self, action: str, status: int, elapsed_ms: float, error_key: str = "") -> None:
        with self._lock:
            self._durations.setdefault(action, []).append(elapsed_ms)
            self._status_buckets.setdefault(action, {})[status] = self._status_buckets.setdefault(action, {}).get(status, 0) + 1
            self._total[action] = self._total.get(action, 0) + 1
            if 200 <= status < 400 and not error_key:
                self._success[action] = self._success.get(action, 0) + 1
            elif error_key:
                bucket = self._error_buckets.setdefault(action, {})
                bucket[error_key] = bucket.get(error_key, 0) + 1

    def summary(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for action, durations in self._durations.items():
            ordered = sorted(durations)
            total = self._total.get(action, 0)
            ok = self._success.get(action, 0)
            result[action] = {
                "requests": total,
                "ok": ok,
                "errors": max(0, total - ok),
                "avg_ms": round(statistics.mean(ordered) if ordered else 0.0, 2),
                "p50_ms": round(percentile(ordered, 0.50), 2),
                "p95_ms": round(percentile(ordered, 0.95), 2),
                "max_ms": round(max(ordered) if ordered else 0.0, 2),
                "status_buckets": self._status_buckets.get(action, {}),
                "error_buckets": self._error_buckets.get(action, {}),
            }
        return result


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    idx = max(0, min(len(values) - 1, int(round((len(values) - 1) * ratio))))
    return values[idx]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate public or authenticated Auto-Shopee desktop users")
    parser.add_argument("--base-url", default=settings.backend_url or "http://127.0.0.1:8000")
    parser.add_argument("--mode", choices=("public", "account", "access-key"), default="public")
    parser.add_argument("--users", type=int, default=200)
    parser.add_argument("--duration-seconds", type=int, default=70)
    parser.add_argument("--min-wait", type=float, default=20.0)
    parser.add_argument("--max-wait", type=float, default=40.0)
    parser.add_argument("--startup-spread", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--seed-users", action="store_true", help="Create users via internal API before running account mode")
    parser.add_argument("--seed-only", action="store_true", help="Create users/devices via internal API, print the account list, then exit")
    parser.add_argument("--deterministic-users", action="store_true", help="Use stable usernames and machine IDs so VPS seed and desktop load test match")
    parser.add_argument("--output-accounts-file", default="", help="Optional path to write the generated account list as JSON")
    parser.add_argument("--plan-code", default="plan-1m")
    parser.add_argument("--username-prefix", default="bench_user")
    parser.add_argument("--password", default="Bench@123456")
    parser.add_argument("--accounts-file", default="", help="JSON file with [{username,password,machine_id,device_name,access_key}]")
    parser.add_argument("--module-list", default=",".join(DEFAULT_MODULES))
    parser.add_argument("--build-id", default="DEV-SOURCE")
    parser.add_argument("--request-timeout", type=float, default=12.0)
    return parser.parse_args()


def sanitize_token(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip())
    return cleaned.strip("-") or "bench"


def users_to_jsonable(users: list[VirtualUser]) -> list[dict[str, str]]:
    return [
        {
            "username": user.username,
            "password": user.password,
            "machine_id": user.machine_id,
            "device_name": user.device_name,
            "access_key": user.access_key,
        }
        for user in users
    ]


def json_request(
    method: str,
    url: str,
    *,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any] | str, float, str]:
    started = time.perf_counter()
    payload = None
    final_headers = dict(headers or {})
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=payload, headers=final_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            try:
                return int(response.status), json.loads(raw), elapsed_ms, ""
            except Exception:
                return int(response.status), raw, elapsed_ms, ""
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        try:
            payload_obj = json.loads(raw)
        except Exception:
            payload_obj = raw
        return int(exc.code), payload_obj, elapsed_ms, f"http:{exc.code}"
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, "", elapsed_ms, type(exc).__name__


def build_url(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def build_internal_headers(secret: str, method: str, path: str, body: dict | None) -> dict[str, str]:
    timestamp = str(current_timestamp())
    nonce = new_nonce()
    return {
        "X-Internal-Key": "autoshopee-internal",
        "X-Internal-Timestamp": timestamp,
        "X-Internal-Nonce": nonce,
        "X-Internal-Signature": sign_internal_request(secret, method, path, timestamp, nonce, body),
    }


def build_session_body(user: VirtualUser, module_name: str, build_id: str) -> dict[str, Any]:
    payload = {
        "build_id": build_id,
        "session_id": user.session_id,
        "machine_id": user.machine_id,
        "module_name": module_name,
        "sync_token": user.sync_token,
        "nonce": new_nonce(),
        "timestamp": current_timestamp(),
    }
    payload["signature"] = sign_session_payload(user.session_key, payload)
    return payload


def verify_module_response(user: VirtualUser, module_name: str, data: dict[str, Any]) -> tuple[bool, str]:
    signature = str(data.get("response_signature") or "")
    if not signature or not verify_server_response(user.session_key, data, signature):
        return False, "response_signature_invalid"
    encrypted_code = str(data.get("encrypted_code") or "")
    if not encrypted_code:
        return False, "encrypted_code_missing"
    if Fernet is not None:
        try:
            raw_code = Fernet(user.session_key.encode("utf-8")).decrypt(encrypted_code.encode("utf-8"))
            if not raw_code:
                return False, "module_empty"
        except Exception:
            return False, "module_decrypt_failed"
    fragment_payload = {
        "module_name": module_name,
        "session_id": user.session_id,
        "session_epoch": int(data.get("session_epoch", user.session_epoch) or user.session_epoch or 0),
        "checksum": str(data.get("checksum", "") or ""),
    }
    fragment_seal = str(data.get("fragment_seal", "") or "")
    if fragment_seal and not verify_fragment_seal(user.session_key, fragment_payload, fragment_seal):
        return False, "fragment_seal_invalid"
    return True, ""


def verify_heartbeat_response(user: VirtualUser, data: dict[str, Any]) -> tuple[bool, str]:
    signature = str(data.get("response_signature") or "")
    if not signature or not verify_server_response(user.session_key, data, signature):
        return False, "response_signature_invalid"
    token = str(data.get("sync_token") or "")
    token_signature = str(data.get("signature") or "")
    if not token or not token_signature:
        return False, "sync_token_missing"
    if sign_hmac(user.session_key, token) != token_signature:
        return False, "sync_token_signature_invalid"
    user.sync_token = token
    user.sync_token_ttl_seconds = int(data.get("sync_token_ttl_seconds", user.sync_token_ttl_seconds) or user.sync_token_ttl_seconds)
    user.session_epoch = int(data.get("session_epoch", user.session_epoch) or user.session_epoch)
    user.session_expiration = str(data.get("session_expiration", user.session_expiration) or user.session_expiration)
    return True, ""


def account_login(base_url: str, user: VirtualUser, build_id: str, timeout: float) -> tuple[int, float, str]:
    body = {
        "username": user.username,
        "password": user.password,
        "machine_id": user.machine_id,
        "device_name": user.device_name,
        "device_binding": f"bind-{user.machine_id}",
        "build_id": build_id,
        "build_attestation": {},
    }
    status, data, elapsed_ms, error_key = json_request("POST", build_url(base_url, "/api/public/login"), body=body, timeout=timeout)
    if status == 200 and isinstance(data, dict):
        user.session_key = str(data.get("session_key") or "")
        user.session_id = str(data.get("session_id") or "")
        user.sync_token = str(data.get("sync_token") or "")
        user.sync_token_ttl_seconds = int(data.get("sync_token_ttl_seconds", user.sync_token_ttl_seconds) or user.sync_token_ttl_seconds)
        user.session_epoch = int(data.get("session_epoch", user.session_epoch) or user.session_epoch)
        user.session_expiration = str(data.get("session_expiration", "") or "")
        if not user.session_key or not user.session_id:
            return status, elapsed_ms, "session_fields_missing"
        return status, elapsed_ms, ""
    return status, elapsed_ms, error_key or "login_failed"


def access_key_login(base_url: str, user: VirtualUser, build_id: str, timeout: float) -> tuple[int, float, str]:
    body = {
        "access_key": user.access_key,
        "machine_id": user.machine_id,
        "device_name": user.device_name,
        "device_binding": f"bind-{user.machine_id}",
        "build_id": build_id,
        "build_attestation": {},
    }
    status, data, elapsed_ms, error_key = json_request("POST", build_url(base_url, "/api/public/access-key-login"), body=body, timeout=timeout)
    if status == 200 and isinstance(data, dict):
        user.session_key = str(data.get("session_key") or "")
        user.session_id = str(data.get("session_id") or "")
        user.sync_token = str(data.get("sync_token") or "")
        user.sync_token_ttl_seconds = int(data.get("sync_token_ttl_seconds", user.sync_token_ttl_seconds) or user.sync_token_ttl_seconds)
        user.session_epoch = int(data.get("session_epoch", user.session_epoch) or user.session_epoch)
        user.session_expiration = str(data.get("session_expiration", "") or "")
        if not user.session_key or not user.session_id:
            return status, elapsed_ms, "session_fields_missing"
        return status, elapsed_ms, ""
    return status, elapsed_ms, error_key or "access_key_login_failed"


def do_heartbeat(base_url: str, user: VirtualUser, build_id: str, timeout: float) -> tuple[int, float, str]:
    body = build_session_body(user, "", build_id)
    status, data, elapsed_ms, error_key = json_request("POST", build_url(base_url, "/heartbeat"), body=body, timeout=timeout)
    if status == 200 and isinstance(data, dict):
        ok, verify_error = verify_heartbeat_response(user, data)
        if ok:
            return status, elapsed_ms, ""
        return status, elapsed_ms, verify_error
    return status, elapsed_ms, error_key or "heartbeat_failed"


def do_fetch_module(base_url: str, user: VirtualUser, module_name: str, build_id: str, timeout: float) -> tuple[int, float, str]:
    body = build_session_body(user, module_name, build_id)
    status, data, elapsed_ms, error_key = json_request("POST", build_url(base_url, "/fetch_module"), body=body, timeout=timeout)
    if status == 200 and isinstance(data, dict):
        ok, verify_error = verify_module_response(user, module_name, data)
        if ok:
            return status, elapsed_ms, ""
        return status, elapsed_ms, verify_error
    return status, elapsed_ms, error_key or "fetch_module_failed"


def do_public_request(base_url: str, path: str, timeout: float) -> tuple[int, float, str]:
    status, _data, elapsed_ms, error_key = json_request("GET", build_url(base_url, path), timeout=timeout)
    return status, elapsed_ms, error_key


def maybe_seed_users(args: argparse.Namespace, users: list[VirtualUser]) -> None:
    if args.mode != "account" or not args.seed_users:
        return
    secret = settings.internal_api_secret
    if not secret:
        raise RuntimeError("INTERNAL_API_SECRET is empty; cannot seed users")

    for user in users:
        upsert_body = {
            "username": user.username,
            "email": f"{user.username}@example.com",
            "password": user.password,
            "full_name": user.username,
            "is_active": True,
            "notes": "simulate_live_users seed",
        }
        path = "/api/internal/users/upsert"
        status, _data, _elapsed_ms, error_key = json_request(
            "POST",
            build_url(args.base_url, path),
            body=upsert_body,
            headers=build_internal_headers(secret, "POST", path, upsert_body),
            timeout=args.request_timeout,
        )
        if status != 200:
            raise RuntimeError(f"user seed failed for {user.username}: {status} {error_key}")

        grant_body = {
            "user_identity": user.username,
            "plan_code": args.plan_code,
            "status": "active",
            "replace_existing_active": True,
            "notes": "simulate_live_users grant",
        }
        path = "/api/internal/subscriptions/grant"
        status, _data, _elapsed_ms, error_key = json_request(
            "POST",
            build_url(args.base_url, path),
            body=grant_body,
            headers=build_internal_headers(secret, "POST", path, grant_body),
            timeout=args.request_timeout,
        )
        if status != 200:
            raise RuntimeError(f"subscription grant failed for {user.username}: {status} {error_key}")

        auth_body = {
            "user_identity": user.username,
            "machine_id": user.machine_id,
            "device_name": user.device_name,
            "status": "active",
            "notes": "simulate_live_users device",
        }
        path = "/api/internal/devices/authorize"
        status, data, _elapsed_ms, error_key = json_request(
            "POST",
            build_url(args.base_url, path),
            body=auth_body,
            headers=build_internal_headers(secret, "POST", path, auth_body),
            timeout=args.request_timeout,
        )
        if status != 200:
            raise RuntimeError(f"device authorize failed for {user.username}: {status} {error_key}")
        if isinstance(data, dict):
            user.access_key = str(data.get("access_key") or user.access_key)


def build_users(args: argparse.Namespace) -> list[VirtualUser]:
    if args.accounts_file:
        items = json.loads(Path(args.accounts_file).read_text(encoding="utf-8"))
        users = []
        for item in items:
            users.append(
                VirtualUser(
                    username=str(item.get("username") or ""),
                    password=str(item.get("password") or ""),
                    machine_id=str(item.get("machine_id") or f"MID-{new_nonce().replace('-', '')[:16]}"),
                    device_name=str(item.get("device_name") or "SIM-DEVICE"),
                    access_key=str(item.get("access_key") or ""),
                )
            )
        return users

    prefix = sanitize_token(args.username_prefix)
    return [
        VirtualUser(
            username=f"{args.username_prefix}_{index:03d}",
            password=args.password,
            machine_id=(
                f"MID-BENCH-{prefix}-{index:04d}"
                if args.deterministic_users
                else f"MID-BENCH-{index:03d}-{new_nonce().replace('-', '')[:12]}"
            ),
            device_name=f"SIM-USER-{index:03d}",
        )
        for index in range(1, max(1, args.users) + 1)
    ]


def simulate_public_user(base_url: str, stop_at: float, args: argparse.Namespace, book: ResultBook) -> None:
    if args.startup_spread > 0:
        time.sleep(random.uniform(0.0, args.startup_spread))
    paths = ["/api/public/health", "/api/public/plans"]
    while time.time() < stop_at:
        path = random.choice(paths)
        status, elapsed_ms, error_key = do_public_request(base_url, path, timeout=args.request_timeout)
        book.record(path, status, elapsed_ms, error_key)
        sleep_seconds = random.uniform(args.min_wait, args.max_wait)
        if time.time() + sleep_seconds >= stop_at:
            break
        time.sleep(sleep_seconds)


def simulate_authenticated_user(
    base_url: str,
    stop_at: float,
    args: argparse.Namespace,
    book: ResultBook,
    user: VirtualUser,
    modules: list[str],
) -> None:
    if args.startup_spread > 0:
        time.sleep(random.uniform(0.0, args.startup_spread))
    if args.mode == "account":
        status, elapsed_ms, error_key = account_login(base_url, user, args.build_id, args.request_timeout)
        book.record("login", status, elapsed_ms, error_key)
    else:
        status, elapsed_ms, error_key = access_key_login(base_url, user, args.build_id, args.request_timeout)
        book.record("access-key-login", status, elapsed_ms, error_key)
    if error_key:
        return

    while time.time() < stop_at:
        if random.random() < 0.55:
            status, elapsed_ms, error_key = do_heartbeat(base_url, user, args.build_id, args.request_timeout)
            book.record("heartbeat", status, elapsed_ms, error_key)
        else:
            module_name = random.choice(modules)
            status, elapsed_ms, error_key = do_fetch_module(base_url, user, module_name, args.build_id, args.request_timeout)
            book.record(f"fetch:{module_name}", status, elapsed_ms, error_key)
        if error_key and status in {0, 401, 403}:
            if args.mode == "account":
                status, elapsed_ms, error_key = account_login(base_url, user, args.build_id, args.request_timeout)
                book.record("relogin", status, elapsed_ms, error_key)
            elif user.access_key:
                status, elapsed_ms, error_key = access_key_login(base_url, user, args.build_id, args.request_timeout)
                book.record("relogin", status, elapsed_ms, error_key)
        sleep_seconds = random.uniform(args.min_wait, args.max_wait)
        if time.time() + sleep_seconds >= stop_at:
            break
        time.sleep(sleep_seconds)


def main() -> None:
    args = parse_args()
    if args.seed_only:
        args.seed_users = True
        if args.mode != "account":
            raise RuntimeError("--seed-only requires --mode account")
    random.seed(20260422)
    started = time.perf_counter()
    stop_at = time.time() + max(1, args.duration_seconds)
    modules = [item.strip() for item in args.module_list.split(",") if item.strip()]
    users = build_users(args)
    if args.mode == "public":
        users = users[: max(1, args.users)]
    elif len(users) != args.users and not args.accounts_file:
        users = users[: max(1, args.users)]

    maybe_seed_users(args, users)

    if args.output_accounts_file:
        Path(args.output_accounts_file).write_text(
            json.dumps(users_to_jsonable(users), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    if args.seed_only:
        print(
            json.dumps(
                {
                    "base_url": args.base_url,
                    "mode": args.mode,
                    "seeded_users": len(users),
                    "plan_code": args.plan_code,
                    "deterministic_users": bool(args.deterministic_users),
                    "accounts_file": args.output_accounts_file or "",
                    "sample_accounts": users_to_jsonable(users[:3]),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    book = ResultBook()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(users))) as executor:
        futures = []
        if args.mode == "public":
            for _user in users:
                futures.append(executor.submit(simulate_public_user, args.base_url, stop_at, args, book))
        else:
            for user in users:
                futures.append(executor.submit(simulate_authenticated_user, args.base_url, stop_at, args, book, user, modules))
        for future in concurrent.futures.as_completed(futures):
            future.result()

    elapsed = max(time.perf_counter() - started, 0.001)
    print(
        json.dumps(
            {
                "base_url": args.base_url,
                "mode": args.mode,
                "users": len(users),
                "duration_seconds": args.duration_seconds,
                "interaction_window_seconds": [args.min_wait, args.max_wait],
                "total_elapsed_seconds": round(elapsed, 2),
                "results": book.summary(),
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
