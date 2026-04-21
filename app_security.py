from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import uuid
from collections import OrderedDict


def canonical_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def normalize_code(code: str) -> str:
    return code.replace("\r\n", "\n").replace("\r", "\n").strip()


def module_checksum(code: str) -> str:
    return sha256_hex(normalize_code(code))


def new_nonce() -> str:
    return str(uuid.uuid4())


def current_timestamp() -> int:
    return int(time.time())


def sign_hmac(secret: str | bytes, message: str | bytes) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    payload = message.encode("utf-8") if isinstance(message, str) else message
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def build_session_message(payload: dict) -> str:
    fields = OrderedDict(
        (
            ("build_id", payload.get("build_id", "")),
            ("machine_id", payload.get("machine_id", "")),
            ("module_name", payload.get("module_name", "")),
            ("nonce", payload.get("nonce", "")),
            ("session_id", payload.get("session_id", "")),
            ("sync_token", payload.get("sync_token", "")),
            ("timestamp", int(payload.get("timestamp", 0) or 0)),
        )
    )
    return canonical_json(dict(fields))


def sign_session_payload(session_key: str, payload: dict) -> str:
    return sign_hmac(session_key, build_session_message(payload))


def verify_session_signature(session_key: str, payload: dict, signature: str) -> bool:
    expected = sign_session_payload(session_key, payload)
    return hmac.compare_digest(expected, signature or "")


def build_internal_message(
    method: str,
    path: str,
    timestamp: str | int,
    nonce: str,
    body: dict | str | bytes | None,
) -> str:
    if body is None:
        body_hash = sha256_hex("")
    elif isinstance(body, dict):
        body_hash = sha256_hex(canonical_json(body))
    elif isinstance(body, (str, bytes)):
        body_hash = sha256_hex(body)
    else:
        body_hash = sha256_hex(str(body))

    return f"{method.upper()}|{path}|{timestamp}|{nonce}|{body_hash}"


def sign_internal_request(
    secret: str,
    method: str,
    path: str,
    timestamp: str | int,
    nonce: str,
    body: dict | None,
) -> str:
    return sign_hmac(secret, build_internal_message(method, path, timestamp, nonce, body))


def _canonical_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return canonical_json(value)
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def build_server_response_message(payload: dict) -> str:
    fields = OrderedDict(
        (
            ("challenge", payload.get("challenge", "")),
            ("checksum", payload.get("checksum", "")),
            ("encrypted_code_hash", sha256_hex(payload.get("encrypted_code", "")) if payload.get("encrypted_code") else ""),
            ("fragment_seal", payload.get("fragment_seal", "")),
            ("issued_at", int(payload.get("issued_at", 0) or 0)),
            ("module_name", payload.get("module_name", "")),
            ("response_type", payload.get("response_type", "")),
            ("session_epoch", int(payload.get("session_epoch", 0) or 0)),
            ("session_id", payload.get("session_id", "")),
            ("solution_hash", sha256_hex(_canonical_value(payload.get("solution")))),
            ("sync_token", payload.get("sync_token", "")),
            ("type", payload.get("type", "")),
        )
    )
    return canonical_json(dict(fields))


def sign_server_response(session_key: str, payload: dict) -> str:
    return sign_hmac(session_key, build_server_response_message(payload))


def verify_server_response(session_key: str, payload: dict, signature: str) -> bool:
    expected = sign_server_response(session_key, payload)
    return hmac.compare_digest(expected, signature or "")


def build_fragment_seal_message(payload: dict) -> str:
    fields = OrderedDict(
        (
            ("checksum", payload.get("checksum", "")),
            ("module_name", payload.get("module_name", "")),
            ("session_epoch", int(payload.get("session_epoch", 0) or 0)),
            ("session_id", payload.get("session_id", "")),
        )
    )
    return canonical_json(dict(fields))


def sign_fragment_seal(session_key: str, payload: dict) -> str:
    return sign_hmac(session_key, build_fragment_seal_message(payload))


def verify_fragment_seal(session_key: str, payload: dict, signature: str) -> bool:
    expected = sign_fragment_seal(session_key, payload)
    return hmac.compare_digest(expected, signature or "")


def sign_release_manifest(payload: dict, private_key_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw_private = base64.b64decode((private_key_b64 or "").encode("ascii"))
    private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
    signature = private_key.sign(canonical_json(payload).encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_release_manifest_signature(payload: dict, signature: str, public_key_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw_public = base64.b64decode((public_key_b64 or "").encode("ascii"))
        raw_signature = base64.b64decode((signature or "").encode("ascii"))
        public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        public_key.verify(raw_signature, canonical_json(payload).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class NonceCache:
    def __init__(self, max_items: int = 10000):
        self.max_items = max_items
        self._values: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()

    def consume(self, nonce: str) -> bool:
        with self._lock:
            if not nonce or nonce in self._values:
                return False

            self._values[nonce] = current_timestamp()
            while len(self._values) > self.max_items:
                self._values.popitem(last=False)
            return True


class RuntimeDefenseState:
    MODE_NORMAL = "normal"
    MODE_DEGRADED = "degraded"
    MODE_POISONED = "poisoned"

    def __init__(self):
        self._lock = threading.Lock()
        self._score = 0
        self._events: OrderedDict[str, dict] = OrderedDict()
        self._boot_salt = sha256_hex(f"{uuid.uuid4()}|{time.time_ns()}")[:16]

    def mark(self, name: str, *, severity: int = 1, detail: str = "") -> str:
        now = current_timestamp()
        with self._lock:
            event = self._events.get(name, {"hits": 0, "detail": detail, "last_seen": now})
            event["hits"] = int(event.get("hits", 0)) + 1
            event["detail"] = detail or event.get("detail", "")
            event["last_seen"] = now
            self._events[name] = event
            self._score += max(1, severity)
            while len(self._events) > 32:
                self._events.popitem(last=False)
            return self._mode_for_score(self._score)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "score": self._score,
                "mode": self._mode_for_score(self._score),
                "events": {key: dict(value) for key, value in self._events.items()},
            }

    def mode(self) -> str:
        with self._lock:
            return self._mode_for_score(self._score)

    def seed_for_feature(self, feature: str) -> str:
        payload = f"{self._boot_salt}|{feature}|{self.mode()}"
        return sha256_hex(payload)

    @staticmethod
    def _mode_for_score(score: int) -> str:
        if score >= 8:
            return RuntimeDefenseState.MODE_POISONED
        if score >= 3:
            return RuntimeDefenseState.MODE_DEGRADED
        return RuntimeDefenseState.MODE_NORMAL


runtime_defense = RuntimeDefenseState()


def register_tamper_signal(name: str, *, severity: int = 1, detail: str = "") -> str:
    return runtime_defense.mark(name, severity=severity, detail=detail)


def runtime_mode() -> str:
    return runtime_defense.mode()


def runtime_snapshot() -> dict:
    return runtime_defense.snapshot()


def should_shadow(feature: str, *, poisoned_only: bool = False) -> bool:
    if feature == "loader:partial_success":
        return False
    mode = runtime_mode()
    if mode == RuntimeDefenseState.MODE_NORMAL:
        return False
    if poisoned_only:
        return mode == RuntimeDefenseState.MODE_POISONED
    token = runtime_defense.seed_for_feature(feature)
    return int(token[:2], 16) % 2 == 0 or mode == RuntimeDefenseState.MODE_POISONED


def shadow_int(
    base: int,
    feature: str,
    *,
    direction: str = "down",
    minimum: int | None = None,
    maximum: int | None = None,
    spread: int = 3,
) -> int:
    token = runtime_defense.seed_for_feature(feature)
    delta = 1 + (int(token[:4], 16) % max(1, spread))
    value = base - delta if direction != "up" else base + delta
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def shadow_hex(value: str, feature: str) -> str:
    if not value:
        return value
    token = runtime_defense.seed_for_feature(feature)
    replacement = (value[:-2] + token[:2]) if len(value) > 2 else token[: len(value)]
    return replacement


def inspect_runtime_integrity() -> list[str]:
    signals: list[str] = []

    trace_fn = sys.gettrace()
    if trace_fn:
        register_tamper_signal("trace_active", severity=4, detail=str(trace_fn))
        signals.append("trace_active")

    marshal_module = getattr(__import__("marshal").loads, "__module__", "marshal")
    if marshal_module != "marshal":
        register_tamper_signal("marshal_hook", severity=3, detail=marshal_module)
        signals.append("marshal_hook")

    try:
        import requests

        requests_post_module = getattr(requests.post, "__module__", "requests.api")
        if requests_post_module != "requests.api":
            register_tamper_signal("requests_post_hook", severity=2, detail=requests_post_module)
            signals.append("requests_post_hook")

        session_request_module = getattr(requests.sessions.Session.request, "__module__", "requests.sessions")
        if session_request_module != "requests.sessions":
            register_tamper_signal("session_request_hook", severity=2, detail=session_request_module)
            signals.append("session_request_hook")
    except Exception as exc:
        register_tamper_signal("runtime_probe_error", severity=1, detail=str(exc))

    suspicious_modules = {
        "bdb",
        "debugpy",
        "frida",
        "frida_tools",
        "pdb",
        "pydevd",
        "pydevd_plugins",
        "pydevd_frame_evaluator",
        "pydevd_frame_evaluator_win32_38_64",
        "pydevd_frame_evaluator_win32_310_64",
    }
    loaded_suspicious = sorted(name for name in sys.modules if name.split(".")[0] in suspicious_modules)
    if loaded_suspicious:
        detail = ",".join(loaded_suspicious[:4])
        register_tamper_signal("suspicious_module_loaded", severity=4, detail=detail)
        signals.append("suspicious_module_loaded")

    suspicious_env = []
    for env_name in ("PYTHONBREAKPOINT", "PYTHONINSPECT", "PYTHONPATH"):
        raw = os.environ.get(env_name, "").strip()
        if raw and raw not in {"0", "false", "False"}:
            suspicious_env.append(f"{env_name}={raw[:64]}")
    if suspicious_env:
        register_tamper_signal("suspicious_env", severity=2, detail=";".join(suspicious_env[:3]))
        signals.append("suspicious_env")

    breakpointhook_module = getattr(getattr(sys, "breakpointhook", None), "__module__", "sys")
    if breakpointhook_module not in {"sys", "_sitebuiltins"}:
        register_tamper_signal("breakpoint_hook", severity=3, detail=breakpointhook_module)
        signals.append("breakpoint_hook")

    if getattr(sys, "frozen", False) or os.environ.get("AUTOSHOPEE_FROZEN") == "1":
        critical_modules = (
            "app_security",
            "utils.remote_loader",
            "utils.licensing",
            "API.shopee_api_client",
            "API.API_Shopee_Order",
        )
        suspicious_paths = []
        for module_name in critical_modules:
            module = sys.modules.get(module_name)
            module_path = getattr(module, "__file__", "") if module else ""
            if module_path and module_path.lower().endswith((".py", ".pyc", ".pyo")):
                suspicious_paths.append(f"{module_name}:{os.path.basename(module_path)}")
        if suspicious_paths:
            register_tamper_signal("frozen_source_artifact", severity=4, detail=";".join(suspicious_paths[:3]))
            signals.append("frozen_source_artifact")

    return signals
