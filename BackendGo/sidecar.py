from __future__ import annotations

import hashlib
import json
import marshal
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet
from passlib.hash import pbkdf2_sha256


MASTER_KEY = os.environ.get("MASTER_KEY", "").encode("utf-8")
if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY is required for sidecar")

SIDEcar_HOST = os.environ.get("BACKEND_PY_SIDECAR_HOST", "127.0.0.1")
SIDEcar_PORT = int(os.environ.get("BACKEND_PY_SIDECAR_PORT", "9801"))


def normalize_code(code: str) -> str:
    return code.replace("\r\n", "\n").replace("\r", "\n").strip()


def module_checksum(code: str) -> str:
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()


def canonical_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sign_hmac(secret: str | bytes, message: str | bytes) -> str:
    import hmac

    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    payload = message.encode("utf-8") if isinstance(message, str) else message
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def sign_fragment_seal(session_key: str, payload: dict) -> str:
    fields = {
        "checksum": payload.get("checksum", ""),
        "module_name": payload.get("module_name", ""),
        "session_epoch": int(payload.get("session_epoch", 0) or 0),
        "session_id": payload.get("session_id", ""),
    }
    return sign_hmac(session_key, canonical_json(fields))


def decrypt_code(encrypted_str: str) -> str:
    return Fernet(MASTER_KEY).decrypt(encrypted_str.encode("utf-8")).decode("utf-8")


def encrypt_code(code_str: str) -> str:
    return Fernet(MASTER_KEY).encrypt(code_str.encode("utf-8")).decode("utf-8")


def compile_module(payload: dict[str, Any]) -> dict[str, Any]:
    module_name = str(payload.get("module_name", "") or "").strip()
    session_id = str(payload.get("session_id", "") or "").strip()
    session_key = str(payload.get("session_key", "") or "").strip()
    encrypted_code = str(payload.get("encrypted_code", "") or "")
    session_epoch = int(payload.get("session_epoch", 1) or 1)
    if not module_name or not session_id or not session_key or not encrypted_code:
        raise ValueError("Missing module compile payload")

    decrypted_source = decrypt_code(encrypted_code)
    checksum = module_checksum(decrypted_source)
    seal_payload = {
        "module_name": module_name,
        "session_id": session_id,
        "session_epoch": session_epoch,
        "checksum": checksum,
    }
    fragment_seal = sign_fragment_seal(session_key, seal_payload)
    prelude = (
        f"__fragment_module__ = {module_name!r}\n"
        f"__fragment_session__ = {session_id!r}\n"
        f"__fragment_epoch__ = {int(session_epoch)}\n"
        f"__fragment_checksum__ = {checksum!r}\n"
        f"__fragment_seal__ = {fragment_seal!r}\n"
        f"# SECURE_ID: {uuid4()}\n"
    )
    mutated_source = f"{prelude}{decrypted_source}"
    code_obj = compile(mutated_source, "<remote_core>", "exec")
    marshaled_bytes = marshal.dumps(code_obj)
    encrypted_for_session = Fernet(session_key.encode("utf-8")).encrypt(marshaled_bytes).decode("utf-8")
    return {
        "checksum": checksum,
        "fragment_seal": fragment_seal,
        "encrypted_code": encrypted_for_session,
    }


class SidecarHandler(BaseHTTPRequestHandler):
    server_version = "AutoShopeeSidecar/1.0"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"detail": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = self._read_json()
            if self.path == "/hash-password":
                password = str(payload.get("password", "") or "")
                if not password:
                    self._send_json(400, {"detail": "password is required"})
                    return
                self._send_json(200, {"password_hash": pbkdf2_sha256.hash(password)})
                return

            if self.path == "/verify-password":
                password = str(payload.get("password", "") or "")
                password_hash = str(payload.get("password_hash", "") or "")
                if not password or not password_hash:
                    self._send_json(400, {"detail": "password and password_hash are required"})
                    return
                valid = pbkdf2_sha256.verify(password, password_hash)
                self._send_json(200, {"valid": bool(valid)})
                return

            if self.path == "/encrypt-module":
                code_content = str(payload.get("code_content", "") or "")
                if not code_content:
                    self._send_json(400, {"detail": "code_content is required"})
                    return
                self._send_json(
                    200,
                    {
                        "encrypted_code": encrypt_code(code_content),
                        "checksum": module_checksum(code_content),
                    },
                )
                return

            if self.path == "/process-module":
                self._send_json(200, compile_module(payload))
                return

            self._send_json(404, {"detail": "Not found"})
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"detail": str(exc)})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> None:
    server = ThreadingHTTPServer((SIDEcar_HOST, SIDEcar_PORT), SidecarHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
