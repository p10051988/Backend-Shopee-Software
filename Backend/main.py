from __future__ import annotations

import datetime
import hashlib
import hmac
import marshal
import random
import sys
import threading
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings
from app_security import (
    NonceCache,
    canonical_json,
    current_timestamp,
    module_checksum,
    new_nonce,
    sign_fragment_seal,
    sign_hmac,
    sign_internal_request,
    sign_server_response,
    sha256_hex,
    verify_session_signature,
    verify_release_manifest_signature,
)
from release_public_key import PUBLIC_KEY_B64
try:
    from Backend.database import Base, engine, ensure_schema, get_db
    from Backend.models import CustomerSubscription, DeviceActivation, License, ModuleVersion, SubscriptionPlan, WebUser
    from Backend.worker_runtime import RuntimeWorkerMonitor, get_runtime_worker_status, scale_runtime_workers
except ImportError:
    from database import Base, engine, ensure_schema, get_db
    from models import CustomerSubscription, DeviceActivation, License, ModuleVersion, SubscriptionPlan, WebUser
    from worker_runtime import RuntimeWorkerMonitor, get_runtime_worker_status, scale_runtime_workers
try:
    from Backend.utils.encryption import decrypt_code, encrypt_code
except ImportError:
    from utils.encryption import decrypt_code, encrypt_code


Base.metadata.create_all(bind=engine)
ensure_schema()

app = FastAPI(title="Auto-Shopee Licensing Server")
runtime_worker_monitor = RuntimeWorkerMonitor()
nonce_cache = NonceCache(max_items=20000)
internal_nonce_cache = NonceCache(max_items=20000)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
INTERNAL_KEY_ID = "autoshopee-internal"
SESSION_LIFETIME_MINUTES = 30
SYNC_TOKEN_TTL_SECONDS = 240
ROTATION_MIN_SECONDS = 600
ROTATION_MAX_SECONDS = 900
DEFAULT_PLAN_CATALOG = [
    {
        "code": "trial-7d",
        "name": "Free 7 ngay",
        "duration_label": "7 ngay dung thu",
        "duration_days": 7,
        "max_devices": 1,
        "is_active": True,
        "is_trial": True,
        "sort_order": 10,
        "price_amount": 0,
        "currency": "VND",
        "price_note": "Goi dung thu mien phi 7 ngay",
        "external_price_ref": "trial-7d",
    },
    {
        "code": "plan-1m",
        "name": "Goi 1 thang",
        "duration_label": "1 thang",
        "duration_days": 30,
        "max_devices": 1,
        "is_active": True,
        "is_trial": False,
        "sort_order": 20,
        "price_amount": 0,
        "currency": "VND",
        "price_note": "Gia co the cap nhat tu website",
        "external_price_ref": "plan-1m",
    },
    {
        "code": "plan-3m",
        "name": "Goi 3 thang",
        "duration_label": "3 thang",
        "duration_days": 90,
        "max_devices": 1,
        "is_active": True,
        "is_trial": False,
        "sort_order": 30,
        "price_amount": 0,
        "currency": "VND",
        "price_note": "Gia co the cap nhat tu website",
        "external_price_ref": "plan-3m",
    },
    {
        "code": "plan-6m",
        "name": "Goi 6 thang",
        "duration_label": "6 thang",
        "duration_days": 180,
        "max_devices": 1,
        "is_active": True,
        "is_trial": False,
        "sort_order": 40,
        "price_amount": 0,
        "currency": "VND",
        "price_note": "Gia co the cap nhat tu website",
        "external_price_ref": "plan-6m",
    },
    {
        "code": "plan-12m",
        "name": "Goi 12 thang",
        "duration_label": "12 thang",
        "duration_days": 365,
        "max_devices": 1,
        "is_active": True,
        "is_trial": False,
        "sort_order": 50,
        "price_amount": 0,
        "currency": "VND",
        "price_note": "Gia co the cap nhat tu website",
        "external_price_ref": "plan-12m",
    },
]


class VerifyAttemptGuard:
    def __init__(self, *, max_failures: int = 10, lock_seconds: int = 1800):
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._values: dict[str, dict[str, datetime.datetime | int]] = {}
        self._lock = threading.Lock()

    def _cleanup_unlocked(self, now: datetime.datetime) -> None:
        expired_keys = []
        for subject, state in self._values.items():
            locked_until = state.get("locked_until")
            if locked_until and isinstance(locked_until, datetime.datetime) and locked_until <= now:
                expired_keys.append(subject)
        for subject in expired_keys:
            self._values.pop(subject, None)

    def check_lock(self, subject: str) -> datetime.datetime | None:
        if not subject:
            return None
        now = utcnow()
        with self._lock:
            self._cleanup_unlocked(now)
            state = self._values.get(subject)
            if not state:
                return None
            locked_until = state.get("locked_until")
            if isinstance(locked_until, datetime.datetime) and locked_until > now:
                return locked_until
            return None

    def register_failure(self, subject: str) -> datetime.datetime | None:
        if not subject:
            return None
        now = utcnow()
        with self._lock:
            self._cleanup_unlocked(now)
            state = self._values.setdefault(subject, {"failures": 0, "locked_until": None})
            failures = int(state.get("failures", 0)) + 1
            state["failures"] = failures
            if failures >= self.max_failures:
                locked_until = now + datetime.timedelta(seconds=self.lock_seconds)
                state["locked_until"] = locked_until
                return locked_until
            return None

    def clear(self, subject: str) -> None:
        if not subject:
            return
        with self._lock:
            self._values.pop(subject, None)


class SessionThrottleGuard:
    def __init__(self):
        self._values: dict[str, datetime.datetime] = {}
        self._lock = threading.Lock()

    def _cleanup(self, now: datetime.datetime) -> None:
        stale_keys = []
        for key, last_seen in self._values.items():
            if (now - last_seen).total_seconds() > 3600:
                stale_keys.append(key)
        for key in stale_keys:
            self._values.pop(key, None)

    def enforce(self, scope: str, *, min_interval_seconds: float) -> None:
        now = utcnow()
        with self._lock:
            self._cleanup(now)
            last_seen = self._values.get(scope)
            if last_seen is not None:
                delta = (now - last_seen).total_seconds()
                if delta < min_interval_seconds:
                    retry_after = max(min_interval_seconds - delta, 0.1)
                    raise HTTPException(
                        status_code=429,
                        detail=f"Too many requests for {scope}",
                        headers={"Retry-After": str(int(retry_after + 0.999))},
                    )
            self._values[scope] = now


class SessionChallengeGuard:
    def __init__(self):
        self._values: dict[str, dict[str, datetime.datetime | int | str]] = {}
        self._lock = threading.Lock()

    def _cleanup(self, now: datetime.datetime) -> None:
        expired = []
        for session_id, state in self._values.items():
            expiration = state.get("session_expiration")
            if isinstance(expiration, datetime.datetime) and expiration <= now:
                expired.append(session_id)
        for session_id in expired:
            self._values.pop(session_id, None)

    def bootstrap(
        self,
        session_id: str,
        *,
        session_expiration: datetime.datetime,
        build_id: str = "",
    ) -> dict[str, datetime.datetime | int | str]:
        now = utcnow()
        state = {
            "build_id": build_id or "DEV-SOURCE",
            "sync_token": new_nonce(),
            "issued_at": now,
            "epoch": 1,
            "token_ttl_seconds": SYNC_TOKEN_TTL_SECONDS,
            "rotation_after_seconds": random.randint(ROTATION_MIN_SECONDS, ROTATION_MAX_SECONDS),
            "session_expiration": session_expiration,
        }
        with self._lock:
            self._cleanup(now)
            self._values[session_id] = state
        return dict(state)

    def refresh(self, session_id: str, *, session_expiration: datetime.datetime) -> dict[str, datetime.datetime | int | str] | None:
        now = utcnow()
        with self._lock:
            self._cleanup(now)
            state = self._values.get(session_id)
            if not state:
                return None
            state["sync_token"] = new_nonce()
            state["issued_at"] = now
            state["epoch"] = int(state.get("epoch", 0) or 0) + 1
            state["session_expiration"] = session_expiration
            if not state.get("rotation_after_seconds"):
                state["rotation_after_seconds"] = random.randint(ROTATION_MIN_SECONDS, ROTATION_MAX_SECONDS)
            return dict(state)

    def validate(
        self,
        session_id: str,
        sync_token: str,
        *,
        allow_stale: bool = False,
    ) -> dict[str, datetime.datetime | int | str] | None:
        now = utcnow()
        with self._lock:
            self._cleanup(now)
            state = self._values.get(session_id)
            if not state:
                return None
            if state.get("sync_token") != sync_token:
                return None
            issued_at = state.get("issued_at")
            ttl = int(state.get("token_ttl_seconds", SYNC_TOKEN_TTL_SECONDS) or SYNC_TOKEN_TTL_SECONDS)
            if isinstance(issued_at, datetime.datetime) and not allow_stale:
                age = (now - issued_at).total_seconds()
                if age > ttl:
                    return None
            return dict(state)

    def clear(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._values.pop(session_id, None)


verify_attempt_guard = VerifyAttemptGuard(max_failures=10, lock_seconds=1800)
session_throttle_guard = SessionThrottleGuard()
session_challenge_guard = SessionChallengeGuard()
plan_seed_lock = threading.Lock()


class LicenseCheckRequest(BaseModel):
    key: str
    machine_id: str
    build_id: str = "DEV-SOURCE"
    build_attestation: dict | None = None


class PublicLoginRequest(BaseModel):
    username: str
    password: str
    machine_id: str
    build_id: str = "DEV-SOURCE"
    build_attestation: dict | None = None
    device_name: str = ""
    device_binding: str = ""


class AccessKeyBootstrapRequest(BaseModel):
    access_key: str
    machine_id: str
    build_id: str = "DEV-SOURCE"
    build_attestation: dict | None = None
    device_name: str = ""
    device_binding: str = ""


class SessionAuthRequest(BaseModel):
    build_id: str
    session_id: str
    machine_id: str
    sync_token: str
    nonce: str
    timestamp: int
    signature: str


class FetchModuleRequest(SessionAuthRequest):
    module_name: str


class PuzzleSolveRequest(SessionAuthRequest):
    type: str
    challenge: str = "default"
    module_name: str


class CreateLicenseReq(BaseModel):
    key: str
    duration_days: int = 30
    max_machines: int = 1
    description: str = "Manual/Internal"


class ResetHWIDReq(BaseModel):
    key: str


class ModuleUploadRequest(BaseModel):
    name: str
    version: str
    code_content: str


class UpsertWebUserReq(BaseModel):
    username: str
    email: str
    password: str | None = None
    full_name: str = ""
    is_active: bool = True
    notes: str = ""


class UpsertPlanReq(BaseModel):
    code: str
    name: str
    duration_label: str = ""
    duration_days: int = 30
    max_devices: int = 1
    is_active: bool = True
    is_trial: bool = False
    sort_order: int = 100
    price_amount: int = 0
    currency: str = "VND"
    price_note: str = ""
    external_price_ref: str = ""


class UpdatePlanPriceReq(BaseModel):
    code: str
    price_amount: int
    currency: str = "VND"
    price_note: str = ""
    external_price_ref: str = ""


class SeedDefaultPlansReq(BaseModel):
    overwrite_existing: bool = False
    overwrite_prices: bool = False


class GrantSubscriptionReq(BaseModel):
    user_identity: str
    plan_code: str
    duration_days: int | None = None
    max_devices: int | None = None
    expires_at: str | None = None
    purchase_ref: str = ""
    notes: str = ""
    status: str = "active"
    replace_existing_active: bool = True
    allow_repeat_trial: bool = False


class AuthorizeDeviceReq(BaseModel):
    user_identity: str
    machine_id: str
    device_name: str = ""
    status: str = "active"
    notes: str = ""


class RevokeDeviceReq(BaseModel):
    user_identity: str
    machine_id: str


class WorkerScaleReq(BaseModel):
    action: str = "add"
    count: int = 1
    persist: bool = False


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow()


def normalize_identity(value: str) -> str:
    return (value or "").strip().lower()


def normalize_machine_id(value: str) -> str:
    return (value or "").strip()


def normalize_client_ip(request: Request | None) -> str:
    if not request or not request.client:
        return ""
    return (request.client.host or "").strip()


def hash_attempt_value(value: str) -> str:
    normalized = (value or "").strip().lower()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]


def build_auth_scope_keys(
    machine_id: str,
    request: Request | None,
    *,
    identity: str = "",
    access_key: str = "",
) -> list[str]:
    scopes: list[str] = []
    machine = normalize_machine_id(machine_id)
    if machine:
        scopes.append(f"machine:{machine}")

    client_ip = normalize_client_ip(request)
    if client_ip:
        scopes.append(f"ip:{client_ip}")

    identity_hash = hash_attempt_value(identity)
    if identity_hash:
        scopes.append(f"identity:{identity_hash}")

    access_hash = hash_attempt_value(access_key)
    if access_hash:
        scopes.append(f"access:{access_hash}")

    return list(dict.fromkeys(scope for scope in scopes if scope))


def get_auth_lock(scopes: list[str]) -> datetime.datetime | None:
    locked_until: datetime.datetime | None = None
    for scope in scopes:
        scope_lock = verify_attempt_guard.check_lock(scope)
        if scope_lock and (locked_until is None or scope_lock > locked_until):
            locked_until = scope_lock
    return locked_until


def clear_auth_failures(scopes: list[str]) -> None:
    for scope in scopes:
        verify_attempt_guard.clear(scope)


def register_auth_failure(scopes: list[str], detail: str, *, status_code: int = 403) -> None:
    locked_until: datetime.datetime | None = None
    for scope in scopes:
        scope_lock = verify_attempt_guard.register_failure(scope)
        if scope_lock and (locked_until is None or scope_lock > locked_until):
            locked_until = scope_lock
    if locked_until:
        raise HTTPException(
            status_code=429,
            detail=f"Machine locked until {locked_until.isoformat()} after too many failed login attempts",
        )
    raise HTTPException(status_code=status_code, detail=detail)


def hash_device_binding(device_binding: str) -> str:
    normalized = (device_binding or "").strip()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def allow_dev_source_build(request: Request | None) -> bool:
    if settings.dev_mode or settings.allow_insecure_defaults:
        return True
    client_ip = normalize_client_ip(request)
    return client_ip in {"127.0.0.1", "::1", "localhost"}


def verify_build_attestation(build_id: str, build_attestation: dict | None, request: Request | None) -> tuple[str, str]:
    normalized_build_id = str(build_id or "DEV-SOURCE").strip() or "DEV-SOURCE"
    if normalized_build_id == "DEV-SOURCE":
        if not allow_dev_source_build(request):
            raise HTTPException(
                status_code=403,
                detail="DEV-SOURCE build chi duoc phep tren local/dev backend. Build production phai co release manifest hop le.",
            )
        return normalized_build_id, "dev-source"

    if not isinstance(build_attestation, dict) or not build_attestation:
        raise HTTPException(status_code=403, detail="Missing release manifest attestation for production build")

    signed_payload = dict(build_attestation)
    signature = str(signed_payload.pop("signature", "") or "")
    public_key_b64 = (PUBLIC_KEY_B64 or "").strip()
    if not public_key_b64:
        raise HTTPException(status_code=503, detail="Release manifest public key is not configured")
    if signed_payload.get("signature_algorithm") != "ed25519":
        raise HTTPException(status_code=403, detail="Release manifest algorithm invalid")
    if str(signed_payload.get("build_nonce", "") or "") != normalized_build_id:
        raise HTTPException(status_code=403, detail="Release manifest build id mismatch")
    if not verify_release_manifest_signature(signed_payload, signature, public_key_b64):
        raise HTTPException(status_code=403, detail="Release manifest signature invalid")

    fingerprint = sha256_hex(canonical_json(signed_payload) + "|" + signature)
    return normalized_build_id, fingerprint


def parse_optional_datetime(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def issue_session_for_license(license_item: License, db: Session, *, build_id: str, account_context: dict | None = None) -> dict:
    license_item.session_id = str(uuid4())
    license_item.session_key = Fernet.generate_key().decode("utf-8")
    license_item.session_expiration = utcnow() + datetime.timedelta(minutes=SESSION_LIFETIME_MINUTES)
    db.commit()
    db.refresh(license_item)
    challenge_state = session_challenge_guard.bootstrap(
        license_item.session_id,
        session_expiration=license_item.session_expiration,
        build_id=build_id or "DEV-SOURCE",
    )
    return build_session_response(license_item, challenge_state, account_context=account_context)


def build_session_response(license_item: License, challenge_state: dict | None = None, *, account_context: dict | None = None) -> dict:
    challenge_state = challenge_state or session_challenge_guard.bootstrap(
        license_item.session_id,
        session_expiration=license_item.session_expiration,
        build_id="DEV-SOURCE",
    )
    response = {
        "valid": True,
        "message": "Authorized",
        "license_expiration": license_item.expiration_date,
        "expiration": license_item.expiration_date,
        "machine_id_bound": license_item.machine_id,
        "session_id": license_item.session_id,
        "session_key": license_item.session_key,
        "session_expiration": license_item.session_expiration,
        "build_id": challenge_state.get("build_id", "DEV-SOURCE"),
        "sync_token": challenge_state.get("sync_token", ""),
        "sync_token_ttl_seconds": challenge_state.get("token_ttl_seconds", SYNC_TOKEN_TTL_SECONDS),
        "rotation_after_seconds": challenge_state.get("rotation_after_seconds", ROTATION_MAX_SECONDS),
        "session_epoch": challenge_state.get("epoch", 1),
        "access_key": license_item.key,
        "plan_code": license_item.plan_code,
        "auth_source": license_item.source or "legacy",
    }
    if account_context:
        response.update(account_context)
    return response


def get_license_by_key(db: Session, key: str) -> License:
    license_item = db.query(License).filter(License.key == key).first()
    if not license_item:
        raise HTTPException(status_code=403, detail="License verification failed")
    if not license_item.is_active:
        raise HTTPException(status_code=403, detail="License verification failed")
    return license_item


def validate_license_binding(license_item: License, machine_id: str, db: Session) -> None:
    if not license_item.machine_id:
        license_item.machine_id = machine_id
        license_item.activated_at = utcnow()
        license_item.expiration_date = utcnow() + datetime.timedelta(days=license_item.duration_days)
        db.commit()
        db.refresh(license_item)
    elif license_item.machine_id != machine_id:
        raise HTTPException(status_code=403, detail="License verification failed")

    if license_item.expiration_date and utcnow() > license_item.expiration_date:
        raise HTTPException(status_code=403, detail="License expired")


def get_user_by_identity(db: Session, identity: str) -> WebUser | None:
    normalized = normalize_identity(identity)
    if not normalized:
        return None
    return (
        db.query(WebUser)
        .filter(or_(WebUser.username == normalized, WebUser.email == normalized))
        .first()
    )


def get_plan_by_code(db: Session, code: str) -> SubscriptionPlan | None:
    return db.query(SubscriptionPlan).filter(SubscriptionPlan.code == code.strip().lower()).first()


def serialize_plan(plan: SubscriptionPlan) -> dict:
    return {
        "plan_code": plan.code,
        "name": plan.name,
        "duration_label": plan.duration_label or "",
        "duration_days": plan.duration_days,
        "max_devices": plan.max_devices,
        "is_active": plan.is_active,
        "is_trial": plan.is_trial,
        "sort_order": plan.sort_order,
        "price_amount": plan.price_amount,
        "currency": plan.currency or "VND",
        "price_note": plan.price_note or "",
        "external_price_ref": plan.external_price_ref or "",
    }


def ensure_default_plans(db: Session, *, overwrite_existing: bool = False, overwrite_prices: bool = False) -> list[dict]:
    applied: list[dict] = []
    with plan_seed_lock:
        for definition in DEFAULT_PLAN_CATALOG:
            plan = get_plan_by_code(db, definition["code"])
            if not plan:
                plan = SubscriptionPlan(
                    code=definition["code"],
                    name=definition["name"],
                    duration_label=definition["duration_label"],
                    duration_days=definition["duration_days"],
                    max_devices=definition["max_devices"],
                    is_active=definition["is_active"],
                    is_trial=definition["is_trial"],
                    sort_order=definition["sort_order"],
                    price_amount=definition["price_amount"],
                    currency=definition["currency"],
                    price_note=definition["price_note"],
                    external_price_ref=definition["external_price_ref"],
                )
                db.add(plan)
            elif overwrite_existing:
                plan.name = definition["name"]
                plan.duration_label = definition["duration_label"]
                plan.duration_days = definition["duration_days"]
                plan.max_devices = definition["max_devices"]
                plan.is_active = definition["is_active"]
                plan.is_trial = definition["is_trial"]
                plan.sort_order = definition["sort_order"]
                plan.price_note = definition["price_note"]
                plan.external_price_ref = definition["external_price_ref"]
                if overwrite_prices:
                    plan.price_amount = definition["price_amount"]
                    plan.currency = definition["currency"]
                plan.updated_at = utcnow()
            elif overwrite_prices:
                plan.price_amount = definition["price_amount"]
                plan.currency = definition["currency"]
                plan.updated_at = utcnow()
            applied.append({"plan_code": definition["code"]})
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
    return applied


def get_active_subscription(db: Session, user_id: int) -> CustomerSubscription | None:
    subscription = (
        db.query(CustomerSubscription)
        .filter(CustomerSubscription.user_id == user_id)
        .filter(CustomerSubscription.status == "active")
        .order_by(CustomerSubscription.expires_at.desc(), CustomerSubscription.id.desc())
        .first()
    )
    if not subscription:
        return None
    if subscription.expires_at and subscription.expires_at <= utcnow():
        subscription.status = "expired"
        db.commit()
        return None
    return subscription


def get_device_activation(db: Session, user_id: int, machine_id: str) -> DeviceActivation | None:
    return (
        db.query(DeviceActivation)
        .filter(DeviceActivation.user_id == user_id)
        .filter(DeviceActivation.machine_id == machine_id)
        .order_by(DeviceActivation.id.desc())
        .first()
    )


def enforce_device_binding(device: DeviceActivation, device_binding: str) -> None:
    provided_hash = hash_device_binding(device_binding)
    if not provided_hash:
        raise HTTPException(
            status_code=403,
            detail="Phien ban EXE nay thieu device binding proof. Vui long dang nhap bang ban EXE moi nhat.",
        )

    stored_hash = (device.device_binding_hash or "").strip()
    if stored_hash:
        if not hmac.compare_digest(stored_hash, provided_hash):
            raise HTTPException(
                status_code=403,
                detail="Device binding proof mismatch. Access nay khong the su dung tren may khac.",
            )
    else:
        device.device_binding_hash = provided_hash
        device.binding_updated_at = utcnow()


def create_access_key() -> str:
    token = uuid4().hex.upper()
    return f"ACC-{token[:8]}-{token[8:16]}-{token[16:24]}-{token[24:32]}"


def ensure_device_access_license(
    db: Session,
    *,
    user: WebUser,
    subscription: CustomerSubscription,
    device: DeviceActivation,
) -> License:
    remaining_days = 30
    if subscription.expires_at:
        remaining_days = max(1, int((subscription.expires_at - utcnow()).total_seconds() // 86400) + 1)
    license_item = None
    if device.license_id:
        license_item = db.query(License).filter(License.id == device.license_id).first()

    if not license_item:
        license_item = License(
            key=create_access_key(),
            machine_id=device.machine_id,
            account_username=user.username,
            plan_code=subscription.plan_code,
            source="account_portal",
            is_active=True,
            created_at=utcnow(),
            activated_at=device.approved_at or utcnow(),
            expiration_date=subscription.expires_at,
            duration_days=remaining_days,
            notes=f"Auto-created for {user.username}:{device.machine_id}",
        )
        db.add(license_item)
        db.flush()
        device.license_id = license_item.id
    else:
        license_item.machine_id = device.machine_id
        license_item.account_username = user.username
        license_item.plan_code = subscription.plan_code
        license_item.source = "account_portal"
        license_item.is_active = True
        license_item.expiration_date = subscription.expires_at
        license_item.duration_days = remaining_days
        license_item.activated_at = device.approved_at or license_item.activated_at or utcnow()
        license_item.notes = f"Synced for {user.username}:{device.machine_id}"

    db.commit()
    db.refresh(license_item)
    return license_item


def build_account_context(
    user: WebUser,
    subscription: CustomerSubscription,
    device: DeviceActivation,
    *,
    plan: SubscriptionPlan | None = None,
) -> dict:
    return {
        "account_username": user.username,
        "account_email": user.email,
        "subscription_status": subscription.status,
        "subscription_expires_at": subscription.expires_at,
        "subscription_plan_code": subscription.plan_code,
        "subscription_plan_name": plan.name if plan else subscription.plan_code,
        "subscription_plan": serialize_plan(plan) if plan else None,
        "subscription_max_devices": subscription.max_devices,
        "device_id": device.machine_id,
        "device_name": device.device_name or "",
    }


def clear_license_session(license_item: License) -> None:
    session_challenge_guard.clear(license_item.session_id)
    license_item.session_id = None
    license_item.session_key = None
    license_item.session_expiration = None


def deactivate_license_access(license_item: License, db: Session, *, keep_active: bool = False) -> None:
    clear_license_session(license_item)
    if not keep_active:
        license_item.is_active = False
    db.commit()
    db.refresh(license_item)


def build_account_context_from_license(
    db: Session,
    license_item: License,
    machine_id: str,
    *,
    device_name: str = "",
    device_binding: str = "",
) -> dict | None:
    if (license_item.source or "legacy") != "account_portal":
        return None

    identity = normalize_identity(license_item.account_username or "")
    if not identity:
        deactivate_license_access(license_item, db)
        raise HTTPException(status_code=403, detail="Account-bound access key is invalid")

    user = get_user_by_identity(db, identity)
    if not user:
        deactivate_license_access(license_item, db)
        raise HTTPException(status_code=403, detail="Account-bound access key is invalid")
    if not user.is_active:
        deactivate_license_access(license_item, db)
        raise HTTPException(status_code=403, detail="Account is disabled")

    subscription = get_active_subscription(db, user.id)
    if not subscription:
        deactivate_license_access(license_item, db)
        raise HTTPException(
            status_code=402,
            detail="Tai khoan chua co goi su dung hoac goi da het han. Vui long mua goi tren website.",
        )

    device = get_device_activation(db, user.id, machine_id)
    if not device or device.status != "active":
        deactivate_license_access(license_item, db)
        raise HTTPException(
            status_code=403,
            detail="Thiet bi nay chua duoc kich hoat cho tai khoan. Vui long vao website de dang ky machine ID.",
        )
    enforce_device_binding(device, device_binding)

    if device.license_id and device.license_id != license_item.id:
        deactivate_license_access(license_item, db)
        raise HTTPException(
            status_code=403,
            detail="Access key hien tai khong con hop le cho thiet bi nay. Vui long dang nhap lai tren EXE.",
        )

    plan = get_plan_by_code(db, subscription.plan_code)
    remaining_days = 30
    if subscription.expires_at:
        remaining_days = max(1, int((subscription.expires_at - utcnow()).total_seconds() // 86400) + 1)

    license_item.machine_id = machine_id
    license_item.account_username = user.username
    license_item.plan_code = subscription.plan_code
    license_item.source = "account_portal"
    license_item.is_active = True
    license_item.expiration_date = subscription.expires_at
    license_item.duration_days = remaining_days
    license_item.activated_at = device.approved_at or license_item.activated_at or utcnow()

    device.license_id = license_item.id
    device.last_login_at = utcnow()
    if device_name.strip():
        device.device_name = device_name.strip()
    if not device.approved_at:
        device.approved_at = utcnow()

    db.commit()
    db.refresh(license_item)
    db.refresh(device)
    return build_account_context(user, subscription, device, plan=plan)


def register_machine_auth_failure(machine_id: str, detail: str, *, status_code: int = 403) -> None:
    locked_until = verify_attempt_guard.register_failure(machine_id)
    if locked_until:
        raise HTTPException(
            status_code=429,
            detail=f"Machine locked until {locked_until.isoformat()} after too many failed login attempts",
        )
    raise HTTPException(status_code=status_code, detail=detail)


def require_internal_auth(
    request: Request,
    x_internal_key: str = Header(..., alias="X-Internal-Key"),
    x_internal_timestamp: str = Header(..., alias="X-Internal-Timestamp"),
    x_internal_nonce: str = Header(..., alias="X-Internal-Nonce"),
    x_internal_signature: str = Header(..., alias="X-Internal-Signature"),
):
    if x_internal_key != INTERNAL_KEY_ID:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid internal key id")

    if not settings.internal_api_secret:
        raise HTTPException(status_code=503, detail="Internal API secret is not configured")

    body = getattr(request.state, "json_body", None)
    expected = sign_internal_request(
        settings.internal_api_secret,
        request.method,
        request.url.path,
        x_internal_timestamp,
        x_internal_nonce,
        body,
    )
    if not hmac.compare_digest(expected, x_internal_signature or ""):
        raise HTTPException(status_code=403, detail="Forbidden: Invalid internal signature")

    try:
        timestamp = int(x_internal_timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid internal timestamp") from exc

    if abs(current_timestamp() - timestamp) > 300:
        raise HTTPException(status_code=403, detail="Internal request timestamp out of sync")

    if not internal_nonce_cache.consume(x_internal_nonce):
        raise HTTPException(status_code=403, detail="Internal request replay detected")


@app.middleware("http")
async def capture_json_body(request: Request, call_next):
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            request.state.json_body = await request.json()
        except Exception:
            request.state.json_body = None
    else:
        request.state.json_body = None
    return await call_next(request)


@app.middleware("http")
async def track_worker_runtime(request: Request, call_next):
    if request.url.path.startswith("/api/internal/runtime/workers"):
        return await call_next(request)
    runtime_worker_monitor.request_started(request.url.path, request.method)
    response = None
    try:
        response = await call_next(request)
        return response
    finally:
        status_code = getattr(response, "status_code", 500)
        runtime_worker_monitor.request_finished(status_code)


def validate_session_request(
    req: SessionAuthRequest | FetchModuleRequest,
    db: Session,
    *,
    allow_stale_sync: bool = False,
) -> tuple[License, dict]:
    if not nonce_cache.consume(req.nonce):
        raise HTTPException(status_code=403, detail="Nonce already used")

    if abs(current_timestamp() - int(req.timestamp)) > 10:
        raise HTTPException(status_code=403, detail="Timestamp out of sync")

    license_item = (
        db.query(License)
        .filter(License.session_id == req.session_id)
        .filter(License.is_active == True)  # noqa: E712
        .first()
    )
    if not license_item or not license_item.session_key:
        raise HTTPException(status_code=403, detail="Invalid session")

    if license_item.machine_id != req.machine_id:
        raise HTTPException(status_code=403, detail="Machine mismatch")

    if not license_item.session_expiration or utcnow() > license_item.session_expiration:
        raise HTTPException(status_code=401, detail="Session expired")

    payload = {
        "build_id": req.build_id,
        "session_id": req.session_id,
        "machine_id": req.machine_id,
        "sync_token": req.sync_token,
        "module_name": getattr(req, "module_name", ""),
        "nonce": req.nonce,
        "timestamp": req.timestamp,
    }
    if not verify_session_signature(license_item.session_key, payload, req.signature):
        raise HTTPException(status_code=403, detail="Invalid session signature")

    challenge_state = session_challenge_guard.validate(
        req.session_id,
        req.sync_token,
        allow_stale=allow_stale_sync,
    )
    if not challenge_state:
        raise HTTPException(status_code=401, detail="Session challenge expired")
    if str(challenge_state.get("build_id", "DEV-SOURCE") or "DEV-SOURCE") != str(req.build_id or "DEV-SOURCE"):
        raise HTTPException(status_code=403, detail="Build attestation mismatch")

    return license_item, challenge_state


def mutate_code(
    source_code: str,
    *,
    module_name: str,
    session_id: str,
    session_epoch: int,
    checksum: str,
    session_key: str,
) -> tuple[str, str]:
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
    return f"{prelude}{source_code}", fragment_seal


@app.get("/")
def read_root():
    return {"status": "Server running", "time": utcnow()}


@app.get("/api/public/health")
def public_health():
    return {"status": "ok", "time": utcnow()}


@app.get("/api/public/plans")
def public_plans(db: Session = Depends(get_db)):
    plans = (
        db.query(SubscriptionPlan)
        .filter(SubscriptionPlan.is_active == True)  # noqa: E712
        .order_by(SubscriptionPlan.sort_order.asc(), SubscriptionPlan.duration_days.asc(), SubscriptionPlan.id.asc())
        .all()
    )
    if not plans:
        ensure_default_plans(db)
        plans = (
            db.query(SubscriptionPlan)
            .filter(SubscriptionPlan.is_active == True)  # noqa: E712
            .order_by(SubscriptionPlan.sort_order.asc(), SubscriptionPlan.duration_days.asc(), SubscriptionPlan.id.asc())
            .all()
        )
    return {"plans": [serialize_plan(plan) for plan in plans]}


@app.post("/verify_license")
def verify_license(req: LicenseCheckRequest, request: Request, db: Session = Depends(get_db)):
    key = req.key.strip()
    machine_id = normalize_machine_id(req.machine_id)
    if not key or not machine_id:
        raise HTTPException(status_code=400, detail="Missing key or machine_id")
    build_id, _ = verify_build_attestation(req.build_id, req.build_attestation, request)

    auth_scopes = build_auth_scope_keys(machine_id, request, access_key=key)
    locked_until = get_auth_lock(auth_scopes)
    if locked_until:
        raise HTTPException(
            status_code=429,
            detail=f"Machine locked until {locked_until.isoformat()} after too many failed license attempts",
        )

    account_context = None
    try:
        license_item = get_license_by_key(db, key)
        validate_license_binding(license_item, machine_id, db)
        account_context = build_account_context_from_license(db, license_item, machine_id)
    except HTTPException as exc:
        if exc.status_code == 403 and exc.detail != "License expired":
            register_auth_failure(auth_scopes, str(exc.detail), status_code=exc.status_code)
        raise

    clear_auth_failures(auth_scopes)
    return issue_session_for_license(
        license_item,
        db,
        build_id=build_id,
        account_context=account_context,
    )


@app.post("/api/public/login")
def public_login(req: PublicLoginRequest, request: Request, db: Session = Depends(get_db)):
    username = normalize_identity(req.username)
    password = req.password or ""
    machine_id = normalize_machine_id(req.machine_id)
    if not username or not password or not machine_id:
        raise HTTPException(status_code=400, detail="Missing username, password, or machine_id")
    build_id, _ = verify_build_attestation(req.build_id, req.build_attestation, request)

    auth_scopes = build_auth_scope_keys(machine_id, request, identity=username)
    locked_until = get_auth_lock(auth_scopes)
    if locked_until:
        raise HTTPException(
            status_code=429,
            detail=f"Machine locked until {locked_until.isoformat()} after too many failed login attempts",
        )

    user = get_user_by_identity(db, username)
    if not user or not verify_password(password, user.password_hash):
        register_auth_failure(auth_scopes, "Invalid username/email or password", status_code=401)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    subscription = get_active_subscription(db, user.id)
    if not subscription:
        raise HTTPException(
            status_code=402,
            detail="Tai khoan chua co goi su dung hoac goi da het han. Vui long mua goi tren website.",
        )

    device = get_device_activation(db, user.id, machine_id)
    if not device or device.status != "active":
        raise HTTPException(
            status_code=403,
            detail="Thiet bi nay chua duoc kich hoat cho tai khoan. Vui long vao website de dang ky machine ID.",
        )
    enforce_device_binding(device, req.device_binding)
    plan = get_plan_by_code(db, subscription.plan_code)

    device.device_name = (req.device_name or device.device_name or "").strip()
    device.last_login_at = utcnow()
    if not device.approved_at:
        device.approved_at = utcnow()
    db.commit()
    db.refresh(device)

    license_item = ensure_device_access_license(db, user=user, subscription=subscription, device=device)
    clear_auth_failures(auth_scopes)
    return issue_session_for_license(
        license_item,
        db,
        build_id=build_id,
        account_context=build_account_context(user, subscription, device, plan=plan),
    )


@app.post("/api/public/access-key-login")
def public_access_key_login(req: AccessKeyBootstrapRequest, request: Request, db: Session = Depends(get_db)):
    access_key = req.access_key.strip()
    machine_id = normalize_machine_id(req.machine_id)
    if not access_key or not machine_id:
        raise HTTPException(status_code=400, detail="Missing access_key or machine_id")
    build_id, _ = verify_build_attestation(req.build_id, req.build_attestation, request)

    auth_scopes = build_auth_scope_keys(machine_id, request, access_key=access_key)
    locked_until = get_auth_lock(auth_scopes)
    if locked_until:
        raise HTTPException(
            status_code=429,
            detail=f"Machine locked until {locked_until.isoformat()} after too many failed login attempts",
        )

    try:
        license_item = get_license_by_key(db, access_key)
        validate_license_binding(license_item, machine_id, db)
        account_context = build_account_context_from_license(
            db,
            license_item,
            machine_id,
            device_name=req.device_name or "",
            device_binding=req.device_binding or "",
        )
    except HTTPException as exc:
        if exc.status_code in {401, 403}:
            register_auth_failure(auth_scopes, str(exc.detail), status_code=exc.status_code)
        raise

    clear_auth_failures(auth_scopes)
    return issue_session_for_license(
        license_item,
        db,
        build_id=build_id,
        account_context=account_context,
    )


@app.post("/fetch_module")
def fetch_module(req: FetchModuleRequest, db: Session = Depends(get_db)):
    license_item, challenge_state = validate_session_request(req, db)
    session_throttle_guard.enforce(
        f"fetch:{req.session_id}:{req.module_name}",
        min_interval_seconds=1.0,
    )
    module = (
        db.query(ModuleVersion)
        .filter(ModuleVersion.name == req.module_name)
        .order_by(ModuleVersion.id.desc())
        .first()
    )
    if not module:
        raise HTTPException(status_code=404, detail=f"Module {req.module_name} not found")

    decrypted_source = decrypt_code(module.encrypted_code)
    expected_checksum = module_checksum(decrypted_source)
    if module.hash_checksum and module.hash_checksum != expected_checksum:
        raise HTTPException(status_code=500, detail="Module integrity check failed")

    mutated_source, fragment_seal = mutate_code(
        decrypted_source,
        module_name=req.module_name,
        session_id=req.session_id,
        session_epoch=int(challenge_state.get("epoch", 1) or 1),
        checksum=expected_checksum,
        session_key=license_item.session_key,
    )
    code_obj = compile(mutated_source, "<remote_core>", "exec")
    marshaled_bytes = marshal.dumps(code_obj)
    encrypted_for_session = Fernet(license_item.session_key.encode("utf-8")).encrypt(marshaled_bytes).decode("utf-8")
    response_payload = {
        "name": module.name,
        "version": module.version,
        "checksum": expected_checksum,
        "fragment_seal": fragment_seal,
        "encrypted_code": encrypted_for_session,
        "response_type": "module",
        "module_name": req.module_name,
        "session_id": req.session_id,
        "sync_token": req.sync_token,
        "session_epoch": challenge_state.get("epoch", 1),
        "issued_at": current_timestamp(),
    }
    response_payload["response_signature"] = sign_server_response(license_item.session_key, response_payload)
    return response_payload


@app.post("/heartbeat")
def heartbeat(req: SessionAuthRequest, db: Session = Depends(get_db)):
    license_item, _ = validate_session_request(req, db, allow_stale_sync=True)
    session_throttle_guard.enforce(
        f"heartbeat:{req.session_id}",
        min_interval_seconds=5.0,
    )
    challenge_state = session_challenge_guard.refresh(
        req.session_id,
        session_expiration=license_item.session_expiration,
    )
    if not challenge_state:
        raise HTTPException(status_code=401, detail="Session challenge expired")
    token = str(challenge_state.get("sync_token", ""))
    response_payload = {
        "status": "ok",
        "sync_token": token,
        "signature": sign_hmac(license_item.session_key, token),
        "session_expiration": license_item.session_expiration,
        "response_type": "heartbeat",
        "session_id": req.session_id,
        "session_epoch": challenge_state.get("epoch", 1),
        "sync_token_ttl_seconds": challenge_state.get("token_ttl_seconds", SYNC_TOKEN_TTL_SECONDS),
        "rotation_after_seconds": challenge_state.get("rotation_after_seconds", ROTATION_MAX_SECONDS),
        "issued_at": current_timestamp(),
    }
    response_payload["response_signature"] = sign_server_response(license_item.session_key, response_payload)
    return response_payload


internal_router = APIRouter(
    prefix="/api/internal",
    tags=["Internal"],
    dependencies=[Depends(require_internal_auth)],
)


@internal_router.post("/create_license")
def create_license_api(req: CreateLicenseReq, db: Session = Depends(get_db)):
    existing = db.query(License).filter(License.key == req.key).first()
    if existing:
        raise HTTPException(status_code=400, detail="Key already exists")

    new_license = License(
        key=req.key,
        machine_id="",
        duration_days=req.duration_days,
        expiration_date=None,
        session_id=None,
        session_key=None,
        session_expiration=None,
        source="legacy",
        notes=req.description,
    )
    db.add(new_license)
    db.commit()
    return {"status": "success", "key": req.key}


@internal_router.post("/users/upsert")
def upsert_user_api(req: UpsertWebUserReq, db: Session = Depends(get_db)):
    username = normalize_identity(req.username)
    email = normalize_identity(req.email)
    if not username or not email:
        raise HTTPException(status_code=400, detail="username and email are required")

    user = get_user_by_identity(db, username) or get_user_by_identity(db, email)
    creating = user is None
    old_username = normalize_identity(user.username) if user else ""
    if creating:
        if not req.password:
            raise HTTPException(status_code=400, detail="password is required for new users")
        user = WebUser(
            username=username,
            email=email,
            password_hash=hash_password(req.password),
            full_name=req.full_name.strip(),
            is_active=req.is_active,
            notes=req.notes.strip(),
        )
        db.add(user)
    else:
        user.username = username
        user.email = email
        user.full_name = req.full_name.strip()
        user.is_active = req.is_active
        user.notes = req.notes.strip()
        if req.password:
            user.password_hash = hash_password(req.password)
        user.updated_at = utcnow()
    if not creating and old_username and old_username != username:
        (
            db.query(License)
            .filter(License.account_username == old_username)
            .filter(License.source == "account_portal")
            .update({License.account_username: username}, synchronize_session=False)
        )
    db.commit()
    db.refresh(user)
    if not user.is_active:
        account_licenses = (
            db.query(License)
            .filter(License.account_username == user.username)
            .filter(License.source == "account_portal")
            .all()
        )
        for item in account_licenses:
            clear_license_session(item)
            item.is_active = False
        if account_licenses:
            db.commit()
    return {
        "status": "created" if creating else "updated",
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
    }


@internal_router.post("/plans/upsert")
def upsert_plan_api(req: UpsertPlanReq, db: Session = Depends(get_db)):
    code = req.code.strip().lower()
    if not code:
        raise HTTPException(status_code=400, detail="plan code is required")

    plan = get_plan_by_code(db, code)
    creating = plan is None
    if creating:
        plan = SubscriptionPlan(
            code=code,
            name=req.name.strip(),
            duration_label=req.duration_label.strip(),
            duration_days=max(1, req.duration_days),
            max_devices=max(1, req.max_devices),
            is_active=req.is_active,
            is_trial=req.is_trial,
            sort_order=max(1, req.sort_order),
            price_amount=max(0, req.price_amount),
            currency=(req.currency or "VND").strip().upper(),
            price_note=req.price_note.strip(),
            external_price_ref=req.external_price_ref.strip(),
        )
        db.add(plan)
    else:
        plan.name = req.name.strip()
        plan.duration_label = req.duration_label.strip()
        plan.duration_days = max(1, req.duration_days)
        plan.max_devices = max(1, req.max_devices)
        plan.is_active = req.is_active
        plan.is_trial = req.is_trial
        plan.sort_order = max(1, req.sort_order)
        plan.price_amount = max(0, req.price_amount)
        plan.currency = (req.currency or "VND").strip().upper()
        plan.price_note = req.price_note.strip()
        plan.external_price_ref = req.external_price_ref.strip()
        plan.updated_at = utcnow()
    db.commit()
    db.refresh(plan)
    return {
        "status": "created" if creating else "updated",
        "plan": serialize_plan(plan),
    }


@internal_router.get("/plans")
def list_plans_api(include_inactive: bool = True, db: Session = Depends(get_db)):
    query = db.query(SubscriptionPlan)
    if not include_inactive:
        query = query.filter(SubscriptionPlan.is_active == True)  # noqa: E712
    plans = query.order_by(SubscriptionPlan.sort_order.asc(), SubscriptionPlan.duration_days.asc(), SubscriptionPlan.id.asc()).all()
    return {"plans": [serialize_plan(plan) for plan in plans]}


@internal_router.post("/plans/seed-defaults")
def seed_default_plans_api(req: SeedDefaultPlansReq, db: Session = Depends(get_db)):
    applied = ensure_default_plans(
        db,
        overwrite_existing=req.overwrite_existing,
        overwrite_prices=req.overwrite_prices,
    )
    plans = (
        db.query(SubscriptionPlan)
        .order_by(SubscriptionPlan.sort_order.asc(), SubscriptionPlan.duration_days.asc(), SubscriptionPlan.id.asc())
        .all()
    )
    return {
        "status": "ok",
        "applied_count": len(applied),
        "plans": [serialize_plan(plan) for plan in plans],
    }


@internal_router.post("/plans/update-price")
def update_plan_price_api(req: UpdatePlanPriceReq, db: Session = Depends(get_db)):
    plan = get_plan_by_code(db, req.code)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    plan.price_amount = max(0, req.price_amount)
    plan.currency = (req.currency or "VND").strip().upper()
    if req.price_note.strip():
        plan.price_note = req.price_note.strip()
    if req.external_price_ref.strip():
        plan.external_price_ref = req.external_price_ref.strip()
    plan.updated_at = utcnow()
    db.commit()
    db.refresh(plan)
    return {"status": "updated", "plan": serialize_plan(plan)}


@internal_router.post("/subscriptions/grant")
def grant_subscription_api(req: GrantSubscriptionReq, db: Session = Depends(get_db)):
    user = get_user_by_identity(db, req.user_identity)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    plan = get_plan_by_code(db, req.plan_code)
    if not plan or not plan.is_active:
        raise HTTPException(status_code=404, detail="Plan not found or inactive")

    starts_at = utcnow()
    expires_at = parse_optional_datetime(req.expires_at)
    duration_days = req.duration_days if req.duration_days is not None else plan.duration_days
    if not expires_at:
        expires_at = starts_at + datetime.timedelta(days=max(1, duration_days))
    requested_status = req.status.strip().lower() or "active"

    if plan.is_trial and not req.allow_repeat_trial:
        prior_trial = (
            db.query(CustomerSubscription)
            .filter(CustomerSubscription.user_id == user.id)
            .filter(CustomerSubscription.plan_code == plan.code)
            .first()
        )
        if prior_trial:
            raise HTTPException(status_code=409, detail="User da su dung goi dung thu nay truoc do")

    subscription = (
        db.query(CustomerSubscription)
        .filter(CustomerSubscription.user_id == user.id)
        .filter(CustomerSubscription.plan_code == plan.code)
        .order_by(CustomerSubscription.id.desc())
        .first()
    )
    creating = subscription is None
    if creating:
        subscription = CustomerSubscription(
            user_id=user.id,
            plan_code=plan.code,
            status=requested_status,
            starts_at=starts_at,
            expires_at=expires_at,
            max_devices=max(1, req.max_devices if req.max_devices is not None else plan.max_devices),
            purchase_ref=req.purchase_ref.strip(),
            notes=req.notes.strip(),
        )
        db.add(subscription)
    else:
        subscription.status = requested_status
        subscription.starts_at = starts_at
        subscription.expires_at = expires_at
        subscription.max_devices = max(1, req.max_devices if req.max_devices is not None else plan.max_devices)
        subscription.purchase_ref = req.purchase_ref.strip()
        subscription.notes = req.notes.strip()
        subscription.updated_at = utcnow()
    db.flush()
    if requested_status == "active" and req.replace_existing_active:
        (
            db.query(CustomerSubscription)
            .filter(CustomerSubscription.user_id == user.id)
            .filter(CustomerSubscription.status == "active")
            .filter(CustomerSubscription.id != subscription.id)
            .update(
                {
                    CustomerSubscription.status: "superseded",
                    CustomerSubscription.updated_at: utcnow(),
                },
                synchronize_session=False,
            )
        )
    db.commit()
    db.refresh(subscription)
    return {
        "status": "created" if creating else "updated",
        "user_id": user.id,
        "plan_code": subscription.plan_code,
        "subscription_status": subscription.status,
        "expires_at": subscription.expires_at,
        "max_devices": subscription.max_devices,
        "plan": serialize_plan(plan),
    }


@internal_router.post("/devices/authorize")
def authorize_device_api(req: AuthorizeDeviceReq, db: Session = Depends(get_db)):
    user = get_user_by_identity(db, req.user_identity)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    machine_id = normalize_machine_id(req.machine_id)
    if not machine_id:
        raise HTTPException(status_code=400, detail="machine_id is required")

    subscription = get_active_subscription(db, user.id)
    if not subscription:
        raise HTTPException(status_code=400, detail="User has no active subscription")

    existing = get_device_activation(db, user.id, machine_id)
    requested_status = req.status.strip().lower() or "active"
    active_count = (
        db.query(DeviceActivation)
        .filter(DeviceActivation.user_id == user.id)
        .filter(DeviceActivation.status == "active")
        .count()
    )
    if requested_status == "active":
        effective_active_count = active_count
        if existing and existing.status == "active":
            effective_active_count = max(0, active_count - 1)
        if effective_active_count >= max(1, subscription.max_devices):
            raise HTTPException(status_code=409, detail="Max device limit reached for this subscription")

    if not existing:
        existing = DeviceActivation(
            user_id=user.id,
            machine_id=machine_id,
            device_name=req.device_name.strip(),
            status=requested_status,
            approved_at=utcnow() if requested_status == "active" else None,
            notes=req.notes.strip(),
        )
        db.add(existing)
        db.commit()
        db.refresh(existing)
    else:
        existing.device_name = req.device_name.strip() or existing.device_name
        existing.status = requested_status
        existing.approved_at = utcnow() if existing.status == "active" else existing.approved_at
        existing.notes = req.notes.strip()
        existing.updated_at = utcnow()
        db.commit()
        db.refresh(existing)

    license_item = ensure_device_access_license(db, user=user, subscription=subscription, device=existing)
    return {
        "status": existing.status,
        "user_id": user.id,
        "machine_id": existing.machine_id,
        "device_name": existing.device_name or "",
        "access_key": license_item.key,
        "subscription_expires_at": subscription.expires_at,
    }


@internal_router.post("/devices/revoke")
def revoke_device_api(req: RevokeDeviceReq, db: Session = Depends(get_db)):
    user = get_user_by_identity(db, req.user_identity)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    machine_id = normalize_machine_id(req.machine_id)
    device = get_device_activation(db, user.id, machine_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.status = "revoked"
    device.updated_at = utcnow()
    device.last_login_at = utcnow()
    if device.license_id:
        license_item = db.query(License).filter(License.id == device.license_id).first()
        if license_item:
            license_item.is_active = False
            session_challenge_guard.clear(license_item.session_id)
            license_item.session_id = None
            license_item.session_key = None
            license_item.session_expiration = None
    db.commit()
    return {"status": "revoked", "machine_id": machine_id}


@internal_router.get("/users/status")
def user_status_api(identity: str, db: Session = Depends(get_db)):
    user = get_user_by_identity(db, identity)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    subscription = get_active_subscription(db, user.id)
    current_plan = get_plan_by_code(db, subscription.plan_code) if subscription else None
    devices = (
        db.query(DeviceActivation)
        .filter(DeviceActivation.user_id == user.id)
        .order_by(DeviceActivation.id.desc())
        .all()
    )
    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
        },
        "subscription": {
            "plan_code": subscription.plan_code if subscription else None,
            "plan_name": current_plan.name if current_plan else None,
            "status": subscription.status if subscription else "inactive",
            "expires_at": subscription.expires_at if subscription else None,
            "max_devices": subscription.max_devices if subscription else 0,
            "plan": serialize_plan(current_plan) if current_plan else None,
        },
        "devices": [
            {
                "machine_id": item.machine_id,
                "device_name": item.device_name,
                "status": item.status,
                "approved_at": item.approved_at,
                "last_login_at": item.last_login_at,
                "license_id": item.license_id,
            }
            for item in devices
        ],
    }


@internal_router.post("/reset_hwid")
def reset_hwid_api(req: ResetHWIDReq, db: Session = Depends(get_db)):
    license_item = db.query(License).filter(License.key == req.key).first()
    if not license_item:
        raise HTTPException(status_code=404, detail="License not found")

    license_item.machine_id = ""
    session_challenge_guard.clear(license_item.session_id)
    license_item.session_id = None
    license_item.session_key = None
    license_item.session_expiration = None
    db.commit()
    return {"status": "success", "message": "HWID Reset Complete"}


@internal_router.get("/stats")
def get_stats_api(db: Session = Depends(get_db)):
    total_licenses = db.query(License).count()
    active_sessions = db.query(License).filter(License.session_id != None).count()  # noqa: E711
    total_users = db.query(WebUser).count()
    total_devices = db.query(DeviceActivation).count()
    active_subscriptions = db.query(CustomerSubscription).filter(CustomerSubscription.status == "active").count()
    total_plans = db.query(SubscriptionPlan).count()
    return {
        "total_licenses": total_licenses,
        "active_sessions": active_sessions,
        "total_users": total_users,
        "total_devices": total_devices,
        "active_subscriptions": active_subscriptions,
        "total_plans": total_plans,
        "server_status": "online",
    }


@internal_router.get("/runtime/workers")
def get_runtime_workers_api():
    return get_runtime_worker_status()


@internal_router.post("/runtime/workers/scale")
def scale_runtime_workers_api(req: WorkerScaleReq):
    action = (req.action or "").strip().lower()
    if action not in {"add", "remove"}:
        raise HTTPException(status_code=400, detail="action must be 'add' or 'remove'")
    try:
        return scale_runtime_workers(
            action=action,
            count=max(1, int(req.count or 1)),
            persist=bool(req.persist),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@internal_router.post("/upload_module")
def upload_module(req: ModuleUploadRequest, db: Session = Depends(get_db)):
    normalized_checksum = module_checksum(req.code_content)
    encrypted_str = encrypt_code(req.code_content)
    new_module = ModuleVersion(
        name=req.name,
        version=req.version,
        encrypted_code=encrypted_str,
        hash_checksum=normalized_checksum,
    )
    db.add(new_module)
    db.commit()
    return {"status": "Uploaded", "module": req.name, "hash_checksum": normalized_checksum}


app.include_router(internal_router)


@app.post("/puzzle/solve")
def solve_puzzle(req: PuzzleSolveRequest, db: Session = Depends(get_db)):
    expected_scope = f"puzzle:{req.type}:{req.challenge}"
    if req.module_name != expected_scope:
        raise HTTPException(status_code=403, detail="Invalid puzzle scope")

    license_item, challenge_state = validate_session_request(req, db)

    import hashlib

    result = None
    if req.type == "api_offset":
        try:
            result = (int(req.challenge) * 3) % 7
        except Exception:
            result = 0
    elif req.type == "magic_token":
        salt = (license_item.session_key or "SALT")[:5]
        result = hashlib.md5((str(req.challenge) + salt).encode()).hexdigest()[:16]
    elif req.type == "param_shuffle":
        result = [0, 1, 2]
    elif req.type == "status_map":
        result = {
            "ALL": 100,
            "UNPAID": 200,
            "TO_SHIP": 300,
            "SHIPPING": 400,
            "COMPLETED": 500,
            "CANCELLED": 100,
            "TO_RETURN": 100,
        }.get(req.challenge, 100)
    elif req.type == "flash_window":
        result = 7
    elif req.type in {"chat_limit", "sync_batch", "rating_limit", "product_limit"}:
        session_secret = license_item.session_key or "NO_SESSION"
        salt_val = int(hashlib.md5(session_secret.encode()).hexdigest(), 16)
        result = {
            "limit": 20 if req.type in {"rating_limit", "product_limit"} else 50,
            "retries": 3 if req.type == "chat_limit" else 0,
            "magic_salt": str(salt_val),
        }
    elif req.type == "ui_unlock":
        result = "7f8a9b1c2d3e4f5a6b7c8d9e0f1a2b3c" if req.challenge == "sidebar_init" else "INVALID"

    response_payload = {
        "status": "ok",
        "solution": result,
        "response_type": "puzzle",
        "type": req.type,
        "challenge": req.challenge,
        "session_id": req.session_id,
        "sync_token": req.sync_token,
        "session_epoch": challenge_state.get("epoch", 1),
        "issued_at": current_timestamp(),
    }
    response_payload["response_signature"] = sign_server_response(license_item.session_key, response_payload)
    return response_payload


if __name__ == "__main__":
    import uvicorn

    print("Launching backend in direct mode...")
    uvicorn.run("Backend.main:app", host="127.0.0.1", port=8000, reload=True, reload_dirs=["Backend"])
