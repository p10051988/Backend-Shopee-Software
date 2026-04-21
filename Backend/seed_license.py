from __future__ import annotations

import sys
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app_config import settings
from app_security import current_timestamp, new_nonce, sign_internal_request


BASE_URL = settings.backend_url
PATH = "/api/internal/create_license"
KEY_TO_ADD = "VIP-KEY-6n5jab5a"
DAYS = 3650


def build_headers(body: dict) -> dict:
    if not settings.internal_api_secret:
        raise RuntimeError("INTERNAL_API_SECRET is not configured. Update .env before seeding licenses.")

    timestamp = str(current_timestamp())
    nonce = new_nonce()
    return {
        "X-Internal-Key": "autoshopee-internal",
        "X-Internal-Timestamp": timestamp,
        "X-Internal-Nonce": nonce,
        "X-Internal-Signature": sign_internal_request(
            settings.internal_api_secret,
            "POST",
            PATH,
            timestamp,
            nonce,
            body,
        ),
    }


def add_license():
    payload = {
        "key": KEY_TO_ADD,
        "duration_days": DAYS,
        "max_machines": 1,
        "description": "Seeded by script",
    }
    try:
        response = requests.post(f"{BASE_URL}{PATH}", json=payload, headers=build_headers(payload), timeout=10)
        if response.status_code == 200:
            print(f"Success: {response.json()}")
        else:
            print(f"Failed: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    add_license()
