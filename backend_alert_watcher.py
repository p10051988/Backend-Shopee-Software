#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
from pathlib import Path

from backend_monitor_lib import build_alert_message, classify_state, load_config, load_state_file, safe_fetch, save_state_file, send_telegram


SCRIPT_DIR = Path(__file__).resolve().parent
STATE_PATH = SCRIPT_DIR / "run" / "backend-alert-state.json"


def main() -> int:
    config = load_config()
    if not config.telegram_bot_token or not config.telegram_chat_id:
        print("[ALERT] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing. Running log-only mode.", flush=True)
    while True:
        snapshot = safe_fetch(config)
        status, reasons = classify_state(snapshot, config)
        state = load_state_file(STATE_PATH)
        now = int(time.time())
        previous_status = state.get("status", "UNKNOWN")
        last_sent_at = int(state.get("last_sent_at", 0) or 0)
        should_send = False
        if status != "HEALTHY":
            if previous_status != status or (now - last_sent_at) >= config.alert_cooldown_seconds:
                should_send = True
        elif previous_status in {"WARNING", "CRITICAL"}:
            should_send = True

        if should_send:
            if status == "HEALTHY":
                message = "<b>Auto-Shopee Backend Recovery</b>\nStatus: <b>HEALTHY</b>\nAll monitored signals are back in range."
            else:
                message = build_alert_message(snapshot, status, reasons)
            try:
                send_telegram(config, message)
                last_sent_at = now
                print(f"[ALERT] Sent {status} notification", flush=True)
            except Exception as exc:
                print(f"[ALERT] Telegram send failed: {exc}", flush=True)

        save_state_file(
            STATE_PATH,
            {
                "status": status,
                "reasons": reasons,
                "last_sent_at": last_sent_at,
                "updated_at": now,
            },
        )
        time.sleep(config.alert_poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
