from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.worker_runtime import get_runtime_worker_status, scale_runtime_workers


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect or scale Auto-Shopee backend workers")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show current worker status")

    add_parser = subparsers.add_parser("add", help="Add Gunicorn workers")
    add_parser.add_argument("count", nargs="?", type=int, default=1)
    add_parser.add_argument("--persist", action="store_true", help="Persist BACKEND_WORKERS into .env")

    remove_parser = subparsers.add_parser("remove", help="Remove Gunicorn workers")
    remove_parser.add_argument("count", nargs="?", type=int, default=1)
    remove_parser.add_argument("--persist", action="store_true", help="Persist BACKEND_WORKERS into .env")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.command == "status":
            payload = get_runtime_worker_status()
        else:
            payload = scale_runtime_workers(
                action=args.command,
                count=max(1, int(args.count or 1)),
                persist=bool(args.persist),
            )
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    except RuntimeError as exc:
        print(f"[WORKERCTL] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
