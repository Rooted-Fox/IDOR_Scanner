"""One-time session capture helper.

Opens a real browser; you log in as a user once, press Enter, and the session
(cookies, Authorization headers, localStorage tokens) is saved to ./sessions/.
The scanner then reuses it automatically - no manual header copying.

Usage:
    python capture_session.py https://target.example.com user_a --role user
    python capture_session.py https://target.example.com admin  --role admin

Capture two different users to enable cross-user IDOR testing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from core.browser import capture_session


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture a login session for the IDOR scanner")
    ap.add_argument("target", help="Target URL to open for login")
    ap.add_argument("name", help="Logical session name, e.g. user_a / user_b / admin")
    ap.add_argument("--role", default="user", choices=["user", "admin"])
    ap.add_argument("--no-sandbox", action="store_true",
                    help="Pass --no-sandbox to Chromium (some Linux/container setups)")
    args = ap.parse_args()

    launch_args = ["--no-sandbox"] if args.no_sandbox else []
    bundle = capture_session(args.target, args.name, args.role, launch_args=launch_args)

    out_dir = Path("sessions")
    out_dir.mkdir(exist_ok=True)
    path = out_dir / f"{args.name}.json"
    path.write_text(bundle.to_json(), encoding="utf-8")
    print(f"\nSaved session '{args.name}' ({args.role}) -> {path}")
    print(f"  cookies: {len(bundle.cookies)}  headers: {list(bundle.headers)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
