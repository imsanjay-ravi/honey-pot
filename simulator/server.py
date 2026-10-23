"""
simulator/server.py — CLI Launcher for the Linux Attacker Simulator.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import sys
import uvicorn

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="Start the Linux Attacker Simulator UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Port to bind (default: 8001)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    args = parser.parse_args()

    print(f"[*] Starting Linux Attacker Simulator on http://{args.host}:{args.port}")
    uvicorn.run("simulator.app:app", host=args.host, port=args.port, reload=args.reload, app_dir=str(REPO_ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
