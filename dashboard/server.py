"""
dashboard/server.py — CLI Launcher for the Analysis Dashboard.
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
    parser = argparse.ArgumentParser(description="Start the AI Adaptive Cyber Deception Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    args = parser.parse_args()

    print(f"[*] Starting Analysis Dashboard on http://{args.host}:{args.port}")
    uvicorn.run("dashboard.app:app", host=args.host, port=args.port, reload=args.reload, app_dir=str(REPO_ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
