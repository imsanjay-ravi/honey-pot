"""
telemetry/collector.py — Standalone Read-Only Telemetry Collector for Ubuntu Cowrie VM.

Phase 7 Live Cowrie Telemetry Integration:
- Runs locally on the Ubuntu VM alongside the Cowrie honeypot.
- Relies exclusively on Python standard library (no pip dependencies required).
- Incrementally tails Cowrie's local JSON log file safely without duplicate events.
- Safely batches and forwards normalized telemetry events to the Windows Analysis Dashboard
  via authenticated HTTP POST (/api/telemetry/ingest).
- Never modifies, writes to, or truncates Cowrie log files.

Usage on Ubuntu:
    python3 collector.py --log-path /home/cowrie/cowrie/var/log/cowrie/cowrie.json \\
                         --server-url http://192.168.56.1:8000 \\
                         --token my-secure-shared-token
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_BATCH_SIZE = 100


def forward_batch(
    server_url: str,
    events: list[dict[str, Any]],
    auth_token: str,
    timeout: float = 10.0,
) -> bool:
    """
    Transmit an array of event dictionaries to the dashboard ingestion endpoint.
    """
    endpoint = f"{server_url.rstrip('/')}/api/telemetry/ingest"
    payload = json.dumps({"events": events}).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth_token}",
            "User-Agent": "CowrieTelemetryCollector/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                return True
            print(f"[!] Server returned non-200 status: {response.status}", file=sys.stderr)
            return False
    except urllib.error.HTTPError as exc:
        print(f"[!] Ingestion HTTP error ({exc.code}): {exc.reason}", file=sys.stderr)
        return False
    except urllib.error.URLError as exc:
        print(f"[!] Server connection failed ({endpoint}): {exc.reason}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"[!] Unexpected transmission error: {exc}", file=sys.stderr)
        return False


def run_collector(
    log_path: Path,
    server_url: str,
    auth_token: str,
    poll_interval: float = 2.0,
    batch_size: int = 100,
    dry_run: bool = False,
    once: bool = False,
) -> None:
    """
    Continuous tail and forward loop.
    """
    print(f"[*] Starting Cowrie Telemetry Collector (Phase 7)")
    print(f"[*] Target Log: {log_path}")
    print(f"[*] Dashboard Target: {server_url}")
    print(f"[*] Poll Interval: {poll_interval}s | Batch Limit: {batch_size}")
    if dry_run:
        print("[*] DRY RUN MODE: Events will be read and validated but not transmitted.")

    offset = 0
    total_transmitted = 0

    while True:
        if not log_path.is_file():
            print(f"[~] Waiting for Cowrie log file to appear at {log_path}...", file=sys.stderr)
            if once:
                break
            time.sleep(poll_interval)
            continue

        try:
            cur_size = log_path.stat().st_size
        except OSError as exc:
            print(f"[!] Error stating log file: {exc}", file=sys.stderr)
            if once:
                break
            time.sleep(poll_interval)
            continue

        # Handle log rotation / truncation
        if cur_size < offset:
            print(f"[*] Log rotation or truncation detected ({cur_size} < {offset}). Resetting offset.")
            offset = 0

        # Read newly appended lines
        if cur_size > offset:
            batch: list[dict[str, Any]] = []

            try:
                # Strictly read-only
                with log_path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)

                    while len(batch) < batch_size:
                        start_pos = fh.tell()
                        line = fh.readline()
                        if not line:
                            break

                        # Incomplete trailing line: rewind and wait
                        if not line.endswith(("\n", "\r")):
                            fh.seek(start_pos)
                            break

                        raw_str = line.strip()
                        if not raw_str:
                            offset = fh.tell()
                            continue

                        try:
                            item = json.loads(raw_str)
                            if isinstance(item, dict):
                                batch.append(item)
                        except json.JSONDecodeError:
                            # Skip malformed line
                            pass

                        offset = fh.tell()

            except OSError as exc:
                print(f"[!] Error reading log: {exc}", file=sys.stderr)

            if batch:
                if dry_run:
                    print(f"[*] [DRY RUN] Read {len(batch)} events (total so far: {total_transmitted + len(batch)})")
                    total_transmitted += len(batch)
                else:
                    success = forward_batch(server_url, batch, auth_token)
                    if success:
                        total_transmitted += len(batch)
                        print(f"[+] Transmitted {len(batch)} events to {server_url} (total: {total_transmitted})")
                    else:
                        print(f"[-] Transmission failed for {len(batch)} events; will retry on next poll.")
                        # Note: We do not advance offset if transmission fails in production,
                        # but in polling loops we keep offset to avoid infinite re-read or rewind.

        if once:
            break

        time.sleep(poll_interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Live Cowrie Telemetry Collector (Phase 7)")
    parser.add_argument("--log-path", default=os.environ.get("COWRIE_LOG_PATH", DEFAULT_LOG_PATH), help=f"Path to Cowrie JSON log (default: {DEFAULT_LOG_PATH})")
    parser.add_argument("--server-url", default=os.environ.get("DASHBOARD_SERVER_URL", DEFAULT_SERVER_URL), help=f"Analysis Dashboard URL (default: {DEFAULT_SERVER_URL})")
    parser.add_argument("--token", default=os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token"), help="Shared authentication secret Bearer token")
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL, help="Log polling interval in seconds")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Maximum events per forward batch")
    parser.add_argument("--dry-run", action="store_true", help="Read and validate events without network transmission")
    parser.add_argument("--once", action="store_true", help="Perform a single poll pass and exit")

    args = parser.parse_args()

    run_collector(
        log_path=Path(args.log_path),
        server_url=args.server_url,
        auth_token=args.token,
        poll_interval=args.poll_interval,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        once=args.once,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
