"""
telemetry/cowrie_source.py — Read-only Cowrie JSON log tailer and source abstraction.

Phase 7 Live Cowrie Telemetry Integration:
- Ingests JSONL events from real Cowrie logs incrementally without duplicate events.
- Tracks file byte offset and detects truncation or file rotation.
- Tolerates partial trailing lines (e.g. while Cowrie is actively flushing to disk).
- Operates in strict read-only mode (never modifies or writes to source log file).
- Prevents unbounded memory usage by streaming line-by-line.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parser.cowrie_parser import ParseWarning, normalize_event


@dataclass
class CowrieSourceConfig:
    """Configuration options for Cowrie live telemetry ingestion."""
    log_path: Path | None = None
    poll_interval_seconds: float = 2.0
    max_events_per_poll: int = 1000
    auth_token: str = "cowrie-live-telemetry-secret-token"
    enabled: bool = True


@dataclass
class SourceHealth:
    """Operational health status of the Cowrie telemetry source."""
    status: str = "uninitialized"  # 'ok', 'waiting_for_events', 'file_not_found', 'error'
    log_path: str = ""
    file_exists: bool = False
    connected: bool = False
    file_size_bytes: int = 0
    current_offset: int = 0
    total_events_read: int = 0
    total_warnings: int = 0
    last_poll_time: str | None = None
    last_event_time: str | None = None
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "connected": self.connected,
            "log_path": self.log_path,
            "file_exists": self.file_exists,
            "file_size_bytes": self.file_size_bytes,
            "current_offset": self.current_offset,
            "total_events_read": self.total_events_read,
            "total_warnings": self.total_warnings,
            "last_poll_time": self.last_poll_time,
            "last_event_time": self.last_event_time,
            "last_error": self.last_error,
        }


class CowrieLogTailer:
    """
    Incremental, read-only JSONL log tailer for Cowrie honeypot logs.
    """

    def __init__(
        self,
        log_path: str | Path | CowrieSourceConfig,
        start_at_beginning: bool = True,
        max_batch_size: int = 1000,
    ) -> None:
        if isinstance(log_path, CowrieSourceConfig):
            self.log_path = Path(log_path.log_path).resolve()
            self.start_at_beginning = start_at_beginning
            self.max_batch_size = log_path.max_events_per_poll
        else:
            self.log_path = Path(log_path).resolve()
            self.start_at_beginning = start_at_beginning
            self.max_batch_size = max_batch_size

        self._offset: int = 0
        self._last_size: int = 0
        self._last_mtime: float = 0.0
        self._total_events_read: int = 0
        self._warnings: list[ParseWarning] = []
        self._last_error: str | None = None
        self._last_poll_time: str | None = None
        self._last_event_time: str | None = None

        # If not starting at beginning and file exists, position at EOF
        if not start_at_beginning and self.log_path.is_file():
            try:
                self._offset = self.log_path.stat().st_size
                self._last_size = self._offset
            except OSError:
                self._offset = 0

    @property
    def current_offset(self) -> int:
        return self._offset

    @property
    def last_offset(self) -> int:
        return self._offset

    @property
    def total_events_read(self) -> int:
        return self._total_events_read

    def get_health(self) -> SourceHealth:
        """Inspect source log accessibility and return health metrics."""
        exists = self.log_path.is_file()
        size = 0
        if exists:
            try:
                size = self.log_path.stat().st_size
            except OSError:
                exists = False

        status = "ok"
        if not exists:
            status = "file_not_found"
        elif self._total_events_read == 0 and size == 0:
            status = "waiting_for_events"
        elif self._last_error:
            status = "error"

        return SourceHealth(
            status=status,
            log_path=str(self.log_path),
            file_exists=exists,
            connected=exists and status in ("ok", "waiting_for_events"),
            file_size_bytes=size,
            current_offset=self._offset,
            total_events_read=self._total_events_read,
            total_warnings=len(self._warnings),
            last_poll_time=self._last_poll_time,
            last_event_time=self._last_event_time,
            last_error=self._last_error,
        )

    def reset(self) -> None:
        """Reset read position to beginning of file and clear statistics."""
        self._offset = 0
        self._last_size = 0
        self._total_events_read = 0
        self._warnings.clear()
        self._last_error = None
        self._last_poll_time = None
        self._last_event_time = None

    def poll(self) -> tuple[list[dict[str, Any]], list[ParseWarning]]:
        """
        Poll the Cowrie log file for newly appended JSON lines.

        Returns
        -------
        tuple[list[dict[str, Any]], list[ParseWarning]]
            A tuple of (newly_ingested_events, new_warnings).
        """
        self._last_poll_time = datetime.now(timezone.utc).isoformat()
        new_events: list[dict[str, Any]] = []
        new_warnings: list[ParseWarning] = []

        if not self.log_path.is_file():
            self._last_error = f"Log file not found at {self.log_path}"
            return new_events, new_warnings

        try:
            current_stat = self.log_path.stat()
            current_size = current_stat.st_size
            current_mtime = current_stat.st_mtime
            self._last_error = None
        except OSError as exc:
            self._last_error = f"Cannot stat log file: {exc}"
            return new_events, new_warnings

        # Detection of file rotation or truncation:
        # If current size is strictly smaller than last read offset, the file
        # was truncated or rotated by logrotate. Reset offset to 0.
        if current_size < self._offset:
            self._offset = 0
            new_warnings.append(
                ParseWarning(
                    line_number=0,
                    reason=f"Log file truncation or rotation detected ({current_size} < {self._last_size}). Offset reset to 0.",
                )
            )

        # Nothing new appended
        if current_size == self._offset and self._offset > 0:
            return new_events, new_warnings

        self._last_size = current_size
        self._last_mtime = current_mtime

        # Open in strictly READ-ONLY text mode.
        try:
            with self.log_path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._offset)

                line_num = 0
                while len(new_events) < self.max_batch_size:
                    start_line_pos = fh.tell()
                    line = fh.readline()

                    # EOF reached
                    if not line:
                        break

                    # Incomplete trailing line detection:
                    # If line does not terminate with newline, Cowrie is actively
                    # writing/flushing. Rewind to start of line and wait for next poll.
                    if not line.endswith(("\n", "\r")):
                        fh.seek(start_line_pos)
                        break

                    line_num += 1
                    raw_str = line.strip()
                    if not raw_str:
                        # Skip blank lines safely
                        self._offset = fh.tell()
                        continue

                    try:
                        raw_event = json.loads(raw_str)
                    except json.JSONDecodeError as exc:
                        warn = ParseWarning(
                            line_number=line_num,
                            reason=f"Malformed JSON line skipped: {exc}",
                        )
                        new_warnings.append(warn)
                        self._warnings.append(warn)
                        self._offset = fh.tell()
                        continue

                    if not isinstance(raw_event, dict):
                        warn = ParseWarning(
                            line_number=line_num,
                            reason=f"Expected JSON object, got {type(raw_event).__name__}",
                        )
                        new_warnings.append(warn)
                        self._warnings.append(warn)
                        self._offset = fh.tell()
                        continue

                    try:
                        normalized = normalize_event(raw_event)
                        if "eventid" not in normalized and "eventid" in raw_event:
                            normalized["eventid"] = raw_event["eventid"]
                        new_events.append(normalized)
                        self._total_events_read += 1
                        self._last_event_time = normalized.get("timestamp")
                    except KeyError as exc:
                        warn = ParseWarning(
                            line_number=line_num,
                            reason=f"Missing required Cowrie field: {exc}",
                        )
                        new_warnings.append(warn)
                        self._warnings.append(warn)
                    except (TypeError, ValueError) as exc:
                        warn = ParseWarning(
                            line_number=line_num,
                            reason=f"Event normalization error: {exc}",
                        )
                        new_warnings.append(warn)
                        self._warnings.append(warn)

                    self._offset = fh.tell()

        except OSError as exc:
            self._last_error = f"Error reading log file: {exc}"

        return new_events, new_warnings
