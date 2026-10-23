"""
telemetry/live_service.py — Live Cowrie Telemetry Processing Service.

Manages:
- Ingestion of live events from local tailer or authenticated Ubuntu collector.
- Real-time session grouping, deterministic behaviour analysis, and heuristic scoring.
- Simulated/advisory deception policy recommendations (strictly offline recommendations,
  never applied to the live honeypot).
- Source health and connectivity tracking.
- Output formatting adhering to the Phase 5 dashboard pipeline schema.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analysis.engine import analyse_session
from deception.engine import DeceptionEngine
from deception.world_state import WorldState
from parser.cowrie_parser import ParseWarning, group_events_by_session, normalize_event
from telemetry.cowrie_source import CowrieLogTailer, SourceHealth


class LiveCowrieService:
    """
    Authoritative service managing live Cowrie honeypot telemetry in memory.
    """

    def __init__(
        self,
        tailer: CowrieLogTailer | None = None,
        auth_token: str | None = None,
    ) -> None:
        self.tailer: CowrieLogTailer | None = tailer
        self.auth_token: str = auth_token or os.environ.get(
            "COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token"
        )
        self.events: list[dict[str, Any]] = []
        self.sessions: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.session_analyses: dict[str, dict[str, Any]] = {}
        self.session_deceptions: dict[str, dict[str, Any]] = {}
        self.warnings: list[dict[str, Any]] = []

        # Advisory-only deception engine; maintains fictional state for visualization
        self.deception_engine = DeceptionEngine(world_state=WorldState.create_default())

        self.last_ingest_time: str | None = None
        self.last_poll_time: str | None = None
        self.collector_connected: bool = False
        self.last_collector_ip: str | None = None

    def set_tailer(self, tailer: CowrieLogTailer) -> None:
        """Configure local/mounted log file tailer."""
        self.tailer = tailer

    def verify_auth_token(self, provided_token: str | None) -> bool:
        """Validate ingestion bearer token."""
        if not self.auth_token:
            return True
        return provided_token == self.auth_token

    def poll_local(self) -> int:
        """
        Poll local/mounted Cowrie log tailer if configured.
        Returns number of new events ingested.
        """
        if not self.tailer:
            return 0

        self.last_poll_time = datetime.now(timezone.utc).isoformat()
        new_events, new_warnings = self.tailer.poll()

        for w in new_warnings:
            self.warnings.append({"line_number": w.line_number, "reason": w.reason})

        if new_events:
            self._process_events(new_events)
            self.last_ingest_time = datetime.now(timezone.utc).isoformat()

        return len(new_events)

    def ingest_batch(
        self,
        raw_events: list[dict[str, Any]],
        remote_ip: str | None = None,
    ) -> tuple[int, int]:
        """
        Ingest a batch of events pushed by an external collector (e.g. from Ubuntu VM).

        Returns
        -------
        tuple[int, int]
            (accepted_events_count, warnings_count)
        """
        self.collector_connected = True
        self.last_collector_ip = remote_ip
        self.last_ingest_time = datetime.now(timezone.utc).isoformat()

        accepted: list[dict[str, Any]] = []
        warn_count = 0

        for idx, item in enumerate(raw_events):
            if not isinstance(item, dict):
                self.warnings.append({
                    "line_number": idx + 1,
                    "reason": f"Expected dict, got {type(item).__name__}",
                })
                warn_count += 1
                continue

            # Check if event is already normalized or raw Cowrie
            if "event_type" in item and "timestamp" in item and "session_id" in item:
                accepted.append(item)
            else:
                try:
                    norm = normalize_event(item)
                    accepted.append(norm)
                except Exception as exc:
                    self.warnings.append({
                        "line_number": idx + 1,
                        "reason": f"Ingestion normalization error: {exc}",
                    })
                    warn_count += 1

        if accepted:
            self._process_events(accepted)

        return len(accepted), warn_count

    def _process_events(self, events: list[dict[str, Any]]) -> None:
        """Group events into sessions and incrementally update analysis & advisory deception."""
        for evt in events:
            self.events.append(evt)
            sid = evt.get("session_id")
            if sid:
                self.sessions[sid].append(evt)

        # Update analysis and advisory deception for all touched sessions
        for sid, sess_events in self.sessions.items():
            analysis = analyse_session(sess_events, session_id=sid)
            self.session_analyses[sid] = analysis

            # Advisory deception recommendation: strictly simulated
            deception = self.deception_engine.process(analysis)
            # Tag explicitly as advisory-only recommendation
            advisory_deception = dict(deception)
            advisory_deception["advisory_only"] = True
            advisory_deception["status"] = (
                "simulated_recommendation"
                if deception.get("status") in ("accepted", "action_taken")
                else "no_action_recommended"
            )
            raw_expl = deception.get("explanation", "")
            advisory_deception["explanation"] = f"[ADVISORY RECOMMENDATION — Real Honeypot Unmodified] {raw_expl}"
            self.session_deceptions[sid] = advisory_deception

    def has_activity(self) -> bool:
        """Return True if any live Cowrie events have been ingested."""
        return len(self.events) > 0

    def get_health(self) -> dict[str, Any]:
        """Return live telemetry connection health status and ingestion metrics."""
        tailer_health = self.tailer.get_health().to_dict() if self.tailer else None

        has_active = self.has_activity()
        is_connected = False
        status = "waiting_for_events"

        if self.tailer and tailer_health:
            if not tailer_health.get("file_exists"):
                status = "tailer_path_unreachable"
                is_connected = False
            elif tailer_health.get("last_error"):
                status = "error"
                is_connected = False
            elif has_active:
                status = "healthy"
                is_connected = True
            else:
                status = "tailing_log"
                is_connected = True
        elif self.collector_connected:
            is_connected = True
            status = "healthy" if has_active else "connected"
        elif has_active:
            is_connected = True
            status = "healthy"
        else:
            status = "waiting_for_events"
            is_connected = False

        return {
            "status": status,
            "connected": is_connected,
            "has_activity": has_active,
            "total_events_ingested": len(self.events),
            "total_sessions_analyzed": len(self.sessions),
            "warnings_count": len(self.warnings),
            "last_ingest_time": self.last_ingest_time,
            "last_ingested_at": self.last_ingest_time,
            "last_poll_time": self.last_poll_time,
            "collector_connected": self.collector_connected,
            "last_collector_ip": self.last_collector_ip,
            "tailer": tailer_health,
        }

    def get_pipeline_result(self) -> dict[str, Any]:
        """
        Format live Cowrie sessions into the standard Phase 5 dashboard pipeline schema.
        """
        # If a tailer is configured, perform a poll to ensure fresh events
        if self.tailer:
            try:
                self.poll_local()
            except Exception:
                pass

        session_records: list[dict[str, Any]] = []

        def _sort_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[str, str]:
            sid, evts = item
            first_ts = evts[0].get("timestamp", "") if evts else ""
            return (first_ts, sid)

        for sid, sess_events in sorted(self.sessions.items(), key=_sort_key):
            analysis = self.session_analyses.get(sid, {})
            deception = self.session_deceptions.get(sid, {})
            src_ip = sess_events[0].get("source_ip", "unknown") if sess_events else "unknown"

            session_records.append({
                "session_id": sid,
                "source_ip": src_ip,
                "event_count": len(sess_events),
                "analysis": {
                    "primary_category": analysis.get("primary_category", "unknown"),
                    "score": analysis.get("score", 0),
                    "findings": analysis.get("findings", []),
                    "score_explanation": analysis.get("score_explanation", ""),
                    "warnings": analysis.get("warnings", []),
                },
                "deception": deception,
            })

        has_active = self.has_activity()
        input_desc = "live://ubuntu-collector"
        if self.tailer:
            input_desc = f"file://{self.tailer.log_path}"

        world_dict = self.deception_engine.world_state.to_dict()
        advisory_history = []
        for act in world_dict.get("action_history", []):
            item = dict(act)
            item["advisory_only"] = True
            item["status"] = "simulated_recommendation"
            if not item.get("explanation", "").startswith("[ADVISORY RECOMMENDATION"):
                item["explanation"] = f"[ADVISORY RECOMMENDATION — Real Honeypot Unmodified] {item.get('explanation', '')}"
            advisory_history.append(item)
        world_dict["action_history"] = advisory_history

        # Deception metric semantics:
        # Phase 7 live telemetry is strictly read-only.
        # Zero actions were executed on the real honeypot.
        # Actions generated are simulated policy recommendations.
        executed_count = 0
        recommendations_count = len([
            a for a in advisory_history
            if a.get("action_id") and a.get("action_id") != "no_op"
        ])
        deception_metric = {
            "label": "RECOMMENDATIONS GENERATED",
            "value": recommendations_count,
            "actions_executed_count": executed_count,
            "recommendations_count": recommendations_count,
            "is_advisory": True,
            "status_note": "Read-Only: 0 actions executed on real honeypot",
        }

        health_dict = self.get_health()

        return {
            "loaded": has_active,
            "source": "live_cowrie",
            "source_label": "Live Cowrie Honeypot (Ubuntu Telemetry)",
            "pipeline_version": "1.0.0",
            "input_file": input_desc,
            "events_parsed": len(self.events) if has_active else 0,
            "warnings_count": len(self.warnings),
            "warnings": self.warnings,
            "sessions_count": len(session_records) if has_active else 0,
            "sessions": session_records if has_active else [],
            "world_state": world_dict,
            "deception_metric": deception_metric,
            "live_health": health_dict,
            "health": health_dict,
        }

    def reset(self) -> None:
        """Reset live telemetry buffer, sessions, warnings, and advisory world state."""
        self.events.clear()
        self.sessions.clear()
        self.session_analyses.clear()
        self.session_deceptions.clear()
        self.warnings.clear()
        self.deception_engine.reset()
        if self.tailer:
            self.tailer.reset()
        self.last_ingest_time = None
        self.last_poll_time = None
        self.collector_connected = False


# Singleton service instance
_LIVE_SERVICE: LiveCowrieService | None = None


def get_live_service() -> LiveCowrieService:
    """Return the global singleton LiveCowrieService instance."""
    global _LIVE_SERVICE
    if _LIVE_SERVICE is None:
        tailer = None
        env_path = os.environ.get("COWRIE_LOG_PATH")
        if env_path:
            p = Path(env_path)
            tailer = CowrieLogTailer(p)
        _LIVE_SERVICE = LiveCowrieService(tailer=tailer)
    return _LIVE_SERVICE
