"""
tests/test_live_cowrie.py — Comprehensive test suite for Phase 7: Live Cowrie Telemetry Integration.

Covers:
1. Initial JSONL ingestion via CowrieLogTailer.
2. Incremental appended events polling.
3. Duplicate prevention via byte offset tracking.
4. Malformed records and incomplete trailing lines handling.
5. File truncation and log rotation detection.
6. Source timestamps, session IDs, and network metadata preservation.
7. Session grouping and behaviour analysis accuracy.
8. Source health reporting, unavailable source, and reconnection behaviour.
9. Dashboard selection and rendering of Live Cowrie data (/api/current-state, /api/sources).
10. Strict isolation between synthetic scenario, simulator, and live cowrie states.
11. Invalid event schemas, token authentication, and oversized batch rejection (> 1000 events).
12. Confirmation that source logs are never modified (read-only mode verified).
13. Confirmation that no shell execution, attacker connections, or real honeypot modifications occur.
14. Advisory-only deception recommendation tagging for live telemetry.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from dashboard.app import app
from telemetry.collector import run_collector
from telemetry.cowrie_source import CowrieLogTailer, CowrieSourceConfig
from telemetry.live_service import LiveCowrieService, get_live_service


SAMPLE_EVENT_1 = {
    "eventid": "cowrie.session.connect",
    "timestamp": "2026-10-23T20:00:00.000000Z",
    "session": "test-session-001",
    "src_ip": "198.51.100.42",
    "src_port": 49152,
    "dst_ip": "192.168.1.100",
    "dst_port": 2222,
    "protocol": "ssh",
}

SAMPLE_EVENT_2 = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-10-23T20:00:01.000000Z",
    "session": "test-session-001",
    "src_ip": "198.51.100.42",
    "username": "root",
    "password": "password123",
}

SAMPLE_EVENT_3 = {
    "eventid": "cowrie.login.success",
    "timestamp": "2026-10-23T20:00:02.000000Z",
    "session": "test-session-001",
    "src_ip": "198.51.100.42",
    "username": "root",
    "password": "correct_horse",
}

SAMPLE_EVENT_4 = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-10-23T20:00:03.000000Z",
    "session": "test-session-001",
    "src_ip": "198.51.100.42",
    "input": "uname -a && cat /etc/passwd",
}

SAMPLE_EVENT_SESSION_2 = {
    "eventid": "cowrie.session.connect",
    "timestamp": "2026-10-23T20:05:00.000000Z",
    "session": "test-session-002",
    "src_ip": "203.0.113.88",
    "src_port": 51234,
    "dst_ip": "192.168.1.100",
    "dst_port": 2222,
    "protocol": "ssh",
}


class TestCowrieLogTailer(unittest.TestCase):
    """Test suite for CowrieLogTailer offset tracking and edge cases."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="cowrie_test_")
        self.log_path = os.path.join(self.test_dir, "cowrie.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_initial_jsonl_ingestion(self):
        """Initial read consumes existing events and advances offset safely."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")
            f.write(json.dumps(SAMPLE_EVENT_2) + "\n")

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        events, warnings = tailer.poll()

        self.assertEqual(len(events), 2)
        self.assertEqual(len(warnings), 0)
        self.assertEqual(events[0]["eventid"], "cowrie.session.connect")
        self.assertEqual(events[1]["eventid"], "cowrie.login.failed")
        self.assertGreater(tailer.last_offset, 0)
        self.assertEqual(tailer.total_events_read, 2)

    def test_02_incremental_appended_events(self):
        """Subsequent poll only reads newly appended lines."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        events1, _ = tailer.poll()
        self.assertEqual(len(events1), 1)

        # Append second event
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_2) + "\n")

        events2, _ = tailer.poll()
        self.assertEqual(len(events2), 1)
        self.assertEqual(events2[0]["eventid"], "cowrie.login.failed")
        self.assertEqual(tailer.total_events_read, 2)

    def test_03_duplicate_prevention(self):
        """Polling an unchanged file produces 0 new events and does not re-emit."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        events1, _ = tailer.poll()
        self.assertEqual(len(events1), 1)

        # Poll again without modifying file
        events2, _ = tailer.poll()
        self.assertEqual(len(events2), 0)
        self.assertEqual(tailer.total_events_read, 1)

    def test_04_malformed_records_and_incomplete_trailing_lines(self):
        """Incomplete trailing lines without newline are held back; malformed lines emit warnings."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")
            f.write("CORRUPTED NON JSON LINE\n")
            # Incomplete line (no trailing newline)
            f.write('{"timestamp": "2026-10-23T20:00:04.000000Z", "eventid": "cowrie.login.fail')

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        events, warnings = tailer.poll()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["eventid"], "cowrie.session.connect")
        self.assertEqual(len(warnings), 1)
        self.assertIn("JSON", warnings[0].reason)

        # Now complete the trailing line
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write('ed", "session": "test-session-001"}\n')

        events_followup, _ = tailer.poll()
        self.assertEqual(len(events_followup), 1)
        self.assertEqual(events_followup[0]["eventid"], "cowrie.login.failed")

    def test_05_file_truncation_and_rotation(self):
        """File truncation resets offset to 0 and reads new content without error."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")
            f.write(json.dumps(SAMPLE_EVENT_2) + "\n")
            f.write(json.dumps(SAMPLE_EVENT_3) + "\n")

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        events1, _ = tailer.poll()
        self.assertEqual(len(events1), 3)

        # Truncate file (e.g. logrotate replaced or truncated file)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_4) + "\n")

        events2, warnings2 = tailer.poll()
        self.assertEqual(len(events2), 1)
        self.assertEqual(events2[0]["eventid"], "cowrie.command.input")

    def test_06_source_timestamps_and_session_id_preservation(self):
        """Preserves source timestamp, session ID, IP, port, and order."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        events, _ = tailer.poll()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["timestamp"], "2026-10-23T20:00:00+00:00")
        self.assertEqual(ev["session_id"], "test-session-001")
        self.assertEqual(ev["source_ip"], "198.51.100.42")

    def test_08_source_health_unavailable_and_reconnection(self):
        """Reports disconnected when file missing, restores connected when file appears."""
        missing_path = os.path.join(self.test_dir, "non_existent.json")
        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=missing_path))

        events, warnings = tailer.poll()
        self.assertEqual(len(events), 0)
        health = tailer.get_health()
        self.assertFalse(health.connected)

        # File appears
        with open(missing_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")

        events2, _ = tailer.poll()
        self.assertEqual(len(events2), 1)
        health2 = tailer.get_health()
        self.assertTrue(health2.connected)
        self.assertEqual(health2.total_events_read, 1)

    def test_12_confirmation_source_logs_never_modified(self):
        """Verify that the source log file is opened read-only and never modified."""
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(SAMPLE_EVENT_1) + "\n")
            f.write(json.dumps(SAMPLE_EVENT_2) + "\n")

        with open(self.log_path, "rb") as f:
            initial_hash = hashlib.sha256(f.read()).hexdigest()
        initial_stat = os.stat(self.log_path)

        tailer = CowrieLogTailer(CowrieSourceConfig(log_path=self.log_path))
        tailer.poll()

        with open(self.log_path, "rb") as f:
            post_hash = hashlib.sha256(f.read()).hexdigest()
        post_stat = os.stat(self.log_path)

        self.assertEqual(initial_hash, post_hash, "Source file content was modified by tailer!")
        self.assertEqual(initial_stat.st_mtime_ns, post_stat.st_mtime_ns, "Source file mtime changed!")


class TestLiveCowrieService(unittest.TestCase):
    """Test suite for LiveCowrieService session grouping, analysis, and safety."""

    def setUp(self):
        self.service = LiveCowrieService()

    def test_07_session_grouping_and_analysis_correctness(self):
        """Ingested events group into sessions and trigger behaviour analysis + threat scoring."""
        count, warnings = self.service.ingest_batch([
            SAMPLE_EVENT_1,
            SAMPLE_EVENT_2,
            SAMPLE_EVENT_3,
            SAMPLE_EVENT_4,
            SAMPLE_EVENT_SESSION_2,
        ])
        self.assertEqual(count, 5)
        self.assertEqual(warnings, 0)

        result = self.service.get_pipeline_result()
        self.assertTrue(result["loaded"])
        self.assertEqual(result["events_parsed"], 5)
        self.assertEqual(result["sessions_count"], 2)

        # Check session test-session-001 has analysis
        session_1 = next((s for s in result["sessions"] if s["session_id"] == "test-session-001"), None)
        self.assertIsNotNone(session_1)
        self.assertEqual(session_1["source_ip"], "198.51.100.42")
        self.assertIn("analysis", session_1)
        self.assertIn("score", session_1["analysis"])
        self.assertIn("findings", session_1["analysis"])

    def test_14_advisory_deception_recommendations(self):
        """Deception decisions for live sessions are tagged as simulated advisory recommendations."""
        self.service.ingest_batch([
            SAMPLE_EVENT_1,
            SAMPLE_EVENT_2,
            SAMPLE_EVENT_3,
            SAMPLE_EVENT_4,
        ])
        result = self.service.get_pipeline_result()
        history = result["world_state"]["action_history"]
        if history:
            for action in history:
                self.assertTrue(action.get("advisory_only", False))
                self.assertEqual(action.get("status"), "simulated_recommendation")
                self.assertIn("[ADVISORY RECOMMENDATION", action.get("explanation", ""))

    def test_13_no_shell_execution_or_attacker_connections(self):
        """Confirm that live ingestion and analysis never invoke subprocess or network connections."""
        with patch("subprocess.run") as mock_subproc, \
             patch("subprocess.Popen") as mock_popen, \
             patch("socket.socket") as mock_socket:

            self.service.ingest_batch([
                SAMPLE_EVENT_1,
                SAMPLE_EVENT_2,
                SAMPLE_EVENT_3,
                SAMPLE_EVENT_4,
            ])
            _ = self.service.get_pipeline_result()

            mock_subproc.assert_not_called()
            mock_popen.assert_not_called()
            mock_socket.assert_not_called()


class TestDashboardLiveCowrieIntegration(unittest.TestCase):
    """Test suite for FastAPI endpoints with Live Cowrie source."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Reset live cowrie service
        self.client.post("/api/reset?target=live_cowrie")
        self.client.post("/api/reset?target=simulator")
        self.client.post("/api/reset?target=scenario")

    def test_09_dashboard_selection_and_rendering_of_live_cowrie(self):
        """Dashboard source endpoints reflect Live Cowrie state."""
        # 1. Sources list includes live_cowrie
        res = self.client.get("/api/sources")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        sources = {s["id"]: s for s in data}
        self.assertIn("live_cowrie", sources)
        self.assertTrue(sources["live_cowrie"]["available"])

        # 2. Initial empty state for live_cowrie
        res2 = self.client.get("/api/current-state?source=live_cowrie")
        self.assertEqual(res2.status_code, 200)
        state_data = res2.json()
        self.assertFalse(state_data["loaded"])
        self.assertEqual(state_data["source"], "live_cowrie")
        self.assertIn("health", state_data)

        # 3. Ingest live telemetry
        token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")
        ingest_res = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": [SAMPLE_EVENT_1, SAMPLE_EVENT_2]},
        )
        self.assertEqual(ingest_res.status_code, 200)
        self.assertEqual(ingest_res.json()["events_ingested"], 2)

        # 4. Check updated live_cowrie current-state
        res3 = self.client.get("/api/current-state?source=live_cowrie")
        self.assertEqual(res3.status_code, 200)
        state_data3 = res3.json()
        self.assertTrue(state_data3["loaded"])
        self.assertEqual(state_data3["events_parsed"], 2)
        self.assertEqual(state_data3["sessions_count"], 1)

    def test_10_isolation_between_sources(self):
        """Live Cowrie telemetry, simulator state, and scenario data remain completely isolated."""
        token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")
        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": [SAMPLE_EVENT_1]},
        )

        # Load synthetic scenario
        sc_res = self.client.post(
            "/api/run-scenario",
            json={"scenario": "reconnaissance.jsonl", "accumulate_state": False},
        )
        self.assertEqual(sc_res.status_code, 200)

        # Verify synthetic scenario state
        sc_state = self.client.get("/api/current-state?source=scenario").json()
        self.assertTrue(sc_state["loaded"])
        self.assertIn("reconnaissance.jsonl", sc_state["input_file"])

        # Verify live cowrie state is unaffected
        live_state = self.client.get("/api/current-state?source=live_cowrie").json()
        self.assertTrue(live_state["loaded"])
        self.assertEqual(live_state["events_parsed"], 1)
        self.assertEqual(live_state["source"], "live_cowrie")

        # Resetting live cowrie does NOT clear synthetic scenario
        self.client.post("/api/reset?target=live_cowrie")
        sc_state_after = self.client.get("/api/current-state?source=scenario").json()
        self.assertTrue(sc_state_after["loaded"])

        live_state_after = self.client.get("/api/current-state?source=live_cowrie").json()
        self.assertFalse(live_state_after["loaded"])

    def test_11_invalid_schema_oversized_batch_and_auth_rejection(self):
        """Reject unauthenticated requests, oversized batches (> 1000), and invalid payloads."""
        token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")

        # 1. Missing Authorization header -> 401
        res1 = self.client.post("/api/telemetry/ingest", json={"events": [SAMPLE_EVENT_1]})
        self.assertEqual(res1.status_code, 401)

        # 2. Invalid Token -> 401
        res2 = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": "Bearer wrong-token"},
            json={"events": [SAMPLE_EVENT_1]},
        )
        self.assertEqual(res2.status_code, 401)

        # 3. Oversized batch (> 1000 events) -> 400
        oversized_events = [SAMPLE_EVENT_1] * 1001
        res3 = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": oversized_events},
        )
        self.assertEqual(res3.status_code, 400)
        self.assertIn("Batch exceeds maximum limit", res3.json()["detail"])

        # 4. Invalid schema (non-dict items) -> 422 Unprocessable Entity rejected by Pydantic
        res4 = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": ["not a dict", {"eventid": "cowrie.command.input"}]},
        )
        self.assertEqual(res4.status_code, 422)

        # 5. Invalid / incomplete event dict fields -> accepted with warnings
        res5 = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": [{"random_unrecognized_key": "val"}]},
        )
        self.assertEqual(res5.status_code, 200)
        data = res5.json()
        self.assertEqual(data["events_ingested"], 0)
        self.assertGreaterEqual(len(data["warnings"]), 1)

    def test_15_deception_action_counter_semantics_and_advisory_label(self):
        """
        Verify that deception action metrics strictly distinguish between
        executed simulated actions vs advisory recommendations:
        - For Live Cowrie: label is 'RECOMMENDATIONS GENERATED', actions_executed_count is 0,
          and is_advisory is True.
        - For Synthetic Scenarios & Simulator: label is 'DECEPTION ACTIONS EXECUTED',
          and is_advisory is False.
        """
        token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")

        # 1. Ingest live recon event into Live Cowrie
        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": [SAMPLE_EVENT_1, SAMPLE_EVENT_2, SAMPLE_EVENT_3, SAMPLE_EVENT_4]},
        )
        live_res = self.client.get("/api/current-state?source=live_cowrie")
        self.assertEqual(live_res.status_code, 200)
        live_data = live_res.json()
        self.assertIn("deception_metric", live_data)
        metric = live_data["deception_metric"]
        self.assertEqual(metric["label"], "RECOMMENDATIONS GENERATED")
        self.assertEqual(metric["actions_executed_count"], 0)
        self.assertTrue(metric["is_advisory"])
        self.assertIn("Read-Only", metric["status_note"])

        # 2. Compare with Synthetic Scenario run
        sc_res = self.client.post(
            "/api/run-scenario",
            json={"scenario": "reconnaissance.jsonl", "accumulate_state": False},
        )
        self.assertEqual(sc_res.status_code, 200)
        sc_data = self.client.get("/api/current-state?source=scenario").json()
        sc_metric = sc_data["deception_metric"]
        self.assertEqual(sc_metric["label"], "DECEPTION ACTIONS EXECUTED")
        self.assertFalse(sc_metric["is_advisory"])
        self.assertGreaterEqual(sc_metric["actions_executed_count"], 1)

    def test_16_live_status_states_distinction(self):
        """
        Verify that the backend accurately distinguishes:
        1. Live Cowrie connected and receiving events
        2. Live source selected but waiting for events
        3. Telemetry disconnected or unreachable
        4. Synthetic/simulator mode
        """
        # State 1: Reset live service -> waiting for events
        self.client.post("/api/reset?target=live_cowrie")
        waiting_state = self.client.get("/api/current-state?source=live_cowrie").json()
        health_waiting = waiting_state["health"]
        self.assertEqual(health_waiting["status"], "waiting_for_events")
        self.assertFalse(health_waiting["has_activity"])

        # State 2: Tailer unreachable
        unreachable_service = LiveCowrieService(tailer=CowrieLogTailer(log_path="/path/to/nonexistent/cowrie.json"))
        unreachable_health = unreachable_service.get_health()
        self.assertEqual(unreachable_health["status"], "tailer_path_unreachable")
        self.assertFalse(unreachable_health["connected"])

        # State 3: Live Cowrie connected and receiving events
        token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")
        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": [SAMPLE_EVENT_1]},
        )
        active_state = self.client.get("/api/current-state?source=live_cowrie").json()
        health_active = active_state["health"]
        self.assertEqual(health_active["status"], "healthy")
        self.assertTrue(health_active["connected"])
        self.assertTrue(health_active["has_activity"])
        self.assertEqual(active_state["events_parsed"], 1)

        # State 4: Synthetic and Simulator modes are identified as separate sources
        sc_state = self.client.get("/api/current-state?source=scenario").json()
        self.assertEqual(sc_state["source"], "scenario")

        sim_state = self.client.get("/api/current-state?source=simulator").json()
        self.assertEqual(sim_state["source"], "simulator")

    def test_17_collector_retains_offset_on_failed_transmission(self):
        """
        Regression test: Verify that run_collector does NOT advance its log offset
        if forward_batch fails (e.g. transient network drop or backend restart).
        Events remain queued at the exact offset and are transmitted on the next attempt.
        """
        temp_dir = tempfile.mkdtemp(prefix="collector_offset_test_")
        try:
            log_file = Path(temp_dir) / "cowrie.json"
            event_line = json.dumps(SAMPLE_EVENT_1) + "\n"
            log_file.write_text(event_line, encoding="utf-8")

            # 1. First poll with simulated transmission failure (mock forward_batch returning False)
            with patch("telemetry.collector.forward_batch", return_value=False) as mock_forward:
                offset_1, sent_1 = run_collector(
                    log_path=log_file,
                    server_url="http://mock-server:8000",
                    auth_token="test-tok",
                    once=True,
                    start_offset=0,
                )
                self.assertEqual(mock_forward.call_count, 1)
                # Offset MUST NOT have advanced past the failed event
                self.assertEqual(offset_1, 0)
                self.assertEqual(sent_1, 0)

            # 2. Second poll when network/server recovers (mock forward_batch returning True)
            with patch("telemetry.collector.forward_batch", return_value=True) as mock_forward:
                offset_2, sent_2 = run_collector(
                    log_path=log_file,
                    server_url="http://mock-server:8000",
                    auth_token="test-tok",
                    once=True,
                    start_offset=offset_1,
                )
                self.assertEqual(mock_forward.call_count, 1)
                # Offset NOW successfully advances to the end of the file
                self.assertGreater(offset_2, 0)
                self.assertEqual(offset_2, log_file.stat().st_size)
                self.assertEqual(sent_2, 1)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
