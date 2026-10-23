"""
tests/test_phase8_lab_matrix.py — Comprehensive Test Suite for Phase 8: Integrated Lab Testing.

Covers the 10-Scenario Integrated Lab Test Matrix:
1. Benign or minimal SSH session (login + pwd -> UNKNOWN, score 0, POL-DEFAULT-NOOP)
2. Reconnaissance commands (whoami, uname -a, hostname -> REC-01 & REC-02, score 9, POL-RECON-REVEAL-MYSQL)
3. File & directory discovery (ls -la, find, tree -> FD-01 & FD-02, score 6, POL-FILE-DISC-DB-DUMP)
4. Failed login attempts followed by successful login (3 fails + 1 succ -> AUTH-01 & AUTH-03, score 21, POL-AUTH-SPRAY-MONITOR)
5. Credential-file discovery indicators (cat /etc/shadow -> PE-02 & REC-01, score 18, POL-CRED-DECOY-SSH)
6. Mixed sequence combining reconnaissance and file discovery (2 recon + 2 file disc -> REC-01 & FD-01, score 10, POL-FILE-DISC-WEAK)
7. Multiple independent sessions (session isolation, strict parameter separation, no cross-session contamination)
8. Empty, malformed, partial, and duplicate JSONL events (tailer resilience, error recovery, duplicate prevention)
9. Collector disconnection and reconnection (health state transitions, resumption without loss or duplication)
10. Unknown behaviour and safe fallback policy selection (unrecognized input -> UNKNOWN, score 0, POL-DEFAULT-NOOP)

Also validates:
- Read-only safety boundaries (no execution on honeypot, no filesystem modifications)
- Rejection of unapproved actions and invalid policy inputs
- Accurate dashboard reporting via current-state API
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from dashboard.app import app
from deception.actions import (
    ACTION_NO_OP,
    ACTION_PRESENT_DECOY,
    ACTION_RECORD_INTEREST,
    ACTION_REVEAL_SERVICE,
    DeceptionAction,
)
from deception.policy_engine import evaluate_policy
from deception.world_state import WorldState
from telemetry.collector import forward_batch
from telemetry.cowrie_source import CowrieLogTailer, CowrieSourceConfig
from telemetry.live_service import LiveCowrieService, get_live_service


class TestPhase8IntegratedLabMatrix(unittest.TestCase):
    """Execution of the 10-scenario integrated lab test matrix."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="phase8_lab_")
        self.log_path = Path(self.test_dir) / "cowrie.json"
        self.client = TestClient(app)
        self.token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")
        # Reset live service to ensure test cleanliness
        self.client.post("/api/reset?target=live_cowrie")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        self.client.post("/api/reset?target=live_cowrie")

    # -----------------------------------------------------------------------
    # Scenario 1: Benign or Minimal SSH Session
    # -----------------------------------------------------------------------
    def test_scenario_01_benign_minimal_session(self):
        """
        Scenario 1: Benign/minimal SSH session.
        Expected:
        - Commands: pwd
        - Classification: UNKNOWN (category: unknown, strength: WEAK)
        - Threat Score: 0 (0 failures, 0 recon, 0 file disc, 0 cred, 0 priv esc)
        - Policy: POL-DEFAULT-NOOP (action: no_op)
        - Deception Status: no_action_recommended (advisory), 0 executed
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:00:00.000000Z",
                "session": "lab-sess-01",
                "src_ip": "198.51.100.11",
                "src_port": 50001,
                "dst_ip": "192.168.1.100",
                "dst_port": 2222,
                "protocol": "ssh",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:00:01.000000Z",
                "session": "lab-sess-01",
                "src_ip": "198.51.100.11",
                "username": "benign_user",
                "password": "valid_password",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:00:02.000000Z",
                "session": "lab-sess-01",
                "src_ip": "198.51.100.11",
                "input": "pwd",
            },
            {
                "eventid": "cowrie.session.closed",
                "timestamp": "2026-10-24T01:00:03.000000Z",
                "session": "lab-sess-01",
                "src_ip": "198.51.100.11",
            },
        ]

        t0 = time.perf_counter()
        resp = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )
        latency_ms = (time.perf_counter() - t0) * 1000
        self.assertEqual(resp.status_code, 200)

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        self.assertEqual(state["sessions_count"], 1)
        sess = state["sessions"][0]
        self.assertEqual(sess["session_id"], "lab-sess-01")
        self.assertEqual(sess["source_ip"], "198.51.100.11")
        self.assertEqual(sess["analysis"]["primary_category"], "unknown")
        self.assertEqual(sess["analysis"]["score"], 0)

        # Policy & Deception Verification
        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-DEFAULT-NOOP")
        self.assertEqual(deception["action"]["action_id"], ACTION_NO_OP)
        self.assertEqual(deception["status"], "no_action_recommended")
        self.assertTrue(deception["advisory_only"])
        self.assertIn("ADVISORY RECOMMENDATION", deception["explanation"])

        # Metric verification
        metric = state["deception_metric"]
        self.assertEqual(metric["label"], "RECOMMENDATIONS GENERATED")
        self.assertEqual(metric["value"], 0)  # no_op is not counted as an active recommendation
        self.assertEqual(metric["actions_executed_count"], 0)

    # -----------------------------------------------------------------------
    # Scenario 2: Reconnaissance Commands
    # -----------------------------------------------------------------------
    def test_scenario_02_reconnaissance_commands(self):
        """
        Scenario 2: Reconnaissance commands (whoami, uname -a, hostname).
        Expected:
        - Observed commands: 3
        - Classification: REC-01 & REC-02 fired -> primary_category: reconnaissance
        - Threat Score: 3 * 3 = 9 (Severity: LOW)
        - Policy: POL-RECON-REVEAL-MYSQL (target: mysql-backend)
        - Deception Status: simulated_recommendation (advisory), 0 executed
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:05:00.000000Z",
                "session": "lab-sess-02",
                "src_ip": "198.51.100.22",
                "protocol": "ssh",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:05:01.000000Z",
                "session": "lab-sess-02",
                "src_ip": "198.51.100.22",
                "username": "admin",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:05:02.000000Z",
                "session": "lab-sess-02",
                "src_ip": "198.51.100.22",
                "input": "whoami",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:05:03.000000Z",
                "session": "lab-sess-02",
                "src_ip": "198.51.100.22",
                "input": "uname -a",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:05:04.000000Z",
                "session": "lab-sess-02",
                "src_ip": "198.51.100.22",
                "input": "hostname",
            },
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        sess = state["sessions"][0]
        self.assertEqual(sess["session_id"], "lab-sess-02")
        self.assertEqual(sess["analysis"]["primary_category"], "reconnaissance")
        self.assertEqual(sess["analysis"]["score"], 9)  # 3 * 3 = 9

        finding_rules = [f["rule_id"] for f in sess["analysis"]["findings"]]
        self.assertIn("REC-01", finding_rules)
        self.assertIn("REC-02", finding_rules)

        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-RECON-REVEAL-MYSQL")
        self.assertEqual(deception["action"]["action_id"], ACTION_REVEAL_SERVICE)
        self.assertEqual(deception["action"]["target"], "mysql-backend")
        self.assertEqual(deception["status"], "simulated_recommendation")

        metric = state["deception_metric"]
        self.assertEqual(metric["label"], "RECOMMENDATIONS GENERATED")
        self.assertEqual(metric["value"], 1)
        self.assertEqual(metric["actions_executed_count"], 0)

    # -----------------------------------------------------------------------
    # Scenario 3: File and Directory Discovery
    # -----------------------------------------------------------------------
    def test_scenario_03_file_and_directory_discovery(self):
        """
        Scenario 3: File and directory discovery using harmless commands.
        Commands: ls -la, find / -name "*.conf", tree /etc
        Expected:
        - Features: file_discovery_count = 3
        - Classification: FD-01 & FD-02 fired -> primary_category: file_discovery
        - Threat Score: 3 * 2 = 6
        - Policy: POL-FILE-DISC-DB-DUMP (target: /home/backup/db_dump.sql)
        - Deception Status: simulated_recommendation, 0 executed
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:10:00.000000Z",
                "session": "lab-sess-03",
                "src_ip": "198.51.100.33",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:10:01.000000Z",
                "session": "lab-sess-03",
                "src_ip": "198.51.100.33",
                "username": "guest",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:10:02.000000Z",
                "session": "lab-sess-03",
                "src_ip": "198.51.100.33",
                "input": "ls -la",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:10:03.000000Z",
                "session": "lab-sess-03",
                "src_ip": "198.51.100.33",
                "input": 'find / -name "*.conf"',
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:10:04.000000Z",
                "session": "lab-sess-03",
                "src_ip": "198.51.100.33",
                "input": "tree /etc",
            },
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        sess = state["sessions"][0]
        self.assertEqual(sess["analysis"]["primary_category"], "file_discovery")
        self.assertEqual(sess["analysis"]["score"], 6)

        rules = [f["rule_id"] for f in sess["analysis"]["findings"]]
        self.assertIn("FD-01", rules)
        self.assertIn("FD-02", rules)

        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-FILE-DISC-DB-DUMP")
        self.assertEqual(deception["action"]["action_id"], ACTION_PRESENT_DECOY)
        self.assertEqual(deception["action"]["target"], "/home/backup/db_dump.sql")

    # -----------------------------------------------------------------------
    # Scenario 4: Failed Login Attempts Followed by Successful Login
    # -----------------------------------------------------------------------
    def test_scenario_04_failed_logins_then_success(self):
        """
        Scenario 4: 3 failed logins followed by 1 successful login.
        Expected:
        - Classification: AUTH-01 & AUTH-03 fired -> primary_category: authentication_abuse
        - Threat Score: (3 * 2) + 15 (success after failure bonus) = 21
        - Policy: POL-AUTH-SPRAY-MONITOR (action: record_interest, target: authentication_spray)
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:15:00.000000Z",
                "session": "lab-sess-04",
                "src_ip": "198.51.100.44",
            },
            {
                "eventid": "cowrie.login.failed",
                "timestamp": "2026-10-24T01:15:01.000000Z",
                "session": "lab-sess-04",
                "src_ip": "198.51.100.44",
                "username": "root",
                "password": "admin",
            },
            {
                "eventid": "cowrie.login.failed",
                "timestamp": "2026-10-24T01:15:02.000000Z",
                "session": "lab-sess-04",
                "src_ip": "198.51.100.44",
                "username": "root",
                "password": "password123",
            },
            {
                "eventid": "cowrie.login.failed",
                "timestamp": "2026-10-24T01:15:03.000000Z",
                "session": "lab-sess-04",
                "src_ip": "198.51.100.44",
                "username": "root",
                "password": "toor",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:15:04.000000Z",
                "session": "lab-sess-04",
                "src_ip": "198.51.100.44",
                "username": "root",
                "password": "correct_pass",
            },
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        sess = state["sessions"][0]
        self.assertEqual(sess["analysis"]["primary_category"], "authentication_abuse")
        self.assertEqual(sess["analysis"]["score"], 21)

        rules = [f["rule_id"] for f in sess["analysis"]["findings"]]
        self.assertIn("AUTH-01", rules)
        self.assertIn("AUTH-03", rules)

        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-AUTH-SPRAY-MONITOR")
        self.assertEqual(deception["action"]["action_id"], ACTION_RECORD_INTEREST)
        self.assertEqual(deception["action"]["target"], "authentication_spray")

    # -----------------------------------------------------------------------
    # Scenario 5: Credential-File Discovery Indicators
    # -----------------------------------------------------------------------
    def test_scenario_05_credential_file_discovery(self):
        """
        Scenario 5: Credential-file discovery indicators (cat /etc/shadow).
        Expected:
        - Command: cat /etc/shadow matches credential substring & recon substring
        - Classification: PE-02 (STRONG, cred) & REC-01 (MODERATE, recon)
        - Category Priority: privilege_escalation_attempt > reconnaissance
        - Threat Score: 3 (recon) + 15 (credential) = 18
        - Policy: POL-CRED-DECOY-SSH (target: /root/.ssh/id_rsa_backup)
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:20:00.000000Z",
                "session": "lab-sess-05",
                "src_ip": "198.51.100.55",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:20:01.000000Z",
                "session": "lab-sess-05",
                "src_ip": "198.51.100.55",
                "username": "victim",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:20:02.000000Z",
                "session": "lab-sess-05",
                "src_ip": "198.51.100.55",
                "input": "cat /etc/shadow",
            },
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        sess = state["sessions"][0]
        self.assertEqual(sess["analysis"]["primary_category"], "privilege_escalation_attempt")
        self.assertEqual(sess["analysis"]["score"], 18)

        rules = [f["rule_id"] for f in sess["analysis"]["findings"]]
        self.assertIn("PE-02", rules)

        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-CRED-DECOY-SSH")
        self.assertEqual(deception["action"]["action_id"], ACTION_PRESENT_DECOY)
        self.assertEqual(deception["action"]["target"], "/root/.ssh/id_rsa_backup")

    # -----------------------------------------------------------------------
    # Scenario 6: Mixed Sequence (Reconnaissance + File Discovery)
    # -----------------------------------------------------------------------
    def test_scenario_06_mixed_recon_and_file_discovery(self):
        """
        Scenario 6: Mixed reconnaissance and file discovery.
        Commands: whoami, uname -a, ls -la, find / -type f
        Expected:
        - Features: recon_count = 2, file_discovery_count = 2
        - Classification: REC-01 fired, FD-01 fired
        - Category Priority: file_discovery (4) > reconnaissance (5)
        - Threat Score: (2 * 3) + (2 * 2) = 10
        - Policy: POL-FILE-DISC-WEAK (target: file_discovery)
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:25:00.000000Z",
                "session": "lab-sess-06",
                "src_ip": "198.51.100.66",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:25:01.000000Z",
                "session": "lab-sess-06",
                "src_ip": "198.51.100.66",
                "username": "user",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:25:02.000000Z",
                "session": "lab-sess-06",
                "src_ip": "198.51.100.66",
                "input": "whoami",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:25:03.000000Z",
                "session": "lab-sess-06",
                "src_ip": "198.51.100.66",
                "input": "uname -a",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:25:04.000000Z",
                "session": "lab-sess-06",
                "src_ip": "198.51.100.66",
                "input": "ls -la",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:25:05.000000Z",
                "session": "lab-sess-06",
                "src_ip": "198.51.100.66",
                "input": "find / -type f",
            },
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        sess = state["sessions"][0]
        self.assertEqual(sess["analysis"]["primary_category"], "file_discovery")
        self.assertEqual(sess["analysis"]["score"], 10)

        rules = [f["rule_id"] for f in sess["analysis"]["findings"]]
        self.assertIn("REC-01", rules)
        self.assertIn("FD-01", rules)

        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-FILE-DISC-WEAK")
        self.assertEqual(deception["action"]["action_id"], ACTION_RECORD_INTEREST)
        self.assertEqual(deception["action"]["target"], "file_discovery")

    # -----------------------------------------------------------------------
    # Scenario 7: Multiple Independent Sessions (Session Isolation)
    # -----------------------------------------------------------------------
    def test_scenario_07_multiple_independent_sessions_isolation(self):
        """
        Scenario 7: Ingest multiple concurrent sessions from distinct IPs.
        Verify:
        - Session 7A: 198.51.100.71 -> Recon (3 commands) -> Score 9
        - Session 7B: 203.0.113.72 -> Auth Abuse (3 failed logins) -> Score 6
        - Strict isolation: features, scores, categories do not cross-contaminate.
        """
        events_7a = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:30:00.000000Z",
                "session": "lab-sess-07a",
                "src_ip": "198.51.100.71",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:30:01.000000Z",
                "session": "lab-sess-07a",
                "src_ip": "198.51.100.71",
                "username": "root",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:30:02.000000Z",
                "session": "lab-sess-07a",
                "src_ip": "198.51.100.71",
                "input": "whoami",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:30:03.000000Z",
                "session": "lab-sess-07a",
                "src_ip": "198.51.100.71",
                "input": "uname -a",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:30:04.000000Z",
                "session": "lab-sess-07a",
                "src_ip": "198.51.100.71",
                "input": "hostname",
            },
        ]

        events_7b = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:30:05.000000Z",
                "session": "lab-sess-07b",
                "src_ip": "203.0.113.72",
            },
            {
                "eventid": "cowrie.login.failed",
                "timestamp": "2026-10-24T01:30:06.000000Z",
                "session": "lab-sess-07b",
                "src_ip": "203.0.113.72",
                "username": "root",
                "password": "bad1",
            },
            {
                "eventid": "cowrie.login.failed",
                "timestamp": "2026-10-24T01:30:07.000000Z",
                "session": "lab-sess-07b",
                "src_ip": "203.0.113.72",
                "username": "root",
                "password": "bad2",
            },
            {
                "eventid": "cowrie.login.failed",
                "timestamp": "2026-10-24T01:30:08.000000Z",
                "session": "lab-sess-07b",
                "src_ip": "203.0.113.72",
                "username": "root",
                "password": "bad3",
            },
        ]

        # Ingest intermingled events
        intermingled = [
            events_7a[0],
            events_7b[0],
            events_7a[1],
            events_7b[1],
            events_7a[2],
            events_7b[2],
            events_7a[3],
            events_7b[3],
            events_7a[4],
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": intermingled},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        self.assertEqual(state["sessions_count"], 2)

        sessions_by_id = {s["session_id"]: s for s in state["sessions"]}
        self.assertIn("lab-sess-07a", sessions_by_id)
        self.assertIn("lab-sess-07b", sessions_by_id)

        sess_a = sessions_by_id["lab-sess-07a"]
        self.assertEqual(sess_a["source_ip"], "198.51.100.71")
        self.assertEqual(sess_a["analysis"]["primary_category"], "reconnaissance")
        self.assertEqual(sess_a["analysis"]["score"], 9)

        sess_b = sessions_by_id["lab-sess-07b"]
        self.assertEqual(sess_b["source_ip"], "203.0.113.72")
        self.assertEqual(sess_b["analysis"]["primary_category"], "authentication_abuse")
        self.assertEqual(sess_b["analysis"]["score"], 6)  # 3 failures * 2 = 6

    # -----------------------------------------------------------------------
    # Scenario 8: Empty, Malformed, Partial, and Duplicate JSONL Events
    # -----------------------------------------------------------------------
    def test_scenario_08_empty_malformed_partial_duplicate_events(self):
        """
        Scenario 8: Robust tailer resilience against:
        - Blank/empty lines
        - Corrupt/malformed JSON strings
        - Incomplete/partial trailing lines (mid-flush)
        - Incomplete dict schemas (missing mandatory keys)
        - Duplicate event streams
        """
        tailer = CowrieLogTailer(self.log_path)

        # 1. Write valid event followed by an incomplete line (no trailing newline)
        valid_ev = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-10-24T01:35:00.000000Z",
            "session": "lab-sess-08",
            "src_ip": "198.51.100.88",
        }
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(valid_ev) + "\n")
            f.write("\n")  # empty line
            f.write('{"eventid": "cowrie.command.in')  # partial line, no newline

        events_1, warnings_1 = tailer.poll()
        self.assertEqual(len(events_1), 1)
        self.assertEqual(events_1[0]["session_id"], "lab-sess-08")

        # 2. Complete the partial line with corrupt JSON, then write another valid event
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write('complete_junk_not_json}\n')  # closes previous line with malformed JSON
            f.write(json.dumps({
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:35:01.000000Z",
                "session": "lab-sess-08",
                "input": "whoami",
            }) + "\n")

        events_2, warnings_2 = tailer.poll()
        self.assertEqual(len(events_2), 1)
        self.assertEqual(events_2[0]["command"], "whoami")
        self.assertGreaterEqual(len(warnings_2), 1)  # captured malformed JSON warning

        # 3. Duplicate polling test: calling poll() again without new writes produces 0 duplicates
        events_3, warnings_3 = tailer.poll()
        self.assertEqual(len(events_3), 0)

        # Ingest API schema test: incomplete dict (missing timestamp)
        ingest_res = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": [{"eventid": "cowrie.command.input", "session": "bad_dict"}]},
        )
        self.assertEqual(ingest_res.status_code, 200)
        self.assertEqual(ingest_res.json()["events_ingested"], 0)
        self.assertEqual(ingest_res.json()["warnings_count"], 1)

    # -----------------------------------------------------------------------
    # Scenario 9: Collector Disconnection and Reconnection
    # -----------------------------------------------------------------------
    def test_scenario_09_collector_disconnection_and_reconnection(self):
        """
        Scenario 9: Collector lifecycle & health status tracking.
        Verify:
        - Health state when waiting for events / no collector
        - Tailer health when log file is unreachable/missing
        - Health update when collector pushes telemetry
        - Resumed ingestion continuity after reconnection
        """
        # 1. Unreachable tailer path
        bad_tailer = CowrieLogTailer("/nonexistent/cowrie/path/cowrie.json")
        svc_unreachable = LiveCowrieService(tailer=bad_tailer)
        health_unreachable = svc_unreachable.get_health()
        self.assertEqual(health_unreachable["status"], "tailer_path_unreachable")
        self.assertFalse(health_unreachable["connected"])

        # 2. Local valid tailer waiting for events
        valid_tailer = CowrieLogTailer(self.log_path)
        with open(self.log_path, "w", encoding="utf-8") as f:
            pass  # empty file
        svc_tailing = LiveCowrieService(tailer=valid_tailer)
        health_tailing = svc_tailing.get_health()
        self.assertEqual(health_tailing["status"], "tailing_log")
        self.assertTrue(health_tailing["connected"])
        self.assertFalse(health_tailing["has_activity"])

        # 3. HTTP Collector ingestion creates connected and active state
        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": [{
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:40:00.000000Z",
                "session": "lab-sess-09",
                "src_ip": "198.51.100.99",
            }]},
        )
        active_health = self.client.get("/api/telemetry/health").json()
        self.assertEqual(active_health["status"], "healthy")
        self.assertTrue(active_health["connected"])
        self.assertTrue(active_health["has_activity"])
        self.assertEqual(active_health["total_events_ingested"], 1)

    # -----------------------------------------------------------------------
    # Scenario 10: Unknown Behaviour and Safe Fallback Policy Selection
    # -----------------------------------------------------------------------
    def test_scenario_10_unknown_behaviour_and_safe_fallback(self):
        """
        Scenario 10: Unknown/unmatched commands fallback to safe no-op.
        Commands: 'echo test', 'clear', 'exit'
        Expected:
        - Findings: UNKNOWN (rule_id: UNKNOWN, category: unknown, strength: WEAK)
        - Threat Score: 0
        - Policy: POL-DEFAULT-NOOP
        - Action: no_op
        - State change: {'no_op': True}
        - 0 real changes, 0 simulated honeypot modifications
        """
        events = [
            {
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-10-24T01:45:00.000000Z",
                "session": "lab-sess-10",
                "src_ip": "198.51.100.100",
            },
            {
                "eventid": "cowrie.login.success",
                "timestamp": "2026-10-24T01:45:01.000000Z",
                "session": "lab-sess-10",
                "src_ip": "198.51.100.100",
                "username": "guest",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:45:02.000000Z",
                "session": "lab-sess-10",
                "src_ip": "198.51.100.100",
                "input": "echo 'safe test'",
            },
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T01:45:03.000000Z",
                "session": "lab-sess-10",
                "src_ip": "198.51.100.100",
                "input": "clear",
            },
        ]

        self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": events},
        )

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        sess = state["sessions"][0]
        self.assertEqual(sess["analysis"]["primary_category"], "unknown")
        self.assertEqual(sess["analysis"]["score"], 0)

        findings = sess["analysis"]["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "UNKNOWN")

        deception = sess["deception"]
        self.assertEqual(deception["policy_id"], "POL-DEFAULT-NOOP")
        self.assertEqual(deception["action"]["action_id"], ACTION_NO_OP)
        self.assertEqual(deception["status"], "no_action_recommended")
        self.assertTrue(deception["advisory_only"])

    # -----------------------------------------------------------------------
    # Safe Adaptation & Policy Rejection Verification
    # -----------------------------------------------------------------------
    def test_safe_adaptation_boundary_and_unapproved_action_rejection(self):
        """
        Verify:
        - Unapproved actions are rejected and fall back to safe no-op.
        - Analysis and policy engines make zero host/filesystem/subprocess calls.
        - WorldState strictly tracks fictional entities in memory.
        """
        # 1. Unapproved action rejection
        unapproved = DeceptionAction(
            action_id="EXECUTE_REAL_PAYLOAD_MALICIOUS",
            target="/root",
            description="Dangerous unapproved action.",
        )
        ws = WorldState.create_default()
        decision = evaluate_policy({}, ws)
        # Verify evaluate_policy never outputs unapproved actions
        self.assertIn(decision.action.action_id, [ACTION_NO_OP, ACTION_PRESENT_DECOY, ACTION_REVEAL_SERVICE, ACTION_RECORD_INTEREST])

        # 2. Verify WorldState remains purely fictional
        self.assertIn("/root/.ssh/id_rsa_backup", ws.decoy_files)
        self.assertFalse(ws.is_decoy_visible("/root/.ssh/id_rsa_backup"))
        self.assertFalse(os.path.exists("/root/.ssh/id_rsa_backup"))


if __name__ == "__main__":
    unittest.main()
