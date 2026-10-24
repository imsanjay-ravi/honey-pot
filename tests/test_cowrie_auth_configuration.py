"""
tests/test_cowrie_auth_configuration.py — Verification of Cowrie Authentication Policy & Telemetry.

Validates:
1. Exact Cowrie UserDB authentication logic:
   - Root cause verification: Why default templates with 'root:x:*' accepted every password.
   - Hardened policy verification: Why honeypot/etc/userdb.txt correctly rejects incorrect passwords
     and only accepts approved test credentials.
   - Rejection of unknown usernames and explicit negation rules (!password).
2. Telemetry ingestion, normalization, and feature extraction for login events:
   - Preservation of timestamp, session_id, src_ip, username, and success flags.
3. Behavior analysis, scoring, and policy response to authentication abuse:
   - AUTH-01 (>= 3 failures), AUTH-02 (>= 5 failures), AUTH-03 (success after failure).
   - Heuristic score computation and progression.
   - Policy selection: POL-AUTH-SPRAY-MONITOR.
   - Continuity of post-login commands following an approved login.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from analysis.classifier import classify, primary_category
from analysis.engine import analyse_session
from analysis.features import extract_features
from analysis.scorer import compute_score
from dashboard.app import app
from deception.actions import ACTION_NO_OP, ACTION_RECORD_INTEREST
from deception.policy_engine import evaluate_policy
from deception.world_state import WorldState
from parser.cowrie_parser import normalize_event
from telemetry.live_service import LiveCowrieService


class CowrieUserDBSimulator:
    """
    Direct Python simulation of Cowrie's core/auth.py UserDB implementation.
    Used to mathematically verify Cowrie's rule parsing and evaluation.
    """

    def __init__(self, userdb_content: str) -> None:
        self.rules: list[tuple[bytes, bytes, bool]] = []
        self._load(userdb_content)

    def _load(self, content: str) -> None:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            login = parts[0].strip().encode("utf-8")
            raw_passwd = parts[2].strip().encode("utf-8")

            policy = True
            if raw_passwd.startswith(b"!"):
                raw_passwd = raw_passwd[1:]
                policy = False

            self.rules.append((login, raw_passwd, policy))

    def checklogin(self, login: str, password: str) -> bool:
        login_b = login.encode("utf-8")
        passwd_b = password.encode("utf-8")

        for rule_login, rule_passwd, policy in self.rules:
            # Login matching: b"*" matches any user; otherwise exact match
            login_matched = (rule_login == b"*") or (rule_login == login_b)
            if not login_matched:
                continue

            # Password matching: b"*" matches any password; otherwise exact match
            passwd_matched = (rule_passwd == b"*") or (rule_passwd == passwd_b)
            if passwd_matched:
                return policy

        # If no rule matches, authentication is rejected
        return False


class TestCowrieAuthenticationBehavior(unittest.TestCase):
    """Test suite demonstrating the Cowrie authentication issue and the verified fix."""

    def test_01_root_cause_default_cowrie_accepts_all_passwords(self):
        """
        Demonstrate root cause:
        Default Cowrie userdb.example contains:
          root:x:!root
          root:x:!123456
          root:x:*
        Because of the 'root:x:*' wildcard, ANY password for root other than the
        two negated rules is accepted as valid.
        """
        default_userdb_example = """
root:0:!root
root:0:!123456
root:0:*
admin:0:admin
"""
        sim = CowrieUserDBSimulator(default_userdb_example)

        # Specifically negated passwords are rejected
        self.assertFalse(sim.checklogin("root", "root"))
        self.assertFalse(sim.checklogin("root", "123456"))

        # BUT EVERY OTHER PASSWORD IS UNINTENTIONALLY ACCEPTED DUE TO root:0:*
        self.assertTrue(sim.checklogin("root", "randompassword123"))
        self.assertTrue(sim.checklogin("root", "toor"))
        self.assertTrue(sim.checklogin("root", "admin"))
        self.assertTrue(sim.checklogin("root", "CyberDeception2026!"))

    def test_02_hardened_userdb_rejects_wrong_and_accepts_approved(self):
        """
        Demonstrate the fix:
        In honeypot/etc/userdb.txt, the 'root:0:*' wildcard is removed.
        Only explicit credentials (root:0:CyberDeception2026!) are approved.
        All other passwords for root are rejected with False.
        """
        userdb_path = Path(__file__).resolve().parent.parent / "honeypot" / "etc" / "userdb.txt"
        self.assertTrue(userdb_path.is_file(), f"userdb.txt must exist at {userdb_path}")

        hardened_content = userdb_path.read_text(encoding="utf-8")
        sim = CowrieUserDBSimulator(hardened_content)

        # 1. Deliberately incorrect passwords produce False (cowrie.login.failed)
        self.assertFalse(sim.checklogin("root", "wrongpassword"))
        self.assertFalse(sim.checklogin("root", "toor"))
        self.assertFalse(sim.checklogin("root", "123456"))
        self.assertFalse(sim.checklogin("root", "admin"))
        self.assertFalse(sim.checklogin("root", "password"))
        self.assertFalse(sim.checklogin("admin", "wrongadminpass"))

        # 2. Unknown usernames produce False
        self.assertFalse(sim.checklogin("oracle", "oracle"))
        self.assertFalse(sim.checklogin("hacker", "hacker"))

        # 3. Approved test credentials produce True (cowrie.login.success)
        self.assertTrue(sim.checklogin("root", "CyberDeception2026!"))
        self.assertTrue(sim.checklogin("admin", "AdminPass2026!"))
        self.assertTrue(sim.checklogin("ubuntu", "ubuntu"))
        self.assertTrue(sim.checklogin("testuser", "TestPass123!"))


class TestCowrieAuthTelemetryAndDetectionPipeline(unittest.TestCase):
    """
    Verifies that failed and successful Cowrie login events flow seamlessly
    through ingestion, feature extraction, behaviour classification, threat scoring,
    and the deception policy engine.
    """

    def setUp(self):
        self.client = TestClient(app)
        self.token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")
        self.client.post("/api/reset?target=live_cowrie")

    def tearDown(self):
        self.client.post("/api/reset?target=live_cowrie")

    def test_03_login_events_metadata_and_normalization_preservation(self):
        """
        Verify that failed and successful login events retain timestamp, source IP,
        session ID, username, and event type upon normalization.
        """
        raw_failed = {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-10-24T05:00:00.123456Z",
            "session": "sess-auth-meta",
            "src_ip": "10.10.10.5",
            "src_port": 41234,
            "dst_ip": "10.10.10.2",
            "dst_port": 2222,
            "username": "root",
            "password": "wrongpassword",
        }
        raw_success = {
            "eventid": "cowrie.login.success",
            "timestamp": "2026-10-24T05:00:02.654321Z",
            "session": "sess-auth-meta",
            "src_ip": "10.10.10.5",
            "src_port": 41234,
            "dst_ip": "10.10.10.2",
            "dst_port": 2222,
            "username": "root",
            "password": "CyberDeception2026!",
        }

        norm_f = normalize_event(raw_failed)
        self.assertEqual(norm_f["event_type"], "login")
        self.assertFalse(norm_f["success"])
        self.assertEqual(norm_f["username"], "root")
        self.assertEqual(norm_f["source_ip"], "10.10.10.5")
        self.assertEqual(norm_f["session_id"], "sess-auth-meta")
        self.assertEqual(norm_f["timestamp"], "2026-10-24T05:00:00.123456+00:00")

        norm_s = normalize_event(raw_success)
        self.assertEqual(norm_s["event_type"], "login")
        self.assertTrue(norm_s["success"])
        self.assertEqual(norm_s["username"], "root")
        self.assertEqual(norm_s["source_ip"], "10.10.10.5")
        self.assertEqual(norm_s["session_id"], "sess-auth-meta")

    def test_04_failed_attempts_trigger_auth_abuse_classification(self):
        """
        Verify that 3 failed login attempts trigger AUTH-01 (MODERATE),
        5 failed attempts trigger AUTH-02 (STRONG), and subsequent success
        triggers AUTH-03 (STRONG, brute force victory).
        """
        # Session A: 3 failed attempts
        session_a_events = [
            {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T05:10:00Z", "session": "s-a", "src_ip": "10.10.10.5"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:10:01Z", "session": "s-a", "src_ip": "10.10.10.5", "username": "root", "password": "p1"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:10:02Z", "session": "s-a", "src_ip": "10.10.10.5", "username": "root", "password": "p2"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:10:03Z", "session": "s-a", "src_ip": "10.10.10.5", "username": "root", "password": "p3"},
        ]
        norm_a = [normalize_event(e) for e in session_a_events]
        analysis_a = analyse_session(norm_a, session_id="s-a")
        rules_a = [f["rule_id"] for f in analysis_a["findings"]]
        self.assertIn("AUTH-01", rules_a)
        self.assertNotIn("AUTH-02", rules_a)
        self.assertEqual(analysis_a["primary_category"], "authentication_abuse")
        self.assertEqual(analysis_a["score"], 6)  # 3 * 2 pts

        # Session B: 5 failed attempts + 1 successful attempt
        session_b_events = [
            {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T05:20:00Z", "session": "s-b", "src_ip": "10.10.10.5"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:20:01Z", "session": "s-b", "src_ip": "10.10.10.5", "username": "root", "password": "p1"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:20:02Z", "session": "s-b", "src_ip": "10.10.10.5", "username": "root", "password": "p2"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:20:03Z", "session": "s-b", "src_ip": "10.10.10.5", "username": "root", "password": "p3"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:20:04Z", "session": "s-b", "src_ip": "10.10.10.5", "username": "root", "password": "p4"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:20:05Z", "session": "s-b", "src_ip": "10.10.10.5", "username": "root", "password": "p5"},
            {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T05:20:06Z", "session": "s-b", "src_ip": "10.10.10.5", "username": "root", "password": "CyberDeception2026!"},
        ]
        norm_b = [normalize_event(e) for e in session_b_events]
        analysis_b = analyse_session(norm_b, session_id="s-b")
        rules_b = [f["rule_id"] for f in analysis_b["findings"]]
        self.assertNotIn("AUTH-01", rules_b)  # AUTH-01 is for 3-4 failures
        self.assertIn("AUTH-02", rules_b)      # AUTH-02 is for >= 5 failures
        self.assertIn("AUTH-03", rules_b)      # AUTH-03 is for success after failures
        self.assertEqual(analysis_b["primary_category"], "authentication_abuse")
        # Score calculation: 5 failures * 2 = 10 pts + 15 bonus for success after failure = 25 pts
        self.assertEqual(analysis_b["score"], 25)

        # Deception policy response
        ws = WorldState.create_default()
        decision = evaluate_policy(analysis_b, ws)
        self.assertEqual(decision.policy_id, "POL-AUTH-SPRAY-MONITOR")
        self.assertEqual(decision.action.action_id, ACTION_RECORD_INTEREST)
        self.assertEqual(decision.action.target, "authentication_spray")

    def test_05_post_login_commands_flow_after_successful_auth(self):
        """
        Verify that post-login commands executed after a successful login
        flow continuously within the same session and are classified appropriately.
        """
        full_session = [
            {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T05:30:00Z", "session": "s-c", "src_ip": "10.10.10.5"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T05:30:01Z", "session": "s-c", "src_ip": "10.10.10.5", "username": "root", "password": "bad"},
            {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T05:30:02Z", "session": "s-c", "src_ip": "10.10.10.5", "username": "root", "password": "CyberDeception2026!"},
            # Post-login interactive reconnaissance commands:
            {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T05:30:03Z", "session": "s-c", "src_ip": "10.10.10.5", "input": "whoami"},
            {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T05:30:04Z", "session": "s-c", "src_ip": "10.10.10.5", "input": "uname -a"},
            {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T05:30:05Z", "session": "s-c", "src_ip": "10.10.10.5", "input": "hostname"},
        ]

        resp = self.client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"events": full_session},
        )
        self.assertEqual(resp.status_code, 200)

        state = self.client.get("/api/current-state?source=live_cowrie").json()
        self.assertEqual(state["sessions_count"], 1)
        sess = state["sessions"][0]
        self.assertEqual(sess["session_id"], "s-c")
        self.assertEqual(sess["source_ip"], "10.10.10.5")

        # Category: Recon commands (3) + 1 failure + 1 success
        # Findings include AUTH-03 (success after failure) and REC-01, REC-02
        finding_rules = [f["rule_id"] for f in sess["analysis"]["findings"]]
        self.assertIn("AUTH-03", finding_rules)
        self.assertIn("REC-01", finding_rules)
        self.assertIn("REC-02", finding_rules)

        # Primary category: authentication_abuse > reconnaissance
        self.assertEqual(sess["analysis"]["primary_category"], "authentication_abuse")
        # Score: 1 failure * 2 = 2 + 15 (bonus) + 3 recon * 3 = 9 -> 26
        self.assertEqual(sess["analysis"]["score"], 26)


if __name__ == "__main__":
    unittest.main()
