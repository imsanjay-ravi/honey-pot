"""
tests/test_dashboard.py — Tests for the Phase 5 Ubuntu Analysis Dashboard API & Backend.

Covers:
- API health check (/api/health).
- Scenario listing (/api/scenarios).
- Pipeline scenario execution (/api/run-scenario).
- Security & Path traversal validation (rejecting '../', absolute paths, unknown fixtures).
- Current state retrieval and initial empty state (/api/current-state).
- State reset functionality (/api/reset).
- Data export endpoint (/api/export).
- Static frontend index.html delivery.
- Proof that the dashboard backend never invokes subprocess or system calls.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from dashboard.app import app


class TestDashboardAPI(unittest.TestCase):
    """Test suite for dashboard REST endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Reset state before each test
        self.client.post("/api/reset")

    def test_health_endpoint(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertGreater(data["scenarios_available"], 0)

    def test_list_scenarios_returns_approved_scenarios(self):
        res = self.client.get("/api/scenarios")
        self.assertEqual(res.status_code, 200)
        scenarios = res.json()
        self.assertIsInstance(scenarios, list)
        self.assertGreaterEqual(len(scenarios), 6)

        filenames = [s["filename"] for s in scenarios]
        self.assertIn("reconnaissance.jsonl", filenames)
        self.assertIn("authentication_abuse.jsonl", filenames)
        self.assertIn("combined_multi_session.jsonl", filenames)

    def test_current_state_initial_empty(self):
        res = self.client.get("/api/current-state")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["loaded"])
        self.assertEqual(data["events_parsed"], 0)
        self.assertIn("world_state", data)

    def test_run_scenario_success(self):
        payload = {"scenario": "reconnaissance.jsonl", "accumulate_state": False}
        res = self.client.post("/api/run-scenario", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["events_parsed"], 8)
        self.assertEqual(data["sessions_count"], 1)
        self.assertEqual(data["sessions"][0]["analysis"]["primary_category"], "reconnaissance")
        self.assertEqual(data["sessions"][0]["deception"]["policy_id"], "POL-RECON-REVEAL-MYSQL")

        # Verify state is updated in /api/current-state
        state_res = self.client.get("/api/current-state")
        self.assertEqual(state_res.status_code, 200)
        state_data = state_res.json()
        self.assertTrue(state_data["loaded"])
        self.assertIn("mysql-backend", state_data["world_state"]["discovered_services"])

    def test_run_scenario_accumulate_state(self):
        # Run 1: Reconnaissance (reveals mysql-backend)
        self.client.post("/api/run-scenario", json={"scenario": "reconnaissance.jsonl", "accumulate_state": False})

        # Run 2: Privilege Escalation with accumulate_state=True
        res = self.client.post(
            "/api/run-scenario",
            json={"scenario": "privilege_escalation.jsonl", "accumulate_state": True},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Both state updates accumulated in WorldState
        ws = data["world_state"]
        self.assertIn("mysql-backend", ws["discovered_services"])
        self.assertIn("/root/.ssh/id_rsa_backup", ws["discovered_files"])

    def test_reset_state(self):
        # Load scenario first
        self.client.post("/api/run-scenario", json={"scenario": "reconnaissance.jsonl"})

        # Reset
        res = self.client.post("/api/reset")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "success")

        # Verify current-state is clear
        state_res = self.client.get("/api/current-state")
        self.assertFalse(state_res.json()["loaded"])

    def test_export_endpoint(self):
        # When not loaded -> returns 400
        res_empty = self.client.get("/api/export")
        self.assertEqual(res_empty.status_code, 400)

        # Load scenario
        self.client.post("/api/run-scenario", json={"scenario": "reconnaissance.jsonl"})

        # Export returns valid JSON attachment
        res_export = self.client.get("/api/export")
        self.assertEqual(res_export.status_code, 200)
        self.assertEqual(res_export.headers["content-type"], "application/json")
        self.assertIn("attachment", res_export.headers["content-disposition"])
        parsed = json.loads(res_export.text)
        self.assertEqual(parsed["events_parsed"], 8)

    def test_path_traversal_attempts_rejected(self):
        malicious_inputs = [
            "../../etc/passwd",
            "../analysis/engine.py",
            "/etc/shadow",
            "C:\\Windows\\system32\\cmd.exe",
            "..\\..\\config.json",
        ]
        for bad_path in malicious_inputs:
            res = self.client.post("/api/run-scenario", json={"scenario": bad_path})
            self.assertEqual(
                res.status_code,
                400,
                f"Path traversal payload '{bad_path}' should be rejected with HTTP 400!",
            )

    def test_nonexistent_scenario_returns_404(self):
        res = self.client.post("/api/run-scenario", json={"scenario": "nonexistent_fixture_999.jsonl"})
        self.assertEqual(res.status_code, 404)

    def test_static_index_html_served(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers["content-type"])
        self.assertIn("AI ADAPTIVE CYBER DECEPTION SYSTEM", res.text)
        self.assertIn("id=\"scenarioSelect\"", res.text)

    def test_no_system_calls_made_by_dashboard(self):
        """Verify the dashboard never invokes subprocess or system commands."""
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen invoked!")):
            with patch("subprocess.run", side_effect=AssertionError("subprocess.run invoked!")):
                with patch("subprocess.call", side_effect=AssertionError("subprocess.call invoked!")):
                    with patch("os.system", side_effect=AssertionError("os.system invoked!")):
                        # Run a scenario via API
                        res = self.client.post(
                            "/api/run-scenario",
                            json={"scenario": "reconnaissance.jsonl"},
                        )
                        self.assertEqual(res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
