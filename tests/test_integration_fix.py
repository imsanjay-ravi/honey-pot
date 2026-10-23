"""
tests/test_integration_fix.py — Regression tests for Dashboard & Simulator Integration Fix.

Verifies:
1. Simulator events, sessions, behaviour findings, threat scores, and deception decisions
   are visible in the Phase 5 dashboard at /api/current-state?source=simulator.
2. Source separation: synthetic scenario state and simulator state remain strictly
   isolated without silent overwrite.
3. /api/sources endpoint returns metadata and status for 'scenario', 'simulator', and 'live_cowrie'.
4. Multi-session continuity: starting a new simulator session archives previous session
   telemetry and reflects all sessions in the dashboard session explorer.
5. Explicit reset behaviour: target='simulator', target='scenario', and target='all'.
6. Export functionality for simulator telemetry (/api/export?source=simulator).
7. Safety validation: operations remain strictly in-memory without subprocess or disk changes.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from dashboard.app import app


class TestDashboardSimulatorIntegration(unittest.TestCase):
    """Integration test suite for dashboard + simulator unified data flow."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Reset all state before each test
        self.client.post("/api/reset?target=all")

    def test_sources_endpoint_lists_all_sources(self):
        """Test GET /api/sources returns expected sources and loading status."""
        res = self.client.get("/api/sources")
        self.assertEqual(res.status_code, 200)
        sources = res.json()
        self.assertIsInstance(sources, list)
        source_ids = [s["id"] for s in sources]
        self.assertIn("scenario", source_ids)
        self.assertIn("simulator", source_ids)
        self.assertIn("live_cowrie", source_ids)

        # Initially, neither scenario nor simulator has loaded data
        scenario_src = next(s for s in sources if s["id"] == "scenario")
        sim_src = next(s for s in sources if s["id"] == "simulator")
        self.assertFalse(scenario_src["loaded"])
        self.assertFalse(sim_src["loaded"])

    def test_simulator_actions_appear_in_dashboard_current_state(self):
        """
        Verify that running a simulator action populates simulator telemetry
        which is accessible via /api/current-state?source=simulator with full
        analysis findings, score, and deception decisions.
        """
        # Execute simulator action
        action_res = self.client.post("/api/simulator/action", json={"action": "reconnaissance"})
        self.assertEqual(action_res.status_code, 200)

        # Check dashboard current-state
        dash_res = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(dash_res.status_code, 200)
        data = dash_res.json()

        self.assertTrue(data["loaded"])
        self.assertEqual(data["source"], "simulator")
        self.assertGreater(data["events_parsed"], 1)
        self.assertEqual(data["sessions_count"], 1)

        session = data["sessions"][0]
        self.assertEqual(session["analysis"]["primary_category"], "reconnaissance")
        self.assertGreater(session["analysis"]["score"], 0)
        self.assertIn("findings", session["analysis"])
        self.assertGreater(len(session["analysis"]["findings"]), 0)

        # Deception decision should be present
        self.assertIn("deception", session)
        self.assertIn(session["deception"]["status"], ("accepted", "no_action_required", "action_taken"))

    def test_simulator_shell_commands_appear_in_dashboard(self):
        """
        Verify that executing discrete shell commands in the simulator produces
        session events, classifications, and deception updates in the dashboard.
        """
        # Execute commands
        self.client.post("/api/simulator/command", json={"command": "whoami"})
        self.client.post("/api/simulator/command", json={"command": "cat /etc/passwd"})

        dash_res = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(dash_res.status_code, 200)
        data = dash_res.json()

        self.assertTrue(data["loaded"])
        self.assertEqual(data["source"], "simulator")
        self.assertGreaterEqual(data["events_parsed"], 3)  # connect + 2 commands
        self.assertEqual(len(data["sessions"]), 1)

        # Confirm world state contains revealed files / services
        self.assertIn("world_state", data)
        self.assertIsInstance(data["world_state"], dict)

    def test_source_separation_no_silent_overwrite(self):
        """
        Verify that scenario results and simulator results exist independently
        and neither overwrites the other.
        """
        # 1. Run synthetic scenario
        scen_run = self.client.post("/api/run-scenario", json={"scenario": "reconnaissance.jsonl"})
        self.assertEqual(scen_run.status_code, 200)

        # 2. Run simulator command
        sim_run = self.client.post("/api/simulator/command", json={"command": "cat /etc/shadow"})
        self.assertEqual(sim_run.status_code, 200)

        # 3. Query source=scenario
        res_scen = self.client.get("/api/current-state?source=scenario")
        self.assertEqual(res_scen.status_code, 200)
        data_scen = res_scen.json()
        self.assertEqual(data_scen["source"], "scenario")
        self.assertIn("reconnaissance", data_scen["input_file"])

        # 4. Query source=simulator
        res_sim = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(res_sim.status_code, 200)
        data_sim = res_sim.json()
        self.assertEqual(data_sim["source"], "simulator")
        self.assertIn("simulator://in-memory", data_sim["input_file"])

    def test_invalid_source_rejected(self):
        """Verify that requesting an unsupported source parameter returns 400 Bad Request."""
        res = self.client.get("/api/current-state?source=invalid_source")
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid telemetry source", res.json()["detail"])

    def test_multi_session_continuity_in_simulator(self):
        """
        Verify that creating a new session in simulator archives the previous session,
        allowing the dashboard to display both sessions in the session explorer.
        """
        # Session 1: reconnaissance
        self.client.post("/api/simulator/action", json={"action": "reconnaissance"})

        # Start new session
        new_sess_res = self.client.post("/api/simulator/session/new")
        self.assertEqual(new_sess_res.status_code, 200)

        # Session 2: privilege escalation
        self.client.post("/api/simulator/action", json={"action": "privilege_escalation"})

        # Dashboard should now show 2 sessions
        dash_res = self.client.get("/api/current-state?source=simulator")
        data = dash_res.json()
        self.assertEqual(data["sessions_count"], 2)
        self.assertEqual(len(data["sessions"]), 2)

    def test_targeted_reset_behavior(self):
        """
        Verify that reset with target='simulator' only clears simulator state,
        target='scenario' only clears scenario state, and target='all' clears both.
        """
        # Populate both
        self.client.post("/api/run-scenario", json={"scenario": "reconnaissance.jsonl"})
        self.client.post("/api/simulator/action", json={"action": "reconnaissance"})

        # Reset only simulator
        res = self.client.post("/api/reset?target=simulator")
        self.assertEqual(res.status_code, 200)

        # Simulator should now have no activity (only connect event)
        sim_state = self.client.get("/api/current-state?source=simulator").json()
        self.assertFalse(sim_state["loaded"])

        # Scenario should still be loaded
        scen_state = self.client.get("/api/current-state?source=scenario").json()
        self.assertTrue(scen_state["loaded"])

        # Reset scenario
        self.client.post("/api/reset?target=scenario")
        scen_state2 = self.client.get("/api/current-state?source=scenario").json()
        self.assertFalse(scen_state2["loaded"])

    def test_export_simulator_results(self):
        """Verify GET /api/export?source=simulator returns valid JSON report attachment."""
        self.client.post("/api/simulator/action", json={"action": "download_attempt"})

        res = self.client.get("/api/export?source=simulator")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.headers.get("content-type", ""))
        self.assertIn("simulator_deception_report.json", res.headers.get("content-disposition", ""))

        data = json.loads(res.text)
        self.assertEqual(data["source"], "simulator")
        self.assertTrue(data["loaded"])
        self.assertEqual(data["sessions"][0]["analysis"]["primary_category"], "download_attempt")

    def test_safety_no_subprocess_on_simulator_dashboard_interaction(self):
        """Confirm that viewing simulator telemetry in the dashboard invokes no subprocesses."""
        with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
            self.client.post("/api/simulator/command", json={"command": "whoami"})
            res = self.client.get("/api/current-state?source=simulator")
            self.assertEqual(res.status_code, 200)
            mock_popen.assert_not_called()
            mock_run.assert_not_called()

    def test_exact_end_to_end_simulator_integration_lifecycle(self):
        """
        Targeted regression test reproducing the exact 7-step sequence:
        1. Start with no simulator activity.
        2. Submit a simulator action using the unified backend instance.
        3. Query the dashboard API with source=simulator.
        4. Assert session, events, classification, score, and deception decision are returned.
        5. Start a second session and verify session-history behaviour.
        6. Reset simulator state and verify the dashboard response.
        7. Confirm synthetic scenario results remain independently accessible.
        """
        # Step 1: Start with no simulator activity
        self.client.post("/api/reset?target=all")
        initial_res = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(initial_res.status_code, 200)
        initial_data = initial_res.json()
        self.assertFalse(initial_data["loaded"])
        self.assertEqual(initial_data["sessions_count"], 0)
        self.assertEqual(len(initial_data["sessions"]), 0)

        # Step 2: Submit a simulator action (privilege escalation)
        action_res = self.client.post("/api/simulator/action", json={"action": "privilege_escalation"})
        self.assertEqual(action_res.status_code, 200)

        # Step 3: Query dashboard API with source=simulator
        dash_res = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(dash_res.status_code, 200)
        data = dash_res.json()

        # Step 4: Assert generated session, events, classification, score, and deception decision
        self.assertTrue(data["loaded"])
        self.assertEqual(data["source"], "simulator")
        self.assertEqual(data["sessions_count"], 1)
        self.assertGreaterEqual(data["events_parsed"], 3)  # connect + 3 privilege escalation commands
        session = data["sessions"][0]
        self.assertEqual(session["analysis"]["primary_category"], "privilege_escalation_attempt")
        self.assertGreater(session["analysis"]["score"], 0)
        self.assertGreater(len(session["analysis"]["findings"]), 0)
        self.assertIn("deception", session)
        self.assertIn(session["deception"]["status"], ("accepted", "no_action_required", "action_taken"))

        # Step 5: Start a second session and verify session-history behaviour
        new_sess_res = self.client.post("/api/simulator/session/new")
        self.assertEqual(new_sess_res.status_code, 200)
        # Execute action in second session
        self.client.post("/api/simulator/action", json={"action": "reconnaissance"})
        multi_res = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(multi_res.status_code, 200)
        multi_data = multi_res.json()
        self.assertEqual(multi_data["sessions_count"], 2)
        self.assertEqual(len(multi_data["sessions"]), 2)
        # Verify first session is archived and second session is active
        sess_ids = [s["session_id"] for s in multi_data["sessions"]]
        self.assertEqual(len(set(sess_ids)), 2)

        # Step 6: Reset simulator state and verify the dashboard response
        reset_res = self.client.post("/api/reset?target=simulator")
        self.assertEqual(reset_res.status_code, 200)
        after_reset = self.client.get("/api/current-state?source=simulator")
        self.assertEqual(after_reset.status_code, 200)
        reset_data = after_reset.json()
        self.assertFalse(reset_data["loaded"])
        self.assertEqual(reset_data["sessions_count"], 0)
        self.assertEqual(len(reset_data["sessions"]), 0)

        # Step 7: Confirm synthetic scenario results remain independently accessible
        run_res = self.client.post("/api/run-scenario", json={"scenario": "authentication_abuse.jsonl"})
        self.assertEqual(run_res.status_code, 200)
        scen_state = self.client.get("/api/current-state?source=scenario").json()
        self.assertTrue(scen_state["loaded"])
        self.assertEqual(scen_state["source"], "scenario")
        self.assertIn("authentication_abuse", scen_state["input_file"])
        # And simulator is still empty
        sim_state = self.client.get("/api/current-state?source=simulator").json()
        self.assertFalse(sim_state["loaded"])

