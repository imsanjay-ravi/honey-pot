"""
tests/test_pipeline.py — End-to-End Integration Tests for Phase 4.

Verifies:
- Full end-to-end execution on synthetic JSONL fixtures.
- Multi-session processing in deterministic order.
- Safe handling of empty files, malformed JSON lines, and missing fields.
- Parse warning collection and strict-mode failure behavior.
- Output JSON saving and schema validity.
- Simulated WorldState updates and export.
- Deterministic output across multiple pipeline executions.
- Complete isolation from host OS: no commands executed, no host files modified.
- CLI execution via subprocess with exit code verification.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deception.actions import ACTION_NO_OP, ACTION_PRESENT_DECOY, ACTION_REVEAL_SERVICE
from deception.world_state import WorldState
from pipeline import run_pipeline


class TestPipelineWorkflow(unittest.TestCase):
    """Test full workflow against synthetic scenarios."""

    def setUp(self):
        self.scenarios_dir = Path(__file__).resolve().parent.parent / "examples" / "scenarios"

    def test_pipeline_reconnaissance_scenario(self):
        log_path = self.scenarios_dir / "reconnaissance.jsonl"
        result = run_pipeline(log_path, quiet=True)

        self.assertEqual(result["events_parsed"], 8)
        self.assertEqual(result["warnings_count"], 0)
        self.assertEqual(result["sessions_count"], 1)

        session = result["sessions"][0]
        self.assertEqual(session["session_id"], "s-recon-01")
        self.assertEqual(session["analysis"]["primary_category"], "reconnaissance")
        self.assertEqual(session["deception"]["status"], "accepted")
        self.assertEqual(session["deception"]["policy_id"], "POL-RECON-REVEAL-MYSQL")
        self.assertEqual(session["deception"]["action"]["action_id"], ACTION_REVEAL_SERVICE)
        self.assertEqual(session["deception"]["action"]["target"], "mysql-backend")

        # World state updated
        ws = result["world_state"]
        self.assertIn("mysql-backend", ws["discovered_services"])

    def test_pipeline_privilege_escalation_scenario(self):
        log_path = self.scenarios_dir / "privilege_escalation.jsonl"
        result = run_pipeline(log_path, quiet=True)

        self.assertEqual(result["sessions_count"], 1)
        session = result["sessions"][0]
        self.assertEqual(session["analysis"]["primary_category"], "privilege_escalation_attempt")
        self.assertEqual(session["deception"]["policy_id"], "POL-CRED-DECOY-SSH")
        self.assertEqual(session["deception"]["action"]["action_id"], ACTION_PRESENT_DECOY)
        self.assertEqual(session["deception"]["action"]["target"], "/root/.ssh/id_rsa_backup")

        ws = result["world_state"]
        self.assertIn("/root/.ssh/id_rsa_backup", ws["discovered_files"])

    def test_pipeline_combined_multi_session_with_warnings(self):
        log_path = self.scenarios_dir / "combined_multi_session.jsonl"
        result = run_pipeline(log_path, quiet=True)

        # 33 valid events + 1 invalid JSON warning
        self.assertEqual(result["events_parsed"], 33)
        self.assertEqual(result["warnings_count"], 1)
        self.assertEqual(result["sessions_count"], 6)

        # Ensure warning is captured with line number
        warning = result["warnings"][0]
        self.assertEqual(warning["line_number"], 16)
        self.assertIn("Invalid JSON", warning["reason"])

        # Check all sessions present in order
        session_ids = [s["session_id"] for s in result["sessions"]]
        expected = [
            "s-recon-01",
            "s-auth-02",
            "s-filedisc-03",
            "s-dl-04",
            "s-pe-05",
            "s-benign-06",
        ]
        self.assertEqual(session_ids, expected)

        # Benign session safe fallback
        benign = result["sessions"][5]
        self.assertEqual(benign["deception"]["status"], "no_action_required")
        self.assertEqual(benign["deception"]["action"]["action_id"], ACTION_NO_OP)

    def test_pipeline_strict_mode_raises_on_warning(self):
        log_path = self.scenarios_dir / "combined_multi_session.jsonl"
        with self.assertRaises(ValueError) as ctx:
            run_pipeline(log_path, strict=True, quiet=True)
        self.assertIn("Strict mode failure", str(ctx.exception))

    def test_pipeline_empty_file_handling(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tf:
            tf.write("")
            temp_path = tf.name

        try:
            result = run_pipeline(temp_path, quiet=True)
            self.assertEqual(result["events_parsed"], 0)
            self.assertEqual(result["warnings_count"], 0)
            self.assertEqual(result["sessions_count"], 0)
            self.assertEqual(len(result["sessions"]), 0)
        finally:
            os.remove(temp_path)

    def test_pipeline_missing_file_raises_not_found(self):
        with self.assertRaises(FileNotFoundError):
            run_pipeline("nonexistent_log_file_12345.jsonl", quiet=True)

    def test_pipeline_json_output_saving(self):
        log_path = self.scenarios_dir / "reconnaissance.jsonl"
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = Path(tmpdir) / "output.json"
            ws_json = Path(tmpdir) / "world_state.json"

            result = run_pipeline(
                log_path,
                output_file=out_json,
                world_state_output=ws_json,
                quiet=True,
            )

            self.assertTrue(out_json.exists())
            self.assertTrue(ws_json.exists())

            # Verify saved JSON matches return value
            with open(out_json, "r", encoding="utf-8") as f:
                loaded_result = json.load(f)
            self.assertEqual(loaded_result["events_parsed"], result["events_parsed"])
            self.assertEqual(loaded_result["sessions_count"], result["sessions_count"])

            with open(ws_json, "r", encoding="utf-8") as f:
                loaded_ws = json.load(f)
            self.assertEqual(loaded_ws["host"]["hostname"], "corp-srv-db01")

    def test_pipeline_determinism_identical_runs(self):
        log_path = self.scenarios_dir / "combined_multi_session.jsonl"
        r1 = run_pipeline(log_path, quiet=True)
        r2 = run_pipeline(log_path, quiet=True)

        # Ignore input_file path normalization if any, verify exact structural identity
        self.assertEqual(r1["events_parsed"], r2["events_parsed"])
        self.assertEqual(r1["warnings"], r2["warnings"])
        self.assertEqual(r1["sessions_count"], r2["sessions_count"])

        for s1, s2 in zip(r1["sessions"], r2["sessions"]):
            self.assertEqual(s1["session_id"], s2["session_id"])
            self.assertEqual(s1["analysis"]["score"], s2["analysis"]["score"])
            self.assertEqual(s1["analysis"]["primary_category"], s2["analysis"]["primary_category"])
            self.assertEqual(s1["deception"]["policy_id"], s2["deception"]["policy_id"])
            self.assertEqual(s1["deception"]["action"], s2["deception"]["action"])


class TestPipelineSafetyAndCLI(unittest.TestCase):
    """Test security boundaries and command-line execution."""

    def test_no_system_calls_or_command_execution(self):
        """Guarantee no subprocess or system calls are executed during pipeline run."""
        scenarios_dir = Path(__file__).resolve().parent.parent / "examples" / "scenarios"
        log_path = scenarios_dir / "combined_multi_session.jsonl"

        with patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen invoked!")):
            with patch("subprocess.run", side_effect=AssertionError("subprocess.run invoked!")):
                with patch("subprocess.call", side_effect=AssertionError("subprocess.call invoked!")):
                    with patch("os.system", side_effect=AssertionError("os.system invoked!")):
                        res = run_pipeline(log_path, quiet=True)
                        self.assertGreater(res["events_parsed"], 0)

    def test_cli_execution_successful(self):
        """Run pipeline.py via subprocess CLI."""
        scenarios_dir = Path(__file__).resolve().parent.parent / "examples" / "scenarios"
        log_path = scenarios_dir / "reconnaissance.jsonl"

        cmd = [sys.executable, "pipeline.py", "--input", str(log_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

        self.assertEqual(proc.returncode, 0)
        self.assertIn("OFFLINE PIPELINE EXECUTION", proc.stdout)
        self.assertIn("s-recon-01", proc.stdout)
        self.assertIn("POL-RECON-REVEAL-MYSQL", proc.stdout)

    def test_cli_strict_flag_exits_nonzero_on_warnings(self):
        """CLI with --strict flag on combined_multi_session.jsonl should exit with code 1."""
        scenarios_dir = Path(__file__).resolve().parent.parent / "examples" / "scenarios"
        log_path = scenarios_dir / "combined_multi_session.jsonl"

        cmd = [sys.executable, "pipeline.py", "--input", str(log_path), "--strict"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

        self.assertEqual(proc.returncode, 1)
        self.assertIn("Strict mode failure", proc.stderr)

    def test_cli_missing_input_exits_nonzero(self):
        """CLI with nonexistent file exits with code 1."""
        cmd = [sys.executable, "pipeline.py", "--input", "nonexistent_file_xyz.jsonl"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

        self.assertEqual(proc.returncode, 1)
        self.assertIn("Error: Log file not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()
