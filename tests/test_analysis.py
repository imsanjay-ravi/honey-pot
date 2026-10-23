"""
tests/test_analysis.py — Tests for the Phase 2 analysis engine.

All fixtures are synthetic (RFC 5737 IPs, fictional timestamps).
No raw captured attacker data is used.

Test classes:
  A. TestFeatureExtraction      — features.extract_features()
  B. TestClassifierRules        — classifier.classify() individual rules
  C. TestClassifierMultiple     — multiple findings per session
  D. TestClassifierFalsePos     — false-positive-prone inputs
  E. TestClassifierEdgeCases    — empty / malformed inputs
  F. TestPrimaryCategory        — classifier.primary_category()
  G. TestScorer                 — scorer.compute_score()
  H. TestEngine                 — engine.analyse_session() + full pipeline
  I. TestEngineMultiSession     — engine.analyse_all_sessions()
  J. TestCLI                    — CLI smoke tests via subprocess
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from analysis.features import extract_features
from analysis.classifier import (
    classify,
    primary_category,
    Finding,
    STRONG,
    MODERATE,
    WEAK,
)
from analysis.scorer import compute_score
from analysis.engine import analyse_session, analyse_all_sessions

from tests.fixtures.synthetic_sessions import (
    empty_session,
    connect_only,
    single_ls,
    recon_session,
    brute_force_session,
    brute_force_then_success,
    download_session,
    privilege_escalation_session,
    credential_access_session,
    multi_behaviour_session,
    file_discovery_session,
    unknown_commands_session,
    ambiguous_ls_session,
    missing_fields_events,
    two_session_events,
)


# ===========================================================================
# A. Feature extraction
# ===========================================================================

class TestFeatureExtraction(unittest.TestCase):

    def test_empty_session_zero_counts(self):
        f = extract_features(empty_session())
        self.assertEqual(f["total_events"], 0)
        self.assertEqual(f["command_count"], 0)
        self.assertEqual(f["login_attempt_count"], 0)
        self.assertIsNone(f["session_duration_s"])

    def test_connect_only_no_commands(self):
        f = extract_features(connect_only())
        self.assertEqual(f["command_count"], 0)
        self.assertFalse(f["has_recon_commands"])

    def test_recon_commands_detected(self):
        f = extract_features(recon_session())
        self.assertTrue(f["has_recon_commands"])
        self.assertGreaterEqual(f["recon_command_count"], 3)

    def test_file_discovery_detected(self):
        f = extract_features(file_discovery_session())
        self.assertTrue(f["has_file_discovery"])
        self.assertGreaterEqual(f["file_discovery_count"], 3)

    def test_download_detected(self):
        f = extract_features(download_session())
        self.assertTrue(f["has_download_attempt"])
        self.assertEqual(f["download_attempt_count"], 1)

    def test_privilege_escalation_detected(self):
        f = extract_features(privilege_escalation_session())
        self.assertTrue(f["has_privilege_escalation"])
        self.assertGreaterEqual(f["privilege_escalation_count"], 1)

    def test_credential_access_detected(self):
        f = extract_features(credential_access_session())
        self.assertTrue(f["has_credential_commands"])
        self.assertGreaterEqual(f["credential_command_count"], 2)

    def test_login_counts(self):
        f = extract_features(brute_force_then_success())
        self.assertEqual(f["login_failure_count"], 5)
        self.assertEqual(f["login_success_count"], 1)
        self.assertEqual(f["login_attempt_count"], 6)

    def test_root_login_detected(self):
        f = extract_features(recon_session())
        self.assertTrue(f["has_root_login"])

    def test_no_root_login(self):
        f = extract_features(privilege_escalation_session())
        # Fixture uses "www-data"
        self.assertFalse(f["has_root_login"])

    def test_session_duration_calculated(self):
        f = extract_features(recon_session())
        self.assertIsNotNone(f["session_duration_s"])
        self.assertGreater(f["session_duration_s"], 0)

    def test_session_duration_none_for_single_event(self):
        f = extract_features(connect_only())
        self.assertIsNone(f["session_duration_s"])

    def test_unknown_commands_no_categories(self):
        f = extract_features(unknown_commands_session())
        self.assertFalse(f["has_recon_commands"])
        self.assertFalse(f["has_download_attempt"])
        self.assertFalse(f["has_privilege_escalation"])

    def test_missing_optional_fields_no_crash(self):
        # Events missing 'command', 'username', 'success' fields
        f = extract_features(missing_fields_events())
        self.assertIsInstance(f["command_count"], int)
        self.assertIsInstance(f["login_attempt_count"], int)

    def test_non_list_input_returns_zeroes(self):
        f = extract_features(None)
        self.assertEqual(f["total_events"], 0)

    def test_feature_dict_has_all_expected_keys(self):
        f = extract_features(empty_session())
        required = {
            "total_events", "session_duration_s", "command_count",
            "failed_command_count", "login_attempt_count",
            "login_success_count", "login_failure_count",
            "other_event_count", "unknown_event_count",
            "has_recon_commands", "has_file_discovery",
            "has_download_attempt", "has_privilege_escalation",
            "has_credential_commands",
            "recon_command_count", "file_discovery_count",
            "download_attempt_count", "privilege_escalation_count",
            "credential_command_count",
            "unique_username_count", "has_root_login",
        }
        self.assertTrue(required.issubset(set(f.keys())))

    def test_unknown_event_count_alias(self):
        """unknown_event_count must equal other_event_count."""
        f = extract_features(recon_session())
        self.assertEqual(f["unknown_event_count"], f["other_event_count"])

    def test_ls_counted_as_file_discovery(self):
        f = extract_features(single_ls())
        self.assertTrue(f["has_file_discovery"])
        self.assertEqual(f["file_discovery_count"], 1)

    def test_commands_are_not_executed(self):
        """A command that looks like a shell injection must not raise."""
        dangerous = [
            {"timestamp": "2026-01-15T10:00:00+00:00",
             "event_type": "command",
             "command": "$(rm -rf /)"},
            {"timestamp": "2026-01-15T10:01:00+00:00",
             "event_type": "command",
             "command": "; cat /etc/passwd"},
        ]
        # Must complete without error or side effects
        f = extract_features(dangerous)
        self.assertIsInstance(f, dict)


# ===========================================================================
# B. Classifier — individual rules
# ===========================================================================

class TestClassifierRules(unittest.TestCase):

    def _rule_ids(self, findings):
        return {f.rule_id for f in findings}

    def _categories(self, findings):
        return {f.category for f in findings}

    def test_recon_light_fires_on_one_recon_command(self):
        f = extract_features(single_ls())
        # ls matches file_discovery but not recon; use recon_session for REC-01
        f2 = extract_features(recon_session())
        findings = classify(f2)
        self.assertIn("REC-01", self._rule_ids(findings))

    def test_recon_strong_fires_on_three_plus_commands(self):
        f = extract_features(recon_session())
        findings = classify(f)
        self.assertIn("REC-02", self._rule_ids(findings))

    def test_auth_moderate_fires_on_3_to_4_failures(self):
        events = brute_force_session(num_failures=3)
        f = extract_features(events)
        findings = classify(f)
        self.assertIn("AUTH-01", self._rule_ids(findings))
        self.assertNotIn("AUTH-02", self._rule_ids(findings))

    def test_auth_strong_fires_on_5_plus_failures(self):
        events = brute_force_session(num_failures=7)
        f = extract_features(events)
        findings = classify(f)
        self.assertIn("AUTH-02", self._rule_ids(findings))

    def test_auth_success_after_failure_fires(self):
        f = extract_features(brute_force_then_success())
        findings = classify(f)
        self.assertIn("AUTH-03", self._rule_ids(findings))

    def test_file_discovery_weak_fires_on_one_ls(self):
        f = extract_features(single_ls())
        findings = classify(f)
        self.assertIn("FD-01", self._rule_ids(findings))

    def test_file_discovery_moderate_fires_on_three_plus(self):
        f = extract_features(file_discovery_session())
        findings = classify(f)
        self.assertIn("FD-02", self._rule_ids(findings))

    def test_download_fires(self):
        f = extract_features(download_session())
        findings = classify(f)
        self.assertIn("DL-01", self._rule_ids(findings))

    def test_priv_esc_pe01_fires(self):
        f = extract_features(privilege_escalation_session())
        findings = classify(f)
        self.assertIn("PE-01", self._rule_ids(findings))

    def test_credential_access_pe02_fires(self):
        f = extract_features(credential_access_session())
        findings = classify(f)
        self.assertIn("PE-02", self._rule_ids(findings))

    def test_unknown_returned_for_empty_session(self):
        f = extract_features(empty_session())
        findings = classify(f)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "UNKNOWN")
        self.assertEqual(findings[0].category, "unknown")

    def test_finding_is_frozen_dataclass(self):
        f = extract_features(recon_session())
        findings = classify(f)
        for finding in findings:
            self.assertIsInstance(finding, Finding)
            with self.assertRaises(Exception):
                finding.rule_id = "MODIFIED"  # frozen

    def test_finding_has_required_fields(self):
        f = extract_features(recon_session())
        findings = classify(f)
        for finding in findings:
            self.assertIsInstance(finding.rule_id, str)
            self.assertIsInstance(finding.category, str)
            self.assertIsInstance(finding.evidence, str)
            self.assertIn(finding.evidence_strength, {STRONG, MODERATE, WEAK})

    def test_non_dict_features_returns_unknown(self):
        findings = classify(None)
        self.assertEqual(findings[0].rule_id, "UNKNOWN")

    def test_auth01_not_auth02_for_four_failures(self):
        events = brute_force_session(num_failures=4)
        f = extract_features(events)
        findings = classify(f)
        rule_ids = self._rule_ids(findings)
        self.assertIn("AUTH-01", rule_ids)
        self.assertNotIn("AUTH-02", rule_ids)

    def test_two_failures_does_not_fire_auth01(self):
        events = brute_force_session(num_failures=2)
        f = extract_features(events)
        findings = classify(f)
        rule_ids = self._rule_ids(findings)
        self.assertNotIn("AUTH-01", rule_ids)
        self.assertNotIn("AUTH-02", rule_ids)


# ===========================================================================
# C. Classifier — multiple findings per session
# ===========================================================================

class TestClassifierMultiple(unittest.TestCase):

    def _rule_ids(self, findings):
        return {f.rule_id for f in findings}

    def _categories(self, findings):
        return {f.category for f in findings}

    def test_multi_behaviour_has_multiple_findings(self):
        f = extract_features(multi_behaviour_session())
        findings = classify(f)
        self.assertGreater(len(findings), 1)

    def test_multi_behaviour_categories(self):
        f = extract_features(multi_behaviour_session())
        findings = classify(f)
        cats = self._categories(findings)
        # Should include recon, file_discovery, and download
        self.assertIn("reconnaissance", cats)
        self.assertIn("file_discovery", cats)
        self.assertIn("download_attempt", cats)

    def test_no_unknown_in_active_session(self):
        """An active session with real findings must not also return UNKNOWN."""
        f = extract_features(recon_session())
        findings = classify(f)
        rule_ids = self._rule_ids(findings)
        self.assertNotIn("UNKNOWN", rule_ids)

    def test_priv_esc_and_recon_together(self):
        f = extract_features(privilege_escalation_session())
        findings = classify(f)
        cats = self._categories(findings)
        self.assertIn("privilege_escalation_attempt", cats)
        self.assertIn("reconnaissance", cats)

    def test_credential_and_file_discovery_together(self):
        f = extract_features(credential_access_session())
        findings = classify(f)
        cats = self._categories(findings)
        self.assertIn("privilege_escalation_attempt", cats)
        self.assertIn("file_discovery", cats)


# ===========================================================================
# D. Classifier — false positive scenarios
# ===========================================================================

class TestClassifierFalsePos(unittest.TestCase):

    def test_single_ls_is_only_weak(self):
        """One 'ls' fires FD-01 (WEAK) but nothing stronger."""
        f = extract_features(ambiguous_ls_session())
        findings = classify(f)
        strengths = {fn.evidence_strength for fn in findings}
        # Must not produce any STRONG finding for a single ls
        self.assertNotIn(STRONG, strengths)

    def test_single_ls_does_not_fire_fd02(self):
        f = extract_features(ambiguous_ls_session())
        findings = classify(f)
        rule_ids = {fn.rule_id for fn in findings}
        self.assertNotIn("FD-02", rule_ids)

    def test_connect_only_produces_unknown(self):
        f = extract_features(connect_only())
        findings = classify(f)
        self.assertEqual(findings[0].category, "unknown")

    def test_two_failures_not_auth_abuse(self):
        """Two failures is below the AUTH-01 threshold (3)."""
        events = brute_force_session(num_failures=2)
        f = extract_features(events)
        findings = classify(f)
        categories = {fn.category for fn in findings}
        self.assertNotIn("authentication_abuse", categories)

    def test_unknown_commands_score_low(self):
        """Commands that match no pattern should not inflate the score."""
        f = extract_features(unknown_commands_session())
        result = compute_score(f)
        # Only a successful login after a clean login — score should be minimal
        self.assertLess(result["score"], 20)

    def test_shell_injection_string_not_classified_as_download(self):
        """$(wget ...) must not trigger DL-01 unless 'wget' appears."""
        events = [
            {"timestamp": "2026-01-15T10:00:00+00:00",
             "event_type": "command",
             "command": "$(rm -rf /)"},
        ]
        f = extract_features(events)
        self.assertFalse(f["has_download_attempt"])


# ===========================================================================
# E. Classifier — edge cases and malformed inputs
# ===========================================================================

class TestClassifierEdgeCases(unittest.TestCase):

    def test_empty_features_dict_returns_unknown(self):
        findings = classify({})
        self.assertEqual(findings[0].rule_id, "UNKNOWN")

    def test_none_features_returns_unknown(self):
        findings = classify(None)
        self.assertEqual(findings[0].rule_id, "UNKNOWN")

    def test_extra_keys_in_features_ignored(self):
        """Classifier must not crash on extra/unexpected feature keys."""
        f = {"recon_command_count": 5, "extra_key": "unexpected", "login_failure_count": 0}
        findings = classify(f)
        self.assertIsInstance(findings, list)
        self.assertTrue(len(findings) >= 1)

    def test_classify_is_deterministic(self):
        """Identical input must always produce identical output."""
        f = extract_features(multi_behaviour_session())
        result1 = classify(f)
        result2 = classify(f)
        self.assertEqual(
            [(fn.rule_id, fn.category) for fn in result1],
            [(fn.rule_id, fn.category) for fn in result2],
        )

    def test_string_command_values_are_not_executed(self):
        events = [
            {"timestamp": "2026-01-15T10:00:00+00:00",
             "event_type": "command",
             "command": "__import__('os').system('echo pwned')"},
        ]
        f = extract_features(events)
        findings = classify(f)
        self.assertIsInstance(findings, list)


# ===========================================================================
# F. Primary category selection
# ===========================================================================

class TestPrimaryCategory(unittest.TestCase):

    def test_priv_esc_beats_recon(self):
        f = extract_features(privilege_escalation_session())
        findings = classify(f)
        self.assertEqual(primary_category(findings), "privilege_escalation_attempt")

    def test_download_beats_auth_abuse(self):
        f = extract_features(download_session())
        findings = classify(f)
        cat = primary_category(findings)
        # download_attempt has higher priority than authentication_abuse
        self.assertNotEqual(cat, "authentication_abuse")

    def test_unknown_for_empty_session(self):
        f = extract_features(empty_session())
        findings = classify(f)
        self.assertEqual(primary_category(findings), "unknown")

    def test_returns_string(self):
        f = extract_features(recon_session())
        findings = classify(f)
        self.assertIsInstance(primary_category(findings), str)


# ===========================================================================
# G. Scorer
# ===========================================================================

class TestScorer(unittest.TestCase):

    def test_score_is_int(self):
        f = extract_features(recon_session())
        result = compute_score(f)
        self.assertIsInstance(result["score"], int)

    def test_score_within_bounds(self):
        for fixture in [
            empty_session(), recon_session(), brute_force_session(10),
            download_session(), privilege_escalation_session(),
            credential_access_session(), multi_behaviour_session(),
        ]:
            f = extract_features(fixture)
            r = compute_score(f)
            self.assertGreaterEqual(r["score"], 0, msg=f"score < 0 for {fixture}")
            self.assertLessEqual(r["score"], 100, msg=f"score > 100 for {fixture}")

    def test_empty_session_scores_zero(self):
        f = extract_features(empty_session())
        result = compute_score(f)
        self.assertEqual(result["score"], 0)

    def test_connect_only_scores_zero(self):
        f = extract_features(connect_only())
        result = compute_score(f)
        self.assertEqual(result["score"], 0)

    def test_single_ls_scores_low(self):
        """One 'ls' (file discovery) must score below 10."""
        f = extract_features(ambiguous_ls_session())
        result = compute_score(f)
        self.assertLess(result["score"], 10)

    def test_download_scores_high(self):
        """Download command must contribute significantly to the score."""
        f = extract_features(download_session())
        result = compute_score(f)
        self.assertGreater(result["score"], 20)

    def test_priv_esc_scores_high(self):
        f = extract_features(privilege_escalation_session())
        result = compute_score(f)
        self.assertGreater(result["score"], 20)

    def test_brute_force_scores_proportionally(self):
        """More failures → higher score, up to cap."""
        f3 = compute_score(extract_features(brute_force_session(3)))
        f10 = compute_score(extract_features(brute_force_session(10)))
        self.assertLess(f3["score"], f10["score"])

    def test_severe_session_can_reach_100(self):
        """A session with many indicators must be able to saturate at 100."""
        f = extract_features(multi_behaviour_session())
        # Add more to the features directly to force saturation
        f2 = dict(f)
        f2["login_failure_count"] = 20
        f2["download_attempt_count"] = 5
        f2["privilege_escalation_count"] = 5
        f2["credential_command_count"] = 5
        result = compute_score(f2)
        self.assertEqual(result["score"], 100)

    def test_contributions_list_present(self):
        f = extract_features(recon_session())
        result = compute_score(f)
        self.assertIsInstance(result["contributions"], list)
        self.assertTrue(len(result["contributions"]) > 0)

    def test_each_contribution_has_required_keys(self):
        f = extract_features(recon_session())
        result = compute_score(f)
        for c in result["contributions"]:
            self.assertIn("factor", c)
            self.assertIn("value", c)
            self.assertIn("weight", c)
            self.assertIn("contribution", c)
            self.assertIn("capped_at", c)

    def test_explanation_is_string(self):
        f = extract_features(recon_session())
        result = compute_score(f)
        self.assertIsInstance(result["explanation"], str)

    def test_zero_score_has_explanation(self):
        f = extract_features(empty_session())
        result = compute_score(f)
        self.assertIn("0", result["explanation"])

    def test_score_is_deterministic(self):
        f = extract_features(multi_behaviour_session())
        r1 = compute_score(f)
        r2 = compute_score(f)
        self.assertEqual(r1["score"], r2["score"])

    def test_non_dict_features_scores_zero(self):
        result = compute_score(None)
        self.assertEqual(result["score"], 0)


# ===========================================================================
# H. Engine — full pipeline
# ===========================================================================

class TestEngine(unittest.TestCase):

    def _required_keys(self):
        return {
            "session_id", "engine_version", "rule_set_version",
            "features", "findings", "primary_category",
            "score", "score_contributions", "score_explanation", "warnings",
        }

    def test_result_has_all_keys(self):
        result = analyse_session(recon_session(), session_id="test-1")
        self.assertTrue(self._required_keys().issubset(set(result.keys())))

    def test_session_id_propagated(self):
        result = analyse_session(recon_session(), session_id="my-session")
        self.assertEqual(result["session_id"], "my-session")

    def test_session_id_none_when_not_provided(self):
        result = analyse_session(recon_session())
        self.assertIsNone(result["session_id"])

    def test_empty_session_produces_result(self):
        result = analyse_session(empty_session())
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["primary_category"], "unknown")
        self.assertTrue(len(result["warnings"]) > 0)

    def test_non_list_events_produces_warning(self):
        result = analyse_session(None)
        self.assertTrue(any("list" in w.lower() for w in result["warnings"]))

    def test_findings_are_list_of_dicts(self):
        result = analyse_session(recon_session())
        self.assertIsInstance(result["findings"], list)
        for f in result["findings"]:
            self.assertIn("rule_id", f)
            self.assertIn("category", f)
            self.assertIn("evidence", f)
            self.assertIn("evidence_strength", f)

    def test_score_in_range(self):
        for events in [
            empty_session(), recon_session(), brute_force_session(7),
            download_session(), privilege_escalation_session(),
        ]:
            r = analyse_session(events)
            self.assertGreaterEqual(r["score"], 0)
            self.assertLessEqual(r["score"], 100)

    def test_engine_version_is_string(self):
        r = analyse_session(recon_session())
        self.assertIsInstance(r["engine_version"], str)

    def test_rule_set_version_is_string(self):
        r = analyse_session(recon_session())
        self.assertIsInstance(r["rule_set_version"], str)

    def test_deterministic_output(self):
        events = multi_behaviour_session()
        r1 = analyse_session(events, session_id="x")
        r2 = analyse_session(events, session_id="x")
        self.assertEqual(r1["score"], r2["score"])
        self.assertEqual(r1["primary_category"], r2["primary_category"])
        r1_rule_ids = [f["rule_id"] for f in r1["findings"]]
        r2_rule_ids = [f["rule_id"] for f in r2["findings"]]
        self.assertEqual(r1_rule_ids, r2_rule_ids)

    def test_result_is_json_serializable(self):
        result = analyse_session(multi_behaviour_session(), session_id="json-test")
        try:
            json.dumps(result)
        except (TypeError, ValueError) as exc:
            self.fail(f"Result is not JSON-serializable: {exc}")

    def test_features_dict_in_result(self):
        result = analyse_session(recon_session())
        self.assertIsInstance(result["features"], dict)
        self.assertIn("recon_command_count", result["features"])

    def test_brute_force_primary_category(self):
        result = analyse_session(brute_force_session(7))
        self.assertEqual(result["primary_category"], "authentication_abuse")

    def test_download_primary_category(self):
        result = analyse_session(download_session())
        self.assertEqual(result["primary_category"], "download_attempt")

    def test_priv_esc_primary_category(self):
        result = analyse_session(privilege_escalation_session())
        self.assertEqual(result["primary_category"], "privilege_escalation_attempt")


# ===========================================================================
# I. Engine — multi-session
# ===========================================================================

class TestEngineMultiSession(unittest.TestCase):

    def test_two_sessions_analysed(self):
        results = analyse_all_sessions(two_session_events())
        self.assertEqual(len(results), 2)

    def test_session_ids_propagated(self):
        results = analyse_all_sessions(two_session_events())
        sids = {r["session_id"] for r in results}
        self.assertIn("sess-alpha", sids)
        self.assertIn("sess-beta", sids)

    def test_sessions_sorted_by_id(self):
        results = analyse_all_sessions(two_session_events())
        ids = [r["session_id"] for r in results]
        self.assertEqual(ids, sorted(ids))

    def test_empty_events_returns_empty_list(self):
        results = analyse_all_sessions([])
        # No events means one "None" session group if all have no session_id,
        # but with our fixtures no events → empty
        for r in results:
            self.assertEqual(r["score"], 0)

    def test_each_result_json_serializable(self):
        for r in analyse_all_sessions(two_session_events()):
            try:
                json.dumps(r)
            except (TypeError, ValueError) as exc:
                self.fail(f"Result not JSON-serializable: {exc}")


# ===========================================================================
# J. CLI smoke tests
# ===========================================================================

class TestCLI(unittest.TestCase):

    def _write_events(self, directory: str, events: list) -> Path:
        path = Path(directory) / "events.json"
        path.write_text(json.dumps(events), encoding="utf-8")
        return path

    def test_cli_runs_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_events(td, recon_session())
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path)],
                capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_cli_output_contains_session_header(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_events(td, recon_session())
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path)],
                capture_output=True, text=True, check=True,
            )
        self.assertIn("Score", result.stdout)
        self.assertIn("Category", result.stdout)

    def test_cli_json_output_written(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_events(td, brute_force_session(7))
            out = Path(td) / "results.json"
            subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path),
                 "--output", str(out)],
                capture_output=True, text=True, check=True,
            )
            data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertIn("score", data[0])

    def test_cli_refuses_to_overwrite_input(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_events(td, recon_session())
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path),
                 "--output", str(path)],
                capture_output=True, text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR", result.stderr)

    def test_cli_json_only_requires_output(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_events(td, recon_session())
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path), "--json-only"],
                capture_output=True, text=True,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_missing_file_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "analysis.cli", "/nonexistent/path.json"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_invalid_json_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.json"
            path.write_text("{not valid json}", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path)],
                capture_output=True, text=True,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_no_features_flag_suppresses_features(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write_events(td, recon_session())
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path), "--no-features"],
                capture_output=True, text=True, check=True,
            )
        self.assertNotIn("recon_command_count", result.stdout)

    def test_cli_empty_events_array_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "empty.json"
            path.write_text("[]", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "analysis.cli", str(path)],
                capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
