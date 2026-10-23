"""
Tests for parser.cowrie_parser

All fixtures are synthetic; no raw captured attacker data is used.
IPs are RFC 5737 documentation addresses (192.0.2.x).
Timestamps are clearly fictional (2026-xx-xx).
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from parser.cowrie_parser import (
    ParseWarning,
    normalize_timestamp,
    normalize_event,
    parse_cowrie_log,
    group_events_by_session,
    summarize_session,
    build_session_summaries,
    save_json,
)


# ============================================================
# Helpers
# ============================================================

#: Minimal valid raw event dict used across many tests.
_CONNECT_RAW = {
    "session": "aabbccdd0001",
    "src_ip": "192.0.2.1",
    "dst_ip": "192.0.2.10",
    "dst_port": 2222,
    "eventid": "cowrie.session.connect",
    "timestamp": "2026-01-15T10:00:00Z",
}

_COMMAND_RAW = {
    "session": "aabbccdd0001",
    "src_ip": "192.0.2.1",
    "dst_ip": "192.0.2.10",
    "dst_port": 2222,
    "eventid": "cowrie.command.input",
    "input": "whoami",
    "timestamp": "2026-01-15T10:01:00Z",
}


def _write_jsonl(directory, lines):
    """Write *lines* (each a dict or a raw string) to a temp cowrie.json."""
    path = Path(directory) / "cowrie.json"
    with path.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(
                (json.dumps(line) if isinstance(line, dict) else line) + "\n"
            )
    return path


# ============================================================
# A. normalize_timestamp
# ============================================================

class TestNormalizeTimestamp(unittest.TestCase):

    def test_z_suffix_converted_to_utc(self):
        result = normalize_timestamp("2026-01-15T10:00:00Z")
        self.assertTrue(result.endswith("+00:00"))

    def test_explicit_offset_preserved_as_utc(self):
        result = normalize_timestamp("2026-01-15T10:00:00+05:30")
        # Should be shifted to UTC: 10:00 IST = 04:30 UTC
        self.assertIn("04:30:00+00:00", result)

    def test_naive_timestamp_assumed_utc(self):
        result = normalize_timestamp("2026-01-15T10:00:00")
        self.assertTrue(result.endswith("+00:00"))

    def test_microseconds_preserved(self):
        result = normalize_timestamp("2026-01-15T10:00:00.123456Z")
        self.assertIn("123456", result)

    def test_non_string_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_timestamp(12345)

    def test_none_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_timestamp(None)

    def test_empty_string_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_timestamp("")

    def test_whitespace_only_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_timestamp("   ")

    def test_garbage_string_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_timestamp("not-a-date")

    def test_partial_date_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_timestamp("2026-01")


# ============================================================
# B. normalize_event — valid events
# ============================================================

class TestNormalizeEventValid(unittest.TestCase):

    def test_session_connect(self):
        event = normalize_event(_CONNECT_RAW)
        self.assertEqual(event["event_type"], "session_connect")
        self.assertEqual(event["session_id"], "aabbccdd0001")
        self.assertEqual(event["source_ip"], "192.0.2.1")
        self.assertEqual(event["destination_ip"], "192.0.2.10")
        self.assertEqual(event["destination_port"], 2222)

    def test_session_closed(self):
        raw = {**_CONNECT_RAW, "eventid": "cowrie.session.closed"}
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "session_closed")

    def test_session_params(self):
        raw = {**_CONNECT_RAW, "eventid": "cowrie.session.params"}
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "session_params")

    def test_login_success(self):
        raw = {
            **_CONNECT_RAW,
            "eventid": "cowrie.login.success",
            "username": "admin",
        }
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "login")
        self.assertEqual(event["username"], "admin")
        self.assertTrue(event["success"])

    def test_login_failed(self):
        raw = {
            **_CONNECT_RAW,
            "eventid": "cowrie.login.failed",
            "username": "admin",
        }
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "login")
        self.assertFalse(event["success"])

    def test_command_input(self):
        event = normalize_event(_COMMAND_RAW)
        self.assertEqual(event["event_type"], "command")
        self.assertEqual(event["command"], "whoami")

    def test_command_failed(self):
        raw = {**_COMMAND_RAW, "eventid": "cowrie.command.failed", "input": "badsync"}
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "command_failed")
        self.assertEqual(event["command"], "badsync")

    def test_client_version_metadata(self):
        raw = {
            **_CONNECT_RAW,
            "eventid": "cowrie.client.version",
            "version": "SSH-2.0-OpenSSH_8.9",
        }
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "client_metadata")
        self.assertIn("version", event["metadata"])
        self.assertEqual(event["metadata"]["version"], "SSH-2.0-OpenSSH_8.9")

    def test_client_kex_metadata(self):
        raw = {**_CONNECT_RAW, "eventid": "cowrie.client.kex", "kex": "curve25519"}
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "client_metadata")

    def test_client_metadata_excluded_fields_absent(self):
        """Sensor/UUID/message fields must not appear in the metadata dict."""
        raw = {
            **_CONNECT_RAW,
            "eventid": "cowrie.client.version",
            "version": "SSH-2.0-OpenSSH_8.9",
            "sensor": "my-sensor",
            "uuid": "abc-123",
            "message": "new connection",
        }
        event = normalize_event(raw)
        self.assertNotIn("sensor", event["metadata"])
        self.assertNotIn("uuid", event["metadata"])
        self.assertNotIn("message", event["metadata"])

    def test_log_closed(self):
        raw = {**_CONNECT_RAW, "eventid": "cowrie.log.closed"}
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "log_closed")

    def test_unknown_event_type_preserved(self):
        raw = {**_CONNECT_RAW, "eventid": "cowrie.some.future.event"}
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "other")
        self.assertEqual(event["original_event_id"], "cowrie.some.future.event")

    def test_missing_eventid_treated_as_other(self):
        raw = {**_CONNECT_RAW}
        del raw["eventid"]
        event = normalize_event(raw)
        self.assertEqual(event["event_type"], "other")

    def test_z_timestamp_normalized(self):
        event = normalize_event(_CONNECT_RAW)
        self.assertTrue(event["timestamp"].endswith("+00:00"))


# ============================================================
# C. normalize_event — invalid inputs
# ============================================================

class TestNormalizeEventInvalid(unittest.TestCase):

    def test_missing_timestamp_raises_key_error(self):
        raw = {k: v for k, v in _CONNECT_RAW.items() if k != "timestamp"}
        with self.assertRaises(KeyError):
            normalize_event(raw)

    def test_invalid_timestamp_raises_value_error(self):
        raw = {**_CONNECT_RAW, "timestamp": "not-a-date"}
        with self.assertRaises(ValueError):
            normalize_event(raw)

    def test_numeric_timestamp_raises_value_error(self):
        raw = {**_CONNECT_RAW, "timestamp": 1234567890}
        with self.assertRaises(ValueError):
            normalize_event(raw)

    def test_non_dict_input_raises_type_error(self):
        with self.assertRaises(TypeError):
            normalize_event("not a dict")

    def test_list_input_raises_type_error(self):
        with self.assertRaises(TypeError):
            normalize_event([1, 2, 3])


# ============================================================
# D. parse_cowrie_log — valid input
# ============================================================

class TestParseCowrieLogValid(unittest.TestCase):

    def test_two_valid_events_returns_both(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [_CONNECT_RAW, _COMMAND_RAW])
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(len(warnings), 0)
        self.assertEqual(events[0]["event_type"], "session_connect")
        self.assertEqual(events[1]["event_type"], "command")
        self.assertEqual(events[1]["command"], "whoami")

    def test_blank_lines_skipped_silently(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            with path.open("w", encoding="utf-8") as fh:
                fh.write("\n")
                fh.write(json.dumps(_CONNECT_RAW) + "\n")
                fh.write("\n\n")
                fh.write(json.dumps(_COMMAND_RAW) + "\n")
                fh.write("\n")
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(len(warnings), 0)

    def test_no_trailing_newline(self):
        """A valid JSON line with no trailing newline must be accepted."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            with path.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps(_CONNECT_RAW))  # no trailing \n
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 1)
        self.assertEqual(len(warnings), 0)

    def test_empty_file_returns_empty_lists(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            path.write_text("", encoding="utf-8")
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(events, [])
        self.assertEqual(warnings, [])

    def test_only_blank_lines_returns_empty_lists(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            path.write_text("\n\n\n", encoding="utf-8")
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(events, [])
        self.assertEqual(warnings, [])

    def test_return_type_is_tuple_of_two_lists(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [_CONNECT_RAW])
            result = parse_cowrie_log(path)

        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        events, warnings = result
        self.assertIsInstance(events, list)
        self.assertIsInstance(warnings, list)


# ============================================================
# E. parse_cowrie_log — invalid / mixed input
# ============================================================

class TestParseCowrieLogInvalid(unittest.TestCase):

    def test_malformed_json_skipped_with_warning(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            with path.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps(_CONNECT_RAW) + "\n")
                fh.write("{this is not json}\n")
                fh.write(json.dumps(_COMMAND_RAW) + "\n")
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].line_number, 2)
        self.assertIn("Invalid JSON", warnings[0].reason)

    def test_missing_timestamp_field_skipped_with_warning(self):
        raw_no_ts = {k: v for k, v in _CONNECT_RAW.items() if k != "timestamp"}
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [raw_no_ts])
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 0)
        self.assertEqual(len(warnings), 1)
        self.assertIn("timestamp", warnings[0].reason)

    def test_invalid_timestamp_value_skipped_with_warning(self):
        raw_bad_ts = {**_CONNECT_RAW, "timestamp": "not-a-date"}
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [raw_bad_ts])
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 0)
        self.assertEqual(len(warnings), 1)

    def test_numeric_timestamp_skipped_with_warning(self):
        raw_num_ts = {**_CONNECT_RAW, "timestamp": 9999999}
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [raw_num_ts])
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 0)
        self.assertEqual(len(warnings), 1)

    def test_json_array_line_skipped_with_warning(self):
        """A line whose top-level value is a JSON array, not an object."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            with path.open("w", encoding="utf-8") as fh:
                fh.write('[1, 2, 3]\n')
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 0)
        self.assertEqual(len(warnings), 1)
        self.assertIn("JSON object", warnings[0].reason)

    def test_json_string_line_skipped_with_warning(self):
        """A line whose top-level value is a JSON string, not an object."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            with path.open("w", encoding="utf-8") as fh:
                fh.write('"just a string"\n')
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 0)
        self.assertEqual(len(warnings), 1)

    def test_truncated_json_at_end_skipped_with_warning(self):
        """Simulates a file truncated mid-write — the incomplete line is skipped."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cowrie.json"
            with path.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps(_CONNECT_RAW) + "\n")
                # Truncated line — valid JSON object cut off mid-field
                fh.write('{"eventid": "cowrie.command.input", "timestamp": "202')
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 1)
        self.assertEqual(len(warnings), 1)
        self.assertIn("Invalid JSON", warnings[0].reason)

    def test_mixed_valid_and_invalid_lines(self):
        """Valid lines before and after bad lines are all collected."""
        raw_bad_ts = {**_CONNECT_RAW, "timestamp": "BADTS"}
        raw_no_ts = {k: v for k, v in _COMMAND_RAW.items() if k != "timestamp"}
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [
                _CONNECT_RAW,   # valid
                raw_bad_ts,     # bad timestamp → warning
                "{bad json}",   # malformed JSON → warning
                raw_no_ts,      # missing timestamp → warning
                _COMMAND_RAW,   # valid
            ])
            events, warnings = parse_cowrie_log(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(len(warnings), 3)

    def test_warning_namedtuple_fields(self):
        """ParseWarning must expose .line_number and .reason."""
        raw_bad = {**_CONNECT_RAW, "timestamp": "BADTS"}
        with tempfile.TemporaryDirectory() as td:
            path = _write_jsonl(td, [raw_bad])
            _, warnings = parse_cowrie_log(path)

        self.assertEqual(len(warnings), 1)
        w = warnings[0]
        self.assertIsInstance(w, ParseWarning)
        self.assertIsInstance(w.line_number, int)
        self.assertIsInstance(w.reason, str)


# ============================================================
# F. Session grouping
# ============================================================

class TestSessionGrouping(unittest.TestCase):

    def test_two_sessions_grouped_correctly(self):
        events = [
            {"session_id": "sess-a", "event_type": "command", "command": "pwd"},
            {"session_id": "sess-b", "event_type": "command", "command": "ls"},
            {"session_id": "sess-a", "event_type": "command", "command": "whoami"},
        ]
        sessions = group_events_by_session(events)
        self.assertEqual(len(sessions), 2)
        self.assertEqual(len(sessions["sess-a"]), 2)
        self.assertEqual(len(sessions["sess-b"]), 1)

    def test_event_with_none_session_id_dropped(self):
        events = [
            {"session_id": "sess-a", "event_type": "command", "command": "pwd"},
            {"session_id": None, "event_type": "other"},
        ]
        sessions = group_events_by_session(events)
        self.assertEqual(list(sessions.keys()), ["sess-a"])

    def test_event_missing_session_key_dropped(self):
        events = [
            {"session_id": "sess-a", "event_type": "command", "command": "pwd"},
            {"event_type": "other"},  # no session_id key at all
        ]
        sessions = group_events_by_session(events)
        self.assertEqual(list(sessions.keys()), ["sess-a"])

    def test_single_session(self):
        events = [
            {"session_id": "sess-a", "event_type": "session_connect"},
            {"session_id": "sess-a", "event_type": "command", "command": "id"},
        ]
        sessions = group_events_by_session(events)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(sessions["sess-a"]), 2)

    def test_empty_event_list(self):
        sessions = group_events_by_session([])
        self.assertEqual(sessions, {})


# ============================================================
# G. Session summary
# ============================================================

class TestSessionSummary(unittest.TestCase):

    def _make_events(self):
        return [
            {
                "timestamp": "2026-01-15T10:00:00+00:00",
                "session_id": "sess-a",
                "event_type": "session_connect",
                "source_ip": "192.0.2.1",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
            },
            {
                "timestamp": "2026-01-15T10:01:00+00:00",
                "session_id": "sess-a",
                "event_type": "login",
                "source_ip": "192.0.2.1",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
                "username": "root",
                "success": True,
            },
            {
                "timestamp": "2026-01-15T10:02:00+00:00",
                "session_id": "sess-a",
                "event_type": "command",
                "source_ip": "192.0.2.1",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
                "command": "whoami",
            },
            {
                "timestamp": "2026-01-15T10:03:00+00:00",
                "session_id": "sess-a",
                "event_type": "command_failed",
                "source_ip": "192.0.2.1",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
                "command": "badsync",
            },
        ]

    def test_counts(self):
        summary = summarize_session("sess-a", self._make_events())
        self.assertEqual(summary["event_count"], 4)
        self.assertEqual(summary["command_count"], 1)
        self.assertEqual(summary["failed_command_count"], 1)

    def test_command_lists(self):
        summary = summarize_session("sess-a", self._make_events())
        self.assertEqual(summary["commands"], ["whoami"])
        self.assertEqual(summary["failed_commands"], ["badsync"])

    def test_usernames(self):
        summary = summarize_session("sess-a", self._make_events())
        self.assertEqual(summary["usernames"], ["root"])

    def test_time_bounds(self):
        summary = summarize_session("sess-a", self._make_events())
        self.assertEqual(summary["start_time"], "2026-01-15T10:00:00+00:00")
        self.assertEqual(summary["end_time"], "2026-01-15T10:03:00+00:00")

    def test_network_fields(self):
        summary = summarize_session("sess-a", self._make_events())
        self.assertEqual(summary["source_ips"], ["192.0.2.1"])
        self.assertEqual(summary["destination_ips"], ["192.0.2.10"])
        self.assertEqual(summary["destination_ports"], [2222])

    def test_empty_session(self):
        summary = summarize_session("sess-x", [])
        self.assertEqual(summary["event_count"], 0)
        self.assertIsNone(summary["start_time"])
        self.assertIsNone(summary["end_time"])
        self.assertEqual(summary["commands"], [])

    def test_session_id_propagated(self):
        summary = summarize_session("my-session", self._make_events())
        self.assertEqual(summary["session_id"], "my-session")


# ============================================================
# H. build_session_summaries
# ============================================================

class TestBuildSessionSummaries(unittest.TestCase):

    def test_sorted_by_start_time(self):
        events = [
            {
                "timestamp": "2026-01-15T10:05:00+00:00",
                "session_id": "sess-b",
                "event_type": "session_connect",
                "source_ip": "192.0.2.2",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
            },
            {
                "timestamp": "2026-01-15T10:00:00+00:00",
                "session_id": "sess-a",
                "event_type": "session_connect",
                "source_ip": "192.0.2.1",
                "destination_ip": "192.0.2.10",
                "destination_port": 2222,
            },
        ]
        summaries = build_session_summaries(events)
        self.assertEqual(summaries[0]["session_id"], "sess-a")
        self.assertEqual(summaries[1]["session_id"], "sess-b")

    def test_empty_input(self):
        self.assertEqual(build_session_summaries([]), [])


# ============================================================
# I. save_json
# ============================================================

class TestSaveJson(unittest.TestCase):

    def test_round_trip(self):
        data = {"key": "value", "number": 42}
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "output.json"
            save_json(data, path)
            result = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result, data)

    def test_creates_parent_directories(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "nested" / "deep" / "output.json"
            save_json([], path)
            self.assertTrue(path.exists())

    def test_indented_output(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "output.json"
            save_json({"a": 1}, path)
            text = path.read_text(encoding="utf-8")
        # Formatted JSON must have indentation
        self.assertIn("\n", text)


# ============================================================
# J. CLI smoke test
# ============================================================

class TestCLI(unittest.TestCase):

    def _make_log(self, directory, events):
        return _write_jsonl(directory, events)

    def test_cli_runs_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            log = self._make_log(td, [_CONNECT_RAW, _COMMAND_RAW])
            events_out = Path(td) / "events.json"
            sessions_out = Path(td) / "sessions.json"

            result = subprocess.run(
                [
                    sys.executable, "-m", "parser.cowrie_parser",
                    str(log),
                    "--events-output", str(events_out),
                    "--sessions-output", str(sessions_out),
                ],
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Parsed 2 events", result.stdout)
        self.assertIn("Identified 1 session", result.stdout)

    def test_cli_strict_flag_exits_nonzero_on_bad_line(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "cowrie.json"
            with log.open("w", encoding="utf-8") as fh:
                fh.write("{bad json}\n")
            events_out = Path(td) / "events.json"
            sessions_out = Path(td) / "sessions.json"

            result = subprocess.run(
                [
                    sys.executable, "-m", "parser.cowrie_parser",
                    str(log),
                    "--events-output", str(events_out),
                    "--sessions-output", str(sessions_out),
                    "--strict",
                ],
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WARNING", result.stderr)

    def test_cli_output_files_created(self):
        with tempfile.TemporaryDirectory() as td:
            log = self._make_log(td, [_CONNECT_RAW])
            events_out = Path(td) / "events.json"
            sessions_out = Path(td) / "sessions.json"

            subprocess.run(
                [
                    sys.executable, "-m", "parser.cowrie_parser",
                    str(log),
                    "--events-output", str(events_out),
                    "--sessions-output", str(sessions_out),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            events = json.loads(events_out.read_text(encoding="utf-8"))
            sessions = json.loads(sessions_out.read_text(encoding="utf-8"))

        self.assertEqual(len(events), 1)
        self.assertEqual(len(sessions), 1)


if __name__ == "__main__":
    unittest.main()
