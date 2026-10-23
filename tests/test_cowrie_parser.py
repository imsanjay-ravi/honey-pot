import json
import tempfile
import unittest
from pathlib import Path

from parser.cowrie_parser import (
    normalize_event,
    parse_cowrie_log,
    group_events_by_session,
    summarize_session,
    build_session_summaries,
)


class TestNormalizeEvent(unittest.TestCase):

    def test_command_event(self):
        raw = {
            "session": "test-session",
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "dst_port": 2222,
            "eventid": "cowrie.command.input",
            "input": "ls",
            "timestamp": "2026-08-23T21:00:00Z",
        }

        event = normalize_event(raw)

        self.assertEqual(event["event_type"], "command")
        self.assertEqual(event["command"], "ls")
        self.assertEqual(event["session_id"], "test-session")
        self.assertEqual(event["source_ip"], "10.10.10.20")
        self.assertEqual(event["destination_port"], 2222)


    def test_login_success(self):
        raw = {
            "session": "test-session",
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "dst_port": 2222,
            "eventid": "cowrie.login.success",
            "username": "root",
            "timestamp": "2026-08-23T21:00:00Z",
        }

        event = normalize_event(raw)

        self.assertEqual(event["event_type"], "login")
        self.assertEqual(event["username"], "root")
        self.assertTrue(event["success"])


    def test_login_failed(self):
        raw = {
            "session": "test-session",
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "dst_port": 2222,
            "eventid": "cowrie.login.failed",
            "username": "root",
            "timestamp": "2026-08-23T21:00:00Z",
        }

        event = normalize_event(raw)

        self.assertEqual(event["event_type"], "login")
        self.assertFalse(event["success"])


    def test_client_metadata(self):
        raw = {
            "session": "test-session",
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "dst_port": 2222,
            "eventid": "cowrie.client.version",
            "version": "SSH-2.0-OpenSSH",
            "timestamp": "2026-08-23T21:00:00Z",
        }

        event = normalize_event(raw)

        self.assertEqual(
            event["event_type"],
            "client_metadata"
        )

        self.assertIn(
            "version",
            event["metadata"]
        )


    def test_unknown_event(self):
        raw = {
            "session": "test-session",
            "eventid": "cowrie.some.future.event",
            "timestamp": "2026-08-23T21:00:00Z",
        }

        event = normalize_event(raw)

        self.assertEqual(
            event["event_type"],
            "other"
        )

        self.assertEqual(
            event["original_event_id"],
            "cowrie.some.future.event"
        )


class TestSessionGrouping(unittest.TestCase):

    def test_group_events_by_session(self):

        events = [
            {
                "session_id": "session-a",
                "event_type": "command",
                "command": "pwd",
            },
            {
                "session_id": "session-b",
                "event_type": "command",
                "command": "ls",
            },
            {
                "session_id": "session-a",
                "event_type": "command",
                "command": "whoami",
            },
        ]

        sessions = group_events_by_session(events)

        self.assertEqual(
            len(sessions),
            2
        )

        self.assertEqual(
            len(sessions["session-a"]),
            2
        )

        self.assertEqual(
            len(sessions["session-b"]),
            1
        )


class TestSessionSummary(unittest.TestCase):

    def test_session_summary(self):

        events = [
            {
                "timestamp": "2026-08-23T21:00:00+00:00",
                "session_id": "session-a",
                "event_type": "session_connect",
                "source_ip": "10.10.10.20",
                "destination_ip": "10.10.10.10",
                "destination_port": 2222,
            },
            {
                "timestamp": "2026-08-23T21:01:00+00:00",
                "session_id": "session-a",
                "event_type": "command",
                "source_ip": "10.10.10.20",
                "destination_ip": "10.10.10.10",
                "destination_port": 2222,
                "command": "whoami",
            },
            {
                "timestamp": "2026-08-23T21:02:00+00:00",
                "session_id": "session-a",
                "event_type": "command_failed",
                "source_ip": "10.10.10.20",
                "destination_ip": "10.10.10.10",
                "destination_port": 2222,
                "command": "whowho",
            },
        ]

        summary = summarize_session(
            "session-a",
            events
        )

        self.assertEqual(
            summary["session_id"],
            "session-a"
        )

        self.assertEqual(
            summary["event_count"],
            3
        )

        self.assertEqual(
            summary["command_count"],
            1
        )

        self.assertEqual(
            summary["failed_command_count"],
            1
        )

        self.assertEqual(
            summary["commands"],
            ["whoami"]
        )

        self.assertEqual(
            summary["failed_commands"],
            ["whowho"]
        )


class TestParser(unittest.TestCase):

    def test_parse_cowrie_log(self):

        raw_events = [
            {
                "session": "session-a",
                "src_ip": "10.10.10.20",
                "dst_ip": "10.10.10.10",
                "dst_port": 2222,
                "eventid": "cowrie.session.connect",
                "timestamp": "2026-08-23T21:00:00Z",
            },
            {
                "session": "session-a",
                "src_ip": "10.10.10.20",
                "dst_ip": "10.10.10.10",
                "dst_port": 2222,
                "eventid": "cowrie.command.input",
                "input": "pwd",
                "timestamp": "2026-08-23T21:01:00Z",
            },
        ]

        with tempfile.TemporaryDirectory() as directory:

            input_file = Path(directory) / "cowrie.json"

            with input_file.open(
                "w",
                encoding="utf-8"
            ) as file:

                for event in raw_events:
                    file.write(
                        json.dumps(event) + "\n"
                    )

            events = parse_cowrie_log(
                input_file
            )

            self.assertEqual(
                len(events),
                2
            )

            self.assertEqual(
                events[0]["event_type"],
                "session_connect"
            )

            self.assertEqual(
                events[1]["event_type"],
                "command"
            )

            self.assertEqual(
                events[1]["command"],
                "pwd"
            )


if __name__ == "__main__":
    unittest.main()
