"""
analysis/features.py — Feature extraction from normalized Cowrie events.

This module converts a list of normalized event dicts (as produced by
parser.cowrie_parser) into a flat, typed feature dict.  Feature extraction
is deliberately kept separate from classification so it can be tested,
logged, and evolved independently.

Feature names and definitions
------------------------------
All features operate on the *normalized* event schema (timestamp,
session_id, event_type, source_ip, destination_ip, destination_port,
command, username, success, metadata, original_event_id).

Core counts
  total_events          int   Total events in the session.
  session_duration_s    float Seconds between first and last timestamp,
                              or None when fewer than two timestamps exist.
  command_count         int   Events with event_type == "command".
  failed_command_count  int   Events with event_type == "command_failed".
  login_attempt_count   int   Events with event_type == "login".
  login_success_count   int   Login events where success == True.
  login_failure_count   int   Login events where success == False.
  other_event_count     int   Events with event_type == "other".
  unknown_event_count   int   Alias for other_event_count (legacy name).

Command-category indicators (bool — True if at least one match found)
  has_recon_commands          id, whoami, uname, hostname, ifconfig, ip,
                              netstat, ss, arp, cat /etc/passwd, cat
                              /etc/shadow, cat /etc/hosts, w, who, last,
                              uptime, env, printenv, set
  has_file_discovery          ls, find, locate, dir, tree, stat, file,
                              lsof, du, df
  has_download_attempt        wget, curl, tftp, scp, sftp, nc, ncat,
                              python -c (with http/url body), fetch, axel
  has_privilege_escalation    sudo, su, chmod +s, chown root, passwd,
                              usermod, adduser, visudo, echo >> /etc/sudoers
  has_credential_commands     cat /etc/passwd, cat /etc/shadow,
                              grep passwd, grep shadow, cat ~/.ssh,
                              cat /root/.ssh

Quantity counts (int)
  recon_command_count         Number of commands matching recon patterns.
  file_discovery_count        Number of commands matching file-discovery.
  download_attempt_count      Number of commands matching download patterns.
  privilege_escalation_count  Number of commands matching priv-esc patterns.
  credential_command_count    Number of commands matching credential access.

Usernames
  unique_username_count   int   Distinct usernames tried across all login events.
  has_root_login          bool  Any login attempt used the username "root".

Safety note
-----------
Commands are treated as untrusted text.  No command string is executed,
evaluated, or passed to a shell.  Matching is done with str.startswith()
and substring search (__contains__) on the already-normalized command
string.  The command string is lower-cased for matching only; the original
value is never altered.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

# Each entry is a tuple of lowercase string prefixes or substrings.
# Matching uses: cmd.startswith(prefix) OR substring in cmd.
# Entries with a trailing space prevent partial-word matches where needed.

_RECON_PREFIXES: tuple[str, ...] = (
    "id",
    "whoami",
    "uname",
    "hostname",
    "ifconfig",
    "ip ",
    "ip\t",
    "netstat",
    "ss ",
    "ss\t",
    "arp",
    "w ",
    "w\t",
    "who",
    "last",
    "uptime",
    "env",
    "printenv",
    "set",
)

_RECON_SUBSTRINGS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/os-release",
    "/proc/version",
)

_FILE_DISCOVERY_PREFIXES: tuple[str, ...] = (
    "ls",
    "find ",
    "find\t",
    "locate ",
    "dir ",
    "tree",
    "stat ",
    "stat\t",
    "file ",
    "lsof",
    "du ",
    "du\t",
    "df ",
    "df\t",
)

_DOWNLOAD_PREFIXES: tuple[str, ...] = (
    "wget",
    "curl",
    "tftp",
    "scp ",
    "sftp",
    "nc ",
    "nc\t",
    "ncat",
    "fetch ",
    "axel ",
)

_DOWNLOAD_SUBSTRINGS: tuple[str, ...] = (
    "http://",
    "https://",
    "ftp://",
)

_PRIV_ESC_PREFIXES: tuple[str, ...] = (
    "sudo",
    "su ",
    "su\t",
    "passwd",
    "usermod",
    "adduser",
    "visudo",
    "chown root",
)

_PRIV_ESC_SUBSTRINGS: tuple[str, ...] = (
    "chmod +s",
    "/etc/sudoers",
)

_CREDENTIAL_PREFIXES: tuple[str, ...] = (
    "grep passwd",
    "grep shadow",
)

_CREDENTIAL_SUBSTRINGS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/.ssh",
    "/root/.ssh",
    "id_rsa",
    "authorized_keys",
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _matches(cmd: str, prefixes: tuple[str, ...], substrings: tuple[str, ...]) -> bool:
    """Return True if *cmd* (already lowercased) matches any prefix or substring."""
    for p in prefixes:
        if cmd.startswith(p):
            return True
    for s in substrings:
        if s in cmd:
            return True
    return False


def _parse_utc(ts: str | None) -> datetime | None:
    """Parse an ISO-8601 UTC timestamp string safely; return None on failure."""
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(events: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Extract a flat feature dict from a list of normalized event dicts.

    Parameters
    ----------
    events:
        List of normalized event dicts as returned by
        ``parser.cowrie_parser.normalize_event`` (or
        ``parse_cowrie_log``).  May be empty.

    Returns
    -------
    dict
        Feature dict with all keys described in this module's docstring.
        Never raises; missing or malformed values produce safe defaults.
    """

    if not isinstance(events, list):
        events = []

    total_events = len(events)

    # ----------------------------------------------------------------
    # Timestamps → session duration
    # ----------------------------------------------------------------
    timestamps: list[datetime] = []
    for ev in events:
        dt = _parse_utc(ev.get("timestamp"))
        if dt is not None:
            timestamps.append(dt)

    if len(timestamps) >= 2:
        session_duration_s: float | None = (
            max(timestamps) - min(timestamps)
        ).total_seconds()
    else:
        session_duration_s = None

    # ----------------------------------------------------------------
    # Command lists (safe: strings only, never executed)
    # ----------------------------------------------------------------
    commands: list[str] = []
    for ev in events:
        if ev.get("event_type") == "command":
            cmd = ev.get("command")
            if isinstance(cmd, str):
                commands.append(cmd)

    failed_commands: list[str] = []
    for ev in events:
        if ev.get("event_type") == "command_failed":
            cmd = ev.get("command")
            if isinstance(cmd, str):
                failed_commands.append(cmd)

    # ----------------------------------------------------------------
    # Login counts
    # ----------------------------------------------------------------
    login_attempts = [
        ev for ev in events if ev.get("event_type") == "login"
    ]
    login_success_count = sum(
        1 for ev in login_attempts if ev.get("success") is True
    )
    login_failure_count = sum(
        1 for ev in login_attempts if ev.get("success") is False
    )

    # ----------------------------------------------------------------
    # Other/unknown events
    # ----------------------------------------------------------------
    other_count = sum(
        1 for ev in events if ev.get("event_type") == "other"
    )

    # ----------------------------------------------------------------
    # Command-category matching (lowercase only for matching)
    # ----------------------------------------------------------------
    recon_count = 0
    file_disc_count = 0
    dl_count = 0
    priv_esc_count = 0
    cred_count = 0

    for raw_cmd in commands:
        cmd = raw_cmd.lower().strip()
        if _matches(cmd, _RECON_PREFIXES, _RECON_SUBSTRINGS):
            recon_count += 1
        if _matches(cmd, _FILE_DISCOVERY_PREFIXES, ()):
            file_disc_count += 1
        if _matches(cmd, _DOWNLOAD_PREFIXES, _DOWNLOAD_SUBSTRINGS):
            dl_count += 1
        if _matches(cmd, _PRIV_ESC_PREFIXES, _PRIV_ESC_SUBSTRINGS):
            priv_esc_count += 1
        if _matches(cmd, _CREDENTIAL_PREFIXES, _CREDENTIAL_SUBSTRINGS):
            cred_count += 1

    # ----------------------------------------------------------------
    # Usernames
    # ----------------------------------------------------------------
    usernames: set[str] = set()
    for ev in login_attempts:
        u = ev.get("username")
        if isinstance(u, str) and u:
            usernames.add(u)

    return {
        # Core counts
        "total_events": total_events,
        "session_duration_s": session_duration_s,
        "command_count": len(commands),
        "failed_command_count": len(failed_commands),
        "login_attempt_count": len(login_attempts),
        "login_success_count": login_success_count,
        "login_failure_count": login_failure_count,
        "other_event_count": other_count,
        "unknown_event_count": other_count,  # alias
        # Command-category booleans
        "has_recon_commands": recon_count > 0,
        "has_file_discovery": file_disc_count > 0,
        "has_download_attempt": dl_count > 0,
        "has_privilege_escalation": priv_esc_count > 0,
        "has_credential_commands": cred_count > 0,
        # Command-category counts
        "recon_command_count": recon_count,
        "file_discovery_count": file_disc_count,
        "download_attempt_count": dl_count,
        "privilege_escalation_count": priv_esc_count,
        "credential_command_count": cred_count,
        # Usernames
        "unique_username_count": len(usernames),
        "has_root_login": "root" in usernames,
    }
