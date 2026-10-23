import argparse
import json
import sys
from collections import defaultdict, namedtuple
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# Parse warning record
# ============================================================

#: Returned alongside events from parse_cowrie_log() for every
#: line that was skipped due to a recoverable error.
ParseWarning = namedtuple("ParseWarning", ["line_number", "reason"])


# ============================================================
# Timestamp handling
# ============================================================

def normalize_timestamp(timestamp):
    """
    Convert a Cowrie timestamp string into UTC ISO-8601 format.

    Raises:
        ValueError: if *timestamp* is not a string or cannot be parsed
                    as an ISO-8601 datetime.
    """

    if not isinstance(timestamp, str):
        raise ValueError(
            f"timestamp must be a string, got {type(timestamp).__name__!r}"
        )

    if not timestamp.strip():
        raise ValueError("timestamp is empty or whitespace-only")

    try:
        dt = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            f"Cannot parse timestamp {timestamp!r}: {error}"
        ) from error

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat()


# ============================================================
# Event normalization
# ============================================================

def normalize_event(raw):
    """
    Convert one raw Cowrie event dict into the project's
    normalized event representation.

    Raises:
        TypeError:  if *raw* is not a dict.
        KeyError:   if the required ``timestamp`` field is absent.
        ValueError: if ``timestamp`` cannot be parsed.
    """

    if not isinstance(raw, dict):
        raise TypeError(
            f"Expected a dict, got {type(raw).__name__!r}"
        )

    # timestamp is required; let KeyError propagate to the caller
    timestamp_str = raw["timestamp"]

    event_id = raw.get("eventid", "")

    event = {
        "timestamp": normalize_timestamp(timestamp_str),
        "session_id": raw.get("session"),
        "event_type": None,
        "source_ip": raw.get("src_ip"),
        "destination_ip": raw.get("dst_ip"),
        "destination_port": raw.get("dst_port"),
    }

    # --------------------------------------------------------
    # Session events
    # --------------------------------------------------------

    if event_id == "cowrie.session.connect":

        event["event_type"] = "session_connect"

    elif event_id == "cowrie.session.closed":

        event["event_type"] = "session_closed"

    elif event_id == "cowrie.session.params":

        event["event_type"] = "session_params"

    # --------------------------------------------------------
    # Authentication events
    # --------------------------------------------------------

    elif event_id == "cowrie.login.success":

        event["event_type"] = "login"
        event["username"] = raw.get("username")
        event["success"] = True

    elif event_id == "cowrie.login.failed":

        event["event_type"] = "login"
        event["username"] = raw.get("username")
        event["success"] = False

    # --------------------------------------------------------
    # Command events
    # --------------------------------------------------------

    elif event_id == "cowrie.command.input":

        event["event_type"] = "command"
        event["command"] = raw.get("input")

    elif event_id == "cowrie.command.failed":

        event["event_type"] = "command_failed"
        event["command"] = raw.get("input")

    # --------------------------------------------------------
    # Client metadata
    # --------------------------------------------------------

    elif event_id in {
        "cowrie.client.version",
        "cowrie.client.kex",
        "cowrie.client.size",
        "cowrie.client.var",
    }:

        event["event_type"] = "client_metadata"

        excluded_fields = {
            "timestamp",
            "session",
            "eventid",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "message",
            "sensor",
            "uuid",
        }

        event["metadata"] = {
            key: value
            for key, value in raw.items()
            if key not in excluded_fields
        }

    # --------------------------------------------------------
    # Log lifecycle
    # --------------------------------------------------------

    elif event_id == "cowrie.log.closed":

        event["event_type"] = "log_closed"

    # --------------------------------------------------------
    # Unknown / future Cowrie events
    # --------------------------------------------------------

    else:

        event["event_type"] = "other"
        event["original_event_id"] = event_id

    return event


# ============================================================
# Parse Cowrie JSON-lines file
# ============================================================

def parse_cowrie_log(log_file):
    """
    Read a Cowrie JSON-lines log and return normalized events.

    Behaviour for invalid lines:
    - Blank lines are silently skipped.
    - Lines that are not valid JSON, whose top-level value is not a
      dict, whose ``timestamp`` field is absent, or whose timestamp
      cannot be parsed are **skipped** and recorded as
      :class:`ParseWarning` entries — they are not raised as
      exceptions.  This makes the parser tolerant of file rotation
      artefacts and truncated trailing lines without hiding errors
      from the caller.

    Returns:
        tuple[list[dict], list[ParseWarning]]:
            ``(events, warnings)`` where *events* is the list of
            normalized event dicts and *warnings* lists every
            skipped line with a human-readable reason.

    Raises:
        FileNotFoundError: if *log_file* does not exist.
        OSError:           on other I/O failures.
    """

    log_file = Path(log_file)

    events = []
    warnings = []

    with log_file.open("r", encoding="utf-8") as fh:

        for line_number, line in enumerate(fh, start=1):

            line = line.strip()

            # Blank lines are expected between rotated chunks.
            if not line:
                continue

            # ------------------------------------------------
            # JSON decode
            # ------------------------------------------------
            try:
                raw_event = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(
                    ParseWarning(
                        line_number=line_number,
                        reason=f"Invalid JSON: {exc}",
                    )
                )
                continue

            # ------------------------------------------------
            # Type guard — each record must be a JSON object
            # ------------------------------------------------
            if not isinstance(raw_event, dict):
                warnings.append(
                    ParseWarning(
                        line_number=line_number,
                        reason=(
                            f"Expected a JSON object, got "
                            f"{type(raw_event).__name__!r}"
                        ),
                    )
                )
                continue

            # ------------------------------------------------
            # Normalize (includes timestamp validation)
            # ------------------------------------------------
            try:
                normalized = normalize_event(raw_event)
            except KeyError as exc:
                warnings.append(
                    ParseWarning(
                        line_number=line_number,
                        reason=f"Missing required field: {exc}",
                    )
                )
                continue
            except (TypeError, ValueError) as exc:
                warnings.append(
                    ParseWarning(
                        line_number=line_number,
                        reason=str(exc),
                    )
                )
                continue

            events.append(normalized)

    return events, warnings


# ============================================================
# Session identification
# ============================================================

def group_events_by_session(events):
    """
    Group normalized events according to their session ID.

    Returns:

        {
            "session_id_1": [event1, event2, ...],
            "session_id_2": [event1, event2, ...]
        }
    """

    sessions = defaultdict(list)

    for event in events:

        session_id = event.get("session_id")

        if session_id is not None:
            sessions[session_id].append(event)

    return dict(sessions)


# ============================================================
# Session summary
# ============================================================

def summarize_session(session_id, events):
    """
    Create a compact summary of one attacker session.
    """

    timestamps = [
        event["timestamp"]
        for event in events
        if event.get("timestamp")
    ]

    commands = [
        event["command"]
        for event in events
        if event.get("event_type") == "command"
        and event.get("command") is not None
    ]

    failed_commands = [
        event["command"]
        for event in events
        if event.get("event_type") == "command_failed"
        and event.get("command") is not None
    ]

    usernames = [
        event["username"]
        for event in events
        if event.get("event_type") == "login"
        and event.get("username") is not None
    ]

    source_ips = {
        event.get("source_ip")
        for event in events
        if event.get("source_ip")
    }

    destination_ips = {
        event.get("destination_ip")
        for event in events
        if event.get("destination_ip")
    }

    destination_ports = {
        event.get("destination_port")
        for event in events
        if event.get("destination_port") is not None
    }

    return {
        "session_id": session_id,
        "start_time": min(timestamps) if timestamps else None,
        "end_time": max(timestamps) if timestamps else None,
        "source_ips": sorted(source_ips),
        "destination_ips": sorted(destination_ips),
        "destination_ports": sorted(destination_ports),
        "event_count": len(events),
        "command_count": len(commands),
        "failed_command_count": len(failed_commands),
        "commands": commands,
        "failed_commands": failed_commands,
        "usernames": usernames,
    }


def build_session_summaries(events):
    """
    Group events by session and generate a summary for
    every identified session.
    """

    grouped = group_events_by_session(events)

    summaries = []

    for session_id, session_events in grouped.items():

        summaries.append(
            summarize_session(
                session_id,
                session_events
            )
        )

    summaries.sort(
        key=lambda session: session["start_time"] or ""
    )

    return summaries


# ============================================================
# Save JSON
# ============================================================

def save_json(data, output_file):
    """
    Save Python data as formatted JSON.
    """

    output_file = Path(output_file)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_file.open("w", encoding="utf-8") as file:

        json.dump(
            data,
            file,
            indent=2
        )


# ============================================================
# Main command-line interface
# ============================================================

def main():

    arg_parser = argparse.ArgumentParser(
        description=(
            "Parse Cowrie logs into normalized events "
            "and attacker sessions."
        )
    )

    arg_parser.add_argument(
        "input",
        help="Path to Cowrie cowrie.json"
    )

    arg_parser.add_argument(
        "--events-output",
        default="data/normalized_events.json",
        help="Output file for normalized events"
    )

    arg_parser.add_argument(
        "--sessions-output",
        default="data/sessions.json",
        help="Output file for session summaries"
    )

    arg_parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit with a non-zero status code if any lines "
            "were skipped due to parse errors."
        ),
    )

    args = arg_parser.parse_args()

    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    events, warnings = parse_cowrie_log(args.input)

    # --------------------------------------------------------
    # Report warnings
    # --------------------------------------------------------

    for warning in warnings:
        print(
            f"WARNING line {warning.line_number}: {warning.reason}",
            file=sys.stderr,
        )

    # --------------------------------------------------------
    # Save normalized events
    # --------------------------------------------------------

    save_json(
        events,
        args.events_output
    )

    # --------------------------------------------------------
    # Build session summaries
    # --------------------------------------------------------

    sessions = build_session_summaries(events)

    save_json(
        sessions,
        args.sessions_output
    )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    print(f"Parsed {len(events)} events.")
    if warnings:
        print(f"Skipped {len(warnings)} invalid line(s) — see warnings above.")
    print(f"Identified {len(sessions)} sessions.")

    print()
    print(f"Normalized events: {args.events_output}")
    print(f"Session summaries: {args.sessions_output}")

    if args.strict and warnings:
        sys.exit(1)


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()
