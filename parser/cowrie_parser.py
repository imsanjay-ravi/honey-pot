import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# Timestamp handling
# ============================================================

def normalize_timestamp(timestamp):
    """
    Convert a Cowrie timestamp into UTC ISO-8601 format.
    """

    dt = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat()


# ============================================================
# Event normalization
# ============================================================

def normalize_event(raw):
    """
    Convert one raw Cowrie event into the project's
    normalized event representation.
    """

    event_id = raw.get("eventid", "")

    event = {
        "timestamp": normalize_timestamp(raw["timestamp"]),
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
    """

    log_file = Path(log_file)

    events = []

    with log_file.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:

                raw_event = json.loads(line)

                normalized = normalize_event(raw_event)

                events.append(normalized)

            except json.JSONDecodeError as error:

                raise ValueError(
                    f"Invalid JSON at line {line_number}: {error}"
                ) from error

            except KeyError as error:

                raise ValueError(
                    f"Missing required field {error} "
                    f"at line {line_number}"
                ) from error

    return events


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

    parser = argparse.ArgumentParser(
        description=(
            "Parse Cowrie logs into normalized events "
            "and attacker sessions."
        )
    )

    parser.add_argument(
        "input",
        help="Path to Cowrie cowrie.json"
    )

    parser.add_argument(
        "--events-output",
        default="data/normalized_events.json",
        help="Output file for normalized events"
    )

    parser.add_argument(
        "--sessions-output",
        default="data/sessions.json",
        help="Output file for session summaries"
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    events = parse_cowrie_log(args.input)

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
    print(f"Identified {len(sessions)} sessions.")

    print()
    print(f"Normalized events: {args.events_output}")
    print(f"Session summaries: {args.sessions_output}")


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    main()
