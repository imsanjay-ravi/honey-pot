"""
pipeline.py — End-to-End Offline Integration Pipeline.

Connects the components of the AI Adaptive Cyber Deception System:
1. Parser (parser.cowrie_parser): Reads and normalizes raw Cowrie JSONL events.
2. Session Grouper: Groups events by session identifier.
3. Analysis Engine (analysis.engine): Extracts features, classifies behaviour, and computes threat scores.
4. Deception Engine (deception.engine): Evaluates deterministic policies and updates in-memory world state.

SAFETY CONSTRAINTS:
- Entirely offline: No live Cowrie, VMs, or network activity required.
- In-memory world state: Real host files are never created, modified, or accessed.
- Passive telemetry: Captured commands are never executed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from analysis.engine import analyse_session
from deception.engine import DeceptionEngine
from deception.world_state import WorldState
from parser.cowrie_parser import group_events_by_session, parse_cowrie_log, save_json

PIPELINE_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Formatting Helpers for Console Output
# ---------------------------------------------------------------------------

def _format_console_report(result: dict[str, Any]) -> str:
    """Generate a clean, readable terminal report of pipeline execution."""
    lines: list[str] = []
    sep = "=" * 78
    subsep = "-" * 78

    lines.append(sep)
    lines.append("  AI ADAPTIVE CYBER DECEPTION SYSTEM -- OFFLINE PIPELINE EXECUTION")
    lines.append(sep)
    lines.append(f"Input Log:       {result.get('input_file')}")
    lines.append(f"Events Parsed:   {result.get('events_parsed', 0)}")
    lines.append(f"Parse Warnings:  {result.get('warnings_count', 0)}")
    lines.append(f"Sessions Found:  {result.get('sessions_count', 0)}")
    lines.append(subsep)

    # Warnings Section
    warnings = result.get("warnings", [])
    if warnings:
        lines.append("PARSE WARNINGS (Non-Fatal Recoverable Line Issues):")
        for w in warnings:
            lines.append(f"  - Line {w.get('line_number')}: {w.get('reason')}")
        lines.append(subsep)

    # Sessions Section
    sessions = result.get("sessions", [])
    if not sessions:
        lines.append("No valid sessions identified in input.")
    else:
        lines.append("SESSION ANALYSIS & DECEPTION DECISIONS:")
        for idx, s in enumerate(sessions, start=1):
            sid = s.get("session_id", "unknown")
            src_ip = s.get("source_ip", "unknown")
            analysis = s.get("analysis", {})
            deception = s.get("deception", {})
            score = analysis.get("score", 0)
            category = analysis.get("primary_category", "unknown")
            status = deception.get("status", "unknown").upper()
            policy_id = deception.get("policy_id", "none")
            action = deception.get("action", {})
            action_id = action.get("action_id", "no_op")
            target = action.get("target") or "none"
            explanation = deception.get("explanation", "")
            state_applied = deception.get("state_change_applied", {})

            lines.append(f"\n[{idx}] Session: {sid} (Source IP: {src_ip})")
            lines.append(f"    Threat Score:     {score}/100 [{category}]")
            lines.append(f"    Deception Policy: {policy_id} -> {status}")
            lines.append(f"    Action Chosen:    {action_id} (Target: {target})")
            lines.append(f"    Rationale:        {explanation}")
            if state_applied:
                lines.append(f"    State Transition: {json.dumps(state_applied)}")

            findings = analysis.get("findings", [])
            if findings:
                lines.append("    Findings:")
                for f in findings:
                    rid = f.get("rule_id", "")
                    fcat = f.get("category", "")
                    strength = f.get("evidence_strength", "")
                    ev = f.get("evidence", "")
                    lines.append(f"      * [{rid}] {fcat} ({strength}): {ev}")

    # Final World State Summary
    lines.append("\n" + subsep)
    ws = result.get("world_state", {})
    discovered_files = ws.get("discovered_files", [])
    discovered_services = ws.get("discovered_services", [])
    attacker_interests = ws.get("attacker_interests", [])
    action_history = ws.get("action_history", [])

    lines.append("FINAL FICTIONAL WORLD STATE SUMMARY:")
    lines.append(f"  Discovered Files:    {len(discovered_files)} {discovered_files}")
    lines.append(f"  Revealed Services:   {len(discovered_services)} {discovered_services}")
    lines.append(f"  Attacker Interests:  {len(attacker_interests)} {attacker_interests}")
    lines.append(f"  Total Actions Run:   {len(action_history)}")
    lines.append(sep)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core Pipeline Execution
# ---------------------------------------------------------------------------

def run_pipeline(
    log_file: str | Path,
    output_file: str | Path | None = None,
    world_state_output: str | Path | None = None,
    world_state: WorldState | None = None,
    strict: bool = False,
    quiet: bool = False,
) -> dict[str, Any]:
    """
    Execute the offline deception pipeline on a sanitized Cowrie log fixture.

    Parameters
    ----------
    log_file:
        Path to the raw JSONL log file.
    output_file:
        Optional path where complete structured pipeline results are saved as JSON.
    world_state_output:
        Optional path where the final WorldState is saved as JSON.
    world_state:
        Optional initial WorldState instance. If None, a fresh default state is created.
    strict:
        If True, raises a ValueError if any parse warnings are encountered.
    quiet:
        If True, suppresses terminal console output.

    Returns
    -------
    dict[str, Any]
        Complete structured pipeline execution results.
    """
    log_path = Path(log_file)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    # 1. Parse raw Cowrie events
    events, parse_warnings = parse_cowrie_log(log_path)

    if strict and parse_warnings:
        reasons = "; ".join(f"Line {w.line_number}: {w.reason}" for w in parse_warnings)
        raise ValueError(f"Strict mode failure: {len(parse_warnings)} warnings encountered: {reasons}")

    # 2. Group events into sessions
    sessions_dict = group_events_by_session(events)

    # 3. Initialize or reuse stateful DeceptionEngine
    engine = DeceptionEngine(world_state=world_state or WorldState.create_default())

    # 4. Process each session in deterministic chronological order
    session_records: list[dict[str, Any]] = []

    def _sort_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[str, str]:
        sid, evts = item
        first_ts = evts[0].get("timestamp", "") if evts else ""
        return (first_ts, sid)

    for sid, session_events in sorted(sessions_dict.items(), key=_sort_key):
        # Run Phase 2 analysis
        analysis_result = analyse_session(session_events, session_id=sid)

        # Run Phase 3 deception decision and update world state
        deception_result = engine.process(analysis_result)

        src_ip = session_events[0].get("source_ip") if session_events else None

        record = {
            "session_id": sid,
            "source_ip": src_ip,
            "event_count": len(session_events),
            "analysis": {
                "primary_category": analysis_result.get("primary_category"),
                "score": analysis_result.get("score"),
                "findings": analysis_result.get("findings", []),
                "score_explanation": analysis_result.get("score_explanation"),
                "warnings": analysis_result.get("warnings", []),
            },
            "deception": {
                "status": deception_result.get("status"),
                "policy_id": deception_result.get("policy_id"),
                "action": deception_result.get("action"),
                "explanation": deception_result.get("explanation"),
                "state_change_applied": deception_result.get("state_change_applied"),
                "error": deception_result.get("error"),
            },
        }
        session_records.append(record)

    # 5. Assemble master result
    pipeline_result: dict[str, Any] = {
        "pipeline_version": PIPELINE_VERSION,
        "input_file": str(log_path),
        "events_parsed": len(events),
        "warnings_count": len(parse_warnings),
        "warnings": [
            {"line_number": w.line_number, "reason": w.reason}
            for w in parse_warnings
        ],
        "sessions_count": len(session_records),
        "sessions": session_records,
        "world_state": engine.world_state.to_dict(),
        "deception_metric": {
            "label": "DECEPTION ACTIONS EXECUTED",
            "value": len([
                a for a in engine.world_state.action_history
                if a.get("action_id") and a.get("action_id") != "no_op" and a.get("success", True) is not False
            ]),
            "actions_executed_count": len([
                a for a in engine.world_state.action_history
                if a.get("action_id") and a.get("action_id") != "no_op" and a.get("success", True) is not False
            ]),
            "recommendations_count": len([
                a for a in engine.world_state.action_history
                if a.get("action_id") and a.get("action_id") != "no_op"
            ]),
            "is_advisory": False,
            "status_note": "Applied to simulated environment",
        },
    }

    # 6. Save outputs if requested
    if output_file:
        save_json(pipeline_result, output_file)

    if world_state_output:
        save_json(engine.world_state.to_dict(), world_state_output)

    # 7. Print console report
    if not quiet:
        print(_format_console_report(pipeline_result))

    return pipeline_result


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> int:
    """Command-line interface for the offline pipeline."""
    parser = argparse.ArgumentParser(
        description="AI Adaptive Cyber Deception System — Offline End-to-End Pipeline",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to synthetic Cowrie JSONL log file",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional path to save structured pipeline results as JSON",
    )
    parser.add_argument(
        "--world-state-output",
        default=None,
        help="Optional path to save final simulated WorldState as JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with non-zero error code if any parser warnings occur",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal output",
    )

    args = parser.parse_args()

    try:
        run_pipeline(
            log_file=args.input,
            output_file=args.output,
            world_state_output=args.world_state_output,
            strict=args.strict,
            quiet=args.quiet,
        )
        return 0
    except (FileNotFoundError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected pipeline failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
