"""
analysis/cli.py — Command-line entry point for the analysis engine.

Usage
-----
  # Analyse a normalized-events JSON file produced by the parser:
  python -m analysis.cli events.json

  # Analyse and write structured JSON output:
  python -m analysis.cli events.json --output results.json

  # Suppress the feature detail block:
  python -m analysis.cli events.json --no-features

  # Compact one-line-per-session output (JSON):
  python -m analysis.cli events.json --output results.json --json-only

Input format
------------
The input file must be a JSON array of normalized event dicts (the
format written by `python -m parser.cowrie_parser`).  Events from
multiple sessions can be mixed; the engine groups them by session_id.

The tool never writes results to the same path as the input file.
It never executes any content from the events it reads.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from analysis.engine import analyse_all_sessions


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _print_result(result: dict, show_features: bool) -> None:
    sid = result.get("session_id") or "<no session_id>"
    score = result.get("score", 0)
    primary = result.get("primary_category", "unknown")

    print(f"\n{'=' * 60}")
    print(f"Session : {sid}")
    print(f"Category: {primary}")
    print(f"Score   : {score}/100")
    print(f"          {result.get('score_explanation', '')}")

    findings = result.get("findings", [])
    if findings:
        print(f"\nFindings ({len(findings)}):")
        for f in findings:
            strength = f.get("evidence_strength", "?")
            rule_id = f.get("rule_id", "?")
            evidence = f.get("evidence", "")
            print(f"  [{strength:8s}] {rule_id} — {evidence}")

    if show_features:
        features = result.get("features", {})
        print("\nFeatures:")
        for key, val in features.items():
            if key == "unknown_event_count":
                continue  # alias — skip to avoid duplication
            print(f"  {key:<35} {val}")

    warnings = result.get("warnings", [])
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  ! {w}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    arg_parser = argparse.ArgumentParser(
        description=(
            "Analyse normalized Cowrie events and produce "
            "behaviour findings and a heuristic threat score."
        )
    )
    arg_parser.add_argument(
        "input",
        help="Path to a JSON file containing normalized events "
             "(array of event dicts).",
    )
    arg_parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write structured JSON results.  "
             "Must not be the same as the input path.",
    )
    arg_parser.add_argument(
        "--no-features",
        action="store_true",
        help="Suppress the feature detail block in console output.",
    )
    arg_parser.add_argument(
        "--json-only",
        action="store_true",
        help="Skip console output and only write --output file "
             "(requires --output).",
    )

    args = arg_parser.parse_args()

    # ----------------------------------------------------------------
    # Safety: refuse to overwrite input
    # ----------------------------------------------------------------
    input_path = Path(args.input).resolve()
    if args.output:
        output_path = Path(args.output).resolve()
        if output_path == input_path:
            print(
                "ERROR: --output path must differ from the input path.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        output_path = None

    if args.json_only and output_path is None:
        print(
            "ERROR: --json-only requires --output to be specified.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ----------------------------------------------------------------
    # Read input
    # ----------------------------------------------------------------
    try:
        raw_text = input_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Cannot read input file: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        events = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Input file is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(events, list):
        print(
            "ERROR: Input JSON must be an array of event objects.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ----------------------------------------------------------------
    # Analyse
    # ----------------------------------------------------------------
    results = analyse_all_sessions(events)

    # ----------------------------------------------------------------
    # Console output
    # ----------------------------------------------------------------
    if not args.json_only:
        print(f"Analysed {len(results)} session(s) from {input_path.name}.")
        for result in results:
            _print_result(result, show_features=not args.no_features)
        print(f"\n{'=' * 60}")

    # ----------------------------------------------------------------
    # JSON output
    # ----------------------------------------------------------------
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(results, indent=2),
            encoding="utf-8",
        )
        if not args.json_only:
            print(f"\nResults written to: {output_path}")


if __name__ == "__main__":
    main()
