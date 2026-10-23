"""
analysis/engine.py — Orchestrator that wires feature extraction,
classification, and scoring into a single analysis result.

Result structure
----------------
{
    "session_id": str | None,
    "engine_version": str,
    "features": dict,            # from analysis.features.extract_features
    "findings": [                # from analysis.classifier.classify
        {
            "rule_id": str,
            "category": str,
            "evidence": str,
            "evidence_strength": str,
        },
        ...
    ],
    "primary_category": str,     # from analysis.classifier.primary_category
    "score": int,                # 0–100
    "score_contributions": [...],
    "score_explanation": str,
    "warnings": [str],           # input-quality issues (not parse errors)
    "rule_set_version": str,
}
"""

from __future__ import annotations

from typing import Any

from analysis.features import extract_features
from analysis.classifier import classify, primary_category, Finding
from analysis.scorer import compute_score

ENGINE_VERSION = "1.0.0"
RULE_SET_VERSION = "1.0.0"


def analyse_session(
    events: list[dict[str, Any]],
    session_id: str | None = None,
) -> dict[str, Any]:
    """
    Run the full analysis pipeline for one session.

    Parameters
    ----------
    events:
        List of normalized event dicts for a single session.  May be empty.
    session_id:
        Optional session identifier to include in the result.

    Returns
    -------
    dict
        Fully populated analysis result (see module docstring for schema).
    """
    warnings: list[str] = []

    # Input validation
    if not isinstance(events, list):
        warnings.append(
            f"events must be a list, got {type(events).__name__!r}; "
            "treating as empty session."
        )
        events = []

    if not events:
        warnings.append("Session has no events; results may be incomplete.")

    # 1. Feature extraction
    features = extract_features(events)

    # 2. Classification
    findings: list[Finding] = classify(features)

    # 3. Scoring
    score_result = compute_score(features)

    # 4. Assemble result
    return {
        "session_id": session_id,
        "engine_version": ENGINE_VERSION,
        "rule_set_version": RULE_SET_VERSION,
        "features": features,
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category,
                "evidence": f.evidence,
                "evidence_strength": f.evidence_strength,
            }
            for f in findings
        ],
        "primary_category": primary_category(findings),
        "score": score_result["score"],
        "score_contributions": score_result["contributions"],
        "score_explanation": score_result["explanation"],
        "warnings": warnings,
    }


def analyse_all_sessions(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Group events by session_id and run :func:`analyse_session` on each.

    Parameters
    ----------
    events:
        All normalized events across any number of sessions.

    Returns
    -------
    list[dict]
        One analysis result per session, sorted by session_id.
    """
    from collections import defaultdict

    grouped: dict[str | None, list] = defaultdict(list)
    for ev in events:
        sid = ev.get("session_id")
        grouped[sid].append(ev)

    results = []
    for sid, session_events in sorted(grouped.items(), key=lambda x: (x[0] or "")):
        results.append(analyse_session(session_events, session_id=sid))

    return results
