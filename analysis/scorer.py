"""
analysis/scorer.py — Heuristic threat score (0–100).

The score is NOT a probability.  It is a bounded indicator of how
suspicious a session appears based on the features extracted from its
events.  A higher score means more behavioural evidence of malicious
intent, not a calibrated confidence value.

Score formula
-------------
The score is a sum of weighted contributions, capped at 100.

Factor                         Max contribution    Notes
───────────────────────────────────────────────────────────────────
Login failures (capped)              20            2 pts per failure, max 10
                                                   failures counted
Login success after failure          15            flat bonus
Recon commands (capped)              15            3 pts each, max 5 counted
File-discovery commands (capped)     10            2 pts each, max 5 counted
Download attempt (flat)              20            per attempt, max 2 counted
Privilege escalation (flat)          20            per command, max 2 counted
Credential access (flat)             15            per command, max 1 counted
───────────────────────────────────────────────────────────────────
Maximum raw sum before cap          115  (intentionally above 100 so that
                                         severe sessions reliably reach 100)

The final score is min(raw_sum, 100), rounded to the nearest integer.

Limitations
-----------
- The weights are expert-chosen and have NOT been tuned on labelled data.
  Treat them as a reasonable starting point, not ground truth.
- Single-command sessions that match only FD-01 (one 'ls') will score low
  (≈2), which is intentional — one ambiguous command should not produce
  a high score.
- The score does not account for session duration, attacker IP reputation,
  or inter-session correlations.
- Correlated rules (REC-01 and REC-02 both fire for the same commands) are
  mitigated by counting raw command quantities rather than rule counts.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Weight constants (edit here to tune)
# ---------------------------------------------------------------------------

_W_LOGIN_FAILURE_PER_ATTEMPT = 2        # per failure (capped at 10 failures)
_W_LOGIN_SUCCESS_AFTER_FAILURE = 15     # flat bonus
_W_RECON_PER_COMMAND = 3               # per recon command (capped at 5)
_W_FILE_DISCOVERY_PER_COMMAND = 2      # per file-disc command (capped at 5)
_W_DOWNLOAD_PER_ATTEMPT = 20           # per download command (capped at 2)
_W_PRIV_ESC_PER_COMMAND = 20           # per priv-esc command (capped at 2)
_W_CREDENTIAL_PER_COMMAND = 15         # per credential command (capped at 1)


def compute_score(features: dict[str, Any]) -> dict[str, Any]:
    """
    Compute a heuristic threat score from extracted features.

    Parameters
    ----------
    features:
        Feature dict as returned by :func:`analysis.features.extract_features`.

    Returns
    -------
    dict with keys:
        score (int):
            Integer in [0, 100].
        contributions (list[dict]):
            Each entry has keys ``factor``, ``value``, ``weight``,
            ``contribution``, ``capped_at``.
        explanation (str):
            Human-readable summary of the main scoring factors.
    """
    if not isinstance(features, dict):
        features = {}

    contributions: list[dict[str, Any]] = []
    raw_total = 0.0

    def _add(factor: str, raw_value: int, weight: float, cap: int) -> None:
        nonlocal raw_total
        capped_value = min(raw_value, cap)
        contribution = capped_value * weight
        contributions.append({
            "factor": factor,
            "value": raw_value,
            "capped_at": cap,
            "weight": weight,
            "contribution": contribution,
        })
        raw_total += contribution

    # Login failures (capped at 10)
    _add(
        "login_failures",
        features.get("login_failure_count", 0),
        _W_LOGIN_FAILURE_PER_ATTEMPT,
        cap=10,
    )

    # Success after failure (0 or 1)
    success_after_failure = (
        1
        if features.get("login_success_count", 0) >= 1
        and features.get("login_failure_count", 0) >= 1
        else 0
    )
    _add(
        "login_success_after_failure",
        success_after_failure,
        _W_LOGIN_SUCCESS_AFTER_FAILURE,
        cap=1,
    )

    # Recon commands (capped at 5)
    _add(
        "recon_commands",
        features.get("recon_command_count", 0),
        _W_RECON_PER_COMMAND,
        cap=5,
    )

    # File discovery commands (capped at 5)
    _add(
        "file_discovery_commands",
        features.get("file_discovery_count", 0),
        _W_FILE_DISCOVERY_PER_COMMAND,
        cap=5,
    )

    # Download attempts (capped at 2)
    _add(
        "download_attempts",
        features.get("download_attempt_count", 0),
        _W_DOWNLOAD_PER_ATTEMPT,
        cap=2,
    )

    # Privilege-escalation commands (capped at 2)
    _add(
        "privilege_escalation_commands",
        features.get("privilege_escalation_count", 0),
        _W_PRIV_ESC_PER_COMMAND,
        cap=2,
    )

    # Credential-access commands (capped at 1)
    _add(
        "credential_access_commands",
        features.get("credential_command_count", 0),
        _W_CREDENTIAL_PER_COMMAND,
        cap=1,
    )

    final_score = min(round(raw_total), 100)

    # Build a human-readable explanation of the dominant factors
    significant = [
        c for c in contributions if c["contribution"] > 0
    ]
    significant.sort(key=lambda c: c["contribution"], reverse=True)

    if not significant:
        explanation = "No suspicious activity detected; score is 0."
    else:
        parts = [
            f"{c['factor']} (+{c['contribution']:.0f})"
            for c in significant[:4]
        ]
        explanation = (
            f"Score {final_score}/100. "
            f"Main factors: {', '.join(parts)}."
        )
        if final_score >= 80:
            explanation += " High threat — multiple strong indicators present."
        elif final_score >= 50:
            explanation += " Moderate threat — several suspicious indicators."
        elif final_score >= 20:
            explanation += " Low-moderate threat — limited suspicious activity."
        else:
            explanation += " Low threat — minimal or ambiguous indicators."

    return {
        "score": final_score,
        "contributions": contributions,
        "explanation": explanation,
    }
