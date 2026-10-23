"""
deception/policy_engine.py — Deterministic deception policy engine.

Consumes the structured analysis result produced by the Phase 2 analysis engine
and the current fictional WorldState, evaluating named, deterministic policies
to select an approved deception action.

Inputs:
- Analysis result dict from Phase 2 (containing findings, features, primary_category, score).
- Fictional WorldState.

Outputs:
- PolicyDecision object containing the selected action, status, policy identifier,
  matching finding, evidence, explanation, and expected state change.

Key design principles:
- Deterministic, named policies.
- Evaluates evidence and preconditions, never score alone.
- Idempotency & state awareness: does not repeatedly apply already completed actions.
- Safe conservative fallback to no_op for unknown or low-confidence activity.
- Strict allowlist adherence: only approved actions can ever be emitted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deception.actions import (
    ACTION_NO_OP,
    ACTION_PRESENT_DECOY,
    ACTION_RECORD_INTEREST,
    ACTION_REVEAL_SERVICE,
    APPROVED_ACTIONS,
    DeceptionAction,
    validate_action,
)
from deception.world_state import WorldState


# ---------------------------------------------------------------------------
# Decision Data Class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyDecision:
    """
    Structured outcome of policy evaluation.

    Attributes
    ----------
    policy_id:
        Identifier of the policy rule that fired.
    action:
        The selected DeceptionAction.
    status:
        "accepted", "rejected", or "no_action_required".
    finding:
        The matching behaviour finding dict from analysis, or None.
    explanation:
        Concise explanation of the decision rationale.
    state_change_expected:
        Summary of the anticipated state modification.
    """
    policy_id: str
    action: DeceptionAction
    status: str
    finding: dict[str, Any] | None
    explanation: str
    state_change_expected: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "status": self.status,
            "action": self.action.to_dict(),
            "finding": self.finding,
            "explanation": self.explanation,
            "state_change_expected": self.state_change_expected,
        }


# ---------------------------------------------------------------------------
# Deterministic Policy Implementations
# ---------------------------------------------------------------------------

def _finding_dict(finding: Any) -> dict[str, Any] | None:
    if finding is None:
        return None
    if isinstance(finding, dict):
        return finding
    return {
        "rule_id": getattr(finding, "rule_id", ""),
        "category": getattr(finding, "category", ""),
        "evidence": getattr(finding, "evidence", ""),
        "evidence_strength": getattr(finding, "evidence_strength", ""),
    }


def _safe_no_op_fallback(
    policy_id: str = "POL-DEFAULT-NOOP",
    finding: dict[str, Any] | None = None,
    explanation: str = "Insufficient evidence or benign behaviour; no deception action taken.",
) -> PolicyDecision:
    """Return a safe fallback decision."""
    return PolicyDecision(
        policy_id=policy_id,
        action=DeceptionAction(
            action_id=ACTION_NO_OP,
            target=None,
            description="Safe fallback: no operation performed.",
        ),
        status="no_action_required",
        finding=finding,
        explanation=explanation,
        state_change_expected={"no_op": True},
    )


# Priority order for policy evaluation:
# 1. Privilege Escalation / Credential Access
# 2. Download / External Tool Transfer
# 3. Systematic File Discovery
# 4. Systematic Reconnaissance
# 5. Authentication Abuse
# 6. Fallback / No-Op

def evaluate_policy(
    analysis_result: dict[str, Any],
    world_state: WorldState,
) -> PolicyDecision:
    """
    Evaluate deterministic policies against the analysis result and world state.

    Parameters
    ----------
    analysis_result:
        Result dict from analysis.engine.analyse_session.
    world_state:
        The current in-memory WorldState.

    Returns
    -------
    PolicyDecision
        The chosen decision record.
    """
    if not isinstance(analysis_result, dict) or not isinstance(world_state, WorldState):
        return _safe_no_op_fallback(
            policy_id="POL-MALFORMED-INPUT",
            explanation="Malformed analysis result or world state; falling back to safe no-op.",
        )

    raw_findings = analysis_result.get("findings", [])
    if not isinstance(raw_findings, list) or not raw_findings:
        return _safe_no_op_fallback(
            policy_id="POL-DEFAULT-NOOP",
            explanation="No findings reported in session analysis; no deception action taken.",
        )

    findings: list[dict[str, Any]] = [
        _finding_dict(f) for f in raw_findings if _finding_dict(f) is not None
    ]

    # Map findings by rule_id and category
    findings_by_rule = {f.get("rule_id"): f for f in findings if f.get("rule_id")}
    findings_by_cat: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        cat = f.get("category", "unknown")
        findings_by_cat.setdefault(cat, []).append(f)

    # -----------------------------------------------------------------------
    # Policy 1: Credential Access / Privilege Escalation (PE-02, PE-01)
    # -----------------------------------------------------------------------
    if "PE-02" in findings_by_rule:
        f = findings_by_rule["PE-02"]
        # Precondition check: Decoy SSH key available?
        target_ssh = "/root/.ssh/id_rsa_backup"
        if not world_state.is_decoy_visible(target_ssh):
            action = DeceptionAction(
                action_id=ACTION_PRESENT_DECOY,
                target=target_ssh,
                description="Present decoy administrative SSH private key to satisfy credential search.",
            )
            return PolicyDecision(
                policy_id="POL-CRED-DECOY-SSH",
                action=action,
                status="accepted",
                finding=f,
                explanation="Attacker searched for credentials; presenting decoy SSH key.",
                state_change_expected={"decoy_presented": target_ssh, "is_visible": True},
            )

        # Alternative decoy: App secrets .env
        target_env = "/var/www/internal/.env"
        if not world_state.is_decoy_visible(target_env):
            action = DeceptionAction(
                action_id=ACTION_PRESENT_DECOY,
                target=target_env,
                description="Present decoy application environment secrets to satisfy credential search.",
            )
            return PolicyDecision(
                policy_id="POL-CRED-DECOY-ENV",
                action=action,
                status="accepted",
                finding=f,
                explanation="Attacker searched for credentials; presenting decoy environment file.",
                state_change_expected={"decoy_presented": target_env, "is_visible": True},
            )

        # Both already presented -> record interest to avoid duplicate actions
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="credential_harvesting",
            description="All credential decoys already presented; updating attacker interest profile.",
        )
        return PolicyDecision(
            policy_id="POL-CRED-RECORD-INTEREST",
            action=action,
            status="accepted",
            finding=f,
            explanation="Credential decoys already deployed; recording attacker interest.",
            state_change_expected={"topic": "credential_harvesting"},
        )

    if "PE-01" in findings_by_rule:
        f = findings_by_rule["PE-01"]
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="privilege_escalation",
            description="Privilege escalation commands observed; recording attacker profile interest.",
        )
        return PolicyDecision(
            policy_id="POL-PRIV-ESC-RECORD",
            action=action,
            status="accepted",
            finding=f,
            explanation="Privilege escalation commands observed; updating attacker interest profile.",
            state_change_expected={"topic": "privilege_escalation"},
        )

    # -----------------------------------------------------------------------
    # Policy 2: Download Attempt (DL-01)
    # -----------------------------------------------------------------------
    if "DL-01" in findings_by_rule:
        f = findings_by_rule["DL-01"]
        target_env = "/var/www/internal/.env"
        if not world_state.is_decoy_visible(target_env):
            action = DeceptionAction(
                action_id=ACTION_PRESENT_DECOY,
                target=target_env,
                description="Present decoy configuration to lure attacker away from binary download.",
            )
            return PolicyDecision(
                policy_id="POL-DOWNLOAD-DECOY-ENV",
                action=action,
                status="accepted",
                finding=f,
                explanation="External download attempt observed; presenting decoy configuration.",
                state_change_expected={"decoy_presented": target_env, "is_visible": True},
            )

        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="tooling_download",
            description="External download attempt observed; recording tooling interest.",
        )
        return PolicyDecision(
            policy_id="POL-DOWNLOAD-RECORD-INTEREST",
            action=action,
            status="accepted",
            finding=f,
            explanation="External download attempt observed; recording tooling download interest.",
            state_change_expected={"topic": "tooling_download"},
        )

    # -----------------------------------------------------------------------
    # Policy 3: File Discovery (FD-02, FD-01)
    # -----------------------------------------------------------------------
    if "FD-02" in findings_by_rule:
        f = findings_by_rule["FD-02"]
        target_dump = "/home/backup/db_dump.sql"
        if not world_state.is_decoy_visible(target_dump):
            action = DeceptionAction(
                action_id=ACTION_PRESENT_DECOY,
                target=target_dump,
                description="Present decoy database backup to systematic filesystem explorer.",
            )
            return PolicyDecision(
                policy_id="POL-FILE-DISC-DB-DUMP",
                action=action,
                status="accepted",
                finding=f,
                explanation="Systematic file discovery observed; presenting decoy database dump.",
                state_change_expected={"decoy_presented": target_dump, "is_visible": True},
            )

        target_ssl = "/etc/nginx/ssl_admin_key.pem"
        if not world_state.is_decoy_visible(target_ssl):
            action = DeceptionAction(
                action_id=ACTION_PRESENT_DECOY,
                target=target_ssl,
                description="Present decoy SSL key to systematic filesystem explorer.",
            )
            return PolicyDecision(
                policy_id="POL-FILE-DISC-SSL-KEY",
                action=action,
                status="accepted",
                finding=f,
                explanation="Systematic file discovery observed; presenting decoy SSL key.",
                state_change_expected={"decoy_presented": target_ssl, "is_visible": True},
            )

        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="file_discovery",
            description="Decoy files already revealed; recording file discovery interest.",
        )
        return PolicyDecision(
            policy_id="POL-FILE-DISC-RECORD",
            action=action,
            status="accepted",
            finding=f,
            explanation="Decoys already deployed; recording file discovery interest.",
            state_change_expected={"topic": "file_discovery"},
        )

    if "FD-01" in findings_by_rule:
        f = findings_by_rule["FD-01"]
        # FD-01 is WEAK evidence (e.g. single ls). Do NOT deploy overt decoys.
        # Conservative handling: record interest or safe no-op.
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="file_discovery",
            description="Single file discovery command; logging interest without active decoy deployment.",
        )
        return PolicyDecision(
            policy_id="POL-FILE-DISC-WEAK",
            action=action,
            status="accepted",
            finding=f,
            explanation="Weak file discovery evidence; recording interest conservatively.",
            state_change_expected={"topic": "file_discovery"},
        )

    # -----------------------------------------------------------------------
    # Policy 4: Reconnaissance (REC-02, REC-01)
    # -----------------------------------------------------------------------
    recon_finding = findings_by_rule.get("REC-02") or findings_by_rule.get("REC-01")
    if recon_finding:
        # Precondition check: Reveal hidden service?
        target_mysql = "mysql-backend"
        if not world_state.is_service_revealed(target_mysql):
            action = DeceptionAction(
                action_id=ACTION_REVEAL_SERVICE,
                target=target_mysql,
                description="Reveal simulated internal MySQL database service to reconnaissance.",
            )
            return PolicyDecision(
                policy_id="POL-RECON-REVEAL-MYSQL",
                action=action,
                status="accepted",
                finding=recon_finding,
                explanation="System enumeration observed; revealing internal MySQL service.",
                state_change_expected={"service_revealed": target_mysql, "new_state": "revealed"},
            )

        target_redis = "redis-cache"
        if not world_state.is_service_revealed(target_redis):
            action = DeceptionAction(
                action_id=ACTION_REVEAL_SERVICE,
                target=target_redis,
                description="Reveal simulated internal Redis cache service to reconnaissance.",
            )
            return PolicyDecision(
                policy_id="POL-RECON-REVEAL-REDIS",
                action=action,
                status="accepted",
                finding=recon_finding,
                explanation="System enumeration observed; revealing internal Redis cache service.",
                state_change_expected={"service_revealed": target_redis, "new_state": "revealed"},
            )

        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="reconnaissance",
            description="All fake services revealed; recording reconnaissance interest.",
        )
        return PolicyDecision(
            policy_id="POL-RECON-RECORD-INTEREST",
            action=action,
            status="accepted",
            finding=recon_finding,
            explanation="Simulated services already revealed; recording reconnaissance interest.",
            state_change_expected={"topic": "reconnaissance"},
        )

    # -----------------------------------------------------------------------
    # Policy 5: Authentication Abuse (AUTH-01, AUTH-02, AUTH-03)
    # -----------------------------------------------------------------------
    auth_finding = (
        findings_by_rule.get("AUTH-02")
        or findings_by_rule.get("AUTH-03")
        or findings_by_rule.get("AUTH-01")
    )
    if auth_finding:
        action = DeceptionAction(
            action_id=ACTION_RECORD_INTEREST,
            target="authentication_spray",
            description="Authentication abuse detected; recording credential spray interest.",
        )
        return PolicyDecision(
            policy_id="POL-AUTH-SPRAY-MONITOR",
            action=action,
            status="accepted",
            finding=auth_finding,
            explanation="Authentication abuse detected; logging attacker interest.",
            state_change_expected={"topic": "authentication_spray"},
        )

    # -----------------------------------------------------------------------
    # Policy 6: Unknown or benign activity -> Safe No-Op Fallback
    # -----------------------------------------------------------------------
    unknown_finding = findings_by_rule.get("UNKNOWN") or (findings[0] if findings else None)
    return _safe_no_op_fallback(
        policy_id="POL-DEFAULT-NOOP",
        finding=unknown_finding,
        explanation="No active threat pattern triggered deception policy; safe no-op fallback.",
    )
