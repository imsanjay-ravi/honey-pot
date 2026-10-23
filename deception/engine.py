"""
deception/engine.py — Orchestrator for simulated cyber deception.

Wires together:
1. Receiving the Phase 2 analysis result.
2. Reading the fictional WorldState.
3. Evaluating deterministic policies (deception.policy_engine).
4. Validating the selected action and state preconditions (deception.actions).
5. Applying the approved in-memory state transition.
6. Returning a structured decision record.

SAFETY GUARANTEES:
- No subprocess, shell, network, or real file access.
- Invalid or unknown actions are rejected and safely fall back to no_op.
- State updates are strictly in-memory and idempotent.
"""

from __future__ import annotations

from typing import Any

from deception.actions import (
    ACTION_NO_OP,
    APPROVED_ACTIONS,
    ActionResult,
    DeceptionAction,
    apply_action,
    validate_action,
)
from deception.policy_engine import PolicyDecision, evaluate_policy
from deception.world_state import WorldState


# ---------------------------------------------------------------------------
# Functional Orchestration API
# ---------------------------------------------------------------------------

def process_session_deception(
    analysis_result: dict[str, Any],
    world_state: WorldState | None = None,
) -> tuple[dict[str, Any], WorldState]:
    """
    Process an analysis result against a world state and apply approved deception.

    Parameters
    ----------
    analysis_result:
        Output dict from analysis.engine.analyse_session.
    world_state:
        Optional WorldState instance. If None, a fresh default state is created.

    Returns
    -------
    tuple[dict[str, Any], WorldState]
        Structured decision record and the updated WorldState.
    """
    state = world_state if world_state is not None else WorldState.create_default()

    # 1. Evaluate deterministic policy
    decision: PolicyDecision = evaluate_policy(analysis_result, state)

    # 2. Safety check: ensure action is in explicit allowlist
    if decision.action.action_id not in APPROVED_ACTIONS:
        fallback_action = DeceptionAction(
            action_id=ACTION_NO_OP,
            target=None,
            description="Rejected non-allowlisted action; safe no-op fallback.",
        )
        record = {
            "session_id": analysis_result.get("session_id") if isinstance(analysis_result, dict) else None,
            "status": "rejected",
            "policy_id": decision.policy_id,
            "action": fallback_action.to_dict(),
            "finding": decision.finding,
            "explanation": f"Action {decision.action.action_id!r} not in approved allowlist.",
            "state_change_expected": {},
            "state_change_applied": {},
            "world_state_summary": _summarize_world_state(state),
            "error": f"Disallowed action: {decision.action.action_id}",
        }
        return record, state

    # 3. Validate action against current world state
    is_valid, validation_msg = validate_action(decision.action, state)
    if not is_valid:
        # Rejected action; safe fallback
        fallback_action = DeceptionAction(
            action_id=ACTION_NO_OP,
            target=None,
            description=f"Action validation failed: {validation_msg}",
        )
        record = {
            "session_id": analysis_result.get("session_id") if isinstance(analysis_result, dict) else None,
            "status": "rejected",
            "policy_id": decision.policy_id,
            "action": fallback_action.to_dict(),
            "finding": decision.finding,
            "explanation": f"Action rejected: {validation_msg}",
            "state_change_expected": decision.state_change_expected,
            "state_change_applied": {},
            "world_state_summary": _summarize_world_state(state),
            "error": validation_msg,
        }
        return record, state

    # 4. Apply action to fictional world state
    action_result: ActionResult = apply_action(decision.action, state)

    record = {
        "session_id": analysis_result.get("session_id") if isinstance(analysis_result, dict) else None,
        "status": decision.status,
        "policy_id": decision.policy_id,
        "action": decision.action.to_dict(),
        "finding": decision.finding,
        "explanation": decision.explanation,
        "state_change_expected": decision.state_change_expected,
        "state_change_applied": action_result.state_change,
        "world_state_summary": _summarize_world_state(state),
        "error": action_result.error,
    }

    return record, state


def _summarize_world_state(state: WorldState) -> dict[str, Any]:
    """Return a lightweight summary of current world state."""
    return {
        "discovered_files_count": len(state.discovered_files),
        "discovered_services_count": len(state.discovered_services),
        "attacker_interests": sorted(state.attacker_interests),
        "action_history_count": len(state.action_history),
        "events_count": len(state.events),
    }


# ---------------------------------------------------------------------------
# Class Interface
# ---------------------------------------------------------------------------

class DeceptionEngine:
    """
    Stateful deception orchestration engine holding a WorldState instance.
    """

    def __init__(self, world_state: WorldState | None = None) -> None:
        self.world_state = (
            world_state if world_state is not None else WorldState.create_default()
        )

    def process(self, analysis_result: dict[str, Any]) -> dict[str, Any]:
        """
        Process an analysis result and update internal world state.
        """
        record, self.world_state = process_session_deception(
            analysis_result,
            self.world_state,
        )
        return record

    def reset(self) -> None:
        """Reset world state to default fresh state."""
        self.world_state = WorldState.create_default()
