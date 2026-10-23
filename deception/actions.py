"""
deception/actions.py — Approved deception actions and safe state transitions.

Defines the explicit allowlist of simulated deception actions that can be
applied to the fictional world state:
- present_decoy_file
- reveal_fake_service
- record_attacker_interest
- no_op (safe fallback)

Each action enforces strict preconditions, target validation, and deterministic
state transitions.

SAFETY CONSTRAINTS:
- No subprocesses, shell executions, or system calls.
- No interaction with the host operating system or filesystem.
- Only targets within the fictional world state are valid.
- Any action outside the allowlist is rejected immediately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deception.world_state import WorldState


# ---------------------------------------------------------------------------
# Action Identifiers Allowlist
# ---------------------------------------------------------------------------

ACTION_PRESENT_DECOY = "present_decoy_file"
ACTION_REVEAL_SERVICE = "reveal_fake_service"
ACTION_RECORD_INTEREST = "record_attacker_interest"
ACTION_NO_OP = "no_op"

APPROVED_ACTIONS = frozenset({
    ACTION_PRESENT_DECOY,
    ACTION_REVEAL_SERVICE,
    ACTION_RECORD_INTEREST,
    ACTION_NO_OP,
})

# Recognized attacker interest topics
VALID_INTEREST_TOPICS = frozenset({
    "reconnaissance",
    "authentication_spray",
    "credential_harvesting",
    "file_discovery",
    "tooling_download",
    "privilege_escalation",
    "persistence",
    "evasion",
})


# ---------------------------------------------------------------------------
# Action and Result Data Classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeceptionAction:
    """
    Representation of a simulated deception action.

    Attributes
    ----------
    action_id:
        One of APPROVED_ACTIONS.
    target:
        Target in the fictional environment (e.g. file path, service name, or topic).
    parameters:
        Optional key-value parameters.
    description:
        Human-readable explanation of intent.
    """
    action_id: str
    target: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "target": self.target,
            "parameters": dict(self.parameters),
            "description": self.description,
        }


@dataclass(frozen=True)
class ActionResult:
    """
    Outcome of validating and applying an action to the WorldState.
    """
    success: bool
    action_id: str
    target: str | None
    explanation: str
    state_change: dict[str, Any]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "action_id": self.action_id,
            "target": self.target,
            "explanation": self.explanation,
            "state_change": self.state_change,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Action Validation
# ---------------------------------------------------------------------------

def validate_action(
    action: DeceptionAction,
    world_state: WorldState,
) -> tuple[bool, str]:
    """
    Validate whether an action is approved, properly formed, and satisfies
    preconditions against the current world state.

    Returns
    -------
    tuple[bool, str]
        (True, "OK") if valid, or (False, reason) if invalid or impossible.
    """
    if not isinstance(action, DeceptionAction):
        return False, f"Expected DeceptionAction, got {type(action).__name__}"

    if action.action_id not in APPROVED_ACTIONS:
        return False, f"Action {action.action_id!r} is not in the approved actions allowlist."

    # 1. no_op is always valid
    if action.action_id == ACTION_NO_OP:
        return True, "Safe no-op action is always valid."

    # 2. present_decoy_file
    if action.action_id == ACTION_PRESENT_DECOY:
        if not action.target or not isinstance(action.target, str):
            return False, "present_decoy_file requires a valid target file path string."
        if action.target not in world_state.decoy_files:
            return False, f"Target file {action.target!r} does not exist in fictional decoy catalog."
        if world_state.is_decoy_visible(action.target):
            return False, f"Precondition failed: decoy file {action.target!r} is already visible."
        return True, f"Precondition satisfied: decoy {action.target} can be presented."

    # 3. reveal_fake_service
    if action.action_id == ACTION_REVEAL_SERVICE:
        if not action.target or not isinstance(action.target, str):
            return False, "reveal_fake_service requires a valid target service name string."
        if action.target not in world_state.services:
            return False, f"Target service {action.target!r} does not exist in fictional service catalog."
        svc = world_state.services[action.target]
        if svc.state != "hidden" or action.target in world_state.discovered_services:
            return False, f"Precondition failed: service {action.target!r} is already active or revealed."
        return True, f"Precondition satisfied: service {action.target} can be revealed."

    # 4. record_attacker_interest
    if action.action_id == ACTION_RECORD_INTEREST:
        if not action.target or not isinstance(action.target, str):
            return False, "record_attacker_interest requires a valid interest topic string."
        if action.target not in VALID_INTEREST_TOPICS:
            return False, f"Interest topic {action.target!r} is not in recognized topics allowlist."
        return True, f"Precondition satisfied: interest topic {action.target} can be recorded."

    return False, f"Unhandled action {action.action_id!r}."


# ---------------------------------------------------------------------------
# Action Execution / State Transition
# ---------------------------------------------------------------------------

def apply_action(
    action: DeceptionAction,
    world_state: WorldState,
) -> ActionResult:
    """
    Safely apply an approved deception action to the fictional world state.

    Parameters
    ----------
    action:
        The action to apply.
    world_state:
        The fictional world state to modify in-memory.

    Returns
    -------
    ActionResult
        Details of whether the transition succeeded and the state change applied.
    """
    is_valid, validation_msg = validate_action(action, world_state)
    if not is_valid:
        return ActionResult(
            success=False,
            action_id=action.action_id,
            target=action.target,
            explanation=action.description or "Action validation failed.",
            state_change={},
            error=validation_msg,
        )

    # 1. no_op
    if action.action_id == ACTION_NO_OP:
        record = {
            "action_id": ACTION_NO_OP,
            "target": action.target,
            "explanation": action.description or "No deception action required.",
        }
        world_state.action_history.append(record)
        return ActionResult(
            success=True,
            action_id=ACTION_NO_OP,
            target=action.target,
            explanation=action.description or "No deception action required.",
            state_change={"no_op": True},
        )

    # 2. present_decoy_file
    if action.action_id == ACTION_PRESENT_DECOY:
        assert action.target is not None
        ok = world_state.present_decoy(action.target)
        if not ok:
            return ActionResult(
                success=False,
                action_id=ACTION_PRESENT_DECOY,
                target=action.target,
                explanation=action.description,
                state_change={},
                error="Failed to present decoy file: state conflict.",
            )
        decoy = world_state.decoy_files[action.target]
        state_change = {
            "decoy_presented": action.target,
            "file_type": decoy.file_type,
            "is_visible": True,
        }
        record = {
            "action_id": ACTION_PRESENT_DECOY,
            "target": action.target,
            "explanation": action.description,
            "state_change": state_change,
        }
        world_state.action_history.append(record)
        return ActionResult(
            success=True,
            action_id=ACTION_PRESENT_DECOY,
            target=action.target,
            explanation=action.description or f"Presented decoy file {action.target}.",
            state_change=state_change,
        )

    # 3. reveal_fake_service
    if action.action_id == ACTION_REVEAL_SERVICE:
        assert action.target is not None
        ok = world_state.reveal_service(action.target)
        if not ok:
            return ActionResult(
                success=False,
                action_id=ACTION_REVEAL_SERVICE,
                target=action.target,
                explanation=action.description,
                state_change={},
                error="Failed to reveal service: state conflict.",
            )
        svc = world_state.services[action.target]
        state_change = {
            "service_revealed": action.target,
            "port": svc.port,
            "protocol": svc.protocol,
            "new_state": "revealed",
        }
        record = {
            "action_id": ACTION_REVEAL_SERVICE,
            "target": action.target,
            "explanation": action.description,
            "state_change": state_change,
        }
        world_state.action_history.append(record)
        return ActionResult(
            success=True,
            action_id=ACTION_REVEAL_SERVICE,
            target=action.target,
            explanation=action.description or f"Revealed simulated service {action.target}.",
            state_change=state_change,
        )

    # 4. record_attacker_interest
    if action.action_id == ACTION_RECORD_INTEREST:
        assert action.target is not None
        newly_added = world_state.record_interest(action.target)
        state_change = {
            "topic": action.target,
            "newly_added": newly_added,
        }
        record = {
            "action_id": ACTION_RECORD_INTEREST,
            "target": action.target,
            "explanation": action.description,
            "state_change": state_change,
        }
        world_state.action_history.append(record)
        return ActionResult(
            success=True,
            action_id=ACTION_RECORD_INTEREST,
            target=action.target,
            explanation=action.description or f"Recorded attacker interest: {action.target}.",
            state_change=state_change,
        )

    # Fallback safety
    return ActionResult(
        success=False,
        action_id=action.action_id,
        target=action.target,
        explanation="Action not recognized by execution handler.",
        state_change={},
        error=f"Unrecognized action_id: {action.action_id}",
    )
