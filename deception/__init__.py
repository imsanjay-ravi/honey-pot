"""
deception — AI Adaptive Cyber Deception Engine and Simulated World State.

Modules:
- world_state: In-memory representation of fictional honeypot environment.
- actions: Approved deception action catalog and safe state transitions.
- policy_engine: Deterministic policy rules mapping analysis findings to actions.
- engine: Orchestrator wiring analysis results to world state updates.
"""

from deception.actions import (
    ACTION_NO_OP,
    ACTION_PRESENT_DECOY,
    ACTION_RECORD_INTEREST,
    ACTION_REVEAL_SERVICE,
    APPROVED_ACTIONS,
    ActionResult,
    DeceptionAction,
    apply_action,
    validate_action,
)
from deception.engine import DeceptionEngine, process_session_deception
from deception.policy_engine import PolicyDecision, evaluate_policy
from deception.world_state import (
    DecoyFile,
    FictionalService,
    FictionalUser,
    HostIdentity,
    WorldState,
)

__all__ = [
    "ACTION_NO_OP",
    "ACTION_PRESENT_DECOY",
    "ACTION_RECORD_INTEREST",
    "ACTION_REVEAL_SERVICE",
    "APPROVED_ACTIONS",
    "ActionResult",
    "DeceptionAction",
    "DeceptionEngine",
    "DecoyFile",
    "FictionalService",
    "FictionalUser",
    "HostIdentity",
    "PolicyDecision",
    "WorldState",
    "apply_action",
    "evaluate_policy",
    "process_session_deception",
    "validate_action",
]
