"""
simulator/routes.py — REST API endpoints for the Linux Attacker Simulator.

Exposes endpoints to:
- Execute simulated shell commands from the explicit allowlist.
- Trigger high-level attack scenario actions.
- Retrieve current session state, telemetry events, and deception decisions.
- Start fresh sessions or reset simulation baseline.

SAFETY GUARANTEES:
- Strictly in-memory: Never invokes subprocess, shell, or host command executors.
- Strictly validates command and action parameters against allowlists.
- No network connections to real targets.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from simulator.engine import (
    SUPPORTED_ACTIONS,
    SUPPORTED_COMMANDS,
    SimulatorEngine,
)

router = APIRouter(prefix="/api/simulator", tags=["simulator"])

# Global simulator engine instance
_SIMULATOR = SimulatorEngine()


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class CommandRequest(BaseModel):
    command: str = Field(..., description="Simulated shell command to execute")


class ActionRequest(BaseModel):
    action: str = Field(..., description="High-level scenario action to simulate")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
def get_health() -> dict[str, Any]:
    """Return simulator health status and capability metadata."""
    return {
        "status": "ok",
        "service": "Linux Attacker Simulator",
        "active_session": _SIMULATOR.session_id,
        "supported_commands": sorted(SUPPORTED_COMMANDS),
        "supported_actions": sorted(SUPPORTED_ACTIONS),
    }


@router.get("/state")
def get_state() -> dict[str, Any]:
    """Return the active simulation session state, events, and world state."""
    return _SIMULATOR.get_state()


@router.post("/session/new")
def start_new_session() -> dict[str, str]:
    """Start a fresh simulated session ID."""
    sid = _SIMULATOR.start_new_session()
    return {"status": "success", "session_id": sid, "message": "New simulated session initialized."}


@router.post("/reset")
def reset_simulation() -> dict[str, str]:
    """Reset the simulated session and restore WorldState to clean baseline."""
    _SIMULATOR.reset()
    return {
        "status": "success",
        "session_id": _SIMULATOR.session_id,
        "message": "Simulator session and fictional WorldState reset to clean baseline.",
    }


@router.post("/command")
def execute_command(req: CommandRequest) -> dict[str, Any]:
    """
    Safely process a simulated command entered by the user.
    """
    if not isinstance(req.command, str):
        raise HTTPException(status_code=400, detail="Command must be a string.")

    # Guard against excessively long input
    if len(req.command) > 500:
        raise HTTPException(status_code=400, detail="Command exceeds maximum length of 500 characters.")

    return _SIMULATOR.execute_command(req.command)


@router.post("/action")
def execute_action(req: ActionRequest) -> dict[str, Any]:
    """
    Execute a predefined attack scenario action.
    """
    if req.action not in SUPPORTED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Action '{req.action}' is not supported. Choose from: {sorted(SUPPORTED_ACTIONS)}",
        )

    try:
        return _SIMULATOR.execute_action(req.action)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation error: {exc}")
