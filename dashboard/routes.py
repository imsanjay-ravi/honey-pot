"""
dashboard/routes.py — REST API endpoints for the Ubuntu Analysis Dashboard.

Exposes endpoints to:
- List approved synthetic scenarios.
- Execute offline pipeline runs on selected scenarios.
- Query current session analysis, threat findings, and deception decisions.
- Inspect the fictional WorldState.
- Export sanitized pipeline results.
- Reset the in-memory simulation state.

SECURITY CONSTRAINTS:
- Strict path traversal prevention: Only approved fixtures from examples/scenarios/ can be loaded.
- Never executes shell commands or attacker strings.
- Operates entirely in memory; no modifications to host filesystem.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from deception.world_state import WorldState
from pipeline import PIPELINE_VERSION, run_pipeline
from simulator.routes import _SIMULATOR
from telemetry.live_service import get_live_service

router = APIRouter(prefix="/api", tags=["dashboard"])

# Approved base directory for synthetic scenarios
SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "examples" / "scenarios"

# Global state for dashboard backend
_CURRENT_RESULT: dict[str, Any] | None = None
_CURRENT_WORLD_STATE: WorldState = WorldState.create_default()


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class ScenarioInfo(BaseModel):
    name: str
    filename: str
    description: str
    category: str


class RunScenarioRequest(BaseModel):
    scenario: str = Field(..., description="Filename of approved scenario in examples/scenarios/")
    accumulate_state: bool = Field(
        default=False,
        description="Whether to accumulate state into existing WorldState or start fresh",
    )


class HealthResponse(BaseModel):
    status: str
    version: str
    scenarios_available: int


class TelemetryIngestRequest(BaseModel):
    events: list[dict[str, Any]] = Field(..., description="Array of Cowrie JSON event dictionaries")


# Metadata descriptions for standard scenarios
SCENARIO_METADATA: dict[str, dict[str, str]] = {
    "reconnaissance.jsonl": {
        "name": "Reconnaissance Enumeration",
        "category": "reconnaissance",
        "description": "Systematic host inspection commands (whoami, uname, hostname, id, ifconfig).",
    },
    "authentication_abuse.jsonl": {
        "name": "Authentication Abuse / Brute Force",
        "category": "authentication_abuse",
        "description": "Repeated failed login attempts across multiple common administrative usernames.",
    },
    "file_discovery.jsonl": {
        "name": "Systematic File Discovery",
        "category": "file_discovery",
        "description": "Filesystem search commands targeting configuration and environment files (ls, find, locate).",
    },
    "download_attempt.jsonl": {
        "name": "Download / Tooling Transfer",
        "category": "download_attempt",
        "description": "Attacker command attempting external payload retrieval using wget.",
    },
    "privilege_escalation.jsonl": {
        "name": "Privilege Escalation / Credential Access",
        "category": "privilege_escalation_attempt",
        "description": "Direct attempts to read /etc/passwd, /etc/shadow, and SSH key directories.",
    },
    "unknown_benign.jsonl": {
        "name": "Benign Operational Commands",
        "category": "unknown",
        "description": "Routine non-threatening system health commands (date, echo). Safe no-op response.",
    },
    "combined_multi_session.jsonl": {
        "name": "Full Multi-Session Scenario",
        "category": "multi_session",
        "description": "Comprehensive scenario containing all 6 behaviors plus recoverable parser warnings.",
    },
}


# ---------------------------------------------------------------------------
# Path Security Validator
# ---------------------------------------------------------------------------

def _validate_scenario_path(filename: str) -> Path:
    """
    Validate that *filename* is a valid file within SCENARIOS_DIR.
    Prevents path traversal attempts (e.g. '../', absolute paths, etc.).
    """
    if not filename or not isinstance(filename, str):
        raise HTTPException(status_code=400, detail="Scenario filename must be a non-empty string.")

    # Disallow path separators in filename
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(
            status_code=400,
            detail="Path traversal characters ('/', '\\', '..') are strictly prohibited.",
        )

    resolved_path = (SCENARIOS_DIR / filename).resolve()
    resolved_dir = SCENARIOS_DIR.resolve()

    # Ensure path stays strictly inside SCENARIOS_DIR
    try:
        resolved_path.relative_to(resolved_dir)
    except ValueError:
        raise HTTPException(status_code=400, detail="Access outside approved scenarios directory is prohibited.")

    if not resolved_path.is_file():
        raise HTTPException(status_code=404, detail=f"Scenario fixture '{filename}' not found.")

    return resolved_path


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return API health status and engine version."""
    count = len(list(SCENARIOS_DIR.glob("*.jsonl"))) if SCENARIOS_DIR.exists() else 0
    return HealthResponse(
        status="ok",
        version=PIPELINE_VERSION,
        scenarios_available=count,
    )


@router.get("/scenarios", response_model=list[ScenarioInfo])
def list_scenarios() -> list[ScenarioInfo]:
    """List all available approved synthetic scenarios."""
    if not SCENARIOS_DIR.exists():
        return []

    scenarios = []
    for p in sorted(SCENARIOS_DIR.glob("*.jsonl")):
        fname = p.name
        meta = SCENARIO_METADATA.get(fname, {
            "name": fname.replace(".jsonl", "").replace("_", " ").title(),
            "category": "custom",
            "description": f"Synthetic scenario fixture ({fname}).",
        })
        scenarios.append(
            ScenarioInfo(
                filename=fname,
                name=meta["name"],
                category=meta["category"],
                description=meta["description"],
            )
        )
    return scenarios


@router.get("/sources")
def list_sources() -> list[dict[str, Any]]:
    """
    List available telemetry sources, indicating whether each source currently
    has active or loaded data.
    """
    live_service = get_live_service()
    live_health = live_service.get_health()

    return [
        {
            "id": "scenario",
            "name": "Synthetic Scenarios",
            "loaded": _CURRENT_RESULT is not None,
            "description": "Pre-packaged offline Cowrie session fixtures from examples/scenarios/.",
        },
        {
            "id": "simulator",
            "name": "Attacker Simulator",
            "loaded": _SIMULATOR.has_activity(),
            "description": "Interactive in-memory Linux Attacker Simulator sessions.",
        },
        {
            "id": "live_cowrie",
            "name": "Live Cowrie Honeypot",
            "loaded": live_service.has_activity(),
            "available": True,
            "status": live_health["status"],
            "description": "Real-time Cowrie JSON telemetry streamed from the Ubuntu honeypot.",
        },
    ]


@router.post("/run-scenario")
def run_scenario(req: RunScenarioRequest) -> dict[str, Any]:
    """
    Execute the offline analysis and deception pipeline on the requested scenario.
    """
    global _CURRENT_RESULT, _CURRENT_WORLD_STATE

    scenario_path = _validate_scenario_path(req.scenario)

    target_world_state = _CURRENT_WORLD_STATE if req.accumulate_state else WorldState.create_default()

    try:
        result = run_pipeline(
            log_file=scenario_path,
            world_state=target_world_state,
            quiet=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline processing error: {exc}")

    result["source"] = "scenario"
    result["source_label"] = f"Synthetic Scenario ({req.scenario})"
    _CURRENT_RESULT = result
    _CURRENT_WORLD_STATE = target_world_state

    return result


@router.get("/current-state")
def get_current_state(source: str | None = Query(default=None)) -> dict[str, Any]:
    """
    Return the latest pipeline run results and current WorldState.
    Supports explicitly selecting 'scenario', 'simulator', or 'live_cowrie' as the telemetry source.
    """
    global _CURRENT_RESULT, _CURRENT_WORLD_STATE

    if source not in (None, "scenario", "simulator", "live_cowrie"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid telemetry source '{source}'. Choose from: 'scenario', 'simulator', 'live_cowrie'.",
        )

    live_service = get_live_service()

    # Explicit request for live cowrie honeypot telemetry
    if source == "live_cowrie":
        return live_service.get_pipeline_result()

    # Explicit request for simulator telemetry
    if source == "simulator":
        return _SIMULATOR.get_pipeline_result()

    # Explicit request for synthetic scenario results
    if source == "scenario":
        if _CURRENT_RESULT is None:
            return {
                "loaded": False,
                "source": "scenario",
                "source_label": "Synthetic Scenarios",
                "message": "No scenario has been loaded yet.",
                "world_state": _CURRENT_WORLD_STATE.to_dict(),
                "sessions": [],
                "events_parsed": 0,
                "warnings_count": 0,
            }
        return {
            "loaded": True,
            "source": "scenario",
            "source_label": _CURRENT_RESULT.get("source_label", "Synthetic Scenarios"),
            **_CURRENT_RESULT,
        }

    # Default fallback: if scenario result is loaded, prefer it;
    # otherwise, if simulator has activity, return simulator;
    # otherwise, if live cowrie has activity, return live cowrie.
    if _CURRENT_RESULT is not None:
        return {
            "loaded": True,
            "source": "scenario",
            "source_label": _CURRENT_RESULT.get("source_label", "Synthetic Scenarios"),
            **_CURRENT_RESULT,
        }

    if _SIMULATOR.has_activity():
        return _SIMULATOR.get_pipeline_result()

    if live_service.has_activity():
        return live_service.get_pipeline_result()

    return {
        "loaded": False,
        "source": "scenario",
        "source_label": "Synthetic Scenarios",
        "message": "No scenario telemetry has been loaded yet.",
        "world_state": _CURRENT_WORLD_STATE.to_dict(),
        "sessions": [],
        "events_parsed": 0,
        "warnings_count": 0,
    }


@router.post("/reset")
def reset_state(target: str = Query(default="all")) -> dict[str, str]:
    """
    Reset the fictional world state and clear active scenario, simulator, or live telemetry results.
    Optional query parameter 'target': 'all', 'scenario', 'simulator', or 'live_cowrie'.
    """
    global _CURRENT_RESULT, _CURRENT_WORLD_STATE

    if target not in ("all", "scenario", "simulator", "live_cowrie"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid reset target '{target}'. Choose from: 'all', 'scenario', 'simulator', 'live_cowrie'.",
        )

    live_service = get_live_service()
    messages = []

    if target in ("all", "scenario"):
        _CURRENT_RESULT = None
        _CURRENT_WORLD_STATE = WorldState.create_default()
        messages.append("Synthetic scenario state reset")

    if target in ("all", "simulator"):
        _SIMULATOR.reset()
        messages.append("Simulator state reset")

    if target in ("all", "live_cowrie"):
        live_service.reset()
        messages.append("Live Cowrie telemetry buffer reset")

    return {
        "status": "success",
        "target": target,
        "message": f"{'; '.join(messages)} to clean baseline.",
    }


@router.get("/export")
def export_results(source: str | None = Query(default=None)) -> Response:
    """
    Download the current sanitized analysis and deception results as a JSON file.
    Supports querying by source ('scenario', 'simulator', or 'live_cowrie').
    """
    global _CURRENT_RESULT

    if source not in (None, "scenario", "simulator", "live_cowrie"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid telemetry source '{source}'. Choose from: 'scenario', 'simulator', 'live_cowrie'.",
        )

    live_service = get_live_service()

    if source == "live_cowrie" or (
        source is None
        and _CURRENT_RESULT is None
        and not _SIMULATOR.has_activity()
        and live_service.has_activity()
    ):
        res = live_service.get_pipeline_result()
        if not res.get("loaded"):
            raise HTTPException(
                status_code=400,
                detail="No live Cowrie results available to export. Ingest live telemetry first.",
            )
        payload = json.dumps(res, indent=2)
        filename = "live_cowrie_deception_report.json"
    elif source == "simulator" or (
        source is None
        and _CURRENT_RESULT is None
        and _SIMULATOR.has_activity()
    ):
        res = _SIMULATOR.get_pipeline_result()
        if not res.get("loaded"):
            raise HTTPException(
                status_code=400,
                detail="No simulator results available to export. Run actions in the simulator first.",
            )
        payload = json.dumps(res, indent=2)
        filename = "simulator_deception_report.json"
    else:
        if _CURRENT_RESULT is None:
            raise HTTPException(
                status_code=400,
                detail="No scenario results available to export. Run a scenario first.",
            )
        payload = json.dumps({
            "source": "scenario",
            "source_label": _CURRENT_RESULT.get("source_label", "Synthetic Scenarios"),
            **_CURRENT_RESULT,
        }, indent=2)
        filename = "cyber_deception_report.json"

    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Phase 7 Live Telemetry Ingestion Endpoints
# ---------------------------------------------------------------------------

@router.post("/telemetry/ingest")
def ingest_telemetry(
    req: TelemetryIngestRequest,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """
    Authenticated ingestion endpoint for the Ubuntu Cowrie Telemetry Collector.
    Accepts arrays of JSON event objects from the honeypot.
    """
    live_service = get_live_service()

    # Extract bearer token
    token = None
    if authorization:
        parts = authorization.split()
        token = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else authorization

    if not live_service.verify_auth_token(token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing or invalid telemetry bearer token.",
        )

    # Protect against unbounded payload sizes
    if len(req.events) > 1000:
        raise HTTPException(
            status_code=400,
            detail="Batch exceeds maximum limit of 1000 events.",
        )

    remote_ip = request.client.host if request.client else "unknown"
    accepted, warn_count = live_service.ingest_batch(req.events, remote_ip=remote_ip)

    return {
        "status": "success",
        "accepted_events": accepted,
        "events_ingested": accepted,
        "warnings_count": warn_count,
        "warnings": live_service.warnings,
        "total_events_in_service": len(live_service.events),
        "sessions_count": len(live_service.sessions),
    }


@router.get("/telemetry/health")
def get_telemetry_health() -> dict[str, Any]:
    """Return live telemetry connection health status and ingestion metrics."""
    return get_live_service().get_health()


@router.post("/telemetry/poll")
def poll_telemetry() -> dict[str, Any]:
    """Manually trigger a poll check against the configured local or mounted Cowrie log file."""
    live_service = get_live_service()
    polled = live_service.poll_local()
    return {
        "status": "success",
        "polled_events": polled,
        "health": live_service.get_health(),
    }


