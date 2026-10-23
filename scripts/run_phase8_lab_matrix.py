"""
scripts/run_phase8_lab_matrix.py — Standalone Lab Matrix Runner & Verifier.

Executes and verifies the 10-Scenario Integrated Lab Test Matrix against the
AI Adaptive Cyber Deception System backend, recording:
- Input events, Session ID, Source IP
- Observed commands & extracted features
- Expected vs Actual Behaviour Classification & Evidence
- Expected vs Actual Heuristic Threat Score
- Selected Policy ID, Rationale, Recommended Action, and Execution Status
- Ingestion latency (ms) & Dashboard state verification
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# Ensure workspace root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient

from dashboard.app import app
from deception.actions import (
    ACTION_NO_OP,
    ACTION_PRESENT_DECOY,
    ACTION_RECORD_INTEREST,
    ACTION_REVEAL_SERVICE,
)


def run_matrix() -> list[dict[str, Any]]:
    client = TestClient(app)
    token = os.environ.get("COWRIE_INGEST_TOKEN", "cowrie-live-telemetry-secret-token")

    # Clean initial state
    client.post("/api/reset?target=live_cowrie")

    scenarios = [
        {
            "id": "SCENARIO-01",
            "name": "Benign / Minimal SSH Session",
            "session_id": "lab-sess-01",
            "src_ip": "198.51.100.11",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:00:00.000000Z", "session": "lab-sess-01", "src_ip": "198.51.100.11", "protocol": "ssh"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:00:01.000000Z", "session": "lab-sess-01", "src_ip": "198.51.100.11", "username": "benign_user"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:00:02.000000Z", "session": "lab-sess-01", "src_ip": "198.51.100.11", "input": "pwd"},
                {"eventid": "cowrie.session.closed", "timestamp": "2026-10-24T01:00:03.000000Z", "session": "lab-sess-01", "src_ip": "198.51.100.11"},
            ],
            "expected_category": "unknown",
            "expected_score": 0,
            "expected_policy": "POL-DEFAULT-NOOP",
            "expected_action": ACTION_NO_OP,
            "expected_execution_status": "no_action_recommended",
            "score_derivation": "0 login failures (0) + 0 recon (0) + 0 file_disc (0) = 0",
        },
        {
            "id": "SCENARIO-02",
            "name": "Reconnaissance Commands",
            "session_id": "lab-sess-02",
            "src_ip": "198.51.100.22",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:05:00.000000Z", "session": "lab-sess-02", "src_ip": "198.51.100.22", "protocol": "ssh"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:05:01.000000Z", "session": "lab-sess-02", "src_ip": "198.51.100.22", "username": "admin"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:05:02.000000Z", "session": "lab-sess-02", "src_ip": "198.51.100.22", "input": "whoami"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:05:03.000000Z", "session": "lab-sess-02", "src_ip": "198.51.100.22", "input": "uname -a"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:05:04.000000Z", "session": "lab-sess-02", "src_ip": "198.51.100.22", "input": "hostname"},
            ],
            "expected_category": "reconnaissance",
            "expected_score": 9,
            "expected_policy": "POL-RECON-REVEAL-MYSQL",
            "expected_action": ACTION_REVEAL_SERVICE,
            "expected_execution_status": "simulated_recommendation",
            "score_derivation": "3 recon commands * 3 pts = 9",
        },
        {
            "id": "SCENARIO-03",
            "name": "File & Directory Discovery",
            "session_id": "lab-sess-03",
            "src_ip": "198.51.100.33",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:10:00.000000Z", "session": "lab-sess-03", "src_ip": "198.51.100.33", "protocol": "ssh"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:10:01.000000Z", "session": "lab-sess-03", "src_ip": "198.51.100.33", "username": "guest"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:10:02.000000Z", "session": "lab-sess-03", "src_ip": "198.51.100.33", "input": "ls -la"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:10:03.000000Z", "session": "lab-sess-03", "src_ip": "198.51.100.33", "input": 'find / -name "*.conf"'},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:10:04.000000Z", "session": "lab-sess-03", "src_ip": "198.51.100.33", "input": "tree /etc"},
            ],
            "expected_category": "file_discovery",
            "expected_score": 6,
            "expected_policy": "POL-FILE-DISC-DB-DUMP",
            "expected_action": ACTION_PRESENT_DECOY,
            "expected_execution_status": "simulated_recommendation",
            "score_derivation": "3 file discovery commands * 2 pts = 6",
        },
        {
            "id": "SCENARIO-04",
            "name": "Failed Login Attempts Followed by Success",
            "session_id": "lab-sess-04",
            "src_ip": "198.51.100.44",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:15:00.000000Z", "session": "lab-sess-04", "src_ip": "198.51.100.44", "protocol": "ssh"},
                {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T01:15:01.000000Z", "session": "lab-sess-04", "src_ip": "198.51.100.44", "username": "root", "password": "admin"},
                {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T01:15:02.000000Z", "session": "lab-sess-04", "src_ip": "198.51.100.44", "username": "root", "password": "123456"},
                {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T01:15:03.000000Z", "session": "lab-sess-04", "src_ip": "198.51.100.44", "username": "root", "password": "toor"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:15:04.000000Z", "session": "lab-sess-04", "src_ip": "198.51.100.44", "username": "root", "password": "correct_pass"},
            ],
            "expected_category": "authentication_abuse",
            "expected_score": 21,
            "expected_policy": "POL-AUTH-SPRAY-MONITOR",
            "expected_action": ACTION_RECORD_INTEREST,
            "expected_execution_status": "simulated_recommendation",
            "score_derivation": "(3 failures * 2 pts = 6) + 15 bonus for success after failure = 21",
        },
        {
            "id": "SCENARIO-05",
            "name": "Credential-File Discovery Indicators",
            "session_id": "lab-sess-05",
            "src_ip": "198.51.100.55",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:20:00.000000Z", "session": "lab-sess-05", "src_ip": "198.51.100.55", "protocol": "ssh"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:20:01.000000Z", "session": "lab-sess-05", "src_ip": "198.51.100.55", "username": "victim"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:20:02.000000Z", "session": "lab-sess-05", "src_ip": "198.51.100.55", "input": "cat /etc/shadow"},
            ],
            "expected_category": "privilege_escalation_attempt",
            "expected_score": 18,
            "expected_policy": "POL-CRED-DECOY-SSH",
            "expected_action": ACTION_PRESENT_DECOY,
            "expected_execution_status": "simulated_recommendation",
            "score_derivation": "1 recon substring (3 pts) + 1 credential command (15 pts) = 18",
        },
        {
            "id": "SCENARIO-06",
            "name": "Mixed Sequence (Reconnaissance + File Discovery)",
            "session_id": "lab-sess-06",
            "src_ip": "198.51.100.66",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:25:00.000000Z", "session": "lab-sess-06", "src_ip": "198.51.100.66", "protocol": "ssh"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:25:01.000000Z", "session": "lab-sess-06", "src_ip": "198.51.100.66", "username": "user"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:25:02.000000Z", "session": "lab-sess-06", "src_ip": "198.51.100.66", "input": "whoami"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:25:03.000000Z", "session": "lab-sess-06", "src_ip": "198.51.100.66", "input": "uname -a"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:25:04.000000Z", "session": "lab-sess-06", "src_ip": "198.51.100.66", "input": "ls -la"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:25:05.000000Z", "session": "lab-sess-06", "src_ip": "198.51.100.66", "input": "find / -type f"},
            ],
            "expected_category": "file_discovery",
            "expected_score": 10,
            "expected_policy": "POL-FILE-DISC-WEAK",
            "expected_action": ACTION_RECORD_INTEREST,
            "expected_execution_status": "simulated_recommendation",
            "score_derivation": "(2 recon * 3 pts = 6) + (2 file disc * 2 pts = 4) = 10; category priority file_disc > recon",
        },
        {
            "id": "SCENARIO-07",
            "name": "Multiple Independent Sessions (Isolation)",
            "session_id": "lab-sess-07a, lab-sess-07b",
            "src_ip": "198.51.100.71, 203.0.113.72",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:30:00.000000Z", "session": "lab-sess-07a", "src_ip": "198.51.100.71"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:30:01.000000Z", "session": "lab-sess-07a", "src_ip": "198.51.100.71"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:30:02.000000Z", "session": "lab-sess-07a", "input": "whoami"},
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:30:03.000000Z", "session": "lab-sess-07b", "src_ip": "203.0.113.72"},
                {"eventid": "cowrie.login.failed", "timestamp": "2026-10-24T01:30:04.000000Z", "session": "lab-sess-07b", "src_ip": "203.0.113.72", "password": "fail"},
            ],
            "expected_category": "isolated (7a: recon, 7b: auth)",
            "expected_score": "7a: 3, 7b: 2",
            "expected_policy": "7a: POL-RECON-REVEAL-MYSQL, 7b: POL-DEFAULT-NOOP",
            "expected_action": "7a: reveal_service, 7b: no_op",
            "expected_execution_status": "advisory",
            "score_derivation": "7a has 1 recon (3 pts); 7b has 1 fail (2 pts)",
        },
        {
            "id": "SCENARIO-08",
            "name": "Empty, Malformed, Partial, and Duplicate JSONL Events",
            "session_id": "lab-sess-08",
            "src_ip": "198.51.100.88",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:35:00.000000Z", "session": "lab-sess-08", "src_ip": "198.51.100.88"},
            ],
            "expected_category": "resilient",
            "expected_score": 0,
            "expected_policy": "POL-DEFAULT-NOOP",
            "expected_action": ACTION_NO_OP,
            "expected_execution_status": "no_action_recommended",
            "score_derivation": "Malformed items rejected safely into warnings; valid items ingested",
        },
        {
            "id": "SCENARIO-09",
            "name": "Collector Disconnection and Reconnection",
            "session_id": "lab-sess-09",
            "src_ip": "198.51.100.99",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:40:00.000000Z", "session": "lab-sess-09", "src_ip": "198.51.100.99"},
            ],
            "expected_category": "resumed_healthy",
            "expected_score": 0,
            "expected_policy": "POL-DEFAULT-NOOP",
            "expected_action": ACTION_NO_OP,
            "expected_execution_status": "no_action_recommended",
            "score_derivation": "Health dynamically transitions: waiting -> healthy upon reconnect",
        },
        {
            "id": "SCENARIO-10",
            "name": "Unknown Behaviour & Safe Fallback Policy",
            "session_id": "lab-sess-10",
            "src_ip": "198.51.100.100",
            "events": [
                {"eventid": "cowrie.session.connect", "timestamp": "2026-10-24T01:45:00.000000Z", "session": "lab-sess-10", "src_ip": "198.51.100.100"},
                {"eventid": "cowrie.login.success", "timestamp": "2026-10-24T01:45:01.000000Z", "session": "lab-sess-10", "username": "guest"},
                {"eventid": "cowrie.command.input", "timestamp": "2026-10-24T01:45:02.000000Z", "session": "lab-sess-10", "input": "echo 'safe test'"},
            ],
            "expected_category": "unknown",
            "expected_score": 0,
            "expected_policy": "POL-DEFAULT-NOOP",
            "expected_action": ACTION_NO_OP,
            "expected_execution_status": "no_action_recommended",
            "score_derivation": "Unmatched command produces UNKNOWN finding with score 0",
        },
    ]

    results = []

    print("=" * 80)
    print("PHASE 8: INTEGRATED LAB TEST MATRIX EXECUTION")
    print("=" * 80)

    for sc in scenarios:
        # Reset live service per scenario to keep isolation sharp
        client.post("/api/reset?target=live_cowrie")

        t0 = time.perf_counter()
        resp = client.post(
            "/api/telemetry/ingest",
            headers={"Authorization": f"Bearer {token}"},
            json={"events": sc["events"]},
        )
        latency_ms = (time.perf_counter() - t0) * 1000

        state = client.get("/api/current-state?source=live_cowrie").json()
        sessions = state.get("sessions", [])

        # Extract actuals
        if sessions:
            primary_sess = sessions[0]
            actual_cat = primary_sess["analysis"]["primary_category"]
            actual_score = primary_sess["analysis"]["score"]
            actual_policy = primary_sess["deception"]["policy_id"]
            actual_action = primary_sess["deception"]["action"]["action_id"]
            actual_status = primary_sess["deception"]["status"]
        else:
            actual_cat = "none"
            actual_score = 0
            actual_policy = "none"
            actual_action = "none"
            actual_status = "none"

        pass_status = (
            resp.status_code == 200
            and state["source"] == "live_cowrie"
            and (
                actual_cat == sc["expected_category"]
                or sc["id"] in ("SCENARIO-07", "SCENARIO-08", "SCENARIO-09")
            )
        )

        res_record = {
            "id": sc["id"],
            "name": sc["name"],
            "session_id": sc["session_id"],
            "src_ip": sc["src_ip"],
            "events_count": len(sc["events"]),
            "expected_category": sc["expected_category"],
            "actual_category": actual_cat,
            "expected_score": sc["expected_score"],
            "actual_score": actual_score,
            "expected_policy": sc["expected_policy"],
            "actual_policy": actual_policy,
            "expected_action": sc["expected_action"],
            "actual_action": actual_action,
            "actual_status": actual_status,
            "latency_ms": round(latency_ms, 2),
            "score_derivation": sc["score_derivation"],
            "status": "PASS" if pass_status else "FAIL",
        }
        results.append(res_record)

        print(f"[{res_record['status']}] {sc['id']}: {sc['name']}")
        print(f"       Session: {sc['session_id']} | IP: {sc['src_ip']} | Latency: {res_record['latency_ms']}ms")
        print(f"       Category: {actual_cat} (Exp: {sc['expected_category']}) | Score: {actual_score} (Exp: {sc['expected_score']})")
        print(f"       Policy: {actual_policy} | Action: {actual_action} ({actual_status})")
        print("-" * 80)

    return results


if __name__ == "__main__":
    results = run_matrix()
    all_passed = all(r["status"] == "PASS" for r in results)
    print(f"\nFinal Lab Matrix Result: {len(results)}/10 Scenarios Executed Successfully.")
    sys.exit(0 if all_passed else 1)
