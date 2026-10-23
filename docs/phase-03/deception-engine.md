# Phase 3 — Adaptive Deception Engine and Simulated World State Design

## 1. Overview and Purpose

Phase 3 introduces an in-memory, deterministic deception policy engine and a fictional world state for the AI Adaptive Cyber Deception System.

The engine consumes structured analysis results produced by the Phase 2 behaviour analysis engine (`analysis/engine.py`) and evaluates explainable, deterministic policies to manipulate a simulated honeypot environment without interacting with real host infrastructure or executing captured attacker commands.

---

## 2. Fictional World State Architecture (`deception/world_state.py`)

The fictional world state maintains an isolated, in-memory representation of an enterprise Linux host.

### Schema Components

1. **Host Identity (`HostIdentity`)**:
   - `hostname`: Fictional hostname (`corp-srv-db01`).
   - `os_name`: Operating system distribution (`Ubuntu 22.04.3 LTS`).
   - `kernel`: Fictional kernel version (`5.15.0-88-generic`).
   - `architecture`: Machine architecture (`x86_64`).
   - `uptime_seconds`: Simulated uptime (`1843200` seconds).
   - `primary_ip`: RFC 5737 documentation IP (`192.0.2.10`).

2. **Fictional Accounts (`FictionalUser`)**:
   - Simulated user accounts (`root`, `deploy`, `backup`, `www-data`) with associated UIDs, GIDs, home directories, login shells, and operational roles.

3. **Simulated Services (`FictionalService`)**:
   - Services with port, protocol, state (`active`, `hidden`, `revealed`), banner, and description.
   - Publicly active services: `ssh` (port 22), `http-web` (port 80).
   - Internal decoy services: `mysql-backend` (port 3306), `redis-cache` (port 6379), `admin-mgmt` (port 8443).

4. **Decoy Files (`DecoyFile`)**:
   - Fictional decoy assets placed at realistic paths:
     - `/root/.ssh/id_rsa_backup` (SSH private key)
     - `/var/www/internal/.env` (Application database secrets)
     - `/home/backup/db_dump.sql` (Database dump archive)
     - `/etc/nginx/ssl_admin_key.pem` (TLS administrative key)
   - Tracks visibility (`is_visible: bool`), metadata (owner, permissions), and synthetic content hints.

5. **Entity Discovery & Interest Tracking**:
   - `discovered_files`: Set of file paths visible to or accessed by the attacker.
   - `discovered_services`: Set of revealed or active service names.
   - `discovered_users`: Set of discovered usernames.
   - `attacker_interests`: Categorical attacker profiling tags (`reconnaissance`, `credential_harvesting`, `file_discovery`, `tooling_download`, `privilege_escalation`, `authentication_spray`).

6. **Audit and Dashboard Visualization**:
   - `action_history`: Chronological record of all applied deception actions.
   - `events`: Ordered event stream containing monotonically increasing `sequence_id`, UTC `timestamp`, `event_type`, and event details.

7. **Isolation & Serialization**:
   - `WorldState.create_default()` initializes a fresh, isolated state with deep copies.
   - `to_dict()` and `from_dict()` provide full JSON serializability for state persistence and dashboard consumption.

---

## 3. Approved Deception Actions (`deception/actions.py`)

All deception actions are restricted to an explicit, immutable allowlist (`APPROVED_ACTIONS`). Any action not in this allowlist is rejected immediately.

| Action Identifier | Target Requirement | Preconditions | State Transition |
|---|---|---|---|
| `present_decoy_file` | Valid decoy path in `decoy_files` | Target file exists in catalog; `is_visible == False` | Sets `is_visible = True`; adds target to `discovered_files`; logs `decoy_file_presented` event |
| `reveal_fake_service` | Valid service name in `services` | Target exists in catalog; `state == "hidden"`; not in `discovered_services` | Sets `state = "revealed"`; adds target to `discovered_services`; logs `service_revealed` event |
| `record_attacker_interest` | Recognized topic in `VALID_INTEREST_TOPICS` | Non-empty topic string | Appends topic to `attacker_interests` (idempotent); logs `attacker_interest_recorded` event |
| `no_op` | None / optional label | None (always valid) | Safe fallback; no modification to files, services, or users |

---

## 4. Deterministic Policy Rules (`deception/policy_engine.py`)

The policy engine maps behaviour findings from Phase 2 to appropriate deception actions based on evidence strength and current world state preconditions:

| Policy ID | Triggering Finding / Evidence | Preconditions | Action Selected | Target |
|---|---|---|---|---|
| `POL-CRED-DECOY-SSH` | `PE-02` (Credential commands targeting `/etc/passwd`, `/etc/shadow`, `.ssh`) | `/root/.ssh/id_rsa_backup` not visible | `present_decoy_file` | `/root/.ssh/id_rsa_backup` |
| `POL-CRED-DECOY-ENV` | `PE-02` | SSH key already visible; `/var/www/internal/.env` not visible | `present_decoy_file` | `/var/www/internal/.env` |
| `POL-CRED-RECORD-INTEREST` | `PE-02` | All credential decoys already visible | `record_attacker_interest` | `credential_harvesting` |
| `POL-PRIV-ESC-RECORD` | `PE-01` (Sudo, su, setuid chmod commands) | None | `record_attacker_interest` | `privilege_escalation` |
| `POL-DOWNLOAD-DECOY-ENV` | `DL-01` (Download command: wget, curl, nc, tftp) | `/var/www/internal/.env` not visible | `present_decoy_file` | `/var/www/internal/.env` |
| `POL-DOWNLOAD-RECORD-INTEREST` | `DL-01` | Decoy already visible | `record_attacker_interest` | `tooling_download` |
| `POL-FILE-DISC-DB-DUMP` | `FD-02` (Systematic file discovery >= 3 commands) | `/home/backup/db_dump.sql` not visible | `present_decoy_file` | `/home/backup/db_dump.sql` |
| `POL-FILE-DISC-SSL-KEY` | `FD-02` | DB dump already visible; SSL key not visible | `present_decoy_file` | `/etc/nginx/ssl_admin_key.pem` |
| `POL-FILE-DISC-RECORD` | `FD-02` | Both decoys already visible | `record_attacker_interest` | `file_discovery` |
| `POL-FILE-DISC-WEAK` | `FD-01` (Single file discovery command, WEAK) | None | `record_attacker_interest` | `file_discovery` |
| `POL-RECON-REVEAL-MYSQL` | `REC-02` or `REC-01` (Reconnaissance commands) | `mysql-backend` service hidden | `reveal_fake_service` | `mysql-backend` |
| `POL-RECON-REVEAL-REDIS` | `REC-02` or `REC-01` | MySQL already revealed; Redis service hidden | `reveal_fake_service` | `redis-cache` |
| `POL-RECON-RECORD-INTEREST` | `REC-02` or `REC-01` | All fake services revealed | `record_attacker_interest` | `reconnaissance` |
| `POL-AUTH-SPRAY-MONITOR` | `AUTH-01`, `AUTH-02`, `AUTH-03` | None | `record_attacker_interest` | `authentication_spray` |
| `POL-DEFAULT-NOOP` | No findings, unknown behaviour, or empty session | None | `no_op` | `None` |

---

## 5. Orchestration Interface (`deception/engine.py`)

The orchestrator wires analysis results with the world state:

```python
from deception.engine import process_session_deception
from deception.world_state import WorldState

# Process a session
record, updated_world_state = process_session_deception(analysis_result, world_state)
```

### Decision Record Schema
```json
{
  "session_id": "recon-session-001",
  "status": "accepted",
  "policy_id": "POL-RECON-REVEAL-MYSQL",
  "action": {
    "action_id": "reveal_fake_service",
    "target": "mysql-backend",
    "parameters": {},
    "description": "Reveal simulated internal MySQL database service to reconnaissance."
  },
  "finding": {
    "rule_id": "REC-02",
    "category": "reconnaissance",
    "evidence": "5 reconnaissance commands — systematic system enumeration pattern.",
    "evidence_strength": "STRONG"
  },
  "explanation": "System enumeration observed; revealing internal MySQL service.",
  "state_change_expected": {
    "service_revealed": "mysql-backend",
    "new_state": "revealed"
  },
  "state_change_applied": {
    "service_revealed": "mysql-backend",
    "port": 3306,
    "protocol": "tcp",
    "new_state": "revealed"
  },
  "world_state_summary": {
    "discovered_files_count": 0,
    "discovered_services_count": 3,
    "attacker_interests": [],
    "action_history_count": 1,
    "events_count": 1
  },
  "error": null
}
```

---

## 6. Safety Boundaries and Threat Containment

1. **Strictly In-Memory Operations**:
   - The engine operates solely upon Python dataclasses and dictionaries.
   - Real system directories (`/root`, `/var/www`, `/etc`) are never accessed, queried, created, or modified.
2. **No Command Execution**:
   - Attacker commands captured in telemetry logs are treated exclusively as passive text patterns for feature extraction.
   - Subprocesses (`subprocess.Popen`, `subprocess.run`, `os.system`) are strictly disallowed and tested via mock assertions.
3. **Explicit Action Allowlist**:
   - Any action outside the four approved primitives (`present_decoy_file`, `reveal_fake_service`, `record_attacker_interest`, `no_op`) is rejected prior to execution.
4. **Idempotence & State-Aware Fallbacks**:
   - State preconditions prevent applying conflicting or redundant state transitions (e.g. presenting an already visible decoy).

---

## 7. Offline Usage Example

```python
from parser.cowrie_parser import normalize_event
from analysis.engine import analyse_session
from deception.engine import DeceptionEngine

# Initialize stateful engine
engine = DeceptionEngine()

# Example synthetic events
events = [
    {
        "timestamp": "2026-01-15T10:00:00+00:00",
        "session_id": "offline-session-101",
        "event_type": "command",
        "source_ip": "192.0.2.1",
        "destination_ip": "192.0.2.10",
        "destination_port": 2222,
        "command": "cat /etc/shadow",
    }
]

# Run analysis and deception
analysis = analyse_session(events, session_id="offline-session-101")
decision_record = engine.process(analysis)

print("Policy Fired:", decision_record["policy_id"])
print("Action Selected:", decision_record["action"]["action_id"])
print("Target:", decision_record["action"]["target"])
print("State Summary:", decision_record["world_state_summary"])
```
