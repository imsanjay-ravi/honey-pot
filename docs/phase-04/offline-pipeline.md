# Phase 4 — Offline End-to-End Pipeline Documentation

## 1. Overview

Phase 4 delivers an offline, end-to-end integration entry point (`pipeline.py`) that wires together:
1. **Telemetry Ingestion & Parsing** (`parser.cowrie_parser`): Reads raw, sanitized Cowrie JSONL events and captures non-fatal line warnings.
2. **Session Identification & Grouping**: Groups normalized events into sessions.
3. **Deterministic Behaviour Analysis** (`analysis.engine`): Extracts behavioral features, fires classifier rules, and calculates threat scores (0–100).
4. **Adaptive Deception Engine** (`deception.engine`): Evaluates deterministic, explainable policies against the in-memory fictional world state (`deception.world_state`), applying approved deception actions.

The pipeline executes entirely offline without requiring Cowrie, virtual machines, external databases, or paid cloud AI services.

---

## 2. Command-Line Usage

### Basic Run
Run the pipeline against any sanitized Cowrie JSONL log fixture:

```bash
python pipeline.py --input examples/scenarios/reconnaissance.jsonl
```

### Full Multi-Session Scenario with Warnings Handled
Run the multi-session scenario demonstrating warning collection, threat analysis, and cumulative world state transitions:

```bash
python pipeline.py --input examples/scenarios/combined_multi_session.jsonl
```

### Exporting Structured Results & World State to JSON
```bash
python pipeline.py \
  --input examples/scenarios/combined_multi_session.jsonl \
  --output data/pipeline_results.json \
  --world-state-output data/final_world_state.json
```

### CLI Options

| Flag | Shorthand | Type | Description |
|---|---|---|---|
| `--input` | `-i` | String (Required) | Path to the synthetic Cowrie JSONL log file. |
| `--output` | `-o` | String (Optional) | Path where structured pipeline execution results are saved as JSON. |
| `--world-state-output` | | String (Optional) | Path where the final fictional `WorldState` snapshot is saved as JSON. |
| `--strict` | | Flag | If set, exits with code 1 if any parser warnings are encountered. |
| `--quiet` | `-q` | Flag | Suppresses terminal console output. |

---

## 3. Synthetic Scenarios Included

All scenarios use RFC 5737 documentation IP addresses (`192.0.2.x`), fictional timestamps (`2026-01-15`), and synthetic attacker commands:

- `examples/scenarios/reconnaissance.jsonl`: Systematic system enumeration (`whoami`, `uname -a`, `hostname`, `id`, `ifconfig`). Triggers `POL-RECON-REVEAL-MYSQL` (`reveal_fake_service`).
- `examples/scenarios/authentication_abuse.jsonl`: Multiple failed logins across administrative accounts. Triggers `POL-AUTH-SPRAY-MONITOR` (`record_attacker_interest`).
- `examples/scenarios/file_discovery.jsonl`: Systematic directory browsing (`find`, `ls`, `locate`). Triggers `POL-FILE-DISC-DB-DUMP` (`present_decoy_file`).
- `examples/scenarios/download_attempt.jsonl`: External payload retrieval command (`wget`). Triggers `POL-DOWNLOAD-DECOY-ENV` (`present_decoy_file`).
- `examples/scenarios/privilege_escalation.jsonl`: Credential file inspection (`/etc/passwd`, `/etc/shadow`, `.ssh`). Triggers `POL-CRED-DECOY-SSH` (`present_decoy_file`).
- `examples/scenarios/unknown_benign.jsonl`: Routine operational commands (`date`, `echo`). Triggers `POL-DEFAULT-NOOP` (`no_op`).
- `examples/scenarios/combined_multi_session.jsonl`: Multi-session scenario containing all 6 scenarios and an invalid JSON line to verify warning recovery.

---

## 4. Interpreting the Pipeline Output

### Console Output Breakdown
The console output contains four structured sections:

1. **Header Block**: Summary of file path, events parsed, parse warnings, and sessions found.
2. **Parse Warnings Block**: Details any skipped or malformed lines without aborting pipeline execution.
3. **Session Breakdown**: For each session:
   - **Threat Score & Primary Category**: Heuristic threat level (0–100) and primary classification.
   - **Deception Policy & Decision Status**: The exact policy rule evaluated and status (`ACCEPTED` or `NO_ACTION_REQUIRED`).
   - **Action & Target**: Approved deception action and fictional target (e.g. `reveal_fake_service -> mysql-backend`).
   - **Findings**: The specific rules fired with evidence strength (`STRONG`, `MODERATE`, `WEAK`).
   - **State Transition**: The exact in-memory state transition applied to the simulated environment.
4. **Final World State Summary**: Cumulative state across all processed sessions, showing visible decoys, revealed services, and attacker interest tags.

### JSON Output Schema
```json
{
  "pipeline_version": "1.0.0",
  "input_file": "examples/scenarios/reconnaissance.jsonl",
  "events_parsed": 8,
  "warnings_count": 0,
  "warnings": [],
  "sessions_count": 1,
  "sessions": [
    {
      "session_id": "s-recon-01",
      "source_ip": "192.0.2.101",
      "event_count": 8,
      "analysis": {
        "primary_category": "reconnaissance",
        "score": 15,
        "findings": [
          {
            "rule_id": "REC-01",
            "category": "reconnaissance",
            "evidence": "5 reconnaissance command(s) observed (id/whoami/uname/hostname/ifconfig/etc.)",
            "evidence_strength": "MODERATE"
          },
          {
            "rule_id": "REC-02",
            "category": "reconnaissance",
            "evidence": "5 reconnaissance commands -- systematic system enumeration pattern.",
            "evidence_strength": "STRONG"
          }
        ],
        "score_explanation": "Reconnaissance commands: +15",
        "warnings": []
      },
      "deception": {
        "status": "accepted",
        "policy_id": "POL-RECON-REVEAL-MYSQL",
        "action": {
          "action_id": "reveal_fake_service",
          "target": "mysql-backend",
          "parameters": {},
          "description": "Reveal simulated internal MySQL database service to reconnaissance."
        },
        "explanation": "System enumeration observed; revealing internal MySQL service.",
        "state_change_applied": {
          "service_revealed": "mysql-backend",
          "port": 3306,
          "protocol": "tcp",
          "new_state": "revealed"
        },
        "error": null
      }
    }
  ],
  "world_state": {
    "host": {
      "hostname": "corp-srv-db01",
      "os_name": "Ubuntu 22.04.3 LTS",
      "primary_ip": "192.0.2.10"
    },
    "discovered_files": [],
    "discovered_services": ["http-web", "mysql-backend", "ssh"],
    "attacker_interests": [],
    "action_history": [
      {
        "action_id": "reveal_fake_service",
        "target": "mysql-backend",
        "explanation": "Reveal simulated internal MySQL database service to reconnaissance.",
        "state_change": {
          "service_revealed": "mysql-backend",
          "port": 3306,
          "protocol": "tcp",
          "new_state": "revealed"
        }
      }
    ]
  }
}
```

---

## 5. Programmatic API

The pipeline can also be called directly in Python:

```python
from pipeline import run_pipeline

result = run_pipeline(
    log_file="examples/scenarios/reconnaissance.jsonl",
    output_file="data/run_result.json",
    quiet=False,
)

print(f"Processed {result['sessions_count']} sessions.")
```

---

## 6. Safety & Isolation Verification

- **No Shell Execution**: Attacker command strings are never passed to `subprocess` or `os.system`.
- **No Real Filesystem Alteration**: Decoy file paths (`/root/.ssh/...`, `/var/www/...`) exist only within Python data structures and are never touched on the real host.
- **Strict Allowlist**: Any unapproved deception action is rejected and safely falls back to `no_op`.
