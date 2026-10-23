# Phase 5 — Ubuntu Analysis Dashboard Documentation

## 1. Overview and Architecture

The **Ubuntu Analysis Dashboard** is the browser-based visualization and control interface for the AI Adaptive Cyber Deception System.

Rather than reimplementing analysis or deception logic, the dashboard acts as a visual layer on top of the offline components established in Phases 1–4:
- Ingests sanitized Cowrie JSONL events via `parser.cowrie_parser`.
- Runs deterministic classification and heuristic scoring via `analysis.engine`.
- Evaluates adaptive deception policies and simulates state transitions via `deception.engine` and `deception.world_state`.
- Orchestrates and formats end-to-end execution through `pipeline.py`.

```
       +-------------------------------------------------------+
       |                  Browser Frontend                     |
       |  (HTML5 / Vanilla CSS / Vanilla JS / SVG Attack Graph)|
       +-------------------------------------------------------+
                                  |
                                  | REST API (JSON)
                                  v
       +-------------------------------------------------------+
       |               FastAPI Backend (Uvicorn)               |
       |                   dashboard/app.py                    |
       |                  dashboard/routes.py                  |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |                  Integration Pipeline                 |
       |                      pipeline.py                      |
       +-------------------------------------------------------+
              |                    |                    |
              v                    v                    v
      +---------------+   +------------------+  +------------------+
      |     Parser    |   | Analysis Engine  |  | Deception Engine |
      | (parser/...)  |   | (analysis/...)   |  | (deception/...)  |
      +---------------+   +------------------+  +------------------+
```

---

## 2. Dependencies and Setup

### Required Dependencies
The backend requires:
- Python 3.10+ (tested on Python 3.14)
- `fastapi`
- `uvicorn`

No additional external packages, databases, or frontend build toolchains (npm/webpack) are required. The frontend is built using standard Vanilla HTML, CSS, and modern JavaScript.

---

## 3. Starting and Accessing the Dashboard

### Starting the Server on Ubuntu / Local Machine
To launch the dashboard server on `127.0.0.1:8000`:

```bash
# Option A: Using the CLI launcher script
python dashboard/server.py --host 127.0.0.1 --port 8000

# Option B: Running directly with uvicorn
python -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
```

### Accessing in Browser
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### Stopping the Server
Press `Ctrl + C` in the terminal to stop Uvicorn.

---

## 4. Dashboard Features & Views

### 1. Overview
- **Metric KPI Cards**: Displays Attacker Sessions, Normalized Events Parsed, Average Heuristic Threat Index, and Simulated Deception Actions Applied.
- **Behaviour Distribution**: Bar charts showing counts and percentages of categorized threats.
- **Threat Index Severity**: Grouping into Low (0–25), Moderate (26–70), and Elevated (71–100) buckets.
- **Recent Sessions Table**: Clickable session list with quick navigation to deep session inspection.

### 2. Session Explorer
- **Search & Filters**: Search by Session ID or Source IP, filter by behavior category, and filter by score severity.
- **Split View**: Left column displays session cards with score badges; right pane details:
  - Session metadata (ID, source IP, event count).
  - Behaviour findings with evidence confidence badges (`STRONG`, `MODERATE`, `WEAK`).
  - Safe, inert command input streams (never executed).
  - Deception policy fired, chosen action, target, and state change applied.

### 3. Attack Timeline & Graph
- **Interactive SVG Attack Graph**:
  - Visualizes links between Attacker Sessions (cyan), Behaviour Techniques (amber/rose), and Deception Defense Actions (emerald).
  - Pan (drag with mouse) and Zoom (+ / - / mouse wheel).
  - Click any session node to jump directly to its detailed inspection pane.
- **Chronological Timeline**: Step-by-step sequential view of session activity and deception defenses.

### 4. Behaviour Analysis
- **Scoring Clarification**: Highlights that threat scores are explainable, rule-based heuristic indexes (0–100), not machine-learning compromise probabilities.
- **Aggregated Findings Matrix**: Tabular breakdown of rule identifiers, categories, confidence levels, and triggering sessions.

### 5. Deception Planner
- **Isolation Banner**: Prominently highlights that all world state assets are fictional in-memory representations.
- **Simulated Host Identity**: Shows hostname (`corp-srv-db01`), distribution (`Ubuntu 22.04.3 LTS`), kernel, architecture, and RFC 5737 IP (`192.0.2.10`).
- **Decoy Files Catalog**: Shows all fictional files and their real-time visibility (`VISIBLE (DEPLOYED)` vs `STANDBY (HIDDEN)`).
- **Simulated Services**: Displays active vs hidden bait services (`mysql-backend`, `redis-cache`).
- **Action History Audit Trail**: Complete log of simulated actions executed across sessions.

### 6. Reports & Warnings
- **Parser Diagnostics**: Displays valid events parsed vs skipped line warnings.
- **Warnings Log**: Pinpoints specific line numbers and parser reasons for corrupted or rotated log lines without losing sessions.
- **Export**: One-click download of sanitized JSON analysis and world-state results.

---

## 5. REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Returns health status and version. |
| `/api/scenarios` | `GET` | Returns list of approved synthetic scenarios. |
| `/api/run-scenario` | `POST` | Executes pipeline on selected scenario JSONL. Accepts `{"scenario": str, "accumulate_state": bool}`. |
| `/api/current-state`| `GET` | Returns the latest pipeline result and WorldState. |
| `/api/reset` | `POST` | Resets WorldState and clears active scenario results. |
| `/api/export` | `GET` | Downloads current sanitized results as JSON attachment. |

---

## 6. Security and Containment Boundaries

1. **Path Traversal Prevention**:
   The `/api/run-scenario` endpoint strictly prohibits path traversal (`../`, `/`, `\`). Any attempt to access files outside `examples/scenarios/` is rejected with `HTTP 400 Bad Request`.
2. **Zero Host Execution**:
   Captured commands are parsed as passive telemetry strings. Neither the backend nor the frontend passes attacker input to `subprocess`, `os.system`, or host shells.
3. **Simulated State Isolation**:
   Fictional files (e.g. `/root/.ssh/id_rsa_backup`) exist only in memory within `WorldState` dataclasses. The host operating system's filesystem is never read, created, or modified.
4. **Local Network Binding**:
   By default, the server binds to `127.0.0.1` (localhost).

---

## 7. Future VM Networking Considerations

In future phases (Phase 6+), when the Linux attacker VM is introduced:
- The Ubuntu Analysis Dashboard can be accessed across a private host-only or internal hypervisor virtual switch (e.g. `192.168.56.0/24` or `10.0.4.0/24`).
- To allow access from another VM on the isolated internal network:
  ```bash
  python dashboard/server.py --host 0.0.0.0 --port 8000
  ```
- **Strict Warning**: Never expose this service to the public Internet without authentication and TLS.
