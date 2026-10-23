# Phase 7 — Live Cowrie Telemetry Integration

## 1. Overview & Architecture

Phase 7 integrates real-time, read-only Cowrie honeypot telemetry from an Ubuntu Linux VM into the AI Adaptive Cyber Deception System's analysis pipeline and Phase 5 Ubuntu Analysis Dashboard.

This phase is **strictly read-only and telemetry-centric**. It observes, parses, classifies, and heuristic-scores real attacker behavior. The deterministic deception engine generates simulated policy recommendations and tracks hypothetical state transitions, but **never executes commands, modifies honeypot configurations, alters filesystem assets, or makes network connections to attackers**.

```
+--------------------------------------------------------------------------------+
|                           Ubuntu Honeypot VM                                  |
|                                                                                |
|   +-----------------------+              +---------------------------------+   |
|   |   Cowrie Honeypot     |              |   Read-Only Telemetry Collector |   |
|   |  (SSH / Telnet Emul)  |              |       (telemetry/collector.py)  |   |
|   +-----------+-----------+              +----------------+----------------+   |
|               | Appends JSONL                             | Tails locally      |
|               v                                           | (read-only mode)   |
|     /var/log/cowrie/cowrie.json                           |                    |
|     (or /home/cowrie/cowrie/var/log/cowrie/cowrie.json) --+                    |
+-----------------------------------------------------------|--------------------+
                                                            |
                                        Authenticated HTTP  | POST /api/telemetry/ingest
                                        Bearer Token Auth   | (Bounded batch <= 1000)
                                                            v
+--------------------------------------------------------------------------------+
|                     Windows Host / Analysis Dashboard                          |
|                                                                                |
|   +-----------------------+              +---------------------------------+   |
|   |   FastAPI Backend     |              |     LiveCowrieService           |   |
|   |  (dashboard/app.py)   | <----------> |   (telemetry/live_service.py)   |   |
|   +-----------+-----------+              +----------------+----------------+   |
|               | Serves UI                                 | Groups sessions    |
|               v                                           | Runs analysis      |
|   +-------------------------------------------------------v----------------+   |
|   |  Ubuntu Analysis Dashboard (Browser UI at http://127.0.0.1:8000/)      |   |
|   |  - Telemetry Source: "Live Cowrie"                                     |   |
|   |  - Source Health, Connection Status, Last Ingest Time                  |   |
|   |  - Session Explorer, Timelines, Threat Scores, Primary Behaviors       |   |
|   |  - Advisory Deception Recommendations (Marked Simulated)               |   |
|   +------------------------------------------------------------------------+   |
+--------------------------------------------------------------------------------+
```

---

## 2. Configuration Variables & Examples

All configuration parameters can be supplied via environment variables or CLI flags without committing sensitive keys to Git:

| Environment Variable | Default Value | Description |
|----------------------|---------------|-------------|
| `COWRIE_LOG_PATH` | *None* (or `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`) | Optional direct filesystem path to Cowrie JSON log if shared/mounted. |
| `COWRIE_INGEST_TOKEN` | `cowrie-live-telemetry-secret-token` | Secret Bearer authentication token required by `POST /api/telemetry/ingest`. |
| `DASHBOARD_SERVER_URL` | `http://127.0.0.1:8000` | Target URL where the Ubuntu collector pushes ingested event batches. |
| `COWRIE_POLL_INTERVAL` | `2.0` | Polling frequency in seconds for reading appended log lines. |
| `COWRIE_BATCH_SIZE` | `100` | Maximum number of events forwarded per HTTP ingestion request. |

### Example `.env` (Windows Host):
```bash
# Windows Dashboard Server Environment
COWRIE_INGEST_TOKEN=ProductionSecretToken_ChangeMe98231
```

### Example `.env` or Environment Setup (Ubuntu VM):
```bash
# Ubuntu VM Telemetry Collector
export COWRIE_LOG_PATH=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
export DASHBOARD_SERVER_URL=http://192.168.56.1:8000
export COWRIE_INGEST_TOKEN=ProductionSecretToken_ChangeMe98231
export COWRIE_POLL_INTERVAL=2.0
```

---

## 3. Locating & Verifying Cowrie Logs on Ubuntu

Cowrie installations default to specific log paths depending on how Cowrie was deployed:

1. **Standard Python virtualenv install (most common):**
   ```bash
   /home/cowrie/cowrie/var/log/cowrie/cowrie.json
   ```
2. **Docker / Container install:**
   ```bash
   /cowrie/cowrie-git/var/log/cowrie/cowrie.json
   # or host mount:
   /var/log/cowrie/cowrie.json
   ```
3. **Debian/Ubuntu package install:**
   ```bash
   /var/log/cowrie/cowrie.json
   ```

### Verification Command (run on Ubuntu VM):
```bash
# Check if file exists, is non-empty, and valid JSON lines:
head -n 2 /home/cowrie/cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool
```

---

## 4. Cross-Machine Telemetry Transport: Windows & Ubuntu

Because development and analysis run on Windows while Cowrie runs inside an Ubuntu VM, the systems communicate via safe network isolation:

### Preferred Model: Standalone Ubuntu Collector Agent (`telemetry/collector.py`)
- The Ubuntu collector uses Python's standard library only (`urllib.request`), requiring **zero third-party dependencies** on the honeypot VM.
- Tailing is non-invasive and read-only (`open("r")`). File offsets are tracked so lines are never re-ingested.
- Events are dispatched in small batches over HTTP `POST /api/telemetry/ingest` with `Authorization: Bearer <token>`.
- Ingestion is guarded against oversized payloads (strict cap of 1000 events per batch).

### Alternative Model: Shared Folder or Host Mount
- If VirtualBox Shared Folders or VMware Host-Guest filesystem sharing is active, configure `COWRIE_LOG_PATH` on Windows to point directly to the mounted `cowrie.json`.
- The internal `CowrieLogTailer` will safely tail the file directly, tracking byte offsets, handling incomplete trailing lines, and detecting file rotations.

---

## 5. Safe Network Configuration & Security Boundaries

1. **Loopback & Host-Only Adapter:**
   - Bind the dashboard to `127.0.0.1` for local-only testing, or to the VirtualBox Host-Only adapter IP (e.g., `192.168.56.1:8000`) for VM communication.
   - **Never bind telemetry ingestion directly to public 0.0.0.0 on an internet-facing interface without TLS and firewall filtering.**
2. **Authentication:**
   - Every push to `/api/telemetry/ingest` requires a valid `Authorization: Bearer <token>` matching `COWRIE_INGEST_TOKEN`.
   - Requests with missing or incorrect tokens receive `401 Unauthorized`.
3. **Strictly Read-Only Guarantee:**
   - The honeypot file is opened exclusively in `"r"` mode.
   - No filesystem modification, truncation, deletion, or permission changes are ever attempted.
4. **Zero Attacker Interaction:**
   - No shell commands from attacker events are executed.
   - No network sockets are opened to attacker IP addresses.
   - No SSH/Telnet sessions are initiated.
5. **Simulated Deception Advisory Only:**
   - The deception engine evaluates real attacker sessions deterministically.
   - Deception decisions are labeled with `advisory_only: True` and prefixed `[ADVISORY RECOMMENDATION — Real Honeypot Unmodified]`.
   - Real Cowrie filesystem files, decoys, and configurations remain 100% untouched.

---

## 6. How to Run the Collector and Dashboard

### Step 1: Start the Dashboard on Windows
```powershell
python dashboard/server.py --host 0.0.0.0 --port 8000
```
Open your browser at `http://127.0.0.1:8000/`.

### Step 2: Start the Collector on Ubuntu VM
```bash
# Dry run to verify log access without sending:
python3 telemetry/collector.py \
  --log-path /home/cowrie/cowrie/var/log/cowrie/cowrie.json \
  --dry-run

# Run collector in background or systemd:
python3 telemetry/collector.py \
  --log-path /home/cowrie/cowrie/var/log/cowrie/cowrie.json \
  --endpoint http://192.168.56.1:8000/api/telemetry/ingest \
  --token cowrie-live-telemetry-secret-token \
  --interval 2.0
```

---

## 7. Verifying Real Telemetry in the Dashboard

1. Navigate to `http://127.0.0.1:8000/`.
2. In the top navigation bar, select **Source: Live Cowrie Telemetry**.
3. **Overview Tab**:
   - Connection status pill indicates `ONLINE / CONNECTED`.
   - Banner displays: `READ-ONLY LIVE TELEMETRY • Honeypot untouched • Deception recommendations are simulated advisory only`.
   - Metrics display real sessions count, normalized events, and heuristic average threat score.
4. **Session Explorer Tab**:
   - Inspect attacker IP addresses, connection timestamps, login attempts, and command timelines.
5. **Behaviour Analysis Tab**:
   - View deterministic behavior classifications (e.g. `reconnaissance`, `privilege_escalation_attempt`, `download_attempt`).
6. **Deception Planner Tab**:
   - Amber warning card confirms advisory status: `Live Honeypot Safety Boundary • Simulated Advisory Recommendations Only`.
   - Audit trail records policy recommendations.

---

## 8. Source Health & Diagnostics

- **Health Endpoint**:
  ```bash
  curl http://127.0.0.1:8000/api/telemetry/health
  ```
- **Returns**:
  - `status`: `"healthy"`, `"connected"`, `"waiting_for_events"`, or `"tailer_path_unreachable"`.
  - `total_events_ingested`: Cumulative event count in memory.
  - `total_sessions_analyzed`: Number of active Cowrie sessions grouped.
  - `warnings_count`: Parser or JSON line skipping warnings.
  - `last_ingest_time`: ISO-8601 UTC timestamp of last batch ingestion.
  - `collector_connected`: Boolean flag.

---

## 9. Known Limitations & Unverified Deployment Steps

- **Windows-Only Verification**: All unit tests, parser integrations, and API interactions have been verified on Windows.
- **Physical VM Network Boundary**: Actual VM network routing (e.g., VirtualBox host-only adapter subnet, Ubuntu UFW firewall allowing outbound port 8000) must be confirmed when booting the live Ubuntu VM.
- **Why Live Deception Actions are Disabled**: Real honeypot modification (Phase 8/9) requires formal risk analysis, Cowrie backend plugin architecture, and safety guardrails to ensure decoy deployment never interferes with honeypot stability or attacker containment.
