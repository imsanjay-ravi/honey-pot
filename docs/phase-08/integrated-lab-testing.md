# Phase 8 — Integrated Lab Testing and Safe Adaptation

## 1. Overview & Architecture Audit

Phase 8 evaluates and verifies the integrated end-to-end operation of the **AI Adaptive Cyber Deception System** in an isolated lab environment consisting of:
- **Kali Linux VM**: Attacker and test probe machine (`192.168.56.20` / test subnet).
- **Ubuntu Honeypot VM**: Hosts Cowrie SSH honeypot (port 2222) and the Python read-only telemetry collector (`/home/sanjay/cowrie/var/log/cowrie/cowrie.json`).
- **Windows / Analysis Host**: Runs the unified FastAPI backend, deterministic analysis pipeline, simulated deception engine, and Ubuntu Analysis Dashboard (`http://127.0.0.1:8000/`).

### End-to-End Telemetry Trace & Component Mapping

```
[Attacker SSH / Probe] (Kali Linux VM)
        |
        | SSH Port 2222 (interactive terminal, credentials, recon, discovery)
        v
[Cowrie Honeypot] (Ubuntu VM)
        |
        | Appends JSONL records asynchronously
        v
[Cowrie Log File] (`cowrie.json` on Ubuntu VM)
        |
        | Read-only tailing with byte offset tracking
        v
[Telemetry Collector] (`telemetry/collector.py` & `telemetry/cowrie_source.py`)
        |
        | Authenticated HTTP POST (Bearer Token, bounded batches <= 1000)
        v
[Ingestion API] (`POST /api/telemetry/ingest` in `dashboard/routes.py`)
        |
        | Token validation & Pydantic schema verification
        v
[Event Normalization] (`parser/cowrie_parser.py:normalize_event()`)
        |
        | UTC timestamps, session IDs, event types, sanitized command text
        v
[Session Correlation] (`telemetry/live_service.py:LiveCowrieService`)
        |
        | In-memory session grouping, source IP tracking, command sequencing
        v
[Behaviour Analysis] (`analysis/engine.py`, `analysis/features.py`, `analysis/classifier.py`)
        |
        | Deterministic feature extraction, MITRE ATT&CK rule evaluation
        v
[Threat Scoring] (`analysis/scorer.py:compute_score()`)
        |
        | Bounded heuristic score (0–100), contributions, and explanation
        v
[Deception Policy Engine] (`deception/policy_engine.py:evaluate_policy()`)
        |
        | Deterministic policy evaluation (`POL-*`), state preconditions check
        v
[Simulated / Advisory Response] (`deception/engine.py`, `telemetry/live_service.py`)
        |
        | Strictly simulated world state (`is_advisory = True`, 0 real executions)
        v
[Ubuntu Analysis Dashboard] (`GET /api/current-state`, `dashboard/static/js/dashboard.js`)
        |
        +--> Header Status Badge (`● LIVE COWRIE CONNECTED`, `⏳ WAITING`, `✕ DISCONNECTED`)
        +--> Overview Stats (`RECOMMENDATIONS GENERATED`, Threat Score, Sessions)
        +--> Timeline, Findings Explorer, Session Graph, and Advisory Audit Trail
```

---

## 2. Lab Environment & Configuration

| Parameter | Configuration / Value | Notes |
| :--- | :--- | :--- |
| **Attacker VM** | Kali Linux 2024.x | Non-destructive test probe; commands restricted to lab targets. |
| **Honeypot VM** | Ubuntu 22.04 LTS | Cowrie SSH honeypot listening on port `2222`. |
| **Cowrie Log Path** | `/home/sanjay/cowrie/var/log/cowrie/cowrie.json` | JSONL log format; strictly read-only access. |
| **Collector Script** | `telemetry/collector.py` | Python 3 standard library only; runs on Ubuntu. |
| **Collector Poll Rate** | `2.0` seconds (configurable) | Bounded batch forwarder. |
| **Ingest Endpoint** | `http://<HOST_IP>:8000/api/telemetry/ingest` | Secured by Bearer token authentication. |
| **Ingest Auth Token** | `COWRIE_INGEST_TOKEN` (environment variable) | Secret key never committed to version control. |
| **Dashboard URL** | `http://127.0.0.1:8000/` | Served via FastAPI / Uvicorn. |

---

## 3. Integrated Test Matrix & Verification

A repeatable 10-scenario test matrix was executed to validate deterministic classification, scoring, policy selection, session isolation, and safety boundaries.

### Scenario Results Table

| ID | Scenario Description | Input Commands / Events | Expected vs Actual Category | Expected vs Actual Score | Selected Policy & Action | Advisory Execution Status | Ingest Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SC-01** | Benign / Minimal Session | `pwd` | Exp: `unknown`<br>Act: `unknown` | Exp: `0`<br>Act: `0` | `POL-DEFAULT-NOOP`<br>`no_op` | `no_action_recommended`<br>(0 executed) | 4.59 ms |
| **SC-02** | Reconnaissance Commands | `whoami`<br>`uname -a`<br>`hostname` | Exp: `reconnaissance`<br>Act: `reconnaissance` | Exp: `9`<br>Act: `9` | `POL-RECON-REVEAL-MYSQL`<br>`reveal_service` (`mysql-backend`) | `simulated_recommendation`<br>(0 executed) | 3.92 ms |
| **SC-03** | File & Directory Discovery | `ls -la`<br>`find / -name "*.conf"`<br>`tree /etc` | Exp: `file_discovery`<br>Act: `file_discovery` | Exp: `6`<br>Act: `6` | `POL-FILE-DISC-DB-DUMP`<br>`present_decoy` (`/home/backup/db_dump.sql`) | `simulated_recommendation`<br>(0 executed) | 3.45 ms |
| **SC-04** | Failed Logins then Success | 3 failed logins<br>1 successful login | Exp: `authentication_abuse`<br>Act: `authentication_abuse` | Exp: `21`<br>Act: `21` | `POL-AUTH-SPRAY-MONITOR`<br>`record_interest` (`authentication_spray`) | `simulated_recommendation`<br>(0 executed) | 4.73 ms |
| **SC-05** | Credential File Discovery | `cat /etc/shadow` | Exp: `privilege_escalation_attempt`<br>Act: `privilege_escalation_attempt` | Exp: `18`<br>Act: `18` | `POL-CRED-DECOY-SSH`<br>`present_decoy` (`/root/.ssh/id_rsa_backup`) | `simulated_recommendation`<br>(0 executed) | 3.81 ms |
| **SC-06** | Mixed Sequence (Recon + Discovery) | `whoami`, `uname -a`<br>`ls -la`, `find / -type f` | Exp: `file_discovery`<br>Act: `file_discovery` | Exp: `10`<br>Act: `10` | `POL-FILE-DISC-WEAK`<br>`record_interest` (`file_discovery`) | `simulated_recommendation`<br>(0 executed) | 4.20 ms |
| **SC-07** | Multiple Independent Sessions | Interleaved events for Session 7A & 7B | Exp: Isolated (7A: recon, 7B: auth)<br>Act: Isolated (7A: recon, 7B: auth) | Exp: 7A: `9`, 7B: `6`<br>Act: 7A: `9`, 7B: `6` | 7A: `POL-RECON-REVEAL-MYSQL`<br>7B: `POL-AUTH-SPRAY-MONITOR` | `simulated_recommendation`<br>(0 executed) | 4.06 ms |
| **SC-08** | Malformed & Partial Events | Blank lines, unclosed JSON, incomplete lines | Exp: Skipped with warnings<br>Act: Skipped with warnings | Exp: `0`<br>Act: `0` | `POL-DEFAULT-NOOP`<br>`no_op` | `no_action_recommended`<br>(0 executed) | 3.06 ms |
| **SC-09** | Collector Disconnect / Reconnect | Ingest stopped, tailer reset, ingest resumed | Exp: Transition waiting -> healthy<br>Act: Transition waiting -> healthy | Exp: `0`<br>Act: `0` | `POL-DEFAULT-NOOP`<br>`no_op` | `no_action_recommended`<br>(0 executed) | 6.18 ms |
| **SC-10** | Unknown Behaviour / Fallback | `echo 'safe test'`<br>`clear` | Exp: `unknown`<br>Act: `unknown` | Exp: `0`<br>Act: `0` | `POL-DEFAULT-NOOP`<br>`no_op` | `no_action_recommended`<br>(0 executed) | 4.33 ms |

---

## 4. Threat Score Derivations

All scores were mathematically derived from active scoring rules in `analysis/scorer.py` without guessing or hardcoding:

1. **SC-01 (Benign)**:
   - Login failures: 0. Recon commands: 0. Discovery: 0. Credential: 0. Priv-esc: 0.
   - **Score**: `min(0, 100) = 0` (Severity: `LOW`).
2. **SC-02 (Reconnaissance)**:
   - 3 recon commands (`whoami`, `uname -a`, `hostname`).
   - Factor weight: `3` pts per recon command (cap: 5 commands).
   - **Score**: `3 * 3 = 9` (Severity: `LOW`).
3. **SC-03 (File Discovery)**:
   - 3 file discovery commands (`ls -la`, `find / -name "*.conf"`, `tree /etc`).
   - Factor weight: `2` pts per file discovery command (cap: 5 commands).
   - **Score**: `3 * 2 = 6` (Severity: `LOW`).
4. **SC-04 (Authentication Abuse)**:
   - 3 failed login attempts: `3 * 2 pts = 6 pts`.
   - 1 login success after failure bonus: `15 pts` flat bonus.
   - **Score**: `6 + 15 = 21` (Severity: `LOW`).
5. **SC-05 (Credential File Discovery)**:
   - `cat /etc/shadow` matches both `_RECON_SUBSTRINGS` (`/etc/shadow`) and `_CREDENTIAL_SUBSTRINGS` (`/etc/shadow`).
   - Recon: 1 command * 3 pts = `3 pts`.
   - Credential access: 1 command * 15 pts = `15 pts`.
   - **Score**: `3 + 15 = 18` (Severity: `LOW`).
   - Category Priority: `privilege_escalation_attempt` takes precedence over `reconnaissance`.
6. **SC-06 (Mixed Sequence)**:
   - 2 recon commands (`whoami`, `uname -a`): `2 * 3 = 6 pts`.
   - 2 file discovery commands (`ls -la`, `find`): `2 * 2 = 4 pts`.
   - **Score**: `6 + 4 = 10` (Severity: `LOW`).
   - Category Priority: `file_discovery` (Priority 4) takes precedence over `reconnaissance` (Priority 5).

---

## 5. Classification & Policy Analysis

### False Positives and False Negatives (Observed in Limited Test Set)

> [!NOTE]
> Statistical claims of detection accuracy (e.g., "99.9% precision") are intentionally avoided because this test matrix is a curated integration benchmark, not a statistically sampled distribution of production attack traffic.

1. **Dual-Matching Overlap (Credential Access vs. Reconnaissance)**:
   - `cat /etc/shadow` triggers both `REC-01` (`reconnaissance`) and `PE-02` (`privilege_escalation_attempt`).
   - **System Resolution**: The deterministic `primary_category()` resolver applies a strict priority ladder:
     $$\text{PrivEsc} > \text{Download} > \text{AuthAbuse} > \text{FileDiscovery} > \text{Recon} > \text{Unknown}$$
     Consequently, `privilege_escalation_attempt` is chosen as the primary category and triggers `POL-CRED-DECOY-SSH`, which is the intended security response.
2. **Ambiguity of Benign Discovery**:
   - A single `ls -la` executed by a legitimate operator fires `FD-01` (`file_discovery`, WEAK).
   - **Safe Adaptation Handling**: Rather than deploying intrusive decoys, policy `POL-FILE-DISC-WEAK` selects `record_attacker_interest`. No decoy files or services are altered, preventing disruption of legitimate operators.
3. **Multi-Session Isolation**:
   - Ingesting interleaved streams from separate source IPs (`198.51.100.71` vs `203.0.113.72`) confirmed that feature counters and classifications remain strictly partitioned by `session_id`. Zero cross-session contamination was observed.

---

## 6. Safe Adaptation & Boundary Enforcement

The test suite explicitly validated all safety boundaries:

1. **Read-Only Telemetry**:
   - Neither `telemetry/collector.py` nor `telemetry/cowrie_source.py` opens `cowrie.json` in write mode. Filesystem hashes and file sizes of the honeypot log remained unaltered during all ingestion tests.
2. **Zero Command Execution on Attacker Sessions**:
   - No shell commands, SSH channels, or reverse connections are ever established to attacker machines or honeypot shells (`test_13_no_shell_execution_or_attacker_connections` verified).
3. **Purely Fictional In-Memory World State**:
   - The deception engine modifies only Python dataclasses (`WorldState`) in server memory. No real files (such as `/root/.ssh/id_rsa_backup` or `/var/www/internal/.env`) are created or modified on the host operating system.
4. **Rejection of Unapproved Deception Actions**:
   - Actions outside the approved allowlist (`ACTION_NO_OP`, `ACTION_PRESENT_DECOY`, `ACTION_REVEAL_SERVICE`, `ACTION_RECORD_INTEREST`) are immediately rejected by `validate_action()` and fall back to safe `no_op`.
5. **Dashboard Accuracy**:
   - The overview metric displays `RECOMMENDATIONS GENERATED` with the note `"Read-Only: 0 actions executed on real honeypot"`. Confirmed executed actions count is strictly `0` for live Cowrie mode.

---

## 7. Performance & Latency Measurements

End-to-end processing latency was measured using high-resolution performance timers (`time.perf_counter`) across ingestion, normalization, session correlation, behaviour classification, heuristic scoring, and policy evaluation:

| Benchmark Metric | Measured Result | Evaluation |
| :--- | :--- | :--- |
| **Ingestion API Latency** | `3.06 ms – 6.18 ms` per batch | Sub-10ms response time; zero blocking of collector threads. |
| **Analysis Pipeline Latency** | `< 1.2 ms` per session | Immediate deterministic evaluation. |
| **Dashboard Polling Cycle** | `3.0 seconds` | Consistent with standard frontend refresh cadence. |
| **Max Batch Size Enforced** | `1000 events` | Prevents memory exhaustion on bursty brute-force attacks. |

---

## 8. Repeatable Demo Steps

### Automated Test Matrix Execution

Run the standalone CLI test runner from the repository root:
```bash
python scripts/run_phase8_lab_matrix.py
```
*Expected Result*: All 10 scenarios output `[PASS]` with detailed session, category, score, and latency breakdowns.

Run the full pytest suite:
```bash
python -m pytest tests/test_phase8_lab_matrix.py -v
python -m pytest tests/ -v --tb=short
```
*Expected Result*: **282 tests passed**, 0 failures.

### Live Lab Testing (Kali Linux to Ubuntu VM)

1. **Start Dashboard Server on Windows/Host**:
   ```bash
   python dashboard/server.py --host 0.0.0.0 --port 8000
   ```
2. **Start Cowrie Honeypot on Ubuntu VM**:
   ```bash
   sudo systemctl start cowrie
   # Confirm listening on port 2222:
   sudo netstat -tulpn | grep 2222
   ```
3. **Start Telemetry Collector on Ubuntu VM**:
   ```bash
   python3 telemetry/collector.py \
       --log-path /home/sanjay/cowrie/var/log/cowrie/cowrie.json \
       --server-url http://192.168.56.1:8000 \
       --token cowrie-live-telemetry-secret-token \
       --poll-interval 2.0
   ```
4. **Execute Controlled Test Actions from Kali Linux VM**:
   ```bash
   # Scenario 2: Reconnaissance
   ssh -p 2222 root@192.168.56.10
   # (Once connected, execute):
   whoami
   uname -a
   hostname
   exit
   ```
5. **Observe Ubuntu Analysis Dashboard**:
   - Open browser at `http://127.0.0.1:8000/`.
   - Select **Live Cowrie Honeypot** source.
   - Header badge indicates `● LIVE COWRIE CONNECTED (N EVENTS)`.
   - Session table displays source IP `192.168.56.20`, primary category `reconnaissance`, score `9`.
   - Metric card 4 displays `RECOMMENDATIONS GENERATED: 1` (`POL-RECON-REVEAL-MYSQL`).

---

## 9. Known Limitations

1. **Local Tailer vs Remote Collector**:
   - When the dashboard server runs on Windows and Cowrie runs inside an Ubuntu VM without a shared folder mount, telemetry must be pushed via `telemetry/collector.py`. Local tailing only applies if the filesystem is shared or if the dashboard runs directly on Ubuntu.
2. **Stateless Restarts**:
   - Telemetry events and session groupings are currently held in memory. Restarting the backend server resets active sessions unless logs are re-ingested from the tailer.
3. **Advisory Scope**:
   - Deception actions remain strictly advisory and simulated. Real honeypot command interception (e.g. dynamically spoofing `cat /etc/passwd` output in Cowrie) is deferred to future architectural phases.

---

## 10. Phase 8 Completion Sign-Off

- **Baseline Tests**: 271 passed.
- **New Regression Tests**: 11 passed (`tests/test_phase8_lab_matrix.py`).
- **Total Suite**: **282 passed, 0 failed, 1 warning** in 12.10s.
- **Phase 8 Objectives**: Completed and verified. Ready for review before proceeding to Phase 9.
