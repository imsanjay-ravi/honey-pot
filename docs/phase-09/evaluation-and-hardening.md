# Phase 9 — Evaluation and Final Hardening

## 1. Executive Summary & Baselines

Phase 9 evaluates detection accuracy, false positives/negatives, invalid-action rejection, latency, and reliability across the **AI Adaptive Cyber Deception System**. It hardens telemetry ingest reliability against data loss during network hiccups and produces a repeatable benchmark report.

### Test Baselines
- **Baseline Test Suite (Phase 8 End)**: 282 passed, 1 deprecation warning, 0 failed.
- **Phase 8 Scenario Runner**: 10/10 integrated lab scenarios passed in ~4ms average batch latency.
- **Hardening Regression Tests Added**:
  - `telemetry/collector.py`: Offset retention on failed HTTP telemetry submission (`test_17_collector_retains_offset_on_failed_transmission` in `tests/test_live_cowrie.py`).
  - `tests/test_phase9_evaluation_and_hardening.py`: 8 comprehensive evaluation tests across detection quality, invalid-action safety, latency micro-benchmarks, and 1000-event burst stress.
- **Final Test Suite (Phase 9 End)**: **291 passed, 1 deprecation warning, 0 failed** in 12.47s.

---

## 2. Evaluation Dataset & Detection Quality

### Benchmark Dataset
Detection quality was evaluated using a curated benchmark of 14 ground-truth labeled sessions representing the primary attacker activity categories:
- **Reconnaissance** (`GT-RECON-1`, `GT-RECON-2`): Commands such as `whoami`, `id`, `uname -a`, `hostname`, `uptime`.
- **File & Directory Discovery** (`GT-FILEDISC-1`, `GT-FILEDISC-2`): Commands such as `ls -la /var/log`, `find / -name '*.txt'`, `tree /home`, `locate backup`, `file /bin/ls`.
- **Authentication Abuse** (`GT-AUTH-1`, `GT-AUTH-2`): Repeated login failures (brute force) and credential stuffing followed by a successful login.
- **Privilege Escalation & Credential Access** (`GT-PRIVESC-1`, `GT-PRIVESC-2`): `sudo -i`, `cat /root/.ssh/id_rsa`.
- **Download Attempt** (`GT-DOWNLOAD-1`, `GT-DOWNLOAD-2`): `wget http://.../miner.sh`, `curl -O https://.../exploit`.
- **Benign / Unknown Activity** (`GT-BENIGN-1`, `GT-BENIGN-2`): `pwd`, `echo 'system healthy'`, `clear`.
- **Mixed / Multi-Stage Attacks** (`GT-MIXED-1`, `GT-MIXED-2`): Sequences exercising category priority resolution (e.g. recon + download, file discovery + sudo).

### Confusion Matrix

$$\begin{array}{l|cccccc}
\textbf{Ground Truth \ Predicted} & \textbf{Recon} & \textbf{FileDisc} & \textbf{Auth} & \textbf{PrivEsc} & \textbf{Download} & \textbf{Unknown} \\
\hline
\textbf{Reconnaissance} & 2 & 0 & 0 & 0 & 0 & 0 \\
\textbf{File Discovery} & 0 & 2 & 0 & 0 & 0 & 0 \\
\textbf{Authentication Abuse} & 0 & 0 & 2 & 0 & 0 & 0 \\
\textbf{Privilege Escalation} & 0 & 0 & 0 & 3^* & 0 & 0 \\
\textbf{Download Attempt} & 0 & 0 & 0 & 0 & 3^* & 0 \\
\textbf{Unknown / Benign} & 0 & 0 & 0 & 0 & 0 & 2 \\
\end{array}$$

*\*Note: Includes mixed-stage sessions where download or privilege escalation represents the higher-severity primary label.*

### Detection Metrics

| Category | Samples (GT) | TP | FP | TN | FN | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Reconnaissance** | 2 | 2 | 0 | 12 | 0 | **1.00** | **1.00** | **1.00** |
| **File Discovery** | 2 | 2 | 0 | 12 | 0 | **1.00** | **1.00** | **1.00** |
| **Authentication Abuse** | 2 | 2 | 0 | 12 | 0 | **1.00** | **1.00** | **1.00** |
| **Privilege Escalation** | 3 | 3 | 0 | 11 | 0 | **1.00** | **1.00** | **1.00** |
| **Download Attempt** | 3 | 3 | 0 | 11 | 0 | **1.00** | **1.00** | **1.00** |
| **Unknown / Benign** | 2 | 2 | 0 | 12 | 0 | **1.00** | **1.00** | **1.00** |

> [!IMPORTANT]
> **Metric Limitations**: These precision and recall scores apply strictly to this curated integration test dataset. In uncurated, wild traffic, ambiguous or non-standard attacker commands (e.g. obfuscated base64 scripts, uncommon binaries) may fall back to `unknown`, producing lower recall.

---

## 3. False Positives, False Negatives, and Overlap Analysis

1. **Credential Targeting vs. File Discovery (`/etc/passwd`)**:
   - *Observation*: If an attacker executes `stat /etc/passwd` or `file /etc/passwd`, the token `/etc/passwd` matches `_CREDENTIAL_SUBSTRINGS`, which activates rule `PE-02`.
   - *Analysis*: Because `privilege_escalation_attempt` has higher priority than `file_discovery`, the classifier promotes the primary category to privilege escalation.
   - *Security Justification*: This is defensive by design: touching credential vaults (`/etc/passwd`, `/etc/shadow`, `id_rsa`) indicates credential interest regardless of the specific binary utility used to read metadata.
2. **Weak Indicators vs. Active Decoys**:
   - *Observation*: A single `ls` command produces rule `FD-01` (`file_discovery`, WEAK).
   - *Safety Handling*: Rather than immediately presenting active file decoys (which would be a false positive disruption for benign users), the policy engine executes `POL-FILE-DISC-WEAK`, which records interest conservatively without altering the environment.
3. **Multi-Stage Sessions and Priority Ladders**:
   - *Observation*: A session that performs both reconnaissance (`whoami`) and external tool download (`wget`) correctly classifies as `download_attempt`.
   - *Mechanism*: `primary_category()` enforces deterministic order:
     $$\text{PrivEsc} > \text{Download} > \text{AuthAbuse} > \text{FileDiscovery} > \text{Recon} > \text{Unknown}$$

---

## 4. Invalid-Action Rejection & Safety Boundaries

The policy engine and world state enforce strict safety boundaries:

| Safety Requirement | Test Mechanism | Outcome |
| :--- | :--- | :--- |
| **Allowlist Enforcement** | Injected unauthorized action IDs (e.g. `EXECUTE_SHELL_COMMAND`, `MODIFY_REAL_PASSWD`, `DEPLOY_REAL_IPTABLES_RULE`). | **100% Rejected** (`validate_action` returns `False`; orchestrator falls back to `POL-DEFAULT-NOOP` / `no_op`). |
| **Precondition Validation** | Attempted to present non-existent decoys or reveal non-existent services. | **100% Rejected** with clear error message (`"does not exist in fictional catalog"`). |
| **Idempotency & Duplicate Avoidance** | Repeated execution of `PE-02` (credential search). | Automatically transitions from primary decoy (`id_rsa_backup`) to secondary decoy (`.env`) to recording interest (`POL-CRED-RECORD-INTEREST`). |
| **Read-Only Live Telemetry** | Monitored `os.system` and `subprocess.Popen` calls during live telemetry ingest. | **0 subprocess calls, 0 host commands executed**. Real honeypot is never modified. |
| **State Distinction** | Inspected API output for live Cowrie mode vs synthetic scenarios. | Live Cowrie metric explicitly reports `RECOMMENDATIONS GENERATED`, `is_advisory: True`, and `actions_executed_count: 0`. |

---

## 5. Latency & Performance Benchmarks

Micro-benchmarks were measured over 200 consecutive iterations on the host environment:

| Pipeline Stage | Function Under Test | Average Latency (µs) | Latency (ms) | Target Threshold |
| :--- | :--- | :---: | :---: | :---: |
| **Event Normalization** | `parser.cowrie_parser:normalize_event` | **18.4 µs** | 0.018 ms | < 0.500 ms |
| **Feature Extraction** | `analysis.features:extract_features` | **42.1 µs** | 0.042 ms | < 0.500 ms |
| **Behaviour Classification** | `analysis.classifier:classify` | **26.8 µs** | 0.027 ms | < 0.500 ms |
| **Threat Scoring** | `analysis.scorer:compute_score` | **14.2 µs** | 0.014 ms | < 0.500 ms |
| **Policy Evaluation** | `deception.policy_engine:evaluate_policy` | **19.6 µs** | 0.020 ms | < 0.500 ms |
| **End-to-End Analysis** | Ingest batch → Session update → Recommendation | **~ 3.5 – 5.5 ms** | 3.5 – 5.5 ms | < 50.0 ms |

### Burst Stress Test
- **Input**: 1000 simulated Cowrie events pushed in a single HTTP batch (`POST /api/telemetry/ingest`).
- **Processing Time**: **118.2 ms** total wall-clock time.
- **Result**: All 1000 events parsed, normalized, session-correlated, and scored with 0 errors and 0 dropped records.

---

## 6. Confirmed Defects & Hardening Fixes

### Defect 1: Telemetry Data Loss on Failed HTTP Ingestion
- **Location**: `telemetry/collector.py:run_collector()`
- **Vulnerability**: In the original implementation, the collector read lines from `cowrie.json` and advanced its local `offset` variable on line 153 inside the readline loop *before* calling `forward_batch(server_url, batch, auth_token)`. If `forward_batch()` returned `False` (due to network disruption, server restarting, or timeout), the next poll resumed from the advanced offset, permanently discarding the unforwarded batch.
- **Hardening Fix**:
  1. Refactored `run_collector()` to record `start_offset` and track candidate read positions in `new_offset`.
  2. The collector now commits `offset = new_offset` **only when `forward_batch()` confirms HTTP 200 success**, or if the batch contained solely empty/malformed lines.
  3. On HTTP failure, `offset` remains at `start_offset`. The collector retains the exact byte offset and safely re-reads and re-submits the batch on the next poll interval.
- **Regression Test**: Added `test_17_collector_retains_offset_on_failed_transmission` in `tests/test_live_cowrie.py`. Tested transmission failure followed by recovery; verified zero events were lost and file offsets remained intact.

---

## 7. Assessment of Optional AI / LLM Capabilities

Per project guidelines, no external or paid AI service was integrated. Here is the architectural assessment:

### Current Capabilities with Deterministic Rules
- **Speed**: Sub-millisecond execution (18–42 µs per stage).
- **Explainability**: Every finding references a specific rule ID (e.g. `REC-01`, `PE-02`) with the exact triggering command and MITRE ATT&CK technique mapping.
- **Safety**: Zero hallucination risk; zero chance of generating unapproved command actions or executing unexpected side-effects.

### Potential Value of an AI Component
An LLM or local SLM (e.g. a small local ONNX or Ollama model) could add value in two specific edge areas:
1. **Semantic Command Clustering**: Detecting novel or heavily obfuscated command wrappers (e.g. custom bash functions, nested base64 pipes) that evade exact prefix or substring rules.
2. **Contextual Synthetic Decoy Generation**: Generating realistic, highly tailored fake `.env` keys, application database dumps, or bash history entries matching the observed attacker persona.

### Required Evidence Before Adopting AI
Before introducing an AI/LLM model in a future phase, the following evidence must be demonstrated:
1. Benchmark proof that the AI classifier reduces false negatives on an obfuscated command dataset without degrading latency beyond 100ms.
2. Formal sandboxing guaranteeing that LLM outputs cannot produce unvalidated deception actions outside `APPROVED_ACTIONS`.
3. Offline, zero-cost execution (local inference without external cloud API dependencies).

---

## 8. Remaining Limitations & Outstanding Manual Checks

1. **Cross-VM Network Verification (Ubuntu & Kali)**:
   - Automated regression tests use mock tailers and HTTP test clients. Live lab verification requires the physical VMs:
     - Ubuntu VM: Start Cowrie (`systemctl start cowrie`) and run `python3 telemetry/collector.py`.
     - Kali VM: Issue live probes (`ssh -p 2222 root@<UBUNTU_IP>`).
     - Host: Observe live dashboard at `http://127.0.0.1:8000/`.
2. **In-Memory Live Telemetry Lifespan**:
   - Ingested live sessions are maintained in memory. A server restart resets the live session buffer unless the collector is restarted to re-tail from the beginning of `cowrie.json`.

---

## 9. Demonstration Readiness & Phase 9 Sign-Off

- **Test Suite**: **291 tests passing, 0 failures, 1 deprecation warning**.
- **Integrated Lab Matrix**: **10/10 scenarios passed**.
- **Security & Safety**: Verified read-only live boundary, unapproved action rejection, and safe no-op fallbacks.
- **Telemetry Integrity**: Collector offset retention prevents event loss during network interruptions.
- **Phase 9 Status**: **100% COMPLETE**. Ready for Phase 10 (Final Wrap-up and Documentation).
