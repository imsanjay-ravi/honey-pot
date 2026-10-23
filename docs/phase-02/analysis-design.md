# Phase 2 — Analysis Engine Design

## Purpose

This document describes the deterministic behaviour analysis engine
introduced in Phase 2.  It is the reference for anyone adding rules,
adjusting weights, or writing tests.

---

## 1. Feature Definitions (`analysis/features.py`)

Feature extraction converts a list of normalized event dicts into a flat
dict.  All values are safe Python scalars.  No command string is executed
or passed to a shell at any point.

### Core Counts

| Feature | Type | Definition |
|---|---|---|
| `total_events` | int | Total events in the session list |
| `session_duration_s` | float or None | Seconds from first to last timestamp; None when fewer than 2 timestamps |
| `command_count` | int | Events where `event_type == "command"` |
| `failed_command_count` | int | Events where `event_type == "command_failed"` |
| `login_attempt_count` | int | Events where `event_type == "login"` |
| `login_success_count` | int | Login events where `success == True` |
| `login_failure_count` | int | Login events where `success == False` |
| `other_event_count` | int | Events where `event_type == "other"` |
| `unknown_event_count` | int | Alias for `other_event_count` |

### Command-Category Indicators

Matching uses `str.startswith()` and substring search on the **lowercased**
command string only.  The original string is never modified or executed.

| Feature (bool) | Commands / patterns matched |
|---|---|
| `has_recon_commands` | `id`, `whoami`, `uname`, `hostname`, `ifconfig`, `ip `, `netstat`, `ss `, `arp`, `w `, `who`, `last`, `uptime`, `env`, `printenv`, `set`; substrings `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/os-release`, `/proc/version` |
| `has_file_discovery` | `ls`, `find `, `locate `, `dir `, `tree`, `stat `, `file `, `lsof`, `du `, `df ` |
| `has_download_attempt` | `wget`, `curl`, `tftp`, `scp `, `sftp`, `nc `, `ncat`, `fetch `, `axel `; substrings `http://`, `https://`, `ftp://` |
| `has_privilege_escalation` | `sudo`, `su `, `passwd`, `usermod`, `adduser`, `visudo`, `chown root`; substrings `chmod +s`, `/etc/sudoers` |
| `has_credential_commands` | `grep passwd`, `grep shadow`; substrings `/etc/passwd`, `/etc/shadow`, `/.ssh`, `/root/.ssh`, `id_rsa`, `authorized_keys` |

### Command-Category Counts

| Feature | Type | Definition |
|---|---|---|
| `recon_command_count` | int | Number of commands matching recon patterns |
| `file_discovery_count` | int | Number of commands matching file-discovery patterns |
| `download_attempt_count` | int | Number of commands matching download patterns |
| `privilege_escalation_count` | int | Number of commands matching priv-esc patterns |
| `credential_command_count` | int | Number of commands matching credential-access patterns |

### Username Features

| Feature | Type | Definition |
|---|---|---|
| `unique_username_count` | int | Distinct non-empty usernames across all login events |
| `has_root_login` | bool | Any login event used username `"root"` |

---

## 2. Classification Rules (`analysis/classifier.py`)

Rules are evaluated **independently** — a session can match any number of
rules.  When no rule fires, the session is categorised as `unknown`.

### Evidence-Strength Levels

| Level | Meaning |
|---|---|
| `STRONG` | Unambiguous indicator; very low false-positive rate |
| `MODERATE` | Clear indicator but innocent explanations possible |
| `WEAK` | Suggestive; easy to false-positive; requires context |

### Rule Table

| Rule ID | Category | Min Evidence | Strength | Description |
|---|---|---|---|---|
| REC-01 | `reconnaissance` | `recon_command_count >= 1` | MODERATE | At least one recon command |
| REC-02 | `reconnaissance` | `recon_command_count >= 3` | STRONG | Three or more — systematic enumeration |
| AUTH-01 | `authentication_abuse` | `login_failure_count` in [3,4] | MODERATE | Possible credential guessing |
| AUTH-02 | `authentication_abuse` | `login_failure_count >= 5` | STRONG | Brute-force credential attack |
| AUTH-03 | `authentication_abuse` | success ≥ 1 AND failure ≥ 1 | STRONG | Login succeeded after failures |
| FD-01 | `file_discovery` | `file_discovery_count >= 1` | WEAK | One file/dir discovery command |
| FD-02 | `file_discovery` | `file_discovery_count >= 3` | MODERATE | Systematic filesystem browsing |
| DL-01 | `download_attempt` | `download_attempt_count >= 1` | STRONG | Any download/transfer command |
| PE-01 | `privilege_escalation_attempt` | `privilege_escalation_count >= 1` | STRONG | Privilege-escalation command |
| PE-02 | `privilege_escalation_attempt` | `credential_command_count >= 1` | STRONG | Credential-file access command |

### Primary Category Priority

When a session matches multiple categories, `primary_category()` returns
the highest-priority one:

1. `privilege_escalation_attempt`
2. `download_attempt`
3. `authentication_abuse`
4. `file_discovery`
5. `reconnaissance`
6. `unknown`

### Known False-Positive Risks

| Rule | FP Risk | Mitigation |
|---|---|---|
| FD-01 | A legitimate admin running `ls` will match | Threshold is 1; check context with REC rules |
| REC-01 | Automated healthchecks may run `hostname` or `uptime` | Requires `recon_command_count >= 1`; score contribution is low |
| AUTH-01 | Typos produce 3 failures easily | Threshold is 3; MODERATE strength; score is low without other signals |

---

## 3. Scoring Formula (`analysis/scorer.py`)

Score is an integer in **[0, 100]**.  It is NOT a probability.

### Factor Weights

| Factor | Weight per unit | Cap (units) | Max contribution |
|---|---|---|---|
| Login failures | 2 | 10 | 20 |
| Login success after failure | 15 | 1 | 15 |
| Recon commands | 3 | 5 | 15 |
| File-discovery commands | 2 | 5 | 10 |
| Download attempts | 20 | 2 | 40 |
| Privilege-escalation commands | 20 | 2 | 40 |
| Credential-access commands | 15 | 1 | 15 |
| **Raw maximum** | | | **155** |
| **Final (capped)** | | | **100** |

`score = min(round(raw_sum), 100)`

### Limitations

- Weights are expert-chosen, not trained on labelled data.
- A single `ls` scores only 2 (one file-discovery command); this is intentional.
- Download and privilege-escalation are weighted highest because they are
  reliably malicious in an SSH honeypot context.
- Score does not account for inter-session correlation or IP reputation.

---

## 4. Analysis Result Schema (`analysis/engine.py`)

```json
{
  "session_id": "string or null",
  "engine_version": "1.0.0",
  "rule_set_version": "1.0.0",
  "features": { ... },
  "findings": [
    {
      "rule_id": "AUTH-02",
      "category": "authentication_abuse",
      "evidence": "7 failed login attempts — brute-force credential attack.",
      "evidence_strength": "STRONG"
    }
  ],
  "primary_category": "authentication_abuse",
  "score": 64,
  "score_contributions": [
    {
      "factor": "login_failures",
      "value": 7,
      "capped_at": 10,
      "weight": 2,
      "contribution": 14.0
    }
  ],
  "score_explanation": "Score 64/100. Main factors: ...",
  "warnings": []
}
```

---

## 5. CLI Usage (`analysis/cli.py`)

```
# Analyse normalized events, print to console:
python -m analysis.cli path/to/normalized_events.json

# Analyse and save JSON results:
python -m analysis.cli path/to/normalized_events.json --output results.json

# Suppress the feature block:
python -m analysis.cli path/to/normalized_events.json --no-features

# Machine-readable output only (requires --output):
python -m analysis.cli path/to/normalized_events.json \
    --output results.json --json-only
```

The CLI never writes results to the same path as the input.

---

## 6. Synthetic Fixtures

All tests use synthetic fixtures defined inline in `tests/test_analysis.py`.
IP addresses are RFC 5737 documentation addresses (`192.0.2.x`).
Timestamps are clearly fictional (`2026-01-15T10:xx:00Z`).

The tracked `data/normalized_events.json` and `data/sessions.json` files
are **not** used as test fixtures.

---

## 7. Known Limitations

- No ML model; rules are hand-written and may miss novel attack patterns.
- Commands must be in the `command` field of a `command` event; commands
  embedded in other event types are not matched.
- The engine works on one session's events at a time; it does not correlate
  across multiple source IPs or time windows.
- Score weights have not been validated against labelled attack scenarios.
