"""
analysis/classifier.py — Deterministic behaviour classifier.

Each rule has a stable string ID, a human-readable description, the
minimum evidence required to fire, and an evidence-strength indicator.

Evidence-strength levels
------------------------
STRONG  — Unambiguous indicator; very low false-positive rate.
MODERATE — Clear indicator but possible innocent explanations.
WEAK    — Suggestive but context-dependent; easy to false-positive.

A session may match zero, one, or many rules.  Rules are NOT mutually
exclusive; a session that downloads a tool after bruteforcing SSH will
produce findings for both AUTHENTICATION_ABUSE and DOWNLOAD_ATTEMPT.

When no rule fires, the classifier returns a single UNKNOWN finding.

Categories
----------
  reconnaissance
  authentication_abuse
  file_discovery
  download_attempt
  privilege_escalation_attempt
  unknown

Rule table
----------
Rule ID                   Category                   Min evidence
REC-01  recon_command_count >= 1                     MODERATE
REC-02  recon_command_count >= 3                     STRONG
AUTH-01 login_failure_count >= 3                     MODERATE
AUTH-02 login_failure_count >= 5                     STRONG
AUTH-03 login_success_count >= 1 AND
          login_failure_count >= 1                    STRONG  (success after failures)
FD-01   file_discovery_count >= 1                    WEAK
FD-02   file_discovery_count >= 3                    MODERATE
DL-01   download_attempt_count >= 1                  STRONG
PE-01   privilege_escalation_count >= 1              STRONG
PE-02   has_credential_commands == True              STRONG
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Evidence strength constants
# ---------------------------------------------------------------------------

STRONG = "STRONG"
MODERATE = "MODERATE"
WEAK = "WEAK"

# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """
    One behaviour finding produced by the classifier.

    Attributes
    ----------
    rule_id:
        Stable identifier, e.g. ``"AUTH-02"``.
    category:
        Behaviour category string (see module docstring).
    evidence:
        Concise human-readable description of the evidence that fired
        this rule.  Treated as display text only; never executed.
    evidence_strength:
        One of ``STRONG``, ``MODERATE``, ``WEAK``.
    """
    rule_id: str
    category: str
    evidence: str
    evidence_strength: str


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    rule_id: str
    category: str
    evidence_strength: str
    description: str  # human-readable intent of the rule

    def evaluate(
        self,
        features: dict[str, Any],
    ) -> Finding | None:
        """Return a Finding if this rule fires, else None."""
        raise NotImplementedError


class _ReconLight(_Rule):
    """REC-01: at least one recon command observed."""

    def evaluate(self, features):
        n = features.get("recon_command_count", 0)
        if n >= 1:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} reconnaissance command(s) observed "
                         f"(id/whoami/uname/hostname/ifconfig/etc.)",
                evidence_strength=self.evidence_strength,
            )
        return None


class _ReconStrong(_Rule):
    """REC-02: three or more recon commands — systematic enumeration."""

    def evaluate(self, features):
        n = features.get("recon_command_count", 0)
        if n >= 3:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} reconnaissance commands — systematic "
                         f"system enumeration pattern.",
                evidence_strength=self.evidence_strength,
            )
        return None


class _AuthBruteModerate(_Rule):
    """AUTH-01: 3–4 consecutive login failures — possible credential spray."""

    def evaluate(self, features):
        failures = features.get("login_failure_count", 0)
        if 3 <= failures <= 4:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{failures} failed login attempt(s) — "
                         f"possible credential guessing.",
                evidence_strength=self.evidence_strength,
            )
        return None


class _AuthBruteStrong(_Rule):
    """AUTH-02: 5 or more login failures — brute-force credential attack."""

    def evaluate(self, features):
        failures = features.get("login_failure_count", 0)
        if failures >= 5:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{failures} failed login attempt(s) — "
                         f"brute-force credential attack.",
                evidence_strength=self.evidence_strength,
            )
        return None


class _AuthSuccessAfterFailure(_Rule):
    """AUTH-03: at least one success following at least one failure."""

    def evaluate(self, features):
        successes = features.get("login_success_count", 0)
        failures = features.get("login_failure_count", 0)
        if successes >= 1 and failures >= 1:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"Login succeeded after {failures} failure(s) — "
                         f"credential successfully guessed or valid credential used.",
                evidence_strength=self.evidence_strength,
            )
        return None


class _FileDiscoveryWeak(_Rule):
    """FD-01: one file-discovery command — could be legitimate."""

    def evaluate(self, features):
        n = features.get("file_discovery_count", 0)
        if n >= 1:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} file/directory discovery command(s) "
                         f"(ls/find/locate/etc.).",
                evidence_strength=self.evidence_strength,
            )
        return None


class _FileDiscoveryModerate(_Rule):
    """FD-02: three or more file-discovery commands — systematic browsing."""

    def evaluate(self, features):
        n = features.get("file_discovery_count", 0)
        if n >= 3:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} file/directory discovery commands — "
                         f"systematic filesystem browsing.",
                evidence_strength=self.evidence_strength,
            )
        return None


class _DownloadAttempt(_Rule):
    """DL-01: any command that would transfer data from an external host."""

    def evaluate(self, features):
        n = features.get("download_attempt_count", 0)
        if n >= 1:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} download/transfer attempt(s) "
                         f"(wget/curl/nc/tftp/etc.).",
                evidence_strength=self.evidence_strength,
            )
        return None


class _PrivEscCommand(_Rule):
    """PE-01: any privilege-escalation command observed."""

    def evaluate(self, features):
        n = features.get("privilege_escalation_count", 0)
        if n >= 1:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} privilege-escalation command(s) "
                         f"(sudo/su/chmod+s/visudo/etc.).",
                evidence_strength=self.evidence_strength,
            )
        return None


class _CredentialAccess(_Rule):
    """PE-02: command targeting credential files."""

    def evaluate(self, features):
        n = features.get("credential_command_count", 0)
        if n >= 1:
            return Finding(
                rule_id=self.rule_id,
                category=self.category,
                evidence=f"{n} credential-access command(s) targeting "
                         f"/etc/passwd, /etc/shadow, or .ssh/.",
                evidence_strength=self.evidence_strength,
            )
        return None


# ---------------------------------------------------------------------------
# Rule registry (ordered; each rule evaluated independently)
# ---------------------------------------------------------------------------

_RULES: list[_Rule] = [
    _ReconLight(
        rule_id="REC-01",
        category="reconnaissance",
        evidence_strength=MODERATE,
        description="At least one reconnaissance command observed.",
    ),
    _ReconStrong(
        rule_id="REC-02",
        category="reconnaissance",
        evidence_strength=STRONG,
        description="Three or more recon commands — systematic enumeration.",
    ),
    _AuthBruteModerate(
        rule_id="AUTH-01",
        category="authentication_abuse",
        evidence_strength=MODERATE,
        description="Three to four failed login attempts.",
    ),
    _AuthBruteStrong(
        rule_id="AUTH-02",
        category="authentication_abuse",
        evidence_strength=STRONG,
        description="Five or more failed login attempts — brute force.",
    ),
    _AuthSuccessAfterFailure(
        rule_id="AUTH-03",
        category="authentication_abuse",
        evidence_strength=STRONG,
        description="Successful login following at least one failure.",
    ),
    _FileDiscoveryWeak(
        rule_id="FD-01",
        category="file_discovery",
        evidence_strength=WEAK,
        description="At least one file/directory discovery command.",
    ),
    _FileDiscoveryModerate(
        rule_id="FD-02",
        category="file_discovery",
        evidence_strength=MODERATE,
        description="Three or more file/directory discovery commands.",
    ),
    _DownloadAttempt(
        rule_id="DL-01",
        category="download_attempt",
        evidence_strength=STRONG,
        description="Any download/transfer command observed.",
    ),
    _PrivEscCommand(
        rule_id="PE-01",
        category="privilege_escalation_attempt",
        evidence_strength=STRONG,
        description="Any privilege-escalation command observed.",
    ),
    _CredentialAccess(
        rule_id="PE-02",
        category="privilege_escalation_attempt",
        evidence_strength=STRONG,
        description="Command targeting credential files (/etc/passwd, .ssh, etc.).",
    ),
]

# Public access to the rule list for documentation and testing
RULES: list[_Rule] = _RULES

# Unknown finding returned when no rule fires
_UNKNOWN_FINDING = Finding(
    rule_id="UNKNOWN",
    category="unknown",
    evidence="No rule produced sufficient evidence for a definitive finding.",
    evidence_strength=WEAK,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify(features: dict[str, Any]) -> list[Finding]:
    """
    Apply all rules to *features* and return a list of :class:`Finding`.

    Parameters
    ----------
    features:
        Feature dict as returned by :func:`analysis.features.extract_features`.

    Returns
    -------
    list[Finding]
        One or more findings.  Returns ``[UNKNOWN_FINDING]`` when no rule
        fires.  Rules are evaluated independently; a session may produce
        multiple findings.
    """
    if not isinstance(features, dict):
        return [_UNKNOWN_FINDING]

    findings: list[Finding] = []
    for rule in _RULES:
        result = rule.evaluate(features)
        if result is not None:
            findings.append(result)

    if not findings:
        findings.append(_UNKNOWN_FINDING)

    return findings


def primary_category(findings: list[Finding]) -> str:
    """
    Select the single most significant category from a list of findings.

    Priority order (highest first): privilege_escalation_attempt,
    download_attempt, authentication_abuse, file_discovery,
    reconnaissance, unknown.

    This is a convenience function for display and summary purposes.
    The full findings list is the authoritative source of behaviour.
    """
    priority = [
        "privilege_escalation_attempt",
        "download_attempt",
        "authentication_abuse",
        "file_discovery",
        "reconnaissance",
        "unknown",
    ]
    categories = {f.category for f in findings}
    for cat in priority:
        if cat in categories:
            return cat
    return "unknown"
