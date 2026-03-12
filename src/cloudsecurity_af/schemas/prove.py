"""PROVE phase schemas for CloudSecurity AF.

See docs/ARCHITECTURE.md Phase 4: PROVE for full specifications.
"""

from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from ..scoring import Severity
from .chain import AttackPath, BlastRadius
from .hunt import AffectedResource
from .recon import DriftedResource


class Verdict(str, Enum):
    """Exploitability verdict semantics."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    INCONCLUSIVE = "inconclusive"
    NOT_EXPLOITABLE = "not_exploitable"


class ProofMethod(str, Enum):
    """Verification method used to reach the verdict."""

    STATIC_ANALYSIS = "static_analysis"
    LIVE_API_VERIFICATION = "live_api_verification"
    IAM_SIMULATION = "iam_simulation"
    DRIFT_COMPARISON = "drift_comparison"


class Proof(BaseModel):
    """Evidence supporting the verdict."""

    method: ProofMethod = ProofMethod.STATIC_ANALYSIS
    evidence: list[str] = Field(default_factory=list)
    scripts_executed: list[str] = Field(
        default_factory=list,
        description="Actual commands/scripts the harness ran",
    )
    verification_tier: str = Field(
        default="static",
        description="static | live",
    )


class IaCDiff(BaseModel):
    """A unified diff patch for remediation."""

    file_path: str
    original_lines: str
    patched_lines: str
    start_line: int = 0
    end_line: int = 0


class RemediationSuggestion(BaseModel):
    """Actionable IaC fix for a finding."""

    finding_id: str = ""
    description: str
    diffs: list[IaCDiff] = Field(default_factory=list)
    breaking_change: bool = False
    downtime_estimate: str | None = Field(
        default=None,
        description="none | seconds | minutes | requires_maintenance_window",
    )
    effort: str = Field(
        default="moderate",
        description="trivial | moderate | significant",
    )
    alternative_approaches: list[str] = Field(default_factory=list)


class VerifiedFinding(BaseModel):
    """Finding fully assessed by PROVE phase."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    verdict: Verdict
    severity: Severity
    category: str
    resources: list[AffectedResource] = Field(default_factory=list)
    attack_path: AttackPath | None = None
    drift: DriftedResource | None = None
    proof: Proof = Field(default_factory=Proof)
    compliance_mappings: list[str] = Field(
        default_factory=list,
        description="CIS control IDs, SOC2 controls, etc.",
    )
    risk_score: float = 0.0
    remediation: RemediationSuggestion | None = None

    # SARIF integration
    sarif_rule_id: str = ""
    sarif_security_severity: float = 0.0

    # Traceability
    iac_file: str = ""
    iac_line: int = 0
    config_snippet: str = ""
    description: str = ""
    fingerprint: str = Field(default_factory=lambda: str(uuid4()))
    hunter_strategy: str = ""
    drop_reason: str | None = None
