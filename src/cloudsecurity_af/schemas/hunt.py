"""HUNT phase schemas for CloudSecurity AF.

See docs/ARCHITECTURE.md Phase 2: HUNT for full specifications.
"""

from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from ..scoring import Severity


class Confidence(str, Enum):
    """Confidence level for provisional findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class HunterStrategy(str, Enum):
    """Hunter specialization catalog."""

    IAM = "iam"
    NETWORK = "network"
    DATA = "data"
    SECRETS = "secrets"
    COMPUTE = "compute"
    LOGGING = "logging"
    COMPLIANCE = "compliance"


class FindingCategory(str, Enum):
    """High-level finding category."""

    OVERPRIVILEGE = "overprivilege"
    PUBLIC_EXPOSURE = "public_exposure"
    MISSING_ENCRYPTION = "missing_encryption"
    MISSING_LOGGING = "missing_logging"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_DEFAULT = "insecure_default"
    MISSING_MFA = "missing_mfa"
    DRIFT_INTRODUCED = "drift_introduced"
    COMPLIANCE_GAP = "compliance_gap"
    DANGEROUS_TRUST = "dangerous_trust"
    MISSING_BACKUP = "missing_backup"
    PRIVILEGED_CONTAINER = "privileged_container"
    OUTDATED_RUNTIME = "outdated_runtime"


class AffectedResource(BaseModel):
    """A specific resource attribute that is misconfigured."""

    resource_id: str
    resource_type: str
    attribute: str = Field(description="The specific attribute that is misconfigured")
    current_value: str = ""
    recommended_value: str = ""


class RawFinding(BaseModel):
    """Potential misconfiguration or policy violation from a hunter."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    hunter_strategy: str = Field(description="iam | network | data | secrets | compute | logging | compliance")
    title: str
    description: str
    category: str = Field(description="Finding category from FindingCategory enum")
    resources: list[AffectedResource] = Field(default_factory=list)
    estimated_severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    iac_file: str = ""
    iac_line: int = 0
    config_snippet: str = ""
    benchmark_id: str | None = Field(
        default=None,
        description="CIS control ID, SOC2 control, etc.",
    )
    fingerprint: str = Field(default_factory=lambda: str(uuid4()))

    def for_dedup(self) -> "FindingForDedup":
        """Project minimal fields for deduplication."""
        from .views import FindingForDedup

        return FindingForDedup(
            id=self.id,
            fingerprint=self.fingerprint,
            title=self.title,
            iac_file=self.iac_file,
            iac_line=self.iac_line,
            category=self.category,
            hunter_strategy=self.hunter_strategy,
            estimated_severity=self.estimated_severity.value,
        )


class HuntResult(BaseModel):
    """Deduplicated and correlated HUNT phase output."""

    findings: list[RawFinding] = Field(default_factory=list)
    total_raw: int = 0
    deduplicated_count: int = 0
    strategies_run: list[str] = Field(default_factory=list)
    hunt_duration_seconds: float = 0.0
