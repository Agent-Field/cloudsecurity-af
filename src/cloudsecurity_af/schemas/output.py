"""Output and orchestration schemas for CloudSecurity AF.

See docs/ARCHITECTURE.md for output payload specifications.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from ..scoring import Severity
from .chain import AttackPath
from .prove import VerifiedFinding  # noqa: TC001


class CloudSecurityScanResult(BaseModel):
    """Top-level CloudSecurity scan output."""

    repository: str
    commit_sha: str
    branch: str | None = None
    timestamp: datetime
    depth_profile: str
    tier: int = Field(description="1 = static, 2 = live, 3 = deep")
    providers_detected: list[str] = Field(default_factory=list)

    # Findings
    findings: list["VerifiedFinding"] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)

    # Counts
    total_resources_scanned: int = 0
    total_raw_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    inconclusive: int = 0
    not_exploitable: int = 0
    noise_reduction_pct: float = 0.0
    by_severity: dict[str, int] = Field(default_factory=dict)

    # Drift (Tier 2+)
    drift_resources: int = 0
    shadow_it_resources: int = 0

    # Compliance
    compliance_frameworks_checked: list[str] = Field(default_factory=list)
    compliance_gaps: list[str] = Field(default_factory=list)

    # Strategies
    strategies_used: list[str] = Field(default_factory=list)

    # Performance
    duration_seconds: float = 0.0
    agent_invocations: int = 0
    cost_usd: float = 0.0
    cost_breakdown: dict[str, float] = Field(default_factory=dict)

    # Metadata
    metadata: dict[str, object] = Field(default_factory=dict)
    sarif: str = ""


# Resolve forward references
_ = CloudSecurityScanResult.model_rebuild()


class ScanProgress(BaseModel):
    """Orchestrator phase progress event."""

    phase: str
    phase_progress: float
    agents_total: int
    agents_completed: int
    agents_running: int
    findings_so_far: int
    elapsed_seconds: float
    estimated_remaining_seconds: float
    cost_so_far_usd: float


class ScanMetrics(BaseModel):
    """Run-level performance and budget metrics."""

    duration_seconds: float
    agent_invocations: int
    cost_usd: float
    cost_breakdown: dict[str, float] = Field(default_factory=dict)
    budget_exhausted: bool = False
    findings_not_verified: int = 0
