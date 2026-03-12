"""CHAIN phase schemas for CloudSecurity AF.

See docs/ARCHITECTURE.md Phase 3: CHAIN for full specifications.
The CHAIN phase is CloudSecurity's key differentiator — it constructs
multi-resource attack paths via meta-prompting.
"""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field

from ..scoring import Severity


class AttackStep(BaseModel):
    """One step in a multi-resource attack path."""

    step_number: int
    resource_id: str
    resource_type: str
    action: str = Field(description="What the attacker does at this step")
    permission_used: str = Field(description="The specific permission or config that enables this step")
    description: str = ""


class BlastRadius(BaseModel):
    """Impact assessment for a confirmed attack path."""

    data_stores_reachable: list[str] = Field(default_factory=list)
    compute_reachable: list[str] = Field(default_factory=list)
    estimated_data_volume: str | None = None
    services_affected: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    """A multi-resource attack path assembled from individual findings."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    steps: list[AttackStep] = Field(default_factory=list)
    entry_point: str = Field(description="Public-facing resource where attack begins")
    target: str = Field(description="What the attacker ultimately reaches")
    findings_involved: list[str] = Field(
        default_factory=list,
        description="IDs of HUNT findings that compose this path",
    )
    combined_severity: Severity = Severity.HIGH
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)


class ChainResult(BaseModel):
    """Complete CHAIN phase output."""

    attack_paths: list[AttackPath] = Field(default_factory=list)
    total_paths_evaluated: int = 0
    viable_paths: int = 0
    chain_duration_seconds: float = 0.0
