"""Phase-boundary view models for context-specific data passing.

These provide minimal projections of complex schemas for specific consumers,
following the Composite Intelligence principle of contextual fidelity.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FindingForDedup(BaseModel):
    """Minimal fields needed for deduplication."""

    id: str
    fingerprint: str
    title: str
    iac_file: str
    iac_line: int
    category: str
    hunter_strategy: str
    estimated_severity: str


class FindingForProver(BaseModel):
    """What the prover pipeline needs from a RawFinding + attack path."""

    id: str
    title: str
    description: str
    category: str
    hunter_strategy: str
    iac_file: str
    iac_line: int
    config_snippet: str
    resources_summary: str = Field(
        default="",
        description="Natural language summary of affected resources",
    )
    attack_path_summary: str = Field(
        default="",
        description="Natural language summary of attack path (if any)",
    )
    benchmark_id: str | None = None


class FindingForChain(BaseModel):
    """What the chain constructor needs from a RawFinding."""

    id: str
    title: str
    description: str
    category: str
    resources: list[str] = Field(
        default_factory=list,
        description="Resource IDs affected by this finding",
    )
    estimated_severity: str = ""
    confidence: str = ""
