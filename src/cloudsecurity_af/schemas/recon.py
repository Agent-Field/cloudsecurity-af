"""RECON phase schemas for CloudSecurity AF.

See docs/ARCHITECTURE.md Phase 1: RECON for full specifications.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# IaC Reader output
# ---------------------------------------------------------------------------


class Variable(BaseModel):
    """Terraform variable or CloudFormation parameter."""

    name: str
    type: str | None = None
    default: str | None = None
    description: str | None = None
    file_path: str | None = None


class Output(BaseModel):
    """Terraform output or CloudFormation output."""

    name: str
    value: str | None = None
    description: str | None = None
    file_path: str | None = None


class ProviderConfig(BaseModel):
    """Cloud provider block (e.g., aws, google, azurerm)."""

    name: str
    region: str | None = None
    alias: str | None = None
    version: str | None = None


class Module(BaseModel):
    """Terraform module reference."""

    name: str
    source: str
    version: str | None = None
    file_path: str | None = None


class Resource(BaseModel):
    """Individual IaC resource (Terraform resource, CloudFormation resource, K8s object)."""

    id: str = Field(description='e.g., "aws_s3_bucket.data_lake"')
    type: str = Field(description='e.g., "aws_s3_bucket"')
    name: str = Field(description='e.g., "data_lake"')
    provider: str = Field(description="aws | gcp | azure | kubernetes")
    file_path: str
    line_number: int = 0
    config: dict[str, Any] = Field(default_factory=dict, description="Raw resource configuration")
    references: list[str] = Field(
        default_factory=list,
        description="IDs of resources this depends on",
    )
    referenced_by: list[str] = Field(
        default_factory=list,
        description="IDs of resources that depend on this",
    )


class ResourceInventory(BaseModel):
    """Inventory pointer from IaC reader harness."""

    inventory_saved_path: str = Field(description="Absolute path to the generated inventory.json file")
    total_resources: int = 0
    iac_type: str = Field(
        default="terraform",
        description="terraform | cloudformation | kubernetes",
    )
    iac_version: str | None = None


# ---------------------------------------------------------------------------
# Resource Graph Builder output
# ---------------------------------------------------------------------------


class ResourceGraph(BaseModel):
    """Graph pointer from Resource Graph Builder harness."""

    graph_saved_path: str = Field(description="Absolute path to the generated graph.json file")
    total_nodes: int = 0
    total_edges: int = 0


# ---------------------------------------------------------------------------
# Drift Detection output (Tier 2+)
# ---------------------------------------------------------------------------


class ConfigDiff(BaseModel):
    """Single attribute difference between IaC and live state."""

    attribute: str
    iac_value: Any = None
    live_value: Any = None
    security_impact: str | None = None


class DriftedResource(BaseModel):
    """A resource that has drifted from its IaC declaration."""

    resource_id: str
    resource_type: str
    iac_config: dict[str, Any] = Field(default_factory=dict)
    live_config: dict[str, Any] = Field(default_factory=dict)
    diffs: list[ConfigDiff] = Field(default_factory=list)
    security_relevant: bool = False
    significance: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )


class DriftReport(BaseModel):
    """Complete drift analysis between IaC and live cloud."""

    drifted_resources: list[DriftedResource] = Field(default_factory=list)
    iac_only_resources: list[str] = Field(
        default_factory=list,
        description="Declared in IaC but not deployed",
    )
    cloud_only_resources: list[str] = Field(
        default_factory=list,
        description="Deployed but not in IaC (shadow IT)",
    )


# ---------------------------------------------------------------------------
# Aggregated RECON result
# ---------------------------------------------------------------------------


class ReconResult(BaseModel):
    """Complete RECON phase output."""

    inventory: ResourceInventory = Field(default_factory=ResourceInventory)
    resource_graph: ResourceGraph = Field(default_factory=ResourceGraph)
    drift_report: DriftReport | None = Field(
        default=None,
        description="Only populated for Tier 2+ scans",
    )
    live_inventory: ResourceInventory | None = Field(
        default=None,
        description="Live cloud state (Tier 2+ only)",
    )
    iac_type: str = "terraform"
    providers_detected: list[str] = Field(default_factory=list)
    total_resources: int = 0
    total_edges: int = 0
    recon_duration_seconds: float = 0.0
