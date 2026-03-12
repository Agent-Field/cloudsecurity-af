"""REST API input schema for CloudSecurity AF scans.

See docs/ARCHITECTURE.md for input contract details.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CloudConfig(BaseModel):
    """Cloud provider credentials and targeting configuration.

    Credentials are resolved from environment variables (AWS_ACCESS_KEY_ID, etc.),
    never passed in the API payload.
    """

    provider: str = Field(
        default="aws",
        description="Cloud provider: aws | gcp | azure",
    )
    regions: list[str] = Field(
        default_factory=lambda: ["us-east-1"],
        description="Cloud regions to scan",
    )
    account_id: str | None = Field(
        default=None,
        description="Cloud account/project ID (optional, auto-detected if omitted)",
    )
    assume_role_arn: str | None = Field(
        default=None,
        description="AWS IAM role ARN to assume for scanning (OIDC-compatible)",
    )


class CloudSecurityInput(BaseModel):
    """Top-level input for cloudsecurity.scan and cloudsecurity.prove skills."""

    repo_url: str = Field(..., description="Git repository URL or local path containing IaC files")
    branch: str = Field(default="main", description="Branch to scan")
    commit_sha: str | None = Field(default=None, description="Specific commit SHA to scan")
    base_commit_sha: str | None = Field(
        default=None,
        description="Base commit SHA for diff-aware PR scanning",
    )
    depth: str = Field(
        default="standard",
        description="Scan depth profile: quick | standard | thorough",
    )
    severity_threshold: str = Field(
        default="low",
        description="Minimum severity to report: critical | high | medium | low | info",
    )
    output_formats: list[str] = Field(default_factory=lambda: ["json"])
    compliance_frameworks: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks to check: cis_aws | soc2 | hipaa | pci_dss",
    )

    # Cloud configuration (Tier 2+ — omit for static-only scans)
    cloud: CloudConfig | None = Field(
        default=None,
        description="Cloud provider config. Omit for Tier 1 static-only scans.",
    )

    # Budget controls
    max_cost_usd: float | None = Field(default=None, description="Budget cap in USD")
    max_duration_seconds: int | None = Field(default=None, description="Maximum execution time")
    max_concurrent_hunters: int | None = Field(default=None, description="Max parallel hunters")
    max_concurrent_provers: int | None = Field(default=None, description="Max parallel provers")

    # Path filtering
    include_paths: list[str] | None = Field(
        default=None,
        description="Only scan these repository paths (glob patterns)",
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["tests/", ".git/", "examples/", ".terraform/"],
    )

    # CI/CD integration
    is_pr: bool = Field(default=False, description="Whether scan is for a pull request")
    pr_id: str | None = Field(default=None, description="Pull request identifier")
    fail_on_findings: bool = Field(
        default=False,
        description="Return non-zero exit status for CI gating",
    )

    @property
    def tier(self) -> int:
        """Determine scan tier from configuration."""
        if self.cloud is None:
            return 1
        return 2
