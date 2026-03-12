from __future__ import annotations

import os
import tempfile
from enum import Enum

from pydantic import BaseModel, Field

from .schemas.input import CloudSecurityInput


class DepthProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"


class BudgetConfig(BaseModel):
    max_cost_usd: float | None = None
    max_duration_seconds: int | None = None
    max_concurrent_hunters: int = 4
    max_concurrent_provers: int = 3
    max_concurrent_chain_children: int = 3
    recon_budget_pct: float = 0.10
    hunt_budget_pct: float = 0.35
    chain_budget_pct: float = 0.20
    prove_budget_pct: float = 0.25
    remediate_budget_pct: float = 0.10


DEPTH_HUNTER_MAP: dict[DepthProfile, list[str]] = {
    DepthProfile.QUICK: ["iam", "network", "data", "secrets", "compute"],
    DepthProfile.STANDARD: ["iam", "network", "data", "secrets", "compute", "logging", "compliance"],
    DepthProfile.THOROUGH: ["iam", "network", "data", "secrets", "compute", "logging", "compliance"],
}

DEPTH_CHAIN_LIMITS: dict[DepthProfile, int] = {
    DepthProfile.QUICK: 5,
    DepthProfile.STANDARD: 15,
    DepthProfile.THOROUGH: 100,
}

DEPTH_PROVER_CAPS: dict[DepthProfile, int] = {
    DepthProfile.QUICK: 20,
    DepthProfile.STANDARD: 30,
    DepthProfile.THOROUGH: 10_000,
}


class ScanConfig(BaseModel):
    repo_path: str
    depth: DepthProfile = DepthProfile.STANDARD
    tier: int = 1
    severity_threshold: str = "low"
    output_formats: list[str] = Field(default_factory=lambda: ["json"])
    compliance_frameworks: list[str] = Field(default_factory=list)
    include_paths: list[str] | None = None
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["tests/", ".git/", "examples/", ".terraform/"],
    )
    budget: BudgetConfig = Field(default_factory=BudgetConfig)

    @classmethod
    def from_input(cls, scan_input: CloudSecurityInput, repo_path: str) -> ScanConfig:
        depth = DepthProfile(scan_input.depth)
        budget = BudgetConfig(
            max_cost_usd=scan_input.max_cost_usd,
            max_duration_seconds=scan_input.max_duration_seconds,
        )
        if scan_input.max_concurrent_hunters is not None:
            budget.max_concurrent_hunters = scan_input.max_concurrent_hunters
        if scan_input.max_concurrent_provers is not None:
            budget.max_concurrent_provers = scan_input.max_concurrent_provers
        return cls(
            repo_path=repo_path,
            depth=depth,
            tier=scan_input.tier,
            severity_threshold=scan_input.severity_threshold,
            output_formats=scan_input.output_formats,
            compliance_frameworks=scan_input.compliance_frameworks,
            include_paths=scan_input.include_paths,
            exclude_paths=scan_input.exclude_paths,
            budget=budget,
        )


class AIIntegrationConfig(BaseModel):
    provider: str = Field(
        default_factory=lambda: os.getenv("CLOUDSECURITY_PROVIDER", os.getenv("HARNESS_PROVIDER", "opencode"))
    )
    harness_model: str = Field(
        default_factory=lambda: os.getenv(
            "CLOUDSECURITY_MODEL",
            os.getenv("HARNESS_MODEL", "minimax/minimax-m2.5"),
        )
    )
    ai_model: str = Field(
        default_factory=lambda: os.getenv(
            "CLOUDSECURITY_AI_MODEL",
            os.getenv("AI_MODEL", os.getenv("CLOUDSECURITY_MODEL", "minimax/minimax-m2.5")),
        )
    )
    max_turns: int = Field(default_factory=lambda: int(os.getenv("CLOUDSECURITY_MAX_TURNS", "50")))
    opencode_bin: str = Field(default_factory=lambda: os.getenv("CLOUDSECURITY_OPENCODE_BIN", "opencode"))

    @classmethod
    def from_env(cls) -> AIIntegrationConfig:
        return cls()

    def provider_env(self) -> dict[str, str]:
        env_keys = (
            "OPENROUTER_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GOOGLE_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "AZURE_SUBSCRIPTION_ID",
        )
        env: dict[str, str] = {key: value for key in env_keys if (value := os.getenv(key))}
        xdg = os.getenv("XDG_DATA_HOME") or os.path.join(tempfile.gettempdir(), "opencode-shared-data")
        os.makedirs(xdg, exist_ok=True)
        env["XDG_DATA_HOME"] = xdg
        return env
