from __future__ import annotations

import pytest

from cloudsecurity_af.config import (
    DEPTH_CHAIN_LIMITS,
    DEPTH_HUNTER_MAP,
    DEPTH_PROVER_CAPS,
    AIIntegrationConfig,
    BudgetConfig,
    DepthProfile,
    ScanConfig,
)
from cloudsecurity_af.schemas.input import CloudSecurityInput


def test_aforge_exec_is_the_default_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "CLOUDSECURITY_PROVIDER",
        "HARNESS_PROVIDER",
        "CLOUDSECURITY_AFORGE_BIN",
        "AFORGE_BIN",
        "AGENTFIELD_AFORGE_COMMAND",
    ):
        monkeypatch.delenv(key, raising=False)

    config = AIIntegrationConfig.from_env()

    assert config.provider == "aforge"
    assert config.aforge_bin == "aforge"
    assert config.provider_env()["AGENTFIELD_AFORGE_COMMAND"] == "exec"


def test_opencode_remains_an_explicit_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HARNESS_PROVIDER", "opencode")

    assert AIIntegrationConfig.from_env().provider == "opencode"


def test_aforge_bin_is_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLOUDSECURITY_AFORGE_BIN", raising=False)
    monkeypatch.setenv("AFORGE_BIN", "/opt/aforge/bin/aforge")

    assert AIIntegrationConfig.from_env().aforge_bin == "/opt/aforge/bin/aforge"

    monkeypatch.setenv("CLOUDSECURITY_AFORGE_BIN", "/usr/local/bin/aforge")

    assert AIIntegrationConfig.from_env().aforge_bin == "/usr/local/bin/aforge"


def test_installed_sdk_supports_the_aforge_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pinned agentfield floor must accept the provider/bin this agent wires up."""
    from agentfield import HarnessConfig

    for key in ("CLOUDSECURITY_PROVIDER", "HARNESS_PROVIDER", "CLOUDSECURITY_AFORGE_BIN", "AFORGE_BIN"):
        monkeypatch.delenv(key, raising=False)
    config = AIIntegrationConfig.from_env()

    harness = HarnessConfig(
        provider=config.provider,
        model=config.harness_model,
        max_turns=config.max_turns,
        env=config.provider_env(),
        opencode_bin=config.opencode_bin,
        aforge_bin=config.aforge_bin,
        permission_mode="auto",
    )

    assert harness.provider == "aforge"
    assert harness.aforge_bin == "aforge"


class TestDepthProfile:
    def test_enum_values(self) -> None:
        assert DepthProfile.QUICK.value == "quick"
        assert DepthProfile.STANDARD.value == "standard"
        assert DepthProfile.THOROUGH.value == "thorough"

    def test_quick_hunters(self) -> None:
        hunters = DEPTH_HUNTER_MAP[DepthProfile.QUICK]
        assert "iam" in hunters
        assert "network" in hunters
        assert "compliance" not in hunters

    def test_standard_hunters(self) -> None:
        hunters = DEPTH_HUNTER_MAP[DepthProfile.STANDARD]
        assert len(hunters) == 7
        assert "compliance" in hunters

    def test_chain_limits(self) -> None:
        assert DEPTH_CHAIN_LIMITS[DepthProfile.QUICK] == 5
        assert DEPTH_CHAIN_LIMITS[DepthProfile.STANDARD] == 15
        assert DEPTH_CHAIN_LIMITS[DepthProfile.THOROUGH] == 100

    def test_prover_caps(self) -> None:
        assert DEPTH_PROVER_CAPS[DepthProfile.QUICK] == 10
        assert DEPTH_PROVER_CAPS[DepthProfile.THOROUGH] == 10_000


class TestBudgetConfig:
    def test_defaults(self) -> None:
        budget = BudgetConfig()
        assert budget.max_concurrent_hunters == 4
        assert budget.max_concurrent_provers == 3
        assert budget.max_cost_usd is None
        total = (
            budget.recon_budget_pct
            + budget.hunt_budget_pct
            + budget.chain_budget_pct
            + budget.prove_budget_pct
            + budget.remediate_budget_pct
        )
        assert total == pytest.approx(1.0)


class TestScanConfig:
    def test_from_input_tier1(self) -> None:
        inp = CloudSecurityInput(repo_url="/tmp/repo", depth="quick")
        cfg = ScanConfig.from_input(inp, "/tmp/repo")
        assert cfg.depth == DepthProfile.QUICK
        assert cfg.tier == 1
        assert cfg.repo_path == "/tmp/repo"

    def test_from_input_tier2(self) -> None:
        from cloudsecurity_af.schemas.input import CloudConfig

        inp = CloudSecurityInput(repo_url="/tmp/repo", cloud=CloudConfig())
        cfg = ScanConfig.from_input(inp, "/tmp/repo")
        assert cfg.tier == 2

    def test_from_input_budget_override(self) -> None:
        inp = CloudSecurityInput(
            repo_url="/tmp/repo",
            max_concurrent_hunters=2,
            max_concurrent_provers=1,
            max_cost_usd=5.0,
        )
        cfg = ScanConfig.from_input(inp, "/tmp/repo")
        assert cfg.budget.max_concurrent_hunters == 2
        assert cfg.budget.max_concurrent_provers == 1
        assert cfg.budget.max_cost_usd == 5.0
