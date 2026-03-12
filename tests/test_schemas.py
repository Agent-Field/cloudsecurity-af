"""Schema instantiation tests — verify all Pydantic models can be created and validated."""

from __future__ import annotations

import pytest

from cloudsecurity_af.schemas.input import CloudConfig, CloudSecurityInput
from cloudsecurity_af.schemas.recon import (
    ConfigDiff,
    DriftedResource,
    DriftReport,
    Module,
    Output,
    ProviderConfig,
    ReconResult,
    Resource,
    ResourceCluster,
    ResourceEdge,
    ResourceGraph,
    ResourceInventory,
    ResourceNode,
    Variable,
)
from cloudsecurity_af.schemas.hunt import (
    AffectedResource,
    Confidence,
    FindingCategory,
    HunterStrategy,
    HuntResult,
    RawFinding,
)
from cloudsecurity_af.schemas.chain import AttackPath, AttackStep, BlastRadius, ChainResult
from cloudsecurity_af.schemas.prove import (
    IaCDiff,
    Proof,
    ProofMethod,
    RemediationSuggestion,
    Verdict,
    VerifiedFinding,
)
from cloudsecurity_af.schemas.output import CloudSecurityScanResult, ScanMetrics, ScanProgress
from cloudsecurity_af.scoring import Severity


# ---------------------------------------------------------------------------
# Input schemas
# ---------------------------------------------------------------------------


class TestCloudConfig:
    def test_defaults(self) -> None:
        cfg = CloudConfig()
        assert cfg.provider == "aws"
        assert cfg.regions == ["us-east-1"]
        assert cfg.account_id is None
        assert cfg.assume_role_arn is None

    def test_custom(self) -> None:
        cfg = CloudConfig(provider="gcp", regions=["us-central1"], account_id="my-project")
        assert cfg.provider == "gcp"
        assert cfg.regions == ["us-central1"]


class TestCloudSecurityInput:
    def test_tier1_no_cloud(self) -> None:
        inp = CloudSecurityInput(repo_url="/tmp/my-repo")
        assert inp.tier == 1
        assert inp.cloud is None
        assert inp.depth == "standard"

    def test_tier2_with_cloud(self) -> None:
        inp = CloudSecurityInput(
            repo_url="/tmp/my-repo",
            cloud=CloudConfig(provider="aws"),
        )
        assert inp.tier == 2

    def test_depth_options(self) -> None:
        for depth in ("quick", "standard", "thorough"):
            inp = CloudSecurityInput(repo_url=".", depth=depth)
            assert inp.depth == depth

    def test_default_exclude_paths(self) -> None:
        inp = CloudSecurityInput(repo_url=".")
        assert ".git/" in inp.exclude_paths
        assert ".terraform/" in inp.exclude_paths


# ---------------------------------------------------------------------------
# Recon schemas
# ---------------------------------------------------------------------------


class TestReconSchemas:
    def test_resource_node_defaults(self) -> None:
        node = ResourceNode(
            resource_id="aws_s3_bucket.data",
            resource_type="aws_s3_bucket",
            name="data",
            provider="aws",
            file_path="main.tf",
        )
        assert node.config_summary == ""
        assert node.resource_id == "aws_s3_bucket.data"

    def test_resource_edge(self) -> None:
        edge = ResourceEdge(
            source_id="role.admin",
            target_id="bucket.data",
            relationship="data_access",
            description="Admin role can read data bucket",
        )
        assert edge.relationship == "data_access"

    def test_resource_graph_empty(self) -> None:
        graph = ResourceGraph()
        assert graph.nodes == []
        assert graph.edges == []
        assert graph.clusters == []

    def test_resource_inventory_empty(self) -> None:
        inv = ResourceInventory()
        assert inv.resources == []
        assert inv.iac_type == "terraform"

    def test_resource_inventory_populated(self) -> None:
        inv = ResourceInventory(
            resources=[
                Resource(
                    id="aws_s3_bucket.data",
                    type="aws_s3_bucket",
                    name="data",
                    provider="aws",
                    file_path="main.tf",
                )
            ],
            modules=[Module(name="vpc", source="terraform-aws-modules/vpc/aws")],
            variables=[Variable(name="region", default="us-east-1")],
            outputs=[Output(name="bucket_arn")],
            provider_configs=[ProviderConfig(name="aws", region="us-east-1")],
        )
        assert len(inv.resources) == 1
        assert inv.resources[0].provider == "aws"
        assert len(inv.modules) == 1

    def test_drift_report_empty(self) -> None:
        drift = DriftReport()
        assert drift.drifted_resources == []
        assert drift.iac_only_resources == []
        assert drift.cloud_only_resources == []

    def test_recon_result_defaults(self) -> None:
        result = ReconResult()
        assert result.total_resources == 0
        assert result.iac_type == "terraform"
        assert result.drift_report is None


# ---------------------------------------------------------------------------
# Hunt schemas
# ---------------------------------------------------------------------------


class TestHuntSchemas:
    def test_raw_finding_defaults(self) -> None:
        finding = RawFinding(
            hunter_strategy="iam",
            title="Over-permissioned role",
            description="Role has wildcard access",
            category="overprivilege",
        )
        assert finding.estimated_severity == Severity.MEDIUM
        assert finding.confidence == Confidence.MEDIUM
        assert finding.id  # UUID generated
        assert finding.iac_file == ""

    def test_finding_for_dedup(self) -> None:
        finding = RawFinding(
            hunter_strategy="network",
            title="Open security group",
            description="SG allows 0.0.0.0/0",
            category="public_exposure",
        )
        dedup = finding.for_dedup()
        assert dedup.id == finding.id
        assert dedup.title == finding.title

    def test_hunt_result_empty(self) -> None:
        result = HuntResult()
        assert result.findings == []
        assert result.total_raw == 0

    def test_hunter_strategy_enum(self) -> None:
        assert HunterStrategy.IAM.value == "iam"
        assert HunterStrategy.COMPLIANCE.value == "compliance"

    def test_finding_category_enum(self) -> None:
        assert FindingCategory.OVERPRIVILEGE.value == "overprivilege"
        assert FindingCategory.PRIVILEGED_CONTAINER.value == "privileged_container"


# ---------------------------------------------------------------------------
# Chain schemas
# ---------------------------------------------------------------------------


class TestChainSchemas:
    def test_attack_step(self) -> None:
        step = AttackStep(
            step_number=1,
            resource_id="role.admin",
            resource_type="aws_iam_role",
            action="Assume role via sts:AssumeRole",
            permission_used="sts:AssumeRole",
        )
        assert step.step_number == 1

    def test_attack_path(self) -> None:
        path = AttackPath(
            title="Public S3 to admin role",
            description="Chain from public bucket to admin",
            entry_point="aws_s3_bucket.public",
            target="aws_iam_role.admin",
            steps=[],
        )
        assert path.combined_severity == Severity.HIGH
        assert path.blast_radius.data_stores_reachable == []

    def test_chain_result_empty(self) -> None:
        result = ChainResult()
        assert result.attack_paths == []
        assert result.viable_paths == 0


# ---------------------------------------------------------------------------
# Prove schemas
# ---------------------------------------------------------------------------


class TestProveSchemas:
    def test_verified_finding_minimal(self) -> None:
        finding = VerifiedFinding(
            title="Test finding",
            verdict=Verdict.CONFIRMED,
            severity=Severity.HIGH,
            category="overprivilege",
        )
        assert finding.verdict == Verdict.CONFIRMED
        assert finding.risk_score == 0.0
        assert finding.proof.method == ProofMethod.STATIC_ANALYSIS

    def test_remediation_suggestion(self) -> None:
        rem = RemediationSuggestion(
            finding_id="test-id",
            description="Enable encryption",
            diffs=[
                IaCDiff(
                    file_path="main.tf",
                    original_lines="  encryption = false",
                    patched_lines="  encryption = true",
                    start_line=10,
                    end_line=10,
                )
            ],
            breaking_change=False,
            downtime_estimate="none",
        )
        assert len(rem.diffs) == 1
        assert not rem.breaking_change

    def test_verdict_enum(self) -> None:
        assert Verdict.CONFIRMED.value == "confirmed"
        assert Verdict.NOT_EXPLOITABLE.value == "not_exploitable"


# ---------------------------------------------------------------------------
# Output schemas
# ---------------------------------------------------------------------------


class TestOutputSchemas:
    def test_scan_result_minimal(self) -> None:
        from datetime import datetime

        result = CloudSecurityScanResult(
            repository="/tmp/repo",
            commit_sha="abc123",
            timestamp=datetime.now(),
            depth_profile="standard",
            tier=1,
        )
        assert result.tier == 1
        assert result.confirmed == 0
        assert result.findings == []

    def test_scan_progress(self) -> None:
        progress = ScanProgress(
            phase="HUNT",
            phase_progress=0.5,
            agents_total=7,
            agents_completed=3,
            agents_running=4,
            findings_so_far=12,
            elapsed_seconds=30.0,
            estimated_remaining_seconds=30.0,
            cost_so_far_usd=0.02,
        )
        assert progress.phase == "HUNT"

    def test_scan_metrics(self) -> None:
        metrics = ScanMetrics(
            duration_seconds=60.0,
            agent_invocations=15,
            cost_usd=0.05,
        )
        assert not metrics.budget_exhausted
