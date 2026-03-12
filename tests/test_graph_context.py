from __future__ import annotations

from cloudsecurity_af.agents._utils import build_graph_context_for_hunter
from cloudsecurity_af.schemas.recon import (
    Resource,
    ResourceEdge,
    ResourceGraph,
    ResourceInventory,
    ResourceNode,
)


def _make_graph() -> ResourceGraph:
    return ResourceGraph(
        nodes=[
            ResourceNode(
                resource_id="aws_iam_role.admin",
                resource_type="aws_iam_role",
                name="admin",
                provider="aws",
                file_path="iam.tf",
                config_summary="AdministratorAccess policy attached",
            ),
            ResourceNode(
                resource_id="aws_s3_bucket.data",
                resource_type="aws_s3_bucket",
                name="data",
                provider="aws",
                file_path="storage.tf",
                config_summary="Public access enabled, no encryption",
            ),
            ResourceNode(
                resource_id="aws_vpc.main",
                resource_type="aws_vpc",
                name="main",
                provider="aws",
                file_path="network.tf",
                config_summary="10.0.0.0/16 CIDR",
            ),
        ],
        edges=[
            ResourceEdge(
                source_id="aws_iam_role.admin",
                target_id="aws_s3_bucket.data",
                relationship="data_access",
                description="Admin role can read data bucket",
            ),
            ResourceEdge(
                source_id="aws_vpc.main",
                target_id="aws_s3_bucket.data",
                relationship="network_path",
                description="VPC endpoint to S3",
            ),
        ],
    )


def _make_inventory() -> ResourceInventory:
    return ResourceInventory(
        resources=[
            Resource(id="aws_iam_role.admin", type="aws_iam_role", name="admin", provider="aws", file_path="iam.tf"),
            Resource(
                id="aws_s3_bucket.data", type="aws_s3_bucket", name="data", provider="aws", file_path="storage.tf"
            ),
            Resource(id="aws_vpc.main", type="aws_vpc", name="main", provider="aws", file_path="network.tf"),
        ],
    )


class TestBuildGraphContextForHunter:
    def test_iam_keywords_filter(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        summary, stats, edges = build_graph_context_for_hunter(graph, inventory, ["iam", "role"])
        assert "aws_iam_role.admin" in summary
        assert "aws_s3_bucket.data" not in summary
        assert "aws_iam_role.admin" in edges

    def test_network_keywords_filter(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        summary, stats, edges = build_graph_context_for_hunter(graph, inventory, ["vpc", "subnet"])
        assert "aws_vpc.main" in summary
        assert "aws_iam_role.admin" not in summary

    def test_s3_keywords_return_bucket(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        summary, stats, edges = build_graph_context_for_hunter(graph, inventory, ["s3", "bucket"])
        assert "aws_s3_bucket.data" in summary

    def test_empty_keyword_matches_all(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        summary, stats, edges = build_graph_context_for_hunter(graph, inventory, [""])
        assert "aws_iam_role.admin" in summary
        assert "aws_s3_bucket.data" in summary
        assert "aws_vpc.main" in summary

    def test_no_match_returns_none_message(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        summary, stats, edges = build_graph_context_for_hunter(graph, inventory, ["nonexistent_type_xyz"])
        assert "none matched" in summary

    def test_inventory_stats_format(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        _, stats, _ = build_graph_context_for_hunter(graph, inventory, ["iam"])
        assert "Total resources: 3" in stats
        assert "Graph nodes: 3" in stats
        assert "Graph edges: 2" in stats

    def test_edge_includes_connected_edges(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        _, _, edges = build_graph_context_for_hunter(graph, inventory, ["iam", "role"])
        assert "data_access" in edges
        assert "aws_s3_bucket.data" in edges

    def test_config_summary_in_output(self) -> None:
        graph = _make_graph()
        inventory = _make_inventory()
        summary, _, _ = build_graph_context_for_hunter(graph, inventory, ["iam"])
        assert "AdministratorAccess" in summary

    def test_empty_graph(self) -> None:
        graph = ResourceGraph()
        inventory = ResourceInventory()
        summary, stats, edges = build_graph_context_for_hunter(graph, inventory, ["iam"])
        assert "none matched" in summary
        assert "Total resources: 0" in stats
        assert "no edges matched" in edges
