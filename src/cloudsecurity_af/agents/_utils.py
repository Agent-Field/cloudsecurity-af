from __future__ import annotations

import json
from typing import TypeVar

from pydantic import BaseModel

from cloudsecurity_af.schemas.recon import ResourceGraph, ResourceInventory

T = TypeVar("T", bound=BaseModel)


def extract_harness_result(result: object, schema: type[T], agent_name: str) -> T:
    """Extract and validate a Pydantic model from an AgentField harness result.

    Handles the AgentField harness response envelope:
    - Checks ``is_error`` flag and raises on harness errors.
    - Extracts the ``parsed`` attribute, which is the structured output.
    - Falls back to ``model_validate`` if ``parsed`` is a raw dict.
    """
    is_error = bool(getattr(result, "is_error", False))
    if is_error:
        error_message = getattr(result, "error_message", None)
        result_text = getattr(result, "result", None)
        num_turns = getattr(result, "num_turns", "?")
        duration_ms = getattr(result, "duration_ms", "?")
        print(
            f"[{agent_name}] HARNESS ERROR: {error_message}\n"
            f"  turns={num_turns}, duration_ms={duration_ms}\n"
            f"  result_text={str(result_text)[:500] if result_text else None}",
            flush=True,
        )
        raise RuntimeError(f"{agent_name} harness error: {error_message}")

    parsed = getattr(result, "parsed", None)
    if isinstance(parsed, schema):
        return parsed

    debug_message = (
        f"[{agent_name}] harness result type={type(result).__name__}, "
        + f"is_error={getattr(result, 'is_error', '?')}, "
        + f"parsed type={type(getattr(result, 'parsed', None)).__name__}"
    )

    if isinstance(parsed, dict):
        try:
            return schema.model_validate(parsed)
        except Exception:
            print(debug_message, flush=True)
            raise

    print(debug_message, flush=True)
    raise TypeError(f"{agent_name} did not return a valid {schema.__name__}")


def build_graph_context_for_hunter(
    graph_path: str,
    inventory_path: str,
    domain_keywords: list[str],
) -> tuple[str, str, str]:
    import json

    _default_graph: dict[str, list[object]] = {"nodes": [], "edges": [], "clusters": []}
    _default_inventory: dict[str, list[object]] = {
        "resources": [],
        "modules": [],
        "variables": [],
        "outputs": [],
        "provider_configs": [],
    }

    try:
        with open(graph_path, "r") as f:
            graph_data = json.load(f)
    except Exception:
        graph_data = _default_graph
    if not isinstance(graph_data, dict):
        graph_data = _default_graph

    try:
        with open(inventory_path, "r") as f:
            inventory_data = json.load(f)
    except Exception:
        inventory_data = _default_inventory
    if not isinstance(inventory_data, dict):
        inventory_data = _default_inventory

    lowered_keywords = [keyword.lower() for keyword in domain_keywords if keyword]

    def _matches(node_type: str) -> bool:
        if not lowered_keywords:
            return True
        node_type_l = node_type.lower()
        return any(keyword in node_type_l for keyword in lowered_keywords)

    raw_nodes = graph_data.get("nodes", [])
    if not isinstance(raw_nodes, list):
        raw_nodes = []

    all_nodes_by_id: dict[str, dict[str, object]] = {}
    for node in raw_nodes:
        if isinstance(node, dict):
            all_nodes_by_id[node.get("resource_id", "")] = node

    relevant_nodes = [node for node in raw_nodes if isinstance(node, dict) and _matches(node.get("resource_type", ""))]
    relevant_node_ids = {node.get("resource_id") for node in relevant_nodes}

    raw_edges = graph_data.get("edges", [])
    if not isinstance(raw_edges, list):
        raw_edges = []

    relevant_edges = [
        edge
        for edge in raw_edges
        if isinstance(edge, dict)
        and (edge.get("source") in relevant_node_ids or edge.get("target") in relevant_node_ids)
    ]

    neighbor_ids: set[str] = set()
    for edge in relevant_edges:
        if isinstance(edge, dict):
            s, t = edge.get("source", ""), edge.get("target", "")
            if s not in relevant_node_ids:
                neighbor_ids.add(s)
            if t not in relevant_node_ids:
                neighbor_ids.add(t)

    neighbor_nodes = [all_nodes_by_id[nid] for nid in neighbor_ids if nid in all_nodes_by_id]

    node_lines = ["RELEVANT RESOURCES:"]
    if not relevant_nodes:
        node_lines.append("  - none matched this hunter domain")
    for node in relevant_nodes:
        node_lines.append(f"  - {node.get('resource_id')} ({node.get('resource_type')}) @ {node.get('file_path')}")
        node_lines.append(f"    Config: {node.get('config_summary')}")

    if neighbor_nodes:
        node_lines.append("\nCONNECTED RESOURCES (1-hop neighbors):")
        for node in neighbor_nodes:
            node_lines.append(f"  - {node.get('resource_id')} ({node.get('resource_type')}) @ {node.get('file_path')}")
            node_lines.append(f"    Config: {node.get('config_summary')}")

    edge_lines = ["RELEVANT RELATIONSHIPS:"]
    if not relevant_edges:
        edge_lines.append("  - no edges matched this hunter domain")
    for edge in relevant_edges:
        edge_lines.append(f"  - {edge.get('source')} --[{edge.get('type', 'references')}]--> {edge.get('target')}")
        if edge.get("description"):
            edge_lines.append(f"    {edge.get('description')}")

    raw_resources = inventory_data.get("resources", [])
    if not isinstance(raw_resources, list):
        raw_resources = []
    providers = sorted(
        {
            resource.get("provider")
            for resource in raw_resources
            if isinstance(resource, dict) and resource.get("provider")
        }
    )
    inventory_stats = "\n".join(
        [
            f"Total resources: {len(inventory_data.get('resources', []))}",
            f"Providers: {', '.join(providers) if providers else 'none'}",
            f"Modules: {len(inventory_data.get('modules', []))}",
            f"Variables: {len(inventory_data.get('variables', []))}",
            f"Outputs: {len(inventory_data.get('outputs', []))}",
            f"Graph nodes: {len(graph_data.get('nodes', []))}",
            f"Graph edges: {len(graph_data.get('edges', []))}",
            f"Filtered nodes: {len(relevant_nodes)}",
            f"Filtered edges: {len(relevant_edges)}",
        ]
    )

    return "\n".join(node_lines), inventory_stats, "\n".join(edge_lines)
