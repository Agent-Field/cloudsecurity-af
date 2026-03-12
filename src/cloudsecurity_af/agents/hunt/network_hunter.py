from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cloudsecurity_af.agents._utils import build_graph_context_for_hunter, extract_harness_result
from cloudsecurity_af.schemas.hunt import HuntResult
from cloudsecurity_af.schemas.recon import ResourceGraph, ResourceInventory


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        project_dir: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "network.txt"


async def run_network_hunter(
    app: HarnessCapable,
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    resource_graph_summary, inventory_stats, relevant_edges = build_graph_context_for_hunter(
        resource_graph_path,
        inventory_path,
        [
            "vpc",
            "subnet",
            "security_group",
            "nacl",
            "route",
            "peering",
            "endpoint",
            "load_balancer",
            "elb",
            "alb",
            "nlb",
            "firewall",
            "gateway",
            "igw",
            "nat",
            "network_interface",
            "eni",
            "flow_log",
            "lb",
        ],
    )
    recon_context = f"{resource_graph_summary}\n\n{relevant_edges}\n\nINVENTORY STATS:\n{inventory_stats}"
    prompt = (
        prompt_template.replace("{{REPO_PATH}}", repo_path)
        .replace("{{DEPTH}}", depth)
        .replace("{{RESOURCE_GRAPH_SUMMARY}}", resource_graph_summary)
        .replace("{{INVENTORY_STATS}}", inventory_stats)
        .replace("{{RELEVANT_EDGES}}", relevant_edges)
        .replace("{{RECON_CONTEXT}}", recon_context)
    )

    harness_cwd = str(Path(repo_path).resolve())
    result = await app.harness(
        prompt=prompt,
        schema=HuntResult,
        cwd=harness_cwd,
        project_dir=repo_path,
    )
    parsed = extract_harness_result(result, HuntResult, "network_hunter")
    findings = parsed.findings
    return parsed.model_copy(
        update={
            "total_raw": parsed.total_raw or len(findings),
            "deduplicated_count": parsed.deduplicated_count or len(findings),
            "strategies_run": ["network"],
        }
    )
