from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.agents.recon._graph_builder_fast import build_graph_from_inventory
from cloudsecurity_af.schemas.recon import ResourceGraph, ResourceInventory

log = logging.getLogger(__name__)


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "resource_graph_builder.txt"


async def run_resource_graph_builder(app: HarnessCapable, repo_path: str, inventory_path: str) -> ResourceGraph:
    work_dir = tempfile.mkdtemp(prefix="cloudsecurity-recon-graph-builder-")
    try:
        return _fast_build(inventory_path, work_dir)
    except Exception as exc:
        log.warning("Deterministic graph builder failed (%s), falling back to harness", exc)
        return await _harness_fallback(app, repo_path, inventory_path, work_dir)


def _fast_build(inventory_path: str, work_dir: str) -> ResourceGraph:
    graph_path, total_nodes, total_edges = build_graph_from_inventory(inventory_path, work_dir)
    return ResourceGraph(
        graph_saved_path=graph_path,
        total_nodes=total_nodes,
        total_edges=total_edges,
    )


async def _harness_fallback(app: HarnessCapable, repo_path: str, inventory_path: str, work_dir: str) -> ResourceGraph:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = prompt_template.replace("{{INVENTORY_PATH}}", inventory_path)
    result = await app.harness(
        prompt=prompt,
        schema=ResourceGraph,
        cwd=work_dir,
        project_dir=repo_path,
    )
    return extract_harness_result(result, ResourceGraph, "Resource graph builder")
