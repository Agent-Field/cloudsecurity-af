from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.schemas.chain import AttackPath, ChainResult
from cloudsecurity_af.schemas.hunt import RawFinding
from cloudsecurity_af.schemas.recon import DriftReport, ResourceGraph


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


class ChildInvestigation(BaseModel):
    title: str
    rationale: str = ""
    findings_involved: list[str] = Field(default_factory=list)
    child_prompt: str


class PathInvestigationPlan(BaseModel):
    investigations: list[ChildInvestigation] = Field(default_factory=list)


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "chain" / "path_constructor.txt"


def _compact_finding(f: RawFinding) -> dict[str, Any]:
    return {
        "id": f.id,
        "title": f.title,
        "category": f.category,
        "severity": f.estimated_severity.value if hasattr(f.estimated_severity, "value") else str(f.estimated_severity),
        "resources": [r.resource_id for r in f.resources] if f.resources else [],
        "iac_file": f.iac_file,
        "iac_line": f.iac_line,
        "fingerprint": f.fingerprint,
    }


def _filter_graph_for_findings(graph_data: dict[str, Any], findings: list[RawFinding]) -> dict[str, Any]:
    finding_resources: set[str] = set()
    for f in findings:
        if f.resources:
            for r in f.resources:
                finding_resources.add(r.resource_id)
        if f.iac_file:
            finding_resources.add(f.iac_file)

    raw_edges = graph_data.get("edges", [])
    if not isinstance(raw_edges, list):
        raw_edges = []

    neighbors: set[str] = set()
    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        src, tgt = edge.get("source", ""), edge.get("target", "")
        if src in finding_resources:
            neighbors.add(tgt)
        if tgt in finding_resources:
            neighbors.add(src)

    relevant_ids = finding_resources | neighbors

    raw_nodes = graph_data.get("nodes", [])
    if not isinstance(raw_nodes, list):
        raw_nodes = []
    filtered_nodes = [n for n in raw_nodes if isinstance(n, dict) and n.get("resource_id") in relevant_ids]
    filtered_edges = [
        e
        for e in raw_edges
        if isinstance(e, dict) and e.get("source") in relevant_ids and e.get("target") in relevant_ids
    ]

    return {"nodes": filtered_nodes, "edges": filtered_edges, "clusters": graph_data.get("clusters", [])}


def _build_parent_prompt(
    template: str,
    findings: list[RawFinding],
    resource_graph_path: str,
    drift_report: DriftReport | None,
    max_paths: int,
    max_children: int,
) -> str:
    prompt = template
    prompt = prompt.replace("{{MAX_PATHS}}", str(max_paths))
    prompt = prompt.replace("{{MAX_CHILDREN}}", str(max_children))

    compact_findings = [_compact_finding(f) for f in findings]
    prompt = prompt.replace("{{FINDINGS_JSON}}", json.dumps(compact_findings, indent=2))

    try:
        with open(resource_graph_path, "r") as f:
            graph_data = json.load(f)
    except Exception:
        graph_data = {"nodes": [], "edges": [], "clusters": []}
    if not isinstance(graph_data, dict):
        graph_data = {"nodes": [], "edges": [], "clusters": []}

    filtered_graph = _filter_graph_for_findings(graph_data, findings)
    prompt = prompt.replace("{{RESOURCE_GRAPH_JSON}}", json.dumps(filtered_graph, indent=2))

    drift_payload = drift_report.model_dump() if drift_report is not None else {}
    prompt = prompt.replace("{{DRIFT_REPORT_JSON}}", json.dumps(drift_payload, indent=2))
    return prompt


def _child_prompt(investigation: ChildInvestigation, max_paths: int) -> str:
    return (
        f"{investigation.child_prompt.strip()}\n\n"
        "OUTPUT REQUIREMENTS:\n"
        "- Return a single JSON object matching AttackPath.\n"
        "- Only include a path if there is a coherent attacker progression across resources.\n"
        "- Use findings_involved IDs tied to the path steps.\n"
        "- Keep steps in strict step_number order starting at 1.\n"
        f"- The parent will keep at most {max_paths} final attack paths."
    )


async def run_path_constructor(
    app: HarnessCapable,
    findings: list[RawFinding],
    resource_graph_path: str,
    max_paths: int,
    max_children: int,
    drift_report: DriftReport | None = None,
) -> ChainResult:
    started = time.perf_counter()

    if not findings or max_paths <= 0 or max_children <= 0:
        return ChainResult(attack_paths=[], total_paths_evaluated=0, viable_paths=0, chain_duration_seconds=0.0)

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    parent_prompt = _build_parent_prompt(
        template=prompt_template,
        findings=findings,
        resource_graph_path=resource_graph_path,
        drift_report=drift_report,
        max_paths=max_paths,
        max_children=max_children,
    )

    harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-chain-")
    try:
        plan_result = await app.harness(prompt=parent_prompt, schema=PathInvestigationPlan, cwd=harness_cwd)
        plan = extract_harness_result(plan_result, PathInvestigationPlan, "PathConstructor")

        investigations = plan.investigations[:max_children]
        if not investigations:
            duration = time.perf_counter() - started
            return ChainResult(
                attack_paths=[],
                total_paths_evaluated=0,
                viable_paths=0,
                chain_duration_seconds=round(duration, 3),
            )

        async def _run_child(inv: ChildInvestigation) -> AttackPath | None:
            try:
                child_result = await app.harness(
                    prompt=_child_prompt(inv, max_paths),
                    schema=AttackPath,
                    cwd=harness_cwd,
                )
                return extract_harness_result(child_result, AttackPath, "PathConstructorChild")
            except Exception:
                return None

        child_results = await asyncio.gather(*[_run_child(inv) for inv in investigations])
        viable_paths = [path for path in child_results if path is not None][:max_paths]

        duration = time.perf_counter() - started
        return ChainResult(
            attack_paths=viable_paths,
            total_paths_evaluated=len(investigations),
            viable_paths=len(viable_paths),
            chain_duration_seconds=round(duration, 3),
        )
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
