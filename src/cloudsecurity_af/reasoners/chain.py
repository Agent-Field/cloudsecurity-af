from __future__ import annotations

from typing import Any

from cloudsecurity_af.agents.chain.path_constructor import run_path_constructor as _run_path_constructor
from cloudsecurity_af.schemas.hunt import RawFinding
from cloudsecurity_af.schemas.recon import DriftReport, ResourceGraph

from . import router

_runtime_router: Any = router


@router.reasoner()
async def run_path_constructor(
    findings: list[dict[str, Any]],
    resource_graph_path: str,
    max_paths: int,
    max_children: int,
    drift_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding_models = [RawFinding.model_validate(f) for f in findings]
    drift_model = DriftReport.model_validate(drift_report) if drift_report is not None else None
    result = await _run_path_constructor(
        _runtime_router,
        findings=finding_models,
        resource_graph_path=resource_graph_path,
        max_paths=max_paths,
        max_children=max_children,
        drift_report=drift_model,
    )
    return result.model_dump()
