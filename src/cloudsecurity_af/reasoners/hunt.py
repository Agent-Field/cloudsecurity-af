from __future__ import annotations

from typing import Any

from cloudsecurity_af.agents.hunt.compliance_hunter import run_compliance_hunter as _run_compliance_hunter
from cloudsecurity_af.agents.hunt.compute_hunter import run_compute_hunter as _run_compute_hunter
from cloudsecurity_af.agents.hunt.data_hunter import run_data_hunter as _run_data_hunter
from cloudsecurity_af.agents.hunt.iam_hunter import run_iam_hunter as _run_iam_hunter
from cloudsecurity_af.agents.hunt.logging_hunter import run_logging_hunter as _run_logging_hunter
from cloudsecurity_af.agents.hunt.network_hunter import run_network_hunter as _run_network_hunter
from cloudsecurity_af.agents.hunt.secrets_hunter import run_secrets_hunter as _run_secrets_hunter
from cloudsecurity_af.schemas.recon import ResourceGraph, ResourceInventory

from . import router

_runtime_router: Any = router


async def _run_hunter(
    runner: Any,
    *,
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    result = await runner(
        app=_runtime_router,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )
    return result.model_dump()


@router.reasoner()
async def run_iam_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_iam_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )


@router.reasoner()
async def run_network_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_network_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )


@router.reasoner()
async def run_data_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_data_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )


@router.reasoner()
async def run_secrets_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_secrets_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )


@router.reasoner()
async def run_compute_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_compute_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )


@router.reasoner()
async def run_logging_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_logging_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )


@router.reasoner()
async def run_compliance_hunter(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str,
) -> dict[str, Any]:
    return await _run_hunter(
        _run_compliance_hunter,
        repo_path=repo_path,
        resource_graph_path=resource_graph_path,
        inventory_path=inventory_path,
        depth=depth,
    )
