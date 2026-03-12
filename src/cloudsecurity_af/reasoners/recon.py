from __future__ import annotations

from typing import Any, cast

from cloudsecurity_af.agents.recon.cloud_connector import run_cloud_connector as _run_cloud_connector
from cloudsecurity_af.agents.recon.drift_detector import run_drift_detector as _run_drift_detector
from cloudsecurity_af.agents.recon.iac_reader import run_iac_reader as _run_iac_reader
from cloudsecurity_af.agents.recon.resource_graph_builder import run_resource_graph_builder as _run_resource_graph_builder
from cloudsecurity_af.schemas.recon import ResourceGraph, ResourceInventory

from . import router


@router.reasoner()
async def run_iac_reader(repo_path: str) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    result = await _run_iac_reader(runtime_router, repo_path)
    return result.model_dump()


@router.reasoner()
async def run_resource_graph_builder(repo_path: str, inventory_path: str) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    result = await _run_resource_graph_builder(runtime_router, repo_path, inventory_path)
    return result.model_dump()


@router.reasoner()
async def run_cloud_connector(cloud_config: dict[str, Any]) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    result = await _run_cloud_connector(runtime_router, cloud_config)
    return result.model_dump()


@router.reasoner()
async def run_drift_detector(iac_graph_path: str, cloud_config: dict[str, Any]) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    result = await _run_drift_detector(runtime_router, iac_graph_path, cloud_config)
    return result.model_dump()
