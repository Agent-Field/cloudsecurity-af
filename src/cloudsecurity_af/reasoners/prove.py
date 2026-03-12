from __future__ import annotations

from typing import Any

from cloudsecurity_af.agents.prove.live_prover import run_live_prover as _run_live_prover
from cloudsecurity_af.agents.prove.static_prover import run_static_prover as _run_static_prover
from cloudsecurity_af.schemas.chain import AttackPath
from cloudsecurity_af.schemas.hunt import RawFinding

from . import router

_runtime_router: Any = router


@router.reasoner()
async def run_static_prover(
    repo_path: str,
    finding: dict[str, Any],
    tier: int,
    attack_path: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding_model = RawFinding.model_validate(finding)
    attack_path_model = AttackPath.model_validate(attack_path) if attack_path is not None else None
    result = await _run_static_prover(
        _runtime_router,
        repo_path,
        finding_model,
        attack_path_model,
        tier,
    )
    return result.model_dump()


@router.reasoner()
async def run_live_prover(
    repo_path: str,
    finding: dict[str, Any],
    tier: int,
    attack_path: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding_model = RawFinding.model_validate(finding)
    attack_path_model = AttackPath.model_validate(attack_path) if attack_path is not None else None
    result = await _run_live_prover(
        _runtime_router,
        repo_path,
        finding_model,
        attack_path_model,
        tier,
    )
    return result.model_dump()
