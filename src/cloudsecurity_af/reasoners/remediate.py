from __future__ import annotations

from typing import Any

from cloudsecurity_af.agents.remediate.fix_generator import run_fix_generator as _run_fix_generator
from cloudsecurity_af.schemas.prove import VerifiedFinding

from . import router

_runtime_router: Any = router


@router.reasoner()
async def run_fix_generator(repo_path: str, finding: dict[str, Any]) -> dict[str, Any]:
    finding_model = VerifiedFinding.model_validate(finding)
    result = await _run_fix_generator(_runtime_router, repo_path, finding_model)
    return result.model_dump()
