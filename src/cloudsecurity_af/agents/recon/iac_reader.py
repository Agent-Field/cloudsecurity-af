from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.agents.recon._terraform_parser import parse_terraform_directory
from cloudsecurity_af.schemas.recon import ResourceInventory

log = logging.getLogger(__name__)


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "iac_reader.txt"


async def run_iac_reader(app: HarnessCapable, repo_path: str) -> ResourceInventory:
    work_dir = tempfile.mkdtemp(prefix="cloudsecurity-recon-iac-reader-")
    try:
        return _fast_parse(repo_path, work_dir)
    except Exception as exc:
        log.warning("Deterministic parser failed (%s), falling back to harness", exc)
        return await _harness_fallback(app, repo_path, work_dir)


def _fast_parse(repo_path: str, work_dir: str) -> ResourceInventory:
    inv_path, total, iac_type = parse_terraform_directory(repo_path, work_dir)
    return ResourceInventory(
        inventory_saved_path=inv_path,
        total_resources=total,
        iac_type=iac_type,
    )


async def _harness_fallback(app: HarnessCapable, repo_path: str, work_dir: str) -> ResourceInventory:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = prompt_template.replace("{{REPO_PATH}}", repo_path)
    result = await app.harness(
        prompt=prompt,
        schema=ResourceInventory,
        cwd=work_dir,
        project_dir=repo_path,
    )
    return extract_harness_result(result, ResourceInventory, "IaC reader")
