"""Cloud connector harness for RECON."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Protocol

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.schemas.recon import ResourceInventory


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "cloud_connector.txt"


async def run_cloud_connector(app: HarnessCapable, cloud_config: dict[str, Any]) -> ResourceInventory:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = prompt_template.replace("{{CLOUD_CONFIG_JSON}}", json.dumps(cloud_config, indent=2))
    agent_name = "recon-cloud-connector"
    harness_cwd = tempfile.mkdtemp(prefix=f"cloudsecurity-{agent_name}-")
    repo_path = harness_cwd
    try:
        result = await app.harness(
            prompt=prompt,
            schema=ResourceInventory,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        return extract_harness_result(result, ResourceInventory, "Cloud connector")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
