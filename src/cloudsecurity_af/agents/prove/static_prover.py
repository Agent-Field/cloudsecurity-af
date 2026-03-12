from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.schemas.chain import AttackPath
from cloudsecurity_af.schemas.hunt import RawFinding
from cloudsecurity_af.schemas.prove import VerifiedFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "static_prover.txt"


def _build_prompt(
    template: str,
    finding: RawFinding,
    attack_path: AttackPath | None,
    tier: int,
    repo_path: str,
) -> str:
    prompt = template
    replacements = {
        "{{TITLE}}": finding.title,
        "{{DESCRIPTION}}": finding.description,
        "{{CATEGORY}}": finding.category,
        "{{HUNTER_STRATEGY}}": finding.hunter_strategy,
        "{{IAC_FILE}}": finding.iac_file,
        "{{IAC_LINE}}": str(finding.iac_line),
        "{{CONFIG_SNIPPET}}": finding.config_snippet,
        "{{ESTIMATED_SEVERITY}}": finding.estimated_severity.value,
        "{{CONFIDENCE}}": finding.confidence.value,
        "{{FINDING_JSON}}": json.dumps(finding.model_dump(), indent=2),
        "{{ATTACK_PATH_JSON}}": json.dumps(attack_path.model_dump(), indent=2) if attack_path else "{}",
        "{{TIER}}": str(tier),
        "{{REPO_PATH}}": repo_path,
    }
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_static_prover(
    app: HarnessCapable,
    repo_path: str,
    finding: RawFinding,
    attack_path: AttackPath | None,
    tier: int,
) -> VerifiedFinding:
    template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(template, finding, attack_path, tier, repo_path)
    harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-static-prover-")
    try:
        result = await app.harness(
            prompt=prompt,
            schema=VerifiedFinding,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        return extract_harness_result(result, VerifiedFinding, "StaticProver")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
