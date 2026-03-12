from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.schemas.prove import RemediationSuggestion, VerifiedFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "remediate" / "fix_generator.txt"


def _build_prompt(template: str, finding: VerifiedFinding, repo_path: str) -> str:
    prompt = template
    replacements = {
        "{{TITLE}}": finding.title,
        "{{DESCRIPTION}}": finding.description,
        "{{VERDICT}}": finding.verdict.value,
        "{{SEVERITY}}": finding.severity.value,
        "{{CATEGORY}}": finding.category,
        "{{IAC_FILE}}": finding.iac_file,
        "{{IAC_LINE}}": str(finding.iac_line),
        "{{CONFIG_SNIPPET}}": finding.config_snippet,
        "{{SARIF_RULE_ID}}": finding.sarif_rule_id,
        "{{RISK_SCORE}}": str(finding.risk_score),
        "{{FINDING_JSON}}": json.dumps(finding.model_dump(mode="json"), indent=2),
        "{{REPO_PATH}}": repo_path,
    }
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_fix_generator(
    app: HarnessCapable,
    repo_path: str,
    finding: VerifiedFinding,
) -> RemediationSuggestion:
    template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(template, finding, repo_path)
    harness_cwd = tempfile.mkdtemp(prefix="cloudsecurity-fix-generator-")
    try:
        result = await app.harness(
            prompt=prompt,
            schema=RemediationSuggestion,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        return extract_harness_result(result, RemediationSuggestion, "FixGenerator")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
