from __future__ import annotations

# pyright: reportMissingImports=false

import os
import subprocess
import time
from pathlib import Path
from typing import Any, cast

import agentfield as _agentfield
from dotenv import load_dotenv

_project_root = Path(__file__).resolve().parents[2]
load_dotenv(_project_root / ".env")

from fastapi import HTTPException

from agentfield import Agent, AIConfig

from .config import AIIntegrationConfig
from .orchestrator import ScanOrchestrator
from .reasoners import router as reasoner_router
from .schemas.chain import ChainResult
from .schemas.hunt import HuntResult
from .schemas.input import CloudSecurityInput
from .schemas.prove import VerifiedFinding
from .schemas.recon import ReconResult

_ai_config = AIIntegrationConfig.from_env()
NODE_ID = os.getenv("NODE_ID", "cloudsecurity")
HarnessConfig = getattr(_agentfield, "HarnessConfig")

app = Agent(
    node_id=NODE_ID,
    version="0.1.0",
    description="AI-Native Cloud Infrastructure Security Scanner",
    agentfield_server=os.getenv("AGENTFIELD_SERVER", "http://localhost:8080"),
    callback_url=os.getenv("AGENT_CALLBACK_URL", "http://host.docker.internal:8020"),
    api_key=os.getenv("AGENTFIELD_API_KEY"),
    harness_config=HarnessConfig(
        provider=_ai_config.provider,
        model=_ai_config.harness_model,
        max_turns=_ai_config.max_turns,
        env=_ai_config.provider_env(),
        opencode_bin=_ai_config.opencode_bin,
        permission_mode="auto",
    ),
    ai_config=AIConfig(
        provider=_ai_config.provider,
        model=_ai_config.ai_model,
    ),
)


def _unwrap(result: object, name: str) -> object:
    if isinstance(result, dict):
        if "error" in result and isinstance(result["error"], dict):
            message = result["error"].get("message") or result["error"].get("detail") or str(result["error"])
            raise RuntimeError(f"{name} failed: {message}")
        if "output" in result:
            return result["output"]
        if "result" in result:
            return result["result"]
    return result


def _as_dict(payload: object, name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"{name} returned non-dict payload: {type(payload).__name__}")
    return payload


def _resolve_repo(repo_url: str) -> str:
    if os.path.isdir(repo_url):
        return str(Path(repo_url).resolve())

    if repo_url.startswith(("https://", "http://", "git@")):
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        target_dir = f"/workspaces/{repo_name}"
        os.makedirs("/workspaces", exist_ok=True)

        if os.path.isdir(target_dir):
            subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=target_dir,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"},
                timeout=60,
                capture_output=True,
            )
            return target_dir

        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir],
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"},
            timeout=120,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(f"git clone failed: {result.stderr.strip()}")
        return target_dir

    return str(Path(os.getenv("CLOUDSECURITY_REPO_PATH", os.getcwd())).resolve())


@app.reasoner()
async def scan(
    repo_url: str,
    depth: str = "standard",
    branch: str = "main",
    commit_sha: str | None = None,
    base_commit_sha: str | None = None,
    severity_threshold: str = "low",
    output_formats: list[str] | None = None,
    compliance_frameworks: list[str] | None = None,
    max_cost_usd: float | None = None,
    max_duration_seconds: int | None = None,
    max_concurrent_hunters: int | None = None,
    max_concurrent_provers: int | None = None,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    is_pr: bool = False,
    pr_id: str | None = None,
    fail_on_findings: bool = False,
) -> dict[str, object]:
    scan_input = CloudSecurityInput(
        repo_url=repo_url,
        depth=depth,
        branch=branch,
        commit_sha=commit_sha,
        base_commit_sha=base_commit_sha,
        severity_threshold=severity_threshold,
        output_formats=output_formats or ["json"],
        compliance_frameworks=compliance_frameworks or [],
        cloud=None,
        max_cost_usd=max_cost_usd,
        max_duration_seconds=max_duration_seconds,
        max_concurrent_hunters=max_concurrent_hunters,
        max_concurrent_provers=max_concurrent_provers,
        include_paths=include_paths,
        exclude_paths=exclude_paths or ["tests/", ".git/", "examples/", ".terraform/"],
        is_pr=is_pr,
        pr_id=pr_id,
        fail_on_findings=fail_on_findings,
    )
    return await _run_pipeline(scan_input)


@app.reasoner()
async def prove(
    repo_url: str,
    cloud_provider: str = "aws",
    cloud_regions: list[str] | None = None,
    assume_role_arn: str | None = None,
    depth: str = "standard",
    branch: str = "main",
    commit_sha: str | None = None,
    severity_threshold: str = "low",
    output_formats: list[str] | None = None,
    compliance_frameworks: list[str] | None = None,
    max_cost_usd: float | None = None,
    max_duration_seconds: int | None = None,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    is_pr: bool = False,
    fail_on_findings: bool = False,
) -> dict[str, object]:
    from .schemas.input import CloudConfig

    scan_input = CloudSecurityInput(
        repo_url=repo_url,
        depth=depth,
        branch=branch,
        commit_sha=commit_sha,
        severity_threshold=severity_threshold,
        output_formats=output_formats or ["json"],
        compliance_frameworks=compliance_frameworks or [],
        cloud=CloudConfig(
            provider=cloud_provider,
            regions=cloud_regions or ["us-east-1"],
            assume_role_arn=assume_role_arn,
        ),
        max_cost_usd=max_cost_usd,
        max_duration_seconds=max_duration_seconds,
        include_paths=include_paths,
        exclude_paths=exclude_paths or ["tests/", ".git/", "examples/", ".terraform/"],
        is_pr=is_pr,
        fail_on_findings=fail_on_findings,
    )
    return await _run_pipeline(scan_input)


async def _run_pipeline(scan_input: CloudSecurityInput) -> dict[str, object]:
    orchestrator = ScanOrchestrator(app=app, input=scan_input)
    repo_path = _resolve_repo(scan_input.repo_url)
    orchestrator.repo_path = Path(repo_path)
    orchestrator.checkpoint_dir = orchestrator.repo_path / ".cloudsecurity"

    try:
        result = await orchestrator.run()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
    except Exception as exc:
        import traceback

        tb = traceback.format_exc()
        print(f"SCAN ERROR: {exc}\n{tb}", flush=True)
        raise HTTPException(status_code=500, detail={"error": f"scan execution failed: {exc}"}) from exc

    return result.model_dump()


async def health() -> dict[str, str]:
    return {"status": "healthy", "version": "0.1.0"}


cast("Any", app).add_api_route("/health", health, methods=["GET"])

app.include_router(reasoner_router)


def main() -> None:
    port = int(os.getenv("PORT", "8005"))
    app.run(port=port, host="0.0.0.0")


if __name__ == "__main__":
    main()
