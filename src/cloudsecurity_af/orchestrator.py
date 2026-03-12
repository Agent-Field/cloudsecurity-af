from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from agentfield import Agent  # noqa: TC001
from pydantic import BaseModel

from .config import BudgetConfig, DepthProfile, ScanConfig
from .schemas.chain import AttackPath, ChainResult
from .schemas.hunt import HuntResult, RawFinding
from .schemas.input import CloudSecurityInput  # noqa: TC001
from .schemas.output import CloudSecurityScanResult, ScanProgress
from .schemas.prove import ProofMethod, Verdict, VerifiedFinding
from .schemas.recon import ReconResult
from .scoring import Severity, compute_risk_score, EvidenceMethod, Exposure, apply_benchmark_severity_floor

# ProofMethod (LLM output) → EvidenceMethod (scoring input) mapping.
# The two enums use different value strings, so direct casting fails.
_PROOF_TO_EVIDENCE: dict[ProofMethod, EvidenceMethod] = {
    ProofMethod.STATIC_ANALYSIS: EvidenceMethod.STATIC_CONFIG_MATCH,
    ProofMethod.LIVE_API_VERIFICATION: EvidenceMethod.LIVE_VERIFIED,
    ProofMethod.IAM_SIMULATION: EvidenceMethod.IAM_SIMULATED,
    ProofMethod.DRIFT_COMPARISON: EvidenceMethod.DRIFT_CONFIRMED,
}

SchemaT = TypeVar("SchemaT", bound=BaseModel)


class BudgetExhausted(RuntimeError):
    pass


class _PhaseHarnessProxy:
    def __init__(self, orchestrator: ScanOrchestrator, phase: str):
        self._orchestrator = orchestrator
        self._phase = phase

    async def harness(self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object) -> object:
        if self._orchestrator._budget_or_timeout_exhausted(self._phase):
            raise BudgetExhausted(f"{self._phase} budget exhausted")
        result = await self._orchestrator.app.harness(prompt, schema=schema, cwd=cwd, **kwargs)
        self._orchestrator.agent_invocations += 1
        self._orchestrator._register_cost(self._phase, getattr(result, "cost_usd", None))
        return result


class ScanOrchestrator:
    _PHASE_ORDER: tuple[str, ...] = ("recon", "hunt", "chain", "prove", "remediate")

    def __init__(self, app: Agent, input: CloudSecurityInput):
        self.app = cast("Any", app)
        self.input = input
        self.started_at = time.monotonic()
        self.repo_path = Path(os.getenv("CLOUDSECURITY_REPO_PATH", os.getcwd())).resolve()
        self.checkpoint_dir = self.repo_path / ".cloudsecurity"
        self.config = ScanConfig.from_input(self.input, str(self.repo_path))
        self.budget_config = self.config.budget
        self.max_cost_usd = input.max_cost_usd
        self.max_duration_seconds = input.max_duration_seconds
        self.total_cost_usd = 0.0
        self.cost_breakdown: dict[str, float] = {phase: 0.0 for phase in self._PHASE_ORDER}
        self.agent_invocations = 0
        self.budget_exhausted = False
        self.findings_not_verified = 0

    async def run(self) -> CloudSecurityScanResult:
        node_id = os.getenv("NODE_ID", "cloudsecurity")

        recon_raw = await self.app.call(
            f"{node_id}.recon_phase",
            repo_path=str(self.repo_path),
            depth=self.config.depth.value,
            tier=self.config.tier,
            cloud_config=self.input.cloud.model_dump() if self.input.cloud else None,
        )
        recon = ReconResult.model_validate(_as_dict(_unwrap(recon_raw, "recon_phase"), "recon_phase"))
        recon.recon_duration_seconds = time.monotonic() - self.started_at
        self._write_checkpoint("recon", recon)
        self._emit_progress(phase="recon", agents_total=1, agents_completed=1, findings_so_far=0)

        hunt_raw = await self.app.call(
            f"{node_id}.hunt_phase",
            repo_path=str(self.repo_path),
            resource_graph_path=recon.resource_graph.graph_saved_path,
            inventory_path=recon.inventory.inventory_saved_path,
            depth=self.config.depth.value,
            max_concurrent_hunters=self.budget_config.max_concurrent_hunters,
        )
        hunt = HuntResult.model_validate(_as_dict(_unwrap(hunt_raw, "hunt_phase"), "hunt_phase"))
        hunt.hunt_duration_seconds = time.monotonic() - self.started_at - recon.recon_duration_seconds
        self._write_checkpoint("hunt", hunt)
        self._emit_progress(phase="hunt", agents_total=1, agents_completed=1, findings_so_far=len(hunt.findings))

        chain_raw = await self.app.call(
            f"{node_id}.chain_phase",
            findings=[f.model_dump() for f in hunt.findings],
            resource_graph_path=recon.resource_graph.graph_saved_path,
            drift_report=recon.drift_report.model_dump() if recon.drift_report else None,
            depth=self.config.depth.value,
            max_children=self.budget_config.max_concurrent_chain_children,
        )
        chain = ChainResult.model_validate(_as_dict(_unwrap(chain_raw, "chain_phase"), "chain_phase"))
        self._write_checkpoint("chain", chain)

        prove_raw = await self.app.call(
            f"{node_id}.prove_phase",
            repo_path=str(self.repo_path),
            hunt_result=hunt.model_dump(),
            chain_result=chain.model_dump(),
            depth=self.config.depth.value,
            tier=self.config.tier,
            max_concurrent_provers=self.budget_config.max_concurrent_provers,
        )
        prove_dict = _as_dict(_unwrap(prove_raw, "prove_phase"), "prove_phase")
        verified = [VerifiedFinding.model_validate(v) for v in prove_dict["verified"]]
        self.findings_not_verified = prove_dict.get("not_verified", 0)
        self._write_checkpoint("prove", verified)

        remediation_raw = await self.app.call(
            f"{node_id}.remediation_phase",
            repo_path=str(self.repo_path),
            verified_findings=[v.model_dump() for v in verified],
        )
        remediation_dict = _as_dict(_unwrap(remediation_raw, "remediation_phase"), "remediation_phase")
        verified = [VerifiedFinding.model_validate(v) for v in remediation_dict["verified"]]

        self.agent_invocations = prove_dict.get("total_selected", 0) + len(hunt.strategies_run) + 5
        result = self._generate_output(recon=recon, hunt=hunt, chain=chain, verified=verified)
        return result

    def _generate_output(
        self,
        *,
        recon: ReconResult,
        hunt: HuntResult,
        chain: ChainResult,
        verified: list[VerifiedFinding],
    ) -> CloudSecurityScanResult:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold_value = severity_order.get(self.input.severity_threshold.lower(), 0)
        if threshold_value > 0:
            verified = [f for f in verified if severity_order.get(f.severity.value.lower(), 0) >= threshold_value]

        for finding in verified:
            finding.severity = apply_benchmark_severity_floor(
                finding.compliance_mappings[0] if finding.compliance_mappings else None,
                finding.severity,
            )
            finding.risk_score = compute_risk_score(
                severity=finding.severity,
                evidence_method=_PROOF_TO_EVIDENCE.get(finding.proof.method, EvidenceMethod.HEURISTIC_MATCH),
                exposure=Exposure.VPC_INTERNAL,
                has_attack_path=finding.attack_path is not None,
                has_drift=finding.drift is not None,
            )
            finding.sarif_security_severity = finding.risk_score

        verdict_counts: dict[Verdict, int] = {v: 0 for v in Verdict}
        severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in verified:
            verdict_counts[finding.verdict] += 1
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        total_raw = hunt.total_raw
        not_exploitable = verdict_counts[Verdict.NOT_EXPLOITABLE]
        noise_reduction = (not_exploitable / total_raw * 100.0) if total_raw > 0 else 0.0

        drift_resources = 0
        shadow_it = 0
        if recon.drift_report:
            drift_resources = len(recon.drift_report.drifted_resources)
            shadow_it = len(recon.drift_report.cloud_only_resources)

        from .output.sarif import generate_sarif

        result = CloudSecurityScanResult(
            repository=self.input.repo_url,
            commit_sha=self.input.commit_sha or "HEAD",
            branch=self.input.branch,
            timestamp=datetime.now(UTC),
            depth_profile=self.input.depth,
            tier=self.config.tier,
            providers_detected=recon.providers_detected,
            findings=verified,
            attack_paths=chain.attack_paths,
            total_resources_scanned=recon.total_resources,
            total_raw_findings=total_raw,
            confirmed=verdict_counts[Verdict.CONFIRMED],
            likely=verdict_counts[Verdict.LIKELY],
            inconclusive=verdict_counts[Verdict.INCONCLUSIVE],
            not_exploitable=not_exploitable,
            noise_reduction_pct=round(noise_reduction, 2),
            by_severity=severity_counts,
            drift_resources=drift_resources,
            shadow_it_resources=shadow_it,
            compliance_frameworks_checked=self.input.compliance_frameworks,
            strategies_used=hunt.strategies_run,
            duration_seconds=time.monotonic() - self.started_at,
            agent_invocations=self.agent_invocations,
            cost_usd=round(self.total_cost_usd, 4),
            cost_breakdown={phase: round(cost, 4) for phase, cost in self.cost_breakdown.items()},
            metadata={"findings_not_verified": self.findings_not_verified},
            sarif="",
        )
        result.sarif = generate_sarif(result)
        return result

    def _write_checkpoint(self, phase: str, payload: BaseModel | list[VerifiedFinding]) -> None:
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        path = self.checkpoint_dir / f"checkpoint-{phase}.json"
        data: Any = [item.model_dump() for item in payload] if isinstance(payload, list) else payload.model_dump()
        body = {
            "phase": phase,
            "created_at": datetime.now(UTC).isoformat(),
            "data": data,
        }
        path.write_text(json.dumps(body, indent=2), encoding="utf-8")

    def _read_checkpoint(self, phase: str, schema: type[SchemaT]) -> SchemaT:
        path = self.checkpoint_dir / f"checkpoint-{phase}.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        return schema(**payload.get("data", {}))

    def _budget_or_timeout_exhausted(self, phase: str) -> bool:
        if self.max_duration_seconds is not None:
            elapsed = time.monotonic() - self.started_at
            if elapsed > self.max_duration_seconds:
                self.budget_exhausted = True
                return True
        if self.max_cost_usd is not None and self.total_cost_usd >= self.max_cost_usd:
            self.budget_exhausted = True
            return True
        phase_limit = self._phase_budget_limit(phase)
        if phase_limit is not None and self.cost_breakdown.get(phase, 0.0) >= phase_limit:
            self.budget_exhausted = True
            return True
        return False

    def _phase_budget_limit(self, phase: str) -> float | None:
        if self.max_cost_usd is None:
            return None
        weights = {
            "recon": self.budget_config.recon_budget_pct,
            "hunt": self.budget_config.hunt_budget_pct,
            "chain": self.budget_config.chain_budget_pct,
            "prove": self.budget_config.prove_budget_pct,
            "remediate": self.budget_config.remediate_budget_pct,
        }
        return self.max_cost_usd * weights.get(phase, 0.1)

    def _register_cost(self, phase: str, cost_usd: float | None) -> None:
        if cost_usd is None or cost_usd < 0:
            return
        self.total_cost_usd += cost_usd
        self.cost_breakdown[phase] = self.cost_breakdown.get(phase, 0.0) + cost_usd

    def _emit_progress(self, *, phase: str, agents_total: int, agents_completed: int, findings_so_far: int) -> None:
        elapsed = time.monotonic() - self.started_at
        safe_total = max(1, agents_total)
        phase_progress = min(1.0, agents_completed / safe_total)
        estimated_total = elapsed / phase_progress if phase_progress > 0 else elapsed
        progress = ScanProgress(
            phase=phase,
            phase_progress=phase_progress,
            agents_total=agents_total,
            agents_completed=agents_completed,
            agents_running=max(0, agents_total - agents_completed),
            findings_so_far=findings_so_far,
            elapsed_seconds=elapsed,
            estimated_remaining_seconds=max(0.0, estimated_total - elapsed),
            cost_so_far_usd=round(self.total_cost_usd, 4),
        )


def _unwrap(result: object, name: str) -> object:
    if isinstance(result, dict):
        if "error" in result and isinstance(result["error"], dict):
            message = result["error"].get("message") or result["error"].get("detail") or str(result["error"])
            raise RuntimeError(f"{name} failed: {message}")
        if "error_message" in result and result["error_message"]:
            raise RuntimeError(f"{name} failed: {result['error_message']}")
        if result.get("status") in ("failed", "error"):
            raise RuntimeError(f"{name} failed: {result.get('error_message', 'Unknown error')}")
        if "output" in result:
            return result["output"]
        if "result" in result:
            return result["result"]
    return result


def _as_dict(payload: object, name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"{name} returned non-dict payload: {type(payload).__name__}")
    return payload
