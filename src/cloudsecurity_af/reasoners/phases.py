from __future__ import annotations

import asyncio
import os
from typing import Any, cast

from cloudsecurity_af.config import DEPTH_CHAIN_LIMITS, DEPTH_HUNTER_MAP, DEPTH_PROVER_CAPS, DepthProfile
from cloudsecurity_af.schemas.chain import ChainResult
from cloudsecurity_af.schemas.hunt import HuntResult, RawFinding
from cloudsecurity_af.schemas.prove import RemediationSuggestion, Verdict, VerifiedFinding
from cloudsecurity_af.schemas.recon import (
    DriftReport,
    ReconResult,
    ResourceGraph,
    ResourceInventory,
)
from cloudsecurity_af.scoring import Severity

from . import router

_runtime_router: Any = router
NODE_ID = os.getenv("NODE_ID", "cloudsecurity")


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


def _normalize_depth(depth: str) -> DepthProfile:
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


# ---------------------------------------------------------------------------
# RECON PHASE
# ---------------------------------------------------------------------------


@router.reasoner()
async def recon_phase(
    repo_path: str,
    depth: str = "standard",
    tier: int = 1,
    cloud_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    iac_raw = await _runtime_router.call(
        f"{NODE_ID}.run_iac_reader",
        repo_path=repo_path,
    )
    inventory = ResourceInventory.model_validate(_as_dict(_unwrap(iac_raw, "run_iac_reader"), "run_iac_reader"))

    graph_raw = await _runtime_router.call(
        f"{NODE_ID}.run_resource_graph_builder",
        repo_path=repo_path,
        inventory_path=inventory.inventory_saved_path,
    )
    resource_graph = ResourceGraph.model_validate(
        _as_dict(_unwrap(graph_raw, "run_resource_graph_builder"), "run_resource_graph_builder")
    )

    drift_report = None
    live_inventory = None

    if tier >= 2 and cloud_config is not None:
        live_raw, drift_raw = await asyncio.gather(
            _runtime_router.call(
                f"{NODE_ID}.run_cloud_connector",
                cloud_config=cloud_config,
            ),
            _runtime_router.call(
                f"{NODE_ID}.run_drift_detector",
                iac_graph_path=resource_graph.graph_saved_path,
                cloud_config=cloud_config,
            ),
        )
        live_inventory = ResourceInventory.model_validate(
            _as_dict(_unwrap(live_raw, "run_cloud_connector"), "run_cloud_connector")
        )
        drift_report = DriftReport.model_validate(
            _as_dict(_unwrap(drift_raw, "run_drift_detector"), "run_drift_detector")
        )

    import json

    try:
        with open(inventory.inventory_saved_path, "r") as f:
            inv_data = json.load(f)
            if not isinstance(inv_data, dict):
                inv_data = {"resources": []}
            raw_res = inv_data.get("resources", [])
            if not isinstance(raw_res, list):
                raw_res = []
            providers = sorted({r.get("provider") for r in raw_res if isinstance(r, dict) and r.get("provider")})
    except Exception:
        providers = []

    recon = ReconResult(
        inventory=inventory,
        resource_graph=resource_graph,
        drift_report=drift_report,
        live_inventory=live_inventory,
        iac_type=inventory.iac_type,
        providers_detected=providers,
        total_resources=inventory.total_resources,
        total_edges=resource_graph.total_edges,
    )
    return recon.model_dump()


def _cross_hunter_dedup(findings: list[RawFinding]) -> list[RawFinding]:
    sev_rank = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
    seen: dict[str, RawFinding] = {}
    for f in findings:
        primary_resource = f.resources[0].resource_id if f.resources else f.iac_file
        dedup_key = f"{primary_resource}::{f.category}"
        if dedup_key in seen:
            existing = seen[dedup_key]
            if sev_rank.get(f.estimated_severity, 0) > sev_rank.get(existing.estimated_severity, 0):
                seen[dedup_key] = f
        else:
            seen[dedup_key] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# HUNT PHASE
# ---------------------------------------------------------------------------


@router.reasoner()
async def hunt_phase(
    repo_path: str,
    resource_graph_path: str,
    inventory_path: str,
    depth: str = "standard",
    max_concurrent_hunters: int = 3,
) -> dict[str, Any]:
    profile = _normalize_depth(depth)
    active_hunters = DEPTH_HUNTER_MAP.get(profile, DEPTH_HUNTER_MAP[DepthProfile.STANDARD])

    concurrency_limit = max(1, min(max_concurrent_hunters, len(active_hunters)))
    findings_queue: asyncio.Queue[list[RawFinding]] = asyncio.Queue()
    semaphore = asyncio.Semaphore(concurrency_limit)

    async def _run_and_enqueue(hunter_name: str) -> None:
        async with semaphore:
            operation_name = f"run_{hunter_name}_hunter"
            try:
                raw = await _runtime_router.call(
                    f"{NODE_ID}.{operation_name}",
                    repo_path=repo_path,
                    resource_graph_path=resource_graph_path,
                    inventory_path=inventory_path,
                    depth=depth,
                )
                payload = HuntResult.model_validate(_as_dict(_unwrap(raw, operation_name), operation_name))
                await findings_queue.put(payload.findings)
            except Exception as exc:
                await findings_queue.put([])

    async def _incremental_dedup() -> tuple[list[RawFinding], int]:
        all_findings: list[RawFinding] = []
        seen_fingerprints: set[str] = set()
        completed = 0
        total_raw = 0

        while completed < len(active_hunters):
            batch = await findings_queue.get()
            completed += 1
            total_raw += len(batch)

            for finding in batch:
                fp = finding.fingerprint
                if not fp:
                    fp = f"{finding.iac_file}:{finding.iac_line}:{finding.category}"
                    finding.fingerprint = fp
                if fp in seen_fingerprints:
                    continue
                seen_fingerprints.add(fp)
                all_findings.append(finding)

        return _cross_hunter_dedup(all_findings), total_raw

    producers = [asyncio.create_task(_run_and_enqueue(h)) for h in active_hunters]
    consumer = asyncio.create_task(_incremental_dedup())

    await asyncio.gather(*producers)
    deduped, total_raw = await consumer

    hunt = HuntResult(
        findings=deduped,
        total_raw=total_raw,
        deduplicated_count=len(deduped),
        strategies_run=active_hunters,
        hunt_duration_seconds=0.0,
    )
    return hunt.model_dump()


# ---------------------------------------------------------------------------
# CHAIN PHASE
# ---------------------------------------------------------------------------


@router.reasoner()
async def chain_phase(
    findings: list[dict[str, Any]],
    resource_graph_path: str,
    drift_report: dict[str, Any] | None = None,
    depth: str = "standard",
    max_children: int = 3,
) -> dict[str, Any]:
    profile = _normalize_depth(depth)
    max_paths = DEPTH_CHAIN_LIMITS.get(profile, 15)

    raw = await _runtime_router.call(
        f"{NODE_ID}.run_path_constructor",
        findings=findings,
        resource_graph_path=resource_graph_path,
        max_paths=max_paths,
        max_children=max_children,
        drift_report=drift_report,
    )
    chain = ChainResult.model_validate(_as_dict(_unwrap(raw, "run_path_constructor"), "run_path_constructor"))
    return chain.model_dump()


# ---------------------------------------------------------------------------
# PROVE PHASE
# ---------------------------------------------------------------------------


def _prioritize_findings(findings: list[RawFinding]) -> list[RawFinding]:
    sev = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
    return sorted(findings, key=lambda f: sev.get(f.estimated_severity, 0), reverse=True)


@router.reasoner()
async def prove_phase(
    repo_path: str,
    hunt_result: dict[str, Any],
    chain_result: dict[str, Any],
    depth: str = "standard",
    tier: int = 1,
    max_concurrent_provers: int = 3,
) -> dict[str, Any]:
    hunt = HuntResult.model_validate(hunt_result)
    chain = ChainResult.model_validate(chain_result)

    profile = _normalize_depth(depth)
    cap = DEPTH_PROVER_CAPS.get(profile, 30)

    prioritized = _prioritize_findings(hunt.findings)
    selected = prioritized[:cap]

    concurrency_limit = max(1, min(max_concurrent_provers, len(selected))) if selected else 1
    semaphore = asyncio.Semaphore(concurrency_limit)

    attack_path_map: dict[str, Any] = {}
    for path in chain.attack_paths:
        for fid in path.findings_involved:
            attack_path_map[fid] = path.model_dump()

    async def _run_prover(finding: RawFinding) -> object:
        async with semaphore:
            prover_name = "run_static_prover" if tier < 2 else "run_live_prover"
            kwargs: dict[str, Any] = {
                "repo_path": repo_path,
                "finding": finding.model_dump(),
                "tier": tier,
            }
            ap = attack_path_map.get(finding.id)
            if ap is not None:
                kwargs["attack_path"] = ap
            return await _runtime_router.call(
                f"{NODE_ID}.{prover_name}",
                **kwargs,
            )

    prove_results = await asyncio.gather(
        *[_run_prover(f) for f in selected],
        return_exceptions=True,
    )

    verified: list[VerifiedFinding] = []
    for idx, raw in enumerate(prove_results):
        finding = selected[idx]
        if isinstance(raw, Exception):
            verified.append(_fallback_verified(finding, str(raw)))
            continue
        try:
            payload = _as_dict(_unwrap(raw, "prover"), "prover")
            verified.append(VerifiedFinding.model_validate(payload))
        except Exception as exc:
            verified.append(_fallback_verified(finding, f"Schema parse failed: {exc}"))

    return {
        "verified": [v.model_dump(exclude_none=True) for v in verified],
        "total_selected": len(selected),
        "total_findings": len(hunt.findings),
        "not_verified": max(0, len(hunt.findings) - len(selected)),
    }


def _fallback_verified(finding: RawFinding, error_msg: str) -> VerifiedFinding:
    from cloudsecurity_af.schemas.prove import Proof, ProofMethod

    return VerifiedFinding(
        id=finding.id,
        title=finding.title,
        verdict=Verdict.INCONCLUSIVE,
        severity=finding.estimated_severity,
        category=finding.category,
        resources=finding.resources,
        proof=Proof(method=ProofMethod.STATIC_ANALYSIS, evidence=[error_msg]),
        iac_file=finding.iac_file,
        iac_line=finding.iac_line,
        config_snippet=finding.config_snippet,
        description=finding.description,
        fingerprint=finding.fingerprint,
        hunter_strategy=finding.hunter_strategy,
        sarif_rule_id=f"cloudsecurity/{finding.hunter_strategy}/{finding.category}",
        sarif_security_severity=0.0,
        drop_reason="prover_error",
    )


# ---------------------------------------------------------------------------
# REMEDIATION PHASE
# ---------------------------------------------------------------------------


@router.reasoner()
async def remediation_phase(
    repo_path: str,
    verified_findings: list[dict[str, Any]],
    max_concurrent_remediations: int = 3,
) -> dict[str, Any]:
    findings = [VerifiedFinding.model_validate(v) for v in verified_findings]
    needs_remediation = [
        (idx, f)
        for idx, f in enumerate(findings)
        if f.verdict in {Verdict.CONFIRMED, Verdict.LIKELY} and f.remediation is None
    ]

    if not needs_remediation:
        return {"verified": [f.model_dump(exclude_none=True) for f in findings]}

    semaphore = asyncio.Semaphore(max(1, min(max_concurrent_remediations, len(needs_remediation))))

    async def _call_remediation(idx: int, finding: VerifiedFinding) -> tuple[int, dict[str, Any] | None]:
        async with semaphore:
            try:
                raw = await _runtime_router.call(
                    f"{NODE_ID}.run_fix_generator",
                    repo_path=repo_path,
                    finding=finding.model_dump(),
                )
                payload = _as_dict(_unwrap(raw, "run_fix_generator"), "run_fix_generator")
                return (idx, payload)
            except Exception:
                return (idx, None)

    results = await asyncio.gather(*[_call_remediation(idx, f) for idx, f in needs_remediation])

    generated = 0
    for idx, payload in results:
        if payload is not None:
            try:
                findings[idx].remediation = RemediationSuggestion.model_validate(payload)
                generated += 1
            except Exception:
                pass

    return {"verified": [f.model_dump(exclude_none=True) for f in findings]}
