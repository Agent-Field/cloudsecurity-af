"""JSON output formatter for CloudSecurity AF."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ..schemas.output import CloudSecurityScanResult


def generate_json(result: CloudSecurityScanResult, pretty: bool = True) -> str:
    """Full JSON serialization of the scan result."""
    full_json = result.model_dump_json()
    if not pretty:
        return full_json
    return json.dumps(json.loads(full_json), indent=2)


def generate_summary_json(result: CloudSecurityScanResult) -> str:
    """Compact summary JSON with statistics and top-level findings."""
    summary: dict[str, object] = {
        "repository": result.repository,
        "commit_sha": result.commit_sha,
        "timestamp": result.timestamp.isoformat(),
        "depth_profile": result.depth_profile,
        "tier": result.tier,
        "providers_detected": result.providers_detected,
        "summary": {
            "total_resources_scanned": result.total_resources_scanned,
            "total_findings": len(result.findings),
            "confirmed": result.confirmed,
            "likely": result.likely,
            "inconclusive": result.inconclusive,
            "not_exploitable": result.not_exploitable,
            "noise_reduction_pct": result.noise_reduction_pct,
            "by_severity": result.by_severity,
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "verdict": f.verdict.value,
                "risk_score": f.risk_score,
                "category": f.category,
                "iac_file": f.iac_file,
                "iac_line": f.iac_line,
                "hunter_strategy": f.hunter_strategy,
                "has_attack_path": f.attack_path is not None,
                "has_drift": f.drift is not None,
            }
            for f in result.findings
        ],
        "attack_paths": [
            {
                "id": path.id,
                "title": path.title,
                "entry_point": path.entry_point,
                "target": path.target,
                "combined_severity": path.combined_severity.value,
                "steps_count": len(path.steps),
                "findings_involved": path.findings_involved,
            }
            for path in result.attack_paths
        ],
        "drift": {
            "drifted_resources": result.drift_resources,
            "shadow_it_resources": result.shadow_it_resources,
        },
        "compliance_frameworks_checked": result.compliance_frameworks_checked,
        "performance": {
            "duration_seconds": result.duration_seconds,
            "cost_usd": result.cost_usd,
            "cost_breakdown": result.cost_breakdown,
            "agent_invocations": result.agent_invocations,
        },
    }
    return json.dumps(summary, indent=2)


def render_json(result: CloudSecurityScanResult) -> dict[str, object]:
    """Return parsed JSON dict (for API responses)."""
    return cast("dict[str, object]", json.loads(generate_json(result, pretty=True)))
