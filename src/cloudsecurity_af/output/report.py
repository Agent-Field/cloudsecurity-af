"""Markdown report generator for CloudSecurity AF."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.chain import AttackPath
    from ..schemas.output import CloudSecurityScanResult
    from ..schemas.prove import VerifiedFinding


def generate_report(result: CloudSecurityScanResult) -> str:
    """Generate a Markdown report from a CloudSecurity scan result."""
    lines: list[str] = [
        "# CloudSecurity AF Infrastructure Security Report",
        "",
        *_render_summary(result),
        "## Findings",
        "",
    ]

    if result.findings:
        for finding in result.findings:
            lines.extend(_render_finding(finding))
    else:
        lines.extend(["No findings.", ""])

    lines.extend(["## Attack Paths", ""])
    if result.attack_paths:
        for path in result.attack_paths:
            lines.extend(_render_attack_path(path))
    else:
        lines.extend(["No multi-resource attack paths identified.", ""])

    if result.drift_resources > 0 or result.shadow_it_resources > 0:
        lines.extend(
            [
                "## Drift Summary",
                "",
                f"- Drifted resources: **{result.drift_resources}**",
                f"- Shadow IT (cloud-only) resources: **{result.shadow_it_resources}**",
                "",
            ]
        )

    if result.compliance_frameworks_checked:
        lines.extend(
            [
                "## Compliance",
                "",
                f"- Frameworks checked: {', '.join(result.compliance_frameworks_checked)}",
                "",
            ]
        )

    lines.extend(
        [
            "## Performance & Cost",
            "",
            f"- Duration: {result.duration_seconds:.1f}s",
            f"- Agent invocations: {result.agent_invocations}",
            f"- Cost: ${result.cost_usd:.4f}",
            "- Cost breakdown:",
        ]
    )
    if result.cost_breakdown:
        for phase, cost in result.cost_breakdown.items():
            lines.append(f"  - {phase}: ${cost:.4f}")
    else:
        lines.append("  - n/a")
    lines.append("")

    return "\n".join(lines)


def render_report(result: CloudSecurityScanResult) -> str:
    """Alias for ``generate_report``."""
    return generate_report(result)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_summary(result: CloudSecurityScanResult) -> list[str]:
    return [
        "## Summary",
        "",
        f"- Repository: `{result.repository}`",
        f"- Commit: `{result.commit_sha}`",
        f"- Branch: `{result.branch}`" if result.branch else "- Branch: n/a",
        f"- Timestamp: `{result.timestamp.isoformat()}`",
        f"- Depth profile: `{result.depth_profile}`",
        f"- Tier: **{result.tier}** ({'static' if result.tier == 1 else 'live' if result.tier == 2 else 'deep'})",
        f"- Providers: {', '.join(result.providers_detected) or 'none detected'}",
        f"- Resources scanned: **{result.total_resources_scanned}**",
        (
            f"- Findings: **{len(result.findings)}** (confirmed: {result.confirmed}, "
            f"likely: {result.likely}, inconclusive: {result.inconclusive}, "
            f"not exploitable: {result.not_exploitable})"
        ),
        f"- Noise reduction: **{result.noise_reduction_pct:.1f}%**",
        "",
    ]


def _render_finding(finding: VerifiedFinding) -> list[str]:
    lines = [
        f"### {finding.title}",
        "",
        f"- ID: `{finding.id}`",
        f"- Verdict: `{finding.verdict.value}` | Severity: `{finding.severity.value}`",
        f"- Risk score: **{finding.risk_score:.2f}/10**",
        f"- Category: `{finding.category}` | Hunter: `{finding.hunter_strategy}`",
        f"- Location: `{finding.iac_file}:{finding.iac_line}`",
    ]
    if finding.description:
        lines.append(f"- Description: {finding.description}")
    if finding.attack_path:
        lines.append(f"- Attack path: **{finding.attack_path.title}**")
    if finding.drift:
        lines.append(f"- Drift detected: `{finding.drift.resource_id}` ({finding.drift.significance})")
    if finding.compliance_mappings:
        lines.append(f"- Compliance: {', '.join(finding.compliance_mappings)}")
    if finding.remediation:
        lines.append(f"- Remediation: {finding.remediation.description}")
        if finding.remediation.breaking_change:
            lines.append("  - **WARNING: Breaking change**")
        if finding.remediation.downtime_estimate:
            lines.append(f"  - Downtime: {finding.remediation.downtime_estimate}")
    if finding.config_snippet:
        lines.extend(["", "```hcl", finding.config_snippet, "```"])
    lines.append("")
    return lines


def _render_attack_path(path: AttackPath) -> list[str]:
    lines = [
        f"### {path.title}",
        "",
        f"- ID: `{path.id}`",
        f"- Combined severity: `{path.combined_severity.value}`",
        f"- Entry: `{path.entry_point}` → Target: `{path.target}`",
        f"- Findings involved: {', '.join(f'`{fid}`' for fid in path.findings_involved)}",
        "- Steps:",
    ]
    for step in path.steps:
        lines.append(
            f"  {step.step_number}. `{step.resource_id}` ({step.resource_type}) — "
            f"{step.action} via `{step.permission_used}`"
        )
    if path.blast_radius.data_stores_reachable:
        lines.append(f"- Blast radius — data stores: {', '.join(path.blast_radius.data_stores_reachable)}")
    if path.blast_radius.compute_reachable:
        lines.append(f"- Blast radius — compute: {', '.join(path.blast_radius.compute_reachable)}")
    lines.append("")
    return lines
