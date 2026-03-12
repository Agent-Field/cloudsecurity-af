"""SARIF 2.1.0 output generator for CloudSecurity AF.

Produces SARIF compliant with GitHub Code Scanning for the Security tab.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from .. import __version__

if TYPE_CHECKING:
    from ..schemas.output import CloudSecurityScanResult
    from ..schemas.prove import VerifiedFinding


_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_LEVEL_RANK: dict[str, int] = {"error": 3, "warning": 2, "note": 1}

_VERDICT_TO_PRECISION: dict[str, str] = {
    "confirmed": "very-high",
    "likely": "high",
    "inconclusive": "medium",
    "not_exploitable": "low",
}

_PRECISION_RANK: dict[str, int] = {"very-high": 4, "high": 3, "medium": 2, "low": 1}


def generate_sarif(result: CloudSecurityScanResult) -> str:
    """Generate SARIF 2.1.0 JSON string from a CloudSecurity scan result.

    Filters out ``not_exploitable`` findings (noise reduction).
    """
    included = [f for f in result.findings if f.verdict.value != "not_exploitable"]

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": _build_tool_section(included),
                "results": [_build_result(f) for f in included],
                "automationDetails": {
                    "id": f"cloudsecurity-af/scan/{result.repository}/{result.timestamp.isoformat()}",
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_sarif(result: CloudSecurityScanResult) -> str:
    """Alias for ``generate_sarif``."""
    return generate_sarif(result)


# ---------------------------------------------------------------------------
# Tool / Rules
# ---------------------------------------------------------------------------


def _build_tool_section(findings: list[VerifiedFinding]) -> dict[str, object]:
    rules_by_id: dict[str, list[VerifiedFinding]] = {}
    for finding in findings:
        rule_id = finding.sarif_rule_id or f"cloudsecurity/{finding.hunter_strategy}/{finding.category}"
        rules_by_id.setdefault(rule_id, []).append(finding)

    rules = [_build_rule(rule_id, rule_findings) for rule_id, rule_findings in sorted(rules_by_id.items())]
    return {
        "driver": {
            "name": "CloudSecurity AF",
            "semanticVersion": __version__,
            "informationUri": "https://github.com/Agent-Field/cloudsecurity-af",
            "rules": rules,
        }
    }


def _build_rule(rule_id: str, findings: list[VerifiedFinding]) -> dict[str, object]:
    representative = findings[0]
    level = _max_level(findings)
    security_severity = _format_security_severity(max(f.sarif_security_severity for f in findings))
    precision = _max_precision(findings)
    tags = _aggregate_rule_tags(findings)

    return {
        "id": rule_id,
        "name": _rule_name(rule_id),
        "shortDescription": {"text": f"{representative.title}"},
        "fullDescription": {"text": representative.description or representative.title},
        "defaultConfiguration": {"level": level},
        "properties": {
            "precision": precision,
            "security-severity": security_severity,
            "tags": tags,
        },
    }


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


def _build_result(finding: VerifiedFinding) -> dict[str, object]:
    rule_id = finding.sarif_rule_id or f"cloudsecurity/{finding.hunter_strategy}/{finding.category}"
    location = _physical_location(finding)

    result: dict[str, object] = {
        "ruleId": rule_id,
        "level": _severity_to_level(finding.severity.value),
        "message": {"text": _message_text(finding)},
        "locations": [{"physicalLocation": location}],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint,
        },
        "properties": {
            "security-severity": _format_security_severity(finding.sarif_security_severity),
            "cloudsecurity/verdict": finding.verdict.value,
            "cloudsecurity/risk_score": finding.risk_score,
            "cloudsecurity/hunter_strategy": finding.hunter_strategy,
            "cloudsecurity/category": finding.category,
            "cloudsecurity/compliance": finding.compliance_mappings,
            "tags": _result_tags(finding),
        },
    }

    if finding.attack_path:
        result["properties"]["cloudsecurity/attack_path"] = finding.attack_path.title  # type: ignore[index]

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _message_text(finding: VerifiedFinding) -> str:
    verdict = finding.verdict.value.upper()
    desc = finding.description or finding.title
    return f"[{verdict}] {finding.title}: {desc}"


def _physical_location(finding: VerifiedFinding) -> dict[str, object]:
    region: dict[str, object] = {
        "startLine": max(finding.iac_line, 1),
    }
    if finding.config_snippet:
        region["snippet"] = {"text": finding.config_snippet}

    return {
        "artifactLocation": {
            "uri": finding.iac_file or "unknown",
            "uriBaseId": "%SRCROOT%",
        },
        "region": region,
    }


def _severity_to_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity, "warning")


def _max_level(findings: list[VerifiedFinding]) -> str:
    levels = [_severity_to_level(f.severity.value) for f in findings]
    return max(levels, key=lambda lvl: _LEVEL_RANK.get(lvl, 0))


def _max_precision(findings: list[VerifiedFinding]) -> str:
    precisions = [_VERDICT_TO_PRECISION.get(f.verdict.value, "medium") for f in findings]
    return max(precisions, key=lambda p: _PRECISION_RANK.get(p, 0))


def _format_security_severity(score: float) -> str:
    bounded = min(10.0, max(0.0, score))
    return f"{bounded:.1f}"


def _aggregate_rule_tags(findings: list[VerifiedFinding]) -> list[str]:
    tags: set[str] = set()
    for f in findings:
        tags.update(_base_tags(f))
    return sorted(tags)


def _result_tags(finding: VerifiedFinding) -> list[str]:
    return sorted(set(_base_tags(finding)))


def _base_tags(finding: VerifiedFinding) -> list[str]:
    tags = ["security", "infrastructure"]
    tags.append(finding.category)
    tags.append(finding.hunter_strategy)
    if finding.compliance_mappings:
        for mapping in finding.compliance_mappings:
            tags.append(f"compliance:{mapping}")
    return tags


def _rule_name(rule_id: str) -> str:
    raw_name = rule_id.split("/")[-1]
    chunks = [chunk for chunk in raw_name.replace("_", "-").split("-") if chunk]
    return "".join(chunk.capitalize() for chunk in chunks) or "CloudSecurityRule"
