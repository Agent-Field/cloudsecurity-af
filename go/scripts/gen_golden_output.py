#!/usr/bin/env python3
"""Committed golden generator for internal/output and internal/pyfmt (Dumps).

Standalone sibling of ``gen_golden.py`` (which is owned by the RECON/HUNT
assignments and is left untouched here on purpose — the two scripts write
disjoint trees and can be run in either order).

REPRODUCE (from the repo root of the worktree):

    PYTHONPATH=src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python \
        go/scripts/gen_golden_output.py

Every golden is written by CALLING THE REAL PYTHON FUNCTION. A generator that
re-implemented the formatting would happily agree with a broken port.

It writes two families of fixture:

``internal/output/testdata/<name>.json`` + ``testdata/golden/<name>.*``
    Three CloudSecurityScanResult fixtures and, for each, the four artifacts
    ``src/cloudsecurity_af/output`` produces from it:

        <name>.sarif.json         generate_sarif(result)
        <name>.full.json          generate_json(result, pretty=True)
        <name>.full_compact.json  generate_json(result, pretty=False)
        <name>.summary.json       generate_summary_json(result)
        <name>.report.md          generate_report(result)

    The Go test loads the SAME ``<name>.json`` into schemas.CloudSecurityScanResult
    and diffs its own output against those bytes, so the fixture is the shared
    input and neither side re-implements the other.

``internal/pyfmt/testdata/models_fixture.json`` + ``testdata/golden/dumps_*.txt``
    ``json.dumps(Model(**sub_fixture).model_dump(), indent=2)`` and the compact
    spelling, for four real pydantic models plus one plain JSON document. This
    is the parity gate for ``pyfmt.Dumps`` / ``pyfmt.DumpsCompact`` (DESIGN §2b).

The fixture files are dumped with ``sort_keys=False``, so the file preserves the
dict order the literals below declare — which is the order the LIVE orchestrator
produces:

* ``by_severity``    seeded ``{s.value: 0 for s in Severity}`` -> critical,
  high, medium, low, info (orchestrator.py:165)
* ``cost_breakdown`` seeded from ``_PHASE_ORDER`` -> recon, hunt, chain, prove,
  remediate (orchestrator.py:54,67)

The Go port reproduces exactly those two orders from
``schemas.BySeverityOrder()`` / ``schemas.CostBreakdownOrder`` instead of
sorting, so the goldens are a real order check rather than a neutralised one.

``metadata`` has no knowable order (it is free-form), so the port sorts it and
the fixtures below spell it in sorted order. The ``scan_result_edge`` fixture's
``cost_breakdown`` carries keys OUTSIDE ``_PHASE_ORDER``, which the live path
cannot produce; it is written known-phases-first-then-sorted, the deterministic
tail the port falls back to.

Deterministic and idempotent: every input is a fixed literal (no clock, no uuid),
so rerunning overwrites the fixtures with identical bytes unless
``src/cloudsecurity_af/output/**`` or a schema changed.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Make `cloudsecurity_af` importable when run from the repo root without an install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_GO_ROOT = os.path.join(_REPO_ROOT, "go")

from cloudsecurity_af.output.json_output import generate_json, generate_summary_json  # noqa: E402
from cloudsecurity_af.output.report import generate_report  # noqa: E402
from cloudsecurity_af.output.sarif import generate_sarif  # noqa: E402
from cloudsecurity_af.schemas.chain import AttackPath, AttackStep, BlastRadius, ChainResult  # noqa: E402
from cloudsecurity_af.schemas.hunt import AffectedResource  # noqa: E402
from cloudsecurity_af.schemas.output import CloudSecurityScanResult, ScanMetrics  # noqa: E402
from cloudsecurity_af.schemas.prove import (  # noqa: E402
    IaCDiff,
    Proof,
    ProofMethod,
    RemediationSuggestion,
    Verdict,
    VerifiedFinding,
)
from cloudsecurity_af.schemas.recon import ConfigDiff, DriftedResource  # noqa: E402
from cloudsecurity_af.scoring import Severity  # noqa: E402

_OUTPUT_TESTDATA = "internal/output/testdata"
_OUTPUT_GOLDEN = "internal/output/testdata/golden"
_PYFMT_TESTDATA = "internal/pyfmt/testdata"
_PYFMT_GOLDEN = "internal/pyfmt/testdata/golden"

# A fixed instant, so the fixture (and every artifact that interpolates it) is
# reproducible. Microseconds are non-zero on purpose: both the isoformat()
# spelling used by report.py/sarif.py ("+00:00") and the model_dump_json()
# spelling used by json_output.py ("Z") must carry the six fractional digits.
_TIMESTAMP = datetime(2026, 5, 6, 7, 8, 9, 123456, tzinfo=timezone.utc)
# The empty fixture's clock has ZERO microseconds, which is the other branch of
# both spellings (no fractional part at all).
_TIMESTAMP_WHOLE = datetime(2026, 5, 6, 7, 8, 9, tzinfo=timezone.utc)
# A non-UTC offset, which pydantic renders as "+05:30" rather than "Z".
_TIMESTAMP_OFFSET = datetime(2026, 5, 6, 7, 8, 9, 500000, tzinfo=timezone(timedelta(hours=5, minutes=30)))


def _write(rel_path: str, text: str) -> None:
    """Write text under go/ and report it, creating parent directories."""
    dest = Path(_GO_ROOT) / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    _ = dest.write_text(text, encoding="utf-8", newline="")
    print(f"wrote {rel_path} ({len(text.encode('utf-8'))} bytes)")


# ---------------------------------------------------------------------------
# Fixture 1 — "scan_result": the ordinary, fully populated scan.
# ---------------------------------------------------------------------------
def _scan_result() -> CloudSecurityScanResult:
    path = AttackPath(
        id="path-1",
        title="Public ALB to customer PII bucket",
        description="An internet-facing load balancer reaches a role that can read the PII bucket.",
        steps=[
            AttackStep(
                step_number=1,
                resource_id="aws_lb.public",
                resource_type="aws_lb",
                action="Reach the listener from the internet",
                permission_used="ingress 0.0.0.0/0:443",
                description="The security group allows the world.",
            ),
            AttackStep(
                step_number=2,
                resource_id="aws_iam_role.app",
                resource_type="aws_iam_role",
                action="Assume the task role",
                permission_used="sts:AssumeRole",
            ),
            AttackStep(
                step_number=3,
                resource_id="aws_s3_bucket.pii",
                resource_type="aws_s3_bucket",
                action="Read every object",
                permission_used="s3:GetObject",
            ),
        ],
        entry_point="aws_lb.public",
        target="aws_s3_bucket.pii",
        findings_involved=["finding-net-1", "finding-iam-1"],
        combined_severity=Severity.CRITICAL,
        blast_radius=BlastRadius(
            data_stores_reachable=["aws_s3_bucket.pii", "aws_rds_cluster.main"],
            compute_reachable=["aws_ecs_service.api"],
            estimated_data_volume="~400 GB",
            services_affected=["s3", "rds", "ecs"],
        ),
    )

    drift = DriftedResource(
        resource_id="aws_s3_bucket.pii",
        resource_type="aws_s3_bucket",
        iac_config={"acl": "private", "versioning": True},
        live_config={"acl": "public-read", "versioning": False},
        diffs=[
            ConfigDiff(
                attribute="acl",
                iac_value="private",
                live_value="public-read",
                security_impact="Bucket is world-readable in the account.",
            )
        ],
        security_relevant=True,
        significance="critical",
    )

    iam = VerifiedFinding(
        id="finding-iam-1",
        title="Wildcard IAM policy on the task role",
        verdict=Verdict.CONFIRMED,
        severity=Severity.CRITICAL,
        category="overprivilege",
        resources=[
            AffectedResource(
                resource_id="aws_iam_role_policy.app",
                resource_type="aws_iam_role_policy",
                attribute="policy.Statement[0].Action",
                current_value='"*"',
                recommended_value='["s3:GetObject"]',
            )
        ],
        attack_path=path,
        drift=None,
        proof=Proof(
            method=ProofMethod.STATIC_ANALYSIS,
            evidence=["policy document grants Action:* on Resource:*"],
            scripts_executed=["grep -rn 'Action' iam.tf"],
            verification_tier="static",
        ),
        compliance_mappings=["CIS-AWS-1.16", "SOC2-CC6.1"],
        risk_score=9.5,
        remediation=RemediationSuggestion(
            finding_id="finding-iam-1",
            description="Scope the policy to the two objects the service actually reads.",
            diffs=[
                IaCDiff(
                    file_path="iam.tf",
                    original_lines='  Action = "*"',
                    patched_lines='  Action = ["s3:GetObject"]',
                    start_line=41,
                    end_line=41,
                )
            ],
            breaking_change=True,
            downtime_estimate="seconds",
            effort="moderate",
            alternative_approaches=["Attach a permissions boundary instead."],
        ),
        sarif_rule_id="cloudsecurity/iam/overprivilege",
        sarif_security_severity=9.5,
        iac_file="iam.tf",
        iac_line=41,
        config_snippet='resource "aws_iam_role_policy" "app" {\n  policy = jsonencode({ Action = "*" })\n}',
        description="The task role can perform any action on any resource.",
        fingerprint="fp-iam-1",
        hunter_strategy="iam",
        drop_reason=None,
    )

    net = VerifiedFinding(
        id="finding-net-1",
        title="Security group open to the internet",
        verdict=Verdict.LIKELY,
        severity=Severity.HIGH,
        category="public_exposure",
        resources=[],
        attack_path=path,
        drift=drift,
        proof=Proof(method=ProofMethod.DRIFT_COMPARISON, verification_tier="live"),
        compliance_mappings=["CIS-AWS-5.2"],
        risk_score=7.25,
        remediation=RemediationSuggestion(
            finding_id="finding-net-1",
            description="Restrict ingress to the corporate CIDR.",
            breaking_change=False,
            downtime_estimate=None,
            effort="trivial",
        ),
        # Same rule id as the finding below, so the rule aggregation (max level,
        # max precision, max security-severity, tag union) has something to do.
        sarif_rule_id="cloudsecurity/network/public_exposure",
        sarif_security_severity=7.2,
        iac_file="network.tf",
        iac_line=12,
        config_snippet="",
        description="0.0.0.0/0 on port 443.",
        fingerprint="fp-net-1",
        hunter_strategy="network",
    )

    net_low = VerifiedFinding(
        id="finding-net-2",
        title="Load balancer logs disabled",
        verdict=Verdict.INCONCLUSIVE,
        severity=Severity.LOW,
        category="public_exposure",
        proof=Proof(),
        compliance_mappings=[],
        risk_score=2.0,
        sarif_rule_id="cloudsecurity/network/public_exposure",
        sarif_security_severity=3.0,
        iac_file="network.tf",
        iac_line=88,
        description="",
        fingerprint="fp-net-2",
        hunter_strategy="network",
    )

    dropped = VerifiedFinding(
        id="finding-dropped",
        title="Unused KMS key",
        verdict=Verdict.NOT_EXPLOITABLE,
        severity=Severity.MEDIUM,
        category="encryption",
        proof=Proof(),
        risk_score=0.0,
        sarif_rule_id="cloudsecurity/data/encryption",
        sarif_security_severity=4.0,
        iac_file="kms.tf",
        iac_line=3,
        description="The key has no grants.",
        fingerprint="fp-dropped",
        hunter_strategy="data",
        drop_reason="not_exploitable",
    )

    return CloudSecurityScanResult(
        repository="https://github.com/Agent-Field/vulnerable-infra",
        commit_sha="0f1e2d3c4b5a69788796a5b4c3d2e1f000112233",
        branch="main",
        timestamp=_TIMESTAMP,
        depth_profile="standard",
        tier=2,
        providers_detected=["aws", "gcp"],
        findings=[iam, net, net_low, dropped],
        attack_paths=[path],
        total_resources_scanned=137,
        total_raw_findings=19,
        confirmed=1,
        likely=1,
        inconclusive=1,
        not_exploitable=1,
        noise_reduction_pct=78.94736842105263,
        by_severity={"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0},
        drift_resources=3,
        shadow_it_resources=1,
        compliance_frameworks_checked=["CIS-AWS", "SOC2"],
        compliance_gaps=["CIS-AWS-2.1.1 has no evidence"],
        strategies_used=["iam", "network", "data"],
        duration_seconds=412.6499999999999,
        agent_invocations=23,
        cost_usd=1.23456789,
        cost_breakdown={"recon": 0.13456789, "hunt": 0.5, "chain": 0.2, "prove": 0.4},
        metadata={"harness": "aforge", "live_verified": True, "model": "minimax/minimax-m2.5"},
        sarif="",
    )


# ---------------------------------------------------------------------------
# Fixture 2 — "scan_result_empty": every "nothing to report" branch at once.
# ---------------------------------------------------------------------------
def _scan_result_empty() -> CloudSecurityScanResult:
    return CloudSecurityScanResult(
        repository="",
        commit_sha="",
        branch=None,
        timestamp=_TIMESTAMP_WHOLE,
        depth_profile="quick",
        tier=1,
        providers_detected=[],
        findings=[],
        attack_paths=[],
        by_severity={},
        compliance_frameworks_checked=[],
        strategies_used=[],
        cost_breakdown={},
        metadata={},
    )


# ---------------------------------------------------------------------------
# Fixture 3 — "scan_result_edge": escaping, float spellings and every guard.
# ---------------------------------------------------------------------------
def _scan_result_edge() -> CloudSecurityScanResult:
    # An attack path with NO steps, NO findings_involved and an empty blast
    # radius: the "- Steps:" header with nothing under it, and both blast-radius
    # lines suppressed.
    bare_path = AttackPath(
        id="path-bare",
        title='Path with "quotes" & <angle brackets>',
        description="",
        steps=[],
        entry_point="",
        target="",
        findings_involved=[],
        combined_severity=Severity.INFO,
        blast_radius=BlastRadius(),
    )

    # No sarif_rule_id -> the "cloudsecurity/{strategy}/{category}" fallback,
    # which here has an EMPTY last segment, so _rule_name falls back to
    # "CloudSecurityRule". iac_line 0 is floored to 1; the empty iac_file
    # becomes "unknown".
    fallback = VerifiedFinding(
        id="finding-fallback",
        title="Unnamed rule",
        verdict=Verdict.CONFIRMED,
        severity=Severity.INFO,
        category="",
        proof=Proof(),
        compliance_mappings=[],
        # 1e-05: json.dumps renders it "1e-05", pydantic renders it "0.00001".
        risk_score=1e-05,
        sarif_rule_id="",
        sarif_security_severity=-3.0,  # clamped up to 0.0
        iac_file="",
        iac_line=0,
        config_snippet="",
        description="",
        fingerprint="fp-fallback",
        hunter_strategy="",
    )

    # Shares the fallback rule id, and is LOWER on both ranks, so max_level and
    # max_precision must keep the FIRST maximum rather than the last.
    fallback_twin = VerifiedFinding(
        id="finding-fallback-2",
        title="Unnamed rule, second sighting",
        verdict=Verdict.NOT_EXPLOITABLE,  # dropped before rules are built
        severity=Severity.CRITICAL,
        category="",
        proof=Proof(),
        risk_score=-0.0,
        sarif_rule_id="",
        sarif_security_severity=99.0,  # clamped down to 10.0 (if it survived)
        hunter_strategy="",
        fingerprint="fp-fallback-2",
    )

    # Escaping: non-ASCII (ensure_ascii vs raw UTF-8), an astral character
    # (surrogate pair), HTML characters (Go escapes them, Python does not), a
    # backslash, a quote and a tab.
    escaped = VerifiedFinding(
        id="finding-éscaped",
        title='S3 bucket "public" — 世界 \U0001F680',
        verdict=Verdict.LIKELY,
        severity=Severity.MEDIUM,
        category="public_exposure",
        proof=Proof(evidence=["<script>alert(1)</script> & friends"]),
        compliance_mappings=["CIS-AWS-2.1.1", "§5.2"],
        # Ties for the report's :.2f / :.4f / :.1f renderings.
        risk_score=2.675,
        remediation=RemediationSuggestion(
            finding_id="finding-éscaped",
            description="Set `acl = \"private\"`.",
            breaking_change=True,
            downtime_estimate="",  # falsy -> the Downtime line is suppressed
            effort="trivial",
        ),
        sarif_rule_id="cloudsecurity/data/PUBLIC-exposure_v2",
        sarif_security_severity=10.0,
        iac_file="s3\\buckets.tf",
        iac_line=7,
        config_snippet='resource "aws_s3_bucket" "b" {\n\tacl = "public-read"\n}',
        description="Bucket ACL is public-read.\tSee <docs>.",
        fingerprint="fp-éscaped",
        hunter_strategy="data",
    )

    # An unknown severity/verdict cannot exist (the enums are closed), so the
    # ".get(..., default)" arms of _severity_to_level / _VERDICT_TO_PRECISION
    # are unreachable from a validated model — noted rather than fixtured.
    return CloudSecurityScanResult(
        repository="repo/with spaces & <brackets>",
        commit_sha="",
        branch="",  # falsy -> the report's "n/a" arm, like None
        timestamp=_TIMESTAMP_OFFSET,
        depth_profile="thorough",
        tier=7,  # neither 1 nor 2 -> "deep"
        providers_detected=["azure"],
        findings=[fallback, fallback_twin, escaped],
        attack_paths=[bare_path],
        total_resources_scanned=0,
        total_raw_findings=0,
        confirmed=2,
        likely=1,
        inconclusive=0,
        not_exploitable=1,
        # 1e16 renders "1e+16" in both spellings; 0.05 is a :.1f tie.
        noise_reduction_pct=0.05,
        by_severity={"critical": 1, "medium": 1, "info": 1},
        drift_resources=0,
        shadow_it_resources=2,  # only one of the two guards is non-zero
        compliance_frameworks_checked=["CIS-AWS"],
        compliance_gaps=[],
        strategies_used=[],
        duration_seconds=0.05,
        agent_invocations=0,
        cost_usd=0.00005,
        cost_breakdown={"prove": 0.12345, "zzz": -0.0, "éphase": 1e16},
        metadata={"note": "tab\there", "ratio": 0.5, "unicode": "—"},
        sarif="",
    )


_SCAN_FIXTURES: dict[str, Any] = {
    "scan_result": _scan_result,
    "scan_result_empty": _scan_result_empty,
    "scan_result_edge": _scan_result_edge,
}


def gen_output() -> None:
    print("internal/output:")
    for name, build in _SCAN_FIXTURES.items():
        # Round-trip through the fixture file so Python generates its goldens
        # from EXACTLY the bytes the Go test will read.
        fixture_text = json.dumps(json.loads(build().model_dump_json()), indent=2, sort_keys=False) + "\n"
        _write(f"{_OUTPUT_TESTDATA}/{name}.json", fixture_text)

        result = CloudSecurityScanResult.model_validate_json(fixture_text)
        _write(f"{_OUTPUT_GOLDEN}/{name}.sarif.json", generate_sarif(result))
        _write(f"{_OUTPUT_GOLDEN}/{name}.full.json", generate_json(result, pretty=True))
        _write(f"{_OUTPUT_GOLDEN}/{name}.full_compact.json", generate_json(result, pretty=False))
        _write(f"{_OUTPUT_GOLDEN}/{name}.summary.json", generate_summary_json(result))
        _write(f"{_OUTPUT_GOLDEN}/{name}.report.md", generate_report(result))


# ---------------------------------------------------------------------------
# internal/pyfmt — json.dumps parity for pyfmt.Dumps / DumpsCompact
# ---------------------------------------------------------------------------
# One sub-object per model, plus a plain document. The Go test decodes the SAME
# sub-object into the identically named Go struct and renders it with
# pyfmt.Dumps; Python builds the model and renders model_dump().
#
# No model here has a `datetime` field: json.dumps cannot serialise one, which
# is exactly why json_output.py goes through model_dump_json() instead. The
# datetime spelling is covered by the internal/output goldens.
_PYFMT_MODELS: dict[str, Any] = {
    "VerifiedFinding": VerifiedFinding,
    "AttackPath": AttackPath,
    "ChainResult": ChainResult,
    "ScanMetrics": ScanMetrics,
}


def _pyfmt_fixture() -> dict[str, Any]:
    return {
        # Nested models, optional pointers left at None, empty lists, an enum,
        # unicode and a control character.
        "VerifiedFinding": {
            "id": "vf-1",
            "title": "Bucket éxposed — \U0001F680",
            "verdict": "likely",
            "severity": "high",
            "category": "public_exposure",
            "resources": [
                {
                    "resource_id": "aws_s3_bucket.b",
                    "resource_type": "aws_s3_bucket",
                    "attribute": "acl",
                    "current_value": "public-read",
                    "recommended_value": "private",
                }
            ],
            "attack_path": None,
            "drift": None,
            "proof": {
                "method": "iam_simulation",
                "evidence": ["<policy> & \"quote\"", "line\twith tab"],
                "scripts_executed": [],
                "verification_tier": "live",
            },
            "compliance_mappings": [],
            "risk_score": 7.25,
            "remediation": None,
            "sarif_rule_id": "cloudsecurity/data/public_exposure",
            "sarif_security_severity": 10.0,
            "iac_file": "s3.tf",
            "iac_line": 12,
            "config_snippet": "",
            "description": "",
            "fingerprint": "fp-1",
            "hunter_strategy": "data",
            "drop_reason": None,
        },
        # A deeply nested list of models plus a defaulted sub-model.
        "AttackPath": {
            "id": "ap-1",
            "title": "Path",
            "description": "",
            "steps": [
                {
                    "step_number": 1,
                    "resource_id": "a",
                    "resource_type": "t",
                    "action": "act",
                    "permission_used": "perm",
                    "description": "",
                },
                {
                    "step_number": 2,
                    "resource_id": "b",
                    "resource_type": "t",
                    "action": "act2",
                    "permission_used": "perm2",
                    "description": "d",
                },
            ],
            "entry_point": "a",
            "target": "b",
            "findings_involved": ["f1", "f2"],
            "combined_severity": "critical",
            "blast_radius": {
                "data_stores_reachable": [],
                "compute_reachable": ["c1"],
                "estimated_data_volume": None,
                "services_affected": [],
            },
        },
        # Empty list + the awkward float spellings.
        "ChainResult": {
            "attack_paths": [],
            "total_paths_evaluated": 12,
            "viable_paths": 0,
            "chain_duration_seconds": 1e-05,
        },
        # dict[str, float] (sorted-key deviation), bool, ints, and the float
        # spellings Go's %v gets wrong.
        "ScanMetrics": {
            "duration_seconds": 1000000000000000.0,
            "agent_invocations": 41,
            "cost_usd": 1e16,
            "cost_breakdown": {"a": 1.0, "b": 0.5, "c": -0.0, "z": 1e-05},
            "budget_exhausted": True,
            "findings_not_verified": 0,
        },
        # A plain JSON document (not a model): ints stay ints, floats keep their
        # repr spelling, strings get ensure_ascii-escaped, containers nest.
        "edge_cases": {
            "int": 7,
            "big_int": 1234567890123456789,
            "float_integral": 1.0,
            "float_tiny": 1e-05,
            "float_huge": 1e16,
            "float_neg_zero": -0.0,
            "float_pi": 3.141592653589793,
            "true": True,
            "false": False,
            "null": None,
            "empty_list": [],
            "empty_obj": {},
            "html": "<a> & </a> /",
            "unicode": "héllo — 世界 \U0001F680",
            "control": "a\tb\nc\u0000d\u007f",
            "nested": {"list_of_obj": [{"k": 1}, {"k": 2}]},
        },
    }


def gen_pyfmt() -> None:
    print("internal/pyfmt:")
    fixture = _pyfmt_fixture()
    _write(f"{_PYFMT_TESTDATA}/models_fixture.json", json.dumps(fixture, indent=2, sort_keys=True) + "\n")

    # Re-read so Python renders from exactly the bytes the Go test parses.
    reloaded = json.loads(
        (Path(_GO_ROOT) / _PYFMT_TESTDATA / "models_fixture.json").read_text(encoding="utf-8")
    )
    for name, model in _PYFMT_MODELS.items():
        dumped = model(**reloaded[name]).model_dump()
        _write(f"{_PYFMT_GOLDEN}/dumps_{name}_indent2.txt", json.dumps(dumped, indent=2))
        _write(f"{_PYFMT_GOLDEN}/dumps_{name}_compact.txt", json.dumps(dumped))

    # The plain document is compared with sort_keys=True, because pyfmt.Dumps
    # sorts Go map keys (its one documented ordering deviation) — the comparison
    # is therefore about VALUE rendering, and the ordering deviation itself is
    # pinned separately by TestDumpsMapKeysAreSorted.
    doc = reloaded["edge_cases"]
    _write(f"{_PYFMT_GOLDEN}/dumps_edge_cases_indent2.txt", json.dumps(doc, indent=2, sort_keys=True))
    _write(f"{_PYFMT_GOLDEN}/dumps_edge_cases_compact.txt", json.dumps(doc, sort_keys=True))


def main() -> None:
    gen_pyfmt()
    gen_output()
    print("done")


if __name__ == "__main__":
    main()
