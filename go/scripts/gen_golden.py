#!/usr/bin/env python3
"""Committed golden-fixture generator for the cloudsecurity-af Go port (RECON).

This script is the SINGLE SOURCE OF TRUTH for two kinds of fixture under
``go/internal/agents/recon/testdata/``:

``golden/*.txt``
    The exact prompt strings the PYTHON recon agents hand to ``app.harness``.
    They are captured by binding a recording fake to the agent's ``app``
    parameter and driving the real coroutine, so a fixture can only change when
    the Python builder or the prompt template changes. The Go golden test
    renders the same inputs through ``BuildIaCReaderPrompt`` /
    ``BuildResourceGraphBuilderPrompt`` / ``BuildCloudConnectorPrompt`` /
    ``BuildDriftDetectorPrompt`` and compares byte-for-byte.

``../hunt/testdata/golden/*.txt`` and ``../util/testdata/golden/*.txt``
    The same treatment for the HUNT phase: the seven hunters' full harness
    prompts, and the three text blocks
    ``_utils.build_graph_context_for_hunter`` returns for a handful of keyword
    /file cases. Both are driven off ONE committed fixture pair,
    ``internal/agents/util/testdata/fixture/{graph,inventory}.json``, which is
    copied into the hunt package's testdata so each Go package's tests are
    self-contained.

``python/inventory.json`` and ``python/graph.json``
    The output of the real ``parse_terraform_directory`` and
    ``build_graph_from_inventory`` over ``tests/fixtures/vulnerable_infra``.
    They are the ground truth the Go parser is asserted against — structurally,
    field by field, with the documented expression-rendering divergence
    enumerated explicitly in the Go test rather than papered over.

REPRODUCE (from the repo root):

    PYTHONPATH=src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python \
        go/scripts/gen_golden.py

The script is deterministic and idempotent: rerunning overwrites the fixtures
with identical bytes unless a Python builder, a prompt template or the parser
changed — which is exactly the signal the Go tests exist to catch.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_REPO_ROOT, "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from cloudsecurity_af.agents._utils import build_graph_context_for_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.compliance_hunter import run_compliance_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.compute_hunter import run_compute_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.data_hunter import run_data_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.iam_hunter import run_iam_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.logging_hunter import run_logging_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.network_hunter import run_network_hunter  # noqa: E402
from cloudsecurity_af.agents.hunt.secrets_hunter import run_secrets_hunter  # noqa: E402
from cloudsecurity_af.agents.chain import path_constructor  # noqa: E402
from cloudsecurity_af.agents.chain.path_constructor import ChildInvestigation  # noqa: E402
from cloudsecurity_af.agents.prove import live_prover, static_prover  # noqa: E402
from cloudsecurity_af.agents.recon import cloud_connector, drift_detector, iac_reader  # noqa: E402
from cloudsecurity_af.agents.recon import resource_graph_builder  # noqa: E402
from cloudsecurity_af.agents.recon._graph_builder_fast import build_graph_from_inventory  # noqa: E402
from cloudsecurity_af.agents.recon._terraform_parser import parse_terraform_directory  # noqa: E402
from cloudsecurity_af.agents.remediate import fix_generator  # noqa: E402
from cloudsecurity_af.schemas.chain import AttackPath, AttackStep, BlastRadius  # noqa: E402
from cloudsecurity_af.schemas.hunt import AffectedResource, Confidence, RawFinding  # noqa: E402
from cloudsecurity_af.schemas.prove import (  # noqa: E402
    IaCDiff,
    Proof,
    ProofMethod,
    RemediationSuggestion,
    Verdict,
    VerifiedFinding,
)
from cloudsecurity_af.schemas.recon import (  # noqa: E402
    ConfigDiff,
    DriftedResource,
    DriftReport,
    ResourceGraph,
    ResourceInventory,
)
from cloudsecurity_af.scoring import Severity  # noqa: E402

_GO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDATA = os.path.join(_GO_ROOT, "internal", "agents", "recon", "testdata")
GOLDEN = os.path.join(TESTDATA, "golden")
PYDATA = os.path.join(TESTDATA, "python")
TF_FIXTURE = os.path.join(_REPO_ROOT, "tests", "fixtures", "vulnerable_infra")

# --- HUNT phase (assignment C4) ---------------------------------------------
UTIL_TESTDATA = os.path.join(_GO_ROOT, "internal", "agents", "util", "testdata")
UTIL_FIXTURE = os.path.join(UTIL_TESTDATA, "fixture")
UTIL_GOLDEN = os.path.join(UTIL_TESTDATA, "golden")
HUNT_TESTDATA = os.path.join(_GO_ROOT, "internal", "agents", "hunt", "testdata")
HUNT_FIXTURE = os.path.join(HUNT_TESTDATA, "fixture")
HUNT_GOLDEN = os.path.join(HUNT_TESTDATA, "golden")

# The committed graph/inventory pair every HUNT fixture is derived from. It is
# hand-written (not parser output) so it can exercise the shapes that matter to
# build_graph_context_for_hunter: nested config_summary dicts whose key order is
# NOT alphabetical, None/bool/int/float/non-ASCII values, a string containing
# double quotes, an edge with no "type" (default "references"), an edge with an
# empty description, an edge with no description, a hunter with no matching
# edges at all, and providers that need dedup + sorting.
FIXTURE_GRAPH = os.path.join(UTIL_FIXTURE, "graph.json")
FIXTURE_INVENTORY = os.path.join(UTIL_FIXTURE, "inventory.json")
# A valid JSON document that is not an object -> both loads fall back to the
# empty default.
FIXTURE_NOT_AN_OBJECT = os.path.join(UTIL_FIXTURE, "not_an_object.json")
# A path that does not exist -> json.load raises -> same empty default.
FIXTURE_ABSENT = os.path.join(UTIL_FIXTURE, "absent.json")

HUNT_REPO_PATH = "/fixture/repo"
HUNT_DEPTH = "standard"

# (module name, coroutine) in the order reasoners/hunt.py registers them.
HUNTERS = [
    ("iam_hunter", run_iam_hunter),
    ("network_hunter", run_network_hunter),
    ("data_hunter", run_data_hunter),
    ("secrets_hunter", run_secrets_hunter),
    ("compute_hunter", run_compute_hunter),
    ("logging_hunter", run_logging_hunter),
    ("compliance_hunter", run_compliance_hunter),
]

# build_graph_context_for_hunter cases, named after the Go sub-test that reads
# them. Each is (graph_path, inventory_path, domain_keywords).
GRAPH_CONTEXT_CASES = {
    # The iam hunter's own keyword list: two matching nodes, one matching edge
    # WITH a description, no 1-hop neighbors.
    "iam": (FIXTURE_GRAPH, FIXTURE_INVENTORY, ["iam", "role", "policy"]),
    # The data hunter's shape: two matching nodes, two matching edges (one with
    # an empty description, one with no "type"), one 1-hop neighbor.
    "data": (FIXTURE_GRAPH, FIXTURE_INVENTORY, ["s3", "bucket", "kms"]),
    # What the compliance hunter's [""] reduces to: no keywords -> match all.
    "all": (FIXTURE_GRAPH, FIXTURE_INVENTORY, [""]),
    # Nothing matches: both "none matched" / "no edges matched" branches.
    "nomatch": (FIXTURE_GRAPH, FIXTURE_INVENTORY, ["nonexistent_type_xyz"]),
    # Unreadable files -> the bare `except Exception` default documents.
    "missing_files": (FIXTURE_ABSENT, FIXTURE_ABSENT, ["iam"]),
    # Readable but not a dict -> the isinstance re-check default documents.
    "not_an_object": (FIXTURE_NOT_AN_OBJECT, FIXTURE_NOT_AN_OBJECT, ["iam"]),
}

# Fixed, path-independent fixture inputs. They are deliberately NOT real
# temporary paths: a golden has to be reproducible on any machine.
REPO_PATH = "/fixture/repo"
INVENTORY_PATH = "/fixture/work/inventory.json"
IAC_GRAPH_PATH = "/fixture/work/graph.json"

# cloud_config cases.
#   A = CloudConfig().model_dump()      — every default, two explicit Nones
#   B = every field populated           — multi-region, account, assume-role
#   C = {}                              — the empty-dict edge case
CLOUD_CONFIG_CASES = {
    "a": {"provider": "aws", "regions": ["us-east-1"], "account_id": None, "assume_role_arn": None},
    "b": {
        "provider": "gcp",
        "regions": ["us-central1", "europe-west1"],
        "account_id": "123456789012",
        "assume_role_arn": "arn:aws:iam::123456789012:role/cloudsecurity-scanner",
    },
    "c": {},
}


# ---------------------------------------------------------------------------
# Recording fake app
# ---------------------------------------------------------------------------
class _FakeResult:
    """Mimics the harness result shape extract_harness_result reads."""

    def __init__(self, parsed: object) -> None:
        self.is_error = False
        self.error_message = None
        self.result = None
        self.parsed = parsed


class _FakeApp:
    """Records every harness prompt and answers with a schema-valid model."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def harness(self, prompt: str, *, schema=None, cwd=None, **kwargs):  # noqa: ANN001
        self.prompts.append(prompt)
        return _FakeResult(schema.model_construct() if schema is not None else None)


def capture(coro_factory) -> str:
    """Run one agent coroutine and return the single prompt it emitted."""
    app = _FakeApp()
    asyncio.new_event_loop().run_until_complete(coro_factory(app))
    assert len(app.prompts) == 1, f"expected exactly one harness call, got {len(app.prompts)}"
    return app.prompts[0]


def emit(directory: str, name: str, text: str) -> None:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    print(f"  wrote {os.path.relpath(path, _GO_ROOT)} ({len(text.encode('utf-8'))} bytes)")


# ---------------------------------------------------------------------------
# Prompt goldens
# ---------------------------------------------------------------------------
def gen_prompts() -> None:
    print("prompt goldens:")

    # iac_reader._harness_fallback(app, repo_path, work_dir)
    emit(
        GOLDEN,
        "iac_reader_prompt.txt",
        capture(lambda app: iac_reader._harness_fallback(app, REPO_PATH, "/fixture/work")),
    )

    # resource_graph_builder._harness_fallback(app, repo_path, inventory_path, work_dir)
    emit(
        GOLDEN,
        "resource_graph_builder_prompt.txt",
        capture(
            lambda app: resource_graph_builder._harness_fallback(
                app, REPO_PATH, INVENTORY_PATH, "/fixture/work"
            )
        ),
    )

    for case, cfg in CLOUD_CONFIG_CASES.items():
        emit(
            GOLDEN,
            f"cloud_connector_prompt_{case}.txt",
            capture(lambda app, cfg=cfg: cloud_connector.run_cloud_connector(app, cfg)),
        )

    for case, cfg in CLOUD_CONFIG_CASES.items():
        emit(
            GOLDEN,
            f"drift_detector_prompt_{case}.txt",
            capture(
                lambda app, cfg=cfg: drift_detector.run_drift_detector(app, IAC_GRAPH_PATH, cfg)
            ),
        )


# ---------------------------------------------------------------------------
# Parser / graph ground truth
# ---------------------------------------------------------------------------
def gen_parser_ground_truth() -> None:
    print("parser ground truth:")
    work = tempfile.mkdtemp(prefix="cloudsecurity-gen-golden-")
    try:
        inv_path, total, iac_type = parse_terraform_directory(TF_FIXTURE, work)
        graph_path, nodes, edges = build_graph_from_inventory(inv_path, work)

        os.makedirs(PYDATA, exist_ok=True)
        shutil.copyfile(inv_path, os.path.join(PYDATA, "inventory.json"))
        shutil.copyfile(graph_path, os.path.join(PYDATA, "graph.json"))

        # A tiny sidecar so the Go test asserts the scalar returns too, without
        # hard-coding them in two places.
        summary = {
            "total_resources": total,
            "iac_type": iac_type,
            "total_nodes": nodes,
            "total_edges": edges,
        }
        emit(PYDATA, "summary.json", json.dumps(summary, indent=2) + "\n")
        print(f"  wrote python/inventory.json ({total} resources, iac_type={iac_type})")
        print(f"  wrote python/graph.json ({nodes} nodes, {edges} edges)")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def gen_expressions_ground_truth() -> None:
    """Parse the Go-tree-only expression-coverage fixture with the Python parser.

    tests/fixtures/vulnerable_infra exercises the shapes that actually occur in
    the benchmark repo; testdata/expressions/main.tf additionally covers every
    HCL expression KIND (interpolation, heredoc, conditional, function call,
    unary minus, null, quoted object keys, labeled/repeated nested blocks,
    variable/output/provider/module blocks). Committing the Python output for it
    is what lets the Go test assert "every CONSTANT leaf is identical" instead of
    hand-transcribing expected values.
    """
    print("expression ground truth:")
    fixture = os.path.join(TESTDATA, "expressions")
    work = tempfile.mkdtemp(prefix="cloudsecurity-gen-golden-expr-")
    try:
        inv_path, total, _ = parse_terraform_directory(fixture, work)
        shutil.copyfile(inv_path, os.path.join(PYDATA, "expressions_inventory.json"))
        print(f"  wrote python/expressions_inventory.json ({total} resources)")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def gen_tf_fixture_copy() -> None:
    """Copy the Terraform fixture into the Go tree so `go test` is self-contained."""
    print("terraform fixture:")
    dest = os.path.join(TESTDATA, "vulnerable_infra")
    os.makedirs(dest, exist_ok=True)
    for name in sorted(os.listdir(TF_FIXTURE)):
        src = os.path.join(TF_FIXTURE, name)
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(dest, name))
            print(f"  copied vulnerable_infra/{name}")


# ---------------------------------------------------------------------------
# HUNT phase: shared fixture, graph-context goldens, hunter prompt goldens
# ---------------------------------------------------------------------------
class _RecordingApp:
    """Records the full harness kwargs and answers with a defaulted model."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def harness(self, prompt: str, *, schema=None, cwd=None, project_dir=None, **kwargs):  # noqa: ANN001
        self.calls.append(
            {"prompt": prompt, "schema": schema.__name__ if schema else None, "cwd": cwd, "project_dir": project_dir}
        )
        return _FakeResult(schema.model_construct() if schema is not None else None)


def gen_hunt_fixture_copy() -> None:
    """Mirror the util fixture into the hunt package so both are self-contained."""
    print("hunt fixture:")
    os.makedirs(HUNT_FIXTURE, exist_ok=True)
    for name in sorted(os.listdir(UTIL_FIXTURE)):
        src_path = os.path.join(UTIL_FIXTURE, name)
        if os.path.isfile(src_path):
            shutil.copyfile(src_path, os.path.join(HUNT_FIXTURE, name))
            print(f"  copied hunt/testdata/fixture/{name}")


def gen_graph_context_goldens() -> None:
    """Capture build_graph_context_for_hunter's three blocks for each case."""
    print("graph-context goldens:")
    for case, (graph_path, inventory_path, keywords) in GRAPH_CONTEXT_CASES.items():
        nodes, stats, edges = build_graph_context_for_hunter(graph_path, inventory_path, keywords)
        emit(UTIL_GOLDEN, f"{case}_nodes.txt", nodes)
        emit(UTIL_GOLDEN, f"{case}_stats.txt", stats)
        emit(UTIL_GOLDEN, f"{case}_edges.txt", edges)


def gen_hunt_prompts() -> None:
    """Capture each hunter's full harness prompt, options and returned model."""
    print("hunt prompt goldens:")
    options: dict[str, dict] = {}
    results: dict[str, dict] = {}
    for module, runner in HUNTERS:
        app = _RecordingApp()
        result = asyncio.new_event_loop().run_until_complete(
            runner(app, HUNT_REPO_PATH, FIXTURE_GRAPH, FIXTURE_INVENTORY, HUNT_DEPTH)
        )
        assert len(app.calls) == 1, f"{module}: expected one harness call, got {len(app.calls)}"
        call = app.calls[0]
        emit(HUNT_GOLDEN, f"{module}_prompt.txt", call["prompt"])
        options[module] = {"schema": call["schema"], "cwd": call["cwd"], "project_dir": call["project_dir"]}
        results[module] = result.model_dump()
    emit(HUNT_GOLDEN, "harness_options.json", json.dumps(options, indent=2) + "\n")
    emit(HUNT_GOLDEN, "empty_result.json", json.dumps(results, indent=2) + "\n")


# ---------------------------------------------------------------------------
# CHAIN / PROVE / REMEDIATE goldens
# ---------------------------------------------------------------------------
#
# The three phases below are prompt-only agents: each renders a template by
# string substitution and hands the result to the harness. Their fixtures are
# therefore (a) an ``inputs.json`` holding the exact pydantic models the Python
# builder was driven with, so the Go test binds the SAME values instead of
# transcribing them, and (b) one ``*.txt`` per case holding the prompt Python
# produced.
#
# Two fixture-design rules keep the goldens honest about the port's two
# documented JSON divergences instead of hiding them:
#
#   * every ``Any``-typed leaf (ConfigDiff.iac_value / .live_value) is a string,
#     float, bool or None — never an int, because Go's encoding/json decodes a
#     JSON int into float64 and would render "1" as "1.0". A dedicated Go unit
#     test pins that divergence explicitly.
#   * every free-form dict (DriftedResource.iac_config / .live_config) has
#     ALPHABETICALLY ORDERED keys, because a Go map has no insertion order and
#     the port sorts. A dedicated Go unit test pins that one too.

CHAIN_TESTDATA = os.path.join(_GO_ROOT, "internal", "agents", "chain", "testdata")
CHAIN_GOLDEN = os.path.join(CHAIN_TESTDATA, "golden")
PROVE_GOLDEN = os.path.join(_GO_ROOT, "internal", "agents", "prove", "testdata", "golden")
REMEDIATE_GOLDEN = os.path.join(_GO_ROOT, "internal", "agents", "remediate", "testdata", "golden")

# A resource graph exercising: a node the findings touch, a 1-hop neighbour, an
# unrelated node, an edge that survives, an edge with one endpoint outside the
# relevant set, an edge between two unrelated nodes, a non-dict edge entry, a
# clusters value that is passed through untouched, and a top-level key that the
# filter drops.
CHAIN_GRAPH = {
    "nodes": [
        {
            "resource_id": "aws_iam_role.admin",
            "resource_type": "aws_iam_role",
            "file_path": "main.tf",
            "config_summary": {"assume_role_policy": "*", "name": "admin"},
        },
        {
            "resource_id": "aws_s3_bucket.data",
            "resource_type": "aws_s3_bucket",
            "file_path": "data.tf",
            "config_summary": {},
        },
        {
            "resource_id": "aws_kms_key.unrelated",
            "resource_type": "aws_kms_key",
            "file_path": "kms.tf",
            "config_summary": {"enable_key_rotation": False},
        },
        "not-a-dict-node",
        {"resource_type": "aws_vpc.no_id"},
    ],
    "edges": [
        {
            "source": "aws_iam_role.admin",
            "target": "aws_s3_bucket.data",
            "type": "data_access",
            "description": "role can read the bucket",
        },
        {"source": "aws_s3_bucket.data", "target": "aws_kms_key.unrelated", "type": "encryption"},
        {"source": "unrelated.a", "target": "unrelated.b", "type": "references"},
        "not-a-dict-edge",
        {"target": "aws_s3_bucket.data"},
    ],
    "clusters": [{"name": "prod", "members": ["aws_iam_role.admin"]}],
    "generated_by": "gen_golden.py",
}

REPO = "/fixture/repo"


def _chain_findings_pair() -> list[RawFinding]:
    return [
        RawFinding(
            id="finding-1",
            hunter_strategy="iam",
            title="Role trusts * <everyone> & assumes admin",
            description="aws_iam_role.admin has a wildcard trust policy.",
            category="overprivilege",
            resources=[
                AffectedResource(
                    resource_id="aws_iam_role.admin",
                    resource_type="aws_iam_role",
                    attribute="assume_role_policy",
                    current_value='{"Principal": "*"}',
                    recommended_value="scoped principal",
                )
            ],
            estimated_severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            iac_file="main.tf",
            iac_line=12,
            config_snippet='resource "aws_iam_role" "admin" {\n  assume_role_policy = "*"\n}',
            benchmark_id="CIS-1.16",
            fingerprint="fp-iam-1",
        ),
        RawFinding(
            id="finding-2",
            hunter_strategy="network",
            title="Security group open to 0.0.0.0/0 — pörté 22",
            description="Ingress from anywhere.",
            category="public_exposure",
            resources=[],
            estimated_severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            iac_file="network.tf",
            iac_line=0,
            config_snippet="",
            benchmark_id=None,
            fingerprint="fp-net-2",
        ),
    ]


def _chain_findings_single() -> list[RawFinding]:
    # No resources and no iac_file: finding_resources is EMPTY, so nothing in the
    # graph is relevant. Exercises the empty-filter path.
    return [
        RawFinding(
            id="finding-3",
            hunter_strategy="logging",
            title="No CloudTrail",
            description="",
            category="missing_logging",
            resources=[],
            estimated_severity=Severity.LOW,
            confidence=Confidence.LOW,
            iac_file="",
            iac_line=0,
            config_snippet="",
            fingerprint="fp-log-3",
        )
    ]


def _drift_report() -> DriftReport:
    return DriftReport(
        drifted_resources=[
            DriftedResource(
                resource_id="aws_s3_bucket.data",
                resource_type="aws_s3_bucket",
                iac_config={"acl": "private", "versioning": True},
                live_config={"acl": "public-read", "versioning": False},
                diffs=[
                    ConfigDiff(
                        attribute="acl",
                        iac_value="private",
                        live_value="public-read",
                        security_impact="bucket became world readable",
                    ),
                    ConfigDiff(attribute="retention_days", iac_value=30.0, live_value=None),
                    ConfigDiff(attribute="mfa_delete", iac_value=True, live_value=False),
                ],
                security_relevant=True,
                significance="critical",
            )
        ],
        iac_only_resources=["aws_kms_key.unrelated"],
        cloud_only_resources=[],
    )


def _attack_path() -> AttackPath:
    return AttackPath(
        id="path-1",
        title="Wildcard role -> public bucket",
        description="An anonymous principal assumes the admin role and reads the data lake.",
        steps=[
            AttackStep(
                step_number=1,
                resource_id="aws_iam_role.admin",
                resource_type="aws_iam_role",
                action="sts:AssumeRole as any principal",
                permission_used="assume_role_policy: *",
                description="",
            ),
            AttackStep(
                step_number=2,
                resource_id="aws_s3_bucket.data",
                resource_type="aws_s3_bucket",
                action="s3:GetObject",
                permission_used="role policy allows s3:*",
                description="Exfiltrate the data lake.",
            ),
        ],
        entry_point="aws_iam_role.admin",
        target="aws_s3_bucket.data",
        findings_involved=["finding-1", "finding-2"],
        combined_severity=Severity.CRITICAL,
        blast_radius=BlastRadius(
            data_stores_reachable=["aws_s3_bucket.data"],
            compute_reachable=[],
            estimated_data_volume="~2 TB",
            services_affected=["s3", "iam"],
        ),
    )


def _investigations() -> list[ChildInvestigation]:
    return [
        ChildInvestigation(
            title="Wildcard trust to data lake",
            rationale="finding-1 and finding-2 share a network path.",
            findings_involved=["finding-1", "finding-2"],
            child_prompt=(
                "\n\n  Verify whether an anonymous attacker can assume aws_iam_role.admin\n"
                "  and then read aws_s3_bucket.data. Evidence required per hop.\t \n\n"
            ),
        ),
        ChildInvestigation(
            title="Isolated logging gap",
            rationale="",
            findings_involved=[],
            child_prompt="Check whether the missing CloudTrail hides the pivot.",
        ),
    ]


def _verified_full() -> VerifiedFinding:
    return VerifiedFinding(
        id="verified-1",
        title="Role trusts * <everyone> & assumes admin",
        verdict=Verdict.CONFIRMED,
        severity=Severity.CRITICAL,
        category="overprivilege",
        resources=[
            AffectedResource(
                resource_id="aws_iam_role.admin",
                resource_type="aws_iam_role",
                attribute="assume_role_policy",
                current_value='{"Principal": "*"}',
                recommended_value="scoped principal",
            )
        ],
        attack_path=_attack_path(),
        drift=_drift_report().drifted_resources[0],
        proof=Proof(
            method=ProofMethod.STATIC_ANALYSIS,
            evidence=["main.tf:12 assume_role_policy allows *"],
            scripts_executed=[],
            verification_tier="static",
        ),
        compliance_mappings=["CIS-1.16", "SOC2-CC6.1"],
        risk_score=9.25,
        remediation=RemediationSuggestion(
            finding_id="verified-1",
            description="Scope the trust policy.",
            diffs=[
                IaCDiff(
                    file_path="main.tf",
                    original_lines='  assume_role_policy = "*"',
                    patched_lines='  assume_role_policy = data.aws_iam_policy_document.scoped.json',
                    start_line=12,
                    end_line=12,
                )
            ],
            breaking_change=False,
            downtime_estimate="none",
            effort="trivial",
            alternative_approaches=["Use a permission boundary"],
        ),
        sarif_rule_id="cloudsecurity/iam/overprivilege",
        sarif_security_severity=9.0,
        iac_file="main.tf",
        iac_line=12,
        config_snippet='resource "aws_iam_role" "admin" {\n  assume_role_policy = "*"\n}',
        description="aws_iam_role.admin has a wildcard trust policy.",
        fingerprint="fp-iam-1",
        hunter_strategy="iam",
        drop_reason=None,
    )


def _verified_bare() -> VerifiedFinding:
    # Every optional at its default: exercises `null`, `[]`, `{}` and the
    # float-zero rendering ("0.0", which Go's encoding/json would write as "0").
    return VerifiedFinding(
        id="verified-2",
        title="",
        verdict=Verdict.INCONCLUSIVE,
        severity=Severity.INFO,
        category="",
        fingerprint="fp-bare-2",
    )


def gen_chain_goldens() -> None:
    print("chain goldens:")
    os.makedirs(CHAIN_GOLDEN, exist_ok=True)

    graph_text = json.dumps(CHAIN_GRAPH, indent=2)
    emit(CHAIN_GOLDEN, "graph.json", graph_text)
    emit(CHAIN_GOLDEN, "graph_not_object.json", json.dumps([1, 2], indent=2))

    graph_path = os.path.join(CHAIN_GOLDEN, "graph.json")
    not_object_path = os.path.join(CHAIN_GOLDEN, "graph_not_object.json")
    missing_path = os.path.join(CHAIN_GOLDEN, "does-not-exist.json")

    pair = _chain_findings_pair()
    single = _chain_findings_single()
    drift = _drift_report()
    investigations = _investigations()

    emit(
        CHAIN_GOLDEN,
        "inputs.json",
        json.dumps(
            {
                "findings_pair": [f.model_dump(mode="json") for f in pair],
                "findings_single": [f.model_dump(mode="json") for f in single],
                "drift_report": drift.model_dump(mode="json"),
                "investigations": [i.model_dump(mode="json") for i in investigations],
            },
            indent=2,
        ),
    )

    template = path_constructor.PROMPT_PATH.read_text(encoding="utf-8")

    # a: two findings, a real graph, a drift report.
    emit(
        CHAIN_GOLDEN,
        "parent_prompt_a.txt",
        path_constructor._build_parent_prompt(
            template=template,
            findings=pair,
            resource_graph_path=graph_path,
            drift_report=drift,
            max_paths=5,
            max_children=3,
        ),
    )
    # b: the graph file does not exist and there is no drift report.
    emit(
        CHAIN_GOLDEN,
        "parent_prompt_b.txt",
        path_constructor._build_parent_prompt(
            template=template,
            findings=pair,
            resource_graph_path=missing_path,
            drift_report=None,
            max_paths=1,
            max_children=1,
        ),
    )
    # c: the graph file's top level is a list, and the finding touches nothing.
    emit(
        CHAIN_GOLDEN,
        "parent_prompt_c.txt",
        path_constructor._build_parent_prompt(
            template=template,
            findings=single,
            resource_graph_path=not_object_path,
            drift_report=None,
            max_paths=2,
            max_children=4,
        ),
    )

    emit(CHAIN_GOLDEN, "child_prompt_a.txt", path_constructor._child_prompt(investigations[0], 5))
    emit(CHAIN_GOLDEN, "child_prompt_b.txt", path_constructor._child_prompt(investigations[1], 1))


def gen_prove_goldens() -> None:
    print("prove goldens:")
    os.makedirs(PROVE_GOLDEN, exist_ok=True)

    full, bare = _chain_findings_pair()
    path = _attack_path()

    emit(
        PROVE_GOLDEN,
        "inputs.json",
        json.dumps(
            {
                "finding_full": full.model_dump(mode="json"),
                "finding_bare": bare.model_dump(mode="json"),
                "attack_path": path.model_dump(mode="json"),
                "repo_path": REPO,
            },
            indent=2,
        ),
    )

    emit(
        PROVE_GOLDEN,
        "static_prompt_a.txt",
        capture(lambda app: static_prover.run_static_prover(app, REPO, full, path, 1)),
    )
    emit(
        PROVE_GOLDEN,
        "static_prompt_b.txt",
        capture(lambda app: static_prover.run_static_prover(app, REPO, bare, None, 2)),
    )
    emit(
        PROVE_GOLDEN,
        "live_prompt_a.txt",
        capture(lambda app: live_prover.run_live_prover(app, REPO, full, path, 2)),
    )
    emit(
        PROVE_GOLDEN,
        "live_prompt_b.txt",
        capture(lambda app: live_prover.run_live_prover(app, REPO, bare, None, 3)),
    )


def gen_remediate_goldens() -> None:
    print("remediate goldens:")
    os.makedirs(REMEDIATE_GOLDEN, exist_ok=True)

    full = _verified_full()
    bare = _verified_bare()

    emit(
        REMEDIATE_GOLDEN,
        "inputs.json",
        json.dumps(
            {
                "verified_full": full.model_dump(mode="json"),
                "verified_bare": bare.model_dump(mode="json"),
                "repo_path": REPO,
            },
            indent=2,
        ),
    )

    emit(
        REMEDIATE_GOLDEN,
        "fix_prompt_a.txt",
        capture(lambda app: fix_generator.run_fix_generator(app, REPO, full)),
    )
    emit(
        REMEDIATE_GOLDEN,
        "fix_prompt_b.txt",
        capture(lambda app: fix_generator.run_fix_generator(app, REPO, bare)),
    )


def main() -> None:
    gen_tf_fixture_copy()
    gen_parser_ground_truth()
    gen_expressions_ground_truth()
    gen_prompts()
    gen_hunt_fixture_copy()
    gen_graph_context_goldens()
    gen_hunt_prompts()
    gen_chain_goldens()
    gen_prove_goldens()
    gen_remediate_goldens()
    print("done")


if __name__ == "__main__":
    main()
