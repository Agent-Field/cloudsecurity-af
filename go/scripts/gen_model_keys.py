#!/usr/bin/env python
"""Emit the pydantic ground truth the Go schema-parity test asserts against.

For every pydantic model reachable from ``src/cloudsecurity_af`` (every class in
``schemas/*.py`` plus the two models declared inside
``agents/chain/path_constructor.py``) this writes, into
``go/internal/schemas/testdata/model_keys.json``:

* ``module`` — the defining Python module, so a reviewer can diff coverage.
* ``keys``   — ``list(Model(**minimal_required).model_dump().keys())`` in
  declaration order. The Go test asserts the marshaled key SET of the
  corresponding ``New<Model>()`` value matches exactly (no ``omitempty``
  anywhere: ``model_dump()`` emits every field).
* ``dump``   — ``jsonable_encoder(model_dump())`` of that same instance, i.e.
  the exact JSON the control plane sees when a reasoner returns the model.
  The Go test compares this value-by-value for every key not listed in
  ``nondeterministic``, which pins every pydantic default (``"terraform"``,
  ``["us-east-1"]``, ``"moderate"``, ``Severity.HIGH`` …).
* ``nondeterministic`` — fields whose default is ``uuid4()``/``datetime.now``
  and therefore cannot be compared by value.

Regenerate with (never ``python3``, which lacks the deps):

    PYTHONPATH=<worktree>/src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python \
        go/scripts/gen_model_keys.py
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.encoders import jsonable_encoder

from cloudsecurity_af.agents.chain.path_constructor import ChildInvestigation, PathInvestigationPlan
from cloudsecurity_af.schemas.chain import AttackPath, AttackStep, BlastRadius, ChainResult
from cloudsecurity_af.schemas.hunt import AffectedResource, HuntResult, RawFinding
from cloudsecurity_af.schemas.input import CloudConfig, CloudSecurityInput
from cloudsecurity_af.schemas.output import CloudSecurityScanResult, ScanMetrics, ScanProgress
from cloudsecurity_af.schemas.prove import (
    IaCDiff,
    Proof,
    ProofMethod,
    RemediationSuggestion,
    Verdict,
    VerifiedFinding,
)
from cloudsecurity_af.schemas.recon import (
    ConfigDiff,
    DriftedResource,
    DriftReport,
    Module,
    Output,
    ProviderConfig,
    ReconResult,
    Resource,
    ResourceGraph,
    ResourceInventory,
    Variable,
)
from cloudsecurity_af.schemas.views import FindingForChain, FindingForDedup, FindingForProver
from cloudsecurity_af.scoring import Severity

# The fixed timestamp the Go test also uses for CloudSecurityScanResult, so the
# "timestamp" key can be compared by value instead of being skipped.
FIXED_TS = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)

# Stand-in written into the fixture for every uuid4()-defaulted field.
UUID_PLACEHOLDER = "<uuid4>"

# model -> (minimal required kwargs, nondeterministic field names).
#
# "minimal required" means exactly the fields pydantic refuses to default; every
# required string is passed as "" and every required int as 0 so the resulting
# dump is the pure default vector the Go New<Model>() constructor must match.
MODELS: list[tuple[str, type, dict[str, Any], list[str]]] = [
    # --- schemas/recon.py ---
    ("Variable", Variable, {"name": ""}, []),
    ("Output", Output, {"name": ""}, []),
    ("ProviderConfig", ProviderConfig, {"name": ""}, []),
    ("Module", Module, {"name": "", "source": ""}, []),
    (
        "Resource",
        Resource,
        {"id": "", "type": "", "name": "", "provider": "", "file_path": ""},
        [],
    ),
    ("ResourceInventory", ResourceInventory, {"inventory_saved_path": ""}, []),
    ("ResourceGraph", ResourceGraph, {"graph_saved_path": ""}, []),
    ("ConfigDiff", ConfigDiff, {"attribute": ""}, []),
    ("DriftedResource", DriftedResource, {"resource_id": "", "resource_type": ""}, []),
    ("DriftReport", DriftReport, {}, []),
    # ReconResult's `inventory`/`resource_graph` default_factories raise (both
    # inner models have a required field), so the "minimal" instance must pass
    # them explicitly. See doc.go "ReconResult" parity note.
    (
        "ReconResult",
        ReconResult,
        {
            "inventory": ResourceInventory(inventory_saved_path=""),
            "resource_graph": ResourceGraph(graph_saved_path=""),
        },
        [],
    ),
    # --- schemas/hunt.py ---
    (
        "AffectedResource",
        AffectedResource,
        {"resource_id": "", "resource_type": "", "attribute": ""},
        [],
    ),
    (
        "RawFinding",
        RawFinding,
        {"hunter_strategy": "", "title": "", "description": "", "category": ""},
        ["id", "fingerprint"],
    ),
    ("HuntResult", HuntResult, {}, []),
    # --- schemas/chain.py ---
    (
        "AttackStep",
        AttackStep,
        {
            "step_number": 0,
            "resource_id": "",
            "resource_type": "",
            "action": "",
            "permission_used": "",
        },
        [],
    ),
    ("BlastRadius", BlastRadius, {}, []),
    (
        "AttackPath",
        AttackPath,
        {"title": "", "description": "", "entry_point": "", "target": ""},
        ["id"],
    ),
    ("ChainResult", ChainResult, {}, []),
    # --- schemas/prove.py ---
    ("Proof", Proof, {}, []),
    (
        "IaCDiff",
        IaCDiff,
        {"file_path": "", "original_lines": "", "patched_lines": ""},
        [],
    ),
    ("RemediationSuggestion", RemediationSuggestion, {"description": ""}, []),
    (
        "VerifiedFinding",
        VerifiedFinding,
        {
            "title": "",
            "verdict": Verdict.CONFIRMED,
            "severity": Severity.MEDIUM,
            "category": "",
        },
        ["id", "fingerprint"],
    ),
    # --- schemas/input.py ---
    ("CloudConfig", CloudConfig, {}, []),
    ("CloudSecurityInput", CloudSecurityInput, {"repo_url": ""}, []),
    # --- schemas/output.py ---
    (
        "CloudSecurityScanResult",
        CloudSecurityScanResult,
        {
            "repository": "",
            "commit_sha": "",
            "timestamp": FIXED_TS,
            "depth_profile": "",
            "tier": 0,
        },
        [],
    ),
    (
        "ScanProgress",
        ScanProgress,
        {
            "phase": "",
            "phase_progress": 0.0,
            "agents_total": 0,
            "agents_completed": 0,
            "agents_running": 0,
            "findings_so_far": 0,
            "elapsed_seconds": 0.0,
            "estimated_remaining_seconds": 0.0,
            "cost_so_far_usd": 0.0,
        },
        [],
    ),
    (
        "ScanMetrics",
        ScanMetrics,
        {"duration_seconds": 0.0, "agent_invocations": 0, "cost_usd": 0.0},
        [],
    ),
    # --- schemas/views.py ---
    (
        "FindingForDedup",
        FindingForDedup,
        {
            "id": "",
            "fingerprint": "",
            "title": "",
            "iac_file": "",
            "iac_line": 0,
            "category": "",
            "hunter_strategy": "",
            "estimated_severity": "",
        },
        [],
    ),
    (
        "FindingForProver",
        FindingForProver,
        {
            "id": "",
            "title": "",
            "description": "",
            "category": "",
            "hunter_strategy": "",
            "iac_file": "",
            "iac_line": 0,
            "config_snippet": "",
        },
        [],
    ),
    (
        "FindingForChain",
        FindingForChain,
        {"id": "", "title": "", "description": "", "category": ""},
        [],
    ),
    # --- agents/chain/path_constructor.py (BaseModels outside schemas/) ---
    ("ChildInvestigation", ChildInvestigation, {"title": "", "child_prompt": ""}, []),
    ("PathInvestigationPlan", PathInvestigationPlan, {}, []),
]


def main() -> None:
    out: dict[str, Any] = {}
    for name, model, kwargs, nondet in MODELS:
        instance = model(**kwargs)
        dump = instance.model_dump()
        encoded = jsonable_encoder(dump)
        # Keep the committed fixture byte-stable across regenerations: uuid4()
        # defaults are replaced by a placeholder. The Go test skips these keys
        # for value comparison and instead asserts the Go default is a distinct,
        # well-formed RFC 4122 v4 string.
        for field in nondet:
            encoded[field] = UUID_PLACEHOLDER
        out[name] = {
            "module": model.__module__,
            "keys": list(dump.keys()),
            "dump": encoded,
            "nondeterministic": nondet,
        }
    target = Path(__file__).resolve().parent.parent / "internal" / "schemas" / "testdata" / "model_keys.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(f"wrote {target} ({len(out)} models)")


if __name__ == "__main__":
    main()
