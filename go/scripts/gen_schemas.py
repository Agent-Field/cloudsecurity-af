#!/usr/bin/env python3
"""Committed schema-fixture generator for the cloudsecurity-af Go port.

This script is the SINGLE SOURCE OF TRUTH for the JSON-schema fixtures under
``go/internal/harnessx/testdata/schemas/``. It imports the REAL pydantic models
that this repo hands to ``app.harness(..., schema=...)`` and emits, for each
one, EXACTLY the schema the Python SDK would build from it — i.e.
``model_json_schema()`` — so the Go harness embeds that schema instead of
reflecting its Go destination struct with invopop.

WHY THIS EXISTS
---------------
The Go SDK (pinned ``sdk/go`` in ``go/go.mod``) validates every parsed harness
output against the schema map with a strict JSON-Schema validator
(``santhosh-tekuri/jsonschema/v5`` in ``harness/schema.go`` ->
``validateAgainstSchema``) and drives its schema-retry loop off validation
failures. An invopop-reflected schema marks EVERY field required, renders
pointer fields non-nullable and sets ``additionalProperties: false``. Pydantic
instead makes defaulted fields optional, ``X | None`` fields nullable, and
ignores extra keys — so Python-valid model output would be REJECTED by the Go
node: wasted retries, fallback outputs, lost findings. Embedding the pydantic
schema restores parity on those three axes.

NO DEVIATIONS
-------------
Unlike the pr-af port, cloudsecurity-af has no ``BeforeValidator``-normalized
enums (``scoring.Severity`` and friends are plain ``str, Enum`` classes with no
coercion), so every fixture is a verbatim ``model_json_schema()`` dump. If a
coercing validator is ever added, relax the corresponding enum here and say so.

FIXTURE NAMING
--------------
``harnessx.SchemaFor[T]`` resolves a fixture by the Go destination type's NAME:
``testdata/schemas/<TypeName>.json``. The port contract requires Go struct names
to equal the pydantic class names exactly, so the dict below is keyed by the
pydantic class name and nothing else needs to stay in sync.

The model list is the complete set of ``schema=`` call sites, enumerated with::

    grep -rn 'schema=' src/

    src/cloudsecurity_af/agents/recon/iac_reader.py:48              ResourceInventory
    src/cloudsecurity_af/agents/recon/cloud_connector.py:33         ResourceInventory
    src/cloudsecurity_af/agents/recon/resource_graph_builder.py:48  ResourceGraph
    src/cloudsecurity_af/agents/recon/drift_detector.py:35          DriftReport
    src/cloudsecurity_af/agents/hunt/iam_hunter.py:52               HuntResult
    src/cloudsecurity_af/agents/hunt/network_hunter.py:72           HuntResult
    src/cloudsecurity_af/agents/hunt/data_hunter.py:74              HuntResult
    src/cloudsecurity_af/agents/hunt/secrets_hunter.py:66           HuntResult
    src/cloudsecurity_af/agents/hunt/compute_hunter.py:68           HuntResult
    src/cloudsecurity_af/agents/hunt/logging_hunter.py:52           HuntResult
    src/cloudsecurity_af/agents/hunt/compliance_hunter.py:52        HuntResult
    src/cloudsecurity_af/agents/chain/path_constructor.py:163       PathInvestigationPlan
    src/cloudsecurity_af/agents/chain/path_constructor.py:180       AttackPath
    src/cloudsecurity_af/agents/prove/static_prover.py:70           VerifiedFinding
    src/cloudsecurity_af/agents/prove/live_prover.py:70             VerifiedFinding
    src/cloudsecurity_af/agents/remediate/fix_generator.py:59       RemediationSuggestion
    src/cloudsecurity_af/orchestrator.py:47                         (_PhaseHarnessProxy passthrough)

There are no ``app.ai(schema=...)`` call sites in this repo.

REPRODUCE (from the repo root)::

    PYTHONPATH=src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python go/scripts/gen_schemas.py

Deterministic and idempotent: rerunning overwrites the fixtures with identical
bytes unless a pydantic model changed — exactly the signal the Go drift test
exists to catch.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

# Make `cloudsecurity_af` importable when run from the repo root without install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_REPO_ROOT, "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from cloudsecurity_af.agents.chain.path_constructor import PathInvestigationPlan  # noqa: E402
from cloudsecurity_af.schemas.chain import AttackPath  # noqa: E402
from cloudsecurity_af.schemas.hunt import HuntResult  # noqa: E402
from cloudsecurity_af.schemas.prove import RemediationSuggestion, VerifiedFinding  # noqa: E402
from cloudsecurity_af.schemas.recon import DriftReport, ResourceGraph, ResourceInventory  # noqa: E402

TESTDATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "internal",
    "harnessx",
    "testdata",
    "schemas",
)

# fixture basename (== the Go destination type name == the pydantic class name)
# -> the pydantic model. go:embed skips names beginning with "_" or "." unless
# the pattern uses the all: prefix, so every basename here must be plain.
MODELS: dict[str, Any] = {
    "AttackPath": AttackPath,
    "DriftReport": DriftReport,
    "HuntResult": HuntResult,
    "PathInvestigationPlan": PathInvestigationPlan,
    "RemediationSuggestion": RemediationSuggestion,
    "ResourceGraph": ResourceGraph,
    "ResourceInventory": ResourceInventory,
    "VerifiedFinding": VerifiedFinding,
}


def main() -> int:
    os.makedirs(TESTDATA, exist_ok=True)

    written = []
    for name, model in sorted(MODELS.items()):
        schema = model.model_json_schema()
        path = os.path.join(TESTDATA, f"{name}.json")
        # sort_keys keeps the bytes stable across pydantic versions that reorder
        # their dict construction; indent=2 matches the repo's JSON style.
        #
        # It also makes the committed bytes match what the reader will emit.
        # harnessx decodes this fixture into a map[string]any and the Go SDK
        # renders THAT with json.MarshalIndent, which sorts map keys — so the
        # JSON Schema block appended to every harness prompt is alphabetised in
        # Go and in pydantic declaration order in Python. Same content, same
        # byte length, different order; recorded as divergence 7 in
        # go/README.md and in internal/harnessx/schema.go. Writing the fixture
        # unsorted would only make the committed file disagree with the prompt
        # as well.
        payload = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        written.append(os.path.relpath(path, _REPO_ROOT))

    for path in written:
        print(f"wrote {path}")

    # Fail loudly if a stale fixture is left behind after a model is removed:
    # an orphan would still be embedded and silently used by SchemaFor.
    expected = {f"{name}.json" for name in MODELS}
    actual = {entry for entry in os.listdir(TESTDATA) if entry.endswith(".json")}
    orphans = sorted(actual - expected)
    if orphans:
        print(f"ERROR: orphaned fixtures (delete them): {orphans}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
