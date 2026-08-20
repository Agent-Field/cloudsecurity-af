#!/usr/bin/env python3
"""Golden generator for internal/aix.Strictify.

Runs the REAL AgentField Python SDK function that `app.ai(schema=Model)` uses —
``agentfield.agent_ai._strictify_openai_schema`` — over the committed pydantic
schema fixtures, and writes its output to ``go/internal/aix/testdata/``. The Go
test then strictifies the same fixtures and compares.

The inputs are the fixtures under ``go/internal/harnessx/testdata/schemas/``,
which gen_schemas.py writes with ``sort_keys=True``; that matters because the
strictifier's ``required`` list is ``list(props.keys())``, i.e. the input dict's
insertion order. With a sorted input, Python's order and the Go port's (sorted)
order are the same, so the goldens compare byte-for-byte after both sides are
re-dumped with sorted keys.

REPRODUCE (from the repo root)::

    ~/.agentfield/packages/cloudsecurity-af/venv/bin/python go/scripts/gen_strictify_golden.py
"""

from __future__ import annotations

import json
import os
import sys

from agentfield.agent_ai import _strictify_openai_schema

_GO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMAS = os.path.join(_GO_ROOT, "internal", "harnessx", "testdata", "schemas")
TESTDATA = os.path.join(_GO_ROOT, "internal", "aix", "testdata")

# One flat model and one with a deep $defs graph, which is where the recursion
# into $defs / properties / items / anyOf is actually exercised.
FIXTURES = ["PathInvestigationPlan", "HuntResult", "VerifiedFinding"]


def main() -> int:
    os.makedirs(TESTDATA, exist_ok=True)
    for name in FIXTURES:
        src = os.path.join(SCHEMAS, f"{name}.json")
        with open(src, encoding="utf-8") as handle:
            schema = json.load(handle)

        strict = _strictify_openai_schema(schema)

        dst = os.path.join(TESTDATA, f"strict_{name}.json")
        with open(dst, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(strict, indent=2, sort_keys=True) + "\n")
        print(f"wrote {os.path.relpath(dst, _GO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
