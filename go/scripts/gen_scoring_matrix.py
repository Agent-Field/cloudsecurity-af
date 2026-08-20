#!/usr/bin/env python
"""Emit the exhaustive compute_risk_score() ground truth for the Go scoring test.

Writes ``go/internal/scoring/testdata/risk_score_matrix.json``: every
(Severity x EvidenceMethod x Exposure x has_attack_path x has_drift) combination
— 5*6*5*2*2 = 600 rows — with the exact float Python's
``round(min(max(score, 0.0), 10.0), 2)`` produces. The Go test replays the
matrix through scoring.ComputeRiskScore and requires bit-identical float64s,
which is what pins the banker's-rounding helper.

Regenerate with (never ``python3``, which lacks the deps):

    PYTHONPATH=<worktree>/src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python \
        go/scripts/gen_scoring_matrix.py
"""

from __future__ import annotations

import json
from pathlib import Path

from cloudsecurity_af.scoring import EvidenceMethod, Exposure, Severity, compute_risk_score


def main() -> None:
    rows = []
    for severity in Severity:
        for evidence in EvidenceMethod:
            for exposure in Exposure:
                for has_attack_path in (False, True):
                    for has_drift in (False, True):
                        rows.append(
                            {
                                "severity": severity.value,
                                "evidence_method": evidence.value,
                                "exposure": exposure.value,
                                "has_attack_path": has_attack_path,
                                "has_drift": has_drift,
                                "score": compute_risk_score(
                                    severity,
                                    evidence,
                                    exposure,
                                    has_attack_path=has_attack_path,
                                    has_drift=has_drift,
                                ),
                            }
                        )
    target = Path(__file__).resolve().parent.parent / "internal" / "scoring" / "testdata" / "risk_score_matrix.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(rows, indent=2) + "\n")
    print(f"wrote {target} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
