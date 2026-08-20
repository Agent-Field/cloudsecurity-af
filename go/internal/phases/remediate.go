package phases

import (
	"context"
	"sync"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// RemediationPhase ports src/cloudsecurity_af/reasoners/phases.py
// remediation_phase.
//
// Python:
//
//	@router.reasoner()
//	async def remediation_phase(repo_path: str, verified_findings: list[dict[str, Any]],
//	                            max_concurrent_remediations: int = 3) -> dict[str, Any]:
//
// DAG shape: one run_fix_generator child per CONFIRMED/LIKELY finding that does
// not already carry a remediation, under a semaphore of
// max(1, min(max_concurrent_remediations, len(needs_remediation))).
//
// Python parity notes:
//
//   - The early return when nothing needs remediation still re-dumps every
//     finding with exclude_none, so the reasoner's output shape is identical on
//     both branches.
//   - A failed generator call is swallowed (payload None) and a payload that
//     will not bind as a RemediationSuggestion is swallowed too; the finding
//     simply keeps remediation=None. No note, no error.
//   - Python counts the successes into a local `generated` that it never
//     returns. The counter is kept here for fidelity and explicitly discarded.
//   - The orchestrator hands this phase model_dump() (NOT exclude_none) output,
//     while the phase hands BACK exclude_none output. The asymmetry is Python's.
func RemediationPhase(
	ctx context.Context,
	app appx.Caller,
	nodeID string,
	repoPath string,
	verifiedFindings []map[string]any,
	maxConcurrentRemediations int,
) (afx.Payload, error) {
	findings := make([]schemas.VerifiedFinding, 0, len(verifiedFindings))
	for _, raw := range verifiedFindings {
		bound, err := afx.Bind[schemas.VerifiedFinding](raw)
		if err != nil {
			return nil, err
		}
		findings = append(findings, bound)
	}

	needsRemediation := make([]int, 0, len(findings))
	for idx, f := range findings {
		if (f.Verdict == schemas.VerdictConfirmed || f.Verdict == schemas.VerdictLikely) && f.Remediation == nil {
			needsRemediation = append(needsRemediation, idx)
		}
	}

	if len(needsRemediation) == 0 {
		return verifiedEnvelope(findings)
	}

	concurrencyLimit := maxConcurrentRemediations
	if len(needsRemediation) < concurrencyLimit {
		concurrencyLimit = len(needsRemediation)
	}
	if concurrencyLimit < 1 {
		concurrencyLimit = 1
	}
	sem := newSemaphore(concurrencyLimit)

	// payloads[i] mirrors the (idx, payload | None) tuple Python's gather
	// returns for needs_remediation[i].
	payloads := make([]map[string]any, len(needsRemediation))

	var wg sync.WaitGroup
	for slot, findingIdx := range needsRemediation {
		wg.Add(1)
		go func(slot, findingIdx int) {
			defer wg.Done()
			sem.acquire()
			defer sem.release()

			dumped, dumpErr := afx.ToMap(findings[findingIdx])
			if dumpErr != nil {
				return
			}
			raw, callErr := app.Call(ctx, nodeID+".run_fix_generator", map[string]any{
				"repo_path": repoPath,
				"finding":   dumped,
			})
			if callErr != nil {
				// Python parity: `except Exception: return (idx, None)`.
				return
			}
			payload, unwrapErr := afx.UnwrapStrict(raw, "run_fix_generator")
			if unwrapErr != nil {
				return
			}
			asMap, mapErr := afx.AsMap(payload, "run_fix_generator")
			if mapErr != nil {
				return
			}
			payloads[slot] = asMap
		}(slot, findingIdx)
	}
	wg.Wait()

	generated := 0
	for slot, payload := range payloads {
		if payload == nil {
			continue
		}
		suggestion, err := afx.Bind[schemas.RemediationSuggestion](payload)
		if err != nil {
			// Python parity: `except Exception: pass`.
			continue
		}
		findings[needsRemediation[slot]].Remediation = &suggestion
		generated++
	}
	// Python parity: `generated` is computed and never used.
	_ = generated

	return verifiedEnvelope(findings)
}

// verifiedEnvelope ports the two identical return statements of
// remediation_phase: `{"verified": [f.model_dump(exclude_none=True) for f in findings]}`.
func verifiedEnvelope(findings []schemas.VerifiedFinding) (afx.Payload, error) {
	dumps := make([]afx.Payload, 0, len(findings))
	for _, f := range findings {
		dumped, err := afx.DumpExcludeNone(f)
		if err != nil {
			return nil, err
		}
		dumps = append(dumps, dumped)
	}
	return afx.Payload{{K: "verified", V: dumps}}, nil
}
