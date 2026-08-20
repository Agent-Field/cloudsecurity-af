package phases

import (
	"context"
	"sort"
	"sync"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// PrioritizeFindings ports phases.py _prioritize_findings:
//
//	sorted(findings, key=lambda f: sev.get(f.estimated_severity, 0), reverse=True)
//
// Python's sorted() is stable and `reverse=True` does NOT reverse ties (CPython
// reverses the list, sorts, and reverses again), so findings of equal severity
// keep their input order — which is exactly sort.SliceStable with a strict
// greater-than comparison. It returns a NEW slice; the input is not reordered,
// matching sorted().
func PrioritizeFindings(findings []schemas.RawFinding) []schemas.RawFinding {
	out := make([]schemas.RawFinding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank[out[i].EstimatedSeverity] > severityRank[out[j].EstimatedSeverity]
	})
	return out
}

// ProvePhase ports src/cloudsecurity_af/reasoners/phases.py prove_phase.
//
// Python:
//
//	@router.reasoner()
//	async def prove_phase(repo_path: str, hunt_result: dict[str, Any], chain_result: dict[str, Any],
//	                      depth: str = "standard", tier: int = 1,
//	                      max_concurrent_provers: int = 3) -> dict[str, Any]:
//
// DAG shape: K children, all of them run_static_prover when tier < 2 and all of
// them run_live_prover otherwise, under a semaphore of
// max(1, min(max_concurrent_provers, len(selected))).
//
// Python parity notes:
//
//   - K = min(len(hunt.findings), DEPTH_PROVER_CAPS[depth]) — quick 20,
//     standard 30, thorough 10000 — over the severity-prioritized order.
//   - The `attack_path` kwarg is present ONLY for a finding that appears in
//     some AttackPath.findings_involved. Its value is the LAST path that names
//     the finding (`attack_path_map[fid] = path.model_dump()` overwrites), in
//     chain.attack_paths order.
//   - gather(return_exceptions=True): a failed prover does not abort the phase.
//     A transport/unwrap failure yields _fallback_verified(finding, str(exc));
//     a payload that will not bind yields
//     _fallback_verified(finding, f"Schema parse failed: {exc}"). The evidence
//     text therefore embeds a Go error string where Python embeds a Python
//     exception string — the one place the two nodes' bytes cannot match.
//   - `_unwrap(raw, "prover")` uses the literal name "prover", NOT the prover
//     reasoner's name, so a failed envelope reads "prover failed: ...".
//   - The result dict's `verified` entries are model_dump(exclude_none=True);
//     the three counters are plain ints.
func ProvePhase(
	ctx context.Context,
	app appx.Caller,
	nodeID string,
	repoPath string,
	huntResult map[string]any,
	chainResult map[string]any,
	depth string,
	tier int,
	maxConcurrentProvers int,
) (afx.Payload, error) {
	hunt, err := afx.Bind[schemas.HuntResult](huntResult)
	if err != nil {
		return nil, err
	}
	chain, err := afx.Bind[schemas.ChainResult](chainResult)
	if err != nil {
		return nil, err
	}

	profile := config.NormalizeDepth(depth)
	proverCap := proverCapFor(profile)

	prioritized := PrioritizeFindings(hunt.Findings)
	selected := prioritized
	if len(selected) > proverCap {
		selected = selected[:proverCap]
	}

	// Python parity: `max(1, min(max_concurrent_provers, len(selected))) if selected else 1`.
	concurrencyLimit := 1
	if len(selected) > 0 {
		concurrencyLimit = maxConcurrentProvers
		if len(selected) < concurrencyLimit {
			concurrencyLimit = len(selected)
		}
		if concurrencyLimit < 1 {
			concurrencyLimit = 1
		}
	}
	sem := newSemaphore(concurrencyLimit)

	attackPathMap := make(map[string]map[string]any)
	for _, path := range chain.AttackPaths {
		dumped, dumpErr := afx.ToMap(path)
		if dumpErr != nil {
			return nil, dumpErr
		}
		for _, findingID := range path.FindingsInvolved {
			attackPathMap[findingID] = dumped
		}
	}

	proverName := "run_static_prover"
	if tier >= 2 {
		proverName = "run_live_prover"
	}

	type proveOutcome struct {
		raw any
		err error
	}
	outcomes := make([]proveOutcome, len(selected))

	var wg sync.WaitGroup
	for i := range selected {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem.acquire()
			defer sem.release()

			finding := selected[idx]
			dumped, dumpErr := afx.ToMap(finding)
			if dumpErr != nil {
				outcomes[idx] = proveOutcome{err: dumpErr}
				return
			}
			kwargs := map[string]any{
				"repo_path": repoPath,
				"finding":   dumped,
				"tier":      tier,
			}
			if attackPath, present := attackPathMap[finding.ID]; present {
				kwargs["attack_path"] = attackPath
			}
			raw, callErr := app.Call(ctx, nodeID+"."+proverName, kwargs)
			outcomes[idx] = proveOutcome{raw: raw, err: callErr}
		}(i)
	}
	wg.Wait()

	verified := make([]schemas.VerifiedFinding, 0, len(selected))
	for idx, outcome := range outcomes {
		finding := selected[idx]
		if outcome.err != nil {
			verified = append(verified, FallbackVerified(finding, outcome.err.Error()))
			continue
		}
		bound, bindErr := bindCallResult[schemas.VerifiedFinding](outcome.raw, "prover")
		if bindErr != nil {
			verified = append(verified, FallbackVerified(finding, "Schema parse failed: "+bindErr.Error()))
			continue
		}
		verified = append(verified, bound)
	}

	dumps := make([]afx.Payload, 0, len(verified))
	for _, v := range verified {
		dumped, dumpErr := afx.DumpExcludeNone(v)
		if dumpErr != nil {
			return nil, dumpErr
		}
		dumps = append(dumps, dumped)
	}

	notVerified := len(hunt.Findings) - len(selected)
	if notVerified < 0 {
		notVerified = 0
	}

	// Python parity — KEY ORDER. phases.py returns the dict LITERAL
	//
	//	{"verified": ..., "total_selected": ..., "total_findings": ...,
	//	 "not_verified": ...}
	//
	// and json.dumps preserves a dict's insertion order, so those four keys
	// reach the caller in that order. A Go map would put them on the wire
	// alphabetically (not_verified, total_findings, total_selected, verified).
	return afx.Payload{
		{K: "verified", V: dumps},
		{K: "total_selected", V: len(selected)},
		{K: "total_findings", V: len(hunt.Findings)},
		{K: "not_verified", V: notVerified},
	}, nil
}

// FallbackVerified ports phases.py _fallback_verified: the INCONCLUSIVE stand-in
// a finding gets when its prover call or its reply could not be used.
//
//	VerifiedFinding(
//	    id=..., title=..., verdict=INCONCLUSIVE, severity=finding.estimated_severity,
//	    category=..., resources=..., proof=Proof(method=STATIC_ANALYSIS, evidence=[error_msg]),
//	    iac_file=..., iac_line=..., config_snippet=..., description=..., fingerprint=...,
//	    hunter_strategy=..., sarif_rule_id=f"cloudsecurity/{hunter_strategy}/{category}",
//	    sarif_security_severity=0.0, drop_reason="prover_error")
//
// Every field NOT listed above keeps its pydantic default, so the Go port starts
// from schemas.NewVerifiedFinding() and overwrites — notably attack_path, drift
// and remediation stay nil (and are therefore dropped by exclude_none), while
// compliance_mappings stays [].
//
// Python parity: `id` and `fingerprint` are copied from the raw finding, so the
// uuid4 default_factories NewVerifiedFinding mints are always overwritten.
//
// Python parity: `resources` shares the RawFinding's list object in Python; the
// Go port copies the slice header, which is the same aliasing, and nothing
// mutates it afterwards.
func FallbackVerified(finding schemas.RawFinding, errorMsg string) schemas.VerifiedFinding {
	proof := schemas.NewProof()
	proof.Method = schemas.ProofMethodStaticAnalysis
	proof.Evidence = []string{errorMsg}

	dropReason := "prover_error"

	out := schemas.NewVerifiedFinding()
	out.ID = finding.ID
	out.Title = finding.Title
	out.Verdict = schemas.VerdictInconclusive
	out.Severity = finding.EstimatedSeverity
	out.Category = finding.Category
	out.Resources = finding.Resources
	out.Proof = proof
	out.IaCFile = finding.IaCFile
	out.IaCLine = finding.IaCLine
	out.ConfigSnippet = finding.ConfigSnippet
	out.Description = finding.Description
	out.Fingerprint = finding.Fingerprint
	out.HunterStrategy = finding.HunterStrategy
	out.SARIFRuleID = "cloudsecurity/" + finding.HunterStrategy + "/" + finding.Category
	out.SARIFSecuritySeverity = 0.0
	out.DropReason = &dropReason
	return out
}
