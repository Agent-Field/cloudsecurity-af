package phases

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// huntResultMap builds prove_phase's `hunt_result` argument.
// Python parity: every list field of a model_dump() is a LIST, never null —
// `HuntResult(findings=None)` is a pydantic ValidationError — so the seeded
// empty slice must survive a call with no variadic arguments (which hands the
// helper a NIL slice).
func huntResultMap(t *testing.T, findings ...schemas.RawFinding) map[string]any {
	t.Helper()
	h := schemas.NewHuntResult()
	h.Findings = append(h.Findings, findings...)
	h.TotalRaw = len(findings)
	h.DeduplicatedCount = len(findings)
	h.StrategiesRun = []string{"iam"}
	return jsonMap(t, h)
}

// chainResultMap builds prove_phase's `chain_result` argument.
func chainResultMap(t *testing.T, paths ...schemas.AttackPath) map[string]any {
	t.Helper()
	c := schemas.NewChainResult()
	c.AttackPaths = append(c.AttackPaths, paths...)
	c.TotalPathsEvaluated = len(paths)
	c.ViablePaths = len(paths)
	return jsonMap(t, c)
}

func attackPath(id string, findingIDs ...string) schemas.AttackPath {
	p := schemas.NewAttackPath()
	p.ID = id
	p.Title = "t"
	p.Description = "d"
	p.EntryPoint = "e"
	p.Target = "t2"
	p.FindingsInvolved = findingIDs
	p.CombinedSeverity = scoring.SeverityHigh
	return p
}

// TestPrioritizeFindings_StableDescending reproduces the probe's
// PRIORITIZE ['cr', 'hi', 'lo', 'lo2'] — descending severity with ties in input
// order.
func TestPrioritizeFindings_StableDescending(t *testing.T) {
	in := []schemas.RawFinding{
		rawFinding("lo", scoring.SeverityLow, "a", "c"),
		rawFinding("cr", scoring.SeverityCritical, "b", "c"),
		rawFinding("lo2", scoring.SeverityLow, "c", "c"),
		rawFinding("hi", scoring.SeverityHigh, "d", "c"),
	}
	got := idsOf(PrioritizeFindings(in))
	if !equalStrings(got, []string{"cr", "hi", "lo", "lo2"}) {
		t.Fatalf("order = %v, want [cr hi lo lo2]", got)
	}
	// sorted() returns a NEW list; the input must be untouched.
	if !equalStrings(idsOf(in), []string{"lo", "cr", "lo2", "hi"}) {
		t.Fatalf("input was reordered: %v", idsOf(in))
	}
}

// TestProvePhase_ProbeParity reproduces the Python probe run end to end: two
// findings, one attack path naming the critical one, a prover that always
// raises, depth quick / tier 1.
//
//	PROVE_CALLS [('cloudsecurity.run_static_prover', ['attack_path','finding','repo_path','tier']),
//	             ('cloudsecurity.run_static_prover', ['finding','repo_path','tier'])]
//	PROVE_COUNTS {'total_selected': 2, 'total_findings': 2, 'not_verified': 0}
//	PROVE_EVIDENCE [['prover down'], ['prover down']]
func TestProvePhase_ProbeParity(t *testing.T) {
	hunt := huntResultMap(t,
		rawFinding("p1", scoring.SeverityCritical, "a", "public_access"),
		rawFinding("p2", scoring.SeverityLow, "b", "public_access"),
	)
	chain := chainResultMap(t, attackPath("ap1", "p1"))

	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return nil, errors.New("prover down")
	}}

	out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chain, "quick", 1, 3)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}

	if got := fake.CallTargets(); !equalStrings(got, []string{
		testNodeID + ".run_static_prover", testNodeID + ".run_static_prover"}) {
		t.Fatalf("targets = %v", got)
	}
	// The two provers run concurrently, so the RECORDED order is not
	// meaningful (Python's gather has the same property); key the assertions on
	// the finding each call carried. p1 is the one named by the attack path.
	byFinding := map[string]map[string]any{}
	for _, c := range fake.Calls {
		finding := jsonMap(t, c.Input["finding"])
		byFinding[finding["id"].(string)] = c.Input
	}
	if got := keysOf(byFinding["p1"]); !equalStrings(got, []string{"attack_path", "finding", "repo_path", "tier"}) {
		t.Fatalf("p1 prover kwargs = %v", got)
	}
	if got := keysOf(byFinding["p2"]); !equalStrings(got, []string{"finding", "repo_path", "tier"}) {
		t.Fatalf("p2 prover kwargs = %v", got)
	}
	if byFinding["p1"]["repo_path"] != "/repo" || byFinding["p1"]["tier"] != 1 {
		t.Fatalf("kwargs values = %#v", byFinding["p1"])
	}

	if pm(out)["total_selected"] != 2 || pm(out)["total_findings"] != 2 || pm(out)["not_verified"] != 0 {
		t.Fatalf("counters = %#v", out)
	}
	verified := verifiedList(t, out)
	if len(verified) != 2 {
		t.Fatalf("verified = %d", len(verified))
	}
	for i, v := range verified {
		evidence := proofEvidence(t, v)
		if len(evidence) != 1 || evidence[0] != "prover down" {
			t.Fatalf("verified[%d] evidence = %v", i, evidence)
		}
		if v["verdict"] != "inconclusive" || v["drop_reason"] != "prover_error" {
			t.Fatalf("verified[%d] = %#v", i, v)
		}
	}
	// exclude_none: the three optional model fields are absent, matching the
	// probe's PROVE_VERIFIED_KEYS.
	wantKeys := []string{
		"category", "compliance_mappings", "config_snippet", "description", "drop_reason",
		"fingerprint", "hunter_strategy", "iac_file", "iac_line", "id", "proof", "resources",
		"risk_score", "sarif_rule_id", "sarif_security_severity", "severity", "title", "verdict",
	}
	if got := keysOf(verified[0]); !equalStrings(got, wantKeys) {
		t.Fatalf("verified keys = %v\nwant %v", got, wantKeys)
	}
}

// TestProvePhase_TierSelectsProver: tier < 2 -> run_static_prover, else
// run_live_prover.
func TestProvePhase_TierSelectsProver(t *testing.T) {
	cases := []struct {
		tier int
		want string
	}{
		{tier: 0, want: "run_static_prover"},
		{tier: 1, want: "run_static_prover"},
		{tier: 2, want: "run_live_prover"},
		{tier: 3, want: "run_live_prover"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("tier%d", tc.tier), func(t *testing.T) {
			hunt := huntResultMap(t, rawFinding("p1", scoring.SeverityHigh, "a", "c"))
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
				if in["tier"] != tc.tier {
					t.Errorf("tier kwarg = %v, want %d", in["tier"], tc.tier)
				}
				return nil, errors.New("x")
			}}
			if _, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt,
				chainResultMap(t), "standard", tc.tier, 3); err != nil {
				t.Fatalf("ProvePhase: %v", err)
			}
			if got := fake.CallTargets(); !equalStrings(got, []string{testNodeID + "." + tc.want}) {
				t.Fatalf("targets = %v, want %s", got, tc.want)
			}
		})
	}
}

// TestProvePhase_DepthCapsSelection pins DEPTH_PROVER_CAPS (quick 20 —
// tests/test_config.py's 10 is stale — standard 30, thorough 10000) and the
// derived counters.
func TestProvePhase_DepthCapsSelection(t *testing.T) {
	cases := []struct {
		depth           string
		findings        int
		wantSelected    int
		wantNotVerified int
	}{
		{depth: "quick", findings: 25, wantSelected: 20, wantNotVerified: 5},
		{depth: "standard", findings: 25, wantSelected: 25, wantNotVerified: 0},
		{depth: "standard", findings: 40, wantSelected: 30, wantNotVerified: 10},
		{depth: "thorough", findings: 40, wantSelected: 40, wantNotVerified: 0},
		{depth: "bogus", findings: 40, wantSelected: 30, wantNotVerified: 10},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s-%d", tc.depth, tc.findings), func(t *testing.T) {
			findings := make([]schemas.RawFinding, 0, tc.findings)
			for i := 0; i < tc.findings; i++ {
				findings = append(findings, rawFinding(fmt.Sprintf("f%02d", i), scoring.SeverityMedium,
					fmt.Sprintf("fp%02d", i), "c"))
			}
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				return nil, errors.New("x")
			}}
			out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
				huntResultMap(t, findings...), chainResultMap(t), tc.depth, 1, 3)
			if err != nil {
				t.Fatalf("ProvePhase: %v", err)
			}
			if len(fake.Calls) != tc.wantSelected {
				t.Fatalf("calls = %d, want %d", len(fake.Calls), tc.wantSelected)
			}
			if pm(out)["total_selected"] != tc.wantSelected {
				t.Errorf("total_selected = %v, want %d", pm(out)["total_selected"], tc.wantSelected)
			}
			if pm(out)["total_findings"] != tc.findings {
				t.Errorf("total_findings = %v, want %d", pm(out)["total_findings"], tc.findings)
			}
			if pm(out)["not_verified"] != tc.wantNotVerified {
				t.Errorf("not_verified = %v, want %d", pm(out)["not_verified"], tc.wantNotVerified)
			}
		})
	}
}

// TestProvePhase_AttackPathMapLastPathWins: attack_path_map[fid] is overwritten
// by every later path that names the finding, so the LAST one is passed.
func TestProvePhase_AttackPathMapLastPathWins(t *testing.T) {
	hunt := huntResultMap(t, rawFinding("p1", scoring.SeverityHigh, "a", "c"))
	chain := chainResultMap(t, attackPath("first", "p1"), attackPath("second", "p1"))

	var captured map[string]any
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
		captured = in
		return nil, errors.New("x")
	}}
	if _, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chain, "standard", 1, 3); err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	ap, ok := captured["attack_path"].(map[string]any)
	if !ok {
		t.Fatalf("attack_path is %T", captured["attack_path"])
	}
	if ap["id"] != "second" {
		t.Fatalf("attack_path id = %v, want second", ap["id"])
	}
}

// TestProvePhase_SchemaParseFailureFallback covers the second _fallback_verified
// arm, whose evidence is prefixed "Schema parse failed: ".
func TestProvePhase_SchemaParseFailureFallback(t *testing.T) {
	cases := []struct {
		name       string
		reply      map[string]any
		wantSuffix string
	}{
		{
			name:       "non dict payload",
			reply:      map[string]any{"output": "a string"},
			wantSuffix: "prover returned non-dict payload: str",
		},
		{
			// Every OTHER required field is present, so the only thing the
			// bind can fail on is the enum — mirroring pydantic, which reports
			// the missing fields AND the bad value when both are wrong.
			name: "invalid verdict enum",
			reply: map[string]any{
				"title": "t", "verdict": "bogus", "severity": "high", "category": "c",
			},
			wantSuffix: `"bogus" is not a valid Verdict`,
		},
		{
			// Python: VerifiedFinding.model_validate({}) raises
			// "4 validation errors for VerifiedFinding ... Field required", so
			// prove_phase takes the same _fallback_verified branch. Before the
			// port enforced required fields this reply bound successfully to a
			// finding with verdict "" and severity "" — uncounted in the
			// verdict tallies and dropped by the severity threshold.
			name:       "missing required fields",
			reply:      map[string]any{},
			wantSuffix: "4 validation errors for VerifiedFinding: title, verdict, severity, category: Field required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hunt := huntResultMap(t, rawFinding("p1", scoring.SeverityHigh, "fp1", "c"))
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				return tc.reply, nil
			}}
			out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chainResultMap(t), "standard", 1, 3)
			if err != nil {
				t.Fatalf("ProvePhase: %v", err)
			}
			verified := verifiedList(t, out)
			evidence := proofEvidence(t, verified[0])
			got := evidence[0].(string)
			if !strings.HasPrefix(got, "Schema parse failed: ") {
				t.Fatalf("evidence = %q, want the Schema parse failed prefix", got)
			}
			if !strings.Contains(got, tc.wantSuffix) {
				t.Fatalf("evidence = %q, want it to mention %q", got, tc.wantSuffix)
			}
			if verified[0]["id"] != "p1" {
				t.Fatalf("fallback lost the finding id: %#v", verified[0])
			}
		})
	}
}

// TestProvePhase_SuccessfulProverPayloadIsUsed proves a valid reply is bound as
// the VerifiedFinding rather than falling back.
func TestProvePhase_SuccessfulProverPayloadIsUsed(t *testing.T) {
	proven := verifiedFinding("p1", schemas.VerdictConfirmed, scoring.SeverityCritical)
	proven.RiskScore = 9.5
	hunt := huntResultMap(t, rawFinding("p1", scoring.SeverityHigh, "fp1", "c"))
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return jsonMap(t, proven), nil
	}}
	out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chainResultMap(t), "standard", 1, 3)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	verified := verifiedList(t, out)
	// afx.DumpExcludeNone renders through pyfmt, so a float field stays a
	// float (and re-renders as 9.5 / 0.0) while an integer inside a free-form
	// dict stays an int.
	if verified[0]["verdict"] != "confirmed" || verified[0]["risk_score"] != 9.5 {
		t.Fatalf("verified = %#v", verified[0])
	}
	if _, present := verified[0]["drop_reason"]; present {
		t.Fatalf("drop_reason must be absent (exclude_none) for a real reply: %#v", verified[0])
	}
}

// TestProvePhase_SemaphoreBoundsConcurrency asserts
// max(1, min(max_concurrent_provers, len(selected))) — and the `if selected else 1`
// arm for the empty case.
func TestProvePhase_SemaphoreBoundsConcurrency(t *testing.T) {
	cases := []struct {
		name     string
		findings int
		limit    int
		wantPeak int
	}{
		{name: "limit below selection", findings: 6, limit: 2, wantPeak: 2},
		{name: "default limit", findings: 6, limit: 3, wantPeak: 3},
		{name: "limit above selection", findings: 2, limit: 10, wantPeak: 2},
		{name: "zero limit clamps to one", findings: 3, limit: 0, wantPeak: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := make([]schemas.RawFinding, 0, tc.findings)
			for i := 0; i < tc.findings; i++ {
				findings = append(findings, rawFinding(fmt.Sprintf("f%d", i), scoring.SeverityMedium,
					fmt.Sprintf("fp%d", i), "c"))
			}
			fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
				time.Sleep(25 * time.Millisecond)
				return nil, errors.New("x")
			}}
			if _, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
				huntResultMap(t, findings...), chainResultMap(t), "standard", 1, tc.limit); err != nil {
				t.Fatalf("ProvePhase: %v", err)
			}
			if peak := fake.MaxConcurrentCalls(); peak != tc.wantPeak {
				t.Fatalf("peak concurrency = %d, want %d", peak, tc.wantPeak)
			}
		})
	}
}

// TestProvePhase_NoFindingsMakesNoCalls covers the empty-selection path.
func TestProvePhase_NoFindingsMakesNoCalls(t *testing.T) {
	fake := &appx.Fake{}
	out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
		huntResultMap(t), chainResultMap(t), "standard", 1, 3)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("calls = %v", fake.CallTargets())
	}
	if pm(out)["total_selected"] != 0 || pm(out)["total_findings"] != 0 || pm(out)["not_verified"] != 0 {
		t.Fatalf("counters = %#v", out)
	}
	if got := verifiedList(t, out); len(got) != 0 {
		t.Fatalf("verified = %v", got)
	}
}

// TestFallbackVerified reproduces the Python probe's FALLBACK dump field by
// field.
func TestFallbackVerified(t *testing.T) {
	src := rawFinding("x", scoring.SeverityHigh, "fpx", "public_access")
	got := FallbackVerified(src, "boom")

	if got.ID != "x" || got.Title != "t" || got.Category != "public_access" {
		t.Errorf("identity fields = %#v", got)
	}
	if got.Verdict != schemas.VerdictInconclusive {
		t.Errorf("verdict = %v", got.Verdict)
	}
	if got.Severity != scoring.SeverityHigh {
		t.Errorf("severity = %v (must come from estimated_severity)", got.Severity)
	}
	if got.Proof.Method != schemas.ProofMethodStaticAnalysis {
		t.Errorf("proof.method = %v", got.Proof.Method)
	}
	if !equalStrings(got.Proof.Evidence, []string{"boom"}) {
		t.Errorf("proof.evidence = %v", got.Proof.Evidence)
	}
	if got.Proof.VerificationTier != "static" || len(got.Proof.ScriptsExecuted) != 0 {
		t.Errorf("proof defaults = %#v", got.Proof)
	}
	if got.IaCFile != "main.tf" || got.IaCLine != 1 || got.Description != "d" || got.Fingerprint != "fpx" {
		t.Errorf("traceability fields = %#v", got)
	}
	if got.HunterStrategy != "iam" {
		t.Errorf("hunter_strategy = %q", got.HunterStrategy)
	}
	if got.SARIFRuleID != "cloudsecurity/iam/public_access" {
		t.Errorf("sarif_rule_id = %q", got.SARIFRuleID)
	}
	if got.SARIFSecuritySeverity != 0.0 || got.RiskScore != 0.0 {
		t.Errorf("scores = %v / %v", got.SARIFSecuritySeverity, got.RiskScore)
	}
	if got.DropReason == nil || *got.DropReason != "prover_error" {
		t.Errorf("drop_reason = %v", got.DropReason)
	}
	if got.AttackPath != nil || got.Drift != nil || got.Remediation != nil {
		t.Errorf("optional models must stay nil: %#v", got)
	}
	if got.ComplianceMappings == nil || len(got.ComplianceMappings) != 0 {
		t.Errorf("compliance_mappings = %#v, want []", got.ComplianceMappings)
	}
	if got.Resources == nil || len(got.Resources) != 0 {
		t.Errorf("resources = %#v, want []", got.Resources)
	}
}

// TestProvePhase_VerifiedFollowsPrioritizedOrder proves the reply list is keyed
// on the ARGUMENT order gather preserves (severity-prioritized), not on the
// order the provers happened to finish in.
func TestProvePhase_VerifiedFollowsPrioritizedOrder(t *testing.T) {
	hunt := huntResultMap(t,
		rawFinding("low", scoring.SeverityLow, "fp-low", "c"),
		rawFinding("critical", scoring.SeverityCritical, "fp-critical", "c"),
		rawFinding("high", scoring.SeverityHigh, "fp-high", "c"),
	)
	// Make the CRITICAL prover the slowest so completion order is the reverse
	// of the prioritized order.
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
		id := jsonMap(t, in["finding"])["id"].(string)
		switch id {
		case "critical":
			time.Sleep(40 * time.Millisecond)
		case "high":
			time.Sleep(20 * time.Millisecond)
		}
		return nil, fmt.Errorf("failed %s", id)
	}}

	out, err := ProvePhase(context.Background(), fake, testNodeID, "/repo", hunt, chainResultMap(t), "standard", 1, 3)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	verified := verifiedList(t, out)
	got := make([]string, 0, len(verified))
	for _, v := range verified {
		got = append(got, v["id"].(string))
	}
	if !equalStrings(got, []string{"critical", "high", "low"}) {
		t.Fatalf("verified order = %v, want [critical high low]", got)
	}
	// Each fallback carries ITS OWN finding's error, proving the index pairing.
	for i, id := range got {
		evidence := proofEvidence(t, verified[i])
		if evidence[0] != "failed "+id {
			t.Fatalf("verified[%d] evidence = %v, want the %s error", i, evidence, id)
		}
	}
}
