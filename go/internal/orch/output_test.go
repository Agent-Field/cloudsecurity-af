package orch

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/output"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// probeFixture rebuilds the exact inputs the Python probe fed to
// ScanOrchestrator._generate_output.
func probeFixture(t *testing.T) (schemas.ReconResult, schemas.HuntResult, schemas.ChainResult, []schemas.VerifiedFinding) {
	t.Helper()

	drifted := schemas.NewDriftedResource()
	drifted.ResourceID = "a"
	drifted.ResourceType = "t"
	drifted.SecurityRelevant = true
	drifted.Significance = "high"

	drift := schemas.NewDriftReport()
	drift.DriftedResources = []schemas.DriftedResource{drifted}
	drift.CloudOnlyResources = []string{"shadow1", "shadow2"}

	recon := schemas.NewReconResult()
	recon.Inventory.InventorySavedPath = "/inv.json"
	recon.Inventory.TotalResources = 3
	recon.Inventory.IaCType = "terraform"
	recon.ResourceGraph.GraphSavedPath = "/g.json"
	recon.ResourceGraph.TotalNodes = 3
	recon.ResourceGraph.TotalEdges = 2
	recon.DriftReport = &drift
	recon.IaCType = "terraform"
	recon.ProvidersDetected = []string{"aws"}
	recon.TotalResources = 3
	recon.TotalEdges = 2

	hunt := schemas.NewHuntResult()
	hunt.TotalRaw = 10
	hunt.StrategiesRun = []string{"iam", "network"}

	chain := schemas.NewChainResult()

	c1 := verifiedFinding("c1", schemas.VerdictConfirmed, scoring.SeverityMedium)
	c1.ComplianceMappings = []string{"CIS-AWS-1.4"}
	c2 := verifiedFinding("c2", schemas.VerdictNotExploitable, scoring.SeverityLow)
	c3 := verifiedFinding("c3", schemas.VerdictNotExploitable, scoring.SeverityInfo)
	c4 := verifiedFinding("c4", schemas.VerdictLikely, scoring.SeverityHigh)
	c4.Proof.Method = schemas.ProofMethodLiveAPIVerification

	return recon, hunt, chain, []schemas.VerifiedFinding{c1, c2, c3, c4}
}

// TestGenerateOutput_ProbeParity reproduces the Python probe's _generate_output
// run field by field.
func TestGenerateOutput_ProbeParity(t *testing.T) {
	recon, hunt, chain, verified := probeFixture(t)
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	o.FindingsNotVerified = 2

	got := o.GenerateOutput(recon, hunt, chain, verified)

	if got.Confirmed != 1 {
		t.Errorf("confirmed = %d, want 1", got.Confirmed)
	}
	if got.Likely != 1 {
		t.Errorf("likely = %d, want 1", got.Likely)
	}
	if got.Inconclusive != 0 {
		t.Errorf("inconclusive = %d, want 0", got.Inconclusive)
	}
	if got.NotExploitable != 1 {
		t.Errorf("not_exploitable = %d, want 1 (c3 was filtered by the threshold)", got.NotExploitable)
	}
	if got.NoiseReductionPct != 10.0 {
		t.Errorf("noise_reduction_pct = %v, want 10.0", got.NoiseReductionPct)
	}
	wantSeverity := map[string]int{"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
	for k, v := range wantSeverity {
		if got.BySeverity[k] != v {
			t.Errorf("by_severity[%q] = %d, want %d (%v)", k, got.BySeverity[k], v, got.BySeverity)
		}
	}
	if len(got.BySeverity) != len(wantSeverity) {
		t.Errorf("by_severity = %v", got.BySeverity)
	}
	if got.DriftResources != 1 || got.ShadowITResources != 2 {
		t.Errorf("drift/shadow = %d/%d, want 1/2", got.DriftResources, got.ShadowITResources)
	}
	if got.TotalRawFindings != 10 {
		t.Errorf("total_raw_findings = %d", got.TotalRawFindings)
	}
	if got.CommitSHA != "HEAD" {
		t.Errorf("commit_sha = %q", got.CommitSHA)
	}
	if got.Branch == nil || *got.Branch != "main" {
		t.Errorf("branch = %v", got.Branch)
	}
	if got.DepthProfile != "quick" {
		t.Errorf("depth_profile = %q", got.DepthProfile)
	}
	if got.Tier != 1 {
		t.Errorf("tier = %d", got.Tier)
	}
	if got.Metadata["findings_not_verified"] != 2 {
		t.Errorf("metadata = %v", got.Metadata)
	}
	if got.CostUSD != 0.0 {
		t.Errorf("cost_usd = %v", got.CostUSD)
	}
	for _, phase := range PhaseOrder {
		if got.CostBreakdown[phase] != 0.0 {
			t.Errorf("cost_breakdown[%q] = %v", phase, got.CostBreakdown[phase])
		}
	}
	if len(got.ComplianceGaps) != 0 {
		t.Errorf("compliance_gaps = %v, want []", got.ComplianceGaps)
	}
	if !equalStrings(got.StrategiesUsed, []string{"iam", "network"}) {
		t.Errorf("strategies_used = %v", got.StrategiesUsed)
	}
	if !equalStrings(got.ProvidersDetected, []string{"aws"}) {
		t.Errorf("providers_detected = %v", got.ProvidersDetected)
	}
	if !equalStrings(got.ComplianceFrameworksChecked, []string{"cis_aws"}) {
		t.Errorf("compliance_frameworks_checked = %v", got.ComplianceFrameworksChecked)
	}
	if got.TotalResourcesScanned != 3 {
		t.Errorf("total_resources_scanned = %d", got.TotalResourcesScanned)
	}

	// probe: [('c1', critical, 3.5, 3.5), ('c2', low, 1.05, 1.05), ('c4', high, 5.6, 5.6)]
	type row struct {
		id       string
		severity scoring.Severity
		score    float64
	}
	want := []row{
		{id: "c1", severity: scoring.SeverityCritical, score: 3.5},
		{id: "c2", severity: scoring.SeverityLow, score: 1.05},
		{id: "c4", severity: scoring.SeverityHigh, score: 5.6},
	}
	if len(got.Findings) != len(want) {
		t.Fatalf("findings = %d, want %d", len(got.Findings), len(want))
	}
	for i, w := range want {
		f := got.Findings[i]
		if f.ID != w.id || f.Severity != w.severity || f.RiskScore != w.score || f.SARIFSecuritySeverity != w.score {
			t.Errorf("finding %d = (%s, %s, %v, %v), want (%s, %s, %v, %v)",
				i, f.ID, f.Severity, f.RiskScore, f.SARIFSecuritySeverity, w.id, w.severity, w.score, w.score)
		}
	}
}

// TestGenerateOutput_SeverityThreshold pins the filter, including the
// rank-0 no-op arms.
func TestGenerateOutput_SeverityThreshold(t *testing.T) {
	recon, hunt, chain, _ := probeFixture(t)
	findings := []schemas.VerifiedFinding{
		verifiedFinding("a", schemas.VerdictConfirmed, scoring.SeverityMedium),
		verifiedFinding("b", schemas.VerdictConfirmed, scoring.SeverityCritical),
		verifiedFinding("c", schemas.VerdictConfirmed, scoring.SeverityInfo),
	}
	cases := []struct {
		threshold string
		want      []string
	}{
		{threshold: "high", want: []string{"b"}},           // probe: THRESH_HIGH ['b']
		{threshold: "low", want: []string{"a", "b"}},       // info drops out
		{threshold: "info", want: []string{"a", "b", "c"}}, // rank 0 -> no filter
		{threshold: "", want: []string{"a", "b", "c"}},     // unknown -> rank 0
		{threshold: "BOGUS", want: []string{"a", "b", "c"}},
		{threshold: "CRITICAL", want: []string{"b"}}, // .lower() is applied
	}
	for _, tc := range cases {
		t.Run(tc.threshold, func(t *testing.T) {
			input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.SeverityThreshold = tc.threshold })
			o := newTestOrchestrator(t, &appx.Fake{}, input, fixedClock())
			got := o.GenerateOutput(recon, hunt, chain, findings)
			ids := make([]string, 0, len(got.Findings))
			for _, f := range got.Findings {
				ids = append(ids, f.ID)
			}
			if !equalStrings(ids, tc.want) {
				t.Fatalf("findings = %v, want %v", ids, tc.want)
			}
		})
	}
}

// TestGenerateOutput_RiskScoreInputs pins every argument compute_risk_score
// receives: the (possibly raised) severity, the mapped evidence method, the
// hard-coded VPC_INTERNAL exposure, and the two boolean bonuses.
func TestGenerateOutput_RiskScoreInputs(t *testing.T) {
	recon, hunt, chain, _ := probeFixture(t)
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, func(in *schemas.CloudSecurityInput) {
		in.SeverityThreshold = "info"
	}), fixedClock())

	path := schemas.NewAttackPath()
	path.ID = "ap"
	drift := schemas.NewDriftedResource()
	drift.ResourceID = "r"

	cases := []struct {
		name  string
		build func() schemas.VerifiedFinding
		want  float64
	}{
		{
			name: "static analysis maps to static_config_match",
			build: func() schemas.VerifiedFinding {
				f := verifiedFinding("x", schemas.VerdictConfirmed, scoring.SeverityHigh)
				f.Proof.Method = schemas.ProofMethodStaticAnalysis
				return f
			},
			want: 2.8, // 8.0 * 0.5 * 0.7
		},
		{
			name: "iam simulation maps to iam_simulated",
			build: func() schemas.VerifiedFinding {
				f := verifiedFinding("x", schemas.VerdictConfirmed, scoring.SeverityHigh)
				f.Proof.Method = schemas.ProofMethodIAMSimulation
				return f
			},
			want: 5.04, // 8.0 * 0.9 * 0.7
		},
		{
			name: "drift comparison maps to drift_confirmed",
			build: func() schemas.VerifiedFinding {
				f := verifiedFinding("x", schemas.VerdictConfirmed, scoring.SeverityHigh)
				f.Proof.Method = schemas.ProofMethodDriftComparison
				return f
			},
			want: 4.76, // 8.0 * 0.85 * 0.7
		},
		{
			name: "attack path doubles the score",
			build: func() schemas.VerifiedFinding {
				f := verifiedFinding("x", schemas.VerdictConfirmed, scoring.SeverityHigh)
				f.AttackPath = &path
				return f
			},
			want: 5.6, // 8.0 * 0.5 * 0.7 * 2
		},
		{
			name: "drift adds 30 percent",
			build: func() schemas.VerifiedFinding {
				f := verifiedFinding("x", schemas.VerdictConfirmed, scoring.SeverityHigh)
				f.Drift = &drift
				return f
			},
			want: 3.64, // 8.0 * 0.5 * 0.7 * 1.3
		},
		{
			name: "score is clamped at 10",
			build: func() schemas.VerifiedFinding {
				f := verifiedFinding("x", schemas.VerdictConfirmed, scoring.SeverityCritical)
				f.Proof.Method = schemas.ProofMethodLiveAPIVerification
				f.AttackPath = &path
				f.Drift = &drift
				return f
			},
			want: 10.0, // 10 * 1 * 0.7 * 2 * 1.3 = 18.2 -> clamped
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := o.GenerateOutput(recon, hunt, chain, []schemas.VerifiedFinding{tc.build()})
			if got.Findings[0].RiskScore != tc.want {
				t.Fatalf("risk_score = %v, want %v", got.Findings[0].RiskScore, tc.want)
			}
		})
	}
}

// TestGenerateOutput_BenchmarkFloorUsesFirstComplianceMapping pins
// `finding.compliance_mappings[0] if finding.compliance_mappings else None`.
func TestGenerateOutput_BenchmarkFloorUsesFirstComplianceMapping(t *testing.T) {
	recon, hunt, chain, _ := probeFixture(t)
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, func(in *schemas.CloudSecurityInput) {
		in.SeverityThreshold = "info"
	}), fixedClock())

	first := verifiedFinding("first", schemas.VerdictConfirmed, scoring.SeverityLow)
	first.ComplianceMappings = []string{"CIS-AWS-1.4", "CIS-AWS-2.1.1"}
	second := verifiedFinding("second", schemas.VerdictConfirmed, scoring.SeverityLow)
	second.ComplianceMappings = []string{"not-a-benchmark", "CIS-AWS-1.4"}
	none := verifiedFinding("none", schemas.VerdictConfirmed, scoring.SeverityLow)

	got := o.GenerateOutput(recon, hunt, chain, []schemas.VerifiedFinding{first, second, none})
	if got.Findings[0].Severity != scoring.SeverityCritical {
		t.Errorf("first mapping should raise to critical, got %s", got.Findings[0].Severity)
	}
	if got.Findings[1].Severity != scoring.SeverityLow {
		t.Errorf("only the FIRST mapping is consulted, got %s", got.Findings[1].Severity)
	}
	if got.Findings[2].Severity != scoring.SeverityLow {
		t.Errorf("no mappings must leave severity alone, got %s", got.Findings[2].Severity)
	}
}

// TestGenerateOutput_NoiseReductionEdgeCases pins the
// `if total_raw > 0 else 0.0` guard and the round(…, 2).
func TestGenerateOutput_NoiseReductionEdgeCases(t *testing.T) {
	recon, _, chain, _ := probeFixture(t)
	cases := []struct {
		name     string
		totalRaw int
		verdicts []schemas.Verdict
		want     float64
	}{
		{name: "no raw findings", totalRaw: 0, verdicts: []schemas.Verdict{schemas.VerdictNotExploitable}, want: 0.0},
		{name: "all noise", totalRaw: 2, verdicts: []schemas.Verdict{schemas.VerdictNotExploitable, schemas.VerdictNotExploitable}, want: 100.0},
		{name: "rounds to two places", totalRaw: 3, verdicts: []schemas.Verdict{schemas.VerdictNotExploitable}, want: 33.33},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hunt := schemas.NewHuntResult()
			hunt.TotalRaw = tc.totalRaw
			findings := make([]schemas.VerifiedFinding, 0, len(tc.verdicts))
			for i, v := range tc.verdicts {
				findings = append(findings, verifiedFinding(string(rune('a'+i)), v, scoring.SeverityHigh))
			}
			o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
			got := o.GenerateOutput(recon, hunt, chain, findings)
			if got.NoiseReductionPct != tc.want {
				t.Fatalf("noise_reduction_pct = %v, want %v", got.NoiseReductionPct, tc.want)
			}
		})
	}
}

// TestGenerateOutput_NoDriftReportZeroesTheDriftCounts.
func TestGenerateOutput_NoDriftReportZeroesTheDriftCounts(t *testing.T) {
	recon, hunt, chain, verified := probeFixture(t)
	recon.DriftReport = nil
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	got := o.GenerateOutput(recon, hunt, chain, verified)
	if got.DriftResources != 0 || got.ShadowITResources != 0 {
		t.Fatalf("drift/shadow = %d/%d, want 0/0", got.DriftResources, got.ShadowITResources)
	}
}

// TestGenerateOutput_CommitShaFallsBackToHEAD pins `input.commit_sha or "HEAD"`.
func TestGenerateOutput_CommitShaFallsBackToHEAD(t *testing.T) {
	recon, hunt, chain, verified := probeFixture(t)
	cases := []struct {
		name string
		sha  *string
		want string
	}{
		{name: "nil", sha: nil, want: "HEAD"},
		{name: "empty string is falsy", sha: stringPtr(""), want: "HEAD"},
		{name: "real sha", sha: stringPtr("deadbeef"), want: "deadbeef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.CommitSHA = tc.sha })
			o := newTestOrchestrator(t, &appx.Fake{}, input, fixedClock())
			if got := o.GenerateOutput(recon, hunt, chain, verified).CommitSHA; got != tc.want {
				t.Fatalf("commit_sha = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGenerateOutput_SarifIsRenderedFromTheScoredFindings: the `sarif` field is
// filled AFTER the risk scores are recomputed, so the document carries the final
// security-severity values, and not_exploitable findings are excluded.
func TestGenerateOutput_SarifIsRenderedFromTheScoredFindings(t *testing.T) {
	recon, hunt, chain, verified := probeFixture(t)
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	got := o.GenerateOutput(recon, hunt, chain, verified)

	if got.SARIF == "" {
		t.Fatal("sarif is empty")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(got.SARIF), &doc); err != nil {
		t.Fatalf("sarif is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("sarif version = %v", doc["version"])
	}
	if !strings.Contains(got.SARIF, "3.5") {
		t.Error("sarif should carry the recomputed security-severity 3.5")
	}
	// generate_sarif is called on the finished result, so re-rendering it must
	// be a no-op modulo the (already-populated) sarif string itself.
	rerendered := got
	rerendered.SARIF = ""
	if output.GenerateSarif(rerendered) != got.SARIF {
		t.Error("sarif was not rendered from the final result")
	}
}

// TestGenerateOutput_CostsAreRoundedToFourPlaces pins round(cost, 4).
func TestGenerateOutput_CostsAreRoundedToFourPlaces(t *testing.T) {
	recon, hunt, chain, verified := probeFixture(t)
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	o.TotalCostUSD = 0.123456
	o.CostBreakdown["recon"] = 0.987654
	got := o.GenerateOutput(recon, hunt, chain, verified)
	if got.CostUSD != 0.1235 {
		t.Errorf("cost_usd = %v, want 0.1235", got.CostUSD)
	}
	if got.CostBreakdown["recon"] != 0.9877 {
		t.Errorf("cost_breakdown[recon] = %v, want 0.9877", got.CostBreakdown["recon"])
	}
}

// TestGenerateOutput_TimestampUsesTheInjectedClock.
func TestGenerateOutput_TimestampUsesTheInjectedClock(t *testing.T) {
	recon, hunt, chain, verified := probeFixture(t)
	o := newTestOrchestrator(t, &appx.Fake{}, scanInput(t, nil), fixedClock())
	got := o.GenerateOutput(recon, hunt, chain, verified)
	if want := "2026-01-02T03:04:05.123456+00:00"; got.Timestamp.ISOFormat() != want {
		t.Fatalf("timestamp = %q, want %q", got.Timestamp.ISOFormat(), want)
	}
}
