package orch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/agents/util"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// pipelineReplies is a scripted control plane: one canned reply per phase
// reasoner, recorded by appx.Fake.
type pipelineReplies struct {
	recon       schemas.ReconResult
	hunt        schemas.HuntResult
	chain       schemas.ChainResult
	proveExtra  map[string]any
	verified    []schemas.VerifiedFinding
	remediated  []schemas.VerifiedFinding
	overrideFor map[string]func(map[string]any) (map[string]any, error)
}

func defaultReplies(t *testing.T) *pipelineReplies {
	t.Helper()
	recon := schemas.NewReconResult()
	recon.Inventory.InventorySavedPath = "/inv.json"
	recon.Inventory.TotalResources = 3
	recon.Inventory.IaCType = "terraform"
	recon.ResourceGraph.GraphSavedPath = "/graph.json"
	recon.ResourceGraph.TotalNodes = 3
	recon.ResourceGraph.TotalEdges = 2
	recon.IaCType = "terraform"
	recon.ProvidersDetected = []string{"aws"}
	recon.TotalResources = 3
	recon.TotalEdges = 2

	hunt := schemas.NewHuntResult()
	hunt.Findings = []schemas.RawFinding{rawFinding("f1", scoring.SeverityHigh, "fp1")}
	hunt.TotalRaw = 4
	hunt.DeduplicatedCount = 1
	hunt.StrategiesRun = []string{"iam", "network"}

	chain := schemas.NewChainResult()

	verified := []schemas.VerifiedFinding{verifiedFinding("f1", schemas.VerdictConfirmed, scoring.SeverityHigh)}

	return &pipelineReplies{
		recon:      recon,
		hunt:       hunt,
		chain:      chain,
		verified:   verified,
		remediated: verified,
		proveExtra: map[string]any{"total_selected": 1, "total_findings": 1, "not_verified": 0},
	}
}

func (p *pipelineReplies) fake(t *testing.T) *appx.Fake {
	t.Helper()
	return &appx.Fake{CallFn: func(_ context.Context, target string, in map[string]any) (map[string]any, error) {
		if override, present := p.overrideFor[target]; present {
			return override(in)
		}
		switch target {
		case "cloudsecurity.recon_phase":
			return jsonMap(t, p.recon), nil
		case "cloudsecurity.hunt_phase":
			return jsonMap(t, p.hunt), nil
		case "cloudsecurity.chain_phase":
			return jsonMap(t, p.chain), nil
		case "cloudsecurity.prove_phase":
			out := map[string]any{"verified": dumpAll(t, p.verified)}
			for k, v := range p.proveExtra {
				out[k] = v
			}
			return out, nil
		case "cloudsecurity.remediation_phase":
			return map[string]any{"verified": dumpAll(t, p.remediated)}, nil
		}
		t.Errorf("unexpected target %q", target)
		return nil, nil
	}}
}

func dumpAll(t *testing.T, findings []schemas.VerifiedFinding) []any {
	t.Helper()
	out := make([]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, jsonMap(t, f))
	}
	return out
}

// TestRun_CallsFivePhasesInOrder pins the DAG's first level: five sequential
// children, in Python's order, on the NODE_ID the environment names.
func TestRun_CallsFivePhasesInOrder(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	fake := replies.fake(t)
	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())

	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{
		"cloudsecurity.recon_phase",
		"cloudsecurity.hunt_phase",
		"cloudsecurity.chain_phase",
		"cloudsecurity.prove_phase",
		"cloudsecurity.remediation_phase",
	}
	if got := fake.CallTargets(); !equalStrings(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
}

// TestRun_HonoursNodeIDEnv proves the target prefix is read at call time.
func TestRun_HonoursNodeIDEnv(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity-go")
	replies := defaultReplies(t)
	fake := &appx.Fake{CallFn: func(ctx context.Context, target string, in map[string]any) (map[string]any, error) {
		inner := replies.fake(t)
		return inner.CallFn(ctx, "cloudsecurity"+target[len("cloudsecurity-go"):], in)
	}}
	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, target := range fake.CallTargets() {
		if len(target) < len("cloudsecurity-go.") || target[:len("cloudsecurity-go.")] != "cloudsecurity-go." {
			t.Fatalf("target %q does not use the NODE_ID prefix", target)
		}
	}
}

// TestRun_PhaseKwargs pins every kwarg key AND the values that come from the
// resolved config/budget, for all five phases.
func TestRun_PhaseKwargs(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	fake := replies.fake(t)
	input := scanInput(t, func(in *schemas.CloudSecurityInput) {
		in.Depth = "quick"
		in.MaxConcurrentHunters = intPtr(2)
		in.MaxConcurrentProvers = intPtr(5)
	})
	o := newTestOrchestrator(t, fake, input, fixedClock())
	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	byTarget := map[string]map[string]any{}
	for _, c := range fake.Calls {
		byTarget[c.Target] = c.Input
	}

	recon := byTarget["cloudsecurity.recon_phase"]
	if got := keysOf(recon); !equalStrings(got, []string{"cloud_config", "depth", "repo_path", "tier"}) {
		t.Errorf("recon_phase kwargs = %v", got)
	}
	if recon["repo_path"] != o.RepoPath || recon["depth"] != "quick" || recon["tier"] != 1 {
		t.Errorf("recon_phase values = %#v", recon)
	}
	if recon["cloud_config"] != nil {
		t.Errorf("cloud_config should be nil for a static scan, got %#v", recon["cloud_config"])
	}

	hunt := byTarget["cloudsecurity.hunt_phase"]
	if got := keysOf(hunt); !equalStrings(got, []string{
		"depth", "inventory_path", "max_concurrent_hunters", "repo_path", "resource_graph_path"}) {
		t.Errorf("hunt_phase kwargs = %v", got)
	}
	if hunt["resource_graph_path"] != "/graph.json" || hunt["inventory_path"] != "/inv.json" {
		t.Errorf("hunt_phase paths = %#v", hunt)
	}
	if hunt["max_concurrent_hunters"] != 2 {
		t.Errorf("max_concurrent_hunters = %v, want the budget override 2", hunt["max_concurrent_hunters"])
	}

	chain := byTarget["cloudsecurity.chain_phase"]
	if got := keysOf(chain); !equalStrings(got, []string{
		"depth", "drift_report", "findings", "max_children", "resource_graph_path"}) {
		t.Errorf("chain_phase kwargs = %v", got)
	}
	if chain["drift_report"] != nil {
		t.Errorf("drift_report should be nil without a drift report, got %#v", chain["drift_report"])
	}
	if chain["max_children"] != 3 {
		t.Errorf("max_children = %v", chain["max_children"])
	}
	findings, ok := chain["findings"].([]map[string]any)
	if !ok || len(findings) != 1 || findings[0]["id"] != "f1" {
		t.Errorf("chain findings = %#v", chain["findings"])
	}

	prove := byTarget["cloudsecurity.prove_phase"]
	if got := keysOf(prove); !equalStrings(got, []string{
		"chain_result", "depth", "hunt_result", "max_concurrent_provers", "repo_path", "tier"}) {
		t.Errorf("prove_phase kwargs = %v", got)
	}
	if prove["max_concurrent_provers"] != 5 {
		t.Errorf("max_concurrent_provers = %v, want the budget override 5", prove["max_concurrent_provers"])
	}
	if prove["tier"] != 1 {
		t.Errorf("tier = %v", prove["tier"])
	}

	remediation := byTarget["cloudsecurity.remediation_phase"]
	if got := keysOf(remediation); !equalStrings(got, []string{"repo_path", "verified_findings"}) {
		t.Errorf("remediation_phase kwargs = %v", got)
	}
	verifiedFindings, ok := remediation["verified_findings"].([]map[string]any)
	if !ok || len(verifiedFindings) != 1 {
		t.Fatalf("verified_findings = %#v", remediation["verified_findings"])
	}
	// The orchestrator hands over model_dump() (NOT exclude_none), so the null
	// optional fields are present.
	if _, present := verifiedFindings[0]["remediation"]; !present {
		t.Errorf("verified_findings should be a full model_dump: %v", keysOf(verifiedFindings[0]))
	}
}

// TestRun_CloudConfigIsDumpedForTierTwo covers the
// `self.input.cloud.model_dump() if self.input.cloud else None` ternary.
func TestRun_CloudConfigIsDumpedForTierTwo(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	fake := replies.fake(t)

	cloud := schemas.NewCloudConfig()
	cloud.Provider = "aws"
	cloud.Regions = []string{"eu-west-1"}
	cloud.AssumeRoleARN = stringPtr("arn:aws:iam::1:role/x")
	input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.Cloud = &cloud })

	o := newTestOrchestrator(t, fake, input, fixedClock())
	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	recon := fake.Calls[0].Input
	got := jsonMap(t, recon["cloud_config"])
	if got["provider"] != "aws" || got["assume_role_arn"] != "arn:aws:iam::1:role/x" {
		t.Fatalf("cloud_config = %#v", got)
	}
	if recon["tier"] != 2 {
		t.Fatalf("tier = %v, want 2 for a cloud scan", recon["tier"])
	}
	if fake.Calls[3].Input["tier"] != 2 {
		t.Fatalf("prove tier = %v, want 2", fake.Calls[3].Input["tier"])
	}
}

// TestRun_DriftReportIsForwardedToChain covers the second dump-or-None ternary.
func TestRun_DriftReportIsForwardedToChain(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	drift := schemas.NewDriftReport()
	drift.CloudOnlyResources = []string{"shadow-1"}
	replies.recon.DriftReport = &drift
	fake := replies.fake(t)

	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	chain := fake.Calls[2].Input
	got := jsonMap(t, chain["drift_report"])
	cloudOnly, ok := got["cloud_only_resources"].([]any)
	if !ok || len(cloudOnly) != 1 || cloudOnly[0] != "shadow-1" {
		t.Fatalf("drift_report = %#v", got)
	}
}

// TestRun_AgentInvocationsFormula pins
// `total_selected + len(strategies_run) + 5`.
func TestRun_AgentInvocationsFormula(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	cases := []struct {
		totalSelected any
		strategies    []string
		want          int
	}{
		{totalSelected: 7, strategies: []string{"iam", "network"}, want: 14},
		{totalSelected: float64(7), strategies: []string{"iam", "network"}, want: 14},
		// Python parity: `strategies_run` has default_factory=list, so an empty
		// HuntResult dumps `[]` — never null, which model_validate rejects.
		{totalSelected: 0, strategies: []string{}, want: 5},
		{totalSelected: nil, strategies: []string{"iam"}, want: 6}, // key absent -> .get default 0
	}
	for _, tc := range cases {
		replies := defaultReplies(t)
		replies.hunt.StrategiesRun = tc.strategies
		replies.proveExtra = map[string]any{"not_verified": 0}
		if tc.totalSelected != nil {
			replies.proveExtra["total_selected"] = tc.totalSelected
		}
		fake := replies.fake(t)
		o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
		result, err := o.Run(context.Background())
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if o.AgentInvocations != tc.want || result.AgentInvocations != tc.want {
			t.Fatalf("agent_invocations = %d/%d, want %d", o.AgentInvocations, result.AgentInvocations, tc.want)
		}
	}
}

// TestRun_FindingsNotVerifiedIsCarriedIntoMetadata pins
// `self.findings_not_verified = prove_dict.get("not_verified", 0)` and its trip
// into the result metadata.
func TestRun_FindingsNotVerifiedIsCarriedIntoMetadata(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	replies.proveExtra = map[string]any{"total_selected": 1, "not_verified": float64(4)}
	fake := replies.fake(t)
	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
	result, err := o.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if o.FindingsNotVerified != 4 {
		t.Fatalf("FindingsNotVerified = %d", o.FindingsNotVerified)
	}
	if result.Metadata["findings_not_verified"] != 4 {
		t.Fatalf("metadata = %#v", result.Metadata)
	}
}

// TestRun_RemediationReplyReplacesTheVerifiedList proves the result carries the
// REMEDIATED findings, not the prove-phase ones.
func TestRun_RemediationReplyReplacesTheVerifiedList(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	remediated := verifiedFinding("f1", schemas.VerdictConfirmed, scoring.SeverityHigh)
	suggestion := schemas.NewRemediationSuggestion()
	suggestion.FindingID = "f1"
	suggestion.Description = "fix it"
	remediated.Remediation = &suggestion
	replies.remediated = []schemas.VerifiedFinding{remediated}
	fake := replies.fake(t)

	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
	result, err := o.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Remediation == nil {
		t.Fatalf("findings = %#v", result.Findings)
	}
	if result.Findings[0].Remediation.Description != "fix it" {
		t.Fatalf("remediation = %#v", result.Findings[0].Remediation)
	}
}

// TestRun_MissingVerifiedKeyIsAKeyError pins the KeyError parity: Python's
// prove_dict["verified"] raises KeyError('verified'), which app.py renders as
// "scan execution failed: 'verified'".
func TestRun_MissingVerifiedKeyIsAKeyError(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	for _, target := range []string{"cloudsecurity.prove_phase", "cloudsecurity.remediation_phase"} {
		t.Run(target, func(t *testing.T) {
			replies := defaultReplies(t)
			replies.overrideFor = map[string]func(map[string]any) (map[string]any, error){
				target: func(map[string]any) (map[string]any, error) {
					return map[string]any{"total_selected": 0}, nil
				},
			}
			fake := replies.fake(t)
			o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
			_, err := o.Run(context.Background())
			if err == nil || err.Error() != "'verified'" {
				t.Fatalf("err = %v, want 'verified'", err)
			}
		})
	}
}

// TestRun_PhaseFailurePropagates covers the strict _unwrap arms at the
// orchestrator level and proves the pipeline stops at the failing phase.
func TestRun_PhaseFailurePropagates(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	cases := []struct {
		target    string
		reply     map[string]any
		callErr   error
		wantErr   string
		wantCalls int
	}{
		{
			target:    "cloudsecurity.recon_phase",
			reply:     map[string]any{"error_message": "no iac"},
			wantErr:   "recon_phase failed: no iac",
			wantCalls: 1,
		},
		{
			target:    "cloudsecurity.hunt_phase",
			reply:     map[string]any{"status": "failed", "error_message": "hunters died"},
			wantErr:   "hunt_phase failed: hunters died",
			wantCalls: 2,
		},
		{
			target:    "cloudsecurity.chain_phase",
			reply:     map[string]any{"error": map[string]any{"detail": "no graph"}},
			wantErr:   "chain_phase failed: no graph",
			wantCalls: 3,
		},
		{
			target:    "cloudsecurity.prove_phase",
			callErr:   errors.New("control plane unreachable"),
			wantErr:   "control plane unreachable",
			wantCalls: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			replies := defaultReplies(t)
			replies.overrideFor = map[string]func(map[string]any) (map[string]any, error){
				tc.target: func(map[string]any) (map[string]any, error) { return tc.reply, tc.callErr },
			}
			fake := replies.fake(t)
			o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
			_, err := o.Run(context.Background())
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if len(fake.Calls) != tc.wantCalls {
				t.Fatalf("calls = %d, want %d (%v)", len(fake.Calls), tc.wantCalls, fake.CallTargets())
			}
		})
	}
}

// TestRun_WritesFourCheckpoints: recon, hunt, chain and prove get a checkpoint;
// remediation does NOT.
func TestRun_WritesFourCheckpoints(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	fake := replies.fake(t)
	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entries, err := os.ReadDir(o.CheckpointDir)
	if err != nil {
		t.Fatalf("read checkpoint dir: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sortStrings(got)
	want := []string{"checkpoint-chain.json", "checkpoint-hunt.json", "checkpoint-prove.json", "checkpoint-recon.json"}
	if !equalStrings(got, want) {
		t.Fatalf("checkpoints = %v, want %v", got, want)
	}
}

// TestRun_DurationsAreDerivedFromTheMonotonicClock pins
// recon_duration_seconds = elapsed and
// hunt_duration_seconds = elapsed - recon_duration.
func TestRun_DurationsAreDerivedFromTheMonotonicClock(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	fake := replies.fake(t)
	// StartedAt consumes call 0; each later nowFn call advances by one second.
	o := newTestOrchestrator(t, fake, scanInput(t, nil), steppingClock(1000*1000*1000))
	result, err := o.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// recon checkpoint holds the duration the orchestrator stamped.
	recon, err := ReadCheckpoint[schemas.ReconResult](o, "recon")
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if recon.ReconDurationSeconds <= 0 {
		t.Fatalf("recon_duration_seconds = %v, want > 0", recon.ReconDurationSeconds)
	}
	hunt, err := ReadCheckpoint[schemas.HuntResult](o, "hunt")
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if hunt.HuntDurationSeconds <= 0 {
		t.Fatalf("hunt_duration_seconds = %v, want > 0", hunt.HuntDurationSeconds)
	}
	if result.DurationSeconds <= recon.ReconDurationSeconds {
		t.Fatalf("duration_seconds = %v, want > recon %v", result.DurationSeconds, recon.ReconDurationSeconds)
	}
}

// TestNew_RepoPathAndCheckpointDir covers the constructor's path resolution and
// the app.py-style override.
func TestNew_RepoPathAndCheckpointDir(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("CLOUDSECURITY_REPO_PATH", repo)
	o, err := New(&appx.Fake{}, scanInput(t, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := util.ResolvePath(repo)
	if o.RepoPath != want {
		t.Fatalf("RepoPath = %q, want %q", o.RepoPath, want)
	}
	if o.CheckpointDir != filepath.Join(want, ".cloudsecurity") {
		t.Fatalf("CheckpointDir = %q", o.CheckpointDir)
	}
	if o.Config.RepoPath != want {
		t.Fatalf("Config.RepoPath = %q", o.Config.RepoPath)
	}

	// app.py's override.
	other := t.TempDir()
	o.RepoPath = other
	o.SetCheckpointDirFromRepoPath()
	if o.CheckpointDir != filepath.Join(other, ".cloudsecurity") {
		t.Fatalf("CheckpointDir after override = %q", o.CheckpointDir)
	}
	// Python parity: ScanConfig is NOT re-derived, so its repo_path goes stale.
	if o.Config.RepoPath != want {
		t.Fatalf("Config.RepoPath should stay stale, got %q", o.Config.RepoPath)
	}
}

// TestNew_SeedsBudgetAndCostBreakdown covers the remaining constructor state.
func TestNew_SeedsBudgetAndCostBreakdown(t *testing.T) {
	t.Setenv("CLOUDSECURITY_REPO_PATH", t.TempDir())
	input := scanInput(t, func(in *schemas.CloudSecurityInput) {
		in.MaxCostUSD = floatPtr(2.5)
		in.MaxDurationSeconds = intPtr(600)
	})
	o, err := New(&appx.Fake{}, input)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if o.MaxCostUSD == nil || *o.MaxCostUSD != 2.5 {
		t.Errorf("MaxCostUSD = %v", o.MaxCostUSD)
	}
	if o.MaxDurationSeconds == nil || *o.MaxDurationSeconds != 600 {
		t.Errorf("MaxDurationSeconds = %v", o.MaxDurationSeconds)
	}
	if o.TotalCostUSD != 0 || o.AgentInvocations != 0 || o.BudgetExhausted || o.FindingsNotVerified != 0 {
		t.Errorf("counters = %#v", o)
	}
	if len(o.CostBreakdown) != len(PhaseOrder) {
		t.Fatalf("cost_breakdown = %#v", o.CostBreakdown)
	}
	for _, phase := range PhaseOrder {
		if v, present := o.CostBreakdown[phase]; !present || v != 0.0 {
			t.Fatalf("cost_breakdown[%q] = %v (present=%v)", phase, v, present)
		}
	}
	if o.BudgetConfig.MaxConcurrentHunters != 4 || o.BudgetConfig.MaxConcurrentProvers != 3 ||
		o.BudgetConfig.MaxConcurrentChainChildren != 3 {
		t.Fatalf("budget = %#v", o.BudgetConfig)
	}
}

// TestNew_RejectsUnknownDepth pins the ValueError ScanConfig.from_input raises
// before run() is ever reached.
func TestNew_RejectsUnknownDepth(t *testing.T) {
	t.Setenv("CLOUDSECURITY_REPO_PATH", t.TempDir())
	input := scanInput(t, func(in *schemas.CloudSecurityInput) { in.Depth = "extreme" })
	if _, err := New(&appx.Fake{}, input); err == nil ||
		err.Error() != "'extreme' is not a valid DepthProfile" {
		t.Fatalf("err = %v", err)
	}
}

// TestRun_EmitsNoNotes pins the fact that orchestrator.py never calls app.note
// — not even from _emit_progress, which builds a ScanProgress and drops it.
func TestRun_EmitsNoNotes(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")
	replies := defaultReplies(t)
	fake := replies.fake(t)
	o := newTestOrchestrator(t, fake, scanInput(t, nil), fixedClock())
	if _, err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fake.Notes) != 0 {
		t.Fatalf("the orchestrator must not emit notes, got %v", fake.NoteMessages())
	}
	if len(fake.Harnesses) != 0 || len(fake.AIs) != 0 {
		t.Fatalf("the orchestrator must only use app.call, got %d harness / %d ai calls",
			len(fake.Harnesses), len(fake.AIs))
	}
}
