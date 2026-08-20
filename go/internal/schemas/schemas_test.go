package schemas

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// This file ports tests/test_schemas.py.
//
// STALE-TEST NOTE (verified against the venv interpreter, 2026-08-19):
// tests/test_schemas.py does not currently import. It asks for
// `ResourceNode`, `ResourceEdge` and `ResourceCluster` from
// cloudsecurity_af.schemas.recon, and none of the three exists any more —
// schemas/recon.py was reworked so ResourceInventory/ResourceGraph are *pointers*
// to files on disk (`inventory_saved_path` / `graph_saved_path`) rather than
// inline node/edge containers. The import error means the WHOLE module fails to
// collect, so every test in it is dead in Python today.
//
// Consequently:
//   - Tests whose subject still exists are ported verbatim, named after the
//     Python class::test.
//   - Five TestReconSchemas tests (test_resource_node_defaults,
//     test_resource_edge, test_resource_graph_empty,
//     test_resource_inventory_empty, test_resource_inventory_populated) target
//     removed classes or removed fields. They are replaced by tests of the
//     CURRENT shape, each carrying a comment naming the Python test it stands
//     in for. Restoring them verbatim would mean re-adding schema classes the
//     Python node no longer has, which would break parity.
//
// tests/test_graph_context.py is stale for the same reason AND targets
// cloudsecurity_af.agents._utils.build_graph_context_for_hunter, which now takes
// two file PATHS instead of the two models the test constructs. It belongs to
// the internal/agents/util owner, not to internal/schemas.

func mustJSONMap(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// Input schemas — tests/test_schemas.py::TestCloudConfig
// ---------------------------------------------------------------------------

// test_defaults
func TestCloudConfig_Defaults(t *testing.T) {
	cfg := NewCloudConfig()
	if cfg.Provider != "aws" {
		t.Errorf("provider = %q, want %q", cfg.Provider, "aws")
	}
	if !reflect.DeepEqual(cfg.Regions, []string{"us-east-1"}) {
		t.Errorf("regions = %v, want [us-east-1]", cfg.Regions)
	}
	if cfg.AccountID != nil {
		t.Errorf("account_id = %v, want nil", *cfg.AccountID)
	}
	if cfg.AssumeRoleARN != nil {
		t.Errorf("assume_role_arn = %v, want nil", *cfg.AssumeRoleARN)
	}
}

// test_custom
func TestCloudConfig_Custom(t *testing.T) {
	var cfg CloudConfig
	if err := json.Unmarshal([]byte(`{"provider":"gcp","regions":["us-central1"],"account_id":"my-project"}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Provider != "gcp" {
		t.Errorf("provider = %q, want gcp", cfg.Provider)
	}
	if !reflect.DeepEqual(cfg.Regions, []string{"us-central1"}) {
		t.Errorf("regions = %v, want [us-central1]", cfg.Regions)
	}
	if cfg.AccountID == nil || *cfg.AccountID != "my-project" {
		t.Errorf("account_id = %v, want my-project", cfg.AccountID)
	}
}

// ---------------------------------------------------------------------------
// tests/test_schemas.py::TestCloudSecurityInput
// ---------------------------------------------------------------------------

// test_tier1_no_cloud
func TestCloudSecurityInput_Tier1NoCloud(t *testing.T) {
	var in CloudSecurityInput
	if err := json.Unmarshal([]byte(`{"repo_url":"/tmp/my-repo"}`), &in); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if in.Tier() != 1 {
		t.Errorf("tier = %d, want 1", in.Tier())
	}
	if in.Cloud != nil {
		t.Errorf("cloud = %+v, want nil", in.Cloud)
	}
	if in.Depth != "standard" {
		t.Errorf("depth = %q, want standard", in.Depth)
	}
}

// test_tier2_with_cloud
func TestCloudSecurityInput_Tier2WithCloud(t *testing.T) {
	var in CloudSecurityInput
	if err := json.Unmarshal([]byte(`{"repo_url":"/tmp/my-repo","cloud":{"provider":"aws"}}`), &in); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if in.Tier() != 2 {
		t.Errorf("tier = %d, want 2", in.Tier())
	}
	// The nested CloudConfig re-seeds its own defaults.
	if !reflect.DeepEqual(in.Cloud.Regions, []string{"us-east-1"}) {
		t.Errorf("nested cloud.regions = %v, want [us-east-1]", in.Cloud.Regions)
	}
}

// test_depth_options
func TestCloudSecurityInput_DepthOptions(t *testing.T) {
	for _, depth := range []string{"quick", "standard", "thorough"} {
		var in CloudSecurityInput
		payload := `{"repo_url":".","depth":"` + depth + `"}`
		if err := json.Unmarshal([]byte(payload), &in); err != nil {
			t.Fatalf("unmarshal %s: %v", depth, err)
		}
		if in.Depth != depth {
			t.Errorf("depth = %q, want %q", in.Depth, depth)
		}
	}
}

// test_default_exclude_paths
func TestCloudSecurityInput_DefaultExcludePaths(t *testing.T) {
	var in CloudSecurityInput
	if err := json.Unmarshal([]byte(`{"repo_url":"."}`), &in); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"tests/", ".git/", "examples/", ".terraform/"}
	if !reflect.DeepEqual(in.ExcludePaths, want) {
		t.Fatalf("exclude_paths = %v, want %v", in.ExcludePaths, want)
	}
}

// ---------------------------------------------------------------------------
// Recon schemas — tests/test_schemas.py::TestReconSchemas
// ---------------------------------------------------------------------------

// Stands in for test_resource_node_defaults / test_resource_edge, whose
// ResourceNode / ResourceEdge classes no longer exist. Resource is the model
// that survived the rework; this pins its defaults.
func TestReconSchemas_ResourceDefaults(t *testing.T) {
	r := NewResource()
	r.ID = "aws_s3_bucket.data"
	r.Type = "aws_s3_bucket"
	r.Name = "data"
	r.Provider = "aws"
	r.FilePath = "main.tf"
	if r.LineNumber != 0 {
		t.Errorf("line_number = %d, want 0", r.LineNumber)
	}
	got := mustJSONMap(t, r)
	// default_factory=dict / list must marshal as {} / [], never null.
	if !reflect.DeepEqual(got["config"], map[string]any{}) {
		t.Errorf("config = %v, want {}", got["config"])
	}
	if !reflect.DeepEqual(got["references"], []any{}) {
		t.Errorf("references = %v, want []", got["references"])
	}
	if !reflect.DeepEqual(got["referenced_by"], []any{}) {
		t.Errorf("referenced_by = %v, want []", got["referenced_by"])
	}
}

// Stands in for test_resource_graph_empty. ResourceGraph is now a pointer to a
// graph.json file; `graph_saved_path` is REQUIRED, so `ResourceGraph()` raises
// in Python and the empty nodes/edges/clusters lists the old test asserted are
// gone.
func TestReconSchemas_ResourceGraphIsAPointer(t *testing.T) {
	g := NewResourceGraph()
	if g.TotalNodes != 0 || g.TotalEdges != 0 {
		t.Errorf("counts = %d/%d, want 0/0", g.TotalNodes, g.TotalEdges)
	}
	got := mustJSONMap(t, g)
	wantKeys := []string{"graph_saved_path", "total_nodes", "total_edges"}
	if len(got) != len(wantKeys) {
		t.Fatalf("keys = %v, want exactly %v", got, wantKeys)
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
}

// Stands in for test_resource_inventory_empty / test_resource_inventory_populated.
// ResourceInventory is now a pointer to inventory.json; it has no `resources`,
// `modules`, `variables`, `outputs` or `provider_configs` fields any more. The
// one default that survived is iac_type="terraform".
func TestReconSchemas_ResourceInventoryDefaults(t *testing.T) {
	inv := NewResourceInventory()
	if inv.IaCType != "terraform" {
		t.Errorf("iac_type = %q, want terraform", inv.IaCType)
	}
	if inv.TotalResources != 0 {
		t.Errorf("total_resources = %d, want 0", inv.TotalResources)
	}
	if inv.IaCVersion != nil {
		t.Errorf("iac_version = %v, want nil", *inv.IaCVersion)
	}
	// Decoding a payload without iac_type keeps the default; an explicit value
	// overrides it (pydantic parity).
	var decoded ResourceInventory
	if err := json.Unmarshal([]byte(`{"inventory_saved_path":"/tmp/inventory.json"}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.IaCType != "terraform" {
		t.Errorf("absent iac_type = %q, want terraform", decoded.IaCType)
	}
	if err := json.Unmarshal([]byte(`{"inventory_saved_path":"/x","iac_type":"kubernetes"}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.IaCType != "kubernetes" {
		t.Errorf("explicit iac_type = %q, want kubernetes", decoded.IaCType)
	}
}

// test_drift_report_empty
func TestReconSchemas_DriftReportEmpty(t *testing.T) {
	d := NewDriftReport()
	if len(d.DriftedResources) != 0 || len(d.IaCOnlyResources) != 0 || len(d.CloudOnlyResources) != 0 {
		t.Fatalf("expected all three lists empty, got %+v", d)
	}
	got := mustJSONMap(t, d)
	for _, k := range []string{"drifted_resources", "iac_only_resources", "cloud_only_resources"} {
		if !reflect.DeepEqual(got[k], []any{}) {
			t.Errorf("%s = %v, want [] (never null)", k, got[k])
		}
	}
}

// test_recon_result_defaults — Python's ReconResult() raises today (see doc.go),
// so this asserts NewReconResult()'s intended default vector instead.
func TestReconSchemas_ReconResultDefaults(t *testing.T) {
	r := NewReconResult()
	if r.TotalResources != 0 {
		t.Errorf("total_resources = %d, want 0", r.TotalResources)
	}
	if r.IaCType != "terraform" {
		t.Errorf("iac_type = %q, want terraform", r.IaCType)
	}
	if r.DriftReport != nil {
		t.Errorf("drift_report = %+v, want nil", r.DriftReport)
	}
	if r.LiveInventory != nil {
		t.Errorf("live_inventory = %+v, want nil", r.LiveInventory)
	}
	if r.Inventory.IaCType != "terraform" {
		t.Errorf("nested inventory.iac_type = %q, want terraform", r.Inventory.IaCType)
	}
}

// ---------------------------------------------------------------------------
// Hunt schemas — tests/test_schemas.py::TestHuntSchemas
// ---------------------------------------------------------------------------

// test_raw_finding_defaults
func TestHuntSchemas_RawFindingDefaults(t *testing.T) {
	f := NewRawFinding()
	f.HunterStrategy = "iam"
	f.Title = "Over-permissioned role"
	f.Description = "Role has wildcard access"
	f.Category = "overprivilege"

	if f.EstimatedSeverity != scoring.SeverityMedium {
		t.Errorf("estimated_severity = %q, want medium", f.EstimatedSeverity)
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", f.Confidence)
	}
	if f.ID == "" {
		t.Error("id should be a generated uuid")
	}
	if f.IaCFile != "" {
		t.Errorf("iac_file = %q, want empty", f.IaCFile)
	}
}

// test_finding_for_dedup
func TestHuntSchemas_FindingForDedup(t *testing.T) {
	f := NewRawFinding()
	f.HunterStrategy = "network"
	f.Title = "Open security group"
	f.Description = "SG allows 0.0.0.0/0"
	f.Category = "public_exposure"
	f.EstimatedSeverity = scoring.SeverityCritical
	f.IaCFile = "network.tf"
	f.IaCLine = 7

	dedup := f.ForDedup()
	if dedup.ID != f.ID {
		t.Errorf("id = %q, want %q", dedup.ID, f.ID)
	}
	if dedup.Title != f.Title {
		t.Errorf("title = %q, want %q", dedup.Title, f.Title)
	}
	if dedup.Fingerprint != f.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", dedup.Fingerprint, f.Fingerprint)
	}
	if dedup.Category != "public_exposure" || dedup.HunterStrategy != "network" {
		t.Errorf("category/strategy = %q/%q", dedup.Category, dedup.HunterStrategy)
	}
	if dedup.IaCFile != "network.tf" || dedup.IaCLine != 7 {
		t.Errorf("iac_file/line = %q/%d", dedup.IaCFile, dedup.IaCLine)
	}
	// Python parity: for_dedup() passes `self.estimated_severity.value`, so the
	// view's field is the plain string, not the enum.
	if dedup.EstimatedSeverity != "critical" {
		t.Errorf("estimated_severity = %q, want the raw value %q", dedup.EstimatedSeverity, "critical")
	}
}

// test_hunt_result_empty
func TestHuntSchemas_HuntResultEmpty(t *testing.T) {
	r := NewHuntResult()
	if len(r.Findings) != 0 {
		t.Errorf("findings = %v, want empty", r.Findings)
	}
	if r.TotalRaw != 0 {
		t.Errorf("total_raw = %d, want 0", r.TotalRaw)
	}
	got := mustJSONMap(t, r)
	if !reflect.DeepEqual(got["findings"], []any{}) {
		t.Errorf("findings marshals as %v, want []", got["findings"])
	}
}

// test_hunter_strategy_enum
func TestHuntSchemas_HunterStrategyEnum(t *testing.T) {
	if HunterStrategyIAM.String() != "iam" {
		t.Errorf("IAM = %q, want iam", HunterStrategyIAM)
	}
	if HunterStrategyCompliance.String() != "compliance" {
		t.Errorf("COMPLIANCE = %q, want compliance", HunterStrategyCompliance)
	}
	if len(AllHunterStrategies) != 7 {
		t.Errorf("AllHunterStrategies has %d members, want 7", len(AllHunterStrategies))
	}
}

// test_finding_category_enum
func TestHuntSchemas_FindingCategoryEnum(t *testing.T) {
	if FindingCategoryOverprivilege.String() != "overprivilege" {
		t.Errorf("OVERPRIVILEGE = %q", FindingCategoryOverprivilege)
	}
	if FindingCategoryPrivilegedContainer.String() != "privileged_container" {
		t.Errorf("PRIVILEGED_CONTAINER = %q", FindingCategoryPrivilegedContainer)
	}
	if len(AllFindingCategories) != 13 {
		t.Errorf("AllFindingCategories has %d members, want 13", len(AllFindingCategories))
	}
}

// Not in the Python suite: the Confidence enum's members and strictness.
func TestHuntSchemas_ConfidenceEnum(t *testing.T) {
	want := []string{"high", "medium", "low"}
	if len(AllConfidences) != len(want) {
		t.Fatalf("AllConfidences has %d members, want %d", len(AllConfidences), len(want))
	}
	for i, w := range want {
		if AllConfidences[i].String() != w {
			t.Errorf("AllConfidences[%d] = %q, want %q", i, AllConfidences[i], w)
		}
	}
	if _, err := ParseConfidence("HIGH"); err == nil {
		t.Error("ParseConfidence is case-sensitive, matching Python's Enum(value)")
	}
}

// ---------------------------------------------------------------------------
// Chain schemas — tests/test_schemas.py::TestChainSchemas
// ---------------------------------------------------------------------------

// test_attack_step
func TestChainSchemas_AttackStep(t *testing.T) {
	step := NewAttackStep()
	step.StepNumber = 1
	step.ResourceID = "role.admin"
	step.ResourceType = "aws_iam_role"
	step.Action = "Assume role via sts:AssumeRole"
	step.PermissionUsed = "sts:AssumeRole"
	if step.StepNumber != 1 {
		t.Errorf("step_number = %d, want 1", step.StepNumber)
	}
	if step.Description != "" {
		t.Errorf("description = %q, want empty", step.Description)
	}
}

// test_attack_path
func TestChainSchemas_AttackPath(t *testing.T) {
	path := NewAttackPath()
	path.Title = "Public S3 to admin role"
	path.Description = "Chain from public bucket to admin"
	path.EntryPoint = "aws_s3_bucket.public"
	path.Target = "aws_iam_role.admin"
	path.Steps = []AttackStep{}

	if path.CombinedSeverity != scoring.SeverityHigh {
		t.Errorf("combined_severity = %q, want high", path.CombinedSeverity)
	}
	if len(path.BlastRadius.DataStoresReachable) != 0 {
		t.Errorf("blast_radius.data_stores_reachable = %v, want empty", path.BlastRadius.DataStoresReachable)
	}
	if path.ID == "" {
		t.Error("id should be a generated uuid")
	}
	got := mustJSONMap(t, path)
	br, ok := got["blast_radius"].(map[string]any)
	if !ok {
		t.Fatalf("blast_radius = %v, want an object", got["blast_radius"])
	}
	if !reflect.DeepEqual(br["data_stores_reachable"], []any{}) {
		t.Errorf("nested blast_radius lists must marshal as [], got %v", br["data_stores_reachable"])
	}
}

// test_chain_result_empty
func TestChainSchemas_ChainResultEmpty(t *testing.T) {
	r := NewChainResult()
	if len(r.AttackPaths) != 0 {
		t.Errorf("attack_paths = %v, want empty", r.AttackPaths)
	}
	if r.ViablePaths != 0 {
		t.Errorf("viable_paths = %d, want 0", r.ViablePaths)
	}
}

// ---------------------------------------------------------------------------
// Prove schemas — tests/test_schemas.py::TestProveSchemas
// ---------------------------------------------------------------------------

// test_verified_finding_minimal
func TestProveSchemas_VerifiedFindingMinimal(t *testing.T) {
	f := NewVerifiedFinding()
	f.Title = "Test finding"
	f.Verdict = VerdictConfirmed
	f.Severity = scoring.SeverityHigh
	f.Category = "overprivilege"

	if f.Verdict != VerdictConfirmed {
		t.Errorf("verdict = %q, want confirmed", f.Verdict)
	}
	if f.RiskScore != 0.0 {
		t.Errorf("risk_score = %v, want 0.0", f.RiskScore)
	}
	if f.Proof.Method != ProofMethodStaticAnalysis {
		t.Errorf("proof.method = %q, want static_analysis", f.Proof.Method)
	}
	if f.Proof.VerificationTier != "static" {
		t.Errorf("proof.verification_tier = %q, want static", f.Proof.VerificationTier)
	}
}

// test_remediation_suggestion
func TestProveSchemas_RemediationSuggestion(t *testing.T) {
	rem := NewRemediationSuggestion()
	rem.FindingID = "test-id"
	rem.Description = "Enable encryption"
	diff := NewIaCDiff()
	diff.FilePath = "main.tf"
	diff.OriginalLines = "  encryption = false"
	diff.PatchedLines = "  encryption = true"
	diff.StartLine = 10
	diff.EndLine = 10
	rem.Diffs = []IaCDiff{diff}
	rem.BreakingChange = false
	downtime := "none"
	rem.DowntimeEstimate = &downtime

	if len(rem.Diffs) != 1 {
		t.Fatalf("diffs = %v, want 1 entry", rem.Diffs)
	}
	if rem.BreakingChange {
		t.Error("breaking_change should be false")
	}
	if rem.Effort != "moderate" {
		t.Errorf("effort = %q, want the default moderate", rem.Effort)
	}
}

// test_verdict_enum
func TestProveSchemas_VerdictEnum(t *testing.T) {
	if VerdictConfirmed.String() != "confirmed" {
		t.Errorf("CONFIRMED = %q", VerdictConfirmed)
	}
	if VerdictNotExploitable.String() != "not_exploitable" {
		t.Errorf("NOT_EXPLOITABLE = %q", VerdictNotExploitable)
	}
	if len(AllVerdicts) != 4 {
		t.Errorf("AllVerdicts has %d members, want 4", len(AllVerdicts))
	}
}

// Not in the Python suite: the ProofMethod enum's members.
func TestProveSchemas_ProofMethodEnum(t *testing.T) {
	want := []string{"static_analysis", "live_api_verification", "iam_simulation", "drift_comparison"}
	if len(AllProofMethods) != len(want) {
		t.Fatalf("AllProofMethods has %d members, want %d", len(AllProofMethods), len(want))
	}
	for i, w := range want {
		if AllProofMethods[i].String() != w {
			t.Errorf("AllProofMethods[%d] = %q, want %q", i, AllProofMethods[i], w)
		}
	}
}

// ---------------------------------------------------------------------------
// Output schemas — tests/test_schemas.py::TestOutputSchemas
// ---------------------------------------------------------------------------

// test_scan_result_minimal
func TestOutputSchemas_ScanResultMinimal(t *testing.T) {
	r := NewCloudSecurityScanResult()
	r.Repository = "/tmp/repo"
	r.CommitSHA = "abc123"
	r.Timestamp = NewTimestamp(time.Now().UTC())
	r.DepthProfile = "standard"
	r.Tier = 1

	if r.Tier != 1 {
		t.Errorf("tier = %d, want 1", r.Tier)
	}
	if r.Confirmed != 0 {
		t.Errorf("confirmed = %d, want 0", r.Confirmed)
	}
	if len(r.Findings) != 0 {
		t.Errorf("findings = %v, want empty", r.Findings)
	}
	got := mustJSONMap(t, r)
	if !reflect.DeepEqual(got["findings"], []any{}) {
		t.Errorf("findings marshals as %v, want []", got["findings"])
	}
	if !reflect.DeepEqual(got["by_severity"], map[string]any{}) {
		t.Errorf("by_severity marshals as %v, want {}", got["by_severity"])
	}
	if got["branch"] != nil {
		t.Errorf("branch marshals as %v, want null", got["branch"])
	}
}

// test_scan_progress
func TestOutputSchemas_ScanProgress(t *testing.T) {
	p := ScanProgress{
		Phase:                     "HUNT",
		PhaseProgress:             0.5,
		AgentsTotal:               7,
		AgentsCompleted:           3,
		AgentsRunning:             4,
		FindingsSoFar:             12,
		ElapsedSeconds:            30.0,
		EstimatedRemainingSeconds: 30.0,
		CostSoFarUSD:              0.02,
	}
	if p.Phase != "HUNT" {
		t.Errorf("phase = %q, want HUNT", p.Phase)
	}
}

// test_scan_metrics
func TestOutputSchemas_ScanMetrics(t *testing.T) {
	m := NewScanMetrics()
	m.DurationSeconds = 60.0
	m.AgentInvocations = 15
	m.CostUSD = 0.05
	if m.BudgetExhausted {
		t.Error("budget_exhausted should default to false")
	}
	if m.FindingsNotVerified != 0 {
		t.Errorf("findings_not_verified = %d, want 0", m.FindingsNotVerified)
	}
	got := mustJSONMap(t, m)
	if !reflect.DeepEqual(got["cost_breakdown"], map[string]any{}) {
		t.Errorf("cost_breakdown marshals as %v, want {}", got["cost_breakdown"])
	}
}
