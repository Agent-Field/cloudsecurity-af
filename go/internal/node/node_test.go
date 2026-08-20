package node

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/orch"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/reasoners"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// clearNodeEnv unsets every variable BuildAgent reads, so a test starts from
// the code defaults regardless of the developer's shell.
//
// It UNSETS rather than blanks: config.AIConfigFromEnv ports
// `int(os.getenv("CLOUDSECURITY_MAX_TURNS", "50"))`, where a key PRESENT with an
// empty value is int("") — a boot failure, not the default. t.Setenv is called
// first only to register the restore of the developer's original value.
func clearNodeEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"NODE_ID", "PORT", "AGENTFIELD_SERVER", "AGENTFIELD_API_KEY", "AGENT_CALLBACK_URL",
		"OPENROUTER_API_KEY",
		"CLOUDSECURITY_PROVIDER", "HARNESS_PROVIDER",
		"CLOUDSECURITY_MODEL", "HARNESS_MODEL",
		"CLOUDSECURITY_AI_MODEL", "AI_MODEL",
		"CLOUDSECURITY_MAX_TURNS",
		"CLOUDSECURITY_OPENCODE_BIN", "CLOUDSECURITY_AFORGE_BIN", "AFORGE_BIN",
	} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}

// --- BuildAgent / buildConfig ------------------------------------------------

func TestBuildConfig_Defaults(t *testing.T) {
	clearNodeEnv(t)

	cfg, err := buildConfig("cloudsecurity", "8015", "AI-Native Cloud Infrastructure Security Scanner")
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.NodeID != "cloudsecurity" {
		t.Errorf("NodeID = %q, want cloudsecurity", cfg.NodeID)
	}
	if cfg.Version != "0.1.0" {
		t.Errorf("Version = %q, want 0.1.0 (app.py version=\"0.1.0\")", cfg.Version)
	}
	if cfg.AgentFieldURL != "http://localhost:8080" {
		t.Errorf("AgentFieldURL = %q", cfg.AgentFieldURL)
	}
	if cfg.ListenAddress != ":8015" {
		t.Errorf("ListenAddress = %q, want :8015", cfg.ListenAddress)
	}
	if cfg.CLIConfig == nil || cfg.CLIConfig.AppDescription != "AI-Native Cloud Infrastructure Security Scanner" {
		t.Errorf("CLIConfig = %#v", cfg.CLIConfig)
	}
	// DIVERGENCE pinned: Python's callback_url default is the docker-only
	// http://host.docker.internal:8020 (wrong host AND wrong port). Go leaves
	// PublicURL empty so the SDK uses http://localhost:<listen port>.
	if cfg.PublicURL != "" {
		t.Errorf("PublicURL = %q, want empty so the SDK derives http://localhost:8015", cfg.PublicURL)
	}
}

func TestBuildConfig_EnvOverrides(t *testing.T) {
	clearNodeEnv(t)
	t.Setenv("NODE_ID", "cloudsecurity-go")
	t.Setenv("PORT", "9100")
	t.Setenv("AGENTFIELD_SERVER", "http://agentfield:8080")
	t.Setenv("AGENTFIELD_API_KEY", "cp-token")
	t.Setenv("AGENT_CALLBACK_URL", "http://cloudsecurity-go:9100")

	cfg, err := buildConfig("cloudsecurity", "8015", "d")
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.NodeID != "cloudsecurity-go" {
		t.Errorf("NodeID = %q", cfg.NodeID)
	}
	if cfg.ListenAddress != ":9100" {
		t.Errorf("ListenAddress = %q", cfg.ListenAddress)
	}
	if cfg.AgentFieldURL != "http://agentfield:8080" {
		t.Errorf("AgentFieldURL = %q", cfg.AgentFieldURL)
	}
	if cfg.Token != "cp-token" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.PublicURL != "http://cloudsecurity-go:9100" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
}

// TestBuildConfig_AIConfigOnlyWhenTheKeyIsSet pins divergence 2: the Go ai
// client rejects an empty key at construction, so AIConfig is attached only
// when OPENROUTER_API_KEY is set.
func TestBuildConfig_AIConfigOnlyWhenTheKeyIsSet(t *testing.T) {
	clearNodeEnv(t)

	cfg, err := buildConfig("cloudsecurity", "8015", "d")
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.AIConfig != nil {
		t.Fatal("AIConfig must be nil without OPENROUTER_API_KEY")
	}

	t.Setenv("OPENROUTER_API_KEY", "sk-test")
	t.Setenv("AI_MODEL", "openrouter/moonshotai/kimi-k2.5")
	cfg, err = buildConfig("cloudsecurity", "8015", "d")
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.AIConfig == nil {
		t.Fatal("AIConfig must be attached when OPENROUTER_API_KEY is set")
	}
	if cfg.AIConfig.APIKey != "sk-test" {
		t.Errorf("APIKey = %q", cfg.AIConfig.APIKey)
	}
	if cfg.AIConfig.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("BaseURL = %q", cfg.AIConfig.BaseURL)
	}
	// The LiteLLM routing prefix must be stripped for the direct API call.
	if cfg.AIConfig.Model != "moonshotai/kimi-k2.5" {
		t.Errorf("Model = %q, want the openrouter/ prefix stripped", cfg.AIConfig.Model)
	}
}

func TestAIModelForAPI(t *testing.T) {
	cases := map[string]string{
		"openrouter/minimax/minimax-m2.5": "minimax/minimax-m2.5",
		"minimax/minimax-m2.5":            "minimax/minimax-m2.5",
		"":                                "",
		// Only a LEADING prefix is consumed.
		"x/openrouter/y": "x/openrouter/y",
	}
	for in, want := range cases {
		if got := aiModelForAPI(in); got != want {
			t.Errorf("aiModelForAPI(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHarnessConfig_MapsPythonHarnessConfig pins the HarnessConfig mapping,
// including the one-BinPath-per-provider selection Python performs inside the
// SDK (it passes both opencode_bin and aforge_bin).
func TestHarnessConfig_MapsPythonHarnessConfig(t *testing.T) {
	clearNodeEnv(t)

	c := config.AIIntegrationConfig{
		Provider:     "aforge",
		HarnessModel: "openrouter/minimax/minimax-m2.5",
		AIModel:      "openrouter/minimax/minimax-m2.5",
		MaxTurns:     50,
		OpencodeBin:  "opencode",
		AforgeBin:    "aforge",
	}
	hc, err := harnessConfig(c)
	if err != nil {
		t.Fatalf("harnessConfig: %v", err)
	}
	if hc.Provider != "aforge" || hc.Model != "openrouter/minimax/minimax-m2.5" || hc.MaxTurns != 50 {
		t.Fatalf("harnessConfig = %#v", hc)
	}
	if hc.PermissionMode != "auto" {
		t.Errorf("PermissionMode = %q, want auto (app.py permission_mode=\"auto\")", hc.PermissionMode)
	}
	if hc.BinPath != "aforge" {
		t.Errorf("BinPath = %q, want the aforge bin", hc.BinPath)
	}

	c.Provider = "opencode"
	if got := mustHarnessConfig(t, c).BinPath; got != "opencode" {
		t.Errorf("opencode BinPath = %q", got)
	}

	c.Provider = "claude-code"
	if got := mustHarnessConfig(t, c).BinPath; got != "" {
		t.Errorf("claude-code BinPath = %q, want empty (SDK default executable)", got)
	}
}

// TestHarnessConfig_ForwardsProviderEnv proves the cloud/LLM credential
// forwarding survives the mapping — provider_env() is what gives the harness
// subprocess its AWS keys.
func TestHarnessConfig_ForwardsProviderEnv(t *testing.T) {
	clearNodeEnv(t)
	t.Setenv("OPENROUTER_API_KEY", "sk-test")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-test")

	aiConf, err := config.AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env := mustHarnessConfig(t, aiConf).Env
	if env["OPENROUTER_API_KEY"] != "sk-test" || env["AWS_ACCESS_KEY_ID"] != "AKIA-test" {
		t.Fatalf("harness env is missing forwarded credentials: %v", env)
	}
}

// TestBuildAgent_FailsOnMalformedMaxTurns: Python builds AIIntegrationConfig at
// import time, so the same value makes the node fail to boot.
func TestBuildAgent_FailsOnMalformedMaxTurns(t *testing.T) {
	clearNodeEnv(t)
	t.Setenv("CLOUDSECURITY_MAX_TURNS", "not-a-number")

	if _, err := BuildAgent("cloudsecurity", "8015", "d"); err == nil {
		t.Fatal("expected BuildAgent to fail on a malformed CLOUDSECURITY_MAX_TURNS")
	}
}

// --- registration parity -----------------------------------------------------

// pythonSurface is the ordered reasoner surface app.py registers: the two
// @app.reasoner() functions, then app.include_router(reasoner_router).
var pythonSurface = append([]string{"scan", "prove"}, reasoners.RouterNames()...)

func TestRegisterAll_SurfaceOrderAndTags(t *testing.T) {
	n := newTestNode(t)
	n.RegisterAll()

	if got := n.RegisteredNames(); !reflect.DeepEqual(got, pythonSurface) {
		t.Fatalf("registered surface =\n%v\nwant\n%v", got, pythonSurface)
	}
	if len(pythonSurface) != 22 {
		t.Fatalf("expected 22 reasoners (2 top-level + 20 router), have %d", len(pythonSurface))
	}

	// scan/prove are @app.reasoner() — no router tags.
	for _, name := range []string{"scan", "prove"} {
		if tags := n.TagsFor(name); len(tags) != 0 {
			t.Errorf("%s tags = %v, want none", name, tags)
		}
	}
	// The 20 router reasoners carry the AgentRouter's domain tags.
	want := []string{"cloud", "security", "infrastructure"}
	for _, name := range reasoners.RouterNames() {
		if tags := n.TagsFor(name); !reflect.DeepEqual(tags, want) {
			t.Errorf("%s tags = %v, want %v", name, tags, want)
		}
	}
}

// TestRegisterAll_EveryNameDispatches proves the surface is live on the agent,
// not merely recorded.
func TestRegisterAll_EveryNameDispatches(t *testing.T) {
	n := newTestNode(t)
	n.RegisterAll()

	for _, name := range n.RegisteredNames() {
		_, err := n.App.Execute(context.Background(), name, map[string]any{})
		if err != nil && strings.Contains(err.Error(), "unknown reasoner or skill") {
			t.Errorf("%s: not registered on the agent (%v)", name, err)
		}
	}
}

// --- scan()/prove() input binding -------------------------------------------

func TestScanInput_SignatureDefaults(t *testing.T) {
	in, err := afx.Bind[ScanInput](map[string]any{"repo_url": "/repo"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if in.Depth != "standard" || in.Branch != "main" || in.SeverityThreshold != "low" {
		t.Fatalf("defaults = %+v", in)
	}
	if in.IsPR || in.FailOnFindings {
		t.Fatal("is_pr / fail_on_findings must default to false")
	}
	for _, p := range []any{in.CommitSHA, in.BaseCommitSHA, in.MaxCostUSD, in.MaxDurationSeconds,
		in.MaxConcurrentHunters, in.MaxConcurrentProvers, in.PRID} {
		if !reflect.ValueOf(p).IsNil() {
			t.Fatalf("optional parameter %#v must default to None", p)
		}
	}
	if in.OutputFormats != nil || in.ComplianceFrameworks != nil || in.IncludePaths != nil || in.ExcludePaths != nil {
		t.Fatal("list parameters must default to None at the signature level")
	}
}

func TestProveInput_SignatureDefaults(t *testing.T) {
	in, err := afx.Bind[ProveInput](map[string]any{"repo_url": "/repo"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if in.CloudProvider != "aws" {
		t.Fatalf("cloud_provider = %q, want aws", in.CloudProvider)
	}
	if in.Depth != "standard" || in.Branch != "main" || in.SeverityThreshold != "low" {
		t.Fatalf("defaults = %+v", in)
	}
}

// TestScanInput_BuildsATierOneCloudSecurityInput ports the assertions app.py's
// scan() construction implies.
func TestScanInput_BuildsATierOneCloudSecurityInput(t *testing.T) {
	in, err := afx.Bind[ScanInput](map[string]any{"repo_url": "/repo"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := in.CloudSecurityInput()

	if got.RepoURL != "/repo" {
		t.Errorf("repo_url = %q", got.RepoURL)
	}
	if got.Cloud != nil {
		t.Error("scan() must build cloud=None (Tier 1)")
	}
	if got.Tier() != 1 {
		t.Errorf("tier = %d, want 1", got.Tier())
	}
	if !reflect.DeepEqual(got.OutputFormats, []string{"json"}) {
		t.Errorf("output_formats = %v, want [json]", got.OutputFormats)
	}
	if !reflect.DeepEqual(got.ComplianceFrameworks, []string{}) {
		t.Errorf("compliance_frameworks = %v, want []", got.ComplianceFrameworks)
	}
	wantExclude := []string{"tests/", ".git/", "examples/", ".terraform/"}
	if !reflect.DeepEqual(got.ExcludePaths, wantExclude) {
		t.Errorf("exclude_paths = %v, want %v", got.ExcludePaths, wantExclude)
	}
	if got.IncludePaths != nil {
		t.Errorf("include_paths = %v, want nil (passed through untouched)", got.IncludePaths)
	}
}

// TestScanInput_EmptyListsTakeTheOrDefault pins Python's TRUTHINESS fallbacks:
// `output_formats or ["json"]` replaces an explicitly empty list too.
func TestScanInput_EmptyListsTakeTheOrDefault(t *testing.T) {
	in, err := afx.Bind[ScanInput](map[string]any{
		"repo_url":       "/repo",
		"output_formats": []any{},
		"exclude_paths":  []any{},
		"include_paths":  []any{},
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := in.CloudSecurityInput()

	if !reflect.DeepEqual(got.OutputFormats, []string{"json"}) {
		t.Errorf("output_formats = %v, want the [json] fallback", got.OutputFormats)
	}
	if len(got.ExcludePaths) != 4 {
		t.Errorf("exclude_paths = %v, want the four-entry fallback", got.ExcludePaths)
	}
	// include_paths is NOT an `or` fallback — the empty list survives.
	if got.IncludePaths == nil || len(got.IncludePaths) != 0 {
		t.Errorf("include_paths = %v, want the explicit empty list", got.IncludePaths)
	}
}

func TestScanInput_ExplicitValuesWin(t *testing.T) {
	in, err := afx.Bind[ScanInput](map[string]any{
		"repo_url":               "https://github.com/o/r",
		"depth":                  "thorough",
		"branch":                 "release",
		"severity_threshold":     "high",
		"output_formats":         []any{"sarif"},
		"compliance_frameworks":  []any{"cis_aws"},
		"max_cost_usd":           2.5,
		"max_duration_seconds":   900,
		"max_concurrent_hunters": 2,
		"max_concurrent_provers": 5,
		"exclude_paths":          []any{"vendor/"},
		"is_pr":                  true,
		"pr_id":                  "42",
		"fail_on_findings":       true,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := in.CloudSecurityInput()

	if got.Depth != "thorough" || got.Branch != "release" || got.SeverityThreshold != "high" {
		t.Fatalf("scalars = %+v", got)
	}
	if !reflect.DeepEqual(got.OutputFormats, []string{"sarif"}) ||
		!reflect.DeepEqual(got.ComplianceFrameworks, []string{"cis_aws"}) ||
		!reflect.DeepEqual(got.ExcludePaths, []string{"vendor/"}) {
		t.Fatalf("lists = %+v", got)
	}
	if got.MaxCostUSD == nil || *got.MaxCostUSD != 2.5 {
		t.Fatalf("max_cost_usd = %v", got.MaxCostUSD)
	}
	if got.MaxDurationSeconds == nil || *got.MaxDurationSeconds != 900 {
		t.Fatalf("max_duration_seconds = %v", got.MaxDurationSeconds)
	}
	if got.MaxConcurrentHunters == nil || *got.MaxConcurrentHunters != 2 {
		t.Fatalf("max_concurrent_hunters = %v", got.MaxConcurrentHunters)
	}
	if got.MaxConcurrentProvers == nil || *got.MaxConcurrentProvers != 5 {
		t.Fatalf("max_concurrent_provers = %v", got.MaxConcurrentProvers)
	}
	if !got.IsPR || !got.FailOnFindings || got.PRID == nil || *got.PRID != "42" {
		t.Fatalf("ci flags = %+v", got)
	}
}

// TestProveInput_BuildsATierTwoCloudSecurityInput pins the CloudConfig prove()
// constructs and the four parameters prove() deliberately does NOT accept.
func TestProveInput_BuildsATierTwoCloudSecurityInput(t *testing.T) {
	in, err := afx.Bind[ProveInput](map[string]any{"repo_url": "/repo"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := in.CloudSecurityInput()

	if got.Cloud == nil {
		t.Fatal("prove() must build a CloudConfig")
	}
	if got.Cloud.Provider != "aws" {
		t.Errorf("provider = %q, want aws", got.Cloud.Provider)
	}
	if !reflect.DeepEqual(got.Cloud.Regions, []string{"us-east-1"}) {
		t.Errorf("regions = %v, want [us-east-1]", got.Cloud.Regions)
	}
	if got.Cloud.AccountID != nil || got.Cloud.AssumeRoleARN != nil {
		t.Errorf("account_id/assume_role_arn = %v/%v, want nil", got.Cloud.AccountID, got.Cloud.AssumeRoleARN)
	}
	if got.Tier() != 2 {
		t.Errorf("tier = %d, want 2", got.Tier())
	}
	// prove()'s signature omits these four; they keep CloudSecurityInput's own
	// None defaults.
	if got.BaseCommitSHA != nil || got.MaxConcurrentHunters != nil ||
		got.MaxConcurrentProvers != nil || got.PRID != nil {
		t.Errorf("prove() must not populate base_commit_sha/max_concurrent_*/pr_id: %+v", got)
	}
}

func TestProveInput_CloudOverrides(t *testing.T) {
	in, err := afx.Bind[ProveInput](map[string]any{
		"repo_url":        "/repo",
		"cloud_provider":  "gcp",
		"cloud_regions":   []any{"europe-west1", "us-central1"},
		"assume_role_arn": "arn:aws:iam::1:role/scan",
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	got := in.CloudSecurityInput()
	if got.Cloud.Provider != "gcp" {
		t.Errorf("provider = %q", got.Cloud.Provider)
	}
	if !reflect.DeepEqual(got.Cloud.Regions, []string{"europe-west1", "us-central1"}) {
		t.Errorf("regions = %v", got.Cloud.Regions)
	}
	if got.Cloud.AssumeRoleARN == nil || *got.Cloud.AssumeRoleARN != "arn:aws:iam::1:role/scan" {
		t.Errorf("assume_role_arn = %v", got.Cloud.AssumeRoleARN)
	}
}

// TestAppExcludePathsMatchScanConfigDefaults documents that app.py's literal and
// config.py's DEFAULT_EXCLUDE_PATHS agree today. If they ever diverge in Python,
// this test tells the porter which copy changed.
func TestAppExcludePathsMatchScanConfigDefaults(t *testing.T) {
	if got, want := defaultExcludePaths(), config.DefaultExcludePaths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("app.py exclude paths %v != config defaults %v", got, want)
	}
}

// --- _run_pipeline error mapping --------------------------------------------

func TestRunPipeline_SetsRepoPathAndCheckpointDirBeforeRunning(t *testing.T) {
	n := newTestNode(t)
	repo := t.TempDir()
	n.resolveRepo = func(context.Context, string) (string, error) { return repo, nil }

	var seen *orch.ScanOrchestrator
	n.runOrchestrator = func(_ context.Context, o *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		seen = o
		return schemas.NewCloudSecurityScanResult(), nil
	}

	if _, err := n.runPipeline(context.Background(), scanInputFor("/repo")); err != nil {
		t.Fatalf("runPipeline: %v", err)
	}
	if seen == nil {
		t.Fatal("the orchestrator was never run")
	}
	if seen.RepoPath != repo {
		t.Fatalf("RepoPath = %q, want %q", seen.RepoPath, repo)
	}
	if want := filepath.Join(repo, ".cloudsecurity"); seen.CheckpointDir != want {
		t.Fatalf("CheckpointDir = %q, want %q", seen.CheckpointDir, want)
	}
}

// TestRunPipeline_ReturnsTheModelDump pins `return result.model_dump()`.
func TestRunPipeline_ReturnsTheModelDump(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		result := schemas.NewCloudSecurityScanResult()
		result.Repository = "/repo"
		return result, nil
	}

	out, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	if err != nil {
		t.Fatalf("runPipeline: %v", err)
	}
	payload, ok := out.(afx.Payload)
	if !ok {
		t.Fatalf("runPipeline returned %T, want afx.Payload", out)
	}
	m := payload.Map()
	if m["repository"] != "/repo" {
		t.Fatalf("repository = %#v", m["repository"])
	}
	for _, key := range []string{"findings", "attack_paths", "by_severity", "cost_breakdown", "timestamp"} {
		if _, present := m[key]; !present {
			t.Fatalf("model_dump is missing %q", key)
		}
	}
}

// TestRunPipeline_ValueErrorClassIsA400 pins `except ValueError -> 400` with the
// RAW message (no prefix).
func TestRunPipeline_ValueErrorClassIsA400(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }

	// A real afx.Bind failure — the Go form of a pydantic ValidationError, the
	// only ValueError subclass ScanOrchestrator.run() can raise.
	_, bindErr := afx.Bind[schemas.VerifiedFinding](map[string]any{"verdict": "maybe"})
	if bindErr == nil {
		t.Fatal("expected a bind failure to build the fixture")
	}
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		return schemas.CloudSecurityScanResult{}, bindErr
	}

	_, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	execErr := asExecuteError(t, err)
	if execErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", execErr.StatusCode)
	}
	if execErr.Message != bindErr.Error() {
		t.Fatalf("message = %q, want the raw %q", execErr.Message, bindErr.Error())
	}
	if strings.Contains(execErr.Message, "scan execution failed") {
		t.Fatal("the 400 branch must not carry the 500 prefix")
	}
}

// TestRunPipeline_OtherFailuresAre500WithThePrefix pins
// `except Exception -> 500 {"error": f"scan execution failed: {exc}"}`.
func TestRunPipeline_OtherFailuresAre500WithThePrefix(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		// The RuntimeError shape _unwrap raises.
		return schemas.CloudSecurityScanResult{}, errors.New("hunt_phase failed: boom")
	}

	var out strings.Builder
	previous := scanErrorOut
	scanErrorOut = &out
	t.Cleanup(func() { scanErrorOut = previous })

	_, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	execErr := asExecuteError(t, err)
	if execErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", execErr.StatusCode)
	}
	if execErr.Message != "scan execution failed: hunt_phase failed: boom" {
		t.Fatalf("message = %q", execErr.Message)
	}
	// Python prints `SCAN ERROR: {exc}` before raising.
	if !strings.HasPrefix(out.String(), "SCAN ERROR: hunt_phase failed: boom") {
		t.Fatalf("diagnostic = %q", out.String())
	}
}

// TestRunPipeline_PreTryFailuresAre500WithoutThePrefix covers the statements
// app.py runs OUTSIDE its try/except: the orchestrator constructor and
// _resolve_repo. Python leaves both uncaught (FastAPI renders a generic 500);
// Go reports 500 with the message and without the prefix.
func TestRunPipeline_PreTryFailuresAre500WithoutThePrefix(t *testing.T) {
	t.Run("orchestrator construction", func(t *testing.T) {
		n := newTestNode(t)
		n.resolveRepo = func(context.Context, string) (string, error) {
			t.Fatal("_resolve_repo must not run after the constructor failed")
			return "", nil
		}
		n.newOrchestrator = func(appx.App, schemas.CloudSecurityInput) (*orch.ScanOrchestrator, error) {
			// What ScanConfig.from_input raises for an unknown depth.
			return nil, errors.New("'bogus' is not a valid DepthProfile")
		}

		_, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
		execErr := asExecuteError(t, err)
		if execErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (the constructor runs outside the try)", execErr.StatusCode)
		}
		if execErr.Message != "'bogus' is not a valid DepthProfile" {
			t.Fatalf("message = %q", execErr.Message)
		}
	})

	t.Run("repo resolution", func(t *testing.T) {
		n := newTestNode(t)
		n.resolveRepo = func(context.Context, string) (string, error) {
			return "", errors.New("git clone failed: fatal: repository not found")
		}
		n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
			t.Fatal("the orchestrator must not run when the repo cannot be resolved")
			return schemas.CloudSecurityScanResult{}, nil
		}

		_, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
		execErr := asExecuteError(t, err)
		if execErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", execErr.StatusCode)
		}
		if execErr.Message != "git clone failed: fatal: repository not found" {
			t.Fatalf("message = %q", execErr.Message)
		}
	})
}

// TestUnknownDepthReaches500ThroughTheRealOrchestrator is the end-to-end form of
// the constructor quirk: a bad `depth` looks like a 400 but Python builds the
// orchestrator before entering the try, so it is a 500.
func TestUnknownDepthReaches500ThroughTheRealOrchestrator(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }

	in := scanInputFor("/repo")
	in.Depth = "bogus"

	_, err := n.runPipeline(context.Background(), in)
	execErr := asExecuteError(t, err)
	if execErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", execErr.StatusCode)
	}
	if !strings.Contains(execErr.Message, "DepthProfile") {
		t.Fatalf("message = %q, want the DepthProfile ValueError", execErr.Message)
	}
}

// TestScanHandler_RejectsAMalformedBody: a body the ScanInput cannot bind is a
// client error, not a pipeline failure.
//
// The expectations come from running the real
// `Agent._validate_handler_input(body, fields)` (agentfield Python SDK) against
// cloudsecurity's own `scan` signature:
//
//	{}                              -> "Missing required field: repo_url"
//	{"depth": 17}                   -> "Missing required field: repo_url"
//	{"repo_url": None}              -> "Field 'repo_url' cannot be None"
//
// all rendered as HTTP 422 by agent.py:2120-2128.
func TestScanHandler_RejectsAMalformedBody(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"empty body", map[string]any{}, "Missing required field: repo_url"},
		{"only an optional parameter", map[string]any{"depth": 17}, "Missing required field: repo_url"},
		{"explicit null for a required parameter", map[string]any{"repo_url": nil}, "Field 'repo_url' cannot be None"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNode(t)
			n.resolveRepo = func(context.Context, string) (string, error) {
				t.Fatal("repo resolution must not run for an invalid body")
				return "", nil
			}
			n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
				t.Fatal("the pipeline must not run for an invalid body")
				return schemas.CloudSecurityScanResult{}, nil
			}

			_, err := n.scanHandler(context.Background(), tc.body)
			execErr := asExecuteError(t, err)
			if execErr.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (the Python endpoint's validation status)", execErr.StatusCode)
			}
			if execErr.Message != tc.want {
				t.Fatalf("message = %q, want %q", execErr.Message, tc.want)
			}
		})
	}
}

// TestScanHandler_CoercesScalarsThePythonSDKCoerces is the other direction of
// the same contract: the Python SDK's `str(value)` / `int(value)` /
// `float(value)` / bool whitelist run BEFORE the handler, so these bodies are
// accepted by the Python node and must be accepted here. Ground truth, from the
// real _validate_handler_input on scan():
//
//	{"repo_url": 123}                        -> repo_url == "123"
//	{"repo_url": "/r", "is_pr": "yes"}       -> is_pr is True
//
// and, for the nullable ints/floats the SDK leaves alone, from pydantic's lax
// validation of CloudSecurityInput:
//
//	max_concurrent_hunters="4"  -> 4
//	max_cost_usd="2.5"          -> 2.5
func TestScanHandler_CoercesScalarsThePythonSDKCoerces(t *testing.T) {
	var got schemas.CloudSecurityInput
	n := newTestNode(t)
	n.resolveRepo = func(_ context.Context, url string) (string, error) { return url, nil }
	n.newOrchestrator = func(_ appx.App, in schemas.CloudSecurityInput) (*orch.ScanOrchestrator, error) {
		got = in
		return &orch.ScanOrchestrator{}, nil
	}
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		return schemas.CloudSecurityScanResult{}, nil
	}

	if _, err := n.scanHandler(context.Background(), map[string]any{
		"repo_url":               123,
		"is_pr":                  "yes",
		"fail_on_findings":       "true",
		"max_concurrent_hunters": "4",
		"max_cost_usd":           "2.5",
		"depth":                  "quick",
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if got.RepoURL != "123" {
		t.Errorf("repo_url = %q, want \"123\" (Python str(123))", got.RepoURL)
	}
	if !got.IsPR {
		t.Error("is_pr = false, want true (the \"yes\" whitelist)")
	}
	if !got.FailOnFindings {
		t.Error("fail_on_findings = false, want true")
	}
	if got.MaxConcurrentHunters == nil || *got.MaxConcurrentHunters != 4 {
		t.Errorf("max_concurrent_hunters = %v, want 4", got.MaxConcurrentHunters)
	}
	if got.MaxCostUSD == nil || *got.MaxCostUSD != 2.5 {
		t.Errorf("max_cost_usd = %v, want 2.5", got.MaxCostUSD)
	}
}

// TestScanHandler_DropsUndeclaredKeys pins `result = {}` in
// _validate_handler_input: the handler is called with the validated map, not
// the raw body, so an undeclared key can never reach the model.
func TestScanHandler_DropsUndeclaredKeys(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(_ context.Context, url string) (string, error) { return url, nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		return schemas.CloudSecurityScanResult{}, nil
	}
	if _, err := n.scanHandler(context.Background(), map[string]any{
		"repo_url":    "/repo",
		"unknown_key": []any{"whatever"},
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
}

// TestScanAndProveHandlersShareThePipeline proves both top-level reasoners run
// the same _run_pipeline, differing only in the CloudSecurityInput they build.
func TestScanAndProveHandlersShareThePipeline(t *testing.T) {
	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }

	var tiers []int
	n.runOrchestrator = func(_ context.Context, o *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		tiers = append(tiers, o.Input.Tier())
		return schemas.NewCloudSecurityScanResult(), nil
	}

	if _, err := n.scanHandler(context.Background(), map[string]any{"repo_url": "/repo"}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := n.proveHandler(context.Background(), map[string]any{"repo_url": "/repo"}); err != nil {
		t.Fatalf("prove: %v", err)
	}
	if !reflect.DeepEqual(tiers, []int{1, 2}) {
		t.Fatalf("tiers = %v, want [1 2] (scan is static-only, prove is live)", tiers)
	}
}

// --- the ValueError-class marker --------------------------------------------

// TestIsValueErrorClass_PinsTheAfxBindMarker asserts the marker against a REAL
// afx.Bind failure, so a change to afx's message text fails here loudly instead
// of silently downgrading every 400 to a 500.
func TestIsValueErrorClass_PinsTheAfxBindMarker(t *testing.T) {
	// pydantic raises ValidationError for BOTH of these, and both are
	// ValueError subclasses, so both must reach app.py's `except ValueError`
	// branch: a bad enum value and a MISSING REQUIRED field.
	full := map[string]any{
		"title": "t", "verdict": "confirmed", "severity": "high", "category": "c",
	}
	badEnum := map[string]any{}
	for k, v := range full {
		badEnum[k] = v
	}
	badEnum["severity"] = "catastrophic"

	for name, payload := range map[string]map[string]any{
		"invalid enum":           badEnum,
		"missing required field": {"verdict": "confirmed"},
	} {
		_, err := afx.Bind[schemas.VerifiedFinding](payload)
		if err == nil {
			t.Fatalf("%s: expected a bind failure", name)
		}
		if !strings.Contains(err.Error(), afxBindErrorMarker) {
			t.Fatalf("%s: afx.Bind message %q no longer contains %q — update afxBindErrorMarker", name, err, afxBindErrorMarker)
		}
		if !isValueErrorClass(err) {
			t.Fatalf("%s: a pydantic-equivalent validation failure must map to the 400 branch", name)
		}
	}
}

// TestIsValueErrorClass_RelayedChildBindFailureIsNotValueErrorClass pins the
// half text-matching gets wrong.
//
// A bind failure inside a CHILD reasoner is published by that child's SDK
// handler as `{"error": "afx.Bind: ..."}`, recorded by the control plane as the
// execution's error_message, and relayed to this process as an
// *agent.ExecuteError whose text still starts with the marker. In Python that
// arrives as agentfield.exceptions.ExecutionFailedError, whose MRO is
// (ExecutionFailedError, AgentFieldClientError, AgentFieldError, Exception) —
// NOT a ValueError — so app.py:222-232 takes the `except Exception` branch and
// answers 500 with the "scan execution failed: " prefix. Classifying it 400
// because the relayed text contains "afx.Bind: " inverts the
// client-error/retryable class every caller branches on.
func TestIsValueErrorClass_RelayedChildBindFailureIsNotValueErrorClass(t *testing.T) {
	relayed := &agent.ExecuteError{
		StatusCode: 502,
		Message:    `afx.Bind: 1 validation error for VerifiedFinding: verdict: Field required`,
	}
	if !strings.Contains(relayed.Error(), afxBindErrorMarker) {
		t.Fatalf("premise broken: the relayed message no longer carries %q", afxBindErrorMarker)
	}
	if isValueErrorClass(relayed) {
		t.Fatal("a relayed child failure must take the 500 branch, as Python's `except Exception` does")
	}

	n := newTestNode(t)
	n.resolveRepo = func(context.Context, string) (string, error) { return t.TempDir(), nil }
	n.runOrchestrator = func(context.Context, *orch.ScanOrchestrator) (schemas.CloudSecurityScanResult, error) {
		return schemas.CloudSecurityScanResult{}, relayed
	}
	_, err := n.runPipeline(context.Background(), scanInputFor("/repo"))
	execErr := asExecuteError(t, err)
	if execErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", execErr.StatusCode)
	}
	if want := "scan execution failed: " + relayed.Error(); execErr.Message != want {
		t.Errorf("message = %q, want %q", execErr.Message, want)
	}
}

func TestIsValueErrorClass_NonValueErrors(t *testing.T) {
	for _, err := range []error{
		nil,
		errors.New("run_iac_reader failed: boom"),   // RuntimeError (_unwrap)
		errors.New("'verified'"),                    // KeyError
		errors.New("post /api/v1/execute: timeout"), // transport
	} {
		if isValueErrorClass(err) {
			t.Errorf("isValueErrorClass(%v) = true, want false", err)
		}
	}
}

// --- helpers -----------------------------------------------------------------

// mustHarnessConfig is harnessConfig with the boot-failure error asserted away.
func mustHarnessConfig(t *testing.T, c config.AIIntegrationConfig) *agent.HarnessConfig {
	t.Helper()
	hc, err := harnessConfig(c)
	if err != nil {
		t.Fatalf("harnessConfig: %v", err)
	}
	return hc
}

// newTestNode builds a Node whose agent is real (so registration is real) but
// whose capability seam is a recording fake, and whose repo resolution and
// orchestrator run are stubbed by the caller.
func newTestNode(t *testing.T) *Node {
	t.Helper()
	clearNodeEnv(t)
	n, err := BuildAgent("cloudsecurity", "8015", "AI-Native Cloud Infrastructure Security Scanner")
	if err != nil {
		t.Fatalf("BuildAgent: %v", err)
	}
	n.pipelineApp = &appx.Fake{}
	return n
}

func scanInputFor(repoURL string) schemas.CloudSecurityInput {
	in := NewScanInput()
	in.RepoURL = repoURL
	return in.CloudSecurityInput()
}

func asExecuteError(t *testing.T, err error) *agent.ExecuteError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var execErr *agent.ExecuteError
	if !errors.As(err, &execErr) {
		t.Fatalf("error %v (%T) is not an *agent.ExecuteError", err, err)
	}
	return execErr
}

// TestBuildAgent_FailsOnUnwritableXDGDataHome: Python calls
// `_ai_config.provider_env()` inside app.py's module-level Agent(...) literal,
// so an unwritable XDG_DATA_HOME (a read-only volume, a path component that is
// a regular file) is an import-time crash and the node never registers.
// Verified against the repo venv: provider_env() raises NotADirectoryError.
func TestBuildAgent_FailsOnUnwritableXDGDataHome(t *testing.T) {
	clearNodeEnv(t)
	blocker := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", filepath.Join(blocker, "sub"))

	if _, err := BuildAgent("cloudsecurity", "8015", "d"); err == nil {
		t.Fatal("BuildAgent succeeded; Python's provider_env() crashes the import")
	}
}

// TestScanInput_NonFiniteMaxCostIsARegularRejection pins the shape of the
// failure for a non-finite `max_cost_usd`.
//
// Python accepts it — `CloudSecurityInput(repo_url="/tmp", max_cost_usd=v)` in
// the repo venv yields nan for "NaN"/"nan", inf for "Infinity"/"1e999" and
// -inf for "-inf" — and the scan then RUNS, because every budget comparison
// against a non-finite number is False. Go cannot represent that value in the
// JSON round trip afx.Bind performs, so it rejects; what this test pins is that
// the rejection is the ORDINARY uncoercible-optional decode error and not the
// Go-internals "marshal input: json: unsupported value: NaN" that the pyFloat
// coercion used to produce. See afx.pyFloat's comment and go/README.md's
// divergence list.
func TestScanInput_NonFiniteMaxCostIsARegularRejection(t *testing.T) {
	for _, spelling := range []string{"NaN", "nan", "Infinity", "-inf", "1e999"} {
		_, err := afx.BindHandlerInput[ScanInput](map[string]any{
			"repo_url":     "/r",
			"max_cost_usd": spelling,
		})
		if err == nil {
			t.Errorf("max_cost_usd=%q bound; Go cannot carry a non-finite float", spelling)
			continue
		}
		if got := err.Error(); strings.Contains(got, "marshal input") {
			t.Errorf("max_cost_usd=%q -> %q, want the ordinary decode error", spelling, got)
		}
	}
	// The finite control still coerces, exactly as pydantic does.
	in, err := afx.BindHandlerInput[ScanInput](map[string]any{"repo_url": "/r", "max_cost_usd": "2.5"})
	if err != nil {
		t.Fatalf("max_cost_usd=\"2.5\": %v", err)
	}
	if in.MaxCostUSD == nil || *in.MaxCostUSD != 2.5 {
		t.Fatalf("max_cost_usd = %v, want 2.5", in.MaxCostUSD)
	}
}
