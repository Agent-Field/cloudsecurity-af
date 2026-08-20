package config

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
)

// This file ports the config-related tests in tests/test_config.py. Each Go
// test names the Python test it came from so reviewers can diff coverage.
//
// Ground truth for the values asserted here was re-confirmed against this
// repo's interpreter:
//
//	PYTHONPATH=src ~/.agentfield/packages/cloudsecurity-af/venv/bin/python -c \
//	  "from cloudsecurity_af.config import *; print(ScanConfig.from_input(...).model_dump())"

// unsetEnv clears keys for the duration of the test and restores them after,
// standing in for pytest's monkeypatch.delenv(..., raising=False).
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if old, ok := os.LookupEnv(key); ok {
			k := key
			v := old
			t.Cleanup(func() { _ = os.Setenv(k, v) })
		} else {
			k := key
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unsetting %s: %v", key, err)
		}
	}
}

// allEnvKeys is every variable this package reads; clearing them gives a test a
// known-clean baseline regardless of the developer's shell.
func cleanEnv(t *testing.T) {
	t.Helper()
	unsetEnv(t,
		"CLOUDSECURITY_PROVIDER", "HARNESS_PROVIDER",
		"CLOUDSECURITY_MODEL", "HARNESS_MODEL",
		"CLOUDSECURITY_AI_MODEL", "AI_MODEL",
		"CLOUDSECURITY_MAX_TURNS",
		"CLOUDSECURITY_OPENCODE_BIN",
		"CLOUDSECURITY_AFORGE_BIN", "AFORGE_BIN",
		"AGENTFIELD_AFORGE_COMMAND", "XDG_DATA_HOME",
	)
	unsetEnv(t, providerEnvKeys...)
}

// ---------------------------------------------------------------------------
// AIIntegrationConfig — ports test_config.py's module-level tests
// ---------------------------------------------------------------------------

// Ports test_aforge_exec_is_the_default_harness.
func TestAforgeExecIsTheDefaultHarness(t *testing.T) {
	cleanEnv(t)

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.Provider != "aforge" {
		t.Errorf("Provider = %q, want aforge", cfg.Provider)
	}
	if cfg.AforgeBin != "aforge" {
		t.Errorf("AforgeBin = %q, want aforge", cfg.AforgeBin)
	}
	providerEnv, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	if got := providerEnv["AGENTFIELD_AFORGE_COMMAND"]; got != "exec" {
		t.Errorf("AGENTFIELD_AFORGE_COMMAND = %q, want exec", got)
	}
}

// Ports test_opencode_remains_an_explicit_rollback.
func TestOpencodeRemainsAnExplicitRollback(t *testing.T) {
	cleanEnv(t)
	t.Setenv("HARNESS_PROVIDER", "opencode")

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.Provider != "opencode" {
		t.Errorf("Provider = %q, want opencode", cfg.Provider)
	}
}

// Ports test_aforge_bin_is_overridable.
func TestAforgeBinIsOverridable(t *testing.T) {
	cleanEnv(t)

	t.Setenv("AFORGE_BIN", "/opt/aforge/bin/aforge")
	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.AforgeBin != "/opt/aforge/bin/aforge" {
		t.Errorf("AforgeBin = %q", cfg.AforgeBin)
	}

	// The node-specific variable wins over the generic one.
	t.Setenv("CLOUDSECURITY_AFORGE_BIN", "/usr/local/bin/aforge")
	cfg, err = AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	if cfg.AforgeBin != "/usr/local/bin/aforge" {
		t.Errorf("AforgeBin = %q", cfg.AforgeBin)
	}
}

// Ports test_installed_sdk_supports_the_aforge_harness: the pinned SDK must
// accept the provider/bin this node wires up. In Go the aforge/opencode binary
// override is the single HarnessConfig.BinPath field (the Python SDK has two
// separate aforge_bin/opencode_bin keyword arguments), which is why the node
// package picks between AforgeBin and OpencodeBin by provider — this test pins
// the SDK-side shape that choice targets.
func TestInstalledSDKSupportsTheAforgeHarness(t *testing.T) {
	cleanEnv(t)

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	providerEnv, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}
	hc := agent.HarnessConfig{
		Provider:       cfg.Provider,
		Model:          cfg.HarnessModel,
		MaxTurns:       cfg.MaxTurns,
		Env:            providerEnv,
		BinPath:        cfg.AforgeBin,
		PermissionMode: "auto",
	}
	if hc.Provider != "aforge" {
		t.Errorf("HarnessConfig.Provider = %q, want aforge", hc.Provider)
	}
	if hc.BinPath != "aforge" {
		t.Errorf("HarnessConfig.BinPath = %q, want aforge", hc.BinPath)
	}
}

// The precedence chains are the whole point of the default_factory lambdas, so
// each hop gets its own case.
func TestAIConfigFromEnv_Precedence(t *testing.T) {
	t.Run("all defaults", func(t *testing.T) {
		cleanEnv(t)
		cfg, err := AIConfigFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		want := AIIntegrationConfig{
			Provider:     "aforge",
			HarnessModel: "openrouter/minimax/minimax-m2.5",
			AIModel:      "openrouter/minimax/minimax-m2.5",
			MaxTurns:     50,
			OpencodeBin:  "opencode",
			AforgeBin:    "aforge",
		}
		if !reflect.DeepEqual(cfg, want) {
			t.Fatalf("config = %+v, want %+v", cfg, want)
		}
	})

	t.Run("generic vars are the second hop", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("HARNESS_PROVIDER", "opencode")
		t.Setenv("HARNESS_MODEL", "generic/model")
		t.Setenv("AI_MODEL", "generic/ai")
		cfg, _ := AIConfigFromEnv()
		if cfg.Provider != "opencode" || cfg.HarnessModel != "generic/model" || cfg.AIModel != "generic/ai" {
			t.Fatalf("config = %+v", cfg)
		}
	})

	t.Run("node vars win over generic", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("HARNESS_PROVIDER", "opencode")
		t.Setenv("CLOUDSECURITY_PROVIDER", "aforge")
		t.Setenv("HARNESS_MODEL", "generic/model")
		t.Setenv("CLOUDSECURITY_MODEL", "node/model")
		t.Setenv("AI_MODEL", "generic/ai")
		t.Setenv("CLOUDSECURITY_AI_MODEL", "node/ai")
		cfg, _ := AIConfigFromEnv()
		if cfg.Provider != "aforge" || cfg.HarnessModel != "node/model" || cfg.AIModel != "node/ai" {
			t.Fatalf("config = %+v", cfg)
		}
	})

	// ai_model's third hop is CLOUDSECURITY_MODEL — the harness model — not the
	// literal default.
	t.Run("ai_model falls back to the harness model", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("CLOUDSECURITY_MODEL", "node/model")
		cfg, _ := AIConfigFromEnv()
		if cfg.AIModel != "node/model" {
			t.Fatalf("AIModel = %q, want node/model", cfg.AIModel)
		}
	})

	// os.getenv(key, default) does NOT substitute for a key set to "".
	t.Run("a set-but-empty var is honoured, not defaulted", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("CLOUDSECURITY_PROVIDER", "")
		cfg, _ := AIConfigFromEnv()
		if cfg.Provider != "" {
			t.Fatalf("Provider = %q, want the empty string", cfg.Provider)
		}
	})
}

// Python parity: int() inside the default_factory raises, and because app.py
// builds the config at import time that means the node does not boot.
func TestAIConfigFromEnv_MalformedMaxTurnsIsAnError(t *testing.T) {
	cleanEnv(t)
	t.Setenv("CLOUDSECURITY_MAX_TURNS", "fifty")

	_, err := AIConfigFromEnv()
	if err == nil {
		t.Fatal("expected an error for a malformed CLOUDSECURITY_MAX_TURNS")
	}
	want := "invalid literal for int() with base 10: 'fifty'"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestAIConfigFromEnv_MaxTurnsOverride(t *testing.T) {
	cleanEnv(t)
	t.Setenv("CLOUDSECURITY_MAX_TURNS", "7")
	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxTurns != 7 {
		t.Fatalf("MaxTurns = %d, want 7", cfg.MaxTurns)
	}
}

// ---------------------------------------------------------------------------
// provider_env
// ---------------------------------------------------------------------------

func TestProviderEnv_ForwardsOnlyNonEmptyCredentials(t *testing.T) {
	cleanEnv(t)
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	t.Setenv("OPENROUTER_API_KEY", "or-key")
	t.Setenv("AWS_ACCESS_KEY_ID", "akid")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "") // set-but-empty -> dropped

	cfg, _ := AIConfigFromEnv()
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}

	want := map[string]string{
		"OPENROUTER_API_KEY":        "or-key",
		"AWS_ACCESS_KEY_ID":         "akid",
		"AGENTFIELD_AFORGE_COMMAND": "exec",
		"XDG_DATA_HOME":             xdg,
	}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("ProviderEnv = %#v, want %#v", env, want)
	}
}

// The key list is a packaging contract (the manifest's user_environment block
// mirrors it), so it is pinned exactly and in order.
func TestProviderEnvKeys_MatchThePythonTuple(t *testing.T) {
	want := []string{
		"OPENROUTER_API_KEY",
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GOOGLE_API_KEY",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"AZURE_TENANT_ID",
		"AZURE_SUBSCRIPTION_ID",
	}
	if got := ProviderEnvKeys(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ProviderEnvKeys() = %#v, want %#v", got, want)
	}
}

func TestProviderEnv_CreatesTheDefaultXDGDataHome(t *testing.T) {
	cleanEnv(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // os.TempDir() reads $TMPDIR

	cfg, _ := AIConfigFromEnv()
	env, err := cfg.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}

	want := filepath.Join(tmp, "opencode-shared-data")
	if env["XDG_DATA_HOME"] != want {
		t.Fatalf("XDG_DATA_HOME = %q, want %q", env["XDG_DATA_HOME"], want)
	}
	info, err := os.Stat(want)
	if err != nil || !info.IsDir() {
		t.Fatalf("ProviderEnv did not create %s: %v", want, err)
	}
}

// Python parity: XDG_DATA_HOME uses `or`, so a set-but-EMPTY value still falls
// back — unlike AGENTFIELD_AFORGE_COMMAND, which uses os.getenv's default and
// therefore keeps an explicit "".
func TestProviderEnv_EmptyStringHandlingDiffersPerKey(t *testing.T) {
	cleanEnv(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("AGENTFIELD_AFORGE_COMMAND", "")

	env, _ := AIConfigFromEnv()
	got, err := env.ProviderEnv()
	if err != nil {
		t.Fatalf("ProviderEnv: %v", err)
	}

	if got["XDG_DATA_HOME"] != filepath.Join(tmp, "opencode-shared-data") {
		t.Errorf("XDG_DATA_HOME = %q, want the temp fallback", got["XDG_DATA_HOME"])
	}
	if got["AGENTFIELD_AFORGE_COMMAND"] != "" {
		t.Errorf("AGENTFIELD_AFORGE_COMMAND = %q, want the explicit empty string", got["AGENTFIELD_AFORGE_COMMAND"])
	}
}

// ---------------------------------------------------------------------------
// DepthProfile — ports test_config.py::TestDepthProfile
// ---------------------------------------------------------------------------

// Ports TestDepthProfile::test_enum_values.
func TestDepthProfile_EnumValues(t *testing.T) {
	if DepthQuick != "quick" || DepthStandard != "standard" || DepthThorough != "thorough" {
		t.Fatalf("depth values drifted: %q %q %q", DepthQuick, DepthStandard, DepthThorough)
	}
}

// Ports TestDepthProfile::test_quick_hunters and ::test_standard_hunters, and
// additionally pins the ORDER, which hunt_phase's fan-out preserves.
func TestDepthProfile_HunterMap(t *testing.T) {
	quick := DepthHunterMap[DepthQuick]
	wantQuick := []string{"iam", "network", "data", "secrets", "compute"}
	if !reflect.DeepEqual(quick, wantQuick) {
		t.Fatalf("quick hunters = %v, want %v", quick, wantQuick)
	}

	standard := DepthHunterMap[DepthStandard]
	wantStandard := []string{"iam", "network", "data", "secrets", "compute", "logging", "compliance"}
	if !reflect.DeepEqual(standard, wantStandard) {
		t.Fatalf("standard hunters = %v, want %v", standard, wantStandard)
	}
	if len(standard) != 7 {
		t.Fatalf("standard hunters len = %d, want 7", len(standard))
	}
	if !reflect.DeepEqual(DepthHunterMap[DepthThorough], wantStandard) {
		t.Fatalf("thorough hunters = %v, want the standard list", DepthHunterMap[DepthThorough])
	}
}

func TestHuntersForDepth_ReturnsAnIsolatedCopy(t *testing.T) {
	got := HuntersForDepth(DepthQuick)
	got[0] = "mutated"
	if DepthHunterMap[DepthQuick][0] != "iam" {
		t.Fatal("HuntersForDepth handed out the shared backing array")
	}
	if fallback := HuntersForDepth("nonsense"); !reflect.DeepEqual(fallback, DepthHunterMap[DepthStandard]) {
		t.Fatalf("unknown profile = %v, want the standard list", fallback)
	}
}

// Ports TestDepthProfile::test_chain_limits.
func TestDepthProfile_ChainLimits(t *testing.T) {
	want := map[DepthProfile]int{DepthQuick: 5, DepthStandard: 15, DepthThorough: 100}
	if !reflect.DeepEqual(DepthChainLimits, want) {
		t.Fatalf("DepthChainLimits = %v, want %v", DepthChainLimits, want)
	}
}

// Ports TestDepthProfile::test_prover_caps — WITH A DELIBERATE CORRECTION.
//
// The Python test asserts DEPTH_PROVER_CAPS[QUICK] == 10, but config.py has
// declared 20 since the value was raised; that Python assertion FAILS on main
// today (verified: `DEPTH_PROVER_CAPS[DepthProfile.QUICK]` prints 20 under this
// repo's interpreter). The port follows the code, which is what actually runs
// and what prove_phase caps against. If the Python test is ever repaired, it
// will move to 20 and match this.
func TestDepthProverCaps_QuickIsTwentyNotTheStalePythonTestValue(t *testing.T) {
	want := map[DepthProfile]int{DepthQuick: 20, DepthStandard: 30, DepthThorough: 10_000}
	if !reflect.DeepEqual(DepthProverCaps, want) {
		t.Fatalf("DepthProverCaps = %v, want %v", DepthProverCaps, want)
	}
}

// ---------------------------------------------------------------------------
// ParseDepth / NormalizeDepth
// ---------------------------------------------------------------------------

// Python: DepthProfile("bogus") -> ValueError: 'bogus' is not a valid DepthProfile
func TestParseDepth_IsStrictAndCaseSensitive(t *testing.T) {
	for _, ok := range []string{"quick", "standard", "thorough"} {
		if got, err := ParseDepth(ok); err != nil || string(got) != ok {
			t.Fatalf("ParseDepth(%q) = %v, %v", ok, got, err)
		}
	}
	for _, bad := range []string{"bogus", "Quick", "", "QUICK", "deep"} {
		_, err := ParseDepth(bad)
		if err == nil {
			t.Fatalf("ParseDepth(%q) accepted an invalid depth", bad)
		}
		want := "'" + bad + "' is not a valid DepthProfile"
		if err.Error() != want {
			t.Errorf("ParseDepth(%q) error = %q, want %q", bad, err.Error(), want)
		}
	}
}

// Ports reasoners/phases.py::_normalize_depth.
func TestNormalizeDepth_LowercasesAndFallsBackToStandard(t *testing.T) {
	cases := map[string]DepthProfile{
		"quick":    DepthQuick,
		"QUICK":    DepthQuick,
		"Quick":    DepthQuick,
		"standard": DepthStandard,
		"thorough": DepthThorough,
		"ThOrOuGh": DepthThorough,
		"bogus":    DepthStandard,
		"":         DepthStandard,
		"deep":     DepthStandard,
	}
	for in, want := range cases {
		if got := NormalizeDepth(in); got != want {
			t.Errorf("NormalizeDepth(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// BudgetConfig — ports test_config.py::TestBudgetConfig
// ---------------------------------------------------------------------------

// Ports TestBudgetConfig::test_defaults.
func TestBudgetConfig_Defaults(t *testing.T) {
	b := NewBudgetConfig()
	if b.MaxConcurrentHunters != 4 {
		t.Errorf("MaxConcurrentHunters = %d, want 4", b.MaxConcurrentHunters)
	}
	if b.MaxConcurrentProvers != 3 {
		t.Errorf("MaxConcurrentProvers = %d, want 3", b.MaxConcurrentProvers)
	}
	if b.MaxConcurrentChainChildren != 3 {
		t.Errorf("MaxConcurrentChainChildren = %d, want 3", b.MaxConcurrentChainChildren)
	}
	if b.MaxCostUSD != nil {
		t.Errorf("MaxCostUSD = %v, want nil", *b.MaxCostUSD)
	}
	if b.MaxDurationSeconds != nil {
		t.Errorf("MaxDurationSeconds = %v, want nil", *b.MaxDurationSeconds)
	}
	total := b.ReconBudgetPct + b.HuntBudgetPct + b.ChainBudgetPct + b.ProveBudgetPct + b.RemediateBudgetPct
	if math.Abs(total-1.0) > 1e-9 {
		t.Errorf("budget percentages total %v, want 1.0", total)
	}
}

func TestBudgetConfig_UnmarshalSeedsDefaults(t *testing.T) {
	var b BudgetConfig
	if err := json.Unmarshal([]byte(`{"max_concurrent_hunters": 1}`), &b); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if b.MaxConcurrentHunters != 1 {
		t.Errorf("MaxConcurrentHunters = %d, want 1", b.MaxConcurrentHunters)
	}
	if b.MaxConcurrentProvers != 3 || b.HuntBudgetPct != 0.35 {
		t.Errorf("defaults were not seeded: %+v", b)
	}
}

// ---------------------------------------------------------------------------
// ScanConfig — ports test_config.py::TestScanConfig
// ---------------------------------------------------------------------------

// testCloudSecurityInput mirrors schemas.CloudSecurityInput's serialized shape
// (that package is owned by another part of the port; this local copy keeps the
// config tests independent of its landing order). newTestInput seeds the same
// pydantic defaults the real model does.
type testCloudSecurityInput struct {
	RepoURL              string   `json:"repo_url"`
	Branch               string   `json:"branch"`
	Depth                string   `json:"depth"`
	SeverityThreshold    string   `json:"severity_threshold"`
	OutputFormats        []string `json:"output_formats"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	Cloud                any      `json:"cloud"`
	MaxCostUSD           *float64 `json:"max_cost_usd"`
	MaxDurationSeconds   *int     `json:"max_duration_seconds"`
	MaxConcurrentHunters *int     `json:"max_concurrent_hunters"`
	MaxConcurrentProvers *int     `json:"max_concurrent_provers"`
	IncludePaths         []string `json:"include_paths"`
	ExcludePaths         []string `json:"exclude_paths"`
}

func newTestInput(repoURL string) testCloudSecurityInput {
	return testCloudSecurityInput{
		RepoURL:              repoURL,
		Branch:               "main",
		Depth:                "standard",
		SeverityThreshold:    "low",
		OutputFormats:        DefaultOutputFormats(),
		ComplianceFrameworks: []string{},
		ExcludePaths:         DefaultExcludePaths(),
	}
}

// Ports TestScanConfig::test_from_input_tier1. The full expected model_dump is
// pinned because it is the Python transcript:
//
//	{'repo_path': '/tmp/repo', 'depth': <DepthProfile.QUICK: 'quick'>, 'tier': 1,
//	 'severity_threshold': 'low', 'output_formats': ['json'],
//	 'compliance_frameworks': [], 'include_paths': None,
//	 'exclude_paths': ['tests/', '.git/', 'examples/', '.terraform/'],
//	 'budget': {...max_concurrent_hunters: 4, max_concurrent_provers: 3...}}
func TestScanConfig_FromInputTier1(t *testing.T) {
	in := newTestInput("/tmp/repo")
	in.Depth = "quick"

	cfg, err := ScanConfigFromInput(in, "/tmp/repo")
	if err != nil {
		t.Fatalf("ScanConfigFromInput: %v", err)
	}
	if cfg.Depth != DepthQuick {
		t.Errorf("Depth = %q, want quick", cfg.Depth)
	}
	if cfg.Tier != 1 {
		t.Errorf("Tier = %d, want 1", cfg.Tier)
	}
	if cfg.RepoPath != "/tmp/repo" {
		t.Errorf("RepoPath = %q", cfg.RepoPath)
	}
	if cfg.SeverityThreshold != "low" {
		t.Errorf("SeverityThreshold = %q", cfg.SeverityThreshold)
	}
	if !reflect.DeepEqual(cfg.OutputFormats, []string{"json"}) {
		t.Errorf("OutputFormats = %v", cfg.OutputFormats)
	}
	if !reflect.DeepEqual(cfg.ComplianceFrameworks, []string{}) {
		t.Errorf("ComplianceFrameworks = %v", cfg.ComplianceFrameworks)
	}
	if cfg.IncludePaths != nil {
		t.Errorf("IncludePaths = %v, want nil (Python None)", cfg.IncludePaths)
	}
	if !reflect.DeepEqual(cfg.ExcludePaths, DefaultExcludePaths()) {
		t.Errorf("ExcludePaths = %v", cfg.ExcludePaths)
	}
	if cfg.Budget.MaxConcurrentHunters != 4 || cfg.Budget.MaxConcurrentProvers != 3 {
		t.Errorf("Budget = %+v, want the defaults", cfg.Budget)
	}
	if cfg.Budget.MaxCostUSD != nil || cfg.Budget.MaxDurationSeconds != nil {
		t.Errorf("Budget caps = %+v, want nil", cfg.Budget)
	}
}

// Ports TestScanConfig::test_from_input_tier2. Tier is CloudSecurityInput.tier,
// a @property that is 2 as soon as `cloud` is present, so the port derives it
// from the serialized `cloud` key.
func TestScanConfig_FromInputTier2(t *testing.T) {
	in := newTestInput("/tmp/repo")
	in.Cloud = map[string]any{"provider": "aws", "regions": []string{"us-east-1"}}

	cfg, err := ScanConfigFromInput(in, "/tmp/repo")
	if err != nil {
		t.Fatalf("ScanConfigFromInput: %v", err)
	}
	if cfg.Tier != 2 {
		t.Fatalf("Tier = %d, want 2", cfg.Tier)
	}
}

func TestScanConfig_ExplicitNullCloudIsStillTier1(t *testing.T) {
	cfg, err := ScanConfigFromInput(map[string]any{"depth": "standard", "cloud": nil}, "/tmp/repo")
	if err != nil {
		t.Fatalf("ScanConfigFromInput: %v", err)
	}
	if cfg.Tier != 1 {
		t.Fatalf("Tier = %d, want 1", cfg.Tier)
	}
}

// Ports TestScanConfig::test_from_input_budget_override.
func TestScanConfig_FromInputBudgetOverride(t *testing.T) {
	hunters, provers, cost := 2, 1, 5.0
	in := newTestInput("/tmp/repo")
	in.MaxConcurrentHunters = &hunters
	in.MaxConcurrentProvers = &provers
	in.MaxCostUSD = &cost

	cfg, err := ScanConfigFromInput(in, "/tmp/repo")
	if err != nil {
		t.Fatalf("ScanConfigFromInput: %v", err)
	}
	if cfg.Budget.MaxConcurrentHunters != 2 {
		t.Errorf("MaxConcurrentHunters = %d, want 2", cfg.Budget.MaxConcurrentHunters)
	}
	if cfg.Budget.MaxConcurrentProvers != 1 {
		t.Errorf("MaxConcurrentProvers = %d, want 1", cfg.Budget.MaxConcurrentProvers)
	}
	if cfg.Budget.MaxCostUSD == nil || *cfg.Budget.MaxCostUSD != 5.0 {
		t.Errorf("MaxCostUSD = %v, want 5.0", cfg.Budget.MaxCostUSD)
	}
}

// Python parity: from_input uses the STRICT DepthProfile constructor, so an
// unknown depth is a ValueError, which app.py turns into HTTP 400. It must NOT
// silently normalize to standard.
func TestScanConfig_FromInputRejectsAnUnknownDepth(t *testing.T) {
	in := newTestInput("/tmp/repo")
	in.Depth = "bogus"

	_, err := ScanConfigFromInput(in, "/tmp/repo")
	if err == nil {
		t.Fatal("expected a ValueError-equivalent for depth=bogus")
	}
	if err.Error() != "'bogus' is not a valid DepthProfile" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestScanConfig_FromInputAcceptsTheTypedView(t *testing.T) {
	cfg, err := ScanConfigFromInput(ScanInput{Depth: "thorough", Tier: 2, SeverityThreshold: "high"}, "/repo")
	if err != nil {
		t.Fatalf("ScanConfigFromInput: %v", err)
	}
	if cfg.Depth != DepthThorough || cfg.Tier != 2 || cfg.SeverityThreshold != "high" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestNewScanConfig_Defaults(t *testing.T) {
	cfg := NewScanConfig("/repo")
	if cfg.Depth != DepthStandard || cfg.Tier != 1 || cfg.SeverityThreshold != "low" {
		t.Fatalf("config = %+v", cfg)
	}
	// Mutating the returned slices must not affect the next call.
	cfg.ExcludePaths[0] = "mutated"
	if NewScanConfig("/repo").ExcludePaths[0] != "tests/" {
		t.Fatal("the exclude_paths default_factory handed out a shared slice")
	}
}

func TestScanConfig_UnmarshalSeedsDefaults(t *testing.T) {
	var cfg ScanConfig
	if err := json.Unmarshal([]byte(`{"repo_path": "/r", "tier": 2}`), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.RepoPath != "/r" || cfg.Tier != 2 {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Depth != DepthStandard || cfg.SeverityThreshold != "low" {
		t.Fatalf("defaults were not seeded: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.ExcludePaths, DefaultExcludePaths()) {
		t.Fatalf("ExcludePaths = %v", cfg.ExcludePaths)
	}
}

// VALIDATION CONTRACT — an unwritable XDG_DATA_HOME fails the BOOT.
//
// config.py:135 is a bare `os.makedirs(xdg, exist_ok=True)` (exist_ok
// suppresses only FileExistsError) and provider_env() runs in app.py's module
// body, inside the Agent(...) literal — so the process never registers.
// Ground truth from the repo venv, with XDG_DATA_HOME pointing under a path
// component that is a regular file:
//
//	AIIntegrationConfig.from_env().provider_env()
//	  -> NotADirectoryError: [Errno 20] Not a directory: '<tmp>/notadir/sub'
//
// Swallowing it instead lets the node register, answer /health 200 and appear
// live in the control-plane UI, then fail every scan deep inside the first
// harness invocation.
func TestProviderEnv_UnwritableXDGDataHomeIsAnError(t *testing.T) {
	cleanEnv(t)
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", filepath.Join(blocker, "sub"))

	cfg, err := AIConfigFromEnv()
	if err != nil {
		t.Fatalf("AIConfigFromEnv: %v", err)
	}
	env, err := cfg.ProviderEnv()
	if err == nil {
		t.Fatalf("ProviderEnv returned %#v; Python raises NotADirectoryError here", env)
	}
	if env != nil {
		t.Errorf("ProviderEnv returned a partial env alongside the error: %#v", env)
	}
	if !strings.Contains(err.Error(), "XDG_DATA_HOME") {
		t.Errorf("error %q does not name XDG_DATA_HOME", err)
	}
}
