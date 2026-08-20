package hunt

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// The fixture inputs go/scripts/gen_golden.py used to capture every golden in
// testdata/golden. HUNT_REPO_PATH is absolute and non-existent on purpose: it
// makes str(Path(repo_path).resolve()) a no-op, so the goldens are
// machine-independent.
const (
	fixtureRepoPath  = "/fixture/repo"
	fixtureDepth     = "standard"
	fixtureGraph     = "testdata/fixture/graph.json"
	fixtureInventory = "testdata/fixture/inventory.json"
)

// hunterFn is the shape all seven exported entry points share.
type hunterFn func(context.Context, appx.Harnesser, string, string, string, string) (schemas.HuntResult, error)

// allHunters is the registration order of reasoners/hunt.py. The Go table is
// itself the parity assertion: a hunter added to Python without a Go entry (or
// with the wrong prompt/agent name/strategy) fails TestHunterSpecs.
var allHunters = []struct {
	// module is the Python file name, which is ALSO the agent name
	// extract_harness_result reports errors under and the golden basename.
	module   string
	spec     hunter
	run      hunterFn
	strategy string
	prompt   string
}{
	{"iam_hunter", iamHunter, RunIAMHunter, "iam", "hunt/iam.txt"},
	{"network_hunter", networkHunter, RunNetworkHunter, "network", "hunt/network.txt"},
	{"data_hunter", dataHunter, RunDataHunter, "data", "hunt/data.txt"},
	{"secrets_hunter", secretsHunter, RunSecretsHunter, "secrets", "hunt/secrets.txt"},
	{"compute_hunter", computeHunter, RunComputeHunter, "compute", "hunt/compute.txt"},
	{"logging_hunter", loggingHunter, RunLoggingHunter, "logging", "hunt/logging.txt"},
	{"compliance_hunter", complianceHunter, RunComplianceHunter, "compliance", "hunt/compliance.txt"},
}

// emptyHuntResult is what a schema-valid but empty model returns.
const emptyHuntResult = `{"findings": [], "total_raw": 0, "deduplicated_count": 0, ` +
	`"strategies_run": [], "hunt_duration_seconds": 0.0}`

func fakeReturning(body string) *appx.Fake {
	return &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return json.RawMessage(body), nil
		}),
	}
}

// ---------------------------------------------------------------------------
// Prompt goldens
// ---------------------------------------------------------------------------

// TestHunterPrompts_MatchThePythonGoldens is the byte-for-byte parity gate on
// everything that reaches the LLM: the template, the six chained replacements,
// and the three graph-context blocks util.BuildGraphContextForHunter produced.
// The goldens are captured by driving the REAL Python coroutines over the same
// fixture (go/scripts/gen_golden.py: gen_hunt_prompts).
func TestHunterPrompts_MatchThePythonGoldens(t *testing.T) {
	for _, h := range allHunters {
		h := h
		t.Run(h.module, func(t *testing.T) {
			app := fakeReturning(emptyHuntResult)
			if _, err := h.run(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth); err != nil {
				t.Fatalf("%s: %v", h.module, err)
			}
			if len(app.Harnesses) != 1 {
				t.Fatalf("%s: expected exactly one harness call, got %d", h.module, len(app.Harnesses))
			}
			want := readGolden(t, h.module+"_prompt.txt")
			if got := app.Harnesses[0].Prompt; got != want {
				t.Errorf("%s prompt differs from Python\n--- got ---\n%s\n--- want ---\n%s", h.module, got, want)
			}
		})
	}
}

// Every placeholder the template declares must be gone once the prompt is
// rendered — the Go counterpart of tests/test_utils.py::TestHuntPromptPlaceholders,
// which only checks that the placeholders EXIST in the template (that half
// lives in internal/prompts).
func TestHunterPrompts_LeaveNoPlaceholderBehind(t *testing.T) {
	placeholders := []string{
		"{{RESOURCE_GRAPH_SUMMARY}}", "{{INVENTORY_STATS}}", "{{RELEVANT_EDGES}}",
		"{{REPO_PATH}}", "{{DEPTH}}", "{{RECON_CONTEXT}}",
	}
	for _, h := range allHunters {
		prompt, err := h.spec.buildPrompt(fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
		if err != nil {
			t.Fatalf("%s: %v", h.module, err)
		}
		for _, placeholder := range placeholders {
			if strings.Contains(prompt, placeholder) {
				t.Errorf("%s: rendered prompt still contains %s", h.module, placeholder)
			}
		}
		// The two scalar substitutions must actually have landed.
		if !strings.Contains(prompt, fixtureRepoPath) {
			t.Errorf("%s: rendered prompt does not mention the repo path", h.module)
		}
		if !strings.Contains(prompt, "Depth profile: "+fixtureDepth) {
			t.Errorf("%s: rendered prompt does not carry the depth", h.module)
		}
	}
}

// The graph context is filtered per hunter, so each prompt must carry its own
// domain's resources and drop the others'.
func TestHunterPrompts_CarryTheirOwnDomainSlice(t *testing.T) {
	cases := []struct {
		module  string
		present []string
		absent  []string
	}{
		{"iam_hunter", []string{"aws_iam_role.admin", "aws_iam_policy.broad"}, []string{"aws_vpc.main", "aws_cloudtrail.audit"}},
		{"network_hunter", []string{"aws_vpc.main", "aws_subnet.private"}, []string{"aws_iam_role.admin", "aws_kms_key.master"}},
		{"data_hunter", []string{"aws_s3_bucket.data", "aws_kms_key.master"}, []string{"aws_iam_role.admin", "aws_vpc.main"}},
		{"secrets_hunter", []string{"aws_secretsmanager_secret.db", "aws_kms_key.master", "aws_instance.web"}, []string{"aws_vpc.main"}},
		{"compute_hunter", []string{"aws_instance.web"}, []string{"aws_vpc.main", "aws_iam_role.admin"}},
		{"logging_hunter", []string{"aws_cloudtrail.audit"}, []string{"aws_iam_role.admin", "aws_s3_bucket.data"}},
		// The compliance hunter's [""] reduces to no keywords, so it sees the
		// whole graph.
		{"compliance_hunter", []string{
			"aws_iam_role.admin", "aws_vpc.main", "aws_s3_bucket.data",
			"aws_instance.web", "aws_cloudtrail.audit", "aws_secretsmanager_secret.db",
		}, nil},
	}
	for _, tc := range cases {
		prompt := readGolden(t, tc.module+"_prompt.txt")
		for _, want := range tc.present {
			if !strings.Contains(prompt, want) {
				t.Errorf("%s: prompt is missing %s", tc.module, want)
			}
		}
		for _, unwanted := range tc.absent {
			if strings.Contains(prompt, unwanted) {
				t.Errorf("%s: prompt unexpectedly contains %s", tc.module, unwanted)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Harness invocation
// ---------------------------------------------------------------------------

// Python: app.harness(prompt=..., schema=HuntResult, cwd=str(Path(repo_path).resolve()),
// project_dir=repo_path). The captured Python kwargs live in
// testdata/golden/harness_options.json.
func TestHunters_HarnessOptionsMatchPython(t *testing.T) {
	var want map[string]struct {
		Schema     string `json:"schema"`
		Cwd        string `json:"cwd"`
		ProjectDir string `json:"project_dir"`
	}
	decodeGolden(t, "harness_options.json", &want)

	huntResultSchema := harnessx.SchemaFor[schemas.HuntResult]()

	for _, h := range allHunters {
		app := fakeReturning(emptyHuntResult)
		if _, err := h.run(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth); err != nil {
			t.Fatalf("%s: %v", h.module, err)
		}
		expected, ok := want[h.module]
		if !ok {
			t.Fatalf("%s: no captured Python options", h.module)
		}
		got := app.Harnesses[0]
		if got.Opts.Cwd != expected.Cwd {
			t.Errorf("%s: Cwd = %q, want %q", h.module, got.Opts.Cwd, expected.Cwd)
		}
		if got.Opts.ProjectDir != expected.ProjectDir {
			t.Errorf("%s: ProjectDir = %q, want %q", h.module, got.Opts.ProjectDir, expected.ProjectDir)
		}
		if expected.Schema != "HuntResult" {
			t.Fatalf("%s: Python passed schema=%s, expected HuntResult", h.module, expected.Schema)
		}
		if got.Schema == nil || got.Schema["title"] != huntResultSchema["title"] {
			t.Errorf("%s: harness did not receive the HuntResult schema (%v)", h.module, got.Schema)
		}
		// Nothing else is set here — provider/model/max_turns come from the
		// agent's default HarnessConfig, exactly as in Python.
		if got.Opts.Provider != "" || got.Opts.Model != "" || got.Opts.MaxTurns != 0 {
			t.Errorf("%s: unexpected per-call harness overrides: %+v", h.module, got.Opts)
		}
	}
}

// Cwd is the RESOLVED repo path while ProjectDir is the raw argument; they
// differ whenever the caller passes something relative or symlinked.
func TestHunters_CwdIsResolvedButProjectDirIsNot(t *testing.T) {
	dir := t.TempDir()
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolving the temp dir: %v", err)
	}
	real := filepath.Join(root, "repo")
	if err := os.MkdirAll(real, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(root, "repo-link")
	if err := os.Symlink("repo", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	app := fakeReturning(emptyHuntResult)
	if _, err := RunIAMHunter(context.Background(), app, link, fixtureGraph, fixtureInventory, fixtureDepth); err != nil {
		t.Fatalf("RunIAMHunter: %v", err)
	}
	opts := app.Harnesses[0].Opts
	if opts.Cwd != real {
		t.Errorf("Cwd = %q, want the resolved %q", opts.Cwd, real)
	}
	if opts.ProjectDir != link {
		t.Errorf("ProjectDir = %q, want the raw %q", opts.ProjectDir, link)
	}
}

// ---------------------------------------------------------------------------
// Result post-processing (the model_copy(update=...) block)
// ---------------------------------------------------------------------------

// The captured Python return for an all-defaults model: counts stay 0 (0 or 0
// is 0) and strategies_run is replaced by the hunter's own single label.
func TestHunters_EmptyResultMatchesPython(t *testing.T) {
	var want map[string]json.RawMessage
	decodeGolden(t, "empty_result.json", &want)

	for _, h := range allHunters {
		app := fakeReturning(emptyHuntResult)
		got, err := h.run(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
		if err != nil {
			t.Fatalf("%s: %v", h.module, err)
		}
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("%s: marshal: %v", h.module, err)
		}
		var gotAny, wantAny any
		if err := json.Unmarshal(gotJSON, &gotAny); err != nil {
			t.Fatalf("%s: %v", h.module, err)
		}
		if err := json.Unmarshal(want[h.module], &wantAny); err != nil {
			t.Fatalf("%s: %v", h.module, err)
		}
		if !jsonEqual(gotAny, wantAny) {
			t.Errorf("%s: model_dump differs\n got: %s\nwant: %s", h.module, gotJSON, want[h.module])
		}
	}
}

// `parsed.total_raw or len(findings)` — a ZERO count is backfilled from the
// finding count; a non-zero one is left alone.
func TestHunters_ZeroCountsAreBackfilledFromTheFindings(t *testing.T) {
	body := `{"findings": [` + rawFinding("f1") + `,` + rawFinding("f2") + `],
	          "total_raw": 0, "deduplicated_count": 0, "strategies_run": ["bogus"],
	          "hunt_duration_seconds": 1.5}`
	app := fakeReturning(body)
	got, err := RunIAMHunter(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
	if err != nil {
		t.Fatalf("RunIAMHunter: %v", err)
	}
	if got.TotalRaw != 2 {
		t.Errorf("TotalRaw = %d, want 2", got.TotalRaw)
	}
	if got.DeduplicatedCount != 2 {
		t.Errorf("DeduplicatedCount = %d, want 2", got.DeduplicatedCount)
	}
	// strategies_run is REPLACED, never merged.
	if len(got.StrategiesRun) != 1 || got.StrategiesRun[0] != "iam" {
		t.Errorf("StrategiesRun = %v, want [iam]", got.StrategiesRun)
	}
	// Everything else survives the model_copy untouched.
	if got.HuntDurationSeconds != 1.5 {
		t.Errorf("HuntDurationSeconds = %v, want 1.5", got.HuntDurationSeconds)
	}
	if len(got.Findings) != 2 || got.Findings[0].ID != "f1" {
		t.Errorf("findings were not preserved: %+v", got.Findings)
	}
}

func TestHunters_NonZeroCountsSurvive(t *testing.T) {
	body := `{"findings": [` + rawFinding("f1") + `], "total_raw": 9,
	          "deduplicated_count": 7, "strategies_run": [], "hunt_duration_seconds": 0.0}`
	app := fakeReturning(body)
	got, err := RunNetworkHunter(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
	if err != nil {
		t.Fatalf("RunNetworkHunter: %v", err)
	}
	if got.TotalRaw != 9 || got.DeduplicatedCount != 7 {
		t.Errorf("counts = (%d, %d), want (9, 7)", got.TotalRaw, got.DeduplicatedCount)
	}
	if len(got.StrategiesRun) != 1 || got.StrategiesRun[0] != "network" {
		t.Errorf("StrategiesRun = %v, want [network]", got.StrategiesRun)
	}
}

// Python parity: `x or y` only replaces FALSY values, so a negative count from
// a misbehaving model is truthy and is kept verbatim.
func TestHunters_NegativeCountsAreTruthyAndKept(t *testing.T) {
	body := `{"findings": [` + rawFinding("f1") + `], "total_raw": -1,
	          "deduplicated_count": -2, "strategies_run": [], "hunt_duration_seconds": 0.0}`
	app := fakeReturning(body)
	got, err := RunDataHunter(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
	if err != nil {
		t.Fatalf("RunDataHunter: %v", err)
	}
	if got.TotalRaw != -1 || got.DeduplicatedCount != -2 {
		t.Errorf("counts = (%d, %d), want (-1, -2)", got.TotalRaw, got.DeduplicatedCount)
	}
}

// Each hunter stamps its OWN strategy label, and only that one.
func TestHunters_StrategyLabels(t *testing.T) {
	for _, h := range allHunters {
		app := fakeReturning(emptyHuntResult)
		got, err := h.run(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
		if err != nil {
			t.Fatalf("%s: %v", h.module, err)
		}
		if len(got.StrategiesRun) != 1 || got.StrategiesRun[0] != h.strategy {
			t.Errorf("%s: StrategiesRun = %v, want [%s]", h.module, got.StrategiesRun, h.strategy)
		}
	}
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// extract_harness_result raises RuntimeError(f"{agent_name} harness error: {msg}")
// and the agent_name is the PYTHON MODULE name, not the strategy.
func TestHunters_HarnessErrorCarriesTheAgentName(t *testing.T) {
	for _, h := range allHunters {
		app := &appx.Fake{
			HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
				return nil, errBoom{}
			}),
		}
		_, err := h.run(context.Background(), app, fixtureRepoPath, fixtureGraph, fixtureInventory, fixtureDepth)
		if err == nil {
			t.Fatalf("%s: expected an error", h.module)
		}
		if want := h.module + " harness error: boom"; err.Error() != want {
			t.Errorf("%s: error = %q, want %q", h.module, err.Error(), want)
		}
	}
}

// A missing RECON artifact is NOT an error: build_graph_context_for_hunter
// swallows it and the hunter still runs, with an empty context.
func TestHunters_MissingReconArtifactsStillProduceAPrompt(t *testing.T) {
	app := fakeReturning(emptyHuntResult)
	got, err := RunComputeHunter(context.Background(), app,
		fixtureRepoPath, "testdata/fixture/absent.json", "testdata/fixture/absent.json", fixtureDepth)
	if err != nil {
		t.Fatalf("RunComputeHunter: %v", err)
	}
	if len(got.StrategiesRun) != 1 || got.StrategiesRun[0] != "compute" {
		t.Errorf("StrategiesRun = %v", got.StrategiesRun)
	}
	prompt := app.Harnesses[0].Prompt
	for _, want := range []string{
		"  - none matched this hunter domain",
		"  - no edges matched this hunter domain",
		"Total resources: 0",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt is missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Spec table
// ---------------------------------------------------------------------------

// The four values that distinguish the seven Python files, asserted against the
// Python literals. Keeping them in one place is what lets hunt.go hold a single
// shared body without losing per-hunter fidelity.
func TestHunterSpecs(t *testing.T) {
	for _, h := range allHunters {
		if h.spec.promptPath != h.prompt {
			t.Errorf("%s: promptPath = %q, want %q", h.module, h.spec.promptPath, h.prompt)
		}
		if h.spec.agentName != h.module {
			t.Errorf("%s: agentName = %q, want %q", h.module, h.spec.agentName, h.module)
		}
		if h.spec.strategy != h.strategy {
			t.Errorf("%s: strategy = %q, want %q", h.module, h.spec.strategy, h.strategy)
		}
		if len(h.spec.keywords) == 0 {
			t.Errorf("%s: no domain keywords", h.module)
		}
	}
	if len(allHunters) != 7 {
		t.Errorf("expected 7 hunters, got %d", len(allHunters))
	}
	// Every strategy label is a member of the HunterStrategy catalog in
	// schemas/hunt.py.
	for _, h := range allHunters {
		if !schemas.HunterStrategy(h.strategy).Valid() {
			t.Errorf("%s: %q is not a schemas.HunterStrategy", h.module, h.strategy)
		}
	}
}

// The keyword lists are what make each hunter's graph slice different; a
// copy-paste slip between two files would otherwise go unnoticed.
func TestHunterKeywordsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, h := range allHunters {
		key := strings.Join(h.spec.keywords, "|")
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s share a keyword list", other, h.module)
		}
		seen[key] = h.module
	}
	if got := strings.Join(complianceHunter.keywords, "|"); got != "" {
		t.Errorf("compliance keywords = %q, want the single empty string", got)
	}
}

// ---------------------------------------------------------------------------

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func rawFinding(id string) string {
	return `{"id": "` + id + `", "hunter_strategy": "iam", "title": "t", "description": "d",
	         "category": "overprivilege", "resources": [], "estimated_severity": "high",
	         "confidence": "medium", "iac_file": "iam.tf", "iac_line": 1,
	         "config_snippet": "", "benchmark_id": null, "fingerprint": "fp-` + id + `"}`
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("reading golden %s: %v (regenerate with go/scripts/gen_golden.py)", name, err)
	}
	return string(b)
}

func decodeGolden(t *testing.T, name string, dest any) {
	t.Helper()
	if err := json.Unmarshal([]byte(readGolden(t, name)), dest); err != nil {
		t.Fatalf("decoding golden %s: %v", name, err)
	}
}

func jsonEqual(a, b any) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(left) == string(right)
}
