package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// VALIDATION CONTRACT for the four RECON agents (from iac_reader.py,
// resource_graph_builder.py, cloud_connector.py and drift_detector.py):
//
//  1. run_iac_reader / run_resource_graph_builder try the deterministic path
//     first and only call the harness when it raises; the harness is NOT called
//     on the happy path.
//  2. Their work directory SURVIVES the call — the returned path points into it.
//     cloud_connector's and drift_detector's work directory is REMOVED in a
//     finally block.
//  3. Every harness call gets Cwd = the work dir and ProjectDir = the repo
//     (= the work dir itself for the two cloud agents).
//  4. Temp-dir prefixes are exactly "cloudsecurity-recon-iac-reader-",
//     "cloudsecurity-recon-graph-builder-", "cloudsecurity-recon-cloud-connector-"
//     and "cloudsecurity-recon-drift-detector-".
//  5. A harness error surfaces as `"<agent name> harness error: <message>"` with
//     the agent names "IaC reader", "Resource graph builder", "Cloud connector"
//     and "Drift detector".
//  6. The prompts are the templates with their placeholders substituted — see
//     golden_test.go for the byte-verbatim assertions.

const fixtureRepoPath = "/fixture/repo"

// harnessSpy records the options of every harness call and answers with canned
// JSON.
type harnessSpy struct {
	*appx.Fake
	opts []harness.Options
}

func newSpy(reply string) *harnessSpy {
	spy := &harnessSpy{Fake: &appx.Fake{}}
	inner := appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(reply), nil
	})
	spy.HarnessFn = func(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
		spy.opts = append(spy.opts, opts)
		return inner(ctx, prompt, schema, dest, opts)
	}
	return spy
}

func newFailingSpy(message string) *harnessSpy {
	spy := &harnessSpy{Fake: &appx.Fake{}}
	spy.HarnessFn = func(_ context.Context, _ string, _ map[string]any, _ any, opts harness.Options) (*harness.Result, error) {
		spy.opts = append(spy.opts, opts)
		return &harness.Result{IsError: true, ErrorMessage: message}, nil
	}
	return spy
}

// silenceDiagnostics redirects the stdout/stderr diagnostics the port emits so a
// passing test run stays quiet, and returns what was captured on stderr.
func silenceWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := warnOut
	warnOut = &buf
	t.Cleanup(func() { warnOut = prev })
	return &buf
}

// ---------------------------------------------------------------------------
// run_iac_reader
// ---------------------------------------------------------------------------

// Contract items 1 and 2.
func TestRunIaCReader_FastPathSkipsTheHarnessAndKeepsItsWorkDir(t *testing.T) {
	app := &appx.Fake{} // no HarnessFn: any harness call fails the test loudly

	got, err := RunIaCReader(context.Background(), app, vulnerableInfraFixture)
	if err != nil {
		t.Fatalf("RunIaCReader: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(got.InventorySavedPath)) })

	if len(app.Harnesses) != 0 {
		t.Errorf("the deterministic path must not call the harness, got %d calls", len(app.Harnesses))
	}
	if got.TotalResources != 7 {
		t.Errorf("TotalResources = %d, want 7", got.TotalResources)
	}
	if got.IaCType != "terraform" {
		t.Errorf("IaCType = %q, want %q", got.IaCType, "terraform")
	}
	if got.IaCVersion != nil {
		t.Errorf("IaCVersion = %v, want nil (Python leaves the default)", got.IaCVersion)
	}
	if filepath.Base(got.InventorySavedPath) != "inventory.json" {
		t.Errorf("InventorySavedPath = %q, want .../inventory.json", got.InventorySavedPath)
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(got.InventorySavedPath)), iacReaderTempPrefix) {
		t.Errorf("work dir %q does not use the %q prefix", got.InventorySavedPath, iacReaderTempPrefix)
	}
	// Contract item 2: the file must still be there — every downstream phase
	// reads it.
	if _, err := os.Stat(got.InventorySavedPath); err != nil {
		t.Errorf("inventory.json must survive the call: %v", err)
	}
}

// Contract items 1, 3, 5 and 6.
func TestRunIaCReader_FallsBackToTheHarnessWhenTheFastPathFails(t *testing.T) {
	warnings := silenceWarnings(t)

	prev := iacFastParseFn
	iacFastParseFn = func(string, string) (schemas.ResourceInventory, error) {
		return schemas.ResourceInventory{}, errors.New("pyhcl2 exploded")
	}
	t.Cleanup(func() { iacFastParseFn = prev })

	spy := newSpy(`{"inventory_saved_path":"/tmp/x/inventory.json","total_resources":3,"iac_type":"terraform"}`)
	got, err := RunIaCReader(context.Background(), spy.Fake, fixtureRepoPath)
	if err != nil {
		t.Fatalf("RunIaCReader: %v", err)
	}

	if len(spy.Harnesses) != 1 {
		t.Fatalf("harness calls = %d, want 1", len(spy.Harnesses))
	}
	if got.TotalResources != 3 || got.InventorySavedPath != "/tmp/x/inventory.json" {
		t.Errorf("harness result not returned: %+v", got)
	}

	opts := spy.opts[0]
	if opts.ProjectDir != fixtureRepoPath {
		t.Errorf("ProjectDir = %q, want %q", opts.ProjectDir, fixtureRepoPath)
	}
	if !strings.HasPrefix(filepath.Base(opts.Cwd), iacReaderTempPrefix) {
		t.Errorf("Cwd = %q, want a %q temp dir", opts.Cwd, iacReaderTempPrefix)
	}
	t.Cleanup(func() { _ = os.RemoveAll(opts.Cwd) })

	wantPrompt := goldenPrompt(t, "iac_reader_prompt.txt")
	if spy.Harnesses[0].Prompt != wantPrompt {
		t.Error("fallback prompt does not match the Python golden")
	}

	if w := warnings.String(); !strings.Contains(w, "Deterministic parser failed (pyhcl2 exploded), falling back to harness") {
		t.Errorf("missing the Python log.warning text, got %q", w)
	}
}

// Contract item 5.
func TestRunIaCReader_HarnessErrorUsesThePythonMessage(t *testing.T) {
	silenceWarnings(t)
	prev := iacFastParseFn
	iacFastParseFn = func(string, string) (schemas.ResourceInventory, error) {
		return schemas.ResourceInventory{}, errors.New("nope")
	}
	t.Cleanup(func() { iacFastParseFn = prev })

	spy := newFailingSpy("model timed out")
	_, err := RunIaCReader(context.Background(), spy.Fake, fixtureRepoPath)
	if err == nil {
		t.Fatal("want an error")
	}
	if want := "IaC reader harness error: model timed out"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	t.Cleanup(func() { _ = os.RemoveAll(spy.opts[0].Cwd) })
}

// ---------------------------------------------------------------------------
// run_resource_graph_builder
// ---------------------------------------------------------------------------

// Contract items 1 and 2.
func TestRunResourceGraphBuilder_FastPathSkipsTheHarness(t *testing.T) {
	app := &appx.Fake{}

	got, err := RunResourceGraphBuilder(context.Background(), app, fixtureRepoPath, pythonInventoryFixture)
	if err != nil {
		t.Fatalf("RunResourceGraphBuilder: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(got.GraphSavedPath)) })

	if len(app.Harnesses) != 0 {
		t.Errorf("the deterministic path must not call the harness, got %d calls", len(app.Harnesses))
	}
	if got.TotalNodes != 7 || got.TotalEdges != 1 {
		t.Errorf("(nodes, edges) = (%d, %d), want (7, 1) — the Python inventory's graph", got.TotalNodes, got.TotalEdges)
	}
	if filepath.Base(got.GraphSavedPath) != "graph.json" {
		t.Errorf("GraphSavedPath = %q, want .../graph.json", got.GraphSavedPath)
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(got.GraphSavedPath)), graphBuilderTempPrefix) {
		t.Errorf("work dir %q does not use the %q prefix", got.GraphSavedPath, graphBuilderTempPrefix)
	}
	if _, err := os.Stat(got.GraphSavedPath); err != nil {
		t.Errorf("graph.json must survive the call: %v", err)
	}
}

// Contract items 1, 3, 5 and 6 — reached naturally, by handing it an inventory
// path that does not exist.
func TestRunResourceGraphBuilder_FallsBackToTheHarnessOnAMissingInventory(t *testing.T) {
	warnings := silenceWarnings(t)

	spy := newSpy(`{"graph_saved_path":"/tmp/x/graph.json","total_nodes":4,"total_edges":2}`)
	missing := filepath.Join(t.TempDir(), "inventory.json")

	got, err := RunResourceGraphBuilder(context.Background(), spy.Fake, fixtureRepoPath, missing)
	if err != nil {
		t.Fatalf("RunResourceGraphBuilder: %v", err)
	}
	if got.TotalNodes != 4 || got.TotalEdges != 2 {
		t.Errorf("harness result not returned: %+v", got)
	}
	if len(spy.opts) != 1 {
		t.Fatalf("harness calls = %d, want 1", len(spy.opts))
	}
	opts := spy.opts[0]
	t.Cleanup(func() { _ = os.RemoveAll(opts.Cwd) })
	if opts.ProjectDir != fixtureRepoPath {
		t.Errorf("ProjectDir = %q, want the REPO path %q", opts.ProjectDir, fixtureRepoPath)
	}
	if !strings.HasPrefix(filepath.Base(opts.Cwd), graphBuilderTempPrefix) {
		t.Errorf("Cwd = %q, want a %q temp dir", opts.Cwd, graphBuilderTempPrefix)
	}

	// The prompt interpolates the INVENTORY path, not the repo path.
	if !strings.Contains(spy.Harnesses[0].Prompt, missing) {
		t.Error("the fallback prompt must carry the inventory path")
	}
	if w := warnings.String(); !strings.Contains(w, "Deterministic graph builder failed") {
		t.Errorf("missing the Python log.warning text, got %q", w)
	}
}

// Contract item 5.
func TestRunResourceGraphBuilder_HarnessErrorUsesThePythonMessage(t *testing.T) {
	silenceWarnings(t)
	spy := newFailingSpy("out of turns")
	_, err := RunResourceGraphBuilder(context.Background(), spy.Fake, fixtureRepoPath, filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("want an error")
	}
	if want := "Resource graph builder harness error: out of turns"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	t.Cleanup(func() { _ = os.RemoveAll(spy.opts[0].Cwd) })
}

// ---------------------------------------------------------------------------
// run_cloud_connector
// ---------------------------------------------------------------------------

// Contract items 2, 3 and 4.
func TestRunCloudConnector_HarnessOptionsAndTempDirLifecycle(t *testing.T) {
	spy := newSpy(`{"inventory_saved_path":"/live/inventory.json","total_resources":12,"iac_type":"terraform"}`)

	got, err := RunCloudConnector(context.Background(), spy.Fake, cloudConfigCaseA())
	if err != nil {
		t.Fatalf("RunCloudConnector: %v", err)
	}
	if got.TotalResources != 12 {
		t.Errorf("TotalResources = %d, want 12", got.TotalResources)
	}
	if len(spy.opts) != 1 {
		t.Fatalf("harness calls = %d, want 1", len(spy.opts))
	}

	opts := spy.opts[0]
	if !strings.HasPrefix(filepath.Base(opts.Cwd), "cloudsecurity-"+cloudConnectorAgentName+"-") {
		t.Errorf("Cwd = %q, want a cloudsecurity-recon-cloud-connector- temp dir", opts.Cwd)
	}
	if opts.ProjectDir != opts.Cwd {
		t.Errorf("ProjectDir = %q, want it equal to Cwd %q (Python: repo_path = harness_cwd)", opts.ProjectDir, opts.Cwd)
	}
	// Contract item 2: this agent DOES clean up (Python's finally: rmtree).
	if _, err := os.Stat(opts.Cwd); !os.IsNotExist(err) {
		t.Errorf("work dir %q must be removed after the call (stat err = %v)", opts.Cwd, err)
	}
}

// Contract item 5.
func TestRunCloudConnector_HarnessErrorUsesThePythonMessage(t *testing.T) {
	spy := newFailingSpy("no credentials")
	_, err := RunCloudConnector(context.Background(), spy.Fake, cloudConfigCaseA())
	if err == nil {
		t.Fatal("want an error")
	}
	if want := "Cloud connector harness error: no credentials"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	// Even on the error path the finally block runs.
	if _, statErr := os.Stat(spy.opts[0].Cwd); !os.IsNotExist(statErr) {
		t.Errorf("work dir must be removed on the error path too (stat err = %v)", statErr)
	}
}

// ---------------------------------------------------------------------------
// run_drift_detector
// ---------------------------------------------------------------------------

// Contract items 2, 3 and 4.
func TestRunDriftDetector_HarnessOptionsAndTempDirLifecycle(t *testing.T) {
	spy := newSpy(`{"drifted_resources":[],"iac_only_resources":["a"],"cloud_only_resources":["b"]}`)

	got, err := RunDriftDetector(context.Background(), spy.Fake, "/fixture/work/graph.json", cloudConfigCaseA())
	if err != nil {
		t.Fatalf("RunDriftDetector: %v", err)
	}
	if len(got.IaCOnlyResources) != 1 || got.IaCOnlyResources[0] != "a" {
		t.Errorf("IaCOnlyResources = %v, want [a]", got.IaCOnlyResources)
	}
	if len(spy.opts) != 1 {
		t.Fatalf("harness calls = %d, want 1", len(spy.opts))
	}

	opts := spy.opts[0]
	if !strings.HasPrefix(filepath.Base(opts.Cwd), "cloudsecurity-"+driftDetectorAgentName+"-") {
		t.Errorf("Cwd = %q, want a cloudsecurity-recon-drift-detector- temp dir", opts.Cwd)
	}
	if opts.ProjectDir != opts.Cwd {
		t.Errorf("ProjectDir = %q, want it equal to Cwd %q", opts.ProjectDir, opts.Cwd)
	}
	if _, err := os.Stat(opts.Cwd); !os.IsNotExist(err) {
		t.Errorf("work dir %q must be removed after the call (stat err = %v)", opts.Cwd, err)
	}
}

// Contract item 5.
func TestRunDriftDetector_HarnessErrorUsesThePythonMessage(t *testing.T) {
	spy := newFailingSpy("timeout")
	_, err := RunDriftDetector(context.Background(), spy.Fake, "/fixture/work/graph.json", cloudConfigCaseA())
	if err == nil {
		t.Fatal("want an error")
	}
	if want := "Drift detector harness error: timeout"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if _, statErr := os.Stat(spy.opts[0].Cwd); !os.IsNotExist(statErr) {
		t.Errorf("work dir must be removed on the error path too (stat err = %v)", statErr)
	}
}

// The ported Python bug: `{{IAC_GRAPH_PATH}}` is substituted but the template
// says `{{IAC_GRAPH_JSON}}`, so the graph path never reaches the model.
func TestBuildDriftDetectorPrompt_GraphPathSubstitutionIsANoOp(t *testing.T) {
	prompt, err := BuildDriftDetectorPrompt("/fixture/work/graph.json", cloudConfigCaseA())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "/fixture/work/graph.json") {
		t.Error("the graph path must NOT appear — Python substitutes a placeholder the template does not contain")
	}
	if !strings.Contains(prompt, "{{IAC_GRAPH_JSON}}") {
		t.Error("the literal {{IAC_GRAPH_JSON}} token must survive into the prompt, as it does in Python")
	}
}
