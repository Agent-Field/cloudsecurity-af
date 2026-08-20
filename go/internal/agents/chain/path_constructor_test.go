package chain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// chainInputs mirrors go/scripts/gen_golden.py's chain inputs.json. Binding the
// SAME pydantic dumps the Python builder was driven with is what makes the
// golden comparison meaningful — the Go test never transcribes a fixture by
// hand.
type chainInputs struct {
	FindingsPair   []schemas.RawFinding         `json:"findings_pair"`
	FindingsSingle []schemas.RawFinding         `json:"findings_single"`
	DriftReport    schemas.DriftReport          `json:"drift_report"`
	Investigations []schemas.ChildInvestigation `json:"investigations"`
}

func loadInputs(t *testing.T) chainInputs {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", "inputs.json"))
	if err != nil {
		t.Fatalf("read inputs.json: %v", err)
	}
	var in chainInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("decode inputs.json: %v", err)
	}
	return in
}

func golden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(raw)
}

func goldenPath(name string) string { return filepath.Join("testdata", "golden", name) }

// ---------------------------------------------------------------------------
// Prompt goldens — the bytes that reach the model
// ---------------------------------------------------------------------------

// TestBuildParentPrompt_Golden pins _build_parent_prompt byte-for-byte across
// the three interesting graph-file states: a real graph, a missing file, and a
// file whose top-level JSON value is not an object.
func TestBuildParentPrompt_Golden(t *testing.T) {
	in := loadInputs(t)
	drift := in.DriftReport

	cases := []struct {
		name        string
		findings    []schemas.RawFinding
		graphPath   string
		drift       *schemas.DriftReport
		maxPaths    int
		maxChildren int
		want        string
	}{
		{"a_real_graph_with_drift", in.FindingsPair, goldenPath("graph.json"), &drift, 5, 3, "parent_prompt_a.txt"},
		{"b_missing_graph_no_drift", in.FindingsPair, goldenPath("does-not-exist.json"), nil, 1, 1, "parent_prompt_b.txt"},
		{"c_graph_is_a_list", in.FindingsSingle, goldenPath("graph_not_object.json"), nil, 2, 4, "parent_prompt_c.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BuildParentPrompt(tc.findings, tc.graphPath, tc.drift, tc.maxPaths, tc.maxChildren)
			if err != nil {
				t.Fatalf("BuildParentPrompt: %v", err)
			}
			if want := golden(t, tc.want); got != want {
				t.Errorf("parent prompt differs from Python\n%s", firstDiff(got, want))
			}
		})
	}
}

// TestBuildChildPrompt_Golden pins _child_prompt, including the .strip() of the
// model-authored child prompt and the trailing max_paths sentence.
func TestBuildChildPrompt_Golden(t *testing.T) {
	in := loadInputs(t)
	cases := []struct {
		name     string
		inv      schemas.ChildInvestigation
		maxPaths int
		want     string
	}{
		{"a_whitespace_wrapped", in.Investigations[0], 5, "child_prompt_a.txt"},
		{"b_plain", in.Investigations[1], 1, "child_prompt_b.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildChildPrompt(tc.inv, tc.maxPaths)
			if want := golden(t, tc.want); got != want {
				t.Errorf("child prompt differs from Python\n%s", firstDiff(got, want))
			}
		})
	}
}

// TestBuildParentPrompt_SubstitutionOrder pins the parity quirk that the four
// replacements run in sequence over the same accumulating string, so a
// placeholder embedded in an earlier value IS substituted afterwards.
func TestBuildParentPrompt_SubstitutionOrder(t *testing.T) {
	f := schemas.NewRawFinding()
	f.ID = "f-1"
	// {{MAX_CHILDREN}} is substituted BEFORE the findings JSON is spliced in,
	// so a title containing it survives; {{DRIFT_REPORT_JSON}} is substituted
	// AFTER, so a title containing it gets the drift report spliced in.
	f.Title = "{{MAX_CHILDREN}} and {{DRIFT_REPORT_JSON}}"
	f.IaCFile = "main.tf"

	got, err := BuildParentPrompt([]schemas.RawFinding{f}, goldenPath("does-not-exist.json"), nil, 5, 3)
	if err != nil {
		t.Fatalf("BuildParentPrompt: %v", err)
	}
	if !strings.Contains(got, `"title": "{{MAX_CHILDREN}} and {}"`) {
		t.Errorf("expected the later placeholder to be substituted inside the findings JSON and the earlier one to survive; got:\n%s", got)
	}
}

// ---------------------------------------------------------------------------
// _compact_finding
// ---------------------------------------------------------------------------

// TestCompactFinding_KeyOrderAndProjection asserts the 8-key projection, its
// dict-literal key ORDER (json.dumps preserves it, so it is prompt bytes) and
// the `resources` / `severity` conversions.
func TestCompactFinding_KeyOrderAndProjection(t *testing.T) {
	f := schemas.NewRawFinding()
	f.ID = "f-1"
	f.Title = "t"
	f.Category = "overprivilege"
	f.EstimatedSeverity = "critical"
	f.Resources = []schemas.AffectedResource{{ResourceID: "a"}, {ResourceID: "b"}}
	f.IaCFile = "main.tf"
	f.IaCLine = 12
	f.Fingerprint = "fp"

	got := compactFinding(f)
	wantKeys := []string{"id", "title", "category", "severity", "resources", "iac_file", "iac_line", "fingerprint"}
	if len(got) != len(wantKeys) {
		t.Fatalf("compactFinding produced %d keys, want %d: %v", len(got), len(wantKeys), got)
	}
	for i, k := range wantKeys {
		if got[i].K != k {
			t.Errorf("key %d = %q, want %q", i, got[i].K, k)
		}
	}
	if v, _ := got.Get("severity"); v != "critical" {
		t.Errorf("severity = %v, want the enum VALUE %q", v, "critical")
	}
	if v, _ := got.Get("resources"); fmt.Sprint(v) != "[a b]" {
		t.Errorf("resources = %v, want the resource_id list", v)
	}
	if v, _ := got.Get("iac_line"); v != 12 {
		t.Errorf("iac_line = %v (%T), want the int 12", v, v)
	}
}

// TestCompactFinding_NoResourcesRendersEmptyList pins that a finding with no
// resources dumps `[]`, not `null` — Python's `... if f.resources else []`.
func TestCompactFinding_NoResourcesRendersEmptyList(t *testing.T) {
	f := schemas.RawFinding{ID: "f"} // Resources is a nil slice
	if got := pyfmt.Dumps(compactFinding(f), 0); !strings.Contains(got, `"resources": []`) {
		t.Errorf("nil Resources rendered as %s, want an empty list", got)
	}
}

// ---------------------------------------------------------------------------
// _filter_graph_for_findings
// ---------------------------------------------------------------------------

func mustLoadOrdered(t *testing.T, text string) pyfmt.Ordered {
	t.Helper()
	v, err := pyfmt.Load([]byte(text))
	if err != nil {
		t.Fatalf("pyLoad: %v", err)
	}
	o, ok := v.(pyfmt.Ordered)
	if !ok {
		t.Fatalf("pyLoad produced %T, want an object", v)
	}
	return o
}

// TestFilterGraphForFindings_NeighborExpansion covers the whole contract:
// finding resources and iac_files seed the relevant set, one hop of edge
// traversal expands it, nodes and edges are filtered against it, non-dict
// entries are skipped, and `clusters` passes through untouched.
func TestFilterGraphForFindings_NeighborExpansion(t *testing.T) {
	graph := mustLoadOrdered(t, `{
	  "nodes": [
	    {"resource_id": "role", "kind": "seed"},
	    {"resource_id": "bucket", "kind": "neighbor"},
	    {"resource_id": "kms", "kind": "far"},
	    "not-a-dict",
	    {"kind": "no-id"}
	  ],
	  "edges": [
	    {"source": "role", "target": "bucket"},
	    {"source": "bucket", "target": "kms"},
	    {"source": "x", "target": "y"},
	    "not-a-dict"
	  ],
	  "clusters": [{"name": "prod"}],
	  "dropped": 1
	}`)

	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: "role"}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})

	if len(got) != 3 || got[0].K != "nodes" || got[1].K != "edges" || got[2].K != "clusters" {
		t.Fatalf("result keys = %v, want exactly nodes/edges/clusters in that order", got)
	}
	// relevant = {role} + neighbours of role = {bucket}. "kms" is two hops out.
	nodes := got[0].V.([]any)
	if len(nodes) != 2 {
		t.Fatalf("kept %d nodes, want 2 (role, bucket): %v", len(nodes), nodes)
	}
	// The bucket->kms edge has one endpoint outside the relevant set.
	edges := got[1].V.([]any)
	if len(edges) != 1 {
		t.Fatalf("kept %d edges, want 1 (role->bucket): %v", len(edges), edges)
	}
	if dump := pyfmt.Dumps(got[2].V, 0); dump != `[{"name": "prod"}]` {
		t.Errorf("clusters = %s, want the input value passed through untouched", dump)
	}
}

// TestFilterGraphForFindings_IaCFileIsASeed pins that a finding's iac_file
// joins the relevant-id set — the graph's node ids and the finding's file path
// live in the SAME set in Python.
func TestFilterGraphForFindings_IaCFileIsASeed(t *testing.T) {
	graph := mustLoadOrdered(t, `{"nodes": [{"resource_id": "main.tf"}], "edges": []}`)
	f := schemas.NewRawFinding()
	f.IaCFile = "main.tf"

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if nodes := got[0].V.([]any); len(nodes) != 1 {
		t.Errorf("iac_file did not seed the relevant set: %v", nodes)
	}
}

// TestFilterGraphForFindings_EmptyIaCFileIsNotASeed pins the `if f.iac_file:`
// guard: the empty string must NOT enter the set, or every edge with a missing
// `source` would match through the `.get("source", "")` default.
func TestFilterGraphForFindings_EmptyIaCFileIsNotASeed(t *testing.T) {
	graph := mustLoadOrdered(t, `{"nodes": [{"resource_id": ""}], "edges": [{"target": "x"}]}`)
	f := schemas.NewRawFinding() // IaCFile == ""

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if nodes := got[0].V.([]any); len(nodes) != 0 {
		t.Errorf("the empty iac_file seeded the relevant set: %v", nodes)
	}
}

// TestFilterGraphForFindings_MissingKeysAndTypes covers the two `.get` defaults
// that differ between the neighbour pass and the edge filter, and the
// missing-`clusters` fallback.
func TestFilterGraphForFindings_MissingKeysAndTypes(t *testing.T) {
	// "edges" is not a list and "nodes" is missing entirely.
	graph := mustLoadOrdered(t, `{"edges": "nope"}`)
	f := schemas.NewRawFinding()
	f.IaCFile = "main.tf"

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != `{"nodes": [], "edges": [], "clusters": []}` {
		t.Errorf("degenerate graph produced %s", dump)
	}
}

// TestFilterGraphForFindings_EdgeFilterUsesNoDefault pins the asymmetry: an edge
// missing `source` participates in NEIGHBOUR discovery through the `""` default
// but can never survive the edge FILTER, which uses `.get("source")` -> None.
func TestFilterGraphForFindings_EdgeFilterUsesNoDefault(t *testing.T) {
	graph := mustLoadOrdered(t, `{"nodes": [], "edges": [{"target": "role"}]}`)
	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: "role"}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if edges := got[1].V.([]any); len(edges) != 0 {
		t.Errorf("an edge with no source survived the filter: %v", edges)
	}
}

// TestFilterGraphForFindings_NonStringEndpointIsNotTheEmptyString pins the
// difference between "the key is absent" and "the key is present but not a
// string" in the neighbour pass.
//
// Python: `src = edge.get("source", "")` substitutes "" only for an ABSENT key;
// a present `5` stays 5, and `5 in finding_resources` (a set of str) is False.
// Verified against the repo venv on _filter_graph_for_findings with
//
//	graph    {"nodes":[{"resource_id":"aws_s3_bucket.logs"}],
//	          "edges":[{"source":5,"target":"aws_s3_bucket.logs"}]}
//	finding  resources=[AffectedResource(resource_id="")]
//
// -> {"nodes": [], "edges": [], "clusters": []}.
//
// Collapsing the non-string endpoint to "" instead makes it MATCH the empty
// resource_id and splices aws_s3_bucket.logs into {{RESOURCE_GRAPH_JSON}} in
// the CHAIN parent prompt.
func TestFilterGraphForFindings_NonStringEndpointIsNotTheEmptyString(t *testing.T) {
	graph := mustLoadOrdered(t, `{"nodes": [{"resource_id": "aws_s3_bucket.logs"}], "edges": [{"source": 5, "target": "aws_s3_bucket.logs"}], "clusters": []}`)
	f := schemas.NewRawFinding()
	// `resource_id: str` carries no min_length in either schema, so a model
	// may emit "" — that is what makes the collapse observable.
	f.Resources = []schemas.AffectedResource{{ResourceID: ""}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != `{"nodes": [], "edges": [], "clusters": []}` {
		t.Errorf("filtered graph = %s, want the empty graph Python produces", dump)
	}
}

// The other half of the same rule, also run against the venv: an ABSENT
// `source` key DOES take the "" default and therefore does promote its target.
func TestFilterGraphForFindings_AbsentEndpointKeyStillTakesTheEmptyDefault(t *testing.T) {
	graph := mustLoadOrdered(t, `{"nodes": [{"resource_id": "aws_s3_bucket.logs"}], "edges": [{"target": "aws_s3_bucket.logs"}], "clusters": []}`)
	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: ""}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != `{"nodes": [{"resource_id": "aws_s3_bucket.logs"}], "edges": [], "clusters": []}` {
		t.Errorf("filtered graph = %s, want the node Python keeps", dump)
	}
}

// ---------------------------------------------------------------------------
// RunPathConstructor
// ---------------------------------------------------------------------------

const planJSON = `{"investigations": [
  {"title": "one", "rationale": "", "findings_involved": [], "child_prompt": "a"},
  {"title": "two", "rationale": "", "findings_involved": [], "child_prompt": "b"},
  {"title": "three", "rationale": "", "findings_involved": [], "child_prompt": "c"}
]}`

func attackPathJSON(id string) string {
	return `{"id": "` + id + `", "title": "` + id + `", "description": "", "entry_point": "e", "target": "t"}`
}

// scriptedApp answers the parent call with plan and every child call with the
// JSON that child(prompt) returns; a nil/error return drops that child.
func scriptedApp(plan string, child func(prompt string) (string, error)) *appx.Fake {
	f := &appx.Fake{}
	f.HarnessFn = appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
		if strings.Contains(prompt, "You are the CHAIN parent harness") {
			return json.RawMessage(plan), nil
		}
		out, err := child(prompt)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(out), nil
	})
	return f
}

// TestRunPathConstructor_GuardReturnsZeroDuration covers the three short-circuit
// conditions. All three return a literal 0.0 duration and MUST NOT touch the
// harness or create a temp dir.
func TestRunPathConstructor_GuardReturnsZeroDuration(t *testing.T) {
	in := loadInputs(t)
	cases := []struct {
		name        string
		findings    []schemas.RawFinding
		maxPaths    int
		maxChildren int
	}{
		{"no_findings", nil, 5, 3},
		{"max_paths_zero", in.FindingsPair, 0, 3},
		{"max_children_zero", in.FindingsPair, 5, 0},
		{"max_paths_negative", in.FindingsPair, -1, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := &appx.Fake{} // unscripted: any harness call fails the test
			got, err := RunPathConstructor(context.Background(), app, tc.findings, goldenPath("graph.json"), tc.maxPaths, tc.maxChildren, nil)
			if err != nil {
				t.Fatalf("RunPathConstructor: %v", err)
			}
			if len(app.Harnesses) != 0 {
				t.Errorf("guard branch made %d harness calls, want 0", len(app.Harnesses))
			}
			if got.TotalPathsEvaluated != 0 || got.ViablePaths != 0 || len(got.AttackPaths) != 0 {
				t.Errorf("guard branch returned %+v, want an empty ChainResult", got)
			}
			if got.ChainDurationSeconds != 0.0 {
				t.Errorf("chain_duration_seconds = %v, want the literal 0.0", got.ChainDurationSeconds)
			}
			if dump, err := json.Marshal(got.AttackPaths); err != nil || string(dump) != "[]" {
				t.Errorf("attack_paths marshaled as %s, want []", dump)
			}
		})
	}
}

// TestRunPathConstructor_ParentHarnessOptions pins the parent call's cwd prefix
// and — the parity detail that separates CHAIN from every other phase — that it
// passes NO project_dir.
func TestRunPathConstructor_ParentHarnessOptions(t *testing.T) {
	in := loadInputs(t)
	app := scriptedApp(`{"investigations": []}`, nil)

	if _, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 5, 3, nil); err != nil {
		t.Fatalf("RunPathConstructor: %v", err)
	}
	if len(app.Harnesses) != 1 {
		t.Fatalf("made %d harness calls, want 1", len(app.Harnesses))
	}
	opts := app.Harnesses[0].Opts
	if base := filepath.Base(opts.Cwd); !strings.HasPrefix(base, pathConstructorTempPrefix) {
		t.Errorf("cwd = %q, want a tempdir named %q*", opts.Cwd, pathConstructorTempPrefix)
	}
	if opts.ProjectDir != "" {
		t.Errorf("project_dir = %q, want empty (Python passes only cwd)", opts.ProjectDir)
	}
	if _, err := os.Stat(opts.Cwd); !os.IsNotExist(err) {
		t.Errorf("temp dir %q survived the call (stat err = %v)", opts.Cwd, err)
	}
}

// TestRunPathConstructor_ParentFailurePropagates: only the parent call can fail
// the phase, and it does so with extract_harness_result's exact message.
func TestRunPathConstructor_ParentFailurePropagates(t *testing.T) {
	in := loadInputs(t)
	app := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return nil, errors.New("boom")
	})}

	_, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 5, 3, nil)
	if err == nil {
		t.Fatal("expected the parent harness failure to propagate")
	}
	if want := "PathConstructor harness error: boom"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

// TestRunPathConstructor_NoInvestigations returns an empty result but WITH a
// measured (rounded) duration, unlike the guard branch.
func TestRunPathConstructor_NoInvestigations(t *testing.T) {
	in := loadInputs(t)
	app := scriptedApp(`{"investigations": []}`, nil)

	got, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 5, 3, nil)
	if err != nil {
		t.Fatalf("RunPathConstructor: %v", err)
	}
	if got.TotalPathsEvaluated != 0 || got.ViablePaths != 0 || len(got.AttackPaths) != 0 {
		t.Errorf("got %+v, want an empty ChainResult", got)
	}
	if got.ChainDurationSeconds < 0 {
		t.Errorf("chain_duration_seconds = %v, want a measured duration", got.ChainDurationSeconds)
	}
	if r := pyfmt.Round(got.ChainDurationSeconds, 3); r != got.ChainDurationSeconds {
		t.Errorf("chain_duration_seconds = %v, want it rounded to 3 dp", got.ChainDurationSeconds)
	}
}

// TestRunPathConstructor_FansOutChildren covers the happy path end to end: the
// investigations are truncated to max_children, every child gets the prompt
// _child_prompt builds in the parent's cwd, and the counters line up.
func TestRunPathConstructor_FansOutChildren(t *testing.T) {
	in := loadInputs(t)
	app := scriptedApp(planJSON, func(prompt string) (string, error) {
		return attackPathJSON(strings.SplitN(prompt, "\n", 2)[0]), nil
	})

	got, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 5, 2, nil)
	if err != nil {
		t.Fatalf("RunPathConstructor: %v", err)
	}
	// max_children = 2 truncates the 3-investigation plan.
	if got.TotalPathsEvaluated != 2 {
		t.Errorf("total_paths_evaluated = %d, want 2 (truncated to max_children)", got.TotalPathsEvaluated)
	}
	if got.ViablePaths != 2 || len(got.AttackPaths) != 2 {
		t.Fatalf("viable_paths = %d / %d paths, want 2", got.ViablePaths, len(got.AttackPaths))
	}
	// gather preserves ORDER: path i comes from investigation i.
	if got.AttackPaths[0].ID != "a" || got.AttackPaths[1].ID != "b" {
		t.Errorf("paths = %q/%q, want them ordered by investigation index", got.AttackPaths[0].ID, got.AttackPaths[1].ID)
	}
	if len(app.Harnesses) != 3 {
		t.Fatalf("made %d harness calls, want 1 parent + 2 children", len(app.Harnesses))
	}
	parentCwd := app.Harnesses[0].Opts.Cwd
	for i, call := range app.Harnesses[1:] {
		if call.Opts.Cwd != parentCwd {
			t.Errorf("child %d ran in %q, want the parent's cwd %q", i, call.Opts.Cwd, parentCwd)
		}
		if call.Opts.ProjectDir != "" {
			t.Errorf("child %d got project_dir %q, want empty", i, call.Opts.ProjectDir)
		}
		if !strings.HasSuffix(call.Prompt, "- The parent will keep at most 5 final attack paths.") {
			t.Errorf("child %d prompt is not the _child_prompt output:\n%s", i, call.Prompt)
		}
	}
}

// TestRunPathConstructor_FailingChildrenAreDropped pins `except Exception:
// return None` — a child failure removes only that path and never fails the
// phase, and the surviving paths keep their investigation order.
func TestRunPathConstructor_FailingChildrenAreDropped(t *testing.T) {
	in := loadInputs(t)
	app := scriptedApp(planJSON, func(prompt string) (string, error) {
		switch {
		case strings.HasPrefix(prompt, "a"):
			return "", errors.New("harness exploded")
		case strings.HasPrefix(prompt, "b"):
			return `{"not": "an attack path"`, nil // unparsable
		}
		return attackPathJSON("c"), nil
	})

	got, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 5, 3, nil)
	if err != nil {
		t.Fatalf("child failures must not fail the phase: %v", err)
	}
	if got.TotalPathsEvaluated != 3 {
		t.Errorf("total_paths_evaluated = %d, want 3 (all investigations were attempted)", got.TotalPathsEvaluated)
	}
	if got.ViablePaths != 1 || len(got.AttackPaths) != 1 || got.AttackPaths[0].ID != "c" {
		t.Errorf("got %d viable paths %+v, want only the third child's", got.ViablePaths, got.AttackPaths)
	}
}

// TestRunPathConstructor_TruncatesToMaxPaths pins that viable_paths is counted
// AFTER the [:max_paths] slice, not before.
func TestRunPathConstructor_TruncatesToMaxPaths(t *testing.T) {
	in := loadInputs(t)
	app := scriptedApp(planJSON, func(prompt string) (string, error) {
		return attackPathJSON(strings.SplitN(prompt, "\n", 2)[0]), nil
	})

	got, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 2, 3, nil)
	if err != nil {
		t.Fatalf("RunPathConstructor: %v", err)
	}
	if got.TotalPathsEvaluated != 3 {
		t.Errorf("total_paths_evaluated = %d, want 3", got.TotalPathsEvaluated)
	}
	if got.ViablePaths != 2 || len(got.AttackPaths) != 2 {
		t.Errorf("viable_paths = %d / %d paths, want 2 (max_paths)", got.ViablePaths, len(got.AttackPaths))
	}
	if got.AttackPaths[0].ID != "a" || got.AttackPaths[1].ID != "b" {
		t.Errorf("kept %q/%q, want the FIRST max_paths in investigation order", got.AttackPaths[0].ID, got.AttackPaths[1].ID)
	}
}

// TestRunPathConstructor_ChildrenRunConcurrently pins the gather fan-out: CHAIN
// has NO semaphore, so all max_children children are in flight at once.
func TestRunPathConstructor_ChildrenRunConcurrently(t *testing.T) {
	in := loadInputs(t)

	const children = 3
	var mu sync.Mutex
	release := make(chan struct{})
	arrived := 0

	app := &appx.Fake{}
	app.HarnessFn = appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
		if strings.Contains(prompt, "You are the CHAIN parent harness") {
			return json.RawMessage(planJSON), nil
		}
		mu.Lock()
		arrived++
		all := arrived == children
		mu.Unlock()
		if all {
			close(release)
		}
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			return nil, errors.New("children did not run concurrently")
		}
		return json.RawMessage(attackPathJSON("p")), nil
	})

	got, err := RunPathConstructor(context.Background(), app, in.FindingsPair, goldenPath("graph.json"), 5, children, nil)
	if err != nil {
		t.Fatalf("RunPathConstructor: %v", err)
	}
	if got.ViablePaths != children {
		t.Fatalf("viable_paths = %d, want %d", got.ViablePaths, children)
	}
	if peak := app.MaxConcurrentHarness(); peak != children {
		t.Errorf("peak concurrent harness calls = %d, want %d (asyncio.gather with no semaphore)", peak, children)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// firstDiff renders the first differing line of two strings, which is far more
// readable than dumping two multi-KB prompts.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return fmt.Sprintf("first difference at line %d:\n  go:     %q\n  python: %q", i+1, g[i], w[i])
		}
	}
	return fmt.Sprintf("line counts differ: go %d lines, python %d lines", len(g), len(w))
}

// TestFilterGraphForFindings_NullEndpointJoinsTheIDSet pins that ids are
// compared BY VALUE, not as strings.
//
// Python's neighbour pass adds the opposite endpoint unconditionally
// (`if src in finding_resources: neighbors.add(tgt)`), so a JSON `null` target
// lands in relevant_ids and then matches both `n.get("resource_id") in
// relevant_ids` and the two-endpoint edge test. Ground truth from the repo venv
// on _filter_graph_for_findings with the graph below and one finding whose only
// resource_id is "a":
//
//	{"nodes": [{"resource_id": "a", "resource_type": "t"},
//	           {"resource_id": null, "resource_type": "nullid"}],
//	 "edges": [{"source": "a", "target": null, "type": "e1"},
//	           {"source": null, "target": "a", "type": "e2"}],
//	 "clusters": []}
//
// i.e. the input unchanged. Dropping the null-id node and both edges (what a
// map[string]bool id set does) changes the {{RESOURCE_GRAPH_JSON}} splice in
// the CHAIN parent prompt by two nodes' worth of text.
func TestFilterGraphForFindings_NullEndpointJoinsTheIDSet(t *testing.T) {
	const graphJSON = `{"nodes": [{"resource_id": "a", "resource_type": "t"}, {"resource_id": null, "resource_type": "nullid"}], "edges": [{"source": "a", "target": null, "type": "e1"}, {"source": null, "target": "a", "type": "e2"}], "clusters": []}`
	graph := mustLoadOrdered(t, graphJSON)

	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: "a"}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != graphJSON {
		t.Errorf("filtered graph = %s,\n                  want %s", dump, graphJSON)
	}
}

// A NUMERIC endpoint is promoted the same way, and its node survives even
// though `5` is not a string. Venv ground truth for the graph below with one
// finding whose only resource_id is "a":
//
//	{"nodes": [{"resource_id": "a"}, {"resource_id": 5}],
//	 "edges": [{"source": "a", "target": 5}], "clusters": []}
func TestFilterGraphForFindings_NumericEndpointJoinsTheIDSet(t *testing.T) {
	const graphJSON = `{"nodes": [{"resource_id": "a"}, {"resource_id": 5}], "edges": [{"source": "a", "target": 5}], "clusters": []}`
	graph := mustLoadOrdered(t, graphJSON)

	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: "a"}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != graphJSON {
		t.Errorf("filtered graph = %s,\n                  want %s", dump, graphJSON)
	}
}

// Once Python None is in relevant_ids, a node with NO resource_id key matches
// too, because `n.get("resource_id")` is None for it. Venv ground truth:
//
//	{"nodes": [{"resource_id": "a"}, {"kind": "no-id"}],
//	 "edges": [{"source": "a", "target": null}], "clusters": []}
func TestFilterGraphForFindings_NoneInTheSetKeepsIDLessNodes(t *testing.T) {
	const graphJSON = `{"nodes": [{"resource_id": "a"}, {"kind": "no-id"}], "edges": [{"source": "a", "target": null}], "clusters": []}`
	graph := mustLoadOrdered(t, graphJSON)

	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: "a"}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != graphJSON {
		t.Errorf("filtered graph = %s,\n                  want %s", dump, graphJSON)
	}
}

// Python hashes True == 1 into one set slot, so promoting `true` also keeps a
// node whose resource_id is the int 1. Venv ground truth for
// nodes=[{"resource_id": true}, {"resource_id": 1}],
// edges=[{"source": "a", "target": true}] and a finding with resource_id "a":
//
//	{"nodes": [{"resource_id": true}, {"resource_id": 1}],
//	 "edges": [{"source": "a", "target": true}], "clusters": []}
func TestFilterGraphForFindings_BoolAndIntShareASetSlot(t *testing.T) {
	const graphJSON = `{"nodes": [{"resource_id": true}, {"resource_id": 1}], "edges": [{"source": "a", "target": true}], "clusters": []}`
	graph := mustLoadOrdered(t, graphJSON)

	f := schemas.NewRawFinding()
	f.Resources = []schemas.AffectedResource{{ResourceID: "a"}}

	got := filterGraphForFindings(graph, []schemas.RawFinding{f})
	if dump := pyfmt.Dumps(got, 0); dump != graphJSON {
		t.Errorf("filtered graph = %s,\n                  want %s", dump, graphJSON)
	}
}
