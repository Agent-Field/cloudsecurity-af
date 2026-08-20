package reasoners_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdkagent "github.com/Agent-Field/agentfield/sdk/go/agent"
	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/prompts"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/reasoners"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// pythonRouterNames is the ordered surface Python registers on the
// AgentRouter, read straight off src/cloudsecurity_af/reasoners/: the
// __init__.py import order (recon, hunt, chain, prove, remediate, phases) and
// the decorator order inside each module.
var pythonRouterNames = []string{
	"run_iac_reader",
	"run_resource_graph_builder",
	"run_cloud_connector",
	"run_drift_detector",
	"run_iam_hunter",
	"run_network_hunter",
	"run_data_hunter",
	"run_secrets_hunter",
	"run_compute_hunter",
	"run_logging_hunter",
	"run_compliance_hunter",
	"run_path_constructor",
	"run_static_prover",
	"run_live_prover",
	"run_fix_generator",
	"recon_phase",
	"hunt_phase",
	"chain_phase",
	"prove_phase",
	"remediation_phase",
}

// --- registration parity -----------------------------------------------------

func TestRouterNames_MatchPythonRegistrationOrder(t *testing.T) {
	if got := reasoners.RouterNames(); !reflect.DeepEqual(got, pythonRouterNames) {
		t.Fatalf("RouterNames() =\n%v\nwant\n%v", got, pythonRouterNames)
	}
	if len(pythonRouterNames) != 20 {
		t.Fatalf("expected 20 router reasoners, have %d", len(pythonRouterNames))
	}
}

func TestRouterNames_ReturnsACopy(t *testing.T) {
	first := reasoners.RouterNames()
	first[0] = "mutated"
	if reasoners.RouterNames()[0] != "run_iac_reader" {
		t.Fatal("RouterNames() leaks its backing array")
	}
}

func TestRegisterAll_ReturnsTheRegisteredNamesInOrder(t *testing.T) {
	got := reasoners.RegisterAll(sdkagent.NewRouter(), &appx.Fake{})
	if !reflect.DeepEqual(got, pythonRouterNames) {
		t.Fatalf("RegisterAll() =\n%v\nwant\n%v", got, pythonRouterNames)
	}
}

func TestTags_MatchPythonAgentRouterTags(t *testing.T) {
	// src/cloudsecurity_af/reasoners/__init__.py:
	//   router = AgentRouter(tags=["cloud", "security", "infrastructure"])
	want := []string{"cloud", "security", "infrastructure"}
	if got := reasoners.Tags(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Tags() = %v, want %v", got, want)
	}
	mutated := reasoners.Tags()
	mutated[0] = "nope"
	if reasoners.Tags()[0] != "cloud" {
		t.Fatal("Tags() leaks its backing array")
	}
}

// TestRegisterAll_MountsEveryNameOnTheAgent proves the names are not just
// bookkeeping: after IncludeRouter every one of them resolves to a handler on a
// real *agent.Agent, so Agent.Call(nodeID+"."+name) from a phase has a target.
func TestRegisterAll_MountsEveryNameOnTheAgent(t *testing.T) {
	app := newTestAgent(t)
	router := sdkagent.NewRouter()
	names := reasoners.RegisterAll(router, &appx.Fake{})
	app.IncludeRouter(router, sdkagent.RouterOptions{Tags: reasoners.Tags()})

	for _, name := range names {
		_, err := app.Execute(context.Background(), name, map[string]any{})
		if err != nil && strings.Contains(err.Error(), "unknown reasoner or skill") {
			t.Fatalf("%s: not registered on the agent (%v)", name, err)
		}
	}

	// A name Python does NOT register must stay unknown.
	if _, err := app.Execute(context.Background(), "run_deduplicator", map[string]any{}); err == nil ||
		!strings.Contains(err.Error(), "unknown reasoner or skill") {
		t.Fatalf("unexpected extra reasoner registered: %v", err)
	}
}

// TestRegisterAll_NoPrefixOnMount pins the RouterOptions contract the node uses:
// Python's app.include_router(reasoner_router) passes NO prefix, so the reasoner
// is reachable as "run_iac_reader", never "cloud.run_iac_reader".
func TestRegisterAll_NoPrefixOnMount(t *testing.T) {
	app := newTestAgent(t)
	router := sdkagent.NewRouter()
	reasoners.RegisterAll(router, &appx.Fake{})
	app.IncludeRouter(router, sdkagent.RouterOptions{Tags: reasoners.Tags()})

	if _, err := app.Execute(context.Background(), "cloud.run_iac_reader", map[string]any{}); err == nil ||
		!strings.Contains(err.Error(), "unknown reasoner or skill") {
		t.Fatalf("router was mounted with a prefix: %v", err)
	}
}

// --- hunt.py: the seven hunters ---------------------------------------------

// TestHunterReasoners_BindArgumentsAndSelectTheRightHunter checks each hunter
// reasoner forwards its four kwargs to the matching agents/hunt entry point:
// the harness prompt must be the hunter's OWN template (line 2 of every hunt
// template is a unique role sentence), the repo_path must reach the harness as
// project_dir, and the reply must be HuntResult.model_dump() with
// strategies_run rewritten to the hunter's single strategy.
func TestHunterReasoners_BindArgumentsAndSelectTheRightHunter(t *testing.T) {
	cases := []struct {
		reasoner   string
		promptFile string
		strategy   string
	}{
		{"run_iam_hunter", "hunt/iam.txt", "iam"},
		{"run_network_hunter", "hunt/network.txt", "network"},
		{"run_data_hunter", "hunt/data.txt", "data"},
		{"run_secrets_hunter", "hunt/secrets.txt", "secrets"},
		{"run_compute_hunter", "hunt/compute.txt", "compute"},
		{"run_logging_hunter", "hunt/logging.txt", "logging"},
		{"run_compliance_hunter", "hunt/compliance.txt", "compliance"},
	}

	for _, tc := range cases {
		t.Run(tc.reasoner, func(t *testing.T) {
			hunt := schemas.NewHuntResult()
			hunt.Findings = []schemas.RawFinding{}
			fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
				return mustJSON(t, hunt), nil
			})}
			app := mountRouter(t, fake)

			out, err := app.Execute(context.Background(), tc.reasoner, map[string]any{
				"repo_path":           "/repo",
				"resource_graph_path": "/tmp/graph.json",
				"inventory_path":      "/tmp/inventory.json",
				"depth":               "thorough",
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}

			if len(fake.Harnesses) != 1 {
				t.Fatalf("harness invocations = %d, want 1", len(fake.Harnesses))
			}
			call := fake.Harnesses[0]
			if marker := roleLine(t, tc.promptFile); !strings.Contains(call.Prompt, marker) {
				t.Fatalf("prompt does not come from %s (missing %q)", tc.promptFile, marker)
			}
			if call.Opts.ProjectDir != "/repo" {
				t.Fatalf("project_dir = %q, want /repo", call.Opts.ProjectDir)
			}
			if !strings.Contains(call.Prompt, "thorough") {
				t.Fatal("depth was not substituted into the prompt")
			}

			m := asMap(t, out)
			if got := m["strategies_run"]; !reflect.DeepEqual(got, []string{tc.strategy}) {
				t.Fatalf("strategies_run = %#v, want [%q]", got, tc.strategy)
			}
			// model_dump() emits every HuntResult field.
			for _, key := range []string{"findings", "total_raw", "deduplicated_count", "strategies_run", "hunt_duration_seconds"} {
				if _, ok := m[key]; !ok {
					t.Fatalf("result is missing %q (keys: %v)", key, sortedKeys(m))
				}
			}
		})
	}
}

// --- recon.py ----------------------------------------------------------------

func TestIaCReaderReasoner_BindsRepoPathAndDumpsInventory(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "main.tf"), `resource "aws_s3_bucket" "b" {
  bucket = "demo"
}
`)

	fake := &appx.Fake{}
	app := mountRouter(t, fake)

	out, err := app.Execute(context.Background(), "run_iac_reader", map[string]any{"repo_path": repo})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fake.Harnesses) != 0 {
		t.Fatalf("deterministic parse should not touch the harness, got %d calls", len(fake.Harnesses))
	}

	m := asMap(t, out)
	for _, key := range []string{"inventory_saved_path", "total_resources", "iac_type", "iac_version"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("result is missing %q (keys: %v)", key, sortedKeys(m))
		}
	}
	if m["total_resources"] != 1 {
		t.Fatalf("total_resources = %#v, want 1", m["total_resources"])
	}
}

func TestResourceGraphBuilderReasoner_BindsBothPaths(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "main.tf"), `resource "aws_s3_bucket" "b" {
  bucket = "demo"
}
`)
	fake := &appx.Fake{}
	app := mountRouter(t, fake)

	inventory, err := app.Execute(context.Background(), "run_iac_reader", map[string]any{"repo_path": repo})
	if err != nil {
		t.Fatalf("run_iac_reader: %v", err)
	}
	invPath, _ := asMap(t, inventory)["inventory_saved_path"].(string)
	if invPath == "" {
		t.Fatal("run_iac_reader returned no inventory_saved_path")
	}

	out, err := app.Execute(context.Background(), "run_resource_graph_builder", map[string]any{
		"repo_path":      repo,
		"inventory_path": invPath,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	m := asMap(t, out)
	for _, key := range []string{"graph_saved_path", "total_nodes", "total_edges"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("result is missing %q (keys: %v)", key, sortedKeys(m))
		}
	}
}

func TestCloudConnectorReasoner_ForwardsCloudConfigToTheHarness(t *testing.T) {
	inventory := schemas.NewResourceInventory()
	inventory.TotalResources = 3
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return mustJSON(t, inventory), nil
	})}
	app := mountRouter(t, fake)

	out, err := app.Execute(context.Background(), "run_cloud_connector", map[string]any{
		"cloud_config": map[string]any{"provider": "aws", "regions": []any{"eu-west-1"}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("harness invocations = %d, want 1", len(fake.Harnesses))
	}
	if !strings.Contains(fake.Harnesses[0].Prompt, "eu-west-1") {
		t.Fatal("cloud_config did not reach the cloud-connector prompt")
	}
	if got := asMap(t, out)["total_resources"]; got != 3 {
		t.Fatalf("total_resources = %#v, want 3", got)
	}
}

func TestDriftDetectorReasoner_ForwardsGraphPathAndCloudConfig(t *testing.T) {
	drift := schemas.NewDriftReport()
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return mustJSON(t, drift), nil
	})}
	app := mountRouter(t, fake)

	out, err := app.Execute(context.Background(), "run_drift_detector", map[string]any{
		"iac_graph_path": "/tmp/graph.json",
		"cloud_config":   map[string]any{"provider": "gcp"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("harness invocations = %d, want 1", len(fake.Harnesses))
	}
	prompt := fake.Harnesses[0].Prompt
	if !strings.Contains(prompt, "gcp") {
		t.Fatal("cloud_config did not reach the drift-detector prompt")
	}
	// Python parity (reproduced bug): drift_detector.py substitutes
	// {{IAC_GRAPH_PATH}} while the template declares {{IAC_GRAPH_JSON}}, so the
	// bound path is never interpolated. Pin that so a "fix" cannot land here
	// silently — it belongs on the Python side.
	if strings.Contains(prompt, "/tmp/graph.json") {
		t.Fatal("iac_graph_path was interpolated; Python's replacement is a no-op")
	}
	m := asMap(t, out)
	for _, key := range []string{"drifted_resources", "iac_only_resources", "cloud_only_resources"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("result is missing %q (keys: %v)", key, sortedKeys(m))
		}
	}
}

// --- chain.py ----------------------------------------------------------------

func TestPathConstructorReasoner_BindsFindingsAndOptionalDriftReport(t *testing.T) {
	finding := schemas.NewRawFinding()
	finding.ID = "f1"
	finding.Title = "public bucket"
	finding.HunterStrategy = "data"
	finding.Category = "public_access"

	plan := schemas.NewPathInvestigationPlan()
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return mustJSON(t, plan), nil
	})}
	app := mountRouter(t, fake)

	out, err := app.Execute(context.Background(), "run_path_constructor", map[string]any{
		"findings":            []any{jsonRoundTrip(t, finding)},
		"resource_graph_path": "/tmp/graph.json",
		"max_paths":           7,
		"max_children":        2,
		// drift_report omitted -> Python's `= None` default.
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fake.Harnesses) == 0 {
		t.Fatal("path constructor never reached the harness")
	}
	parent := fake.Harnesses[0].Prompt
	if !strings.Contains(parent, "public bucket") {
		t.Fatal("bound findings did not reach the parent prompt")
	}
	m := asMap(t, out)
	for _, key := range []string{"attack_paths", "total_paths_evaluated", "viable_paths", "chain_duration_seconds"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("result is missing %q (keys: %v)", key, sortedKeys(m))
		}
	}
}

func TestPathConstructorReasoner_RejectsAMalformedFinding(t *testing.T) {
	app := mountRouter(t, &appx.Fake{})
	_, err := app.Execute(context.Background(), "run_path_constructor", map[string]any{
		// estimated_severity is a STRICT enum in this port (pydantic parity):
		// an unknown value is a validation error, exactly as
		// RawFinding.model_validate would raise.
		"findings":            []any{map[string]any{"estimated_severity": "catastrophic"}},
		"resource_graph_path": "/tmp/graph.json",
		"max_paths":           1,
		"max_children":        1,
	})
	if err == nil {
		t.Fatal("expected a bind error for an invalid RawFinding")
	}
}

// --- prove.py ----------------------------------------------------------------

func TestProverReasoners_BindFindingAndOptionalAttackPath(t *testing.T) {
	for _, reasoner := range []string{"run_static_prover", "run_live_prover"} {
		t.Run(reasoner, func(t *testing.T) {
			verified := schemas.NewVerifiedFinding()
			verified.ID = "f1"
			verified.Title = "t"
			// verdict/severity are REQUIRED in Python (no default), so a
			// canned prover reply must carry them.
			verified.Verdict = schemas.VerdictConfirmed
			verified.Severity = scoring.SeverityHigh

			finding := schemas.NewRawFinding()
			finding.ID = "f1"
			finding.Title = "world-readable bucket"

			path := schemas.NewAttackPath()
			path.ID = "p1"
			path.Title = "bucket -> exfiltration"

			fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
				return mustJSON(t, verified), nil
			})}
			app := mountRouter(t, fake)

			out, err := app.Execute(context.Background(), reasoner, map[string]any{
				"repo_path":   "/repo",
				"finding":     jsonRoundTrip(t, finding),
				"tier":        2,
				"attack_path": jsonRoundTrip(t, path),
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if len(fake.Harnesses) != 1 {
				t.Fatalf("harness invocations = %d, want 1", len(fake.Harnesses))
			}
			call := fake.Harnesses[0]
			if call.Opts.ProjectDir != "/repo" {
				t.Fatalf("project_dir = %q, want /repo", call.Opts.ProjectDir)
			}
			if !strings.Contains(call.Prompt, "world-readable bucket") {
				t.Fatal("bound finding did not reach the prover prompt")
			}
			if !strings.Contains(call.Prompt, "bucket -> exfiltration") {
				t.Fatal("bound attack_path did not reach the prover prompt")
			}
			if got := asMap(t, out)["id"]; got != "f1" {
				t.Fatalf("id = %#v, want f1", got)
			}
		})
	}
}

// TestProverReasoners_OmittedAttackPathIsNone pins the `= None` default: with
// attack_path absent the prompt renders the empty-JSON placeholder rather than
// failing to bind.
func TestProverReasoners_OmittedAttackPathIsNone(t *testing.T) {
	verified := schemas.NewVerifiedFinding()
	verified.Verdict = schemas.VerdictInconclusive
	verified.Severity = scoring.SeverityLow
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return mustJSON(t, verified), nil
	})}
	app := mountRouter(t, fake)

	if _, err := app.Execute(context.Background(), "run_static_prover", map[string]any{
		"repo_path": "/repo",
		"finding":   jsonRoundTrip(t, schemas.NewRawFinding()),
		"tier":      1,
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("harness invocations = %d, want 1", len(fake.Harnesses))
	}
	if !strings.Contains(fake.Harnesses[0].Prompt, "{}") {
		t.Fatal("a nil attack_path should render the empty-object placeholder")
	}
}

// --- remediate.py ------------------------------------------------------------

func TestFixGeneratorReasoner_BindsVerifiedFinding(t *testing.T) {
	suggestion := schemas.NewRemediationSuggestion()
	suggestion.FindingID = "f1"
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return mustJSON(t, suggestion), nil
	})}
	app := mountRouter(t, fake)

	finding := schemas.NewVerifiedFinding()
	finding.ID = "f1"
	finding.Title = "unencrypted volume"
	finding.Verdict = schemas.VerdictConfirmed
	finding.Severity = scoring.SeverityMedium

	out, err := app.Execute(context.Background(), "run_fix_generator", map[string]any{
		"repo_path": "/repo",
		"finding":   jsonRoundTrip(t, finding),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(fake.Harnesses) != 1 {
		t.Fatalf("harness invocations = %d, want 1", len(fake.Harnesses))
	}
	if !strings.Contains(fake.Harnesses[0].Prompt, "unencrypted volume") {
		t.Fatal("bound finding did not reach the fix-generator prompt")
	}
	if got := asMap(t, out)["finding_id"]; got != "f1" {
		t.Fatalf("finding_id = %#v, want f1", got)
	}
}

// --- phases.py ---------------------------------------------------------------

// TestPhaseReasoners_DispatchThroughAppCallWithPythonDefaults exercises the five
// phase reasoners end to end through the agent: each must reach internal/phases,
// which issues the `NODE_ID.<reasoner>` control-plane calls that ARE the DAG.
// It also pins the signature defaults (depth "standard", tier 1, the three
// concurrency caps 3) by omitting them from the request.
func TestPhaseReasoners_DispatchThroughAppCallWithPythonDefaults(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity")

	t.Run("recon_phase", func(t *testing.T) {
		inventory := schemas.NewResourceInventory()
		inventory.InventorySavedPath = "/tmp/inv.json"
		graph := schemas.NewResourceGraph()
		graph.GraphSavedPath = "/tmp/graph.json"

		fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
			switch target {
			case "cloudsecurity.run_iac_reader":
				return jsonRoundTrip(t, inventory), nil
			case "cloudsecurity.run_resource_graph_builder":
				return jsonRoundTrip(t, graph), nil
			}
			return nil, nil
		}}
		app := mountRouter(t, fake)

		if _, err := app.Execute(context.Background(), "recon_phase", map[string]any{"repo_path": "/repo"}); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		want := []string{"cloudsecurity.run_iac_reader", "cloudsecurity.run_resource_graph_builder"}
		if got := fake.CallTargets(); !reflect.DeepEqual(got, want) {
			// tier defaults to 1, so the two tier-2 calls must NOT happen.
			t.Fatalf("call targets = %v, want %v", got, want)
		}
	})

	t.Run("hunt_phase", func(t *testing.T) {
		empty := schemas.NewHuntResult()
		fake := &appx.Fake{CallFn: func(_ context.Context, string2 string, _ map[string]any) (map[string]any, error) {
			return jsonRoundTrip(t, empty), nil
		}}
		app := mountRouter(t, fake)

		if _, err := app.Execute(context.Background(), "hunt_phase", map[string]any{
			"repo_path":           "/repo",
			"resource_graph_path": "/tmp/graph.json",
			"inventory_path":      "/tmp/inv.json",
		}); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		// depth defaults to "standard" -> the 7-hunter map.
		if len(fake.Calls) != 7 {
			t.Fatalf("hunter calls = %d, want 7 (the standard DEPTH_HUNTER_MAP)", len(fake.Calls))
		}
		if max := fake.MaxConcurrentCalls(); max > 3 {
			t.Fatalf("max concurrent hunters = %d, want <= 3 (the signature default)", max)
		}
		for _, c := range fake.Calls {
			if !strings.HasPrefix(c.Target, "cloudsecurity.run_") || !strings.HasSuffix(c.Target, "_hunter") {
				t.Fatalf("unexpected hunt target %q", c.Target)
			}
			if got := c.Input["depth"]; got != "standard" {
				t.Fatalf("depth kwarg = %#v, want \"standard\"", got)
			}
		}
	})

	t.Run("chain_phase", func(t *testing.T) {
		chain := schemas.NewChainResult()
		var recorded map[string]any
		fake := &appx.Fake{CallFn: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
			recorded = in
			return jsonRoundTrip(t, chain), nil
		}}
		app := mountRouter(t, fake)

		if _, err := app.Execute(context.Background(), "chain_phase", map[string]any{
			"findings":            []any{},
			"resource_graph_path": "/tmp/graph.json",
		}); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if got := fake.CallTargets(); !reflect.DeepEqual(got, []string{"cloudsecurity.run_path_constructor"}) {
			t.Fatalf("call targets = %v", got)
		}
		// depth "standard" -> DEPTH_CHAIN_LIMITS[standard]; max_children default 3.
		if got := recorded["max_children"]; got != 3 {
			t.Fatalf("max_children = %#v, want 3", got)
		}
		if _, ok := recorded["max_paths"]; !ok {
			t.Fatalf("max_paths kwarg missing (keys: %v)", sortedKeys(recorded))
		}
	})

	t.Run("prove_phase", func(t *testing.T) {
		verified := schemas.NewVerifiedFinding()
		verified.ID = "f1"
		verified.Verdict = schemas.VerdictLikely
		verified.Severity = scoring.SeverityHigh
		fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
			return jsonRoundTrip(t, verified), nil
		}}
		app := mountRouter(t, fake)

		hunt := schemas.NewHuntResult()
		f := schemas.NewRawFinding()
		f.ID = "f1"
		hunt.Findings = []schemas.RawFinding{f}

		out, err := app.Execute(context.Background(), "prove_phase", map[string]any{
			"repo_path":    "/repo",
			"hunt_result":  jsonRoundTrip(t, hunt),
			"chain_result": jsonRoundTrip(t, schemas.NewChainResult()),
		})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		// tier defaults to 1 -> the STATIC prover.
		if got := fake.CallTargets(); !reflect.DeepEqual(got, []string{"cloudsecurity.run_static_prover"}) {
			t.Fatalf("call targets = %v, want the static prover (tier default 1)", got)
		}
		m := asMap(t, out)
		for _, key := range []string{"verified", "total_selected", "total_findings", "not_verified"} {
			if _, ok := m[key]; !ok {
				t.Fatalf("prove_phase result is missing %q (keys: %v)", key, sortedKeys(m))
			}
		}
	})

	t.Run("remediation_phase", func(t *testing.T) {
		suggestion := schemas.NewRemediationSuggestion()
		fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
			return jsonRoundTrip(t, suggestion), nil
		}}
		app := mountRouter(t, fake)

		confirmed := schemas.NewVerifiedFinding()
		confirmed.ID = "f1"
		confirmed.Verdict = schemas.VerdictConfirmed
		confirmed.Severity = scoring.SeverityCritical

		out, err := app.Execute(context.Background(), "remediation_phase", map[string]any{
			"repo_path":         "/repo",
			"verified_findings": []any{jsonRoundTrip(t, confirmed)},
		})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if got := fake.CallTargets(); !reflect.DeepEqual(got, []string{"cloudsecurity.run_fix_generator"}) {
			t.Fatalf("call targets = %v", got)
		}
		if _, ok := asMap(t, out)["verified"]; !ok {
			t.Fatal("remediation_phase result is missing \"verified\"")
		}
	})
}

// TestPhaseReasoners_HonorNodeIDEnv proves the phase handlers resolve NODE_ID at
// call time, so a node started with NODE_ID=cloudsecurity-go calls its OWN
// reasoners rather than the Python node's.
func TestPhaseReasoners_HonorNodeIDEnv(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity-go")

	chain := schemas.NewChainResult()
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return jsonRoundTrip(t, chain), nil
	}}
	app := mountRouter(t, fake)

	if _, err := app.Execute(context.Background(), "chain_phase", map[string]any{
		"findings":            []any{},
		"resource_graph_path": "/tmp/graph.json",
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := fake.CallTargets(); !reflect.DeepEqual(got, []string{"cloudsecurity-go.run_path_constructor"}) {
		t.Fatalf("call targets = %v", got)
	}
}

// --- helpers -----------------------------------------------------------------

func newTestAgent(t *testing.T) *sdkagent.Agent {
	t.Helper()
	app, err := sdkagent.New(sdkagent.Config{NodeID: "cloudsecurity-test", Version: "0.1.0"})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	return app
}

// mountRouter builds an agent, registers the router surface against fake and
// mounts it exactly as node.BuildAgent does.
func mountRouter(t *testing.T, fake *appx.Fake) *sdkagent.Agent {
	t.Helper()
	app := newTestAgent(t)
	router := sdkagent.NewRouter()
	reasoners.RegisterAll(router, fake)
	app.IncludeRouter(router, sdkagent.RouterOptions{Tags: reasoners.Tags()})
	return app
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return b
}

// jsonRoundTrip renders v the way the control plane hands a model_dump() back:
// a plain map of JSON-native values.
func jsonRoundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(mustJSON(t, v), &out); err != nil {
		t.Fatalf("round-trip %T: %v", v, err)
	}
	return out
}

// asMap normalizes a handler's reply into a keyed lookup. Handlers return an
// afx.Payload — an INSERTION-ORDERED object, because the wire key order is part
// of the parity contract (payload_order_test.go pins it) — whose values stay
// typed, exactly as afx.ToMap's did.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	p, ok := v.(afx.Payload)
	if !ok {
		t.Fatalf("handler returned %T, want afx.Payload", v)
	}
	return p.Map()
}

// roleLine returns line 2 of an embedded prompt template — the sentence that is
// unique to each hunter/agent template and survives placeholder substitution.
func roleLine(t *testing.T, rel string) string {
	t.Helper()
	text, err := prompts.Load(rel)
	if err != nil {
		t.Fatalf("prompts.Load(%q): %v", rel, err)
	}
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		t.Fatalf("prompt %q has no second line", rel)
	}
	return strings.TrimSpace(lines[1])
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
