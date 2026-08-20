package reasoners_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	sdkagent "github.com/Agent-Field/agentfield/sdk/go/agent"
	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
)

// harnessReply is appx.HarnessJSON with a constant body.
func harnessReply(body string) func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
	return appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(body), nil
	})
}

// VALIDATION CONTRACT — the reasoner request body.
//
// The Python SDK validates every body against the reasoner's SIGNATURE before
// the coroutine runs and answers 422 on a violation
// (Agent._validate_handler_input, rendered at agent.py:2120-2128). The Go SDK
// does no such check, so internal/afx ports it and internal/reasoners' `reg`
// runs it. Every expectation below was produced by executing the REAL
// `Agent._validate_handler_input(body, fields)` from
// /home/abir/agentfield/sdk/python against the transcribed signatures:
//
//	run_static_prover {"repo_path":"/r","finding":{},"tier":"2"}
//	    -> OK, tier == 2                       (int("2"))
//	run_static_prover {"repo_path":"/r","finding":{}}
//	    -> "Missing required field: tier"
//	run_static_prover {"repo_path":"/r","finding":"nope","tier":1}
//	    -> "Field 'finding' must be a dict"
//	hunt_phase {...,"max_concurrent_hunters":"4"}  -> OK, 4
//	hunt_phase {...,"depth":3}                     -> OK, depth == "3"  (str(3))
//	hunt_phase {"resource_graph_path":"/g"}        -> "Missing required field: repo_path"
//	run_iam_hunter {repo/graph/inventory paths}    -> "Missing required field: depth"
//	    (depth carries NO default on the hunters, unlike on the phases)
//	run_iam_hunter {"repo_path":123,...}           -> OK, repo_path == "123"

// executeReasoner runs one reasoner against a router mounted on a real agent.
func executeReasoner(t *testing.T, fake *appx.Fake, name string, body map[string]any) (any, error) {
	t.Helper()
	if fake == nil {
		fake = &appx.Fake{}
	}
	app := mountRouter(t, fake)
	return app.Execute(context.Background(), name, body)
}

func TestReasonerInputs_MissingRequiredParameterIs422(t *testing.T) {
	cases := []struct {
		reasoner string
		body     map[string]any
		want     string
	}{
		{"run_iac_reader", map[string]any{}, "Missing required field: repo_path"},
		{"run_resource_graph_builder", map[string]any{"repo_path": "/r"}, "Missing required field: inventory_path"},
		{"run_cloud_connector", map[string]any{}, "Missing required field: cloud_config"},
		{"run_drift_detector", map[string]any{"cloud_config": map[string]any{}}, "Missing required field: iac_graph_path"},
		{
			"run_iam_hunter",
			map[string]any{"repo_path": "/r", "resource_graph_path": "/g", "inventory_path": "/i"},
			"Missing required field: depth",
		},
		{
			"run_static_prover",
			map[string]any{"repo_path": "/r", "finding": map[string]any{}},
			"Missing required field: tier",
		},
		{"run_fix_generator", map[string]any{"repo_path": "/r"}, "Missing required field: finding"},
		{
			"run_path_constructor",
			map[string]any{"resource_graph_path": "/g", "max_paths": 5, "max_children": 3},
			"Missing required field: findings",
		},
		{"recon_phase", map[string]any{"depth": "quick"}, "Missing required field: repo_path"},
		{"hunt_phase", map[string]any{"resource_graph_path": "/g"}, "Missing required field: repo_path"},
		{"chain_phase", map[string]any{"resource_graph_path": "/g"}, "Missing required field: findings"},
		{
			"prove_phase",
			map[string]any{"repo_path": "/r", "hunt_result": map[string]any{}},
			"Missing required field: chain_result",
		},
		{"remediation_phase", map[string]any{"repo_path": "/r"}, "Missing required field: verified_findings"},
	}

	for _, tc := range cases {
		t.Run(tc.reasoner, func(t *testing.T) {
			fake := &appx.Fake{
				HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
					t.Fatal("the handler must not run for an invalid body")
					return nil, nil
				},
				CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
					t.Fatal("the handler must not run for an invalid body")
					return nil, nil
				},
			}
			_, err := executeReasoner(t, fake, tc.reasoner, tc.body)
			if err == nil {
				t.Fatalf("%s accepted a body Python answers 422 to", tc.reasoner)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
			var execErr *sdkagent.ExecuteError
			if !errors.As(err, &execErr) {
				t.Fatalf("error is %T, want *agent.ExecuteError so the status reaches the caller", err)
			}
			if execErr.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422", execErr.StatusCode)
			}
		})
	}
}

func TestReasonerInputs_WrongContainerTypeIs422(t *testing.T) {
	cases := []struct {
		reasoner string
		body     map[string]any
		want     string
	}{
		{
			"run_static_prover",
			map[string]any{"repo_path": "/r", "finding": "nope", "tier": 1},
			"Field 'finding' must be a dict",
		},
		{
			"run_cloud_connector",
			map[string]any{"cloud_config": []any{"aws"}},
			"Field 'cloud_config' must be a dict",
		},
		{
			"chain_phase",
			map[string]any{"findings": map[string]any{}, "resource_graph_path": "/g"},
			"Field 'findings' must be a list",
		},
		{
			"remediation_phase",
			map[string]any{"repo_path": "/r", "verified_findings": "none"},
			"Field 'verified_findings' must be a list",
		},
	}
	for _, tc := range cases {
		t.Run(tc.reasoner, func(t *testing.T) {
			_, err := executeReasoner(t, nil, tc.reasoner, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// The mirror image: bodies the Python node ACCEPTS because the SDK coerces them.
// Rejecting these turned working callers (a CP UI form field, a loosely typed
// agent) into failed executions.
func TestReasonerInputs_CoercesScalarsThePythonSDKCoerces(t *testing.T) {
	t.Run("run_static_prover tier as a string", func(t *testing.T) {
		fake := &appx.Fake{
			HarnessFn: harnessReply(`{"title":"t","verdict":"confirmed","severity":"high","category":"c"}`),
		}
		app := mountRouter(t, fake)
		_, err := app.Execute(context.Background(), "run_static_prover", map[string]any{
			"repo_path": "/r",
			"finding": map[string]any{
				"hunter_strategy": "iam", "title": "t", "description": "d", "category": "c",
			},
			"tier": "2",
		})
		if err != nil {
			t.Fatalf("run_static_prover rejected tier \"2\", which Python coerces to 2: %v", err)
		}
		// The prompt is the only place tier is observable from outside; assert
		// the call simply succeeded and the harness ran.
		if len(fake.Harnesses) != 1 {
			t.Fatalf("harness calls = %d, want 1", len(fake.Harnesses))
		}
	})

	t.Run("hunt_phase max_concurrent_hunters as a string", func(t *testing.T) {
		fake := &appx.Fake{CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
			return map[string]any{"findings": []any{}}, nil
		}}
		app := mountRouter(t, fake)
		if _, err := app.Execute(context.Background(), "hunt_phase", map[string]any{
			"repo_path":              "/r",
			"resource_graph_path":    "/g",
			"inventory_path":         "/i",
			"max_concurrent_hunters": "4",
		}); err != nil {
			t.Fatalf("hunt_phase rejected max_concurrent_hunters \"4\", which Python coerces to 4: %v", err)
		}
	})

	t.Run("a hunter path as a number", func(t *testing.T) {
		fake := &appx.Fake{HarnessFn: harnessReply(`{"findings":[]}`)}
		app := mountRouter(t, fake)
		if _, err := app.Execute(context.Background(), "run_iam_hunter", map[string]any{
			"repo_path":           123,
			"resource_graph_path": "/g",
			"inventory_path":      "/i",
			"depth":               "quick",
		}); err != nil {
			t.Fatalf("run_iam_hunter rejected repo_path 123, which Python renders as \"123\": %v", err)
		}
		if got := fake.Harnesses[0].Prompt; !strings.Contains(got, "123") {
			t.Errorf("the coerced repo_path did not reach the prompt")
		}
	})

	t.Run("recon_phase depth as a number", func(t *testing.T) {
		// Python: str(3) == "3", which _normalize_depth then folds to the
		// standard profile — an accepted request either way.
		fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
			switch {
			case strings.HasSuffix(target, ".run_iac_reader"):
				return map[string]any{"inventory_saved_path": "/tmp/inv.json"}, nil
			default:
				return map[string]any{"graph_saved_path": "/tmp/graph.json"}, nil
			}
		}}
		app := mountRouter(t, fake)
		if _, err := app.Execute(context.Background(), "recon_phase", map[string]any{
			"repo_path": "/r",
			"depth":     3,
		}); err != nil {
			t.Fatalf("recon_phase rejected depth 3, which Python renders as \"3\": %v", err)
		}
	})
}

// Python's `result = {}` drops undeclared keys, so an extra key can never reach
// the handler in either node.
func TestReasonerInputs_UndeclaredKeysAreDropped(t *testing.T) {
	fake := &appx.Fake{HarnessFn: harnessReply(`{"inventory_saved_path":"/tmp/inv.json"}`)}
	app := mountRouter(t, fake)
	if _, err := app.Execute(context.Background(), "run_iac_reader", map[string]any{
		"repo_path":   "/r",
		"unexpected":  map[string]any{"deep": 1},
		"another_one": 5,
	}); err != nil {
		t.Fatalf("run_iac_reader rejected a body with extra keys: %v", err)
	}
}

// TestReasonerInputs_ChainPhaseForwardsNonObjectFindingsToTheChild pins the one
// list parameter Python does NOT bind.
//
// `chain_phase(findings: list[dict[str, Any]], ...)` hands `findings` straight
// to run_path_constructor (src/cloudsecurity_af/reasoners/phases.py:225-243),
// and the SDK's Agent._validate_handler_input only checks `isinstance(value,
// list)` for a `list[...]` annotation — never the element type. Verified in the
// repo venv with `_runtime_router` faked:
//
//	await chain_phase(findings=[1, 2, "x"], resource_graph_path="/g")
//	-> CALLS [('cloudsecurity.run_path_constructor',
//	          {'findings': [1, 2, 'x'], 'resource_graph_path': '/g',
//	           'max_paths': 15, 'max_children': 3, 'drift_report': None})]
//	-> RAISED RuntimeError run_path_constructor failed: boom
//
// So the parent must reach the child (one DAG edge, a FAILED child node) and
// surface the child's relayed error — not fail its own bind with a 422 and no
// child at all.
func TestReasonerInputs_ChainPhaseForwardsNonObjectFindingsToTheChild(t *testing.T) {
	var captured map[string]any
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
		captured = in
		return map[string]any{"status": "error", "error_message": "boom"}, nil
	}}
	app := mountRouter(t, fake)

	_, err := app.Execute(context.Background(), "chain_phase", map[string]any{
		"findings":            []any{1, 2, "x"},
		"resource_graph_path": "/g",
	})
	if err == nil {
		t.Fatal("chain_phase succeeded; Python relays the child's failure")
	}
	if got := err.Error(); !strings.Contains(got, "run_path_constructor failed: boom") {
		t.Fatalf("err = %q, want the relayed child failure; a bind error here means\n"+
			"the parent rejected the list Python forwards verbatim", got)
	}
	if got := fake.CallTargets(); len(got) != 1 {
		t.Fatalf("child calls = %v, want exactly one run_path_constructor edge", got)
	}
	b, mErr := json.Marshal(captured["findings"])
	if mErr != nil {
		t.Fatalf("marshal forwarded findings: %v", mErr)
	}
	if string(b) != `[1,2,"x"]` {
		t.Fatalf("findings forwarded as %s, want [1,2,\"x\"] verbatim", b)
	}
}

// TestReasonerInputs_ProverBindsTheFindingWithPydanticsLaxRules pins the
// `RawFinding.model_validate(finding)` at src/cloudsecurity_af/reasoners/
// prove.py:22 — the boundary a caller-supplied finding dict crosses.
//
// pydantic v2 validates in LAX mode, so it coerces scalars encoding/json
// refuses and rejects an explicit null for a field that is not `X | None`.
// Measured in the repo venv (pydantic 2.13.4):
//
//	RawFinding.model_validate({..., "iac_line": "12"})   -> OK, iac_line == 12
//	RawFinding.model_validate({..., "resources": None})  -> ValidationError
func TestReasonerInputs_ProverBindsTheFindingWithPydanticsLaxRules(t *testing.T) {
	finding := func(extra map[string]any) map[string]any {
		out := map[string]any{
			"hunter_strategy": "iam", "title": "t", "description": "d", "category": "c",
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	t.Run("a stringified int is coerced, not rejected", func(t *testing.T) {
		fake := &appx.Fake{
			HarnessFn: harnessReply(`{"title":"t","verdict":"confirmed","severity":"high","category":"c"}`),
		}
		app := mountRouter(t, fake)
		if _, err := app.Execute(context.Background(), "run_static_prover", map[string]any{
			"repo_path": "/r",
			"finding":   finding(map[string]any{"iac_line": "12"}),
			"tier":      1,
		}); err != nil {
			t.Fatalf("run_static_prover rejected iac_line \"12\", which pydantic coerces to 12: %v", err)
		}
		if len(fake.Harnesses) != 1 {
			t.Fatalf("harness calls = %d, want 1 — the prover never ran", len(fake.Harnesses))
		}
	})

	t.Run("a null for a non-Optional field is rejected", func(t *testing.T) {
		fake := &appx.Fake{
			HarnessFn: harnessReply(`{"title":"t","verdict":"confirmed","severity":"high","category":"c"}`),
		}
		app := mountRouter(t, fake)
		_, err := app.Execute(context.Background(), "run_static_prover", map[string]any{
			"repo_path": "/r",
			"finding":   finding(map[string]any{"resources": nil}),
			"tier":      1,
		})
		if err == nil {
			t.Fatal("run_static_prover accepted resources=null; pydantic raises list_type")
		}
		if got := err.Error(); !strings.Contains(got, "resources") {
			t.Fatalf("err = %q, want the offending field named", got)
		}
		if len(fake.Harnesses) != 0 {
			t.Fatalf("harness ran %d time(s); the bind must fail first", len(fake.Harnesses))
		}
	})
}
