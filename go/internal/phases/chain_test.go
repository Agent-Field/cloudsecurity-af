package phases

import (
	"context"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

func chainFake(t *testing.T, capture *map[string]any) *appx.Fake {
	t.Helper()
	chain := schemas.NewChainResult()
	return &appx.Fake{CallFn: func(_ context.Context, _ string, in map[string]any) (map[string]any, error) {
		if capture != nil {
			*capture = in
		}
		return mustMap(t, chain), nil
	}}
}

// TestChainPhase_SingleChildAndKwargs pins the one child and the five kwargs the
// Python probe recorded:
//
//	[('cloudsecurity.run_path_constructor',
//	  ['drift_report', 'findings', 'max_children', 'max_paths', 'resource_graph_path'])]
func TestChainPhase_SingleChildAndKwargs(t *testing.T) {
	var captured map[string]any
	fake := chainFake(t, &captured)

	findings := []any{map[string]any{"id": "x"}}
	out, err := ChainPhase(context.Background(), fake, testNodeID, findings, "/g.json", nil, "quick", 3)
	if err != nil {
		t.Fatalf("ChainPhase: %v", err)
	}

	if got := fake.CallTargets(); !equalStrings(got, []string{testNodeID + ".run_path_constructor"}) {
		t.Fatalf("targets = %v", got)
	}
	want := []string{"drift_report", "findings", "max_children", "max_paths", "resource_graph_path"}
	if got := keysOf(captured); !equalStrings(got, want) {
		t.Fatalf("kwargs = %v, want %v", got, want)
	}
	if captured["drift_report"] != nil {
		t.Errorf("drift_report should be nil, got %#v", captured["drift_report"])
	}
	if captured["resource_graph_path"] != "/g.json" {
		t.Errorf("resource_graph_path = %v", captured["resource_graph_path"])
	}
	if captured["max_children"] != 3 {
		t.Errorf("max_children = %v", captured["max_children"])
	}

	// probe: CHAIN_KEYS ['attack_paths', 'chain_duration_seconds',
	//                    'total_paths_evaluated', 'viable_paths']
	wantKeys := []string{"attack_paths", "chain_duration_seconds", "total_paths_evaluated", "viable_paths"}
	if got := payloadKeys(out); !equalStrings(got, wantKeys) {
		t.Fatalf("chain keys = %v, want %v", got, wantKeys)
	}
}

// TestChainPhase_MaxPathsFromDepth pins DEPTH_CHAIN_LIMITS (the probe recorded
// CHAIN_MAXPATHS 5 for depth="quick").
func TestChainPhase_MaxPathsFromDepth(t *testing.T) {
	cases := []struct {
		depth string
		want  int
	}{
		{depth: "quick", want: 5},
		{depth: "standard", want: 15},
		{depth: "thorough", want: 100},
		{depth: "THOROUGH", want: 100},
		{depth: "bogus", want: 15},
		{depth: "", want: 15},
	}
	for _, tc := range cases {
		t.Run(tc.depth, func(t *testing.T) {
			var captured map[string]any
			fake := chainFake(t, &captured)
			if _, err := ChainPhase(context.Background(), fake, testNodeID, nil, "/g.json", nil, tc.depth, 3); err != nil {
				t.Fatalf("ChainPhase: %v", err)
			}
			if captured["max_paths"] != tc.want {
				t.Fatalf("max_paths = %v, want %d", captured["max_paths"], tc.want)
			}
		})
	}
}

// TestChainPhase_ForwardsFindingsAndDriftVerbatim: chain_phase never binds
// either value, so whatever it was handed reaches run_path_constructor unchanged.
func TestChainPhase_ForwardsFindingsAndDriftVerbatim(t *testing.T) {
	var captured map[string]any
	fake := chainFake(t, &captured)

	findings := []any{map[string]any{"id": "x", "not_a_real_field": 1}, map[string]any{"id": "y"}}
	drift := map[string]any{"drifted_resources": []any{}, "extra": "kept"}
	if _, err := ChainPhase(context.Background(), fake, testNodeID, findings, "/g.json", drift, "standard", 7); err != nil {
		t.Fatalf("ChainPhase: %v", err)
	}

	gotFindings, ok := captured["findings"].([]any)
	if !ok {
		t.Fatalf("findings is %T", captured["findings"])
	}
	first, ok := gotFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("findings[0] is %T", gotFindings[0])
	}
	if len(gotFindings) != 2 || first["not_a_real_field"] != 1 {
		t.Fatalf("findings were not forwarded verbatim: %#v", gotFindings)
	}
	gotDrift, ok := captured["drift_report"].(map[string]any)
	if !ok {
		t.Fatalf("drift_report is %T", captured["drift_report"])
	}
	if gotDrift["extra"] != "kept" {
		t.Fatalf("drift_report was not forwarded verbatim: %#v", gotDrift)
	}
	if captured["max_children"] != 7 {
		t.Fatalf("max_children = %v", captured["max_children"])
	}
}

// TestChainPhase_StrictUnwrapFailurePropagates: unlike hunt_phase, chain_phase
// has no try/except — a failed path constructor fails the whole phase.
func TestChainPhase_StrictUnwrapFailurePropagates(t *testing.T) {
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return map[string]any{"status": "error", "error_message": "no graph"}, nil
	}}
	_, err := ChainPhase(context.Background(), fake, testNodeID, nil, "/g.json", nil, "standard", 3)
	if err == nil || err.Error() != "run_path_constructor failed: no graph" {
		t.Fatalf("err = %v", err)
	}
}

// TestChainPhase_UnwrapsOutputEnvelope proves the ported _unwrap still peels an
// {"output": {...}} envelope before validating.
func TestChainPhase_UnwrapsOutputEnvelope(t *testing.T) {
	chain := schemas.NewChainResult()
	chain.TotalPathsEvaluated = 4
	chain.ViablePaths = 2
	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, _ map[string]any) (map[string]any, error) {
		return map[string]any{"output": mustMap(t, chain)}, nil
	}}
	out, err := ChainPhase(context.Background(), fake, testNodeID, nil, "/g.json", nil, "standard", 3)
	if err != nil {
		t.Fatalf("ChainPhase: %v", err)
	}
	if pm(out)["total_paths_evaluated"] != 4 || pm(out)["viable_paths"] != 2 {
		t.Fatalf("out = %#v", out)
	}
}
