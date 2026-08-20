package phases

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// writeInventory drops a JSON document at <dir>/inventory.json and returns its
// path — the file recon_phase re-reads to derive providers_detected.
func writeInventory(t *testing.T, doc any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.json")
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return path
}

// reconFake answers run_iac_reader / run_resource_graph_builder and, when
// asked, the two tier-2 reasoners.
func reconFake(t *testing.T, inventoryPath string, extra func(target string, in map[string]any) (map[string]any, error)) *appx.Fake {
	t.Helper()
	inventory := schemas.NewResourceInventory()
	inventory.InventorySavedPath = inventoryPath
	inventory.TotalResources = 3
	inventory.IaCType = "terraform"

	graph := schemas.NewResourceGraph()
	graph.GraphSavedPath = "/g.json"
	graph.TotalNodes = 3
	graph.TotalEdges = 2

	return &appx.Fake{CallFn: func(_ context.Context, target string, in map[string]any) (map[string]any, error) {
		switch target {
		case testNodeID + ".run_iac_reader":
			return mustMap(t, inventory), nil
		case testNodeID + ".run_resource_graph_builder":
			return mustMap(t, graph), nil
		}
		if extra != nil {
			return extra(target, in)
		}
		t.Errorf("unexpected call target %q", target)
		return nil, nil
	}}
}

// TestReconPhase_Tier1CallsIacReaderThenGraphBuilder pins the two sequential
// children and their kwargs — the Python probe recorded
//
//	[('cloudsecurity.run_iac_reader', ['repo_path']),
//	 ('cloudsecurity.run_resource_graph_builder', ['inventory_path', 'repo_path'])]
func TestReconPhase_Tier1CallsIacReaderThenGraphBuilder(t *testing.T) {
	inventoryPath := writeInventory(t, map[string]any{"resources": []any{}})
	fake := reconFake(t, inventoryPath, nil)

	out, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "quick", 1, nil)
	if err != nil {
		t.Fatalf("ReconPhase: %v", err)
	}

	wantTargets := []string{testNodeID + ".run_iac_reader", testNodeID + ".run_resource_graph_builder"}
	if got := fake.CallTargets(); !equalStrings(got, wantTargets) {
		t.Fatalf("targets = %v, want %v", got, wantTargets)
	}
	if got := keysOf(fake.Calls[0].Input); !equalStrings(got, []string{"repo_path"}) {
		t.Errorf("run_iac_reader kwargs = %v", got)
	}
	if got := fake.Calls[0].Input["repo_path"]; got != "/repo" {
		t.Errorf("repo_path = %v", got)
	}
	if got := keysOf(fake.Calls[1].Input); !equalStrings(got, []string{"inventory_path", "repo_path"}) {
		t.Errorf("run_resource_graph_builder kwargs = %v", got)
	}
	if got := fake.Calls[1].Input["inventory_path"]; got != inventoryPath {
		t.Errorf("inventory_path = %v, want %v", got, inventoryPath)
	}

	// The Python probe printed these ReconResult keys.
	wantKeys := []string{
		"drift_report", "iac_type", "inventory", "live_inventory", "providers_detected",
		"recon_duration_seconds", "resource_graph", "total_edges", "total_resources",
	}
	if got := payloadKeys(out); !equalStrings(got, wantKeys) {
		t.Fatalf("recon keys = %v, want %v", got, wantKeys)
	}
	if pm(out)["iac_type"] != "terraform" {
		t.Errorf("iac_type = %v", pm(out)["iac_type"])
	}
	if pm(out)["total_resources"] != 3 {
		t.Errorf("total_resources = %v", pm(out)["total_resources"])
	}
	if pm(out)["total_edges"] != 2 {
		t.Errorf("total_edges = %v", pm(out)["total_edges"])
	}
	if pm(out)["drift_report"] != (*schemas.DriftReport)(nil) {
		t.Errorf("drift_report should be nil for tier 1, got %#v", pm(out)["drift_report"])
	}
}

// TestReconPhase_ProvidersDetected reproduces the probe's inventory fixture —
// duplicates collapse, falsy and non-dict entries are skipped, and the result is
// sorted: ['aws', 'gcp'].
func TestReconPhase_ProvidersDetected(t *testing.T) {
	cases := []struct {
		name string
		doc  any
		want []string
	}{
		{
			name: "sorted unique truthy providers",
			doc: map[string]any{"resources": []any{
				map[string]any{"provider": "aws"},
				map[string]any{"provider": "gcp"},
				map[string]any{"provider": "aws"},
				map[string]any{"provider": ""},
				map[string]any{"noprov": 1},
				"notadict",
			}},
			want: []string{"aws", "gcp"},
		},
		{name: "no resources key", doc: map[string]any{}, want: []string{}},
		{name: "resources not a list", doc: map[string]any{"resources": "nope"}, want: []string{}},
		{name: "document not an object", doc: []any{1, 2}, want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeInventory(t, tc.doc)
			fake := reconFake(t, path, nil)
			out, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", 1, nil)
			if err != nil {
				t.Fatalf("ReconPhase: %v", err)
			}
			got, ok := pm(out)["providers_detected"].([]string)
			if !ok {
				t.Fatalf("providers_detected is %T", pm(out)["providers_detected"])
			}
			if !equalStrings(got, tc.want) {
				t.Fatalf("providers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReconPhase_MissingInventoryFileYieldsNoProviders covers the bare
// `except Exception: providers = []` arm.
func TestReconPhase_MissingInventoryFileYieldsNoProviders(t *testing.T) {
	fake := reconFake(t, filepath.Join(t.TempDir(), "does-not-exist.json"), nil)
	out, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", 1, nil)
	if err != nil {
		t.Fatalf("ReconPhase: %v", err)
	}
	if got := pm(out)["providers_detected"].([]string); len(got) != 0 {
		t.Fatalf("providers = %v, want []", got)
	}
}

// TestReconPhase_TierTwoGatesOnBothTierAndCloudConfig pins the
// `tier >= 2 and cloud_config is not None` gate, including the fact that an
// EMPTY but non-nil map is not None and therefore opens it.
func TestReconPhase_TierTwoGatesOnBothTierAndCloudConfig(t *testing.T) {
	cases := []struct {
		name        string
		tier        int
		cloudConfig map[string]any
		wantCalls   int
	}{
		{name: "tier 1 with config", tier: 1, cloudConfig: map[string]any{"provider": "aws"}, wantCalls: 2},
		{name: "tier 2 without config", tier: 2, cloudConfig: nil, wantCalls: 2},
		{name: "tier 2 with config", tier: 2, cloudConfig: map[string]any{"provider": "aws"}, wantCalls: 4},
		{name: "tier 2 with empty config", tier: 2, cloudConfig: map[string]any{}, wantCalls: 4},
		{name: "tier 3 with config", tier: 3, cloudConfig: map[string]any{"provider": "aws"}, wantCalls: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeInventory(t, map[string]any{"resources": []any{}})
			live := schemas.NewResourceInventory()
			live.InventorySavedPath = "/live.json"
			live.IaCType = "terraform"
			drift := schemas.NewDriftReport()
			drift.CloudOnlyResources = []string{"shadow"}

			fake := reconFake(t, path, func(target string, _ map[string]any) (map[string]any, error) {
				switch target {
				case testNodeID + ".run_cloud_connector":
					return mustMap(t, live), nil
				case testNodeID + ".run_drift_detector":
					return mustMap(t, drift), nil
				}
				t.Errorf("unexpected target %q", target)
				return nil, nil
			})

			out, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", tc.tier, tc.cloudConfig)
			if err != nil {
				t.Fatalf("ReconPhase: %v", err)
			}
			if got := len(fake.Calls); got != tc.wantCalls {
				t.Fatalf("call count = %d, want %d (%v)", got, tc.wantCalls, fake.CallTargets())
			}
			if tc.wantCalls == 4 {
				if pm(out)["drift_report"] == (*schemas.DriftReport)(nil) {
					t.Error("drift_report should be populated for tier >= 2 with a cloud config")
				}
				if pm(out)["live_inventory"] == (*schemas.ResourceInventory)(nil) {
					t.Error("live_inventory should be populated for tier >= 2 with a cloud config")
				}
			} else if pm(out)["drift_report"] != (*schemas.DriftReport)(nil) {
				t.Error("drift_report should stay nil")
			}
		})
	}
}

// TestReconPhase_TierTwoKwargsAndConcurrency pins the two tier-2 kwarg sets and
// proves the pair really is a gather: the fake blocks each call until both are
// in flight, which deadlocks (and times out the test) if they run serially.
func TestReconPhase_TierTwoKwargsAndConcurrency(t *testing.T) {
	path := writeInventory(t, map[string]any{"resources": []any{}})
	live := schemas.NewResourceInventory()
	live.InventorySavedPath = "/live.json"
	drift := schemas.NewDriftReport()

	var barrier sync.WaitGroup
	barrier.Add(2)
	fake := reconFake(t, path, func(target string, _ map[string]any) (map[string]any, error) {
		barrier.Done()
		barrier.Wait()
		switch target {
		case testNodeID + ".run_cloud_connector":
			return mustMap(t, live), nil
		default:
			return mustMap(t, drift), nil
		}
	})

	cloudConfig := map[string]any{"provider": "aws", "regions": []any{"us-east-1"}}
	if _, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", 2, cloudConfig); err != nil {
		t.Fatalf("ReconPhase: %v", err)
	}

	var connector, detector map[string]any
	for _, c := range fake.Calls {
		switch c.Target {
		case testNodeID + ".run_cloud_connector":
			connector = c.Input
		case testNodeID + ".run_drift_detector":
			detector = c.Input
		}
	}
	if connector == nil || detector == nil {
		t.Fatalf("missing tier-2 calls: %v", fake.CallTargets())
	}
	if got := keysOf(connector); !equalStrings(got, []string{"cloud_config"}) {
		t.Errorf("run_cloud_connector kwargs = %v", got)
	}
	if got := keysOf(detector); !equalStrings(got, []string{"cloud_config", "iac_graph_path"}) {
		t.Errorf("run_drift_detector kwargs = %v", got)
	}
	if got := detector["iac_graph_path"]; got != "/g.json" {
		t.Errorf("iac_graph_path = %v", got)
	}
	if fake.MaxConcurrentCalls() < 2 {
		t.Errorf("tier-2 calls did not overlap: max concurrency %d", fake.MaxConcurrentCalls())
	}
}

// TestReconPhase_StrictUnwrapFailuresPropagate covers the phases.py-specific
// _unwrap arms (error_message and status) at every call site.
func TestReconPhase_StrictUnwrapFailuresPropagate(t *testing.T) {
	cases := []struct {
		name    string
		failing string
		reply   map[string]any
		wantErr string
	}{
		{
			name:    "iac reader error_message",
			failing: testNodeID + ".run_iac_reader",
			reply:   map[string]any{"error_message": "no terraform"},
			wantErr: "run_iac_reader failed: no terraform",
		},
		{
			name:    "graph builder failed status",
			failing: testNodeID + ".run_resource_graph_builder",
			reply:   map[string]any{"status": "failed"},
			wantErr: "run_resource_graph_builder failed: Unknown error",
		},
		{
			name:    "graph builder error dict",
			failing: testNodeID + ".run_resource_graph_builder",
			reply:   map[string]any{"error": map[string]any{"message": "boom"}},
			wantErr: "run_resource_graph_builder failed: boom",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeInventory(t, map[string]any{"resources": []any{}})
			base := reconFake(t, path, nil)
			inner := base.CallFn
			fake := &appx.Fake{CallFn: func(ctx context.Context, target string, in map[string]any) (map[string]any, error) {
				if target == tc.failing {
					return tc.reply, nil
				}
				return inner(ctx, target, in)
			}}
			_, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", 1, nil)
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestReconPhase_TierTwoConnectorErrorWinsOverDriftError documents the
// determinism fix: asyncio.gather propagates whichever call fails first in wall
// clock time, Go always reports the cloud-connector slot first.
func TestReconPhase_TierTwoConnectorErrorWinsOverDriftError(t *testing.T) {
	path := writeInventory(t, map[string]any{"resources": []any{}})
	fake := reconFake(t, path, func(target string, _ map[string]any) (map[string]any, error) {
		switch target {
		case testNodeID + ".run_cloud_connector":
			return map[string]any{"error_message": "connector down"}, nil
		default:
			return map[string]any{"error_message": "detector down"}, nil
		}
	})
	_, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", "standard", 2, map[string]any{})
	if err == nil || err.Error() != "run_cloud_connector failed: connector down" {
		t.Fatalf("err = %v, want the connector error", err)
	}
}

// TestReconPhase_DepthIsIgnored pins the Python quirk that recon_phase accepts
// `depth` and never reads it: no depth kwarg reaches any child, and the output
// does not vary with it.
func TestReconPhase_DepthIsIgnored(t *testing.T) {
	path := writeInventory(t, map[string]any{"resources": []any{map[string]any{"provider": "aws"}}})
	for _, depth := range []string{"quick", "standard", "thorough", "bogus"} {
		fake := reconFake(t, path, nil)
		out, err := ReconPhase(context.Background(), fake, testNodeID, "/repo", depth, 1, nil)
		if err != nil {
			t.Fatalf("ReconPhase(%q): %v", depth, err)
		}
		for _, c := range fake.Calls {
			if _, present := c.Input["depth"]; present {
				t.Fatalf("depth leaked into %s kwargs", c.Target)
			}
		}
		if got := pm(out)["providers_detected"].([]string); !equalStrings(got, []string{"aws"}) {
			t.Fatalf("providers = %v", got)
		}
	}
}
