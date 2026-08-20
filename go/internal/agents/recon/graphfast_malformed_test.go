package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// VALIDATION CONTRACT — malformed inventory.json (derived by RUNNING
// src/cloudsecurity_af/agents/recon/_graph_builder_fast.py:build_graph_from_inventory
// under the repo venv, not by reading the Go code):
//
//	inventory field                observable Python behaviour
//	-----------------------------  -----------------------------------------------
//	references: null               TypeError: 'NoneType' object is not iterable
//	references: 5                  TypeError: 'int' object is not iterable
//	referenced_by: null            TypeError: 'NoneType' object is not iterable
//	file_path: 12                  AttributeError: 'int' object has no attribute 'split'
//	file_path: null                AttributeError: 'NoneType' object has no attribute 'split'
//	type: 7                        TypeError: argument of type 'int' is not iterable
//	references: "b"                NO raise — Python iterates the CHARACTERS, so a
//	                               single-character id "b" DOES produce an edge
//	references: {"b": 1}           NO raise — Python iterates the dict's KEYS
//	file_path absent               NO raise — the "" default splits fine
//	id: 7                          NO raise — the value is copied into the node
//
// Every raise is caught by run_resource_graph_builder's `except Exception` and
// selects the harness fallback (resource_graph_builder.py:27-31). Coercing
// those fields to empty instead would return a SUCCESSFUL, silently edge-less
// graph — total_edges 0, "no edges matched this hunter domain" in every hunter
// prompt — with no error and no warning anywhere.

// malformedResource is one inventory resource with every field spelled out, so
// each case below changes exactly one thing.
func malformedInventory(t *testing.T, resources ...map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body, err := json.Marshal(map[string]any{"resources": resources})
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return path
}

func resource(overrides map[string]any) map[string]any {
	r := map[string]any{
		"id":            "a",
		"type":          "aws_s3_bucket",
		"provider":      "aws",
		"file_path":     "main.tf",
		"config":        map[string]any{},
		"references":    []any{},
		"referenced_by": []any{},
	}
	for k, v := range overrides {
		r[k] = v
	}
	return r
}

func TestBuildGraphFromInventory_RaisesWherePythonRaises(t *testing.T) {
	cases := []struct {
		name    string
		res     map[string]any
		wantErr string
	}{
		{"references null", resource(map[string]any{"references": nil}), "'NoneType' object is not iterable"},
		{"references int", resource(map[string]any{"references": 5}), "'int' object is not iterable"},
		{"references bool", resource(map[string]any{"references": true}), "'bool' object is not iterable"},
		{"referenced_by null", resource(map[string]any{"referenced_by": nil}), "'NoneType' object is not iterable"},
		{"file_path int", resource(map[string]any{"file_path": 12}), "'int' object has no attribute 'split'"},
		{"file_path null", resource(map[string]any{"file_path": nil}), "'NoneType' object has no attribute 'split'"},
		{"type int", resource(map[string]any{"type": 7}), "argument of type 'int' is not iterable"},
		// Both malformed: Python's file_path.split runs first.
		{"file_path and type", resource(map[string]any{"file_path": nil, "type": 7}), "'NoneType' object has no attribute 'split'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := malformedInventory(t, tc.res)
			_, _, _, err := BuildGraphFromInventory(path, t.TempDir())
			if err == nil {
				t.Fatalf("BuildGraphFromInventory succeeded; Python raises %s and falls back to the harness", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Errorf("error = %q, want %q (the exact Python exception text the fallback logs)", err, tc.wantErr)
			}
		})
	}
}

func TestBuildGraphFromInventory_DuckTypesTheReferenceIterationLikePython(t *testing.T) {
	target := resource(map[string]any{"id": "b", "type": "aws_iam_role"})

	t.Run("a string references field iterates its characters", func(t *testing.T) {
		// Python: `for ref in "b"` yields "b", which IS a known resource id, so
		// exactly one edge is built. Coercing to no-references drops it.
		path := malformedInventory(t, resource(map[string]any{"references": "b"}), target)
		graphPath, nodes, edges, err := BuildGraphFromInventory(path, t.TempDir())
		if err != nil {
			t.Fatalf("BuildGraphFromInventory: %v", err)
		}
		if nodes != 2 || edges != 1 {
			t.Fatalf("nodes=%d edges=%d, want 2 and 1", nodes, edges)
		}
		body, err := os.ReadFile(graphPath)
		if err != nil {
			t.Fatalf("read graph: %v", err)
		}
		if !strings.Contains(string(body), `"type": "data_access"`) {
			t.Errorf("edge type must be data_access (aws_s3_bucket -> b), got %s", body)
		}
	})

	t.Run("a dict references field iterates its keys", func(t *testing.T) {
		path := malformedInventory(t,
			resource(map[string]any{"id": "a", "type": "t", "references": map[string]any{"b": 1}}),
			resource(map[string]any{"id": "b", "type": "t"}))
		_, nodes, edges, err := BuildGraphFromInventory(path, t.TempDir())
		if err != nil {
			t.Fatalf("BuildGraphFromInventory: %v", err)
		}
		if nodes != 2 || edges != 1 {
			t.Fatalf("nodes=%d edges=%d, want 2 and 1", nodes, edges)
		}
	})

	t.Run("an absent file_path is the empty-string default, not an error", func(t *testing.T) {
		r := resource(nil)
		delete(r, "file_path")
		path := malformedInventory(t, r)
		if _, _, _, err := BuildGraphFromInventory(path, t.TempDir()); err != nil {
			t.Fatalf("BuildGraphFromInventory: %v", err)
		}
	})
}

// The end-to-end consequence: a malformed inventory must reach the LLM harness,
// which is the branch Python takes and the branch a silent coercion removed.
func TestRunResourceGraphBuilder_MalformedInventoryFallsBackToTheHarness(t *testing.T) {
	warnings := silenceWarnings(t)

	spy := newSpy(`{"graph_saved_path":"/tmp/x/graph.json","total_nodes":4,"total_edges":2}`)
	path := malformedInventory(t, resource(map[string]any{"references": nil}))

	got, err := RunResourceGraphBuilder(context.Background(), spy.Fake, fixtureRepoPath, path)
	if err != nil {
		t.Fatalf("RunResourceGraphBuilder: %v", err)
	}
	if got.TotalNodes != 4 || got.TotalEdges != 2 {
		t.Errorf("harness result not returned: %+v", got)
	}
	if len(spy.opts) != 1 {
		t.Fatalf("harness calls = %d, want 1 (the deterministic build must have raised)", len(spy.opts))
	}
	t.Cleanup(func() { _ = os.RemoveAll(spy.opts[0].Cwd) })
	if w := warnings.String(); !strings.Contains(w, "Deterministic graph builder failed ('NoneType' object is not iterable)") {
		t.Errorf("warning = %q, want Python's log.warning text with the exception", w)
	}
}
