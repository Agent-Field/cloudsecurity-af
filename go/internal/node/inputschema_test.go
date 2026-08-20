package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// inputschema_test.go pins the input schemas the two @app.reasoner() entry
// points publish. They used to be hand transcriptions declared in inputs.go —
// richer than what Python emits and therefore wrong (see the note at the bottom
// of inputs.go). Both now republish the schema captured from the live Python
// node, and these tests assert that end to end: the bytes are read back off the
// agent's own GET /discover payload, i.e. what the control plane records and
// `af ls` renders.

func TestRegisterAll_TopLevelReasonersPublishThePythonInputSchema(t *testing.T) {
	n := newTestNode(t)
	n.RegisterAll()

	published := discoveredInputSchemas(t, n)
	fixture := readReasonerSchemaFixture(t)

	for _, name := range []string{"scan", "prove"} {
		got, ok := published[name]
		if !ok {
			t.Errorf("%s: not present in the discovery payload", name)
			continue
		}
		if want := fixture[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: published schema\n%s\nwant (Python)\n%s", name, indentJSON(t, got), indentJSON(t, want))
		}
	}
}

// TestRegisterAll_ScanSchemaMatchesTheAppPySignature transcribes app.py::scan
// by hand instead of reading the fixture, so a corrupted fixture cannot make
// the test above vacuously pass. Note the two quirks it locks in, both
// properties of the Python SDK's derivation:
//
//   - Not one `default` is published, even though 5 parameters have one — only
//     `repo_url` (the sole parameter WITHOUT a default) reaches `required`.
//   - Every `X | None = None` parameter is typed `{"type": "object"}`, not by
//     its base type: types.UnionType has no __origin__, so
//     Agent._type_to_json_schema's Union branch never runs and the fallback
//     wins. `commit_sha` is a str in the signature and an "object" on the wire.
func TestRegisterAll_ScanSchemaMatchesTheAppPySignature(t *testing.T) {
	n := newTestNode(t)
	n.RegisterAll()

	want := `{
		"type": "object",
		"properties": {
			"repo_url":               {"type": "string"},
			"depth":                  {"type": "string"},
			"branch":                 {"type": "string"},
			"commit_sha":             {"type": "object"},
			"base_commit_sha":        {"type": "object"},
			"severity_threshold":     {"type": "string"},
			"output_formats":         {"type": "object"},
			"compliance_frameworks":  {"type": "object"},
			"max_cost_usd":           {"type": "object"},
			"max_duration_seconds":   {"type": "object"},
			"max_concurrent_hunters": {"type": "object"},
			"max_concurrent_provers": {"type": "object"},
			"include_paths":          {"type": "object"},
			"exclude_paths":          {"type": "object"},
			"is_pr":                  {"type": "boolean"},
			"pr_id":                  {"type": "object"},
			"fail_on_findings":       {"type": "boolean"}
		},
		"required": ["repo_url"]
	}`

	var expected any
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatalf("decode expectation: %v", err)
	}
	got := discoveredInputSchemas(t, n)["scan"]
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("scan schema\n%s\nwant\n%s", indentJSON(t, got), indentJSON(t, expected))
	}
}

// --- helpers ------------------------------------------------------------------

// discoveredInputSchemas returns the input schema the node publishes per
// reasoner id, decoded into plain Go values (so JSON key order is irrelevant;
// array order, e.g. `required`, still counts — Python publishes signature order).
func discoveredInputSchemas(t *testing.T, n *Node) map[string]any {
	t.Helper()

	rec := httptest.NewRecorder()
	n.App.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /discover = %d, body %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Reasoners []struct {
			ID          string `json:"id"`
			InputSchema any    `json:"input_schema"`
		} `json:"reasoners"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode discovery payload: %v", err)
	}

	out := make(map[string]any, len(payload.Reasoners))
	for _, r := range payload.Reasoners {
		out[r.ID] = r.InputSchema
	}
	return out
}

// readReasonerSchemaFixture reads the captured Python schemas off disk rather
// than through internal/reasoners' embedded copy, so the comparison has two
// independent sides.
func readReasonerSchemaFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "reasoners", "testdata", "python_input_schemas.json"))
	if err != nil {
		t.Fatalf("read schema fixture: %v", err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode schema fixture: %v", err)
	}
	return fixture
}

func indentJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(b)
}
