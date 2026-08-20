package reasoners_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	sdkagent "github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/reasoners"
)

// inputschema_test.go is the drift guard on the control-plane input schemas.
//
// The contract, in caller-observable terms:
//
//	(a) every reasoner this node registers publishes a schema derived from the
//	    Python signature, never the SDK's contentless
//	    {"type":"object","additionalProperties":true} default;
//	(b) the fixture and the registered surface cover EXACTLY the same names, in
//	    both directions — a Go reasoner without a fixture entry and a fixture
//	    entry without a Go reasoner are both failures;
//	(c) for a representative slice of signature shapes (plain scalars, a
//	    defaulted parameter, a list-of-dicts, a PEP-604 optional) the published
//	    document is byte-for-byte what the Python node published.
//
// The schemas are read back through GET /discover — the agent's own discovery
// payload, i.e. the same bytes the control plane stores and `af ls` renders —
// so these tests assert what a CALLER sees, not what the fixture file says.

// pythonTopLevelNames is the surface app.py registers with @app.reasoner().
// internal/node mounts these two; the router carries the other 20.
var pythonTopLevelNames = []string{"scan", "prove"}

// --- (b) fixture ↔ registered surface, both directions ------------------------

func TestInputSchemas_FixtureCoversExactlyTheRegisteredSurface(t *testing.T) {
	registered := append(reasoners.RouterNames(), pythonTopLevelNames...)
	sort.Strings(registered)

	if got := reasoners.InputSchemaNames(); !reflect.DeepEqual(got, registered) {
		t.Fatalf("fixture covers\n%v\nregistered surface is\n%v\n"+
			"(a name only in the first is a stale fixture entry; a name only in the "+
			"second would ship the SDK's default schema)", got, registered)
	}
}

func TestInputSchemas_EveryRegisteredReasonerHasAFixtureEntry(t *testing.T) {
	// RegisterAll's return value is what was ACTUALLY mounted, so this walks the
	// live registration sequence rather than the routerNames transcription.
	mounted := reasoners.RegisterAll(sdkagent.NewRouter(), &appx.Fake{})
	for _, name := range append(mounted, pythonTopLevelNames...) {
		if _, ok := reasoners.LookupInputSchema(name); !ok {
			t.Errorf("reasoner %q is registered but has no fixture entry", name)
		}
	}
}

func TestMustInputSchema_PanicsOnAReasonerTheFixtureDoesNotCover(t *testing.T) {
	// Drift must be loud at registration time, not a silent fallback to the
	// SDK's default schema.
	defer func() {
		if recover() == nil {
			t.Fatal("MustInputSchema on an unknown reasoner returned instead of panicking")
		}
	}()
	reasoners.MustInputSchema("run_no_such_reasoner")
}

func TestLookupInputSchema_ReturnsACopy(t *testing.T) {
	first, ok := reasoners.LookupInputSchema(reasoners.NameRunIaCReader)
	if !ok {
		t.Fatal("run_iac_reader has no fixture entry")
	}
	first[0] = 'X'
	second, _ := reasoners.LookupInputSchema(reasoners.NameRunIaCReader)
	if second[0] == 'X' {
		t.Fatal("LookupInputSchema hands out the shared fixture bytes; the SDK stores the RawMessage as-is, so a caller could corrupt every later registration")
	}
}

// --- (a) + (c) what the node actually publishes -------------------------------

func TestInputSchemas_EveryRouterReasonerPublishesItsPythonSchema(t *testing.T) {
	published := discoveredInputSchemas(t, mountRouter(t, &appx.Fake{}))
	fixture := readSchemaFixture(t)

	for _, name := range reasoners.RouterNames() {
		got, ok := published[name]
		if !ok {
			t.Errorf("%s: not present in the discovery payload", name)
			continue
		}
		if isSDKDefaultSchema(got) {
			t.Errorf("%s: publishes the SDK's default schema, so callers learn nothing about the signature", name)
			continue
		}
		if want := fixture[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: published schema\n%s\nwant (Python)\n%s", name, mustIndent(t, got), mustIndent(t, want))
		}
	}
}

// TestInputSchemas_RepresentativeSignaturesMatchPython spells four schemas out
// by hand, transcribed from the Python signatures rather than copied from the
// fixture, so a corrupted or half-regenerated fixture cannot make the test
// above vacuously pass. One reasoner per interesting mapping shape.
func TestInputSchemas_RepresentativeSignaturesMatchPython(t *testing.T) {
	published := discoveredInputSchemas(t, mountRouter(t, &appx.Fake{}))

	cases := map[string]string{
		// reasoners/recon.py: async def run_iac_reader(repo_path: str)
		// The minimal shape: one required scalar.
		reasoners.NameRunIaCReader: `{
			"type": "object",
			"properties": {"repo_path": {"type": "string"}},
			"required": ["repo_path"]
		}`,

		// reasoners/hunt.py: async def run_compliance_hunter(repo_path: str,
		//   resource_graph_path: str, inventory_path: str, depth: str)
		// `depth` carries NO default here, so it IS required — the difference
		// from hunt_phase below is the whole reason both are pinned.
		reasoners.NameRunComplianceHunter: `{
			"type": "object",
			"properties": {
				"repo_path": {"type": "string"},
				"resource_graph_path": {"type": "string"},
				"inventory_path": {"type": "string"},
				"depth": {"type": "string"}
			},
			"required": ["repo_path", "resource_graph_path", "inventory_path", "depth"]
		}`,

		// reasoners/chain.py: async def run_path_constructor(
		//   findings: list[dict[str, Any]], resource_graph_path: str,
		//   max_paths: int, max_children: int,
		//   drift_report: dict[str, Any] | None = None)
		// list[dict[str, Any]] → array + items{object, additionalProperties};
		// the PEP-604 optional collapses to a bare object and drops out of
		// `required` (its default is not published).
		reasoners.NameRunPathConstructor: `{
			"type": "object",
			"properties": {
				"findings": {"type": "array", "items": {"type": "object", "additionalProperties": true}},
				"resource_graph_path": {"type": "string"},
				"max_paths": {"type": "integer"},
				"max_children": {"type": "integer"},
				"drift_report": {"type": "object"}
			},
			"required": ["findings", "resource_graph_path", "max_paths", "max_children"]
		}`,

		// reasoners/phases.py: async def hunt_phase(repo_path: str,
		//   resource_graph_path: str, inventory_path: str,
		//   depth: str = "standard", max_concurrent_hunters: int = 3)
		// Both defaulted parameters keep their declared TYPE but leave
		// `required`, and neither default value is published.
		reasoners.NameHuntPhase: `{
			"type": "object",
			"properties": {
				"repo_path": {"type": "string"},
				"resource_graph_path": {"type": "string"},
				"inventory_path": {"type": "string"},
				"depth": {"type": "string"},
				"max_concurrent_hunters": {"type": "integer"}
			},
			"required": ["repo_path", "resource_graph_path", "inventory_path"]
		}`,
	}

	for name, want := range cases {
		got, ok := published[name]
		if !ok {
			t.Errorf("%s: not present in the discovery payload", name)
			continue
		}
		if !reflect.DeepEqual(got, mustUnmarshal(t, []byte(want))) {
			t.Errorf("%s: published schema\n%s\nwant\n%s", name, mustIndent(t, got), want)
		}
	}
}

// --- helpers ------------------------------------------------------------------

// discoveredInputSchemas reads the agent's own discovery payload — the bytes
// the control plane records for each reasoner — and returns the input schema
// per reasoner id, decoded into plain Go values so comparison ignores JSON key
// order (array order, e.g. `required`, still counts: Python publishes signature
// order and callers render it).
func discoveredInputSchemas(t *testing.T, app *sdkagent.Agent) map[string]any {
	t.Helper()

	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/discover", nil))
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

// readSchemaFixture loads testdata/python_input_schemas.json straight off disk,
// deliberately NOT through the package's embedded copy, so the test compares
// the published bytes against the captured file rather than against itself.
func readSchemaFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "python_input_schemas.json"))
	if err != nil {
		t.Fatalf("read schema fixture: %v", err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode schema fixture: %v", err)
	}
	return fixture
}

// isSDKDefaultSchema reports whether v is the Go SDK's placeholder schema,
// `{"type":"object","additionalProperties":true}` — the thing every reasoner
// published before the fixture was wired in.
func isSDKDefaultSchema(v any) bool {
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != 2 {
		return false
	}
	return obj["type"] == "object" && obj["additionalProperties"] == true
}

func mustUnmarshal(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

func mustIndent(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(b)
}

// --- published contract == enforced contract ---------------------------------

// TestInputSchemas_PublishedRequiredMatchesTheEnforcedRequired closes the loop
// between the two halves of the request contract, which are declared in
// DIFFERENT places and could drift apart silently:
//
//	published — testdata/python_input_schemas.json's `required`, what the
//	            control plane shows a caller;
//	enforced  — each input struct's HandlerInputFields, what afx.BindHandlerInput
//	            rejects a body over (the port of _validate_handler_input).
//
// Python derives both from ONE signature, so they cannot disagree there. Here
// they can. Sending an EMPTY body must therefore be refused, and refused over
// the FIRST name in the published `required` list — Python reports the first
// missing parameter in signature order, and the fixture's `required` preserves
// that order.
func TestInputSchemas_PublishedRequiredMatchesTheEnforcedRequired(t *testing.T) {
	fixture := readSchemaFixture(t)

	for _, name := range reasoners.RouterNames() {
		t.Run(name, func(t *testing.T) {
			schema, ok := fixture[name].(map[string]any)
			if !ok {
				t.Fatalf("fixture entry for %s is not an object", name)
			}
			required, _ := schema["required"].([]any)
			if len(required) == 0 {
				t.Fatalf("%s publishes no required parameters; every cloudsecurity-af "+
					"reasoner has at least one, so this is a broken fixture entry", name)
			}

			app := mountRouter(t, &appx.Fake{
				CallFn: func(context.Context, string, map[string]any) (map[string]any, error) {
					t.Fatal("the handler must not run for a body missing required parameters")
					return nil, nil
				},
			})
			_, err := app.Execute(context.Background(), name, map[string]any{})
			if err == nil {
				t.Fatalf("%s accepted an empty body but publishes required=%v", name, required)
			}

			want := "Missing required field: " + required[0].(string)
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s rejected the empty body with %q, want %q — the published "+
					"schema and HandlerInputFields disagree about what is required", name, err, want)
			}
		})
	}
}
