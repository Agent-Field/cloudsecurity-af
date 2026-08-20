package reasoners

// inputschema.go carries the input schemas the control plane sees for every
// cloudsecurity-af reasoner — the 20 router reasoners registered here AND the
// two top-level ones (`scan`, `prove`) internal/node registers.
//
// WHY A FIXTURE AND NOT A TRANSCRIPTION
//
// The Python SDK derives each reasoner's input schema from the FUNCTION
// SIGNATURE at registration time (Agent._types_to_json_schema, sdk/python/
// agentfield/agent.py) and publishes it through the control plane's discovery
// API, where `af ls`, the CP UI's run form and tool-calling all read it. The Go
// SDK has no signature to introspect: agent.RegisterReasoner defaults every
// handler to `{"type":"object","additionalProperties":true}`
// (sdk/go/agent/agent_register.go), which tells a caller nothing. Attaching
// agent.WithInputSchema is therefore mandatory for parity, and the only way to
// be sure the bytes match is to take them FROM the Python node rather than
// re-derive them by hand — the Python mapping has quirks a transcription
// reliably gets wrong (see "MAPPING QUIRKS" below).
//
// PROVENANCE
//
// testdata/python_input_schemas.json was captured from a LIVE Python
// cloudsecurity-af node running agentfield==0.1.131, read back off the control
// plane's discovery API with include_input_schema=true. It is keyed by reasoner
// id and holds all 22 entries.
//
// To regenerate it (after a Python signature changes, or on an SDK bump):
//
//	# 1. Run the Python node so it registers with a control plane:
//	#      af run cloudsecurity-af
//	# 2. Read the schemas back and reshape into {reasoner_id: input_schema}:
//	curl -sG http://localhost:8080/api/v1/discovery/capabilities \
//	  --data-urlencode 'agent=cloudsecurity' \
//	  --data-urlencode 'include_input_schema=true' |
//	  python3 -c 'import json,sys
//	caps = json.load(sys.stdin)["capabilities"]
//	out = {r["id"]: r["input_schema"] for c in caps for r in c["reasoners"]}
//	print(json.dumps(out, indent=1, sort_keys=True))' \
//	  > internal/reasoners/testdata/python_input_schemas.json
//
// (`agent=` takes the node_id the Python node registers under. Object KEYS are
// sorted by the dump — `required` arrays keep their signature order, which is
// what Python publishes.)
//
// MAPPING QUIRKS worth knowing when reading the fixture, all of them properties
// of Agent._type_to_json_schema:
//
//   - str→string, int→integer, float→number, bool→boolean; a bare `dict`
//     annotation→object, `dict[str, Any]`→object + additionalProperties:true;
//     `list[X]`→array + items:<X's schema>.
//   - A pydantic model→its model_json_schema(). None of these signatures takes
//     one; every model argument crosses the wire as `dict[str, Any]`.
//   - `required` lists exactly the parameters with NO default, in signature
//     order. A parameter WITH a default is omitted from `required` and the
//     default itself is NOT published.
//   - PEP-604 optionals (`str | None`, `list[str] | None`) fall through to the
//     `{"type": "object"}` fallback — `types.UnionType` has no `__origin__`, so
//     the Union branch that would unwrap to the base type never runs. That is
//     why e.g. `scan.commit_sha` and `recon_phase.cloud_config` are typed
//     "object" here rather than "string"/"object+additionalProperties". The
//     port publishes what Python publishes, quirk included.
//   - The schema carries no `additionalProperties` at the top level and no
//     `default` keys — Python emits only {type, properties, required}.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

//go:embed testdata/python_input_schemas.json
var pythonInputSchemasJSON []byte

// pythonInputSchemas is the parsed fixture, one compacted JSON document per
// reasoner id. Parsing at package init means a corrupt fixture fails the
// binary's very first use rather than a later registration.
var pythonInputSchemas = parseInputSchemas(pythonInputSchemasJSON)

// parseInputSchemas decodes the fixture and compacts each schema so the bytes
// handed to agent.WithInputSchema are wire-shaped rather than the fixture's
// pretty-printed form. Compacting is whitespace-only: the published document is
// semantically identical to the captured one.
func parseInputSchemas(raw []byte) map[string]json.RawMessage {
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		panic(fmt.Sprintf("reasoners: testdata/python_input_schemas.json is not a JSON object of schemas: %v", err))
	}
	if len(parsed) == 0 {
		panic("reasoners: testdata/python_input_schemas.json is empty")
	}
	out := make(map[string]json.RawMessage, len(parsed))
	for name, schema := range parsed {
		var buf bytes.Buffer
		if err := json.Compact(&buf, schema); err != nil {
			panic(fmt.Sprintf("reasoners: input schema for %q is not valid JSON: %v", name, err))
		}
		out[name] = json.RawMessage(buf.Bytes())
	}
	return out
}

// MustInputSchema returns the Python-published input schema for the reasoner
// called name.
//
// It PANICS when the fixture has no entry for name. Every call site is a
// registration — reg() below and internal/node.RegisterAll — so the panic fires
// at process start, on the first `af run`/`go test`, and never mid-execution.
// That is deliberate: a reasoner added in Go without a matching fixture entry
// would otherwise silently ship the SDK's contentless default schema, and
// nothing downstream would complain. Loud beats invisible drift.
func MustInputSchema(name string) json.RawMessage {
	schema, ok := LookupInputSchema(name)
	if !ok {
		panic(fmt.Sprintf("reasoners: no input schema for reasoner %q — regenerate "+
			"internal/reasoners/testdata/python_input_schemas.json from the Python node "+
			"(see inputschema.go)", name))
	}
	return schema
}

// LookupInputSchema returns a COPY of the schema published for name, and
// whether the fixture carries one. The copy keeps a caller (or the SDK, which
// stores the json.RawMessage as-is) from mutating the shared fixture bytes.
func LookupInputSchema(name string) (json.RawMessage, bool) {
	schema, ok := pythonInputSchemas[name]
	if !ok {
		return nil, false
	}
	return json.RawMessage(append([]byte(nil), schema...)), true
}

// InputSchemaNames returns every reasoner id the fixture covers, sorted. It is
// the "what Python publishes" side of the drift test in inputschema_test.go,
// which pins it against the registered surface in both directions.
func InputSchemaNames() []string {
	out := make([]string, 0, len(pythonInputSchemas))
	for name := range pythonInputSchemas {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
