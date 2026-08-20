// Package afx holds the small ergonomics over the AgentField Go SDK that every
// reasoner handler, phase and orchestrator step in the cloudsecurity-af port
// reuses:
//
//   - Bind / ToMap        — the pydantic model <-> reasoner-input map boundary
//   - Unwrap / UnwrapStrict / AsMap — the exact ports of the Python node's
//     _unwrap / _as_dict envelope handling for app.call() results
//   - DropNulls / DumpExcludeNone   — model_dump(exclude_none=True) parity
//
// Everything here is a 1:1 port of Python behaviour, including the error
// strings, which the phases and the orchestrator surface to callers.
package afx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Bind decodes a reasoner's untyped input map into a typed value T.
//
// Handlers registered with the SDK receive input as map[string]any. Bind
// round-trips that map through JSON (marshal then unmarshal into T), which
// mirrors how the Python node materializes a pydantic model from the request
// body: field-name matching is by the json struct tags (the exact snake_case
// pydantic field names), and any custom UnmarshalJSON on T runs — so a T whose
// UnmarshalJSON seeds non-zero pydantic defaults gets those defaults for keys
// absent from the input.
//
// The decode uses json.Decoder.UseNumber. That matters for the `Any`-typed
// leaves the ported models carry — DriftedResource.iac_config / live_config are
// `dict[str, Any]` and ConfigDiff.iac_value / live_value are `Any` — because
// plain encoding/json turns every JSON number landing in such a leaf into a
// float64. Python's json.loads keeps `{"port": 5432}` an INT, so a float64
// re-renders as `5432.0` in {{DRIFT_REPORT_JSON}} (the CHAIN parent prompt),
// in {{FINDING_JSON}} (the fix-generator prompt), in
// .cloudsecurity/checkpoint-recon.json and in the scan result. json.Number
// keeps the literal and re-marshals verbatim through both encoding/json and
// pyfmt.Dumps. Decoding into TYPED fields is unaffected — UseNumber only
// changes how `any` targets are filled.
//
// The same decoder is used inside every default-seeding UnmarshalJSON (see
// schemas.decodeSeeded), because a custom UnmarshalJSON receives raw bytes and
// would otherwise re-introduce float64 below Bind's own decode.
//
// DIVERGENCE — THE OTHER HALF OF THE SAME TRADE-OFF, and it is not fixable from
// here. UseNumber pins the literal of the map Bind is HANDED, and by then the
// Go SDK has already decoded the request body with a plain encoding/json
// decoder (sdk/go/agent/agent.go handleReasoner / the skill path — there is no
// UseNumber anywhere in sdk/go), collapsing every JSON number onto float64. So
// a wire `7.0` arrives as float64(7), `json.Marshal` writes it back as `7`, and
// UseNumber pins THAT as json.Number("7"). An integral float inside an `Any`
// leaf therefore loses Python's float spelling:
//
//	wire      {"resource_id":"r","resource_type":"t","iac_config":{"ratio":7.0,"n":5}}
//	Python    "iac_config": {"ratio": 7.0, "n": 5}      (venv, DriftedResource.model_dump)
//	Go        "iac_config": {"n": 5, "ratio": 7}
//
// visible in {{DRIFT_REPORT_JSON}}, {{FINDING_JSON}},
// .cloudsecurity/checkpoint-recon.json and the scan reply. Dropping UseNumber
// would trade this rare case for the common one — `{"port": 5432}` would render
// `5432.0` — so UseNumber stays. (The key ORDER in that example is the
// separately documented map-sorting deviation of pyfmt.Dumps: a Go map has no
// insertion order.) internal/afx/bind_numbers_test.go pins both halves.
//
// Python parity: a nil input map is normalized to an empty object, so
// Bind[T](nil) is Model(**{}) — every pydantic default is seeded. (Marshaling
// a nil map would emit "null", which unmarshals into T as a no-op for a plain
// struct and hands "null" to a custom UnmarshalJSON.)
// Bind also enforces pydantic's REQUIRED fields (see required.go): a T whose
// type — or any model nested inside it — implements RequiredFielder is checked
// against the payload before the decode, so `Model.model_validate(d)` raises in
// Go wherever it raises in Python instead of returning a zero-valued model.
// ValidationError is the Go stand-in for pydantic's ValidationError, which is
// a ValueError SUBCLASS — the distinction app.py's `except ValueError` /
// `except Exception` split turns into HTTP 400 versus 500.
//
// It exists so a caller classifies a bind failure by VALUE (errors.As) instead
// of by scanning message text. Text matching cannot tell an in-process bind
// failure from one that happened inside a CHILD reasoner and was relayed back
// through the control plane: the child's `afx.Bind: ...` message is copied
// verbatim into the execution's error_message and surfaces at the parent as an
// *agent.ExecuteError, which Python sees as a transport exception (500), not as
// a ValueError (400).
//
// The rendered text is unchanged — "afx.Bind: " followed by the cause — so the
// 400 body still matches Python's str(exc) shape.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return "afx.Bind: " + e.Err.Error() }

func (e *ValidationError) Unwrap() error { return e.Err }

func Bind[T any](input map[string]any) (T, error) {
	var out T
	if input == nil {
		input = map[string]any{}
	}
	if err := requireFields(map[string]any(input), reflect.TypeOf(out)); err != nil {
		return out, &ValidationError{Err: err}
	}
	// pydantic's LAX scalar coercion and its rejection of a null for a
	// non-Optional field — the two things a JSON round-trip gets wrong on a
	// value that IS present. See lax.go.
	coerced, err := coerceLax(map[string]any(input), reflect.TypeOf(out))
	if err != nil {
		return out, &ValidationError{Err: err}
	}
	b, err := json.Marshal(coerced)
	if err != nil {
		return out, &ValidationError{Err: fmt.Errorf("marshal input: %w", err)}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return out, &ValidationError{Err: fmt.Errorf("unmarshal into %T: %w", out, err)}
	}
	return out, nil
}

// ToMap is Bind's inverse: it renders a typed input struct as the
// map[string]any shape the SDK's reasoner handlers (and Agent.Call) accept.
// Top-level exported fields become map entries keyed by their json tag, and the
// field VALUES stay typed — deliberately NOT a marshal→unmarshal round trip,
// which would decode nested values into plain Go maps and lose whatever their
// custom marshalers encode (ordered objects, the Timestamp wrapper's isoformat
// rendering, enum normalization). Keeping values typed lets Bind on the handler
// side (and the SDK's workflow-event emitter) re-marshal them through the same
// custom marshalers, so ToMap→Bind is lossless.
//
// The reasoner input structs are flat, fully json-tagged, and carry no
// omitempty (every key is emitted, so Bind-side default seeding never overrides
// a deliberately zero field); ToMap ignores omitempty accordingly. Anonymous
// embedded structs without their own json tag are flattened the way
// encoding/json flattens them.
//
// Use DumpExcludeNone instead when the Python source called
// model_dump(exclude_none=True).
func ToMap(v any) (map[string]any, error) {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, fmt.Errorf("afx.ToMap: nil %T", v)
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("afx.ToMap: %T is not a struct", v)
	}
	out := make(map[string]any, rv.NumField())
	fillMap(out, rv)
	return out, nil
}

// fillMap writes rv's fields into out, recursing through untagged anonymous
// struct fields (encoding/json flattening).
func fillMap(out map[string]any, rv reflect.Value) {
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			if f.Anonymous {
				fv := rv.Field(i)
				for fv.Kind() == reflect.Pointer && !fv.IsNil() {
					fv = fv.Elem()
				}
				if fv.Kind() == reflect.Struct {
					fillMap(out, fv)
					continue
				}
			}
			name = f.Name
		}
		out[name] = rv.Field(i).Interface()
	}
}
