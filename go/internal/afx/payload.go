package afx

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// payload.go is the reasoner RETURN boundary — the Go stand-in for the dict a
// Python reasoner hands back.
//
// Python returns `result.model_dump()` (or a dict literal), FastAPI serialises
// it with json.dumps, and json.dumps preserves a dict's insertion order. So the
// wire body starts
//
//	{"repository": ..., "commit_sha": ..., "branch": ..., "timestamp": ...
//
// in pydantic FIELD-DECLARATION order, and every float field is spelled the
// Python way: `"risk_score": 0.0`, not `0`.
//
// A Go `map[string]any` return loses both: encoding/json SORTS map keys
// (agent_invocations, attack_paths, branch, by_severity, commit_sha, …) and
// renders float64(0) as `0`. Payload keeps the order the model declares and
// delegates the value spelling to pyfmt.Dumps, which is the same renderer the
// port already uses for every on-disk artifact.
//
// SDK CAVEAT (unavoidable from here): when an execution recorded LLM usage, the
// Go SDK re-encodes the handler's result through a map[string]any to merge its
// usage envelope (sdk/go/agent/usage.go wrapSyncResultWithUsage), which sorts
// the keys again. Payload therefore restores Python's byte order on the
// no-usage path and the VALUE spelling everywhere.

// Payload is an insertion-ordered JSON object: the model_dump() of a pydantic
// model, or a reasoner's literal dict, with its key order intact.
//
// It is deliberately the same element type as pyfmt.Ordered so the two convert
// for free. It is a separate type because pyfmt.Ordered must NOT grow a
// MarshalJSON — pyfmt.Dumps checks json.Marshaler before its own Ordered
// branch, so that would make Dumps recurse into itself.
type Payload []pyfmt.KV

// DictFieldOrder is implemented by a model that has map-typed fields whose
// Python dict INSERTION order is fixed and knowable, and returns that order
// keyed by json field name.
//
// A Python dict keeps insertion order and json.dumps honors it, so
// `model_dump()["by_severity"]` goes over the wire as
// {"critical": …, "high": …, "medium": …, "low": …, "info": …} — the Severity
// enum's declaration order, seeded at orchestrator.py:165. A Go map has no
// order, and every renderer in this port therefore SORTS its keys, which would
// put "info" second. Implementing this interface is how a model opts a field
// out of that sort; schemas.CloudSecurityScanResult does it for `by_severity`
// and `cost_breakdown`, the two dicts whose seeding is deterministic.
//
// Fields not named here keep the sorted rendering (`metadata` is the one that
// still does — its keys are assembled ad hoc and Python's order is not
// reproducible from the Go side).
type DictFieldOrder interface {
	DictFieldOrder() map[string][]string
}

// Dump renders a struct as a Payload in FIELD-DECLARATION order.
//
// Like ToMap it keeps the field VALUES typed rather than round-tripping them
// through JSON, so custom marshalers (schemas.Timestamp's isoformat spelling,
// the strict enums) still run at encode time. Untagged anonymous embedded
// structs are flattened the way encoding/json flattens them.
func Dump(v any) (Payload, error) {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, fmt.Errorf("afx.Dump: nil %T", v)
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("afx.Dump: %T is not a struct", v)
	}
	out := make(Payload, 0, rv.NumField())
	out = appendFields(out, rv)
	if orderer, ok := rv.Interface().(DictFieldOrder); ok {
		applyDictFieldOrder(out, orderer.DictFieldOrder())
	}
	return out, nil
}

// applyDictFieldOrder replaces every named map-typed field with an
// insertion-ordered pyfmt.Ordered, in place.
func applyDictFieldOrder(p Payload, orders map[string][]string) {
	if len(orders) == 0 {
		return
	}
	for i, kv := range p {
		order, ok := orders[kv.K]
		if !ok {
			continue
		}
		p[i].V = orderedMap(kv.V, order)
	}
}

// orderedMap renders a Go map as a pyfmt.Ordered whose keys start with `order`
// (skipping any the map does not hold) and end with whatever is left, SORTED —
// a defensive tail Python cannot reach, kept deterministic. A non-map value is
// returned untouched.
func orderedMap(v any, order []string) any {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return v
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Map || rv.IsNil() {
		return v
	}
	byName := make(map[string]any, rv.Len())
	for _, k := range rv.MapKeys() {
		byName[pyfmt.JSONMapKey(k)] = rv.MapIndex(k).Interface()
	}
	out := make(pyfmt.Ordered, 0, len(byName))
	seen := make(map[string]bool, len(order))
	for _, name := range order {
		seen[name] = true
		if val, present := byName[name]; present {
			out = append(out, pyfmt.KV{K: name, V: val})
		}
	}
	rest := make([]string, 0, len(byName))
	for name := range byName {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		out = append(out, pyfmt.KV{K: name, V: byName[name]})
	}
	return out
}

// appendFields walks rv's fields in declaration order.
func appendFields(out Payload, rv reflect.Value) Payload {
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
					out = appendFields(out, fv)
					continue
				}
			}
			name = f.Name
		}
		out = append(out, pyfmt.KV{K: name, V: rv.Field(i).Interface()})
	}
	return out
}

// Get returns the value for key and whether it was present — Python's `d[k]` /
// `k in d`.
func (p Payload) Get(key string) (any, bool) {
	return pyfmt.Ordered(p).Get(key)
}

// Map returns the payload as a plain map, for callers (and tests) that only
// look values up by key. The order is lost, which is the whole reason Payload
// exists — do not feed the result back to a serializer.
func (p Payload) Map() map[string]any {
	out := make(map[string]any, len(p))
	for _, kv := range p {
		if _, seen := out[kv.K]; !seen {
			out[kv.K] = kv.V
		}
	}
	return out
}

// MarshalJSON renders the payload exactly as `json.dumps(model_dump())` would:
// keys in insertion order, floats in Python's repr (`0.0`, not `0`), integers
// verbatim, non-ASCII escaped as \uXXXX.
//
// DIVERGENCE (documented, and the same thing FastAPI does): Python's json.dumps
// would emit NaN and Infinity, which are not valid JSON — but FastAPI's
// JSONResponse passes allow_nan=False and RAISES instead. pyfmt.Dumps
// reproduces the json.dumps spelling, so this method reports an error rather
// than putting an unparsable body on the wire. No arithmetic in the port can
// produce a non-finite float.
//
// Note that encoding/json COMPACTS a Marshaler's output, dropping pyfmt's
// ", " / ": " separators — which is also what FastAPI does
// (separators=(",", ":")), so the wire bytes agree.
func (p Payload) MarshalJSON() ([]byte, error) {
	body := []byte(pyfmt.DumpsCompact(p.renderable()))
	if !json.Valid(body) {
		return nil, fmt.Errorf("afx.Payload: rendered body is not valid JSON (a non-finite float?): %s", body)
	}
	return body, nil
}

// renderable converts the payload into the value model pyfmt.Dumps renders
// NATIVELY, replacing every nested Payload with a pyfmt.Ordered.
//
// This is load-bearing, not cosmetic. pyfmt.Dumps checks json.Marshaler before
// its own Ordered branch, and its Marshaler path decodes the produced bytes
// into a plain map before re-rendering — which SORTS the keys. So a Payload
// nested inside another Payload (prove_phase's `verified` list of
// model_dump(exclude_none=True) results) would come out alphabetised, undoing
// the very ordering this type exists to preserve.
func (p Payload) renderable() pyfmt.Ordered {
	out := make(pyfmt.Ordered, len(p))
	for i, kv := range p {
		out[i] = pyfmt.KV{K: kv.K, V: renderableValue(kv.V)}
	}
	return out
}

// renderableValue converts the containers that can hold a Payload. Anything
// else — structs, typed slices, maps, scalars — is left alone for pyfmt.Dumps
// to walk natively.
func renderableValue(v any) any {
	switch x := v.(type) {
	case Payload:
		return x.renderable()
	case []Payload:
		out := make([]any, len(x))
		for i := range x {
			out[i] = x[i].renderable()
		}
		return out
	case pyfmt.Ordered:
		return Payload(x).renderable()
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = renderableValue(x[i])
		}
		return out
	}
	return v
}
