package afx

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// DropNulls recursively removes every null-valued entry from the JSON-shaped
// tree v, returning a new tree; v is not mutated.
//
// It is the Go stand-in for pydantic's model_dump(exclude_none=True), which
// reasoners/phases.py uses on every VerifiedFinding it returns:
//
//	"verified": [v.model_dump(exclude_none=True) for v in verified]
//
// Shape handled: map[string]any (null entries dropped, values recursed) and
// []any (elements recursed, NOT dropped). Everything else is returned
// unchanged. Null means an untyped nil or a nil pointer/interface; a nil Go
// SLICE is an empty JSON list, not a null, and is left alone.
//
// PYDANTIC SEMANTICS (verified against pydantic 2.13.4 in this repo's venv):
// exclude_none drops MODEL FIELDS whose value is None, but leaves None inside a
// plain dict or list field. Given
//
//	class Inner(BaseModel):  a: str | None = None ; b: str = "x"
//	class Outer(BaseModel):  n: int | None = None ; lst: list[Inner|None] = []
//	                         d: dict[str, Any] = {} ; inner: Inner | None = None
//	Outer(n=None, lst=[Inner(), None], d={"k": None, "j": 1}, inner=Inner())
//	  .model_dump(exclude_none=True)
//	== {'lst': [{'b': 'x'}, None], 'd': {'k': None, 'j': 1}, 'inner': {'b': 'x'}}
//
// i.e. `n` was dropped, the list's None survived, and d's None survived.
//
// DropNulls is the STRUCTURAL half of that rule: it drops nulls at EVERY object
// level, which is only equal to exclude_none for a tree whose objects are all
// model fields. It is NOT the right tool for a model carrying a free-form
// dict — VerifiedFinding.drift.iac_config / live_config are `dict[str, Any]`
// and a null-valued config key (`{"logging": null}` meaning "not configured")
// is ordinary. Use DumpExcludeNone, which walks the Go TYPE alongside the tree
// and therefore knows which objects are models and which are free-form dicts.
func DropNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isNull(val) {
				continue
			}
			out[k] = DropNulls(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			// Python parity: a None ELEMENT of a list survives exclude_none.
			out[i] = DropNulls(e)
		}
		return out
	}
	return v
}

// isNull reports whether v is a JSON null: an untyped nil, or a nil pointer or
// interface. A nil map or slice is deliberately NOT null — those marshal to
// {} / [] the way an empty pydantic container does.
func isNull(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// DumpExcludeNone ports `model.model_dump(exclude_none=True)` end to end and
// returns the result as an insertion-ORDERED Payload, because Python's dict
// keeps the model's field order and json.dumps writes it out that way.
//
// The render goes through pyfmt (not encoding/json) for the same reason
// afx.Payload does: pyfmt spells a float field the Python way ("risk_score":
// 0.0, not 0) and pyfmt.Load's int/float split keeps an integer inside a
// free-form dict an integer. Custom marshalers still run — pyfmt.Dumps honours
// json.Marshaler, so schemas.Timestamp keeps its isoformat spelling.
//
// The prune is TYPE-GUIDED: it walks reflect.TypeOf(v) alongside the rendered
// tree, so a null is dropped only where the enclosing object is a Go STRUCT (a
// pydantic model) and the key names one of its fields. Inside a
// `map[string]any` / `any` field — the Go spelling of `dict[str, Any]` / `Any` —
// nulls are kept verbatim, exactly as pydantic keeps them. Without that guide,
// `VerifiedFinding.drift.iac_config = {"logging": null, "acl": "private"}`
// silently lost the `logging` key on its way out of prove_phase /
// remediation_phase and out of the final scan result.
//
// Use this — not ToMap or Dump — wherever the Python source calls
// model_dump(exclude_none=True).
func DumpExcludeNone(v any) (Payload, error) {
	rendered := pyfmt.DumpsCompact(v)
	tree, err := pyfmt.Load([]byte(rendered))
	if err != nil {
		return nil, fmt.Errorf("afx.DumpExcludeNone: decode %T: %w", v, err)
	}
	cleaned, ok := dropNullsTyped(tree, reflect.TypeOf(v)).(pyfmt.Ordered)
	if !ok {
		return nil, fmt.Errorf("afx.DumpExcludeNone: %T does not encode to a JSON object", v)
	}
	return Payload(cleaned), nil
}

// jsonMarshalerType is the interface whose implementations render themselves —
// their JSON is opaque to the prune, exactly as a pydantic field with a custom
// serializer is opaque to exclude_none.
var jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

// dropNullsTyped prunes tree using the Go type t as the model/free-form guide.
//
//	t is a STRUCT          -> a pydantic model: null-valued keys that name one
//	                          of its fields are DROPPED, and each surviving
//	                          value recurses with that field's type.
//	t is a MAP             -> `dict[str, V]`: nulls are KEPT, values recurse
//	                          with V (so `dict[str, Model]` still gets
//	                          exclude_none, which pydantic also applies).
//	t is a SLICE/ARRAY     -> elements recurse with the element type; a null
//	                          ELEMENT survives, as it does in pydantic.
//	t is an INTERFACE/nil  -> unknown shape (`Any`): the subtree is returned
//	                          untouched, nulls included.
//
// tree is pyfmt.Load's value model (nil | bool | string | int | float64 |
// []any | pyfmt.Ordered), so objects keep their document order throughout.
func dropNullsTyped(tree any, t reflect.Type) any {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	// A type that renders itself owns its whole JSON subtree.
	if t != nil && t.Kind() != reflect.Interface &&
		(t.Implements(jsonMarshalerType) || reflect.PointerTo(t).Implements(jsonMarshalerType)) {
		return tree
	}

	switch x := tree.(type) {
	case pyfmt.Ordered:
		if t == nil || t.Kind() == reflect.Interface {
			return tree
		}
		switch t.Kind() {
		case reflect.Struct:
			fields := jsonFieldTypes(t)
			out := make(pyfmt.Ordered, 0, len(x))
			for _, kv := range x {
				ft, declared := fields[kv.K]
				if declared && isNull(kv.V) {
					continue
				}
				if !declared {
					// Not a model field (an extra key a custom marshaler
					// added): leave it, and its nulls, alone.
					out = append(out, kv)
					continue
				}
				out = append(out, pyfmt.KV{K: kv.K, V: dropNullsTyped(kv.V, ft)})
			}
			return out
		case reflect.Map:
			// Python parity: a None VALUE of a dict field survives exclude_none.
			elem := t.Elem()
			out := make(pyfmt.Ordered, 0, len(x))
			for _, kv := range x {
				out = append(out, pyfmt.KV{K: kv.K, V: dropNullsTyped(kv.V, elem)})
			}
			return out
		default:
			return tree
		}
	case []any:
		if t == nil || t.Kind() == reflect.Interface {
			return tree
		}
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return tree
		}
		elem := t.Elem()
		out := make([]any, len(x))
		for i, e := range x {
			// Python parity: a None ELEMENT of a list survives exclude_none.
			out[i] = dropNullsTyped(e, elem)
		}
		return out
	}
	return tree
}

// jsonFieldTypes maps a struct's JSON key names to the declared field types,
// flattening untagged anonymous embedded structs the way encoding/json does.
func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	collectJSONFieldTypes(out, t)
	return out
}

func collectJSONFieldTypes(out map[string]reflect.Type, t reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if f.Anonymous && ft.Kind() == reflect.Struct {
				collectJSONFieldTypes(out, ft)
				continue
			}
			name = f.Name
		}
		if _, exists := out[name]; !exists {
			out[name] = f.Type
		}
	}
}
