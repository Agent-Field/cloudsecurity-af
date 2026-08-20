package afx

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// lax.go restores the OTHER half of `Model.model_validate(payload)` that a JSON
// round-trip gets wrong — the scalar rules.
//
// required.go covers the fields pydantic raises `missing` for. This file covers
// the two ways `encoding/json` and pydantic v2's LAX mode disagree about a
// value that IS present:
//
//  1. pydantic COERCES scalars encoding/json refuses. `"12"` is a valid int,
//     `"5.5"` a valid float, `1` / `"true"` a valid bool. Without this the Go
//     node rejected bodies the Python node proves, and — worse — rejected
//     harness output the Python node accepts, which costs a whole hunter's
//     findings (hunt_phase swallows a failed hunter into an empty batch).
//  2. pydantic REJECTS an explicit `null` for a field that is not `X | None`,
//     while encoding/json treats `null` as a no-op for a scalar/struct and as
//     "set to nil" for a slice/map — so the seeded pydantic default survived a
//     `null` the Python node answers 422 for, and a seeded `[]` was silently
//     wiped back to `null` in the re-dump.
//
// Both were measured against the repo venv (pydantic 2.13.4) rather than read
// off the docs; the ladders below cite the observed results.
//
// SCOPE. These rules apply to the ported PYDANTIC MODELS only — the types in
// internal/schemas that declare PydanticModel() — and to everything reachable
// from one. They must NOT apply to the reasoner INPUT structs
// (node.ScanInput, phases.ChainPhaseInput, …): those stand for a Python
// FUNCTION SIGNATURE, whose validation is `Agent._validate_handler_input` and
// is ported in handlerinput.go with its own, different ladder (an optional
// parameter is not coerced at all there, and `repo_url: null` becomes the
// string "None" rather than an error).

// PydanticModel marks a Go struct as a port of a pydantic BaseModel, i.e. a
// type whose Go-side bind stands in for a `Model.model_validate(...)` call.
// internal/schemas declares it once per model in model.go.
type PydanticModel interface{ PydanticModel() }

// NullableFielder is implemented by a PydanticModel that has a field which
// accepts `None` in Python but is NOT a Go pointer.
//
// Every `X | None` field in this port maps to a Go pointer EXCEPT
// CloudSecurityInput.include_paths (`list[str] | None` -> `[]string`, because
// Python's own code treats None and [] identically there). Declaring the
// exception is cheaper, and far more legible, than pointerizing the slice.
type NullableFielder interface{ NullableFields() []string }

// InvalidTypeError is the Go stand-in for the pydantic ValidationError raised
// when a value has the wrong TYPE — in this port, always an explicit null for a
// field that is not `X | None`.
//
// DIVERGENCE (message text only, same trade-off as MissingFieldError):
// pydantic renders "1 validation error for RawFinding\n  resources\n  Input
// should be a valid list [type=list_type, input_value=None, ...]". The Go text
// keeps the model, the field and the expectation, which is what the phases
// surface (prove_phase embeds it in the fallback finding's evidence string).
type InvalidTypeError struct {
	Model string
	Field string
	Want  string
}

func (e *InvalidTypeError) Error() string {
	return fmt.Sprintf("1 validation error for %s: %s: Input should be a valid %s",
		e.Model, e.Field, e.Want)
}

// coerceLax rewrites payload so that every value pydantic's lax mode would
// coerce is coerced before the decode sees it, and reports the nulls pydantic
// would reject. Values it has no rule for are returned untouched, so the decode
// stays the thing that rejects what pydantic also rejects (`iac_line: 12.5`,
// `title: 5`, `confidence: "HIGH"`).
func coerceLax(payload any, t reflect.Type) (any, error) {
	return laxWalk(payload, t, false)
}

// laxWalk is the recursive worker. `strict` reports whether this position is
// inside a PydanticModel tree; it turns on at the first model struct and stays
// on for everything below.
func laxWalk(payload any, t reflect.Type, strict bool) (any, error) {
	t = derefType(t)
	if t == nil || t.Kind() == reflect.Interface {
		// `Any` in Python: pydantic stores whatever it is handed.
		return payload, nil
	}

	switch value := payload.(type) {
	case map[string]any:
		if t.Kind() == reflect.Map {
			return laxMap(value, t, strict)
		}
		if t.Kind() != reflect.Struct {
			return payload, nil
		}
		return laxStruct(value, t, strict)
	case []any:
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return payload, nil
		}
		return laxSlice(value, t, strict)
	}

	if !strict {
		return payload, nil
	}
	return laxScalar(payload, t), nil
}

// laxMap walks a `dict[str, V]`: the KEYS are data, the values may be models.
func laxMap(value map[string]any, t reflect.Type, strict bool) (any, error) {
	out := make(map[string]any, len(value))
	for k, v := range value {
		nv, err := laxWalk(v, t.Elem(), strict)
		if err != nil {
			return nil, err
		}
		out[k] = nv
	}
	return out, nil
}

// laxSlice walks a `list[V]`.
func laxSlice(value []any, t reflect.Type, strict bool) (any, error) {
	elem := t.Elem()
	out := make([]any, len(value))
	for i, v := range value {
		if v == nil && strict && !acceptsNull(elem, false) {
			return nil, &InvalidTypeError{Model: modelName(elem), Field: strconv.Itoa(i), Want: pyTypeWord(elem)}
		}
		nv, err := laxWalk(v, elem, strict)
		if err != nil {
			return nil, err
		}
		out[i] = nv
	}
	return out, nil
}

// laxStruct walks one object against a Go struct. Undeclared keys are left
// alone — pydantic's default `extra="ignore"` drops them, and so does the
// decode.
func laxStruct(value map[string]any, t reflect.Type, strict bool) (any, error) {
	fieldStrict := strict || isPydanticModel(t)
	fields := jsonFieldTypes(t)
	nullable := nullableFields(t)

	out := make(map[string]any, len(value))
	for k, v := range value {
		out[k] = v
	}
	// Deterministic order so the reported field is stable run to run.
	keys := make([]string, 0, len(value))
	for k := range value {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		ft, declared := fields[k]
		if !declared {
			continue
		}
		if value[k] == nil {
			if fieldStrict && !acceptsNull(ft, nullable[k]) {
				return nil, &InvalidTypeError{Model: t.Name(), Field: k, Want: pyTypeWord(ft)}
			}
			continue
		}
		nv, err := laxWalk(value[k], ft, fieldStrict)
		if err != nil {
			return nil, err
		}
		out[k] = nv
	}
	return out, nil
}

// acceptsNull reports whether a JSON null is a valid value for a field of type
// ft. Every `X | None` field in the port is a Go pointer, `Any` is an
// interface, and the handful of declared exceptions come in via nullable.
func acceptsNull(ft reflect.Type, declaredNullable bool) bool {
	if declaredNullable {
		return true
	}
	switch ft.Kind() {
	case reflect.Pointer, reflect.Interface:
		return true
	}
	return false
}

// pyTypeWord is the noun pydantic uses in "Input should be a valid ...".
func pyTypeWord(ft reflect.Type) string {
	ft = derefType(ft)
	switch ft.Kind() {
	case reflect.Slice, reflect.Array:
		return "list"
	case reflect.Map:
		return "dictionary"
	case reflect.Bool:
		return "boolean"
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Struct:
		return "dictionary or instance of " + ft.Name()
	}
	return ft.Name()
}

// modelName is the type name to report for a bare element position.
func modelName(ft reflect.Type) string {
	ft = derefType(ft)
	if ft == nil || ft.Name() == "" {
		return "list item"
	}
	return ft.Name()
}

func derefType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func isPydanticModel(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	_, ok := reflect.New(t).Interface().(PydanticModel)
	return ok
}

func nullableFields(t reflect.Type) map[string]bool {
	nf, ok := reflect.New(t).Interface().(NullableFielder)
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for _, name := range nf.NullableFields() {
		out[name] = true
	}
	return out
}

// ---------------------------------------------------------------------------
// the scalar ladders
// ---------------------------------------------------------------------------

// laxScalar applies pydantic v2's LAX scalar coercion for the target kind.
//
// It only ever REWRITES a value the decode would refuse but pydantic accepts.
// Anything else is returned untouched so the decode reports it, which keeps the
// two implementations rejecting the same set (measured in the repo venv:
// `iac_line: 12.5` -> int_from_float and `title: 5` -> string_type are errors
// on BOTH sides, and pydantic does NOT coerce a number or a bool to a str).
func laxScalar(v any, t reflect.Type) any {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if n, ok := laxInt(v); ok {
			return n
		}
	case reflect.Float32, reflect.Float64:
		if f, ok := laxFloat(v); ok {
			return f
		}
	case reflect.Bool:
		if b, ok := laxBool(v); ok {
			return b
		}
	}
	return v
}

// laxInt is pydantic's lax `int` ladder, verified field by field against
// RawFinding.iac_line in the repo venv:
//
//	True/False -> 1/0        12.0 -> 12          12.5 -> int_from_float (ERR)
//	"12" -> 12               " 12 " -> 12        "+12"/"-12" -> 12/-12
//	"012" -> 12              "1_000" -> 1000     "12.0" -> 12
//	"12." / "12.5" / "2e2" / "0x10" / "abc" / "" -> int_parsing (ERR)
//	None -> int_type (ERR, handled one level up)
func laxInt(v any) (any, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case float64:
		if x == math.Trunc(x) && !math.IsInf(x, 0) && !math.IsNaN(x) {
			return x, true // already an integral JSON number; the decode takes it
		}
	case json.Number:
		if n, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return n, true
		}
		if f, err := x.Float64(); err == nil && f == math.Trunc(f) && !math.IsInf(f, 0) {
			return int64(f), true
		}
	case string:
		if n, ok := pydanticIntFromString(x); ok {
			return n, true
		}
	}
	return nil, false
}

// pydanticIntFromString implements pydantic-core's str -> int parser: ASCII
// whitespace is stripped, `_` may separate digits, an optional sign is allowed,
// and a fractional part is accepted ONLY when it is all zeros ("12.0" is 12,
// "12." and "12.5" are errors). Exponents and non-decimal bases are rejected.
func pydanticIntFromString(s string) (int64, bool) {
	text, ok := stripDigitSeparators(strings.TrimSpace(s))
	if !ok {
		return 0, false
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return n, true
	}
	mantissa, fraction, hasDot := strings.Cut(text, ".")
	if !hasDot || fraction == "" || strings.Trim(fraction, "0") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(mantissa, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// laxFloat is pydantic's lax `float` ladder, verified against
// VerifiedFinding.risk_score in the repo venv:
//
//	True/False -> 1.0/0.0    5 -> 5.0            "5" -> 5.0
//	"5.5" / " 5.5 " / "+5.5" / ".5" / "5." / "1e3" / "1_0.5" -> the number
//	"" / "abc" -> float_parsing (ERR)            None -> float_type (ERR)
//
// DIVERGENCE (bounded, and unrepresentable in JSON): pydantic also accepts
// "NaN", "inf", "Infinity" and the overflowing "1e999", yielding nan/±inf.
// encoding/json cannot marshal a non-finite float64 — RFC 8259 has no literal
// for one — so a non-finite result is declined here and the raw string reaches
// the decode, which rejects it with the ordinary
// "cannot unmarshal string into ... of type float64". Go therefore rejects four
// spellings Python accepts; see go/README.md's divergence list.
func laxFloat(v any) (any, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1.0, true
		}
		return 0.0, true
	case string:
		text, ok := stripDigitSeparators(strings.TrimSpace(x))
		if !ok {
			return nil, false
		}
		f, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, false
		}
		return f, true
	}
	return nil, false
}

// laxBool is pydantic's lax `bool` ladder, verified against
// DriftedResource.security_relevant in the repo venv:
//
//	1 / 1.0 -> True          0 / 0.0 -> False
//	2 / -1 -> bool_parsing (ERR)                 1.5 -> bool_type (ERR)
//	"true","True","TRUE","yes","on","1","t","y"  -> True  (case-insensitive)
//	"false","no","off","0","f","n"               -> False
//	"" / "abc" -> bool_parsing (ERR)             None -> bool_type (ERR)
func laxBool(v any) (any, bool) {
	switch x := v.(type) {
	case int:
		return laxBoolFromFloat(float64(x))
	case int64:
		return laxBoolFromFloat(float64(x))
	case float64:
		return laxBoolFromFloat(x)
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return laxBoolFromFloat(f)
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "t", "yes", "y", "on", "1":
			return true, true
		case "false", "f", "no", "n", "off", "0":
			return false, true
		}
	}
	return nil, false
}

// stripDigitSeparators removes the `_` separators pydantic allows inside a
// numeric string ("1_000" is 1000, "1_0.5" is 10.5). A `_` that is not between
// two digits is a parse error, which is reported by returning false.
func stripDigitSeparators(s string) (string, bool) {
	if !strings.Contains(s, "_") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '_' {
			b.WriteByte(s[i])
			continue
		}
		if i == 0 || i == len(s)-1 || !isASCIIDigit(s[i-1]) || !isASCIIDigit(s[i+1]) {
			return "", false
		}
	}
	return b.String(), true
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// laxBoolFromFloat is the numeric half of the bool ladder: pydantic accepts
// only 0 and 1 (int or float); 2, -1 and 1.5 are all errors.
func laxBoolFromFloat(f float64) (any, bool) {
	switch f {
	case 0:
		return false, true
	case 1:
		return true, true
	}
	return nil, false
}
