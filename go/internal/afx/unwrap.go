package afx

import (
	"fmt"
	"reflect"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// Unwrap ports the _unwrap helper defined in src/cloudsecurity_af/app.py
// (the LENIENT variant).
//
// Python:
//
//	def _unwrap(result: object, name: str) -> object:
//	    if isinstance(result, dict):
//	        if "error" in result and isinstance(result["error"], dict):
//	            message = result["error"].get("message") or result["error"].get("detail") or str(result["error"])
//	            raise RuntimeError(f"{name} failed: {message}")
//	        if "output" in result:
//	            return result["output"]
//	        if "result" in result:
//	            return result["result"]
//	    return result
//
// Python parity: an "error" key whose value is NOT a dict falls straight
// through to the "output"/"result" probes — it is not an error.
//
// Python parity: the raised message is `message or detail or str(error_dict)`,
// using PYTHON truthiness — an empty string or a 0 for "message" falls through
// to "detail".
//
// NOTE: app.py's copy of _unwrap is dead code on the live path (app.py calls
// the orchestrator directly, never app.call), but it is ported for
// completeness and because it documents the lenient contract. The phases and
// the orchestrator use UnwrapStrict; use that one for any ported .call() site.
func Unwrap(raw any, name string) (any, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return raw, nil
	}
	if err := checkErrorDict(m, name); err != nil {
		return nil, err
	}
	if v, present := m["output"]; present {
		return v, nil
	}
	if v, present := m["result"]; present {
		return v, nil
	}
	return raw, nil
}

// UnwrapStrict ports the _unwrap helper that src/cloudsecurity_af/reasoners/
// phases.py and src/cloudsecurity_af/orchestrator.py each define (byte-identical
// copies of each other). It is the LENIENT variant plus two extra failure
// probes that run BEFORE the "output"/"result" unwrapping:
//
//	if "error_message" in result and result["error_message"]:
//	    raise RuntimeError(f"{name} failed: {result['error_message']}")
//	if result.get("status") in ("failed", "error"):
//	    raise RuntimeError(f"{name} failed: {result.get('error_message', 'Unknown error')}")
//
// This is the variant every ported app.Call() site in this repo must use — both
// DAG drivers (phases.py, orchestrator.py) use it, and it is what turns a
// control-plane execution envelope that reports a failed child into a Go error
// instead of silently validating an error envelope as a result model.
//
// Python parity: the status probe's fallback message is
// `result.get("error_message", "Unknown error")` — a PRESENT-but-None
// error_message renders as the string "None", not as "Unknown error", because
// dict.get only substitutes the default when the key is absent.
func UnwrapStrict(raw any, name string) (any, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return raw, nil
	}
	if err := checkErrorDict(m, name); err != nil {
		return nil, err
	}
	if v, present := m["error_message"]; present && truthy(v) {
		return nil, fmt.Errorf("%s failed: %s", name, pyfmt.Str(v))
	}
	if s, present := m["status"]; present {
		if sv, isStr := s.(string); isStr && (sv == "failed" || sv == "error") {
			message := "Unknown error"
			if em, hasKey := m["error_message"]; hasKey {
				message = pyfmt.Str(em)
			}
			return nil, fmt.Errorf("%s failed: %s", name, message)
		}
	}
	if v, present := m["output"]; present {
		return v, nil
	}
	if v, present := m["result"]; present {
		return v, nil
	}
	return raw, nil
}

// checkErrorDict is the shared first clause of both _unwrap variants.
func checkErrorDict(m map[string]any, name string) error {
	raw, present := m["error"]
	if !present {
		return nil
	}
	errMap, isMap := raw.(map[string]any)
	if !isMap {
		return nil
	}
	return fmt.Errorf("%s failed: %s", name, errorDictMessage(errMap))
}

// errorDictMessage ports
// `result["error"].get("message") or result["error"].get("detail") or str(result["error"])`.
//
// Python parity / DETERMINISM: the final fallback is Python's str(dict), which
// prints the dict in INSERTION order. A Go map has no order at all, so
// pyfmt.Repr sorts the keys — a deliberate determinism fix (the port contract
// forbids non-deterministic output) that only shows up on the
// no-message/no-detail path.
func errorDictMessage(errMap map[string]any) string {
	if v, present := errMap["message"]; present && truthy(v) {
		return pyfmt.Str(v)
	}
	if v, present := errMap["detail"]; present && truthy(v) {
		return pyfmt.Str(v)
	}
	return pyfmt.Repr(errMap)
}

// truthy reproduces Python's bool(v) for the JSON value kinds that reach it:
// None, False, 0, 0.0, "", [] and {} are falsy; everything else is truthy.
func truthy(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Bool:
		return rv.Bool()
	case reflect.String:
		return rv.Len() > 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() != 0
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() > 0
	case reflect.Pointer, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

// AsMap ports the _as_dict helper that app.py, reasoners/phases.py and
// orchestrator.py each define (all three copies are identical):
//
//	def _as_dict(payload: object, name: str) -> dict[str, Any]:
//	    if not isinstance(payload, dict):
//	        raise RuntimeError(f"{name} returned non-dict payload: {type(payload).__name__}")
//	    return payload
//
// The error string embeds the PYTHON type name of the payload, so PythonTypeName
// maps the Go kinds back onto their Python counterparts (nil -> NoneType,
// string -> str, float64 -> float, []any -> list, ...).
//
// PYTHON PARITY — A NIL MAP IS None, NOT AN EMPTY DICT. The Go SDK returns a
// NIL map[string]any with a NIL error when a succeeded execution's stored
// result is empty or the literal `null` (sdk/go/agent/agent.go
// awaitExecutionResult: `if len(statusResp.Result) > 0 && string(...) != "null"`).
// Boxed into `any` that is a NON-nil interface holding a nil map, so a plain
// type assertion succeeds and every key probe silently misses. Python cannot
// reach that state: the phase reply is None, `isinstance(None, dict)` is False
// and _as_dict raises — verified against the repo venv:
//
//	_as_dict(_unwrap(None, "hunt_phase"), "hunt_phase")
//	  -> RuntimeError: hunt_phase returned non-dict payload: NoneType
//
// Accepting it as `{}` instead lets the orchestrator bind an all-default
// HuntResult/ChainResult (neither declares a required field) and return a 200
// scan reporting total_raw_findings 0 and confirmed 0 — a clean-looking
// security scan — where Python aborts the run with a 500.
func AsMap(payload any, name string) (map[string]any, error) {
	m, ok := payload.(map[string]any)
	if !ok || m == nil {
		return nil, fmt.Errorf("%s returned non-dict payload: %s", name, PythonTypeName(payload))
	}
	return m, nil
}

// PythonTypeName renders type(v).__name__ for the value kinds that cross a
// reasoner boundary as JSON. Anything outside that set (a Go struct that never
// went through JSON) falls back to the Go type's own name, which is the closest
// honest analogue of a Python class name.
func PythonTypeName(v any) string {
	if v == nil {
		return "NoneType"
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Bool:
		// bool must precede the integer cases: Python's bool is a subclass of
		// int but type(True).__name__ is "bool".
		return "bool"
	case reflect.String:
		return "str"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.Map:
		// A nil map is how the Go SDK spells "the execution stored no result",
		// i.e. Python's None — see the parity note on AsMap.
		if rv.IsNil() {
			return "NoneType"
		}
		return "dict"
	case reflect.Slice:
		if rv.IsNil() {
			return "NoneType"
		}
		return "list"
	case reflect.Array:
		return "list"
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return "NoneType"
		}
		return PythonTypeName(rv.Elem().Interface())
	}
	if n := rv.Type().Name(); n != "" {
		return n
	}
	return rv.Type().String()
}
