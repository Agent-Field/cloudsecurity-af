package afx

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/agent"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// handlerinput.go ports the Python SDK's request-body validation, which the Go
// SDK has no counterpart for.
//
// Every Python reasoner endpoint runs its body through
// `Agent._validate_handler_input(body, handler_input_fields)`
// (sdk/python/agentfield/agent.py:1146-1245, called at agent.py:2117 and
// agent.py:3122) BEFORE the coroutine is entered, and renders an
// `_HandlerInputError` as `JSONResponse(status_code=422, {"detail": msg})`.
// That function is the whole contract:
//
//	for each DECLARED parameter (name, annotation, default):
//	    absent  + no default          -> 422 "Missing required field: {name}"
//	    absent  + default             -> the default
//	    None    + Optional annotation -> None
//	    None    + default             -> the default
//	    None    + neither             -> 422 "Field '{name}' cannot be None"
//	    present -> int(v) / float(v) / str(v) / the bool whitelist /
//	               an isinstance check for dict and list
//	               -> 422 "Invalid value for field '{name}'"
//	                  / "Field '{name}' must be a dict" / "... must be a list"
//	UNDECLARED keys are dropped: the handler is called with `result`, not `body`.
//
// The Go SDK reads a reasoner's InputSchema only to build the registration and
// discovery payloads (agent/agent_lifecycle.go, agent/agent.go) and never
// validates against it, so without this layer the port both ACCEPTED bodies
// Python rejects — `cloudsecurity.scan {}` bound repo_url to "" and scanned the
// node's own working directory, returning 200, where Python 422s and runs
// nothing — and REJECTED bodies Python accepts, because plain encoding/json
// refuses `tier: "2"` or `max_concurrent_hunters: "4"` that Python coerces.

// FieldType is the coercion class of a declared reasoner parameter — the
// `actual_type` branch _validate_handler_input takes after unwrapping Optional.
type FieldType int

// The coercion classes, in the order agent.py:1204-1236 tests them.
const (
	// TypeInt is `int`: `int(value)`.
	TypeInt FieldType = iota
	// TypeFloat is `float`: `float(value)`.
	TypeFloat
	// TypeStr is `str`: `str(value)`, which accepts ANY value.
	TypeStr
	// TypeBool is `bool`: a bool passes through, a str is tested against the
	// ("true", "1", "yes") whitelist, anything else goes through bool().
	TypeBool
	// TypeDict is `dict[...]`: an isinstance check, never a conversion.
	TypeDict
	// TypeList is `list[...]`: an isinstance check, never a conversion.
	TypeList
	// TypeAny is every annotation the coercion ladder falls through — the
	// value is passed to the handler untouched.
	TypeAny
)

// Field transcribes one parameter of a Python reasoner signature.
//
// Required and Optional are independent and both come from the SOURCE, not from
// the Go type: Required is `param.default is inspect.Parameter.empty`, Optional
// is "the annotation admits None" (`X | None`). `drift_report: dict | None =
// None` is Optional and not Required; `finding: dict[str, Any]` is Required and
// not Optional.
type Field struct {
	Name     string
	Type     FieldType
	Optional bool
	Required bool
}

// HandlerInput is implemented by every reasoner input struct in this port. The
// struct is the transcription of the Python signature, so the field list lives
// next to it rather than in a registry that could drift from it.
type HandlerInput interface {
	HandlerInputFields() []Field
}

// InputError is `_HandlerInputError`. It carries the exact Python message and
// the 422 the Python endpoint answers with.
//
// DIVERGENCE (unavoidable, SDK-level): Python's body is `{"detail": msg}` and
// the Go SDK renders a handler ExecuteError as `{"error": msg}`. The status
// code and the message text match.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }

// ExecuteError renders the error the way the Python endpoint does.
func (e *InputError) ExecuteError() *agent.ExecuteError {
	return &agent.ExecuteError{StatusCode: http.StatusUnprocessableEntity, Message: e.Message}
}

// ValidateHandlerInput ports _validate_handler_input. The returned map contains
// ONLY declared parameters, coerced; a parameter that is absent (or that
// Python would replace with its default) is omitted, so the input struct's own
// default seeding supplies the same value the Python default would.
func ValidateHandlerInput(data map[string]any, fields []Field) (map[string]any, error) {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		value, present := data[f.Name]
		if !present {
			if f.Required {
				return nil, &InputError{Message: "Missing required field: " + f.Name}
			}
			// Python writes the signature default into result; omitting the
			// key lets the input struct seed the identical value.
			continue
		}

		if value == nil {
			if f.Optional {
				out[f.Name] = nil
				continue
			}
			if !f.Required {
				continue // Python: `result[name] = default`.
			}
			return nil, &InputError{Message: fmt.Sprintf("Field '%s' cannot be None", f.Name)}
		}

		coerced, err := coerceField(f, value)
		if err != nil {
			return nil, err
		}
		out[f.Name] = coerced
	}
	return out, nil
}

// BindHandlerInput is ValidateHandlerInput followed by Bind — the whole Python
// request path for a reasoner: validate the body against the signature, then
// materialise the parameters. A T that does not implement HandlerInput binds
// unvalidated, which is the pre-existing behaviour for any input struct that
// has not been transcribed yet.
func BindHandlerInput[T any](input map[string]any) (T, error) {
	var out T
	if hi, ok := any(out).(HandlerInput); ok {
		validated, err := ValidateHandlerInput(input, hi.HandlerInputFields())
		if err != nil {
			return out, err
		}
		input = validated
	}
	return Bind[T](input)
}

// coerceField applies `_validate_handler_input`'s coercion ladder.
//
// PYTHON SDK QUIRK, verified by running the real
// `Agent._validate_handler_input` on cloudsecurity's own `scan` signature: an
// OPTIONAL parameter is NOT coerced. The unwrap is
//
//	origin = getattr(expected_type, "__origin__", None)
//	if origin is Union: ...
//
// and a PEP 604 annotation (`int | None`, which is what every nullable
// parameter in this node uses) is a types.UnionType with no __origin__, so the
// unwrap never fires and the value falls through the ladder to
// "Pass through for complex/unknown types". Observed: with repo_url set,
// `max_concurrent_hunters: "4"`, `max_cost_usd: "2.5"`, `output_formats:
// "json"` and `max_duration_seconds: "abc"` all leave the validator UNCHANGED.
//
// The rejection happens one layer later, in pydantic's lax validation of the
// model the handler builds — where "4" -> 4 and "2.5" -> 2.5 are accepted while
// `commit_sha: 123`, `output_formats: "json"` and `max_duration_seconds: "abc"`
// raise (all four verified against CloudSecurityInput in the repo venv). So the
// port coerces an optional int/float — that is the only case where pydantic
// ACCEPTS a value encoding/json would refuse — and otherwise passes the value
// through untouched, letting the Bind decode reject exactly what pydantic
// rejects.
func coerceField(f Field, value any) (any, error) {
	if f.Optional {
		switch f.Type {
		case TypeInt:
			if n, ok := pyInt(value); ok {
				return n, nil
			}
		case TypeFloat:
			if x, ok := pyFloat(value); ok {
				return x, nil
			}
		}
		return value, nil
	}

	switch f.Type {
	case TypeInt:
		n, ok := pyInt(value)
		if !ok {
			return nil, invalidValue(f.Name)
		}
		return n, nil
	case TypeFloat:
		x, ok := pyFloat(value)
		if !ok {
			return nil, invalidValue(f.Name)
		}
		return x, nil
	case TypeStr:
		// Python str(value) never fails.
		return pyStr(value), nil
	case TypeBool:
		return pyBool(value), nil
	case TypeDict:
		if _, ok := value.(map[string]any); !ok {
			return nil, &InputError{Message: fmt.Sprintf("Field '%s' must be a dict", f.Name)}
		}
		return value, nil
	case TypeList:
		if _, ok := value.([]any); !ok {
			return nil, &InputError{Message: fmt.Sprintf("Field '%s' must be a list", f.Name)}
		}
		return value, nil
	}
	return value, nil
}

// pyStr is `str(value)` for a value that came out of `json.loads` — the
// coercion agent.py's str branch (`result[name] = str(value)`) applies to every
// non-Optional `str` parameter (scan/prove's repo_url, depth, branch,
// severity_threshold, cloud_provider, and every router reasoner's path params).
//
// PYTHON PARITY — INTEGER LITERALS. CPython's json.loads makes an `int` out of
// a literal with no "." and no exponent, so `{"depth": 4}` reaches the
// validator as int 4 and `str(4)` is "4". The Go SDK decodes the request body
// with a plain encoding/json decoder and no UseNumber
// (sdk/go/agent/agent.go handleReasoner), which collapses EVERY JSON number to
// float64 before the handler sees it — and pyfmt.Str(float64(4)) is Python's
// str(4.0), i.e. "4.0". Rendering an integral float64 with the integer spelling
// restores the int the literal actually carried. Verified against the repo
// venv's installed validator: `Agent._validate_handler_input` on
// json.loads('{"repo_url":123,"depth":4,"branch":7.0}') with those three
// declared `str` returns {'repo_url': '123', 'depth': '4', 'branch': '7.0'}.
//
// DIVERGENCE (unavoidable here, and it is the RARER half): a literal written
// with an explicit fraction — `{"depth": 4.0}` — is a Python float and
// str()s to "4.0", but by the time this code runs it is indistinguishable from
// the integer literal `4`. The int spelling is chosen because JSON encoders
// emit `4`, not `4.0`, for an integer. Above 2^53 the two spellings stop
// round-tripping through float64 at all, so those keep the float rendering
// (Python str(1e30) == "1e+30", which pyfmt.Repr already produces).
func pyStr(value any) string {
	return pyfmt.Str(jsonIntegers(value))
}

// jsonIntegers undoes the SDK decoder's collapse of every JSON number onto
// float64, restoring the `int` CPython's json.loads would have produced, so
// pyfmt.Str/Repr spell it the way Python's str() does. It walks containers
// because str() of a list or dict is a repr that recurses (verified:
// str(json.loads('[1, "x"]')) == "[1, 'x']", not "[1.0, 'x']").
//
// Only float64 is rewritten; strings, bools and nil are Python's own kinds
// already. See pyStr for the one literal this cannot recover (`4.0`).
func jsonIntegers(value any) any {
	switch x := value.(type) {
	case float64:
		if x == math.Trunc(x) && !math.IsInf(x, 0) && math.Abs(x) < 1<<53 {
			return int(x)
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = jsonIntegers(x[i])
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = jsonIntegers(v)
		}
		return out
	}
	return value
}

// invalidValue is the message agent.py:1244 raises for a failed int()/float().
// Python deliberately drops the inner exception's text.
func invalidValue(name string) error {
	return &InputError{Message: fmt.Sprintf("Invalid value for field '%s'", name)}
}

// pyInt is `int(value)` for the value kinds a JSON body can produce.
//
//	bool          -> 1 / 0
//	int / float   -> truncated TOWARD ZERO (int(5.9) == 5, int(-5.9) == -5)
//	str           -> base-10 parse of the stripped text; int("4.0") is a
//	                 ValueError in Python and is rejected here too
//	anything else -> TypeError
func pyInt(v any) (int, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false
		}
		return int(math.Trunc(x)), true
	case json.Number:
		if n, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			return int(n), true
		}
		if fl, err := x.Float64(); err == nil {
			return int(math.Trunc(fl)), true
		}
		return 0, false
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// pyFloat is `float(value)`.
//
// NON-FINITE RESULTS ARE DECLINED, and that is deliberate. Python's float()
// accepts "NaN", "nan", "Infinity", "inf" and the overflowing "1e999", and
// pydantic's lax mode accepts them too — verified in the repo venv:
// `CloudSecurityInput(repo_url="/tmp", max_cost_usd="NaN")` yields nan, and the
// scan then RUNS, because every budget comparison against nan/inf is False.
// Go cannot carry that value: `Bind` round-trips the validated map through
// encoding/json, which refuses to marshal a non-finite float64 (RFC 8259 has no
// literal for one), so coercing "NaN" here turned a scan into a 400 whose body
// was the Go-internals string "afx.Bind: marshal input: json: unsupported
// value: NaN". Declining instead leaves the raw string in place, so the request
// fails the way every other uncoercible optional parameter does. The residual
// divergence — Python runs the scan, Go rejects the body — is recorded in
// go/README.md's divergence list; it is not fixable without a JSON encoding for
// nan/inf on both sides.
//
// pyInt has the same guard (`math.IsNaN(x) || math.IsInf(x, 0)`), for the same
// reason.
func pyFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, finite(x)
	case json.Number:
		f, err := x.Float64()
		return f, err == nil && finite(f)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil && finite(f)
	}
	return 0, false
}

// finite reports whether f survives a JSON round trip.
func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// pyBool is agent.py:1211-1216: a bool passes through, a str is matched against
// the ("true", "1", "yes") whitelist (case-insensitively), and everything else
// goes through Python's bool() truthiness.
func pyBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		switch strings.ToLower(x) {
		case "true", "1", "yes":
			return true
		}
		return false
	}
	return truthy(v)
}
