package harnessx

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
)

// diagnosticsOut is where Extract writes the diagnostic blocks that Python
// prints with print(..., flush=True) — i.e. stdout. It is a variable only so
// tests can capture the bytes; production code must never reassign it.
var diagnosticsOut io.Writer = os.Stdout

// Run ports `await app.harness(prompt=..., schema=Model, cwd=..., project_dir=...)`.
//
// It resolves the committed pydantic schema for T (see SchemaFor), hands the
// SDK a fresh *T destination, and returns that destination together with the
// raw harness Result.
//
// ERROR CONTRACT: the returned error is non-nil ONLY for a transport-level
// failure of app.Harness itself — the Go analogue of the Python SDK's
// .harness() raising. Everything the harness reports IN-BAND (is_error, an
// unparsable payload) is left on the Result for Extract to classify, exactly as
// in Python where `result = await app.harness(...)` succeeds and
// `extract_harness_result(result, ...)` is what raises.
//
// Most callers want RunExtract, which is the pair Python always uses together.
func Run[T any](ctx context.Context, app appx.Harnesser, prompt string, opts harness.Options) (*T, *harness.Result, error) {
	schema := SchemaFor[T]()

	var dest T
	res, err := app.Harness(ctx, prompt, schema, &dest, opts)
	if err != nil {
		return nil, res, err
	}
	return &dest, res, nil
}

// Extract ports extract_harness_result in src/cloudsecurity_af/agents/_utils.py.
//
// Python:
//
//	is_error = bool(getattr(result, "is_error", False))
//	if is_error:
//	    print(f"[{agent_name}] HARNESS ERROR: {error_message}\n"
//	          f"  turns={num_turns}, duration_ms={duration_ms}\n"
//	          f"  result_text={str(result_text)[:500] if result_text else None}", flush=True)
//	    raise RuntimeError(f"{agent_name} harness error: {error_message}")
//	parsed = getattr(result, "parsed", None)
//	if isinstance(parsed, schema):
//	    return parsed
//	debug_message = (f"[{agent_name}] harness result type={type(result).__name__}, "
//	                 f"is_error={getattr(result,'is_error','?')}, "
//	                 f"parsed type={type(getattr(result,'parsed',None)).__name__}")
//	if isinstance(parsed, dict):
//	    try: return schema.model_validate(parsed)
//	    except Exception: print(debug_message, flush=True); raise
//	print(debug_message, flush=True)
//	raise TypeError(f"{agent_name} did not return a valid {schema.__name__}")
//
// dest is the destination Run handed to the SDK. The Go SDK sets Result.Parsed
// to that very pointer on success (harness/runner.go: `Parsed: dest`), so a
// non-nil Parsed is the Go equivalent of Python's `isinstance(parsed, schema)`.
// The `isinstance(parsed, dict)` branch has no Go counterpart: the SDK never
// leaves a raw map in Parsed, it decodes straight into dest.
//
// Python parity: `error_message` is Optional[str] in the Python SDK, so an
// unset one renders as the literal "None" in both the printed block and the
// raised message. The Go field is a plain string, so "" is mapped back to
// "None" to keep the strings identical.
//
// Python parity: result_text is truncated to 500 CHARACTERS (Python slices code
// points, not bytes) and a falsy result text prints as "None".
//
// DIVERGENCE (documented): the debug line's `type(result).__name__` is
// "HarnessResult" in Python and "Result" in Go (the SDK's own type name), and
// `type(parsed).__name__` is the Go type name rather than the pydantic class
// name — except for nil, which prints "NoneType" as Python does. These are
// human-facing stdout diagnostics only; every machine-readable string (the two
// error messages) is byte-identical.
func Extract[T any](res *harness.Result, dest *T, agentName string) (T, error) {
	var zero T

	if res == nil {
		// Python: getattr(None, "is_error", False) is False and
		// getattr(None, "parsed", None) is None -> the TypeError branch.
		printDebugLine(agentName, "NoneType", "?", "NoneType")
		return zero, fmt.Errorf("%s did not return a valid %s", agentName, TypeName[T]())
	}

	if res.IsError {
		message := res.ErrorMessage
		if message == "" {
			message = "None"
		}
		resultText := "None"
		if res.Result != "" {
			resultText = runeSlice(res.Result, 500)
		}
		_, _ = fmt.Fprintf(diagnosticsOut,
			"[%s] HARNESS ERROR: %s\n  turns=%d, duration_ms=%d\n  result_text=%s\n",
			agentName, message, res.NumTurns, res.DurationMS, resultText)
		return zero, fmt.Errorf("%s harness error: %s", agentName, message)
	}

	if res.Parsed != nil && dest != nil {
		return *dest, nil
	}

	printDebugLine(agentName, "Result", boolStr(res.IsError), goTypeName(res.Parsed))
	return zero, fmt.Errorf("%s did not return a valid %s", agentName, TypeName[T]())
}

// RunExtract is Run followed by Extract — the pair every agent file in
// src/cloudsecurity_af/agents/** uses:
//
//	result = await app.harness(prompt=..., schema=Model, cwd=...)
//	return extract_harness_result(result, Model, "iac_reader")
//
// A transport error from Run is returned unchanged (Python would propagate the
// SDK's own exception); everything else goes through Extract's classification.
func RunExtract[T any](ctx context.Context, app appx.Harnesser, prompt string, opts harness.Options, agentName string) (T, error) {
	dest, res, err := Run[T](ctx, app, prompt, opts)
	if err != nil {
		var zero T
		return zero, err
	}
	return Extract[T](res, dest, agentName)
}

// printDebugLine emits the Python debug_message, terminated the way print() is.
func printDebugLine(agentName, resultType, isError, parsedType string) {
	_, _ = fmt.Fprintf(diagnosticsOut, "[%s] harness result type=%s, is_error=%s, parsed type=%s\n",
		agentName, resultType, isError, parsedType)
}

// boolStr renders a Go bool the way Python's f-string renders one.
func boolStr(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// goTypeName is the Go stand-in for type(x).__name__, with Python's "NoneType"
// for nil.
func goTypeName(v any) string {
	if v == nil {
		return "NoneType"
	}
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n := t.Name(); n != "" {
		return n
	}
	return t.String()
}

// TypeName returns T's bare Go name, which the port contract keeps equal to the
// pydantic class name — i.e. Python's schema.__name__ in the TypeError message.
//
// It is the same identifier SchemaFor/fixtureName key the committed pydantic
// fixture on, so it is exported: internal/aix names the destination type in
// every one of its error messages and must not answer that question with a
// second, independently-drifting implementation.
func TypeName[T any]() string {
	t := reflect.TypeOf((*T)(nil)).Elem()
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n := t.Name(); n != "" {
		return n
	}
	return t.String()
}

// runeSlice reproduces Python's s[:n], which counts code points, not bytes.
func runeSlice(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
