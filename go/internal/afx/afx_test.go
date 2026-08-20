package afx

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// The expectations in this file were captured by running the EXACT Python
// helper bodies from src/cloudsecurity_af/app.py, reasoners/phases.py and
// orchestrator.py under this repo's interpreter
// (~/.agentfield/packages/cloudsecurity-af/venv/bin/python, CPython 3.11.12).
// The captured transcript is reproduced above each table.

// ---------------------------------------------------------------------------
// Bind / ToMap
// ---------------------------------------------------------------------------

type bindTarget struct {
	Name    string   `json:"name"`
	Depth   string   `json:"depth"`
	Paths   []string `json:"paths"`
	Count   int      `json:"count"`
	Ratio   float64  `json:"ratio"`
	Skipped bool     `json:"skipped"`
}

// UnmarshalJSON seeds the pydantic defaults the way the ported schema structs
// do, so Bind's default-seeding contract is exercised.
func (b *bindTarget) UnmarshalJSON(data []byte) error {
	type alias bindTarget
	seeded := alias{Depth: "standard", Paths: []string{"tests/"}, Count: 4}
	if err := json.Unmarshal(data, &seeded); err != nil {
		return err
	}
	*b = bindTarget(seeded)
	return nil
}

func TestBind_DecodesByJSONTagAndSeedsDefaults(t *testing.T) {
	got, err := Bind[bindTarget](map[string]any{"name": "x", "ratio": 0.5})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	want := bindTarget{Name: "x", Depth: "standard", Paths: []string{"tests/"}, Count: 4, Ratio: 0.5}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Bind = %+v, want %+v", got, want)
	}
}

// Python parity: Model(**{}) seeds every default, so Bind(nil) must too.
func TestBind_NilInputSeedsDefaults(t *testing.T) {
	got, err := Bind[bindTarget](nil)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Depth != "standard" || got.Count != 4 {
		t.Fatalf("Bind(nil) = %+v, want the pydantic defaults", got)
	}
}

// Numbers cross the reasoner boundary as float64; Bind must land them in the
// typed field without precision gymnastics.
func TestBind_Float64InputIntoIntField(t *testing.T) {
	got, err := Bind[bindTarget](map[string]any{"count": float64(9)})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Count != 9 {
		t.Fatalf("Count = %d, want 9", got.Count)
	}
}

func TestBind_ReportsUnmarshalError(t *testing.T) {
	if _, err := Bind[bindTarget](map[string]any{"count": "not-a-number"}); err == nil {
		t.Fatal("expected an error for a type-mismatched key")
	}
}

type nestedValue struct{ N int }

func (n nestedValue) MarshalJSON() ([]byte, error) { return []byte(`"custom"`), nil }

type toMapOuter struct {
	Embedded
	Name   string      `json:"name"`
	Nested nestedValue `json:"nested"`
	Hidden string      `json:"-"`
	unexp  string      //nolint:unused // exercises the unexported-field skip
}

type Embedded struct {
	Tier int `json:"tier"`
}

func TestToMap_KeysAreJSONTagsAndValuesStayTyped(t *testing.T) {
	got, err := ToMap(toMapOuter{Embedded: Embedded{Tier: 2}, Name: "n", Nested: nestedValue{N: 1}, Hidden: "h"})
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ToMap keys = %v, want exactly name/nested/tier", got)
	}
	if got["name"] != "n" {
		t.Fatalf("name = %v", got["name"])
	}
	if got["tier"] != 2 {
		t.Fatalf("tier = %v (anonymous embedding must flatten)", got["tier"])
	}
	if _, ok := got["nested"].(nestedValue); !ok {
		t.Fatalf("nested = %T, want the value to stay typed so its MarshalJSON still runs", got["nested"])
	}
	if _, ok := got["Hidden"]; ok {
		t.Fatal(`json:"-" field leaked into the map`)
	}
}

func TestToMap_RejectsNonStructs(t *testing.T) {
	if _, err := ToMap(map[string]any{}); err == nil {
		t.Fatal("expected an error for a non-struct")
	}
	var p *toMapOuter
	if _, err := ToMap(p); err == nil {
		t.Fatal("expected an error for a nil pointer")
	}
}

func TestToMap_DereferencesPointers(t *testing.T) {
	got, err := ToMap(&toMapOuter{Name: "n"})
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	if got["name"] != "n" {
		t.Fatalf("name = %v", got["name"])
	}
}

// ---------------------------------------------------------------------------
// Unwrap (app.py, lenient) / UnwrapStrict (phases.py + orchestrator.py)
// ---------------------------------------------------------------------------
//
// Python transcript (the two helper bodies run verbatim):
//
//	lenient {'error': {'message': 'boom'}}                       -> RuntimeError: run_iac_reader failed: boom
//	lenient {'error': {'detail': 'detailed'}}                    -> RuntimeError: run_iac_reader failed: detailed
//	lenient {'error': {'message': '', 'detail': 'fallback'}}     -> RuntimeError: run_iac_reader failed: fallback
//	lenient {'error': {'code': 7}}                               -> RuntimeError: run_iac_reader failed: {'code': 7}
//	lenient {'error': {}}                                        -> RuntimeError: run_iac_reader failed: {}
//	lenient {'error': 'not a dict', 'output': {'a': 1}}          -> OK {'a': 1}
//	lenient {'error_message': 'bad things', 'status': 'ok'}      -> OK  (unchanged)
//	lenient {'status': 'failed'}                                 -> OK  (unchanged)
//	lenient {'status': 'completed', 'output': {'x': 1}}          -> OK {'x': 1}
//	lenient {'result': {'y': 2}}                                 -> OK {'y': 2}
//	lenient {'plain': 1}                                         -> OK  (unchanged)
//	lenient ['a']                                                -> OK  (unchanged)
//
//	strict  {'error_message': 'bad things', 'status': 'ok'}      -> RuntimeError: hunt_phase failed: bad things
//	strict  {'status': 'failed'}                                 -> RuntimeError: hunt_phase failed: Unknown error
//	strict  {'status': 'error', 'error_message': None}           -> RuntimeError: hunt_phase failed: None
//	strict  {'status': 'error', 'error_message': ''}             -> RuntimeError: hunt_phase failed:
//	strict  everything else                                       == lenient

func TestUnwrap_Lenient_PythonGroundTruth(t *testing.T) {
	cases := []struct {
		name    string
		raw     any
		wantVal any
		wantErr string
	}{
		{"error dict with message", map[string]any{"error": map[string]any{"message": "boom"}}, nil, "run_iac_reader failed: boom"},
		{"error dict falls back to detail", map[string]any{"error": map[string]any{"detail": "detailed"}}, nil, "run_iac_reader failed: detailed"},
		{"empty message is falsy, detail wins", map[string]any{"error": map[string]any{"message": "", "detail": "fallback"}}, nil, "run_iac_reader failed: fallback"},
		// str(dict) fallback. The int stays an int here; a value that really
		// crossed the JSON boundary would be a float64 and repr as 7.0.
		{"no message or detail falls back to str(dict)", map[string]any{"error": map[string]any{"code": 7}}, nil, "run_iac_reader failed: {'code': 7}"},
		{"empty error dict", map[string]any{"error": map[string]any{}}, nil, "run_iac_reader failed: {}"},
		{"non-dict error falls through", map[string]any{"error": "not a dict", "output": map[string]any{"a": 1}}, map[string]any{"a": 1}, ""},
		{"output wins over result", map[string]any{"output": 1, "result": 2}, 1, ""},
		{"result when there is no output", map[string]any{"result": map[string]any{"y": 2}}, map[string]any{"y": 2}, ""},
		{"plain payload is returned as-is", map[string]any{"plain": 1}, map[string]any{"plain": 1}, ""},
		{"non-dict payload is returned as-is", []any{"a"}, []any{"a"}, ""},
		// The two probes that the STRICT variant adds are inert here.
		{"error_message is ignored by the lenient variant", map[string]any{"error_message": "bad things", "status": "ok"}, map[string]any{"error_message": "bad things", "status": "ok"}, ""},
		{"status is ignored by the lenient variant", map[string]any{"status": "failed"}, map[string]any{"status": "failed"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Unwrap(tc.raw, "run_iac_reader")
			checkUnwrap(t, got, err, tc.wantVal, tc.wantErr)
		})
	}
}

func TestUnwrapStrict_PythonGroundTruth(t *testing.T) {
	cases := []struct {
		name    string
		raw     any
		wantVal any
		wantErr string
	}{
		{"truthy error_message fails", map[string]any{"error_message": "bad things", "status": "ok"}, nil, "hunt_phase failed: bad things"},
		{"status failed with no error_message key", map[string]any{"status": "failed"}, nil, "hunt_phase failed: Unknown error"},
		// dict.get only substitutes the default when the KEY IS ABSENT, so a
		// present-but-None error_message renders as "None".
		{"status error with null error_message", map[string]any{"status": "error", "error_message": nil}, nil, "hunt_phase failed: None"},
		{"status error with empty error_message", map[string]any{"status": "error", "error_message": ""}, nil, "hunt_phase failed: "},
		{"falsy error_message does not trip the second probe", map[string]any{"error_message": "", "output": 5}, 5, ""},
		{"a non-failure status unwraps normally", map[string]any{"status": "completed", "output": map[string]any{"x": 1}}, map[string]any{"x": 1}, ""},
		{"error dict is still checked first", map[string]any{"error": map[string]any{"message": "boom"}, "status": "failed"}, nil, "hunt_phase failed: boom"},
		{"result key", map[string]any{"result": map[string]any{"y": 2}}, map[string]any{"y": 2}, ""},
		{"plain payload", map[string]any{"plain": 1}, map[string]any{"plain": 1}, ""},
		{"non-dict payload", []any{"a"}, []any{"a"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnwrapStrict(tc.raw, "hunt_phase")
			checkUnwrap(t, got, err, tc.wantVal, tc.wantErr)
		})
	}
}

func checkUnwrap(t *testing.T, got any, err error, wantVal any, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil {
			t.Fatalf("got (%v, nil), want error %q", got, wantErr)
		}
		if err.Error() != wantErr {
			t.Fatalf("error = %q, want %q", err.Error(), wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, wantVal) {
		t.Fatalf("value = %#v, want %#v", got, wantVal)
	}
}

// The error-dict str() fallback must be stable across runs even though Go map
// iteration is randomized (the port contract forbids non-deterministic output).
func TestUnwrap_ErrorDictFallbackIsDeterministic(t *testing.T) {
	raw := map[string]any{"error": map[string]any{"z": 1, "a": 2, "m": 3}}
	want := "n failed: {'a': 2, 'm': 3, 'z': 1}"
	for i := 0; i < 20; i++ {
		_, err := Unwrap(raw, "n")
		if err == nil || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
	}
}

// ---------------------------------------------------------------------------
// AsMap
// ---------------------------------------------------------------------------
//
// Python transcript (_as_dict run verbatim, name="run_x"):
//
//	's'      -> run_x returned non-dict payload: str
//	1        -> run_x returned non-dict payload: int
//	1.5      -> run_x returned non-dict payload: float
//	True     -> run_x returned non-dict payload: bool
//	None     -> run_x returned non-dict payload: NoneType
//	['a']    -> run_x returned non-dict payload: list
//	{'k': 1} -> OK
func TestAsMap_PythonTypeNamesInTheErrorString(t *testing.T) {
	cases := []struct {
		payload any
		want    string
	}{
		{"s", "run_x returned non-dict payload: str"},
		{1, "run_x returned non-dict payload: int"},
		{1.5, "run_x returned non-dict payload: float"},
		{float32(1.5), "run_x returned non-dict payload: float"},
		{true, "run_x returned non-dict payload: bool"},
		{nil, "run_x returned non-dict payload: NoneType"},
		{[]any{"a"}, "run_x returned non-dict payload: list"},
		{[]string{"a"}, "run_x returned non-dict payload: list"},
	}
	for _, tc := range cases {
		_, err := AsMap(tc.payload, "run_x")
		if err == nil {
			t.Fatalf("AsMap(%#v) returned no error", tc.payload)
		}
		if err.Error() != tc.want {
			t.Errorf("AsMap(%#v) error = %q, want %q", tc.payload, err.Error(), tc.want)
		}
	}
}

func TestAsMap_PassesDictsThrough(t *testing.T) {
	in := map[string]any{"k": 1}
	got, err := AsMap(in, "run_x")
	if err != nil {
		t.Fatalf("AsMap: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("AsMap = %#v", got)
	}
}

// A nil pointer inside an interface is Python's None, not a dict.
func TestAsMap_NilPointerIsNoneType(t *testing.T) {
	var p *toMapOuter
	_, err := AsMap(p, "run_x")
	if err == nil || err.Error() != "run_x returned non-dict payload: NoneType" {
		t.Fatalf("error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// DropNulls / DumpExcludeNone
// ---------------------------------------------------------------------------

func TestDropNulls_RemovesNullObjectEntriesRecursively(t *testing.T) {
	in := map[string]any{
		"keep":  1,
		"drop":  nil,
		"inner": map[string]any{"a": nil, "b": "x"},
		"list": []any{
			map[string]any{"c": nil, "d": 2},
			// Python parity: a None ELEMENT of a list survives exclude_none.
			nil,
		},
	}
	want := map[string]any{
		"keep":  1,
		"inner": map[string]any{"b": "x"},
		"list": []any{
			map[string]any{"d": 2},
			nil,
		},
	}
	got := DropNulls(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DropNulls = %#v, want %#v", got, want)
	}
	// The input must not be mutated.
	if _, ok := in["drop"]; !ok {
		t.Fatal("DropNulls mutated its argument")
	}
}

func TestDropNulls_LeavesEmptyContainersAlone(t *testing.T) {
	var nilSlice []string
	var nilMap map[string]any
	in := map[string]any{"s": nilSlice, "m": nilMap, "e": []any{}}
	got, ok := DropNulls(in).(map[string]any)
	if !ok {
		t.Fatal("not a map")
	}
	if len(got) != 3 {
		t.Fatalf("DropNulls = %#v, want all three empty containers kept", got)
	}
}

func TestDropNulls_DropsTypedNilPointers(t *testing.T) {
	var p *toMapOuter
	got, _ := DropNulls(map[string]any{"p": p, "k": 1}).(map[string]any)
	if _, ok := got["p"]; ok {
		t.Fatalf("nil pointer survived: %#v", got)
	}
}

type dumpModel struct {
	Name       string   `json:"name"`
	Suggestion *string  `json:"suggestion"`
	Score      *int     `json:"score"`
	Tags       []string `json:"tags"`
}

func TestDumpExcludeNone_MatchesModelDumpExcludeNone(t *testing.T) {
	score := 3
	payload, err := DumpExcludeNone(dumpModel{Name: "n", Score: &score})
	if err != nil {
		t.Fatalf("DumpExcludeNone: %v", err)
	}
	got := payload.Map()
	// Python: `model_dump(exclude_none=True)` gives {'name': 'n', 'score': 3}
	// — score is an INT, not 3.0. pyfmt.Load's int/float split keeps it an int,
	// so it re-renders as `3`; a float64 decode would emit "3" here but
	// "5432.0" for the same integer inside a free-form dict.
	want := map[string]any{"name": "n", "score": 3, "tags": nil}
	// tags is a nil SLICE -> JSON null -> dropped (a nil Go slice marshals to
	// null, not []; the ported schema structs seed their list defaults in
	// UnmarshalJSON so this only bites on a hand-built zero value).
	delete(want, "tags")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DumpExcludeNone = %#v, want %#v", got, want)
	}
	if _, ok := got["suggestion"]; ok {
		t.Fatal("a nil pointer field survived exclude_none")
	}
}

func TestDumpExcludeNone_RejectsNonObjects(t *testing.T) {
	if _, err := DumpExcludeNone([]int{1}); err == nil {
		t.Fatal("expected an error for a value that does not encode to an object")
	}
}

// VALIDATION CONTRACT — a phase reply of Python None.
//
// The Go SDK returns a NIL map[string]any with a nil error when a succeeded
// execution's stored result is empty or the literal `null`
// (sdk/go/agent/agent.go awaitExecutionResult). Boxed into `any` that is a
// non-nil interface, so both UnwrapStrict's and AsMap's type assertions
// succeed and every key probe misses.
//
// Python's equivalent is a None payload, and the repo venv answers:
//
//	_as_dict(_unwrap(None, "hunt_phase"), "hunt_phase")
//	  -> RuntimeError: hunt_phase returned non-dict payload: NoneType
//	_as_dict(_unwrap({"status": "completed", "result": None}, "hunt_phase"), ...)
//	  -> the same message
//
// A RuntimeError is NOT ValueError-class, so app.py answers it 500 with the
// "scan execution failed: " prefix. Accepting the nil map as `{}` instead binds
// an all-default HuntResult/ChainResult (neither declares a required field) and
// returns a 200 reporting a zero-finding scan.
func TestAsMap_NilMapIsNoneNotAnEmptyDict(t *testing.T) {
	var nilMap map[string]any

	payload, err := UnwrapStrict(nilMap, "hunt_phase")
	if err != nil {
		t.Fatalf("UnwrapStrict: %v", err)
	}
	_, err = AsMap(payload, "hunt_phase")
	if err == nil {
		t.Fatal("AsMap accepted a nil map; Python raises RuntimeError for None")
	}
	if want := "hunt_phase returned non-dict payload: NoneType"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}

	// The same through the lenient variant and through an envelope carrying an
	// explicit null result.
	payload, err = Unwrap(map[string]any{"status": "completed", "result": nil}, "hunt_phase")
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if _, err := AsMap(payload, "hunt_phase"); err == nil || err.Error() != "hunt_phase returned non-dict payload: NoneType" {
		t.Errorf("an explicit null result gave %v, want the NoneType RuntimeError", err)
	}

	// A nil map is not ValueError-class — Python raises RuntimeError, which
	// app.py answers 500, not 400.
	var validation *ValidationError
	if errors.As(err, &validation) {
		t.Error("the NoneType payload error must not be ValueError-class")
	}

	// An EMPTY (non-nil) dict is a real dict and must still pass — Python
	// accepts `{}` and binds every default.
	if _, err := AsMap(map[string]any{}, "hunt_phase"); err != nil {
		t.Errorf("an empty dict was rejected: %v", err)
	}
}

// PythonTypeName spells a nil map/slice NoneType, because that is how the Go
// SDK and encoding/json both represent a JSON null at those targets.
func TestPythonTypeName_NilContainersAreNoneType(t *testing.T) {
	var nilMap map[string]any
	var nilSlice []any
	for _, v := range []any{nil, nilMap, nilSlice} {
		if got := PythonTypeName(v); got != "NoneType" {
			t.Errorf("PythonTypeName(%#v) = %q, want NoneType", v, got)
		}
	}
	for v, want := range map[any]string{
		"s": "str", 1.5: "float", true: "bool",
	} {
		if got := PythonTypeName(v); got != want {
			t.Errorf("PythonTypeName(%#v) = %q, want %q", v, got, want)
		}
	}
	if got := PythonTypeName(map[string]any{}); got != "dict" {
		t.Errorf("PythonTypeName(empty dict) = %q, want dict", got)
	}
	if got := PythonTypeName([]any{}); got != "list" {
		t.Errorf("PythonTypeName(empty list) = %q, want list", got)
	}
}
