package harnessx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/harness"
)

// HuntResult is a stand-in for the schemas package's type of the same name. Its
// NAME is what matters: SchemaFor resolves the committed pydantic fixture by Go
// type name, so declaring it here exercises the real fixture lookup without
// depending on internal/schemas landing first.
type HuntResult struct {
	Findings []map[string]any `json:"findings"`
	TotalRaw int              `json:"total_raw"`
}

// unfixturedResult has no fixture under testdata/schemas, so it takes the
// invopop reflection path.
type unfixturedResult struct {
	Title string `json:"title"`
	Count int    `json:"count"`
}

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

type fakeHarness struct {
	// recorded call
	prompt string
	schema map[string]any
	opts   harness.Options
	calls  int

	// programmed response
	fill   func(dest any)
	result *harness.Result
	err    error
}

func (f *fakeHarness) Harness(_ context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
	f.calls++
	f.prompt = prompt
	f.schema = schema
	f.opts = opts
	if f.fill != nil {
		f.fill(dest)
	}
	if f.result != nil && f.result.Parsed == nil && !f.result.IsError {
		// Mirror the SDK, which stores the destination pointer it was handed.
		f.result.Parsed = dest
	}
	return f.result, f.err
}

// captureDiagnostics swaps the stdout sink Extract writes to (Python's
// print(..., flush=True)) for the duration of a test.
func captureDiagnostics(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	old := diagnosticsOut
	diagnosticsOut = buf
	t.Cleanup(func() { diagnosticsOut = old })
	return buf
}

// ---------------------------------------------------------------------------
// SchemaFor
// ---------------------------------------------------------------------------

func TestSchemaFor_PrefersTheCommittedPydanticFixture(t *testing.T) {
	got := SchemaFor[HuntResult]()

	fixture, err := LoadEmbeddedSchema("HuntResult")
	if err != nil {
		t.Fatalf("LoadEmbeddedSchema: %v", err)
	}
	if !reflect.DeepEqual(got, fixture) {
		t.Fatal("SchemaFor did not return the committed fixture")
	}
	// The fixture is pydantic's, not invopop's: pydantic titles the root with
	// the class name and emits $defs for the nested models.
	if got["title"] != "HuntResult" {
		t.Errorf("title = %v, want HuntResult", got["title"])
	}
	if _, ok := got["$defs"]; !ok {
		t.Error("expected pydantic $defs in the fixture")
	}
	// The whole point of embedding pydantic's schema: defaulted fields are
	// OPTIONAL and extra keys are allowed, unlike an invopop reflection.
	if _, ok := got["additionalProperties"]; ok {
		t.Error("pydantic does not set additionalProperties on the root; the fixture does")
	}
}

func TestSchemaFor_FallsBackToInvopopReflectionWithoutAFixture(t *testing.T) {
	got := SchemaFor[unfixturedResult]()

	props, ok := got["properties"].(map[string]any)
	if !ok {
		t.Fatalf("reflected schema has no inlined properties: %#v", got)
	}
	for _, key := range []string{"title", "count"} {
		if _, ok := props[key]; !ok {
			t.Errorf("reflected properties missing %q: %#v", key, props)
		}
	}
	// ExpandedStruct inlines the root, and Anonymous suppresses the $id derived
	// from the package path — both are load-bearing for the SDK's
	// DiagnoseOutputFailure, which reads map["properties"].
	if _, ok := got["$id"]; ok {
		t.Error("reflector emitted an $id; Anonymous must suppress it")
	}
}

func TestSchemaFor_CachesPerType(t *testing.T) {
	a := SchemaFor[HuntResult]()
	b := SchemaFor[HuntResult]()
	if !sameMap(a, b) {
		t.Fatal("SchemaFor rebuilt the schema instead of serving the cache")
	}
}

func sameMap(a, b map[string]any) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// ---------------------------------------------------------------------------
// Committed fixtures
// ---------------------------------------------------------------------------

// Every fixture must decode and describe an object. gen_schemas.py is the only
// thing that writes these, so a failure here means a hand-edit or a truncated
// generator run.
//
// The struct-tag cross-check that completes this one lives in
// internal/schemas as TestEmbeddedSchemasMatchGoStructTags: for every fixture
// (and every $defs sub-model) it asserts the schema's "properties" keys and the
// Go destination struct's json tags are the same set, and that every "required"
// name has a corresponding tag. It lives there because it needs the schemas
// package's types and harnessx must not depend on that package.
func TestEmbeddedSchemas_DecodeAndDescribeAnObject(t *testing.T) {
	names := EmbeddedSchemaNames()
	want := []string{
		"AttackPath",
		"DriftReport",
		"HuntResult",
		"PathInvestigationPlan",
		"RemediationSuggestion",
		"ResourceGraph",
		"ResourceInventory",
		"VerifiedFinding",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("EmbeddedSchemaNames() = %v, want %v (regenerate with go/scripts/gen_schemas.py)", names, want)
	}

	for _, name := range names {
		schema, err := LoadEmbeddedSchema(name)
		if err != nil {
			t.Errorf("fixture %s does not decode: %v", name, err)
			continue
		}
		if schema["type"] != "object" {
			t.Errorf("fixture %s type = %v, want object", name, schema["type"])
		}
		if _, ok := schema["properties"].(map[string]any); !ok {
			t.Errorf("fixture %s has no properties object", name)
		}
		if schema["title"] != name {
			t.Errorf("fixture %s title = %v, want %s (the fixture basename must be the pydantic class name)", name, schema["title"], name)
		}
	}
}

// The fixtures must round-trip through the marshaling the SDK does before
// handing them to the validator.
func TestEmbeddedSchemas_AreMarshalable(t *testing.T) {
	for _, name := range EmbeddedSchemaNames() {
		schema, err := LoadEmbeddedSchema(name)
		if err != nil {
			t.Fatalf("LoadEmbeddedSchema(%s): %v", name, err)
		}
		if _, err := json.Marshal(schema); err != nil {
			t.Errorf("fixture %s does not marshal: %v", name, err)
		}
	}
}

func TestLoadEmbeddedSchema_MissingFixtureIsAnError(t *testing.T) {
	if _, err := LoadEmbeddedSchema("NoSuchModel"); err == nil {
		t.Fatal("expected an error for a missing fixture")
	}
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

func TestRun_PassesTheFixtureSchemaAndTypedDestination(t *testing.T) {
	fake := &fakeHarness{
		fill:   func(dest any) { dest.(*HuntResult).TotalRaw = 7 },
		result: &harness.Result{Result: "ok"},
	}
	opts := harness.Options{Cwd: "/tmp/work", ProjectDir: "/repo"}

	dest, res, err := Run[HuntResult](context.Background(), fake, "find things", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake.prompt != "find things" {
		t.Errorf("prompt = %q", fake.prompt)
	}
	if !reflect.DeepEqual(fake.opts, opts) {
		t.Errorf("opts = %+v, want %+v (Run must pass options through unchanged)", fake.opts, opts)
	}
	if fake.schema["title"] != "HuntResult" {
		t.Errorf("schema title = %v, want the committed pydantic fixture", fake.schema["title"])
	}
	if dest == nil || dest.TotalRaw != 7 {
		t.Fatalf("dest = %+v, want the value the harness wrote", dest)
	}
	if res == nil || res.Parsed == nil {
		t.Fatal("Run must return the raw Result for the caller to classify")
	}
}

// A transport failure is the ONLY thing Run reports as an error — the Go
// analogue of the Python SDK's .harness() raising.
func TestRun_ReturnsTransportErrorsAndTheResult(t *testing.T) {
	boom := errors.New("subprocess died")
	fake := &fakeHarness{result: &harness.Result{IsError: true, ErrorMessage: "x"}, err: boom}

	dest, res, err := Run[HuntResult](context.Background(), fake, "p", harness.Options{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if dest != nil {
		t.Errorf("dest = %+v, want nil on a transport error", dest)
	}
	if res == nil {
		t.Error("the Result should still be handed back for diagnostics")
	}
}

// An in-band harness error is NOT a Run error: Python's
// `result = await app.harness(...)` succeeds and extract_harness_result raises.
func TestRun_InBandHarnessErrorIsNotATransportError(t *testing.T) {
	fake := &fakeHarness{result: &harness.Result{IsError: true, ErrorMessage: "model refused"}}

	_, res, err := Run[HuntResult](context.Background(), fake, "p", harness.Options{})
	if err != nil {
		t.Fatalf("Run returned %v; in-band errors belong to Extract", err)
	}
	if !res.IsError {
		t.Fatal("the Result lost its error flag")
	}
}

// ---------------------------------------------------------------------------
// Extract — ports tests/test_utils.py::TestExtractHarnessResult
// ---------------------------------------------------------------------------

// Ports test_parsed_is_correct_type.
func TestExtract_ParsedIsCorrectType(t *testing.T) {
	captureDiagnostics(t)
	dest := &HuntResult{TotalRaw: 5}
	res := &harness.Result{IsError: false, Parsed: dest}

	got, err := Extract[HuntResult](res, dest, "test")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got.TotalRaw != 5 {
		t.Fatalf("got = %+v", got)
	}
}

// Ports test_parsed_is_dict_validates.
//
// Python's second branch re-validates a raw dict left in `parsed`. The Go SDK
// never does that — it decodes straight into the destination pointer and stores
// that pointer in Parsed (harness/runner.go: `Parsed: dest`) — so the Go
// equivalent of "the harness produced {'findings': [], 'total_raw': 5}" is the
// destination already carrying those values.
func TestExtract_ParsedDictEquivalentIsTheDecodedDestination(t *testing.T) {
	captureDiagnostics(t)
	dest := &HuntResult{}
	if err := json.Unmarshal([]byte(`{"findings": [], "total_raw": 5}`), dest); err != nil {
		t.Fatalf("seeding dest: %v", err)
	}
	res := &harness.Result{IsError: false, Parsed: dest}

	got, err := Extract[HuntResult](res, dest, "test")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got.TotalRaw != 5 {
		t.Fatalf("TotalRaw = %d, want 5", got.TotalRaw)
	}
}

// Ports test_error_raises (pytest.raises(RuntimeError, match="test harness error")).
func TestExtract_HarnessErrorMessageAndDiagnostics(t *testing.T) {
	buf := captureDiagnostics(t)
	res := &harness.Result{
		IsError:      true,
		ErrorMessage: "something broke",
		Result:       "",
		NumTurns:     3,
		DurationMS:   1000,
	}

	_, err := Extract[HuntResult](res, &HuntResult{}, "test")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "test harness error: something broke" {
		t.Fatalf("error = %q", err.Error())
	}

	// The diagnostic block is the Python print(), verbatim. Python's
	// `str(result_text)[:500] if result_text else None` renders a falsy result
	// text as "None".
	want := "[test] HARNESS ERROR: something broke\n" +
		"  turns=3, duration_ms=1000\n" +
		"  result_text=None\n"
	if buf.String() != want {
		t.Fatalf("diagnostics =\n%q\nwant\n%q", buf.String(), want)
	}
}

// Python parity: error_message is Optional[str], so an absent one renders as
// the literal "None" in both the diagnostic block and the raised message.
func TestExtract_MissingErrorMessageRendersAsNone(t *testing.T) {
	buf := captureDiagnostics(t)
	res := &harness.Result{IsError: true}

	_, err := Extract[HuntResult](res, &HuntResult{}, "iac_reader")
	if err == nil || err.Error() != "iac_reader harness error: None" {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(buf.String(), "HARNESS ERROR: None") {
		t.Fatalf("diagnostics = %q", buf.String())
	}
}

// Python slices result_text to 500 CODE POINTS, not bytes.
func TestExtract_ResultTextIsTruncatedTo500Runes(t *testing.T) {
	buf := captureDiagnostics(t)
	long := strings.Repeat("é", 600) // 600 runes, 1200 bytes
	res := &harness.Result{IsError: true, ErrorMessage: "e", Result: long}

	_, _ = Extract[HuntResult](res, &HuntResult{}, "n")

	out := buf.String()
	idx := strings.Index(out, "result_text=")
	if idx < 0 {
		t.Fatalf("diagnostics = %q", out)
	}
	text := strings.TrimSuffix(out[idx+len("result_text="):], "\n")
	if got := len([]rune(text)); got != 500 {
		t.Fatalf("result_text = %d runes, want 500", got)
	}
}

// Ports test_invalid_parsed_raises_type_error
// (pytest.raises(TypeError, match="did not return a valid")).
func TestExtract_UnparsedResultIsATypeErrorEquivalent(t *testing.T) {
	buf := captureDiagnostics(t)
	res := &harness.Result{IsError: false, Parsed: nil}

	_, err := Extract[HuntResult](res, &HuntResult{}, "test")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "test did not return a valid HuntResult" {
		t.Fatalf("error = %q", err.Error())
	}
	want := "[test] harness result type=Result, is_error=False, parsed type=NoneType\n"
	if buf.String() != want {
		t.Fatalf("diagnostics = %q, want %q", buf.String(), want)
	}
}

func TestExtract_NilResultIsATypeErrorEquivalent(t *testing.T) {
	captureDiagnostics(t)
	_, err := Extract[HuntResult](nil, &HuntResult{}, "test")
	if err == nil || err.Error() != "test did not return a valid HuntResult" {
		t.Fatalf("error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// RunExtract
// ---------------------------------------------------------------------------

func TestRunExtract_HappyPath(t *testing.T) {
	captureDiagnostics(t)
	fake := &fakeHarness{
		fill:   func(dest any) { dest.(*HuntResult).TotalRaw = 11 },
		result: &harness.Result{},
	}

	got, err := RunExtract[HuntResult](context.Background(), fake, "p", harness.Options{Cwd: "/w"}, "iam_hunter")
	if err != nil {
		t.Fatalf("RunExtract: %v", err)
	}
	if got.TotalRaw != 11 {
		t.Fatalf("got = %+v", got)
	}
	if fake.calls != 1 {
		t.Fatalf("harness calls = %d, want 1", fake.calls)
	}
}

func TestRunExtract_PropagatesTheTransportError(t *testing.T) {
	captureDiagnostics(t)
	boom := errors.New("no such binary")
	fake := &fakeHarness{err: boom}

	_, err := RunExtract[HuntResult](context.Background(), fake, "p", harness.Options{}, "iam_hunter")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestRunExtract_MapsAnInBandHarnessError(t *testing.T) {
	captureDiagnostics(t)
	fake := &fakeHarness{result: &harness.Result{IsError: true, ErrorMessage: "rate limited"}}

	_, err := RunExtract[HuntResult](context.Background(), fake, "p", harness.Options{}, "iam_hunter")
	if err == nil || err.Error() != "iam_hunter harness error: rate limited" {
		t.Fatalf("err = %v", err)
	}
}

// TestEmbeddedSchemas_AreKeySortedLikeTheSDKWillRenderThem pins the invariant
// go/README.md's divergence 7 rests on.
//
// The SDK renders the schema into the prompt with json.MarshalIndent over the
// map[string]any SchemaFor returns (sdk/go/harness/schema.go), and Go sorts map
// keys — so the prompt block is alphabetised whatever the fixture's own byte
// order is. gen_schemas.py therefore writes the fixtures with sort_keys=True,
// which keeps the committed file and the prompt block byte-identical; without
// it the file would disagree with the prompt as well as with Python.
//
// It also pins that LoadEmbeddedSchema's UseNumber decode keeps pydantic's
// numeric literals (`"default": 0.0`), which a plain decode would re-render as
// `0` — a second, and fixable, prompt-text difference.
//
// The DIVERGENCE this documents is the order alone: Python appends
// json.dumps(model_json_schema(), indent=2), which keeps pydantic's field
// declaration order (for HuntResult, a 144-line diff of identical content and
// identical byte length). It is not fixable from this package — both
// agent.Harness and harness.BuildPromptSuffix take a map[string]any.
func TestEmbeddedSchemas_AreKeySortedLikeTheSDKWillRenderThem(t *testing.T) {
	entries, err := embeddedSchemas.ReadDir("testdata/schemas")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no committed schema fixtures")
	}
	for _, entry := range entries {
		name := entry.Name()
		raw, readErr := embeddedSchemas.ReadFile("testdata/schemas/" + name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		decoded, err := LoadEmbeddedSchema(strings.TrimSuffix(name, ".json"))
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		rendered, err := json.MarshalIndent(decoded, "", "  ")
		if err != nil {
			t.Fatalf("re-render %s: %v", name, err)
		}
		if string(rendered) != strings.TrimRight(string(raw), "\n") {
			t.Errorf("%s is not in the key order the SDK renders it in; regenerate with "+
				"`PYTHONPATH=<repo>/src <python> go/scripts/gen_schemas.py` (it writes sort_keys=True)", name)
		}
	}
}
