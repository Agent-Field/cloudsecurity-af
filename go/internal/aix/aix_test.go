package aix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
)

// HuntResult mirrors the schemas package's type of the same name; the NAME is
// what SchemaFor uses to find the committed pydantic fixture.
type HuntResult struct {
	Findings []map[string]any `json:"findings"`
	TotalRaw int              `json:"total_raw"`
}

// ---------------------------------------------------------------------------
// Strictify — golden comparison against the real Python SDK function
// ---------------------------------------------------------------------------

// The goldens are produced by go/scripts/gen_strictify_golden.py, which runs
// agentfield.agent_ai._strictify_openai_schema (the exact function
// app.ai(schema=Model) uses) over the committed pydantic fixtures. If this test
// fails, either Strictify drifted or the SDK's transformation changed —
// regenerate and read the diff, do not "fix" the expectation.
func TestStrictify_MatchesThePythonSDKFunction(t *testing.T) {
	for _, name := range []string{"PathInvestigationPlan", "HuntResult", "VerifiedFinding"} {
		t.Run(name, func(t *testing.T) {
			input, err := harnessx.LoadEmbeddedSchema(name)
			if err != nil {
				t.Fatalf("LoadEmbeddedSchema(%s): %v", name, err)
			}

			want := readGolden(t, "strict_"+name+".json")
			got := Strictify(input)

			// reflect.DeepEqual on the decoded trees compares the `required`
			// SLICES element-wise, so this pins their order too.
			if !reflect.DeepEqual(got, want) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(want, "", "  ")
				t.Fatalf("Strictify(%s) diverged from the Python SDK.\n--- got ---\n%s\n--- want ---\n%s", name, gotJSON, wantJSON)
			}
		})
	}
}

// readGolden decodes a golden with UseNumber, the same way
// harnessx.LoadEmbeddedSchema decodes the fixture Strictify is handed — so the
// DeepEqual below compares json.Number to json.Number and pins the numeric
// LITERALS (pydantic's `"default": 0.0`) as well as the tree shape.
func readGolden(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading golden %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decoding golden %s: %v", name, err)
	}
	return m
}

// The transformation itself, on a hand-built schema that exercises every branch
// the Python walk has: $defs, nested properties, items, anyOf, a node with
// properties but no "type", and a node that is NOT an object.
func TestStrictify_TransformationRules(t *testing.T) {
	in := map[string]any{
		"type":  "object",
		"title": "Root",
		"properties": map[string]any{
			"b": map[string]any{"type": "string"},
			"a": map[string]any{
				"type":  "array",
				"items": map[string]any{"$ref": "#/$defs/Nested"},
			},
			"c": map[string]any{
				"anyOf": []any{
					map[string]any{"type": "object", "properties": map[string]any{"z": map[string]any{"type": "integer"}}},
					map[string]any{"type": "null"},
				},
			},
		},
		"$defs": map[string]any{
			// No "type" key, but it has properties -> still strictified.
			"Nested": map[string]any{
				"properties": map[string]any{"n": map[string]any{"type": "string"}},
			},
			// An enum has no properties -> untouched.
			"Sev": map[string]any{"type": "string", "enum": []any{"low", "high"}},
		},
	}

	got := Strictify(in)

	assertStrict(t, got, []any{"a", "b", "c"})

	defs := got["$defs"].(map[string]any)
	assertStrict(t, defs["Nested"].(map[string]any), []any{"n"})

	sev := defs["Sev"].(map[string]any)
	if _, ok := sev["additionalProperties"]; ok {
		t.Error("an enum node without properties must not be strictified")
	}
	if _, ok := sev["required"]; ok {
		t.Error("an enum node without properties must not gain required")
	}

	props := got["properties"].(map[string]any)
	// Recursion reaches inside anyOf list elements.
	anyOf := props["c"].(map[string]any)["anyOf"].([]any)
	assertStrict(t, anyOf[0].(map[string]any), []any{"z"})
	if _, ok := anyOf[1].(map[string]any)["required"]; ok {
		t.Error("the null branch has no properties and must be untouched")
	}
}

func assertStrict(t *testing.T, node map[string]any, wantRequired []any) {
	t.Helper()
	if node["additionalProperties"] != false {
		t.Errorf("additionalProperties = %v, want false", node["additionalProperties"])
	}
	if !reflect.DeepEqual(node["required"], wantRequired) {
		t.Errorf("required = %v, want %v", node["required"], wantRequired)
	}
}

// Strictify must never mutate its argument: harnessx.SchemaFor hands out a
// CACHED, SHARED map, so an in-place edit would poison every later harness call.
func TestStrictify_DoesNotMutateItsArgument(t *testing.T) {
	shared := harnessx.SchemaFor[HuntResult]()
	before, err := json.Marshal(shared)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	_ = Strictify(shared)

	after, err := json.Marshal(shared)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("Strictify mutated the cached schema map")
	}
	if _, ok := shared["additionalProperties"]; ok {
		t.Fatal("Strictify wrote additionalProperties into the shared map")
	}
}

func TestStrictify_IsDeterministic(t *testing.T) {
	schema := harnessx.SchemaFor[HuntResult]()
	first, _ := json.Marshal(Strictify(schema))
	for i := 0; i < 10; i++ {
		next, _ := json.Marshal(Strictify(schema))
		if string(next) != string(first) {
			t.Fatal("Strictify is not deterministic across runs")
		}
	}
}

// ---------------------------------------------------------------------------
// Structured
// ---------------------------------------------------------------------------

// fakeAI applies the options to a Request exactly as the SDK client does, so the
// test can inspect the system message and the response_format the call would
// have sent.
type fakeAI struct {
	prompt string
	req    *ai.Request
	resp   *ai.Response
	err    error
	calls  int
}

func (f *fakeAI) AI(_ context.Context, prompt string, opts ...ai.Option) (*ai.Response, error) {
	f.calls++
	f.prompt = prompt
	req := &ai.Request{Messages: []ai.Message{{
		Role:    "user",
		Content: []ai.ContentPart{{Type: "text", Text: prompt}},
	}}}
	for _, o := range opts {
		if err := o(req); err != nil {
			return nil, err
		}
	}
	f.req = req
	return f.resp, f.err
}

func textResponse(body string) *ai.Response {
	return &ai.Response{Choices: []ai.Choice{{
		Message: ai.Message{Role: "assistant", Content: []ai.ContentPart{{Type: "text", Text: body}}},
	}}}
}

func TestStructured_SendsTheStrictifiedSchemaAndDecodesTheReply(t *testing.T) {
	fake := &fakeAI{resp: textResponse(`{"findings": [], "total_raw": 4}`)}

	got, err := Structured[HuntResult](context.Background(), fake, "you are a gate", "classify this")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if got.TotalRaw != 4 {
		t.Fatalf("got = %+v", got)
	}

	if fake.prompt != "classify this" {
		t.Errorf("user prompt = %q", fake.prompt)
	}
	if len(fake.req.Messages) != 2 || fake.req.Messages[0].Role != "system" {
		t.Fatalf("messages = %+v, want a prepended system message", fake.req.Messages)
	}
	if fake.req.Messages[0].Content[0].Text != "you are a gate" {
		t.Errorf("system = %q", fake.req.Messages[0].Content[0].Text)
	}

	rf := fake.req.ResponseFormat
	if rf == nil || rf.Type != "json_schema" || rf.JSONSchema == nil || !rf.JSONSchema.Strict {
		t.Fatalf("response_format = %+v, want a strict json_schema", rf)
	}
	// Compare the BYTES: the fixture is decoded with UseNumber, so a re-decode
	// of the sent schema yields float64 where Strictify's map holds a
	// json.Number — different Go values for identical JSON.
	wantJSON, err := json.Marshal(Strictify(harnessx.SchemaFor[HuntResult]()))
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if !bytes.Equal(rf.JSONSchema.Schema, wantJSON) {
		t.Fatalf("the schema sent to the model is not the strictified pydantic schema:\n got %s\nwant %s",
			rf.JSONSchema.Schema, wantJSON)
	}
}

// Python's system=None default sends no system message at all.
func TestStructured_EmptySystemPromptAddsNoSystemMessage(t *testing.T) {
	fake := &fakeAI{resp: textResponse(`{"total_raw": 1}`)}

	if _, err := Structured[HuntResult](context.Background(), fake, "", "user only"); err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if len(fake.req.Messages) != 1 || fake.req.Messages[0].Role != "user" {
		t.Fatalf("messages = %+v, want only the user message", fake.req.Messages)
	}
}

// Python parity: an empty completion is NOT a special case in the SDK — it goes
// straight into `json.loads("")`, which raises, so it is a parse failure like
// any other and is therefore RETRIED before it is reported. A nil *ai.Response
// is a Go-only shape routed down the same path.
func TestStructured_EmptyContentIsARetriedParseFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp *ai.Response
	}{
		{"nil response", nil},
		{"no choices", &ai.Response{}},
		{"empty text", textResponse("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAI{resp: tc.resp}
			_, err := Structured[HuntResult](context.Background(), fake, "", "p")
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Error() != "aix.Structured[HuntResult]: Could not parse structured response: " {
				t.Fatalf("err = %q", err.Error())
			}
			if fake.calls != 3 {
				t.Fatalf("AI calls = %d, want 3 (initial + 2 parse retries)", fake.calls)
			}
		})
	}
}

// "Sure! Here is the JSON: {oops" has no closing brace, so the `\{.*\}` salvage
// finds nothing and the body is unparsable by both steps.
func TestStructured_UnparsableJSONIsADescriptiveError(t *testing.T) {
	fake := &fakeAI{resp: textResponse("Sure! Here is the JSON: {oops")}

	_, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "aix.Structured[HuntResult]: Could not parse structured response: Sure! Here is the JSON: {oops" {
		t.Fatalf("err = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// F1 — tolerant parsing + parse retries (agent_ai.py `_execute_and_parse` and
// the `for attempt in range(max_parse_retries + 1)` loop around it).
//
// The live defect that motivated these: kimi-k2.5, asked for a json_schema
// response, returned its object inside a markdown ```json fence and the Go node
// failed the execution where the Python node succeeded.
// ---------------------------------------------------------------------------

// scriptedAI answers the Nth AI call with bodies[N], and errs[N] if set. It is
// the appx.Fake seam driven from a script, so the test can count calls.
func scriptedAI(t *testing.T, bodies ...string) (*appx.Fake, func() int) {
	t.Helper()
	fake := &appx.Fake{}
	n := 0
	fake.AIFn = func(_ context.Context, _ string, _ ...ai.Option) (*ai.Response, error) {
		if n >= len(bodies) {
			t.Errorf("AI called %d times, script only has %d bodies", n+1, len(bodies))
			return textResponse(""), nil
		}
		body := bodies[n]
		n++
		return textResponse(body), nil
	}
	return fake, func() int { return n }
}

// (a) The exact live failure: a fenced body must parse on the FIRST attempt.
func TestStructured_ParsesAFencedJSONBodyWithoutRetrying(t *testing.T) {
	fake, calls := scriptedAI(t, "```json\n{\"findings\": [], \"total_raw\": 7}\n```")

	got, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if got.TotalRaw != 7 {
		t.Fatalf("got = %+v, want TotalRaw 7", got)
	}
	if calls() != 1 {
		t.Fatalf("AI calls = %d, want 1", calls())
	}
}

// (b) Prose on both sides of the object — the same salvage step.
func TestStructured_SalvagesJSONEmbeddedInProse(t *testing.T) {
	fake, calls := scriptedAI(t, "Here you go:\n{\"findings\": [], \"total_raw\": 2}\nHope that helps!")

	got, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if got.TotalRaw != 2 {
		t.Fatalf("got = %+v, want TotalRaw 2", got)
	}
	if calls() != 1 {
		t.Fatalf("AI calls = %d, want 1", calls())
	}
}

// The salvage is GREEDY — first `{` to last `}` — exactly like CPython's
// `re.search(r"\{.*\}", text, re.DOTALL)`. Ground truth for this string was
// taken from the venv interpreter, which returns the whole span including the
// text between the two objects.
func TestStructured_SalvageIsGreedyLikeThePythonRegex(t *testing.T) {
	body := "{\"a\":1} trailing {\"findings\": [], \"total_raw\": 9}"
	if got := jsonObjectPattern.FindString(body); got != body {
		t.Fatalf("FindString = %q, want the whole span %q", got, body)
	}
	// The greedy span is not valid JSON, so this body legitimately fails.
	fake, calls := scriptedAI(t, body, body, body)
	if _, err := Structured[HuntResult](context.Background(), fake, "", "p"); err == nil {
		t.Fatal("expected a parse error for the greedy multi-object span")
	}
	if calls() != 3 {
		t.Fatalf("AI calls = %d, want 3", calls())
	}
}

// (c) Two malformed bodies then a good one: the WHOLE call is re-issued, so the
// third attempt succeeds and exactly three AI calls were made.
func TestStructured_RetriesTheRequestOnParseFailureAndSucceedsOnTheThird(t *testing.T) {
	fake, calls := scriptedAI(t,
		"not json at all",
		"still {not json",
		"{\"findings\": [], \"total_raw\": 3}",
	)

	got, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if got.TotalRaw != 3 {
		t.Fatalf("got = %+v, want TotalRaw 3", got)
	}
	if calls() != 3 {
		t.Fatalf("AI calls = %d, want 3 (initial + 2 parse retries)", calls())
	}
}

// (d) Three malformed bodies: the SDK gives up after max_parse_retries and
// reports the LAST body with the Python error text.
func TestStructured_GivesUpAfterThreeAttempts(t *testing.T) {
	fake, calls := scriptedAI(t, "garbage one", "garbage two", "garbage three")

	_, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "aix.Structured[HuntResult]: Could not parse structured response: garbage three" {
		t.Fatalf("err = %q", err.Error())
	}
	if calls() != 3 {
		t.Fatalf("AI calls = %d, want 3 (initial + 2 parse retries)", calls())
	}
}

// A transport error is not a parse error: Python's retry loop only catches the
// ValueError, so the very first HTTP failure propagates. No retry here either.
func TestStructured_TransportErrorIsNotRetried(t *testing.T) {
	boom := errors.New("429 rate limited")
	fake := &fakeAI{err: boom}

	_, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
	if fake.calls != 1 {
		t.Fatalf("AI calls = %d, want 1 — a transport error must not be retried", fake.calls)
	}
}

// A body that parses but is not a MAPPING is a parse failure, not a silently
// zero-valued result. Python's `schema(**data)` raises TypeError on these;
// encoding/json would decode `null` into a zero T and report success.
func TestStructured_NonObjectBodiesAreParseFailures(t *testing.T) {
	for _, body := range []string{"null", "[1,2]", "42", `"a string"`, "true"} {
		t.Run(body, func(t *testing.T) {
			fake, calls := scriptedAI(t, body, body, body)
			_, err := Structured[HuntResult](context.Background(), fake, "", "p")
			if err == nil {
				t.Fatalf("body %q decoded successfully; a non-mapping body must fail", body)
			}
			if !strings.Contains(err.Error(), "Could not parse structured response") {
				t.Fatalf("err = %q", err.Error())
			}
			if calls() != 3 {
				t.Fatalf("AI calls = %d, want 3", calls())
			}
		})
	}
}

// A half-decodable body must not leak partially-populated fields into the
// salvaged parse or into the returned value.
func TestStructured_PartialDecodeDoesNotLeakIntoTheResult(t *testing.T) {
	// The direct parse fails on the trailing junk AFTER filling total_raw;
	// the salvaged span is the same prefix and parses cleanly.
	fake, calls := scriptedAI(t, "{\"total_raw\": 5, \"findings\": []} <<junk")

	got, err := Structured[HuntResult](context.Background(), fake, "", "p")
	if err != nil {
		t.Fatalf("Structured: %v", err)
	}
	if got.TotalRaw != 5 {
		t.Fatalf("got = %+v, want TotalRaw 5", got)
	}
	if calls() != 1 {
		t.Fatalf("AI calls = %d, want 1", calls())
	}
}

// The retried request must be byte-identical to the first: same user prompt,
// same system message, same strictified response_format.
func TestStructured_RetriesSendTheSameRequest(t *testing.T) {
	fake := &appx.Fake{}
	n := 0
	fake.AIFn = func(_ context.Context, _ string, _ ...ai.Option) (*ai.Response, error) {
		n++
		return textResponse("garbage"), nil
	}

	if _, err := Structured[HuntResult](context.Background(), fake, "sys", "usr"); err == nil {
		t.Fatal("expected a parse error")
	}
	if len(fake.AIs) != 3 {
		t.Fatalf("recorded AI calls = %d, want 3", len(fake.AIs))
	}
	want := Strictify(harnessx.SchemaFor[HuntResult]())
	for i, rec := range fake.AIs {
		if rec.Prompt != "usr" {
			t.Errorf("attempt %d prompt = %q, want \"usr\"", i, rec.Prompt)
		}
		req := &ai.Request{}
		for _, o := range rec.Opts {
			if err := o(req); err != nil {
				t.Fatalf("attempt %d applying option: %v", i, err)
			}
		}
		if len(req.Messages) != 1 || req.Messages[0].Role != "system" || req.Messages[0].Content[0].Text != "sys" {
			t.Errorf("attempt %d messages = %+v, want the system message", i, req.Messages)
		}
		if req.ResponseFormat == nil || req.ResponseFormat.JSONSchema == nil || !req.ResponseFormat.JSONSchema.Strict {
			t.Fatalf("attempt %d response_format = %+v", i, req.ResponseFormat)
		}
		// Compare the BYTES, not decoded maps: the fixture is decoded with
		// UseNumber (harnessx.LoadEmbeddedSchema keeps pydantic's `0.0`
		// spelling for the prompt), so a re-decode of the sent schema yields
		// float64 where `want` holds a json.Number — different Go values for
		// identical JSON.
		wantJSON, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal want: %v", err)
		}
		if !bytes.Equal(req.ResponseFormat.JSONSchema.Schema, wantJSON) {
			t.Errorf("attempt %d did not resend the strictified schema:\n got %s\nwant %s",
				i, req.ResponseFormat.JSONSchema.Schema, wantJSON)
		}
	}
}
