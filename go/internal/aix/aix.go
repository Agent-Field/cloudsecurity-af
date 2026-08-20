// Package aix is the structured `.ai(...)` seam: the Go port of
//
//	await app.ai(system=..., user=..., schema=Model)   # agentfield Python SDK
//
// which returns a validated pydantic model. Structured[T] resolves the same
// committed pydantic schema harnessx uses, strictifies it exactly the way the
// Python SDK does before sending it to an OpenAI-compatible endpoint, makes the
// call, and decodes the response into T.
//
// NOTE for this repo: cloudsecurity-af currently has NO `.ai(...)` call sites —
// `grep -rn '\.ai(' src/` is empty; every LLM interaction goes through the
// harness. This package exists because the port contract lists it as shared
// foundation (sec-af's gates DO use `.ai(schema=...)`, and cloudsecurity's own
// gates are the obvious next feature), and because Strictify is the only
// faithful copy of the SDK's schema transformation. It is fully tested against
// the Python function's real output; it is simply not yet on a live path here.
package aix

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/ai"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/harnessx"
)

// maxParseRetries mirrors the Python SDK's `max_parse_retries = 2`
// (sdk/python/agentfield/agent_ai.py): the WHOLE call — request plus parse — is
// re-issued up to two more times when the model's body cannot be parsed into
// the schema, for three attempts in total.
const maxParseRetries = 2

// jsonObjectPattern ports the SDK's `re.search(r"\{.*\}", text, re.DOTALL)`
// salvage step. Go's regexp is leftmost-first with a greedy `.*`, so — exactly
// like CPython's `re` — it spans from the FIRST `{` to the LAST `}` in the
// body. That is what lets it strip a markdown ```json fence, a "Sure, here you
// go:" preamble, or a trailing apology off an otherwise valid object.
var jsonObjectPattern = regexp.MustCompile(`(?s)\{.*\}`)

// Structured ports `await app.ai(system=system, user=user, schema=T)`.
//
// The Python SDK turns `schema=Model` into an OpenAI `response_format` of type
// json_schema with strict:true, whose schema is
// `_strictify_openai_schema(Model.model_json_schema())`. The Go SDK's
// ai.WithSchema(json.RawMessage) produces the identical request body
// (ResponseFormat{Type: "json_schema", JSONSchema: {Name: "response", Strict:
// true, Schema: raw}}), so the only thing the port has to reproduce is the
// strictification — which Strictify does.
//
// An empty system prompt adds no system message, matching Python's
// `system=None` default (the SDK only prepends one when it is truthy).
//
// TOLERANT PARSING + RETRY (agent_ai.py, the `if schema:` branch of
// `_execute_and_parse` plus the `for attempt in range(max_parse_retries + 1)`
// loop around it). Reproduced here exactly, because a real OpenRouter run of
// the sec-af sibling failed two `run_verifier` executions when kimi-k2.5
// wrapped its json_schema reply in a ```json fence — a body the Python node
// absorbs without a blink:
//
//  1. parse the body directly;
//  2. on failure, salvage the first-`{`-to-last-`}` substring and parse that;
//  3. on failure, RE-ISSUE the AI request and start over, up to
//     maxParseRetries more times;
//  4. after the last attempt, return `Could not parse structured response:
//     <body>` — the SDK's final ValueError text, under the aix prefix.
//
// A transport error (app.AI returning an error) is NOT retried and is returned
// immediately: Python's retry loop only catches the parse `ValueError`, so an
// HTTP/network failure propagates on the first attempt there too.
//
// Python parity, deliberate divergences (both make Go strictly safer, neither
// changes any of the four outcomes above):
//
//   - Python calls `schema(**json_data)`, which requires a MAPPING; a body that
//     parses as `null`, a list or a scalar raises TypeError, which the SDK's
//     `except (JSONDecodeError, ValueError, ValidationError)` does not catch and
//     which therefore escapes uncaught. Go's json.Unmarshal would happily decode
//     `null` into a zero-valued T and report success, so Structured requires the
//     candidate to be a JSON object and otherwise treats it as a parse failure.
//     The caller sees an error either way; Go's is the retried, described one.
//   - `schema(**json_data)` also VALIDATES (missing required field, wrong type),
//     which is the ValidationError arm of the same except-clause; encoding/json
//     is lenient about both. A body that pydantic would reject can therefore
//     decode here into a partially-zero T. That is the port-wide pydantic gap
//     documented in DESIGN §2, not something this function can close.
func Structured[T any](ctx context.Context, app appx.AIer, system, user string) (T, error) {
	var out T

	raw, err := json.Marshal(Strictify(harnessx.SchemaFor[T]()))
	if err != nil {
		return out, fmt.Errorf("aix.Structured[%s]: marshal schema: %w", harnessx.TypeName[T](), err)
	}

	opts := make([]ai.Option, 0, 2)
	if system != "" {
		opts = append(opts, ai.WithSystem(system))
	}
	opts = append(opts, ai.WithSchema(json.RawMessage(raw)))

	var lastErr error
	for attempt := 0; attempt <= maxParseRetries; attempt++ {
		resp, err := app.AI(ctx, user, opts...)
		if err != nil {
			return out, fmt.Errorf("aix.Structured[%s]: %w", harnessx.TypeName[T](), err)
		}

		// A nil response is a Go-only shape (Python always has a response
		// object here); treating it as an empty body routes it down the same
		// path an empty completion takes in Python — parse failure, retry.
		var text string
		if resp != nil {
			text = resp.Text()
		}

		if parsed, ok := parseStructured[T](text); ok {
			return parsed, nil
		}
		lastErr = fmt.Errorf("aix.Structured[%s]: Could not parse structured response: %s", harnessx.TypeName[T](), text)
	}
	return out, lastErr
}

// parseStructured ports the two-step body of agent_ai.py's `if schema:` branch:
// a direct `json.loads(text)` + `schema(**data)`, then the `\{.*\}` salvage of
// the same. It reports whether either step produced a value.
func parseStructured[T any](text string) (T, bool) {
	if v, ok := decodeObject[T](text); ok {
		return v, true
	}
	if m := jsonObjectPattern.FindString(text); m != "" {
		if v, ok := decodeObject[T](m); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// decodeObject parses s into a fresh T, requiring the top-level JSON value to
// be an object — see the mapping-vs-`**kwargs` note on Structured. A fresh T is
// used per attempt because encoding/json can populate fields before it fails,
// and a half-filled value must never leak into the next step or the result.
func decodeObject[T any](s string) (T, bool) {
	// json.loads skips the four JSON whitespace bytes before the value; so
	// does encoding/json, so the object check has to skip them too.
	if trimmed := strings.TrimLeft(s, " \t\n\r"); trimmed == "" || trimmed[0] != '{' {
		var zero T
		return zero, false
	}
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		var zero T
		return zero, false
	}
	return v, true
}

// Strictify ports _strictify_openai_schema from the AgentField Python SDK
// (sdk/python/agentfield/agent_ai.py):
//
//	def walk(node):
//	    if isinstance(node, dict):
//	        node = {key: walk(value) for key, value in node.items()}
//	        props = node.get("properties")
//	        if isinstance(props, dict) and (node.get("type") == "object" or "type" not in node):
//	            node["additionalProperties"] = False
//	            node["required"] = list(props.keys())
//	        return node
//	    if isinstance(node, list):
//	        return [walk(item) for item in node]
//	    return node
//
// OpenAI's strict structured-output mode requires every object to set
// additionalProperties:false and to list ALL of its properties in required;
// pydantic's model_json_schema() emits neither. The walk covers $defs,
// properties, items and anyOf alike because it recurses into every dict value
// and every list element, not into a fixed keyword whitelist.
//
// Strictify returns a DEEP COPY and never mutates its argument — which matters
// here because harnessx.SchemaFor hands out a cached, shared map.
//
// DIVERGENCE (documented, semantically irrelevant): `list(props.keys())` yields
// Python's dict insertion order, i.e. the order pydantic emitted the fields in.
// A Go map has no order, so Strictify SORTS the required names. JSON Schema
// treats `required` as a set, and OpenAI does too, so nothing observable
// changes — and the committed fixtures are themselves written with sorted keys
// (gen_schemas.py uses sort_keys=True), so for every schema this port actually
// sends the two orders are in fact identical. The golden test compares against
// the real Python function run over the real fixture, which is what pins this.
func Strictify(schema map[string]any) map[string]any {
	walked, _ := walk(schema).(map[string]any)
	return walked
}

func walk(node any) any {
	switch x := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(x)+2)
		for k, v := range x {
			out[k] = walk(v)
		}
		props, isObj := out["properties"].(map[string]any)
		nodeType, hasType := out["type"]
		if isObj && (nodeType == "object" || !hasType) {
			out["additionalProperties"] = false
			keys := make([]string, 0, len(props))
			for k := range props {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			// required is []any, not []string, so the result marshals and
			// compares identically to a JSON-decoded schema.
			required := make([]any, len(keys))
			for i, k := range keys {
				required[i] = k
			}
			out["required"] = required
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = walk(e)
		}
		return out
	}
	return node
}
