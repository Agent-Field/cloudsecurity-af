package pyfmt

import (
	"reflect"
	"testing"
)

// Validation contract for Load (derived from what CPython's json.load does, not
// from the Go implementation). Every `want` in this file was captured from the
// real interpreter:
//
//	~/.agentfield/packages/cloudsecurity-af/venv/bin/python -c \
//	  'import json; print(repr(json.loads(<src>)))'
//
// These cases are the union of the three package-local decoders that were
// folded into Load at integration time (internal/agents/{recon,util,chain}).

// Object key order is the whole point: config_summary's order reaches the
// hunter prompt through a dict repr and reaches graph.json through json.dumps.
// A map[string]any decode would sort it away.
func TestLoad_PreservesObjectKeyOrder(t *testing.T) {
	v, err := Load([]byte(`{"zebra": 1, "apple": 2, "middle": 3}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	obj, ok := v.(Ordered)
	if !ok {
		t.Fatalf("expected an Ordered object, got %T", v)
	}
	got := make([]string, 0, len(obj))
	for _, kv := range obj {
		got = append(got, kv.K)
	}
	if want := []string{"zebra", "apple", "middle"}; !reflect.DeepEqual(got, want) {
		t.Errorf("key order = %v, want %v", got, want)
	}
	if s := Str(obj); s != "{'zebra': 1, 'apple': 2, 'middle': 3}" {
		t.Errorf("repr = %s", s)
	}
}

// json.load gives back a Python int for an integral LITERAL and a float
// otherwise, and the two render differently: str(2) is "2", str(2.0) is "2.0".
func TestLoad_IntFloatSplitFollowsTheLiteral(t *testing.T) {
	v, err := Load([]byte(`{"i": 7, "f": 7.0, "e": 7e0, "neg": -3, "big": 1.5}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := Str(v), "{'i': 7, 'f': 7.0, 'e': 7.0, 'neg': -3, 'big': 1.5}"; got != want {
		t.Errorf("repr = %s, want %s", got, want)
	}
}

// Python dict assignment: the last value wins, the FIRST position is kept.
func TestLoad_RepeatedKeyKeepsTheFirstPosition(t *testing.T) {
	v, err := Load([]byte(`{"a": 1, "b": 2, "a": 3}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := Str(v), "{'a': 3, 'b': 2}"; got != want {
		t.Errorf("repr = %s, want %s", got, want)
	}
}

// json.load raises JSONDecodeError("Extra data") rather than ignoring the tail.
func TestLoad_RejectsTrailingContent(t *testing.T) {
	for _, src := range []string{`{"a": 1} {"b": 2}`, `{"a":1} {"b":2}`, `[1] 2`} {
		if _, err := Load([]byte(src)); err == nil {
			t.Errorf("Load(%q) = nil error, want the json.load 'Extra data' rejection", src)
		}
	}
}

func TestLoad_DecodesEveryScalarKind(t *testing.T) {
	v, err := Load([]byte(`[null, true, false, "s", 1, 1.25, [], {}]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := Repr(v), "[None, True, False, 's', 1, 1.25, [], {}]"; got != want {
		t.Errorf("repr = %s, want %s", got, want)
	}
}

// The concrete Go kinds matter, not just the repr: Dumps renders int 1 as `1`
// and float64 1.0 as `1.0`.
func TestLoad_ProducesTheDocumentedValueModel(t *testing.T) {
	v, err := Load([]byte(`{"z": 1, "a": 2.0, "m": [3, 4.5, "s", true, null], "n": {"inner": 1e2}}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	obj, ok := v.(Ordered)
	if !ok {
		t.Fatalf("want Ordered, got %T", v)
	}
	if got, want := Str(obj), "{'z': 1, 'a': 2.0, 'm': [3, 4.5, 's', True, None], 'n': {'inner': 100.0}}"; got != want {
		t.Errorf("repr = %s, want %s", got, want)
	}
	if _, isInt := mustLoadGet(t, obj, "z").(int); !isInt {
		t.Error(`"z" must decode as int: the literal has no "." and no exponent`)
	}
	if _, isFloat := mustLoadGet(t, obj, "a").(float64); !isFloat {
		t.Error(`"a" must decode as float64: the literal has a "."`)
	}
	list, ok := mustLoadGet(t, obj, "m").([]any)
	if !ok {
		t.Fatalf(`"m" = %T, want []any`, mustLoadGet(t, obj, "m"))
	}
	if want := []any{3, 4.5, "s", true, nil}; !reflect.DeepEqual(list, want) {
		t.Errorf(`"m" = %#v, want %#v`, list, want)
	}
	inner, ok := mustLoadGet(t, obj, "n").(Ordered)
	if !ok {
		t.Fatalf(`"n" = %T, want Ordered`, mustLoadGet(t, obj, "n"))
	}
	if v, _ := inner.Get("inner"); v != 100.0 {
		t.Errorf(`"n.inner" = %#v, want float64 100 (the literal has an exponent)`, v)
	}
}

// Dumps(Load(x), 2) is the identity for anything CPython wrote with
// json.dumps(x, indent=2) — this is what makes the graph builder's
// read-modify-write byte-stable. Confirmed identical in the interpreter.
func TestLoad_DumpsRoundTripIsTheIdentity(t *testing.T) {
	src := "{\n  \"z\": 1,\n  \"a\": [\n    1.5,\n    true,\n    null\n  ],\n  \"s\": \"caf\\u00e9\"\n}"
	decoded, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := Dumps(decoded, 2); got != src {
		t.Errorf("round-trip mismatch\n got: %q\nwant: %q", got, src)
	}
}

func TestLoad_RejectsMalformedInput(t *testing.T) {
	for _, src := range []string{``, `{`, `{"a"}`, `[1,`, `nope`} {
		if _, err := Load([]byte(src)); err == nil {
			t.Errorf("Load(%q) = nil error, want a decode failure", src)
		}
	}
}

func mustLoadGet(t *testing.T, o Ordered, key string) any {
	t.Helper()
	v, ok := o.Get(key)
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	return v
}
