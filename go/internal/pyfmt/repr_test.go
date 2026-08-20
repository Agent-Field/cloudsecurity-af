package pyfmt

import "testing"

// ---------------------------------------------------------------------------
// Repr — strings
// ---------------------------------------------------------------------------

// Captured with (note the shell heredoc, so the quotes survive verbatim):
//
//	python - <<'PY'
//	for v in ["hello","it's",'say "hi"','both \' and "',"line\nbreak","tab\there","back\\slash","","café","\x00\x01\x1f\x7f","emoji \U0001F600","nbsp\xa0x","zwsp​x","\r","quote'in\"both"]:
//	    print(repr(v))
//	PY
//
//	'hello'
//	"it's"
//	'say "hi"'
//	'both \' and "'
//	'line\nbreak'
//	'tab\there'
//	'back\\slash'
//	''
//	'café'
//	'\x00\x01\x1f\x7f'
//	'emoji 😀'
//	'nbsp\xa0x'
//	'zwsp\u200bx'
//	'\r'
//	'quote\'in"both'
func TestRepr_String_PythonGroundTruth(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", `'hello'`},
		{"apostrophe only flips to double quotes", "it's", `"it's"`},
		{"double quote only stays single-quoted", `say "hi"`, `'say "hi"'`},
		{"both quotes: single quotes win, apostrophe escaped", `both ' and "`, `'both \' and "'`},
		{"newline", "line\nbreak", `'line\nbreak'`},
		{"tab", "tab\there", `'tab\there'`},
		{"backslash", `back\slash`, `'back\\slash'`},
		{"empty", "", `''`},
		{"printable non-ascii stays literal", "café", `'café'`},
		{"control chars use \\xNN", "\x00\x01\x1f\x7f", `'\x00\x01\x1f\x7f'`},
		{"astral printable stays literal", "emoji \U0001F600", `'emoji 😀'`},
		{"Zs non-breaking space is escaped", "nbsp x", `'nbsp\xa0x'`},
		{"Cf zero-width space uses \\uXXXX", "zwsp\u200bx", `'zwsp\u200bx'`},
		{"carriage return", "\r", `'\r'`},
		{"apostrophe plus double quote", "quote'in\"both", `'quote\'in"both'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Repr(tc.in); got != tc.want {
				t.Fatalf("Repr(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// Captured with:
//
//	python -c "print(repr('\U000E0001'))"   ->  '\U000e0001'   (Cf, above U+FFFF)
func TestRepr_String_AstralNonPrintableUsesCapitalU(t *testing.T) {
	if got := Repr("\U000E0001"); got != `'\U000e0001'` {
		t.Fatalf("Repr = %s", got)
	}
}

// ---------------------------------------------------------------------------
// Repr — scalars, lists, dicts
// ---------------------------------------------------------------------------

// Captured with:
//
//	python - <<'PY'
//	for v in [True, False, None, 42, -7, 3.5, 1.0, ["a","b"], [1,2.5,None,True], [],
//	          ["it's",'q"'], {"k":"v"}, {}, {"b":1,"a":2}, {"n":None,"l":["x"],"d":{"i":1}}]:
//	    print(repr(v))
//	PY
//
//	True
//	False
//	None
//	42
//	-7
//	3.5
//	1.0
//	['a', 'b']
//	[1, 2.5, None, True]
//	[]
//	["it's", 'q"']
//	{'k': 'v'}
//	{}
//	{'b': 1, 'a': 2}
//	{'n': None, 'l': ['x'], 'd': {'i': 1}}
func TestRepr_Values_PythonGroundTruth(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"true", true, "True"},
		{"false", false, "False"},
		{"none", nil, "None"},
		{"int", 42, "42"},
		{"negative int", -7, "-7"},
		{"float", 3.5, "3.5"},
		{"integral float keeps .0", 1.0, "1.0"},
		{"list of str", []string{"a", "b"}, `['a', 'b']`},
		{"heterogeneous list", []any{1, 2.5, nil, true}, `[1, 2.5, None, True]`},
		{"empty list", []any{}, `[]`},
		{"list quoting is per element", []string{"it's", `q"`}, `["it's", 'q"']`},
		{"dict", Ordered{{K: "k", V: "v"}}, `{'k': 'v'}`},
		{"empty dict", Ordered{}, `{}`},
		// Insertion order is preserved by Ordered even when it is not sorted.
		{"dict keeps insertion order", Ordered{{K: "b", V: 1}, {K: "a", V: 2}}, `{'b': 1, 'a': 2}`},
		{"nested", Ordered{
			{K: "n", V: nil},
			{K: "l", V: []string{"x"}},
			{K: "d", V: Ordered{{K: "i", V: 1}}},
		}, `{'n': None, 'l': ['x'], 'd': {'i': 1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Repr(tc.in); got != tc.want {
				t.Fatalf("Repr(%#v) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// Captured with:
//
//	python -c "print(repr({'outer': [{'k': \"v'x\"}, 1.0, None]}))"
//	-> {'outer': [{'k': "v'x"}, 1.0, None]}
func TestRepr_Nested(t *testing.T) {
	in := Ordered{{K: "outer", V: []any{
		Ordered{{K: "k", V: "v'x"}},
		1.0,
		nil,
	}}}
	want := `{'outer': [{'k': "v'x"}, 1.0, None]}`
	if got := Repr(in); got != want {
		t.Fatalf("Repr = %s, want %s", got, want)
	}
}

// A plain Go map has no insertion order, so Repr sorts its keys. This is the
// documented divergence from Python; the test pins it so nobody "fixes" it into
// range order (which Go randomizes).
func TestRepr_PlainMapIsSortedAndDeterministic(t *testing.T) {
	in := map[string]any{"b": 1, "a": 2, "c": nil}
	want := `{'a': 2, 'b': 1, 'c': None}`
	for i := 0; i < 20; i++ {
		if got := Repr(in); got != want {
			t.Fatalf("Repr = %s, want %s", got, want)
		}
	}
}

func TestRepr_KVSliceIsAcceptedLikeOrdered(t *testing.T) {
	if got := Repr([]KV{{K: "z", V: 1}, {K: "a", V: 2}}); got != `{'z': 1, 'a': 2}` {
		t.Fatalf("Repr = %s", got)
	}
}

func TestRepr_PointerDerefAndNil(t *testing.T) {
	s := "hi"
	if got := Repr(&s); got != `'hi'` {
		t.Fatalf("Repr(&s) = %s", got)
	}
	var np *string
	if got := Repr(np); got != "None" {
		t.Fatalf("Repr((*string)(nil)) = %s", got)
	}
}

// Captured with:
//
//	python -c "print(str('raw'), repr('raw'), str(1.0), str(['a']), str(None))"
//	-> raw 'raw' 1.0 ['a'] None
func TestStr_MatchesPythonStr(t *testing.T) {
	if got := Str("raw"); got != "raw" {
		t.Fatalf("Str(string) = %q", got)
	}
	if got := Str(1.0); got != "1.0" {
		t.Fatalf("Str(1.0) = %q", got)
	}
	if got := Str([]string{"a"}); got != `['a']` {
		t.Fatalf("Str(list) = %q", got)
	}
	if got := Str(nil); got != "None" {
		t.Fatalf("Str(nil) = %q", got)
	}
	s := "p"
	if got := Str(&s); got != "p" {
		t.Fatalf("Str(*string) = %q", got)
	}
}

func TestOrdered_Get(t *testing.T) {
	o := Ordered{{K: "a", V: 1}, {K: "b", V: nil}}
	if v, ok := o.Get("a"); !ok || v != 1 {
		t.Fatalf("Get(a) = %v, %v", v, ok)
	}
	if v, ok := o.Get("b"); !ok || v != nil {
		t.Fatalf("Get(b) = %v, %v", v, ok)
	}
	if _, ok := o.Get("missing"); ok {
		t.Fatalf("Get(missing) reported present")
	}
}
