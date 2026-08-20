package pyfmt

import "testing"

// This file is the Python-ground-truth table internal/agents/recon carried for
// its own package-local json.dumps copy before Dumps landed. The copy was
// deleted at integration time and the table moved here verbatim, so the
// coverage it provided over the RECON value model
//
//	nil | bool | string | int | float64 | []any | Ordered
//
// survives against the canonical encoder.
//
// ONE BEHAVIOUR WAS DELIBERATELY DROPPED with the copy: recon's writer had a
// `default=str` fallback that rendered an unknown Go type as a JSON string,
// matching `json.dump(..., default=str)`. Dumps instead walks an unknown struct
// into a JSON object. It is unreachable here — ctyToValue maps every Terraform
// value into the model above before it is written, and orderCloudConfig only
// ever holds JSON-decoded values — so no output byte changes; see
// internal/agents/recon/doc.go.

func TestDumps_ReconValueModelGroundTruth(t *testing.T) {
	cases := []struct {
		name   string
		value  any
		indent int
		want   string
	}{
		{"empty object", Ordered{}, 2, "{}"},
		{"empty array", []any{}, 2, "[]"},
		{"one key", Ordered{{K: "a", V: 1}}, 2, "{\n  \"a\": 1\n}"},
		{
			"nested containers",
			Ordered{
				{K: "a", V: []any{1, 2}},
				{K: "b", V: Ordered{{K: "c", V: nil}}},
			},
			2,
			"{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": {\n    \"c\": null\n  }\n}",
		},
		{
			// The whole reason Ordered is used instead of a Go map:
			// insertion order survives, it is NOT sorted.
			"insertion order is preserved",
			Ordered{{K: "z", V: 1}, {K: "a", V: 2}},
			2,
			"{\n  \"z\": 1,\n  \"a\": 2\n}",
		},
		{
			"string escapes",
			Ordered{{K: "s", V: "a\"b\\c\td\ne"}},
			2,
			"{\n  \"s\": \"a\\\"b\\\\c\\td\\ne\"\n}",
		},
		{
			// ensure_ascii=True, including a surrogate pair above the BMP.
			"non-ascii is escaped",
			Ordered{{K: "u", V: "café ☃ 😀"}},
			2,
			"{\n  \"u\": \"caf\\u00e9 \\u2603 \\ud83d\\ude00\"\n}",
		},
		{
			// Go's encoding/json would emit \u003c \u003e \u0026 here.
			"html characters are not escaped",
			Ordered{{K: "html", V: `<a href="x">&amp;</a>`}},
			2,
			"{\n  \"html\": \"<a href=\\\"x\\\">&amp;</a>\"\n}",
		},
		{
			"floats use python repr",
			Ordered{
				{K: "f", V: 1.0},
				{K: "g", V: 1.5},
				{K: "h", V: reconNegZero()},
				{K: "i", V: 1e16},
				{K: "j", V: 1e-5},
			},
			2,
			"{\n  \"f\": 1.0,\n  \"g\": 1.5,\n  \"h\": -0.0,\n  \"i\": 1e+16,\n  \"j\": 1e-05\n}",
		},
		{
			"ints stay ints",
			Ordered{{K: "i", V: 2}, {K: "neg", V: -3}},
			2,
			"{\n  \"i\": 2,\n  \"neg\": -3\n}",
		},
		{
			"literals",
			Ordered{{K: "t", V: true}, {K: "f", V: false}, {K: "n", V: nil}},
			2,
			"{\n  \"t\": true,\n  \"f\": false,\n  \"n\": null\n}",
		},
		{
			"deep nesting indents cumulatively",
			Ordered{{K: "nested", V: []any{
				Ordered{{K: "a", V: 1}},
				Ordered{{K: "b", V: []any{2, []any{3}}}},
			}}},
			2,
			"{\n  \"nested\": [\n    {\n      \"a\": 1\n    },\n    {\n      \"b\": [\n        2,\n        [\n          3\n        ]\n      ]\n    }\n  ]\n}",
		},
		{
			// indent<=0 selects json.dumps(x) with ", " / ": " separators.
			"compact form",
			Ordered{{K: "a", V: 1}, {K: "b", V: []any{1, 2}}},
			0,
			`{"a": 1, "b": [1, 2]}`,
		},
		{
			"control characters",
			Ordered{{K: "del", V: "\x7f"}, {K: "ctl", V: "\x00\x1f"}},
			2,
			"{\n  \"del\": \"\\u007f\",\n  \"ctl\": \"\\u0000\\u001f\"\n}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Dumps(tc.value, tc.indent); got != tc.want {
				t.Errorf("Dumps mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func reconNegZero() float64 {
	z := 0.0
	return -z
}

// pyDumps must render a Go map deterministically even though Python would have
// used insertion order — the documented divergence.
func TestDumps_ReconValueModelPlainMapKeysAreSorted(t *testing.T) {
	m := map[string]any{"z": 1, "a": 2, "m": 3}
	want := "{\n  \"a\": 2,\n  \"m\": 3,\n  \"z\": 1\n}"
	for i := 0; i < 20; i++ {
		if got := Dumps(m, 2); got != want {
			t.Fatalf("iteration %d: got %q want %q", i, got, want)
		}
	}
}
