package output

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// Every expectation in this file is CPython + pydantic 2.13.4 ground truth from
// ~/.agentfield/packages/cloudsecurity-af/venv/bin/python; the generator
// expression is quoted next to each table.

// TestPydanticFloat pins pydantic's float spelling, which agrees with repr()
// on the DIGITS and differs on the notation threshold and the exponent width.
//
//	class F(BaseModel): v: float
//	F(v=x).model_dump_json()
func TestPydanticFloat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
		// pyRepr is what pyfmt.FormatFloat (json.dumps / repr) produces, quoted
		// where it DIFFERS so the divergence is visible in the source.
		pyRepr string
	}{
		{0.0, "0.0", "0.0"},
		{math.Copysign(0, -1), "-0.0", "-0.0"},
		{1.0, "1.0", "1.0"},
		{0.5, "0.5", "0.5"},
		{0.1, "0.1", "0.1"},
		{3.141592653589793, "3.141592653589793", "3.141592653589793"},

		// The fixed/scientific threshold sits one decade lower than repr's.
		{1e-4, "0.0001", "0.0001"},
		{1e-5, "0.00001", "1e-05"},
		{9.87e-5, "0.0000987", "9.87e-05"},
		{1.5e-5, "0.000015", "1.5e-05"},
		{1.5000000000000002e-05, "0.000015000000000000002", "1.5000000000000002e-05"},

		// Below that, scientific — with an UNPADDED exponent.
		{1e-6, "1e-6", "1e-06"},
		{1e-7, "1e-7", "1e-07"},
		{1e-9, "1e-9", "1e-09"},
		{1e-10, "1e-10", "1e-10"},
		{5e-324, "5e-324", "5e-324"},

		// The upper threshold is repr's: fixed through 1e15, scientific from 1e16.
		{1e15, "1000000000000000.0", "1000000000000000.0"},
		{1e16, "1e+16", "1e+16"},
		{1.5e16, "1.5e+16", "1.5e+16"},
		{-1e16, "-1e+16", "-1e+16"},
		{1.7976931348623157e308, "1.7976931348623157e+308", "1.7976931348623157e+308"},

		{-7.25, "-7.25", "-7.25"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := pydanticFloat(tc.in); got != tc.want {
				t.Errorf("pydanticFloat(%v) = %q, want %q", tc.in, got, tc.want)
			}
			if got := pyfmt.FormatFloat(tc.in); got != tc.pyRepr {
				t.Errorf("pyfmt.FormatFloat(%v) = %q, want %q (repr spelling)", tc.in, got, tc.pyRepr)
			}
			// Whatever the spelling, both must round-trip to the same float —
			// that is what lets generate_json dump with one and re-read with
			// the other.
			var back float64
			if err := json.Unmarshal([]byte(tc.want), &back); err != nil {
				t.Fatalf("pydantic spelling %q is not valid JSON: %v", tc.want, err)
			}
			if back != tc.in && !(math.Signbit(back) == math.Signbit(tc.in) && back == tc.in) {
				t.Errorf("round trip of %q gave %v, want %v", tc.want, back, tc.in)
			}
		})
	}
}

// TestPydanticNonFiniteIsNull pins pydantic's ser_json_inf_nan="null" default,
// which is the one place its numbers are not just repr under another name.
//
//	F(v=float("nan")).model_dump_json() == '{"v":null}'
func TestPydanticNonFiniteIsNull(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if got := pydanticFloat(v); got != "null" {
			t.Errorf("pydanticFloat(%v) = %q, want null", v, got)
		}
		// pyTree drops them to nil BEFORE either renderer sees them, so the
		// pretty path (json.dumps, which would emit the bare NaN token) agrees.
		if got := pyTree(v); got != nil {
			t.Errorf("pyTree(%v) = %v, want nil", v, got)
		}
	}
}

// TestPydanticString pins pydantic-core's escaping: only `"`, `\` and the C0
// controls. Everything else — DEL, U+2028/9, <>&/, all non-ASCII — is raw.
//
//	class S(BaseModel): v: str
//	S(v=s).model_dump_json()
func TestPydanticString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"quote", "a\"b", `"a\"b"`},
		{"backslash", `a\b`, `"a\\b"`},
		{"short escapes", "\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"other control", "\x00\x01\x1f", "\"\\u0000\\u0001\\u001f\""},
		{"DEL is raw", "\x7f", "\"\x7f\""},
		{"html chars are raw", "<a> & </a> /", `"<a> & </a> /"`},
		{"non-ascii is raw", "héllo — 世界 🚀", `"héllo — 世界 🚀"`},
		{"line separators are raw", "\u2028\u2029", "\"\u2028\u2029\""},
		{"empty", "", `""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			writePydanticString(&b, tc.in)
			if got := b.String(); got != tc.want {
				t.Fatalf("writePydanticString(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// The two spellings must genuinely DIFFER where Python's do:
			// json.dumps escapes every non-ASCII rune, pydantic escapes none.
			if tc.name == "non-ascii is raw" {
				py := pyfmt.DumpsCompact(tc.in)
				if strings.Contains(py, "é") || !strings.Contains(py, `\u00e9`) {
					t.Errorf("pyfmt.DumpsCompact = %s; it must ensure_ascii-escape where pydantic does not", py)
				}
			}
		})
	}
}

// TestPydanticISO pins the datetime spelling model_dump_json uses, and that it
// is NOT schemas.Timestamp.ISOFormat().
//
//	class T(BaseModel): ts: datetime
//	T(ts=d).model_dump_json()
func TestPydanticISO(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want string
		iso  string
	}{
		{
			"utc with microseconds",
			time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC),
			"2026-01-02T03:04:05.123456Z",
			"2026-01-02T03:04:05.123456+00:00",
		},
		{
			"utc whole second",
			time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			"2026-01-02T03:04:05Z",
			"2026-01-02T03:04:05+00:00",
		},
		{
			"utc one microsecond",
			time.Date(2026, 1, 2, 3, 4, 5, 1000, time.UTC),
			"2026-01-02T03:04:05.000001Z",
			"2026-01-02T03:04:05.000001+00:00",
		},
		{
			"offset zone",
			time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.FixedZone("+0530", 5*3600+30*60)),
			"2026-01-02T03:04:05.123456+05:30",
			"2026-01-02T03:04:05.123456+05:30",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := schemas.NewTimestamp(tc.in)
			if got := pydanticISO(ts); got != tc.want {
				t.Errorf("pydanticISO = %q, want %q", got, tc.want)
			}
			if got := ts.ISOFormat(); got != tc.iso {
				t.Errorf("ISOFormat = %q, want %q", got, tc.iso)
			}
		})
	}
}

// TestPyTreeStructOrderAndTags pins the struct walk: declaration order (which
// is pydantic field order), json tag names, `json:"-"` and embedded flattening.
func TestPyTreeStructOrderAndTags(t *testing.T) {
	type inner struct {
		Deep string `json:"deep"`
	}
	type Embedded struct {
		First int `json:"first"`
	}
	type sample struct {
		Embedded
		Zed     string `json:"zed"`
		Alpha   int    `json:"alpha"`
		Skipped string `json:"-"`
		Nested  inner  `json:"nested"`
		NoTag   bool
	}

	tree := pyTree(sample{
		Embedded: Embedded{First: 1},
		Zed:      "z",
		Alpha:    2,
		Skipped:  "never",
		Nested:   inner{Deep: "d"},
		NoTag:    true,
	})
	pairs, ok := tree.(pyfmt.Ordered)
	if !ok {
		t.Fatalf("pyTree(struct) = %T, want pyfmt.Ordered", tree)
	}
	var keys []string
	for _, p := range pairs {
		keys = append(keys, p.K)
	}
	want := "first,zed,alpha,nested,NoTag"
	if strings.Join(keys, ",") != want {
		t.Fatalf("keys = %v, want %s", keys, want)
	}
	if got := pydanticDumps(tree); got != `{"first":1,"zed":"z","alpha":2,"nested":{"deep":"d"},"NoTag":true}` {
		t.Fatalf("pydanticDumps = %s", got)
	}
}

// TestPyTreeSortsMapKeys pins the documented ordering deviation: a Go map has
// no insertion order, so keys are sorted in BOTH spellings.
func TestPyTreeSortsMapKeys(t *testing.T) {
	tree := pyTree(map[string]int{"zebra": 1, "Apple": 2, "apple": 3})
	if got, want := pydanticDumps(tree), `{"Apple":2,"apple":3,"zebra":1}`; got != want {
		t.Fatalf("pydanticDumps = %s, want %s", got, want)
	}
	if got, want := pyfmt.Dumps(tree, 0), `{"Apple": 2, "apple": 3, "zebra": 1}`; got != want {
		t.Fatalf("pyfmt.Dumps = %s, want %s", got, want)
	}
}

// TestPyTreeNilsAndPointers pins that nil pointers, nil slices and nil maps all
// render as null (encoding/json semantics, which pyfmt.Dumps shares) and that a
// populated pointer is transparent.
func TestPyTreeNilsAndPointers(t *testing.T) {
	type sample struct {
		Ptr   *string           `json:"ptr"`
		Slice []int             `json:"slice"`
		Map   map[string]string `json:"map"`
	}
	if got, want := pydanticDumps(pyTree(sample{})), `{"ptr":null,"slice":null,"map":null}`; got != want {
		t.Fatalf("zero value = %s, want %s", got, want)
	}
	s := "v"
	filled := sample{Ptr: &s, Slice: []int{}, Map: map[string]string{}}
	if got, want := pydanticDumps(pyTree(filled)), `{"ptr":"v","slice":[],"map":{}}`; got != want {
		t.Fatalf("filled = %s, want %s", got, want)
	}
}

// TestPyTreeKeepsIntegersIntegral guards the one lossy path: a typed int stays
// an int in both spellings, and a json.Number survives untouched — which is how
// a caller that decodes `metadata` with UseNumber gets exact parity.
func TestPyTreeKeepsIntegersIntegral(t *testing.T) {
	type sample struct {
		N int   `json:"n"`
		U uint8 `json:"u"`
	}
	if got, want := pydanticDumps(pyTree(sample{N: 7, U: 3})), `{"n":7,"u":3}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}

	dec := json.NewDecoder(strings.NewReader(`{"i":7,"f":1.5,"e":0.00001}`))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := pydanticDumps(pyTree(doc)), `{"e":0.00001,"f":1.5,"i":7}`; got != want {
		t.Fatalf("json.Number path = %s, want %s", got, want)
	}
	// The documented divergence: without UseNumber, an untyped integer becomes
	// a float64 and renders as "1.0" where Python renders "1".
	var lossy any
	if err := json.Unmarshal([]byte(`{"i":7}`), &lossy); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := pydanticDumps(pyTree(lossy)), `{"i":7.0}`; got != want {
		t.Fatalf("plain-decode path = %s, want %s (documented divergence)", got, want)
	}
}

// TestPydanticDumpsHasNoWhitespace pins the separators: pydantic writes "," and
// ":" with no spaces, where json.dumps writes ", " and ": ".
func TestPydanticDumpsHasNoWhitespace(t *testing.T) {
	tree := pyfmt.Ordered{{K: "a", V: int64(1)}, {K: "b", V: []any{int64(1), int64(2)}}}
	if got, want := pydanticDumps(tree), `{"a":1,"b":[1,2]}`; got != want {
		t.Fatalf("pydanticDumps = %s, want %s", got, want)
	}
	if got, want := pyfmt.DumpsCompact(tree), `{"a": 1, "b": [1, 2]}`; got != want {
		t.Fatalf("pyfmt.DumpsCompact = %s, want %s", got, want)
	}
}

// TestPyTreeSkipsUnexportedEmbeddedType documents the one gap pyTree shares
// with pyfmt.Dumps and afx.ToMap: an embedded field whose TYPE is unexported is
// SKIPPED rather than flattened. encoding/json promotes its exported fields, but
// reflect refuses to read through an unexported field. No struct in the port has
// one; the test exists so a future one fails loudly here rather than silently
// losing keys from an artifact.
func TestPyTreeSkipsUnexportedEmbeddedType(t *testing.T) {
	type hidden struct {
		Inner string `json:"inner"`
	}
	type sample struct {
		hidden
		Kept string `json:"kept"`
	}

	got := pydanticDumps(pyTree(sample{hidden: hidden{Inner: "i"}, Kept: "k"}))
	if got != `{"kept":"k"}` {
		t.Fatalf("pyTree = %s, want {\"kept\":\"k\"} (the documented gap)", got)
	}
	// encoding/json disagrees, which is exactly what the doc comment says.
	std, _ := json.Marshal(sample{hidden: hidden{Inner: "i"}, Kept: "k"})
	if string(std) != `{"inner":"i","kept":"k"}` {
		t.Fatalf("encoding/json = %s; the documented gap description is stale", std)
	}
}
