package util

import (
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

func TestPyLen(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int
	}{
		{"list", []any{1, 2, 3}, 3},
		{"dict", pyfmt.Ordered{{K: "a"}, {K: "b"}}, 2},
		{"str counts code points", "héllo", 5},
		{"empty", []any{}, 0},
		// Python raises TypeError for these; the port reports 0 rather than
		// failing the reasoner (see pyLen's doc comment).
		{"none", nil, 0},
		{"int", 5, 0},
	}
	for _, tc := range cases {
		if got := pyLen(tc.in); got != tc.want {
			t.Errorf("%s: pyLen = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestPyTruthy(t *testing.T) {
	falsy := []any{nil, false, "", 0, 0.0, []any{}, pyfmt.Ordered{}}
	for _, v := range falsy {
		if pyTruthy(v) {
			t.Errorf("pyTruthy(%#v) = true, want false", v)
		}
	}
	truthy := []any{true, "x", 1, -1, 0.5, []any{nil}, pyfmt.Ordered{{K: "a"}}}
	for _, v := range truthy {
		if !pyTruthy(v) {
			t.Errorf("pyTruthy(%#v) = false, want true", v)
		}
	}
}

// A Python set keyed on ids must not conflate None, "" and the string "None",
// nor a number with its string form.
func TestKeySet_DistinguishesPythonKinds(t *testing.T) {
	s := newKeySet()
	for _, v := range []any{nil, "", "None", 5, "5"} {
		s.Add(v)
	}
	if got := len(s.Keys()); got != 5 {
		t.Fatalf("expected 5 distinct keys, got %d", got)
	}
	s.Add(nil) // idempotent
	if got := len(s.Keys()); got != 5 {
		t.Fatalf("re-adding changed the size to %d", got)
	}
	if !s.Has("5") || !s.Has(5) || !s.Has(nil) {
		t.Error("membership lost a member")
	}
	if s.Has("x") {
		t.Error("membership invented a member")
	}
}

func TestDictGet_DefaultlessVersusDefaulted(t *testing.T) {
	d := pyfmt.Ordered{{K: "present", V: "yes"}}
	if got := dictGet(d, "absent"); got != nil {
		t.Errorf("dictGet on a missing key = %#v, want nil (Python None)", got)
	}
	if got := dictGetDefault(d, "absent", ""); got != "" {
		t.Errorf("dictGetDefault on a missing key = %#v, want \"\"", got)
	}
	if got := dictGetDefault(d, "present", "fallback"); got != "yes" {
		t.Errorf("dictGetDefault on a present key = %#v, want \"yes\"", got)
	}
}
