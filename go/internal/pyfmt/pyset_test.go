package pyfmt

import "testing"

// TestKeySet_PythonEqualityRules pins the CPython set semantics SetKey exists
// to reproduce. Ground truth (repo venv, python3.11):
//
//	>>> s = {None, "", "None", 5, "5"}; len(s)
//	5
//	>>> 5.0 in {5}, True in {1}, False in {0}, 1 in {True}
//	(True, True, True, True)
//	>>> "5" in {5}
//	False
func TestKeySet_PythonEqualityRules(t *testing.T) {
	s := NewKeySet()
	for _, v := range []any{nil, "", "None", 5, "5"} {
		s.Add(v)
	}
	if s.Len() != 5 {
		t.Fatalf("len = %d, want 5 distinct keys", s.Len())
	}
	s.Add(nil)
	if s.Len() != 5 {
		t.Fatalf("re-adding None changed len to %d", s.Len())
	}

	// 5 == 5.0 == (no bool here) — one slot.
	if !s.Has(5.0) {
		t.Error("5.0 not in {5}: Python hashes an integral float into the int's slot")
	}
	if s.Has("x") {
		t.Error("membership invented a member")
	}

	b := NewKeySet()
	b.Add(true)
	b.Add(false)
	if b.Len() != 2 {
		t.Fatalf("len({True, False}) = %d, want 2", b.Len())
	}
	if !b.Has(1) || !b.Has(0) || !b.Has(1.0) {
		t.Error("True/False must share a slot with 1/0 as Python does")
	}
	if b.Has("1") {
		t.Error(`"1" must not match True`)
	}
}

// A non-integral float keeps its own slot, and Keys() is first-insertion order
// (the deliberate divergence from Python's randomized set iteration).
func TestKeySet_FloatsAndInsertionOrder(t *testing.T) {
	s := NewKeySet()
	for _, v := range []any{"b", 1.5, "a", 1.5} {
		s.Add(v)
	}
	if s.Len() != 3 {
		t.Fatalf("len = %d, want 3", s.Len())
	}
	if !s.Has(1.5) || s.Has(1) {
		t.Error("1.5 must match itself and not the int 1")
	}
	got := s.Keys()
	if got[0] != KeyOf("b") || got[1] != KeyOf(1.5) || got[2] != KeyOf("a") {
		t.Errorf("Keys() = %v, want first-insertion order b, 1.5, a", got)
	}
}

// Clone is `set(a)`: independent storage, same members, same order.
func TestKeySet_CloneIsIndependent(t *testing.T) {
	a := NewKeySet()
	a.Add("x")
	b := a.Clone()
	b.Add("y")
	if a.Has("y") {
		t.Error("Clone shares storage with the original")
	}
	if !b.Has("x") {
		t.Error("Clone lost a member")
	}
}
