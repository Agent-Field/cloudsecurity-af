package pyfmt

import (
	"encoding/json"
	"math"
)

// ---------------------------------------------------------------------------
// Python set / dict keys over the json.load value model
// ---------------------------------------------------------------------------

// SetKey is a comparable stand-in for a Python dict/set key drawn from the
// Load value model (nil | bool | string | int | float64 | []any | Ordered).
//
// It exists because two ported functions key a dict and several sets by a
// value read straight out of a model-authored JSON file — `node.get("resource_id")`
// in build_graph_context_for_hunter (internal/agents/util) and
// `edge.get("source", "")` in _filter_graph_for_findings (internal/agents/chain).
// That value is a string in every file this port's own deterministic builders
// produce, but graph.json is also authored by the LLM when
// resource_graph_builder falls back to the harness, so `null`, a number or a
// bool can and do appear there. Python compares those BY VALUE, so a JSON null
// endpoint really does join the id set and really does keep its node in the
// filtered graph; a Go `map[string]bool` silently drops it.
//
// Equality reproduces CPython's:
//
//	None       distinct from "" and from the string "None"
//	"5"        distinct from 5
//	5 == 5.0   the same key (Python hashes them into one slot)
//	True == 1  the same key, and False == 0
//
// DIVERGENCE (deliberate, unreachable from a real graph file): a list/dict id
// raises `TypeError: unhashable type` in Python; SetKey renders it with Repr
// and keeps going rather than crashing the reasoner.
type SetKey struct {
	kind byte    // 'N' none, 'S' string, 'I' integral number, 'F' non-integral float, 'O' repr-rendered
	text string  // the string itself for 'S', Repr(v) for 'O'
	i    int64   // 'I'
	f    float64 // 'F'
}

// KeyOf maps a Load-model value onto its Python set key.
func KeyOf(v any) SetKey {
	switch x := v.(type) {
	case nil:
		return SetKey{kind: 'N'}
	case string:
		return SetKey{kind: 'S', text: x}
	case bool:
		// Python: hash(True) == hash(1) and True == 1.
		if x {
			return SetKey{kind: 'I', i: 1}
		}
		return SetKey{kind: 'I', i: 0}
	case int:
		return SetKey{kind: 'I', i: int64(x)}
	case int64:
		return SetKey{kind: 'I', i: x}
	case json.Number:
		// An arbitrary-precision Python int (see loadNumber). Within int64 it
		// shares the ordinary int slot; beyond it, equal literals still share a
		// slot because Repr is the exact digits.
		if n, err := x.Int64(); err == nil {
			return SetKey{kind: 'I', i: n}
		}
		return SetKey{kind: 'O', text: Repr(x)}
	case float64:
		// Python: 5.0 == 5, so an integral float shares the int's slot.
		if !math.IsNaN(x) && !math.IsInf(x, 0) && x == math.Trunc(x) &&
			x >= math.MinInt64 && x <= math.MaxInt64 {
			return SetKey{kind: 'I', i: int64(x)}
		}
		return SetKey{kind: 'F', f: x}
	default:
		return SetKey{kind: 'O', text: Repr(x)}
	}
}

// KeySet is a Python set of Load-model values with a deterministic,
// first-insertion iteration order.
//
// Python parity NOTE — THE ORDER IS THE DIVERGENCE. Python iterates a `set`,
// whose order depends on hashing and is therefore randomized per process
// (PYTHONHASHSEED). The port contract requires determinism, so this type
// remembers insertion order. Membership semantics are unchanged, and callers
// that only test membership (e.g. _filter_graph_for_findings) are unaffected
// either way.
type KeySet struct {
	index map[SetKey]struct{}
	order []SetKey
}

// NewKeySet returns an empty set.
func NewKeySet() *KeySet {
	return &KeySet{index: map[SetKey]struct{}{}}
}

// Add inserts v, remembering its first-insertion position.
func (s *KeySet) Add(v any) {
	k := KeyOf(v)
	if _, ok := s.index[k]; ok {
		return
	}
	s.index[k] = struct{}{}
	s.order = append(s.order, k)
}

// Has ports `v in s`.
func (s *KeySet) Has(v any) bool {
	_, ok := s.index[KeyOf(v)]
	return ok
}

// Keys returns the members in first-insertion order.
func (s *KeySet) Keys() []SetKey { return s.order }

// Len is `len(s)`.
func (s *KeySet) Len() int { return len(s.order) }

// Clone returns an independent copy, the way `a | b` and `set(a)` do in Python.
func (s *KeySet) Clone() *KeySet {
	out := &KeySet{index: make(map[SetKey]struct{}, len(s.index)), order: append([]SetKey(nil), s.order...)}
	for k := range s.index {
		out.index[k] = struct{}{}
	}
	return out
}
