package util

import (
	"encoding/json"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// This file is the minimal Python-value layer build_graph_context_for_hunter
// needs in order to behave like `json.load(f)` followed by dict/list/f-string
// operations on whatever came back.
//
// The value model is exactly the one json.load produces:
//
//	nil | bool | string | int | float64 | []any | pyfmt.Ordered
//
// pyfmt.Ordered (a []pyfmt.KV) stands in for a Python dict and preserves
// INSERTION ORDER, which is observable in the prompt text (see doc.go).
//
// CONSOLIDATION (integration): this file used to carry its own unexported,
// order-preserving json.load copy, as did internal/agents/recon and
// internal/agents/chain. All three were byte-identical apart from their doc
// comments and were folded into pyfmt.Load, whose tests are the merged union of
// the three local suites. The helpers below — the dict/list/truthiness/set
// layer — are what actually belongs to this package.

// ---------------------------------------------------------------------------
// dict / list / truthiness helpers
// ---------------------------------------------------------------------------

// pyDict is the `isinstance(x, dict)` test plus the unwrap, in one step.
func pyDict(v any) (pyfmt.Ordered, bool) {
	o, ok := v.(pyfmt.Ordered)
	return o, ok
}

// pyList is the `isinstance(x, list)` test plus the unwrap.
func pyList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

// dictGet ports `d.get(key)` — the value, or nil when absent (Python None).
func dictGet(d pyfmt.Ordered, key string) any {
	v, _ := d.Get(key)
	return v
}

// dictGetDefault ports `d.get(key, fallback)`.
//
// The two forms are NOT interchangeable in the ported function and the
// difference is observable: build_graph_context_for_hunter reads a node's id
// as `node.get("resource_id", "")` when keying all_nodes_by_id but as
// `node.get("resource_id")` when building relevant_node_ids, so a node with no
// id contributes "" to one and None to the other.
func dictGetDefault(d pyfmt.Ordered, key string, fallback any) any {
	if v, ok := d.Get(key); ok {
		return v
	}
	return fallback
}

// pyLen ports len(x) for the kinds json.load can produce.
//
// Python parity: len() of a non-sized object (None, a number, a bool) raises
// TypeError. There is no error channel on build_graph_context_for_hunter, and
// every call site here is a `.get(key, [])` whose default is a list, so the
// only way to reach a non-sized value is a hand-written graph/inventory file
// with e.g. `"nodes": 3`. Go reports 0 for those instead of crashing the
// reasoner; the divergence is deliberate and confined to malformed input.
func pyLen(v any) int {
	switch x := v.(type) {
	case pyfmt.Ordered:
		return len(x)
	case []any:
		return len(x)
	case string:
		return len([]rune(x)) // Python len() counts code points
	}
	return 0
}

// pyTruthy ports Python's truth-value testing for this value model: None,
// False, 0, 0.0, "" and every empty container are falsy; everything else is
// truthy.
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case json.Number:
		// An arbitrary-precision Python int (see pyfmt.loadNumber): truthy
		// unless it is zero.
		f, err := x.Float64()
		return err != nil || f != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case pyfmt.Ordered:
		return len(x) > 0
	}
	return true
}

// ---------------------------------------------------------------------------
// set / dict keys
// ---------------------------------------------------------------------------

// pyKey / keySet are the Python set-key semantics this file needs, shared with
// internal/agents/chain's _filter_graph_for_findings port. The implementation
// (and the divergence notes) live in pyfmt.SetKey / pyfmt.KeySet; these aliases
// keep the Python-shaped lowercase spelling the ported code below reads with.
type pyKey = pyfmt.SetKey

func keyOf(v any) pyKey { return pyfmt.KeyOf(v) }

type keySet = pyfmt.KeySet

func newKeySet() *keySet { return pyfmt.NewKeySet() }
