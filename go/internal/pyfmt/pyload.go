package pyfmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// json.load() / json.loads()
// ---------------------------------------------------------------------------

// Load is the DECODING half of the json.dumps parity layer: it reproduces
// CPython's `json.load(f)` / `json.loads(s)` for the value model Dumps writes.
//
//	JSON object  -> Ordered, in DOCUMENT order (never sorted)
//	JSON array   -> []any
//	JSON number  -> int when the LITERAL has no "." and no exponent, else float64
//	JSON string  -> string
//	true/false   -> bool
//	null         -> nil
//
// so the model is exactly
//
//	nil | bool | string | int | float64 | []any | Ordered
//
// and Dumps(Load(b), 2) is the identity for any document CPython wrote with
// `json.dumps(x, indent=2)`.
//
// WHY THIS EXISTS AT ALL — encoding/json's `map[string]any` decode cannot be
// used anywhere the decoded bytes are re-emitted, because a Go map has no order
// and every renderer in this port therefore SORTS its keys (see the map-key
// deviation documented on Dumps). Python dicts keep the file's order across a
// read-modify-write, and that order is observable in three places in this port:
//
//   - _graph_builder_fast reads inventory.json and copies a filtered view of
//     each resource's `config` into the graph node's `config_summary`, whose
//     order reaches graph.json (internal/agents/recon);
//   - build_graph_context_for_hunter interpolates `config_summary` with an
//     f-string, i.e. a CPython dict repr, straight into the hunter prompt
//     (internal/agents/util);
//   - _build_parent_prompt reads graph.json and re-emits a filtered view of it
//     into the CHAIN parent prompt via json.dumps (internal/agents/chain).
//
// CONSOLIDATION NOTE: this function was written three times independently, once
// per consumer package (recon/pyjson.go, util/pyvalue.go, chain/pyload.go),
// while Dumps was still being landed and pyfmt was owned by a different agent.
// The three copies were byte-identical apart from their doc comments; they were
// folded into this one at integration time and their tests merged below.
//
// The int/float split is observable and is not an implementation detail:
// f"{2}" is "2" while f"{2.0}" is "2.0", and Dumps renders int 2 as `2` and
// float64 2.0 as `2.0`.
func Load(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	v, err := loadValue(dec)
	if err != nil {
		return nil, err
	}
	// json.load rejects trailing content with "Extra data"; so does this.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("extra data after top-level value")
	}
	return v, nil
}

func loadValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return loadFromToken(dec, tok)
}

func loadFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := Ordered{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				val, err := loadValue(dec)
				if err != nil {
					return nil, err
				}
				// Python parity: a repeated key overwrites in place, keeping
				// the FIRST occurrence's position (dict assignment semantics).
				replaced := false
				for i := range obj {
					if obj[i].K == key {
						obj[i].V = val
						replaced = true
						break
					}
				}
				if !replaced {
					obj = append(obj, KV{K: key, V: val})
				}
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := loadValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %q", t)
	case json.Number:
		return loadNumber(string(t)), nil
	case string, bool, nil:
		return t, nil
	}
	return nil, fmt.Errorf("unexpected token %T", tok)
}

// loadNumber maps a JSON number literal onto Python's int/float split.
//
// Python ints are arbitrary precision and Go's int is not, so an integer
// literal that overflows `int` is returned as a json.Number holding the literal
// rather than degraded to a float64. That is not a theoretical case: the port's
// OWN writer produces such a literal — a Terraform `big_port =
// 12345678901234567890` is carried through recon.ctyToValue as a json.Number
// and written verbatim into inventory.json, which graph builder reads back
// through here on its way into graph.json's `config_summary` and the hunter
// prompt. Repr, KeyOf, pyTruthy and pyTypeName all treat an integral
// json.Number as the Python int it stands for, so the value behaves like one
// everywhere the loaded model is consumed.
func loadNumber(lit string) any {
	if !strings.ContainsAny(lit, ".eE") {
		if n, err := strconv.Atoi(lit); err == nil {
			return n
		}
		// A JSON integer token is `-?\d+`, so the only way Atoi fails here is
		// an overflow of Go's int — exactly the case Python keeps exact.
		return json.Number(lit)
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return lit
	}
	return f
}
