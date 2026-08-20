// Package pyfmt reproduces the CPython value-rendering primitives that the
// cloudsecurity-af Python node relies on when it builds prompt text, note
// messages and JSON payloads:
//
//   - Round   == Python's builtin round(x, ndigits) (correct decimal rounding
//     of the exact binary value, ties to even)
//   - FormatFloat == Python's str(float) / repr(float)
//   - Repr    == Python's repr() for the value kinds these prompts interpolate
//     (str, bool, None, int, float, list, dict)
//   - Str     == Python's str() (repr for containers, bare text for strings)
//
// Go's own strconv/fmt disagree with CPython on all four (Go's %g flips to
// scientific notation at 1e6, Go's %v renders maps unordered and with Go
// syntax, Go has no half-even decimal round). Every Go port that renders a
// number or a container INTO PROMPT TEXT must go through this package, because
// the LLM sees the difference and the golden tests pin it.
//
// Every behaviour here was verified against the repo's own interpreter:
//
//	~/.agentfield/packages/cloudsecurity-af/venv/bin/python   (CPython 3.11.12)
//
// The exact one-liners and their captured output live in pyfmt_test.go next to
// the assertions they justify.
package pyfmt

import (
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// round()
// ---------------------------------------------------------------------------

// ndigitsMax / ndigitsMin mirror CPython's NDIGITS_MAX / NDIGITS_MIN guards in
// Objects/floatobject.c:double_round. Beyond them the answer is decided without
// touching the decimal conversion at all: no double has a representable digit
// past 10**-323, and none survives rounding at 10**323.
const (
	ndigitsMax = 323
	ndigitsMin = -323
)

// Round ports Python's builtin round(x, ndigits) for float arguments.
//
// CPython (Objects/floatobject.c: double_round) converts the double to its
// EXACT decimal expansion with _Py_dg_dtoa in mode 3 (ndigits after the decimal
// point, ties-to-even), then parses that decimal string back with
// _Py_dg_strtod. The two facts that follow from "exact expansion" and that a
// naive `math.Floor(x*p+0.5)/p` gets wrong:
//
//	round(2.675, 2) == 2.67   # 2.675 is really 2.67499999999999982236431606
//	round(0.125, 2) == 0.12   # 0.125 is exact; tie -> even -> 2
//	round(0.375, 2) == 0.38   # 0.375 is exact; tie -> even -> 8
//
// This implementation reproduces both properties by carrying the value as an
// exact big.Rat (big.Rat.SetFloat64 is lossless for a finite float64), scaling
// by 10**ndigits, rounding half-to-even on the exact quotient, then converting
// back with big.Rat.Float64 — which, like strtod, returns the nearest double.
//
// Python parity: round() with no second argument returns an int; Go has no
// dynamic return type, so callers pass ndigits=0 and get the identical VALUE as
// a float64 (round(1.5) == 2 == Round(1.5, 0); round(2.5) == 2 == Round(2.5, 0)).
//
// Python parity: the sign of a zero result follows the sign of the input —
// round(-0.5, 0) is -0.0, not 0.0 — because CPython's strtod parses the "-0"
// that dtoa emitted.
//
// Python parity: a non-finite input is returned unchanged (round(inf, 2) is inf,
// round(nan, 2) is nan); CPython returns early for !isfinite(x).
func Round(x float64, ndigits int) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return x
	}
	// CPython: ndigits above NDIGITS_MAX always rounds x to itself; below
	// NDIGITS_MIN it always rounds to a signed zero.
	if ndigits > ndigitsMax {
		return x
	}
	if ndigits < ndigitsMin {
		return math.Copysign(0, x)
	}
	if x == 0 {
		// Short-circuits big.Rat and preserves -0.0 (big.Rat has no signed zero).
		return x
	}

	exact := new(big.Rat).SetFloat64(x) // lossless for finite float64
	scale := pow10Rat(ndigits)
	scaled := new(big.Rat).Mul(exact, scale)

	rounded := roundHalfEvenRat(scaled)

	out := new(big.Rat).SetInt(rounded)
	out.Quo(out, scale)
	f, _ := out.Float64()

	if f == 0 {
		// big.Rat cannot carry -0.0; restore CPython's signed zero.
		return math.Copysign(0, x)
	}
	return f
}

// pow10Rat returns 10**n as an exact rational, for positive or negative n.
func pow10Rat(n int) *big.Rat {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	p := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(abs)), nil)
	if n >= 0 {
		return new(big.Rat).SetInt(p)
	}
	return new(big.Rat).SetFrac(big.NewInt(1), p)
}

// roundHalfEvenRat rounds an exact rational to the nearest integer, ties to
// even — the rule _Py_dg_dtoa applies to the exact decimal expansion.
func roundHalfEvenRat(r *big.Rat) *big.Int {
	num, den := r.Num(), r.Denom() // den > 0 by big.Rat invariant
	q := new(big.Int)
	rem := new(big.Int)
	q.QuoRem(num, den, rem) // truncated toward zero; rem carries num's sign

	twiceRem := new(big.Int).Abs(rem)
	twiceRem.Lsh(twiceRem, 1)

	cmp := twiceRem.Cmp(den)
	// q.Bit(0) is the two's-complement low bit, so parity is correct for
	// negative quotients too (-3 is odd, -4 is even).
	if cmp > 0 || (cmp == 0 && q.Bit(0) == 1) {
		if num.Sign() < 0 {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	return q
}

// ---------------------------------------------------------------------------
// str(float) / repr(float)
// ---------------------------------------------------------------------------

// FormatFloat ports Python's str(float), which since Python 3.1 is identical to
// repr(float): the SHORTEST decimal string that round-trips to the same double,
// rendered so it always reads as a float.
//
// CPython (Python/pystrtod.c: format_float_short, format_code 'r') picks fixed
// vs. scientific notation from the decimal point position `decpt` — the value is
// 0.d1d2... * 10**decpt:
//
//	decpt <= -4 || decpt > 16  ->  scientific
//	otherwise                  ->  fixed, with a forced ".0" when integral
//
// The 1e16 cutoff is deliberate in CPython ("we used to convert at 1e17, but
// that gives odd-looking results"), which is why:
//
//	str(1e15) == '1000000000000000.0'      # decpt 16 -> fixed
//	str(1e16) == '1e+16'                   # decpt 17 -> scientific
//	str(0.0001) == '0.0001'                # decpt -3 -> fixed
//	str(0.00001) == '1e-05'                # decpt -4 -> scientific
//
// Go's strconv 'g' verb with shortest precision is NOT a substitute: it flips to
// scientific at an exponent of 6, so it renders 1234567.0 as "1.234567e+06"
// where Python renders "1234567.0".
//
// Python parity: the special values print as 'inf', '-inf', 'nan' (no sign on
// nan), and negative zero prints as '-0.0'.
func FormatFloat(f float64) string {
	if math.IsNaN(f) {
		return "nan"
	}
	if math.IsInf(f, 1) {
		return "inf"
	}
	if math.IsInf(f, -1) {
		return "-inf"
	}

	sign := ""
	if math.Signbit(f) {
		sign = "-"
	}

	digits, decpt := ShortestDigits(math.Abs(f))

	if decpt <= -4 || decpt > 16 {
		return sign + sciNotation(digits, decpt)
	}
	return sign + fixedNotation(digits, decpt)
}

// ShortestDigits returns the shortest round-tripping significand digits of a
// non-negative finite float and its CPython `decpt` (the value is
// 0.<digits> * 10**decpt). It reuses strconv's shortest 'e' rendering, which
// solves the same Ryu/Grisu shortest-representation problem _Py_dg_dtoa does.
//
// It is EXPORTED because the digits are a spelling-independent primitive:
// internal/output/pydantic.go renders floats with pydantic's spelling (a
// different fixed/scientific threshold and an unpadded exponent) but needs the
// exact same significand. Two copies of a shortest-round-trip routine is
// precisely the kind of thing that drifts silently, so there is one.
func ShortestDigits(f float64) (digits string, decpt int) {
	s := strconv.FormatFloat(f, 'e', -1, 64) // e.g. "1.5e+16", "0e+00"
	ePos := strings.IndexByte(s, 'e')
	mant := s[:ePos]
	exp, err := strconv.Atoi(s[ePos+1:])
	if err != nil { // unreachable: strconv always emits a parseable exponent
		exp = 0
	}
	digits = strings.Replace(mant, ".", "", 1)
	return digits, exp + 1
}

// sciNotation renders <d>[.<rest>]e±XX, the exponent always signed and at least
// two digits wide (Python: '1e+16', '1e-05', '5e-324').
func sciNotation(digits string, decpt int) string {
	var b strings.Builder
	b.WriteByte(digits[0])
	if len(digits) > 1 {
		b.WriteByte('.')
		b.WriteString(digits[1:])
	}
	exp := decpt - 1
	b.WriteByte('e')
	if exp < 0 {
		b.WriteByte('-')
		exp = -exp
	} else {
		b.WriteByte('+')
	}
	es := strconv.Itoa(exp)
	if len(es) < 2 {
		b.WriteByte('0')
	}
	b.WriteString(es)
	return b.String()
}

// fixedNotation renders the digits with the decimal point at decpt, always
// keeping at least one digit on each side (Python: '0.0001', '100.0', '0.0').
func fixedNotation(digits string, decpt int) string {
	switch {
	case decpt <= 0:
		return "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return digits[:decpt] + "." + digits[decpt:]
	}
}

// ---------------------------------------------------------------------------
// repr() / str()
// ---------------------------------------------------------------------------

// KV is one entry of an insertion-ordered Python dict.
type KV struct {
	K string
	V any
}

// Ordered is an insertion-ordered Python dict. Repr renders it in slice order,
// which is what CPython does for a dict literal / a JSON-decoded dict. Build
// one wherever the Python source repr()s a dict whose key order is observable
// in prompt text.
type Ordered []KV

// Get returns the value for key and whether it was present (Python `d[k]` /
// `k in d`). First match wins, mirroring dict semantics for a well-formed
// Ordered.
func (o Ordered) Get(key string) (any, bool) {
	for _, kv := range o {
		if kv.K == key {
			return kv.V, true
		}
	}
	return nil, false
}

// Repr ports Python's repr() for the value kinds the ported prompt builders and
// error messages interpolate.
//
//	nil                -> None
//	bool               -> True / False
//	string             -> 'single quoted' (see reprString for the quote rules)
//	int kinds          -> decimal
//	float kinds        -> FormatFloat (repr(float) == str(float))
//	Ordered / []KV     -> {'k': 'v'} in slice order
//	map[string]any     -> {'k': 'v'} with keys SORTED (see the warning below)
//	any slice/array    -> ['a', 'b']
//	pointer            -> the pointee's repr, or None when nil
//
// WARNING — map key order: a Python dict preserves insertion order and repr()
// shows it, but a Go map has no order at all and ranging one is deliberately
// randomized. Rendering a map[string]any would therefore be non-deterministic,
// which the port contract forbids, so Repr SORTS map keys. That is a documented
// divergence from Python whenever the Python dict's insertion order was not
// already alphabetical. Use Ordered when the order is load-bearing (i.e. when
// the rendered text reaches an LLM or a golden test).
func Repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return reprString(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	case Ordered:
		return reprPairs(x)
	case []KV:
		return reprPairs(x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]KV, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, KV{K: k, V: x[k]})
		}
		return reprPairs(pairs)
	case map[string]string:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]KV, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, KV{K: k, V: x[k]})
		}
		return reprPairs(pairs)
	case json.Number:
		// pyfmt.Load and recon.ctyToValue use json.Number for a Python int that
		// overflows Go's int (and for any number whose literal must survive
		// verbatim). repr() of that value is the int's digits; a literal with a
		// fraction or an exponent was a float in Python and reprs as one.
		return jsonNumberLiteral(string(x))
	case int:
		return strconv.Itoa(x)
	case int8:
		return strconv.FormatInt(int64(x), 10)
	case int16:
		return strconv.FormatInt(int64(x), 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint8:
		return strconv.FormatUint(uint64(x), 10)
	case uint16:
		return strconv.FormatUint(uint64(x), 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float32:
		return FormatFloat(float64(x))
	case float64:
		return FormatFloat(x)
	case []string:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = reprString(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = Repr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return reprReflect(v)
}

// reprPairs renders {'k': v, ...} in the given order (CPython dict repr: keys
// are repr'd as strings, ": " between key and value, ", " between entries).
func reprPairs(pairs []KV) string {
	if len(pairs) == 0 {
		return "{}"
	}
	parts := make([]string, len(pairs))
	for i, kv := range pairs {
		parts[i] = reprString(kv.K) + ": " + Repr(kv.V)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// Str ports Python's str(): identical to repr() for every kind EXCEPT a bare
// string, which str() renders unquoted and unescaped. This is what an f-string
// `{value}` interpolation produces.
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if p, ok := v.(*string); ok {
		if p == nil {
			return "None"
		}
		return *p
	}
	return Repr(v)
}
