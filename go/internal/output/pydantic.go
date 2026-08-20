package output

import (
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
)

// This file ports the ONE thing json_output.py needs that pyfmt.Dumps cannot
// give it: pydantic v2's `BaseModel.model_dump_json()` spelling.
//
//	src/cloudsecurity_af/output/json_output.py:15
//	    full_json = result.model_dump_json()
//	    if not pretty: return full_json
//	    return json.dumps(json.loads(full_json), indent=2)
//
// So `generate_json` has TWO serializers in it, and they disagree:
//
//	                     pydantic model_dump_json      json.dumps
//	separators           ","  ":"                      ", "  ": "  (or indent)
//	non-ASCII            raw UTF-8                     \uXXXX (ensure_ascii)
//	DEL (0x7f)           raw                           
//	datetime             "…T03:04:05.123456Z"          (already a string)
//	1e-05                0.00001                       1e-05
//	1e-07                1e-7                          1e-07
//	NaN / ±Inf           null                          NaN / Infinity
//
// The pretty path is therefore NOT "dump the model with pyfmt": it is
// "dump the model with pydantic, parse it back, dump THAT with json.dumps".
// Both paths are driven from one intermediate tree here (pyTree), so the two
// spellings can never drift out of agreement about which value is at which key:
//
//	tree := pyTree(result)
//	compact := pydanticDumps(tree)   // == result.model_dump_json()
//	pretty  := pyfmt.Dumps(tree, 2)  // == json.dumps(json.loads(compact), indent=2)
//
// The round-trip is lossless because every float in the tree is rendered with
// shortest-round-trip digits by BOTH spellings, so json.loads recovers the
// identical float64.

// timestampType is schemas.Timestamp, the one Go type whose JSON spelling
// differs between the two serializers (isoformat "+00:00" vs pydantic "Z").
var timestampType = reflect.TypeOf(schemas.Timestamp{})

// jsonNumberType is json.Number, which appears in a `map[string]any` only when
// the caller decoded with json.Decoder.UseNumber.
var jsonNumberType = reflect.TypeOf(json.Number(""))

// pyTree converts a Go value into the value tree `json.loads(model_dump_json())`
// produces on the Python side.
//
// The mapping mirrors pyfmt.Dumps' own walk (declaration-ordered structs, json
// tags, sorted map keys, nil slices/maps as null) so the two renderers agree,
// with three pydantic-specific rules layered on top:
//
//   - schemas.Timestamp becomes the pydantic ISO string ("…Z" for UTC), because
//     that is what model_dump_json writes and therefore what json.loads sees.
//     Its own MarshalJSON emits the FastAPI/jsonable_encoder spelling
//     ("+00:00"), which is the reasoner-boundary format, not this one.
//   - A non-finite float becomes nil. pydantic's default
//     `ser_json_inf_nan="null"` writes `null` for NaN and ±Inf where
//     json.dumps would write the bare NaN/Infinity tokens, and since the pretty
//     path re-reads pydantic's output it sees `null` too.
//   - Integers stay integers (int64/uint64), so neither renderer turns 1 into
//     1.0.
//
// Known divergence — `metadata: dict[str, object]`: Go decodes an untyped JSON
// number into float64, so an INTEGER that arrived inside CloudSecurityScanResult.
// Metadata over the control-plane boundary renders as "1.0" where Python renders
// "1" (afx.Bind uses plain encoding/json, deliberately, see afx/bind.go). Every
// typed field is unaffected. Decode with json.Decoder.UseNumber to get exact
// parity; json.Number is passed through untouched here for that reason.
func pyTree(v any) any { return pyTreeValue(reflect.ValueOf(v)) }

func pyTreeValue(rv reflect.Value) any {
	for {
		if !rv.IsValid() {
			return nil
		}
		if k := rv.Kind(); k == reflect.Pointer || k == reflect.Interface {
			if rv.IsNil() {
				return nil
			}
			rv = rv.Elem()
			continue
		}
		break
	}

	switch rv.Type() {
	case timestampType:
		ts, _ := rv.Interface().(schemas.Timestamp)
		return pydanticISO(ts)
	case jsonNumberType:
		return rv.Interface()
	}

	switch rv.Kind() {
	case reflect.Bool:
		return rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return rv.Uint()
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			// Python parity: pydantic's ser_json_inf_nan default is "null".
			return nil
		}
		return f
	case reflect.String:
		return rv.String()
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = pyTreeValue(rv.Index(i))
		}
		return out
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		keys := rv.MapKeys()
		names := make([]string, 0, len(keys))
		byName := make(map[string]reflect.Value, len(keys))
		for _, k := range keys {
			name := pyfmt.JSONMapKey(k)
			names = append(names, name)
			byName[name] = rv.MapIndex(k)
		}
		// Python parity gap: a Python dict keeps insertion order and both
		// serializers honor it. A Go map has none, so keys are SORTED — the
		// same documented deviation pyfmt.Dumps makes. `metadata` is the only
		// dict-typed field this still reaches: by_severity and cost_breakdown
		// have a KNOWN insertion order and are rendered by
		// pyTreeOrderedMap from pyTreeStruct.
		sort.Strings(names)
		out := make(pyfmt.Ordered, 0, len(names))
		for _, name := range names {
			out = append(out, pyfmt.KV{K: name, V: pyTreeValue(byName[name])})
		}
		return out
	case reflect.Struct:
		return pyTreeStruct(rv)
	}
	return nil
}

// orderedDictFields are the model fields whose dict INSERTION order Python
// fixes and a Go map cannot carry, mapped to that order.
//
// `by_severity` is seeded `{s.value: 0 for s in Severity}` and `cost_breakdown`
// is seeded from `_PHASE_ORDER`, both in orchestrator.py, and neither ever
// gains a key on the live path — so their order is deterministic and knowable,
// unlike `metadata`, which stays sorted.
func orderedDictFields(name string) []string {
	switch name {
	case "by_severity":
		return schemas.BySeverityOrder()
	case "cost_breakdown":
		return schemas.CostBreakdownOrder
	}
	return nil
}

// pyTreeOrderedMap renders a map field with the given key order first, then any
// remaining keys sorted (a defensive tail Python cannot reach, kept
// deterministic).
func pyTreeOrderedMap(rv reflect.Value, order []string) any {
	if rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Map {
		return pyTreeValue(rv)
	}
	if rv.IsNil() {
		return nil
	}
	byName := make(map[string]reflect.Value, rv.Len())
	rest := make([]string, 0, rv.Len())
	for _, k := range rv.MapKeys() {
		name := pyfmt.JSONMapKey(k)
		byName[name] = rv.MapIndex(k)
	}
	out := make(pyfmt.Ordered, 0, len(byName))
	seen := make(map[string]bool, len(order))
	for _, name := range order {
		seen[name] = true
		if v, present := byName[name]; present {
			out = append(out, pyfmt.KV{K: name, V: pyTreeValue(v)})
		}
	}
	for name := range byName {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		out = append(out, pyfmt.KV{K: name, V: pyTreeValue(byName[name])})
	}
	return out
}

// pyTreeStruct walks exported fields in DECLARATION order — which is pydantic's
// field order, and therefore model_dump()'s insertion order — honoring the json
// tag name, `json:"-"`, omitempty and encoding/json's flattening of an untagged
// anonymous struct field.
func pyTreeStruct(rv reflect.Value) pyfmt.Ordered {
	rt := rv.Type()
	out := make(pyfmt.Ordered, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if !sf.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if name == "-" && opts == "" {
			continue
		}
		fv := rv.Field(i)
		if name == "" && sf.Anonymous {
			inner := fv
			for inner.Kind() == reflect.Pointer && !inner.IsNil() {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct && inner.Type() != timestampType {
				out = append(out, pyTreeStruct(inner)...)
				continue
			}
		}
		if name == "" {
			name = sf.Name
		}
		if strings.Contains(","+opts+",", ",omitempty,") && pyfmt.IsEmptyValue(fv) {
			continue
		}
		if order := orderedDictFields(name); order != nil {
			out = append(out, pyfmt.KV{K: name, V: pyTreeOrderedMap(fv, order)})
			continue
		}
		out = append(out, pyfmt.KV{K: name, V: pyTreeValue(fv)})
	}
	return out
}

// pydanticDumps renders a pyTree value exactly as pydantic v2's
// `model_dump_json()` does: no whitespace at all, `,` and `:` separators, raw
// UTF-8 (no ensure_ascii), and pydanticFloat numbers.
func pydanticDumps(v any) string {
	var b strings.Builder
	writePydantic(&b, v)
	return b.String()
}

func writePydantic(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writePydanticString(b, x)
	case json.Number:
		writePydanticNumber(b, string(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case float64:
		b.WriteString(pydanticFloat(x))
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writePydantic(b, item)
		}
		b.WriteByte(']')
	case pyfmt.Ordered:
		b.WriteByte('{')
		for i, pair := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writePydanticString(b, pair.K)
			b.WriteByte(':')
			writePydantic(b, pair.V)
		}
		b.WriteByte('}')
	default:
		// pyTree only ever emits the cases above; anything else is a bug
		// upstream and rendering null keeps the document parseable.
		b.WriteString("null")
	}
}

// writePydanticNumber renders a json.Number the way pydantic would render the
// value it stands for: an integral literal verbatim, anything else as a float.
func writePydanticNumber(b *strings.Builder, lit string) {
	if lit == "" {
		b.WriteString("null")
		return
	}
	if !strings.ContainsAny(lit, ".eE") {
		b.WriteString(lit)
		return
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		b.WriteString(lit)
		return
	}
	b.WriteString(pydanticFloat(f))
}

// writePydanticString renders s the way pydantic-core's Rust JSON writer does:
// only `"`, `\` and the C0 control characters are escaped. Verified against the
// venv interpreter:
//
//	DEL (0x7f)        -> raw
//	U+2028 / U+2029   -> raw
//	< > & /           -> raw (Go's encoding/json escapes the first three)
//	non-ASCII         -> raw UTF-8 (json.dumps would emit \uXXXX)
func writePydanticString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(lowerHex[(r>>4)&0xf])
				b.WriteByte(lowerHex[r&0xf])
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

const lowerHex = "0123456789abcdef"

// pydanticFloat renders a float the way pydantic v2 writes it in JSON.
//
// It agrees with Python's repr() — and therefore with pyfmt.FormatFloat — on
// the DIGITS (both use the shortest round-tripping representation) and differs
// only in how it chooses and spells the notation. Verified across
// {1.0, 1.5, 9.87} × 10^[-12,19] against the venv interpreter:
//
//	                repr / json.dumps      pydantic
//	1e-5            1e-05                  0.00001     <- fixed one decade lower
//	9.87e-5         9.87e-05               0.0000987
//	1e-6            1e-06                  1e-6        <- exponent not zero-padded
//	1e-9            1e-09                  1e-9
//	1e-320          1e-320                 1e-320
//	1e15            1000000000000000.0     1000000000000000.0
//	1e16            1e+16                  1e+16
//
// i.e. fixed notation for decpt >= -4 (repr: decpt > -4) and, in scientific
// notation, a signed exponent with NO minimum width (repr pads to two digits).
// `decpt` is CPython's: the value is 0.<digits> * 10**decpt.
func pydanticFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		// Python parity: pydantic's ser_json_inf_nan default is "null".
		// pyTree already replaces these with nil, so this is belt-and-braces.
		return "null"
	}
	sign := ""
	if math.Signbit(f) {
		sign = "-"
	}
	digits, decpt := pyfmt.ShortestDigits(math.Abs(f))
	if decpt < -4 || decpt > 16 {
		return sign + pydanticSci(digits, decpt)
	}
	return sign + pydanticFixed(digits, decpt)
}

// pydanticSci renders <d>[.<rest>]e±X — signed exponent, no zero padding.
func pydanticSci(digits string, decpt int) string {
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
	b.WriteString(strconv.Itoa(exp))
	return b.String()
}

// pydanticFixed renders the digits with the decimal point at decpt, always
// keeping at least one digit on each side ("0.00001", "100.0", "0.0").
func pydanticFixed(digits string, decpt int) string {
	switch {
	case decpt <= 0:
		return "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return digits[:decpt] + "." + digits[decpt:]
	}
}

// pydanticISO renders a schemas.Timestamp the way pydantic v2 serialises a
// `datetime` field into JSON: like datetime.isoformat() except that a zero UTC
// offset is spelled "Z" instead of "+00:00". Verified against the venv:
//
//	datetime(2026,1,2,3,4,5,123456,tzinfo=UTC) -> "2026-01-02T03:04:05.123456Z"
//	datetime(2026,1,2,3,4,5,       tzinfo=UTC) -> "2026-01-02T03:04:05Z"
//	datetime(2026,1,2,3,4,5,123456,tz=+05:30)  -> "2026-01-02T03:04:05.123456+05:30"
//
// schemas.Timestamp.ISOFormat() is the OTHER spelling (always numeric offset) —
// the one output/report.py and output/sarif.py interpolate as
// `result.timestamp.isoformat()`. Do not conflate them.
func pydanticISO(ts schemas.Timestamp) string {
	t := ts.Truncate(time.Microsecond)
	layout := "2006-01-02T15:04:05"
	if t.Nanosecond() != 0 {
		layout += ".000000"
	}
	if _, offset := t.Zone(); offset == 0 {
		return t.Format(layout) + "Z"
	}
	return t.Format(layout + "-07:00")
}
