package pyfmt

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// reprString ports CPython's unicode_repr (Objects/unicodeobject.c).
//
// Quote selection: single quotes, UNLESS the string contains a single quote and
// no double quote — then double quotes are used so the apostrophe needs no
// escape. Verified:
//
//	repr("it's")          == "it's"     (double-quoted, ' left bare)
//	repr('say "hi"')      == 'say "hi"' (single-quoted, " left bare)
//	repr("""both ' and "  """.strip()) -> 'both \' and "'   (both present -> single quotes, ' escaped)
//
// Escapes, in CPython's order: the active quote and backslash get a backslash;
// \t \n \r get their short forms; anything below 0x20 or equal to 0x7f becomes
// \xNN; every other ASCII char is literal; and a non-ASCII rune is literal iff
// Py_UNICODE_ISPRINTABLE, otherwise \xNN / \uXXXX / \UXXXXXXXX by width.
//
// Go's unicode.IsPrint is the exact analogue of Py_UNICODE_ISPRINTABLE: both
// exclude categories Cc, Cf, Cs, Co, Cn, Zl, Zp and Zs-except-U+0020. Verified
// against CPython:
//
//	repr("café")     == "'café'"        (printable, literal)
//	repr("emoji 😀") == "'emoji 😀'"    (So, literal)
//	repr("nbsp\xa0x") == "'nbsp\\xa0x'"  (Zs -> escaped)
//	repr("zwsp​x") == "'zwsp\\u200bx'" (Cf -> escaped)
func reprString(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}

	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			writeHexEscape(&b, r)
		case r < 0x7f:
			b.WriteRune(r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			writeHexEscape(&b, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// writeHexEscape emits CPython's width-selected numeric escape: \xNN below
// U+0100, \uXXXX below U+10000, \UXXXXXXXX above. Hex digits are lowercase.
func writeHexEscape(b *strings.Builder, r rune) {
	switch {
	case r < 0x100:
		b.WriteString(`\x`)
		writeHexDigits(b, uint32(r), 2)
	case r < 0x10000:
		b.WriteString(`\u`)
		writeHexDigits(b, uint32(r), 4)
	default:
		b.WriteString(`\U`)
		writeHexDigits(b, uint32(r), 8)
	}
}

const hexDigits = "0123456789abcdef"

func writeHexDigits(b *strings.Builder, v uint32, width int) {
	for i := width - 1; i >= 0; i-- {
		b.WriteByte(hexDigits[(v>>uint(4*i))&0xf])
	}
}

// reprReflect is the fallback for value kinds Repr's type switch does not name
// explicitly: typed slices/arrays (rendered as a Python list), typed maps
// (rendered as a Python dict with SORTED keys — see the warning on Repr),
// pointers (the pointee, or None), and anything else (Go's own %v rendering,
// which no ported prompt should ever reach).
func reprReflect(v any) string {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Invalid:
		return "None"
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return "None"
		}
		return Repr(rv.Elem().Interface())
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			// Python parity: a Go nil slice stands in for an empty Python list.
			// A Python None would have arrived as an untyped nil.
			return "[]"
		}
		parts := make([]string, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			parts[i] = Repr(rv.Index(i).Interface())
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case reflect.Map:
		keys := rv.MapKeys()
		strKeys := make([]string, len(keys))
		byStr := make(map[string]reflect.Value, len(keys))
		for i, k := range keys {
			ks := Str(k.Interface())
			strKeys[i] = ks
			byStr[ks] = k
		}
		sort.Strings(strKeys)
		pairs := make([]KV, len(strKeys))
		for i, ks := range strKeys {
			pairs[i] = KV{K: ks, V: rv.MapIndex(byStr[ks]).Interface()}
		}
		return reprPairs(pairs)
	case reflect.String:
		return reprString(rv.String())
	case reflect.Bool:
		if rv.Bool() {
			return "True"
		}
		return "False"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return FormatFloat(rv.Float())
	}
	// Unreachable for every value the port interpolates; keep it honest
	// rather than panicking.
	return fmt.Sprintf("%v", v)
}
