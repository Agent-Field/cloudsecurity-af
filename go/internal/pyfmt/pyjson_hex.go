package pyfmt

import "strings"

// This file exists only to supply the one helper pyjson.go needs that this
// repo's pyfmt.go does not already export.
//
// pyjson.go is shared verbatim with the sec-af Go port, where `writeHex` lives
// in pyfmt.go alongside `hexDigits`. cloudsecurity-af's pyfmt.go grew a
// repr-shaped pair instead — `writeHexEscape` (which picks the \x / \u / \U
// width the way repr() does) and `writeHexDigits` (which takes no prefix) — so
// the fixed-width, explicit-prefix spelling json escaping needs is added here
// rather than by editing the shared file or the foundation one.

// writeHex appends prefix followed by exactly width lowercase hex digits of r,
// most significant first. json's \uXXXX escape is always four digits wide, and
// a code point above the BMP is emitted as two of them (a UTF-16 surrogate
// pair), which is why the width is a parameter rather than derived from r.
func writeHex(b *strings.Builder, prefix string, r rune, width int) {
	b.WriteString(prefix)
	for shift := (width - 1) * 4; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0xf])
	}
}
