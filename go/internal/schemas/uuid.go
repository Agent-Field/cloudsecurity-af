package schemas

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewUUID4 returns a random RFC 4122 version-4 UUID in the canonical
// 8-4-4-4-12 lowercase-hex form, e.g. "1f6b9e5a-e48b-4a18-9f72-1047fec0d078".
//
// It ports Python's `str(uuid4())`, which several models use as a
// default_factory. Implemented on crypto/rand rather than github.com/google/uuid
// because the port adds no third-party dependencies beyond the SDK (design §0.6).
//
// Layout (RFC 4122 §4.4): 16 random bytes, then byte 6's high nibble forced to
// 4 (the version) and byte 8's two high bits forced to 10 (the variant).
//
// A crypto/rand failure is unrecoverable and cannot be reported through a
// pydantic-shaped default_factory, so it panics — the same posture as
// google/uuid's uuid.New().
func NewUUID4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("schemas: crypto/rand failed generating a uuid4: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx (RFC 4122)

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}
