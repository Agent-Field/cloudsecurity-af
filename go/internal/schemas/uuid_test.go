package schemas

import (
	"regexp"
	"strings"
	"testing"
)

// NewUUID4 replaces Python's `str(uuid4())` without adding a dependency, so
// these tests assert the exact textual shape and the RFC 4122 version/variant
// bits a consumer might rely on.

var uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestNewUUID4_Shape(t *testing.T) {
	for i := 0; i < 200; i++ {
		u := NewUUID4()
		if len(u) != 36 {
			t.Fatalf("length %d, want 36: %q", len(u), u)
		}
		if !uuidShape.MatchString(u) {
			t.Fatalf("%q is not canonical lowercase 8-4-4-4-12 hex", u)
		}
		// RFC 4122 §4.4: version nibble is 4, variant high bits are 10xx.
		if u[14] != '4' {
			t.Fatalf("%q: version nibble = %q, want '4'", u, u[14])
		}
		if !strings.ContainsRune("89ab", rune(u[19])) {
			t.Fatalf("%q: variant nibble = %q, want one of 8/9/a/b", u, u[19])
		}
	}
}

func TestNewUUID4_Unique(t *testing.T) {
	const n = 5000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		u := NewUUID4()
		if _, dup := seen[u]; dup {
			t.Fatalf("collision after %d draws: %q", i, u)
		}
		seen[u] = struct{}{}
	}
}
