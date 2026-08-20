package recon

import (
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
)

// mustGet fetches a key out of a pyfmt.Load result, failing the test when it is
// absent. It lived next to the package-local json.dumps/json.load copy that was
// folded into pyfmt at integration time; the helper stayed because the recon
// tests read decoded inventory/graph documents everywhere.
func mustGet(t *testing.T, o pyfmt.Ordered, key string) any {
	t.Helper()
	v, ok := o.Get(key)
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	return v
}
