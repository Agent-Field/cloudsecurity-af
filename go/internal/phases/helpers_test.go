package phases

import (
	"encoding/json"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// testNodeID is the NODE_ID the Python probe ran under.
const testNodeID = "cloudsecurity"

// rawFinding mirrors the probe's helper:
//
//	RawFinding(hunter_strategy="iam", title="t", description="d",
//	           category="public_access", iac_file="main.tf", iac_line=1,
//	           config_snippet="", fingerprint="")
//
// with the id/severity/fingerprint/category overridable.
func rawFinding(id string, severity scoring.Severity, fingerprint, category string) schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.ID = id
	f.HunterStrategy = "iam"
	f.Title = "t"
	f.Description = "d"
	f.Category = category
	f.EstimatedSeverity = severity
	f.IaCFile = "main.tf"
	f.IaCLine = 1
	f.ConfigSnippet = ""
	f.Fingerprint = fingerprint
	return f
}

// verifiedFinding mirrors the probe's vf() helper.
func verifiedFinding(id string, verdict schemas.Verdict, severity scoring.Severity) schemas.VerifiedFinding {
	v := schemas.NewVerifiedFinding()
	v.ID = id
	v.Title = "t"
	v.Verdict = verdict
	v.Severity = severity
	v.Category = "public_access"
	v.IaCFile = "main.tf"
	v.IaCLine = 2
	v.ConfigSnippet = ""
	v.Description = "d"
	v.Fingerprint = "fp"
	v.HunterStrategy = "iam"
	v.SARIFRuleID = "r"
	v.SARIFSecuritySeverity = 0.0
	return v
}

// mustMap is afx.ToMap with a fatal on error.
func mustMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, err := afx.ToMap(v)
	if err != nil {
		t.Fatalf("ToMap(%T): %v", v, err)
	}
	return m
}

// jsonMap re-encodes v through JSON so a test can compare a kwarg value that
// ToMap left typed against a plain map literal.
func jsonMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	return out
}

// pm renders a phase reply as a plain map, for the assertions that only look a
// value up by key. The phases return an afx.Payload — an INSERTION-ORDERED
// object — because the wire byte order is part of the parity contract
// (payload_order_test.go pins it against the Python dict order).
func pm(p afx.Payload) map[string]any { return p.Map() }

// verifiedList unwraps a phase reply's `verified` list. The elements are
// afx.Payload — model_dump(exclude_none=True) results, insertion-ordered like
// the Python dicts they port — so the assertions read them as maps.
func verifiedList(t *testing.T, p afx.Payload) []map[string]any {
	t.Helper()
	raw, ok := p.Get("verified")
	if !ok {
		t.Fatalf("reply has no \"verified\" key: %v", p)
	}
	list, ok := raw.([]afx.Payload)
	if !ok {
		t.Fatalf("verified is %T, want []afx.Payload", raw)
	}
	out := make([]map[string]any, 0, len(list))
	for _, entry := range list {
		out = append(out, entry.Map())
	}
	return out
}

// proofEvidence reads a verified finding's proof.evidence list. The nested
// objects are pyfmt.Ordered — insertion-ordered, like the Python dicts
// model_dump produces.
func proofEvidence(t *testing.T, finding map[string]any) []any {
	t.Helper()
	proof, ok := finding["proof"].(pyfmt.Ordered)
	if !ok {
		t.Fatalf("proof is %T, want pyfmt.Ordered", finding["proof"])
	}
	evidence, ok := proof.Get("evidence")
	if !ok {
		t.Fatalf("proof has no evidence key: %v", proof)
	}
	list, ok := evidence.([]any)
	if !ok {
		t.Fatalf("evidence is %T, want a list", evidence)
	}
	return list
}

// payloadKeys is keysOf for a phase reply: the SORTED key set, so a test that
// only cares about the key SET stays readable. The ORDER is asserted separately.
func payloadKeys(p afx.Payload) []string { return keysOf(p.Map()) }

// keysOf returns the sorted key set of a kwargs map, the shape the Python probe
// printed for every recorded call.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
