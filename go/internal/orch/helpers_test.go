package orch

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/afx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/appx"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// fixedTime is the instant every deterministic test pins its clock to. It has a
// non-zero microsecond field so the Timestamp/isoformat fraction is exercised.
var fixedTime = time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)

// fixedClock never advances: every elapsed duration is exactly 0.
func fixedClock() func() time.Time {
	return func() time.Time { return fixedTime }
}

// steppingClock advances by step on every call after the first.
func steppingClock(step time.Duration) func() time.Time {
	calls := 0
	return func() time.Time {
		t := fixedTime.Add(time.Duration(calls) * step)
		calls++
		return t
	}
}

// newTestOrchestrator builds an orchestrator rooted at a scratch repo directory
// with a frozen clock. It sets CLOUDSECURITY_REPO_PATH so New's own resolution
// is exercised rather than bypassed.
func newTestOrchestrator(t *testing.T, app appx.App, input schemas.CloudSecurityInput, nowFn func() time.Time) *ScanOrchestrator {
	t.Helper()
	repo := t.TempDir()
	t.Setenv("CLOUDSECURITY_REPO_PATH", repo)
	o, err := NewWithClock(app, input, nowFn)
	if err != nil {
		t.Fatalf("NewWithClock: %v", err)
	}
	return o
}

// scanInput mirrors the Python probe's CloudSecurityInput construction.
func scanInput(t *testing.T, mutate func(*schemas.CloudSecurityInput)) schemas.CloudSecurityInput {
	t.Helper()
	in := schemas.NewCloudSecurityInput()
	in.RepoURL = "https://example.com/r.git"
	in.Depth = "quick"
	in.SeverityThreshold = "low"
	in.ComplianceFrameworks = []string{"cis_aws"}
	if mutate != nil {
		mutate(&in)
	}
	return in
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

func rawFinding(id string, severity scoring.Severity, fingerprint string) schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.ID = id
	f.HunterStrategy = "iam"
	f.Title = "t"
	f.Description = "d"
	f.Category = "public_access"
	f.EstimatedSeverity = severity
	f.IaCFile = "main.tf"
	f.IaCLine = 1
	f.Fingerprint = fingerprint
	return f
}

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

func floatPtr(f float64) *float64 { return &f }
func intPtr(i int) *int           { return &i }
func stringPtr(s string) *string  { return &s }

// --- bindVerifiedList: the required-field half of model_validate -------------

// VALIDATION CONTRACT — orchestrator.py:121/:131
// `[VerifiedFinding.model_validate(v) for v in prove_dict["verified"]]`.
//
// Ground truth from the repo venv (VerifiedFinding declares title, verdict,
// severity and category with no defaults):
//
//	model_validate({"id": "x", "iac_file": "main.tf"})  -> ValidationError, 4 errors
//	model_validate({"title": "t", "severity": "high", "category": "c"}) -> ValidationError
//	model_validate({... "verdict": "bogus" ...})        -> ValidationError
//	model_validate(5)                                   -> ValidationError
//
// and every one of those is a ValueError SUBCLASS, i.e. app.py's 400 branch.
// A bulk json.Unmarshal into []VerifiedFinding accepts all but the bad enum and
// yields verdict "" — uncounted in the verdict tallies, a bogus "" key in
// by_severity, and dropped by the default severity_threshold.
func TestBindVerifiedList_MissingRequiredFieldsRaise(t *testing.T) {
	for name, element := range map[string]any{
		"no required field at all": map[string]any{"id": "x", "iac_file": "main.tf"},
		"verdict missing":          map[string]any{"title": "t", "severity": "high", "category": "c"},
	} {
		_, err := bindVerifiedList(map[string]any{"verified": []any{element}})
		if err == nil {
			t.Fatalf("%s: expected a validation failure, got none", name)
		}
		var validation *afx.ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("%s: error %v (%T) is not ValueError-class, so app.py's 400 branch is unreachable", name, err, err)
		}
		var missing *afx.MissingFieldError
		if !errors.As(err, &missing) || missing.Model != "VerifiedFinding" {
			t.Fatalf("%s: expected a MissingFieldError for VerifiedFinding, got %v", name, err)
		}
	}
}

// A bad enum value is also ValueError-class (it already was, via
// Verdict.UnmarshalJSON) — pinned so the routing change keeps it that way.
func TestBindVerifiedList_BadEnumIsValueErrorClass(t *testing.T) {
	_, err := bindVerifiedList(map[string]any{"verified": []any{
		map[string]any{"title": "t", "verdict": "bogus", "severity": "high", "category": "c"},
	}})
	var validation *afx.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error %v (%T) is not ValueError-class", err, err)
	}
}

// A non-dict element is a ValidationError in pydantic too.
func TestBindVerifiedList_NonDictElementIsValueErrorClass(t *testing.T) {
	_, err := bindVerifiedList(map[string]any{"verified": []any{5}})
	var validation *afx.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("error %v (%T) is not ValueError-class", err, err)
	}
}

// A complete element still binds, an empty list still binds to an empty (not
// nil) slice, and a missing key is still the KeyError-equivalent — which is NOT
// ValueError-class, so Python answers it 500.
func TestBindVerifiedList_HappyPathAndMissingKey(t *testing.T) {
	got, err := bindVerifiedList(map[string]any{"verified": []any{
		map[string]any{"title": "t", "verdict": "confirmed", "severity": "high", "category": "iam"},
	}})
	if err != nil {
		t.Fatalf("bindVerifiedList: %v", err)
	}
	if len(got) != 1 || got[0].Verdict != schemas.VerdictConfirmed || got[0].Title != "t" {
		t.Fatalf("bound %+v, want one confirmed finding titled t", got)
	}

	empty, err := bindVerifiedList(map[string]any{"verified": []any{}})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list -> (%v, %v), want an empty non-nil slice", empty, err)
	}

	_, err = bindVerifiedList(map[string]any{})
	if !errors.Is(err, errMissingVerifiedKey) {
		t.Fatalf("missing key -> %v, want errMissingVerifiedKey", err)
	}
	var validation *afx.ValidationError
	if errors.As(err, &validation) {
		t.Fatal("a missing 'verified' key is a KeyError in Python, not a ValueError")
	}
}

// A phase whose execution stored a null result reaches the orchestrator as a
// NIL map with a nil error from the SDK. Python sees None and raises
// RuntimeError (500), so the orchestrator must not bind it as an empty dict —
// which for HuntResult/ChainResult (no required fields) would produce a
// fully-defaulted, zero-finding phase result and a 200 "clean" scan.
func TestCallDict_NilReplyIsTheNoneTypeRuntimeError(t *testing.T) {
	app := &appx.Fake{
		CallFn: func(ctx context.Context, target string, input map[string]any) (map[string]any, error) {
			return nil, nil // the SDK's "succeeded, stored result was null"
		},
	}
	_, err := callDict(context.Background(), app, "cloudsecurity.hunt_phase", "hunt_phase", map[string]any{})
	if err == nil {
		t.Fatal("a null phase reply was accepted; Python raises RuntimeError")
	}
	if want := "hunt_phase returned non-dict payload: NoneType"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	var validation *afx.ValidationError
	if errors.As(err, &validation) {
		t.Error("a RuntimeError-equivalent must not be ValueError-class (Python answers it 500, not 400)")
	}
}
